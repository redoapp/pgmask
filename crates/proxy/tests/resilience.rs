//! Phase 4 criteria 5 and 6: cancellation, and failing closed under stress.
//!
//! The theme: every one of these paths must end in "no data" rather than "some
//! data, unmasked". Run via `scripts/test-integration.sh`.

mod support;

use std::time::Duration;

use anyhow::Result;
use bytes::BufMut;
use support::*;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const DB: &str = "postgres";

// --- Criterion 5: cancellation ----------------------------------------------

/// `BackendKeyData` is forwarded verbatim, so the client holds the backend's own
/// PID and secret. A `CancelRequest` arrives as its own short-lived connection
/// and we hand it straight to the backend, which is why this works without the
/// proxy keeping a key table of its own.
#[tokio::test]
async fn cancel_request_actually_cancels() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;

    // tokio-postgres exposes the cancel token, and it goes through the proxy the
    // same way psql's Ctrl-C would.
    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host=127.0.0.1 port={} user=postgres dbname={DB}",
            proxy.addr.port()
        ),
        tokio_postgres::NoTls,
    )
    .await?;
    let cancel = client.cancel_token();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // The sleep goes in the FROM clause, not the target list: a bare
    // `SELECT pg_sleep(30)` projects an expression with no provenance and gets
    // refused before it is ever slow enough to cancel.
    let query = tokio::spawn(async move {
        client
            .simple_query("SELECT s.email FROM canary.subjects s CROSS JOIN pg_sleep(30)")
            .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel_query(tokio_postgres::NoTls).await?;

    let result = tokio::time::timeout(Duration::from_secs(10), query).await??;
    let err = result.expect_err("the query should have been cancelled");
    // tokio-postgres's Display is just "db error"; the SQLSTATE is the signal.
    // 57014 is query_canceled — proof the CancelRequest reached the backend and
    // matched the key the client was handed through the proxy.
    let db_err = err.as_db_error().expect("expected a database error");
    assert_eq!(
        db_err.code(),
        &tokio_postgres::error::SqlState::QUERY_CANCELED,
        "expected query_canceled, got {}: {}",
        db_err.code().code(),
        db_err.message()
    );
    Ok(())
}

// --- Criterion 6: failure injection -----------------------------------------

#[tokio::test]
async fn a_refused_catalog_prevents_startup() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    // A rule naming a column that does not exist must stop the proxy coming up,
    // rather than starting with partial coverage nobody can see.
    let mut rules = default_rules();
    rules.push(rule(
        "canary.subjects",
        "no_such_column",
        pgmask::mask::Mask::Redact,
    ));
    let started = start_proxy(DB, rules).await;
    let err = started.err().expect("must refuse to start");
    let text = format!("{err:#}");
    assert!(
        text.contains("no_such_column") && text.contains("unknown coverage"),
        "expected an explicit refusal, got: {text}"
    );
    Ok(())
}

#[tokio::test]
async fn a_client_vanishing_mid_stream_is_not_a_panic() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;

    // Ask for a large result set and hang up immediately, so the proxy is
    // mid-forward when the client disappears.
    let mut stream = TcpStream::connect(proxy.addr).await?;
    let mut body = bytes::BytesMut::new();
    for (k, v) in [("user", "postgres"), ("database", DB)] {
        body.put_slice(k.as_bytes());
        body.put_u8(0);
        body.put_slice(v.as_bytes());
        body.put_u8(0);
    }
    body.put_u8(0);
    let mut startup = bytes::BytesMut::new();
    startup.put_i32(body.len() as i32 + 8);
    startup.put_i32(196608);
    startup.put_slice(&body);
    stream.write_all(&startup).await?;

    let mut query = bytes::BytesMut::new();
    let sql = "SELECT * FROM canary.subjects, generate_series(1, 50000)\0";
    query.put_u8(b'Q');
    query.put_i32(sql.len() as i32 + 4);
    query.put_slice(sql.as_bytes());
    stream.write_all(&query).await?;
    drop(stream);

    // The proxy must survive: a later connection still works normally.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT city FROM canary.subjects")
        .await?;
    assert_no_canary(&client, "after a client vanished mid-stream");
    Ok(())
}

#[tokio::test]
async fn a_backend_that_never_answers_does_not_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;

    // Point the proxy at a socket that accepts and then says nothing. The client
    // must get nothing rather than anything improvised.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let dead_addr = dead.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = dead.accept().await else {
                return;
            };
            // Hold the connection open, answer nothing.
            std::mem::forget(stream);
        }
    });

    let proxy = start_proxy_at(
        &dead_addr.to_string(),
        DB,
        default_rules(),
        pgmask::catalog::Unclassified::Mask,
        pgmask::catalog::Opaque::Reject,
    )
    .await?;

    // Startup can never complete, so the connect must hang rather than return.
    // The failure this guards against is the proxy synthesising a ReadyForQuery
    // to be helpful and then forwarding whatever arrives later unvetted.
    let outcome =
        tokio::time::timeout(Duration::from_secs(2), RawClient::connect(proxy.addr, DB)).await;
    assert!(
        outcome.is_err(),
        "connect completed against a backend that never answered — the proxy \
         must not invent a startup response"
    );
    Ok(())
}

#[tokio::test]
async fn many_concurrent_sessions_all_stay_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;

    // Every session keeps its own plans; a shared or leaked plan between
    // connections would show up as a canary on at least one of them.
    let mut tasks = Vec::new();
    for i in 0..24 {
        let addr = proxy.addr;
        tasks.push(tokio::spawn(async move {
            let mut client = RawClient::connect(addr, DB).await?;
            // Mix shapes so sessions are not in lockstep.
            let sql = match i % 4 {
                0 => "SELECT * FROM canary.subjects",
                1 => "SELECT lower(email) FROM canary.subjects",
                2 => "SELECT * FROM canary.subject_view",
                _ => "SELECT note, city FROM canary.subjects",
            };
            client.simple_query(sql).await?;
            client
                .simple_query("SELECT email, name FROM canary.subjects")
                .await?;
            assert_no_canary(&client, "concurrent session");
            Ok::<_, anyhow::Error>(())
        }));
    }
    for task in tasks {
        task.await??;
    }
    Ok(())
}
