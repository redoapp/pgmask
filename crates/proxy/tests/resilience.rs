#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
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

    // A genuinely slow query the read-only allowlist serves. `pg_sleep` used to
    // do this, but it is not on the trusted-function allowlist and is refused
    // before it can be slow. A table-free recursive CTE counted with a bare
    // aggregate is provably safe (a reducing aggregate carries no value), so it
    // is served and runs long enough to cancel.
    let query = tokio::spawn(async move {
        client
            .simple_query(
                "WITH RECURSIVE t(n) AS \
                 (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 1000000000) \
                 SELECT count(*) FROM t",
            )
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
    let msgs = client
        .simple_query("SELECT city FROM canary.subjects")
        .await?;
    // "Still works" means it still serves — a refused or silent later query
    // would pass a bare canary check while hiding a proxy that had wedged.
    assert_served(&msgs, "the proxy still serves after a client vanished");
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
            let msgs = client
                .simple_query("SELECT email, name FROM canary.subjects")
                .await?;
            assert_served(&msgs, "concurrent session masked select");
            assert_no_canary(&client, "concurrent session");
            Ok::<_, anyhow::Error>(())
        }));
    }
    for task in tasks {
        task.await??;
    }
    Ok(())
}

// --- Catalog staleness ------------------------------------------------------

/// `DROP VIEW; CREATE VIEW` — what a lot of migration tooling emits — gives the
/// view a new pg_class OID. A catalog pinned at boot silently stops classifying
/// those columns: with default-deny they use the type-aware fallback, and with
/// `unclassified = "allow"` they stop being masked at all.
#[tokio::test]
async fn a_recreated_view_is_reclassified_after_refresh() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;

    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT email, name, city FROM canary.subject_view WHERE id = 1")
        .await?;
    let before = client.received_text();
    assert!(before.contains("Portland"), "allowed column should pass");
    assert!(before.contains("***"), "name should be redacted");
    assert_no_canary(&client, "before recreation");

    // Recreate the view out from under the running proxy.
    let (admin, connection) =
        tokio_postgres::connect(&backend_dsn(DB), tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    admin
        .batch_execute(
            "DROP VIEW canary.subject_view; \
             CREATE VIEW canary.subject_view AS \
               SELECT id, email, name, city FROM canary.subjects;",
        )
        .await?;

    // Give the refresher a beat. The hot path also nudges it on the first
    // unrecognised relation OID, so this converges quickly.
    let mut recovered = false;
    for _ in 0..30 {
        let mut probe = RawClient::connect(proxy.addr, DB).await?;
        probe
            .simple_query("SELECT email, name, city FROM canary.subject_view WHERE id = 1")
            .await?;
        assert_no_canary(&probe, "after recreation");
        if probe.received_text().contains("Portland") {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        recovered,
        "classification never recovered after the view was recreated — the catalog \
         is pinned at boot"
    );
    Ok(())
}

#[tokio::test]
async fn a_dropped_relation_is_reported_not_silent() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;

    let (admin, connection) =
        tokio_postgres::connect(&backend_dsn(DB), tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    admin.batch_execute("DROP VIEW canary.subject_view").await?;

    // Whatever else happens, the classified base table must keep working and no
    // canary may escape while coverage is degraded.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT email, name, city FROM canary.subjects WHERE id = 1")
        .await?;
    assert!(client.received_text().contains("Portland"));
    assert_no_canary(&client, "while coverage is degraded");
    Ok(())
}

// --- Rejection instrumentation ----------------------------------------------

/// The counters exist to answer one question: is the Phase 6 parser worth it?
/// That turns on how much of the rejection volume is set-operation-shaped.
#[tokio::test]
async fn rejections_are_bucketed_by_cause() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // A set operation preserves the column name while losing provenance.
    client
        .simple_query(
            "SELECT email FROM canary.subjects UNION ALL SELECT email FROM canary.subjects",
        )
        .await?;
    // A function call is named after the function.
    client
        .simple_query("SELECT lower(email) FROM canary.subjects")
        .await?;
    // A literal and count(*) are now *rescued* rather than rejected, so use a
    // shape that still cannot be proven safe for the anonymous bucket: a
    // concatenation is anonymous.
    client
        .simple_query("SELECT email || '' FROM canary.subjects")
        .await?;
    // `max(email)` used to reach the opaque_aggregate bucket. It no longer does:
    // `max` is not on the trusted-function allowlist, so it is refused as an
    // untrusted function before the result is ever classified.
    client
        .simple_query("SELECT max(email) FROM canary.subjects")
        .await?;
    // And the ones that should no longer count as rejections at all.
    client.simple_query("SELECT 1").await?;
    client
        .simple_query("SELECT count(*) FROM canary.subjects")
        .await?;
    // COPY ... TO STDOUT used to reach the copy_stream bucket; the read-only
    // allowlist now refuses it as a write before that handler runs.
    client
        .simple_query("COPY canary.subjects TO STDOUT")
        .await?;

    let report = proxy.metrics.report().expect("expected counters");
    for expected in [
        "opaque_named_like_column=1",
        "opaque_function=1",
        "opaque_anonymous=1",
        // max() is refused as untrusted, COPY as a write — earlier gates than
        // the opaque_aggregate / copy_stream buckets they used to land in.
        "untrusted_function=1",
        "write_refused=1",
        "set_op_like_share=",
        // SELECT 1 and count(*) are served now, not refused.
        "fields_rescued=2",
    ] {
        assert!(
            report.contains(expected),
            "missing {expected} in report: {report}"
        );
    }
    Ok(())
}
