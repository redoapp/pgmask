//! Regression tests for statement, portal, and result-plan binding.
//!
//! The governing rule is that the masking plan is bound to the
//! `RowDescription`. These three cases each broke it with a protocol-legal
//! client, no error and no `Close`, and each was found by an audit rather than
//! by the existing suite:
//!
//! 1. `Parse` replacing a statement name left the previous statement's plan
//!    cached. `Execute` emits no `RowDescription`, so the rule never fired.
//! 2. A `Describe` answered with `ErrorResponse` left its slot in the FIFO
//!    forever, so a later plan was filed under a stale name.
//! 3. `described_sql` was a scalar while the Describes were a queue, so two
//!    pipelined Describes analysed both result sets against one statement's
//!    text.
//!
//! The scripted fake backend needs no Postgres or containers. A positive
//! control proves the harness can see an unmasked row; a compatibility control
//! proves that an identical re-Parse retains valid metadata.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use pgmask::catalog::{Lineage, Opaque, Summaries, SystemCatalogs, Unclassified};
use pgmask::mask::{Mask, Masker};
use pgmask::metrics::Metrics;
use pgmask::protocol::{FrameReader, Message};
use pgmask::tls::BackendTls;
use pgmask::{Catalog, Policy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use support::{bind_msg, describe_statement, execute_msg, parse_msg, sync_msg, RawClient};

const CANARY: &str = "CANARY_EMAIL_a1b2c3";

// --- backend message builders ------------------------------------------------

fn auth_ok() -> Bytes {
    let mut b = BytesMut::new();
    b.put_i32(0);
    Message::new(b'R', b.freeze()).encode()
}

fn ready() -> Bytes {
    Message::new(b'Z', Bytes::from_static(b"I")).encode()
}

fn tagless(tag: u8) -> Bytes {
    Message::new(tag, Bytes::new()).encode()
}

fn param_description() -> Bytes {
    let mut b = BytesMut::new();
    b.put_i16(0);
    Message::new(b't', b.freeze()).encode()
}

/// fields: (name, table_oid, column_id, type_oid)
fn row_description(fields: &[(&str, u32, i16, u32)]) -> Bytes {
    let mut b = BytesMut::new();
    b.put_i16(fields.len() as i16);
    for (name, table_oid, column_id, type_oid) in fields {
        b.put_slice(name.as_bytes());
        b.put_u8(0);
        b.put_u32(*table_oid);
        b.put_i16(*column_id);
        b.put_u32(*type_oid);
        b.put_i16(-1);
        b.put_i32(-1);
        b.put_i16(0);
    }
    Message::new(b'T', b.freeze()).encode()
}

fn data_row(values: &[&str]) -> Bytes {
    let mut b = BytesMut::new();
    b.put_i16(values.len() as i16);
    for v in values {
        b.put_i32(v.len() as i32);
        b.put_slice(v.as_bytes());
    }
    Message::new(b'D', b.freeze()).encode()
}

fn command_complete(tag: &str) -> Bytes {
    let mut b = BytesMut::new();
    b.put_slice(tag.as_bytes());
    b.put_u8(0);
    Message::new(b'C', b.freeze()).encode()
}

fn error_response(sqlstate: &str, message: &str) -> Bytes {
    let mut b = BytesMut::new();
    for (t, v) in [(b'S', "ERROR"), (b'C', sqlstate), (b'M', message)] {
        b.put_u8(t);
        b.put_slice(v.as_bytes());
        b.put_u8(0);
    }
    b.put_u8(0);
    Message::new(b'E', b.freeze()).encode()
}

fn cat(parts: &[Bytes]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

// --- scripted fake backend ---------------------------------------------------

/// Accepts one connection, answers startup with AuthenticationOk + ReadyForQuery,
/// then writes `blocks[i]` after the i-th `Sync` or `Query` it receives.
async fn fake_backend(blocks: Vec<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        // Startup packet: [len][body]
        let mut len = [0u8; 4];
        if sock.read_exact(&mut len).await.is_err() {
            return;
        }
        let n = i32::from_be_bytes(len) as usize - 4;
        let mut body = vec![0u8; n];
        if sock.read_exact(&mut body).await.is_err() {
            return;
        }
        let _ = sock.write_all(&auth_ok()).await;
        let _ = sock.write_all(&ready()).await;
        let _ = sock.flush().await;

        let (r, mut w) = sock.into_split();
        let mut frames = FrameReader::new(r);
        let mut i = 0usize;
        while let Ok(Some(msg)) = frames.read_message().await {
            if msg.tag == b'S' || msg.tag == b'Q' {
                if let Some(block) = blocks.get(i) {
                    let _ = w.write_all(block).await;
                    let _ = w.flush().await;
                }
                i += 1;
            }
            if msg.tag == b'X' {
                return;
            }
        }
    });
    addr
}

async fn start_proxy(
    backend: SocketAddr,
    unclassified: Unclassified,
    opaque: Opaque,
) -> SocketAddr {
    let policy = Arc::new(Policy {
        catalog: Arc::new(Catalog::default()),
        masker: Arc::new(Masker::new(b"test-key".to_vec())),
        unclassified,
        unclassified_mask: Mask::Null,
        opaque,
        metrics: Arc::new(Metrics::default()),
        summaries: Summaries::Allow,
        system_catalogs: SystemCatalogs::Refuse,
        lineage: Lineage::Refuse,
        roles: HashMap::new(),
        tls: None,
        backend_tls: BackendTls::Disable,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = backend.to_string();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let policy = policy.clone();
            let backend = backend.clone();
            tokio::spawn(async move {
                let _ = pgmask::handle_connection(client, &backend, policy).await;
            });
        }
    });
    addr
}

/// Sanity: the fake-backend harness can see a leak at all.
#[tokio::test]
async fn control_harness_sees_an_unmasked_row() {
    let backend = fake_backend(vec![cat(&[
        row_description(&[("one", 0, 0, 23)]),
        data_row(&[CANARY]),
        command_complete("SELECT 1"),
        ready(),
    ])])
    .await;
    let proxy = start_proxy(backend, Unclassified::Mask, Opaque::Reject).await;
    let mut c = RawClient::connect(proxy, "db").await.unwrap();
    c.simple_query("SELECT 1").await.unwrap();
    assert!(
        c.received_text().contains(CANARY),
        "control failed: harness cannot detect a leak"
    );
}

// === FINDING 1 ==============================================================
// Re-`Parse` of an existing statement name does not invalidate the plan cached
// under that name. The unnamed statement is implicitly replaced on every Parse,
// so this needs no `Close`.
#[tokio::test]
async fn reparse_invalidates_the_previous_statements_plan() {
    let backend = fake_backend(vec![
        // round 1: Parse("", "SELECT 1") + Describe(S,"") + Sync
        cat(&[
            tagless(b'1'),
            param_description(),
            row_description(&[("?column?", 0, 0, 23)]),
            ready(),
        ]),
        // round 2: Parse("", "SELECT email ...") + Bind + Execute + Sync
        // NOTE: no RowDescription — Execute never emits one.
        cat(&[
            tagless(b'1'),
            tagless(b'2'),
            data_row(&[CANARY]),
            command_complete("SELECT 1"),
            ready(),
        ]),
    ])
    .await;
    let proxy = start_proxy(backend, Unclassified::Mask, Opaque::Reject).await;
    let mut c = RawClient::connect(proxy, "db").await.unwrap();

    c.send(parse_msg("", "SELECT 1")).await.unwrap();
    c.send(describe_statement("")).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(parse_msg("", "SELECT email FROM public.t"))
        .await
        .unwrap();
    c.send(bind_msg("", "")).await.unwrap();
    c.send(execute_msg("", 0)).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready_or_eof().await.unwrap();

    assert!(
        !c.received_text().contains(CANARY),
        "LEAK: a plan built for `SELECT 1` masked a row from `SELECT email`"
    );
}

#[tokio::test]
async fn reparse_of_identical_sql_preserves_its_described_plan() {
    let backend = fake_backend(vec![
        cat(&[
            tagless(b'1'),
            param_description(),
            row_description(&[("?column?", 0, 0, 23)]),
            ready(),
        ]),
        cat(&[
            tagless(b'1'),
            tagless(b'2'),
            data_row(&[CANARY]),
            command_complete("SELECT 1"),
            ready(),
        ]),
    ])
    .await;
    let proxy = start_proxy(backend, Unclassified::Allow, Opaque::Reject).await;
    let mut c = RawClient::connect(proxy, "db").await.unwrap();

    c.send(parse_msg("", "SELECT 1")).await.unwrap();
    c.send(describe_statement("")).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(parse_msg("", "SELECT 1")).await.unwrap();
    c.send(bind_msg("", "")).await.unwrap();
    c.send(execute_msg("", 0)).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    assert!(
        c.received_text().contains(CANARY),
        "same-SQL re-Parse discarded the only available result plan"
    );
}

#[tokio::test]
async fn rejected_named_reparse_cannot_relabel_the_existing_statement() {
    let backend = fake_backend(vec![
        // The backend accepts the original opaque statement.
        cat(&[tagless(b'1'), ready()]),
        // PostgreSQL rejects redefining a named statement without Close.
        cat(&[
            error_response("42P05", "prepared statement \"s\" already exists"),
            ready(),
        ]),
        // Describe still answers for the original, opaque SQL.
        cat(&[
            param_description(),
            row_description(&[("lower", 0, 0, 25)]),
            ready(),
        ]),
        // Even a hostile backend row must not cross after the mismatch.
        cat(&[
            tagless(b'2'),
            data_row(&[CANARY]),
            command_complete("SELECT 1"),
            ready(),
        ]),
    ])
    .await;
    let proxy = start_proxy(backend, Unclassified::Allow, Opaque::Reject).await;
    let mut c = RawClient::connect(proxy, "db").await.unwrap();

    c.send(parse_msg("s", "SELECT lower(email) FROM public.t"))
        .await
        .unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(parse_msg("s", "SELECT 1")).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(describe_statement("s")).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(bind_msg("p", "s")).await.unwrap();
    c.send(execute_msg("p", 0)).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready_or_eof().await.unwrap();

    assert!(
        !c.received_text().contains(CANARY),
        "LEAK: rejected SQL relabelled the backend's existing named statement"
    );
}

// === FINDING 2 ==============================================================
// `pending_describes` is never drained when a Describe is answered with an
// ErrorResponse, so the FIFO desynchronises and a later RowDescription's plan is
// filed under the wrong statement name.
#[tokio::test]
async fn an_errored_describe_leaves_no_stale_fifo_slot() {
    let backend = fake_backend(vec![
        // round 1: Describe(S,"sM") on a statement that does not exist
        cat(&[
            error_response("26000", "prepared statement \"sM\" does not exist"),
            ready(),
        ]),
        // round 2: Parse("sR","SELECT 1") + Describe(S,"sR") + Sync
        cat(&[
            tagless(b'1'),
            param_description(),
            row_description(&[("?column?", 0, 0, 23)]),
            ready(),
        ]),
        // round 3: Parse("sM", "SELECT email ...") + Bind + Execute + Sync
        cat(&[
            tagless(b'1'),
            tagless(b'2'),
            data_row(&[CANARY]),
            command_complete("SELECT 1"),
            ready(),
        ]),
    ])
    .await;
    let proxy = start_proxy(backend, Unclassified::Mask, Opaque::Reject).await;
    let mut c = RawClient::connect(proxy, "db").await.unwrap();

    c.send(describe_statement("sM")).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(parse_msg("sR", "SELECT 1")).await.unwrap();
    c.send(describe_statement("sR")).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(parse_msg("sM", "SELECT email FROM public.t"))
        .await
        .unwrap();
    c.send(bind_msg("p", "sM")).await.unwrap();
    c.send(execute_msg("p", 0)).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready_or_eof().await.unwrap();

    assert!(
        !c.received_text().contains(CANARY),
        "LEAK: a ghost Describe slot took `SELECT 1`'s plan and filed it under sM"
    );
}

// === FINDING 3 ==============================================================
// `described_sql` is a single slot while `pending_describes` is a queue. Two
// pipelined Describes make the second one's SQL the analysis input for BOTH
// RowDescriptions.
#[tokio::test]
async fn pipelined_describes_each_analyse_their_own_sql() {
    let backend = fake_backend(vec![
        cat(&[
            tagless(b'1'),
            tagless(b'1'),
            param_description(),
            row_description(&[("lower", 0, 0, 25)]), // for statement "b"
            param_description(),
            row_description(&[("?column?", 0, 0, 23)]), // for statement "a"
            ready(),
        ]),
        cat(&[
            tagless(b'2'),
            data_row(&[CANARY]),
            command_complete("SELECT 1"),
            ready(),
        ]),
    ])
    .await;
    let proxy = start_proxy(backend, Unclassified::Mask, Opaque::Reject).await;
    let mut c = RawClient::connect(proxy, "db").await.unwrap();

    let mut buf = Vec::new();
    for m in [
        parse_msg("a", "SELECT 1"),
        parse_msg("b", "SELECT lower(email) FROM public.t"),
        describe_statement("b"),
        describe_statement("a"),
        sync_msg(),
    ] {
        buf.extend_from_slice(&m.encode());
    }
    c.send_raw(&buf).await.unwrap();
    c.read_until_ready().await.unwrap();

    c.send(bind_msg("p", "b")).await.unwrap();
    c.send(execute_msg("p", 0)).await.unwrap();
    c.send(sync_msg()).await.unwrap();
    c.read_until_ready_or_eof().await.unwrap();

    assert!(
        !c.received_text().contains(CANARY),
        "LEAK: `SELECT 1`'s releasable verdict was applied to `SELECT lower(email)`"
    );
}
