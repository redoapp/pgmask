//! Test harness: a raw wire client, a canary schema, and an in-process proxy.
//!
//! The client speaks the protocol directly rather than going through a driver,
//! because the interesting adversarial messages are exactly the ones no
//! well-behaved driver will ever send — `FunctionCall`, `Execute` without
//! `Describe`, re-`Bind` of a stale statement, pipelined interleaved portals.
//!
//! It records **every byte** received from the proxy, which is what makes the
//! canary assertion meaningful: not "the values the driver decoded", but "the
//! bytes that crossed the boundary".

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use pgmask::catalog::{ColumnRule, Config, Opaque, Unclassified};
use pgmask::mask::Mask;
use pgmask::protocol::{FrameReader, Message, StartupPacket};
use pgmask::{Catalog, Policy};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Set by `scripts/test-integration.sh`. Tests skip when absent.
pub fn backend_addr() -> Option<String> {
    std::env::var("PGMASK_TEST_PG").ok()
}

pub fn backend_dsn(db: &str) -> String {
    let addr = backend_addr().expect("PGMASK_TEST_PG");
    let (host, port) = addr.split_once(':').unwrap_or((addr.as_str(), "5432"));
    format!("postgres://postgres@{host}:{port}/{db}")
}

/// Skip the test body when no Postgres is configured.
#[macro_export]
macro_rules! require_pg {
    () => {
        match $crate::support::backend_addr() {
            Some(addr) => addr,
            None => {
                eprintln!("skipping: set PGMASK_TEST_PG (see scripts/test-integration.sh)");
                return Ok(());
            }
        }
    };
}

// --- Canary schema ----------------------------------------------------------

/// Sentinels seeded into every classified column. Distinctive enough that a
/// substring search over the received bytes is a sound leak detector.
pub const CANARIES: &[&str] = &[
    "CANARY_EMAIL_a1b2c3",
    "CANARY_NAME_d4e5f6",
    "CANARY_NOTE_97h8i9",
    "CANARY_TEMP_j0k1l2",
];

pub const CANARY_EMAIL: &str = CANARIES[0];
pub const CANARY_NAME: &str = CANARIES[1];
pub const CANARY_NOTE: &str = CANARIES[2];
pub const CANARY_TEMP: &str = CANARIES[3];

pub const SCHEMA_SQL: &str = r#"
DROP SCHEMA IF EXISTS canary CASCADE;
CREATE SCHEMA canary;

CREATE TABLE canary.subjects (
  id    int PRIMARY KEY,
  email text NOT NULL,
  name  text NOT NULL,
  note  text NOT NULL,
  city  text NOT NULL
);

INSERT INTO canary.subjects VALUES
  (1, 'CANARY_EMAIL_a1b2c3', 'CANARY_NAME_d4e5f6', 'CANARY_NOTE_97h8i9', 'Portland'),
  (2, 'CANARY_EMAIL_a1b2c3', 'CANARY_NAME_d4e5f6', 'CANARY_NOTE_97h8i9', 'Denver');

CREATE VIEW canary.subject_view AS SELECT id, email, name, city FROM canary.subjects;

CREATE FUNCTION canary.all_subjects() RETURNS SETOF canary.subjects AS $$
  SELECT * FROM canary.subjects;
$$ LANGUAGE sql STABLE;

CREATE FUNCTION canary.emails() RETURNS TABLE (email text) AS $$
  SELECT email FROM canary.subjects;
$$ LANGUAGE sql STABLE;
"#;

/// Apply the canary schema. Uses tokio-postgres for convenience; the raw client
/// is only for driving the proxy.
pub async fn load_schema(db: &str) -> Result<()> {
    let (client, connection) =
        tokio_postgres::connect(&backend_dsn(db), tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client.batch_execute(SCHEMA_SQL).await?;
    Ok(())
}

/// The catalog used by most tests: classified columns masked, `city` allowed.
pub fn default_rules() -> Vec<ColumnRule> {
    vec![
        rule("canary.subjects", "id", Mask::None),
        rule("canary.subjects", "email", Mask::Pseudonym),
        rule("canary.subjects", "name", Mask::Redact),
        rule("canary.subjects", "city", Mask::None),
        // canary.subjects.note is deliberately unclassified -> default-deny.
        rule("canary.subject_view", "id", Mask::None),
        rule("canary.subject_view", "email", Mask::Pseudonym),
        rule("canary.subject_view", "name", Mask::Redact),
        rule("canary.subject_view", "city", Mask::None),
    ]
}

pub fn rule(relation: &str, column: &str, mask: Mask) -> ColumnRule {
    ColumnRule {
        relation: relation.into(),
        column: column.into(),
        semantic_type: None,
        mask: Some(mask),
        params: Default::default(),
        by_role: Default::default(),
    }
}

// --- In-process proxy -------------------------------------------------------

pub struct ProxyHandle {
    pub addr: SocketAddr,
    pub metrics: Arc<pgmask::metrics::Metrics>,
}

pub async fn start_proxy(db: &str, rules: Vec<ColumnRule>) -> Result<ProxyHandle> {
    start_proxy_with(db, rules, Unclassified::Mask, Opaque::Reject).await
}

pub async fn start_proxy_with(
    db: &str,
    rules: Vec<ColumnRule>,
    unclassified: Unclassified,
    opaque: Opaque,
) -> Result<ProxyHandle> {
    let backend = backend_addr().context("PGMASK_TEST_PG")?;
    start_proxy_at(&backend, db, rules, unclassified, opaque).await
}

/// Same, but forwarding to an arbitrary address — used to point the proxy at a
/// backend that misbehaves.
pub async fn start_proxy_at(
    backend: &str,
    db: &str,
    rules: Vec<ColumnRule>,
    unclassified: Unclassified,
    opaque: Opaque,
) -> Result<ProxyHandle> {
    let backend = backend.to_string();
    let config = Config {
        listen: "127.0.0.1:0".into(),
        backend: backend.clone(),
        catalog_dsn: backend_dsn(db),
        pseudonym_key: "test-key".into(),
        unclassified,
        opaque,
        unclassified_mask: Mask::Null,
        column: rules,
        semantic_type: Vec::new(),
        role: Vec::new(),
        tls_cert: None,
        tls_key: None,
        backend_tls: pgmask::tls::BackendTls::Disable,
        // Tight intervals so tests can observe a refresh without waiting.
        catalog_refresh_seconds: 1,
        catalog_refresh_min_seconds: 1,
        metrics_interval_seconds: 0,
    };
    let catalog = Arc::new(
        Catalog::resolve(&config.column, &config.semantic_type, &config.catalog_dsn).await?,
    );
    tokio::spawn(catalog.clone().run_refresher(
        std::time::Duration::from_secs(config.catalog_refresh_seconds),
        std::time::Duration::from_secs(config.catalog_refresh_min_seconds),
    ));
    let policy = Arc::new(Policy::from_config(&config, catalog)?);
    let metrics = policy.metrics.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
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
    Ok(ProxyHandle { addr, metrics })
}

// --- Raw wire client --------------------------------------------------------

pub struct RawClient {
    frames: FrameReader<tokio::net::tcp::OwnedReadHalf>,
    write: tokio::net::tcp::OwnedWriteHalf,
    /// Every byte the proxy has sent us. The canary assertion runs over this.
    pub received: Vec<u8>,
}

impl RawClient {
    /// Connect and complete startup. Requires `trust` auth on the backend, which
    /// `scripts/test-integration.sh` configures.
    pub async fn connect(addr: SocketAddr, db: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        let (read, write) = stream.into_split();
        let mut client = Self {
            frames: FrameReader::new(read),
            write,
            received: Vec::new(),
        };

        let mut body = BytesMut::new();
        for (k, v) in [("user", "postgres"), ("database", db)] {
            body.put_slice(k.as_bytes());
            body.put_u8(0);
            body.put_slice(v.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0);
        let startup = StartupPacket {
            code: 196608, // protocol 3.0
            body: body.freeze(),
        };
        client.write.write_all(&startup.encode()).await?;
        client.write.flush().await?;
        client.read_until_ready().await?;
        Ok(client)
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.write.write_all(bytes).await?;
        self.write.flush().await?;
        Ok(())
    }

    pub async fn send(&mut self, msg: Message) -> Result<()> {
        self.send_raw(&msg.encode()).await
    }

    /// Read messages until `ReadyForQuery`, recording every byte.
    pub async fn read_until_ready(&mut self) -> Result<Vec<Message>> {
        let mut out = Vec::new();
        loop {
            let Some(msg) = self.frames.read_message().await? else {
                bail!("connection closed before ReadyForQuery");
            };
            self.received.extend_from_slice(&msg.encode());
            let tag = msg.tag;
            out.push(msg);
            if tag == b'Z' {
                return Ok(out);
            }
        }
    }

    /// Like `read_until_ready` but tolerates the proxy hanging up, which is the
    /// correct response to some attacks.
    pub async fn read_until_ready_or_eof(&mut self) -> Result<Vec<Message>> {
        let mut out = Vec::new();
        loop {
            match self.frames.read_message().await {
                Ok(Some(msg)) => {
                    self.received.extend_from_slice(&msg.encode());
                    let tag = msg.tag;
                    out.push(msg);
                    if tag == b'Z' {
                        return Ok(out);
                    }
                }
                Ok(None) | Err(_) => return Ok(out),
            }
        }
    }

    pub async fn simple_query(&mut self, sql: &str) -> Result<Vec<Message>> {
        let mut body = BytesMut::new();
        body.put_slice(sql.as_bytes());
        body.put_u8(0);
        self.send(Message::new(b'Q', body.freeze())).await?;
        self.read_until_ready_or_eof().await
    }

    /// Everything received so far, as a lossy string for substring assertions.
    pub fn received_text(&self) -> String {
        String::from_utf8_lossy(&self.received).into_owned()
    }
}

// --- Extended-protocol message builders -------------------------------------

pub fn parse_msg(name: &str, sql: &str) -> Message {
    let mut body = BytesMut::new();
    body.put_slice(name.as_bytes());
    body.put_u8(0);
    body.put_slice(sql.as_bytes());
    body.put_u8(0);
    body.put_i16(0); // no parameter type hints
    Message::new(b'P', body.freeze())
}

pub fn bind_msg(portal: &str, statement: &str) -> Message {
    let mut body = BytesMut::new();
    body.put_slice(portal.as_bytes());
    body.put_u8(0);
    body.put_slice(statement.as_bytes());
    body.put_u8(0);
    body.put_i16(0); // no parameter format codes
    body.put_i16(0); // no parameters
    body.put_i16(0); // default result format (text)
    Message::new(b'B', body.freeze())
}

pub fn describe_statement(name: &str) -> Message {
    let mut body = BytesMut::new();
    body.put_u8(b'S');
    body.put_slice(name.as_bytes());
    body.put_u8(0);
    Message::new(b'D', body.freeze())
}

pub fn describe_portal(name: &str) -> Message {
    let mut body = BytesMut::new();
    body.put_u8(b'P');
    body.put_slice(name.as_bytes());
    body.put_u8(0);
    Message::new(b'D', body.freeze())
}

pub fn execute_msg(portal: &str, max_rows: i32) -> Message {
    let mut body = BytesMut::new();
    body.put_slice(portal.as_bytes());
    body.put_u8(0);
    body.put_i32(max_rows);
    Message::new(b'E', body.freeze())
}

pub fn sync_msg() -> Message {
    Message::new(b'S', Bytes::new())
}

/// The legacy `FunctionCall` message. No driver sends this; that is the point.
pub fn function_call_msg(oid: u32) -> Message {
    let mut body = BytesMut::new();
    body.put_u32(oid);
    body.put_i16(0); // argument format codes
    body.put_i16(0); // arguments
    body.put_i16(0); // result format
    Message::new(b'F', body.freeze())
}

// --- Assertions -------------------------------------------------------------

/// The assertion the whole suite exists for.
#[track_caller]
pub fn assert_no_canary(client: &RawClient, context: &str) {
    let text = client.received_text();
    for canary in CANARIES {
        assert!(
            !text.contains(canary),
            "LEAK via {context}: {canary} crossed the boundary\n\
             received {} bytes",
            client.received.len(),
        );
    }
}

/// Confirms the harness can actually detect a leak. A canary test that cannot
/// fail proves nothing, so one test deliberately runs wide open and asserts the
/// sentinel IS visible.
#[track_caller]
pub fn assert_canary_present(client: &RawClient, canary: &str) {
    assert!(
        client.received_text().contains(canary),
        "negative control failed: {canary} should have been visible with masking \
         disabled — the canary assertion is not actually detecting anything"
    );
}
