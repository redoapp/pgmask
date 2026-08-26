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
use pgmask::catalog::{
    ColumnRule, Config, JsonFieldRule, Lineage, MaskParams, Opaque, SystemCatalogs, Unclassified,
};
use pgmask::mask::{JsonUnmatched, Mask};
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

/// The Postgres address, or fail the test.
///
/// **This used to `return Ok(())`.** `test-all.sh` runs `cargo test` without
/// `PGMASK_TEST_PG` and does not run `scripts/test-integration.sh`, so all 58
/// tests behind this macro — every raw-wire adversarial test and every
/// resilience test, including `negative_control_the_harness_can_see_a_leak` —
/// reported PASS on every release gate having asserted nothing.
///
/// That is the same defect as the old `exit 0` when sqlsmith was missing,
/// which this repo diagnosed and fixed in `scripts/test-fuzz.sh` and then left
/// standing in the other release path. A suite that reports success by doing
/// nothing is the failure this project keeps finding.
///
/// `PGMASK_ALLOW_SKIP=1` opts out, for running `cargo test` on a machine with
/// no Postgres. **The gate sets it deliberately** for the workspace sweep and
/// then runs these suites for real, serially, as its own entry — two steps
/// with two different jobs. An earlier version of this comment claimed the
/// gate does not set it, which was wrong and briefly sent CI down the wrong
/// path: removing the flag ran all 41 concurrently against one backend and the
/// catalog loader failed with "could not open relation with OID 17545".
///
/// `--test-threads=1` is therefore load-bearing, not caution.
///
/// The count above is checked by `scripts/check-repo-invariants.sh`; it read
/// 31 for several releases after the suites grew to 41.
#[macro_export]
macro_rules! require_pg {
    () => {
        match $crate::support::backend_addr() {
            Some(addr) => addr,
            None if std::env::var("PGMASK_ALLOW_SKIP").is_ok() => {
                eprintln!("skipping by request: PGMASK_ALLOW_SKIP is set");
                return Ok(());
            }
            None => panic!(
                "PGMASK_TEST_PG is not set, so this test would assert nothing. \
                 Run ./scripts/test-integration.sh, or set PGMASK_ALLOW_SKIP=1 to skip."
            ),
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

CREATE TABLE canary.documents (
  id      int PRIMARY KEY,
  payload jsonb NOT NULL,
  legacy  json NOT NULL
);
INSERT INTO canary.documents VALUES (
  1,
  '{
    "profile":{"email":"CANARY_EMAIL_a1b2c3","name":"CANARY_NAME_d4e5f6"},
    "public":"Portland",
    "unknown":"CANARY_NOTE_97h8i9",
    "items":[
      {"token":"CANARY_TEMP_j0k1l2","city":"Denver"},
      {"token":"CANARY_TEMP_j0k1l2","city":"Seattle"}
    ],
    "numeric_object":{"0":{"token":"CANARY_TEMP_j0k1l2"}},
    "n": 99,
    "enabled": true
  }',
  '{
    "profile":{"email":"CANARY_EMAIL_a1b2c3","name":"CANARY_NAME_d4e5f6"},
    "public":"Portland",
    "unknown":"CANARY_NOTE_97h8i9"
  }'
);

CREATE VIEW canary.subject_view AS SELECT id, email, name, city FROM canary.subjects;
CREATE VIEW canary.documents_view AS SELECT id, payload, legacy FROM canary.documents;

CREATE FUNCTION canary.all_subjects() RETURNS SETOF canary.subjects AS $$
  SELECT * FROM canary.subjects;
$$ LANGUAGE sql STABLE;

CREATE FUNCTION canary.emails() RETURNS TABLE (email text) AS $$
  SELECT email FROM canary.subjects;
$$ LANGUAGE sql STABLE;

-- --- Relations that are not a plain table -----------------------------------
--
-- Four constructs that each break an assumption the plan binding makes, and
-- none of which had a fixture. Every one carries the same canary, so an escape
-- through any of them fails the sweep.

-- Declarative partitioning. A `RowDescription` for a query against the *parent*
-- carries the partition's table OID, so a catalog rule written against the
-- parent's name is looked up under a relation the operator never wrote down.
CREATE TABLE canary.events (
  id       int,
  email    text,
  occurred date
) PARTITION BY RANGE (occurred);
CREATE TABLE canary.events_2024 PARTITION OF canary.events
  FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
INSERT INTO canary.events VALUES (1, 'CANARY_EMAIL_a1b2c3', '2024-06-01');

-- Inheritance: the same question in the older spelling, and unlike a partition
-- a child can be queried on its own and carries columns of its own.
CREATE TABLE canary.people (id int, email text);
CREATE TABLE canary.staff (badge text) INHERITS (canary.people);
INSERT INTO canary.people VALUES (1, 'CANARY_EMAIL_a1b2c3');
INSERT INTO canary.staff VALUES (2, 'CANARY_EMAIL_a1b2c3', 'B-1');

-- A domain. The column's type OID is the domain's own, allocated at creation
-- time, not `text`'s — so every `is_text_family` test in the masker sees a type
-- it has never heard of.
CREATE DOMAIN canary.email_address AS text;
CREATE TABLE canary.contacts (id int, email canary.email_address);
INSERT INTO canary.contacts VALUES (1, 'CANARY_EMAIL_a1b2c3');

-- Uniqueness the loader may not see. The singleton-group guard refuses a
-- reducing aggregate whose grouping covers a unique key; a unique key it does
-- not know about is the direction that releases.
-- Numeric, because the disclosure is `sum(x) GROUP BY <unique key>`: one row
-- per group makes the sum the value. `max` cannot be used here — it can return
-- a stored value whatever the grouping, so it is refused unconditionally and a
-- probe built on it measures nothing.
-- `exprkey`, a name no other relation here has a unique key on. Unique keys are
-- unscoped, so calling this `label` made the partial index on a *different*
-- table supply the key and the expression-index fix went untested: reverting it
-- broke nothing.
CREATE TABLE canary.expr_unique (exprkey text, salary int);
CREATE UNIQUE INDEX expr_unique_lower ON canary.expr_unique ((lower(exprkey)));
INSERT INTO canary.expr_unique VALUES ('a', 987654321), ('b', 123456789);

CREATE TABLE canary.partial_unique (label text, salary int);
CREATE UNIQUE INDEX partial_unique_label ON canary.partial_unique (label)
  WHERE label IS NOT NULL;
INSERT INTO canary.partial_unique VALUES ('a', 987654321), ('b', 123456789);

-- A PRIMARY KEY, which is the ordinary case and the one that broke. Postgres
-- records a constraint-backed index's columns only through `pg_constraint`, so
-- a loader reading `pg_depend` alone sees nothing here at all.
CREATE TABLE canary.pk_unique (pkid int PRIMARY KEY, salary int);
INSERT INTO canary.pk_unique VALUES (1, 987654321), (2, 123456789);

-- A UNIQUE constraint, the other constraint-backed shape.
CREATE TABLE canary.uc_unique (ucid int UNIQUE, salary int);
INSERT INTO canary.uc_unique VALUES (1, 987654321), (2, 123456789);

-- The comparison: same shape, no unique key at all, two rows per group. A sum
-- here is a real aggregate and is released, which is what makes the refusals
-- above mean something.
--
-- The grouping column is `bucketname`, not `label`, and that matters. Unique
-- keys are held as a flat list of column-name sets with no relation attached —
-- deliberately, because `group_by_columns` yields bare names and resolving each
-- to a relation is exactly the provenance work the analysis refuses to guess
-- at. So a key on *any* table makes a grouping by that name refuse everywhere.
-- Naming this column `label` made the control refuse and would have made the
-- whole probe read as a fix when it was a blanket.
CREATE TABLE canary.no_unique (bucketname text, salary int, secret_flag boolean);
INSERT INTO canary.no_unique VALUES
  ('a', 987654321, true),
  ('a', 123456789, false);

-- A generated column: a second copy of a classified value under a name the
-- operator has to have thought of separately.
CREATE TABLE canary.derived (
  id         int,
  email      text,
  email_copy text GENERATED ALWAYS AS (email || '') STORED
);
INSERT INTO canary.derived (id, email) VALUES (1, 'CANARY_EMAIL_a1b2c3');
"#;

/// Apply the canary schema. Uses tokio-postgres for convenience; the raw client
/// is only for driving the proxy.
/// Run DDL/DML straight at the backend, bypassing the proxy — for tests that
/// need to reshape a table underneath a running proxy.
pub async fn exec_direct(db: &str, sql: &str) -> Result<()> {
    let (client, connection) =
        tokio_postgres::connect(&backend_dsn(db), tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client.batch_execute(sql).await?;
    Ok(())
}

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
        // Written against the parent, which is what an operator would write.
        // Whether the proxy ever consults them for a partitioned read is the
        // question `relations_that_are_not_plain_tables_stay_masked` asks.
        rule("canary.events", "id", Mask::None),
        rule("canary.events", "email", Mask::Pseudonym),
        rule("canary.people", "id", Mask::None),
        rule("canary.people", "email", Mask::Pseudonym),
        rule("canary.contacts", "id", Mask::None),
        rule("canary.contacts", "email", Mask::Pseudonym),
        rule("canary.expr_unique", "exprkey", Mask::None),
        bucket_rule("canary.expr_unique", "salary", 1000),
        rule("canary.partial_unique", "label", Mask::None),
        bucket_rule("canary.partial_unique", "salary", 1000),
        rule("canary.pk_unique", "pkid", Mask::None),
        bucket_rule("canary.pk_unique", "salary", 1000),
        rule("canary.uc_unique", "ucid", Mask::None),
        bucket_rule("canary.uc_unique", "salary", 1000),
        rule("canary.no_unique", "bucketname", Mask::None),
        bucket_rule("canary.no_unique", "salary", 1000),
        rule("canary.no_unique", "secret_flag", Mask::Null),
        rule("canary.derived", "id", Mask::None),
        rule("canary.derived", "email", Mask::Pseudonym),
        // canary.derived.email_copy is deliberately unclassified: a generated
        // column is a copy of a classified value under a name of its own, and
        // default-deny is the only thing standing between the two.
    ]
}

/// A `numeric-bucket` rule with a real bucket.
///
/// The catalog refuses `bucket = 1` — it floors every value to itself and masks
/// nothing — so the default `params` cannot express this mask at all.
pub fn bucket_rule(relation: &str, column: &str, bucket: i64) -> ColumnRule {
    let mut r = rule(relation, column, Mask::NumericBucket);
    r.params.bucket = Some(bucket);
    r
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

pub fn json_field(pointer: &str, mask: Mask) -> JsonFieldRule {
    JsonFieldRule {
        pointer: pointer.into(),
        mask,
        params: MaskParams::default(),
    }
}

pub fn json_rule(
    relation: &str,
    column: &str,
    unmatched: JsonUnmatched,
    fields: Vec<JsonFieldRule>,
) -> ColumnRule {
    let mut rule = rule(relation, column, Mask::Json);
    rule.params.json_unmatched = Some(unmatched);
    rule.params.json = Some(fields);
    rule
}

// --- In-process proxy -------------------------------------------------------

pub struct ProxyHandle {
    pub addr: SocketAddr,
    pub metrics: Arc<pgmask::metrics::Metrics>,
}

struct TestPolicy {
    unclassified: Unclassified,
    opaque: Opaque,
    roles: Vec<pgmask::catalog::Role>,
    lineage: Lineage,
    posture: pgmask::catalog::Posture,
}

impl Default for TestPolicy {
    fn default() -> Self {
        Self {
            unclassified: Unclassified::Mask,
            opaque: Opaque::Reject,
            roles: Vec::new(),
            lineage: Lineage::Refuse,
            posture: pgmask::catalog::Posture::Default,
        }
    }
}

/// A proxy where the connecting principal *is* a member of `role`.
///
/// The other half of a role test: without it, "the value did not come through"
/// is equally consistent with the role's mask never releasing anything.
pub async fn start_proxy_as_member(db: &str, role: &str) -> Result<ProxyHandle> {
    let mut rules = default_rules();
    for r in &mut rules {
        if r.relation == "canary.subjects" && r.column == "email" {
            r.by_role.insert(role.into(), Mask::None);
        }
    }
    start_proxy_with_roles(
        db,
        rules,
        vec![pgmask::catalog::Role {
            name: role.into(),
            members: vec!["postgres".into()],
        }],
    )
    .await
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

pub async fn start_proxy_with_roles(
    db: &str,
    rules: Vec<ColumnRule>,
    roles: Vec<pgmask::catalog::Role>,
) -> Result<ProxyHandle> {
    let backend = backend_addr().context("PGMASK_TEST_PG")?;
    start_proxy_at_full(
        &backend,
        db,
        rules,
        TestPolicy {
            roles,
            ..Default::default()
        },
    )
    .await
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
    start_proxy_at_full(
        backend,
        db,
        rules,
        TestPolicy {
            unclassified,
            opaque,
            ..Default::default()
        },
    )
    .await
}

/// Same as [`start_proxy`], but with lineage inverted — the posture the GUI
/// catalog ships, and the only one where a missed source is a release.
pub async fn start_proxy_allowing_lineage(db: &str, rules: Vec<ColumnRule>) -> Result<ProxyHandle> {
    let backend = backend_addr().context("PGMASK_TEST_PG")?;
    start_proxy_at_full(
        &backend,
        db,
        rules,
        TestPolicy {
            lineage: Lineage::Allow,
            ..Default::default()
        },
    )
    .await
}

pub async fn start_proxy_hostile(db: &str, rules: Vec<ColumnRule>) -> Result<ProxyHandle> {
    let backend = backend_addr().context("PGMASK_TEST_PG")?;
    start_proxy_at_full(
        &backend,
        db,
        rules,
        TestPolicy {
            posture: pgmask::catalog::Posture::Hostile,
            ..Default::default()
        },
    )
    .await
}

async fn start_proxy_at_full(
    backend: &str,
    db: &str,
    rules: Vec<ColumnRule>,
    policy: TestPolicy,
) -> Result<ProxyHandle> {
    let backend = backend.to_string();
    let config = Config {
        listen: "127.0.0.1:0".into(),
        backend: backend.clone(),
        catalog_dsn: backend_dsn(db),
        pseudonym_key: "test-key-long-enough".into(),
        unclassified: policy.unclassified,
        unclassified_mask: Default::default(),
        opaque: policy.opaque,
        column: rules,
        semantic_type: Vec::new(),
        role: policy.roles,
        tls_cert: None,
        tls_key: None,
        // No certificate, so nothing to require: these harnesses drive a raw
        // wire client in plaintext and must keep working unchanged.
        require_client_tls: None,
        backend_tls: pgmask::tls::BackendTls::Disable,
        backend_ca: None,
        // Tight intervals so tests can observe a refresh without waiting.
        catalog_refresh_seconds: 1,
        catalog_refresh_min_seconds: 1,
        metrics_interval_seconds: 0,
        summaries: pgmask::catalog::Summaries::Allow,
        posture: policy.posture,
        system_catalogs: SystemCatalogs::Refuse,
        lineage: policy.lineage,
        metrics_listen: None,
        rate_limit_per_minute: 0,
        rate_limit_burst: 0,
        max_notices_per_exchange: 0,
    };
    let catalog = Arc::new(
        Catalog::resolve(&config.column, &config.semantic_type, &config.catalog_dsn).await?,
    );
    tokio::spawn(catalog.clone().run_refresher(
        std::time::Duration::from_secs(config.catalog_refresh_seconds),
        std::time::Duration::from_secs(config.catalog_refresh_min_seconds),
    ));
    let policy = Arc::new(Policy::from_config(&config, catalog)?);
    let metrics = policy.metrics();

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

#[derive(Clone, Copy)]
pub enum SqlExpectation {
    Served,
    Refused,
    /// Served or refused, never silent. Use when either outcome is policy, but
    /// a no-canary check would pass if the statement was never exercised.
    Exercised,
}

pub struct SqlCase<'a> {
    pub name: &'a str,
    pub sql: &'a str,
    pub expectation: SqlExpectation,
}

impl<'a> SqlCase<'a> {
    pub const fn served(name: &'a str, sql: &'a str) -> Self {
        Self {
            name,
            sql,
            expectation: SqlExpectation::Served,
        }
    }

    pub const fn refused(name: &'a str, sql: &'a str) -> Self {
        Self {
            name,
            sql,
            expectation: SqlExpectation::Refused,
        }
    }

    pub const fn exercised(name: &'a str, sql: &'a str) -> Self {
        Self {
            name,
            sql,
            expectation: SqlExpectation::Exercised,
        }
    }
}

/// One simple-query round-trip and the bytes received during it.
pub struct QueryRound {
    pub messages: Vec<Message>,
    pub received: Vec<u8>,
}

impl QueryRound {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.received).into_owned()
    }
}

/// Run a simple query and return only the bytes this round added.
pub async fn simple_query_round(client: &mut RawClient, sql: &str) -> Result<QueryRound> {
    let received_before = client.received.len();
    let messages = client.simple_query(sql).await?;
    let received = client
        .received
        .get(received_before..)
        .context("raw client receive buffer shrank during simple query")?
        .to_vec();
    Ok(QueryRound { messages, received })
}

/// Run related SQL shapes through one proxy while keeping each failure local.
///
/// Starting a proxy per row makes the already-serial live-Postgres suite much
/// slower and introduces more catalog-refresh races. The client still retains
/// every byte for the connection-wide canary audit; each row's assertions use
/// only the bytes received during that query, so a failure does not dump all
/// preceding responses or mistake an earlier refusal for this row's outcome.
pub async fn assert_sql_cases(client: &mut RawClient, cases: &[SqlCase<'_>]) -> Result<()> {
    for case in cases {
        let round = simple_query_round(client, case.sql)
            .await
            .with_context(|| format!("SQL matrix case {:?}: {}", case.name, case.sql))?;
        let context = format!("{} ({})", case.name, case.sql);

        match case.expectation {
            SqlExpectation::Served => assert_served(&round.messages, &context),
            SqlExpectation::Refused => assert_refused_bytes(&round.received, &context),
            SqlExpectation::Exercised => {
                assert_exercised_bytes(&round.messages, &round.received, &context);
            }
        }
        assert_no_canary_bytes(&round.received, &context);
    }
    Ok(())
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

/// A Bind that asks for one result format for every column — `1` is how JDBC
/// and tokio-postgres request binary transfer.
pub fn bind_msg_with_result_format(portal: &str, statement: &str, format: i16) -> Message {
    let mut body = BytesMut::new();
    body.put_slice(portal.as_bytes());
    body.put_u8(0);
    body.put_slice(statement.as_bytes());
    body.put_u8(0);
    body.put_i16(0); // no parameter format codes
    body.put_i16(0); // no parameters
    body.put_i16(1); // one result-format code, applied to all columns
    body.put_i16(format);
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

pub fn close_statement(name: &str) -> Message {
    let mut body = BytesMut::new();
    body.put_u8(b'S');
    body.put_slice(name.as_bytes());
    body.put_u8(0);
    Message::new(b'C', body.freeze())
}

pub fn close_portal(name: &str) -> Message {
    let mut body = BytesMut::new();
    body.put_u8(b'P');
    body.put_slice(name.as_bytes());
    body.put_u8(0);
    Message::new(b'C', body.freeze())
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
/// A statement was actually *exercised* — the proxy either served rows or
/// refused it with a `pgmask:` message — rather than silently doing nothing.
///
/// This is the guard against vacuous masking tests. `assert_no_canary` alone
/// passes whether the query was served-and-masked, refused, or dropped on the
/// floor — an error carries no canary. Pairing it with this turns "no canary
/// crossed" into "the proxy handled this statement and no canary crossed".
pub fn assert_exercised(msgs: &[Message], client: &RawClient, context: &str) {
    assert_exercised_bytes(msgs, &client.received, context);
}

#[track_caller]
fn assert_exercised_bytes(msgs: &[Message], received: &[u8], context: &str) {
    let served = msgs.iter().any(|m| m.tag == b'D');
    let refused = String::from_utf8_lossy(received).contains("pgmask:");
    assert!(
        served || refused,
        "{context}: the proxy neither served a row nor refused with a pgmask \
         message — the statement was not exercised, so a clean canary check \
         asserts nothing"
    );
}

/// The proxy served data rows: a masking test that must SUCCEED, not be refused.
/// A refusal carries no canary, so without this a "stays masked" test passes
/// even when the path stopped running.
#[track_caller]
pub fn assert_served(msgs: &[Message], context: &str) {
    assert!(
        msgs.iter().any(|m| m.tag == b'D'),
        "{context}: expected the query to be served (data rows), but none arrived"
    );
}

/// The proxy refused the statement with its own message. A "cannot leak by
/// refusal" test that only checks for a canary passes if the refusal quietly
/// stops happening; this pins that the refusal is what closed the path.
#[track_caller]
pub fn assert_refused(client: &RawClient, context: &str) {
    assert_refused_bytes(&client.received, context);
}

#[track_caller]
fn assert_refused_bytes(received: &[u8], context: &str) {
    let text = String::from_utf8_lossy(received);
    assert!(
        text.contains("pgmask:"),
        "{context}: expected a pgmask refusal, got:\n{text}"
    );
}

#[track_caller]
pub fn assert_no_canary(client: &RawClient, context: &str) {
    assert_no_canary_bytes(&client.received, context);
}

#[track_caller]
pub fn assert_no_canary_bytes(received: &[u8], context: &str) {
    let text = String::from_utf8_lossy(received);
    for canary in CANARIES {
        assert!(
            !text.contains(canary),
            "LEAK via {context}: {canary} crossed the boundary\n\
             received {} bytes",
            received.len(),
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
