//! Configuration and the column classification catalog.
//!
//! The catalog is keyed on `(pg_class OID, attnum)` because that is what the
//! wire gives us — never on output column name, which any query can rename.
//!
//! Names are resolved to OIDs at startup and **re-resolved periodically**,
//! because OIDs are not stable across DDL. `CREATE OR REPLACE VIEW` keeps a
//! relation's OID but `DROP VIEW; CREATE VIEW` does not, and plenty of migration
//! tooling does the latter. A catalog pinned at boot silently loses coverage the
//! first time that happens: with `unclassified = "mask"` the columns quietly use
//! the type-aware fallback, and with `unclassified = "allow"` they quietly stop
//! being masked.

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::Notify;

use crate::mask::{Mask, MaskSpec};

/// Whether summarising aggregates over classified columns may be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Summaries {
    /// `sum`/`avg`/`count` are released. They cannot return a stored value.
    Allow,
    /// Refuse them too. Strictly safer, and refuses most analytical SQL.
    Refuse,
}

/// Who the deployment is protecting against.
///
/// `Default` is the historical threat model: masked values do not appear in
/// projections; filters, ordering and single-row aggregates remain usable as
/// oracles. `Hostile` closes those routes at the cost of most analytical SQL
/// and any predicate on a masked column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    /// Analyst who is not attacking you.
    #[default]
    Default,
    /// Client who will try. Forces `summaries = "refuse"` and refuses any
    /// statement where a masked column appears outside a bare outermost
    /// SELECT-list `ColumnRef`, after crediting `ORDER BY` mentions
    /// (`WHERE email …`, `sum(salary)`, and the error-channel CASE refuse;
    /// cleartext sort order of masked values is accepted).
    Hostile,
}

/// Whether to trace expressions back to their base columns before refusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lineage {
    /// Release an expression when every base column it derives from is
    /// explicitly released. Converts about a third of refusals on analytical
    /// SQL; see docs/lineage-estimate.md.
    Allow,
    /// Refuse anything without provenance, whatever it derives from. The safe
    /// default: lineage is the one rule here where missing something is a
    /// disclosure rather than a lost query.
    Refuse,
}

/// Whether to serve queries that read only `pg_catalog` / `information_schema`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemCatalogs {
    /// Serve them unmasked. Required for GUI clients and psql's `\d`, which
    /// cannot list a table without reading the catalog. Only statements whose
    /// every relation is an explicitly qualified, metadata-only catalog
    /// qualify, plus `SHOW`; see `analysis::reads_only_server_metadata`.
    Allow,
    /// Refuse them, like any other unclassified relation. The safe default, and
    /// it means no GUI client will connect.
    Refuse,
}

/// What to do with a field that HAS provenance but no catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unclassified {
    /// Default-deny. An undeclared column is sensitive until someone says otherwise.
    Mask,
    /// Incremental-rollout escape hatch. Loud in the logs for a reason.
    Allow,
}

/// *Which* mask `unclassified = "mask"` applies.
///
/// The type-aware default keeps unclassified data usable — stable pseudonyms
/// for text and UUID, year-only dates, network-prefix IPs — but pseudonyms
/// preserve equality and frequency, and a client who can also filter on the
/// cleartext (`WHERE col = '…'` runs on the backend) can decode a
/// low-cardinality column's handles in a handful of queries. `posture =
/// "hostile"` closes that predicate route; `unclassified_mask = "null"` opts
/// out of the disclosure entirely, restoring the strict pre-0.1.92 default of
/// NULL for every unclassified value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UnclassifiedMask {
    /// Pseudonyms, coarse dates and IP prefixes chosen per wire type; NULL for
    /// everything else. See `MaskSpec::for_unclassified`.
    #[default]
    TypeAware,
    /// Strict NULL for every unclassified value, whatever its type.
    Null,
}

/// What to do with a result set containing a field with NO provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Opaque {
    /// Refuse the result set. The caller can rewrite to select the column directly.
    Reject,
    /// Null the field and pass the rest.
    Mask,
}

/// Parameters shared by column rules and semantic types.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaskParams {
    /// Characters kept by `partial` / `inner` / `outer`.
    pub keep: Option<u16>,
    /// Bounds for `range`.
    pub start: Option<u16>,
    pub end: Option<u16>,
    /// Bucket size for `numeric-bucket`. Must be >= 2.
    pub bucket: Option<i64>,
    /// Keep an email's domain rather than pseudonymising it. Off by default.
    pub keep_domain: Option<bool>,
    /// Pseudonym domain. Columns sharing a domain stay joinable; columns in
    /// different domains cannot be linked by comparing masked values. Defaults
    /// to the semantic type's name.
    pub domain: Option<String>,
}

impl MaskParams {
    fn apply_to(&self, spec: &mut MaskSpec) {
        if let Some(v) = self.keep {
            spec.keep = v;
        }
        if let Some(v) = self.start {
            spec.start = v;
        }
        if let Some(v) = self.end {
            spec.end = v;
        }
        if let Some(v) = self.bucket {
            spec.bucket = v;
        }
        if let Some(v) = self.keep_domain {
            spec.keep_domain = v;
        }
        if let Some(v) = &self.domain {
            spec.domain = Some(v.as_str().into());
        }
    }
}

/// A named classification with a default mask, so `email` is described once and
/// referenced everywhere. Borrowed from Bytebase's semantic types, and the thing
/// that keeps a real catalog from being thousands of hand-written rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticType {
    pub name: String,
    pub mask: Mask,
    #[serde(flatten)]
    pub params: MaskParams,
    /// Per-role overrides, e.g. `{ analyst = "partial", oncall = "none" }`.
    #[serde(default)]
    pub by_role: HashMap<String, Mask>,
}

/// Maps principals to roles. The principal is the username Postgres verified
/// during authentication, never one the client merely claimed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub name: String,
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnRule {
    /// Schema-qualified, e.g. `demo.customers`.
    pub relation: String,
    pub column: String,
    /// Name of a `[[semantic_type]]`. Supplies the mask unless `mask` overrides.
    #[serde(rename = "type", default)]
    pub semantic_type: Option<String>,
    /// Overrides the semantic type's mask.
    #[serde(default)]
    pub mask: Option<Mask>,
    #[serde(flatten)]
    pub params: MaskParams,
    #[serde(default)]
    pub by_role: HashMap<String, Mask>,
}

impl ColumnRule {
    fn key(&self) -> (String, String) {
        (self.relation.clone(), self.column.clone())
    }

    fn display(&self) -> String {
        format!("{}.{}", self.relation, self.column)
    }
}

/// Everything needed to mask one classified column, per role.
#[derive(Debug, Clone)]
pub struct Classification {
    /// Applied when the principal holds none of the roles below.
    pub default: MaskSpec,
    /// Role name -> mask. Most restrictive wins when a principal holds several.
    pub by_role: HashMap<String, MaskSpec>,
}

impl Classification {
    /// Resolve for a principal's roles.
    ///
    /// **Most restrictive wins.** A principal in both `analyst` and `support`
    /// gets the tighter of the two, because the alternative — widening access by
    /// adding a role — is the kind of surprise a security control must not have.
    pub fn for_roles(&self, roles: &HashSet<String>) -> &MaskSpec {
        // Sorted, because `roles` is a `HashSet` and the iteration order is
        // randomised per instance. Two roles whose masks rank equally —
        // `partial` and `outer` both rank 2 — used to resolve to whichever was
        // seen first, so the same principal running the same query could get a
        // different masking on the next connection.
        //
        // Ranking still ignores mask *parameters*; `by_role` carries only the
        // kind, so two roles sharing a kind share a spec and there is nothing
        // to choose between. Where the kinds differ but rank equally, the
        // lexicographically first role wins — arbitrary, but the same every
        // time, which is what a security control owes its operator.
        let mut matching: Vec<&String> = roles.iter().collect();
        matching.sort();
        let mut chosen: Option<&MaskSpec> = None;
        for role in matching {
            if let Some(spec) = self.by_role.get(role) {
                chosen = Some(match chosen {
                    Some(current)
                        if restrictiveness(current.kind) >= restrictiveness(spec.kind) =>
                    {
                        current
                    }
                    _ => spec,
                });
            }
        }
        chosen.unwrap_or(&self.default)
    }
}

/// How much a mask withholds. Used only to break ties between a principal's
/// roles; higher means less is revealed.
fn restrictiveness(mask: Mask) -> u8 {
    match mask {
        Mask::None => 0,
        // Reveals everything it did not recognise, so it is barely more
        // restrictive than passing the value through. Ranked here deliberately:
        // if one of a principal's roles says `scrub` and another says `redact`,
        // redact has to win.
        Mask::Scrub => 1,
        Mask::Partial | Mask::Inner | Mask::Outer | Mask::Range => 2,
        Mask::DateMonth | Mask::IpPrefix | Mask::NumericBucket => 3,
        Mask::DateYear => 4,
        Mask::Pseudonym => 5,
        Mask::Hash => 6,
        Mask::Redact => 7,
        Mask::Null => 8,
    }
}

/// `deny_unknown_fields` is a security control, not tidiness. TOML puts any key
/// written after a `[[column]]` block *inside* that block, so an appended
/// `tls_cert` silently became a ColumnRule field and the proxy came up in
/// plaintext with no complaint. Found while writing the TLS test.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// `host:port` of the Postgres we front.
    pub backend: String,
    /// Used to resolve names to OIDs, at startup and on every refresh.
    pub catalog_dsn: String,
    /// HMAC key for pseudonyms. Rotating it invalidates every emitted pseudonym.
    /// Wrapped so it cannot be printed.
    ///
    /// `Config` derives `Debug` — for tests and for a config-dump that has been
    /// wanted more than once — and the key is what makes pseudonyms unlinkable.
    /// One `{config:?}` in a log line or a panic message would put it on disk,
    /// and recovering costs a rotation, which invalidates every pseudonym ever
    /// issued. `SecretString` prints as `[REDACTED]` and zeroizes on drop.
    pub pseudonym_key: SecretString,
    #[serde(default = "default_unclassified")]
    pub unclassified: Unclassified,
    /// Which mask `unclassified = "mask"` applies: `type-aware` (default) or
    /// strict `null`. Ignored under `unclassified = "allow"`.
    #[serde(default)]
    pub unclassified_mask: UnclassifiedMask,
    #[serde(default = "default_opaque")]
    pub opaque: Opaque,
    #[serde(default)]
    pub column: Vec<ColumnRule>,
    #[serde(default)]
    pub semantic_type: Vec<SemanticType>,
    #[serde(default)]
    pub role: Vec<Role>,
    /// PEM certificate chain served to clients. Requires `tls_key`.
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    /// Whether a client that has not negotiated TLS is refused.
    ///
    /// Unset means *yes whenever `tls_cert` is set*, because configuring a
    /// certificate and not requiring it is the shape of a mistake, not of a
    /// decision. Postgres has no ALPN and no TLS port: a client simply omits
    /// the `SSLRequest` packet (`sslmode=disable`) and gets a working
    /// plaintext session. Nothing about that is visible in the startup log,
    /// which reports the *configuration*.
    ///
    /// Masked output is not public output. Partial masks are partial by
    /// design — the last four digits of a card, a pseudonym that is a stable
    /// identifier across queries — and the SCRAM exchange and the client's own
    /// SQL cross the same wire. Set this to `false` to allow plaintext
    /// deliberately; those sessions are then counted under
    /// `plaintext_session`, not silent.
    #[serde(default)]
    pub require_client_tls: Option<bool>,
    /// Whether to encrypt the proxy-to-Postgres leg.
    #[serde(default)]
    pub backend_tls: crate::tls::BackendTls,
    /// Extra CA PEMs trusted when `backend_tls = "verify-full"`.
    ///
    /// Unset means the webpki public roots only. Private or self-signed
    /// backends need this file.
    #[serde(default)]
    pub backend_ca: Option<String>,
    /// How often to re-resolve the catalog against `pg_class`.
    #[serde(default = "default_refresh_seconds")]
    pub catalog_refresh_seconds: u64,
    /// Floor on refreshes triggered by seeing an unknown relation, so a stream
    /// of unclassified tables cannot turn into a query storm.
    #[serde(default = "default_refresh_min_seconds")]
    pub catalog_refresh_min_seconds: u64,
    /// How often to log rejection counters. 0 disables.
    #[serde(default = "default_metrics_seconds")]
    pub metrics_interval_seconds: u64,
    /// Release aggregates that only summarise — `sum`, `avg`, `count(col)` —
    /// over classified columns.
    ///
    /// The bar this encodes is "you cannot read an anonymised value", not "no
    /// information flows". A group of one row makes `sum(salary)` that person's
    /// salary; that is the same accepted trade as the predicate oracles in
    /// handoff §11. Set to `refuse` for the stricter reading, at the cost of
    /// roughly 90% of analytical SQL. `posture = "hostile"` forces refuse.
    #[serde(default = "default_summaries")]
    pub summaries: Summaries,
    /// Opt into containing an adversarial client. See [`Posture`].
    #[serde(default)]
    pub posture: Posture,
    /// Off by default: turning it on is a deliberate decision to release
    /// engine metadata, and it is what makes DBeaver and `\d` work.
    #[serde(default = "default_system_catalogs")]
    pub system_catalogs: SystemCatalogs,
    /// Off by default. Turning it on trades a sound-by-construction rule for
    /// one that depends on a resolver being complete.
    #[serde(default = "default_lineage")]
    pub lineage: Lineage,
    /// `host:port` to serve Prometheus metrics on, e.g. `"127.0.0.1:9464"`.
    ///
    /// Absent means no endpoint is opened. Deliberately not defaulted to a
    /// port: this process sits in front of sensitive data, and it should not
    /// start listening on anything the operator did not ask for.
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// Statements per authenticated principal per minute. `0` disables
    /// (default). Charged on `Query` and `Execute` — the notice-channel
    /// oracle under `posture = "hostile"` is a few hundred `DO` blocks, and
    /// this is what makes that campaign expensive without a PL/pgSQL
    /// interpreter. Shared across connections for the same username.
    #[serde(default)]
    pub rate_limit_per_minute: u32,
    /// Burst size when rate limiting is on. `0` means "same as
    /// `rate_limit_per_minute`". Ignored when rate limiting is off.
    #[serde(default)]
    pub rate_limit_burst: u32,
    /// Cap on `NoticeResponse` messages (NOTICE/INFO/WARNING/…) forwarded
    /// between `ReadyForQuery` markers. `0` disables (default).
    ///
    /// Rate limits charge one token per `Query`/`Execute`, so a single `DO`
    /// block can still encode a full masked value as hundreds of notices.
    /// This cap is the blunt instrument for that channel: drop excess notices
    /// for the rest of the exchange and count `notice_flood`.
    #[serde(default)]
    pub max_notices_per_exchange: u32,
}

fn default_listen() -> String {
    "127.0.0.1:6432".into()
}
fn default_unclassified() -> Unclassified {
    Unclassified::Mask
}
fn default_opaque() -> Opaque {
    Opaque::Reject
}
fn default_refresh_seconds() -> u64 {
    30
}
fn default_refresh_min_seconds() -> u64 {
    5
}
fn default_metrics_seconds() -> u64 {
    60
}
fn default_lineage() -> Lineage {
    Lineage::Refuse
}

fn default_system_catalogs() -> SystemCatalogs {
    SystemCatalogs::Refuse
}

fn default_summaries() -> Summaries {
    Summaries::Allow
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        let config: Self = toml::from_str(&text).with_context(|| format!("parsing {path}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Whole-config checks that a per-field deserialiser cannot make.
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_client_tls()?;
        self.validate_backend_tls()?;
        self.validate_pseudonym_key()?;
        self.validate_unique_column_rules()?;
        self.validate_rate_limit()
    }

    /// A positive per-minute budget with a zero burst is a config that cannot
    /// admit a single statement. Prefer the explicit default (burst equals
    /// per-minute) over letting `governor` refuse construction with a less
    /// readable error.
    fn validate_rate_limit(&self) -> Result<()> {
        if self.rate_limit_per_minute > 0 && self.rate_limit_burst == 0 {
            // Resolved at Policy construction via `effective_rate_limit_burst`.
            return Ok(());
        }
        if self.rate_limit_per_minute == 0 && self.rate_limit_burst > 0 {
            bail!(
                "rate_limit_burst is set but rate_limit_per_minute is 0; burst \
                 only applies when rate limiting is enabled. Set \
                 rate_limit_per_minute, or drop rate_limit_burst."
            );
        }
        Ok(())
    }

    /// Burst used when constructing the limiter. `0` collapses to the
    /// per-minute budget so a single knob is enough.
    pub fn effective_rate_limit_burst(&self) -> u32 {
        if self.rate_limit_burst == 0 {
            self.rate_limit_per_minute
        } else {
            self.rate_limit_burst
        }
    }

    /// `backend_ca` without `verify-full` is a config that does nothing, which
    /// is how operators come to believe they are verifying when they are not.
    fn validate_backend_tls(&self) -> Result<()> {
        if self.backend_ca.is_some()
            && !matches!(self.backend_tls, crate::tls::BackendTls::VerifyFull)
        {
            bail!(
                "backend_ca is set but backend_tls is {:?}; the CA file is only \
                 consulted for verify-full. Set backend_tls = \"verify-full\", or \
                 remove backend_ca.",
                self.backend_tls
            );
        }
        Ok(())
    }

    /// Summaries policy after posture is applied.
    pub fn effective_summaries(&self) -> Summaries {
        if self.posture == Posture::Hostile {
            Summaries::Refuse
        } else {
            self.summaries
        }
    }

    pub fn is_hostile(&self) -> bool {
        self.posture == Posture::Hostile
    }

    /// `require_client_tls = true` with no certificate refuses every
    /// connection, which is fail-closed but useless, and reads at a glance as
    /// the strictest setting rather than the broken one. Refuse it at load.
    fn validate_client_tls(&self) -> Result<()> {
        if self.require_client_tls == Some(true) && self.tls_cert.is_none() {
            bail!(
                "require_client_tls = true but no tls_cert is set, so no client could \
                 ever negotiate TLS and every connection would be refused. Set \
                 tls_cert/tls_key, or drop require_client_tls."
            );
        }
        Ok(())
    }

    /// Whether a session that never negotiated TLS should be refused.
    ///
    /// Defaults to "yes if a certificate is configured": see the field.
    pub fn client_tls_required(&self) -> bool {
        self.require_client_tls.unwrap_or(self.tls_cert.is_some())
    }

    /// Checks that apply regardless of how undeclared columns are handled.
    fn validate_pseudonym_key(&self) -> Result<()> {
        // An empty key makes every pseudonym a publicly recomputable
        // HMAC-SHA256 with a zero key: anyone holding the masked output can
        // invert the whole domain by dictionary. `hmac` accepts any key length,
        // so nothing else was going to catch this.
        let key_len = self.pseudonym_key.expose_secret().len();
        if key_len < 16 {
            bail!(
                "pseudonym_key must be at least 16 bytes, got {key_len}. Pseudonyms are \
                 keyed HMAC-SHA256; a short or empty key lets anyone holding the masked \
                 output recompute the whole domain."
            );
        }
        Ok(())
    }

    fn validate_unique_column_rules(&self) -> Result<()> {
        // Two rules for one column both land in the same `(oid, attnum)` and
        // `(relation, column)` keys, so the file order decides — and the second
        // one silently wins even when it is the more permissive. Nothing warned.
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for rule in &self.column {
            let key = (
                rule.relation.to_ascii_lowercase(),
                rule.column.to_ascii_lowercase(),
            );
            if !seen.insert(key) {
                bail!(
                    "duplicate rule for {}.{}. Two rules for one column resolve by file \
                     order, so the later one silently overrides — including when it is the \
                     more permissive of the two.",
                    rule.relation,
                    rule.column
                );
            }
        }
        Ok(())
    }
}

/// One consistent view of the classification, swapped atomically on refresh.
#[derive(Debug, Default)]
pub struct Snapshot {
    by_column: HashMap<(u32, i16), Classification>,
    /// `schema.relation.column` display names of the **classified** columns —
    /// exactly one entry per resolved rule, spelled as the rule wrote it.
    /// Backs refresh-diff logging and rejection bucketing; kept separate from
    /// `all_columns` so neither reader silently changes meaning when the other
    /// map grows.
    names: HashMap<(u32, i16), String>,
    /// Stable `schema.relation.column` identity for **every** live user column,
    /// classified or not, spelled the way `pg_attribute` reports it. The
    /// type-aware fallback keys unclassified pseudonym domains on it, so the
    /// domains survive OID churn and do not depend on client-chosen aliases.
    all_columns: HashMap<(u32, i16), String>,
    /// Whether each live user column is effectively NOT NULL, either directly
    /// or through any domain in its type chain. Kept separately from names
    /// because a missing entry means the catalog has not resolved the column,
    /// while `false` means it positively resolved as nullable.
    column_not_null: HashMap<(u32, i16), bool>,
    /// Relation OIDs we know about, so an unknown one can be told apart from a
    /// relation we resolved whose column is merely unclassified.
    relations: HashSet<u32>,
    /// Rules that failed to resolve on the most recent attempt.
    unresolved: Vec<String>,
    /// `schema.table` (lowercased) -> its column names, for every user relation.
    ///
    /// Needed by lineage: the static analyser has to expand `SELECT *` and
    /// disambiguate unqualified names, and — the load-bearing one — it lets us
    /// check that a table it claims to have resolved actually exists. The crate
    /// returns placeholders like `?cte?` as if they were real tables, so
    /// existence is the only honest test.
    relation_columns: HashMap<String, Vec<String>>,
    /// `(schema.table, column)` -> classification, for looking up a source
    /// column that lineage identified by name rather than by OID.
    by_name: HashMap<(String, String), Classification>,
    /// OIDs of every relation in `pg_catalog` and `information_schema`.
    ///
    /// The engine's own answer to "is this a system catalog", which is the only
    /// answer that survives `search_path`. A client may write `FROM pg_database`
    /// unqualified — Harlequin does — and a user may own a `public.pg_database`,
    /// so a name proves nothing. The OID in the `RowDescription` does.
    system_relations: HashSet<u32>,
    /// Declared unique keys, as sets of lowercased column names.
    ///
    /// Used to spot a `GROUP BY` that makes every group a single row, which
    /// turns a released summary back into the value it was summarising.
    unique_keys: Vec<Vec<String>>,
    /// Lowercased `schema.relation` of every view whose definition contains a
    /// set operation, transitively, plus every view we could not read or parse.
    ///
    /// A `UNION` inside a view is invisible in the statement that selects from
    /// it, and CockroachDB reports the first branch's provenance for the result
    /// either way. Selecting from one of these must be treated exactly like
    /// writing the set operation out by hand.
    opaque_views: HashSet<String>,
}

impl Snapshot {
    /// Column names of a user relation, or `None` if we have never seen it.
    ///
    /// `None` is the answer that matters: it means a name lineage handed us is
    /// not a real table, so nothing resolved.
    pub fn relation_columns(&self, relation: &str) -> Option<&[String]> {
        self.relation_columns
            .get(&relation.to_ascii_lowercase())
            .map(Vec::as_slice)
    }

    /// Classification of a column identified by name.
    ///
    /// `None` means unclassified, which under default-deny is masked — so a
    /// caller deciding releasability must treat `None` as "not releasable",
    /// never as "nothing to worry about".
    pub fn lookup_by_name(&self, relation: &str, column: &str) -> Option<&Classification> {
        self.by_name
            .get(&(relation.to_ascii_lowercase(), column.to_ascii_lowercase()))
    }

    /// Whether this relation is a view whose expansion contains a set operation.
    ///
    /// An unqualified name matches any schema, because resolving it properly
    /// needs the session's `search_path` and getting that wrong in the
    /// permissive direction is a leak. Over-matching costs a refusal.
    pub fn is_opaque_view(&self, schema: Option<&str>, relation: &str) -> bool {
        let relation = relation.to_ascii_lowercase();
        match schema {
            Some(schema) => self
                .opaque_views
                .contains(&format!("{}.{relation}", schema.to_ascii_lowercase())),
            None => self
                .opaque_views
                .iter()
                .any(|known| known.rsplit_once('.').is_some_and(|(_, n)| n == relation)),
        }
    }

    /// The same question for an already-qualified `schema.relation`.
    ///
    /// Falls back to the bare name, because lineage qualifies an unqualified
    /// reference by guessing `public.` — a guess that must not be able to turn
    /// "opaque" into "fine".
    pub fn relation_is_opaque_view(&self, qualified: &str) -> bool {
        let qualified = qualified.to_ascii_lowercase();
        if self.opaque_views.contains(&qualified) {
            return true;
        }
        let bare = qualified
            .rsplit_once('.')
            .map_or(qualified.as_str(), |(_, n)| n);
        self.is_opaque_view(None, bare)
    }

    /// Whether grouping by these columns makes every group a single row.
    ///
    /// A reducing aggregate over a masked column is internally masked with that
    /// column's own mask before it is served (see `Safety::Summary`), so on its
    /// own a one-row group cannot degrade a summary into the exact value. The
    /// guard is still applied as belt and braces: `GROUP BY id` on a unique key
    /// gives one row per group, so every "summary" is exactly the value it
    /// summarised. Measured on the demo fixture, before the summary-masking
    /// change, `SELECT id, sum(annual_salary) … GROUP BY id` returned every
    /// salary in the table, byte-identical to reading it directly, in one
    /// query. The group-of-one trade was written down as an incidental edge
    /// case; grouping by a key makes it the bulk interface.
    ///
    /// Deliberately not resolved to a relation. It asks whether *any* declared
    /// unique key is covered by the grouped names, so `GROUP BY id` is refused
    /// wherever `id` is a key. Resolving which relation the grouping belongs to
    /// would need name resolution this does not have, and being wrong in that
    /// direction releases values; being wrong in this one refuses a query whose
    /// grouping happens to share a key's column names.
    pub fn grouping_covers_a_unique_key(&self, grouped: &[String]) -> bool {
        self.unique_keys
            .iter()
            .any(|key| key.iter().all(|column| grouped.contains(column)))
    }

    #[cfg(test)]
    pub fn insert_unique_key_for_test(&mut self, columns: &[&str]) {
        self.unique_keys
            .push(columns.iter().map(|c| (*c).to_ascii_lowercase()).collect());
    }

    /// Whether the statement mentions the name of any column this principal
    /// may not read.
    ///
    /// **The soundness backstop for lineage.** Three disclosures came from
    /// `sqllineage` under-reporting which base columns feed an output field — a
    /// set operation, a view column, and a scalar subquery — and each was closed
    /// by a guard aimed at that construct. Guards aimed at constructs only cover
    /// the constructs someone thought of.
    ///
    /// This asks a cruder question that does not depend on per-field precision:
    /// is the name of a masked column present in this statement at all? If not,
    /// no output field can carry a masked value, however the expressions are
    /// arranged and whatever the resolver did or did not resolve.
    ///
    /// **It deliberately does not resolve names to relations.** An earlier
    /// version matched each name against the relations the statement mentions,
    /// which made it depend on `pg_query`'s tree walk finding every `RangeVar` —
    /// exactly the kind of completeness assumption that has failed here twice.
    /// Comparing bare names against every masked column in the catalog needs no
    /// traversal to be complete.
    ///
    /// That holds without qualification for a column the operator *classified*.
    /// For one that is merely unclassified — masked by default-deny — the check
    /// below is narrower: it also requires the owning relation's bare name to
    /// appear, so that a common column name existing in some unrelated table
    /// does not disable lineage everywhere. Deliberate, and a real narrowing of
    /// this layer; the sentence that used to sit here said the comparison
    /// "cannot be wrong in the unsafe direction", which described the first arm
    /// and not the second. A doc that overstates its own guarantee is how the
    /// `SELECT *` wrapper survived a day of grouping work.
    ///
    /// The cost is over-refusal, and it is real: if `city` is masked in *any*
    /// relation, lineage will not release an expression over a different,
    /// released `city`. That is utility, on an opt-in feature, in exchange for
    /// the failure mode that has produced three of this project's five
    /// disclosures.
    pub fn statement_references_masked_column(&self, sql: &str, roles: &HashSet<String>) -> bool {
        let inspection = crate::analysis::StatementInspection::new(sql);
        self.inspection_references_masked_column(&inspection, roles)
    }

    pub(crate) fn inspection_references_masked_column(
        &self,
        inspection: &crate::analysis::StatementInspection<'_>,
        roles: &HashSet<String>,
    ) -> bool {
        // Lexer spellings union decoded parse-tree names. `u&"email"` is not
        // the word `email` in the token stream; it is `email` on the ColumnRef.
        // Either source missing the name is how `city || (SELECT u&"email" …)`
        // released a masked address under `lineage = "allow"`.
        let Some(identifiers) = inspection.backstop_identifiers() else {
            return true;
        };
        identifiers.iter().any(|identifier| {
            self.relation_columns.iter().any(|(relation, columns)| {
                if !columns.contains(identifier) {
                    return false;
                }
                match self.lookup_by_name(relation, identifier) {
                    Some(classification) => !classification.for_roles(roles).is_passthrough(),
                    None => {
                        // Unclassified columns are masked by default, but a
                        // bare name that only exists in some unrelated table
                        // must not disable lineage everywhere. Keep this check
                        // lexical (and therefore independent of the SQL tree),
                        // while requiring the owning relation's bare name to
                        // occur too. The omitted-source regressions all name
                        // their underlying relation, including inside nested
                        // subqueries and TABLESAMPLE constructs.
                        let bare_relation = relation
                            .rsplit_once('.')
                            .map_or(relation.as_str(), |(_, name)| name);
                        identifiers.iter().any(|name| name == bare_relation)
                    }
                }
            })
        })
    }

    /// Whether the statement mentions the name of any relation the operator's
    /// catalog knows about.
    ///
    /// Guards the `system_catalogs = "allow"` fast path, which serves a whole
    /// result set unmasked. That path already ANDs a text check with an
    /// engine-authoritative OID check, but the OID check only inspects fields
    /// that *have* provenance, so for computed fields the text check stands
    /// alone — and the text check walks `pg_query`'s tree, which does not enter
    /// a `WindowDef`. `SELECT relname, count(*) OVER (PARTITION BY (SELECT
    /// email FROM demo.customers LIMIT 1)) FROM pg_catalog.pg_class` was judged
    /// metadata-only while reading a user table.
    ///
    /// Same remedy as the lineage backstop and the same reasoning: the lexer
    /// sees every identifier in the text, so it has no traversal gap to fall
    /// through. Over-refusal is possible — a catalog query whose alias happens
    /// to match a user relation's name loses the fast path — and costs a GUI
    /// client one refused introspection query, not a disclosure.
    pub fn statement_mentions_user_relation(&self, sql: &str) -> bool {
        let inspection = crate::analysis::StatementInspection::new(sql);
        self.inspection_mentions_user_relation(&inspection)
    }

    pub(crate) fn inspection_mentions_user_relation(
        &self,
        inspection: &crate::analysis::StatementInspection<'_>,
    ) -> bool {
        let Some(identifiers) = inspection.identifiers() else {
            return true;
        };
        identifiers.iter().any(|identifier| {
            self.relation_columns.keys().any(|relation| {
                relation
                    .rsplit_once('.')
                    .is_some_and(|(_, n)| n == identifier)
            })
        })
    }

    /// Whether any relation the statement names is such a view.
    pub fn statement_touches_opaque_view(&self, sql: &str) -> bool {
        let inspection = crate::analysis::StatementInspection::new(sql);
        self.inspection_touches_opaque_view(&inspection)
    }

    pub(crate) fn inspection_touches_opaque_view(
        &self,
        inspection: &crate::analysis::StatementInspection<'_>,
    ) -> bool {
        if self.opaque_views.is_empty() {
            return false;
        }
        // Lexical, for the same reason the masked-column backstop is.
        //
        // This used to read `referenced_relations`, a parse-tree walk — and an
        // audit found `SELECT … FROM base TABLESAMPLE SYSTEM (10)` yields an
        // *empty* relation list, because the walker does not descend through a
        // `RangeTableSample`. That silently reopened the CockroachDB
        // set-operation leak this check exists to close, and it did so for a
        // construct nobody had thought to test.
        //
        // Names in the token stream cannot go missing that way. The lexer will
        // happily scan nonsense, though, so the parse check stays: a statement
        // we cannot read could reference anything.
        if !inspection.is_parseable() {
            return true;
        }
        match inspection.identifiers() {
            None => true,
            Some(identifiers) => identifiers
                .iter()
                .any(|identifier| self.is_opaque_view(None, identifier)),
        }
    }

    #[cfg(test)]
    pub fn insert_system_relation_for_test(&mut self, table_oid: u32) {
        self.system_relations.insert(table_oid);
    }

    pub fn insert_opaque_view_for_test(&mut self, relation: &str) {
        self.opaque_views.insert(relation.to_ascii_lowercase());
    }

    /// Whether this OID is a relation in `pg_catalog` or `information_schema`.
    pub fn is_system_relation(&self, table_oid: u32) -> bool {
        self.system_relations.contains(&table_oid)
    }

    /// Whether the system-catalog OID set was loaded at all. An empty set would
    /// otherwise make every OID check vacuously fail closed, which is safe but
    /// silently disables GUI support; the caller logs instead of guessing.
    pub fn has_system_relations(&self) -> bool {
        !self.system_relations.is_empty()
    }

    pub fn lookup(&self, table_oid: u32, column_id: i16) -> Option<&Classification> {
        self.by_column.get(&(table_oid, column_id))
    }

    /// Stable `schema.relation.column` identity of a live column, classified or
    /// not. Prefers the engine's own spelling (`all_columns`) so the same
    /// column answers identically whether or not a rule covers it.
    pub fn name_of(&self, table_oid: u32, column_id: i16) -> Option<&str> {
        self.all_columns
            .get(&(table_oid, column_id))
            .or_else(|| self.names.get(&(table_oid, column_id)))
            .map(String::as_str)
    }

    /// The source column's effective nullability, when the catalog resolved it.
    pub(crate) fn is_not_null(&self, table_oid: u32, column_id: i16) -> Option<bool> {
        self.column_not_null.get(&(table_oid, column_id)).copied()
    }

    pub fn knows_relation(&self, table_oid: u32) -> bool {
        self.relations.contains(&table_oid)
    }

    /// Bare column names that are masked for these roles.
    ///
    /// Used by `posture = "hostile"` to decide which identifiers may only
    /// appear as outermost SELECT-list ColumnRefs.
    ///
    /// Includes:
    /// - catalog rules whose effective mask is not passthrough
    /// - **unclassified** columns anywhere in `relation_columns` (default-deny
    ///   nulls them in projections). Leaving them out let
    ///   `WHERE internal_note = 'secret'` / `WHERE token = '…'` on an
    ///   uncatalogued table recover values the SELECT list had nulled.
    ///
    /// Bare names that are passthrough (`mask = "none"`) on any catalogued
    /// column are not added from the unclassified pass — so a filter key like
    /// `id` stays usable even when some other table also has an unclassified
    /// `id`.
    pub fn masked_bare_names_for_roles(&self, roles: &HashSet<String>) -> HashSet<String> {
        let mut names: HashSet<String> = self
            .by_name
            .iter()
            .filter(|(_, classification)| !classification.for_roles(roles).is_passthrough())
            .map(|((_, column), _)| column.clone())
            .collect();

        let passthrough: HashSet<String> = self
            .by_name
            .iter()
            .filter(|(_, classification)| classification.for_roles(roles).is_passthrough())
            .map(|((_, column), _)| column.clone())
            .collect();

        for (relation, columns) in &self.relation_columns {
            for column in columns {
                if self
                    .by_name
                    .contains_key(&(relation.clone(), column.clone()))
                {
                    continue;
                }
                if passthrough.contains(column) {
                    continue;
                }
                names.insert(column.clone());
            }
        }
        names
    }

    /// Relation → column list from the last catalog refresh. Used by hostile
    /// whole-row detection (alias vs column collision on the same relation).
    pub fn relation_columns_map(&self) -> &std::collections::HashMap<String, Vec<String>> {
        &self.relation_columns
    }

    /// Bare column names we classify. Used only to bucket rejections for
    /// reporting — never for enforcement, where matching on a name would be
    /// unsound.
    pub fn classified_column_names(&self) -> HashSet<&str> {
        self.names
            .values()
            .filter_map(|n| n.rsplit('.').next())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.by_column.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_column.is_empty()
    }

    #[cfg(test)]
    /// Register a relation's columns and their masks by name, the way a
    /// refresh would, so lineage can be tested without a database.
    pub fn insert_relation_for_test(&mut self, relation: &str, columns: &[(&str, Mask)]) {
        let relation = relation.to_ascii_lowercase();
        self.relation_columns.insert(
            relation.clone(),
            columns
                .iter()
                .map(|(c, _)| c.to_ascii_lowercase())
                .collect(),
        );
        for (column, mask) in columns {
            self.by_name.insert(
                (relation.clone(), column.to_ascii_lowercase()),
                Classification {
                    default: MaskSpec::new(*mask),
                    by_role: HashMap::new(),
                },
            );
        }
    }

    /// Register a relation's columns with no classification at all, so the
    /// "unclassified is not releasable" path can be exercised.
    pub fn relation_columns_for_test(&mut self, relation: &str, columns: &[&str]) {
        self.relation_columns.insert(
            relation.to_ascii_lowercase(),
            columns.iter().map(|c| c.to_ascii_lowercase()).collect(),
        );
    }

    /// Give a column a different mask for one role.
    pub fn set_role_mask_for_test(&mut self, relation: &str, column: &str, role: &str, mask: Mask) {
        if let Some(c) = self
            .by_name
            .get_mut(&(relation.to_ascii_lowercase(), column.to_ascii_lowercase()))
        {
            c.by_role.insert(role.to_string(), MaskSpec::new(mask));
        }
    }

    pub fn insert_for_test(&mut self, table_oid: u32, column_id: i16, mask: Mask, name: &str) {
        self.by_column.insert(
            (table_oid, column_id),
            Classification {
                default: MaskSpec::new(mask),
                by_role: HashMap::new(),
            },
        );
        self.names.insert((table_oid, column_id), name.to_string());
        // A resolve also sees every classified column in the all-columns pass.
        self.all_columns
            .insert((table_oid, column_id), name.to_string());
        self.relations.insert(table_oid);
    }

    #[cfg(test)]
    /// Register a live-but-unclassified column's stable identity, the way the
    /// all-columns pass of a refresh would — without classifying it.
    pub(crate) fn insert_column_name_for_test(
        &mut self,
        table_oid: u32,
        column_id: i16,
        name: &str,
    ) {
        self.all_columns
            .insert((table_oid, column_id), name.to_string());
    }

    #[cfg(test)]
    pub(crate) fn mark_not_null_for_test(&mut self, table_oid: u32, column_id: i16) {
        self.column_not_null.insert((table_oid, column_id), true);
    }
}

/// The live catalog: a swappable snapshot plus the machinery to keep it current.
pub struct Catalog {
    rules: Vec<ColumnRule>,
    types: HashMap<String, SemanticType>,
    dsn: String,
    /// `ArcSwap` rather than `RwLock<Arc<_>>`: every result set takes this on
    /// the hot path and the refresher writes it every 30 seconds, so readers
    /// should not queue behind a writer. It also removes the poisoned-lock
    /// `expect` from a path that must not panic mid-stream.
    snapshot: ArcSwap<Snapshot>,
    /// Woken when the hot path sees a relation OID we do not recognise.
    refresh_wanted: Notify,
    pub refreshes: AtomicU64,
    pub failed_refreshes: AtomicU64,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            types: HashMap::new(),
            dsn: String::new(),
            snapshot: ArcSwap::from_pointee(Snapshot::default()),
            refresh_wanted: Notify::new(),
            refreshes: AtomicU64::new(0),
            failed_refreshes: AtomicU64::new(0),
        }
    }
}

impl Catalog {
    /// Resolve for the first time. Fails if any rule names a column that does
    /// not exist: a catalog that silently half-loaded has unknown coverage.
    pub async fn resolve(
        rules: &[ColumnRule],
        semantic_types: &[SemanticType],
        dsn: &str,
    ) -> Result<Self> {
        let types: HashMap<String, SemanticType> = semantic_types
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();
        let resolved = resolve_snapshot_retrying(rules, &types, dsn).await?;
        if !resolved.unresolved.is_empty() {
            bail!(
                "catalog references {} column(s) that do not exist: {}. \
                 Refusing to start — a half-loaded catalog has unknown coverage.",
                resolved.unresolved.len(),
                resolved.unresolved.join(", ")
            );
        }
        Ok(Self {
            rules: rules.to_vec(),
            types,
            dsn: dsn.to_string(),
            snapshot: ArcSwap::from_pointee(resolved),
            ..Default::default()
        })
    }

    #[cfg(test)]
    pub fn from_snapshot_for_test(snapshot: Snapshot) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(snapshot),
            ..Default::default()
        }
    }

    /// A stable view for the duration of one `RowDescription`.
    /// How many times the catalog has been re-resolved.
    ///
    /// Doubles as a generation number: a plan built under one generation is not
    /// valid under the next, because a refresh can *tighten* a classification.
    pub fn generation(&self) -> u64 {
        self.refreshes.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshot().is_empty()
    }

    /// Called from the hot path when a relation OID is not one we resolved.
    ///
    /// Cheap and non-blocking: it only nudges the refresher, which enforces its
    /// own floor on how often it will actually re-query.
    pub fn note_unknown_relation(&self) {
        self.refresh_wanted.notify_one();
    }

    /// Re-resolve and swap. Logs every difference, because a silent change in
    /// coverage is the exact failure this mechanism exists to prevent.
    pub async fn refresh(&self) -> Result<()> {
        let previous = self.snapshot();
        let next = match resolve_snapshot_retrying(&self.rules, &self.types, &self.dsn).await {
            Ok(next) => next,
            Err(err) => {
                self.failed_refreshes.fetch_add(1, Ordering::Relaxed);
                // Deliberately keep the old snapshot. Clearing it would be
                // fail-closed in the narrow sense and would mask every column in
                // the database the moment Postgres blinked.
                tracing::error!(
                    error = format!("{err:#}"),
                    "catalog refresh failed, continuing with the previous snapshot ({} classified columns)",
                    previous.len()
                );
                return Err(err);
            }
        };

        for rule in &self.rules {
            let locate = |snap: &Snapshot| {
                snap.names
                    .iter()
                    .find(|(_, name)| **name == rule.display())
                    .map(|(key, _)| *key)
            };
            match (locate(&previous), locate(&next)) {
                (Some(b), Some(a)) if b != a => tracing::info!(
                    "catalog: {} moved (oid.attnum {}.{} -> {}.{}) — relation recreated, classification restored",
                    rule.display(),
                    b.0,
                    b.1,
                    a.0,
                    a.1
                ),
                // Warn, not info: this is the shape of a silent unmasking.
                (Some(b), None) => tracing::warn!(
                    "catalog: coverage lost for {} (was oid.attnum {}.{}) — the relation or column no longer exists; those values are now unclassified",
                    rule.display(),
                    b.0,
                    b.1
                ),
                (None, Some(a)) => tracing::info!(
                    "catalog: coverage restored for {} (oid.attnum {}.{})",
                    rule.display(),
                    a.0,
                    a.1
                ),
                _ => {}
            }
        }

        let changed =
            next.by_column.len() != previous.by_column.len() || next.names != previous.names;
        let count = next.len();
        self.snapshot.store(Arc::new(next));
        self.refreshes.fetch_add(1, Ordering::Relaxed);
        if changed {
            tracing::debug!(classified_columns = count, "catalog refreshed");
        }
        Ok(())
    }

    /// Background loop: refresh on a timer, or sooner when the hot path saw a
    /// relation it did not recognise, but never more often than `min_interval`.
    pub async fn run_refresher(self: Arc<Self>, interval: Duration, min_interval: Duration) {
        let mut last = Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.refresh_wanted.notified() => {
                    // `saturating_sub`: the guard above already establishes
                    // `since < min_interval`, but Duration subtraction panics
                    // on underflow and a panic here would stop the refresher
                    // for the life of the process — the catalog would then
                    // silently stop tracking DDL.
                    let since = last.elapsed();
                    if since < min_interval {
                        tokio::time::sleep(min_interval.saturating_sub(since)).await;
                    }
                }
            }
            last = Instant::now();
            let _ = self.refresh().await;
        }
    }
}

/// Fold a semantic type and a column rule into one classification.
///
/// Precedence, most specific first:
///   1. the column rule's `by_role` entry
///   2. the column rule's `mask`
///   3. the semantic type's `by_role` entry
///   4. the semantic type's `mask`
fn classify(rule: &ColumnRule, types: &HashMap<String, SemanticType>) -> Result<Classification> {
    let semantic = match &rule.semantic_type {
        Some(name) => Some(types.get(name).with_context(|| {
            format!(
                "{} references unknown semantic type \"{name}\"",
                rule.display()
            )
        })?),
        None => None,
    };

    let base_kind = match (rule.mask, semantic) {
        (Some(mask), _) => mask,
        (None, Some(t)) => t.mask,
        (None, None) => bail!("{} needs either `mask` or `type`", rule.display()),
    };

    // Build the default spec: semantic parameters first, column parameters win.
    let build = |kind: Mask| {
        let mut spec = MaskSpec::new(kind);
        if let Some(t) = semantic {
            // A semantic type names its own pseudonym domain, so every column
            // of that type stays joinable without anyone configuring it.
            spec.domain = Some(t.name.as_str().into());
            t.params.apply_to(&mut spec);
        }
        rule.params.apply_to(&mut spec);
        spec
    };

    let mut by_role: HashMap<String, MaskSpec> = HashMap::new();
    if let Some(t) = semantic {
        for (role, kind) in &t.by_role {
            by_role.insert(role.clone(), build(*kind));
        }
    }
    for (role, kind) in &rule.by_role {
        by_role.insert(role.clone(), build(*kind));
    }

    let classification = Classification {
        default: build(base_kind),
        by_role,
    };
    // A mask whose parameters leave the value unchanged is worse than no mask:
    // it looks configured. Refuse at startup, where the catalog already refuses
    // to half-load.
    validate_spec(&classification.default, &rule.display())?;
    for (role, spec) in &classification.by_role {
        validate_spec(spec, &format!("{} for role {role}", rule.display()))?;
    }
    Ok(classification)
}

/// Views whose expansion contains a set operation, so their provenance cannot be
/// believed.
///
/// Two passes, because the property is transitive: a view over a view over a
/// `UNION` reports the union's provenance just as directly as the union does.
/// The fixpoint is bounded by the number of views, and each round can only add,
/// so it terminates.
///
/// Everything unreadable is opaque. A null definition, an empty one, or one
/// `pg_query` cannot parse all mean the same thing here — we do not know what is
/// inside it — and the only safe reading of "do not know" is the one that
/// refuses.
fn opaque_views(defs: &HashMap<String, Option<String>>) -> HashSet<String> {
    let mut opaque: HashSet<String> = HashSet::new();
    for (name, def) in defs {
        let unsafe_def = match def {
            Some(sql) if !sql.trim().is_empty() => !crate::analysis::provenance_is_trustworthy(sql),
            _ => true,
        };
        if unsafe_def {
            opaque.insert(name.clone());
        }
    }

    loop {
        let mut grew = false;
        for (name, def) in defs {
            if opaque.contains(name) {
                continue;
            }
            // Already established as readable and parseable by the pass above,
            // so `None` here cannot happen; treating it as opaque anyway keeps
            // the fail-closed reading local rather than depending on that.
            // Lexical, matching `statement_touches_opaque_view`: a view whose
            // body uses TABLESAMPLE reported no relations at all under the
            // parse-tree walk, so it never inherited its base's opacity.
            let touches = match def
                .as_deref()
                .map(crate::analysis::referenced_identifiers)
                .unwrap_or(None)
            {
                None => true,
                Some(identifiers) => identifiers.iter().any(|identifier| {
                    opaque
                        .iter()
                        .any(|known| known.rsplit_once('.').is_some_and(|(_, n)| n == identifier))
                }),
            };
            if touches {
                opaque.insert(name.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    opaque
}

/// Make a PostgreSQL URI usable by the catalog connection.
///
/// `tokio-postgres` does not parse libpq's verify modes. Rustls still enforces
/// certificate and hostname verification; only the URI spelling changes.
/// Channel binding stays enabled because this connection goes directly to the
/// backend and tokio-postgres-rustls supplies the required certificate digest.
pub fn sanitize_catalog_dsn(dsn: &str) -> (String, Option<&'static str>) {
    let Some((base, query)) = dsn.split_once('?') else {
        return (dsn.to_string(), None);
    };
    let mut changed = false;
    let rewritten_query = query
        .split('&')
        .map(|part| {
            if matches!(part, "sslmode=verify-full" | "sslmode=verify-ca") {
                changed = true;
                "sslmode=require"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    if !changed {
        return (dsn.to_string(), None);
    }
    (
        format!("{base}?{rewritten_query}"),
        Some(
            "catalog_dsn certificate verification is enforced with rustls; sslmode was \
             rewritten to require only for tokio-postgres parsing",
        ),
    )
}

fn catalog_dsn_verifies_server(dsn: &str) -> bool {
    dsn.split_once('?').is_some_and(|(_, query)| {
        query
            .split('&')
            .any(|part| matches!(part, "sslmode=verify-full" | "sslmode=verify-ca"))
    })
}

/// Reject parameter combinations that silently do nothing.
fn validate_spec(spec: &MaskSpec, what: &str) -> Result<()> {
    match spec.kind {
        Mask::NumericBucket if spec.bucket < 2 => bail!(
            "{what}: numeric-bucket needs `bucket` >= 2, got {}. A bucket of 1 \
             floors every value to itself and masks nothing.",
            spec.bucket
        ),
        Mask::Range if spec.end <= spec.start => bail!(
            "{what}: range needs `end` > `start`, got start={} end={}. An empty \
             range returns the value unchanged.",
            spec.start,
            spec.end
        ),
        // `outer` keeps `keep` characters at each end and stars the middle, so
        // `keep = 0` leaves the whole value as the middle. It reads as
        // configured and masks nothing.
        Mask::Outer if spec.keep == 0 => bail!(
            "{what}: outer needs `keep` >= 1. With keep = 0 the whole value is \
             the surviving middle, so nothing is masked."
        ),
        _ => Ok(()),
    }
}

/// Whether a catalog-resolution failure is a concurrent-DDL race rather than a
/// real problem with the database or the configuration.
///
/// `resolve_snapshot` scans `pg_class` and calls `pg_get_viewdef(c.oid)` on
/// each row. The scan runs against a snapshot; `pg_get_viewdef` looks the
/// relation up as it stands *now*. Drop a view in between and the function
/// errors on an OID the scan has already handed it:
///
/// ```text
/// ERROR: could not open relation with OID 17041
/// ```
///
/// This is not hypothetical and it is not only a test condition. It cost
/// `resolve()` — which runs before the proxy binds — so a view dropped at the
/// wrong instant stopped pgmask from starting at all, and an operator whose
/// proxy will not start routes around the proxy.
///
/// Found by CI rather than by the local gate: on a Linux runner the window is
/// wide enough to hit reliably, and on the development machine it never
/// reproduced once in seventy releases.
///
/// Retrying the whole load is the right response rather than skipping the
/// vanished relation, because this file already refuses to run on a partial
/// catalog — "a half-loaded catalog has unknown coverage".
fn is_concurrent_ddl_race(err: &anyhow::Error) -> bool {
    // Matched on the message because the SQLSTATE for this is XX000
    // (internal_error), which is far too broad to retry on.
    let text = format!("{err:#}");
    text.contains("could not open relation with OID")
        || text.contains("cache lookup failed for relation")
}

/// `resolve_snapshot` with a bounded retry over concurrent DDL.
///
/// Bounded, and short: this covers a relation disappearing mid-scan, which
/// resolves on the next attempt. A database genuinely churning its schema
/// faster than pgmask can read it is a condition to report, not to spin on.
async fn resolve_snapshot_retrying(
    rules: &[ColumnRule],
    types: &HashMap<String, SemanticType>,
    dsn: &str,
) -> Result<Snapshot> {
    // One entry per retry, so the attempt count and the backoff cannot drift
    // apart. Written as a table rather than as `100 * attempt` because this
    // crate denies `clippy::arithmetic_side_effects` — a strict lint to carry,
    // and the right one for a proxy where a wrapped length is a disclosure.
    const BACKOFF_MS: &[u64] = &[100, 200, 400];
    let mut backoff = BACKOFF_MS.iter();
    loop {
        match resolve_snapshot(rules, types, dsn).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(err) => match backoff.next() {
                Some(&delay_ms) if is_concurrent_ddl_race(&err) => {
                    tracing::warn!(
                        delay_ms,
                        error = %format!("{err:#}"),
                        "catalog resolution raced concurrent DDL; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                _ => return Err(err),
            },
        }
    }
}

async fn resolve_snapshot(
    rules: &[ColumnRule],
    types: &HashMap<String, SemanticType>,
    dsn: &str,
) -> Result<Snapshot> {
    // TLS-capable, because managed Postgres generally refuses plaintext. A
    // NoTls connector here meant the catalog could not be resolved against Neon
    // (or RDS with rds.force_ssl, or Cloud SQL) at all — the proxy would fail to
    // start against exactly the databases it is most useful in front of.
    // Honor the catalog DSN independently of `backend_tls`: this is a separate,
    // direct connection. tokio-postgres cannot parse libpq's verify modes, so
    // `sanitize_catalog_dsn` translates their spelling after this check while
    // rustls enforces certificate and hostname verification here.
    let tls_mode = if catalog_dsn_verifies_server(dsn) {
        crate::tls::BackendTls::VerifyFull
    } else {
        crate::tls::BackendTls::Require
    };
    let connector = tokio_postgres_rustls::MakeRustlsConnect::new(
        crate::tls::backend_client_config(tls_mode, None)?,
    );
    let (dsn, note) = sanitize_catalog_dsn(dsn);
    if let Some(note) = note {
        // Once per resolve is noisy; once per process would need state. The
        // refresh interval is minutes, so this is fine and stays visible.
        tracing::warn!("catalog: {note}");
    }
    let (client, connection) = tokio_postgres::connect(&dsn, connector)
        .await
        .context("connecting with catalog_dsn to resolve column OIDs")?;
    let handle = tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::warn!(error = %err, "catalog connection error");
        }
    });

    // Every system-catalog relation, so a `RowDescription` OID can be checked
    // against the engine's own namespacing rather than against a name.
    let system_relations: HashSet<u32> = client
        .query(
            "SELECT c.oid::int8 AS oid
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname IN ('pg_catalog', 'information_schema')",
            &[],
        )
        .await
        .context("loading system catalog OIDs")?
        .iter()
        .map(|row| row.get::<_, i64>("oid") as u32)
        .collect();

    // Every user relation and its columns. Bounded by schema count, loaded once
    // per refresh, and lineage cannot resolve anything without it. The
    // recursive arm follows domain base types so `CREATE DOMAIN ... NOT NULL`
    // remains effective even through another domain; ordinary columns add no
    // recursive rows.
    let mut relation_columns: HashMap<String, Vec<String>> = HashMap::new();
    let mut column_names: HashMap<(u32, i16), String> = HashMap::new();
    let mut column_not_null: HashMap<(u32, i16), bool> = HashMap::new();
    for row in client
        .query(
            "WITH RECURSIVE user_columns AS (
                 SELECT n.nspname || '.' || c.relname AS relation,
                        a.attname AS column_name,
                        c.oid::int8 AS oid,
                        a.attnum AS attnum,
                        a.atttypid AS type_oid,
                        a.attnotnull AS not_null
                   FROM pg_class c
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   JOIN pg_attribute a ON a.attrelid = c.oid
                  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                    AND n.nspname NOT LIKE 'pg_temp%'
                    AND a.attnum > 0
                    AND NOT a.attisdropped
                    AND c.relkind = ANY('{r,v,m,p,f}')
             ), column_types AS (
                 SELECT u.relation, u.column_name, u.oid, u.attnum,
                        t.typbasetype AS base_type_oid,
                        (u.not_null OR t.typnotnull) AS not_null
                   FROM user_columns u
                   JOIN pg_type t ON t.oid = u.type_oid
                 UNION ALL
                 SELECT c.relation, c.column_name, c.oid, c.attnum,
                        t.typbasetype AS base_type_oid,
                        (c.not_null OR t.typnotnull) AS not_null
                   FROM column_types c
                   JOIN pg_type t ON t.oid = c.base_type_oid
                  WHERE c.base_type_oid <> 0
             )
             SELECT relation, column_name AS column, oid, attnum,
                    bool_or(not_null) AS not_null
               FROM column_types
              GROUP BY relation, column_name, oid, attnum
              ORDER BY relation, attnum",
            &[],
        )
        .await
        .context("loading relation column lists")?
    {
        let relation: String = row.get("relation");
        let column: String = row.get("column");
        let oid: i64 = row.get("oid");
        let attnum: i16 = row.get("attnum");
        let not_null: bool = row.get("not_null");
        column_names.insert((oid as u32, attnum), format!("{relation}.{column}"));
        column_not_null.insert((oid as u32, attnum), not_null);
        relation_columns
            .entry(relation.to_ascii_lowercase())
            .or_default()
            .push(column.to_ascii_lowercase());
    }

    // View definitions, so a set operation hidden inside one is not trusted.
    // `pg_get_viewdef` is available on both Postgres and CockroachDB; a
    // definition that comes back null or empty is treated as opaque rather than
    // as safe, so an engine that declines to tell us costs refusals, not
    // exposure.
    let mut view_defs: HashMap<String, Option<String>> = HashMap::new();
    for row in client
        .query(
            "SELECT n.nspname || '.' || c.relname AS relation,
                    pg_get_viewdef(c.oid)         AS def
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relkind IN ('v', 'm')
                AND n.nspname NOT IN ('pg_catalog', 'information_schema',
                                      'pg_toast', 'crdb_internal', 'pg_extension')
                AND n.nspname NOT LIKE 'pg_temp%'",
            &[],
        )
        .await
        .context("loading view definitions")?
    {
        let relation: String = row.get("relation");
        let def: Option<String> = row.get("def");
        view_defs.insert(relation.to_ascii_lowercase(), def);
    }
    let opaque_views = opaque_views(&view_defs);

    // Declared unique keys, so a grouping that yields one row per group can be
    // told apart from a real aggregation.
    //
    // WHICH DIRECTION IS SAFE
    //
    // A key here makes the guard refuse. So a key **narrower** than the truth
    // over-refuses — a utility cost — and a key **wider** than the truth, or a
    // key missing entirely, releases an aggregate whose groups are one row
    // each. Every choice below is made on that basis, and two of them were
    // measured leaking before it was.
    //
    // INDKEY ALWAYS, `pg_depend` ONLY TO ADD EXPRESSION COLUMNS
    //
    // `indkey` holds 0 for an expression, and the original query inner-joined
    // it to `pg_attribute`, so a *pure* expression index — `UNIQUE
    // (lower(label))` — matched no attribute, produced no group, and vanished.
    // `GROUP BY label` then released `sum(salary)` one row at a time, and
    // `lower(label)` unique does imply `label` unique, so this was decidable
    // from the catalog and simply was not being read.
    //
    // The first attempt at fixing it replaced `indkey` with `pg_depend`
    // outright, and that was much worse than the bug. A **constraint-backed**
    // index — every `PRIMARY KEY` and every `UNIQUE` constraint — has no direct
    // index-to-column dependency at all; the dependency runs through
    // `pg_constraint`. Measured on Postgres 17: `pg_depend` returns nothing for
    // `t_pkey` and `t_u_key`, and the columns only for a plain
    // `CREATE UNIQUE INDEX`. Nearly every real unique key disappeared, the
    // guard stopped firing, and the generated campaigns went from 0 leaks to
    // 480 and 660. They exist for exactly this.
    //
    // So `indkey` is the source, and `pg_depend` only *adds* the base columns
    // of expressions — and only for non-partial indexes, because a partial
    // index's *predicate* columns are dependencies too: measured,
    // `UNIQUE (label) WHERE salary > 0` yields `label,salary`, a wider key than
    // the truth, which is the releasing direction.
    //
    // AND PARTIAL INDEXES ARE INCLUDED NOW
    //
    // They used to be excluded, reasoned as "they are only unique over the rows
    // matching their predicate". True, and backwards: a key makes the guard
    // refuse, so excluding one is the releasing direction. A partial unique
    // index guarantees at most one row per key among matching rows, and
    // `WHERE label IS NOT NULL GROUP BY label` returned the exact value.
    // Including them over-refuses on queries that do not match the predicate,
    // which is the cost worth paying.
    //
    // KNOWN GAP, NARROW AND DELIBERATE
    //
    // A *partial* index whose key is purely an expression is still missed:
    // `indkey` gives nothing for it and `pg_depend` cannot substitute.
    let mut unique_keys: Vec<Vec<String>> = Vec::new();
    for row in client
        .query(
            "SELECT string_agg(DISTINCT k.col, ',') AS columns
               FROM (
                 SELECT i.indexrelid, a.attname AS col
                   FROM pg_index i
                   JOIN pg_class c ON c.oid = i.indrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS u(attnum, ord)
                   JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = u.attnum
                  WHERE i.indisunique
                    AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                 UNION
                 SELECT i.indexrelid, a.attname AS col
                   FROM pg_index i
                   JOIN pg_class c ON c.oid = i.indrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   JOIN pg_depend d
                     ON d.classid = 'pg_class'::regclass AND d.objid = i.indexrelid
                    AND d.refclassid = 'pg_class'::regclass AND d.refobjid = i.indrelid
                    AND d.refobjsubid > 0
                   JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = d.refobjsubid
                  WHERE i.indisunique AND i.indpred IS NULL AND i.indexprs IS NOT NULL
                    AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
               ) k
              GROUP BY k.indexrelid",
            &[],
        )
        .await
        .context("loading unique keys")?
    {
        let columns: Option<String> = row.get("columns");
        if let Some(columns) = columns {
            unique_keys.push(
                columns
                    .split(',')
                    .map(|c| c.trim().to_ascii_lowercase())
                    .collect(),
            );
        }
    }

    // No column rules: every field below is carried for shape, and the mutation
    // campaign reports all four as deletable with nothing noticing. They are
    // equivalent mutants on this path, and the reason is worth writing down
    // once rather than re-deriving it each run.
    //
    // With no rules, nothing is classified, so default-deny answers every
    // question before these are consulted. `opaque_views` refuses a read of a
    // view containing a set operation — but that read is masked anyway.
    // `unique_keys` only qualifies a *summary*, and a summary needs a released
    // column. `relation_columns` backs "does this statement mention a masked
    // column", and there are none.
    //
    // The one that could differ is `system_relations` under
    // `system_catalogs = "allow"`: an empty set means a `pg_catalog` read is not
    // recognised as one and falls to default-deny instead of being served. That
    // is over-refusal, in the direction that does not disclose, on a
    // configuration that pairs an allow-list for system catalogs with a catalog
    // that classifies nothing.
    //
    // `an_empty_catalog_masks_everything_and_still_refuses` pins the property
    // this path is actually for. It does not kill these mutants and is not
    // meant to.
    if rules.is_empty() {
        let snapshot = Snapshot {
            all_columns: column_names,
            column_not_null,
            system_relations,
            relation_columns,
            opaque_views,
            unique_keys,
            ..Default::default()
        };
        drop(client);
        handle.abort();
        return Ok(snapshot);
    }

    let relations: Vec<String> = {
        let mut seen: Vec<String> = rules.iter().map(|r| r.relation.clone()).collect();
        seen.sort();
        seen.dedup();
        seen
    };

    let rows = client
        .query(
            "SELECT n.nspname || '.' || c.relname AS relation,
                    a.attname                     AS column,
                    c.oid::int8                   AS oid,
                    a.attnum                      AS attnum
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_attribute a ON a.attrelid = c.oid
              WHERE n.nspname || '.' || c.relname = ANY($1)
                AND a.attnum > 0
                AND NOT a.attisdropped
                AND c.relkind = ANY('{r,v,m,p,f}')",
            &[&relations],
        )
        .await
        .context("resolving catalog column OIDs")?;

    let mut resolved: HashMap<(String, String), (u32, i16)> = HashMap::new();
    for row in &rows {
        let relation: String = row.get("relation");
        let column: String = row.get("column");
        let oid: i64 = row.get("oid");
        let attnum: i16 = row.get("attnum");
        resolved.insert((relation, column), (oid as u32, attnum));
    }
    drop(client);
    handle.abort();

    let mut snapshot = Snapshot {
        all_columns: column_names,
        column_not_null,
        system_relations,
        relation_columns,
        opaque_views,
        unique_keys,
        ..Default::default()
    };
    for rule in rules {
        match resolved.get(&rule.key()) {
            Some(&(oid, attnum)) => {
                snapshot
                    .by_column
                    .insert((oid, attnum), classify(rule, types)?);
                snapshot.names.insert((oid, attnum), rule.display());
                snapshot.relations.insert(oid);
                snapshot.by_name.insert(
                    (
                        rule.relation.to_ascii_lowercase(),
                        rule.column.to_ascii_lowercase(),
                    ),
                    classify(rule, types)?,
                );
            }
            None => snapshot.unresolved.push(rule.display()),
        }
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn defs(pairs: &[(&str, Option<&str>)]) -> HashMap<String, Option<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.map(str::to_string)))
            .collect()
    }

    #[test]
    fn a_view_containing_a_set_operation_is_opaque() {
        let out = opaque_views(&defs(&[
            ("s.plain", Some("SELECT city FROM s.t")),
            (
                "s.u",
                Some("SELECT city AS v FROM s.t UNION ALL SELECT email FROM s.t"),
            ),
        ]));
        assert!(out.contains("s.u"));
        assert!(!out.contains("s.plain"));
    }

    /// A view over a view over a union reports the union's provenance just as
    /// directly as the union does, so the property has to be transitive.
    #[test]
    fn opacity_is_transitive_through_layers_of_views() {
        let out = opaque_views(&defs(&[
            ("s.u", Some("SELECT a FROM s.t UNION SELECT b FROM s.t")),
            ("s.over", Some("SELECT v FROM s.u")),
            ("s.over_over", Some("SELECT v FROM s.over")),
            ("s.unrelated", Some("SELECT x FROM s.t")),
        ]));
        assert!(out.contains("s.over"), "one layer up");
        assert!(out.contains("s.over_over"), "two layers up");
        assert!(!out.contains("s.unrelated"));
    }

    /// An engine that will not tell us what is in a view has not told us the
    /// view is safe.
    #[test]
    fn an_unreadable_definition_is_opaque() {
        let out = opaque_views(&defs(&[
            ("s.null_def", None),
            ("s.empty_def", Some("   ")),
            ("s.garbage", Some("SELECT FROM WHERE ((")),
        ]));
        assert!(out.contains("s.null_def"));
        assert!(out.contains("s.empty_def"));
        assert!(out.contains("s.garbage"));
    }

    /// Resolving an unqualified name properly needs `search_path`; matching any
    /// schema costs a refusal, and guessing wrong would cost a disclosure.
    #[test]
    fn an_unqualified_reference_matches_the_view_in_any_schema() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_opaque_view_for_test("sw.v_union");
        assert!(snapshot.is_opaque_view(Some("sw"), "v_union"));
        assert!(snapshot.is_opaque_view(None, "v_union"));
        assert!(snapshot.is_opaque_view(None, "V_UNION"), "case-folded");
        assert!(!snapshot.is_opaque_view(Some("other"), "v_union"));
        assert!(!snapshot.is_opaque_view(None, "something_else"));
    }

    /// Predicates the release rules consult, asserted directly.
    ///
    /// `cargo mutants` replaced each of these with a constant and nothing
    /// failed. They are covered end-to-end by the shell campaigns, which
    /// `cargo test` does not run — so `cargo test` would have stayed green
    /// while `is_system_relation` returned `true` for every OID, which serves
    /// user tables through the `system_catalogs = "allow"` fast path.
    #[test]
    fn predicates_the_release_rules_consult() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_relation_for_test("demo.customers", &[("email", Mask::Redact)]);
        snapshot.relation_columns_for_test("demo.customers", &["id", "email"]);

        // Replacing this with `false` disables the lineage backstop *and* the
        // masked-column check that gates fine-grained `date_trunc`; with
        // `true`, every statement looks like it touches something masked.
        let roles = HashSet::new();
        assert!(
            snapshot.statement_references_masked_column("SELECT email FROM demo.customers", &roles)
        );
        assert!(
            !snapshot.statement_references_masked_column("SELECT 1 FROM demo.customers", &roles)
        );
        // Unicode-escaped names in a scalar subquery: the token is not the
        // word `email`, and sqllineage does not look inside. Measured
        // releasing a concatenated address under `lineage = "allow"`.
        assert!(snapshot.statement_references_masked_column(
            r#"SELECT city || (SELECT u&"email" FROM demo.customers LIMIT 1) FROM demo.customers"#,
            &roles
        ));
        assert!(snapshot.statement_references_masked_column(
            r#"SELECT city || (SELECT u&"e\006dail" FROM demo.customers LIMIT 1) FROM demo.customers"#,
            &roles
        ));
        // Closed output: decode has to be what sees the name, because there
        // is no SubLink for Guard 7 to refuse.
        assert!(snapshot.statement_references_masked_column(
            r#"SELECT city FROM demo.customers WHERE u&"email" = 'x'"#,
            &roles
        ));
        assert!(snapshot.statement_references_masked_column(
            r#"SELECT city FROM demo.customers WHERE u&"e\006dail" = 'x'"#,
            &roles
        ));
        // A custom UESCAPE redefines the alphabet; the scan fails closed.
        assert!(snapshot.statement_references_masked_column(
            r#"SELECT u&"city" UESCAPE '!' FROM demo.customers"#,
            &roles
        ));

        // The system-relation set decides whether a whole result set is served
        // unmasked. Constant in either direction is a different failure: `true`
        // serves user tables, `false` silently disables GUI support.
        assert!(!snapshot.is_system_relation(16385));
        snapshot.insert_system_relation_for_test(1259);
        assert!(snapshot.is_system_relation(1259));
        assert!(!snapshot.is_system_relation(16385));
    }

    /// Hostile must treat default-deny columns like masked ones for predicates.
    ///
    /// `internal_note` is absent from the catalog on purpose (projection nulls
    /// it). Before 0.1.81 it was also absent from the hostile name set, so
    /// `WHERE internal_note = 'secret'` recovered the value. Uncatalogued
    /// tables had the same hole for every column.
    #[test]
    fn hostile_masked_names_include_unclassified_columns() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_relation_for_test(
            "demo.customers",
            &[
                ("id", Mask::None),
                ("email", Mask::Redact),
                ("city", Mask::None),
            ],
        );
        snapshot
            .relation_columns_for_test("demo.customers", &["id", "email", "internal_note", "city"]);
        snapshot.relation_columns_for_test("public.secrets", &["id", "token"]);

        let roles = HashSet::new();
        let names = snapshot.masked_bare_names_for_roles(&roles);
        assert!(names.contains("email"));
        assert!(names.contains("internal_note"));
        assert!(names.contains("token"));
        assert!(
            !names.contains("id"),
            "passthrough id must stay usable in WHERE"
        );
        assert!(
            !names.contains("city"),
            "passthrough city must stay usable in WHERE"
        );
    }

    /// The 16-byte floor on `pseudonym_key`, at its edge.
    ///
    /// Added in 0.1.9 after an unvalidated key made every pseudonym a
    /// recomputable HMAC with a zero key. `cargo mutants` flipped its `<` to
    /// `<=` and nothing noticed, so the boundary itself was never asserted.
    #[test]
    fn the_pseudonym_key_floor_is_exactly_sixteen_bytes() {
        let with_key = |bytes: usize| {
            let key = "k".repeat(bytes);
            let src = format!(
                "backend = \"h:1\"\ncatalog_dsn = \"d\"\npseudonym_key = \"{key}\"\nunclassified = \"allow\"\n"
            );
            let config: Config = toml::from_str(&src).expect("parses");
            config.validate_pseudonym_key()
        };
        assert!(with_key(15).is_err(), "15 bytes must be refused");
        assert!(with_key(16).is_ok(), "16 bytes is the documented floor");
        assert!(with_key(32).is_ok());
    }

    /// A summary over a singleton group is the value it summarised.
    ///
    /// `SELECT id, sum(annual_salary) FROM demo.customers GROUP BY id` returned
    /// every salary in the fixture exactly, in one query, byte-identical to
    /// reading the column directly. The group-of-one trade was recorded as an
    /// incidental edge case; grouping by a key makes it the bulk interface.
    #[test]
    fn grouping_by_a_unique_key_is_recognised() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_unique_key_for_test(&["id"]);
        snapshot.insert_unique_key_for_test(&["tenant", "email"]);

        assert!(snapshot.grouping_covers_a_unique_key(&["id".into()]));
        // A superset of a key still yields one row per group.
        assert!(snapshot.grouping_covers_a_unique_key(&["id".into(), "city".into()]));
        assert!(snapshot.grouping_covers_a_unique_key(&["tenant".into(), "email".into()]));

        // Real aggregation is untouched.
        assert!(!snapshot.grouping_covers_a_unique_key(&["city".into()]));
        // Part of a composite key is not the key.
        assert!(!snapshot.grouping_covers_a_unique_key(&["tenant".into()]));
        assert!(!snapshot.grouping_covers_a_unique_key(&[]));
    }

    /// The `system_catalogs = "allow"` fast path serves a whole result set
    /// unmasked, and its text check walks a tree that does not enter a
    /// `WindowDef`. This is what stops a user relation being smuggled through
    /// there.
    #[test]
    fn a_user_relation_named_anywhere_loses_the_catalog_fast_path() {
        let mut snapshot = Snapshot::default();
        snapshot.relation_columns_for_test("demo.customers", &["id", "email"]);

        // The shape the tree walk missed.
        assert!(snapshot.statement_mentions_user_relation(
            "SELECT relname, count(*) OVER (PARTITION BY (SELECT email FROM demo.customers LIMIT 1)) \
             FROM pg_catalog.pg_class"
        ));
        assert!(snapshot.statement_mentions_user_relation(
            "SELECT c.relname, x.email FROM pg_catalog.pg_class c, demo.customers x"
        ));
        // A genuine catalog query keeps it.
        assert!(!snapshot.statement_mentions_user_relation(
            "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
        ));
        // psql's introspection passes relation names as *string literals*, not
        // identifiers, which is why `\d demo.customers` still works.
        assert!(!snapshot.statement_mentions_user_relation(
            "SELECT c.oid FROM pg_catalog.pg_class c WHERE c.relname = 'customers'"
        ));
        // Unscannable text could name anything.
        assert!(snapshot.statement_mentions_user_relation("SELECT \u{0}"));
    }

    #[test]
    fn a_statement_selecting_from_an_opaque_view_is_flagged() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_opaque_view_for_test("sw.v_union");
        assert!(snapshot.statement_touches_opaque_view("SELECT v FROM sw.v_union"));
        assert!(snapshot.statement_touches_opaque_view(
            "SELECT q.v FROM (SELECT v FROM sw.v_union) q JOIN sw.t ON true"
        ));
        assert!(!snapshot.statement_touches_opaque_view("SELECT email FROM sw.t"));
        // Unparseable, with an opaque view present: we cannot see what it
        // references, so it must not read as clean.
        assert!(snapshot.statement_touches_opaque_view("SELECT FROM WHERE (("));
        // TABLESAMPLE erases the relation from the parse-tree walk this check
        // used to use, which silently un-guarded the set-operation view.
        assert!(snapshot
            .statement_touches_opaque_view("SELECT v FROM sw.v_union TABLESAMPLE SYSTEM (10)"));
    }

    /// With no opaque views at all, nothing is parsed and nothing is flagged —
    /// the common case must not pay for the check.
    #[test]
    fn no_opaque_views_means_no_statement_is_flagged() {
        let snapshot = Snapshot::default();
        assert!(!snapshot.statement_touches_opaque_view("SELECT FROM WHERE (("));
    }

    /// `unclassified_mask` selects the fallback *family*, not an arbitrary
    /// mask: `type-aware` (default) or strict `null`. A config carrying the
    /// pre-0.1.92 knob's `"null"` keeps its old strict meaning across the
    /// upgrade instead of failing to boot — a boot failure whose only remedy
    /// was deleting the line silently switched deployments to the looser
    /// policy. The old knob's other values (`"redact"`, `"none"`, …) stay
    /// rejected: none of them was a sound universal fallback.
    #[test]
    fn unclassified_mask_selects_type_aware_or_strict_null() {
        let base = r#"
backend = "127.0.0.1:2"
catalog_dsn = "postgres://x@y/z"
pseudonym_key = "a-long-enough-key"
"#;
        let config: Config = toml::from_str(base).expect("parses");
        assert_eq!(config.unclassified_mask, UnclassifiedMask::TypeAware);

        let config: Config =
            toml::from_str(&format!("{base}unclassified_mask = \"null\"\n")).expect("parses");
        assert_eq!(config.unclassified_mask, UnclassifiedMask::Null);

        let config: Config =
            toml::from_str(&format!("{base}unclassified_mask = \"type-aware\"\n")).expect("parses");
        assert_eq!(config.unclassified_mask, UnclassifiedMask::TypeAware);

        for old in ["none", "redact", "pseudonym", "hash"] {
            assert!(
                toml::from_str::<Config>(&format!("{base}unclassified_mask = \"{old}\"\n"))
                    .is_err(),
                "the old universal-mask value {old:?} must not parse"
            );
        }
    }

    #[test]
    fn common_config_checks_run_when_unclassified_columns_are_allowed() {
        let short_key = r#"
backend = "h:1"
catalog_dsn = "d"
pseudonym_key = "short"
unclassified = "allow"
"#;
        let config: Config = toml::from_str(short_key).expect("parses");
        let err = config.validate().expect_err("short key must be refused");
        assert!(format!("{err:#}").contains("at least 16 bytes"));

        let duplicate_rule = r#"
backend = "h:1"
catalog_dsn = "d"
pseudonym_key = "a-long-enough-key"
unclassified = "allow"

[[column]]
relation = "s.t"
column = "email"
mask = "redact"

[[column]]
relation = "S.T"
column = "EMAIL"
mask = "none"
"#;
        let config: Config = toml::from_str(duplicate_rule).expect("parses");
        let err = config
            .validate()
            .expect_err("duplicate rules must be refused");
        assert!(format!("{err:#}").contains("duplicate rule"));
    }

    /// Both edges of every parameter guard, including the values `classify`
    /// emits.
    ///
    /// `outer` had a boundary test; `numeric-bucket` and `range` did not, and
    /// the campaign duly reported `bucket < 2` -> `<= 2` and the whole `range`
    /// guard -> `true` as surviving. Over-rejection here is fail-closed, and it
    /// would also mean the catalog `classify` writes no longer loads — it emits
    /// `bucket = 1000` and `start = 2, end = 64`, and nothing connected the two
    /// crates.
    #[test]
    fn every_parameter_guard_is_tested_on_both_sides_of_its_edge() {
        let bucket = |b: i64| {
            let mut spec = MaskSpec::new(Mask::NumericBucket);
            spec.bucket = b;
            validate_spec(&spec, "s.t.c")
        };
        assert!(bucket(1).is_err(), "1 floors every value to itself");
        assert!(bucket(2).is_ok(), "2 is the smallest bucket that masks");
        assert!(bucket(1000).is_ok(), "what classify emits");
        assert!(bucket(0).is_err());
        assert!(bucket(-5).is_err());

        let range = |start: u16, end: u16| {
            let mut spec = MaskSpec::new(Mask::Range);
            spec.start = start;
            spec.end = end;
            validate_spec(&spec, "s.t.c")
        };
        assert!(range(2, 2).is_err(), "an empty window masks nothing");
        assert!(range(3, 2).is_err(), "an inverted window masks nothing");
        assert!(
            range(2, 3).is_ok(),
            "one character wide is the smallest that masks"
        );
        assert!(range(2, 64).is_ok(), "what classify emits for a postcode");
        assert!(range(0, 1).is_ok());
    }

    #[test]
    fn outer_with_keep_zero_is_refused() {
        let mut spec = MaskSpec::new(Mask::Outer);
        spec.keep = 0;
        assert!(validate_spec(&spec, "s.t.c").is_err());
        spec.keep = 1;
        assert!(validate_spec(&spec, "s.t.c").is_ok());
    }

    #[test]
    fn config_parses_semantic_types_roles_and_params() {
        let toml_src = r#"
backend = "h:1"
catalog_dsn = "d"
pseudonym_key = "k"

[[role]]
name = "support"
members = ["sam"]

[[semantic_type]]
name = "email"
mask = "pseudonym"
keep = 3
by_role = { support = "inner" }

[[column]]
relation = "s.t"
column = "email"
type = "email"
by_role = { analyst = "partial" }
"#;
        let cfg: crate::catalog::Config = toml::from_str(toml_src).expect("should parse");
        assert_eq!(cfg.semantic_type.len(), 1, "semantic types");
        assert_eq!(cfg.role.len(), 1, "roles");
        assert_eq!(
            cfg.semantic_type[0].params.keep,
            Some(3),
            "flattened params on semantic type"
        );
        assert_eq!(
            cfg.semantic_type[0].by_role.get("support"),
            Some(&crate::mask::Mask::Inner),
            "by_role on semantic type"
        );
        assert_eq!(
            cfg.column[0].by_role.get("analyst"),
            Some(&crate::mask::Mask::Partial),
            "by_role on column"
        );
        assert_eq!(cfg.column[0].semantic_type.as_deref(), Some("email"));
    }

    #[test]
    fn neon_verify_full_is_adapted_without_dropping_channel_binding() {
        let (out, note) = sanitize_catalog_dsn(
            "postgresql://u:p@h/db?sslmode=verify-full&channel_binding=require&options=-c%20x",
        );
        assert!(out.contains("channel_binding=require"), "got: {out}");
        assert!(
            out.contains("sslmode=require"),
            "tokio-postgres receives its supported spelling: {out}"
        );
        assert!(
            out.contains("options=-c%20x"),
            "other params survive: {out}"
        );
        assert!(note.is_some(), "the rewrite must be announced");
        assert!(catalog_dsn_verifies_server(
            "postgresql://u:p@h/db?sslmode=verify-full&channel_binding=require"
        ));
    }

    #[test]
    fn a_dsn_without_channel_binding_is_untouched() {
        let dsn = "postgresql://u:p@h/db?sslmode=require";
        let (out, note) = sanitize_catalog_dsn(dsn);
        assert_eq!(out, dsn);
        assert!(note.is_none());
    }

    #[test]
    fn channel_binding_without_a_verify_mode_is_untouched() {
        let dsn =
            sanitize_catalog_dsn("postgresql://u:p@h/db?channel_binding=require&sslmode=require");
        assert_eq!(
            dsn.0,
            "postgresql://u:p@h/db?channel_binding=require&sslmode=require"
        );
        assert!(dsn.1.is_none());
    }

    #[test]
    fn verify_ca_uses_the_stronger_verify_full_connector() {
        let dsn = "postgresql://u:p@h/db?sslmode=verify-ca";
        let (out, note) = sanitize_catalog_dsn(dsn);
        assert_eq!(out, "postgresql://u:p@h/db?sslmode=require");
        assert!(note.is_some());
        assert!(catalog_dsn_verifies_server(dsn));
    }

    #[test]
    fn classified_column_names_strips_the_relation() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_for_test(1, 1, Mask::Redact, "public.customers.email");
        let names = snapshot.classified_column_names();
        assert!(names.contains("email"));
        assert!(!names.contains("public.customers.email"));
    }

    #[test]
    fn knows_relation_distinguishes_unknown_from_unclassified() {
        let mut snapshot = Snapshot::default();
        snapshot.insert_for_test(42, 1, Mask::Redact, "public.t.email");
        // Same relation, a column we did not classify: known relation.
        assert!(snapshot.knows_relation(42));
        assert!(snapshot.lookup(42, 2).is_none());
        // A relation we have never resolved at all.
        assert!(!snapshot.knows_relation(99));
    }
}

#[cfg(test)]
mod secret_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn debug_printing_the_config_cannot_reveal_the_key() {
        // `Config` derives Debug and the key is the whole basis of pseudonym
        // unlinkability, so one `{config:?}` would be a disclosure that costs a
        // rotation to recover from. This is the guard on that.
        let config: Config = toml::from_str(
            r#"
backend = "h:1"
catalog_dsn = "d"
pseudonym_key = "correct-horse-battery-staple"
"#,
        )
        .expect("parses");
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("correct-horse-battery-staple"),
            "the key appeared in Debug output: {rendered}"
        );
        assert!(rendered.contains("REDACTED"));
    }
    /// The smallest config that loads, plus whatever the test is about.
    fn tls_test_config(extra: &str) -> Config {
        let src = format!(
            r#"
listen = "127.0.0.1:1"
backend = "127.0.0.1:2"
catalog_dsn = "postgres://x@y/z"
pseudonym_key = "a-long-enough-key"
{extra}"#
        );
        toml::from_str(&src).expect("parses")
    }

    #[test]
    fn a_configured_certificate_is_a_required_certificate() {
        // The default is the whole point of the field. An operator who sets up
        // TLS has expressed an intent; leaving it optional means one client
        // flag silently undoes it, and the startup log still says tls=true.
        let mut config = tls_test_config("");
        assert!(
            !config.client_tls_required(),
            "no certificate: nothing to require"
        );

        config.tls_cert = Some("/tmp/cert.pem".into());
        config.tls_key = Some("/tmp/key.pem".into());
        assert!(
            config.client_tls_required(),
            "a certificate with no explicit setting must be required"
        );

        config.require_client_tls = Some(false);
        assert!(
            !config.client_tls_required(),
            "an operator can still opt out, but has to say so"
        );

        config.require_client_tls = Some(true);
        assert!(config.client_tls_required());
    }

    #[test]
    fn requiring_tls_without_a_certificate_is_refused_at_load() {
        let mut config = tls_test_config("require_client_tls = true\n");
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("no tls_cert"),
            "the error must name the missing piece, got: {err}"
        );

        // ...and is fine once the certificate is there. Paths are not read
        // during validation, only during acceptor construction.
        config.tls_cert = Some("/tmp/cert.pem".into());
        config.tls_key = Some("/tmp/key.pem".into());
        config
            .validate()
            .expect("a required certificate that exists");
    }

    #[test]
    fn requiring_tls_is_not_defaulted_on_for_a_plaintext_deployment() {
        // The counterpart to the test above: adding this knob must not turn a
        // working certificate-free deployment into one that refuses everyone.
        let config = tls_test_config("");
        assert_eq!(config.require_client_tls, None);
        assert!(!config.client_tls_required());
        config.validate().expect("plaintext deployments still load");
    }

    #[test]
    fn hostile_posture_forces_summaries_refuse() {
        let config = tls_test_config("posture = \"hostile\"\nsummaries = \"allow\"\n");
        assert_eq!(config.posture, Posture::Hostile);
        assert_eq!(config.summaries, Summaries::Allow);
        assert_eq!(config.effective_summaries(), Summaries::Refuse);
    }

    #[test]
    fn backend_ca_without_verify_full_is_refused() {
        let config = tls_test_config("backend_tls = \"require\"\nbackend_ca = \"/tmp/ca.pem\"\n");
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("verify-full"),
            "must name the missing mode, got: {err}"
        );
    }

    #[test]
    fn only_a_concurrent_ddl_race_is_retried() {
        // The retry has to be narrow. Retrying a bad DSN, a refused
        // connection, or a permissions error would turn a clear startup
        // failure into a slow one with the reason buried in a warning.
        for text in [
            "db error: ERROR: could not open relation with OID 17041",
            "loading view definitions: cache lookup failed for relation 17041",
        ] {
            assert!(
                is_concurrent_ddl_race(&anyhow::anyhow!("{text}")),
                "should retry: {text}"
            );
        }
        for text in [
            "password authentication failed for user \"pgmask\"",
            "connection refused",
            "permission denied for schema crm",
            "relation \"demo.customers\" does not exist",
            "invalid dsn",
        ] {
            assert!(
                !is_concurrent_ddl_race(&anyhow::anyhow!("{text}")),
                "must not retry: {text}"
            );
        }
    }

    #[test]
    fn the_race_is_recognised_through_a_context_chain() {
        // resolve_snapshot wraps the driver error in `.context("loading view
        // definitions")`, so the text only appears via the `{:#}` alternate
        // form. Matching on `to_string()` would have missed every real case
        // while passing a test written against a bare error.
        let inner = anyhow::anyhow!("db error: ERROR: could not open relation with OID 17041");
        let wrapped = inner.context("loading view definitions");
        assert!(is_concurrent_ddl_race(&wrapped));
        assert!(
            !wrapped.to_string().contains("could not open relation"),
            "if this ever fails the alternate-form subtlety is gone and the \
             comment above should go with it"
        );
    }

    #[test]
    fn rate_limit_burst_without_per_minute_is_refused() {
        let config = tls_test_config("rate_limit_burst = 5");
        let err = config.validate().expect_err("burst alone is a noop config");
        assert!(
            err.to_string().contains("rate_limit_per_minute"),
            "got: {err}"
        );
    }

    #[test]
    fn rate_limit_burst_defaults_to_per_minute() {
        let config = tls_test_config("rate_limit_per_minute = 30");
        config.validate().expect("valid");
        assert_eq!(config.effective_rate_limit_burst(), 30);
        let with_burst = tls_test_config(
            r#"
rate_limit_per_minute = 30
rate_limit_burst = 5
"#,
        );
        assert_eq!(with_burst.effective_rate_limit_burst(), 5);
    }
}
