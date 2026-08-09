//! Configuration and the column classification catalog.
//!
//! The catalog is keyed on `(pg_class OID, attnum)` because that is what the
//! wire gives us — never on output column name, which any query can rename.
//!
//! Names are resolved to OIDs at startup and **re-resolved periodically**,
//! because OIDs are not stable across DDL. `CREATE OR REPLACE VIEW` keeps a
//! relation's OID but `DROP VIEW; CREATE VIEW` does not, and plenty of migration
//! tooling does the latter. A catalog pinned at boot silently loses coverage the
//! first time that happens: with `unclassified = "mask"` the columns quietly turn
//! to NULL, and with `unclassified = "allow"` they quietly stop being masked.

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use secrecy::SecretString;
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
        let mut chosen: Option<&MaskSpec> = None;
        for role in roles {
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
    #[serde(default = "default_opaque")]
    pub opaque: Opaque,
    /// Mask applied to unclassified columns when `unclassified = "mask"`.
    #[serde(default = "default_unclassified_mask")]
    pub unclassified_mask: Mask,
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
    /// Whether to encrypt the proxy-to-Postgres leg.
    #[serde(default)]
    pub backend_tls: crate::tls::BackendTls,
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
    /// roughly 90% of analytical SQL.
    #[serde(default = "default_summaries")]
    pub summaries: Summaries,
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
fn default_unclassified_mask() -> Mask {
    Mask::Null
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
        toml::from_str(&text).with_context(|| format!("parsing {path}"))
    }
}

/// One consistent view of the classification, swapped atomically on refresh.
#[derive(Debug, Default)]
pub struct Snapshot {
    by_column: HashMap<(u32, i16), Classification>,
    names: HashMap<(u32, i16), String>,
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

    pub fn name_of(&self, table_oid: u32, column_id: i16) -> Option<&str> {
        self.names.get(&(table_oid, column_id)).map(String::as_str)
    }

    pub fn knows_relation(&self, table_oid: u32) -> bool {
        self.relations.contains(&table_oid)
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
        self.relations.insert(table_oid);
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
        let resolved = resolve_snapshot(rules, &types, dsn).await?;
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
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    pub fn name_of(&self, table_oid: u32, column_id: i16) -> Option<String> {
        self.snapshot()
            .name_of(table_oid, column_id)
            .map(str::to_string)
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
        let next = match resolve_snapshot(&self.rules, &self.types, &self.dsn).await {
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

/// Make a libpq connection string usable by the catalog connection.
///
/// Managed providers hand out DSNs with `channel_binding=require` — Neon does
/// it by default. Channel binding ties authentication to the TLS certificate of
/// the endpoint the client is talking to, and pgmask terminates TLS by design,
/// so the requirement can never be satisfied and the driver fails with the
/// wonderfully unhelpful "server did not use channel binding".
///
/// Rather than make every operator discover that, rewrite it to `disable` and
/// say so once. The proxy-to-backend leg is still encrypted; what is given up is
/// the ability to *detect* an endpoint that re-originates TLS, which is exactly
/// what this process is. See `docs/phase4.md`.
pub fn sanitize_catalog_dsn(dsn: &str) -> (String, Option<&'static str>) {
    if !dsn.contains("channel_binding") {
        return (dsn.to_string(), None);
    }
    let rewritten = dsn
        .split('&')
        .map(|part| {
            let key = part.rsplit('?').next().unwrap_or(part);
            if key.starts_with("channel_binding=") {
                part.replace(key, "channel_binding=disable")
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    (
        rewritten,
        Some(
            "catalog_dsn requested channel_binding; rewritten to disable — pgmask \
             terminates TLS, so channel binding can never be satisfied through it",
        ),
    )
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
        _ => Ok(()),
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
    let connector =
        tokio_postgres_rustls::MakeRustlsConnect::new(crate::tls::backend_client_config());
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
    // per refresh, and lineage cannot resolve anything without it.
    let mut relation_columns: HashMap<String, Vec<String>> = HashMap::new();
    for row in client
        .query(
            "SELECT n.nspname || '.' || c.relname AS relation, a.attname AS column
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_attribute a ON a.attrelid = c.oid
              WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                AND n.nspname NOT LIKE 'pg_temp%'
                AND a.attnum > 0
                AND NOT a.attisdropped
                AND c.relkind = ANY('{r,v,m,p,f}')
              ORDER BY 1, a.attnum",
            &[],
        )
        .await
        .context("loading relation column lists")?
    {
        let relation: String = row.get("relation");
        let column: String = row.get("column");
        relation_columns
            .entry(relation.to_ascii_lowercase())
            .or_default()
            .push(column.to_ascii_lowercase());
    }

    if rules.is_empty() {
        let snapshot = Snapshot {
            system_relations,
            relation_columns,
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
        system_relations,
        relation_columns,
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
    fn channel_binding_is_rewritten_not_dropped() {
        let (out, note) = sanitize_catalog_dsn(
            "postgresql://u:p@h/db?sslmode=require&channel_binding=require&options=-c%20x",
        );
        assert!(out.contains("channel_binding=disable"), "got: {out}");
        assert!(
            out.contains("sslmode=require"),
            "other params survive: {out}"
        );
        assert!(
            out.contains("options=-c%20x"),
            "other params survive: {out}"
        );
        assert!(note.is_some(), "the rewrite must be announced");
    }

    #[test]
    fn a_dsn_without_channel_binding_is_untouched() {
        let dsn = "postgresql://u:p@h/db?sslmode=require";
        let (out, note) = sanitize_catalog_dsn(dsn);
        assert_eq!(out, dsn);
        assert!(note.is_none());
    }

    #[test]
    fn channel_binding_as_the_first_parameter_is_handled() {
        let (out, _) =
            sanitize_catalog_dsn("postgresql://u:p@h/db?channel_binding=require&sslmode=require");
        assert!(out.contains("channel_binding=disable"), "got: {out}");
        assert!(out.contains("sslmode=require"), "got: {out}");
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
}
