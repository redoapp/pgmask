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

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::sync::Notify;

use crate::mask::Mask;

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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnRule {
    /// Schema-qualified, e.g. `demo.customers`.
    pub relation: String,
    pub column: String,
    pub mask: Mask,
}

impl ColumnRule {
    fn key(&self) -> (String, String) {
        (self.relation.clone(), self.column.clone())
    }

    fn display(&self) -> String {
        format!("{}.{}", self.relation, self.column)
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
    pub pseudonym_key: String,
    #[serde(default = "default_unclassified")]
    pub unclassified: Unclassified,
    #[serde(default = "default_opaque")]
    pub opaque: Opaque,
    /// Mask applied to unclassified columns when `unclassified = "mask"`.
    #[serde(default = "default_unclassified_mask")]
    pub unclassified_mask: Mask,
    #[serde(default)]
    pub column: Vec<ColumnRule>,
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

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        toml::from_str(&text).with_context(|| format!("parsing {path}"))
    }
}

/// One consistent view of the classification, swapped atomically on refresh.
#[derive(Debug, Default)]
pub struct Snapshot {
    by_column: HashMap<(u32, i16), Mask>,
    names: HashMap<(u32, i16), String>,
    /// Relation OIDs we know about, so an unknown one can be told apart from a
    /// relation we resolved whose column is merely unclassified.
    relations: HashSet<u32>,
    /// Rules that failed to resolve on the most recent attempt.
    unresolved: Vec<String>,
}

impl Snapshot {
    pub fn lookup(&self, table_oid: u32, column_id: i16) -> Option<Mask> {
        self.by_column.get(&(table_oid, column_id)).copied()
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
    pub fn insert_for_test(&mut self, table_oid: u32, column_id: i16, mask: Mask, name: &str) {
        self.by_column.insert((table_oid, column_id), mask);
        self.names.insert((table_oid, column_id), name.to_string());
        self.relations.insert(table_oid);
    }
}

/// The live catalog: a swappable snapshot plus the machinery to keep it current.
pub struct Catalog {
    rules: Vec<ColumnRule>,
    dsn: String,
    snapshot: RwLock<Arc<Snapshot>>,
    /// Woken when the hot path sees a relation OID we do not recognise.
    refresh_wanted: Notify,
    pub refreshes: AtomicU64,
    pub failed_refreshes: AtomicU64,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            dsn: String::new(),
            snapshot: RwLock::new(Arc::new(Snapshot::default())),
            refresh_wanted: Notify::new(),
            refreshes: AtomicU64::new(0),
            failed_refreshes: AtomicU64::new(0),
        }
    }
}

impl Catalog {
    /// Resolve for the first time. Fails if any rule names a column that does
    /// not exist: a catalog that silently half-loaded has unknown coverage.
    pub async fn resolve(rules: &[ColumnRule], dsn: &str) -> Result<Self> {
        let resolved = resolve_snapshot(rules, dsn).await?;
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
            dsn: dsn.to_string(),
            snapshot: RwLock::new(Arc::new(resolved)),
            ..Default::default()
        })
    }

    #[cfg(test)]
    pub fn from_snapshot_for_test(snapshot: Snapshot) -> Self {
        Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            ..Default::default()
        }
    }

    /// A stable view for the duration of one `RowDescription`.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.read().expect("catalog lock poisoned").clone()
    }

    pub fn lookup(&self, table_oid: u32, column_id: i16) -> Option<Mask> {
        self.snapshot().lookup(table_oid, column_id)
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
        let next = match resolve_snapshot(&self.rules, &self.dsn).await {
            Ok(next) => next,
            Err(err) => {
                self.failed_refreshes.fetch_add(1, Ordering::Relaxed);
                // Deliberately keep the old snapshot. Clearing it would be
                // fail-closed in the narrow sense and would mask every column in
                // the database the moment Postgres blinked.
                eprintln!(
                    "catalog refresh FAILED, continuing with the previous snapshot \
                     ({} classified columns): {err:#}",
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
                (Some(b), Some(a)) if b != a => eprintln!(
                    "catalog: {} moved (oid.attnum {}.{} -> {}.{}) — relation recreated, \
                     classification restored",
                    rule.display(),
                    b.0,
                    b.1,
                    a.0,
                    a.1
                ),
                (Some(b), None) => eprintln!(
                    "catalog: COVERAGE LOST for {} (was oid.attnum {}.{}) — the relation or \
                     column no longer exists; those values are now unclassified",
                    rule.display(),
                    b.0,
                    b.1
                ),
                (None, Some(a)) => eprintln!(
                    "catalog: coverage restored for {} (oid.attnum {}.{})",
                    rule.display(),
                    a.0,
                    a.1
                ),
                _ => {}
            }
        }

        let changed = next.by_column != previous.by_column;
        let count = next.len();
        *self.snapshot.write().expect("catalog lock poisoned") = Arc::new(next);
        self.refreshes.fetch_add(1, Ordering::Relaxed);
        if changed {
            eprintln!("catalog refreshed: {count} classified column(s)");
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
                    let since = last.elapsed();
                    if since < min_interval {
                        tokio::time::sleep(min_interval - since).await;
                    }
                }
            }
            last = Instant::now();
            let _ = self.refresh().await;
        }
    }
}

async fn resolve_snapshot(rules: &[ColumnRule], dsn: &str) -> Result<Snapshot> {
    if rules.is_empty() {
        return Ok(Snapshot::default());
    }
    let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .context("connecting with catalog_dsn to resolve column OIDs")?;
    let handle = tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("catalog connection error: {err}");
        }
    });

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

    let mut snapshot = Snapshot::default();
    for rule in rules {
        match resolved.get(&rule.key()) {
            Some(&(oid, attnum)) => {
                snapshot.by_column.insert((oid, attnum), rule.mask);
                snapshot.names.insert((oid, attnum), rule.display());
                snapshot.relations.insert(oid);
            }
            None => snapshot.unresolved.push(rule.display()),
        }
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(snapshot.lookup(42, 2), None);
        // A relation we have never resolved at all.
        assert!(!snapshot.knows_relation(99));
    }
}
