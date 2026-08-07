//! Configuration and the column classification catalog.
//!
//! The catalog is keyed on `(pg_class OID, attnum)` because that is what the
//! wire gives us — never on output column name, which any query can rename.
//!
//! Names are resolved to OIDs once at startup. If a configured column does not
//! exist the proxy refuses to start: a catalog that silently half-loaded is a
//! catalog with unknown coverage.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnRule {
    /// Schema-qualified, e.g. `demo.customers`.
    pub relation: String,
    pub column: String,
    pub mask: Mask,
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
    /// Used once at startup to resolve names to OIDs.
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

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        toml::from_str(&text).with_context(|| format!("parsing {path}"))
    }
}

/// Resolved classification, ready for the hot path.
#[derive(Debug, Default)]
pub struct Catalog {
    by_column: HashMap<(u32, i16), Mask>,
    /// For diagnostics only.
    names: HashMap<(u32, i16), String>,
}

impl Catalog {
    pub fn lookup(&self, table_oid: u32, column_id: i16) -> Option<Mask> {
        self.by_column.get(&(table_oid, column_id)).copied()
    }

    pub fn name_of(&self, table_oid: u32, column_id: i16) -> Option<&str> {
        self.names.get(&(table_oid, column_id)).map(String::as_str)
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
    }

    /// Resolve every configured `relation.column` to `(oid, attnum)`.
    ///
    /// Views and materialized views are included deliberately: Phase 0 showed
    /// Postgres reports the *view's* OID, not the base table's, so a catalog
    /// with only base tables would leave every view unclassified.
    pub async fn resolve(rules: &[ColumnRule], dsn: &str) -> Result<Self> {
        if rules.is_empty() {
            return Ok(Self::default());
        }
        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .context("connecting with catalog_dsn to resolve column OIDs")?;
        tokio::spawn(async move {
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

        let mut catalog = Self::default();
        let mut missing = Vec::new();
        for rule in rules {
            match resolved.get(&(rule.relation.clone(), rule.column.clone())) {
                Some(&(oid, attnum)) => {
                    catalog.by_column.insert((oid, attnum), rule.mask);
                    catalog
                        .names
                        .insert((oid, attnum), format!("{}.{}", rule.relation, rule.column));
                }
                None => missing.push(format!("{}.{}", rule.relation, rule.column)),
            }
        }

        if !missing.is_empty() {
            bail!(
                "catalog references {} column(s) that do not exist: {}. \
                 Refusing to start — a half-loaded catalog has unknown coverage.",
                missing.len(),
                missing.join(", ")
            );
        }

        Ok(catalog)
    }
}
