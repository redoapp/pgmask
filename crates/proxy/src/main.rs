//! pgmask — a fail-closed column masking proxy for Postgres.
//!
//!   pgmask <config.toml>

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;

use pgmask::{Catalog, Config, Policy};

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: pgmask <config.toml>")?;
    let config = Config::load(&path)?;

    // Resolving the catalog before binding is deliberate: a proxy that starts
    // with a half-loaded catalog is a proxy with unknown coverage.
    let catalog = Arc::new(
        Catalog::resolve(&config.column, &config.semantic_type, &config.catalog_dsn)
            .await
            .context("resolving the column catalog")?,
    );

    let policy = Arc::new(Policy::from_config(&config, catalog.clone())?);
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;

    eprintln!(
        "pgmask listening on {} -> {} | {} classified column(s) | \
         unclassified={:?} opaque={:?} tls={} backend_tls={:?}",
        config.listen,
        config.backend,
        catalog.len(),
        config.unclassified,
        config.opaque,
        if policy.tls.is_some() { "on" } else { "OFF" },
        config.backend_tls,
    );
    eprintln!(
        "  {} semantic type(s), {} role(s), {} principal(s) with a role",
        config.semantic_type.len(),
        config.role.len(),
        policy.roles.len(),
    );
    if policy.tls.is_none() {
        eprintln!(
            "warning: no tls_cert/tls_key — clients connect in plaintext, and a masking \
             proxy reachable in plaintext is not a security boundary"
        );
    }
    if catalog.is_empty() {
        eprintln!("warning: the catalog is empty — every column will be treated as unclassified");
    }

    // Keep the catalog current. OIDs are not stable across DDL: DROP+CREATE of
    // a view hands it a new OID, and a catalog pinned at boot then silently
    // stops classifying those columns.
    tokio::spawn(catalog.clone().run_refresher(
        Duration::from_secs(config.catalog_refresh_seconds),
        Duration::from_secs(config.catalog_refresh_min_seconds),
    ));

    // Rejection counters, bucketed by cause. These are the numbers that decide
    // whether the Phase 6 parser is worth building; see docs/handoff.md.
    if config.metrics_interval_seconds > 0 {
        let metrics = policy.metrics.clone();
        let interval = Duration::from_secs(config.metrics_interval_seconds);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Some(line) = metrics.report() {
                    eprintln!("pgmask metrics: {line}");
                }
            }
        });
    }

    let backend = Arc::new(config.backend.clone());
    loop {
        let (client, peer) = listener.accept().await?;
        let policy = policy.clone();
        let backend = backend.clone();
        tokio::spawn(async move {
            if let Err(err) = pgmask::handle_connection(client, &backend, policy).await {
                eprintln!("connection from {peer} ended: {err:#}");
            }
        });
    }
}
