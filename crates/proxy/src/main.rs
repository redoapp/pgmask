//! pgmask — a fail-closed column masking proxy for Postgres.
//!
//!   pgmask <config.toml>

mod catalog;
mod mask;
mod protocol;
mod session;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;

use catalog::{Catalog, Config};
use session::Policy;

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: pgmask <config.toml>")?;
    let config = Config::load(&path)?;

    // Resolving the catalog before binding is deliberate: a proxy that starts
    // with a half-loaded catalog is a proxy with unknown coverage.
    let catalog = Arc::new(
        Catalog::resolve(&config.column, &config.catalog_dsn)
            .await
            .context("resolving the column catalog")?,
    );

    let policy = Arc::new(Policy::from_config(&config, catalog.clone()));
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;

    eprintln!(
        "pgmask listening on {} -> {} | {} classified column(s) | unclassified={:?} opaque={:?}",
        config.listen,
        config.backend,
        catalog.len(),
        config.unclassified,
        config.opaque,
    );
    if catalog.is_empty() {
        eprintln!("warning: the catalog is empty — every column will be treated as unclassified");
    }

    let backend = Arc::new(config.backend.clone());
    loop {
        let (client, peer) = listener.accept().await?;
        let policy = policy.clone();
        let backend = backend.clone();
        tokio::spawn(async move {
            if let Err(err) = session::handle_connection(client, &backend, policy).await {
                eprintln!("connection from {peer} ended: {err:#}");
            }
        });
    }
}
