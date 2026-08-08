//! pgmask — a fail-closed column masking proxy for Postgres.
//!
//!   pgmask <config.toml>

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;

use pgmask::{Catalog, Config, Policy};
use tracing::Instrument;
use tracing_subscriber::EnvFilter;

/// Structured logging, filtered by `PGMASK_LOG` (falling back to `RUST_LOG`).
///
/// Written to stderr so stdout stays clean, and *without* ANSI when stderr is
/// not a terminal, because these lines end up in journald and log shippers far
/// more often than in a human's scrollback.
fn init_logging() {
    let filter = EnvFilter::try_from_env("PGMASK_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

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

    tracing::info!(
        listen = %config.listen,
        backend = %config.backend,
        classified_columns = catalog.len(),
        semantic_types = config.semantic_type.len(),
        roles = config.role.len(),
        principals_with_a_role = policy.roles.len(),
        unclassified = ?config.unclassified,
        opaque = ?config.opaque,
        system_catalogs = ?config.system_catalogs,
        summaries = ?config.summaries,
        tls = policy.tls.is_some(),
        backend_tls = ?config.backend_tls,
        "pgmask listening"
    );
    if policy.tls.is_none() {
        tracing::warn!(
            "no tls_cert/tls_key — clients connect in plaintext, and a masking proxy \
             reachable in plaintext is not a security boundary"
        );
    }
    if catalog.is_empty() {
        tracing::warn!("the catalog is empty — every column will be treated as unclassified");
    }

    // Keep the catalog current. OIDs are not stable across DDL: DROP+CREATE of
    // a view hands it a new OID, and a catalog pinned at boot then silently
    // stops classifying those columns.
    tokio::spawn(catalog.clone().run_refresher(
        Duration::from_secs(config.catalog_refresh_seconds),
        Duration::from_secs(config.catalog_refresh_min_seconds),
    ));

    // A Prometheus scrape endpoint, when one is configured. The periodic log
    // line below stays regardless: it needs no scraper, and reading it is how
    // the rejection-cause question got answered in the first place.
    if let Some(addr) = &config.metrics_listen {
        let socket: std::net::SocketAddr = addr
            .parse()
            .with_context(|| format!("parsing metrics_listen {addr:?}"))?;
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(socket)
            .install()
            .with_context(|| format!("starting the metrics exporter on {socket}"))?;
        pgmask::metrics::describe();
        tracing::info!(%socket, "serving Prometheus metrics at /metrics");
    }

    // Rejection counters, bucketed by cause. These are the numbers that decide
    // whether the Phase 6 parser is worth building; see docs/handoff.md.
    if config.metrics_interval_seconds > 0 {
        let metrics = policy.metrics.clone();
        let interval = Duration::from_secs(config.metrics_interval_seconds);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Some(line) = metrics.report() {
                    tracing::info!("pgmask metrics: {line}");
                }
            }
        });
    }

    let backend = Arc::new(config.backend.clone());
    loop {
        let (client, peer) = listener.accept().await?;
        let policy = policy.clone();
        let backend = backend.clone();
        // `.instrument()`, not `span.enter()`: an entered guard does not follow
        // a task across an await point, so a held guard would attribute lines
        // from whichever session happened to be running to this one.
        tokio::spawn(
            async move {
                if let Err(err) = pgmask::handle_connection(client, &backend, policy).await {
                    tracing::warn!(error = format!("{err:#}"), "connection ended");
                }
            }
            .instrument(tracing::info_span!("session", %peer)),
        );
    }
}
