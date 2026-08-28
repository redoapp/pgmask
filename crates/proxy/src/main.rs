//! pgmask — a fail-closed column masking proxy for Postgres.
//!
//!   pgmask <config.toml>
//!   pgmask --version

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
    let path = match std::env::args().nth(1).as_deref() {
        None => anyhow::bail!("{}", usage()),
        Some("-V" | "--version") => {
            println!("pgmask {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("-h" | "--help") => {
            println!("{}", usage());
            return Ok(());
        }
        Some(flag) if flag.starts_with('-') => {
            anyhow::bail!("unrecognised option {flag}\n{}", usage());
        }
        Some(path) => path.to_owned(),
    };

    init_logging();

    let config = Config::load(&path)?;

    // Resolving the catalog before binding is deliberate: a proxy that starts
    // with a half-loaded catalog is a proxy with unknown coverage.
    let column_rules: Vec<_> = config.column_rules().cloned().collect();
    let catalog = Arc::new(
        Catalog::resolve(&column_rules, &config.semantic_type, &config.catalog_dsn)
            .await
            .context("resolving the column catalog")?,
    );

    let policy = Arc::new(Policy::from_config(&config, catalog.clone())?);
    if let Ok(bytes) = std::fs::read(&path) {
        policy.remember_file_bytes(&bytes);
    }
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;

    tracing::info!(
        listen = %config.listen,
        backend = %config.backend,
        classified_columns = catalog.len(),
        semantic_types = config.semantic_type.len(),
        roles = config.role.len(),
        principals_with_a_role = policy.role_count(),
        unclassified = ?config.unclassified,
        opaque = ?config.opaque,
        system_catalogs = ?config.system_catalogs,
        summaries = ?config.effective_summaries(),
        posture = ?config.posture,
        rate_limit_per_minute = config.rate_limit_per_minute,
        rate_limit_burst = config.effective_rate_limit_burst(),
        max_notices_per_exchange = config.max_notices_per_exchange,
        tls = policy.client_tls_configured(),
        tls_required = policy.client_tls_required(),
        backend_tls = ?config.backend_tls,
        "pgmask listening"
    );
    if !policy.client_tls_configured() {
        tracing::warn!(
            "no tls_cert/tls_key — clients connect in plaintext, and a masking proxy \
             reachable in plaintext is not a security boundary"
        );
    } else if !policy.client_tls_required() {
        // The dangerous configuration is not "no certificate", which is a
        // choice. It is "a certificate that any client may decline", which
        // looks like protection in the startup log and in the config file.
        tracing::warn!(
            "require_client_tls = false — a certificate is configured but not required, \
             so any client may connect with sslmode=disable and read masked output in \
             plaintext. Such sessions are counted by pgmask_plaintext_sessions_total"
        );
    }
    if catalog.is_empty() {
        tracing::warn!("the catalog is empty — every column will be treated as unclassified");
    }

    // Keep the catalog current. OIDs are not stable across DDL: DROP+CREATE of
    // a view hands it a new OID, and a catalog pinned at boot then silently
    // stops classifying those columns.
    tokio::spawn(catalog.clone().run_refresher());
    tokio::spawn({
        let policy = policy.clone();
        let config_path = path.clone();
        async move {
            config_reload_loop(policy, config_path).await;
        }
    });

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
        let metrics = policy.metrics();
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
        // Stop accepting on a shutdown signal and return, rather than being
        // killed mid-loop. A rolling deploy sends SIGTERM and expects the
        // process to go quietly; a SIGKILL-shaped exit also skips every
        // at-exit hook, which is how a coverage run of this binary came back
        // reading 0% on every module.
        let (client, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = shutdown_signal() => {
                tracing::info!("shutting down: no longer accepting connections");
                return Ok(());
            }
        };
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

fn usage() -> &'static str {
    "usage: pgmask [--version] <config.toml>"
}

/// Re-read the catalog file on SIGHUP. A failed reload keeps the previous policy.
async fn config_reload_loop(policy: Arc<Policy>, path: String) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(error = %err, "cannot listen for SIGHUP");
            return;
        }
    };
    loop {
        let Some(()) = hangup.recv().await else {
            return;
        };
        if let Err(err) = policy.reload_from_path(&path).await {
            tracing::error!(
                error = format!("{err:#}"),
                "config reload refused; keeping the previous policy"
            );
        }
    }
}

/// Resolves on SIGTERM or SIGINT.
///
/// In-flight sessions are not drained: each is its own task holding its own
/// backend connection, and a masking proxy that lingered to finish streaming a
/// result set would delay a deploy for as long as the longest query. Refusing
/// new connections and exiting is the behaviour a supervisor expects.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(error = %err, "cannot listen for SIGTERM");
            return std::future::pending().await;
        }
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
