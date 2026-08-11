//! What does the proxy cost?
//!
//! Two shapes, because they answer different questions:
//!
//!   * **latency** — a 1-row query, repeated. Isolates the fixed cost of the
//!     extra network hop. This is what interactive clients feel.
//!   * **throughput** — one query returning many rows. Isolates the per-row
//!     cost of parsing and rewriting `DataRow`s. This is what a masking proxy
//!     could plausibly get wrong.
//!
//! Usage:
//!
//! ```text
//! DIRECT_URL=... PROXY_URL=... cargo run -p bench --bin bench --release -- [rows] [iters]
//! ```

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio_postgres::{Client, NoTls};

async fn connect(url: &str) -> Result<Client> {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("connection error: {err}");
        }
    });
    Ok(client)
}

struct Stats {
    samples: Vec<Duration>,
}

impl Stats {
    fn percentile(&self, p: f64) -> Duration {
        let mut sorted = self.samples.clone();
        sorted.sort();
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        // `measure` refuses to build an empty `Stats`, so the fallback is
        // unreachable; a reported 0.000ms is not a plausible measurement and
        // so cannot be mistaken for a fast one.
        sorted.get(idx).copied().unwrap_or(Duration::ZERO)
    }
    fn mean(&self) -> Duration {
        let total: Duration = self.samples.iter().sum();
        let n = u32::try_from(self.samples.len()).unwrap_or(u32::MAX);
        total.checked_div(n).unwrap_or(Duration::ZERO)
    }
}

async fn measure<F, Fut>(iters: usize, mut op: F) -> Result<Stats>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<usize>>,
{
    // A zero-iteration run has no percentiles and no mean, and a table of
    // 0.000ms would read as a measurement rather than as the absence of one.
    anyhow::ensure!(iters > 0, "iters must be greater than zero");
    // Warm up: connection setup, plan caching, and the proxy's first-use paths.
    for _ in 0..(iters / 10).max(5) {
        op().await?;
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        op().await?;
        samples.push(start.elapsed());
    }
    Ok(Stats { samples })
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn report(label: &str, direct: &Stats, proxy: &Stats, rows: usize) {
    println!("\n{label}");
    println!("{}", "-".repeat(72));
    println!(
        "{:<10}{:>12}{:>12}{:>12}{:>12}",
        "", "mean", "p50", "p95", "p99"
    );
    for (name, s) in [("direct", direct), ("pgmask", proxy)] {
        println!(
            "{:<10}{:>11.3}ms{:>11.3}ms{:>11.3}ms{:>11.3}ms",
            name,
            ms(s.mean()),
            ms(s.percentile(0.50)),
            ms(s.percentile(0.95)),
            ms(s.percentile(0.99)),
        );
    }
    let overhead = ms(proxy.mean()) - ms(direct.mean());
    let pct = (ms(proxy.mean()) / ms(direct.mean()) - 1.0) * 100.0;
    println!("{:<10}{:>11.3}ms  ({:+.1}%)", "overhead", overhead, pct);
    if rows > 1 {
        let per_row_us = (overhead * 1000.0) / rows as f64;
        println!(
            "{:<10}{:>11.3}us/row   direct {:.0} rows/s, pgmask {:.0} rows/s",
            "",
            per_row_us,
            rows as f64 / direct.mean().as_secs_f64(),
            rows as f64 / proxy.mean().as_secs_f64(),
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let direct_url = std::env::var("DIRECT_URL").context("DIRECT_URL is required")?;
    let proxy_url = std::env::var("PROXY_URL").context("PROXY_URL is required")?;

    let mut args = std::env::args().skip(1);
    let rows: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(10_000);
    let iters: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(200);

    let direct = connect(&direct_url).await?;
    let proxy = connect(&proxy_url).await?;

    println!("rows={rows} iters={iters}");

    // --- Latency: one row, repeated -----------------------------------------
    let one_row = "SELECT email, name FROM demo.customers LIMIT 1";
    let d_stmt = direct.prepare(one_row).await?;
    let p_stmt = proxy.prepare(one_row).await?;
    let d = measure(iters, || async {
        Ok(direct.query(&d_stmt, &[]).await?.len())
    })
    .await?;
    let p = measure(iters, || async {
        Ok(proxy.query(&p_stmt, &[]).await?.len())
    })
    .await?;
    report("latency — 1 row (fixed per-query cost)", &d, &p, 1);

    // --- Throughput: many rows, one query -----------------------------------
    let many = format!("SELECT email, name FROM demo.customers ORDER BY id LIMIT {rows}");
    let d_stmt = direct.prepare(&many).await?;
    let p_stmt = proxy.prepare(&many).await?;

    // Confirm the proxy really is masking, so we are not benchmarking a no-op.
    // No rows means there is nothing to compare and the check would pass by
    // being empty, so it is an error rather than a skip.
    let direct_rows = direct.query(&d_stmt, &[]).await?;
    let proxy_rows = proxy.query(&p_stmt, &[]).await?;
    let direct_first: String = direct_rows
        .first()
        .context("the throughput query returned no rows directly; the fixture is empty")?
        .get(0);
    let proxy_first: String = proxy_rows
        .first()
        .context("the throughput query returned no rows through the proxy")?
        .get(0);
    println!(
        "\nsanity: direct={direct_first:?} proxy={proxy_first:?} -> {}",
        if direct_first == proxy_first {
            "NOT MASKED (!)"
        } else {
            "masked"
        }
    );

    let iters = (iters / 10).max(10);
    let d = measure(iters, || async {
        Ok(direct.query(&d_stmt, &[]).await?.len())
    })
    .await?;
    let p = measure(iters, || async {
        Ok(proxy.query(&p_stmt, &[]).await?.len())
    })
    .await?;
    report(
        &format!("throughput — {rows} rows x 2 masked text columns"),
        &d,
        &p,
        rows,
    );

    println!();
    Ok(())
}
