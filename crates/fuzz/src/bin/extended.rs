//! Replay a corpus over the **extended** protocol, with the same canary oracle.
//!
//! # Why this is a separate axis and not more of the same
//!
//! The main replay harness uses `simple_query` throughout, and every other
//! end-to-end suite except `binary` does too. That is one protocol out of two,
//! and the two do not agree: CockroachDB reports the first branch's provenance
//! for a set operation on the simple-query path and **zero** for the same
//! statement under `Describe`. A disagreement between protocols is what the
//! first disclosure here was made of, so testing one of them is testing half.
//!
//! `Client::query` goes through Parse/Bind/Execute and asks for binary results,
//! so this drives Describe-derived plans, `Bind` result-format re-stamping and
//! the type-aware decode/encode path — none of which `simple_query` touches.
//!
//! The oracle is the *same* one, shared from `fuzz::oracle` — nine tokens plus
//! four shape detectors for the type-aware masks. It used to be a private
//! one-token copy, which meant that on this path nothing could see a
//! `date-year`, `ip-prefix`, `numeric-bucket` or uuid-pseudonym escape at all,
//! while the module doc claimed the oracle was unchanged. Its poison control
//! unmasked only `redact` — the one thing that copy could see — so the control
//! was structurally incapable of exposing the gap. Two guards keep a quiet run from reading as a
//! clean one:
//!
//!   - every statement also runs directly, and a run where the corpus never
//!     reached a masked value at all reports as vacuous
//!   - `EXPECT_LEAKS=1` inverts the result, for the poison control
//!
//! Usage:
//!   DIRECT_URL=… PROXY_URL=… extended corpus.sql

use anyhow::{bail, Context, Result};
use fuzz::oracle::{shape_leak, CANARIES};
use tokio_postgres::{Client, NoTls, Row};

async fn connect(url: &str) -> Result<Client> {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .with_context(|| format!("connecting to {}", url.rsplit('@').next().unwrap_or("?")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

/// Every value in a row set that can be read as text.
///
/// Non-text columns are skipped rather than rendered: a canary is a text token,
/// and `try_get::<String>` on an `int8` is an error, not a value worth
/// stringifying. Binary is the point of this harness, so the decode is the
/// driver's, over the bytes the proxy actually emitted.
/// Every value in the result set, rendered as text for the oracle to scan.
///
/// This used to read `Option<String>` and nothing else, which silently dropped
/// every column the binary path could not hand back as text — and the detectors
/// it feeds are mostly *not* about text. `sum(int4)` comes back as `int8`, so
/// the numeric poison detector could never fire here: the value was discarded
/// before the oracle saw it. Verified by removing the singleton-group guard and
/// replaying, which leaked exact salaries through psql while this harness
/// reported clean.
///
/// The v0.1.11 note that both harnesses now share `fuzz::oracle` was true and
/// not sufficient. Sharing the detectors does not help if the values never
/// reach them, and that fix was verified with `ip-prefix`, which happens to sit
/// on a `text` column.
///
/// Ordered most specific first; a decode failure means "not this type", while
/// `Ok(None)` means the column really is NULL and there is nothing to scan.
fn render(row: &Row, i: usize) -> Option<String> {
    if let Ok(v) = row.try_get::<_, Option<String>>(i) {
        return v;
    }
    if let Ok(v) = row.try_get::<_, Option<i64>>(i) {
        return v.map(|v| v.to_string());
    }
    if let Ok(v) = row.try_get::<_, Option<i32>>(i) {
        return v.map(|v| v.to_string());
    }
    if let Ok(v) = row.try_get::<_, Option<i16>>(i) {
        return v.map(|v| v.to_string());
    }
    if let Ok(v) = row.try_get::<_, Option<f64>>(i) {
        return v.map(|v| v.to_string());
    }
    if let Ok(v) = row.try_get::<_, Option<bool>>(i) {
        return v.map(|v| v.to_string());
    }
    if let Ok(v) = row.try_get::<_, Option<uuid::Uuid>>(i) {
        return v.map(|v| v.to_string());
    }
    if let Ok(v) = row.try_get::<_, Option<jiff::civil::Date>>(i) {
        return v.map(|v| v.to_string());
    }
    // `numeric`, which is what `avg` over an integer returns. Without this the
    // generator had to avoid `avg` entirely: a disclosure through it would be
    // produced and then discarded before any detector ran, which is the exact
    // blindness that hid the singleton-group leak.
    if let Ok(v) = row.try_get::<_, Option<rust_decimal::Decimal>>(i) {
        return v.map(|v| v.normalize().to_string());
    }
    None
}

fn text_values(rows: &[Row]) -> Vec<String> {
    let mut out = Vec::new();
    for row in rows {
        for i in 0..row.len() {
            if let Some(v) = render(row, i) {
                out.push(v);
            }
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    let corpus_path = std::env::args()
        .nth(1)
        .context("usage: extended <corpus.sql>")?;
    let direct_url = std::env::var("DIRECT_URL").context("DIRECT_URL is required")?;
    let proxy_url = std::env::var("PROXY_URL").context("PROXY_URL is required")?;
    let expect_leaks = std::env::var("EXPECT_LEAKS").is_ok();

    let corpus =
        std::fs::read_to_string(&corpus_path).with_context(|| format!("reading {corpus_path}"))?;
    let statements: Vec<&str> = corpus
        .split(";\n")
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("--"))
        .collect();
    if statements.is_empty() {
        bail!("the corpus is empty, so nothing would be checked");
    }

    let direct = connect(&direct_url).await?;
    let mut proxy = connect(&proxy_url).await?;

    // Long-running generated shapes would otherwise dominate the wall clock.
    // 400ms is what the simple-query campaign settled on: enough for a thousand
    // statements in a couple of seconds, short enough that a pathological join
    // does not stall the run.
    for c in [&direct, &proxy] {
        let _ = c.batch_execute("SET statement_timeout = '400ms'").await;
    }

    let mut served = 0usize;
    let mut refused = 0usize;
    let mut errored = 0usize;
    let mut reconnects = 0usize;
    let mut reached_masked = 0usize;
    let mut visible_directly = 0usize;
    let mut leaks = 0usize;
    let mut reported: Vec<String> = Vec::new();

    for sql in &statements {
        // The control: is there anything to find here at all?
        if let Ok(rows) = direct.query(*sql, &[]).await {
            let found = text_values(&rows)
                .iter()
                .filter(|v| CANARIES.iter().any(|(t, _)| v.contains(t)) || shape_leak(v).is_some())
                .count();
            if found > 0 {
                reached_masked = reached_masked.saturating_add(1);
                visible_directly = visible_directly.saturating_add(found);
            }
        }

        match proxy.query(*sql, &[]).await {
            Ok(rows) => {
                served = served.saturating_add(1);
                for value in text_values(&rows) {
                    let hit = CANARIES
                        .iter()
                        .find(|(token, _)| value.contains(token))
                        .map(|(_, column)| *column)
                        .or_else(|| shape_leak(&value));
                    if let Some(column) = hit {
                        leaks = leaks.saturating_add(1);
                        if reported.len() < 5 {
                            reported.push(format!(
                                "{column} leaked {value:?}\n    via: {}",
                                sql.chars().take(300).collect::<String>()
                            ));
                        }
                    }
                }
            }
            Err(err) => {
                // The server's message, not the Display string: matching on the
                // latter counted every pgmask refusal as an ordinary error in
                // the simple-query harness, making a working proxy look idle.
                let is_refusal = err
                    .as_db_error()
                    .is_some_and(|db| db.message().starts_with("pgmask:"));
                if is_refusal {
                    refused = refused.saturating_add(1);
                } else {
                    errored = errored.saturating_add(1);
                }
                // A dead connection must not turn the rest of the run into
                // vacuous passes.
                if proxy.is_closed() {
                    proxy = connect(&proxy_url).await?;
                    reconnects = reconnects.saturating_add(1);
                }
            }
        }
    }

    println!(
        "\n{} statements over the extended protocol",
        statements.len()
    );
    println!("  reached masked data      {reached_masked:8}  (direct control)");
    println!("  masked values visible    {visible_directly:8}  without the proxy");
    println!("  served                   {served:8}");
    println!("  refused by pgmask        {refused:8}");
    println!("  engine error             {errored:8}");
    println!("  reconnects               {reconnects:8}");
    println!("  LEAKED                   {leaks:8}");
    println!(
        "RESULT statements={} served={served} refused={refused} errors={errored} \
         control={visible_directly} leaks={leaks}",
        statements.len()
    );
    for line in &reported {
        println!("\n  {line}");
    }

    if expect_leaks {
        if leaks == 0 {
            bail!("EXPECT_LEAKS: masking was removed and nothing leaked — the oracle is blind");
        }
        return Ok(());
    }
    // A run that never reached a masked value proves nothing, whatever it says.
    if reached_masked == 0 {
        bail!("no statement in the corpus reached a masked value — vacuous run");
    }
    if leaks > 0 {
        bail!("{leaks} masked value(s) reached the client");
    }
    Ok(())
}
