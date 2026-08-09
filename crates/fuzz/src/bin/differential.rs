//! Run one corpus through two engines and compare what the proxy did.
//!
//! # Why this oracle is different from the others
//!
//! Every other oracle here needs someone to have predicted the bug. The canary
//! oracle needs a token planted in the right column; the shape matrix needs the
//! shape to have been thought of. `shapegen` closed one gap and opened another:
//! it explores what its author imagined, so its blind spots are his.
//!
//! This one needs no prediction. Both engines hold byte-identical fixture data,
//! and **masking is supposed to be a property of the data and the catalog, not
//! of the engine**. So for any statement both proxies serve, the masked output
//! must match. A difference is a defect by construction — nobody has to have
//! guessed which statement would expose it.
//!
//! That matters most for pseudonyms: they are deterministic so that a Postgres
//! copy and a CockroachDB cluster of the same data stay joinable. If one engine
//! yields a different pseudonym for the same row, that property is gone and no
//! single-engine test can see it.
//!
//! # What is a finding and what is not
//!
//! - **Both served, values differ** — a defect. Fails the run.
//! - **One served, the other refused** — reported, not failed. The engines
//!   genuinely disagree about what provenance to report, and pgmask distrusts
//!   CockroachDB in places Postgres never needed distrusting, so a refusal
//!   difference is expected. It is still worth printing: a *new* one is how a
//!   regression in the trust rules would first show.
//! - **Either errored** — ignored. Engines reject different SQL.
//!
//! Row order is not part of the comparison: `GROUP BY`, `DISTINCT` and set
//! operations order differently across engines, so values are sorted first.
//!
//! Usage:
//!   A_URL=… B_URL=… differential corpus.sql

use anyhow::{bail, Context, Result};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

async fn connect(url: &str) -> Result<Client> {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .with_context(|| format!("connecting to {}", url.rsplit('@').next().unwrap_or("?")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

#[derive(PartialEq, Eq)]
enum Outcome {
    /// Sorted values, so row order is not mistaken for a difference.
    Served(Vec<String>),
    Refused,
    Errored,
}

/// Trailing zeros off a decimal, so engine formatting is not read as a masking
/// difference.
///
/// Postgres renders `avg(id)` as `1.00000000000000000000` and CockroachDB as
/// `1.0000000000000000000` — twenty digits against nineteen, on a *released*
/// column where masking never ran. The premise of this oracle is that masking
/// is engine-independent; it says nothing about how an engine prints a numeric,
/// and comparing that produced 19 false findings the moment `avg` entered the
/// generator.
fn normalise(v: &str) -> String {
    let looks_numeric = v.contains('.')
        && v.len() > 1
        && v.chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-');
    if looks_numeric {
        return v.trim_end_matches('0').trim_end_matches('.').to_string();
    }
    v.to_string()
}

async fn run(client: &Client, sql: &str) -> Outcome {
    match client.simple_query(sql).await {
        Ok(response) => {
            let mut values = Vec::new();
            for message in &response {
                let SimpleQueryMessage::Row(row) = message else {
                    continue;
                };
                for i in 0..row.len() {
                    values.push(match row.try_get(i) {
                        Ok(Some(v)) => normalise(v),
                        _ => "\u{0}NULL".to_string(),
                    });
                }
            }
            values.sort();
            Outcome::Served(values)
        }
        Err(err) => {
            if err
                .as_db_error()
                .is_some_and(|db| db.message().starts_with("pgmask:"))
            {
                Outcome::Refused
            } else {
                Outcome::Errored
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let corpus_path = std::env::args()
        .nth(1)
        .context("usage: differential <corpus.sql>")?;
    let a_url = std::env::var("A_URL").context("A_URL is required")?;
    let b_url = std::env::var("B_URL").context("B_URL is required")?;
    let a_name = std::env::var("A_NAME").unwrap_or_else(|_| "A".into());
    let b_name = std::env::var("B_NAME").unwrap_or_else(|_| "B".into());
    // Proves the comparison can fail: with the two sides pointed at differently
    // configured proxies, mismatches must appear.
    let expect_mismatch = std::env::var("EXPECT_MISMATCH").is_ok();

    let corpus =
        std::fs::read_to_string(&corpus_path).with_context(|| format!("reading {corpus_path}"))?;
    let statements: Vec<&str> = corpus
        .split(";\n")
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("--"))
        .collect();
    if statements.is_empty() {
        bail!("the corpus is empty, so nothing would be compared");
    }

    let a = connect(&a_url).await?;
    let b = connect(&b_url).await?;
    for c in [&a, &b] {
        let _ = c.batch_execute("SET statement_timeout = '400ms'").await;
    }

    let mut compared = 0usize;
    let mut agreed = 0usize;
    let mut value_mismatch = 0usize;
    let mut decision_mismatch = 0usize;
    let mut both_refused = 0usize;
    let mut skipped = 0usize;
    let mut reported: Vec<String> = Vec::new();
    let mut decisions: Vec<String> = Vec::new();

    for sql in &statements {
        let (ra, rb) = (run(&a, sql).await, run(&b, sql).await);
        match (&ra, &rb) {
            (Outcome::Errored, _) | (_, Outcome::Errored) => skipped = skipped.saturating_add(1),
            (Outcome::Refused, Outcome::Refused) => both_refused = both_refused.saturating_add(1),
            (Outcome::Served(va), Outcome::Served(vb)) => {
                compared = compared.saturating_add(1);
                if va == vb {
                    agreed = agreed.saturating_add(1);
                } else {
                    value_mismatch = value_mismatch.saturating_add(1);
                    if reported.len() < 5 {
                        let at = va
                            .iter()
                            .zip(vb)
                            .position(|(x, y)| x != y)
                            .unwrap_or_default();
                        reported.push(format!(
                            "{a_name} {:?} vs {b_name} {:?} ({} vs {} values)\n    via: {}",
                            va.get(at),
                            vb.get(at),
                            va.len(),
                            vb.len(),
                            sql.chars().take(280).collect::<String>()
                        ));
                    }
                }
            }
            (served, _) => {
                decision_mismatch = decision_mismatch.saturating_add(1);
                if decisions.len() < 5 {
                    let (yes, no) = if matches!(served, Outcome::Served(_)) {
                        (&a_name, &b_name)
                    } else {
                        (&b_name, &a_name)
                    };
                    decisions.push(format!(
                        "{yes} served, {no} refused: {}",
                        sql.chars().take(200).collect::<String>()
                    ));
                }
            }
        }
    }

    println!(
        "\ndifferential: {a_name} vs {b_name}, {} statements",
        statements.len()
    );
    println!("  both served, values identical  {agreed:8}");
    println!("  both served, VALUES DIFFER     {value_mismatch:8}");
    println!("  both refused                   {both_refused:8}");
    println!("  one served, one refused        {decision_mismatch:8}  (expected; engines differ)");
    println!("  skipped (an engine errored)    {skipped:8}");
    println!(
        "RESULT compared={compared} agreed={agreed} value_mismatch={value_mismatch} \
         decision_mismatch={decision_mismatch}"
    );
    for line in &reported {
        println!("\n  MISMATCH {line}");
    }
    for line in &decisions {
        println!("\n  decision {line}");
    }

    if expect_mismatch {
        if value_mismatch == 0 {
            bail!(
                "EXPECT_MISMATCH: the two sides were configured differently and nothing \
                   differed — the comparison is not comparing"
            );
        }
        return Ok(());
    }
    // Nothing served on both sides means nothing was compared, whatever the
    // other counters say.
    if compared == 0 {
        bail!("no statement was served by both engines — nothing was compared");
    }
    if value_mismatch > 0 {
        bail!(
            "{value_mismatch} statement(s) produced different masked output on the two engines; \
             masking must depend on the data and the catalog, not on the engine"
        );
    }
    Ok(())
}
