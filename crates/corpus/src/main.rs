//! What fraction of a real query workload does pgmask refuse, and why?
//!
//! Point it at a directory of `.sql` files and a DSN. Prints the rejection rate
//! and a breakdown by cause.
//!
//! # Why this needs no data
//!
//! Each query is submitted with `Parse` + `Describe` and never executed.
//! Postgres describes the result set from the schema alone, which is what
//! pgmask classifies against — so the whole measurement runs on an **empty
//! database with only the DDL loaded**. Phase 0 established that every shape is
//! describable without execution; this is that finding paying rent.
//!
//! It also means the analysis is safe to run against a corpus you have not read:
//! nothing is executed, so nothing is scanned, locked, or returned.
//!
//! Usage:
//!   DSN=postgres://... cargo run -p corpus --release -- <dir-of-sql>

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use tokio_postgres::NoTls;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    /// pgmask classified the result set and would serve it.
    Described,
    /// pgmask refused it.
    Refused,
    /// The query did not describe for reasons of its own — dialect, a missing
    /// table, a syntax error. Never counted against pgmask.
    NotOurFault,
}

/// Bucket a refusal by the wording pgmask used, so causes can be counted
/// without reaching into the proxy's own metrics.
fn cause_of(message: &str) -> &'static str {
    if message.contains("COPY") {
        "copy"
    } else if message.contains("cannot be applied to type") {
        "mask/type mismatch"
    } else if message.contains("no column provenance") {
        "no provenance"
    } else {
        "other"
    }
}

/// Strip anything that is not the statement itself.
///
/// Some published corpora prefix session setup — the Altinity TPC-DS files
/// begin with a ClickHouse `USE`/`SET` line — and `Parse` accepts exactly one
/// statement, so trailing semicolons have to go too.
fn clean(sql: &str) -> String {
    let body: String = sql
        .lines()
        .filter(|l| {
            let t = l.trim_start().to_ascii_lowercase();
            !(t.starts_with("use ") || t.starts_with("set ") || t.starts_with("--"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    body.trim().trim_end_matches(';').trim().to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let dir = std::env::args()
        .nth(1)
        .context("usage: corpus <dir-of-sql>")?;
    let dsn = std::env::var("DSN").context("DSN is required")?;

    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .context("connecting")?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("connection error: {err}");
        }
    });

    let mut files: Vec<_> = std::fs::read_dir(Path::new(&dir))
        .with_context(|| format!("reading {dir}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "sql"))
        .collect();
    // Natural-ish order so query_2 precedes query_10 in the listing.
    files.sort_by_key(|p| {
        let name = p
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let digits: String = name.chars().filter(|c| c.is_ascii_digit()).collect();
        (digits.parse::<u32>().unwrap_or(u32::MAX), name)
    });

    let mut counts: BTreeMap<Outcome, usize> = BTreeMap::new();
    let mut causes: BTreeMap<&str, usize> = BTreeMap::new();
    let mut refused_names = Vec::new();
    let mut skipped_names = Vec::new();

    for path in &files {
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let sql = clean(&std::fs::read_to_string(path)?);
        if sql.is_empty() {
            continue;
        }
        let outcome = match client.prepare(&sql).await {
            Ok(_) => Outcome::Described,
            Err(err) => {
                let msg = err
                    .as_db_error()
                    .map(|e| e.message().to_string())
                    .unwrap_or_else(|| err.to_string());
                if msg.contains("pgmask:") {
                    *causes.entry(cause_of(&msg)).or_default() += 1;
                    refused_names.push(name.clone());
                    Outcome::Refused
                } else {
                    skipped_names.push(format!("{name}: {}", first_line(&msg)));
                    Outcome::NotOurFault
                }
            }
        };
        *counts.entry(outcome).or_default() += 1;
    }

    let described = *counts.get(&Outcome::Described).unwrap_or(&0);
    let refused = *counts.get(&Outcome::Refused).unwrap_or(&0);
    let skipped = *counts.get(&Outcome::NotOurFault).unwrap_or(&0);
    let judged = described + refused;

    println!("\n{} file(s) in {dir}", files.len());
    println!("{}", "-".repeat(56));
    println!("  described (would be served) {described:>4}");
    println!("  refused by pgmask           {refused:>4}");
    println!("  did not parse/describe      {skipped:>4}   (not pgmask's doing)");
    if judged > 0 {
        println!(
            "\n  rejection rate: {:.0}% of the {judged} queries pgmask actually judged",
            (refused as f64 / judged as f64) * 100.0
        );
    }
    if !causes.is_empty() {
        println!("\n  by cause:");
        for (cause, n) in &causes {
            println!("    {cause:<22} {n:>4}");
        }
    }
    if !refused_names.is_empty() {
        println!("\n  refused: {}", refused_names.join(" "));
    }
    if !skipped_names.is_empty() {
        println!("\n  not judged (first few):");
        for line in skipped_names.iter().take(5) {
            println!("    {line}");
        }
    }
    println!();
    Ok(())
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(90).collect()
}
