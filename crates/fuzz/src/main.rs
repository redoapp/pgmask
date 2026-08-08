//! Replay generated SQL through the proxy and assert no masked value escapes.
//!
//! There is no second reviewer for this codebase, so the suite has to carry the
//! confidence a reviewer would. This is the part that scales: a mechanical
//! oracle that needs no human to say whether a result was correct.
//!
//! # The oracle
//!
//! Every masked column in the demo fixture holds values containing a token that
//! appears nowhere else — `@example.com` in `email`, `Customer ` in `name`,
//! `555-` in `phone`. Masking rewrites all of them. So for **any** query, by
//! any route, through any expression: **a token in the output is a leak.** No
//! expected-output file, no oracle to maintain, and it holds for SQL nobody
//! wrote by hand.
//!
//! Queries come from `sqlsmith`, which reads the live schema and generates
//! valid random SQL. The point is to reach shapes we would not think to write —
//! which, with nobody else reading the analysis rules, is the closest available
//! substitute for an adversary.
//!
//! Most generated queries fail with a type error. That is expected and fine:
//! errors are not leaks. What is asserted is narrow and absolute — no token in
//! any served value, and the session still works afterwards.
//!
//! # The negative control, which is the part that makes it mean anything
//!
//! Every query runs twice: once straight at Postgres, once through the proxy.
//! A run where the direct connection saw no tokens either proves nothing — the
//! generated SQL simply never reached masked data — and is reported as
//! **vacuous** rather than as a pass. Three assertions in this repo have been
//! silently vacuous already; a fuzzer that can pass by doing nothing would be
//! the most expensive version of that mistake.
//!
//! Usage:
//!   DIRECT_URL=postgres://…:55432/fuzzdb \
//!   PROXY_URL=postgres://…:6470/fuzzdb  fuzz queries.sql

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use tokio_postgres::{NoTls, SimpleQueryMessage};

/// Token -> the column it would betray. Each appears in exactly one masked
/// column of the demo fixture and nowhere else in the database.
const CANARIES: &[(&str, &str)] = &[
    ("CANARY", "a masked text column in fz"),
    ("@example.com", "demo.customers.email"),
    ("Customer ", "demo.customers.name"),
    ("555-", "demo.customers.phone"),
    (" Example Street", "demo.orders.ship_address"),
    ("00000000-0000-4000-9000-", "an fz uuid column"),
    ("00000000-0000-4000-8000-", "demo.customers.account_uuid"),
];

/// Count canary tokens across every value a query returned.
async fn tokens_in_result(
    client: &tokio_postgres::Client,
    sql: &str,
) -> Option<Vec<(String, String)>> {
    let response = client.simple_query(sql).await.ok()?;
    let mut found = Vec::new();
    for message in &response {
        let SimpleQueryMessage::Row(row) = message else {
            continue;
        };
        for i in 0..row.len() {
            let Ok(Some(value)) = row.try_get(i) else {
                continue;
            };
            for (token, column) in CANARIES {
                if value.contains(token) {
                    found.push(((*column).to_string(), value.chars().take(60).collect()));
                }
            }
        }
    }
    Some(found)
}

/// Split on statement boundaries. sqlsmith emits one statement per block,
/// terminated by `;` at end of line.
fn statements(text: &str) -> Vec<String> {
    text.split(";\n")
        .map(|s| s.trim().trim_end_matches(';').trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::var("PROXY_URL").context("PROXY_URL is required")?;
    let direct_url = std::env::var("DIRECT_URL").context("DIRECT_URL is required")?;
    let path = std::env::args()
        .nth(1)
        .context("usage: fuzz <queries.sql>")?;
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let queries = statements(&text);

    let mut served = 0usize;
    let mut refused = 0usize;
    let mut errored = 0usize;
    let mut leaks: Vec<(String, String, String)> = Vec::new();
    let mut reconnects = 0usize;

    let mut client = connect(&url).await?;
    let direct = connect(&direct_url).await?;
    // How much masked data the generated SQL actually reached. Zero means the
    // run proved nothing, whatever the proxy did.
    let mut tokens_visible_directly = 0usize;
    let mut queries_reaching_masked_data = 0usize;

    for (index, sql) in queries.iter().enumerate() {
        // A token present in the query itself would be echoed back legitimately,
        // and we cannot tell that apart from a leak. Skip rather than guess.
        if CANARIES.iter().any(|(token, _)| sql.contains(token)) {
            continue;
        }

        if let Some(found) = tokens_in_result(&direct, sql).await {
            if !found.is_empty() {
                queries_reaching_masked_data += 1;
                tokens_visible_directly += found.len();
            }
        }

        let response = match client.simple_query(sql).await {
            Ok(rows) => rows,
            Err(err) => {
                // Read the server error, not the Display string. Matching on
                // `err.to_string()` counted every one of 1169 pgmask refusals
                // as an ordinary Postgres error, which made a run where the
                // proxy was working hard look like one where it never fired.
                let is_refusal = err
                    .as_db_error()
                    .is_some_and(|db| db.message().starts_with("pgmask:"));
                if is_refusal {
                    refused += 1;
                } else {
                    errored += 1;
                }
                // A dead connection must not silently turn the rest of the run
                // into vacuous passes.
                if client.is_closed() {
                    client = connect(&url).await?;
                    reconnects += 1;
                }
                continue;
            }
        };

        served += 1;
        for message in &response {
            let SimpleQueryMessage::Row(row) = message else {
                continue;
            };
            for i in 0..row.len() {
                let Ok(Some(value)) = row.try_get(i) else {
                    continue;
                };
                for (token, column) in CANARIES {
                    if value.contains(token) {
                        leaks.push((
                            (*column).to_string(),
                            value.chars().take(60).collect(),
                            format!("#{index}: {}", sql.chars().take(200).collect::<String>()),
                        ));
                    }
                }
            }
        }
    }

    // The session has to still work, or every "no leak" above proves nothing.
    // The probe has to name something that exists in the fixture — pointing it
    // at another database's table reports the proxy as dead when it is fine.
    let probe = std::env::var("LIVENESS_SQL")
        .unwrap_or_else(|_| "SELECT id FROM fz.t1 WHERE id = 1".to_string());
    let alive = client.simple_query(&probe).await.is_ok();
    if !alive {
        eprintln!("liveness probe failed: {probe}");
    }

    println!("\n{} statements replayed", queries.len());
    println!("  reached masked data      {queries_reaching_masked_data:>6}  (direct control)");
    println!("  masked values visible    {tokens_visible_directly:>6}  without the proxy");
    println!("  served (rows inspected)  {served:>6}");
    println!("  refused by pgmask        {refused:>6}");
    println!("  postgres error           {errored:>6}");
    if reconnects > 0 {
        println!("  connection re-opened     {reconnects:>6}");
    }
    println!(
        "  session alive afterwards {:>6}",
        if alive { "yes" } else { "NO" }
    );
    println!("  LEAKED                   {:>6}", leaks.len());

    if !leaks.is_empty() {
        let mut by_column: BTreeMap<&str, usize> = BTreeMap::new();
        for (column, _, _) in &leaks {
            *by_column.entry(column.as_str()).or_default() += 1;
        }
        println!("\nmasked values reached the client:");
        for (column, count) in by_column {
            println!("  {column}  x{count}");
        }
        for (column, value, sql) in leaks.iter().take(3) {
            println!("\n  {column} leaked {value:?}\n  via {sql}");
        }
        std::process::exit(1);
    }
    if !alive {
        eprintln!("\nthe session did not survive the run");
        std::process::exit(1);
    }
    if tokens_visible_directly == 0 {
        eprintln!(
            "\nVACUOUS: the generated SQL never reached a masked value, so finding\n\
             no leak proves nothing. Widen the fixture or the query set."
        );
        std::process::exit(2);
    }
    println!(
        "\n{tokens_visible_directly} masked values were readable without the proxy and \
         none through it."
    );
    Ok(())
}

async fn connect(url: &str) -> Result<tokio_postgres::Client> {
    // Read-only, enforced by the server rather than by our discipline.
    //
    // sqlsmith generates DML as well as queries, and the first version of this
    // harness executed it: `fz.t1` went from 40 rows to 3 during a run, with
    // ids the fixture never had. That silently weakened the negative control
    // between runs — 362 masked values reachable on the first pass, 251 on the
    // second — which is the failure mode where a fuzzer quietly stops testing
    // anything.
    let url = if url.contains('?') {
        format!("{url}&options=-c%20default_transaction_read_only%3Don")
    } else {
        format!("{url}?options=-c%20default_transaction_read_only%3Don")
    };
    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .context("connecting to the proxy")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    // Generated SQL can ask for a cross join of everything. A hang would look
    // like a pass.
    let _ = client.simple_query("SET statement_timeout = '5s'").await;
    Ok(client)
}
