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
    ("00000000-0000-4000-a000-", "fz.people.account_uuid"),
    ("555-77", "fz.people.phone"),
    ("@example.com", "demo.customers.email"),
    ("Customer ", "demo.customers.name"),
    ("555-", "demo.customers.phone"),
    (" Example Street", "demo.orders.ship_address"),
    ("00000000-0000-4000-9000-", "an fz uuid column"),
    ("00000000-0000-4000-8000-", "demo.customers.account_uuid"),
];

/// Values whose *shape* betrays an unmasked type-aware column.
///
/// A substring token cannot cover a date or an IP: the leak is not a marker,
/// it is the absence of coarsening. The fixture is seeded so the raw form is a
/// shape the masked form never has — birth dates are never 1 January,
/// addresses in 198.51.100/24 never end .0 — so these patterns match only
/// values that escaped their mask.
fn shape_leak(value: &str) -> Option<&'static str> {
    // 198.51.100.7 escaped; 198.51.100.0 is correctly masked.
    if let Some(rest) = value.strip_prefix("198.51.100.") {
        let host: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !host.is_empty() && host != "0" {
            return Some("fz.people.last_ip (not truncated to /24)");
        }
    }
    // 1975-02-03 escaped; 1975-01-01 is correctly masked.
    for (i, _) in value.match_indices("19") {
        let window = &value[i..];
        if window.len() >= 10 {
            let d = &window[..10];
            let bytes = d.as_bytes();
            if bytes[4] == b'-'
                && bytes[7] == b'-'
                && d[..4].chars().all(|c| c.is_ascii_digit())
                && d[5..7].chars().all(|c| c.is_ascii_digit())
                && d[8..].chars().all(|c| c.is_ascii_digit())
                && &d[5..] != "01-01"
            {
                return Some("fz.people.birth_date (not truncated to its year)");
            }
        }
    }
    None
}

/// Every value a query returned, in order, plus the row count.
///
/// Used for the equivalence oracle: with nothing masked, the proxy must be a
/// byte-exact mirror of the database. Any divergence is the proxy corrupting
/// data it was told to leave alone — masking the wrong column, losing a row,
/// mangling an encoding — none of which the canary oracle can see, because a
/// canary only answers "did anything leak".
fn shape_from(response: &[SimpleQueryMessage]) -> (usize, Vec<String>) {
    let mut rows = 0usize;
    let mut values = Vec::new();
    for message in response {
        let SimpleQueryMessage::Row(row) = message else {
            continue;
        };
        rows += 1;
        for i in 0..row.len() {
            values.push(match row.try_get(i) {
                Ok(Some(v)) => v.to_string(),
                _ => "\u{0}NULL".to_string(),
            });
        }
    }
    (rows, values)
}

async fn shape_of_result(
    client: &tokio_postgres::Client,
    sql: &str,
) -> Option<(usize, Vec<String>)> {
    let response = client.simple_query(sql).await.ok()?;
    let mut rows = 0usize;
    let mut values = Vec::new();
    for message in &response {
        let SimpleQueryMessage::Row(row) = message else {
            continue;
        };
        rows += 1;
        for i in 0..row.len() {
            values.push(match row.try_get(i) {
                Ok(Some(v)) => v.to_string(),
                _ => "\u{0}NULL".to_string(),
            });
        }
    }
    Some((rows, values))
}

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
            if let Some(column) = shape_leak(value) {
                found.push((column.to_string(), value.chars().take(60).collect()));
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
    // A *second* direct session, not a second run on the first.
    //
    // The baseline check originally ran the same query twice on one connection,
    // which cannot detect session-dependence at all: pg_backend_pid() and
    // friends are perfectly stable within a session and differ between them.
    // That produced `direct "45770" vs proxy "45748"` and looked like the proxy
    // corrupting an integer. Comparing two independent sessions catches
    // session-dependent and time-varying values alike.
    let direct2 = connect(&direct_url).await?;
    // How much masked data the generated SQL actually reached. Zero means the
    // run proved nothing, whatever the proxy did.
    let mut tokens_visible_directly = 0usize;
    let mut queries_reaching_masked_data = 0usize;
    // Set when the catalog masks nothing: the proxy then has to be a mirror.
    let mirror = std::env::var("EXPECT_MIRROR").is_ok();
    let mut compared = 0usize;
    let mut row_count_mismatch = 0usize;
    let mut nondeterministic = 0usize;
    let mut value_mismatch: Vec<(String, String, String)> = Vec::new();

    for (index, sql) in queries.iter().enumerate() {
        // A token present in the query itself would be echoed back legitimately,
        // and we cannot tell that apart from a leak. Skip rather than guess.
        if CANARIES.iter().any(|(token, _)| sql.contains(token)) {
            continue;
        }

        // Scoped to this iteration. As an outer variable it survived a query
        // that was refused or errored, and got compared against the *next*
        // query's response — a cross-statement mix-up that reported clean
        // queries as divergent.
        let mut mirror_baseline: Option<(usize, Vec<String>)> = None;

        // Constructs that are non-deterministic by definition. The double-run
        // check below is probabilistic and cannot filter these reliably:
        // TABLESAMPLE SYSTEM on a single-block table returns all-or-nothing, so
        // two consecutive runs agree about 80% of the time and the third
        // disagrees. That produced a "row-count mismatch" that looked like the
        // proxy losing rows.
        const NONDETERMINISTIC: &[&str] = &[
            "tablesample",
            "random(",
            "clock_timestamp",
            "timeofday",
            "nextval",
            "currval",
            "uuid_generate",
            "gen_random_uuid",
        ];
        let lowered = sql.to_ascii_lowercase();
        let skip_mirror = NONDETERMINISTIC.iter().any(|k| lowered.contains(k));

        if mirror && skip_mirror {
            nondeterministic += 1;
        } else if mirror {
            // Run the query twice against the database first. Generated SQL is
            // not all deterministic — volatile functions, LIMIT with no ORDER
            // BY — and a query that disagrees with itself cannot be used to
            // judge the proxy. 11 apparent row-count mismatches in the first
            // run were all of this kind; blaming the proxy for them would have
            // been the mirror-image of a vacuous pass.
            let baseline = shape_of_result(&direct, sql).await;
            let repeat = shape_of_result(&direct2, sql).await;
            if baseline.is_some() && baseline != repeat {
                nondeterministic += 1;
            } else {
                // Compared below, against the single proxy call the main path
                // makes. Querying the proxy twice here made its own rejection
                // counter read double the harness's, which broke the
                // cross-check that exists to catch exactly that kind of drift.
                mirror_baseline = baseline;
            }
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
        if mirror {
            if let Some((dr, dv)) = mirror_baseline.take() {
                let (pr, pv) = shape_from(&response);
                compared += 1;
                if dr != pr {
                    row_count_mismatch += 1;
                    if value_mismatch.len() < 5 {
                        value_mismatch.push((
                            format!("{dr} rows"),
                            format!("{pr} rows"),
                            sql.chars().take(400).collect(),
                        ));
                    }
                } else if dv != pv {
                    let at = dv.iter().zip(&pv).position(|(a, b)| a != b).unwrap_or(0);
                    if value_mismatch.len() < 5 {
                        value_mismatch.push((
                            dv.get(at).cloned().unwrap_or_default(),
                            pv.get(at).cloned().unwrap_or_default(),
                            sql.chars().take(160).collect(),
                        ));
                    }
                }
            }
        }
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
                if let Some(column) = shape_leak(value) {
                    leaks.push((
                        column.to_string(),
                        value.chars().take(60).collect(),
                        format!("#{index}: {}", sql.chars().take(200).collect::<String>()),
                    ));
                }
            }
        }
    }

    if mirror {
        // Nothing is masked in mirror mode, so canaries coming through is the
        // point of the run, not a finding.
        leaks.clear();
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
    println!("  postgres error           {errored:>6}  (incl. timeouts)");
    if reconnects > 0 {
        println!("  connection re-opened     {reconnects:>6}");
    }
    println!(
        "  session alive afterwards {:>6}",
        if alive { "yes" } else { "NO" }
    );
    println!("  LEAKED                   {:>6}", leaks.len());
    // Parsed by scripts/test-fuzz.sh when running seeds in parallel.
    if mirror {
        println!("  compared to direct       {compared:>6}  (mirror mode)");
        println!("  excluded, non-deterministic {nondeterministic:>4}  (disagreed with itself)");
        println!("  row-count mismatches     {row_count_mismatch:>6}");
        println!("  value mismatches         {:>6}", value_mismatch.len());
        for (d, p, sql) in value_mismatch.iter().take(3) {
            println!("    direct {d:?} vs proxy {p:?}\n      via {sql}");
        }
        if row_count_mismatch > 0 || !value_mismatch.is_empty() {
            eprintln!("\nwith nothing masked the proxy must be a byte-exact mirror; it is not");
            std::process::exit(1);
        }
        if compared == 0 {
            eprintln!("\nVACUOUS: mirror mode compared nothing");
            std::process::exit(2);
        }
    }
    println!(
        "RESULT statements={} served={} refused={} errors={} control={} leaks={}",
        queries.len(),
        served,
        refused,
        errored,
        tokens_visible_directly,
        leaks.len()
    );

    // A test that has never failed is not known to work. The poison run in
    // scripts/test-fuzz.sh deliberately unmasks a canary column and sets this,
    // so a fuzzer that has quietly stopped detecting anything fails loudly
    // instead of reporting a clean sweep.
    let expect_leaks = std::env::var("EXPECT_LEAKS").is_ok();
    if expect_leaks {
        println!(
            "\nEXPECT_LEAKS: the oracle must fire on this run ({} found)",
            leaks.len()
        );
        if leaks.is_empty() {
            eprintln!(
                "the oracle did not fire on a deliberately unmasked column — \
                 it is not detecting anything"
            );
            std::process::exit(1);
        }
        return Ok(());
    }

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
    // Generated SQL asks for cross joins across nine populated tables, so a
    // meaningful fraction of it is unbounded work. A hang would look like a
    // pass, and a 5s timeout made a 3000-statement seed take longer than the
    // whole campaign budget. Nothing worth testing here needs a second.
    let timeout = std::env::var("FUZZ_TIMEOUT_MS").unwrap_or_else(|_| "400".into());
    let _ = client
        .simple_query(&format!("SET statement_timeout = '{timeout}ms'"))
        .await;
    Ok(client)
}
