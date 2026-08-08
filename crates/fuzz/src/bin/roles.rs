//! Hammer the same columns from several principals at once and check nobody
//! sees another principal's view.
//!
//! Masks resolve per principal: in this fixture `support_sam` reads
//! `full_name` in the clear, `analyst_ann` gets `birth_date` to month
//! precision, and everyone else gets neither. All sessions share one
//! `Arc<Policy>` and one catalog snapshot, and each keeps its own plans — so
//! the question is whether a plan built for one session can ever be applied in
//! another.
//!
//! Nothing about that failure would be visible to a single-principal test, and
//! it is the kind that appears only under concurrency. A single wrong answer
//! anywhere in the run is a disclosure, so the assertion is exact rather than
//! statistical: every row, every session, every iteration.
//!
//! Usage:
//!   PROXY_URL=postgres://…:6470/fuzzdb roles [sessions] [iterations]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use tokio_postgres::NoTls;

/// What one principal must see, and must never see.
#[derive(Clone, Copy)]
struct Expectation {
    user: &'static str,
    /// `full_name` in the clear, or redacted.
    name_is_clear: bool,
    /// `birth_date` truncated to the month rather than the year.
    date_is_month: bool,
}

const PRINCIPALS: &[Expectation] = &[
    Expectation {
        user: "support_sam",
        name_is_clear: true,
        date_is_month: false,
    },
    Expectation {
        user: "analyst_ann",
        name_is_clear: false,
        date_is_month: true,
    },
    Expectation {
        user: "postgres",
        name_is_clear: false,
        date_is_month: false,
    },
];

#[tokio::main]
async fn main() -> Result<()> {
    let base = std::env::var("PROXY_URL").context("PROXY_URL is required")?;
    let sessions: usize = std::env::args()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let iterations: usize = std::env::args()
        .nth(2)
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    // The raw dates, so each principal's answer is compared against the exact
    // value its mask should produce.
    //
    // Matching the *shape* — "month precision keeps a month, so it must not end
    // -01-01" — is wrong for any date in January, where month and year
    // truncation are the same value. That reported 40 false violations.
    let direct_url = std::env::var("DIRECT_URL").context("DIRECT_URL is required")?;
    let raw_dates: Arc<HashMap<i32, jiff::civil::Date>> = {
        let (client, connection) = tokio_postgres::connect(&direct_url, NoTls)
            .await
            .context("connecting directly for the baseline")?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let rows = client
            .query("SELECT id, birth_date FROM fz.people", &[])
            .await
            .context("reading raw birth dates")?;
        Arc::new(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    };
    if raw_dates.is_empty() {
        bail!("the fixture has no rows, so nothing would be checked");
    }

    let violations = Arc::new(AtomicUsize::new(0));
    let checks = Arc::new(AtomicUsize::new(0));
    let reported: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Prove the check can fail. With POISON set, every principal claims the
    // permissive view, so a run that reports zero violations is a run that is
    // not looking. A test that has never failed is not known to work.
    let poison = std::env::var("POISON").is_ok();

    let mut tasks = Vec::new();
    for i in 0..sessions {
        let base_expect = &PRINCIPALS[i % PRINCIPALS.len()];
        let expect = Expectation {
            user: base_expect.user,
            name_is_clear: base_expect.name_is_clear || poison,
            date_is_month: base_expect.date_is_month || poison,
        };
        // Same host and database, different user. Anchored on `://` because
        // `replacen("postgres:", …)` rewrites the *scheme* first, which
        // produced `support_sam//postgres:demo@…` and failed every connection.
        let url = base.replacen("://postgres:", &format!("://{}:", expect.user), 1);
        let violations = violations.clone();
        let checks = checks.clone();
        let reported = reported.clone();
        let raw_dates = raw_dates.clone();
        tasks.push(tokio::spawn(async move {
            let (client, connection) = tokio_postgres::connect(&url, NoTls)
                .await
                .with_context(|| format!("connecting as {}", expect.user))?;
            tokio::spawn(async move {
                let _ = connection.await;
            });

            for n in 0..iterations {
                // Vary the row so plans are rebuilt rather than trivially reused.
                let id = (n % 40 + 1) as i32;
                let row = client
                    .query_one(
                        // Not `birth_date::text`: a cast is an expression over
                        // a masked column and is refused, correctly.
                        "SELECT full_name, birth_date, email FROM fz.people WHERE id = $1",
                        &[&id],
                    )
                    .await?;
                let name: String = row.get(0);
                let date = row.get::<_, jiff::civil::Date>(1).to_string();
                let email: String = row.get(2);

                let name_ok = if expect.name_is_clear {
                    name.starts_with("CANARY-name-")
                } else {
                    name == "***"
                };
                let raw = raw_dates.get(&id).copied().expect("id is in the fixture");
                let expected = if expect.date_is_month {
                    jiff::civil::date(raw.year(), raw.month(), 1)
                } else {
                    jiff::civil::date(raw.year(), 1, 1)
                };
                let date_ok = date == expected.to_string();
                // Nobody, in any role, may read the address.
                let email_ok = !email.contains("CANARY");

                checks.fetch_add(3, Ordering::Relaxed);
                for (what, ok, got) in [
                    ("full_name", name_ok, name.as_str()),
                    ("birth_date", date_ok, date.as_str()),
                    ("email", email_ok, email.as_str()),
                ] {
                    if !ok {
                        violations.fetch_add(1, Ordering::Relaxed);
                        let mut r = reported.lock().expect("poisoned");
                        if r.len() < 8 {
                            r.push(format!(
                                "{} saw {what} = {got:?} (id {id}, iteration {n})",
                                expect.user
                            ));
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }));
    }

    let mut failed = 0;
    for task in tasks {
        if let Err(err) = task.await.expect("task panicked") {
            eprintln!("session failed: {err:#}");
            failed += 1;
        }
    }

    let checks = checks.load(Ordering::Relaxed);
    let violations = violations.load(Ordering::Relaxed);
    println!("\nper-principal masking under concurrency");
    println!("---------------------------------------------");
    println!(
        "  sessions                {sessions:>8}  ({} principals interleaved)",
        PRINCIPALS.len()
    );
    println!("  assertions              {checks:>8}");
    println!("  sessions that errored   {failed:>8}");
    println!("  VIOLATIONS              {violations:>8}");
    for line in reported.lock().expect("poisoned").iter() {
        println!("    {line}");
    }

    if failed > 0 {
        bail!("{failed} session(s) failed outright");
    }
    // A run where nothing was checked proves nothing, which is the failure this
    // repo keeps rediscovering.
    if checks == 0 {
        bail!("no assertions ran");
    }
    if violations > 0 {
        bail!("{violations} principal(s) saw another principal's view");
    }
    Ok(())
}
