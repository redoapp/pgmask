//! Which release decisions does a generated corpus actually reach?
//!
//! The leak oracle answers "did anything escape". It cannot answer "was this
//! rule ever consulted", and that is the question that matters for a corpus:
//! a rule no generated statement reaches is a rule the campaign says nothing
//! about, however many statements it runs.
//!
//! Two disclosures have now been found in rules that were in exactly that
//! position — `PURE_SCALARS` in 0.1.9 and `date_trunc` in 0.1.23 — both by
//! reading the code, because no statement in the corpus could express them.
//!
//! This replays a corpus through `analysis` alone, with no server and no
//! proxy, and reports how many statements each verdict and each releasable
//! shape accounts for. Run it under `cargo llvm-cov` for line-level detail;
//! run it bare for the summary.
//!
//! Usage:
//!   reach <corpus.sql>

use std::collections::BTreeMap;

use pgmask::analysis::{self, Relaxations, Safety};

const ALLOW: Relaxations = Relaxations {
    summaries: true,
    fine_date_trunc: true,
};

/// The releasable shapes worth counting separately, matched on the statement
/// text. Crude on purpose: the point is which *kinds* of statement the corpus
/// contains, and a false positive here understates a gap rather than hiding it.
const SHAPES: &[(&str, &str)] = &[
    ("reducing aggregate", "sum("),
    ("reducing aggregate", "avg("),
    ("count(*)", "count(*)"),
    ("ranking window", "row_number()"),
    ("windowed aggregate", ") OVER ("),
    ("date_trunc", "date_trunc("),
    ("size formatter", "pg_size_pretty("),
    ("value size", "pg_column_size("),
    ("pure scalar", "round("),
    ("pure scalar", "abs("),
    ("session context", "current_setting("),
    ("set operation", " UNION "),
    ("set operation", " EXCEPT "),
    ("set operation", " INTERSECT "),
    ("grouping", "GROUP BY"),
    ("string_agg", "string_agg("),
    ("min/max", "min("),
    ("min/max", "max("),
];

/// How many fields the server will describe for this statement.
///
/// Read off the top-level target list. A star expands to an unknown number, so
/// there is no answer and the caller falls back — which lands in the same
/// `Unknown` the analysis would reach anyway.
fn target_count(sql: &str) -> Option<usize> {
    let parsed = pg_query::parse(sql).ok()?;
    let [statement] = parsed.protobuf.stmts.as_slice() else {
        return None;
    };
    let pg_query::NodeEnum::SelectStmt(select) = statement.stmt.as_ref()?.node.as_ref()? else {
        return None;
    };
    // Set operations carry their targets on the branches.
    let targets = if select.target_list.is_empty() {
        select.larg.as_ref().map(|l| l.target_list.len())?
    } else {
        select.target_list.len()
    };
    (targets > 0).then_some(targets)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: reach <corpus.sql>")?;
    let corpus = std::fs::read_to_string(&path)?;
    let statements: Vec<&str> = corpus
        .split(";\n")
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("--"))
        .collect();

    let mut releasable = 0usize;
    let mut any_unknown = 0usize;
    let mut shapes: BTreeMap<&str, usize> = BTreeMap::new();

    for sql in &statements {
        // The real target count, not 1. `analyze` collapses everything to
        // Unknown when the field count and the target list disagree, so a
        // guessed count reports the whole corpus as refused and says nothing
        // about which rules ran — the first version of this probe claimed 99
        // of 3000 statements were releasable for exactly that reason.
        let fields = target_count(sql).unwrap_or(1);
        let verdicts = analysis::analyze(sql, fields, ALLOW);
        if verdicts.iter().all(|v| *v == Safety::Releasable) {
            releasable = releasable.saturating_add(1);
        } else {
            any_unknown = any_unknown.saturating_add(1);
        }
        for (label, needle) in SHAPES {
            if sql.contains(needle) {
                *shapes.entry(label).or_insert(0) =
                    shapes.get(label).unwrap_or(&0).saturating_add(1);
            }
        }
    }

    println!("corpus: {} statements", statements.len());
    // `Unknown` here is not "refused". A plain column projection is Unknown to
    // the allowlist by design — it has provenance, so the catalog decides it.
    // These two numbers only say how much of the corpus the *allowlist* settles
    // on its own; the reachability below is what this probe is for.
    println!("  released by the allowlist alone  {releasable:>7}");
    println!("  left to provenance or lineage    {any_unknown:>7}");
    println!("\nshapes present:");
    let mut missing = Vec::new();
    for (label, _) in SHAPES {
        if !shapes.contains_key(label) && !missing.contains(label) {
            missing.push(*label);
        }
    }
    for (label, n) in &shapes {
        println!("  {n:>7}  {label}");
    }
    if missing.is_empty() {
        println!("\nevery tracked shape is present in this corpus");
        return Ok(());
    }
    println!("\nNOT REACHED by any statement — the campaign says nothing about these:");
    for label in &missing {
        println!("    {label}");
    }
    // A release rule with no generated statement behind it is the position both
    // `PURE_SCALARS` and `date_trunc` were in when each produced a disclosure.
    Err(format!(
        "{} release shape(s) unreachable by this corpus",
        missing.len()
    )
    .into())
}
