//! The backstop's premise, checked rather than assumed.
//!
//! `lineage::resolve` refuses to release anything when a masked column's name
//! appears in the statement. That is only a backstop if the name set is at
//! least as complete as the resolver's view: if `sqllineage` can report a source
//! column the backstop never saw, the two have blind spots in the wrong
//! direction and a field could be released whose masked source neither noticed.
//!
//! So this asserts the containment directly, over every construct the shape
//! generator emits plus the three that actually leaked:
//!
//!   every base column `sqllineage` reports as a source
//!     ⊆ every identifier the lexer finds in the statement
//!
//! **This test has already done its job once.** The backstop originally walked
//! `pg_query`'s parse tree for `ColumnRef`s, and this caught it missing `id` in
//! `sum(n) OVER (ORDER BY id …)` — the walker does not enter a `WindowDef`.
//! The backstop is lexical now, which has no such gap.
//!
//! One exception is legitimate and is skipped: `SELECT *`. There `sqllineage`
//! names columns that appear nowhere in the text, and it is the complete side —
//! every such field carries engine provenance anyway. The pair covers it; the
//! containment does not hold in that direction and is not required to.

#![allow(clippy::panic, clippy::unwrap_used)]

use pgmask::analysis;
use sqllineage::types::{AnalyzeOptions, ColumnOrigin, Dialect};

/// Every construct `shapegen` emits, the three shapes that leaked, and a few
/// deliberately awkward ones.
const STATEMENTS: &[&str] = &[
    // Leaf shapes.
    "SELECT a, b FROM fz.t1 r0",
    "SELECT r0.a FROM fz.t1 r0 WHERE r0.n < 100",
    "SELECT lower(a), upper(b), a || '', COALESCE(a, ''), substr(a, 1, 40) FROM fz.t1 r0",
    "SELECT CASE WHEN n > 0 THEN a ELSE NULL END FROM fz.t1 r0",
    "SELECT a::text FROM fz.t1 r0",
    // Composed shapes.
    "SELECT c0 FROM (SELECT a AS c0 FROM fz.t1) q",
    "WITH w AS (SELECT a AS c0 FROM fz.t1) SELECT c0 FROM w",
    "SELECT c0 FROM (SELECT a AS c0 FROM fz.t1) x UNION ALL SELECT c0 FROM (SELECT b AS c0 FROM fz.t2) y",
    "SELECT q.c0, r.b AS c1 FROM (SELECT a AS c0 FROM fz.t1) q JOIN fz.t2 r ON true",
    "SELECT DISTINCT c0 FROM (SELECT a AS c0 FROM fz.t1) q",
    "SELECT c0 FROM (SELECT a AS c0 FROM fz.t1) q ORDER BY 1 LIMIT 5",
    "SELECT c0, row_number() OVER (ORDER BY c0) FROM (SELECT a AS c0 FROM fz.t1) q",
    "SELECT min(c0), max(c0), string_agg(c0, ',') FROM (SELECT a AS c0 FROM fz.t1) q",
    "SELECT c0, count(*) FROM (SELECT a AS c0 FROM fz.t1) q GROUP BY c0",
    "SELECT sum(n) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW) FROM fz.t1 r0",
    // Typed columns.
    "SELECT d, u FROM fz.t1 r0",
    "SELECT birth_date, account_uuid, salary_big FROM fz.people r0",
    // The three that leaked.
    "SELECT city FROM fz.people UNION ALL SELECT email FROM fz.people",
    "SELECT v FROM fz.v_mixed",
    "SELECT min((SELECT d FROM fz.t8 LIMIT 1 OFFSET 3)) OVER (PARTITION BY subq.c0) \
     FROM (SELECT id AS c0 FROM fz.v_join) subq",
    // Awkward on purpose.
    "SELECT (SELECT email FROM fz.people LIMIT 1) AS c0 FROM fz.t1",
    "SELECT a FROM fz.t1 WHERE id IN (SELECT t_id FROM fz.u WHERE note IS NOT NULL)",
    "SELECT t.a FROM fz.t1 t, LATERAL (SELECT note FROM fz.u WHERE t_id = t.id) x",
    "WITH RECURSIVE c(id, a) AS (SELECT id, a FROM fz.t1 WHERE id = 1 \
     UNION ALL SELECT t.id, t.a FROM fz.t1 t JOIN c ON t.id = c.id + 1) SELECT a FROM c",
];

#[test]
fn the_backstop_sees_every_column_the_resolver_reports() {
    let mut checked = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for sql in STATEMENTS {
        // A wildcard makes the resolver name columns the text does not contain.
        // That is the one case where it is the more complete of the two.
        if sql.contains('*') {
            continue;
        }
        let Some(seen) = analysis::referenced_identifiers(sql) else {
            panic!("the lexer could not scan a statement this suite relies on: {sql}");
        };
        let opts = AnalyzeOptions {
            dialect: Dialect::PostgreSql,
            catalog: None,
            normalize_case: true,
        };
        let Ok(results) = sqllineage::analyze(sql, opts) else {
            // The resolver refusing is fine — it releases nothing then.
            continue;
        };
        for result in &results {
            for mapping in &result.columns.mappings {
                for source in &mapping.sources {
                    let ColumnOrigin::Concrete { column, .. } = source else {
                        continue;
                    };
                    checked = checked.saturating_add(1);
                    let wanted = column.to_ascii_lowercase();
                    if !seen.contains(&wanted) {
                        violations.push(format!(
                            "sqllineage reported source column {wanted:?} that the backstop never \
                             saw\n    in: {sql}\n    backstop saw: {seen:?}"
                        ));
                    }
                }
            }
        }
    }

    // A run that compared nothing proves nothing — the failure mode this repo
    // keeps rediscovering. The floor is one resolved source per statement on
    // average, which is a claim about the corpus rather than a number picked to
    // sit just under the current result.
    assert!(
        checked >= STATEMENTS.len(),
        "only {checked} source columns were compared across {} statements; \
         the corpus is not exercising the resolver",
        STATEMENTS.len()
    );
    assert!(
        violations.is_empty(),
        "the backstop is not a backstop for {} case(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
    println!("compared {checked} reported source columns, all seen by the backstop");
}
