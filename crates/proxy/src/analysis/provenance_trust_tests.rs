#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
use super::*;

/// Set operations must never be trusted, whatever the engine reports.
///
/// CockroachDB's simple-query RowDescription gives a UNION the first
/// branch's table OID, so `SELECT city … UNION ALL SELECT email …` applied
/// `city`'s "released" classification to `email`'s values and returned a
/// real address. Postgres zeroes it, which is why five major versions of
/// testing never showed this.
#[test]
fn set_operations_are_never_trusted() {
    for sql in [
        "SELECT city FROM t UNION ALL SELECT email FROM t",
        "SELECT city FROM t UNION SELECT email FROM t",
        "SELECT city FROM t INTERSECT SELECT email FROM t",
        "SELECT city FROM t EXCEPT SELECT email FROM t",
        "SELECT x FROM (SELECT city AS x FROM t UNION ALL SELECT email FROM t) q",
        "WITH u AS (SELECT city FROM t UNION SELECT email FROM t) SELECT * FROM u",
        "SELECT 1 LIMIT (SELECT city FROM t UNION ALL SELECT email FROM t)",
    ] {
        assert!(!provenance_is_trustworthy(sql), "must distrust: {sql}");
    }
}

#[test]
fn ordinary_statements_keep_their_provenance() {
    for sql in [
        "SELECT email FROM t",
        "SELECT a.email, b.city FROM t a JOIN t b ON b.id = a.id",
        "SELECT email FROM t WHERE id = 1 ORDER BY id LIMIT 5",
        "WITH q AS (SELECT email FROM t) SELECT email FROM q",
        "SELECT * FROM t",
    ] {
        assert!(provenance_is_trustworthy(sql), "must trust: {sql}");
    }
}

#[test]
fn unparseable_sql_is_not_trusted() {
    // We cannot rule a set operation out, so we do not claim to.
    assert!(!provenance_is_trustworthy("this is not sql"));
    assert!(!provenance_is_trustworthy(""));
}
