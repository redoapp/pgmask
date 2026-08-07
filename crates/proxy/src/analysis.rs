//! Proving that an output field cannot contain a column value.
//!
//! Fields with no provenance are refused, and measurement against a real
//! database put that at 23% of queries refused for no good reason — `SELECT 1`,
//! `now()`, `count(*)`. This module recovers those.
//!
//! # Why an allowlist of shapes, and not "does it reference a column?"
//!
//! The obvious rule is "walk the expression; if it contains no `ColumnRef` it
//! cannot leak a column". That requires an *exhaustive* traversal, and
//! `pg_query`'s own walker documents that it "doesn't iterate over every
//! possible node type". Proving absence across an incomplete traversal is
//! unsound, and this rule converts refusals into acceptances — so unsound means
//! a leak, not a false pass.
//!
//! So the burden is inverted. Rather than prove no column is referenced, we
//! match a short list of expression shapes that are *positively known* to carry
//! no column data. Anything not on the list stays refused. Adding a shape is a
//! deliberate, reviewable act; forgetting one costs utility, never safety.

use pg_query::protobuf::{node::Node as NodeEnum, SelectStmt, SetOperation};

/// What we can say about one output field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Safety {
    /// Positively identified as carrying no column value.
    ProvablyColumnFree,
    /// Everything else. Says nothing about the field; the caller keeps its
    /// existing behaviour.
    Unknown,
}

/// Zero-argument functions returning session or clock context, never table data.
///
/// Deliberately short. `random()` and `gen_random_uuid()` would also qualify but
/// are omitted because nothing needs them and every entry is attack surface.
const CONTEXT_FUNCTIONS: &[&str] = &[
    "now",
    "current_database",
    "current_catalog",
    "current_schema",
    "current_user",
    "session_user",
    "user",
    "version",
    "clock_timestamp",
    "statement_timestamp",
    "transaction_timestamp",
    "pg_backend_pid",
];

/// Aggregates that reduce to a count and cannot emit a stored value.
///
/// `count(*)` only. `count(col)` is also safe in principle but takes an
/// argument, and admitting arguments is where this gets subtle — `max(email)`
/// returns an actual email address. Keep the door narrow.
const STAR_AGGREGATES: &[&str] = &["count"];

/// Classify each output field of `sql`, given how many fields the server said
/// the result set has.
///
/// Returns `Unknown` for every field unless a strict correspondence between the
/// statement's target list and the described fields can be established. Any
/// doubt anywhere collapses the whole analysis to `Unknown`.
pub fn analyze(sql: &str, field_count: usize) -> Vec<Safety> {
    let unknown = vec![Safety::Unknown; field_count];

    let Ok(parsed) = pg_query::parse(sql) else {
        return unknown;
    };
    // More than one statement means several result sets from one query string,
    // and we would have to track which is which.
    if parsed.protobuf.stmts.len() != 1 {
        return unknown;
    }
    let Some(NodeEnum::SelectStmt(select)) = parsed
        .protobuf
        .stmts
        .first()
        .and_then(|s| s.stmt.as_ref())
        .and_then(|s| s.node.as_ref())
    else {
        return unknown;
    };

    if !positions_are_trustworthy(select, field_count) {
        return unknown;
    }

    select
        .target_list
        .iter()
        .map(|entry| match entry.node.as_ref() {
            Some(NodeEnum::ResTarget(target)) => {
                match target.val.as_ref().and_then(|v| v.node.as_ref()) {
                    Some(expr) => classify(expr),
                    None => Safety::Unknown,
                }
            }
            _ => Safety::Unknown,
        })
        .collect()
}

/// Can target-list position `i` be trusted to be described field `i`?
///
/// A set operation has no single target list. `SELECT *` expands one entry into
/// many fields — which the length check below catches, since the expansion makes
/// the counts disagree.
fn positions_are_trustworthy(select: &SelectStmt, field_count: usize) -> bool {
    select.op == SetOperation::SetopNone as i32
        && select.larg.is_none()
        && select.rarg.is_none()
        && select.target_list.len() == field_count
}

/// The allowlist proper.
fn classify(expr: &NodeEnum) -> Safety {
    match expr {
        // A literal. `SELECT 1`, `SELECT 'x'`, `SELECT NULL`.
        NodeEnum::AConst(_) => Safety::ProvablyColumnFree,

        // A bound parameter: a value the client supplied and already knows.
        NodeEnum::ParamRef(_) => Safety::ProvablyColumnFree,

        // CURRENT_DATE, CURRENT_TIMESTAMP, CURRENT_USER and friends — session
        // and clock context, parsed as their own node kind rather than as calls.
        NodeEnum::SqlvalueFunction(_) => Safety::ProvablyColumnFree,

        // A cast is safe exactly when what it casts is. `SELECT 1::text`.
        NodeEnum::TypeCast(cast) => match cast.arg.as_ref().and_then(|a| a.node.as_ref()) {
            Some(inner) => classify(inner),
            None => Safety::Unknown,
        },

        NodeEnum::FuncCall(call) => {
            let name = function_name(&call.funcname);
            let Some(name) = name else {
                return Safety::Unknown;
            };
            // Anything with arguments, a FILTER, or an OVER clause is out of
            // scope: `row_number() OVER (ORDER BY salary)` reveals an ordering
            // over a column even though it emits no value from one.
            let bare = call.args.is_empty() && call.agg_filter.is_none() && call.over.is_none();

            if call.agg_star && bare && STAR_AGGREGATES.contains(&name.as_str()) {
                return Safety::ProvablyColumnFree; // count(*)
            }
            if !call.agg_star && bare && CONTEXT_FUNCTIONS.contains(&name.as_str()) {
                return Safety::ProvablyColumnFree; // now(), current_database()
            }
            Safety::Unknown
        }

        _ => Safety::Unknown,
    }
}

/// The bare function name, rejecting anything schema-qualified.
///
/// `pg_catalog.now()` is the same function, but `myschema.now()` is not, and
/// telling them apart means resolving search_path. Refusing qualified names
/// costs a little utility and removes the question.
fn function_name(parts: &[pg_query::protobuf::Node]) -> Option<String> {
    if parts.len() != 1 {
        return None;
    }
    match parts[0].node.as_ref()? {
        NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safety(sql: &str, fields: usize) -> Vec<Safety> {
        analyze(sql, fields)
    }

    fn is_safe(sql: &str) -> bool {
        safety(sql, 1) == vec![Safety::ProvablyColumnFree]
    }

    // --- What the rule exists to rescue -------------------------------------

    #[test]
    fn literals_are_provably_column_free() {
        assert!(is_safe("SELECT 1"));
        assert!(is_safe("SELECT 'hello'"));
        assert!(is_safe("SELECT NULL"));
        assert!(is_safe("SELECT 1::text"));
    }

    #[test]
    fn context_functions_are_provably_column_free() {
        assert!(is_safe("SELECT now()"));
        assert!(is_safe("SELECT current_database()"));
        assert!(is_safe("SELECT version()"));
        assert!(is_safe("SELECT CURRENT_TIMESTAMP"));
        assert!(is_safe("SELECT CURRENT_USER"));
    }

    #[test]
    fn count_star_is_provably_column_free() {
        assert!(is_safe("SELECT count(*) FROM t"));
    }

    /// The most common analytical shape there is, and the reason this rule pays
    /// for itself: the group key keeps its normal masking, the count is rescued.
    #[test]
    fn group_by_with_a_count_rescues_only_the_count() {
        assert_eq!(
            safety("SELECT city, count(*) FROM t GROUP BY city", 2),
            vec![Safety::Unknown, Safety::ProvablyColumnFree]
        );
    }

    // --- What must never be rescued -----------------------------------------

    #[test]
    fn anything_touching_a_column_stays_unknown() {
        for sql in [
            "SELECT email FROM t",
            "SELECT lower(email) FROM t",
            "SELECT email || '' FROM t",
            "SELECT coalesce(email, '') FROM t",
            "SELECT CASE WHEN id > 0 THEN email END FROM t",
            "SELECT email::text FROM t",
            "SELECT substr(email, 1, 5) FROM t",
            "SELECT to_json(t) FROM t",
        ] {
            assert_eq!(
                safety(sql, 1),
                vec![Safety::Unknown],
                "{sql} must not be rescued"
            );
        }
    }

    #[test]
    fn aggregates_that_emit_stored_values_stay_unknown() {
        // The trap: these are aggregates, but max(email) IS an email address.
        for sql in [
            "SELECT max(email) FROM t",
            "SELECT min(email) FROM t",
            "SELECT string_agg(email, ',') FROM t",
            "SELECT array_agg(email) FROM t",
            "SELECT count(email) FROM t",
        ] {
            assert_eq!(
                safety(sql, 1),
                vec![Safety::Unknown],
                "{sql} must not be rescued"
            );
        }
    }

    #[test]
    fn a_subquery_returning_a_column_stays_unknown() {
        assert_eq!(
            safety("SELECT (SELECT email FROM t LIMIT 1)", 1),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn window_functions_stay_unknown() {
        // Emits no stored value, but reveals an ordering over one.
        assert_eq!(
            safety("SELECT count(*) OVER () FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT row_number() OVER (ORDER BY salary) FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn filtered_aggregates_stay_unknown() {
        // count(*) FILTER (WHERE email = 'x') is a predicate oracle.
        assert_eq!(
            safety("SELECT count(*) FILTER (WHERE email = 'x') FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn a_shadowed_function_name_stays_unknown() {
        // Someone could define evil.now() returning a column value.
        assert_eq!(safety("SELECT evil.now() FROM t", 1), vec![Safety::Unknown]);
    }

    // --- Position correspondence --------------------------------------------

    #[test]
    fn set_operations_collapse_the_whole_analysis() {
        assert_eq!(
            safety("SELECT 1 UNION ALL SELECT 1", 1),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn a_star_shifts_positions_so_nothing_is_claimed() {
        // `SELECT *, 1 FROM t` has 2 target entries but N fields. If the counts
        // disagree we must not map position 1 to the literal.
        assert_eq!(
            safety("SELECT *, 1 FROM t", 5),
            vec![Safety::Unknown; 5],
            "a star expansion must not let a literal claim the wrong position"
        );
    }

    #[test]
    fn multi_statement_input_collapses_the_analysis() {
        assert_eq!(safety("SELECT 1; SELECT 2", 1), vec![Safety::Unknown]);
    }

    #[test]
    fn unparseable_sql_collapses_the_analysis() {
        assert_eq!(safety("this is not sql", 1), vec![Safety::Unknown]);
        assert_eq!(safety("", 1), vec![Safety::Unknown]);
    }

    #[test]
    fn a_field_count_mismatch_collapses_the_analysis() {
        assert_eq!(safety("SELECT 1, 2", 3), vec![Safety::Unknown; 3]);
    }

    #[test]
    fn non_select_statements_are_not_analysed() {
        assert_eq!(
            safety("INSERT INTO t (a) VALUES (1) RETURNING a", 1),
            vec![Safety::Unknown]
        );
    }
}
