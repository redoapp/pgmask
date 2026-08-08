//! Deciding whether an output field could be used to *read* a classified value.
//!
//! Fields with no provenance are refused. Measured against TPC-DS that refused
//! 90% of the queries — decision-support SQL is aggregate-shaped almost
//! everywhere, and an aggregate over a column has no provenance. This module
//! recovers the ones that cannot be used to read a value.
//!
//! # The threat model this encodes
//!
//! The bar is **"you cannot read an anonymised value"**, not "no information
//! flows". `sum(salary)` is released: it is a summary, not a salary. A group of
//! one row makes it that row's salary, and that is accepted — the same class of
//! trade already recorded for predicate oracles in `docs/handoff.md` §11.
//!
//! That relaxation is what makes this tractable without a lineage engine. If the
//! outermost node of a target expression is a reducing aggregate, it cannot
//! return a stored value *whatever is inside it*, so there is nothing to resolve.
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
    /// Cannot be used to read a classified value — either it references no
    /// column at all, or it only summarises.
    Releasable,
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

/// Aggregates that collapse many rows into a summary and structurally cannot
/// return one of the values they consumed.
///
/// Everything here answers "how many / how much / how spread out", never "which
/// one". Whatever the argument expression is, the result is not a member of the
/// input set.
const REDUCING_AGGREGATES: &[&str] = &[
    "count",
    "sum",
    "avg",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "variance",
    "var_pop",
    "var_samp",
    "corr",
    "covar_pop",
    "covar_samp",
    "regr_avgx",
    "regr_avgy",
    "regr_count",
    "regr_intercept",
    "regr_r2",
    "regr_slope",
    "regr_sxx",
    "regr_sxy",
    "regr_syy",
    "bool_and",
    "bool_or",
    "every",
];

// Deliberately absent from REDUCING_AGGREGATES, having been in it:
//
//   bit_and / bit_or / bit_xor — technically reductions, but far leakier per
//   group than the numeric summaries. `bit_or` over a handful of integers
//   reveals every bit set in any member. They are vanishingly rare over
//   classified columns, so the utility given up is nil.

/// Aggregates and window functions that **return one of the input values**, and
/// are therefore exactly what this module must keep refusing.
///
/// Not used in code — the allowlists above are what gate behaviour — but written
/// down because the temptation to add "aggregates are safe" as a category is
/// what would break this. `max(email)` is an email address.
const _RETURNS_A_STORED_VALUE: &[&str] = &[
    "min",
    "max",
    "mode",
    "percentile_disc",
    "percentile_cont",
    "first_value",
    "last_value",
    "nth_value",
    "lag",
    "lead",
    "string_agg",
    "array_agg",
    "json_agg",
    "jsonb_agg",
    "json_object_agg",
    "jsonb_object_agg",
    "xmlagg",
];

/// Window functions that emit a position or rank, never a value from the row.
///
/// Only released when actually used as a window function; the names are not
/// reserved and a plain call of the same name is not this.
const RANKING_WINDOWS: &[&str] = &[
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
];

/// Precisions `date_trunc` may coarsen to.
///
/// **The precision is an argument, so it is caller-controlled.**
/// `date_trunc('microseconds', birth_date)` coarsens nothing. Only units at or
/// above a day qualify, and the argument has to be a literal we can read — a
/// computed precision is not checkable.
const COARSE_DATE_UNITS: &[&str] = &[
    "day",
    "week",
    "month",
    "quarter",
    "year",
    "decade",
    "century",
    "millennium",
];

/// Pure scalar functions that compute from their arguments and nothing else.
///
/// Releasable *only when every argument is*, which is what makes them safe:
/// `round(sum(a) / sum(b), 1)` is arithmetic over summaries, `round(salary)` is
/// still a salary.
///
/// This has to be an allowlist rather than "any function with releasable
/// arguments". A user-defined `leak_email(1)` takes a constant and returns a
/// column value, so argument safety says nothing about an arbitrary function.
const PURE_SCALARS: &[&str] = &[
    "abs",
    "round",
    "ceil",
    "ceiling",
    "floor",
    "trunc",
    "sign",
    "mod",
    "div",
    "power",
    "sqrt",
    "cbrt",
    "exp",
    "ln",
    "log",
    "greatest",
    "least",
    "nullif",
    "to_char",
    "to_number",
    "numeric",
    "int4",
    "int8",
    "float8",
];

/// Classify each output field of `sql`, given how many fields the server said
/// the result set has.
///
/// Returns `Unknown` for every field unless a strict correspondence between the
/// statement's target list and the described fields can be established. Any
/// doubt anywhere collapses the whole analysis to `Unknown`.
pub fn analyze(sql: &str, field_count: usize, allow_summaries: bool) -> Vec<Safety> {
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

    // `SELECT * FROM (subquery)` wraps most TPC-DS queries. The star means the
    // outer target list has one entry and the result set has many, so positions
    // cannot map — but the fields are exactly the subquery's target list, in
    // order, so unwrap to it. Only for a single unaliased-star over a single
    // FROM entry; anything else and the correspondence is not ours to claim.
    let mut select: &SelectStmt = select;
    while let Some(inner) = unwrap_star_over_subquery(select) {
        select = inner;
    }

    if !positions_are_trustworthy(select, field_count) {
        return unknown;
    }

    select
        .target_list
        .iter()
        .map(|entry| match entry.node.as_ref() {
            Some(NodeEnum::ResTarget(target)) => {
                match target.val.as_ref().and_then(|v| v.node.as_ref()) {
                    Some(expr) => classify(expr, allow_summaries),
                    None => Safety::Unknown,
                }
            }
            _ => Safety::Unknown,
        })
        .collect()
}

/// `SELECT * FROM (subselect) alias` -> the subselect, when that is exactly the
/// shape. `WHERE`/`GROUP BY`/`ORDER BY`/`LIMIT` on the outer query do not change
/// which columns come out, so they are not obstacles.
fn unwrap_star_over_subquery(select: &SelectStmt) -> Option<&SelectStmt> {
    if select.op != SetOperation::SetopNone as i32 || select.from_clause.len() != 1 {
        return None;
    }
    // Exactly one target entry, and it is a bare `*`.
    let [only] = select.target_list.as_slice() else {
        return None;
    };
    let Some(NodeEnum::ResTarget(target)) = only.node.as_ref() else {
        return None;
    };
    let Some(NodeEnum::ColumnRef(col)) = target.val.as_ref().and_then(|v| v.node.as_ref()) else {
        return None;
    };
    let is_bare_star =
        col.fields.len() == 1 && matches!(col.fields[0].node.as_ref(), Some(NodeEnum::AStar(_)));
    if !is_bare_star {
        return None;
    }
    match select.from_clause[0].node.as_ref() {
        Some(NodeEnum::RangeSubselect(sub)) => {
            match sub.subquery.as_ref().and_then(|q| q.node.as_ref()) {
                Some(NodeEnum::SelectStmt(inner)) => Some(inner),
                _ => None,
            }
        }
        _ => None,
    }
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
fn classify(expr: &NodeEnum, allow_summaries: bool) -> Safety {
    match expr {
        // A literal. `SELECT 1`, `SELECT 'x'`, `SELECT NULL`.
        NodeEnum::AConst(_) => Safety::Releasable,

        // A bound parameter: a value the client supplied and already knows.
        NodeEnum::ParamRef(_) => Safety::Releasable,

        // CURRENT_DATE, CURRENT_TIMESTAMP, CURRENT_USER and friends — session
        // and clock context, parsed as their own node kind rather than as calls.
        NodeEnum::SqlvalueFunction(_) => Safety::Releasable,

        // A cast is safe exactly when what it casts is. `SELECT 1::text`.
        NodeEnum::TypeCast(cast) => match cast.arg.as_ref().and_then(|a| a.node.as_ref()) {
            Some(inner) => classify(inner, allow_summaries),
            None => Safety::Unknown,
        },

        NodeEnum::FuncCall(call) => {
            let Some(name) = function_name(&call.funcname) else {
                return Safety::Unknown;
            };
            let name = name.as_str();

            // Zero-argument session and clock context. Always releasable.
            let bare = call.args.is_empty() && call.agg_filter.is_none() && call.over.is_none();
            if !call.agg_star && bare && CONTEXT_FUNCTIONS.contains(&name) {
                return Safety::Releasable;
            }
            // count(*) is releasable even under the strict setting: it consumes
            // no column at all.
            if call.agg_star && call.over.is_none() && name == "count" {
                return Safety::Releasable;
            }
            if !allow_summaries {
                return Safety::Unknown;
            }

            // A reducing aggregate cannot return a value it consumed, so what
            // is inside it does not matter. A FILTER clause is allowed for the
            // same reason a WHERE clause is: the predicate oracle it creates
            // already exists in the query itself and is an accepted limitation.
            if REDUCING_AGGREGATES.contains(&name) {
                return Safety::Releasable;
            }
            // Ranking windows emit a position, not a value — but only when
            // actually used as a window function.
            if call.over.is_some() && RANKING_WINDOWS.contains(&name) {
                return Safety::Releasable;
            }
            // Precision reduction, and *only* to a coarse literal unit.
            //
            // `date_part`/`extract` are deliberately absent: they extract a
            // component rather than coarsen, and the component is an argument.
            // `date_part('epoch', birth_date)` returned the exact date through a
            // year-masked column — found by adversarial review, not by a test.
            // `width_bucket` is absent for the same reason: the bucket count is
            // caller-controlled and can be made lossless.
            if call.over.is_none() && name == "date_trunc" && call.args.len() >= 2 {
                if coarse_unit_literal(&call.args[0]) {
                    return Safety::Releasable;
                }
                return Safety::Unknown;
            }
            // A pure scalar over releasable arguments. `round(sum(a)/sum(b), 1)`
            // is the shape that made this necessary — wrapping a summary in
            // formatting should not lose its releasability.
            if call.over.is_none() && !call.args.is_empty() && PURE_SCALARS.contains(&name) {
                let all = call.args.iter().all(|a| {
                    a.node
                        .as_ref()
                        .map(|inner| classify(inner, allow_summaries) == Safety::Releasable)
                        .unwrap_or(false)
                });
                if all {
                    return Safety::Releasable;
                }
            }
            Safety::Unknown
        }

        // Arithmetic and comparison. Releasable exactly when every operand is:
        // `sum(a)/sum(b)` is still a summary, `salary * 2` is still a salary.
        NodeEnum::AExpr(expr) => {
            let operand = |side: &Option<Box<pg_query::protobuf::Node>>| match side
                .as_ref()
                .and_then(|n| n.node.as_ref())
            {
                Some(inner) => classify(inner, allow_summaries),
                // A missing side is a unary operator, not a hidden column.
                None => Safety::Releasable,
            };
            if operand(&expr.lexpr) == Safety::Releasable
                && operand(&expr.rexpr) == Safety::Releasable
            {
                Safety::Releasable
            } else {
                Safety::Unknown
            }
        }

        // Only the result branches can carry a value out. The WHEN conditions
        // are predicates, and a predicate over a classified column is the
        // already-accepted oracle, not a value read.
        NodeEnum::CaseExpr(case) => {
            let mut all = true;
            for arg in &case.args {
                if let Some(NodeEnum::CaseWhen(when)) = arg.node.as_ref() {
                    let branch = match when.result.as_ref().and_then(|r| r.node.as_ref()) {
                        Some(inner) => classify(inner, allow_summaries),
                        None => Safety::Unknown,
                    };
                    all &= branch == Safety::Releasable;
                } else {
                    all = false;
                }
            }
            if let Some(default) = case.defresult.as_ref().and_then(|d| d.node.as_ref()) {
                all &= classify(default, allow_summaries) == Safety::Releasable;
            }
            if all {
                Safety::Releasable
            } else {
                Safety::Unknown
            }
        }

        NodeEnum::CoalesceExpr(c) => {
            let all = c.args.iter().all(|a| {
                a.node
                    .as_ref()
                    .map(|inner| classify(inner, allow_summaries) == Safety::Releasable)
                    .unwrap_or(false)
            });
            if all {
                Safety::Releasable
            } else {
                Safety::Unknown
            }
        }

        _ => Safety::Unknown,
    }
}

/// Is this argument a string literal naming a coarse date unit?
///
/// Anything computed, or any unit finer than a day, fails closed.
fn coarse_unit_literal(arg: &pg_query::protobuf::Node) -> bool {
    let Some(NodeEnum::AConst(constant)) = arg.node.as_ref() else {
        return false;
    };
    match constant.val.as_ref() {
        Some(pg_query::protobuf::a_const::Val::Sval(s)) => {
            COARSE_DATE_UNITS.contains(&s.sval.trim().to_ascii_lowercase().as_str())
        }
        _ => false,
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

    /// Default posture: summaries released.
    fn safety(sql: &str, fields: usize) -> Vec<Safety> {
        analyze(sql, fields, true)
    }

    /// The stricter posture, for the cases that must hold either way.
    fn strict(sql: &str, fields: usize) -> Vec<Safety> {
        analyze(sql, fields, false)
    }

    fn is_safe(sql: &str) -> bool {
        safety(sql, 1) == vec![Safety::Releasable]
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
            vec![Safety::Unknown, Safety::Releasable]
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
    fn a_subquery_returning_a_column_stays_unknown() {
        assert_eq!(
            safety("SELECT (SELECT email FROM t LIMIT 1)", 1),
            vec![Safety::Unknown]
        );
    }

    /// Superseded by `ranking_windows_are_releasable_but_only_as_windows` and
    /// `aggregates_that_return_a_stored_value_stay_unknown`. What survives here
    /// is the distinction that matters: a window that ranks is fine, a window
    /// that reaches into a row is not.
    #[test]
    fn windows_are_split_by_whether_they_return_a_value() {
        assert_eq!(
            safety("SELECT count(*) OVER () FROM t", 1),
            vec![Safety::Releasable]
        );
        assert_eq!(
            safety("SELECT nth_value(email, 2) OVER (ORDER BY id) FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    /// FILTER is now allowed on a summarising aggregate. It creates a counting
    /// oracle, but the identical oracle already exists via a plain WHERE clause,
    /// which is an accepted limitation — refusing FILTER alone bought nothing.
    #[test]
    fn a_filtered_summary_is_releasable_but_a_filtered_selector_is_not() {
        assert_eq!(
            safety("SELECT count(*) FILTER (WHERE email = 'x') FROM t", 1),
            vec![Safety::Releasable]
        );
        assert_eq!(
            safety("SELECT max(email) FILTER (WHERE id > 0) FROM t", 1),
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

    /// The relaxation itself: a summary cannot return a member of the set it
    /// consumed, so what is inside it does not matter.
    #[test]
    fn summarising_aggregates_are_releasable() {
        for sql in [
            "SELECT sum(salary) FROM t",
            "SELECT avg(salary) FROM t",
            "SELECT count(email) FROM t",
            "SELECT count(DISTINCT email) FROM t",
            "SELECT stddev(salary) FROM t",
            "SELECT sum(CASE WHEN email = 'x' THEN 1 ELSE 0 END) FROM t",
            "SELECT sum(salary) OVER (PARTITION BY dept) FROM t",
            "SELECT sum(a) / sum(b) FROM t",
            "SELECT sum(salary) + 1 FROM t",
        ] {
            assert_eq!(
                safety(sql, 1),
                vec![Safety::Releasable],
                "{sql} should be releasable"
            );
        }
    }

    /// **The trap this whole module exists to avoid.** Every one of these is an
    /// aggregate or window function that hands back a value it consumed.
    /// `max(email)` is an email address.
    #[test]
    fn functions_that_return_a_stored_value_are_never_released() {
        for sql in [
            "SELECT max(email) FROM t",
            "SELECT min(email) FROM t",
            "SELECT mode() WITHIN GROUP (ORDER BY email) FROM t",
            "SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY salary) FROM t",
            "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY salary) FROM t",
            "SELECT string_agg(email, ',') FROM t",
            "SELECT array_agg(email) FROM t",
            "SELECT json_agg(email) FROM t",
            "SELECT jsonb_agg(email) FROM t",
            "SELECT xmlagg(email) FROM t",
            "SELECT first_value(email) OVER (ORDER BY id) FROM t",
            "SELECT last_value(email) OVER (ORDER BY id) FROM t",
            "SELECT nth_value(email, 2) OVER (ORDER BY id) FROM t",
            "SELECT lag(email) OVER (ORDER BY id) FROM t",
            "SELECT lead(email) OVER (ORDER BY id) FROM t",
        ] {
            assert_eq!(
                safety(sql, 1),
                vec![Safety::Unknown],
                "{sql} returns a stored value and must never be released"
            );
        }
    }

    /// Arithmetic is releasable only when every operand is. A summary divided by
    /// a summary is a summary; a column times two is still that column.
    #[test]
    fn arithmetic_is_releasable_only_through_releasable_operands() {
        assert_eq!(safety("SELECT salary * 2 FROM t", 1), vec![Safety::Unknown]);
        assert_eq!(safety("SELECT salary + 0 FROM t", 1), vec![Safety::Unknown]);
        assert_eq!(
            safety("SELECT email || '' FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT sum(a) - sum(b) FROM t", 1),
            vec![Safety::Releasable]
        );
    }

    /// Only CASE *results* can carry a value out. A condition over a classified
    /// column is a predicate, which is the already-accepted oracle.
    #[test]
    fn case_is_judged_on_its_result_branches() {
        assert_eq!(
            safety("SELECT CASE WHEN id > 0 THEN email ELSE NULL END FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT CASE WHEN email = 'x' THEN 1 ELSE 0 END FROM t", 1),
            vec![Safety::Releasable]
        );
        // A releasable branch and a leaking branch is not releasable.
        assert_eq!(
            safety("SELECT CASE WHEN id > 0 THEN 1 ELSE email END FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn ranking_windows_are_releasable_but_only_as_windows() {
        assert_eq!(
            safety("SELECT row_number() OVER (ORDER BY salary) FROM t", 1),
            vec![Safety::Releasable]
        );
        assert_eq!(
            safety("SELECT rank() OVER (ORDER BY salary) FROM t", 1),
            vec![Safety::Releasable]
        );
        assert_eq!(
            safety("SELECT row_number() FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn coarsening_is_releasable_but_never_as_a_window() {
        assert_eq!(
            safety("SELECT date_trunc('month', birth_date) FROM t", 1),
            vec![Safety::Releasable]
        );
        // A window frame can narrow to a single row, so the argument does not
        // hold there.
        assert_eq!(
            safety("SELECT date_trunc('month', birth_date) OVER () FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn the_strict_setting_refuses_summaries_but_keeps_count_star() {
        assert_eq!(
            strict("SELECT sum(salary) FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            strict("SELECT avg(salary) FROM t", 1),
            vec![Safety::Unknown]
        );
        // count(*) consumes no column at all, so it survives either way.
        assert_eq!(
            strict("SELECT count(*) FROM t", 1),
            vec![Safety::Releasable]
        );
        assert_eq!(strict("SELECT 1", 1), vec![Safety::Releasable]);
    }

    #[test]
    fn unknown_and_qualified_function_names_are_not_trusted() {
        assert_eq!(
            safety("SELECT my_agg(email) FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT evil.sum(email) FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    /// `SELECT * FROM (subquery)` wraps most TPC-DS queries; the fields are the
    /// subquery's target list, positionally.
    #[test]
    fn a_star_over_a_subquery_is_unwrapped() {
        assert_eq!(
            safety(
                "SELECT * FROM (SELECT city, sum(salary) FROM t GROUP BY city) q",
                2
            ),
            vec![Safety::Unknown, Safety::Releasable]
        );
        // But not when the correspondence is not ours to claim.
        assert_eq!(
            safety("SELECT * FROM (SELECT 1) a, (SELECT 2) b", 2),
            vec![Safety::Unknown; 2]
        );
        assert_eq!(
            safety(
                "SELECT * FROM (SELECT email FROM t UNION SELECT email FROM t) q",
                1
            ),
            vec![Safety::Unknown]
        );
    }

    #[test]
    fn pure_scalars_pass_through_releasability() {
        assert_eq!(
            safety("SELECT round(sum(a) / sum(b), 1) FROM t", 1),
            vec![Safety::Releasable]
        );
        assert_eq!(
            safety("SELECT abs(sum(salary)) FROM t", 1),
            vec![Safety::Releasable]
        );
        // ...but never over a column.
        assert_eq!(
            safety("SELECT round(salary) FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT abs(salary) FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    /// The reason PURE_SCALARS is an allowlist. A user-defined function taking a
    /// harmless argument can return anything at all, so "all arguments are
    /// releasable" says nothing about an arbitrary callee.
    #[test]
    fn an_unknown_function_over_releasable_arguments_is_not_released() {
        assert_eq!(
            safety("SELECT leak_email(1) FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT leak_email() FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT leak_email(count(*)) FROM t", 1),
            vec![Safety::Unknown]
        );
    }

    /// Regression for a hole found by adversarial review rather than by a test.
    ///
    /// `date_part`/`extract` do not coarsen, they extract a component, and the
    /// component is an argument. Through a `date-year` masked column,
    /// `date_part('epoch', birth_date)` returned the exact date and
    /// `date_part('day', …)` returned precisely what the mask hides.
    #[test]
    fn component_extraction_is_never_released() {
        for sql in [
            "SELECT date_part('epoch', birth_date) FROM t",
            "SELECT date_part('day', birth_date) FROM t",
            "SELECT extract(epoch from birth_date) FROM t",
            "SELECT extract(day from birth_date) FROM t",
            "SELECT width_bucket(salary, 0, 1000000, 1000000) FROM t",
        ] {
            assert_eq!(
                safety(sql, 1),
                vec![Safety::Unknown],
                "{sql} recovers detail the mask removed"
            );
        }
    }

    /// `date_trunc` is released only to a coarse *literal* precision. The unit is
    /// an argument, so a fine one coarsens nothing.
    #[test]
    fn date_trunc_is_released_only_at_coarse_literal_precision() {
        for unit in ["day", "month", "quarter", "year"] {
            assert_eq!(
                safety(
                    &format!("SELECT date_trunc('{unit}', birth_date) FROM t"),
                    1
                ),
                vec![Safety::Releasable],
                "{unit} should be coarse enough"
            );
        }
        for unit in ["microseconds", "milliseconds", "second", "minute", "hour"] {
            assert_eq!(
                safety(
                    &format!("SELECT date_trunc('{unit}', birth_date) FROM t"),
                    1
                ),
                vec![Safety::Unknown],
                "{unit} coarsens too little"
            );
        }
        // A computed precision cannot be checked, so it fails closed.
        assert_eq!(
            safety("SELECT date_trunc(some_unit, birth_date) FROM t", 1),
            vec![Safety::Unknown]
        );
    }
}
