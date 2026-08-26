//! Output-field classification: which expressions cannot carry a stored value.

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{SelectStmt, SetOperation};

use super::names::{
    function_name, CONTEXT_FUNCTIONS, NON_VALUE_REDUCING_AGGREGATES, PURE_SCALARS, RANKING_WINDOWS,
    REDUCING_AGGREGATES, SIZE_FUNCTIONS,
};
use super::StatementInspection;

/// What we can say about one output field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Safety {
    /// Cannot be used to read a classified value — either it references no
    /// column at all, or it only summarises.
    Releasable,
    /// A reducing aggregate: `sum(x)`, `avg(x)`, a variance, a regression
    /// slope. It is a summary when the input set is large and the *identity*
    /// function when the set collapses to one row, so it is only as safe as
    /// what it reduces. The caller resolves a single bare source from explicitly
    /// schema-qualified SQL and applies that column's policy. More complex
    /// summaries retain the opaque posture; optional lineage may still prove
    /// that all of their sources are explicitly released.
    Summary,
    /// A JSON/JSONB extract whose path is a sequence of literals
    /// (`payload->>'email'`, `payload->'profile'`, `#>> '{a,b}'`). Provenance
    /// is gone, so the session resolves the source column from schema-qualified
    /// SQL and applies that column's pointer policy to the extract. Anything
    /// not on the allowlist stays `Unknown` and is refused.
    JsonExtract,
    /// Everything else. Says nothing about the field; the caller keeps its
    /// existing behaviour.
    Unknown,
}

/// Which release paths the session is willing to open for this result set.
///
/// Both depend on facts `analysis` cannot see — the policy, and the catalog —
/// so they are decided by the caller and passed in rather than guessed at here.
#[derive(Clone, Copy, Debug)]
pub struct Relaxations {
    /// `summaries = "allow"`, and the grouping does not make a summary into a
    /// value. See the singleton-group guard in `session`.
    pub summaries: bool,
    /// Whether `date_trunc` may coarsen to a unit finer than a year.
    ///
    /// Year and above are safe unconditionally: they are at least as coarse as
    /// the coarsest date mask, so they cannot return more than the mask allows.
    /// Finer units can, and this module has no way to know whether the column
    /// underneath is masked — the field is computed, so it carries no
    /// provenance and no classification.
    ///
    /// The caller sets this when the *statement* names no masked column, which
    /// is the same lexical backstop the lineage and catalog paths use. It keeps
    /// `date_trunc('month', placed_at)` working on a column the operator has
    /// released, and refuses `date_trunc('day', birth_date)`, which returned
    /// the whole value through a year-masked column.
    pub fine_date_trunc: bool,
}

/// Precisions `date_trunc` may coarsen to.
///
/// **The precision is an argument, so it is caller-controlled.**
/// `date_trunc('microseconds', birth_date)` coarsens nothing, and the argument
/// has to be a literal we can read — a computed precision is not checkable.
///
/// "At or above a day" was the original rule and it was a disclosure. The
/// release is sound only when the truncation is at least as coarse as the
/// *mask*, and this module cannot see the mask: the field is computed, so it
/// has no provenance and no classification. The coarsest date mask pgmask
/// offers is `date-year`, so year is the finest unit that is safe against every
/// column it could be applied to. Measured against the fixture, whose
/// `birth_date` is year-masked to `1975-01-01`:
///
///   date_trunc('year',  birth_date) -> 1975-01-01   the masked value
///   date_trunc('day',   birth_date) -> 1975-02-14   the whole value
///   date_trunc('week',  birth_date) -> 1975-02-10   a seven-day window
///
/// `month` and `quarter` are excluded for the same reason even though a
/// `date-month` column exists: this cannot tell the two masks apart.
///
/// The cost is that `date_trunc('month', ts)` — ordinary time bucketing — is no
/// longer released *here*. It is not refused outright: with no provenance the
/// field falls through to lineage, which resolves the underlying column and
/// releases when it is unmasked. That is the correct division of labour, since
/// deciding this needs the classification that only lineage has.
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

/// Units at least as coarse as the coarsest date mask, so safe against any
/// column whatever its classification.
const YEAR_OR_COARSER: &[&str] = &["year", "decade", "century", "millennium"];

/// Is this argument a literal naming a unit of a year or more?
fn date_unit_at_least_a_year(arg: &pg_query::protobuf::Node) -> bool {
    let Some(NodeEnum::AConst(constant)) = arg.node.as_ref() else {
        return false;
    };
    match constant.val.as_ref() {
        Some(pg_query::protobuf::a_const::Val::Sval(s)) => {
            YEAR_OR_COARSER.contains(&s.sval.trim().to_ascii_lowercase().as_str())
        }
        _ => false,
    }
}

/// Classify each output field of `sql`, given how many fields the server said
/// the result set has.
///
/// Returns `Unknown` for every field unless a strict correspondence between the
/// statement's target list and the described fields can be established. Any
/// doubt anywhere collapses the whole analysis to `Unknown`.
pub fn analyze(sql: &str, field_count: usize, allow: Relaxations) -> Vec<Safety> {
    StatementInspection::new(sql).output_safety(field_count, allow)
}

pub(crate) fn analyze_inspected(
    inspection: &StatementInspection<'_>,
    field_count: usize,
    allow: Relaxations,
) -> Vec<Safety> {
    let unknown = vec![Safety::Unknown; field_count];

    let Some(parsed) = inspection.parsed() else {
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
                    Some(expr) => classify(expr, allow),
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
pub(crate) fn unwrap_star_over_subquery(select: &SelectStmt) -> Option<&SelectStmt> {
    // Both halves are re-enforced structurally below, so this early return is
    // defensive duplication rather than the load-bearing check: a set operation
    // carries no top-level target list and fails the `[only]` pattern, and the
    // `[only_from]` pattern admits exactly one source. `cargo mutants` reports
    // flipping this `||` to `&&` as a survivor for that reason — it is an
    // equivalent mutant, not a hole, and it is left in place rather than
    // deleted because reading the guard here is cheaper than deriving it from
    // two slice patterns forty lines apart.
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
    // Slice patterns rather than a length check plus an index: the compiler
    // enforces the correspondence, where `len() == 1` followed by `[0]` only
    // reads as if it does.
    let [NodeEnum::AStar(_)] = [col
        .fields
        .as_slice()
        .first()
        .and_then(|f| f.node.as_ref())
        .filter(|_| col.fields.len() == 1)?]
    else {
        return None;
    };
    let [only_from] = select.from_clause.as_slice() else {
        return None;
    };
    match only_from.node.as_ref() {
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
pub(crate) fn positions_are_trustworthy(select: &SelectStmt, field_count: usize) -> bool {
    select.op == SetOperation::SetopNone as i32
        && select.larg.is_none()
        && select.rarg.is_none()
        && select.target_list.len() == field_count
        // A star expands to however many columns the relation has, and the
        // length check above was the only thing standing between that and a
        // misaligned verdict. It works whenever a star expands to something
        // other than one column — except that a star over a *zero-column*
        // relation expands to none, and a second star expanding to two puts
        // the total back:
        //
        //   CREATE TEMP TABLE e();
        //   SELECT e.*, 1, upper(p.email), q.* FROM e, people p, (…) q
        //
        // Four targets, four fields, every position after the zero-expander
        // shifted by one — so the literal's `Releasable` landed on
        // `upper(email)`, which has no provenance, and the address was served.
        // `CREATE TEMP TABLE` is granted to PUBLIC by default.
        //
        // Counting cannot distinguish the aligned case from the shifted one, so
        // a star anywhere in the list means the positions are not ours to
        // claim. `SELECT *` alone is unaffected: it never matched the length
        // check to begin with.
        && !select.target_list.iter().any(target_is_star)
}

/// Whether a target is `*` or `alias.*`.
fn target_is_star(node: &pg_query::protobuf::Node) -> bool {
    let Some(NodeEnum::ResTarget(target)) = &node.node else {
        return false;
    };
    let Some(value) = target.val.as_ref().and_then(|v| v.node.as_ref()) else {
        return false;
    };
    let NodeEnum::ColumnRef(column) = value else {
        return false;
    };
    column
        .fields
        .last()
        .and_then(|f| f.node.as_ref())
        .is_some_and(|f| matches!(f, NodeEnum::AStar(_)))
}

/// The name a reducing aggregate's target reduces, when `expr` is that
/// aggregate over a single unadorned column.
///
/// [`classify`] reaches `Safety::Summary` for a `FuncCall` that is a reducing
/// aggregate with no `OVER` clause, and for a cast chain around one — the
/// aggregate's own `FILTER`/`DISTINCT` stay on the `FuncCall`. So the shapes
/// here mirror exactly what a `Summary` field can be: the aggregate call,
/// optionally wrapped in casts. An argument that is an expression, a qualified
/// name, or a whole row is lineage's job — the session refuses rather than
/// guess, and the caller applies the same "masked only, never passthrough" bar.
pub(crate) fn summary_argument_name(expr: &NodeEnum, depth: usize) -> Option<String> {
    if depth > 8 {
        return None;
    }
    match expr {
        NodeEnum::TypeCast(cast) => cast
            .arg
            .as_ref()
            .and_then(|a| a.node.as_ref())
            .and_then(|a| summary_argument_name(a, depth.saturating_add(1))),
        NodeEnum::CollateClause(collate) => collate
            .arg
            .as_ref()
            .and_then(|a| a.node.as_ref())
            .and_then(|a| summary_argument_name(a, depth.saturating_add(1))),
        NodeEnum::FuncCall(call) => {
            // Multi-argument regressions do not necessarily return a summary
            // of their first argument: `regr_avgx(y, x)` returns the average
            // of `x`. One source mask cannot govern an output derived from
            // several inputs, so leave every such call opaque.
            let [arg] = call.args.as_slice() else {
                return None;
            };
            // Peel casts off the argument, mirroring the outer wrapper walk.
            let mut arg = arg;
            let arg = loop {
                match arg.node.as_ref()? {
                    NodeEnum::TypeCast(cast) => arg = cast.arg.as_ref()?,
                    NodeEnum::CollateClause(collate) => arg = collate.arg.as_ref()?,
                    inner => break inner,
                }
            };
            let NodeEnum::ColumnRef(column_ref) = arg else {
                return None;
            };
            // Exactly one, unqualified: `sum(salary)`. `sum(t.salary)` and
            // whole-row refs are left to lineage.
            let [only] = column_ref.fields.as_slice() else {
                return None;
            };
            let NodeEnum::String(name) = only.node.as_ref()? else {
                return None;
            };
            Some(name.sval.to_ascii_lowercase())
        }
        _ => None,
    }
}

/// The allowlist proper.
fn classify(expr: &NodeEnum, allow: Relaxations) -> Safety {
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
            Some(inner) => classify(inner, allow),
            None => Safety::Unknown,
        },
        // Collation changes comparison/sort semantics, not the projected
        // bytes. Keep it aligned with the extract/summary parsers, which both
        // peel this wrapper before attributing the source.
        NodeEnum::CollateClause(collate) => {
            match collate.arg.as_ref().and_then(|a| a.node.as_ref()) {
                Some(inner) => classify(inner, allow),
                None => Safety::Unknown,
            }
        }

        NodeEnum::FuncCall(call) => {
            if super::json_extract::expr_is_json_extract(expr) {
                return Safety::JsonExtract;
            }
            let Some(name) = function_name(&call.funcname) else {
                return Safety::Unknown;
            };
            let name = name.as_str();

            // Zero-argument session and clock context. Always releasable.
            let bare = call.args.is_empty() && call.agg_filter.is_none() && call.over.is_none();
            if !call.agg_star && bare && CONTEXT_FUNCTIONS.contains(&name) {
                return Safety::Releasable;
            }
            // A size function returns a byte count whatever it is pointed at,
            // so no argument of it can come back out. Releasable under the
            // strict setting for the same reason `count(*)` is.
            if call.over.is_none() && SIZE_FUNCTIONS.contains(&name) {
                return Safety::Releasable;
            }
            // count(*) is releasable even under the strict setting: it consumes
            // no column at all.
            //
            // Deliberately not conditioned on `over`, unlike the aggregate arm
            // below. A frame changes *which rows* `count(*)` counts, never what
            // it returns — a row count, never a value from a row. The general
            // aggregates cannot say that: `sum(x)` over a one-row frame is `x`.
            if call.agg_star && name == "count" {
                return Safety::Releasable;
            }
            if !allow.summaries {
                return Safety::Unknown;
            }

            // A reducing aggregate over a masked column can be masked on its
            // way out, so it stays usable where an arbitrary expression over a
            // masked column is refused — see `Safety::Summary`. A FILTER clause
            // is allowed for the same reason a WHERE clause is: the predicate
            // oracle it creates already exists in the query itself and is an
            // accepted limitation.
            //
            // **`over.is_none()` is load-bearing, and its absence was a
            // disclosure.** As a window function the same name does not reduce
            // anything: the frame is chosen by the caller, and
            //
            //   SELECT sum(annual_salary)
            //            OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW)
            //     FROM fz.people
            //
            // returned exact salaries through a bucketed column under the
            // strictest configuration — `lineage = "refuse"`, `opaque =
            // "reject"` — because `Releasable` short-circuits both. A frame of
            // one row makes every "reducing" aggregate the identity function.
            //
            // That is not the accepted group-of-one trade recorded in the module
            // header. A group of one is incidental to the data; a frame of one
            // is a thing the client writes down. `count(*)` above already tests
            // `over`; this arm did not.
            //
            // Analysing the frame to spot the safe ones is precisely the
            // prove-absence reasoning this module refuses to do, so every
            // windowed aggregate is refused.
            if call.over.is_none() && REDUCING_AGGREGATES.contains(&name) {
                // A count returns a tally, never a member of the input set, so
                // it cannot degrade into a value no matter how small the group
                // is. Boolean reductions are the identity over a singleton set
                // and therefore fall through to `Summary` below.
                if NON_VALUE_REDUCING_AGGREGATES.contains(&name) {
                    return Safety::Releasable;
                }
                // Everything else — `sum`, `avg`, a variance, a regression
                // slope — is `Safety::Summary`: potentially the identity of an
                // input when the set collapses. The session applies a source
                // policy only for one bare argument column; complex summaries
                // keep the opaque posture.
                return Safety::Summary;
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
                // `first()` cannot be None here, but expressing that as a
                // fallible read costs nothing and removes the panic entirely.
                if call.args.first().is_some_and(date_unit_at_least_a_year) {
                    return Safety::Releasable;
                }
                // Finer than a year: only when nothing masked is in the
                // statement at all.
                if allow.fine_date_trunc && call.args.first().is_some_and(coarse_unit_literal) {
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
                        .map(|inner| classify(inner, allow) == Safety::Releasable)
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
        NodeEnum::AExpr(_) => {
            if super::json_extract::expr_is_json_extract(expr) {
                return Safety::JsonExtract;
            }
            let NodeEnum::AExpr(aexpr) = expr else {
                return Safety::Unknown;
            };
            let operand = |side: &Option<Box<pg_query::protobuf::Node>>| match side
                .as_ref()
                .and_then(|n| n.node.as_ref())
            {
                Some(inner) => classify(inner, allow),
                // A missing side is a unary operator, not a hidden column.
                None => Safety::Releasable,
            };
            if operand(&aexpr.lexpr) == Safety::Releasable
                && operand(&aexpr.rexpr) == Safety::Releasable
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
                        Some(inner) => classify(inner, allow),
                        None => Safety::Unknown,
                    };
                    all &= branch == Safety::Releasable;
                } else {
                    all = false;
                }
            }
            if let Some(default) = case.defresult.as_ref().and_then(|d| d.node.as_ref()) {
                all &= classify(default, allow) == Safety::Releasable;
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
                    .map(|inner| classify(inner, allow) == Safety::Releasable)
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

/// The column names one `GROUP BY` item can distinguish rows by.
///
/// Appends to `into` and returns `None` the moment the item cannot be read, so
/// a partial answer is never mistaken for a complete one — the caller refuses
/// on `None`, and half a grouping is exactly the case where releasing would be
/// wrong.
pub(crate) fn group_item_columns(
    item: &pg_query::protobuf::Node,
    targets: &[pg_query::protobuf::Node],
    into: &mut Vec<String>,
) -> Option<()> {
    // `GROUP BY ROLLUP(a, CUBE(b, c))` is legal, so this recurses. Bounded
    // because the parser has already rejected anything deeper than its own
    // nesting limit, but bounded explicitly rather than by that assumption.
    fn walk(
        item: &pg_query::protobuf::Node,
        targets: &[pg_query::protobuf::Node],
        into: &mut Vec<String>,
        depth: u32,
        // Whether this node is a *grouping element* — the position where
        // Postgres resolves an output alias. True at the top of an item and
        // through `ROLLUP`/`CUBE`/`GROUPING SETS`, which nest grouping
        // elements; false below an ordinal, which lands in an expression.
        // Measured, not assumed: `GROUP BY ROLLUP(c)` resolves the alias and
        // `GROUP BY c+0` reports `column "c" does not exist`.
        as_element: bool,
    ) -> Option<()> {
        // `> 16` -> `== 16` or `>= 16` both survive the mutation campaign, and
        // both are equivalent for safety: every path increments (`d =
        // depth.saturating_add(1)`, passed to every recursive call), so all
        // three still cap, one level earlier or later. Detecting the difference
        // needs an expression nested exactly 16 deep, and the number is a
        // stack guard rather than a property. What matters is that the cap
        // returns `None` — refuse — and that is tested.
        if depth > 16 {
            return None;
        }
        match item.node.as_ref()? {
            NodeEnum::ColumnRef(column) => {
                let name = column.fields.last().and_then(|f| match &f.node {
                    Some(NodeEnum::String(s)) => Some(s.sval.to_ascii_lowercase()),
                    // `GROUP BY t.*` is not a name we can reduce.
                    _ => None,
                })?;
                into.push(name.clone());

                // A bare name in `GROUP BY` may be an *output alias* rather
                // than a column, and then it denotes whatever the target
                // computes. `SELECT id AS c, sum(salary) … GROUP BY c` groups by
                // `id`, one row per group, and reading only the alias reported
                // `c` — not a key — and released every salary. That is the
                // original disclosure with two extra characters, and it is what
                // "read the grouping" kept getting wrong: a name in the clause
                // is not the column being grouped on. SQL separates the two
                // four ways — ordinal, star, alias, expression.
                //
                // Both names are collected, because which one wins is not
                // decidable here: Postgres prefers an *input* column of that
                // name and only falls back to the output alias, and knowing
                // whether the input column exists needs the relation's columns.
                // Collecting both over-refuses in the shadowed case and cannot
                // under-refuse in either.
                //
                // Only in a grouping element, which is where Postgres applies
                // output-name resolution. The resolved target is walked as a
                // non-element, which both matches Postgres — an alias is not
                // resolved again inside an expression — and bounds the lookup,
                // so `SELECT c AS c … GROUP BY c` cannot chase its own alias.
                if as_element && column.fields.len() == 1 {
                    for entry in targets {
                        let Some(NodeEnum::ResTarget(target)) = entry.node.as_ref() else {
                            continue;
                        };
                        if !target.name.is_empty() && target.name.to_ascii_lowercase() == name {
                            walk(
                                target.val.as_ref()?,
                                targets,
                                into,
                                depth.saturating_add(1),
                                false,
                            )?;
                        }
                    }
                }
                Some(())
            }
            // An ordinal names an *output* column, which is a target-list entry
            // only while the two lists correspond. A star breaks that: it
            // expands to however many columns its relation has, so every
            // position after it is shifted by an amount not visible here, and
            // `GROUP BY 2` can name one column while `target_list[1]` holds
            // another. Resolving it then reports a name that is not the
            // grouping — and if the real one is a key while the reported one is
            // not, that releases the aggregate this exists to refuse. A star
            // over a zero-column relation shifts by one, and `CREATE TEMP
            // TABLE e()` is granted to PUBLIC by default.
            //
            // `positions_are_trustworthy` already refuses any statement with a
            // star before this can matter, so today this is unreachable. It is
            // checked here anyway: this reader is public, its result decides a
            // release on its own, and depending on a neighbouring check to stay
            // sound is how the misaligned-star disclosure got in.
            //
            // Only a plain column reference at the resolved position is
            // readable; an ordinal onto an expression is no more legible than
            // the expression.
            NodeEnum::AConst(constant) => {
                if targets.iter().any(target_is_star) {
                    return None;
                }
                let Some(pg_query::protobuf::a_const::Val::Ival(value)) = constant.val.as_ref()
                else {
                    return None;
                };
                let position = usize::try_from(value.ival).ok()?.checked_sub(1)?;
                let Some(NodeEnum::ResTarget(target)) = targets.get(position)?.node.as_ref() else {
                    return None;
                };
                walk(
                    target.val.as_ref()?,
                    targets,
                    into,
                    depth.saturating_add(1),
                    false,
                )
            }
            // ROLLUP, CUBE and GROUPING SETS. Unioning the names across every
            // set is the safe direction: each set is a subset of the union, so
            // a key contained in one of them is contained in the union. An
            // empty set — `GROUP BY ()` — contributes nothing, which is right,
            // since it groups the whole relation into one row.
            NodeEnum::GroupingSet(set) => {
                for member in &set.content {
                    walk(member, targets, into, depth.saturating_add(1), as_element)?;
                }
                Some(())
            }
            // A multi-column set inside `GROUPING SETS ((a, b), (c))`. Read for
            // consistency with the single-column form, which is otherwise an
            // arbitrary-looking split.
            NodeEnum::RowExpr(row) => {
                for member in &row.args {
                    walk(member, targets, into, depth.saturating_add(1), as_element)?;
                }
                Some(())
            }
            // Everything else, which importantly includes a grouping construct
            // nested inside another: `ROLLUP(a, CUBE(b, c))` parses the inner
            // `CUBE` as an ordinary `FuncCall`, because the raw parse tree is
            // not the analysed tree and only the outermost construct becomes a
            // `GroupingSet`. Reading it would mean matching on the function
            // name, and `cube` is a real function from a real extension.
            _ => None,
        }
    }
    walk(item, targets, into, 0, true)
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
