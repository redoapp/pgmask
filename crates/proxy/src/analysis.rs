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

use std::sync::OnceLock;

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

/// One parsed and lazily scanned view of a statement for a release decision.
///
/// A `RowDescription` asks several independent safety questions. Keeping their
/// conservative rules separate is useful; reparsing the same SQL for each one
/// is not. This module gives those checks one deep interface while preserving
/// their independent implementations.
pub struct StatementInspection<'sql> {
    sql: &'sql str,
    parsed: OnceLock<Option<pg_query::ParseResult>>,
    identifiers: OnceLock<Option<Vec<String>>>,
}

impl<'sql> StatementInspection<'sql> {
    pub fn new(sql: &'sql str) -> Self {
        Self {
            sql,
            parsed: OnceLock::new(),
            identifiers: OnceLock::new(),
        }
    }

    pub fn sql(&self) -> &'sql str {
        self.sql
    }

    pub fn is_parseable(&self) -> bool {
        self.parsed().is_some()
    }

    pub fn identifiers(&self) -> Option<&[String]> {
        self.identifiers
            .get_or_init(|| scan_identifiers(self.sql))
            .as_deref()
    }

    pub fn output_safety(&self, field_count: usize, allow_summaries: bool) -> Vec<Safety> {
        analyze_inspected(self, field_count, allow_summaries)
    }

    pub fn reads_only_server_metadata(&self) -> bool {
        reads_only_server_metadata_inspected(self)
    }

    pub fn provenance_is_trustworthy(&self) -> bool {
        provenance_is_trustworthy_inspected(self)
    }

    pub fn every_relation_is_qualified(&self) -> bool {
        every_relation_is_qualified_inspected(self)
    }

    fn parsed(&self) -> Option<&pg_query::ParseResult> {
        self.parsed
            .get_or_init(|| pg_query::parse(self.sql).ok())
            .as_ref()
    }
}

/// Functions reporting how much storage an object occupies.
///
/// Every GUI client shows table sizes; Beekeeper's stack and Harlequin both
/// call these. They take a relation and return a byte count, so unlike
/// `min(email)` there is no argument that could come back out — the return type
/// is a number, whatever is inside. They do leak approximate row counts, which
/// is the same order of disclosure as `count(*)`, already accepted.
///
/// `pg_read_file` and friends are emphatically not here; those are on
/// [`CATALOG_ESCAPE_FUNCTIONS`].
const SIZE_FUNCTIONS: &[&str] = &[
    "pg_relation_size",
    "pg_table_size",
    "pg_indexes_size",
    "pg_total_relation_size",
    "pg_database_size",
    "pg_tablespace_size",
];

// Size-*formatting* functions. Released only when their argument is.
//
// These were on the list above, justified by the same sentence — "they take a
// relation and return a byte count, so there is no argument that could come
// back out". That is true of the six that remain and false of these three,
// which take a **value**:
//
// ```sql
// SELECT pg_size_pretty(salary) FROM t;                       -- "4321 bytes"
// SELECT pg_size_pretty((salary % 10000)::bigint),
//        pg_size_pretty((salary / 10000)::bigint) FROM t;      -- exact, any bigint
// SELECT pg_column_size(email) FROM t;                         -- exact byte length
// ```
//
// `pg_size_pretty` renders `|v| < 10240` as `"%lld bytes"`, so a modulo and a
// divide reconstruct any value exactly. Same shape as the `sum(...) OVER`
// disclosure: a caller-supplied argument turns an allowlisted "cannot return
// an input" function into the identity. Found by an audit, confirmed against
// a live server.
//
// They live in [`PURE_SCALARS`] instead, which releases a call only when every
// argument is releasable. That keeps the case GUI clients actually need —
// `pg_size_pretty(pg_table_size('t'))`, a formatted *relation* size — and
// refuses the value ones, without a special case for either.

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

/// Set-returning functions allowed in a `FROM` clause of a metadata query.
///
/// An allowlist rather than a denylist, because the denylist here is on
/// *relations*: `LEAKY_SYSTEM_CATALOGS` denies the `pg_stat_activity` and
/// `pg_stat_statements` views, and the SRFs behind them —
/// `pg_stat_get_activity()`, `pg_stat_statements()` — return identical rows
/// while appearing as a `RangeFunction` that no relation rule matches. Naming
/// those two would leave every other data-bearing SRF, `pg_ls_waldir()`
/// included.
///
/// Everything here computes from its arguments and reads no table. The list is
/// short on purpose and exists because psql's `\d` genuinely needs
/// `generate_series` in `FROM`; without it, describing a table stops working
/// on four of five Postgres versions, which is the whole reason
/// `system_catalogs = "allow"` exists.
const GENERATORS_IN_FROM: &[&str] = &["generate_series", "generate_subscripts", "unnest"];

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
    // Size formatters: safe over a size, an identity over a value. See the
    // note above `SIZE_FUNCTIONS`.
    "pg_size_pretty",
    "pg_size_bytes",
    "pg_column_size",
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
    StatementInspection::new(sql).output_safety(field_count, allow_summaries)
}

fn analyze_inspected(
    inspection: &StatementInspection<'_>,
    field_count: usize,
    allow_summaries: bool,
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
fn positions_are_trustworthy(select: &SelectStmt, field_count: usize) -> bool {
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
            if !allow_summaries {
                return Safety::Unknown;
            }

            // A reducing aggregate cannot return a value it consumed, so what
            // is inside it does not matter. A FILTER clause is allowed for the
            // same reason a WHERE clause is: the predicate oracle it creates
            // already exists in the query itself and is an accepted limitation.
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
                // `first()` cannot be None here, but expressing that as a
                // fallible read costs nothing and removes the panic entirely.
                if call.args.first().is_some_and(coarse_unit_literal) {
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
    let [only] = parts else {
        return None;
    };
    match only.node.as_ref()? {
        NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
        _ => None,
    }
}

// --- System catalogs --------------------------------------------------------
//
// GUI clients (DBeaver, DataGrip, pgAdmin) and psql's own `\d` commands read
// `pg_catalog` on connect. Those queries are full of expressions —
// `pg_get_userbyid(c.relowner)`, `format_type(...)`, `'pg_class'::regclass` —
// so output classification refuses them, and the columns that *do* have
// provenance point at catalog tables that are not in anyone's catalog file, so
// default-deny nulls them.
//
// Nulling is the worse half. `\d` sends a follow-up query built from the OID
// the first one returned; masked to NULL, psql interpolates an empty string and
// Postgres answers `invalid input syntax for type oid: ""`. Default-deny did
// not refuse, it corrupted the client's logic.
//
// The rule below releases a result set when **every relation the statement
// reads is a system catalog holding metadata rather than user data**. Nothing
// from a user table can appear in the output of a query that reads no user
// table, so the fields need no provenance.

/// Catalogs that hold user data, not metadata about it.
///
/// Measured, not assumed. On the demo database `pg_stats` returns
/// `most_common_vals = {shared@example.com}` for a pseudonymised column, and
/// exact `histogram_bounds` for a date masked to its year and an IP masked to
/// its /24. Releasing `pg_catalog` wholesale would hand back the values the
/// proxy exists to hide.
///
/// `pg_statistic_ext` is deliberately absent: it records *which* extended
/// statistics objects exist. The values live in `pg_statistic_ext_data`, and
/// `\d` reads the former.
const LEAKY_SYSTEM_CATALOGS: &[&str] = &[
    // Sampled values from user tables.
    "pg_statistic",
    "pg_statistic_ext_data",
    "pg_stats",
    "pg_stats_ext",
    "pg_stats_ext_exprs",
    // Other sessions' SQL text, literals included.
    "pg_stat_activity",
    "pg_stat_statements",
    "pg_prepared_statements",
    // Large object contents.
    "pg_largeobject",
    // Password hashes and connection strings.
    "pg_authid",
    "pg_shadow",
    "pg_user_mapping",
    "pg_user_mappings",
    "pg_subscription",
    // Host configuration and file contents.
    "pg_file_settings",
    "pg_hba_file_rules",
    "pg_ident_file_mappings",
    "pg_backend_memory_contexts",
];

/// Functions that reach data the parse tree never names.
///
/// `query_to_xml('SELECT * FROM demo.customers', …)` takes its query as a
/// *string*, so no `RangeVar` for `customers` exists to check. Without this
/// list the whole rule is bypassable in one call.
const CATALOG_ESCAPE_FUNCTIONS: &[&str] = &[
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "dblink",
    "dblink_send_query",
    "dblink_get_result",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_get",
    "lo_import",
    "lo_export",
];

/// True when this statement reads only server metadata — a `SHOW`, or a query
/// whose every relation is a metadata-only system catalog — so the result set
/// carries nothing from a user table.
///
/// **This check alone is not sufficient, and is not meant to be.** It reasons
/// about names, and a name proves nothing: Harlequin writes `from pg_database`
/// unqualified, and `CREATE TABLE public.pg_database` is permitted (Postgres
/// reserves the `pg_` prefix for *schema* names, not relation names), so
/// `SET search_path TO public, pg_catalog` can make an unqualified catalog name
/// resolve to a user table.
///
/// The caller must therefore also confirm, against `Snapshot::is_system_relation`,
/// that every provenance-bearing field in the `RowDescription` really belongs to
/// `pg_catalog` or `information_schema`. That is the engine's own answer and the
/// only one `search_path` cannot move. This function's job is the part OIDs
/// cannot cover: relations that appear in the statement without surfacing as an
/// output field, and functions that take SQL as a string.
///
/// Fails closed everywhere: an unparseable statement, a statement that names no
/// relation at all, a CTE reference that is not declared locally, and any
/// function on [`CATALOG_ESCAPE_FUNCTIONS`] all return `false`.
pub fn reads_only_server_metadata(sql: &str) -> bool {
    StatementInspection::new(sql).reads_only_server_metadata()
}

fn reads_only_server_metadata_inspected(inspection: &StatementInspection<'_>) -> bool {
    use pg_query::NodeRef;

    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    if parsed.protobuf.stmts.len() != 1 {
        return false;
    }

    // `SHOW search_path` and friends. Every JDBC driver sends one during
    // connection setup, and a GUC holds server configuration — there is no path
    // from a table's contents into one.
    if let Some(NodeEnum::VariableShowStmt(_)) = parsed
        .protobuf
        .stmts
        .first()
        .and_then(|s| s.stmt.as_ref())
        .and_then(|s| s.node.as_ref())
    {
        return true;
    }

    // Collected first: a CTE reference is an unqualified RangeVar, and refusing
    // every catalog query that uses `WITH` would be needlessly strict. The
    // CTE's own body is walked like everything else, so this shadows nothing.
    let mut cte_names: Vec<String> = Vec::new();
    for (node, _, _, _) in parsed.protobuf.nodes() {
        if let NodeRef::CommonTableExpr(cte) = node {
            cte_names.push(cte.ctename.to_ascii_lowercase());
        }
    }

    let mut saw_relation = false;
    for (node, _, _, _) in parsed.protobuf.nodes() {
        match node {
            NodeRef::RangeVar(v) => {
                let schema = v.schemaname.to_ascii_lowercase();
                let relation = v.relname.to_ascii_lowercase();

                if schema.is_empty() {
                    // A locally declared CTE, or a bare name that at least
                    // *looks* like a system catalog. Whether it really is one is
                    // settled by the OID check in the caller, not here.
                    if cte_names.contains(&relation) {
                        continue;
                    }
                    if !relation.starts_with("pg_") {
                        return false;
                    }
                } else if schema != "pg_catalog" && schema != "information_schema" {
                    return false;
                }
                if LEAKY_SYSTEM_CATALOGS.contains(&relation.as_str()) {
                    return false;
                }
                saw_relation = true;
            }
            // A set-returning function in `FROM`.
            //
            // `LEAKY_SYSTEM_CATALOGS` denies `pg_stat_activity` and
            // `pg_stat_statements` — "other sessions' SQL text, literals
            // included". Those are *views*, and the SRFs behind them produce
            // identical rows while appearing as a `RangeFunction` that neither
            // the RangeVar arm nor the escape list matches:
            //
            //   SELECT a.query FROM pg_stat_get_activity(NULL) a, pg_class c
            //
            // The joined `pg_class` even supplies the `saw_relation` the
            // function alone would fail on. That is the denylist polarity
            // problem in its purest form: the same bypass exists for every
            // data-bearing SRF, named or not. A relation-only rule has no such
            // hole, and a catalog query that genuinely needs a function in
            // `FROM` loses the fast path rather than the answer.
            NodeRef::RangeFunction(range) => {
                for item in &range.functions {
                    let Some(NodeEnum::List(list)) = &item.node else {
                        return false;
                    };
                    for element in &list.items {
                        let Some(NodeEnum::FuncCall(call)) = &element.node else {
                            continue;
                        };
                        let safe = call
                            .funcname
                            .last()
                            .and_then(|n| n.node.as_ref())
                            .and_then(|n| match n {
                                NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
                                _ => None,
                            })
                            .is_some_and(|name| GENERATORS_IN_FROM.contains(&name.as_str()));
                        if !safe {
                            return false;
                        }
                    }
                }
            }

            NodeRef::FuncCall(call) => {
                // Compare on the bare name: `pg_catalog.query_to_xml` and
                // `query_to_xml` are the same function.
                let last =
                    call.funcname
                        .last()
                        .and_then(|n| n.node.as_ref())
                        .and_then(|n| match n {
                            NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
                            _ => None,
                        });
                if let Some(name) = last {
                    if CATALOG_ESCAPE_FUNCTIONS.contains(&name.as_str()) {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }

    // A statement naming no relation is not a catalog query, and pg_query has a
    // known bug where a self-referencing CTE yields an empty table list. Either
    // way, releasing on an empty set would release on absence of evidence.
    saw_relation
}

/// Whether the engine's per-field provenance can be believed at all.
///
/// **Found against CockroachDB, and it is a leak, not a nicety.** For
/// `SELECT city FROM t UNION ALL SELECT email FROM t`, CockroachDB's simple-query
/// `RowDescription` reports the *first branch's* table OID and attnum for the
/// single output field — so a released column's classification was applied to a
/// masked column's values and `user7@example.com` came back in the clear. Its
/// extended-protocol `Describe` reports zero for the same statement, so the two
/// protocols disagree and only one of them is safe.
///
/// Postgres zeroes provenance for set operations, which is why this never
/// showed up in five major versions of testing.
///
/// The rule this establishes is worth stating plainly: **provenance is
/// necessary but not sufficient.** A field may carry a table OID and still not
/// come from that column. Where one output field can draw from more than one
/// source column, the OID identifies at most one of them, and acting on it
/// masks the wrong column.
///
/// Returns false when the statement contains a set operation anywhere, in which
/// case the caller must treat every field as having no provenance.
///
/// **This is not sufficient on its own.** A set operation can be hidden inside a
/// view, and then the statement text is an innocent `SELECT v FROM v_union`
/// while CockroachDB still reports the first branch's provenance. The caller
/// must also check [`referenced_relations`] against the snapshot's set of views
/// whose definitions contain one; see `Snapshot::is_opaque_view`.
pub fn provenance_is_trustworthy(sql: &str) -> bool {
    StatementInspection::new(sql).provenance_is_trustworthy()
}

fn provenance_is_trustworthy_inspected(inspection: &StatementInspection<'_>) -> bool {
    use pg_query::NodeRef;
    let Some(parsed) = inspection.parsed() else {
        // Unparseable means we cannot rule a set operation out.
        return false;
    };
    // Exactly one statement, matching the rest of this module: zero tells us
    // nothing, and several mean we do not know which one this RowDescription
    // belongs to.
    if parsed.protobuf.stmts.len() != 1 {
        return false;
    }
    !parsed
        .protobuf
        .nodes()
        .iter()
        .any(|(node, _, _, _)| match node {
            NodeRef::SelectStmt(select) => {
                select.op() != pg_query::protobuf::SetOperation::SetopNone
            }
            _ => false,
        })
}

/// Whether `pg_query` can parse the statement at all.
///
/// The lexer scans nonsense happily, so a caller that needs "we could not read
/// this, so it could reference anything" has to ask the parser separately.
pub fn is_parseable(sql: &str) -> bool {
    StatementInspection::new(sql).is_parseable()
}

/// Every identifier the statement mentions, from the **lexer**.
///
/// Table names, aliases, function names and column names, undifferentiated.
/// That is deliberate: this is a backstop, and over-naming costs a refusal
/// while under-naming costs a disclosure.
///
/// **Why the lexer and not the parse tree.** The first version of this walked
/// `pg_query`'s node tree for `ColumnRef`s, and the containment test in
/// `tests/lineage_superset.rs` immediately caught it missing `id` in
///
/// ```sql
/// SELECT sum(n) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW) FROM t
/// ```
///
/// — the walker does not descend into a `WindowDef`. That is the traversal gap
/// this module's header warns about, and a backstop with a blind spot is not a
/// backstop. The token stream has no such gap: every identifier in the text is
/// a token, whatever the grammar does with it afterwards.
///
/// `None` when the text cannot even be scanned, which the caller must treat as
/// "could mention anything".
pub fn referenced_identifiers(sql: &str) -> Option<Vec<String>> {
    scan_identifiers(sql)
}

fn scan_identifiers(sql: &str) -> Option<Vec<String>> {
    let scanned = pg_query::scan(sql).ok()?;
    Some(
        scanned
            .tokens
            .iter()
            .filter_map(|token| {
                let start = usize::try_from(token.start).ok()?;
                let end = usize::try_from(token.end).ok()?;
                let text = sql.get(start..end)?;
                // Not `token() == Ident`. Two whole classes of name are not
                // `Ident`, and an audit found both:
                //
                //   * a *quoted* name's span includes its quotes, so `"email"`
                //     never matched the catalog's `email`
                //   * pg_query lexes unreserved keywords as their own token
                //     types, so a column called `value`, `source`, `name`,
                //     `comment`, `owner` or `year` produced no token at all
                //
                // Either one silently reopened the hole this function exists to
                // close, and neither is exotic — every ORM quotes identifiers,
                // and `comment` and `source` are ordinary column names.
                //
                // So the rule is textual rather than grammatical: anything
                // shaped like a name counts, keyword or not. Over-naming costs
                // a refusal; under-naming is a disclosure.
                if let Some(inner) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
                    // `""` is an escaped quote inside a quoted identifier.
                    return Some(inner.replace("\"\"", "\"").to_ascii_lowercase());
                }
                let word = !text.is_empty()
                    && text.starts_with(|c: char| c.is_alphabetic() || c == '_')
                    && text
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '$');
                word.then(|| text.to_ascii_lowercase())
            })
            .collect(),
    )
}

/// Whether every relation in the statement carries an explicit schema.
///
/// Used only to decide whether a result set made entirely of expressions can be
/// trusted: with no provenance-bearing field, there is no OID to check, so the
/// name has to have been unambiguous in the first place.
pub fn every_relation_is_qualified(sql: &str) -> bool {
    StatementInspection::new(sql).every_relation_is_qualified()
}

fn every_relation_is_qualified_inspected(inspection: &StatementInspection<'_>) -> bool {
    use pg_query::NodeRef;
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    let mut cte_names: Vec<String> = Vec::new();
    for (node, _, _, _) in parsed.protobuf.nodes() {
        if let NodeRef::CommonTableExpr(cte) = node {
            cte_names.push(cte.ctename.to_ascii_lowercase());
        }
    }
    parsed
        .protobuf
        .nodes()
        .iter()
        .all(|(node, _, _, _)| match node {
            NodeRef::RangeVar(v) => {
                !v.schemaname.is_empty() || cte_names.contains(&v.relname.to_ascii_lowercase())
            }
            _ => true,
        })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    #[test]
    fn inspection_parse_and_scan_failures_make_every_fact_conservative() {
        let inspection = StatementInspection::new("SELECT \0");
        assert!(!inspection.is_parseable());
        assert!(inspection.identifiers().is_none());
        assert!(!inspection.reads_only_server_metadata());
        assert!(!inspection.provenance_is_trustworthy());
        assert!(!inspection.every_relation_is_qualified());
        assert_eq!(inspection.output_safety(2, true), vec![Safety::Unknown; 2]);
    }

    // --- system catalogs ---------------------------------------------------

    #[test]
    fn metadata_only_catalog_queries_are_released() {
        // The shapes psql actually sends. Each is full of expressions that
        // output classification cannot judge.
        for sql in [
            "SELECT n.nspname, c.relname, pg_catalog.pg_get_userbyid(c.relowner) \
             FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace",
            "SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod) \
             FROM pg_catalog.pg_attribute a WHERE a.attrelid = 1",
            "SELECT table_name FROM information_schema.tables",
            "SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_statistic_ext e \
             ON e.stxrelid = c.oid",
        ] {
            assert!(reads_only_server_metadata(sql), "should be released: {sql}");
        }
    }

    #[test]
    fn catalogs_that_carry_user_data_are_not_released() {
        // pg_stats returns most_common_vals and histogram_bounds — literal
        // values sampled out of the user's tables, including the ones the proxy
        // pseudonymises. Measured on the demo database, not assumed.
        for sql in [
            "SELECT most_common_vals FROM pg_catalog.pg_stats",
            "SELECT stavalues1 FROM pg_catalog.pg_statistic",
            "SELECT stxdmcv FROM pg_catalog.pg_statistic_ext_data",
            "SELECT rolpassword FROM pg_catalog.pg_authid",
            "SELECT query FROM pg_catalog.pg_stat_activity",
            "SELECT data FROM pg_catalog.pg_largeobject",
            "SELECT umoptions FROM pg_catalog.pg_user_mappings",
            "SELECT subconninfo FROM pg_catalog.pg_subscription",
        ] {
            assert!(
                !reads_only_server_metadata(sql),
                "must not be released: {sql}"
            );
        }
    }

    #[test]
    fn a_user_table_anywhere_disqualifies_the_whole_statement() {
        for sql in [
            "SELECT c.email FROM demo.customers c JOIN pg_catalog.pg_class k ON true",
            "SELECT relname FROM pg_catalog.pg_class WHERE relname IN (SELECT email FROM demo.customers)",
            "SELECT (SELECT email FROM demo.customers LIMIT 1) FROM pg_catalog.pg_class",
        ] {
            assert!(!reads_only_server_metadata(sql), "must not be released: {sql}");
        }
    }

    #[test]
    fn an_unqualified_catalog_name_passes_here_and_is_settled_by_oids() {
        // Harlequin writes `from pg_database`. Refusing it outright locked out a
        // real client; accepting it on the name alone would be exploitable via
        // `SET search_path TO public, pg_catalog` against a user-owned
        // `public.pg_database`. So this layer lets the name through and
        // session.rs confirms the RowDescription OID really is a system relation.
        assert!(reads_only_server_metadata(
            "SELECT datname FROM pg_database"
        ));
        assert!(reads_only_server_metadata(
            "SELECT relname FROM pg_catalog.pg_class"
        ));
        // A bare name that is not even catalog-shaped is still refused here.
        assert!(!reads_only_server_metadata("SELECT email FROM customers"));
    }

    #[test]
    fn qualification_is_reported_for_the_all_expressions_case() {
        assert!(every_relation_is_qualified(
            "SELECT pg_catalog.pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c"
        ));
        assert!(!every_relation_is_qualified(
            "SELECT upper(datname) FROM pg_database"
        ));
        assert!(every_relation_is_qualified(
            "WITH k AS (SELECT oid FROM pg_catalog.pg_class) SELECT count(*) FROM k"
        ));
    }

    #[test]
    fn functions_that_take_sql_as_a_string_are_refused() {
        // The parse tree has no RangeVar for `demo.customers` here, so without
        // the escape list the entire rule is bypassable in one call.
        for sql in [
            "SELECT pg_catalog.query_to_xml('SELECT email FROM demo.customers', false, true, '') \
             FROM pg_catalog.pg_class",
            "SELECT table_to_xml('demo.customers'::regclass, false, true, '') \
             FROM pg_catalog.pg_class",
            "SELECT pg_read_file('/etc/passwd') FROM pg_catalog.pg_class",
            "SELECT dblink('', 'SELECT email FROM demo.customers') FROM pg_catalog.pg_class",
        ] {
            assert!(
                !reads_only_server_metadata(sql),
                "must not be released: {sql}"
            );
        }
    }

    #[test]
    fn data_bearing_set_returning_functions_do_not_get_the_metadata_fast_path() {
        // Range functions can expose the same data as denied catalog views,
        // while a joined pg_catalog relation supplies the otherwise-required
        // relation marker. Refuse data-bearing SRFs rather than maintaining a
        // second, inevitably incomplete denylist.
        for sql in [
            "SELECT a.query FROM pg_stat_get_activity(NULL) a, pg_catalog.pg_class c",
            "SELECT * FROM pg_ls_waldir(), pg_catalog.pg_class",
        ] {
            assert!(!reads_only_server_metadata(sql), "must be refused: {sql}");
        }
        assert!(reads_only_server_metadata(
            "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
        ));
    }

    #[test]
    fn a_cte_may_go_unqualified_but_only_if_it_is_declared_here() {
        assert!(reads_only_server_metadata(
            "WITH cls AS (SELECT oid, relname FROM pg_catalog.pg_class) \
             SELECT relname FROM cls"
        ));
        // A CTE named after a catalog must not launder a user table.
        assert!(!reads_only_server_metadata(
            "WITH pg_class AS (SELECT email FROM demo.customers) SELECT email FROM pg_class"
        ));
    }

    #[test]
    fn size_functions_are_released_but_value_returning_ones_are_not() {
        // Every GUI client shows table sizes. A byte count cannot carry a row.
        for sql in [
            "SELECT pg_total_relation_size('demo.customers')",
            "SELECT pg_relation_size(c.oid) FROM pg_catalog.pg_class c",
        ] {
            assert_eq!(analyze(sql, 1, false), vec![Safety::Releasable], "{sql}");
        }
        // A formatted size is still released under the default posture. It is
        // a pure scalar now rather than a size function, so it sits behind the
        // summaries gate and the strict posture refuses it — which is what the
        // strict posture is for.
        assert_eq!(
            analyze(
                "SELECT pg_size_pretty(pg_table_size('demo.customers'))",
                1,
                true
            ),
            vec![Safety::Releasable]
        );
        // But the formatters take a *value*, and `pg_size_pretty` renders
        // anything under 10240 as "%lld bytes" — so a modulo and a divide
        // reconstruct any bigint exactly. They are released only over a
        // releasable argument, which is what the GUI case actually is.
        for sql in [
            "SELECT pg_size_pretty(salary) FROM t",
            "SELECT pg_size_pretty((salary % 10000)::bigint) FROM t",
            "SELECT pg_column_size(email) FROM t",
            "SELECT pg_size_bytes(note) FROM t",
        ] {
            assert_eq!(analyze(sql, 1, true), vec![Safety::Unknown], "{sql}");
        }
        // The neighbouring trap stays shut: these return an actual member.
        for sql in [
            "SELECT max(email) FROM demo.customers",
            "SELECT pg_read_file('/etc/passwd')",
        ] {
            assert_eq!(analyze(sql, 1, true), vec![Safety::Unknown], "{sql}");
        }
    }

    #[test]
    fn show_is_released_because_a_guc_is_not_table_data() {
        for sql in ["SHOW search_path", "SHOW ALL", "SHOW transaction_isolation"] {
            assert!(reads_only_server_metadata(sql), "{sql}");
        }
    }

    #[test]
    fn absence_of_evidence_is_not_release() {
        // pg_query has a known bug where a self-referencing CTE yields an empty
        // table list. Releasing on an empty set would turn that into a leak.
        for sql in [
            "SELECT 1",
            "SELECT now()",
            "WITH f AS (SELECT * FROM f LIMIT 1) SELECT * FROM f",
            "not valid sql at all",
            "SELECT 1; SELECT 2",
        ] {
            assert!(
                !reads_only_server_metadata(sql),
                "must not be released: {sql}"
            );
        }
    }

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

    /// A reducing aggregate used as a *window* function reduces nothing.
    ///
    /// The frame belongs to the caller, and `ROWS BETWEEN CURRENT ROW AND
    /// CURRENT ROW` makes `sum` the identity function. Before this was fixed,
    ///
    ///   SELECT sum(annual_salary)
    ///            OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW)
    ///     FROM fz.people
    ///
    /// returned exact salaries through a bucketed column under the *strictest*
    /// configuration, because `Releasable` short-circuits `lineage` and
    /// `opaque` alike. Found by the generated campaign, not by review.
    #[test]
    fn a_reducing_aggregate_over_a_window_is_not_releasable() {
        for sql in [
            "SELECT sum(salary) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW) FROM t",
            "SELECT sum(salary) OVER () FROM t",
            "SELECT avg(salary) OVER (PARTITION BY dept) FROM t",
            "SELECT count(salary) OVER (ORDER BY id) FROM t",
            "SELECT bool_or(flag) OVER (ORDER BY id) FROM t",
        ] {
            assert!(
                !is_safe(sql),
                "a windowed aggregate must not be released: {sql}"
            );
        }
    }

    /// The same names without `OVER` are still summaries, so the fix is a
    /// window check and not a retreat from releasing aggregates.
    #[test]
    fn plain_reducing_aggregates_are_still_releasable() {
        for sql in [
            "SELECT sum(salary) FROM t",
            "SELECT avg(salary) FROM t",
            "SELECT count(*) FROM t",
            "SELECT count(salary) FROM t",
        ] {
            assert!(
                is_safe(sql),
                "a plain summary must still be released: {sql}"
            );
        }
    }

    /// Ranking windows keep working: they emit a position, whatever the frame.
    #[test]
    fn ranking_windows_are_still_releasable() {
        assert!(is_safe("SELECT row_number() OVER (ORDER BY salary) FROM t"));
        assert!(is_safe(
            "SELECT rank() OVER (PARTITION BY dept ORDER BY salary) FROM t"
        ));
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
        // Counts can accidentally match again when one star expands to zero
        // fields and a later star expands to several. Position still is not
        // trustworthy.
        let sql = "SELECT e.*, 1, upper(p.email), q.* \
                   FROM e, fz.people p, (SELECT id, salary FROM fz.people) q";
        assert_eq!(safety(sql, 4), vec![Safety::Unknown; 4]);
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
            // `sum(salary) OVER (PARTITION BY dept)` was here, asserting the
            // behaviour that turned out to be a disclosure: as a window
            // function the caller picks the frame, and a frame of one row makes
            // `sum` the identity. See
            // `a_reducing_aggregate_over_a_window_is_not_releasable`.
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

#[cfg(test)]
mod provenance_trust_tests {
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
}

#[cfg(test)]
mod referenced_identifier_probe {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    /// The statement that leaked. `d` must be in the set even though it only
    /// appears inside a scalar subquery two levels down.
    #[test]
    fn columns_inside_scalar_subqueries_are_seen() {
        let sql = "SELECT min((SELECT d FROM fz.t8 LIMIT 1 OFFSET 3)) OVER (PARTITION BY subq.c0) \
                   FROM (SELECT id AS c0 FROM fz.v_join) subq";
        let cols = referenced_identifiers(sql).expect("scans");
        assert!(cols.contains(&"d".to_string()), "got {cols:?}");
        assert!(cols.contains(&"id".to_string()), "got {cols:?}");
    }

    /// The case that made this lexical: the tree walk does not enter a
    /// `WindowDef`, so `id` was invisible to it.
    #[test]
    fn columns_in_a_window_clause_are_seen() {
        let sql =
            "SELECT sum(n) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW) FROM t";
        let cols = referenced_identifiers(sql).expect("scans");
        assert!(cols.contains(&"id".to_string()), "got {cols:?}");
        assert!(cols.contains(&"n".to_string()), "got {cols:?}");
    }

    #[test]
    fn columns_in_case_arms_casts_and_where_are_seen() {
        let sql = "SELECT CASE WHEN n > 0 THEN cast(email AS text) ELSE note END \
                   FROM t WHERE last_ip IS NOT NULL ORDER BY birth_date";
        let cols = referenced_identifiers(sql).expect("scans");
        for want in ["n", "email", "note", "last_ip", "birth_date"] {
            assert!(cols.contains(&want.to_string()), "missing {want}: {cols:?}");
        }
    }
}
