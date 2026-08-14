//! Deciding whether an output field could be used to *read* a classified value.
//!
//! Fields with no provenance are refused. Measured against TPC-DS that refused
//! 90% of the queries — decision-support SQL is aggregate-shaped almost
//! everywhere, and an aggregate over a column has no provenance. This module
//! recovers the ones that cannot be used to read a value.
//!
//! # The threat model this encodes
//!
//! The bar is **"a masked value does not appear in a projection"**. It is not
//! "you cannot read an anonymised value", which is what this comment used to
//! say and what the README implied — and against an adversarial client that
//! claim is simply false. `scripts/test-inference.sh` measures it:
//!
//!   - `SELECT sum(salary) FROM t GROUP BY id` returned every salary exactly,
//!     in one query, when `id` is unique and released. The "group of one" trade
//!     was written down as an incidental edge case; grouping by a key made it
//!     the bulk interface. **Refused since v0.1.16** — see below.
//!   - the filter side is ungoverned, so `WHERE email LIKE 'a%'` with `count(*)`
//!     recovers a full address in **313 queries**, measured, through the proxy.
//!   - an error is a one-bit channel that needs no aggregate: `1/(CASE WHEN …
//!     THEN 0 ELSE 1 END)`.
//!
//! None of that is a defect in the rules below; every one follows from masking
//! the *projection* and leaving the predicate alone. It is recorded here
//! because the distinction decides who the tool is for: it reduces incidental
//! exposure for an analyst who is not attacking you, and it does not contain
//! one who is. Governing the filter side is the only sound answer and it is a
//! different product — it would refuse `WHERE email = …` outright.
//!
//! The one route that was closed is the one that is decidable from the
//! statement and the catalog alone: [`StatementInspection::group_by_columns`]
//! reads the grouping, and if it covers a declared unique key — or cannot be
//! read at all — the session withholds the aggregate relaxation, so a reducing
//! aggregate is refused rather than released. That leaves real aggregation
//! untouched, which is the point of doing it this way rather than by disabling
//! summaries — and why the reader resolves ordinals and grouping sets instead
//! of refusing them, since `GROUP BY 1` and `ROLLUP(city)` are the honest form
//! of the same syntax. A grouping it still cannot read falls back to the
//! lexical backstop in the session rather than to a refusal, because refusing
//! outright took time-bucketed aggregation with it: `date_trunc` over a coarse
//! literal unit is released on purpose, so `SELECT date_trunc('month', ts),
//! sum(amount) … GROUP BY 1` worked before the guard and not after. The `WHERE id = 1` form of the attack survives and
//! cannot be closed here: whether a predicate matches one row is a property of
//! the data, not of the statement. What the guard buys is the difference
//! between one query for the whole table and one query per row.
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
//!
//! # How this module uses pg_query
//!
//! Parse and scan come from the library (`pg_query::parse`, `pg_query::scan`,
//! protobuf `Node` types). `pg_query`'s `nodes()` iterator is **not** used to
//! prove absence: upstream documents that it "doesn't iterate over every
//! possible node type", and a skipped node is an allow. Hostile / read-only /
//! write gates share one local descent (`walk_tree`) over those protobuf
//! fields. [`StatementInspection`] caches the parse so the session does not
//! re-parse the same SQL for each gate.

use std::collections::HashSet;
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
    /// The columns a top-level `GROUP BY` groups on.
    ///
    /// `Some([])` means there is no grouping. `None` means there is one but it
    /// cannot be reduced to plain column names, and the caller must treat that
    /// as possibly-singleton, because a grouping it cannot read is a grouping
    /// it cannot clear.
    ///
    /// Read off the top-level `SelectStmt`'s `group_clause` rather than walked.
    /// That matters: the walker has documented gaps, and a missed `GROUP BY`
    /// here would look like "no grouping" and release exactly the aggregate
    /// this exists to catch. A direct field read has nothing to miss.
    ///
    /// Read from the statement `analyze_inspected` actually judges: it unwraps
    /// `SELECT * FROM (subselect)` before classifying, so the grouping has to be
    /// taken from the same place or the two halves of the guard disagree. This
    /// used to say that an aggregate inside a subquery "is not the released
    /// field", which the unwrapping in this module had already falsified.
    ///
    /// Three shapes are readable, because refusing them costs real queries:
    /// a column reference, an ordinal into the target list (`GROUP BY 1` is
    /// idiomatic), and `ROLLUP`/`CUBE`/`GROUPING SETS` over either. For a
    /// grouping set the names are unioned across every set, which is the safe
    /// direction: each set is a subset of the union, so a key contained in any
    /// one of them is contained in the union.
    ///
    /// An arbitrary expression stays unreadable. Collecting the columns beneath
    /// it needs a complete traversal, and this file exists because proving
    /// absence across `pg_query`'s incomplete walker is how three disclosures
    /// got in. The cost is small in practice: a query grouping by an expression
    /// almost always selects it too, and an expression target has no provenance,
    /// so it was already refused a step earlier for its own reasons.
    pub fn group_by_columns(&self) -> Option<Vec<String>> {
        let parsed = self.parsed()?;
        let [statement] = parsed.protobuf.stmts.as_slice() else {
            return Some(Vec::new());
        };
        let Some(NodeEnum::SelectStmt(select)) =
            statement.stmt.as_ref().and_then(|s| s.node.as_ref())
        else {
            return Some(Vec::new());
        };

        // The same statement `analyze_inspected` judges, not the one the client
        // wrote. It unwraps `SELECT * FROM (subselect)` and classifies the
        // *subquery's* target list, so the released aggregate can live inside
        // the subquery — while this used to read the outer `group_clause`,
        // which is empty for the wrapper, and report "no grouping".
        //
        // That put the two halves of the guard on different statements and
        // restored the 0.1.16 disclosure verbatim:
        //
        //   SELECT id, sum(annual_salary) FROM demo.customers GROUP BY id
        //     -> refused
        //   SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers
        //                  GROUP BY id) q
        //     -> served, every salary exactly
        //
        // The comment above this function used to argue the case could not
        // arise — "an aggregate inside a subquery is not the released field" —
        // and the unwrapping in the same module had already made that false.
        let mut select: &SelectStmt = select;
        while let Some(inner) = unwrap_star_over_subquery(select) {
            select = inner;
        }

        if select.group_clause.is_empty() {
            return Some(Vec::new());
        }
        let mut columns = Vec::with_capacity(select.group_clause.len());
        for item in &select.group_clause {
            group_item_columns(item, &select.target_list, &mut columns)?;
        }
        Some(columns)
    }

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

    pub fn output_safety(&self, field_count: usize, allow: Relaxations) -> Vec<Safety> {
        analyze_inspected(self, field_count, allow)
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

    pub fn is_write_statement(&self) -> bool {
        is_write_statement_inspected(self)
    }

    pub fn is_sql_prepare_or_cursor(&self) -> bool {
        is_sql_prepare_or_cursor_inspected(self)
    }

    pub fn calls_untrusted_function(&self) -> bool {
        calls_untrusted_function_inspected(self)
    }

    pub fn touches_leaky_system_catalog(&self) -> bool {
        touches_leaky_system_catalog_inspected(self)
    }

    pub fn masked_exceeds_outer_projection(&self, masked: &HashSet<String>) -> bool {
        masked_exceeds_outer_projection_inspected(self, masked)
    }

    pub fn hostile_uses_whole_row(
        &self,
        relation_columns: &std::collections::HashMap<String, Vec<String>>,
    ) -> bool {
        hostile_uses_whole_row_inspected(self, relation_columns)
    }

    pub fn hostile_join_or_rename_masked(
        &self,
        relation_columns: &std::collections::HashMap<String, Vec<String>>,
        masked: &HashSet<String>,
    ) -> bool {
        hostile_join_or_rename_masked_inspected(self, relation_columns, masked)
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
/// `CATALOG_ESCAPE_FUNCTIONS`.
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
/// `system_catalogs = "allow"` exists. `pg_options_to_table` / `aclexplode`
/// are the same `\d` shape for reloptions and ACLs. Do not put catalog-browser
/// helpers here — a helper as a FROM SRF is a different shape than `\d`.
const GENERATORS_IN_FROM: &[&str] = &[
    "generate_series",
    "generate_subscripts",
    "unnest",
    "pg_options_to_table",
    "aclexplode",
];

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
pub fn analyze(sql: &str, field_count: usize, allow: Relaxations) -> Vec<Safety> {
    StatementInspection::new(sql).output_safety(field_count, allow)
}

fn analyze_inspected(
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

    // Over-approximated: every column the grouping could reference, or `None`
    // when that cannot be bounded. Unlike `group_by_columns`, which answers
    // "which columns is this grouping *on*" for the unique-key test, this only
    // has to avoid missing a reference, so an unrecognised node collapses to
    // `None` and refuses instead of releasing.
    let grouped = grouping_may_reference(select, &select.target_list);
    let grouped = grouped.as_deref();

    select
        .target_list
        .iter()
        .map(|entry| match entry.node.as_ref() {
            Some(NodeEnum::ResTarget(target)) => {
                match target.val.as_ref().and_then(|v| v.node.as_ref()) {
                    Some(expr) => classify(expr, allow, grouped),
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
fn classify(expr: &NodeEnum, allow: Relaxations, grouped: Option<&[String]>) -> Safety {
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
            Some(inner) => classify(inner, allow, grouped),
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
            if !allow.summaries {
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
                // A summary of a column the query groups on is that column.
                // Within a group it is constant, so `sum(x)/count(*)` is `x`
                // exactly — every group, any data, no unique key needed. The
                // key test in the session cannot see this, and
                // `SELECT annual_salary AS g0, sum(annual_salary) … GROUP BY 1`
                // served exact salaries until the generated poison campaign
                // caught it.
                //
                // Narrow on purpose. Refusing whenever a *masked* column is
                // grouped was tried first and refused every grouped aggregate
                // in the fixture — under a default-deny catalog almost every
                // column is masked, which is `summaries = "refuse"` by another
                // route. The aggregate's own argument is the thing the grouping
                // makes constant, so that is what is compared.
                if aggregate_argument_is_grouped(call, grouped) {
                    return Safety::Unknown;
                }
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
                        .map(|inner| classify(inner, allow, grouped) == Safety::Releasable)
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
                Some(inner) => classify(inner, allow, grouped),
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
                        Some(inner) => classify(inner, allow, grouped),
                        None => Safety::Unknown,
                    };
                    all &= branch == Safety::Releasable;
                } else {
                    all = false;
                }
            }
            if let Some(default) = case.defresult.as_ref().and_then(|d| d.node.as_ref()) {
                all &= classify(default, allow, grouped) == Safety::Releasable;
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
                    .map(|inner| classify(inner, allow, grouped) == Safety::Releasable)
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

/// Every column the grouping *could* reference, over-approximated.
///
/// `None` means "cannot bound this — assume it references everything", and the
/// caller refuses on it. That inversion is what makes traversing an arbitrary
/// expression sound here, where the rest of this module will not do it: the
/// other walks prove a column is *absent* and are unsound the moment they miss
/// a node type, while this one only ever has to avoid *under*-collecting, and an
/// unrecognised node collapses to "everything" rather than to "nothing".
///
/// Node types are matched explicitly and their child lists exhausted. A
/// `FuncCall` with an aggregate filter, ordering or window clause is not
/// bounded, because those carry columns this does not walk.
///
/// Hand-rolled on purpose, and the alternative was measured rather than
/// assumed. `pg_query`'s own generated traversal, `ParseResult::nodes()`, is
/// the obvious library answer and is *incomplete in the unsafe direction* —
/// asked for the columns under a grouping it returns, on this version:
///
/// | grouping                                | `nodes()` finds |
/// |-----------------------------------------|-----------------|
/// | `coalesce(annual_salary, 0)`            | `annual_salary` |
/// | `(a + b) * c`                           | `a`, `b`, `c`   |
/// | `ARRAY[deep1, deep2]`                   | nothing         |
/// | `GROUPING SETS ((g1),(g2))`             | nothing         |
/// | `row_number() OVER (PARTITION BY w)`    | nothing         |
/// | `xmlelement(name foo, xmlcol)`          | nothing         |
///
/// Four silent misses, each of which would be a release here. The library is
/// still used as an oracle: `library_traversal_finds_no_column_this_misses`
/// asserts this function never returns a *narrower* set than `nodes()` does.
fn grouping_may_reference(
    select: &SelectStmt,
    targets: &[pg_query::protobuf::Node],
) -> Option<Vec<String>> {
    fn walk(
        node: &pg_query::protobuf::Node,
        targets: &[pg_query::protobuf::Node],
        into: &mut Vec<String>,
        depth: u32,
        // Is this node a grouping *element* — the position where Postgres
        // resolves both an output alias and an ordinal? True at the top of an
        // item and through `ROLLUP`/`CUBE`/`GROUPING SETS`, which nest grouping
        // elements; false inside any expression, and false below a resolved
        // target. Without it `SELECT city AS city
        // … GROUP BY city` chases its own alias to the depth cap and reports
        // "unbounded", refusing six honest aggregations in the fixture.
        resolve_alias: bool,
    ) -> Option<()> {
        // `> 24` -> `== 24` or `>= 24` both survive the mutation campaign, and
        // both are equivalent for safety: every path increments (`d =
        // depth.saturating_add(1)`, passed to every recursive call), so all
        // three still cap, one level earlier or later. Detecting the difference
        // needs an expression nested exactly 24 deep, and the number is a
        // stack guard rather than a property. What matters is that the cap
        // returns `None` — refuse — and that is tested.
        if depth > 24 {
            return None;
        }
        let d = depth.saturating_add(1);
        match node.node.as_ref()? {
            NodeEnum::ColumnRef(column) => {
                for field in &column.fields {
                    if let Some(NodeEnum::String(s)) = &field.node {
                        into.push(s.sval.to_ascii_lowercase());
                    }
                }
                // A bare name may be an output alias; the target it names can
                // reference anything.
                if resolve_alias && column.fields.len() == 1 {
                    let name = into.last().cloned().unwrap_or_default();
                    for entry in targets {
                        let Some(NodeEnum::ResTarget(target)) = entry.node.as_ref() else {
                            continue;
                        };
                        if !target.name.is_empty() && target.name.to_ascii_lowercase() == name {
                            walk(target.val.as_ref()?, targets, into, d, false)?;
                        }
                    }
                }
                Some(())
            }
            NodeEnum::AConst(constant) => {
                // An integer is an ordinal only as a grouping *element*.
                // Nested in an expression it is an ordinary literal, and
                // reading it as an ordinal was wrong in both directions:
                // `GROUP BY coalesce(gcol, 0)` resolved `0` to nothing and
                // declared the whole grouping unbounded — refusing an honest
                // aggregate — while `GROUP BY gcol + 1` resolved `1` to the
                // first target and dragged that target's columns in. Safe
                // both times, wrong both times, and found by asserting that
                // each arm actually reads what it claims to.
                if !resolve_alias {
                    return Some(());
                }
                if let Some(pg_query::protobuf::a_const::Val::Ival(value)) = constant.val.as_ref() {
                    let position = usize::try_from(value.ival).ok()?.checked_sub(1)?;
                    let Some(NodeEnum::ResTarget(target)) = targets.get(position)?.node.as_ref()
                    else {
                        return None;
                    };
                    return walk(target.val.as_ref()?, targets, into, d, false);
                }
                Some(())
            }
            NodeEnum::TypeCast(cast) => walk(cast.arg.as_ref()?, targets, into, d, false),
            NodeEnum::CollateClause(c) => walk(c.arg.as_ref()?, targets, into, d, false),
            NodeEnum::AExpr(expr) => {
                for side in [expr.lexpr.as_ref(), expr.rexpr.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    walk(side, targets, into, d, false)?;
                }
                Some(())
            }
            NodeEnum::BoolExpr(expr) => {
                for arg in &expr.args {
                    walk(arg, targets, into, d, false)?;
                }
                Some(())
            }
            NodeEnum::CoalesceExpr(expr) => {
                for arg in &expr.args {
                    walk(arg, targets, into, d, false)?;
                }
                Some(())
            }
            NodeEnum::MinMaxExpr(expr) => {
                for arg in &expr.args {
                    walk(arg, targets, into, d, false)?;
                }
                Some(())
            }
            NodeEnum::NullTest(test) => walk(test.arg.as_ref()?, targets, into, d, false),
            NodeEnum::BooleanTest(test) => walk(test.arg.as_ref()?, targets, into, d, false),
            NodeEnum::FuncCall(call) => {
                // Defence in depth, and the mutation campaign is right that
                // nothing tests it: turning any of these `||` into `&&` breaks
                // no test, because the server rejects the statement before a
                // result set exists. Measured on Postgres 17 —
                //
                //   GROUP BY sum(id) OVER (PARTITION BY id)
                //     ERROR: window functions are not allowed in GROUP BY
                //   GROUP BY count(*) FILTER (WHERE id > 0)
                //   GROUP BY string_agg(email, ',' ORDER BY id)
                //   GROUP BY count(*)
                //     ERROR: aggregate functions are not allowed in GROUP BY
                //
                // — and CockroachDB rejects them too. A statement the engine
                // refuses cannot disclose. Kept because this walker's contract
                // is "return None for anything that could reference more than
                // it appears to", and an engine that one day allows one of
                // these should meet a guard rather than a gap.
                if call.over.is_some()
                    || call.agg_filter.is_some()
                    || !call.agg_order.is_empty()
                    || call.agg_star
                {
                    return None;
                }
                for arg in &call.args {
                    walk(arg, targets, into, d, false)?;
                }
                Some(())
            }
            NodeEnum::CaseExpr(expr) => {
                if let Some(arg) = expr.arg.as_ref() {
                    walk(arg, targets, into, d, false)?;
                }
                for when in &expr.args {
                    let Some(NodeEnum::CaseWhen(when)) = when.node.as_ref() else {
                        return None;
                    };
                    walk(when.expr.as_ref()?, targets, into, d, false)?;
                    walk(when.result.as_ref()?, targets, into, d, false)?;
                }
                if let Some(default) = expr.defresult.as_ref() {
                    walk(default, targets, into, d, false)?;
                }
                Some(())
            }
            NodeEnum::GroupingSet(set) => {
                for member in &set.content {
                    walk(member, targets, into, d, resolve_alias)?;
                }
                Some(())
            }
            NodeEnum::RowExpr(row) => {
                for member in &row.args {
                    walk(member, targets, into, d, resolve_alias)?;
                }
                Some(())
            }
            // Anything else — a sublink, an array, an unrecognised node —
            // could reference a column this does not see.
            _ => None,
        }
    }

    let mut columns = Vec::new();
    for item in &select.group_clause {
        walk(item, targets, &mut columns, 0, true)?;
    }
    Some(columns)
}

/// Is this aggregate's input held constant by the grouping?
///
/// `grouped` is empty when there is no grouping, and also when the grouping
/// could not be read — in which case this declines rather than guessing, and
/// the session's lexical backstop is what stands between the statement and a
/// release.
///
/// Only a plain column reference is compared. An argument this cannot read is
/// treated as *not* grouped, which is the permissive direction and is
/// deliberate: refusing every aggregate over an expression would cost far more
/// than the shape is worth, and the readable case is the one that was actually
/// disclosing.
fn aggregate_argument_is_grouped(
    call: &pg_query::protobuf::FuncCall,
    grouped: Option<&[String]>,
) -> bool {
    // `None` is a grouping whose referenced columns could not be bounded, so
    // any aggregate under it might be summarising a constant.
    let Some(grouped) = grouped else {
        return true;
    };
    if grouped.is_empty() {
        return false;
    }
    call.args.iter().any(|arg| {
        let Some(NodeEnum::ColumnRef(column)) = arg.node.as_ref() else {
            return false;
        };
        column
            .fields
            .last()
            .and_then(|f| match &f.node {
                Some(NodeEnum::String(s)) => Some(s.sval.to_ascii_lowercase()),
                _ => None,
            })
            .is_some_and(|name| grouped.contains(&name))
    })
}

/// The column names one `GROUP BY` item can distinguish rows by.
///
/// Appends to `into` and returns `None` the moment the item cannot be read, so
/// a partial answer is never mistaken for a complete one — the caller refuses
/// on `None`, and half a grouping is exactly the case where releasing would be
/// wrong.
fn group_item_columns(
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
///
/// TOAST heaps are not on this name list: they are `pg_toast.pg_toast_<oid>`
/// and the oid is not known statically. [`range_var_is_leaky_catalog`] matches
/// the schema / `pg_toast_` prefix instead.
const LEAKY_SYSTEM_CATALOGS: &[&str] = &[
    // Sampled values from user tables.
    "pg_statistic",
    "pg_statistic_ext_data",
    "pg_stats",
    "pg_stats_ext",
    "pg_stats_ext_exprs",
    // Other sessions' SQL text, literals included. Session-local
    // `pg_cursors.statement` / `pg_prepared_statements` carry the same
    // class of text (DECLARE / PREPARE bodies with literals).
    "pg_stat_activity",
    "pg_stat_statements",
    "pg_prepared_statements",
    "pg_cursors",
    // Replication conninfo can embed passwords.
    "pg_stat_wal_receiver",
    // Large object contents.
    "pg_largeobject",
    // Password hashes and connection strings.
    "pg_authid",
    "pg_shadow",
    "pg_user",
    "pg_user_mapping",
    "pg_user_mappings",
    "pg_subscription",
    // FDW server / wrapper options: the same class as user mappings
    // (passwords, endpoints). `pg_foreign_table` stays off the list so `\d`
    // of a foreign table still works; heap `\d` never reads these two.
    "pg_foreign_server",
    "pg_foreign_data_wrapper",
    // SQL-standard wrappers of the same option catalogs. `FROM
    // information_schema.user_mapping_options` is metadata-only (schema
    // allowlist) and never names `pg_user_mapping`, so the pg_ catalog
    // denylist does not see it. The previous pass caught three of the
    // five PUBLIC option views; `column_options` / `foreign_table_options`
    // (attfdwoptions / ftoptions) are the same class. Internal
    // `_pg_*` base views carry the raw option arrays those wrappers
    // explode — GRANT is not PUBLIC, but a superuser (or
    // `SET search_path TO information_schema`) still reads them.
    "user_mapping_options",
    "foreign_server_options",
    "foreign_data_wrapper_options",
    "column_options",
    "foreign_table_options",
    "_pg_user_mappings",
    "_pg_foreign_servers",
    "_pg_foreign_data_wrappers",
    "_pg_foreign_tables",
    "_pg_foreign_table_columns",
    // Host configuration and file contents.
    "pg_file_settings",
    "pg_hba_file_rules",
    "pg_ident_file_mappings",
    "pg_backend_memory_contexts",
];

/// Catalogs whose rows are user data, session SQL, passwords, or toasted
/// cell bytes. Refused at the frontend on every posture.
fn range_var_is_leaky_catalog(v: &pg_query::protobuf::RangeVar) -> bool {
    let schema = v.schemaname.to_ascii_lowercase();
    let relation = v.relname.to_ascii_lowercase();
    // TOAST heaps are the toasted bytes of user columns, masked ones
    // included. `reltoastrelid` from `pg_class` plus `SET search_path TO
    // pg_toast` makes `SELECT count(*) FROM pg_toast_NNNN WHERE chunk_data
    // LIKE '%x%'` a membership oracle. `chunk_data` is not in the snapshot
    // (the loader skips `pg_toast`), so the hostile name set never sees it.
    // Unqualified `pg_toast_*` is catalog-shaped (`pg_` prefix) and would
    // otherwise look metadata-only.
    if schema == "pg_toast" || relation.starts_with("pg_toast_") {
        return true;
    }
    // information_schema implements SQL/MED option views on `_pg_*`
    // base views. New ones keep that prefix; a name list alone misses
    // the next wrapper. Unqualified `_pg_*` still needs the name list
    // (a CTE can be called `_pg_foo`; only the schema-qualified form
    // is prefix-matched). `_pg_*` *functions* (`_pg_truetypid`) are
    // FuncCalls, not RangeVars, and stay catalog-safe helpers.
    if schema == "information_schema" && relation.starts_with("_pg_") {
        return true;
    }
    LEAKY_SYSTEM_CATALOGS.contains(&relation.as_str())
}

/// True when the statement names a catalog that holds sampled user data,
/// other sessions' SQL, passwords, or similar — values default-deny nulling
/// is not enough for, because the query still runs and soft stats / empty
/// shapes remain. Refused at the frontend on every posture.
pub fn touches_leaky_system_catalog(sql: &str) -> bool {
    StatementInspection::new(sql).touches_leaky_system_catalog()
}

fn touches_leaky_system_catalog_inspected(inspection: &StatementInspection<'_>) -> bool {
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, |node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::RangeVar(v)) if range_var_is_leaky_catalog(v)
        )
    })
}

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
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "dblink",
    "dblink_send_query",
    "dblink_get_result",
    "dblink_exec",
    "dblink_connect",
    "dblink_connect_u",
    "dblink_disconnect",
    "dblink_open",
    "dblink_fetch",
    "dblink_close",
    "dblink_get_connections",
    "dblink_get_pkey",
    "dblink_build_sql_insert",
    "dblink_build_sql_update",
    "dblink_build_sql_delete",
    // tablefunc: query-as-string / named-table walk, same class as query_to_xml.
    "crosstab",
    "crosstab2",
    "crosstab3",
    "crosstab4",
    "connectby",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_file_read",
    "pg_logdir_ls",
    "pg_ls_dir",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_ls_archive_statusdir",
    "pg_ls_tmpdir",
    "pg_ls_logicalmapdir",
    "pg_ls_logicalsnapdir",
    "pg_ls_summariesdir",
    "pg_stat_file",
    "lo_get",
    "lo_import",
    "lo_export",
    "lo_open",
    "loread",
    // Defense in depth: target-list `FuncCall` is an allowlist now, but a
    // helper that is later added by mistake must still not dump these.
    "pg_stat_get_activity",
    "pg_stat_get_backend_activity",
    "pg_stat_get_wal_receiver",
    "pg_stat_statements",
    "pg_logical_slot_get_changes",
    "pg_logical_slot_peek_changes",
    "pg_logical_slot_get_binary_changes",
    "pg_logical_slot_peek_binary_changes",
    "pg_get_wal_record_info",
    "pg_get_wal_records_info",
    "pg_get_wal_records_info_till_end_of_wal",
    "pg_get_wal_block_info",
    "pg_get_wal_funames",
];

/// Catalog-browser helpers allowed on the metadata-only fast path.
///
/// Target-list `SELECT f() FROM pg_class` used to be metadata-only unless `f`
/// was on [`CATALOG_ESCAPE_FUNCTIONS`]. That is denylist polarity: every
/// unnamed dump (`get_raw_page`, `crosstab`, `pg_sleep`, `set_config`, …)
/// skipped the untrusted-function gate. Same class as RangeFunction, inverted
/// the same way — only trusted names, FROM-generators, and this introspection
/// list keep the fast path. The escape list still wins if a name is on both.
const CATALOG_HELPER_FUNCTIONS: &[&str] = &[
    // psql `\d` / GUI browsers.
    "format_type",
    "pg_get_userbyid",
    "pg_get_indexdef",
    "pg_get_constraintdef",
    "pg_get_expr",
    "pg_get_viewdef",
    "pg_get_functiondef",
    "pg_get_function_arguments",
    "pg_get_function_result",
    "pg_get_function_identity_arguments",
    "pg_get_function_arg_default",
    "pg_get_ruledef",
    "pg_get_triggerdef",
    "pg_get_serial_sequence",
    "pg_get_partkeydef",
    "pg_get_partition_constraintdef",
    "pg_get_replica_identity_index",
    "pg_get_statisticsobjdef",
    "pg_get_statisticsobjdef_columns",
    "pg_get_statisticsobjdef_expressions",
    "pg_get_keywords",
    "pg_get_catalog_foreign_keys",
    "pg_get_multixact_members",
    "pg_get_object_address",
    "pg_identify_object",
    "pg_identify_object_as_address",
    "pg_describe_object",
    "pg_index_column_has_property",
    "pg_index_has_property",
    "pg_indexam_has_property",
    "obj_description",
    "shobj_description",
    "col_description",
    "pg_options_to_table",
    "aclexplode",
    "array_to_string",
    "array_length",
    "cardinality",
    "array_upper",
    "array_lower",
    "array_ndims",
    "array_dims",
    "array_append",
    "array_prepend",
    "array_cat",
    "array_remove",
    "array_replace",
    "array_position",
    "array_positions",
    "string_to_array",
    "pg_typeof",
    "pg_collation_for",
    "pg_collation_actual_version",
    "pg_encoding_to_char",
    "pg_char_to_encoding",
    "current_setting",
    "current_schemas",
    "to_regclass",
    "to_regtype",
    "to_regnamespace",
    "to_regrole",
    "to_regproc",
    "to_regprocedure",
    "to_regoper",
    "to_regoperator",
    "to_regcollation",
    "pg_table_is_visible",
    "pg_type_is_visible",
    "pg_function_is_visible",
    "pg_operator_is_visible",
    "pg_opclass_is_visible",
    "pg_opfamily_is_visible",
    "pg_collation_is_visible",
    "pg_conversion_is_visible",
    "pg_ts_config_is_visible",
    "pg_ts_dict_is_visible",
    "pg_ts_parser_is_visible",
    "pg_ts_template_is_visible",
    "has_table_privilege",
    "has_schema_privilege",
    "has_column_privilege",
    "has_database_privilege",
    "has_sequence_privilege",
    "has_function_privilege",
    "has_language_privilege",
    "has_tablespace_privilege",
    "has_foreign_data_wrapper_privilege",
    "has_server_privilege",
    "has_type_privilege",
    "has_parameter_privilege",
    "pg_has_role",
    "row_to_json",
    "to_json",
    "to_jsonb",
    "json_build_object",
    "json_build_array",
    "jsonb_build_object",
    "jsonb_build_array",
    "json_agg",
    "jsonb_agg",
    "json_object_agg",
    "jsonb_object_agg",
    "array_agg",
    "string_agg",
    "xmlagg",
    "min",
    "max",
    "quote_ident",
    "quote_literal",
    "quote_nullable",
    "starts_with",
    "pg_postmaster_start_time",
    "pg_conf_load_time",
    "pg_is_in_recovery",
    "pg_is_wal_replay_paused",
    "pg_last_wal_receive_lsn",
    "pg_last_wal_replay_lsn",
    "pg_last_xact_replay_timestamp",
    "pg_current_wal_lsn",
    "pg_current_wal_insert_lsn",
    "pg_current_wal_flush_lsn",
    "pg_walfile_name",
    "pg_walfile_name_offset",
    "pg_wal_lsn_diff",
    "pg_relation_filepath",
    "pg_relation_filenode",
    "pg_filenode_relation",
    "pg_tablespace_location",
    "pg_tablespace_databases",
    "pg_current_logfile",
    "pg_read_all_settings",
    "pg_my_temp_schema",
    "pg_is_other_temp_schema",
    "pg_jit_available",
    "pg_listening_channels",
    "pg_notification_queue_usage",
    "pg_control_system",
    "pg_control_checkpoint",
    "pg_control_recovery",
    "pg_control_init",
    "pg_get_wal_resource_managers",
    "age",
    "txid_current",
    "txid_current_if_assigned",
    "txid_current_snapshot",
    "txid_snapshot_xmin",
    "txid_snapshot_xmax",
    "txid_snapshot_xip",
    "txid_visible_in_snapshot",
    "txid_status",
    "pg_current_xact_id",
    "pg_current_xact_id_if_assigned",
    "pg_current_snapshot",
    "pg_snapshot_xmin",
    "pg_snapshot_xmax",
    "pg_snapshot_xip",
    "pg_visible_in_snapshot",
    "pg_xact_status",
    "pg_sequence_parameters",
    "pg_sequence_last_value",
    "pg_get_function_sqlbody",
    "pg_relation_is_updatable",
    "pg_column_is_updatable",
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
/// relation at all, a CTE reference that is not declared locally, a target-list
/// function that is not a catalog helper / trusted name / FROM-generator, and
/// any function on `CATALOG_ESCAPE_FUNCTIONS` all return `false`.
pub fn reads_only_server_metadata(sql: &str) -> bool {
    StatementInspection::new(sql).reads_only_server_metadata()
}

fn reads_only_server_metadata_inspected(inspection: &StatementInspection<'_>) -> bool {
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

    // Same descent as the hostile gates. `nodes()` skips LIMIT / window frames
    // / PREPARE bodies; a user table there would otherwise look like metadata.
    let mut cte_names: Vec<String> = Vec::new();
    walk_parsed(parsed, &mut |node| {
        if let Some(NodeEnum::CommonTableExpr(cte)) = node.node.as_ref() {
            cte_names.push(cte.ctename.to_ascii_lowercase());
        }
    });

    let mut saw_relation = false;
    let mut disqualified = false;
    walk_parsed(parsed, &mut |node| {
        if disqualified {
            return;
        }
        match node.node.as_ref() {
            Some(NodeEnum::RangeVar(v)) => {
                let schema = v.schemaname.to_ascii_lowercase();
                let relation = v.relname.to_ascii_lowercase();

                if schema.is_empty() {
                    // A locally declared CTE, or a bare name that at least
                    // *looks* like a system catalog. Whether it really is one is
                    // settled by the OID check in the caller, not here.
                    if cte_names.contains(&relation) {
                        return;
                    }
                    if !relation.starts_with("pg_") {
                        disqualified = true;
                        return;
                    }
                } else if schema != "pg_catalog" && schema != "information_schema" {
                    disqualified = true;
                    return;
                }
                if range_var_is_leaky_catalog(v) {
                    disqualified = true;
                    return;
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
            Some(NodeEnum::RangeFunction(range)) => {
                for item in &range.functions {
                    let Some(NodeEnum::List(list)) = &item.node else {
                        disqualified = true;
                        return;
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
                            disqualified = true;
                            return;
                        }
                    }
                }
            }

            // Same invert as RangeFunction. `SELECT get_raw_page(...) FROM
            // pg_class` has a catalog RangeVar and constant args, so a
            // denylist of dump names is an allow for every unnamed one
            // (pageinspect, `pg_sleep`, `set_config`, …) and skips
            // untrusted. Helpers / trusted names / FROM-generators keep
            // the fast path; the escape list still wins if both match.
            Some(NodeEnum::FuncCall(call)) if !func_call_is_catalog_safe(call) => {
                disqualified = true;
            }
            _ => {}
        }
    });
    if disqualified {
        return false;
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
/// must also check the statement's [`StatementInspection::identifiers`] against
/// the snapshot's set of views whose definitions contain one; see
/// `Snapshot::is_opaque_view`.
pub fn provenance_is_trustworthy(sql: &str) -> bool {
    StatementInspection::new(sql).provenance_is_trustworthy()
}

fn provenance_is_trustworthy_inspected(inspection: &StatementInspection<'_>) -> bool {
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
    // `nodes()` skips LIMIT / window frames; a UNION there still makes
    // CockroachDB report one branch's OID for the outer field.
    !tree_any(parsed, |node| match node.node.as_ref() {
        Some(NodeEnum::SelectStmt(select)) => {
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
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    let mut cte_names: Vec<String> = Vec::new();
    walk_parsed(parsed, &mut |node| {
        if let Some(NodeEnum::CommonTableExpr(cte)) = node.node.as_ref() {
            cte_names.push(cte.ctename.to_ascii_lowercase());
        }
    });
    !tree_any(parsed, |node| match node.node.as_ref() {
        Some(NodeEnum::RangeVar(v)) => {
            v.schemaname.is_empty() && !cte_names.contains(&v.relname.to_ascii_lowercase())
        }
        _ => false,
    })
}

/// Under `posture = "hostile"`: refuse when a masked column appears more often
/// in the statement than as a bare `ColumnRef` in the outermost SELECT list,
/// after discounting mentions that are only a *simple* `ORDER BY` key.
///
/// That closes the measured *value* inference routes (`WHERE`/`LIKE`,
/// single-row `sum`, error-channel `CASE`) while still allowing
/// `SELECT email, id FROM t WHERE id = 1` and cleartext **ordering** of masked
/// projections (`ORDER BY email`, `ORDER BY 1`, …). Sorting by cleartext does
/// not put the cleartext in the wire result; the operator accepts that trade.
///
/// Counts come from both the token stream and the parse tree (max per name):
/// unicode-escaped identifiers (`u&"email"`) never appear as the bare word
/// `email` in the text, but show up decoded on `ColumnRef` nodes. Unparseable
/// or unscannable SQL refuses whenever any masked name is involved.
///
/// `ORDER BY email = 'x'` is **not** credited — that is a membership oracle
/// smuggled through the sort clause, not cleartext ordering of a column.
pub fn masked_exceeds_outer_projection(sql: &str, masked: &HashSet<String>) -> bool {
    StatementInspection::new(sql).masked_exceeds_outer_projection(masked)
}

fn masked_exceeds_outer_projection_inspected(
    inspection: &StatementInspection<'_>,
    masked: &HashSet<String>,
) -> bool {
    use std::collections::HashMap;

    if masked.is_empty() {
        return false;
    }
    // Unicode-escaped names are invisible to the lexer. If we cannot parse,
    // we cannot count them, and allowing the statement is a leak on any
    // syntax pg_query lags the engine on (JSON_TABLE, …). Fail closed.
    let Some(parsed) = inspection.parsed() else {
        return true;
    };
    let Some(idents) = inspection.identifiers() else {
        return true;
    };
    let mut counts: HashMap<String, usize> = HashMap::new();
    for id in idents {
        if masked.contains(id) {
            counts
                .entry(id.clone())
                .and_modify(|c| *c = c.saturating_add(1))
                .or_insert(1);
        }
    }
    for (name, n) in masked_column_ref_counts(parsed, masked) {
        let entry = counts.entry(name).or_insert(0);
        *entry = (*entry).max(n);
    }
    if counts.is_empty() {
        return false;
    }
    let Some(proj) = outer_bare_projection_counts(parsed) else {
        return true;
    };
    let sort_credit = simple_masked_order_by_credits(parsed, masked);
    counts.iter().any(|(name, &n)| {
        let credited = n.saturating_sub(sort_credit.get(name).copied().unwrap_or(0));
        credited > proj.get(name).copied().unwrap_or(0)
    })
}

/// How often each masked name appears as a `ColumnRef`, a name-list `String`
/// (`USING`, alias colnames, SEARCH/CYCLE), or a `ColumnDef` name.
///
/// One walk from the statement root via [`walk_tree`] — the same descent
/// whole-row / join-rename / untrusted-function use. `pg_query::nodes()` is
/// not a second source of counts (it double-counted inner `SelectStmt`s and
/// skipped PREPARE bodies).
fn masked_column_ref_counts(
    parsed: &pg_query::ParseResult,
    masked: &HashSet<String>,
) -> std::collections::HashMap<String, usize> {
    use std::collections::HashMap;

    let mut counts = HashMap::new();
    walk_parsed(parsed, &mut |node| {
        inspect_masked_name(node, masked, &mut counts);
    });
    counts
}

fn inspect_masked_name(
    node: &pg_query::protobuf::Node,
    masked: &HashSet<String>,
    counts: &mut std::collections::HashMap<String, usize>,
) {
    match node.node.as_ref() {
        Some(NodeEnum::ColumnRef(column)) => tally_masked_column_ref(column, masked, counts),
        Some(NodeEnum::String(_)) => tally_masked_string_node(node, masked, counts),
        Some(NodeEnum::ColumnDef(d)) => {
            let name = d.colname.to_ascii_lowercase();
            if masked.contains(&name) {
                counts
                    .entry(name)
                    .and_modify(|c| *c = c.saturating_add(1))
                    .or_insert(1);
            }
        }
        _ => {}
    }
}

fn tally_masked_string_node(
    node: &pg_query::protobuf::Node,
    masked: &HashSet<String>,
    counts: &mut std::collections::HashMap<String, usize>,
) {
    if let Some(NodeEnum::String(s)) = node.node.as_ref() {
        let name = s.sval.to_ascii_lowercase();
        if masked.contains(&name) {
            counts
                .entry(name)
                .and_modify(|c| *c = c.saturating_add(1))
                .or_insert(1);
        }
    }
}

fn tally_masked_column_ref(
    column: &pg_query::protobuf::ColumnRef,
    masked: &HashSet<String>,
    counts: &mut std::collections::HashMap<String, usize>,
) {
    if let Some(last) = column.fields.last() {
        if let Some(NodeEnum::String(s)) = last.node.as_ref() {
            let name = s.sval.to_ascii_lowercase();
            if masked.contains(&name) {
                counts
                    .entry(name)
                    .and_modify(|c| *c = c.saturating_add(1))
                    .or_insert(1);
            }
        }
    }
}

/// Credit only *simple* sort keys (`ORDER BY email`, `ORDER BY email::text`,
/// `ORDER BY email COLLATE "C"`). Comparisons and functions in the sort list
/// (`ORDER BY email = 'x'`, `ORDER BY length(email)`) are value oracles and
/// must not be discounted.
fn simple_masked_order_by_credits(
    parsed: &pg_query::ParseResult,
    masked: &HashSet<String>,
) -> std::collections::HashMap<String, usize> {
    use std::collections::HashMap;

    let mut counts: HashMap<String, usize> = HashMap::new();
    walk_parsed(parsed, &mut |node| {
        let Some(NodeEnum::SelectStmt(select)) = node.node.as_ref() else {
            return;
        };
        for sort in &select.sort_clause {
            if let Some(NodeEnum::SortBy(s)) = sort.node.as_ref() {
                if let Some(expr) = s.node.as_ref() {
                    if let Some(name) = simple_sort_key_masked_name(expr, masked) {
                        counts
                            .entry(name)
                            .and_modify(|c| *c = c.saturating_add(1))
                            .or_insert(1);
                    }
                }
            }
        }
        for window in &select.window_clause {
            if let Some(NodeEnum::WindowDef(w)) = window.node.as_ref() {
                for sort in &w.order_clause {
                    if let Some(NodeEnum::SortBy(s)) = sort.node.as_ref() {
                        if let Some(expr) = s.node.as_ref() {
                            if let Some(name) = simple_sort_key_masked_name(expr, masked) {
                                counts
                                    .entry(name)
                                    .and_modify(|c| *c = c.saturating_add(1))
                                    .or_insert(1);
                            }
                        }
                    }
                }
            }
        }
    });
    counts
}

fn simple_sort_key_masked_name(
    node: &pg_query::protobuf::Node,
    masked: &HashSet<String>,
) -> Option<String> {
    match node.node.as_ref()? {
        NodeEnum::ColumnRef(column) => {
            let last = column.fields.last()?;
            let NodeEnum::String(s) = last.node.as_ref()? else {
                return None;
            };
            let name = s.sval.to_ascii_lowercase();
            masked.contains(&name).then_some(name)
        }
        NodeEnum::TypeCast(cast) => simple_sort_key_masked_name(cast.arg.as_ref()?, masked),
        NodeEnum::CollateClause(c) => simple_sort_key_masked_name(c.arg.as_ref()?, masked),
        _ => None,
    }
}

/// Under hostile: refuse NATURAL JOIN / column-alias-lists that hide masked
/// columns behind other names.
///
/// - `FROM customers AS t(c1,c2,…)` renames `email` to `c2`, then
///   `WHERE c2 = '…'` is a cleartext membership oracle with no masked token.
/// - `NATURAL JOIN` equates on every same-named column including masked ones,
///   with or without those names appearing in the SQL text.
///
/// Unparseable SQL fails closed when any masked name exists.
pub fn hostile_join_or_rename_masked(
    sql: &str,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
    masked: &HashSet<String>,
) -> bool {
    StatementInspection::new(sql).hostile_join_or_rename_masked(relation_columns, masked)
}

fn hostile_join_or_rename_masked_inspected(
    inspection: &StatementInspection<'_>,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
    masked: &HashSet<String>,
) -> bool {
    if masked.is_empty() {
        return false;
    }
    let Some(parsed) = inspection.parsed() else {
        return true;
    };
    // Walk from the statement root. `nodes()` does not enter PREPARE/DECLARE
    // bodies, subquery alias lists, or CTE column-name lists — each of those
    // is a rename that hides a masked column behind `c2`.
    tree_any(parsed, |node| {
        node_is_join_or_rename(node, relation_columns, masked)
    })
}

fn node_is_join_or_rename(
    node: &pg_query::protobuf::Node,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
    masked: &HashSet<String>,
) -> bool {
    match node.node.as_ref() {
        Some(NodeEnum::RangeVar(v)) => {
            let Some(alias) = v.alias.as_ref() else {
                return false;
            };
            if alias.colnames.is_empty() {
                return false;
            }
            // Unknown relation (CTE, uncatalogued table) plus a column-name
            // list is how `WITH q AS (SELECT * FROM customers) SELECT … FROM
            // q AS t(c1,c2,…)` hides `email` behind `c2`. Fail closed.
            let rel = v.relname.to_ascii_lowercase();
            let schema = v.schemaname.to_ascii_lowercase();
            let cols = columns_for_relation(relation_columns, &schema, &rel);
            cols.is_empty() || cols.iter().any(|c| masked.contains(c))
        }
        Some(NodeEnum::JoinExpr(join)) => {
            if join.is_natural
                && (join_side_has_masked_relation(join.larg.as_deref(), relation_columns, masked)
                    || join_side_has_masked_relation(
                        join.rarg.as_deref(),
                        relation_columns,
                        masked,
                    ))
            {
                return true;
            }
            if alias_renames_columns(join.alias.as_ref())
                && subtree_contains_masked_relation(node, relation_columns, masked)
            {
                return true;
            }
            false
        }
        Some(NodeEnum::RangeSubselect(sub)) => {
            alias_renames_columns(sub.alias.as_ref())
                && (subtree_contains_masked_relation(node, relation_columns, masked)
                    || sub
                        .subquery
                        .as_deref()
                        .is_some_and(|q| select_projects_or_names_masked(q, masked)))
        }
        Some(NodeEnum::RangeFunction(func)) => {
            if alias_renames_columns(func.alias.as_ref())
                && subtree_contains_masked_relation(node, relation_columns, masked)
            {
                return true;
            }
            for def in &func.coldeflist {
                if column_def_name_is_masked(def, masked) {
                    return true;
                }
            }
            false
        }
        Some(NodeEnum::JsonTable(jt)) => {
            alias_renames_columns(jt.alias.as_ref())
                && subtree_contains_masked_relation(node, relation_columns, masked)
        }
        Some(NodeEnum::RangeTableFunc(tf)) => {
            alias_renames_columns(tf.alias.as_ref())
                && subtree_contains_masked_relation(node, relation_columns, masked)
        }
        Some(NodeEnum::CommonTableExpr(cte)) => {
            if cte.aliascolnames.is_empty() {
                return false;
            }
            cte.ctequery
                .as_deref()
                .is_some_and(|q| subtree_contains_masked_relation(q, relation_columns, masked))
        }
        _ => false,
    }
}

fn alias_renames_columns(alias: Option<&pg_query::protobuf::Alias>) -> bool {
    alias.is_some_and(|a| !a.colnames.is_empty())
}

fn column_def_name_is_masked(node: &pg_query::protobuf::Node, masked: &HashSet<String>) -> bool {
    if let Some(NodeEnum::ColumnDef(def)) = node.node.as_ref() {
        return masked.contains(&def.colname.to_ascii_lowercase());
    }
    false
}

fn subtree_contains_masked_relation(
    node: &pg_query::protobuf::Node,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
    masked: &HashSet<String>,
) -> bool {
    subtree_any(node, |n| {
        let Some(NodeEnum::RangeVar(v)) = n.node.as_ref() else {
            return false;
        };
        let rel = v.relname.to_ascii_lowercase();
        let schema = v.schemaname.to_ascii_lowercase();
        let cols = columns_for_relation(relation_columns, &schema, &rel);
        cols.iter().any(|c| masked.contains(c))
    })
}

fn join_side_has_masked_relation(
    node: Option<&pg_query::protobuf::Node>,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
    masked: &HashSet<String>,
) -> bool {
    let Some(node) = node else {
        return false;
    };
    match node.node.as_ref() {
        Some(NodeEnum::RangeVar(v)) => {
            let rel = v.relname.to_ascii_lowercase();
            let schema = v.schemaname.to_ascii_lowercase();
            let cols = columns_for_relation(relation_columns, &schema, &rel);
            cols.iter().any(|c| masked.contains(c))
        }
        Some(NodeEnum::JoinExpr(join)) => {
            join_side_has_masked_relation(join.larg.as_deref(), relation_columns, masked)
                || join_side_has_masked_relation(join.rarg.as_deref(), relation_columns, masked)
        }
        Some(NodeEnum::RangeSubselect(sub)) => {
            // Subquery / VALUES side of NATURAL JOIN: if it exposes a colnames
            // alias that matches a masked name, the join equates on cleartext.
            if let Some(alias) = sub.alias.as_ref() {
                for entry in &alias.colnames {
                    if let Some(NodeEnum::String(s)) = entry.node.as_ref() {
                        if masked.contains(&s.sval.to_ascii_lowercase()) {
                            return true;
                        }
                    }
                }
            }
            // Also: subquery body selecting masked columns — walk SelectStmt.
            if let Some(query) = sub.subquery.as_deref() {
                return select_projects_or_names_masked(query, masked);
            }
            false
        }
        Some(NodeEnum::RangeFunction(func)) => {
            if let Some(alias) = func.alias.as_ref() {
                for entry in &alias.colnames {
                    if let Some(NodeEnum::String(s)) = entry.node.as_ref() {
                        if masked.contains(&s.sval.to_ascii_lowercase()) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn select_projects_or_names_masked(
    node: &pg_query::protobuf::Node,
    masked: &HashSet<String>,
) -> bool {
    match node.node.as_ref() {
        Some(NodeEnum::SelectStmt(select)) => {
            for target in &select.target_list {
                if let Some(NodeEnum::ResTarget(t)) = target.node.as_ref() {
                    if !t.name.is_empty() && masked.contains(&t.name.to_ascii_lowercase()) {
                        return true;
                    }
                    if let Some(val) = t.val.as_ref() {
                        let mut found = false;
                        walk_tree(val, &mut |n| {
                            if found {
                                return;
                            }
                            let mut counts = std::collections::HashMap::new();
                            inspect_masked_name(n, masked, &mut counts);
                            if !counts.is_empty() {
                                found = true;
                            }
                        });
                        if found {
                            return true;
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// Under hostile: refuse whole-row references to a FROM item.
///
/// `t::text`, `format('%s', t)`, `concat(t)`, and `customers::text` never name
/// a masked column, so [`masked_exceeds_outer_projection`] allows them — but
/// Postgres still embeds every column's cleartext in the row text. That is a
/// full cleartext membership oracle.
///
/// `relation_columns` maps qualified (and possibly bare) relation names to
/// their bare column names. A FROM alias that collides with a column *of that
/// relation* (`FROM demo.customers email`) is not treated as a row variable —
/// Postgres prefers the column, and the lexical gate covers masked names.
/// Unparseable SQL fails closed.
pub fn hostile_uses_whole_row(
    sql: &str,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
) -> bool {
    StatementInspection::new(sql).hostile_uses_whole_row(relation_columns)
}

fn hostile_uses_whole_row_inspected(
    inspection: &StatementInspection<'_>,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
) -> bool {
    let Some(parsed) = inspection.parsed() else {
        return true;
    };
    let mut row_names = HashSet::new();
    let mut qualified = HashSet::new();
    walk_parsed(parsed, &mut |node| {
        collect_row_binder(node, relation_columns, &mut row_names, &mut qualified);
    });
    if row_names.is_empty() && qualified.is_empty() {
        return false;
    }
    // Walk each statement from the root. `nodes()` skips LIMIT, window
    // frames, aggregate ORDER BY, JSON constructors, XML, and PREPARE bodies.
    tree_any(parsed, |node| {
        let Some(NodeEnum::ColumnRef(column)) = node.node.as_ref() else {
            return false;
        };
        column_ref_is_whole_row(column, &row_names, &qualified)
    })
}

fn collect_row_binder(
    node: &pg_query::protobuf::Node,
    relation_columns: &std::collections::HashMap<String, Vec<String>>,
    row_names: &mut HashSet<String>,
    qualified: &mut HashSet<String>,
) {
    match node.node.as_ref() {
        Some(NodeEnum::RangeVar(v)) => {
            let rel = v.relname.to_ascii_lowercase();
            if !rel.is_empty() {
                let schema = v.schemaname.to_ascii_lowercase();
                if !schema.is_empty() {
                    qualified.insert(format!("{schema}.{rel}"));
                }
                let cols_on_rel = columns_for_relation(relation_columns, &schema, &rel);
                let mut consider = |binder: String| {
                    if !binder.is_empty() && !cols_on_rel.iter().any(|c| c == &binder) {
                        row_names.insert(binder);
                    }
                };
                if let Some(alias) = v.alias.as_ref() {
                    consider(alias.aliasname.to_ascii_lowercase());
                }
                consider(rel);
            }
        }
        Some(NodeEnum::RangeSubselect(sub)) => {
            if let Some(alias) = sub.alias.as_ref() {
                let a = alias.aliasname.to_ascii_lowercase();
                if !a.is_empty() {
                    row_names.insert(a);
                }
            }
        }
        Some(NodeEnum::RangeFunction(func)) => {
            if let Some(alias) = func.alias.as_ref() {
                let a = alias.aliasname.to_ascii_lowercase();
                if !a.is_empty() {
                    row_names.insert(a);
                }
            }
        }
        Some(NodeEnum::JoinExpr(join)) => {
            if let Some(alias) = join.alias.as_ref() {
                let a = alias.aliasname.to_ascii_lowercase();
                if !a.is_empty() {
                    row_names.insert(a);
                }
            }
        }
        Some(NodeEnum::JsonTable(jt)) => {
            if let Some(alias) = jt.alias.as_ref() {
                let a = alias.aliasname.to_ascii_lowercase();
                if !a.is_empty() {
                    row_names.insert(a);
                }
            }
        }
        Some(NodeEnum::RangeTableFunc(tf)) => {
            if let Some(alias) = tf.alias.as_ref() {
                let a = alias.aliasname.to_ascii_lowercase();
                if !a.is_empty() {
                    row_names.insert(a);
                }
            }
        }
        _ => {}
    }
}

/// Alias colnames `pg_query::nodes()` does not visit. The local walker must.
fn visit_alias_colnames(
    alias: Option<&pg_query::protobuf::Alias>,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    if let Some(alias) = alias {
        for col in &alias.colnames {
            visit(col);
        }
    }
}

/// `varchar(n)` / `numeric(p,s)` typmods are a_expr lists. A subquery there is
/// a membership oracle (`CAST(1 AS numeric((SELECT count(*) WHERE email = 'x'), 0))`)
/// that TypeCast otherwise never enters.
fn visit_type_name(
    type_name: Option<&pg_query::protobuf::TypeName>,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    let Some(type_name) = type_name else {
        return;
    };
    for n in type_name
        .names
        .iter()
        .chain(type_name.typmods.iter())
        .chain(type_name.array_bounds.iter())
    {
        visit(n);
    }
}

fn visit_json_value_expr_children(
    expr: Option<&pg_query::protobuf::JsonValueExpr>,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    let Some(expr) = expr else {
        return;
    };
    if let Some(raw) = expr.raw_expr.as_ref() {
        visit(raw);
    }
    if let Some(formatted) = expr.formatted_expr.as_ref() {
        visit(formatted);
    }
}

fn visit_json_output(
    output: Option<&pg_query::protobuf::JsonOutput>,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    // `RETURNING numeric((SELECT count(*) WHERE email = 'x'), 0)` is the same
    // typmod membership oracle as CAST, but JsonOutput is not a TypeCast and
    // is not a Node, so the walker never reaches those typmods unless we
    // enter them from every JSON constructor that carries an output type.
    let Some(output) = output else {
        return;
    };
    visit_type_name(output.type_name.as_ref(), visit);
}

fn visit_json_agg_constructor_children(
    ctor: Option<&pg_query::protobuf::JsonAggConstructor>,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    let Some(ctor) = ctor else {
        return;
    };
    visit_json_output(ctor.output.as_ref(), visit);
    if let Some(filter) = ctor.agg_filter.as_ref() {
        visit(filter);
    }
    for order in &ctor.agg_order {
        visit(order);
    }
    if let Some(over) = ctor.over.as_ref() {
        for_each_window_def_child(over, visit);
    }
}

fn for_each_child_node(
    node: &pg_query::protobuf::Node,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    match node.node.as_ref() {
        Some(NodeEnum::TypeCast(cast)) => {
            if let Some(arg) = cast.arg.as_ref() {
                visit(arg);
            }
            visit_type_name(cast.type_name.as_ref(), visit);
        }
        Some(NodeEnum::TypeName(t)) => visit_type_name(Some(t), visit),
        Some(NodeEnum::CollateClause(c)) => {
            if let Some(arg) = c.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::AExpr(expr)) => {
            if let Some(l) = expr.lexpr.as_ref() {
                visit(l);
            }
            if let Some(r) = expr.rexpr.as_ref() {
                visit(r);
            }
        }
        Some(NodeEnum::BoolExpr(expr)) => {
            for arg in &expr.args {
                visit(arg);
            }
        }
        Some(NodeEnum::NullTest(n)) => {
            if let Some(arg) = n.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::BooleanTest(b)) => {
            if let Some(arg) = b.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::FuncCall(call)) => {
            for arg in &call.args {
                visit(arg);
            }
            for order in &call.agg_order {
                visit(order);
            }
            if let Some(filter) = call.agg_filter.as_ref() {
                visit(filter);
            }
            if let Some(over) = call.over.as_ref() {
                for_each_window_def_child(over, visit);
            }
        }
        Some(NodeEnum::CoalesceExpr(c)) => {
            for arg in &c.args {
                visit(arg);
            }
        }
        Some(NodeEnum::MinMaxExpr(m)) => {
            for arg in &m.args {
                visit(arg);
            }
        }
        Some(NodeEnum::SubLink(sub)) => {
            if let Some(t) = sub.testexpr.as_ref() {
                visit(t);
            }
            if let Some(s) = sub.subselect.as_ref() {
                visit(s);
            }
        }
        Some(NodeEnum::CaseExpr(c)) => {
            if let Some(a) = c.arg.as_ref() {
                visit(a);
            }
            for arm in &c.args {
                visit(arm);
            }
            if let Some(d) = c.defresult.as_ref() {
                visit(d);
            }
        }
        Some(NodeEnum::CaseWhen(w)) => {
            if let Some(e) = w.expr.as_ref() {
                visit(e);
            }
            if let Some(r) = w.result.as_ref() {
                visit(r);
            }
        }
        Some(NodeEnum::AArrayExpr(arr)) => {
            for el in &arr.elements {
                visit(el);
            }
        }
        Some(NodeEnum::ArrayExpr(arr)) => {
            for el in &arr.elements {
                visit(el);
            }
        }
        Some(NodeEnum::AIndirection(ind)) => {
            if let Some(arg) = ind.arg.as_ref() {
                visit(arg);
            }
            for part in &ind.indirection {
                visit(part);
            }
        }
        Some(NodeEnum::AIndices(i)) => {
            if let Some(l) = i.lidx.as_ref() {
                visit(l);
            }
            if let Some(u) = i.uidx.as_ref() {
                visit(u);
            }
        }
        Some(NodeEnum::XmlExpr(xml)) => {
            for arg in xml.args.iter().chain(xml.named_args.iter()) {
                visit(arg);
            }
        }
        Some(NodeEnum::XmlSerialize(x)) => {
            if let Some(expr) = x.expr.as_ref() {
                visit(expr);
            }
            visit_type_name(x.type_name.as_ref(), visit);
        }
        Some(NodeEnum::NamedArgExpr(named)) => {
            if let Some(arg) = named.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::RowExpr(row)) => {
            for arg in &row.args {
                visit(arg);
            }
        }
        Some(NodeEnum::ResTarget(target)) => {
            if let Some(val) = target.val.as_ref() {
                visit(val);
            }
            for part in &target.indirection {
                visit(part);
            }
        }
        Some(NodeEnum::List(list)) => {
            for item in &list.items {
                visit(item);
            }
        }
        Some(NodeEnum::NullIfExpr(n)) => {
            for arg in &n.args {
                visit(arg);
            }
        }
        Some(NodeEnum::ScalarArrayOpExpr(s)) => {
            for arg in &s.args {
                visit(arg);
            }
        }
        Some(NodeEnum::SortBy(s)) => {
            if let Some(expr) = s.node.as_ref() {
                visit(expr);
            }
        }
        Some(NodeEnum::WindowDef(w)) => for_each_window_def_child(w, visit),
        Some(NodeEnum::SelectStmt(select)) => {
            for n in select
                .distinct_clause
                .iter()
                .chain(select.target_list.iter())
                .chain(select.from_clause.iter())
                .chain(select.group_clause.iter())
                .chain(select.window_clause.iter())
                .chain(select.values_lists.iter())
                .chain(select.sort_clause.iter())
                .chain(select.locking_clause.iter())
            {
                visit(n);
            }
            if let Some(w) = select.where_clause.as_ref() {
                visit(w);
            }
            if let Some(h) = select.having_clause.as_ref() {
                visit(h);
            }
            if let Some(o) = select.limit_offset.as_ref() {
                visit(o);
            }
            if let Some(c) = select.limit_count.as_ref() {
                visit(c);
            }
            if let Some(with) = select.with_clause.as_ref() {
                for cte in &with.ctes {
                    visit(cte);
                }
            }
            if let Some(left) = select.larg.as_ref() {
                let wrap = pg_query::protobuf::Node {
                    node: Some(NodeEnum::SelectStmt(left.clone())),
                };
                visit(&wrap);
            }
            if let Some(right) = select.rarg.as_ref() {
                let wrap = pg_query::protobuf::Node {
                    node: Some(NodeEnum::SelectStmt(right.clone())),
                };
                visit(&wrap);
            }
        }
        Some(NodeEnum::JoinExpr(join)) => {
            if let Some(l) = join.larg.as_ref() {
                visit(l);
            }
            if let Some(r) = join.rarg.as_ref() {
                visit(r);
            }
            if let Some(q) = join.quals.as_ref() {
                visit(q);
            }
            for entry in &join.using_clause {
                visit(entry);
            }
            visit_alias_colnames(join.alias.as_ref(), visit);
            visit_alias_colnames(join.join_using_alias.as_ref(), visit);
        }
        Some(NodeEnum::RangeVar(v)) => visit_alias_colnames(v.alias.as_ref(), visit),
        Some(NodeEnum::RangeSubselect(sub)) => {
            if let Some(q) = sub.subquery.as_ref() {
                visit(q);
            }
            visit_alias_colnames(sub.alias.as_ref(), visit);
        }
        Some(NodeEnum::RangeFunction(func)) => {
            for call in &func.functions {
                visit(call);
            }
            for def in &func.coldeflist {
                visit(def);
            }
            visit_alias_colnames(func.alias.as_ref(), visit);
        }
        Some(NodeEnum::RangeTableSample(sample)) => {
            if let Some(rel) = sample.relation.as_ref() {
                visit(rel);
            }
            for n in sample.method.iter().chain(sample.args.iter()) {
                visit(n);
            }
            if let Some(rep) = sample.repeatable.as_ref() {
                visit(rep);
            }
        }
        Some(NodeEnum::RangeTableFunc(tf)) => {
            if let Some(doc) = tf.docexpr.as_ref() {
                visit(doc);
            }
            if let Some(row) = tf.rowexpr.as_ref() {
                visit(row);
            }
            for ns in &tf.namespaces {
                visit(ns);
            }
            for col in &tf.columns {
                visit(col);
            }
            visit_alias_colnames(tf.alias.as_ref(), visit);
        }
        Some(NodeEnum::CommonTableExpr(cte)) => {
            for col in &cte.aliascolnames {
                visit(col);
            }
            if let Some(q) = cte.ctequery.as_ref() {
                visit(q);
            }
            if let Some(search) = cte.search_clause.as_ref() {
                for col in &search.search_col_list {
                    visit(col);
                }
            }
            if let Some(cycle) = cte.cycle_clause.as_ref() {
                for col in &cycle.cycle_col_list {
                    visit(col);
                }
                if let Some(v) = cycle.cycle_mark_value.as_ref() {
                    visit(v);
                }
                if let Some(d) = cycle.cycle_mark_default.as_ref() {
                    visit(d);
                }
            }
        }
        Some(NodeEnum::CtesearchClause(search)) => {
            for col in &search.search_col_list {
                visit(col);
            }
        }
        Some(NodeEnum::CtecycleClause(cycle)) => {
            for col in &cycle.cycle_col_list {
                visit(col);
            }
            if let Some(v) = cycle.cycle_mark_value.as_ref() {
                visit(v);
            }
            if let Some(d) = cycle.cycle_mark_default.as_ref() {
                visit(d);
            }
        }
        Some(NodeEnum::PrepareStmt(p)) => {
            if let Some(q) = p.query.as_ref() {
                visit(q);
            }
            for t in &p.argtypes {
                visit(t);
            }
        }
        Some(NodeEnum::ExecuteStmt(e)) => {
            for p in &e.params {
                visit(p);
            }
        }
        Some(NodeEnum::VariableSetStmt(s)) => {
            for arg in &s.args {
                visit(arg);
            }
        }
        Some(NodeEnum::DefElem(d)) => {
            if let Some(arg) = d.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::CopyStmt(c)) => {
            if let Some(q) = c.query.as_ref() {
                visit(q);
            }
            for n in c.attlist.iter().chain(c.options.iter()) {
                visit(n);
            }
            if let Some(w) = c.where_clause.as_ref() {
                visit(w);
            }
        }
        Some(NodeEnum::SetOperationStmt(s)) => {
            if let Some(l) = s.larg.as_ref() {
                visit(l);
            }
            if let Some(r) = s.rarg.as_ref() {
                visit(r);
            }
        }
        Some(NodeEnum::LockingClause(l)) => {
            for rel in &l.locked_rels {
                visit(rel);
            }
        }
        Some(NodeEnum::Alias(a)) => {
            for col in &a.colnames {
                visit(col);
            }
        }
        Some(NodeEnum::DeclareCursorStmt(d)) => {
            if let Some(q) = d.query.as_ref() {
                visit(q);
            }
        }
        Some(NodeEnum::ExplainStmt(e)) => {
            if let Some(q) = e.query.as_ref() {
                visit(q);
            }
            for opt in &e.options {
                visit(opt);
            }
        }
        Some(NodeEnum::JsonObjectConstructor(j)) => {
            for expr in &j.exprs {
                visit(expr);
            }
            visit_json_output(j.output.as_ref(), visit);
        }
        Some(NodeEnum::JsonArrayConstructor(j)) => {
            for expr in &j.exprs {
                visit(expr);
            }
            visit_json_output(j.output.as_ref(), visit);
        }
        Some(NodeEnum::JsonConstructorExpr(j)) => {
            for arg in &j.args {
                visit(arg);
            }
            if let Some(func) = j.func.as_ref() {
                visit(func);
            }
            if let Some(coercion) = j.coercion.as_ref() {
                visit(coercion);
            }
        }
        Some(NodeEnum::JsonKeyValue(kv)) => {
            if let Some(key) = kv.key.as_ref() {
                visit(key);
            }
            if let Some(value) = kv.value.as_ref() {
                if let Some(raw) = value.raw_expr.as_ref() {
                    visit(raw);
                }
                if let Some(formatted) = value.formatted_expr.as_ref() {
                    visit(formatted);
                }
            }
        }
        Some(NodeEnum::JsonValueExpr(v)) => {
            if let Some(raw) = v.raw_expr.as_ref() {
                visit(raw);
            }
            if let Some(formatted) = v.formatted_expr.as_ref() {
                visit(formatted);
            }
        }
        Some(NodeEnum::JsonFuncExpr(j)) => {
            if let Some(ctx) = j.context_item.as_ref() {
                if let Some(raw) = ctx.raw_expr.as_ref() {
                    visit(raw);
                }
                if let Some(formatted) = ctx.formatted_expr.as_ref() {
                    visit(formatted);
                }
            }
            if let Some(path) = j.pathspec.as_ref() {
                visit(path);
            }
            for passing in &j.passing {
                visit(passing);
            }
            visit_json_output(j.output.as_ref(), visit);
            if let Some(b) = j.on_empty.as_ref() {
                if let Some(e) = b.expr.as_ref() {
                    visit(e);
                }
            }
            if let Some(b) = j.on_error.as_ref() {
                if let Some(e) = b.expr.as_ref() {
                    visit(e);
                }
            }
        }
        Some(NodeEnum::JsonTable(j)) => {
            if let Some(ctx) = j.context_item.as_ref() {
                if let Some(raw) = ctx.raw_expr.as_ref() {
                    visit(raw);
                }
                if let Some(formatted) = ctx.formatted_expr.as_ref() {
                    visit(formatted);
                }
            }
            if let Some(path) = j.pathspec.as_ref() {
                if let Some(s) = path.string.as_ref() {
                    visit(s);
                }
            }
            for passing in &j.passing {
                visit(passing);
            }
            for col in &j.columns {
                visit(col);
            }
            if let Some(b) = j.on_error.as_ref() {
                if let Some(e) = b.expr.as_ref() {
                    visit(e);
                }
            }
            visit_alias_colnames(j.alias.as_ref(), visit);
        }
        Some(NodeEnum::JsonTableColumn(c)) => {
            visit_type_name(c.type_name.as_ref(), visit);
            if let Some(path) = c.pathspec.as_ref() {
                if let Some(s) = path.string.as_ref() {
                    visit(s);
                }
            }
            for nested in &c.columns {
                visit(nested);
            }
            if let Some(b) = c.on_empty.as_ref() {
                if let Some(e) = b.expr.as_ref() {
                    visit(e);
                }
            }
            if let Some(b) = c.on_error.as_ref() {
                if let Some(e) = b.expr.as_ref() {
                    visit(e);
                }
            }
        }
        Some(NodeEnum::JsonTablePathSpec(p)) => {
            if let Some(s) = p.string.as_ref() {
                visit(s);
            }
        }
        Some(NodeEnum::JsonArgument(a)) => {
            visit_json_value_expr_children(a.val.as_deref(), visit);
        }
        Some(NodeEnum::JsonBehavior(b)) => {
            if let Some(e) = b.expr.as_ref() {
                visit(e);
            }
        }
        Some(NodeEnum::JsonArrayAgg(j)) => {
            visit_json_value_expr_children(j.arg.as_deref(), visit);
            visit_json_agg_constructor_children(j.constructor.as_deref(), visit);
        }
        Some(NodeEnum::JsonObjectAgg(j)) => {
            if let Some(arg) = j.arg.as_ref() {
                if let Some(key) = arg.key.as_ref() {
                    visit(key);
                }
                visit_json_value_expr_children(arg.value.as_deref(), visit);
            }
            visit_json_agg_constructor_children(j.constructor.as_deref(), visit);
        }
        Some(NodeEnum::JsonSerializeExpr(j)) => {
            visit_json_value_expr_children(j.expr.as_deref(), visit);
            visit_json_output(j.output.as_ref(), visit);
        }
        Some(NodeEnum::JsonParseExpr(j)) => {
            visit_json_value_expr_children(j.expr.as_deref(), visit);
            visit_json_output(j.output.as_ref(), visit);
        }
        Some(NodeEnum::JsonScalarExpr(j)) => {
            if let Some(expr) = j.expr.as_ref() {
                visit(expr);
            }
            visit_json_output(j.output.as_ref(), visit);
        }
        Some(NodeEnum::JsonIsPredicate(j)) => {
            if let Some(expr) = j.expr.as_ref() {
                visit(expr);
            }
        }
        Some(NodeEnum::JsonExpr(j)) => {
            if let Some(formatted) = j.formatted_expr.as_ref() {
                visit(formatted);
            }
            if let Some(path) = j.path_spec.as_ref() {
                visit(path);
            }
            for n in j.passing_names.iter().chain(j.passing_values.iter()) {
                visit(n);
            }
            if let Some(b) = j.on_empty.as_ref() {
                if let Some(e) = b.expr.as_ref() {
                    visit(e);
                }
            }
            if let Some(b) = j.on_error.as_ref() {
                if let Some(e) = b.expr.as_ref() {
                    visit(e);
                }
            }
        }
        Some(NodeEnum::JsonArrayQueryConstructor(j)) => {
            if let Some(q) = j.query.as_ref() {
                visit(q);
            }
            visit_json_output(j.output.as_ref(), visit);
        }
        Some(NodeEnum::JsonAggConstructor(c)) => {
            visit_json_agg_constructor_children(Some(c), visit);
        }
        Some(NodeEnum::TableFunc(tf)) => {
            if let Some(doc) = tf.docexpr.as_ref() {
                visit(doc);
            }
            if let Some(row) = tf.rowexpr.as_ref() {
                visit(row);
            }
            if let Some(plan) = tf.plan.as_ref() {
                visit(plan);
            }
            for expr in tf
                .ns_uris
                .iter()
                .chain(tf.ns_names.iter())
                .chain(tf.colnames.iter())
                .chain(tf.coltypes.iter())
                .chain(tf.coltypmods.iter())
                .chain(tf.colcollations.iter())
                .chain(tf.colexprs.iter())
                .chain(tf.coldefexprs.iter())
                .chain(tf.colvalexprs.iter())
                .chain(tf.passingvalexprs.iter())
            {
                visit(expr);
            }
        }
        Some(NodeEnum::JsonTablePathScan(scan)) => {
            if let Some(plan) = scan.plan.as_ref() {
                visit(plan);
            }
            if let Some(child) = scan.child.as_ref() {
                visit(child);
            }
        }
        Some(NodeEnum::JsonTableSiblingJoin(join)) => {
            if let Some(plan) = join.plan.as_ref() {
                visit(plan);
            }
            if let Some(l) = join.lplan.as_ref() {
                visit(l);
            }
            if let Some(r) = join.rplan.as_ref() {
                visit(r);
            }
        }
        Some(NodeEnum::RangeTableFuncCol(c)) => {
            visit_type_name(c.type_name.as_ref(), visit);
            if let Some(expr) = c.colexpr.as_ref() {
                visit(expr);
            }
            if let Some(expr) = c.coldefexpr.as_ref() {
                visit(expr);
            }
        }
        Some(NodeEnum::ColumnDef(d)) => {
            visit_type_name(d.type_name.as_ref(), visit);
            if let Some(expr) = d.raw_default.as_ref() {
                visit(expr);
            }
            if let Some(expr) = d.cooked_default.as_ref() {
                visit(expr);
            }
            if let Some(coll) = d.coll_clause.as_ref() {
                if let Some(arg) = coll.arg.as_ref() {
                    visit(arg);
                }
            }
            for c in &d.constraints {
                visit(c);
            }
        }
        Some(NodeEnum::Constraint(c)) => {
            if let Some(e) = c.raw_expr.as_ref() {
                visit(e);
            }
        }
        Some(NodeEnum::CoerceViaIo(c)) => {
            if let Some(arg) = c.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::ConvertRowtypeExpr(c)) => {
            if let Some(arg) = c.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::RelabelType(r)) => {
            if let Some(arg) = r.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::ArrayCoerceExpr(a)) => {
            if let Some(arg) = a.arg.as_ref() {
                visit(arg);
            }
            if let Some(elem) = a.elemexpr.as_ref() {
                visit(elem);
            }
        }
        Some(NodeEnum::GroupingSet(set)) => {
            for member in &set.content {
                visit(member);
            }
        }
        Some(NodeEnum::SubscriptingRef(sub)) => {
            if let Some(expr) = sub.refexpr.as_ref() {
                visit(expr);
            }
            for idx in sub.refupperindexpr.iter().chain(sub.reflowerindexpr.iter()) {
                visit(idx);
            }
        }
        Some(NodeEnum::FieldSelect(f)) => {
            if let Some(arg) = f.arg.as_ref() {
                visit(arg);
            }
        }
        Some(NodeEnum::RowCompareExpr(r)) => {
            for arg in r.largs.iter().chain(r.rargs.iter()) {
                visit(arg);
            }
        }
        Some(NodeEnum::DistinctExpr(d)) => {
            for arg in &d.args {
                visit(arg);
            }
        }
        Some(NodeEnum::GroupingFunc(g)) => {
            for arg in &g.args {
                visit(arg);
            }
        }
        _ => {}
    }
}

/// Visit `node` then every descendant `for_each_child_node` can see.
///
/// `pg_query::nodes()` is generated from a subset of the protobuf schema and
/// "doesn't iterate over every possible node type" (upstream). Hostile gates
/// cannot prove absence on that iterator, so every tree-shaped check uses this
/// walk instead of a second hand-rolled match.
fn walk_tree(node: &pg_query::protobuf::Node, visit: &mut dyn FnMut(&pg_query::protobuf::Node)) {
    visit(node);
    for_each_child_node(node, &mut |child| walk_tree(child, visit));
}

fn walk_parsed(parsed: &pg_query::ParseResult, visit: &mut dyn FnMut(&pg_query::protobuf::Node)) {
    for raw in &parsed.protobuf.stmts {
        if let Some(stmt) = raw.stmt.as_ref() {
            walk_tree(stmt, visit);
        }
    }
}

fn tree_any(
    parsed: &pg_query::ParseResult,
    mut pred: impl FnMut(&pg_query::protobuf::Node) -> bool,
) -> bool {
    let mut found = false;
    walk_parsed(parsed, &mut |node| {
        if !found {
            found = pred(node);
        }
    });
    found
}

fn subtree_any(
    node: &pg_query::protobuf::Node,
    mut pred: impl FnMut(&pg_query::protobuf::Node) -> bool,
) -> bool {
    let mut found = false;
    walk_tree(node, &mut |n| {
        if !found {
            found = pred(n);
        }
    });
    found
}

fn for_each_window_def_child(
    window: &pg_query::protobuf::WindowDef,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    for part in &window.partition_clause {
        visit(part);
    }
    for sort in &window.order_clause {
        visit(sort);
    }
    if let Some(start) = window.start_offset.as_ref() {
        visit(start);
    }
    if let Some(end) = window.end_offset.as_ref() {
        visit(end);
    }
}

fn columns_for_relation<'a>(
    relation_columns: &'a std::collections::HashMap<String, Vec<String>>,
    schema: &str,
    rel: &str,
) -> &'a [String] {
    if !schema.is_empty() {
        let q = format!("{schema}.{rel}");
        if let Some(cols) = relation_columns.get(&q) {
            return cols.as_slice();
        }
    }
    if let Some(cols) = relation_columns.get(rel) {
        return cols.as_slice();
    }
    // Unqualified FROM with search_path: match any schema.rel suffix.
    for (name, cols) in relation_columns {
        if name == rel || name.ends_with(&format!(".{rel}")) {
            return cols.as_slice();
        }
    }
    &[]
}

fn column_ref_is_whole_row(
    column: &pg_query::protobuf::ColumnRef,
    row_names: &HashSet<String>,
    qualified: &HashSet<String>,
) -> bool {
    let fields: Vec<&str> = column
        .fields
        .iter()
        .filter_map(|f| match f.node.as_ref() {
            Some(NodeEnum::String(s)) => Some(s.sval.as_str()),
            _ => None,
        })
        .collect();
    match fields.as_slice() {
        [name] => row_names.contains(&name.to_ascii_lowercase()),
        [schema, rel] => {
            let q = format!(
                "{}.{}",
                schema.to_ascii_lowercase(),
                rel.to_ascii_lowercase()
            );
            qualified.contains(&q)
        }
        _ => false,
    }
}

/// `DO` / `CALL` / `CREATE FUNCTION` (and `CREATE PROCEDURE`) — they run or
/// install PL/pgSQL without a maskable projection, which is how the timing and
/// exception-presence oracles under `posture = "hostile"` still worked after
/// notice caps. Exploration does not need them; refuse the statement class.
pub fn is_procedural_statement(sql: &str) -> bool {
    let inspection = StatementInspection::new(sql);
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, |node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::DoStmt(_))
                | Some(NodeEnum::CallStmt(_))
                | Some(NodeEnum::CreateFunctionStmt(_))
        )
    })
}

/// SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` and `DECLARE` / `FETCH` /
/// `CLOSE`. A second copy of the extended protocol (`Parse`/`Bind`/`Execute`
/// and named portals). Walked from the statement root so `EXPLAIN PREPARE`
/// is the same class. Analysts keep ordinary `SELECT` — including
/// `SELECT … FETCH FIRST n ROWS`, which is a `SelectStmt` limit, not a
/// `FetchStmt` — and protocol Parse/Bind.
///
/// Parse failure returns false, same as [`is_write_statement`]; other gates
/// still apply. Refused on every posture, not only hostile.
pub fn is_sql_prepare_or_cursor(sql: &str) -> bool {
    StatementInspection::new(sql).is_sql_prepare_or_cursor()
}

fn is_sql_prepare_or_cursor_inspected(inspection: &StatementInspection<'_>) -> bool {
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, |node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::PrepareStmt(_))
                | Some(NodeEnum::ExecuteStmt(_))
                | Some(NodeEnum::DeallocateStmt(_))
                | Some(NodeEnum::DeclareCursorStmt(_))
                | Some(NodeEnum::FetchStmt(_))
                | Some(NodeEnum::ClosePortalStmt(_))
        )
    })
}

/// Anything that is not on the read-only allowlist.
///
/// Fail-closed: every `*Stmt` node must be explicitly permitted, or the
/// statement is refused. A denylist missed `CREATE VIEW` / `LOAD` /
/// `CHECKPOINT` (and would miss the next DDL variant pg_query adds). pgmask
/// is a read-only masking proxy — writes and admin DDL are refused on every
/// posture, not only hostile.
///
/// SQL `PREPARE`/`DECLARE` and friends stay on this allowlist so they are
/// not bucketed as writes; [`is_sql_prepare_or_cursor`] refuses them with
/// a dedicated error.
pub fn is_write_statement(sql: &str) -> bool {
    StatementInspection::new(sql).is_write_statement()
}

fn is_write_statement_inspected(inspection: &StatementInspection<'_>) -> bool {
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, node_is_write)
}

fn node_is_write(node: &pg_query::protobuf::Node) -> bool {
    match node.node.as_ref() {
        // --- read-only / session allowlist ---------------------------------
        Some(NodeEnum::SelectStmt(select)) => {
            // Row locks and SELECT INTO are write-adjacent.
            select.into_clause.is_some() || !select.locking_clause.is_empty()
        }
        Some(NodeEnum::SetOperationStmt(_))
        | Some(NodeEnum::ExplainStmt(_))
        | Some(NodeEnum::VariableSetStmt(_))
        | Some(NodeEnum::VariableShowStmt(_))
        | Some(NodeEnum::TransactionStmt(_))
        | Some(NodeEnum::PrepareStmt(_))
        | Some(NodeEnum::ExecuteStmt(_))
        | Some(NodeEnum::DeallocateStmt(_))
        | Some(NodeEnum::DiscardStmt(_))
        | Some(NodeEnum::DeclareCursorStmt(_))
        | Some(NodeEnum::FetchStmt(_))
        | Some(NodeEnum::ClosePortalStmt(_))
        | Some(NodeEnum::ConstraintsSetStmt(_))
        | Some(NodeEnum::RawStmt(_)) => false,

        // --- every other statement class is refused ------------------------
        Some(NodeEnum::InsertStmt(_))
        | Some(NodeEnum::UpdateStmt(_))
        | Some(NodeEnum::DeleteStmt(_))
        | Some(NodeEnum::MergeStmt(_))
        | Some(NodeEnum::TruncateStmt(_))
        | Some(NodeEnum::CopyStmt(_))
        | Some(NodeEnum::ViewStmt(_))
        | Some(NodeEnum::LoadStmt(_))
        | Some(NodeEnum::CheckPointStmt(_))
        | Some(NodeEnum::CreateStmt(_))
        | Some(NodeEnum::CreateTableAsStmt(_))
        | Some(NodeEnum::CreateSchemaStmt(_))
        | Some(NodeEnum::CreateSeqStmt(_))
        | Some(NodeEnum::CreateForeignTableStmt(_))
        | Some(NodeEnum::CreateFunctionStmt(_))
        | Some(NodeEnum::CreateTrigStmt(_))
        | Some(NodeEnum::CreateRoleStmt(_))
        | Some(NodeEnum::CreatedbStmt(_))
        | Some(NodeEnum::CreateEnumStmt(_))
        | Some(NodeEnum::CreateDomainStmt(_))
        | Some(NodeEnum::CreateExtensionStmt(_))
        | Some(NodeEnum::CreatePlangStmt(_))
        | Some(NodeEnum::CreateConversionStmt(_))
        | Some(NodeEnum::CreateCastStmt(_))
        | Some(NodeEnum::CreateOpClassStmt(_))
        | Some(NodeEnum::CreateOpFamilyStmt(_))
        | Some(NodeEnum::CreateTableSpaceStmt(_))
        | Some(NodeEnum::CreateFdwStmt(_))
        | Some(NodeEnum::CreateForeignServerStmt(_))
        | Some(NodeEnum::CreateUserMappingStmt(_))
        | Some(NodeEnum::CreateEventTrigStmt(_))
        | Some(NodeEnum::CreatePolicyStmt(_))
        | Some(NodeEnum::CreateTransformStmt(_))
        | Some(NodeEnum::CreateAmStmt(_))
        | Some(NodeEnum::CreatePublicationStmt(_))
        | Some(NodeEnum::CreateSubscriptionStmt(_))
        | Some(NodeEnum::CreateStatsStmt(_))
        | Some(NodeEnum::CreateRangeStmt(_))
        | Some(NodeEnum::CompositeTypeStmt(_))
        | Some(NodeEnum::DefineStmt(_))
        | Some(NodeEnum::IndexStmt(_))
        | Some(NodeEnum::RuleStmt(_))
        | Some(NodeEnum::DropStmt(_))
        | Some(NodeEnum::DropRoleStmt(_))
        | Some(NodeEnum::DropdbStmt(_))
        | Some(NodeEnum::DropTableSpaceStmt(_))
        | Some(NodeEnum::DropUserMappingStmt(_))
        | Some(NodeEnum::DropOwnedStmt(_))
        | Some(NodeEnum::DropSubscriptionStmt(_))
        | Some(NodeEnum::AlterTableStmt(_))
        | Some(NodeEnum::AlterSeqStmt(_))
        | Some(NodeEnum::AlterRoleStmt(_))
        | Some(NodeEnum::AlterDatabaseStmt(_))
        | Some(NodeEnum::AlterDatabaseSetStmt(_))
        | Some(NodeEnum::AlterDatabaseRefreshCollStmt(_))
        | Some(NodeEnum::AlterFunctionStmt(_))
        | Some(NodeEnum::AlterOwnerStmt(_))
        | Some(NodeEnum::AlterObjectSchemaStmt(_))
        | Some(NodeEnum::AlterObjectDependsStmt(_))
        | Some(NodeEnum::AlterEnumStmt(_))
        | Some(NodeEnum::AlterSystemStmt(_))
        | Some(NodeEnum::AlterDomainStmt(_))
        | Some(NodeEnum::AlterDefaultPrivilegesStmt(_))
        | Some(NodeEnum::AlterOpFamilyStmt(_))
        | Some(NodeEnum::AlterOperatorStmt(_))
        | Some(NodeEnum::AlterTypeStmt(_))
        | Some(NodeEnum::AlterRoleSetStmt(_))
        | Some(NodeEnum::AlterTsdictionaryStmt(_))
        | Some(NodeEnum::AlterTsconfigurationStmt(_))
        | Some(NodeEnum::AlterFdwStmt(_))
        | Some(NodeEnum::AlterForeignServerStmt(_))
        | Some(NodeEnum::AlterUserMappingStmt(_))
        | Some(NodeEnum::AlterTableSpaceOptionsStmt(_))
        | Some(NodeEnum::AlterTableMoveAllStmt(_))
        | Some(NodeEnum::AlterExtensionStmt(_))
        | Some(NodeEnum::AlterExtensionContentsStmt(_))
        | Some(NodeEnum::AlterEventTrigStmt(_))
        | Some(NodeEnum::AlterPolicyStmt(_))
        | Some(NodeEnum::AlterPublicationStmt(_))
        | Some(NodeEnum::AlterSubscriptionStmt(_))
        | Some(NodeEnum::AlterStatsStmt(_))
        | Some(NodeEnum::AlterCollationStmt(_))
        | Some(NodeEnum::RenameStmt(_))
        | Some(NodeEnum::GrantStmt(_))
        | Some(NodeEnum::GrantRoleStmt(_))
        | Some(NodeEnum::ReassignOwnedStmt(_))
        | Some(NodeEnum::CommentStmt(_))
        | Some(NodeEnum::SecLabelStmt(_))
        | Some(NodeEnum::ImportForeignSchemaStmt(_))
        | Some(NodeEnum::ReplicaIdentityStmt(_))
        | Some(NodeEnum::VacuumStmt(_))
        | Some(NodeEnum::ReindexStmt(_))
        | Some(NodeEnum::ClusterStmt(_))
        | Some(NodeEnum::RefreshMatViewStmt(_))
        | Some(NodeEnum::LockStmt(_))
        | Some(NodeEnum::DoStmt(_))
        | Some(NodeEnum::CallStmt(_))
        | Some(NodeEnum::NotifyStmt(_))
        | Some(NodeEnum::ListenStmt(_))
        | Some(NodeEnum::UnlistenStmt(_))
        | Some(NodeEnum::ReturnStmt(_))
        | Some(NodeEnum::PlassignStmt(_)) => true,

        // Expression / type / utility nodes inside an allowed statement.
        _ => false,
    }
}

/// A function call that is not on the trusted `pg_catalog` allowlist.
///
/// Schema-qualified calls outside `pg_catalog` (e.g. `demo.sleep_if`) are how a
/// preinstalled PL/pgSQL function still ran under read-only + hostile: the
/// return value was opaque-refused, but timing / side effects happened first.
/// Unqualified names must appear on the same allowlists `classify` already
/// trusts; everything else is refused before the backend sees it.
///
/// Metadata-only catalog queries are exempt — they need `format_type` and
/// friends, and [`reads_only_server_metadata`] already gates that path
/// (target-list functions are an allowlist of helpers / trusted names).
pub fn calls_untrusted_function(sql: &str) -> bool {
    StatementInspection::new(sql).calls_untrusted_function()
}

fn calls_untrusted_function_inspected(inspection: &StatementInspection<'_>) -> bool {
    if inspection.reads_only_server_metadata() {
        return false;
    }
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, |node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::FuncCall(call)) if !func_call_is_trusted(call)
        )
    })
}

fn func_call_name_parts(call: &pg_query::protobuf::FuncCall) -> Option<Vec<String>> {
    let mut parts = Vec::with_capacity(call.funcname.len());
    for node in &call.funcname {
        let NodeEnum::String(s) = node.node.as_ref()? else {
            return None;
        };
        parts.push(s.sval.to_ascii_lowercase());
    }
    Some(parts)
}

fn func_call_is_trusted(call: &pg_query::protobuf::FuncCall) -> bool {
    let Some(parts) = func_call_name_parts(call) else {
        return false;
    };
    let name = match parts.as_slice() {
        [name] => name.as_str(),
        [schema, name] if schema == "pg_catalog" => name.as_str(),
        _ => return false,
    };
    is_trusted_function_name(name)
}

/// Target-list functions permitted on the metadata-only fast path.
///
/// Fail-closed: an unparseable name, a schema other than `pg_catalog` /
/// `information_schema`, or a name that is not trusted / a FROM-generator /
/// a catalog helper is not metadata-only. [`CATALOG_ESCAPE_FUNCTIONS`] still
/// wins if a name is on both lists. `information_schema._pg_*` helpers
/// implement the SQL-standard views; they are not dump functions.
fn func_call_is_catalog_safe(call: &pg_query::protobuf::FuncCall) -> bool {
    let Some(parts) = func_call_name_parts(call) else {
        return false;
    };
    let (schema, name) = match parts.as_slice() {
        [name] => (None, name.as_str()),
        [schema, name] if schema == "pg_catalog" || schema == "information_schema" => {
            (Some(schema.as_str()), name.as_str())
        }
        _ => return false,
    };
    if CATALOG_ESCAPE_FUNCTIONS.contains(&name) {
        return false;
    }
    if schema == Some("information_schema") && name.starts_with("_pg") {
        return true;
    }
    is_trusted_function_name(name)
        || GENERATORS_IN_FROM.contains(&name)
        || CATALOG_HELPER_FUNCTIONS.contains(&name)
}

fn is_trusted_function_name(name: &str) -> bool {
    CONTEXT_FUNCTIONS.contains(&name)
        || SIZE_FUNCTIONS.contains(&name)
        || REDUCING_AGGREGATES.contains(&name)
        || RANKING_WINDOWS.contains(&name)
        || PURE_SCALARS.contains(&name)
        || TEXT_FUNCTIONS.contains(&name)
        || name == "date_trunc"
}

/// Unqualified text helpers that analysis already treats as ordinary expressions
/// (usually opaque). Listed so a `lower(city)` under default posture is not
/// mistaken for a user-defined function; they never get a free pass past the
/// projection / opaque gates.
const TEXT_FUNCTIONS: &[&str] = &[
    "length",
    "char_length",
    "character_length",
    "octet_length",
    "lower",
    "upper",
    "initcap",
    "substr",
    "substring",
    "left",
    "right",
    "trim",
    "btrim",
    "ltrim",
    "rtrim",
    "replace",
    "translate",
    "overlay",
    "concat",
    "concat_ws",
    "format",
    "repeat",
    "reverse",
    "ascii",
    "chr",
    "md5",
    "convert",
    "convert_from",
    "convert_to",
    "encode",
    "decode",
];

fn select_stmt_for_outer_projection(
    stmt: &pg_query::protobuf::Node,
) -> Option<&pg_query::protobuf::SelectStmt> {
    match stmt.node.as_ref()? {
        NodeEnum::SelectStmt(select) => Some(select),
        // Analysts EXPLAIN ordinary SELECT. Peel the wrapper so
        // `EXPLAIN SELECT email FROM t` keeps the same residual as the
        // inner statement; `EXPLAIN SELECT count(*) WHERE email = 'x'`
        // still exceeds outer projection and is refused.
        NodeEnum::ExplainStmt(explain) => {
            let query = explain.query.as_ref()?;
            match query.node.as_ref()? {
                NodeEnum::SelectStmt(select) => Some(select),
                _ => None,
            }
        }
        _ => None,
    }
}

fn outer_bare_projection_counts(
    parsed: &pg_query::ParseResult,
) -> Option<std::collections::HashMap<String, usize>> {
    use std::collections::HashMap;
    if parsed.protobuf.stmts.len() != 1 {
        return None;
    }
    let stmt = parsed.protobuf.stmts.first()?.stmt.as_ref()?;
    let select = select_stmt_for_outer_projection(stmt)?;
    // Set operations erase which branch a name came from; hostile refuses them
    // when a masked name is present (caller already saw one).
    if select.op() != SetOperation::SetopNone {
        return None;
    }
    let mut counts = HashMap::new();
    for entry in &select.target_list {
        let Some(NodeEnum::ResTarget(target)) = entry.node.as_ref() else {
            continue;
        };
        let Some(val) = target.val.as_ref() else {
            continue;
        };
        if let Some(name) = bare_column_ref_name(val) {
            let n = counts
                .get(&name)
                .copied()
                .unwrap_or(0usize)
                .saturating_add(1);
            counts.insert(name, n);
        }
    }
    Some(counts)
}

fn bare_column_ref_name(node: &pg_query::protobuf::Node) -> Option<String> {
    let NodeEnum::ColumnRef(column) = node.node.as_ref()? else {
        return None;
    };
    let last = column.fields.last()?;
    match last.node.as_ref()? {
        NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
        _ => None, // `*` or other
    }
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
        assert_eq!(
            inspection.output_safety(2, ALLOW_ALL),
            vec![Safety::Unknown; 2]
        );
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
            "SELECT pg_catalog.pg_get_viewdef(c.oid) FROM pg_catalog.pg_class c",
            "SELECT pg_catalog.pg_get_indexdef(i.indexrelid) FROM pg_catalog.pg_index i",
            "SELECT * FROM generate_series(1, 3) g, pg_catalog.pg_class c",
            "SELECT table_name FROM information_schema.tables",
            "SELECT rolname FROM pg_roles",
            "SELECT * FROM information_schema.user_mappings",
            "SELECT * FROM information_schema.foreign_servers",
            "SELECT * FROM information_schema.foreign_tables",
            "SELECT * FROM information_schema.foreign_data_wrappers",
            "SELECT column_name FROM information_schema.columns",
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
            "SELECT statement FROM pg_catalog.pg_cursors",
            "SELECT statement FROM pg_cursors",
            r#"SELECT statement FROM u&"pg_cursors""#,
            "SELECT conninfo FROM pg_catalog.pg_stat_wal_receiver",
            "SELECT passwd FROM pg_user",
            "SELECT * FROM pg_catalog.pg_user",
            "EXPLAIN SELECT most_common_vals FROM pg_catalog.pg_stats",
            "SELECT chunk_data FROM pg_toast.pg_toast_12345",
            "SELECT count(*) FROM pg_toast.pg_toast_12345 WHERE chunk_data LIKE '%@%'",
            "SELECT * FROM pg_toast_12345",
            r#"SELECT * FROM u&"pg_toast".u&"pg_toast_12345""#,
            "SELECT srvoptions FROM pg_catalog.pg_foreign_server",
            "SELECT fdwoptions FROM pg_foreign_data_wrapper",
            r#"SELECT srvoptions FROM u&"pg_foreign_server""#,
            "EXPLAIN SELECT chunk_data FROM pg_toast.pg_toast_12345",
            "SELECT option_value FROM information_schema.user_mapping_options",
            "SELECT * FROM information_schema.foreign_server_options",
            "SELECT * FROM information_schema.foreign_data_wrapper_options",
            r#"SELECT * FROM information_schema.u&"user_mapping_options""#,
            "SELECT option_value FROM user_mapping_options",
            "SELECT option_value FROM information_schema.column_options",
            "SELECT * FROM information_schema.foreign_table_options",
            r#"SELECT * FROM information_schema.u&"column_options""#,
            "SELECT option_value FROM column_options",
            "SELECT umoptions FROM information_schema._pg_user_mappings",
            "SELECT srvoptions FROM information_schema._pg_foreign_servers",
            "SELECT fdwoptions FROM information_schema._pg_foreign_data_wrappers",
            "SELECT ftoptions FROM information_schema._pg_foreign_tables",
            "SELECT attfdwoptions FROM information_schema._pg_foreign_table_columns",
            "SELECT umoptions FROM _pg_user_mappings",
            r#"SELECT * FROM information_schema.u&"_pg_user_mappings""#,
            "EXPLAIN SELECT * FROM information_schema.column_options",
        ] {
            assert!(
                !reads_only_server_metadata(sql),
                "must not be released: {sql}"
            );
            assert!(
                touches_leaky_system_catalog(sql),
                "must be frontend-refused: {sql}"
            );
        }
    }

    #[test]
    fn a_user_table_anywhere_disqualifies_the_whole_statement() {
        for sql in [
            "SELECT c.email FROM demo.customers c JOIN pg_catalog.pg_class k ON true",
            "SELECT relname FROM pg_catalog.pg_class WHERE relname IN (SELECT email FROM demo.customers)",
            "SELECT (SELECT email FROM demo.customers LIMIT 1) FROM pg_catalog.pg_class",
            // `pg_query::nodes()` does not enter LIMIT / window frames.
            "SELECT relname FROM pg_catalog.pg_class LIMIT (SELECT email FROM demo.customers)",
            "SELECT relname, count(*) OVER (PARTITION BY (SELECT email FROM demo.customers LIMIT 1)) FROM pg_catalog.pg_class",
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
        assert!(!every_relation_is_qualified(
            "SELECT 1 FROM pg_catalog.pg_class LIMIT (SELECT 1 FROM t)"
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
            "SELECT schema_to_xml('demo', false, true, '') FROM pg_catalog.pg_class",
            "SELECT database_to_xml(false, true, '') FROM pg_catalog.pg_class",
            "SELECT pg_read_file('/etc/passwd') FROM pg_catalog.pg_class",
            "SELECT dblink('', 'SELECT email FROM demo.customers') FROM pg_catalog.pg_class",
            "SELECT pg_stat_get_activity(NULL) FROM pg_catalog.pg_class",
            "SELECT pg_ls_logdir() FROM pg_catalog.pg_class",
            "SELECT pg_logical_slot_get_changes('s', NULL, NULL) FROM pg_catalog.pg_class",
            "SELECT pg_stat_get_wal_receiver() FROM pg_catalog.pg_class",
            "SELECT crosstab('SELECT email FROM demo.customers') FROM pg_catalog.pg_class",
            "SELECT dblink_exec('dbname=x', 'SELECT 1') FROM pg_catalog.pg_class",
            "SELECT pg_file_read('postgresql.conf', 0, 100) FROM pg_catalog.pg_class",
            "SELECT loread(1, 100) FROM pg_catalog.pg_class",
            "SELECT pg_get_wal_records_info('0/0', '0/0') FROM pg_catalog.pg_class",
        ] {
            assert!(
                !reads_only_server_metadata(sql),
                "must not be released: {sql}"
            );
        }
    }

    #[test]
    fn unnamed_target_list_functions_are_not_metadata_only() {
        // Denylist polarity: `SELECT f() FROM pg_class` skipped untrusted for
        // every f not on CATALOG_ESCAPE_FUNCTIONS. pageinspect, sleep, GUC
        // writes, and any future dump were the unnamed remainder.
        for sql in [
            "SELECT get_raw_page('demo.customers'::regclass, 0) FROM pg_catalog.pg_class",
            "SELECT pg_catalog.get_raw_page('demo.customers'::regclass, 0) FROM pg_catalog.pg_class",
            r#"SELECT u&"get_raw_page"('demo.customers'::regclass, 0) FROM pg_catalog.pg_class"#,
            "SELECT heap_page_items(get_raw_page('demo.customers'::regclass, 0)) FROM pg_catalog.pg_class",
            "SELECT pg_sleep(0) FROM pg_catalog.pg_class",
            "SELECT set_config('application_name', 'x', false) FROM pg_catalog.pg_class",
            "SELECT pg_file_write('x', 'y', false) FROM pg_catalog.pg_class",
            "SELECT pg_terminate_backend(pg_backend_pid()) FROM pg_catalog.pg_class",
            "SELECT not_a_catalog_fn() FROM pg_catalog.pg_class",
            "SELECT demo.sleep_if(true) FROM pg_catalog.pg_class",
        ] {
            assert!(
                !reads_only_server_metadata(sql),
                "must not be released: {sql}"
            );
            assert!(
                calls_untrusted_function(sql),
                "must hit untrusted after losing the fast path: {sql}"
            );
        }
        // Catalog-browser helpers and trusted names keep the fast path.
        for sql in [
            "SELECT pg_catalog.format_type(a.atttypid, a.atttypmod) \
             FROM pg_catalog.pg_attribute a",
            "SELECT pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c",
            "SELECT pg_get_viewdef(c.oid) FROM pg_catalog.pg_class c",
            "SELECT count(*) FROM pg_catalog.pg_class",
            "SELECT pg_relation_size(c.oid) FROM pg_catalog.pg_class c",
        ] {
            assert!(reads_only_server_metadata(sql), "should be released: {sql}");
            assert!(
                !calls_untrusted_function(sql),
                "metadata-only skips untrusted: {sql}"
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
            assert_eq!(
                analyze(sql, 1, ALLOW_NONE),
                vec![Safety::Releasable],
                "{sql}"
            );
        }
        // A formatted size is still released under the default posture. It is
        // a pure scalar now rather than a size function, so it sits behind the
        // summaries gate and the strict posture refuses it — which is what the
        // strict posture is for.
        assert_eq!(
            analyze(
                "SELECT pg_size_pretty(pg_table_size('demo.customers'))",
                1,
                ALLOW_ALL
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
            assert_eq!(analyze(sql, 1, ALLOW_ALL), vec![Safety::Unknown], "{sql}");
        }
        // The neighbouring trap stays shut: these return an actual member.
        for sql in [
            "SELECT max(email) FROM demo.customers",
            "SELECT pg_read_file('/etc/passwd')",
        ] {
            assert_eq!(analyze(sql, 1, ALLOW_ALL), vec![Safety::Unknown], "{sql}");
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
    /// Everything the session can open, for tests about the shape rules.
    const ALLOW_ALL: Relaxations = Relaxations {
        summaries: true,
        fine_date_trunc: true,
    };
    /// Nothing opened: what a masked column in the statement produces.
    const ALLOW_NONE: Relaxations = Relaxations {
        summaries: false,
        fine_date_trunc: false,
    };

    fn safety(sql: &str, fields: usize) -> Vec<Safety> {
        analyze(sql, fields, ALLOW_ALL)
    }

    /// The stricter posture, for the cases that must hold either way.
    fn strict(sql: &str, fields: usize) -> Vec<Safety> {
        analyze(sql, fields, ALLOW_NONE)
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

    /// A summary over a singleton group is the value it summarised, so the
    /// grouping has to be read — or admitted to be unreadable.
    #[test]
    fn group_by_columns_reads_the_clause_or_admits_it_cannot() {
        let cols = |sql: &str| StatementInspection::new(sql).group_by_columns();
        assert_eq!(cols("SELECT sum(x) FROM t"), Some(vec![]));
        assert_eq!(
            cols("SELECT id, sum(x) FROM t GROUP BY id"),
            Some(vec!["id".to_string()])
        );
        assert_eq!(
            cols("SELECT sum(x) FROM t GROUP BY t.id, city"),
            Some(vec!["id".to_string(), "city".to_string()])
        );
        // The wrapper the analysis unwraps. `analyze_inspected` classifies the
        // *subquery's* targets for `SELECT * FROM (…)`, so the grouping has to
        // come from there too. Reading the outer clause reported "no grouping"
        // and served every salary in the table:
        //
        //   SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers
        //                  GROUP BY id) q
        //
        // Confirmed against a live server before the fix and after it.
        assert_eq!(
            cols("SELECT * FROM (SELECT id, sum(x) FROM t GROUP BY id) q"),
            Some(vec!["id".to_string()])
        );
        assert_eq!(
            cols("SELECT * FROM (SELECT * FROM (SELECT id, sum(x) FROM t GROUP BY id) a) b"),
            Some(vec!["id".to_string()])
        );
        // A wrapper over an ungrouped aggregate is still ungrouped.
        assert_eq!(
            cols("SELECT * FROM (SELECT sum(x) FROM t) q"),
            Some(Vec::new())
        );

        // A grouping that cannot be reduced to names must read as unknown, so
        // the caller refuses rather than assuming it is not a singleton.
        // An ordinal names a target-list entry, and `GROUP BY 1` is idiomatic
        // enough that refusing it costs real queries. Reading it also keeps the
        // guard honest: it is the same attack written differently.
        assert_eq!(
            cols("SELECT id, sum(x) FROM t GROUP BY 1"),
            Some(vec!["id".to_string()])
        );
        assert_eq!(
            cols("SELECT city, id, sum(x) FROM t GROUP BY 2, 1"),
            Some(vec!["id".to_string(), "city".to_string()])
        );

        // Grouping sets union their names, because each set is a subset of the
        // union — a key inside any one of them is inside the union.
        assert_eq!(
            cols("SELECT sum(x) FROM t GROUP BY GROUPING SETS ((a),(b))"),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(
            cols("SELECT city, sum(x) FROM t GROUP BY ROLLUP(city)"),
            Some(vec!["city".to_string()])
        );
        assert_eq!(
            cols("SELECT sum(x) FROM t GROUP BY CUBE(b, c)"),
            Some(vec!["b".to_string(), "c".to_string()])
        );
        assert_eq!(
            cols("SELECT sum(x) FROM t GROUP BY GROUPING SETS ((a, b), (c))"),
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
        // A grouping construct nested in another is *not* readable: the raw
        // parse tree renders the inner `CUBE` as an ordinary `FuncCall`, and
        // only the outermost construct becomes a `GroupingSet`.
        assert_eq!(
            cols("SELECT sum(x) FROM t GROUP BY ROLLUP(a, CUBE(b, c))"),
            None
        );
        // `GROUP BY ()` collapses the relation to one row and distinguishes by
        // nothing, so it contributes no names.
        assert_eq!(
            cols("SELECT sum(x) FROM t GROUP BY GROUPING SETS ((a),())"),
            Some(vec!["a".to_string()])
        );

        // Still unreadable, and still refused by the caller: an expression, and
        // an ordinal pointing at one.
        assert_eq!(cols("SELECT sum(x) FROM t GROUP BY lower(a)"), None);
        assert_eq!(cols("SELECT lower(a), sum(x) FROM t GROUP BY 1"), None);
        assert_eq!(
            cols("SELECT id, sum(x) FROM t GROUP BY ROLLUP(lower(a))"),
            None
        );
        // An ordinal off the end of the target list is not a name either.
        assert_eq!(cols("SELECT id, sum(x) FROM t GROUP BY 9"), None);

        // A star shifts every position after it by an amount not visible in the
        // target list, so an ordinal stops naming the entry it indexes. Here
        // `GROUP BY 2` is `id` if `z` expands to nothing, while `target_list[1]`
        // is `city` — reading it would report a non-key for a grouping that is
        // one. Refused instead, and independently of the star check in
        // `positions_are_trustworthy` that happens to refuse the whole
        // statement first.
        assert_eq!(
            cols("SELECT z.*, city, id, sum(x) FROM z, t GROUP BY 2"),
            None
        );
        assert_eq!(cols("SELECT *, sum(x) FROM t GROUP BY 1"), None);
        // An output alias denotes whatever its target computes, so both names
        // are collected. Reading only the alias released every salary through
        // `SELECT id AS c, sum(salary) … GROUP BY c`.
        assert_eq!(
            cols("SELECT id AS c, sum(x) FROM t GROUP BY c"),
            Some(vec!["c".to_string(), "id".to_string()])
        );
        // An alias onto an expression is as unreadable as the expression, and
        // falls to the caller's lexical backstop rather than to a name.
        assert_eq!(
            cols("SELECT date_trunc('month', ts) AS m, sum(x) FROM t GROUP BY m"),
            None
        );
        // A qualified name is never an output alias, so no lookup happens.
        assert_eq!(
            cols("SELECT id AS c, sum(x) FROM t GROUP BY t.c"),
            Some(vec!["c".to_string()])
        );
        // Self-referential alias: bounded because the lookup only runs at the
        // top of an item.
        assert_eq!(
            cols("SELECT c AS c, sum(x) FROM t GROUP BY c"),
            Some(vec!["c".to_string(), "c".to_string()])
        );
        // A grouping set nests grouping elements, and Postgres resolves an
        // output alias in each of them — verified against a live server, which
        // served `GROUP BY ROLLUP(c)` as a grouping by `id`. Reading only `c`
        // here was a second copy of the same disclosure.
        assert_eq!(
            cols("SELECT id AS c, sum(x) FROM t GROUP BY ROLLUP(c)"),
            Some(vec!["c".to_string(), "id".to_string()])
        );
        assert_eq!(
            cols("SELECT id AS c, sum(x) FROM t GROUP BY GROUPING SETS ((c))"),
            Some(vec!["c".to_string(), "id".to_string()])
        );
        // An ordinal lands in an expression, where Postgres does *not* resolve
        // an alias, so the target is read for what it computes and no lookup
        // runs. `GROUP BY 1` here is `id` either way.
        assert_eq!(
            cols("SELECT id AS c, sum(x) FROM t GROUP BY 1"),
            Some(vec!["id".to_string()])
        );

        // A star does not make a *named* grouping unreadable — only an ordinal
        // depends on the positions.
        assert_eq!(
            cols("SELECT z.*, sum(x) FROM z, t GROUP BY id"),
            Some(vec!["id".to_string()])
        );
    }

    /// The library's traversal as a lower bound on ours.
    ///
    /// `pg_query::ParseResult::nodes()` is generated from the protobuf schema,
    /// so where it *does* descend it is authoritative. It is not complete —
    /// measured misses are tabulated on `grouping_may_reference` — which is why
    /// it cannot replace the hand-written walker. It makes a good oracle in one
    /// direction all the same: any column the library finds under a grouping
    /// that our walker does not is a hole in ours, and a hole here releases a
    /// value.
    ///
    /// Our walker may legitimately return `None` (unbounded, so refuse) or a
    /// *superset*; it may never return less.
    #[test]
    fn library_traversal_finds_no_column_this_misses() {
        use pg_query::protobuf::{ParseResult as PbResult, RawStmt, ResTarget};
        use pg_query::NodeRef;

        let library_columns = |select: &SelectStmt, version: i32| {
            let targets: Vec<pg_query::protobuf::Node> = select
                .group_clause
                .iter()
                .map(|item| pg_query::protobuf::Node {
                    node: Some(NodeEnum::ResTarget(Box::new(ResTarget {
                        name: String::new(),
                        indirection: vec![],
                        val: Some(Box::new(item.clone())),
                        location: -1,
                    }))),
                })
                .collect();
            let synthetic = SelectStmt {
                target_list: targets,
                ..Default::default()
            };
            let node = pg_query::protobuf::Node {
                node: Some(NodeEnum::SelectStmt(Box::new(synthetic))),
            };
            // `nodes()` is pure Rust. `deparse()` on a synthetic tree is not —
            // it aborts the process from C on an invalid enum discriminant.
            let result = PbResult {
                version,
                stmts: vec![RawStmt {
                    stmt: Some(Box::new(node)),
                    stmt_location: 0,
                    stmt_len: 0,
                }],
            };
            let mut found = Vec::new();
            for (node, _, _, _) in result.nodes() {
                if let NodeRef::ColumnRef(column) = node {
                    for field in &column.fields {
                        if let Some(NodeEnum::String(s)) = &field.node {
                            found.push(s.sval.to_ascii_lowercase());
                        }
                    }
                }
            }
            found
        };

        for sql in [
            "SELECT sum(v) FROM t GROUP BY coalesce(a, 0)",
            "SELECT sum(v) FROM t GROUP BY (a + b) * c",
            "SELECT sum(v) FROM t GROUP BY CASE WHEN p THEN q ELSE r END",
            "SELECT sum(v) FROM t GROUP BY abs(a), lower(b)",
            "SELECT sum(v) FROM t GROUP BY a::text",
            "SELECT sum(v) FROM t GROUP BY GROUPING SETS ((g1),(g2))",
            "SELECT sum(v) FROM t GROUP BY ARRAY[d1, d2]",
            "SELECT sum(v) FROM t GROUP BY (SELECT max(hidden) FROM u)",
            "SELECT a AS g, sum(v) FROM t GROUP BY g",
            "SELECT a, sum(v) FROM t GROUP BY 1",
        ] {
            let parsed = pg_query::parse(sql).expect("fixture parses");
            let statement = parsed.protobuf.stmts.first().expect("one statement");
            let Some(NodeEnum::SelectStmt(select)) =
                statement.stmt.as_ref().and_then(|s| s.node.as_ref())
            else {
                panic!("fixture is a SELECT");
            };
            let library = library_columns(select, parsed.protobuf.version);
            match grouping_may_reference(select, &select.target_list) {
                // Unbounded: refuses, so it cannot miss anything.
                None => {}
                Some(ours) => {
                    for column in library {
                        assert!(
                            ours.contains(&column),
                            "{sql}: the library found {column:?} under the grouping and \
                             grouping_may_reference did not — that is a release",
                        );
                    }
                }
            }
        }
    }

    /// Coarsening below the mask is not coarsening.
    ///
    /// `date_trunc` was released for any unit "at or above a day", and the
    /// fixture's `birth_date` is masked to its year. Measured through the
    /// proxy: `date_trunc('day', birth_date)` returned `1975-02-14`, the whole
    /// value, and `'week'` returned a seven-day window — both from a column
    /// whose plain projection is `1975-01-01`.
    ///
    /// Year and coarser are safe against any date column, because year is the
    /// coarsest date mask on offer. Finer units are safe only when the caller
    /// says the statement names nothing masked.
    #[test]
    fn date_trunc_below_the_mask_is_not_a_summary() {
        // `summaries` stays on in both: the summaries gate sits above the
        // `date_trunc` arm and would short-circuit the whole thing, which would
        // make this test pass for the wrong reason.
        const COARSE_ONLY: Relaxations = Relaxations {
            summaries: true,
            fine_date_trunc: false,
        };
        const FINE: Relaxations = Relaxations {
            summaries: true,
            fine_date_trunc: true,
        };
        let unconditional = |sql: &str| analyze(sql, 1, COARSE_ONLY);
        let permitted = |sql: &str| analyze(sql, 1, FINE);

        for unit in ["year", "decade", "century", "millennium"] {
            let sql = format!("SELECT date_trunc('{unit}', birth_date) FROM t");
            assert_eq!(unconditional(&sql), vec![Safety::Releasable], "{sql}");
        }
        for unit in ["day", "week", "month", "quarter"] {
            let sql = format!("SELECT date_trunc('{unit}', birth_date) FROM t");
            assert_eq!(unconditional(&sql), vec![Safety::Unknown], "{sql}");
            assert_eq!(permitted(&sql), vec![Safety::Releasable], "{sql}");
        }
        // Finer than a day was already refused and stays refused either way.
        for unit in ["microseconds", "second", "hour"] {
            let sql = format!("SELECT date_trunc('{unit}', birth_date) FROM t");
            assert_eq!(permitted(&sql), vec![Safety::Unknown], "{sql}");
        }
        // A computed precision is not a literal and cannot be checked.
        assert_eq!(
            permitted("SELECT date_trunc(u, birth_date) FROM t"),
            vec![Safety::Unknown]
        );
    }

    /// The functions a whole rule rests on, asserted directly.
    ///
    /// `cargo mutants` can replace a function body with a constant and see
    /// whether anything notices. These three survived that, which means the
    /// rules built on them were pinned only end-to-end — by
    /// `scripts/test-fuzz.sh`, which `cargo test` does not run. A `cargo test`
    /// that passes while `aggregate_argument_is_grouped` always returns false
    /// is a suite that would not notice the summary-of-a-grouped-column
    /// disclosure coming back.
    #[test]
    fn the_predicates_whole_rules_rest_on() {
        // `aggregate_argument_is_grouped` decides whether a summary is really
        // the value it summarised. Replacing it with `false` reopens the 0.1.19
        // disclosure; deleting its name-reading arm does the same more quietly.
        let call_in = |sql: &str| {
            let parsed = pg_query::parse(sql).expect("fixture parses");
            let statement = parsed.protobuf.stmts.first().expect("one statement");
            let Some(NodeEnum::SelectStmt(select)) =
                statement.stmt.as_ref().and_then(|s| s.node.as_ref())
            else {
                panic!("fixture is a SELECT");
            };
            for entry in &select.target_list {
                let Some(NodeEnum::ResTarget(target)) = entry.node.as_ref() else {
                    continue;
                };
                if let Some(NodeEnum::FuncCall(call)) =
                    target.val.as_ref().and_then(|v| v.node.as_ref())
                {
                    return call.clone();
                }
            }
            panic!("fixture has no function call: {sql}");
        };

        let grouped_on_salary = ["annual_salary".to_string()];
        let grouped_on_city = ["city".to_string()];
        assert!(aggregate_argument_is_grouped(
            &call_in("SELECT sum(annual_salary) FROM t"),
            Some(&grouped_on_salary)
        ));
        assert!(!aggregate_argument_is_grouped(
            &call_in("SELECT sum(annual_salary) FROM t"),
            Some(&grouped_on_city)
        ));
        // No grouping decides nothing; an unbounded grouping refuses.
        assert!(!aggregate_argument_is_grouped(
            &call_in("SELECT sum(annual_salary) FROM t"),
            Some(&[])
        ));
        assert!(aggregate_argument_is_grouped(
            &call_in("SELECT sum(annual_salary) FROM t"),
            None
        ));

        // `is_parseable` is how a caller distinguishes "this says nothing" from
        // "this is nonsense we cannot read". Constant in either direction is
        // wrong: `true` trusts gibberish, `false` refuses everything.
        assert!(is_parseable("SELECT 1"));
        assert!(!is_parseable("SELEKT ¯\\_(ツ)_/¯ FROM"));

        // The lexer is the backstop under lineage, the catalog fast path and
        // the singleton-group guard. Its word test survived three mutations, so
        // pin the edges it actually has to get right.
        let ids = |sql: &str| referenced_identifiers(sql).expect("scans");
        // A quoted name keeps its spelling, minus the quotes, and an escaped
        // quote inside one survives.
        assert!(ids(r#"SELECT "Odd Name" FROM t"#).contains(&"odd name".to_string()));
        assert!(ids(r#"SELECT "a""b" FROM t"#).contains(&"a\"b".to_string()));
        // A leading digit is not a name; a leading underscore is.
        let numeric = ids("SELECT 1234 FROM t");
        assert!(!numeric.contains(&"1234".to_string()));
        assert!(ids("SELECT _x FROM t").contains(&"_x".to_string()));
        // `$` is legal inside a name but not at its start.
        assert!(ids("SELECT a$b FROM t").contains(&"a$b".to_string()));
        // And an operator is not a name, or every statement would name one.
        assert!(!ids("SELECT a + b FROM t").contains(&"+".to_string()));
    }

    /// Every node type `grouping_may_reference` claims to read, read.
    ///
    /// Deleting any arm makes it fall to `_ => None`, which the caller treats
    /// as "could reference anything" and refuses — the safe direction, so no
    /// leak, and therefore nothing failed. `cargo mutants` reported fourteen
    /// such survivors in this one function: every arm was precision-only and
    /// none was pinned.
    ///
    /// Precision is the whole point of the arms. Without them a grouping like
    /// `date_trunc('month', ts)` is unbounded, the aggregate over it is
    /// refused, and ordinary time bucketing stops working — which is exactly
    /// the regression 0.1.23 was fixed to avoid.
    #[test]
    fn every_grouping_node_this_claims_to_read_is_read() {
        let bounded = |sql: &str| -> Option<Vec<String>> {
            let parsed = pg_query::parse(sql).expect("fixture parses");
            let statement = parsed.protobuf.stmts.first().expect("one statement");
            let Some(NodeEnum::SelectStmt(select)) =
                statement.stmt.as_ref().and_then(|s| s.node.as_ref())
            else {
                panic!("fixture is a SELECT");
            };
            grouping_may_reference(select, &select.target_list)
        };

        // (label, statement, a column the grouping must be seen to reference)
        let cases = [
            (
                "column reference",
                "SELECT sum(v) FROM t GROUP BY gcol",
                "gcol",
            ),
            ("ordinal", "SELECT gcol, sum(v) FROM t GROUP BY 1", "gcol"),
            ("cast", "SELECT sum(v) FROM t GROUP BY gcol::text", "gcol"),
            (
                "collate",
                "SELECT sum(v) FROM t GROUP BY gcol COLLATE \"C\"",
                "gcol",
            ),
            (
                "arithmetic",
                "SELECT sum(v) FROM t GROUP BY gcol + 1",
                "gcol",
            ),
            (
                "boolean",
                "SELECT sum(v) FROM t GROUP BY (gcol AND other)",
                "gcol",
            ),
            (
                "coalesce",
                "SELECT sum(v) FROM t GROUP BY coalesce(gcol, 0)",
                "gcol",
            ),
            (
                "greatest/least",
                "SELECT sum(v) FROM t GROUP BY greatest(gcol, 0)",
                "gcol",
            ),
            (
                "null test",
                "SELECT sum(v) FROM t GROUP BY (gcol IS NULL)",
                "gcol",
            ),
            (
                "boolean test",
                "SELECT sum(v) FROM t GROUP BY (gcol IS TRUE)",
                "gcol",
            ),
            (
                "function call",
                "SELECT sum(v) FROM t GROUP BY lower(gcol)",
                "gcol",
            ),
            (
                "case expression",
                "SELECT sum(v) FROM t GROUP BY CASE WHEN p THEN gcol ELSE q END",
                "gcol",
            ),
            (
                "grouping set",
                "SELECT sum(v) FROM t GROUP BY GROUPING SETS ((gcol))",
                "gcol",
            ),
            (
                "row expression",
                "SELECT sum(v) FROM t GROUP BY GROUPING SETS ((gcol, other))",
                "gcol",
            ),
            (
                "output alias",
                "SELECT gcol AS g, sum(v) FROM t GROUP BY g",
                "gcol",
            ),
        ];

        for (label, sql, expected) in cases {
            let found = bounded(sql).unwrap_or_else(|| {
                panic!("{label}: grouping reported unbounded, so the aggregate is refused: {sql}")
            });
            assert!(
                found.iter().any(|c| c == expected),
                "{label}: {found:?} does not mention {expected:?} — {sql}",
            );
        }

        // And the converse still holds: a node this does not model is
        // unbounded, which is what makes the walk sound.
        assert_eq!(bounded("SELECT sum(v) FROM t GROUP BY ARRAY[a, b]"), None);
        assert_eq!(
            bounded("SELECT sum(v) FROM t GROUP BY (SELECT max(h) FROM u)"),
            None
        );
    }

    /// Found by `cargo mutants`, not by review: two guards no test detected
    /// being broken. The code was right; nothing said so.
    ///
    /// Mechanical mutation is worth more than the hand-picked table in
    /// `scripts/test-mutations.py` here, because the table only contains guards
    /// someone already thought to protect — the same blind spot as an inference
    /// suite that only knows the spellings it was given.
    #[test]
    fn guards_that_no_test_was_watching() {
        const FINE: Relaxations = Relaxations {
            summaries: true,
            fine_date_trunc: true,
        };
        let safety = |sql: &str, n: usize| analyze(sql, n, FINE);

        // `bare` is `args.is_empty() && agg_filter.is_none() && over.is_none()`,
        // and flipping either `&&` to `||` survived. It matters: a context
        // function is released *because* it takes nothing, and `CREATE
        // FUNCTION` is available to ordinary users, so `public.now(text)`
        // returning its argument is a real shape. With the guard broken,
        // `now(email)` releases the email.
        assert_eq!(safety("SELECT now(email) FROM t", 1), vec![Safety::Unknown]);
        assert_eq!(
            safety("SELECT current_user(email) FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT version(email) FROM t", 1),
            vec![Safety::Unknown]
        );
        // The releasable form still is.
        assert_eq!(safety("SELECT now()", 1), vec![Safety::Releasable]);
        assert_eq!(safety("SELECT version()", 1), vec![Safety::Releasable]);

        // `COALESCE` releases only when *every* argument does. Flipping the
        // `==` to `!=` survived, and it inverts the rule: two unreadable
        // arguments would have been released together.
        assert_eq!(
            safety("SELECT COALESCE(email, phone) FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(
            safety("SELECT COALESCE(email, '') FROM t", 1),
            vec![Safety::Unknown]
        );
        assert_eq!(safety("SELECT COALESCE(1, 2)", 1), vec![Safety::Releasable]);

        // `unwrap_star_over_subquery`'s early return was the third survivor and
        // is *not* pinned here, because it turned out to be an equivalent
        // mutant: the two conditions it checks are re-enforced by slice
        // patterns further down the same function, so flipping it changes
        // nothing observable. Asserting a shape that happens to be refused
        // anyway would have looked like coverage and provided none — see the
        // note on the function itself.
        //
        // The shape it exists for still unwraps, which is worth holding.
        assert_eq!(
            safety("SELECT * FROM (SELECT 1 AS a) q", 1),
            vec![Safety::Releasable]
        );
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

    #[test]
    fn hostile_projection_gate_closes_the_inference_routes() {
        let masked: HashSet<String> = ["email", "annual_salary"]
            .into_iter()
            .map(str::to_string)
            .collect();
        // Allowed: bare projection, filter on a released key.
        assert!(!masked_exceeds_outer_projection(
            "SELECT email, id FROM demo.customers WHERE id = 1",
            &masked
        ));
        // Predicate oracle.
        assert!(masked_exceeds_outer_projection(
            "SELECT id FROM demo.customers WHERE email LIKE 'u%'",
            &masked
        ));
        // ORDER BY ranking.
        assert!(!masked_exceeds_outer_projection(
            "SELECT id FROM demo.customers ORDER BY email",
            &masked
        ));
        // Single-row aggregate.
        assert!(masked_exceeds_outer_projection(
            "SELECT sum(annual_salary) FROM demo.customers WHERE id = 1",
            &masked
        ));
        // Error-channel CASE over a subquery that projects email.
        assert!(masked_exceeds_outer_projection(
            "SELECT 1/(CASE WHEN (SELECT email FROM demo.customers WHERE id=1) LIKE 'u%' \
             THEN 0 ELSE 1 END)",
            &masked
        ));
        // TypeName.typmods: CAST numeric(p,s) hid a subquery membership oracle.
        assert!(masked_exceeds_outer_projection(
            r#"SELECT CAST(1 AS numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
            &masked
        ));
        // JSON RETURNING uses JsonOutput.type_name, not TypeCast.
        assert!(masked_exceeds_outer_projection(
            r#"SELECT JSON_VALUE('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT JSON_QUERY('1', '$' RETURNING numeric((SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'), 0))"#,
            &masked
        ));
        // Cleartext ORDER BY is accepted — values stay masked on the wire.
        assert!(!masked_exceeds_outer_projection(
            "SELECT email FROM demo.customers ORDER BY 1",
            &masked
        ));
        assert!(!masked_exceeds_outer_projection(
            "SELECT email AS e FROM demo.customers ORDER BY e",
            &masked
        ));
        // EXPLAIN of an allowed SELECT is the same residual (analyst debugging).
        assert!(!masked_exceeds_outer_projection(
            "EXPLAIN SELECT email, id FROM demo.customers WHERE id = 1",
            &masked
        ));
        assert!(!masked_exceeds_outer_projection(
            "EXPLAIN SELECT id FROM demo.customers ORDER BY email",
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            "EXPLAIN SELECT count(*) FROM demo.customers WHERE email = 'x'",
            &masked
        ));
        // ORDER BY with a predicate is a membership oracle — not credited.
        assert!(masked_exceeds_outer_projection(
            "SELECT id FROM demo.customers ORDER BY email = 'user1@example.com' DESC",
            &masked
        ));
        // Unicode-escaped identifiers decode on ColumnRef; lexical scan misses them.
        assert!(masked_exceeds_outer_projection(
            r#"SELECT id FROM demo.customers WHERE u&"email" = 'user1@example.com'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers WHERE u&"e\006dail" LIKE 'u%'"#,
            &masked
        ));
        // Equality on the masked column itself.
        assert!(masked_exceeds_outer_projection(
            "SELECT email FROM demo.customers WHERE email = 'user1@example.com'",
            &masked
        ));
    }

    #[test]
    fn hostile_closes_whole_row_cleartext_oracles() {
        use std::collections::HashMap;
        let mut relations = HashMap::new();
        relations.insert(
            "demo.customers".into(),
            vec!["id".into(), "email".into(), "name".into(), "city".into()],
        );
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers t WHERE t::text LIKE '%u%'",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers t WHERE format('%s', t) LIKE '%u%'",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers WHERE customers::text LIKE '%u%'",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT id FROM demo.customers t ORDER BY t::text",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers a JOIN demo.customers b ON a::text = b::text",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FILTER (WHERE t::text LIKE '%u%') FROM demo.customers t",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers t WHERE t::text COLLATE \"C\" LIKE '%u%'",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM (SELECT * FROM demo.customers) t WHERE t::text LIKE '%u%'",
            &relations
        ));
        assert!(!hostile_uses_whole_row(
            "SELECT email, id FROM demo.customers WHERE id = 1",
            &relations
        ));
        assert!(!hostile_uses_whole_row(
            "SELECT id FROM demo.customers t WHERE t.id = 1",
            &relations
        ));
        assert!(!hostile_uses_whole_row(
            "SELECT email FROM demo.customers email WHERE id = 1",
            &relations
        ));
    }

    #[test]
    fn hostile_closes_join_rename_and_window_oracles() {
        use std::collections::HashMap;
        let masked: HashSet<String> = ["email", "name"].into_iter().map(str::to_string).collect();
        let mut relations = HashMap::new();
        relations.insert(
            "demo.customers".into(),
            vec![
                "id".into(),
                "email".into(),
                "name".into(),
                "phone".into(),
                "city".into(),
                "birth_date".into(),
                "annual_salary".into(),
                "last_ip".into(),
                "account_uuid".into(),
                "internal_note".into(),
                "lookup_key".into(),
            ],
        );
        assert!(hostile_join_or_rename_masked(
            "SELECT count(*) FROM demo.customers AS t(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) \
             WHERE c2 = 'user1@example.com'",
            &relations,
            &masked
        ));
        assert!(hostile_join_or_rename_masked(
            "SELECT count(*) FROM demo.customers a NATURAL JOIN demo.customers b",
            &relations,
            &masked
        ));
        assert!(hostile_join_or_rename_masked(
            r#"SELECT count(*) FROM demo.customers NATURAL JOIN (VALUES ('x')) v(u&"email")"#,
            &relations,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers a
               JOIN (VALUES ('x')) v(u&"email") USING (u&"email")"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT id, count(*) OVER (PARTITION BY u&"email" = 'x')
               FROM demo.customers"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"WITH q(u&"email") AS (SELECT 'x')
               SELECT count(*) FROM demo.customers NATURAL JOIN q"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               GROUP BY GROUPING SETS ((u&"email"))"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers GROUP BY ROLLUP (u&"email")"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               WHERE 'x' = ANY(ARRAY[u&"email"])"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               WHERE CASE u&"email" WHEN 'x' THEN true ELSE false END"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT id FROM demo.customers
               LIMIT (SELECT count(*) FROM demo.customers WHERE u&"email" = 'x')"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers t WHERE (t).u&"email" = 'x'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers WHERE (ARRAY[u&"email"])[1] = 'x'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers WHERE xmlforest(u&"email") IS NOT NULL"#,
            &masked
        ));
        // JOIN … ON, BooleanTest, JSON constructors, xmlserialize — previously live OPEN.
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers a
               JOIN (VALUES (1)) v(x) ON a.u&"email" = 'user1@example.com'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               WHERE (u&"email" = 'user1@example.com') IS TRUE"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               WHERE JSON_OBJECT('e': u&"email")->>'e' = 'user1@example.com'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               WHERE JSON_ARRAY(u&"email")->>0 = 'user1@example.com'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               WHERE xmlserialize(CONTENT xmlforest(u&"email" AS e) AS text)
                     LIKE '%user1@example.com%'"#,
            &masked
        ));
        // Aggregate ORDER BY / WITHIN GROUP, window frame offsets, JSON_VALUE,
        // JSON_TABLE, PREPARE/DECLARE — previously live OPEN.
        assert!(masked_exceeds_outer_projection(
            r#"SELECT string_agg(city, ',' ORDER BY u&"email" = 'x') FROM demo.customers"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT mode() WITHIN GROUP (ORDER BY u&"email") FROM demo.customers"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT id, count(*) OVER (PARTITION BY id ORDER BY id ROWS BETWEEN
               (SELECT count(*) FROM demo.customers t2 WHERE t2.u&"email" = 'x')
               PRECEDING AND CURRENT ROW) FROM demo.customers"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers
               WHERE JSON_VALUE(JSON_OBJECT('e': u&"email"), '$.e') = 'x'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT jt.* FROM demo.customers,
               JSON_TABLE(json_build_object('e', u&"email"), '$'
                 COLUMNS (e text PATH '$.e')) jt"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"PREPARE q AS SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"DECLARE c CURSOR FOR SELECT count(*) FROM demo.customers WHERE u&"email" = 'x'"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"WITH RECURSIVE r AS (SELECT * FROM demo.customers)
               SEARCH DEPTH FIRST BY u&"email" SET ord SELECT count(*) FROM r"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"WITH RECURSIVE r AS (SELECT * FROM demo.customers)
               CYCLE u&"email" SET is_cycle USING path SELECT count(*) FROM r"#,
            &masked
        ));
        assert!(hostile_uses_whole_row(
            "SELECT json_arrayagg(t) FROM demo.customers t",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT json_objectagg('k': t) FROM demo.customers t",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers t WHERE JSON_SERIALIZE(t) LIKE '%x%'",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers t WHERE t IS JSON",
            &relations
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT count(*) FROM demo.customers,
               XMLTABLE('/e' PASSING '<e>x</e>'
                 COLUMNS x text PATH '.' DEFAULT u&"email")"#,
            &masked
        ));
        assert!(masked_exceeds_outer_projection(
            r#"SELECT json_arrayagg(city) OVER (PARTITION BY u&"email") FROM demo.customers"#,
            &masked
        ));
        assert!(hostile_join_or_rename_masked(
            "SELECT count(*) FROM (SELECT * FROM demo.customers) AS t(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) WHERE c2 = 'x'",
            &relations,
            &masked
        ));
        assert!(hostile_join_or_rename_masked(
            "WITH q(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) AS (SELECT * FROM demo.customers) \
             SELECT count(*) FROM q WHERE c2 = 'x'",
            &relations,
            &masked
        ));
        assert!(hostile_join_or_rename_masked(
            r#"PREPARE q AS SELECT count(*) FROM demo.customers a NATURAL JOIN demo.customers b"#,
            &relations,
            &masked
        ));
        assert!(hostile_join_or_rename_masked(
            r#"PREPARE q AS SELECT count(*) FROM demo.customers AS t(c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11) WHERE c2 = 'x'"#,
            &relations,
            &masked
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers t WHERE (ARRAY[t::text])[1] LIKE '%x%'",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT count(*) FROM demo.customers t WHERE JSON_OBJECT('r': t)::text LIKE '%x%'",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT id FROM demo.customers t LIMIT (SELECT count(*) FROM demo.customers t2 WHERE t2::text LIKE '%@%')",
            &relations
        ));
        assert!(hostile_uses_whole_row(
            "SELECT string_agg(city, ',' ORDER BY t::text) FROM demo.customers t",
            &relations
        ));
        assert!(!masked_exceeds_outer_projection(
            r#"SELECT id FROM demo.customers ORDER BY u&"email" USING <"#,
            &masked
        ));
        assert!(!hostile_join_or_rename_masked(
            "SELECT email, id FROM demo.customers WHERE id = 1",
            &relations,
            &masked
        ));
    }

    #[test]
    fn procedural_statements_are_recognised() {
        assert!(is_procedural_statement(
            "DO $$ BEGIN RAISE NOTICE 'x'; END $$"
        ));
        assert!(is_procedural_statement("CALL demo.do_thing()"));
        assert!(is_procedural_statement(
            "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql"
        ));
        assert!(is_procedural_statement(
            "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ BEGIN END $$"
        ));
        assert!(is_procedural_statement(
            "SELECT 1; DO $$ BEGIN NULL; END $$"
        ));
        assert!(!is_procedural_statement(
            "SELECT email, id FROM demo.customers WHERE id = 1"
        ));
        assert!(!is_procedural_statement("SELECT now()"));
    }

    #[test]
    fn write_statements_are_recognised() {
        for sql in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x = 1",
            "DELETE FROM t WHERE id = 1",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
            "TRUNCATE t",
            "CREATE TABLE t (id int)",
            "DROP TABLE t",
            "ALTER TABLE t ADD COLUMN x int",
            "CREATE INDEX ON t (id)",
            "GRANT SELECT ON t TO u",
            "SELECT * INTO t FROM s",
            "CREATE TABLE t AS SELECT 1",
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
            "COPY t FROM STDIN",
            "COPY t TO STDOUT",
            "DO $$ BEGIN NULL; END $$",
            "CALL foo()",
            "NOTIFY x",
            "VACUUM t",
            "SELECT email FROM t FOR UPDATE",
            "SELECT email FROM t FOR SHARE",
            "CREATE VIEW v AS SELECT email FROM t",
            "CREATE OR REPLACE VIEW v AS SELECT 1",
            "LOAD 'auto_explain'",
            "CHECKPOINT",
            "LOCK TABLE t",
            "COMMENT ON TABLE t IS 'x'",
            "CREATE STATISTICS s ON a FROM t",
            "IMPORT FOREIGN SCHEMA s FROM SERVER x INTO public",
            "EXPLAIN INSERT INTO t VALUES (1)",
            "EXPLAIN (ANALYZE true) INSERT INTO t VALUES (1)",
        ] {
            assert!(is_write_statement(sql), "expected write: {sql}");
        }
        for sql in [
            "SELECT email, id FROM demo.customers WHERE id = 1",
            "SELECT 1",
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "EXPLAIN SELECT 1",
            "SHOW search_path",
            "SET search_path TO public",
            "PREPARE q AS SELECT 1",
            "EXECUTE q",
            "DEALLOCATE q",
            "DECLARE c CURSOR FOR SELECT 1",
            "FETCH ALL FROM c",
            "MOVE FORWARD 1 FROM c",
            "CLOSE c",
            "SELECT 1 FETCH FIRST 1 ROW ONLY",
            "DISCARD ALL",
            "RESET ALL",
        ] {
            assert!(!is_write_statement(sql), "expected read: {sql}");
        }
    }

    #[test]
    fn sql_prepare_and_cursor_statements_are_recognised() {
        for sql in [
            "PREPARE q AS SELECT 1",
            "PREPARE q AS SELECT count(*) FROM demo.customers WHERE email = 'x'",
            "EXECUTE q",
            "EXECUTE q(1)",
            "DEALLOCATE q",
            "DEALLOCATE ALL",
            "DECLARE c CURSOR FOR SELECT 1",
            "DECLARE c CURSOR WITH HOLD FOR SELECT email FROM demo.customers",
            "FETCH ALL FROM c",
            "FETCH FORWARD 10 FROM c",
            "MOVE FORWARD 1 FROM c",
            "CLOSE c",
            "CLOSE ALL",
        ] {
            assert!(
                is_sql_prepare_or_cursor(sql),
                "expected SQL PREPARE/cursor: {sql}"
            );
        }
        for sql in [
            "SELECT 1",
            "SELECT email, id FROM demo.customers WHERE id = 1",
            "SELECT * FROM demo.customers FETCH FIRST 10 ROWS ONLY",
            "SELECT * FROM demo.customers FETCH FIRST 10 ROWS WITH TIES",
            "SELECT 1 FETCH FIRST 1 ROW ONLY",
            "BEGIN",
            "EXPLAIN SELECT 1",
            "SHOW search_path",
            "DISCARD ALL",
            "not valid sql at all",
        ] {
            assert!(
                !is_sql_prepare_or_cursor(sql),
                "must not refuse ordinary SELECT/session SQL: {sql}"
            );
        }
    }

    #[test]
    fn untrusted_functions_are_caught_before_execution() {
        assert!(calls_untrusted_function("SELECT demo.sleep_if(1, 'u')"));
        assert!(calls_untrusted_function(
            "SELECT * FROM demo.sleep_if(1, 'u') AS t"
        ));
        assert!(calls_untrusted_function(
            "SELECT id FROM t WHERE demo.email_ok(id, 'u')"
        ));
        assert!(calls_untrusted_function("SELECT pg_sleep(0.1)"));
        assert!(calls_untrusted_function(
            "PREPARE q AS SELECT pg_sleep(0.1)"
        ));
        assert!(calls_untrusted_function(
            "DECLARE c CURSOR FOR SELECT pg_sleep(0.1)"
        ));
        assert!(calls_untrusted_function("SELECT evil.sum(1)"));
        // Trusted builtins / pg_catalog.
        assert!(!calls_untrusted_function("SELECT now()"));
        assert!(!calls_untrusted_function("SELECT pg_catalog.now()"));
        assert!(!calls_untrusted_function(
            "SELECT count(*) FROM demo.customers"
        ));
        assert!(!calls_untrusted_function(
            "SELECT lower(city) FROM demo.customers"
        ));
        assert!(!calls_untrusted_function(
            "SELECT email, id FROM demo.customers WHERE id = 1"
        ));
    }
}
