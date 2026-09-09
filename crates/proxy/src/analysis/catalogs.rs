//! System catalogs that GUI clients and psql `\d` read on connect.
//!
//! GUI clients (DBeaver, DataGrip, pgAdmin) and psql's own `\d` commands read
//! `pg_catalog` on connect. Those queries are full of expressions —
//! `pg_get_userbyid(c.relowner)`, `format_type(...)`, `'pg_class'::regclass` —
//! so output classification refuses them, and the columns that *do* have
//! provenance point at catalog tables that are not in anyone's catalog file, so
//! default-deny masks them.
//!
//! Nulling is the worse half. `\d` sends a follow-up query built from the OID
//! the first one returned; masked to NULL, psql interpolates an empty string and
//! Postgres answers `invalid input syntax for type oid: ""`. Default-deny did
//! not refuse, it corrupted the client's logic.
//!
//! The rule below releases a result set when **every relation the statement
//! reads is a system catalog holding metadata rather than user data**. Nothing
//! from a user table can appear in the output of a query that reads no user
//! table, so the fields need no provenance.

use pg_query::protobuf::node::Node as NodeEnum;

use super::catalog_surface::range_var_is_leaky_catalog;
use super::names::{
    func_call_name_parts, function_name, is_trusted_function_name, CATALOG_ESCAPE_FUNCTIONS,
    CATALOG_HELPER_FUNCTIONS, GENERATORS_IN_FROM,
};
use super::walk::{tree_any, walk_parsed};
use super::StatementInspection;

/// True when the statement names a catalog that holds sampled user data,
/// other sessions' SQL, passwords, or similar — default-deny masking
/// is not enough for, because the query still runs and soft stats / empty
/// shapes remain. Refused at the frontend on every posture.
pub fn touches_leaky_system_catalog(sql: &str) -> bool {
    StatementInspection::new(sql).touches_leaky_system_catalog()
}

pub(crate) fn touches_leaky_system_catalog_inspected(inspection: &StatementInspection<'_>) -> bool {
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
/// Fails closed everywhere: an unparseable statement, a CTE reference that is
/// not declared locally, a target-list function that is not a catalog helper /
/// trusted name / FROM-generator, and any function on
/// `CATALOG_ESCAPE_FUNCTIONS` all return `false`. A statement that names no
/// relation is not a catalog query unless it is a catalog-object lookup with
/// no `FROM` (`pg_get_viewdef`, `obj_description`) — Beekeeper issues those
/// as the entire query. `SELECT now()` stays off this path so the Safety
/// rescue, not `system_catalogs`, remains what serves it.
pub fn reads_only_server_metadata(sql: &str) -> bool {
    StatementInspection::new(sql).reads_only_server_metadata()
}

pub(crate) fn reads_only_server_metadata_inspected(inspection: &StatementInspection<'_>) -> bool {
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
    let mut saw_catalog_lookup = false;
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
            // Classified-leaky catalogs (`pg_stat_activity`, `pg_stat_statements`)
            // are views. The SRFs behind them produce identical rows while
            // appearing as a `RangeFunction` that neither the RangeVar arm nor
            // the escape list matches:
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
                        // Unqualified or `pg_catalog.*` only. Matching on the
                        // last name component used to let `myschema.generate_series`
                        // through this arm (the FuncCall arm still refused it).
                        let Some(name) = function_name(&call.funcname) else {
                            disqualified = true;
                            return;
                        };
                        if !GENERATORS_IN_FROM.contains(&name.as_str()) {
                            disqualified = true;
                            return;
                        }
                        // `generate_series` still needs a catalog RangeVar —
                        // it is not itself a catalog. A helper SRF
                        // (`pg_get_keywords`, `pg_options_to_table`) *is* the
                        // catalog read, so it supplies the relation marker.
                        if CATALOG_HELPER_FUNCTIONS.contains(&name.as_str()) {
                            saw_relation = true;
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
            Some(NodeEnum::FuncCall(call)) => {
                if !func_call_is_catalog_safe(call) {
                    disqualified = true;
                    return;
                }
                // The no-FROM exception only needs this flag when there is no
                // catalog RangeVar. Skip the extra name parse once we have one.
                if saw_relation || saw_catalog_lookup {
                    return;
                }
                if let Some(name) = function_name(&call.funcname) {
                    saw_catalog_lookup = is_catalog_object_lookup(&name);
                }
            }
            _ => {}
        }
    });
    if disqualified {
        return false;
    }
    if saw_relation {
        return true;
    }

    // A statement naming no relation is not a catalog query, and pg_query has a
    // known bug where a self-referencing CTE yields an empty table list. Either
    // way, releasing on an empty set would release on absence of evidence.
    //
    // The exception is a catalog-object lookup with no FROM and no CTE:
    // Beekeeper's view SQL is `SELECT pg_get_viewdef($1::regclass, true)` and
    // its table-properties pane mixes size functions with `obj_description`.
    // Distinct from "we saw no relation" — `WITH f AS (SELECT * FROM f) SELECT
    // * FROM f` still has a FROM. `SELECT now()` is a context function, not a
    // catalog lookup, and stays on the Safety rescue. The lookup flag comes
    // from the walk above; this only checks the statement shape.
    cte_names.is_empty() && saw_catalog_lookup && is_simple_empty_from_select(parsed)
}

/// Single `SELECT` of expressions: no `FROM`, no `VALUES`, no set operation.
/// The catalog-lookup exception is this shape plus [`is_catalog_object_lookup`].
fn is_simple_empty_from_select(parsed: &pg_query::ParseResult) -> bool {
    let Some(NodeEnum::SelectStmt(select)) = parsed
        .protobuf
        .stmts
        .first()
        .and_then(|s| s.stmt.as_ref())
        .and_then(|s| s.node.as_ref())
    else {
        return false;
    };
    select.op() == pg_query::protobuf::SetOperation::SetopNone
        && select.from_clause.is_empty()
        && select.values_lists.is_empty()
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

pub(crate) fn provenance_is_trustworthy_inspected(inspection: &StatementInspection<'_>) -> bool {
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

/// Whether every relation in the statement carries an explicit schema.
///
/// Used only to decide whether a result set made entirely of expressions can be
/// trusted: with no provenance-bearing field, there is no OID to check, so the
/// name has to have been unambiguous in the first place.
pub fn every_relation_is_qualified(sql: &str) -> bool {
    StatementInspection::new(sql).every_relation_is_qualified()
}

pub(crate) fn every_relation_is_qualified_inspected(inspection: &StatementInspection<'_>) -> bool {
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

/// Target-list functions permitted on the metadata-only fast path.
///
/// Fail-closed: an unparseable name, a schema other than `pg_catalog` /
/// `information_schema`, or a name that is not trusted / a FROM-generator /
/// a catalog helper is not metadata-only. [`CATALOG_ESCAPE_FUNCTIONS`] still
/// wins if a name is on both lists. `information_schema._pg_*` helpers
/// implement the SQL-standard views; they are not dump functions.
pub(crate) fn func_call_is_catalog_safe(call: &pg_query::protobuf::FuncCall) -> bool {
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

/// Catalog-object lookup issued with no `FROM`: view SQL, function SQL, comments.
///
/// [`CATALOG_HELPER_FUNCTIONS`] also lists formatters and aggregates so they
/// may appear in a SELECT list *beside* a catalog RangeVar. Those must not
/// open this path on their own — `SELECT string_agg('a', ',')` is not a
/// catalog read. FROM-generator helpers (`pg_get_keywords`) use the
/// RangeFunction arm instead.
fn is_catalog_object_lookup(name: &str) -> bool {
    if GENERATORS_IN_FROM.contains(&name) {
        return false;
    }
    matches!(
        name,
        "obj_description" | "shobj_description" | "col_description"
    ) || (name.starts_with("pg_get_") && CATALOG_HELPER_FUNCTIONS.contains(&name))
}
