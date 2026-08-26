//! Whether an output expression is a shape whose lineage sources are complete.
//!
//! `sqllineage` reports the base columns it found. A non-empty list of
//! released columns is not the same as "it found every column that feeds the
//! field": a scalar subquery is invisible to it, so
//! `city || (SELECT email FROM …)` looks like it comes from `city` alone.
//!
//! Guard 6 (the name backstop) is independent of that and can miss a name
//! the engine accepts but the lexer does not spell. This module asks a
//! different question, the same inversion `classify` uses: is the expression
//! built only from node types we *positively know* do not hide a nested
//! query? Anything else — a `SubLink`, a window, a node kind we have not
//! listed — is incomplete, and lineage must not `Release`.
//!
//! A `ColumnRef` is closed only as a *stored* column. If it names the output
//! of a FROM-clause subquery or a CTE, the value is that inner expression,
//! and we follow it. Leaving those aliases as closed was the wrap that
//! reopened the SubLink leak after Guard 7 looked only at the outermost
//! target list: `SELECT x FROM (SELECT city || (SELECT renamed_email) AS x)`
//! is a `ColumnRef` on the outside and a hidden `SubLink` underneath.
//! `SELECT * FROM (…)` is still unwrapped here the same way
//! `analyze_inspected` unwraps it.
//!
//! A `RangeVar` with a FROM colnames list is incomplete the same way a
//! `RangeFunction` or join-with-colnames is. `AS t(id, city, …)` remaps
//! attnums by position, so the released name `city` can bind to email
//! and Guard 6 never sees the word `email`. A SELECT-list alias
//! (`SELECT city AS x`) is not that list and is still followed.
//!
//! A subquery in WHERE/HAVING/ORDER BY is a predicate, not a source of the
//! projected value, and is not inspected here.

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{CommonTableExpr, Node, SelectStmt, SetOperation};

use super::safety::unwrap_star_over_subquery;
use super::StatementInspection;

/// Recursion bound when following aliases through FROM/CTE. A recursive CTE
/// that names its own output would otherwise loop; exceeding this is
/// incomplete, not a release.
const FOLLOW_DEPTH: u32 = 32;

/// One flag per described field: `true` means the output expression is a
/// closed composition of columns and literals. Unparseable SQL, a set
/// operation whose branches cannot be read, or a field we cannot locate is
/// `false` — lineage must not release on a source list it cannot vouch for.
pub(crate) fn output_lineage_is_closed(
    inspection: &StatementInspection<'_>,
    field_count: usize,
) -> Vec<bool> {
    let incomplete = vec![false; field_count];
    let Some(parsed) = inspection.parsed() else {
        return incomplete;
    };
    let [statement] = parsed.protobuf.stmts.as_slice() else {
        return incomplete;
    };
    let Some(NodeEnum::SelectStmt(select)) = statement.stmt.as_ref().and_then(|s| s.node.as_ref())
    else {
        return incomplete;
    };

    (0..field_count)
        .map(|index| field_is_closed(select, index, &[], 0))
        .collect()
}

/// Whether described field `index` of `select` is a closed value pipeline.
fn field_is_closed(select: &SelectStmt, index: usize, parent_ctes: &[Cte<'_>], depth: u32) -> bool {
    if depth >= FOLLOW_DEPTH {
        return false;
    }
    let mut select = select;
    while let Some(inner) = unwrap_star_over_subquery(select) {
        select = inner;
    }
    let ctes = extend_ctes(parent_ctes, select);
    if select.op != SetOperation::SetopNone as i32 {
        let Some(left) = select.larg.as_ref() else {
            return false;
        };
        let Some(right) = select.rarg.as_ref() else {
            return false;
        };
        return field_is_closed(left, index, &ctes, depth.saturating_add(1))
            && field_is_closed(right, index, &ctes, depth.saturating_add(1));
    }
    if !select.values_lists.is_empty() {
        return values_lists_closed(select, index, &ctes, depth);
    }
    let Some(entry) = select.target_list.get(index) else {
        return false;
    };
    let Some(NodeEnum::ResTarget(target)) = entry.node.as_ref() else {
        return false;
    };
    let Some(expr) = target.val.as_ref().and_then(|v| v.node.as_ref()) else {
        return false;
    };
    expr_is_closed(expr, select, &ctes, depth)
}

fn values_lists_closed(select: &SelectStmt, index: usize, ctes: &[Cte<'_>], depth: u32) -> bool {
    if select.values_lists.is_empty() {
        return false;
    }
    select.values_lists.iter().all(|row| {
        let Some(NodeEnum::List(list)) = row.node.as_ref() else {
            return false;
        };
        let Some(cell) = list.items.get(index) else {
            return false;
        };
        node_is_closed(cell, select, ctes, depth)
    })
}

fn node_is_closed(node: &Node, select: &SelectStmt, ctes: &[Cte<'_>], depth: u32) -> bool {
    node.node
        .as_ref()
        .is_some_and(|expr| expr_is_closed(expr, select, ctes, depth))
}

fn expr_is_closed(expr: &NodeEnum, select: &SelectStmt, ctes: &[Cte<'_>], depth: u32) -> bool {
    match expr {
        NodeEnum::ColumnRef(column) => column_ref_is_closed(column, select, ctes, depth),
        NodeEnum::AStar(_) => false,

        NodeEnum::AConst(_) | NodeEnum::ParamRef(_) | NodeEnum::SqlvalueFunction(_) => true,

        NodeEnum::TypeCast(cast) => cast
            .arg
            .as_deref()
            .is_some_and(|n| node_is_closed(n, select, ctes, depth)),
        NodeEnum::CollateClause(collate) => collate
            .arg
            .as_deref()
            .is_some_and(|n| node_is_closed(n, select, ctes, depth)),

        NodeEnum::AExpr(expr) => {
            optional_closed(expr.lexpr.as_deref(), select, ctes, depth)
                && optional_closed(expr.rexpr.as_deref(), select, ctes, depth)
        }
        NodeEnum::BoolExpr(expr) => expr
            .args
            .iter()
            .all(|n| node_is_closed(n, select, ctes, depth)),
        NodeEnum::NullTest(n) => n
            .arg
            .as_deref()
            .is_some_and(|a| node_is_closed(a, select, ctes, depth)),
        NodeEnum::BooleanTest(b) => b
            .arg
            .as_deref()
            .is_some_and(|a| node_is_closed(a, select, ctes, depth)),

        // A window hides frame offsets and partition keys in a `WindowDef`
        // the historical walker skipped. Lineage does not claim completeness
        // for it; ranking windows are already `Releasable` in `classify`.
        NodeEnum::FuncCall(call) => {
            call.over.is_none()
                && call
                    .args
                    .iter()
                    .all(|n| node_is_closed(n, select, ctes, depth))
        }
        NodeEnum::CoalesceExpr(c) => c
            .args
            .iter()
            .all(|n| node_is_closed(n, select, ctes, depth)),
        NodeEnum::MinMaxExpr(m) => m
            .args
            .iter()
            .all(|n| node_is_closed(n, select, ctes, depth)),
        NodeEnum::NullIfExpr(n) => n
            .args
            .iter()
            .all(|a| node_is_closed(a, select, ctes, depth)),
        NodeEnum::RowExpr(row) => row
            .args
            .iter()
            .all(|n| node_is_closed(n, select, ctes, depth)),
        NodeEnum::NamedArgExpr(named) => named
            .arg
            .as_deref()
            .is_some_and(|n| node_is_closed(n, select, ctes, depth)),

        NodeEnum::CaseExpr(case) => {
            optional_closed(case.arg.as_deref(), select, ctes, depth)
                && case
                    .args
                    .iter()
                    .all(|n| node_is_closed(n, select, ctes, depth))
                && optional_closed(case.defresult.as_deref(), select, ctes, depth)
        }
        NodeEnum::CaseWhen(when) => {
            optional_closed(when.expr.as_deref(), select, ctes, depth)
                && optional_closed(when.result.as_deref(), select, ctes, depth)
        }

        NodeEnum::AArrayExpr(arr) => arr
            .elements
            .iter()
            .all(|n| node_is_closed(n, select, ctes, depth)),
        NodeEnum::ArrayExpr(arr) => arr
            .elements
            .iter()
            .all(|n| node_is_closed(n, select, ctes, depth)),
        NodeEnum::List(list) => list
            .items
            .iter()
            .all(|n| node_is_closed(n, select, ctes, depth)),

        NodeEnum::AIndirection(ind) => {
            ind.arg
                .as_deref()
                .is_some_and(|n| node_is_closed(n, select, ctes, depth))
                && ind
                    .indirection
                    .iter()
                    .all(|n| node_is_closed(n, select, ctes, depth))
        }

        // The construct that leaked. Anything we have not listed is the same
        // direction: a node we do not know how to read may hide a source.
        NodeEnum::SubLink(_) => false,
        _ => false,
    }
}

fn optional_closed(node: Option<&Node>, select: &SelectStmt, ctes: &[Cte<'_>], depth: u32) -> bool {
    node.is_none_or(|n| node_is_closed(n, select, ctes, depth))
}

/// A CTE visible while judging the current select.
#[derive(Clone)]
struct Cte<'a> {
    name: &'a str,
    colnames: Vec<String>,
    query: &'a SelectStmt,
}

fn extend_ctes<'a>(parent: &[Cte<'a>], select: &'a SelectStmt) -> Vec<Cte<'a>> {
    let mut out = parent.to_vec();
    let Some(with) = select.with_clause.as_ref() else {
        return out;
    };
    for node in &with.ctes {
        let Some(NodeEnum::CommonTableExpr(cte)) = node.node.as_ref() else {
            continue;
        };
        let Some(query) = cte_query(cte) else {
            continue;
        };
        let colnames = names_from_nodes(&cte.aliascolnames).unwrap_or_default();
        // A later CTE of the same name shadows, matching SQL.
        out.retain(|existing| existing.name != cte.ctename.as_str());
        out.push(Cte {
            name: cte.ctename.as_str(),
            colnames,
            query,
        });
    }
    out
}

fn cte_query(cte: &CommonTableExpr) -> Option<&SelectStmt> {
    match cte.ctequery.as_ref()?.node.as_ref()? {
        NodeEnum::SelectStmt(select) => Some(select),
        _ => None,
    }
}

fn column_ref_is_closed(
    column: &pg_query::protobuf::ColumnRef,
    select: &SelectStmt,
    ctes: &[Cte<'_>],
    depth: u32,
) -> bool {
    if column
        .fields
        .iter()
        .any(|field| matches!(field.node.as_ref(), Some(NodeEnum::AStar(_))))
    {
        return false;
    }
    let Some((qualifier, name)) = column_ref_parts(column) else {
        return false;
    };
    match resolve_column(select, ctes, qualifier.as_deref(), &name) {
        ColumnOrigin::Base => true,
        ColumnOrigin::Nested { query, index } => {
            field_is_closed(query, index, ctes, depth.saturating_add(1))
        }
        ColumnOrigin::Incomplete => false,
    }
}

fn column_ref_parts(column: &pg_query::protobuf::ColumnRef) -> Option<(Option<String>, String)> {
    let mut parts = Vec::with_capacity(column.fields.len());
    for field in &column.fields {
        let NodeEnum::String(s) = field.node.as_ref()? else {
            return None;
        };
        parts.push(s.sval.to_ascii_lowercase());
    }
    let name = parts.pop()?;
    let qualifier = parts.pop();
    Some((qualifier, name))
}

enum ColumnOrigin<'a> {
    /// A stored column of a named relation. Shape is closed; masking is
    /// OID / lineage's source list, not this module.
    Base,
    /// Output of a FROM subquery or CTE. Follow that field.
    Nested { query: &'a SelectStmt, index: usize },
    /// Several definitions, a construct we do not read, or a name we
    /// cannot place.
    Incomplete,
}

fn resolve_column<'a>(
    select: &'a SelectStmt,
    ctes: &'a [Cte<'a>],
    qualifier: Option<&str>,
    name: &str,
) -> ColumnOrigin<'a> {
    let mut nested: Option<ColumnOrigin<'a>> = None;
    let mut saw_base = false;
    let mut from_items = Vec::new();
    for entry in &select.from_clause {
        flatten_from(entry, &mut from_items);
    }

    for item in from_items {
        match classify_from_item(item, ctes, qualifier, name) {
            None => {}
            Some(ColumnOrigin::Incomplete) => return ColumnOrigin::Incomplete,
            Some(ColumnOrigin::Base) => saw_base = true,
            Some(origin @ ColumnOrigin::Nested { .. }) => {
                if nested.is_some() {
                    return ColumnOrigin::Incomplete;
                }
                nested = Some(origin);
            }
        }
    }

    match (nested, saw_base, qualifier) {
        (Some(_), true, None) => ColumnOrigin::Incomplete,
        (Some(origin), _, _) => origin,
        (None, _, _) => ColumnOrigin::Base,
    }
}

fn flatten_from<'a>(node: &'a Node, out: &mut Vec<&'a Node>) {
    match node.node.as_ref() {
        Some(NodeEnum::JoinExpr(join)) => {
            if join.alias.as_ref().is_some_and(|a| !a.colnames.is_empty()) {
                // `FROM (a JOIN b) AS j(c1, c2)` hides the inputs behind
                // names we cannot map back to expressions.
                out.push(node);
                return;
            }
            if let Some(left) = join.larg.as_ref() {
                flatten_from(left, out);
            }
            if let Some(right) = join.rarg.as_ref() {
                flatten_from(right, out);
            }
        }
        Some(NodeEnum::RangeTableSample(sample)) => {
            if let Some(rel) = sample.relation.as_ref() {
                flatten_from(rel, out);
            } else {
                out.push(node);
            }
        }
        _ => out.push(node),
    }
}

fn classify_from_item<'a>(
    item: &'a Node,
    ctes: &'a [Cte<'a>],
    qualifier: Option<&str>,
    name: &str,
) -> Option<ColumnOrigin<'a>> {
    match item.node.as_ref()? {
        NodeEnum::RangeSubselect(sub) => {
            let alias = sub.alias.as_ref()?;
            let alias_name = alias.aliasname.to_ascii_lowercase();
            if let Some(q) = qualifier {
                if alias_name != q {
                    return None;
                }
            }
            let colnames = names_from_nodes(&alias.colnames).unwrap_or_default();
            let query = match sub.subquery.as_ref()?.node.as_ref()? {
                NodeEnum::SelectStmt(select) => select,
                _ => return Some(ColumnOrigin::Incomplete),
            };
            match output_index(query, &colnames, name) {
                Some(index) => Some(ColumnOrigin::Nested { query, index }),
                None if qualifier.is_some() => Some(ColumnOrigin::Incomplete),
                None => None,
            }
        }
        NodeEnum::RangeVar(range) => {
            let rel = range.relname.to_ascii_lowercase();
            let alias = range
                .alias
                .as_ref()
                .map(|a| a.aliasname.to_ascii_lowercase());
            let item_name = alias.as_deref().unwrap_or(rel.as_str());
            if let Some(q) = qualifier {
                if item_name != q && rel != q {
                    return None;
                }
            }
            // `FROM customers AS t(id, city, …)` remaps attnums by
            // position. The released name `city` can bind to email;
            // Guard 6 never sees the word `email`. Same inversion as
            // RangeFunction / join-with-colnames: names we cannot map
            // back to stored columns. A SELECT-list `AS` is not this
            // list and is still followed above.
            if range.alias.as_ref().is_some_and(|a| !a.colnames.is_empty()) {
                return Some(ColumnOrigin::Incomplete);
            }
            if let Some(cte) = ctes
                .iter()
                .rev()
                .find(|c| c.name == rel || Some(c.name) == alias.as_deref())
            {
                return match output_index(cte.query, &cte.colnames, name) {
                    Some(index) => Some(ColumnOrigin::Nested {
                        query: cte.query,
                        index,
                    }),
                    None if qualifier.is_some() => Some(ColumnOrigin::Incomplete),
                    None => None,
                };
            }
            if qualifier.is_some() {
                return Some(ColumnOrigin::Base);
            }
            // Unqualified: a base table is only a candidate when we cannot
            // already see a nested definition. The caller records `saw_base`.
            Some(ColumnOrigin::Base)
        }
        NodeEnum::JoinExpr(_) => {
            // Flattening already refused join-with-colnames; a leftover
            // JoinExpr is a qualifier we cannot decompose.
            if qualifier.is_some() {
                Some(ColumnOrigin::Incomplete)
            } else {
                None
            }
        }
        NodeEnum::RangeFunction(func) => {
            let alias = func.alias.as_ref()?;
            if let Some(q) = qualifier {
                if alias.aliasname.to_ascii_lowercase() != q {
                    return None;
                }
                return Some(ColumnOrigin::Incomplete);
            }
            let colnames = names_from_nodes(&alias.colnames).unwrap_or_default();
            if colnames.iter().any(|c| c == name) {
                Some(ColumnOrigin::Incomplete)
            } else {
                None
            }
        }
        NodeEnum::RangeTableFunc(tf) => {
            let alias = tf.alias.as_ref()?;
            if let Some(q) = qualifier {
                if alias.aliasname.to_ascii_lowercase() != q {
                    return None;
                }
                return Some(ColumnOrigin::Incomplete);
            }
            let colnames = names_from_nodes(&alias.colnames).unwrap_or_default();
            if colnames.iter().any(|c| c == name) {
                Some(ColumnOrigin::Incomplete)
            } else {
                None
            }
        }
        _ => {
            if qualifier.is_some() {
                Some(ColumnOrigin::Incomplete)
            } else {
                None
            }
        }
    }
}

/// Position of `name` in `query`'s output, using an optional FROM/CTE
/// column-name list, then `AS` / inferred `ColumnRef` names.
fn output_index(query: &SelectStmt, colnames: &[String], name: &str) -> Option<usize> {
    if let Some(index) = colnames.iter().position(|c| c == name) {
        return Some(index);
    }
    if !colnames.is_empty() {
        return None;
    }
    let mut found = None;
    for (index, entry) in query.target_list.iter().enumerate() {
        let Some(NodeEnum::ResTarget(target)) = entry.node.as_ref() else {
            continue;
        };
        let Some(output) = res_target_name(target) else {
            continue;
        };
        if output != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(index);
    }
    found
}

fn res_target_name(target: &pg_query::protobuf::ResTarget) -> Option<String> {
    if !target.name.is_empty() {
        return Some(target.name.to_ascii_lowercase());
    }
    match target.val.as_ref()?.node.as_ref()? {
        NodeEnum::ColumnRef(column) => {
            let last = column.fields.last()?.node.as_ref()?;
            match last {
                NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
                _ => None,
            }
        }
        _ => None,
    }
}

fn names_from_nodes(nodes: &[Node]) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        let NodeEnum::String(s) = node.node.as_ref()? else {
            return None;
        };
        out.push(s.sval.to_ascii_lowercase());
    }
    Some(out)
}
