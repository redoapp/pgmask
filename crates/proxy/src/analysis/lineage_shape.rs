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
//! FROM-clause subqueries and CTEs are not `SubLink`s. They stay out of this
//! walk; tracing through them is what the resolver is for. A subquery in
//! WHERE/HAVING/ORDER BY is a predicate, not a source of the projected
//! value, and is not inspected here.

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{SelectStmt, SetOperation};

use super::safety::unwrap_star_over_subquery;
use super::StatementInspection;

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
        .map(|index| {
            let mut exprs = Vec::new();
            collect_value_exprs(select, index, &mut exprs)
                && exprs.iter().all(|e| expr_is_closed(e))
        })
        .collect()
}

/// Every target expression that feeds described field `index`.
///
/// Set-operation branches each contribute one; `SELECT * FROM (subselect)`
/// is unwrapped to the same inner list `analyze_inspected` classifies, so the
/// two halves of the session do not judge different statements.
fn collect_value_exprs<'a>(
    mut select: &'a SelectStmt,
    index: usize,
    out: &mut Vec<&'a NodeEnum>,
) -> bool {
    while let Some(inner) = unwrap_star_over_subquery(select) {
        select = inner;
    }
    if select.op != SetOperation::SetopNone as i32 {
        let Some(left) = select.larg.as_ref() else {
            return false;
        };
        let Some(right) = select.rarg.as_ref() else {
            return false;
        };
        return collect_value_exprs(left, index, out) && collect_value_exprs(right, index, out);
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
    out.push(expr);
    true
}

fn node_is_closed(node: &pg_query::protobuf::Node) -> bool {
    node.node.as_ref().is_some_and(expr_is_closed)
}

fn expr_is_closed(expr: &NodeEnum) -> bool {
    match expr {
        // A star is several columns, and the resolver's expansion of it is
        // exactly the empty-source case Guard 2 already refuses.
        NodeEnum::ColumnRef(column) => column
            .fields
            .iter()
            .all(|field| !matches!(field.node.as_ref(), Some(NodeEnum::AStar(_)))),
        NodeEnum::AStar(_) => false,

        NodeEnum::AConst(_) | NodeEnum::ParamRef(_) | NodeEnum::SqlvalueFunction(_) => true,

        NodeEnum::TypeCast(cast) => cast.arg.as_deref().is_some_and(node_is_closed),
        NodeEnum::CollateClause(collate) => collate.arg.as_deref().is_some_and(node_is_closed),

        NodeEnum::AExpr(expr) => {
            optional_closed(expr.lexpr.as_deref()) && optional_closed(expr.rexpr.as_deref())
        }
        NodeEnum::BoolExpr(expr) => expr.args.iter().all(node_is_closed),
        NodeEnum::NullTest(n) => n.arg.as_deref().is_some_and(node_is_closed),
        NodeEnum::BooleanTest(b) => b.arg.as_deref().is_some_and(node_is_closed),

        // A window hides frame offsets and partition keys in a `WindowDef`
        // the historical walker skipped. Lineage does not claim completeness
        // for it; ranking windows are already `Releasable` in `classify`.
        NodeEnum::FuncCall(call) => call.over.is_none() && call.args.iter().all(node_is_closed),
        NodeEnum::CoalesceExpr(c) => c.args.iter().all(node_is_closed),
        NodeEnum::MinMaxExpr(m) => m.args.iter().all(node_is_closed),
        NodeEnum::NullIfExpr(n) => n.args.iter().all(node_is_closed),
        NodeEnum::RowExpr(row) => row.args.iter().all(node_is_closed),
        NodeEnum::NamedArgExpr(named) => named.arg.as_deref().is_some_and(node_is_closed),

        NodeEnum::CaseExpr(case) => {
            optional_closed(case.arg.as_deref())
                && case.args.iter().all(node_is_closed)
                && optional_closed(case.defresult.as_deref())
        }
        NodeEnum::CaseWhen(when) => {
            optional_closed(when.expr.as_deref()) && optional_closed(when.result.as_deref())
        }

        NodeEnum::AArrayExpr(arr) => arr.elements.iter().all(node_is_closed),
        NodeEnum::ArrayExpr(arr) => arr.elements.iter().all(node_is_closed),
        NodeEnum::List(list) => list.items.iter().all(node_is_closed),

        NodeEnum::AIndirection(ind) => {
            ind.arg.as_deref().is_some_and(node_is_closed)
                && ind.indirection.iter().all(node_is_closed)
        }

        // The construct that leaked. Anything we have not listed is the same
        // direction: a node we do not know how to read may hide a source.
        NodeEnum::SubLink(_) => false,
        _ => false,
    }
}

fn optional_closed(node: Option<&pg_query::protobuf::Node>) -> bool {
    node.is_none_or(node_is_closed)
}
