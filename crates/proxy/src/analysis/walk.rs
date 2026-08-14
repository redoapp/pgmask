//! Local descent over `pg_query` protobuf nodes.
//!
//! `pg_query::nodes()` is generated from a subset of the protobuf schema and
//! "doesn't iterate over every possible node type" (upstream). Absence proofs
//! in this crate use this walk instead of that iterator.

use pg_query::protobuf::node::Node as NodeEnum;

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
pub(crate) fn walk_tree(
    node: &pg_query::protobuf::Node,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    visit(node);
    for_each_child_node(node, &mut |child| walk_tree(child, visit));
}

pub(crate) fn walk_parsed(
    parsed: &pg_query::ParseResult,
    visit: &mut dyn FnMut(&pg_query::protobuf::Node),
) {
    for raw in &parsed.protobuf.stmts {
        if let Some(stmt) = raw.stmt.as_ref() {
            walk_tree(stmt, visit);
        }
    }
}

pub(crate) fn tree_any(
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

pub(crate) fn subtree_any(
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
