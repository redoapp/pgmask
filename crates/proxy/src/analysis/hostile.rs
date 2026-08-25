//! Hostile-posture predicates: membership oracles, join/rename, whole-row.

use std::collections::HashSet;

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::SetOperation;

use super::walk::{subtree_any, tree_any, walk_parsed, walk_tree};
use super::StatementInspection;

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

pub(crate) fn masked_exceeds_outer_projection_inspected(
    inspection: &StatementInspection<'_>,
    masked: &HashSet<String>,
) -> bool {
    use std::collections::HashMap;

    if masked.is_empty() {
        return false;
    }
    // A parse failure still refuses: unicode-escaped names are now decoded
    // in the token stream, but a tree the walker cannot even build is a
    // count we cannot trust, and allowing the statement is a leak on any
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

pub(crate) fn hostile_join_or_rename_masked_inspected(
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

pub(crate) fn hostile_uses_whole_row_inspected(
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
