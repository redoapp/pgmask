//! Allowlisted JSON/JSONB extraction shapes.
//!
//! `->` / `->>` / `#>` / `#>>` and the `json[b]_extract_path[_text]` names erase
//! `RowDescription` provenance, so a classified document would otherwise be
//! refused as opaque. This module names the shapes whose extract path is a
//! sequence of *literals*, so policy can apply the same pointer rule the
//! stored column would have used.
//!
//! Incomplete analysis stays refusal. Dynamic keys (`payload->col`), JSONPath,
//! set-returning unnesting, and constructors are not on the list.

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{AExpr, FuncCall, Node, SelectStmt};

use super::names::function_name;
use super::safety::unwrap_star_over_subquery;
use super::StatementInspection;

const MAX_EXTRACT_DEPTH: usize = 16;

/// One RFC-6901-style path segment taken from a literal JSON operator key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonExtractPathSegment {
    pub value: String,
    /// `true` only when the SQL operand was an integer (`payload->0`) or a
    /// digit-only `#>` element. Object key `"0"` from `payload->'0'` stays
    /// `false`, so an array wildcard cannot claim it.
    pub array_index: bool,
}

/// How the extract named its source column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonExtractColumn {
    /// `payload->>'x'`
    Bare(String),
    /// `d.payload` or `documents.payload` — one name, matched against alias or
    /// relation name after catalog resolution.
    Named { relation: String, column: String },
    /// `canary.documents.payload`
    Qualified {
        schema: String,
        relation: String,
        column: String,
    },
}

impl JsonExtractColumn {
    /// Bare column name used by hostile projection counting.
    pub fn column_name(&self) -> &str {
        match self {
            Self::Bare(name)
            | Self::Named { column: name, .. }
            | Self::Qualified { column: name, .. } => name,
        }
    }
}

/// A positively identified extract: one column plus a literal path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonExtract {
    pub column: JsonExtractColumn,
    pub path: Vec<JsonExtractPathSegment>,
    /// `->>`, `#>>`, and `json[b]_extract_path_text` return text. The document
    /// operators return `json`/`jsonb` and can still be walked.
    pub as_text: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonExtractArgument {
    Extract(JsonExtract),
    Unattributable,
}

pub struct JsonExtractResolution {
    relations: Vec<QualifiedFrom>,
    fields: Vec<JsonExtractArgument>,
}

impl JsonExtractResolution {
    pub fn relations(&self) -> &[QualifiedFrom] {
        &self.relations
    }

    pub fn fields(&self) -> &[JsonExtractArgument] {
        &self.fields
    }
}

/// A schema-qualified FROM range, with the alias the SELECT list uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedFrom {
    pub schema: String,
    pub relname: String,
    pub alias: Option<String>,
}

impl QualifiedFrom {
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.schema, self.relname)
    }
}

/// Whether `expr` is an allowlisted JSON extract (possibly under casts).
pub(crate) fn expr_is_json_extract(expr: &NodeEnum) -> bool {
    parse_extract(expr, 0).is_some()
}

/// The source column a hostile-posture projection credit should count, when
/// `node` is an allowlisted extract.
pub(crate) fn extract_projection_column(node: &Node) -> Option<String> {
    parse_extract(node.node.as_ref()?, 0).map(|extract| extract.column.column_name().to_string())
}

impl StatementInspection<'_> {
    /// Resolution material for a JSON extract over one schema-qualified column.
    ///
    /// Same collapse-to-`None` bar as [`StatementInspection::summary_resolution`]:
    /// a set operation, a star, an unqualified relation, or a FROM entry that
    /// is not a named range (or a join of named ranges) means the caller keeps
    /// the opaque posture. Joins are collected because `d.payload->>'x'` is the
    /// shape analysts write; a subquery in FROM is not.
    pub fn json_extract_resolution(&self, field_count: usize) -> Option<JsonExtractResolution> {
        let parsed = self.parsed()?;
        if parsed.protobuf.stmts.len() != 1 {
            return None;
        }
        let NodeEnum::SelectStmt(select) = parsed
            .protobuf
            .stmts
            .first()
            .and_then(|s| s.stmt.as_ref())
            .and_then(|s| s.node.as_ref())?
        else {
            return None;
        };
        let mut select: &SelectStmt = select;
        while let Some(inner) = unwrap_star_over_subquery(select) {
            select = inner;
        }
        if !super::safety::positions_are_trustworthy(select, field_count) {
            return None;
        }
        let mut relations = Vec::new();
        for entry in &select.from_clause {
            relations.extend(collect_qualified_from(entry)?);
        }
        let fields = select
            .target_list
            .iter()
            .map(|entry| match entry.node.as_ref() {
                Some(NodeEnum::ResTarget(target)) => target
                    .val
                    .as_ref()
                    .and_then(|v| v.node.as_ref())
                    .and_then(|expr| parse_extract(expr, 0))
                    .map_or(
                        JsonExtractArgument::Unattributable,
                        JsonExtractArgument::Extract,
                    ),
                _ => JsonExtractArgument::Unattributable,
            })
            .collect();
        Some(JsonExtractResolution { relations, fields })
    }
}

fn collect_qualified_from(node: &Node) -> Option<Vec<QualifiedFrom>> {
    match node.node.as_ref()? {
        NodeEnum::RangeVar(range) => {
            if range.schemaname.is_empty() {
                return None;
            }
            Some(vec![QualifiedFrom {
                schema: range.schemaname.to_ascii_lowercase(),
                relname: range.relname.to_ascii_lowercase(),
                alias: range
                    .alias
                    .as_ref()
                    .map(|alias| alias.aliasname.to_ascii_lowercase()),
            }])
        }
        NodeEnum::JoinExpr(join) => {
            let mut out = collect_qualified_from(join.larg.as_ref()?)?;
            out.extend(collect_qualified_from(join.rarg.as_ref()?)?);
            Some(out)
        }
        _ => None,
    }
}

fn parse_extract(expr: &NodeEnum, depth: usize) -> Option<JsonExtract> {
    if depth > MAX_EXTRACT_DEPTH {
        return None;
    }
    match expr {
        NodeEnum::TypeCast(cast) => cast
            .arg
            .as_ref()
            .and_then(|arg| arg.node.as_ref())
            .and_then(|inner| parse_extract(inner, depth.saturating_add(1))),
        NodeEnum::CollateClause(collate) => collate
            .arg
            .as_ref()
            .and_then(|arg| arg.node.as_ref())
            .and_then(|inner| parse_extract(inner, depth.saturating_add(1))),
        NodeEnum::AExpr(aexpr) => parse_operator_extract(aexpr, depth),
        NodeEnum::FuncCall(call) => parse_function_extract(call, depth),
        _ => None,
    }
}

fn parse_operator_extract(aexpr: &AExpr, depth: usize) -> Option<JsonExtract> {
    let name = operator_name(&aexpr.name)?;
    let (as_text, path_is_array) = match name.as_str() {
        "->" => (false, false),
        "->>" => (true, false),
        "#>" => (false, true),
        "#>>" => (true, true),
        _ => return None,
    };
    let left = aexpr.lexpr.as_ref().and_then(|n| n.node.as_ref())?;
    let right = aexpr.rexpr.as_ref().and_then(|n| n.node.as_ref())?;
    let key_segments = if path_is_array {
        parse_path_array(right)?
    } else {
        vec![parse_single_key(right)?]
    };
    if key_segments.is_empty() {
        return None;
    }
    finish_extract(left, key_segments, as_text, depth)
}

fn parse_function_extract(call: &FuncCall, depth: usize) -> Option<JsonExtract> {
    if call.over.is_some() || call.agg_star || call.agg_filter.is_some() {
        return None;
    }
    let name = catalog_function_name(&call.funcname)?;
    let as_text = match name.as_str() {
        "json_extract_path" | "jsonb_extract_path" => false,
        "json_extract_path_text" | "jsonb_extract_path_text" => true,
        _ => return None,
    };
    let (first, rest) = call.args.split_first()?;
    if rest.is_empty() {
        return None;
    }
    let mut key_segments = Vec::with_capacity(rest.len());
    for arg in rest {
        // Function forms take text keys, never integer array indices.
        let NodeEnum::AConst(constant) = arg.node.as_ref()? else {
            return None;
        };
        let pg_query::protobuf::a_const::Val::Sval(s) = constant.val.as_ref()? else {
            return None;
        };
        key_segments.push(JsonExtractPathSegment {
            value: s.sval.clone(),
            array_index: false,
        });
    }
    let left = first.node.as_ref()?;
    finish_extract(left, key_segments, as_text, depth)
}

fn finish_extract(
    left: &NodeEnum,
    key_segments: Vec<JsonExtractPathSegment>,
    as_text: bool,
    depth: usize,
) -> Option<JsonExtract> {
    if let Some(inner) = parse_extract(left, depth.saturating_add(1)) {
        // `payload->'a'->>'b'`: the outer operator decides text vs json.
        if inner.as_text {
            // A text extract cannot be the left of another JSON operator.
            return None;
        }
        let mut path = inner.path;
        path.extend(key_segments);
        return Some(JsonExtract {
            column: inner.column,
            path,
            as_text,
        });
    }
    let column = parse_column_ref(left)?;
    Some(JsonExtract {
        column,
        path: key_segments,
        as_text,
    })
}

fn parse_column_ref(expr: &NodeEnum) -> Option<JsonExtractColumn> {
    let mut expr = expr;
    loop {
        match expr {
            NodeEnum::TypeCast(cast) => {
                expr = cast.arg.as_ref()?.node.as_ref()?;
            }
            NodeEnum::CollateClause(collate) => {
                expr = collate.arg.as_ref()?.node.as_ref()?;
            }
            NodeEnum::ColumnRef(column) => break parse_column_ref_fields(&column.fields),
            _ => return None,
        }
    }
}

fn parse_column_ref_fields(fields: &[Node]) -> Option<JsonExtractColumn> {
    let ident = |node: &Node| match node.node.as_ref()? {
        NodeEnum::String(s) => Some(s.sval.to_ascii_lowercase()),
        _ => None,
    };
    match fields {
        [column] => Some(JsonExtractColumn::Bare(ident(column)?)),
        [relation, column] => Some(JsonExtractColumn::Named {
            relation: ident(relation)?,
            column: ident(column)?,
        }),
        [schema, relation, column] => Some(JsonExtractColumn::Qualified {
            schema: ident(schema)?,
            relation: ident(relation)?,
            column: ident(column)?,
        }),
        _ => None,
    }
}

fn parse_single_key(expr: &NodeEnum) -> Option<JsonExtractPathSegment> {
    let NodeEnum::AConst(constant) = expr else {
        return None;
    };
    match constant.val.as_ref()? {
        pg_query::protobuf::a_const::Val::Sval(s) => Some(JsonExtractPathSegment {
            value: s.sval.clone(),
            array_index: false,
        }),
        pg_query::protobuf::a_const::Val::Ival(i) => {
            if i.ival < 0 {
                return None;
            }
            Some(JsonExtractPathSegment {
                value: i.ival.to_string(),
                array_index: true,
            })
        }
        _ => None,
    }
}

fn parse_path_array(expr: &NodeEnum) -> Option<Vec<JsonExtractPathSegment>> {
    match expr {
        NodeEnum::TypeCast(cast) => cast
            .arg
            .as_ref()
            .and_then(|arg| arg.node.as_ref())
            .and_then(parse_path_array),
        NodeEnum::AArrayExpr(array) => {
            let mut out = Vec::with_capacity(array.elements.len());
            for element in &array.elements {
                out.push(parse_array_element(element.node.as_ref()?)?);
            }
            Some(out)
        }
        NodeEnum::ArrayExpr(array) => {
            if array.multidims {
                return None;
            }
            let mut out = Vec::with_capacity(array.elements.len());
            for element in &array.elements {
                out.push(parse_array_element(element.node.as_ref()?)?);
            }
            Some(out)
        }
        NodeEnum::AConst(constant) => {
            let pg_query::protobuf::a_const::Val::Sval(s) = constant.val.as_ref()? else {
                return None;
            };
            parse_postgres_array_literal(&s.sval)
        }
        _ => None,
    }
}

fn parse_array_element(expr: &NodeEnum) -> Option<JsonExtractPathSegment> {
    match expr {
        NodeEnum::TypeCast(cast) => cast
            .arg
            .as_ref()
            .and_then(|arg| arg.node.as_ref())
            .and_then(parse_array_element),
        NodeEnum::AConst(_) => parse_single_key(expr).map(|mut segment| {
            segment.array_index =
                segment.value.bytes().all(|b| b.is_ascii_digit()) && !segment.value.is_empty();
            segment
        }),
        _ => None,
    }
}

/// `{profile,email}` / `{items,0}` as a Postgres text-array literal.
///
/// Quoted elements, escapes, and nested arrays are refused: a wrong split is a
/// wrong pointer, which is a disclosure if we then apply `none`.
fn parse_postgres_array_literal(text: &str) -> Option<Vec<JsonExtractPathSegment>> {
    let body = text.trim().strip_prefix('{')?.strip_suffix('}')?;
    if body.is_empty() {
        return None;
    }
    if body.contains('"') || body.contains('\\') || body.contains('{') || body.contains('}') {
        return None;
    }
    let mut out = Vec::new();
    for part in body.split(',') {
        let value = part.trim();
        if value.is_empty() {
            return None;
        }
        let array_index = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
        out.push(JsonExtractPathSegment {
            value: value.to_string(),
            array_index,
        });
    }
    Some(out)
}

fn operator_name(parts: &[Node]) -> Option<String> {
    catalog_function_name(parts).or_else(|| {
        let last = parts.last()?;
        match last.node.as_ref()? {
            NodeEnum::String(s) => Some(s.sval.clone()),
            _ => None,
        }
    })
}

/// Unqualified `jsonb_extract_path`, or `pg_catalog.jsonb_extract_path`.
/// Any other schema is a user function and must not inherit this allowlist.
fn catalog_function_name(parts: &[Node]) -> Option<String> {
    match parts {
        [name] => function_name(std::slice::from_ref(name)),
        [schema, name] => {
            let NodeEnum::String(schema) = schema.node.as_ref()? else {
                return None;
            };
            if schema.sval.to_ascii_lowercase() != "pg_catalog" {
                return None;
            }
            function_name(std::slice::from_ref(name))
        }
        _ => None,
    }
}
