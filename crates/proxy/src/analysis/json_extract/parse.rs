//! Literal path parser for allowlisted JSON extract operators.
//!
//! Attribution (FROM ranges, unique owner) stays in the parent module. This
//! file only decides whether an expression is a chain of literal `->` / `->>` /
//! `#>` / `#>>` / `json[b]_extract_path[_text]` keys.

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{AExpr, FuncCall, Node};

use super::super::names::{function_name, JSON_EXTRACT_FUNCTIONS};
use super::{JsonExtract, JsonExtractColumn, JsonExtractPathSegment, JsonPathNavigation};

const MAX_EXTRACT_DEPTH: usize = 16;

pub(super) fn parse_extract(expr: &NodeEnum, depth: usize) -> Option<JsonExtract> {
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
    if !JSON_EXTRACT_FUNCTIONS.contains(&name.as_str()) {
        return None;
    }
    let as_text = name.ends_with("_text");
    let (first, rest) = call.args.split_first()?;
    if rest.is_empty() {
        return None;
    }
    let mut key_segments = Vec::with_capacity(rest.len());
    for arg in rest {
        // Function forms take text keys, never integer array indices.
        let mut arg_expr = arg.node.as_ref()?;
        loop {
            match arg_expr {
                NodeEnum::TypeCast(cast) => {
                    arg_expr = cast.arg.as_ref()?.node.as_ref()?;
                }
                NodeEnum::CollateClause(collate) => {
                    arg_expr = collate.arg.as_ref()?.node.as_ref()?;
                }
                NodeEnum::AConst(constant) => {
                    let pg_query::protobuf::a_const::Val::Sval(s) = constant.val.as_ref()? else {
                        return None;
                    };
                    key_segments.push(JsonExtractPathSegment {
                        value: s.sval.clone(),
                        navigation: JsonPathNavigation::Ambiguous,
                    });
                    break;
                }
                _ => return None,
            }
        }
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
            navigation: JsonPathNavigation::ObjectKey,
        }),
        pg_query::protobuf::a_const::Val::Ival(i) => {
            if i.ival < 0 {
                return None;
            }
            Some(JsonExtractPathSegment {
                value: i.ival.to_string(),
                navigation: JsonPathNavigation::ArrayIndex,
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
            // Every `#>` operand is text[]. Even a digit selects an object key
            // when its runtime parent is an object, so syntax cannot promote
            // it to an array wildcard.
            segment.navigation = JsonPathNavigation::Ambiguous;
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
        out.push(JsonExtractPathSegment {
            value: value.to_string(),
            navigation: JsonPathNavigation::Ambiguous,
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
            if !schema.sval.eq_ignore_ascii_case("pg_catalog") {
                return None;
            }
            function_name(std::slice::from_ref(name))
        }
        _ => None,
    }
}
