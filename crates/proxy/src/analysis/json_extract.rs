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
use pg_query::protobuf::{Node, SelectStmt};

use super::safety::unwrap_star_over_subquery;
use super::StatementInspection;
pub use crate::json_path::JsonPathNavigation;

mod parse;
use parse::parse_extract;

/// One RFC-6901-style path segment taken from a literal JSON operator key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonExtractPathSegment {
    pub value: String,
    /// What the SQL syntax proves about navigation at this segment.
    ///
    /// `#>` and `jsonb_extract_path` take text paths whose digit segments mean
    /// an array index only when the runtime parent is an array. Analysis does
    /// not have that value, so it records [`JsonPathNavigation::Ambiguous`]
    /// rather than letting syntax guess which pointer wildcard applies.
    pub navigation: JsonPathNavigation,
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
