//! Catalog attribution for allowlisted JSON extracts.
//!
//! Syntax lives in `analysis::json_extract`. This module is the catalog half:
//! unique owner, classified source, then a pointer-prefixed [`MaskSpec`]. A
//! missing path must not look like a release — same state machine as summaries.

use std::collections::HashSet;

use crate::analysis::{self, Safety};
use crate::catalog::Snapshot;
use crate::mask::JsonPathNavigation;

use super::ExpressionPolicy;

/// Resolve every result field to one JSON-extract policy state.
///
/// Only [`Safety::JsonExtract`] fields with a literal path on one uniquely
/// owned, schema-qualified column reach a mask. Joins are allowed when every
/// range is schema-qualified; a subquery in FROM collapses the statement.
pub(crate) fn resolve_json_extract_policies(
    inspection: Option<&analysis::StatementInspection<'_>>,
    field_count: usize,
    safety: &[Safety],
    snapshot: &Snapshot,
    roles: &HashSet<String>,
) -> Vec<ExpressionPolicy> {
    let resolution = inspection.and_then(|value| value.json_extract_resolution(field_count));
    (0..field_count)
        .map(|index| {
            if safety.get(index) != Some(&Safety::JsonExtract) {
                return ExpressionPolicy::NotApplicable;
            }
            let Some(resolution) = resolution.as_ref() else {
                return ExpressionPolicy::Opaque;
            };
            let Some(argument) = resolution.fields().get(index) else {
                return ExpressionPolicy::Opaque;
            };
            resolve_json_extract_source(snapshot, resolution.relations(), argument, roles)
        })
        .collect()
}

fn resolve_json_extract_source(
    snapshot: &Snapshot,
    relations: &[analysis::QualifiedFrom],
    argument: &analysis::JsonExtractArgument,
    roles: &HashSet<String>,
) -> ExpressionPolicy {
    let analysis::JsonExtractArgument::Extract(extract) = argument else {
        return ExpressionPolicy::Opaque;
    };
    let Some(owner) = unique_extract_owner(snapshot, relations, &extract.column) else {
        return ExpressionPolicy::Opaque;
    };
    let qualified = owner.qualified_name();
    let column = extract.column.column_name();
    let Some(classification) = snapshot.lookup_by_name(&qualified, column) else {
        return ExpressionPolicy::Opaque;
    };
    let spec = classification.for_roles(roles);
    if spec.is_passthrough() {
        return ExpressionPolicy::Released;
    }
    let path: Vec<(String, JsonPathNavigation)> = extract
        .path
        .iter()
        .map(|segment| (segment.value.clone(), segment.navigation))
        .collect();
    if extract.as_text {
        spec.json_text_extract_spec(&path)
            .map_or(ExpressionPolicy::Opaque, |spec| ExpressionPolicy::Masked {
                spec,
                projection: None,
            })
    } else {
        spec.json_document_projection(&path)
            .map_or(ExpressionPolicy::Opaque, |projection| {
                ExpressionPolicy::Masked {
                    spec: spec.clone(),
                    projection: Some(projection),
                }
            })
    }
}

fn unique_extract_owner<'a>(
    snapshot: &Snapshot,
    relations: &'a [analysis::QualifiedFrom],
    column: &analysis::JsonExtractColumn,
) -> Option<&'a analysis::QualifiedFrom> {
    match column {
        analysis::JsonExtractColumn::Bare(name) => {
            let mut owner = None;
            let mut n = 0usize;
            for relation in relations {
                if snapshot
                    .lookup_by_name(&relation.qualified_name(), name)
                    .is_some()
                    || snapshot
                        .relation_columns(&relation.qualified_name())
                        .is_some_and(|cols| cols.iter().any(|c| c == name))
                {
                    n = n.saturating_add(1);
                    owner = Some(relation);
                }
            }
            (n == 1).then_some(owner).flatten()
        }
        analysis::JsonExtractColumn::Named {
            relation,
            column: _,
        } => {
            let mut owner = None;
            let mut n = 0usize;
            for candidate in relations {
                let matches_alias = candidate.alias.as_deref() == Some(relation.as_str());
                let matches_rel = candidate.relname == *relation;
                if matches_alias || matches_rel {
                    n = n.saturating_add(1);
                    owner = Some(candidate);
                }
            }
            (n == 1).then_some(owner).flatten()
        }
        analysis::JsonExtractColumn::Qualified {
            schema,
            relation,
            column: _,
        } => {
            let matches: Vec<_> = relations
                .iter()
                .filter(|candidate| candidate.schema == *schema && candidate.relname == *relation)
                .collect();
            match matches.as_slice() {
                [only] => Some(*only),
                _ => None,
            }
        }
    }
}
