//! Catalog-time checks for `mask = "json"` pointer tables.
//!
//! Duplicate pointers and equally-specific overlapping wildcards are startup
//! errors: config order must not decide a disclosure. Recursive `json` as a
//! nested pointer mask is refused because one walker already owns the document.

use anyhow::{bail, Result};

use crate::mask::{JsonFieldSpec, Mask, MaskSpec, MAX_JSON_MAX_DEPTH};

use super::validate_spec;

pub(super) fn validate_json_spec(spec: &MaskSpec, what: &str) -> Result<()> {
    if spec.json_max_bytes == 0 {
        bail!("{what}: json_max_bytes must be at least 1");
    }
    if spec.json_max_depth == 0 || spec.json_max_depth > MAX_JSON_MAX_DEPTH {
        bail!(
            "{what}: json_max_depth must be between 1 and {MAX_JSON_MAX_DEPTH}, got {}",
            spec.json_max_depth
        );
    }
    for (index, field) in spec.json.iter().enumerate() {
        if field.spec.kind == Mask::Json {
            bail!(
                "{what}: JSON pointer {:?} cannot recursively use mask `json`",
                field.pointer
            );
        }
        validate_spec(
            &field.spec,
            &format!("{what} JSON pointer {:?}", field.pointer),
        )?;
        if spec
            .json
            .iter()
            .take(index)
            .any(|earlier| earlier.segments == field.segments)
        {
            bail!("{what}: duplicate JSON pointer {:?}", field.pointer);
        }
        if spec.json.iter().take(index).any(|earlier| {
            json_pointer_patterns_overlap(earlier, field)
                && json_pointer_wildcards(earlier) == json_pointer_wildcards(field)
        }) {
            bail!(
                "{what}: JSON pointer {:?} ambiguously overlaps another equally-specific \
                 wildcard pointer",
                field.pointer
            );
        }
    }
    Ok(())
}

fn json_pointer_wildcards(field: &JsonFieldSpec) -> usize {
    field
        .segments
        .iter()
        .filter(|segment| segment.as_str() == "*")
        .count()
}

/// Whether one path can match both patterns. Equal-specificity overlaps would
/// otherwise make config order decide which mask wins for that path — a release
/// direction hidden in TOML ordering — so validation refuses them.
fn json_pointer_patterns_overlap(left: &JsonFieldSpec, right: &JsonFieldSpec) -> bool {
    left.segments.len() == right.segments.len()
        && left
            .segments
            .iter()
            .zip(right.segments.iter())
            .all(|(a, b)| a == b || a == "*" || b == "*")
}
