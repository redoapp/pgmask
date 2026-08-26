//! Structure-aware JSON / JSONB masking.
//!
//! Pointer policy, the lookup trie, document walking, extract prefixes, and
//! the byte/depth preflight live here so `mask.rs` stays the capability table
//! and the per-type algorithms. Policy still binds to a stored column; this
//! module only walks a value the plan already classified as [`Mask::Json`].

use std::collections::HashMap;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::json_path::JsonPathNavigation;

use super::{
    Mask, MaskError, MaskSpec, Masker, FORMAT_BINARY, FORMAT_TEXT, OID_BOOL, OID_JSONB, OID_NUMERIC,
};

pub const DEFAULT_JSON_MAX_BYTES: usize = 1_048_576;
pub const DEFAULT_JSON_MAX_DEPTH: usize = 64;
pub const MAX_JSON_MAX_DEPTH: usize = 128;

/// One pre-parsed JSON Pointer and the policy inherited by that subtree.
///
/// Kept on [`MaskSpec`] rather than in the catalog module because plans clone
/// specs and apply them without consulting mutable configuration state.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonFieldSpec {
    pub pointer: Arc<str>,
    pub segments: Arc<[String]>,
    pub spec: MaskSpec,
}

/// Policy for a scalar leaf not covered by a JSON Pointer rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum JsonUnmatched {
    /// Replace every unmatched scalar with JSON null.
    #[default]
    Null,
    /// Preserve the scalar type without preserving its value.
    TypePlaceholders,
    /// Pass unmatched scalar values through unchanged.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonPathSegment {
    value: String,
    navigation: JsonPathNavigation,
}

/// Where a JSON value sits inside the classified stored document.
///
/// This is plan context, not mask configuration. A [`MaskSpec`] describes the
/// column's policy independent of which SQL projection produced one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonProjection {
    path: Arc<[JsonPathSegment]>,
}

impl JsonFieldSpec {
    pub fn new(pointer: impl Into<Arc<str>>, spec: MaskSpec) -> Result<Self, &'static str> {
        let pointer = pointer.into();
        if pointer.is_empty() {
            return Err("the root pointer is not allowed; configure exact fields");
        }
        let Some(encoded) = pointer.strip_prefix('/') else {
            return Err("a JSON Pointer must start with `/`");
        };
        let mut segments = Vec::new();
        for segment in encoded.split('/') {
            let mut decoded = String::with_capacity(segment.len());
            let mut chars = segment.chars();
            while let Some(ch) = chars.next() {
                if ch != '~' {
                    decoded.push(ch);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return Err("a JSON Pointer may escape only `~0` and `~1`"),
                }
            }
            segments.push(decoded);
        }
        Ok(Self {
            pointer,
            segments: segments.into(),
            spec,
        })
    }

    fn wildcard_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|segment| segment.as_str() == "*")
            .count()
    }
}

/// Compiled JSON Pointer policy.
///
/// Matching follows only exact and array-wildcard edges for the current path;
/// it never scans the complete rule list. More-specific pointer inheritance is
/// still resolved by the caller as it descends the document.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct JsonPolicyTrie {
    root: JsonPolicyNode,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct JsonPolicyNode {
    policy: Option<JsonTriePolicy>,
    children: HashMap<String, JsonPolicyNode>,
}

#[derive(Debug, Clone, PartialEq)]
struct JsonTriePolicy {
    spec: MaskSpec,
    wildcard_count: usize,
}

impl JsonPolicyTrie {
    fn compile(fields: &[JsonFieldSpec]) -> Self {
        let mut trie = Self::default();
        for field in fields {
            let mut node = &mut trie.root;
            for segment in field.segments.iter() {
                node = node.children.entry(segment.clone()).or_default();
            }
            node.policy = Some(JsonTriePolicy {
                spec: field.spec.clone(),
                wildcard_count: field.wildcard_count(),
            });
        }
        trie
    }

    fn policy_at<'a>(&'a self, path: &[JsonPathSegment]) -> Option<&'a MaskSpec> {
        let states = self.states_at(path);
        states
            .into_iter()
            .filter_map(|node| node.policy.as_ref())
            .min_by_key(|policy| policy.wildcard_count)
            .map(|policy| &policy.spec)
    }

    fn has_descendants_at(&self, path: &[JsonPathSegment]) -> bool {
        self.states_at(path)
            .into_iter()
            .any(|node| !node.children.is_empty())
    }

    /// Whether a text path could enter an array-wildcard branch depending on
    /// the runtime JSON shape. The proxy does not have the parent value when it
    /// plans an extract, so choosing that branch would make SQL syntax decide a
    /// disclosure. Refusal is the only shape-independent answer.
    fn has_ambiguous_wildcard(&self, path: &[JsonPathSegment]) -> bool {
        let mut states = vec![&self.root];
        for segment in path {
            if segment.navigation == JsonPathNavigation::Ambiguous
                && states.iter().any(|node| node.children.contains_key("*"))
            {
                return true;
            }
            states = Self::next_states(states, segment);
            if states.is_empty() {
                break;
            }
        }
        false
    }

    fn states_at<'a>(&'a self, path: &[JsonPathSegment]) -> Vec<&'a JsonPolicyNode> {
        let mut states = vec![&self.root];
        for segment in path {
            states = Self::next_states(states, segment);
            if states.is_empty() {
                break;
            }
        }
        states
    }

    fn next_states<'a>(
        states: Vec<&'a JsonPolicyNode>,
        segment: &JsonPathSegment,
    ) -> Vec<&'a JsonPolicyNode> {
        let mut next = Vec::with_capacity(states.len().saturating_mul(2));
        for node in states {
            if let Some(exact) = node.children.get(&segment.value) {
                next.push(exact);
            }
            if segment.navigation == JsonPathNavigation::ArrayIndex {
                if let Some(wildcard) = node.children.get("*") {
                    next.push(wildcard);
                }
            }
        }
        next
    }
}

impl MaskSpec {
    /// Install pointer rules and compile their lookup trie once.
    pub(crate) fn set_json_fields(&mut self, fields: Vec<JsonFieldSpec>) {
        self.json_trie = Arc::new(JsonPolicyTrie::compile(&fields));
        self.json = fields.into();
    }

    /// Bind this JSON column policy to an extracted subtree (`payload->'a'`).
    ///
    /// The stored document's pointer table is kept; the walk starts at `path`
    /// so child overrides still apply. `path` must not be empty — the full
    /// column is the ordinary `Mask::Json` plan.
    pub(crate) fn json_document_projection(
        &self,
        path: &[(String, JsonPathNavigation)],
    ) -> Option<JsonProjection> {
        if self.kind != Mask::Json || path.is_empty() {
            return None;
        }
        let path = path_segments(path);
        if self.json_trie.has_ambiguous_wildcard(&path) {
            return None;
        }
        Some(JsonProjection { path })
    }

    /// Bind this JSON column policy to a text extract (`payload->>'email'`).
    ///
    /// Text extracts cannot walk children: the backend has already serialized
    /// the node. A path with any more-specific pointer therefore refuses
    /// rather than apply `none` to a blob that still contains masked leaves.
    /// Unmatched paths become SQL NULL, matching the default JSON leaf.
    pub(crate) fn json_text_extract_spec(
        &self,
        path: &[(String, JsonPathNavigation)],
    ) -> Option<Self> {
        if self.kind != Mask::Json || path.is_empty() {
            return None;
        }
        let segments = path_segments(path);
        if self.json_trie.has_ambiguous_wildcard(&segments)
            || self.json_trie.has_descendants_at(&segments)
        {
            return None;
        }
        match self.policy_along(&segments) {
            Some(spec) if spec.kind == Mask::Json => None,
            Some(spec) => Some(spec.clone()),
            None => match self.json_unmatched {
                JsonUnmatched::None => Some(Self::new(Mask::None)),
                JsonUnmatched::Null | JsonUnmatched::TypePlaceholders => {
                    Some(Self::new(Mask::Null))
                }
            },
        }
    }

    fn policy_along(&self, path: &[JsonPathSegment]) -> Option<&MaskSpec> {
        let mut inherited = None;
        let mut walked = Vec::with_capacity(path.len());
        for segment in path {
            walked.push(segment.clone());
            inherited = self.json_trie.policy_at(&walked).or(inherited);
        }
        inherited
    }
}

impl Masker {
    /// Decode one JSON document, walk arbitrary objects and arrays, and apply
    /// exact path policies plus a default policy to all remaining leaves.
    ///
    /// Object keys and array shape are preserved. Values are not: the
    /// `json_unmatched` policy governs leaves with no pointer policy.
    pub(super) fn mask_json(
        &self,
        spec: &MaskSpec,
        projection: Option<&JsonProjection>,
        type_oid: u32,
        format: i16,
        bytes: &[u8],
    ) -> Result<Bytes, MaskError> {
        let payload = if type_oid == OID_JSONB && format == FORMAT_BINARY {
            match bytes.split_first() {
                Some((1, payload)) => payload,
                _ => return Err(MaskError::Undecodable { type_oid, format }),
            }
        } else {
            bytes
        };
        if payload.len() > spec.json_max_bytes {
            return Err(MaskError::JsonLimitExceeded {
                limit: JsonLimit::Bytes,
                configured: spec.json_max_bytes,
            });
        }
        if json_nesting_exceeds(payload, spec.json_max_depth) {
            return Err(MaskError::JsonLimitExceeded {
                limit: JsonLimit::Depth,
                configured: spec.json_max_depth,
            });
        }
        let mut value: JsonValue = serde_json::from_slice(payload)
            .map_err(|_| MaskError::Undecodable { type_oid, format })?;
        let mut path: Vec<JsonPathSegment> = projection
            .map(|value| value.path.iter().cloned().collect())
            .unwrap_or_default();
        let inherited = spec.policy_along(&path);
        self.mask_json_node(spec, &mut path, inherited, &mut value)?;

        let encoded =
            serde_json::to_vec(&value).map_err(|_| MaskError::Undecodable { type_oid, format })?;
        if type_oid == OID_JSONB && format == FORMAT_BINARY {
            let mut out = BytesMut::with_capacity(encoded.len().saturating_add(1));
            out.extend_from_slice(&[1]);
            out.extend_from_slice(&encoded);
            Ok(out.freeze())
        } else {
            Ok(Bytes::from(encoded))
        }
    }

    fn mask_json_node(
        &self,
        json_spec: &MaskSpec,
        path: &mut Vec<JsonPathSegment>,
        inherited: Option<&MaskSpec>,
        value: &mut JsonValue,
    ) -> Result<(), MaskError> {
        // The trie follows only path-relevant exact / array-wildcard edges.
        // Catalog validation rejects equally-specific overlap, so this lookup
        // cannot let configuration order choose disclosure.
        let policy = json_spec.json_trie.policy_at(path).or(inherited);

        match value {
            JsonValue::Object(map) => {
                for (key, child) in map {
                    path.push(JsonPathSegment {
                        value: key.clone(),
                        navigation: JsonPathNavigation::ObjectKey,
                    });
                    self.mask_json_node(json_spec, path, policy, child)?;
                    path.pop();
                }
                Ok(())
            }
            JsonValue::Array(values) => {
                for (index, child) in values.iter_mut().enumerate() {
                    path.push(JsonPathSegment {
                        value: index.to_string(),
                        navigation: JsonPathNavigation::ArrayIndex,
                    });
                    self.mask_json_node(json_spec, path, policy, child)?;
                    path.pop();
                }
                Ok(())
            }
            _ => {
                *value = match policy {
                    Some(policy) => self.mask_json_value(policy, value)?,
                    None if json_spec.json_unmatched == JsonUnmatched::TypePlaceholders => {
                        match value {
                            JsonValue::String(_) => JsonValue::String(String::new()),
                            JsonValue::Number(_) => JsonValue::Number(0.into()),
                            JsonValue::Bool(_) => JsonValue::Bool(false),
                            JsonValue::Null => JsonValue::Null,
                            JsonValue::Array(_) | JsonValue::Object(_) => {
                                unreachable!("containers recurse above")
                            }
                        }
                    }
                    None if json_spec.json_unmatched == JsonUnmatched::None => value.clone(),
                    None => JsonValue::Null,
                };
                Ok(())
            }
        }
    }

    fn mask_json_value(&self, spec: &MaskSpec, value: &JsonValue) -> Result<JsonValue, MaskError> {
        if value.is_null() || spec.kind == Mask::Null {
            return Ok(JsonValue::Null);
        }
        if spec.kind == Mask::None {
            return Ok(value.clone());
        }
        if matches!(value, JsonValue::Array(_) | JsonValue::Object(_)) {
            return Err(MaskError::Unsupported {
                type_oid: OID_JSONB,
                format: FORMAT_TEXT,
                kind: spec.kind,
            });
        }
        if spec.kind == Mask::Json {
            return Err(MaskError::Unsupported {
                type_oid: OID_JSONB,
                format: FORMAT_TEXT,
                kind: spec.kind,
            });
        }

        let (type_oid, input) = match value {
            JsonValue::String(text) => (25, Bytes::copy_from_slice(text.as_bytes())),
            JsonValue::Number(number) => {
                (OID_NUMERIC, Bytes::from(number.to_string().into_bytes()))
            }
            JsonValue::Bool(value) => (
                OID_BOOL,
                Bytes::from_static(if *value { b"true" } else { b"false" }),
            ),
            JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => {
                unreachable!("handled above")
            }
        };
        let masked = self.apply(spec, type_oid, FORMAT_TEXT, Some(input))?;
        let Some(masked) = masked else {
            return Ok(JsonValue::Null);
        };
        match value {
            JsonValue::String(_) => String::from_utf8(masked.to_vec())
                .map(JsonValue::String)
                .map_err(|_| MaskError::Undecodable {
                    type_oid,
                    format: FORMAT_TEXT,
                }),
            JsonValue::Number(_) => serde_json::from_slice::<JsonValue>(&masked)
                .ok()
                .filter(JsonValue::is_number)
                .ok_or(MaskError::Undecodable {
                    type_oid,
                    format: FORMAT_TEXT,
                }),
            JsonValue::Bool(_) => serde_json::from_slice::<JsonValue>(&masked)
                .ok()
                .filter(JsonValue::is_boolean)
                .ok_or(MaskError::Undecodable {
                    type_oid,
                    format: FORMAT_TEXT,
                }),
            JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => {
                unreachable!("handled above")
            }
        }
    }
}

/// Check JSON object/array nesting before `serde_json` allocates a value tree.
///
/// This is a lexical preflight, not a second parser. Brackets inside strings
/// and escaped quotes are ignored; malformed JSON proceeds to `serde_json` and
/// is refused as undecodable. Returning `true` on arithmetic doubt is the
/// fail-closed direction.
fn json_nesting_exceeds(bytes: &[u8], max_depth: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                let Some(next) = depth.checked_add(1) else {
                    return true;
                };
                depth = next;
                if depth > max_depth {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

fn path_segments(path: &[(String, JsonPathNavigation)]) -> Arc<[JsonPathSegment]> {
    path.iter()
        .map(|(value, navigation)| JsonPathSegment {
            value: value.clone(),
            navigation: *navigation,
        })
        .collect::<Vec<_>>()
        .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonLimit {
    Bytes,
    Depth,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::{
        json_nesting_exceeds, path_segments, JsonFieldSpec, JsonLimit, JsonPathNavigation,
        JsonPolicyTrie, JsonProjection, JsonUnmatched, Mask, MaskError, MaskSpec, Masker,
        FORMAT_BINARY, FORMAT_TEXT, OID_JSONB,
    };
    use crate::mask::OID_JSON;
    use bytes::Bytes;
    use serde_json::Value as JsonValue;

    fn masker() -> Masker {
        Masker::new(b"test-key".to_vec())
    }

    fn json_spec(default: Mask, fields: Vec<(&str, MaskSpec)>) -> MaskSpec {
        let mut spec = MaskSpec::new(Mask::Json);
        spec.json_unmatched = match default {
            Mask::Null => JsonUnmatched::Null,
            Mask::None => JsonUnmatched::None,
            _ => panic!("test helper supports null or none unmatched policy"),
        };
        let fields = fields
            .into_iter()
            .map(|(pointer, field)| JsonFieldSpec::new(pointer, field).unwrap())
            .collect();
        spec.set_json_fields(fields);
        spec
    }

    fn apply_json(spec: &MaskSpec, oid: u32, format: i16, value: &[u8]) -> JsonValue {
        apply_json_projection(spec, None, oid, format, value)
    }

    fn apply_json_projection(
        spec: &MaskSpec,
        projection: Option<&JsonProjection>,
        oid: u32,
        format: i16,
        value: &[u8],
    ) -> JsonValue {
        let out = masker()
            .apply_planned(
                spec,
                None,
                projection,
                oid,
                format,
                Some(Bytes::copy_from_slice(value)),
            )
            .unwrap()
            .unwrap();
        let payload = if oid == OID_JSONB && format == FORMAT_BINARY {
            assert_eq!(out[0], 1, "jsonb binary version");
            &out[1..]
        } else {
            &out[..]
        };
        serde_json::from_slice(payload).unwrap()
    }

    #[test]
    fn json_masks_arbitrary_nested_fields_and_defaults_every_other_leaf_to_null() {
        let mut email = MaskSpec::new(Mask::Partial);
        email.keep = 4;
        let mut age = MaskSpec::new(Mask::NumericBucket);
        age.bucket = 10;
        let spec = json_spec(
            Mask::Null,
            vec![
                ("/profile/email", email),
                ("/profile/age", age),
                ("/profile/flags/0", MaskSpec::new(Mask::None)),
                ("/public", MaskSpec::new(Mask::None)),
            ],
        );
        let output = apply_json(
            &spec,
            OID_JSONB,
            FORMAT_TEXT,
            br#"{
                "profile": {
                    "email": "secret@example.com",
                    "name": "Alice",
                    "age": 27,
                    "flags": [true, false]
                },
                "public": "Portland",
                "new_field": {"secret": "must not pass"}
            }"#,
        );
        assert_eq!(
            output,
            serde_json::json!({
                "profile": {
                    "email": "**************.com",
                    "name": null,
                    "age": 20,
                    "flags": [true, null]
                },
                "public": "Portland",
                "new_field": {"secret": null}
            })
        );
    }

    #[test]
    fn json_unmatched_none_preserves_unmentioned_nested_values_only_when_explicit() {
        let spec = json_spec(Mask::None, vec![("/private", MaskSpec::new(Mask::Redact))]);
        let output = apply_json(
            &spec,
            OID_JSON,
            FORMAT_TEXT,
            br#"{"private":"secret","arbitrary":{"nested":[1,true,"kept"]}}"#,
        );
        assert_eq!(
            output,
            serde_json::json!({
                "private": "***",
                "arbitrary": {"nested": [1, true, "kept"]}
            })
        );
    }

    #[test]
    fn json_subtree_release_is_inherited_and_more_specific_policies_win() {
        let spec = json_spec(
            Mask::Null,
            vec![
                ("/released", MaskSpec::new(Mask::None)),
                ("/released/private/token", MaskSpec::new(Mask::Redact)),
            ],
        );
        let output = apply_json(
            &spec,
            OID_JSONB,
            FORMAT_TEXT,
            br#"{
                "released": {
                    "future_field": "kept without listing it",
                    "items": [1, true, {"also_future": "kept"}],
                    "private": {"token": "secret", "note": "also kept"}
                },
                "outside": {"secret": "hidden"}
            }"#,
        );
        assert_eq!(
            output,
            serde_json::json!({
                "released": {
                    "future_field": "kept without listing it",
                    "items": [1, true, {"also_future": "kept"}],
                    "private": {"token": "***", "note": "also kept"}
                },
                "outside": {"secret": null}
            })
        );
    }

    #[test]
    fn json_array_wildcard_masks_every_element_and_exact_index_wins() {
        let spec = json_spec(
            Mask::Null,
            vec![
                ("/items/*/city", MaskSpec::new(Mask::None)),
                ("/items/*/token", MaskSpec::new(Mask::Redact)),
                ("/items/1/city", MaskSpec::new(Mask::Redact)),
                ("/*", MaskSpec::new(Mask::None)),
            ],
        );
        let output = apply_json(
            &spec,
            OID_JSONB,
            FORMAT_TEXT,
            br#"{
                "items": [
                    {"city":"Denver","token":"one","unknown":"hidden"},
                    {"city":"Seattle","token":"two","unknown":"hidden"}
                ],
                "*":"literal object key",
                "other":"hidden"
            }"#,
        );
        assert_eq!(
            output,
            serde_json::json!({
                "items": [
                    {"city":"Denver","token":"***","unknown":null},
                    {"city":"***","token":"***","unknown":null}
                ],
                "*":"literal object key",
                "other":null
            })
        );
    }

    #[test]
    fn json_unmatched_type_placeholders_keep_shape_without_leaf_values() {
        let mut spec = json_spec(Mask::Null, Vec::new());
        spec.json_unmatched = JsonUnmatched::TypePlaceholders;
        let output = apply_json(
            &spec,
            OID_JSONB,
            FORMAT_TEXT,
            br#"{
                "string":"secret",
                "integer":42,
                "decimal":3.14,
                "boolean":true,
                "nothing":null,
                "nested":[{"value":"secret"},7,false]
            }"#,
        );
        assert_eq!(
            output,
            serde_json::json!({
                "string":"",
                "integer":0,
                "decimal":0,
                "boolean":false,
                "nothing":null,
                "nested":[{"value":""},0,false]
            })
        );
    }

    #[test]
    fn json_document_extract_starts_the_walk_at_the_extracted_path() {
        let mut email = MaskSpec::new(Mask::Partial);
        email.keep = 4;
        let spec = json_spec(
            Mask::Null,
            vec![
                ("/profile", MaskSpec::new(Mask::None)),
                ("/profile/email", email),
                ("/profile/name", MaskSpec::new(Mask::Redact)),
            ],
        );
        let projection = spec
            .json_document_projection(&[("profile".into(), JsonPathNavigation::ObjectKey)])
            .unwrap();
        let output = apply_json_projection(
            &spec,
            Some(&projection),
            OID_JSONB,
            FORMAT_TEXT,
            br#"{"email":"CANARY_EMAIL_a1b2c3","name":"CANARY_NAME_d4e5f6","extra":"secret"}"#,
        );
        assert_eq!(
            output,
            serde_json::json!({
                "email":"***************b2c3",
                "name":"***",
                "extra":"secret"
            })
        );
    }

    #[test]
    fn json_text_extract_refuses_a_path_that_still_has_child_policies() {
        let spec = json_spec(
            Mask::Null,
            vec![
                ("/profile", MaskSpec::new(Mask::None)),
                ("/profile/email", MaskSpec::new(Mask::Redact)),
            ],
        );
        assert!(spec
            .json_text_extract_spec(&[("profile".into(), JsonPathNavigation::ObjectKey)])
            .is_none());
        let leaf = spec
            .json_text_extract_spec(&[
                ("profile".into(), JsonPathNavigation::ObjectKey),
                ("email".into(), JsonPathNavigation::ObjectKey),
            ])
            .unwrap();
        assert_eq!(leaf.kind, Mask::Redact);
    }

    #[test]
    fn ambiguous_text_paths_never_choose_an_array_wildcard() {
        let spec = json_spec(
            Mask::Null,
            vec![("/items/*/token", MaskSpec::new(Mask::None))],
        );
        let ambiguous = [
            ("items".into(), JsonPathNavigation::Ambiguous),
            ("0".into(), JsonPathNavigation::Ambiguous),
            ("token".into(), JsonPathNavigation::Ambiguous),
        ];
        assert!(
            spec.json_text_extract_spec(&ambiguous).is_none(),
            "#> text paths cannot prove that numeric object keys are array indices"
        );
        assert!(
            spec.json_document_projection(&ambiguous).is_none(),
            "a document prefix must not guess which wildcard branch to inherit"
        );

        let proven = [
            ("items".into(), JsonPathNavigation::ObjectKey),
            ("0".into(), JsonPathNavigation::ArrayIndex),
            ("token".into(), JsonPathNavigation::ObjectKey),
        ];
        assert_eq!(
            spec.json_text_extract_spec(&proven).unwrap().kind,
            Mask::None
        );
    }

    #[test]
    fn json_limits_refuse_before_unbounded_parsing() {
        let mut byte_limited = json_spec(Mask::Null, Vec::new());
        byte_limited.json_max_bytes = 8;
        let oversized_and_malformed = br#"{"not even complete""#;
        assert_eq!(
            masker().apply(
                &byte_limited,
                OID_JSONB,
                FORMAT_TEXT,
                Some(Bytes::from_static(oversized_and_malformed)),
            ),
            Err(MaskError::JsonLimitExceeded {
                limit: JsonLimit::Bytes,
                configured: 8,
            }),
            "the byte limit runs before serde_json parses or allocates"
        );

        let mut depth_limited = json_spec(Mask::Null, Vec::new());
        depth_limited.json_max_depth = 3;
        let too_deep = br#"{"a":[{"b":[1]}],"brackets":"[[[["}"#;
        assert_eq!(
            masker().apply(
                &depth_limited,
                OID_JSONB,
                FORMAT_TEXT,
                Some(Bytes::from_static(too_deep)),
            ),
            Err(MaskError::JsonLimitExceeded {
                limit: JsonLimit::Depth,
                configured: 3,
            })
        );
        assert!(
            !json_nesting_exceeds(br#"{"brackets":"[[[[","quote":"\\\""}"#, 1),
            "brackets and escaped quotes inside strings are not nesting"
        );
    }

    #[test]
    fn compiled_json_trie_keeps_exact_over_wildcard_precedence() {
        let mut fields = (0..512)
            .map(|index| (format!("/irrelevant/{index}"), MaskSpec::new(Mask::None)))
            .collect::<Vec<_>>();
        fields.push(("/items/*/token".to_string(), MaskSpec::new(Mask::Redact)));
        fields.push(("/items/0/token".to_string(), MaskSpec::new(Mask::None)));
        let spec = json_spec(
            Mask::Null,
            fields
                .iter()
                .map(|(pointer, spec)| (pointer.as_str(), spec.clone()))
                .collect(),
        );
        let output = apply_json(
            &spec,
            OID_JSONB,
            FORMAT_TEXT,
            br#"{"items":[{"token":"first"},{"token":"second"}]}"#,
        );
        assert_eq!(
            output,
            serde_json::json!({"items":[{"token":"first"},{"token":"***"}]})
        );
    }

    #[test]
    fn json_array_wildcard_has_no_index_horizon() {
        let mut spec = json_spec(
            Mask::Null,
            vec![("/items/*/account_id", MaskSpec::new(Mask::Redact))],
        );
        spec.json_unmatched = JsonUnmatched::TypePlaceholders;
        let input = serde_json::json!({
            "items": (0..512)
                .map(|index| serde_json::json!({
                    "account_id": format!("secret-{index}"),
                    "sequence": index,
                    "active": true
                }))
                .collect::<Vec<_>>()
        });
        let encoded = serde_json::to_vec(&input).unwrap();
        let output = apply_json(&spec, OID_JSONB, FORMAT_TEXT, &encoded);
        let items = output["items"].as_array().unwrap();
        assert_eq!(items.len(), 512);
        for item in items {
            assert_eq!(item["account_id"], "***");
            assert_eq!(item["sequence"], 0);
            assert_eq!(item["active"], false);
        }
    }

    #[test]
    fn jsonb_binary_version_and_nested_policy_round_trip() {
        let spec = json_spec(Mask::Null, vec![("/email", MaskSpec::new(Mask::Redact))]);
        let mut input = vec![1];
        input.extend_from_slice(br#"{"email":"secret","other":"hidden"}"#);
        let output = apply_json(&spec, OID_JSONB, FORMAT_BINARY, &input);
        assert_eq!(output, serde_json::json!({"email": "***", "other": null}));

        let malformed = masker().apply(
            &spec,
            OID_JSONB,
            FORMAT_BINARY,
            Some(Bytes::from_static(b"\x02{}")),
        );
        assert!(malformed.is_err(), "an unknown jsonb version must refuse");
    }

    #[test]
    fn json_binary_format_is_json_text_without_a_version_byte() {
        let spec = json_spec(Mask::Null, vec![("/email", MaskSpec::new(Mask::Redact))]);
        let output = apply_json(
            &spec,
            OID_JSON,
            FORMAT_BINARY,
            br#"{"email":"secret","other":"hidden"}"#,
        );
        assert_eq!(output, serde_json::json!({"email": "***", "other": null}));
    }

    #[test]
    fn json_leaf_type_mismatch_refuses_instead_of_passing_the_value() {
        let spec = json_spec(Mask::Null, vec![("/email", MaskSpec::new(Mask::Partial))]);
        let result = masker().apply(
            &spec,
            OID_JSONB,
            FORMAT_TEXT,
            Some(Bytes::from_static(br#"{"email":12345}"#)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn json_pointer_escapes_address_literal_key_characters() {
        let spec = json_spec(Mask::Null, vec![("/a~1b/~0key", MaskSpec::new(Mask::None))]);
        let output = apply_json(
            &spec,
            OID_JSON,
            FORMAT_TEXT,
            br#"{"a/b":{"~key":"visible","other":"hidden"}}"#,
        );
        assert_eq!(
            output,
            serde_json::json!({"a/b": {"~key": "visible", "other": null}})
        );
    }

    /// Direct contract for [`JsonPolicyTrie`]: compile, `policy_at`,
    /// `has_ambiguous_wildcard`, and `has_descendants_at`.
    ///
    /// Walker tests still prove disclosure on a document. This table names the
    /// NFA edges so a wrong `*` follow, exact/wildcard tie-break, or descendant
    /// check fails without a JSON blob to decode.
    #[test]
    fn json_policy_trie_lookup_table() {
        use JsonPathNavigation::{Ambiguous, ArrayIndex, ObjectKey};

        #[derive(Debug)]
        enum Policy {
            Kind(Mask),
            Miss,
        }

        struct Case {
            name: &'static str,
            pointers: &'static [(&'static str, Mask)],
            path: &'static [(&'static str, JsonPathNavigation)],
            policy: Policy,
            ambiguous_wildcard: bool,
            descendants: bool,
        }

        let cases = [
            Case {
                name: "empty trie misses",
                pointers: &[],
                path: &[("items", ObjectKey)],
                policy: Policy::Miss,
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "empty path reports whether any pointer exists",
                pointers: &[("/profile/email", Mask::Redact)],
                path: &[],
                policy: Policy::Miss,
                ambiguous_wildcard: false,
                descendants: true,
            },
            Case {
                name: "exact object path",
                pointers: &[("/profile/email", Mask::Redact)],
                path: &[("profile", ObjectKey), ("email", ObjectKey)],
                policy: Policy::Kind(Mask::Redact),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "ambiguous text path still follows exact edges",
                pointers: &[("/profile/email", Mask::Redact)],
                path: &[("profile", Ambiguous), ("email", Ambiguous)],
                policy: Policy::Kind(Mask::Redact),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "parent node has child pointer policies",
                pointers: &[("/profile", Mask::None), ("/profile/email", Mask::Redact)],
                path: &[("profile", ObjectKey)],
                policy: Policy::Kind(Mask::None),
                ambiguous_wildcard: false,
                descendants: true,
            },
            Case {
                name: "proven array index takes the wildcard",
                pointers: &[("/items/*/token", Mask::Redact)],
                path: &[
                    ("items", ObjectKey),
                    ("0", ArrayIndex),
                    ("token", ObjectKey),
                ],
                policy: Policy::Kind(Mask::Redact),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "quoted numeric object key never takes an array wildcard",
                pointers: &[("/items/*/token", Mask::Redact)],
                path: &[("items", ObjectKey), ("0", ObjectKey), ("token", ObjectKey)],
                policy: Policy::Miss,
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "exact index beats equally matching wildcard",
                pointers: &[
                    ("/items/*/token", Mask::Redact),
                    ("/items/0/token", Mask::None),
                ],
                path: &[
                    ("items", ObjectKey),
                    ("0", ArrayIndex),
                    ("token", ObjectKey),
                ],
                policy: Policy::Kind(Mask::None),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "wildcard still applies to a later index when an exact sibling exists",
                pointers: &[
                    ("/items/*/token", Mask::Redact),
                    ("/items/0/token", Mask::None),
                ],
                path: &[
                    ("items", ObjectKey),
                    ("1", ArrayIndex),
                    ("token", ObjectKey),
                ],
                policy: Policy::Kind(Mask::Redact),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "ambiguous segment at a node with * refuses to choose a branch",
                pointers: &[("/items/*/token", Mask::Redact)],
                path: &[("items", ObjectKey), ("0", Ambiguous), ("token", ObjectKey)],
                policy: Policy::Miss,
                ambiguous_wildcard: true,
                descendants: false,
            },
            Case {
                name: "ambiguous first segment is fine when root has no * child",
                pointers: &[("/items/*/token", Mask::Redact)],
                path: &[
                    ("items", Ambiguous),
                    ("0", ArrayIndex),
                    ("token", ObjectKey),
                ],
                policy: Policy::Kind(Mask::Redact),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "/* is the object key * , and any ambiguous step from root is unsafe",
                pointers: &[("/*", Mask::None)],
                path: &[("items", Ambiguous)],
                policy: Policy::Miss,
                ambiguous_wildcard: true,
                descendants: false,
            },
            Case {
                name: "/* matches the literal object key by exact edge",
                pointers: &[("/*", Mask::None)],
                path: &[("*", ObjectKey)],
                policy: Policy::Kind(Mask::None),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "nested wildcards require a proven array step at each *",
                pointers: &[("/a/*/b/*/c", Mask::Redact)],
                path: &[
                    ("a", ObjectKey),
                    ("0", ArrayIndex),
                    ("b", ObjectKey),
                    ("1", ArrayIndex),
                    ("c", ObjectKey),
                ],
                policy: Policy::Kind(Mask::Redact),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "nested wildcard does not fire on a quoted inner index",
                pointers: &[("/a/*/b/*/c", Mask::Redact)],
                path: &[
                    ("a", ObjectKey),
                    ("0", ArrayIndex),
                    ("b", ObjectKey),
                    ("1", ObjectKey),
                    ("c", ObjectKey),
                ],
                policy: Policy::Miss,
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "escaped pointer segments are trie keys, not syntax",
                pointers: &[("/a~1b/~0key", Mask::None)],
                path: &[("a/b", ObjectKey), ("~key", ObjectKey)],
                policy: Policy::Kind(Mask::None),
                ambiguous_wildcard: false,
                descendants: false,
            },
            Case {
                name: "unrelated branch is a miss even when a sibling pointer exists",
                pointers: &[("/profile/email", Mask::Redact)],
                path: &[("public", ObjectKey)],
                policy: Policy::Miss,
                ambiguous_wildcard: false,
                descendants: false,
            },
        ];

        for case in cases {
            let fields: Vec<JsonFieldSpec> = case
                .pointers
                .iter()
                .map(|(pointer, kind)| JsonFieldSpec::new(*pointer, MaskSpec::new(*kind)).unwrap())
                .collect();
            let trie = JsonPolicyTrie::compile(&fields);
            let path = path_segments(
                &case
                    .path
                    .iter()
                    .map(|(value, navigation)| ((*value).to_string(), *navigation))
                    .collect::<Vec<_>>(),
            );

            let got = trie.policy_at(&path).map(|spec| spec.kind);
            let want = match case.policy {
                Policy::Kind(kind) => Some(kind),
                Policy::Miss => None,
            };
            assert_eq!(got, want, "{}: policy_at", case.name);
            assert_eq!(
                trie.has_ambiguous_wildcard(&path),
                case.ambiguous_wildcard,
                "{}: has_ambiguous_wildcard",
                case.name
            );
            assert_eq!(
                trie.has_descendants_at(&path),
                case.descendants,
                "{}: has_descendants_at",
                case.name
            );
        }
    }
}
