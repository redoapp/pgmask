//! Catalog-time checks for `mask = "json"` pointer tables.
//!
//! Duplicate pointers and equally-specific overlapping wildcards are startup
//! errors: config order must not decide a disclosure. Recursive `json` as a
//! nested pointer or key mask is refused because one walker already owns the
//! document. Object-key rules are exact and case-sensitive; duplicates are
//! errors.

use anyhow::{bail, Result};

use crate::mask::{Mask, MaskSpec, MAX_JSON_MAX_DEPTH};

use super::validate_spec;

pub(crate) fn validate_json_spec(spec: &MaskSpec, what: &str) -> Result<()> {
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
        if spec
            .json
            .iter()
            .take(index)
            .any(|earlier| earlier.equally_specific_overlap(field))
        {
            bail!(
                "{what}: JSON pointer {:?} ambiguously overlaps another equally-specific \
                 wildcard pointer",
                field.pointer
            );
        }
    }
    for (index, key) in spec.json_keys.iter().enumerate() {
        if key.spec.kind == Mask::Json {
            bail!(
                "{what}: JSON key {:?} cannot recursively use mask `json`",
                key.key
            );
        }
        validate_spec(&key.spec, &format!("{what} JSON key {:?}", key.key))?;
        if spec
            .json_keys
            .iter()
            .take(index)
            .any(|earlier| earlier.key == key.key)
        {
            bail!("{what}: duplicate JSON key {:?}", key.key);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use crate::mask::{JsonFieldSpec, JsonKeySpec, Mask, MaskSpec};

    fn field(pointer: &str) -> JsonFieldSpec {
        JsonFieldSpec::new(pointer, MaskSpec::new(Mask::Redact)).unwrap()
    }

    #[test]
    fn json_pointer_overlap_table() {
        struct Case {
            name: &'static str,
            left: &'static str,
            right: &'static str,
            overlap: bool,
            equal_specificity: bool,
        }

        let cases = [
            Case {
                name: "identical pointers overlap",
                left: "/profile/email",
                right: "/profile/email",
                overlap: true,
                equal_specificity: true,
            },
            Case {
                name: "exact index vs array wildcard at the same depth overlaps",
                left: "/items/*/id",
                right: "/items/0/id",
                overlap: true,
                equal_specificity: false,
            },
            Case {
                name: "wildcard vs exact-then-wildcard at equal * count is the load-time refuse",
                left: "/items/*/id",
                right: "/items/0/*",
                overlap: true,
                equal_specificity: true,
            },
            Case {
                name: "different leaf keys do not overlap",
                left: "/items/*/id",
                right: "/items/*/token",
                overlap: false,
                equal_specificity: true,
            },
            Case {
                name: "different depths do not overlap",
                left: "/items/*",
                right: "/items/*/id",
                overlap: false,
                equal_specificity: true,
            },
            Case {
                name: "nested wildcards overlap an exact inner path",
                left: "/a/*/b/*/c",
                right: "/a/x/b/y/c",
                overlap: true,
                equal_specificity: false,
            },
            // The helper has no object-vs-array fact: `*` is always a wildcard
            // segment. Load still allows this pair because specificity differs;
            // the trie stores `/*` and `/foo` as sibling keys.
            Case {
                name: "overlap helper treats * as a wildcard even for root /*",
                left: "/*",
                right: "/foo",
                overlap: true,
                equal_specificity: false,
            },
        ];

        for case in cases {
            let left = field(case.left);
            let right = field(case.right);
            assert_eq!(
                JsonFieldSpec::patterns_overlap(&left, &right),
                case.overlap,
                "{}: overlap",
                case.name
            );
            assert_eq!(
                left.wildcard_count() == right.wildcard_count(),
                case.equal_specificity,
                "{}: equal specificity",
                case.name
            );
            assert_eq!(
                left.equally_specific_overlap(&right),
                case.overlap && case.equal_specificity,
                "{}: equally-specific overlap",
                case.name
            );
        }
    }

    #[test]
    fn duplicate_or_recursive_json_key_rules_are_refused() {
        let duplicate = JsonKeySpec {
            key: "email".into(),
            spec: MaskSpec::new(Mask::Redact),
        };
        let mut spec = MaskSpec::new(Mask::Json);
        spec.set_json_policies(Vec::new(), vec![duplicate.clone(), duplicate]);
        let err = super::validate_json_spec(&spec, "s.t.payload")
            .expect_err("duplicate key policies must not depend on order");
        assert!(format!("{err:#}").contains("duplicate JSON key"));

        let recursive = JsonKeySpec {
            key: "payload".into(),
            spec: MaskSpec::new(Mask::Json),
        };
        spec.set_json_policies(Vec::new(), vec![recursive]);
        let err = super::validate_json_spec(&spec, "s.t.payload")
            .expect_err("one document walker must own recursion");
        assert!(format!("{err:#}").contains("cannot recursively use mask `json`"));
    }
}
