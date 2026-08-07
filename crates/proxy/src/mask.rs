//! Masking algorithms.
//!
//! Contract: a mask must preserve the wire type and format of the field it
//! replaces. Returning a string where an `int4` was expected breaks clients
//! below any error handling they have, so anything that cannot honour the type
//! refuses rather than guesses.

use bytes::Bytes;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::protocol::is_text_family;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mask {
    /// Pass the value through untouched. An explicit decision, not a default.
    None,
    /// Type-correct SQL NULL. The only mask valid for every type.
    Null,
    /// Constant sentinel.
    Redact,
    /// Keep the last 4 characters.
    Partial,
    /// Non-reversible digest, hex.
    Hash,
    /// Keyed, deterministic, shaped like the input. Joins still work.
    ///
    /// Determinism is an equality-and-frequency oracle: an analyst can count
    /// distinct principals and join them across tables. Usually the point, but
    /// it is a real disclosure — choose it per column deliberately.
    Pseudonym,
}

impl Mask {
    /// Masks other than `Null` rewrite the value as text, which is only safe for
    /// types whose wire representation *is* text in both formats.
    pub fn needs_text_family(self) -> bool {
        !matches!(self, Mask::None | Mask::Null)
    }
}

pub struct Masker {
    /// Pre-keyed HMAC state, cloned per use.
    ///
    /// `new_from_slice` runs the ipad/opad key schedule — two extra compression
    /// functions on every call. Cloning the initialised state instead skips that
    /// per row, which is most of the pseudonym cost at bulk sizes.
    mac: HmacSha256,
}

impl Masker {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        let key = key.into();
        Self {
            mac: HmacSha256::new_from_slice(&key).expect("hmac accepts any key length"),
        }
    }

    /// Apply a mask to one field value.
    ///
    /// `Err` means the mask cannot be applied safely to this type — callers must
    /// treat that as a rejection, never as a passthrough.
    pub fn apply(
        &self,
        mask: Mask,
        type_oid: u32,
        value: Option<Bytes>,
    ) -> Result<Option<Bytes>, MaskError> {
        if mask == Mask::None {
            return Ok(value);
        }
        if mask == Mask::Null {
            return Ok(None);
        }
        if !is_text_family(type_oid) {
            return Err(MaskError::UnsupportedType { type_oid, mask });
        }
        // SQL NULL stays NULL: masking must not invent a value where there was none.
        let Some(bytes) = value else { return Ok(None) };
        let text = String::from_utf8_lossy(&bytes);

        Ok(Some(match mask {
            Mask::Redact => Bytes::from_static(b"***"),
            Mask::Partial => Bytes::from(partial(&text)),
            Mask::Hash => {
                let mut out = String::with_capacity(32);
                hex_into(&self.digest(text.as_bytes())[..16], &mut out);
                Bytes::from(out)
            }
            Mask::Pseudonym => Bytes::from(self.pseudonym(&text)),
            Mask::None | Mask::Null => unreachable!("handled above"),
        }))
    }

    fn digest(&self, input: &[u8]) -> [u8; 32] {
        let mut mac = self.mac.clone();
        mac.update(input);
        mac.finalize().into_bytes().into()
    }

    /// Deterministic and shaped like the input, so an email still looks like an
    /// email and downstream parsing keeps working.
    fn pseudonym(&self, input: &str) -> String {
        let digest = self.digest(input.as_bytes());
        match input.split_once('@') {
            Some((_, domain)) => {
                let mut out = String::with_capacity(12 + 1 + domain.len());
                hex_into(&digest[..6], &mut out);
                out.push('@');
                out.push_str(domain);
                out
            }
            None => {
                let want = input.len().clamp(8, 32);
                let mut out = String::with_capacity(32);
                hex_into(&digest[..16], &mut out);
                out.truncate(want);
                out
            }
        }
    }
}

fn partial(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 4 {
        return "*".repeat(chars.len());
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}{}", "*".repeat(chars.len() - 4), tail)
}

/// Hex without allocating per byte. The naive `format!("{b:02x}")`-per-byte
/// version allocated a `String` for every byte of every digest, which showed up
/// as roughly half the per-row masking cost in the throughput benchmark.
fn hex_into(bytes: &[u8], out: &mut String) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskError {
    /// The configured mask rewrites text, but this column is not a text type.
    UnsupportedType { type_oid: u32, mask: Mask },
}

impl std::fmt::Display for MaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaskError::UnsupportedType { type_oid, mask } => write!(
                f,
                "mask {mask:?} rewrites values as text and cannot be applied to type OID \
                 {type_oid}; use mask = \"null\" for this column"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: u32 = 25;
    const INT4: u32 = 23;

    fn masker() -> Masker {
        Masker::new(b"test-key".to_vec())
    }

    fn apply(mask: Mask, value: &'static str) -> Option<String> {
        masker()
            .apply(mask, TEXT, Some(Bytes::from_static(value.as_bytes())))
            .unwrap()
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
    }

    #[test]
    fn null_works_for_any_type() {
        for oid in [TEXT, INT4, 1114, 2950] {
            let out = masker()
                .apply(Mask::Null, oid, Some(Bytes::from_static(b"x")))
                .unwrap();
            assert_eq!(out, None);
        }
    }

    #[test]
    fn text_masks_refuse_non_text_types() {
        for mask in [Mask::Redact, Mask::Partial, Mask::Hash, Mask::Pseudonym] {
            let err = masker().apply(mask, INT4, Some(Bytes::from_static(b"42")));
            assert!(err.is_err(), "{mask:?} should refuse int4");
        }
    }

    #[test]
    fn null_input_stays_null() {
        for mask in [Mask::Redact, Mask::Hash, Mask::Pseudonym, Mask::Partial] {
            assert_eq!(masker().apply(mask, TEXT, None).unwrap(), None);
        }
    }

    #[test]
    fn none_is_a_passthrough() {
        assert_eq!(
            apply(Mask::None, "alice@example.com").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn partial_keeps_the_last_four() {
        assert_eq!(
            apply(Mask::Partial, "4111111111111234").unwrap(),
            "************1234"
        );
        assert_eq!(apply(Mask::Partial, "abc").unwrap(), "***");
    }

    #[test]
    fn pseudonym_is_deterministic_and_keeps_the_domain() {
        let a = apply(Mask::Pseudonym, "alice@example.com").unwrap();
        let b = apply(Mask::Pseudonym, "alice@example.com").unwrap();
        assert_eq!(a, b, "joins depend on determinism");
        assert!(a.ends_with("@example.com"));
        assert!(!a.starts_with("alice"));
    }

    #[test]
    fn pseudonym_separates_distinct_inputs() {
        let a = apply(Mask::Pseudonym, "alice@example.com").unwrap();
        let b = apply(Mask::Pseudonym, "bob@example.com").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn pseudonym_is_key_dependent() {
        let one = Masker::new(b"key-one".to_vec());
        let two = Masker::new(b"key-two".to_vec());
        let value = Some(Bytes::from_static(b"alice@example.com"));
        assert_ne!(
            one.apply(Mask::Pseudonym, TEXT, value.clone()).unwrap(),
            two.apply(Mask::Pseudonym, TEXT, value).unwrap()
        );
    }

    #[test]
    fn hash_reveals_nothing_of_the_input() {
        let out = apply(Mask::Hash, "alice@example.com").unwrap();
        assert_eq!(out.len(), 32);
        assert!(!out.contains("alice"));
        assert!(!out.contains("example"));
    }
}
