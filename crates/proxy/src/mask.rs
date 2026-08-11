//! Masking algorithms.
//!
//! Contract: a mask must preserve the wire type **and format** of the field it
//! replaces. Returning a string where an `int4` was expected breaks clients
//! below any error handling they have, so anything that cannot honour the type
//! refuses rather than guesses. `MaskSpec::supports` is checked once at plan
//! time, so a mismatch refuses the whole result set instead of failing halfway
//! through a stream.
//!
//! # Format coverage
//!
//! Text-family types are byte-identical in text and binary formats, so string
//! masks work in both. Everything else needs per-format handling, and each mask
//! declares exactly what it can do in `MaskSpec::supports`.

// Narrowing casts are how `-1` became `32767`: an i64 bucket floor wrapped on
// the way into an i16. Every remaining cast in this module is either clamped
// first or bounded by the algorithm around it, and a new one has to say which.
#![deny(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::protocol::is_text_family;

type HmacSha256 = Hmac<Sha256>;

// Type OIDs we handle beyond the text family.
pub const OID_INT2: u32 = 21;
pub const OID_INT4: u32 = 23;
pub const OID_INT8: u32 = 20;
pub const OID_FLOAT4: u32 = 700;
pub const OID_FLOAT8: u32 = 701;
pub const OID_NUMERIC: u32 = 1700;
pub const OID_DATE: u32 = 1082;
pub const OID_TIMESTAMP: u32 = 1114;
pub const OID_TIMESTAMPTZ: u32 = 1184;
pub const OID_UUID: u32 = 2950;
pub const OID_INET: u32 = 869;
pub const OID_CIDR: u32 = 650;

/// Structured identifiers, and the placeholder each becomes.
///
/// Deliberately short. Every entry is a pattern that can be pinned down without
/// understanding the sentence, which is exactly the set that a regex can be
/// trusted with. Anything needing to know that "Alice Chen" is a person is
/// absent, because a rule that catches it half the time is worse than no rule:
/// the output looks scrubbed either way.
///
/// Order matters. Longer, more specific shapes go first so that an address is
/// not first eaten by the phone pattern.
type Validator = fn(&str) -> bool;

const SCRUB_PATTERNS: &[(&str, &str, Option<Validator>)] = &[
    (
        "<EMAIL>",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        None,
    ),
    ("<URL>", r"https?://[^\s]+", None),
    (
        "<UUID>",
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        None,
    ),
    ("<MAC>", r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", None),
    (
        "<IBAN>",
        r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
        Some(is_iban),
    ),
    // Anchored on a digit at both ends. `(?:[0-9][ -]?){13,19}` let the final
    // repetition swallow the space *after* the number, turning
    // "ending 4111 1111 1111 1111 declined" into "ending <CARD>declined".
    ("<CARD>", r"\b[0-9](?:[ -]?[0-9]){12,18}\b", Some(is_luhn)),
    ("<NATIONAL_ID>", r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", None),
    (
        "<NATIONAL_ID>",
        r"\b[0-9]{3} ?[0-9]{3} ?[0-9]{4}\b",
        Some(is_nhs_number),
    ),
    (
        "<NATIONAL_ID>",
        r"\b[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]\b",
        None,
    ),
    (
        "<POSTCODE>",
        r"\b[A-Z]{1,2}[0-9][A-Z0-9]? ?[0-9][A-Z]{2}\b",
        None,
    ),
    (
        "<CRYPTO>",
        r"\b(?:0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b",
        None,
    ),
    ("<IP>", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", None),
    // Two shapes, both requiring evidence that this is a phone number rather
    // than an order id: either a leading `+`, or internal separators. A bare
    // run of digits is deliberately not matched — "Ref 20201555" becoming
    // <PHONE> would corrupt the readable text this mask exists to preserve.
    (
        "<PHONE>",
        r"\+[0-9][0-9 \-().]{6,15}[0-9]|\b[0-9]{3,4}[ \-.][0-9]{3,4}(?:[ \-.][0-9]{2,4})?\b",
        Some(is_phone_length),
    ),
];

/// Luhn, the check digit on payment cards.
///
/// Hand-written rather than pulled in: it is ten lines, universally specified,
/// and a dependency here would be one more thing to read than the algorithm.
fn is_luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            if i % 2 == 1 {
                // `to_digit(10)` bounds each digit to 0..=9, so the double is at
                // most 18 and the fold-back at least 1. The saturating forms
                // state that bound rather than relying on it going unchecked.
                let doubled = d.saturating_mul(2);
                if doubled > 9 {
                    doubled.saturating_sub(9)
                } else {
                    doubled
                }
            } else {
                *d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// IBAN mod-97, via `iban_validate`, which also carries the per-country length
/// table. That table is the part worth a dependency; the checksum alone is not.
fn is_iban(candidate: &str) -> bool {
    candidate.replace(' ', "").parse::<iban::Iban>().is_ok()
}

/// A plausible number of digits for a telephone number.
///
/// Runs last, so it sees text the stricter patterns declined — and when a
/// checksum rejects a candidate, those digits are still sitting there. Without
/// this bound, a 16-digit batch code that failed Luhn came straight back as
/// `<PHONE>`, which is the same corruption of readable text the checksum was
/// added to prevent. E.164 allows 15 digits internationally; a grouped local
/// number without a country code is at most 11.
fn is_phone_length(candidate: &str) -> bool {
    let digits = candidate.chars().filter(char::is_ascii_digit).count();
    if candidate.trim_start().starts_with('+') {
        (7..=15).contains(&digits)
    } else {
        (7..=11).contains(&digits)
    }
}

/// UK NHS number: ten digits with a mod-11 check digit.
///
/// Without the checksum this pattern matches any ten digits, which in a support
/// note is more often an order reference than a patient. Presidio validates it
/// the same way and for the same reason.
fn is_nhs_number(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    // Held as a fixed array so the weighted sum and the check digit read out
    // without a bounds check, and so a length other than ten declines here.
    let Ok(digits) = <[u32; 10]>::try_from(digits.as_slice()) else {
        return false;
    };
    // Weights run 10 down to 2 across the first nine digits. Each digit is 0..=9
    // and each weight at most 10, so no product exceeds 90 and the sum cannot
    // reach the saturation bound.
    let sum: u32 = digits[..9]
        .iter()
        .zip((2..=10u32).rev())
        .map(|(d, weight)| d.saturating_mul(weight))
        .sum();
    // Matching on the remainder instead of on `11 - remainder` keeps the
    // subtraction inside the arm where it is provably positive.
    let check = match sum % 11 {
        0 => 0,
        // A remainder of 1 wants check digit 10, which no single digit can be.
        1 => return false,
        // `sum % 11` is 2..=10 here, so this never reaches zero.
        remainder => 11u32.saturating_sub(remainder),
    };
    check == digits[9]
}

/// Compiled once. `RegexSet` answers "does this value contain anything at all"
/// in one pass, and most free text contains nothing — measured at 113ns per
/// value gated this way against 789ns rewriting unconditionally.
static SCRUB: std::sync::LazyLock<(regex::RegexSet, Vec<regex::Regex>)> =
    std::sync::LazyLock::new(|| {
        let set = regex::RegexSet::new(SCRUB_PATTERNS.iter().map(|(_, p, _)| *p))
            .expect("static patterns compile");
        let each = SCRUB_PATTERNS
            .iter()
            .map(|(_, p, _)| regex::Regex::new(p).expect("static patterns compile"))
            .collect();
        (set, each)
    });

/// Replace recognised identifiers with their placeholders.
fn scrub_free_text(text: &str) -> String {
    let (set, each) = &*SCRUB;
    let matched = set.matches(text);
    if !matched.matched_any() {
        return text.to_string();
    }
    // Only the patterns that actually hit are run again to substitute, so a
    // value containing one address costs one rewrite rather than eight.
    let mut out = std::borrow::Cow::Borrowed(text);
    // Walked as a zip of the pattern table and its compiled regexes rather than
    // by index: the `RegexSet` was built from `SCRUB_PATTERNS` in this order, and
    // pairing them here means no lookup that could fall out of range and skip a
    // pattern that was supposed to run.
    for (index, (&(label, _, validator), regex)) in
        SCRUB_PATTERNS.iter().zip(each.iter()).enumerate()
    {
        if !matched.matched(index) {
            continue;
        }
        out = std::borrow::Cow::Owned(match validator {
            // A pattern with a checksum only replaces what passes it. In a mask
            // that reveals, a false positive does not merely over-hide — it
            // rewrites readable text into a placeholder that was never there.
            Some(valid) => regex
                .replace_all(&out, |caps: &regex::Captures| {
                    let hit = &caps[0];
                    if valid(hit) {
                        label.to_string()
                    } else {
                        hit.to_string()
                    }
                })
                .into_owned(),
            None => regex.replace_all(&out, label).into_owned(),
        });
    }
    out.into_owned()
}

/// The 16 bytes a uuid denotes, whatever form it arrived in.
///
/// Binary is already those bytes. Text is 32 hex digits with hyphens wherever
/// the sender chose to put them — Postgres emits the canonical 8-4-4-4-12, but
/// accepting any placement costs nothing and refusing a well-formed value would
/// turn a mask into an outage.
fn canonical_uuid(bytes: &[u8], format: i16) -> Option<[u8; 16]> {
    if format == FORMAT_BINARY {
        return <[u8; 16]>::try_from(bytes).ok();
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut out = [0u8; 16];
    let mut nibbles = text.chars().filter(|c| *c != '-');
    for byte in &mut out {
        let hi = nibbles.next()?.to_digit(16)?;
        let lo = nibbles.next()?.to_digit(16)?;
        // Both nibbles are 0..=15 out of `to_digit(16)`, so the recombination
        // cannot overflow; checked arithmetic keeps the impossible case on the
        // same `None` path as a malformed digit, which the caller turns into
        // `Undecodable` rather than a guessed byte.
        *byte = u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()?;
    }
    // Anything left over is not a uuid, and guessing would mask two different
    // values to the same pseudonym.
    if nibbles.next().is_some() {
        return None;
    }
    Some(out)
}

/// Fixed pseudonym width, in hex characters. 64 bits.
const PSEUDONYM_HEX_CHARS: usize = 16;

pub const FORMAT_TEXT: i16 = 0;
pub const FORMAT_BINARY: i16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mask {
    /// Pass the value through untouched. An explicit decision, not a default.
    None,
    /// Type-correct SQL NULL. The only mask valid for every type and format.
    Null,
    /// Constant sentinel.
    Redact,
    /// Keep the last `keep` characters: `************1234`.
    Partial,
    /// Keep `keep` characters at each end: `12**56`.
    Inner,
    /// Keep the middle, mask `keep` characters at each end: `**34**`.
    Outer,
    /// Mask characters in `[start, end)`.
    Range,
    /// Non-reversible digest, hex.
    Hash,
    /// Keyed, deterministic, shaped like the input. Joins still work.
    ///
    /// Determinism is an equality-and-frequency oracle: an analyst can count
    /// distinct principals and join them across tables. Usually the point, but
    /// it is a real disclosure — choose it per column deliberately, and see
    /// `domain` for controlling *which* joins remain possible.
    Pseudonym,
    /// Truncate a date or timestamp to 1 January of its year.
    DateYear,
    /// Truncate a date or timestamp to the first of its month.
    DateMonth,
    /// Floor a number to a multiple of `bucket`.
    NumericBucket,
    /// Replace recognised identifiers inside free text with placeholders,
    /// leaving the rest of the sentence readable:
    /// `called alice@acme.com` -> `called <EMAIL>`.
    ///
    /// **This mask reveals the value it is applied to, minus what it
    /// recognised.** Every other mask here hides by default and a gap costs
    /// utility; this one shows by default and a gap is a disclosure. It matches
    /// structured identifiers — email, URL, uuid, MAC, IBAN, card, postcode,
    /// crypto address, IP, phone — and it does not and cannot match a person's
    /// name, a postal
    /// address written in prose, or `alice [at] acme [dot] com`. Measured
    /// against realistic support notes it catches roughly half of what a human
    /// would call sensitive.
    ///
    /// Choose it when a human needs to read the note and you accept that. Never
    /// as a default, and never for a column nobody has looked at.
    Scrub,
    /// Keep the network prefix of an IP: `203.0.113.7` -> `203.0.113.0`.
    IpPrefix,
}

/// A mask plus its parameters and pseudonym domain.
#[derive(Debug, Clone, PartialEq)]
pub struct MaskSpec {
    pub kind: Mask,
    /// Characters kept by `partial` / `inner` / `outer`.
    pub keep: u16,
    /// Bounds for `range`.
    pub start: u16,
    pub end: u16,
    /// Bucket size for `numeric-bucket`.
    pub bucket: i64,
    /// Keep the domain of an email address rather than pseudonymising it.
    ///
    /// Off by default: for business data the domain identifies the company, and
    /// with one contact there it identifies the person.
    pub keep_domain: bool,
    /// Domain separator for `hash` / `pseudonym`.
    ///
    /// Two columns sharing a domain pseudonymise identically, so joins across
    /// them keep working. Two columns in *different* domains do not, so a phone
    /// number that happens to equal an account number cannot be used to link
    /// them. Defaults to the semantic type name, which is usually what you want.
    pub domain: Option<Arc<str>>,
}

impl Default for MaskSpec {
    fn default() -> Self {
        Self {
            kind: Mask::Null,
            keep: 4,
            start: 0,
            end: 0,
            bucket: 1,
            keep_domain: false,
            domain: None,
        }
    }
}

impl MaskSpec {
    pub fn new(kind: Mask) -> Self {
        Self {
            kind,
            ..Default::default()
        }
    }

    pub fn is_passthrough(&self) -> bool {
        self.kind == Mask::None
    }

    /// Can this mask honour the given type in the given wire format?
    ///
    /// Checked once per result set rather than per row, so a misconfiguration is
    /// a clean refusal up front rather than a stream that dies mid-flight.
    pub fn supports(&self, type_oid: u32, format: i16) -> bool {
        match self.kind {
            // Always safe: -1 length is format-independent.
            Mask::None | Mask::Null => true,

            // String rewrites. Text-family types only, where text and binary
            // encodings are the same bytes.
            Mask::Redact | Mask::Partial | Mask::Inner | Mask::Outer | Mask::Range => {
                is_text_family(type_oid)
            }

            Mask::Hash => is_text_family(type_oid),

            // UUID is byte-shaped in binary and hyphen-shaped in text; both are
            // reproducible from a digest, so both are supported.
            Mask::Pseudonym => is_text_family(type_oid) || type_oid == OID_UUID,

            Mask::DateYear | Mask::DateMonth => {
                matches!(type_oid, OID_DATE | OID_TIMESTAMP | OID_TIMESTAMPTZ)
            }

            // `numeric` has a bespoke binary encoding we do not implement, and
            // parsing it as a float would silently lose precision.
            Mask::NumericBucket => match type_oid {
                OID_INT2 | OID_INT4 | OID_INT8 | OID_FLOAT4 | OID_FLOAT8 => true,
                OID_NUMERIC => format == FORMAT_TEXT,
                _ => false,
            },

            // Rewrites text in place, so text-family only.
            Mask::Scrub => is_text_family(type_oid),

            // inet/cidr binary is a packed struct we do not decode.
            Mask::IpPrefix => {
                is_text_family(type_oid)
                    || (matches!(type_oid, OID_INET | OID_CIDR) && format == FORMAT_TEXT)
            }
        }
    }

    /// Why `supports` said no, phrased for whoever has to fix the config.
    pub fn unsupported_hint(&self) -> &'static str {
        match self.kind {
            Mask::NumericBucket => {
                "numeric-bucket handles int2/int4/int8/float4/float8, and numeric only in \
                 text format. Use mask = \"null\" otherwise."
            }
            Mask::DateYear | Mask::DateMonth => {
                "date-year/date-month handle date, timestamp and timestamptz. Use \
                 mask = \"null\" otherwise."
            }
            Mask::IpPrefix => {
                "ip-prefix handles text columns, and inet/cidr only in text format. Use \
                 mask = \"null\" otherwise."
            }
            Mask::Pseudonym => {
                "pseudonym handles text-family types and uuid. Use mask = \"null\" otherwise."
            }
            _ => "This mask rewrites values as text. Use mask = \"null\" for non-text types.",
        }
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
    /// `Err` means the mask cannot be applied safely — callers must treat that
    /// as a rejection, never as a passthrough.
    pub fn apply(
        &self,
        spec: &MaskSpec,
        type_oid: u32,
        format: i16,
        value: Option<Bytes>,
    ) -> Result<Option<Bytes>, MaskError> {
        if spec.kind == Mask::None {
            return Ok(value);
        }
        if spec.kind == Mask::Null {
            return Ok(None);
        }
        if !spec.supports(type_oid, format) {
            return Err(MaskError::Unsupported {
                type_oid,
                format,
                kind: spec.kind,
            });
        }
        // SQL NULL stays NULL: masking must not invent a value where there was none.
        let Some(bytes) = value else { return Ok(None) };

        let out = match spec.kind {
            Mask::Redact => Bytes::from_static(b"***"),
            Mask::Partial => text_op(&bytes, |t| partial(t, spec.keep as usize)),
            Mask::Inner => text_op(&bytes, |t| inner(t, spec.keep as usize)),
            Mask::Outer => text_op(&bytes, |t| outer(t, spec.keep as usize)),
            Mask::Range => text_op(&bytes, |t| range(t, spec.start as usize, spec.end as usize)),
            Mask::Hash => {
                let mut out = String::with_capacity(32);
                hex_into(&self.digest(spec, &bytes)[..16], &mut out);
                Bytes::from(out)
            }
            Mask::Pseudonym => self.pseudonym(spec, type_oid, format, &bytes)?,
            Mask::DateYear | Mask::DateMonth => truncate_date(&bytes, type_oid, format, spec.kind)?,
            Mask::NumericBucket => bucket_number(&bytes, type_oid, format, spec.bucket)?,
            Mask::IpPrefix => text_op(&bytes, ip_prefix),
            Mask::Scrub => text_op(&bytes, scrub_free_text),
            Mask::None | Mask::Null => unreachable!("handled above"),
        };
        Ok(Some(out))
    }

    fn digest(&self, spec: &MaskSpec, input: &[u8]) -> [u8; 32] {
        let mut mac = self.mac.clone();
        // Domain separation: same value in different domains must not collide,
        // so unrelated columns cannot be linked by comparing pseudonyms.
        if let Some(domain) = &spec.domain {
            mac.update(domain.as_bytes());
            mac.update(b"\x00");
        }
        mac.update(input);
        mac.finalize().into_bytes().into()
    }

    /// Deterministic, fixed width, and by default revealing nothing of the
    /// input — not even its length.
    ///
    /// Width is constant at 16 hex characters (64 bits). Deriving it from the
    /// input leaked the original's length, and short inputs got as few as 32
    /// bits, where 380k values collide about sixteen times by the birthday
    /// bound. Collisions here are not merely a privacy problem: two people
    /// sharing a pseudonym corrupts joins and counts.
    fn pseudonym(
        &self,
        spec: &MaskSpec,
        type_oid: u32,
        format: i16,
        bytes: &Bytes,
    ) -> Result<Bytes, MaskError> {
        if type_oid == OID_UUID {
            // Hash the canonical 16 bytes, never the wire bytes.
            //
            // A uuid is 16 raw bytes in binary and 36 hyphenated characters in
            // text, so digesting the wire form gave the same row two different
            // pseudonyms depending on the client's protocol. psql and pgx
            // reading the same column could not be joined to each other, which
            // defeats the point of deterministic pseudonymisation. Found by the
            // first end-to-end test that asked for binary results.
            let canonical =
                canonical_uuid(bytes, format).ok_or(MaskError::Undecodable { type_oid, format })?;
            let digest = self.digest(spec, &Bytes::copy_from_slice(&canonical));
            return Ok(if format == FORMAT_BINARY {
                Bytes::copy_from_slice(&uuid_bytes(&digest))
            } else {
                Bytes::from(uuid_text(&uuid_bytes(&digest)))
            });
        }

        let digest = self.digest(spec, bytes);

        let text = String::from_utf8_lossy(bytes);
        let as_email = text
            .split_once('@')
            .filter(|(local, domain)| !local.is_empty() && !domain.is_empty());
        Ok(Bytes::from(match as_email {
            // The local part alone is not the identifying half of a work
            // address. `alice@tinystartup.io` names a company, and with one
            // contact there it names a person — so the domain is pseudonymised
            // too unless `keep_domain` is set. Domains map deterministically, so
            // "group by employer" still works without naming the employer.
            Some((_, domain)) if !spec.keep_domain => {
                let mut out = String::with_capacity(PSEUDONYM_HEX_CHARS + 14);
                hex_into(&digest[..PSEUDONYM_HEX_CHARS / 2], &mut out);
                out.push('@');
                let mut mac = self.mac.clone();
                mac.update(b"domain\x00");
                mac.update(domain.as_bytes());
                let dd: [u8; 32] = mac.finalize().into_bytes().into();
                hex_into(&dd[..4], &mut out);
                out.push_str(".invalid");
                out
            }
            Some((_, domain)) => {
                // A capacity hint only, so saturating at `usize::MAX` would cost
                // a reallocation and nothing else.
                let mut out = String::with_capacity(
                    PSEUDONYM_HEX_CHARS
                        .saturating_add(1)
                        .saturating_add(domain.len()),
                );
                hex_into(&digest[..PSEUDONYM_HEX_CHARS / 2], &mut out);
                out.push('@');
                out.push_str(domain);
                out
            }
            None => {
                let mut out = String::with_capacity(PSEUDONYM_HEX_CHARS);
                hex_into(&digest[..PSEUDONYM_HEX_CHARS / 2], &mut out);
                out
            }
        }))
    }
}

// --- String masks -----------------------------------------------------------

fn text_op(bytes: &Bytes, f: impl Fn(&str) -> String) -> Bytes {
    Bytes::from(f(&String::from_utf8_lossy(bytes)))
}

fn partial(text: &str, keep: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    // The masked run is what is left after the kept tail. `checked_sub` filtered
    // to a non-zero remainder is exactly the old `len <= keep` guard: with
    // nothing left to star, the whole value is starred rather than revealed.
    let Some(masked) = chars.len().checked_sub(keep).filter(|n| *n > 0) else {
        return "*".repeat(chars.len());
    };
    let tail: String = chars.iter().skip(masked).collect();
    format!("{}{tail}", "*".repeat(masked))
}

fn inner(text: &str, keep: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    // `keep` characters at each end. A value too short to spare both ends — or a
    // `keep` wide enough to overflow the doubling — is masked outright, which is
    // the same answer the unchecked `len <= keep * 2` gave for every value it
    // could compute.
    let Some(masked) = keep
        .checked_mul(2)
        .and_then(|ends| chars.len().checked_sub(ends))
        .filter(|n| *n > 0)
    else {
        return "*".repeat(chars.len());
    };
    let head: String = chars.iter().take(keep).collect();
    // Skipping the head and then the masked run lands on the last `keep`
    // characters without recomputing an offset.
    let tail: String = chars.iter().skip(keep).skip(masked).collect();
    format!("{head}{}{tail}", "*".repeat(masked))
}

fn outer(text: &str, keep: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    // `keep = 0` keeps *nothing at each end*, which under the mirror below
    // makes the surviving middle the entire value — a passthrough that reads as
    // configured. `partial` and `inner` both full-mask at 0; `outer` inverted.
    // Rejected at config load too; this is the second line.
    if keep == 0 {
        return "*".repeat(chars.len());
    }
    // Mirror of `inner`: `kept` is the middle that survives, and a value with no
    // middle left is masked outright.
    //
    // The `> 0` here is the one of the three that is an *equivalent* mutant:
    // relaxing it to `>= 0` at `len == keep * 2` gives `kept = 0`, so the middle
    // is empty and the output is `"*" * keep` twice — exactly the `len` stars
    // the `else` branch produces. `partial` and `inner` are not equivalent at
    // their boundaries and both have tests; this one cannot, and saying so here
    // is cheaper than re-deriving it next time cargo-mutants reports it.
    let Some(kept) = keep
        .checked_mul(2)
        .and_then(|ends| chars.len().checked_sub(ends))
        .filter(|n| *n > 0)
    else {
        return "*".repeat(chars.len());
    };
    let middle: String = chars.iter().skip(keep).take(kept).collect();
    format!("{}{middle}{}", "*".repeat(keep), "*".repeat(keep))
}

fn range(text: &str, start: usize, end: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    // A window that starts past the end of the value masked *nothing* and
    // returned it verbatim: `range(start=4, end=8)` on `"1234"` clamped both
    // bounds to 4, so the loop never fired. A rule sized for a 16-digit account
    // number silently passed through every short one, and because the failure
    // is value-dependent no config check could catch it.
    //
    // Too short for the window is the same situation `partial`, `inner` and
    // `outer` each answer by masking outright.
    if start >= chars.len() {
        return "*".repeat(chars.len());
    }
    let start = start.min(chars.len());
    let end = end.clamp(start, chars.len());
    let mut out = String::with_capacity(chars.len());
    for (i, c) in chars.iter().enumerate() {
        out.push(if i >= start && i < end { '*' } else { *c });
    }
    out
}

/// Keep the network portion: /24 for v4, /48 for v6.
///
/// Parsed rather than split on separators. The string approach produced invalid
/// addresses for compressed IPv6 — `2001:db8::1` became `2001:db8:::` and `::1`
/// became `::1::` — and passed zone identifiers straight through. Anything that
/// does not parse is fully masked rather than half-transformed.
fn ip_prefix(text: &str) -> String {
    let stars = || "*".repeat(text.chars().count());
    let (addr, had_prefix) = match text.split_once('/') {
        Some((a, _)) => (a, true),
        None => (text, false),
    };
    // Zone identifiers (`fe80::1%eth0`) are not part of the address and std
    // will not parse them.
    let addr = addr.split('%').next().unwrap_or(addr).trim();

    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        let base = std::net::Ipv4Addr::new(o[0], o[1], o[2], 0);
        return if had_prefix {
            format!("{base}/24")
        } else {
            base.to_string()
        };
    }
    if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
        let mut octets = v6.octets();
        octets[6..].fill(0); // keep the first 48 bits
        let base = std::net::Ipv6Addr::from(octets);
        return if had_prefix {
            format!("{base}/48")
        } else {
            base.to_string()
        };
    }
    stars()
}

// --- Date truncation --------------------------------------------------------

// Postgres date and timestamp handling goes through `postgres-types`'
// `FromSql`/`ToSql` with jiff's civil types, rather than epoch arithmetic of our
// own. What used to live here was Howard Hinnant's civil-date algorithm plus a
// Postgres epoch offset, hand-written, and it produced three of the defects
// found in a day: an overflow at the extremes of the microsecond domain, a
// narrowing cast that moved a date rather than coarsening it, and a dropped
// `BC` era. jiff's types are range-checked by construction, so a value outside
// what Postgres can represent fails to decode instead of wrapping.

/// Coarsen a jiff civil date to the first of its year or month.
fn coarsen(date: jiff::civil::Date, to_month: bool) -> Result<jiff::civil::Date, MaskError> {
    jiff::civil::Date::new(date.year(), if to_month { date.month() } else { 1 }, 1).map_err(|_| {
        MaskError::Undecodable {
            type_oid: OID_DATE,
            format: FORMAT_BINARY,
        }
    })
}

/// Coarsen Postgres' text rendering of a date or timestamp.
///
/// Parsed by locating the delimiters, not by fixed offsets. **A Postgres year
/// is not four digits.** `date` reaches `5874897-12-31` and renders every digit
/// of it, and this used to read `&text[0..4]`: `10000-06-15` masked to
/// `1000-01-01`, a perfectly well-formed date nine thousand years from the real
/// one, with nothing for the client to notice. Confirmed against Postgres 17,
/// which also renders `10000-06-15 13:45:00` and `5874897-12-31` verbatim.
///
/// The era suffix comes off before anything else reads the string. It used to
/// be appended *after* a timezone slice that ran to the end of the text, so
/// `0044-03-15 10:00:00+00 BC` came back as `0044-03-01 00:00:00+00 BC BC`.
/// That one was reachable and a test covers it.
///
/// The timezone is looked for inside the time field rather than by the old
/// `rfind(['+', '-']).filter(|i| *i > 10)` over the whole string. **This is not
/// independently load-bearing** — the `i > 10` test is correct for every input
/// that gets this far, because the year is already bounded to four digits
/// twenty lines up, and a poison control confirms restoring it breaks nothing.
/// It is here because a magic offset that is only right by virtue of an
/// invariant enforced elsewhere is the kind of coupling that breaks the next
/// time the bound moves.
///
/// Refuses any year the binary path cannot produce. jiff's civil date stops at
/// ±9999, so a wider year fails to decode in binary; text succeeding there
/// would mean the same stored value masked differently depending on which
/// protocol the client happened to use, which is exactly what
/// `binary_date_truncation_agrees_with_the_text_path` exists to forbid.
fn truncate_date_text(
    text: &str,
    type_oid: u32,
    format: i16,
    to_month: bool,
) -> Result<String, MaskError> {
    let undecodable = || MaskError::Undecodable { type_oid, format };
    // Postgres renders pre-year-1 dates with a ` BC` suffix. Dropping it moves
    // the value roughly four thousand years into the future.
    let (stem, era) = match text.strip_suffix(" BC") {
        Some(stem) => (stem, " BC"),
        None => (text, ""),
    };
    // A `date` is the date alone; a timestamp adds ` HH:MM:SS[.ffffff][±TZ]`.
    let (date_part, time_part) = match stem.split_once(' ') {
        Some((date, time)) => (date, Some(time)),
        None => (stem, None),
    };
    let mut fields = date_part.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(undecodable());
    };
    let digits = |field: &str, width: std::ops::RangeInclusive<usize>| {
        width.contains(&field.len()) && field.bytes().all(|b| b.is_ascii_digit())
    };
    if !digits(year, 1..=7) || !digits(month, 2..=2) || !digits(day, 2..=2) {
        return Err(undecodable());
    }
    if year.parse::<i32>().map_err(|_| undecodable())? > 9999 {
        return Err(undecodable());
    }
    let month = if to_month { month } else { "01" };
    if type_oid == OID_DATE {
        return Ok(format!("{year}-{month}-01{era}"));
    }
    // Keep any timezone offset so the client parses what it expects.
    let tz = match time_part {
        Some(time) => time
            .rfind(['+', '-'])
            .and_then(|i| time.get(i..))
            .unwrap_or(""),
        None => "",
    };
    Ok(format!("{year}-{month}-01 00:00:00{tz}{era}"))
}

fn truncate_date(
    bytes: &Bytes,
    type_oid: u32,
    format: i16,
    kind: Mask,
) -> Result<Bytes, MaskError> {
    let to_month = kind == Mask::DateMonth;

    if format == FORMAT_TEXT {
        let text = String::from_utf8_lossy(bytes);
        return truncate_date_text(&text, type_oid, format, to_month).map(Bytes::from);
    }

    // Binary: decode with the type's own codec, coarsen, re-encode. No epoch
    // constants and no casts, so the range checks are the library's problem.
    use postgres_types::{FromSql, ToSql, Type};
    let undecodable = || MaskError::Undecodable { type_oid, format };
    let mut out = BytesMut::new();
    match type_oid {
        OID_DATE => {
            let date =
                jiff::civil::Date::from_sql(&Type::DATE, bytes).map_err(|_| undecodable())?;
            coarsen(date, to_month)?
                .to_sql(&Type::DATE, &mut out)
                .map_err(|_| undecodable())?;
        }
        OID_TIMESTAMP => {
            let dt = jiff::civil::DateTime::from_sql(&Type::TIMESTAMP, bytes)
                .map_err(|_| undecodable())?;
            coarsen(dt.date(), to_month)?
                .to_datetime(jiff::civil::Time::midnight())
                .to_sql(&Type::TIMESTAMP, &mut out)
                .map_err(|_| undecodable())?;
        }
        OID_TIMESTAMPTZ => {
            let ts =
                jiff::Timestamp::from_sql(&Type::TIMESTAMPTZ, bytes).map_err(|_| undecodable())?;
            // Coarsen in UTC: the wire value is an instant, and the session's
            // display zone is not ours to guess.
            let utc = ts.to_zoned(jiff::tz::TimeZone::UTC);
            coarsen(utc.date(), to_month)?
                .to_datetime(jiff::civil::Time::midnight())
                .to_zoned(jiff::tz::TimeZone::UTC)
                .map_err(|_| undecodable())?
                .timestamp()
                .to_sql(&Type::TIMESTAMPTZ, &mut out)
                .map_err(|_| undecodable())?;
        }
        _ => return Err(undecodable()),
    }
    Ok(out.freeze())
}

// --- Numeric bucketing ------------------------------------------------------

fn bucket_number(
    bytes: &Bytes,
    type_oid: u32,
    format: i16,
    bucket: i64,
) -> Result<Bytes, MaskError> {
    let bucket = bucket.max(1);

    if format == FORMAT_TEXT {
        let text = String::from_utf8_lossy(bytes);
        let trimmed = text.trim();
        if let Ok(v) = trimmed.parse::<i64>() {
            return Ok(Bytes::from(floor_to(v, bucket).to_string()));
        }
        // `numeric` is arbitrary precision. Going through f64 silently rounded
        // large values and printed them back in a shape Postgres might not
        // accept; a decimal keeps the digits and renders a valid literal.
        if let Ok(v) = trimmed.parse::<rust_decimal::Decimal>() {
            let b = rust_decimal::Decimal::from(bucket);
            // `Decimal`'s operators panic on overflow, which for a value near the
            // 96-bit limit would take the connection down mid-stream. The checked
            // forms refuse the value instead, and `bucket` is at least 1 so the
            // division has no zero divisor.
            let floored = v
                .checked_div(b)
                .map(|quotient| quotient.floor())
                .and_then(|q| q.checked_mul(b))
                .ok_or(MaskError::Undecodable { type_oid, format })?;
            return Ok(Bytes::from(floored.normalize().to_string()));
        }
        if let Ok(v) = trimmed.parse::<f64>() {
            // Postgres accepts NaN/Infinity/-Infinity for float and numeric, and
            // spells them that way. Rust prints "inf", which the client cannot
            // parse back into the column's type. Bucketing a non-finite value
            // is meaningless anyway, so echo the canonical spelling.
            if !v.is_finite() {
                return Ok(Bytes::from_static(if v.is_nan() {
                    b"NaN"
                } else if v.is_sign_positive() {
                    b"Infinity"
                } else {
                    b"-Infinity"
                }));
            }
            let b = bucket as f64;
            return Ok(Bytes::from(((v / b).floor() * b).to_string()));
        }
        return Err(MaskError::Undecodable { type_oid, format });
    }

    // `<[u8; N]>::try_from` on a slice succeeds only at exactly N bytes, so it
    // carries the width check the arm guards used to do. A payload of the wrong
    // size refuses with the same `Undecodable` the unmatched arm returns rather
    // than decoding a prefix of a value it does not understand.
    let undecodable = || MaskError::Undecodable { type_oid, format };
    match type_oid {
        OID_INT2 => {
            let raw = <[u8; 2]>::try_from(bytes.as_ref()).map_err(|_| undecodable())?;
            let v = i64::from(i16::from_be_bytes(raw));
            let out = floor_within(v, bucket, i64::from(i16::MIN), i64::from(i16::MAX))
                .ok_or_else(undecodable)?;
            let out = i16::try_from(out).map_err(|_| undecodable())?;
            Ok(Bytes::copy_from_slice(&out.to_be_bytes()))
        }
        OID_INT4 => {
            let raw = <[u8; 4]>::try_from(bytes.as_ref()).map_err(|_| undecodable())?;
            let v = i64::from(i32::from_be_bytes(raw));
            let out = floor_within(v, bucket, i64::from(i32::MIN), i64::from(i32::MAX))
                .ok_or_else(undecodable)?;
            let out = i32::try_from(out).map_err(|_| undecodable())?;
            Ok(Bytes::copy_from_slice(&out.to_be_bytes()))
        }
        OID_INT8 => {
            let raw = <[u8; 8]>::try_from(bytes.as_ref()).map_err(|_| undecodable())?;
            let v = i64::from_be_bytes(raw);
            Ok(Bytes::copy_from_slice(&floor_to(v, bucket).to_be_bytes()))
        }
        OID_FLOAT4 => {
            let raw = <[u8; 4]>::try_from(bytes.as_ref()).map_err(|_| undecodable())?;
            let v = f64::from(f32::from_be_bytes(raw));
            let b = bucket as f64;
            // Flooring a float4 near its minimum can push the result past what
            // an f32 holds, turning a masked value into -inf.
            let bucketed = ((v / b).floor() * b).clamp(f32::MIN as f64, f32::MAX as f64);
            // Clamped into f32's range immediately above; floats have no
            // TryFrom, so the intent is stated rather than checked.
            #[allow(clippy::cast_possible_truncation)]
            let narrowed = bucketed as f32;
            Ok(Bytes::copy_from_slice(&narrowed.to_be_bytes()))
        }
        OID_FLOAT8 => {
            let raw = <[u8; 8]>::try_from(bytes.as_ref()).map_err(|_| undecodable())?;
            let v = f64::from_be_bytes(raw);
            let b = bucket as f64;
            Ok(Bytes::copy_from_slice(&((v / b).floor() * b).to_be_bytes()))
        }
        _ => Err(MaskError::Undecodable { type_oid, format }),
    }
}

/// Floor division, so negatives bucket downward rather than toward zero.
///
/// Saturating, because `i64::MIN` with a bucket that does not divide it
/// overflows the multiply — a panic in debug, and in release a wrap that
/// produces a value *larger* than the input, which is the opposite of masking.
fn floor_to(v: i64, bucket: i64) -> i64 {
    let bucket = bucket.max(1);
    v.div_euclid(bucket).saturating_mul(bucket)
}

/// Floor to a bucket boundary, or `None` when that boundary is out of range.
///
/// A bucket wider than the type is legitimate — it means "one bucket covers
/// everything" — but the floor then sits below the type's minimum, and the cast
/// wrapped it to a large positive number. `-1` with a bucket of 32769 came back
/// as `32767`.
///
/// This used to `clamp`, and clamping breaks the one property a bucket mask
/// promises: that the value you see is a bucket boundary. `-2146760705` with a
/// bucket of `759365` floors to `-2147484220`, below `i32::MIN`, and the
/// clamped `i32::MIN` is not a multiple of anything — so the output silently
/// stopped being a bucket and started being "somewhere near the bottom of the
/// range", which is a narrower statement about the real value than a bucket is.
/// Found by `integer_buckets_are_sound` once proptest drew a large enough
/// bucket; it predates the lint work.
///
/// Refusing is right: the proxy cannot represent the masked value in this
/// column's type, and emitting something that is not a bucket is worse than
/// emitting nothing.
fn floor_within(v: i64, bucket: i64, min: i64, max: i64) -> Option<i64> {
    let floored = floor_to(v, bucket);
    (min..=max).contains(&floored).then_some(floored)
}

// --- Helpers ----------------------------------------------------------------

/// Hex without allocating per byte. The naive `format!("{b:02x}")`-per-byte
/// version allocated a `String` for every byte of every digest, which showed up
/// as roughly half the per-row masking cost in the throughput benchmark.
fn hex_into(bytes: &[u8], out: &mut String) {
    for &byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            // Derived rather than looked up in a digit table: a nibble is 0..=15
            // by construction, but a table index the compiler cannot bound needs
            // a miss branch, and there is no character a hex encoder could put
            // there that would not corrupt the digest it is writing. The
            // saturating forms only restate the bound — `b'0' + 9` and
            // `b'a' + 5` are both far inside ASCII.
            out.push(char::from(if nibble < 10 {
                b'0'.saturating_add(nibble)
            } else {
                b'a'.saturating_add(nibble.saturating_sub(10))
            }));
        }
    }
}

/// A digest shaped into a syntactically valid v4 UUID.
fn uuid_bytes(digest: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out[6] = (out[6] & 0x0f) | 0x40; // version 4
    out[8] = (out[8] & 0x3f) | 0x80; // RFC 4122 variant
    out
}

fn uuid_text(bytes: &[u8; 16]) -> String {
    let mut hex = String::with_capacity(32);
    hex_into(bytes, &mut hex);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskError {
    /// The mask cannot honour this type in this wire format.
    Unsupported {
        type_oid: u32,
        format: i16,
        kind: Mask,
    },
    /// The value did not decode as its declared type.
    Undecodable { type_oid: u32, format: i16 },
}

impl std::fmt::Display for MaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaskError::Unsupported {
                type_oid,
                format,
                kind,
            } => write!(
                f,
                "mask {kind:?} cannot be applied to type OID {type_oid} in {} format",
                if *format == FORMAT_BINARY {
                    "binary"
                } else {
                    "text"
                }
            ),
            MaskError::Undecodable { type_oid, format } => write!(
                f,
                "value of type OID {type_oid} did not decode in {} format",
                if *format == FORMAT_BINARY {
                    "binary"
                } else {
                    "text"
                }
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const TEXT: u32 = 25;

    fn masker() -> Masker {
        Masker::new(b"test-key".to_vec())
    }

    fn spec(kind: Mask) -> MaskSpec {
        MaskSpec::new(kind)
    }

    fn apply_text(spec: &MaskSpec, value: &str) -> String {
        let out = masker()
            .apply(
                spec,
                TEXT,
                FORMAT_TEXT,
                Some(Bytes::copy_from_slice(value.as_bytes())),
            )
            .unwrap()
            .unwrap();
        String::from_utf8(out.to_vec()).unwrap()
    }

    // --- Invariants that hold for every mask --------------------------------

    #[test]
    fn null_works_for_any_type_and_format() {
        for oid in [TEXT, OID_INT4, OID_TIMESTAMP, OID_UUID, OID_NUMERIC] {
            for format in [FORMAT_TEXT, FORMAT_BINARY] {
                let out = masker()
                    .apply(
                        &spec(Mask::Null),
                        oid,
                        format,
                        Some(Bytes::from_static(b"x")),
                    )
                    .unwrap();
                assert_eq!(out, None, "oid {oid} format {format}");
            }
        }
    }

    #[test]
    fn null_input_stays_null_for_every_mask() {
        for kind in [
            Mask::Redact,
            Mask::Partial,
            Mask::Inner,
            Mask::Outer,
            Mask::Range,
            Mask::Hash,
            Mask::Pseudonym,
            Mask::IpPrefix,
        ] {
            assert_eq!(
                masker()
                    .apply(&spec(kind), TEXT, FORMAT_TEXT, None)
                    .unwrap(),
                None,
                "{kind:?} invented a value where there was none"
            );
        }
    }

    #[test]
    fn unsupported_combinations_refuse_rather_than_guess() {
        // A string mask on an int.
        assert!(!spec(Mask::Redact).supports(OID_INT4, FORMAT_TEXT));
        // Date truncation on a string.
        assert!(!spec(Mask::DateYear).supports(TEXT, FORMAT_TEXT));
        // numeric in binary — bespoke encoding we do not decode.
        assert!(!spec(Mask::NumericBucket).supports(OID_NUMERIC, FORMAT_BINARY));
        assert!(spec(Mask::NumericBucket).supports(OID_NUMERIC, FORMAT_TEXT));
        // inet in binary.
        assert!(!spec(Mask::IpPrefix).supports(OID_INET, FORMAT_BINARY));
    }

    // --- String masks --------------------------------------------------------

    #[test]
    fn partial_keeps_the_configured_tail() {
        assert_eq!(
            apply_text(&spec(Mask::Partial), "4111111111111234"),
            "************1234"
        );
        let mut s = spec(Mask::Partial);
        s.keep = 2;
        assert_eq!(apply_text(&s, "4111111111111234"), "**************34");
        assert_eq!(apply_text(&spec(Mask::Partial), "abc"), "***");
    }

    #[test]
    fn inner_and_outer_mirror_each_other() {
        let mut s = spec(Mask::Inner);
        s.keep = 2;
        assert_eq!(apply_text(&s, "123456"), "12**56");
        let mut s = spec(Mask::Outer);
        s.keep = 2;
        assert_eq!(apply_text(&s, "123456"), "**34**");
    }

    /// Both string masks that used to fail open on a short value.
    ///
    /// `range` clamped a window past the end to an empty window and returned
    /// the value; `outer` at `keep = 0` made the whole value the surviving
    /// middle. Every other string mask answers "too short for these
    /// parameters" by masking outright, and now these do too.
    #[test]
    fn string_masks_never_fail_open_on_a_short_value() {
        assert_eq!(range("1234", 4, 8), "****");
        assert_eq!(range("abc", 10, 20), "***");
        assert_eq!(range("", 4, 8), "");
        // Still masks the overlapping part when the window does reach.
        assert_eq!(range("123456", 4, 99), "1234**");
        assert_eq!(outer("topsecret", 0), "*********");
        assert_eq!(outer("", 0), "");
        // ...and still keeps the ends when asked to.
        assert_eq!(outer("topsecret", 2), "**psecr**");
    }

    /// The window `classify` proposes for a postcode, against real shapes.
    ///
    /// `start = 2, end = 64` reads as nonsense until you know `end` is clamped
    /// to the value's length, so it means "keep the first two". This is pinned
    /// here because the proposal lives in another crate: if the clamp ever
    /// stops clamping, a postcode column starts arriving verbatim and the only
    /// thing that would notice is this.
    #[test]
    fn the_postcode_window_keeps_the_prefix_at_every_length() {
        let mut s = spec(Mask::Range);
        s.start = 2;
        s.end = 64;
        assert_eq!(apply_text(&s, "94103"), "94***", "US ZIP");
        assert_eq!(apply_text(&s, "SW1A 1AA"), "SW******", "UK postcode");
        assert_eq!(apply_text(&s, "K1A 0B1"), "K1*****", "Canadian");
        // Shorter than the window: masked outright rather than passed through.
        assert_eq!(apply_text(&s, "12"), "**");
        assert_eq!(apply_text(&s, "1"), "*");
        assert_eq!(apply_text(&s, ""), "");
    }

    #[test]
    fn range_masks_the_requested_window() {
        let mut s = spec(Mask::Range);
        s.start = 2;
        s.end = 6;
        assert_eq!(apply_text(&s, "12345678"), "12****78");
    }

    /// A value exactly as long as the window it keeps.
    ///
    /// The floors are `checked_sub(...).filter(|n| *n > 0)`, and at `len ==
    /// keep` — or `keep * 2` for `inner` — the subtraction is `Some(0)`.
    /// Relaxing that filter to `>= 0` makes the masked run zero characters
    /// long, so `partial` emits the whole value and `inner` emits head plus
    /// tail, which is also the whole value. Both mutants survived the campaign:
    /// every existing test sat strictly inside or strictly outside the window,
    /// never on it.
    #[test]
    fn a_value_exactly_the_length_of_its_window_is_masked_outright() {
        let mut p = spec(Mask::Partial);
        p.keep = 4;
        assert_eq!(apply_text(&p, "abcd"), "****", "len == keep");
        assert_eq!(apply_text(&p, "abcde"), "*bcde", "one longer still reveals");

        let mut i = spec(Mask::Inner);
        i.keep = 4;
        assert_eq!(apply_text(&i, "abcdefgh"), "********", "len == keep * 2");
        assert_eq!(apply_text(&i, "abcdefghi"), "abcd*fghi", "one longer");

        // `outer` at its boundary is an equivalent mutant — see the comment on
        // the function — so this pins the value, not the branch.
        let mut o = spec(Mask::Outer);
        o.keep = 4;
        assert_eq!(apply_text(&o, "abcdefgh"), "********", "len == keep * 2");
        assert_eq!(apply_text(&o, "abcdefghi"), "****e****", "one longer");
    }

    #[test]
    fn short_values_do_not_leak_through_the_keep_window() {
        let mut s = spec(Mask::Inner);
        s.keep = 4;
        // 6 chars with keep=4 each end would otherwise reveal everything.
        assert_eq!(apply_text(&s, "123456"), "******");
    }

    #[test]
    fn ip_prefix_drops_the_host_portion() {
        assert_eq!(
            apply_text(&spec(Mask::IpPrefix), "203.0.113.7"),
            "203.0.113.0"
        );
        assert_eq!(
            apply_text(&spec(Mask::IpPrefix), "203.0.113.7/32"),
            "203.0.113.0/24"
        );
        assert_eq!(
            apply_text(&spec(Mask::IpPrefix), "2001:db8:1:2:3:4:5:6"),
            "2001:db8:1::"
        );
    }

    // --- Pseudonyms and domains ---------------------------------------------

    #[test]
    fn pseudonym_is_deterministic() {
        let a = apply_text(&spec(Mask::Pseudonym), "alice@example.com");
        let b = apply_text(&spec(Mask::Pseudonym), "alice@example.com");
        assert_eq!(a, b, "joins depend on determinism");
        assert!(!a.contains("alice"));
        // Domain handling is covered by email_domains_are_pseudonymised_by_default.
    }

    #[test]
    fn separate_domains_break_cross_column_linkage() {
        let mut people = spec(Mask::Pseudonym);
        people.domain = Some("person".into());
        let mut accounts = spec(Mask::Pseudonym);
        accounts.domain = Some("account".into());

        // The same raw value in two domains must not pseudonymise alike, or an
        // analyst could link the two columns by comparing masked values.
        assert_ne!(apply_text(&people, "12345"), apply_text(&accounts, "12345"));
        // ...while a shared domain keeps joins working.
        let mut same = spec(Mask::Pseudonym);
        same.domain = Some("person".into());
        assert_eq!(apply_text(&people, "12345"), apply_text(&same, "12345"));
    }

    #[test]
    fn uuid_pseudonyms_are_valid_uuids_in_both_formats() {
        let m = masker();
        let s = spec(Mask::Pseudonym);
        let raw = Bytes::from_static(b"11111111-2222-3333-4444-555555555555");
        let text = m
            .apply(&s, OID_UUID, FORMAT_TEXT, Some(raw.clone()))
            .unwrap()
            .unwrap();
        let text = String::from_utf8(text.to_vec()).unwrap();
        assert_eq!(text.len(), 36);
        assert_eq!(text.chars().filter(|c| *c == '-').count(), 4);
        assert_eq!(&text[14..15], "4", "should be a v4 uuid");

        let bin = m
            .apply(
                &s,
                OID_UUID,
                FORMAT_BINARY,
                Some(Bytes::from(vec![0u8; 16])),
            )
            .unwrap()
            .unwrap();
        assert_eq!(bin.len(), 16, "binary uuid must stay 16 bytes");
    }

    // --- Dates ---------------------------------------------------------------

    #[test]
    fn date_year_truncates_in_text() {
        let m = masker();
        let out = m
            .apply(
                &spec(Mask::DateYear),
                OID_DATE,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"2024-03-15")),
            )
            .unwrap()
            .unwrap();
        assert_eq!(&out[..], b"2024-01-01");
    }

    #[test]
    fn date_month_keeps_the_month_in_text() {
        let m = masker();
        let out = m
            .apply(
                &spec(Mask::DateMonth),
                OID_TIMESTAMP,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"2024-03-15 10:30:00")),
            )
            .unwrap()
            .unwrap();
        assert_eq!(&out[..], b"2024-03-01 00:00:00");
    }

    // --- Numbers -------------------------------------------------------------

    #[test]
    fn numeric_bucket_floors_in_binary() {
        let m = masker();
        let mut s = spec(Mask::NumericBucket);
        s.bucket = 10;
        let out = m
            .apply(
                &s,
                OID_INT4,
                FORMAT_BINARY,
                Some(Bytes::copy_from_slice(&37i32.to_be_bytes())),
            )
            .unwrap()
            .unwrap();
        assert_eq!(i32::from_be_bytes([out[0], out[1], out[2], out[3]]), 30);
    }

    #[test]
    fn numeric_bucket_floors_negatives_downward() {
        // -37 with bucket 10 must land on -40, not -30: rounding toward zero
        // would make the mask reveal more than the bucket size promises.
        assert_eq!(floor_to(-37, 10), -40);
        assert_eq!(floor_to(37, 10), 30);
        assert_eq!(floor_to(-40, 10), -40);
    }

    #[test]
    fn numeric_bucket_works_in_text() {
        let m = masker();
        let mut s = spec(Mask::NumericBucket);
        s.bucket = 1000;
        let out = m
            .apply(
                &s,
                OID_INT8,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"187500")),
            )
            .unwrap()
            .unwrap();
        assert_eq!(&out[..], b"187000");
    }

    // --- Regressions for defects found by attacking the masks directly -----

    /// A pseudonym must reveal nothing of the input, including its length, and
    /// must be wide enough that 380k values do not collide.
    #[test]
    fn pseudonyms_are_fixed_width_regardless_of_input() {
        let widths: Vec<usize> = ["a", "ab", "abcdefgh", &"x".repeat(64)]
            .iter()
            .map(|v| apply_text(&spec(Mask::Pseudonym), v).len())
            .collect();
        assert!(
            widths.iter().all(|w| *w == PSEUDONYM_HEX_CHARS),
            "input length must not show through: {widths:?}"
        );
    }

    #[test]
    fn pseudonyms_do_not_collide_across_many_values() {
        use std::collections::HashSet;
        let m = masker();
        let seen: HashSet<String> = (0..50_000)
            .map(|i| {
                let v = format!("subject-{i}");
                String::from_utf8(
                    m.apply(
                        &spec(Mask::Pseudonym),
                        TEXT,
                        FORMAT_TEXT,
                        Some(Bytes::from(v)),
                    )
                    .unwrap()
                    .unwrap()
                    .to_vec(),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(seen.len(), 50_000, "collisions corrupt joins and counts");
    }

    /// For business data the domain names the company, and with one contact
    /// there it names the person. Domains map deterministically so grouping by
    /// employer still works without naming the employer.
    #[test]
    fn email_domains_are_pseudonymised_by_default() {
        let out = apply_text(&spec(Mask::Pseudonym), "alice@tinystartup.io");
        assert!(!out.contains("tinystartup"), "domain leaked: {out}");
        assert!(
            out.contains('@'),
            "should still look like an address: {out}"
        );

        // Same domain, different people -> same masked domain.
        let a = apply_text(&spec(Mask::Pseudonym), "alice@acme.com");
        let b = apply_text(&spec(Mask::Pseudonym), "bob@acme.com");
        assert_ne!(a, b);
        assert_eq!(
            a.split('@').nth(1),
            b.split('@').nth(1),
            "colleagues must still group together"
        );

        // Opt back in explicitly.
        let mut keep = spec(Mask::Pseudonym);
        keep.keep_domain = true;
        let kept = masker()
            .apply(
                &keep,
                TEXT,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"alice@acme.com")),
            )
            .unwrap()
            .unwrap();
        assert!(String::from_utf8(kept.to_vec())
            .unwrap()
            .ends_with("@acme.com"));
    }

    /// Splitting on `:` produced invalid addresses for compressed forms and let
    /// zone identifiers through. Parse, mask, re-emit.
    #[test]
    fn ip_prefix_emits_valid_addresses() {
        for (input, want) in [
            ("203.0.113.7", "203.0.113.0"),
            ("203.0.113.7/32", "203.0.113.0/24"),
            ("2001:db8:1:2:3:4:5:6", "2001:db8:1::"),
            ("2001:db8::1", "2001:db8::"),
            ("::1", "::"),
            ("fe80::1%eth0", "fe80::"),
        ] {
            assert_eq!(
                apply_text(&spec(Mask::IpPrefix), input),
                want,
                "input {input}"
            );
        }
        // Anything that does not parse is fully masked, not half-transformed.
        assert_eq!(apply_text(&spec(Mask::IpPrefix), "not-an-ip"), "*********");
    }

    // --- Dates, now expressed in the same types the wire codec uses ---------

    fn date_wire(y: i16, m: i8, d: i8) -> Bytes {
        use postgres_types::{ToSql, Type};
        let mut out = BytesMut::new();
        jiff::civil::Date::new(y, m, d)
            .unwrap()
            .to_sql(&Type::DATE, &mut out)
            .unwrap();
        out.freeze()
    }

    fn date_from_wire(bytes: &Bytes) -> jiff::civil::Date {
        use postgres_types::{FromSql, Type};
        jiff::civil::Date::from_sql(&Type::DATE, bytes).unwrap()
    }

    #[test]
    fn binary_date_truncation_agrees_with_the_text_path() {
        let m = masker();
        let binary = m
            .apply(
                &spec(Mask::DateYear),
                OID_DATE,
                FORMAT_BINARY,
                Some(date_wire(2024, 3, 15)),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            date_from_wire(&binary),
            jiff::civil::Date::new(2024, 1, 1).unwrap()
        );

        let text = m
            .apply(
                &spec(Mask::DateYear),
                OID_DATE,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"2024-03-15")),
            )
            .unwrap()
            .unwrap();
        assert_eq!(&text[..], b"2024-01-01", "text and binary must agree");
    }

    /// The year bound is `> 9999`, so 9999 itself must still be masked.
    ///
    /// `> 9999` -> `>= 9999` survived the campaign: the refusal tests use 10000
    /// and 5874897, the acceptance tests use 2024, and nothing sat on the edge.
    /// Over-refusing here would be safe and still wrong — jiff represents 9999.
    #[test]
    fn the_last_representable_year_is_masked_not_refused() {
        let out = masker()
            .apply(
                &spec(Mask::DateMonth),
                OID_DATE,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"9999-06-15")),
            )
            .unwrap()
            .unwrap();
        assert_eq!(&out[..], b"9999-06-01");
        assert!(
            jiff::civil::Date::new(9999, 6, 15).is_ok(),
            "and binary agrees"
        );
    }

    /// Masking a date in text must reject exactly what masking it in binary
    /// rejects, or the same stored value masks differently depending on which
    /// protocol the client used.
    ///
    /// jiff's civil date stops at ±9999. Postgres does not: `date` reaches
    /// `5874897-12-31` and renders every digit. The text path read `&text[0..4]`
    /// and produced `1000-01-01` for `10000-06-15` — a well-formed date nine
    /// thousand years from the real one, which no client could detect.
    #[test]
    fn a_year_wider_than_four_digits_is_refused_rather_than_truncated() {
        let m = masker();
        for (oid, rendering) in [
            (OID_DATE, "10000-06-15"),
            (OID_DATE, "5874897-12-31"),
            (OID_TIMESTAMP, "10000-06-15 13:45:00"),
            (OID_TIMESTAMPTZ, "10000-06-15 11:45:00+00"),
        ] {
            let out = m.apply(
                &spec(Mask::DateYear),
                oid,
                FORMAT_TEXT,
                Some(Bytes::copy_from_slice(rendering.as_bytes())),
            );
            assert!(
                matches!(out, Err(MaskError::Undecodable { .. })),
                "{rendering} should be refused, got {out:?}",
            );
        }
        // And the binary path agrees, which is the reason for refusing.
        assert!(jiff::civil::Date::new(10000, 6, 15).is_err());
    }

    /// The era suffix was appended after a timezone slice that ran to the end
    /// of the string, so it came back twice.
    #[test]
    fn a_bc_timestamp_with_an_offset_keeps_one_era() {
        let out = masker()
            .apply(
                &spec(Mask::DateMonth),
                OID_TIMESTAMPTZ,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"0044-03-15 10:00:00+00 BC")),
            )
            .unwrap()
            .unwrap();
        assert_eq!(&out[..], b"0044-03-01 00:00:00+00 BC");
    }

    /// An offset is still preserved on an ordinary timestamp, and the day and
    /// time are still discarded.
    #[test]
    fn an_offset_survives_truncation() {
        let m = masker();
        let cases = [
            (
                Mask::DateYear,
                "2024-03-15 13:45:00+02",
                "2024-01-01 00:00:00+02",
            ),
            (
                Mask::DateMonth,
                "2024-03-15 13:45:00+02",
                "2024-03-01 00:00:00+02",
            ),
            (
                Mask::DateMonth,
                "2024-03-15 13:45:00-05:30",
                "2024-03-01 00:00:00-05:30",
            ),
            (
                Mask::DateMonth,
                "2024-03-15 13:45:00",
                "2024-03-01 00:00:00",
            ),
        ];
        for (kind, input, want) in cases {
            let out = m
                .apply(
                    &spec(kind),
                    OID_TIMESTAMPTZ,
                    FORMAT_TEXT,
                    Some(Bytes::copy_from_slice(input.as_bytes())),
                )
                .unwrap()
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&out), want, "{kind:?} on {input}",);
        }
    }

    /// Text that is not a date is refused, not reshaped into one.
    ///
    /// The old length-and-char-boundary check let anything ten bytes long
    /// through and read fixed offsets out of it.
    #[test]
    fn text_that_is_not_a_date_is_refused() {
        let m = masker();
        for rendering in [
            "not-a-date",
            "2024-3-15",     // one-digit month
            "2024-03",       // two fields
            "2024-03-15-01", // four fields
            "20xx-03-15",
            "",
            "-2024-03-15", // an empty year field
        ] {
            let out = m.apply(
                &spec(Mask::DateYear),
                OID_DATE,
                FORMAT_TEXT,
                Some(Bytes::copy_from_slice(rendering.as_bytes())),
            );
            assert!(
                matches!(out, Err(MaskError::Undecodable { .. })),
                "{rendering:?} should be refused, got {out:?}",
            );
        }
    }

    /// Postgres counts from 2000, so anything earlier is a negative day count —
    /// the case the hand-rolled epoch arithmetic used to get wrong.
    #[test]
    fn dates_before_the_postgres_epoch_truncate_correctly() {
        let out = masker()
            .apply(
                &spec(Mask::DateYear),
                OID_DATE,
                FORMAT_BINARY,
                Some(date_wire(1999, 6, 15)),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            date_from_wire(&out),
            jiff::civil::Date::new(1999, 1, 1).unwrap()
        );
    }

    #[test]
    fn month_truncation_keeps_the_month() {
        let out = masker()
            .apply(
                &spec(Mask::DateMonth),
                OID_DATE,
                FORMAT_BINARY,
                Some(date_wire(2024, 3, 15)),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            date_from_wire(&out),
            jiff::civil::Date::new(2024, 3, 1).unwrap()
        );
    }

    /// A value outside what the type can represent must fail to decode rather
    /// than wrap. This is the property the library buys us.
    #[test]
    fn out_of_range_binary_dates_are_refused_not_wrapped() {
        let refused = masker().apply(
            &spec(Mask::DateYear),
            OID_DATE,
            FORMAT_BINARY,
            Some(Bytes::copy_from_slice(&i32::MAX.to_be_bytes())),
        );
        assert!(
            refused.is_err(),
            "an unrepresentable date must be refused, not silently moved"
        );
    }

    /// `numeric` is arbitrary precision. The old f64 round-trip lost digits on
    /// large values; a decimal keeps them and renders a literal Postgres reads.
    #[test]
    fn numeric_text_bucketing_keeps_precision() {
        let mut s = spec(Mask::NumericBucket);
        s.bucket = 1000;
        let out = masker()
            .apply(
                &s,
                OID_NUMERIC,
                FORMAT_TEXT,
                Some(Bytes::from_static(b"123456789012345678901234.56")),
            )
            .unwrap()
            .unwrap();
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(
            !text.contains('e') && !text.contains('E'),
            "must not fall back to scientific notation: {text}"
        );
        assert!(
            text.ends_with("000"),
            "must land on a bucket boundary: {text}"
        );
        assert!(
            text.parse::<rust_decimal::Decimal>().is_ok(),
            "must still be a numeric literal: {text}"
        );
    }
}

#[cfg(test)]
mod uuid_format_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const RAW: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03,
    ];

    #[test]
    fn a_uuid_pseudonymises_identically_in_both_wire_formats() {
        // The bug this pins: digesting the wire bytes gave psql and a binary
        // driver different pseudonyms for the same row, so masked data could
        // not be joined across clients.
        let masker = Masker::new(b"k".to_vec());
        let spec = MaskSpec::new(Mask::Pseudonym);

        let from_binary = masker
            .apply(
                &spec,
                OID_UUID,
                FORMAT_BINARY,
                Some(Bytes::copy_from_slice(&RAW)),
            )
            .expect("binary masks")
            .expect("not null");
        let from_text = masker
            .apply(
                &spec,
                OID_UUID,
                FORMAT_TEXT,
                Some(Bytes::from(uuid_text(&RAW))),
            )
            .expect("text masks")
            .expect("not null");

        let binary_as_text = uuid_text(&<[u8; 16]>::try_from(&from_binary[..]).expect("16 bytes"));
        assert_eq!(
            binary_as_text,
            String::from_utf8_lossy(&from_text),
            "the same uuid must pseudonymise to the same value in either format"
        );
    }

    #[test]
    fn uppercase_and_hyphenless_text_uuids_canonicalise_the_same() {
        let canonical = canonical_uuid(uuid_text(&RAW).as_bytes(), FORMAT_TEXT);
        let upper = canonical_uuid(uuid_text(&RAW).to_uppercase().as_bytes(), FORMAT_TEXT);
        let bare = canonical_uuid(uuid_text(&RAW).replace('-', "").as_bytes(), FORMAT_TEXT);
        assert_eq!(canonical, Some(RAW));
        assert_eq!(upper, Some(RAW));
        assert_eq!(bare, Some(RAW));
    }

    #[test]
    fn a_malformed_uuid_is_refused_rather_than_guessed() {
        assert_eq!(canonical_uuid(b"not-a-uuid", FORMAT_TEXT), None);
        assert_eq!(canonical_uuid(b"", FORMAT_TEXT), None);
        // Too many digits: truncating would map two values to one pseudonym.
        let long = format!("{}00", uuid_text(&RAW));
        assert_eq!(canonical_uuid(long.as_bytes(), FORMAT_TEXT), None);
        assert_eq!(canonical_uuid(&RAW[..15], FORMAT_BINARY), None);
    }
}

#[cfg(test)]
mod scrub_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn scrub(text: &str) -> String {
        scrub_free_text(text)
    }

    #[test]
    fn structured_identifiers_become_placeholders() {
        assert_eq!(
            scrub("Emailed alice@acme.com about the refund"),
            "Emailed <EMAIL> about the refund"
        );
        assert_eq!(
            scrub("Called +1 (555) 010-4419 twice"),
            "Called <PHONE> twice"
        );
        assert_eq!(
            scrub("Logged in from 203.0.113.44 at 09:12"),
            "Logged in from <IP> at 09:12"
        );
        assert_eq!(scrub("IBAN GB33BUKB20201555555555"), "IBAN <IBAN>");
        assert_eq!(
            scrub("See https://tickets.example/t/91 for detail"),
            "See <URL> for detail"
        );
    }

    #[test]
    fn the_readable_part_survives() {
        // The whole point: a human still gets the sentence.
        let out = scrub("Customer alice@acme.com asked for a refund on order 5512");
        assert!(out.contains("asked for a refund"), "{out}");
        assert!(!out.contains("alice@acme.com"), "{out}");
    }

    #[test]
    fn several_identifiers_in_one_value_are_all_replaced() {
        let out = scrub("mail bob@x.io or call +1 555 010 4419");
        assert!(!out.contains("bob@x.io") && !out.contains("4419"), "{out}");
    }

    #[test]
    fn text_with_nothing_to_find_is_returned_unchanged() {
        let clean = "Refund processed, no further action needed";
        assert_eq!(scrub(clean), clean);
    }

    #[test]
    fn scrubbing_is_deterministic() {
        // Two rows holding the same note must mask identically, or counts and
        // groupings over a scrubbed column stop meaning anything.
        let s = "ping alice@acme.com";
        assert_eq!(scrub(s), scrub(s));
    }

    /// The limits, written down as assertions rather than as a comment nobody
    /// reads. Each of these is a value a human would call sensitive and this
    /// mask leaves in place. If a future change starts catching one, this test
    /// fails and the docs get updated with it — that is the point.
    #[test]
    fn what_it_does_not_catch_is_pinned_here() {
        for leaves_intact in [
            "Spoke to Alice Chen in accounts payable",
            "Reach her at alice [at] acme [dot] com",
            "DOB 14th of March, nineteen eighty two",
            "Twitter handle @alicechen_",
            "Her son goes to Ashville Primary",
        ] {
            assert_eq!(
                scrub(leaves_intact),
                leaves_intact,
                "this mask does not claim to catch this; if it now does, update the docs"
            );
        }
    }

    #[test]
    fn a_postal_address_is_only_partly_caught() {
        // Adding the UK postcode pattern moved this case: the postcode now
        // goes, the street does not. Half an address is not an anonymised
        // address, and pretending otherwise is how this mask gets misused.
        let out = scrub_free_text("Her address is 14 Bellevue Terrace, Leeds LS8 2QP");
        assert!(out.contains("<POSTCODE>"), "{out}");
        assert!(
            out.contains("14 Bellevue Terrace"),
            "the street survives: {out}"
        );
    }

    #[test]
    fn scrub_refuses_non_text_types() {
        let spec = MaskSpec::new(Mask::Scrub);
        assert!(spec.supports(25, FORMAT_TEXT), "text");
        assert!(spec.supports(1043, FORMAT_TEXT), "varchar");
        assert!(!spec.supports(OID_DATE, FORMAT_TEXT));
        assert!(!spec.supports(OID_UUID, FORMAT_BINARY));
        assert!(!spec.supports(OID_INT4, FORMAT_TEXT));
    }

    #[test]
    fn a_more_restrictive_role_still_wins_over_scrub() {
        // scrub reveals nearly everything, so it must never beat redact when a
        // principal holds both roles.
        use crate::catalog::Classification;
        use std::collections::{HashMap, HashSet};
        let mut by_role = HashMap::new();
        by_role.insert("support".to_string(), MaskSpec::new(Mask::Scrub));
        by_role.insert("auditor".to_string(), MaskSpec::new(Mask::Redact));
        let c = Classification {
            default: MaskSpec::new(Mask::Null),
            by_role,
        };
        let both: HashSet<String> = ["support".into(), "auditor".into()].into_iter().collect();
        assert_eq!(c.for_roles(&both).kind, Mask::Redact);
    }
}

#[cfg(test)]
mod scrub_pattern_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn a_replacement_does_not_eat_the_surrounding_text() {
        // The card pattern used to consume the trailing space.
        assert_eq!(
            scrub_free_text("card ending 4111 1111 1111 1111 declined"),
            "card ending <CARD> declined"
        );
    }

    #[test]
    fn short_local_phone_numbers_are_caught() {
        assert_eq!(
            scrub_free_text("voicemail on 555-0102"),
            "voicemail on <PHONE>"
        );
        assert_eq!(scrub_free_text("call 555 010 4419"), "call <PHONE>");
        assert_eq!(scrub_free_text("call +1 (555) 010-4419"), "call <PHONE>");
    }

    #[test]
    fn bare_reference_numbers_are_left_alone() {
        // A run of digits with no separator is an order id far more often than
        // a phone number, and mangling it defeats the point of the mask.
        for kept in [
            "Refund processed for order 4",
            "Ref 20201555 confirmed",
            "Order 4417 shipped",
        ] {
            assert_eq!(scrub_free_text(kept), kept, "should be untouched");
        }
    }

    #[test]
    fn a_more_specific_pattern_wins_over_a_looser_one() {
        // An IP and a card both look phone-ish; each must get its own label.
        assert_eq!(scrub_free_text("from 203.0.113.44 ok"), "from <IP> ok");
        assert!(scrub_free_text("pay 4111 1111 1111 1111 now").contains("<CARD>"));
    }
}

#[cfg(test)]
mod scrub_validator_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn a_checksum_keeps_lookalikes_readable() {
        // The whole reason validators are here. Both are 16 digits; only one is
        // a card, and turning the other into <CARD> would corrupt the note.
        assert_eq!(
            scrub_free_text("card 4111 1111 1111 1111 declined"),
            "card <CARD> declined"
        );
        let not_a_card = "batch 1234 5678 9012 3456 shipped";
        assert_eq!(
            scrub_free_text(not_a_card),
            not_a_card,
            "fails Luhn, left alone"
        );
    }

    #[test]
    fn iban_is_validated_not_just_shaped() {
        assert_eq!(
            scrub_free_text("IBAN GB33BUKB20201555555555"),
            "IBAN <IBAN>"
        );
        // Right shape, wrong check digits.
        let bogus = "IBAN GB00BUKB20201555555555";
        assert_eq!(scrub_free_text(bogus), bogus);
    }

    #[test]
    fn nhs_numbers_need_their_check_digit() {
        // 943 476 5919 is the number the NHS publishes as a valid example.
        assert_eq!(scrub_free_text("NHS 943 476 5919"), "NHS <NATIONAL_ID>");
        // A failed check digit must not be labelled a national id. A 3-3-4
        // grouping is also a common phone shape, so it may still be caught as
        // <PHONE> — a different and defensible claim about the same digits.
        let out = scrub_free_text("order 943 476 5910 dispatched");
        assert!(!out.contains("<NATIONAL_ID>"), "{out}");
    }

    #[test]
    fn the_new_distinctive_patterns_match() {
        assert_eq!(
            scrub_free_text("nino JG121212C on file"),
            "nino <NATIONAL_ID> on file"
        );
        assert_eq!(
            scrub_free_text("lives at LS8 2QP now"),
            "lives at <POSTCODE> now"
        );
        assert_eq!(scrub_free_text("mac 00:1B:44:11:3A:B7"), "mac <MAC>");
        assert_eq!(
            scrub_free_text("wallet 0x52908400098527886E0F7030069857D2E4169EE7"),
            "wallet <CRYPTO>"
        );
    }

    #[test]
    fn luhn_and_nhs_agree_with_published_vectors() {
        assert!(is_luhn("4111111111111111"));
        assert!(is_luhn("5500 0000 0000 0004"));
        assert!(!is_luhn("4111111111111112"));
        assert!(is_nhs_number("9434765919"));
        assert!(!is_nhs_number("9434765910"));
        assert!(!is_nhs_number("123456789"));
        assert!(is_iban("GB33BUKB20201555555555"));
        assert!(!is_iban("GB00BUKB20201555555555"));
    }
}

#[cfg(test)]
mod overflow_regression_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    /// `numeric-bucket` on a `numeric` near the 96-bit limit used to panic.
    ///
    /// `(v / b).floor() * b` on `rust_decimal` panics on overflow, and the
    /// value comes off the wire — so a single row could kill the connection
    /// task mid-result-set. Verified against rust_decimal 1.42.1: the old
    /// expression panics with "Multiplication overflowed". Refusing is the
    /// right answer; a masking proxy that cannot mask a value must not emit it.
    #[test]
    fn a_numeric_at_the_limit_refuses_instead_of_panicking() {
        let masker = Masker::new(b"k".to_vec());
        let mut spec = MaskSpec::new(Mask::NumericBucket);
        spec.bucket = 1000;
        // Only the negative extreme overflows: flooring rounds towards minus
        // infinity, so MIN goes past the limit while MAX floors safely inward.
        let min = masker.apply(
            &spec,
            OID_NUMERIC,
            FORMAT_TEXT,
            Some(Bytes::from(rust_decimal::Decimal::MIN.to_string())),
        );
        assert!(
            matches!(min, Err(MaskError::Undecodable { .. })),
            "Decimal::MIN should refuse, got {min:?}"
        );

        let max = masker
            .apply(
                &spec,
                OID_NUMERIC,
                FORMAT_TEXT,
                Some(Bytes::from(rust_decimal::Decimal::MAX.to_string())),
            )
            .expect("MAX floors inward and still buckets")
            .expect("not null");
        assert!(
            String::from_utf8_lossy(&max).ends_with("000"),
            "still bucketed: {:?}",
            String::from_utf8_lossy(&max)
        );
    }

    /// The ordinary case must still work, or the fix above is just a break.
    #[test]
    fn ordinary_numerics_still_bucket() {
        let masker = Masker::new(b"k".to_vec());
        let mut spec = MaskSpec::new(Mask::NumericBucket);
        spec.bucket = 25_000;
        let out = masker
            .apply(&spec, OID_NUMERIC, FORMAT_TEXT, Some(Bytes::from("62200")))
            .expect("masks")
            .expect("not null");
        assert_eq!(&out[..], b"50000");
    }
}
