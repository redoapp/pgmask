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
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
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
    if digits.len() != 10 {
        return false;
    }
    let sum: u32 = digits[..9]
        .iter()
        .enumerate()
        .map(|(i, d)| d * (10 - u32::try_from(i).expect("index fits")))
        .sum();
    let check = match 11 - (sum % 11) {
        11 => 0,
        10 => return false,
        other => other,
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
    for index in matched.iter() {
        let (label, _, validator) = SCRUB_PATTERNS[index];
        out = std::borrow::Cow::Owned(match validator {
            // A pattern with a checksum only replaces what passes it. In a mask
            // that reveals, a false positive does not merely over-hide — it
            // rewrites readable text into a placeholder that was never there.
            Some(valid) => each[index]
                .replace_all(&out, |caps: &regex::Captures| {
                    let hit = &caps[0];
                    if valid(hit) {
                        label.to_string()
                    } else {
                        hit.to_string()
                    }
                })
                .into_owned(),
            None => each[index].replace_all(&out, label).into_owned(),
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
        *byte = u8::try_from(hi * 16 + lo).ok()?;
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
    /// structured identifiers — address, phone, card, IBAN, national id, IP,
    /// URL, uuid — and it does not and cannot match a person's name, a postal
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
                let mut out = String::with_capacity(PSEUDONYM_HEX_CHARS + 1 + domain.len());
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
    if chars.len() <= keep {
        return "*".repeat(chars.len());
    }
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{}{}", "*".repeat(chars.len() - keep), tail)
}

fn inner(text: &str, keep: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= keep * 2 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(chars.len() - keep * 2))
}

fn outer(text: &str, keep: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= keep * 2 {
        return "*".repeat(chars.len());
    }
    let middle: String = chars[keep..chars.len() - keep].iter().collect();
    format!("{}{middle}{}", "*".repeat(keep), "*".repeat(keep))
}

fn range(text: &str, start: usize, end: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
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

fn truncate_date(
    bytes: &Bytes,
    type_oid: u32,
    format: i16,
    kind: Mask,
) -> Result<Bytes, MaskError> {
    let to_month = kind == Mask::DateMonth;

    if format == FORMAT_TEXT {
        // Text is `YYYY-MM-DD[ HH:MM:SS...]`; rebuilding from the leading date
        // avoids re-deriving the timezone suffix.
        let text = String::from_utf8_lossy(bytes);
        if text.len() < 10 || !text.is_char_boundary(10) {
            return Err(MaskError::Undecodable { type_oid, format });
        }
        // Postgres renders pre-year-1 dates with a ` BC` suffix. Dropping it
        // moves the value roughly four thousand years into the future.
        let era = if text.ends_with(" BC") { " BC" } else { "" };
        let year = &text[0..4];
        let month = if to_month { &text[5..7] } else { "01" };
        return Ok(Bytes::from(if type_oid == OID_DATE {
            format!("{year}-{month}-01{era}")
        } else {
            // Keep any timezone suffix so the client parses what it expects.
            let tz = text
                .rfind(['+', '-'])
                .filter(|i| *i > 10)
                .map(|i| &text[i..])
                .unwrap_or("");
            format!("{year}-{month}-01 00:00:00{tz}{era}")
        }));
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
            let floored = (v / b).floor() * b;
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

    match type_oid {
        OID_INT2 if bytes.len() == 2 => {
            let v = i16::from_be_bytes([bytes[0], bytes[1]]) as i64;
            let out = floor_within(v, bucket, i16::MIN as i64, i16::MAX as i64);
            let out = i16::try_from(out).expect("clamped into range above");
            Ok(Bytes::copy_from_slice(&out.to_be_bytes()))
        }
        OID_INT4 if bytes.len() == 4 => {
            let v = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
            let out = floor_within(v, bucket, i32::MIN as i64, i32::MAX as i64);
            let out = i32::try_from(out).expect("clamped into range above");
            Ok(Bytes::copy_from_slice(&out.to_be_bytes()))
        }
        OID_INT8 if bytes.len() == 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[..8]);
            let v = i64::from_be_bytes(raw);
            Ok(Bytes::copy_from_slice(&floor_to(v, bucket).to_be_bytes()))
        }
        OID_FLOAT4 if bytes.len() == 4 => {
            let v = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64;
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
        OID_FLOAT8 if bytes.len() == 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[..8]);
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

/// Floor, then bring the result back inside the column's own range.
///
/// A bucket wider than the type is legitimate — it means "one bucket covers
/// everything" — but the floor then sits below the type's minimum, and the cast
/// wrapped it to a large positive number. `-1` with a bucket of 32769 came back
/// as `32767`. Clamping keeps the guarantee that matters: never above the input.
fn floor_within(v: i64, bucket: i64, min: i64, max: i64) -> i64 {
    floor_to(v, bucket).clamp(min, max)
}

// --- Helpers ----------------------------------------------------------------

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

    #[test]
    fn range_masks_the_requested_window() {
        let mut s = spec(Mask::Range);
        s.start = 2;
        s.end = 6;
        assert_eq!(apply_text(&s, "12345678"), "12****78");
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
