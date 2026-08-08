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

use std::sync::Arc;

use bytes::Bytes;
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
        let digest = self.digest(spec, bytes);

        if type_oid == OID_UUID {
            return Ok(if format == FORMAT_BINARY {
                Bytes::copy_from_slice(&uuid_bytes(&digest))
            } else {
                Bytes::from(uuid_text(&uuid_bytes(&digest)))
            });
        }

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

/// Days from 1970-01-01 to a civil date. Howard Hinnant's algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The inverse.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Postgres counts days and microseconds from 2000-01-01, not the Unix epoch.
const PG_EPOCH_DAYS: i64 = 10957;
const MICROS_PER_DAY: i64 = 86_400_000_000;

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

    match type_oid {
        OID_DATE => {
            if bytes.len() != 4 {
                return Err(MaskError::Undecodable { type_oid, format });
            }
            let days = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
            let (y, m, _) = civil_from_days(days + PG_EPOCH_DAYS);
            let truncated = days_from_civil(y, if to_month { m } else { 1 }, 1) - PG_EPOCH_DAYS;
            Ok(Bytes::copy_from_slice(&(truncated as i32).to_be_bytes()))
        }
        OID_TIMESTAMP | OID_TIMESTAMPTZ => {
            if bytes.len() != 8 {
                return Err(MaskError::Undecodable { type_oid, format });
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[..8]);
            let micros = i64::from_be_bytes(raw);
            // Floor, so instants before the epoch land on the right day.
            let days = micros.div_euclid(MICROS_PER_DAY);
            let (y, m, _) = civil_from_days(days + PG_EPOCH_DAYS);
            let truncated = days_from_civil(y, if to_month { m } else { 1 }, 1) - PG_EPOCH_DAYS;
            // Saturating for the same reason `floor_to` is: the extremes of the
            // i64 microsecond domain are far outside what a day count times a
            // microsecond multiplier can hold, and the wrap moves the value
            // rather than coarsening it.
            Ok(Bytes::copy_from_slice(
                &truncated.saturating_mul(MICROS_PER_DAY).to_be_bytes(),
            ))
        }
        _ => Err(MaskError::Undecodable { type_oid, format }),
    }
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
        if let Ok(v) = text.trim().parse::<i64>() {
            return Ok(Bytes::from(floor_to(v, bucket).to_string()));
        }
        if let Ok(v) = text.trim().parse::<f64>() {
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
            Ok(Bytes::copy_from_slice(&(out as i16).to_be_bytes()))
        }
        OID_INT4 if bytes.len() == 4 => {
            let v = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
            let out = floor_within(v, bucket, i32::MIN as i64, i32::MAX as i64);
            Ok(Bytes::copy_from_slice(&(out as i32).to_be_bytes()))
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
            Ok(Bytes::copy_from_slice(
                &(((v / b).floor() * b) as f32).to_be_bytes(),
            ))
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
    fn civil_date_conversion_round_trips() {
        for (y, m, d) in [
            (1970, 1, 1),
            (2000, 1, 1),
            (2024, 2, 29),
            (1899, 12, 31),
            (2100, 6, 15),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "{y}-{m}-{d}");
        }
    }

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

    #[test]
    fn date_truncation_in_binary_matches_text() {
        let m = masker();
        // 2024-03-15 as days since 2000-01-01.
        let days = (days_from_civil(2024, 3, 15) - PG_EPOCH_DAYS) as i32;
        let out = m
            .apply(
                &spec(Mask::DateYear),
                OID_DATE,
                FORMAT_BINARY,
                Some(Bytes::copy_from_slice(&days.to_be_bytes())),
            )
            .unwrap()
            .unwrap();
        let got = i32::from_be_bytes([out[0], out[1], out[2], out[3]]) as i64;
        assert_eq!(civil_from_days(got + PG_EPOCH_DAYS), (2024, 1, 1));
    }

    #[test]
    fn timestamps_before_the_postgres_epoch_floor_correctly() {
        let m = masker();
        // 1999-06-15, i.e. negative microseconds since 2000-01-01.
        let days = days_from_civil(1999, 6, 15) - PG_EPOCH_DAYS;
        let micros = days * MICROS_PER_DAY;
        let out = m
            .apply(
                &spec(Mask::DateYear),
                OID_TIMESTAMP,
                FORMAT_BINARY,
                Some(Bytes::copy_from_slice(&micros.to_be_bytes())),
            )
            .unwrap()
            .unwrap();
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&out[..8]);
        let got_days = i64::from_be_bytes(raw) / MICROS_PER_DAY;
        assert_eq!(civil_from_days(got_days + PG_EPOCH_DAYS), (1999, 1, 1));
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
}
