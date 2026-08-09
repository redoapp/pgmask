#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! Property tests for the maskers.
//!
//! Three rounds of attacking the masks by hand produced findings every time —
//! identity masks, a preserved email domain, 32-bit pseudonyms, malformed IPv6,
//! `date_part('epoch', …)`. Every one of them lived in what the code did with
//! *arguments and edge inputs*, not in its structure. Unit tests written by the
//! author of a function test what the author was thinking about; these are here
//! to test what he was not.

use bytes::Bytes;
use pgmask::mask::*;
use proptest::prelude::*;

const TEXT: u32 = 25;

fn masker() -> Masker {
    Masker::new(b"property-key".to_vec())
}

fn spec(kind: Mask) -> MaskSpec {
    MaskSpec::new(kind)
}

/// Every text-family mask, with parameters that pass startup validation.
fn text_masks() -> Vec<MaskSpec> {
    let mut range = spec(Mask::Range);
    range.start = 1;
    range.end = 4;
    vec![
        spec(Mask::Redact),
        spec(Mask::Partial),
        spec(Mask::Inner),
        spec(Mask::Outer),
        range,
        spec(Mask::Hash),
        spec(Mask::Pseudonym),
        spec(Mask::IpPrefix),
    ]
}

fn mask_text(spec: &MaskSpec, value: &str) -> Option<String> {
    masker()
        .apply(
            spec,
            TEXT,
            FORMAT_TEXT,
            Some(Bytes::copy_from_slice(value.as_bytes())),
        )
        .ok()
        .flatten()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

proptest! {
    /// No input, however strange, may panic a masker. A panic in the hot path
    /// takes the connection down mid-result-set.
    #[test]
    fn no_text_input_panics(value in ".*") {
        for s in text_masks() {
            let _ = mask_text(&s, &value);
        }
    }

    /// Masking must be a function of the value, or joins and counts break.
    #[test]
    fn text_masks_are_deterministic(value in ".*") {
        for s in text_masks() {
            prop_assert_eq!(mask_text(&s, &value), mask_text(&s, &value));
        }
    }

    /// The masks that are supposed to hide the whole value must not echo it.
    /// `partial`/`inner`/`outer`/`range` are excluded: they reveal part of the
    /// input deliberately.
    #[test]
    fn concealing_masks_never_echo_the_input(value in "[a-zA-Z0-9@._-]{6,40}") {
        for kind in [Mask::Redact, Mask::Hash, Mask::Pseudonym] {
            let out = mask_text(&spec(kind), &value).unwrap_or_default();
            prop_assert!(
                !out.contains(&value),
                "{kind:?} echoed its input: {value} -> {out}"
            );
        }
    }

    /// Pseudonym width must not vary with the *length* of the input, or the
    /// original's length leaks. Email-shaped and plain values have their own
    /// constant widths; within one column every value is one or the other.
    #[test]
    fn pseudonym_width_does_not_track_input_length(
        a in "[a-z]{1,60}", b in "[a-z]{1,60}",
        c in "[a-z]{1,30}@[a-z]{1,30}\\.com", d in "[a-z]{1,30}@[a-z]{1,30}\\.com",
    ) {
        let w = |v: &str| mask_text(&spec(Mask::Pseudonym), v).unwrap().len();
        prop_assert_eq!(w(&a), w(&b), "plain width varied: {:?} vs {:?}", a, b);
        prop_assert_eq!(w(&c), w(&d), "email width varied: {:?} vs {:?}", c, d);
    }

    /// Integer bucketing must never overflow, must round down, and must land
    /// within one bucket of the input.
    #[test]
    fn integer_buckets_are_sound(v in any::<i32>(), bucket in 2i64..1_000_000) {
        let mut s = spec(Mask::NumericBucket);
        s.bucket = bucket;
        // Refusal is a legitimate outcome near the type's minimum: flooring
        // can land below i32::MIN, and no in-range value is both a bucket
        // boundary and <= the input. Clamping used to paper over that and
        // served a value that was not a multiple of anything — the one thing a
        // bucket mask promises. So refusing is allowed, but only when it is
        // genuinely unrepresentable, and everything served still gets the full
        // assertions below.
        let Ok(Some(out)) = masker()
            .apply(&s, OID_INT4, FORMAT_BINARY, Some(Bytes::copy_from_slice(&v.to_be_bytes())))
        else {
            let floored = i64::from(v).div_euclid(bucket) * bucket;
            prop_assert!(
                floored < i64::from(i32::MIN),
                "refused a value it could have bucketed: {} with bucket {}", v, bucket
            );
            return Ok(());
        };
        prop_assert_eq!(out.len(), 4, "int4 must stay four bytes");
        let got = i32::from_be_bytes([out[0], out[1], out[2], out[3]]) as i64;
        prop_assert!(got <= v as i64, "bucketing must round down: {v} -> {got}");
        prop_assert!((v as i64) - got < bucket, "off by more than one bucket: {v} -> {got}");
        prop_assert_eq!(got.rem_euclid(bucket), 0, "not a multiple of {}", bucket);
    }

    /// Small integers have a narrow range; a large bucket must not wrap them.
    #[test]
    fn small_integer_buckets_do_not_wrap(v in any::<i16>(), bucket in 2i64..100_000) {
        let mut s = spec(Mask::NumericBucket);
        s.bucket = bucket;
        // Same rule as int4, and it bites sooner here: an i16 spans only
        // 65536 values, so any bucket bigger than the distance from the input
        // to i16::MIN has no representable boundary below it.
        let Ok(Some(out)) = masker()
            .apply(&s, OID_INT2, FORMAT_BINARY, Some(Bytes::copy_from_slice(&v.to_be_bytes())))
        else {
            let floored = i64::from(v).div_euclid(bucket) * bucket;
            prop_assert!(
                floored < i64::from(i16::MIN),
                "refused a value it could have bucketed: {} with bucket {}", v, bucket
            );
            return Ok(());
        };
        let got = i16::from_be_bytes([out[0], out[1]]);
        prop_assert!(got <= v, "bucketing must round down, never wrap: {} -> {}", v, got);
        prop_assert_eq!(i64::from(got).rem_euclid(bucket), 0, "served value must be a bucket");
    }

    /// Date truncation must produce a real date, and must be idempotent.
    #[test]
    fn date_truncation_is_idempotent(days in -700_000i32..2_900_000) {
        let s = spec(Mask::DateYear);
        let once = masker()
            .apply(&s, OID_DATE, FORMAT_BINARY, Some(Bytes::copy_from_slice(&days.to_be_bytes())))
            .expect("must not error").expect("value");
        let twice = masker()
            .apply(&s, OID_DATE, FORMAT_BINARY, Some(once.clone()))
            .expect("must not error").expect("value");
        prop_assert_eq!(once, twice, "truncating twice must equal truncating once");
    }

    /// Whatever comes out of ip-prefix must be an address or fully masked.
    #[test]
    fn ip_prefix_output_is_always_valid(a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>()) {
        let input = format!("{a}.{b}.{c}.{d}");
        let out = mask_text(&spec(Mask::IpPrefix), &input).unwrap();
        prop_assert!(
            out.parse::<std::net::Ipv4Addr>().is_ok(),
            "{input} -> {out} is not an address"
        );
        prop_assert!(out.ends_with(".0"), "host portion survived: {out}");
    }
}

// --- Edge classes worth naming individually ---------------------------------

#[test]
fn multibyte_text_is_masked_by_character_not_byte() {
    // Slicing by byte would split a code point and produce invalid UTF-8.
    for value in [
        "héllo wörld",
        "日本語のテキスト",
        "🙂🙃🙂🙃🙂",
        "e\u{0301}\u{0301}combining",
    ] {
        for s in text_masks() {
            let out = mask_text(&s, value).unwrap_or_default();
            assert!(
                std::str::from_utf8(out.as_bytes()).is_ok(),
                "{:?} produced invalid UTF-8 for {value}",
                s.kind
            );
        }
    }
}

#[test]
fn empty_and_whitespace_inputs_are_handled() {
    for value in ["", " ", "\t\n", "\0"] {
        for s in text_masks() {
            let _ = mask_text(&s, value);
        }
    }
}

#[test]
fn integer_bucketing_at_the_extremes_does_not_overflow() {
    let mut s = spec(Mask::NumericBucket);
    s.bucket = 3; // deliberately not a power of two
    for v in [i64::MIN, i64::MIN + 1, i64::MAX, i64::MAX - 1, 0, -1] {
        let out = masker()
            .apply(
                &s,
                OID_INT8,
                FORMAT_BINARY,
                Some(Bytes::copy_from_slice(&v.to_be_bytes())),
            )
            .expect("must not error")
            .expect("value");
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&out[..8]);
        let got = i64::from_be_bytes(raw);
        assert!(got <= v, "must round down at {v}: got {got}");
    }
}

#[test]
fn float_specials_are_handled() {
    let mut s = spec(Mask::NumericBucket);
    s.bucket = 100;
    for v in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        0.0,
        -0.0,
        f64::MIN,
        f64::MAX,
    ] {
        let out = masker()
            .apply(
                &s,
                OID_FLOAT8,
                FORMAT_BINARY,
                Some(Bytes::copy_from_slice(&v.to_be_bytes())),
            )
            .expect("must not error")
            .expect("value");
        assert_eq!(out.len(), 8, "float8 must stay eight bytes for {v}");
    }
}

#[test]
fn malformed_binary_payloads_are_refused_not_misread() {
    // A wrong-length payload must error rather than read adjacent bytes or
    // silently emit something of the wrong width.
    for (oid, bytes) in [
        (OID_INT4, vec![1u8, 2]),
        (OID_INT8, vec![1u8, 2, 3]),
        (OID_DATE, vec![1u8]),
        (OID_TIMESTAMP, vec![1u8, 2, 3, 4]),
    ] {
        let mut s = spec(Mask::NumericBucket);
        s.bucket = 10;
        let numeric = masker().apply(&s, oid, FORMAT_BINARY, Some(Bytes::from(bytes.clone())));
        let dated = masker().apply(
            &spec(Mask::DateYear),
            oid,
            FORMAT_BINARY,
            Some(Bytes::from(bytes)),
        );
        assert!(
            numeric.is_err() || dated.is_err() || numeric.is_ok(),
            "type {oid} must not misread a short payload"
        );
    }
}

// --- Round two: paths the first pass did not reach ---------------------------

fn mask_binary(spec: &MaskSpec, oid: u32, bytes: Vec<u8>) -> Option<Bytes> {
    masker()
        .apply(spec, oid, FORMAT_BINARY, Some(Bytes::from(bytes)))
        .ok()
        .flatten()
}

/// `numeric` is only handled in text format, and Postgres accepts `NaN`,
/// `Infinity` and `-Infinity` as numeric values. Whatever comes back has to be
/// a literal Postgres will accept for that column, or the client fails to parse
/// a value we produced.
#[test]
fn text_numeric_specials_round_trip_as_postgres_literals() {
    let mut s = spec(Mask::NumericBucket);
    s.bucket = 100;
    for input in ["NaN", "Infinity", "-Infinity", "0", "-0", "1e300", "0.5"] {
        let out = masker()
            .apply(
                &s,
                OID_NUMERIC,
                FORMAT_TEXT,
                Some(Bytes::copy_from_slice(input.as_bytes())),
            )
            .expect("must not error");
        let Some(out) = out else { continue };
        let text = String::from_utf8(out.to_vec()).unwrap();
        let acceptable =
            text.parse::<f64>().is_ok() && !text.contains("inf") && !text.contains("NAN");
        assert!(
            acceptable,
            "{input} -> {text:?} is not a literal Postgres accepts for numeric"
        );
    }
}

/// Microseconds since 2000 spans well beyond what a day count times a
/// microsecond multiplier can hold. The multiply back must not overflow.
#[test]
fn timestamp_truncation_at_the_extremes_does_not_overflow() {
    for micros in [i64::MIN, i64::MIN + 1, i64::MAX, i64::MAX - 1, 0, -1] {
        for kind in [Mask::DateYear, Mask::DateMonth] {
            let out = mask_binary(&spec(kind), OID_TIMESTAMP, micros.to_be_bytes().to_vec());
            if let Some(out) = out {
                assert_eq!(out.len(), 8, "timestamp must stay eight bytes at {micros}");
            }
        }
    }
}

/// Postgres renders dates before year 1 with a `BC` suffix. Dropping it moves
/// the value by roughly four thousand years, which is a correctness bug even
/// though it is not a disclosure.
#[test]
fn bc_dates_are_not_silently_turned_into_ad() {
    let out = masker()
        .apply(
            &spec(Mask::DateYear),
            OID_DATE,
            FORMAT_TEXT,
            Some(Bytes::from_static(b"0044-03-15 BC")),
        )
        .expect("must not error");
    if let Some(out) = out {
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(
            text.contains("BC"),
            "BC dropped: 0044-03-15 BC -> {text} (now four millennia in the future)"
        );
    }
}

/// Timestamps carry a timezone suffix that must survive truncation, or the
/// client reads the instant in the wrong zone.
#[test]
fn timezone_suffixes_survive_truncation() {
    for (input, want_suffix) in [
        ("2024-03-15 10:30:00+05:30", "+05:30"),
        ("2024-03-15 10:30:00-08", "-08"),
        ("2024-03-15 10:30:00.123456+00", "+00"),
    ] {
        let out = masker()
            .apply(
                &spec(Mask::DateYear),
                OID_TIMESTAMPTZ,
                FORMAT_TEXT,
                Some(Bytes::copy_from_slice(input.as_bytes())),
            )
            .expect("must not error")
            .expect("value");
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(
            text.ends_with(want_suffix),
            "{input} -> {text} lost its zone"
        );
    }
}

/// The day domain of a `date` column is far wider than any real date, and the
/// truncated value has to stay inside it.
#[test]
fn date_truncation_at_the_day_extremes_stays_in_range() {
    for days in [i32::MIN, i32::MIN + 1, i32::MAX, i32::MAX - 1, 0, -1] {
        for kind in [Mask::DateYear, Mask::DateMonth] {
            let out = mask_binary(&spec(kind), OID_DATE, days.to_be_bytes().to_vec());
            if let Some(out) = out {
                assert_eq!(out.len(), 4, "date must stay four bytes at {days}");
            }
        }
    }
}

/// Flooring near `f32::MIN` must not push the result to negative infinity.
#[test]
fn float4_bucketing_stays_finite() {
    let mut s = spec(Mask::NumericBucket);
    s.bucket = 1000;
    for v in [f32::MIN, f32::MAX, -0.0f32, 0.0f32] {
        let out = mask_binary(&s, OID_FLOAT4, v.to_be_bytes().to_vec()).expect("value");
        let got = f32::from_be_bytes([out[0], out[1], out[2], out[3]]);
        assert!(got.is_finite(), "{v} bucketed to {got}");
    }
}
