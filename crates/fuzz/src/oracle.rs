//! Shared leak oracle.
//!
//! Lives in a library so every harness uses the *same* detectors. It did not,
//! and that cost real coverage: `extended.rs` carried its own one-token list
//! while this one has nine tokens plus four shape detectors, so on the
//! extended/binary path nothing could see a `date-year`, `ip-prefix`,
//! `numeric-bucket` or uuid-pseudonym escape at all. That is the same blind
//! spot that let the windowed-aggregate disclosure through on the simple-query
//! side, reintroduced on the other protocol.

/// Token -> the column it would betray. Each appears in exactly one masked
/// column of the demo fixture and nowhere else in the database.
pub const CANARIES: &[(&str, &str)] = &[
    ("CANARY", "a masked text column in fz"),
    ("00000000-0000-4000-a000-", "fz.people.account_uuid"),
    ("555-77", "fz.people.phone"),
    ("@example.com", "demo.customers.email"),
    ("Customer ", "demo.customers.name"),
    ("555-", "demo.customers.phone"),
    (" Example Street", "demo.orders.ship_address"),
    ("00000000-0000-4000-9000-", "an fz uuid column"),
    ("00000000-0000-4000-8000-", "demo.customers.account_uuid"),
];

/// Values whose *shape* betrays an unmasked type-aware column.
///
/// A substring token cannot cover a date or an IP: the leak is not a marker,
/// it is the absence of coarsening. The fixture is seeded so the raw form is a
/// shape the masked form never has — birth dates are never 1 January,
/// addresses in 198.51.100/24 never end .0 — so these patterns match only
/// values that escaped their mask.
pub fn shape_leak(value: &str) -> Option<&'static str> {
    // 198.51.100.7 escaped; 198.51.100.0 is correctly masked.
    if let Some(rest) = value.strip_prefix("198.51.100.") {
        let host: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !host.is_empty() && host != "0" {
            return Some("fz.people.last_ip (not truncated to /24)");
        }
    }
    // 1975-02-03 escaped; 1975-01-01 is correctly masked.
    //
    // Matched over bytes rather than by slicing the `&str`: a ten-byte window
    // starting at a `19` can end in the middle of a multi-byte character, and
    // `&value[i..i + 10]` panics there rather than declining to match.
    let bytes = value.as_bytes();
    for (i, _) in value.match_indices("19") {
        let Some(&[_, _, y2, y3, b'-', m0, m1, b'-', d0, d1]) = bytes.get(i..i.saturating_add(10))
        else {
            continue;
        };
        // `19` is already known; the remaining eight bytes have to be a date,
        // and `01-01` is what year truncation produces.
        if [y2, y3, m0, m1, d0, d1].iter().all(u8::is_ascii_digit) && [m0, m1, d0, d1] != *b"0101" {
            return Some("fz.people.birth_date (not truncated to its year)");
        }
    }
    // A salary that is not on a bucket boundary.
    //
    // There was no numeric detector here, and it cost something real: the
    // windowed-aggregate disclosure — `sum(annual_salary) OVER (… ROWS BETWEEN
    // CURRENT ROW AND CURRENT ROW)` returning exact salaries — was caught only
    // because the same shape also reached a *date* column. A campaign that
    // happened to reach only salaries would have reported clean.
    //
    // The fixture makes this exact: salaries are `41111 + i * 137` for
    // i in 1..=60, so every raw value lies in a known range and none is a
    // multiple of its bucket, while every masked value is.
    if let Ok(v) = value.trim().parse::<i64>() {
        // Exact membership of the fixture's sequence, not its range.
        //
        // `annual_salary` is `900000000 + i * 137`. A range test over the
        // old 41k values called every integer between them a leak, because
        // `row_number()` over a join produces exactly those integers in order:
        // 8,221 "leaks" in one 3000-statement run, every one an ordinal.
        // Tightening to exact-sequence membership still left 60 — an ordinal
        // sequence sweeps through all sixty real values on its way past.
        //
        // So the fixture moved instead of the test. A detector that cries wolf
        // is worse than none: a real escape would have been three lines into
        // eight thousand.
        if (900_000_001..=900_008_220).contains(&v)
            && v.wrapping_sub(900_000_000).rem_euclid(137) == 0
            && v.rem_euclid(25_000) != 0
        {
            return Some("fz.people.annual_salary (not floored to its bucket)");
        }
        if (9_000_000_000..=9_000_008_220).contains(&v) && v % 1_000_000 != 0 {
            return Some("fz.people.salary_big (not floored to its bucket)");
        }
    }
    None
}
