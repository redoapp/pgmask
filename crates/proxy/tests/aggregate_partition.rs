#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! Pins which of Postgres's aggregates pgmask releases.
//!
//! The list of value-returning functions is the load-bearing artifact of the
//! summaries relaxation, and it was originally written from memory. This is the
//! answer checked against the real thing:
//!
//! ```sql
//! SELECT DISTINCT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
//! WHERE p.prokind = 'a' AND n.nspname = 'pg_catalog' ORDER BY 1;
//! ```
//!
//! 54 aggregates in PostgreSQL 17. The split below is exhaustive over them, so
//! any change to the allowlist shows up here as a diff a human has to approve
//! rather than as a silent widening.

use pgmask::analysis::{analyze, Safety};

/// Every `pg_catalog` aggregate in PostgreSQL 17.
const ALL_AGGREGATES: &[&str] = &[
    "any_value",
    "array_agg",
    "avg",
    "bit_and",
    "bit_or",
    "bit_xor",
    "bool_and",
    "bool_or",
    "corr",
    "count",
    "covar_pop",
    "covar_samp",
    "cume_dist",
    "dense_rank",
    "every",
    "json_agg",
    "json_agg_strict",
    "json_object_agg",
    "json_object_agg_strict",
    "json_object_agg_unique",
    "json_object_agg_unique_strict",
    "jsonb_agg",
    "jsonb_agg_strict",
    "jsonb_object_agg",
    "jsonb_object_agg_strict",
    "jsonb_object_agg_unique",
    "jsonb_object_agg_unique_strict",
    "max",
    "min",
    "mode",
    "percent_rank",
    "percentile_cont",
    "percentile_disc",
    "range_agg",
    "range_intersect_agg",
    "rank",
    "regr_avgx",
    "regr_avgy",
    "regr_count",
    "regr_intercept",
    "regr_r2",
    "regr_slope",
    "regr_sxx",
    "regr_sxy",
    "regr_syy",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "string_agg",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
    "xmlagg",
];

/// The complete set released over a classified column. Everything else refuses.
const RELEASED: &[&str] = &[
    "avg",
    "bool_and",
    "bool_or",
    "corr",
    "count",
    "covar_pop",
    "covar_samp",
    "every",
    "regr_avgx",
    "regr_avgy",
    "regr_count",
    "regr_intercept",
    "regr_r2",
    "regr_slope",
    "regr_sxx",
    "regr_sxy",
    "regr_syy",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
];

#[test]
fn the_released_set_is_exactly_what_we_intend() {
    let mut actual: Vec<&str> = Vec::new();
    for name in ALL_AGGREGATES {
        let sql = format!("SELECT {name}(email) FROM t");
        if analyze(&sql, 1, true).first() == Some(&Safety::Releasable) {
            actual.push(name);
        }
    }
    assert_eq!(
        actual, RELEASED,
        "the released aggregate set changed — every entry converts refusals \
         into acceptances, so this needs a human decision, not a test update"
    );
}

/// Spot-check the reasoning rather than only the membership: each of these
/// hands back a value, or all the values, from the set it consumed.
#[test]
fn every_value_returning_aggregate_is_refused() {
    for name in [
        "any_value",
        "min",
        "max",
        "mode",
        "percentile_disc",
        "percentile_cont",
        "array_agg",
        "string_agg",
        "xmlagg",
        "range_agg",
        "json_agg",
        "json_agg_strict",
        "jsonb_object_agg_unique_strict",
    ] {
        let sql = format!("SELECT {name}(email) FROM t");
        assert_eq!(
            analyze(&sql, 1, true).first(),
            Some(&Safety::Unknown),
            "{name} returns a value it consumed and must never be released"
        );
    }
}
