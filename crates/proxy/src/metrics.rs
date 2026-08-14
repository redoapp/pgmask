//! Why result sets get refused, counted by cause.
//!
//! The point is a decision, not dashboards. We currently reject every result set
//! containing a field with no provenance, and we are *guessing* that set
//! operations are the dominant cause. That guess decides whether the Phase 6
//! parser is worth building. Counting for a week in shadow mode replaces the
//! guess for an afternoon of work.
//!
//! # Why the buckets are heuristic, and why that is fine here
//!
//! `tableID = 0` tells us "not a stored column" and nothing else, so the cause
//! cannot be recovered exactly without parsing. But Postgres names output
//! columns predictably, and the name is a good enough signal to *bucket* them:
//!
//! * `?column?`      — an anonymous expression: a literal, an operator, a cast
//! * `count`, `sum`  — an aggregate
//! * `lower`, `upper`— a function call, named after the function
//! * a real column name — the interesting one. Set operations, recursive CTEs
//!   and `SETOF` functions all *preserve* the source column's name while losing
//!   its provenance, so an opaque field named exactly like a column we classify
//!   is very likely one of those.
//!
//! This inference would be unsound for enforcement — a query can alias anything
//! to anything — which is why it is confined to counters. Nothing here changes
//! what gets masked.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::catalog::Snapshot;

/// Aggregate function names, for bucketing only.
const AGGREGATES: &[&str] = &[
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "string_agg",
    "array_agg",
    "json_agg",
    "jsonb_agg",
    "bool_and",
    "bool_or",
    "every",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// Opaque field named like a column we classify. Likely a set operation,
    /// recursive CTE, or SETOF function — the class Phase 6 would fix first.
    OpaqueNamedLikeColumn,
    /// Opaque field named `?column?`: a literal, operator or cast.
    OpaqueAnonymous,
    /// Opaque field named after an aggregate.
    OpaqueAggregate,
    /// Opaque field named after some other function.
    OpaqueFunction,
    /// The configured mask cannot apply to this column's type.
    MaskTypeMismatch,
    /// Rows arrived with no described result set.
    NoActivePlan,
    /// A COPY stream, which carries no RowDescription.
    CopyStream,
    /// The legacy FunctionCall message.
    FunctionCallMessage,
    /// A backend message we do not recognise.
    UnknownBackendMessage,
    /// A message we could not parse.
    Malformed,
    /// SCRAM channel binding through a TLS-terminating proxy.
    ChannelBinding,
    /// A client that had not negotiated TLS, refused because one is required.
    PlaintextRefused,
    /// A plaintext session that policy allows. Counted so that "we run with
    /// TLS" is a claim the operator can check rather than assume: this is the
    /// only signal distinguishing a certificate that is configured from one
    /// that is used.
    PlaintextSession,
    /// `posture = "hostile"` refused a statement that named a masked column
    /// outside a bare outermost projection.
    HostileMaskedUse,
    /// Authenticated principal exceeded `rate_limit_per_minute` /
    /// `rate_limit_burst`. The statement never reached the backend.
    RateLimited,
    /// A statement emitted more notices than `max_notices_per_exchange`.
    /// Excess notices are dropped for the rest of the exchange.
    NoticeFlood,
    /// DML, DDL, `DO`/`CALL`, or other mutating SQL — pgmask is read-only.
    WriteRefused,
    /// SQL `PREPARE`/`EXECUTE`/`DEALLOCATE` or `DECLARE`/`FETCH`/`CLOSE`.
    /// The extended protocol (Parse/Bind/Execute) is the supported path;
    /// `SELECT … FETCH FIRST n ROWS` is a limit clause, not this class.
    SqlPrepareCursor,
    /// A function call outside the trusted `pg_catalog` allowlist.
    UntrustedFunction,
    /// Statement named a system catalog that holds sampled user data,
    /// passwords, or other sessions' SQL (`pg_stats`, `pg_authid`, …).
    LeakyCatalog,
}

impl Cause {
    pub const ALL: &'static [Cause] = &[
        Cause::OpaqueNamedLikeColumn,
        Cause::OpaqueAnonymous,
        Cause::OpaqueAggregate,
        Cause::OpaqueFunction,
        Cause::MaskTypeMismatch,
        Cause::NoActivePlan,
        Cause::CopyStream,
        Cause::FunctionCallMessage,
        Cause::UnknownBackendMessage,
        Cause::Malformed,
        Cause::ChannelBinding,
        Cause::PlaintextRefused,
        Cause::PlaintextSession,
        Cause::HostileMaskedUse,
        Cause::RateLimited,
        Cause::NoticeFlood,
        Cause::WriteRefused,
        Cause::SqlPrepareCursor,
        Cause::UntrustedFunction,
        Cause::LeakyCatalog,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Cause::OpaqueNamedLikeColumn => "opaque_named_like_column",
            Cause::OpaqueAnonymous => "opaque_anonymous",
            Cause::OpaqueAggregate => "opaque_aggregate",
            Cause::OpaqueFunction => "opaque_function",
            Cause::MaskTypeMismatch => "mask_type_mismatch",
            Cause::NoActivePlan => "no_active_plan",
            Cause::CopyStream => "copy_stream",
            Cause::FunctionCallMessage => "function_call_message",
            Cause::UnknownBackendMessage => "unknown_backend_message",
            Cause::Malformed => "malformed",
            Cause::ChannelBinding => "channel_binding",
            Cause::PlaintextRefused => "plaintext_refused",
            Cause::PlaintextSession => "plaintext_session",
            Cause::HostileMaskedUse => "hostile_masked_use",
            Cause::RateLimited => "rate_limited",
            Cause::NoticeFlood => "notice_flood",
            Cause::WriteRefused => "write_refused",
            Cause::SqlPrepareCursor => "sql_prepare_cursor",
            Cause::UntrustedFunction => "untrusted_function",
            Cause::LeakyCatalog => "leaky_catalog",
        }
    }

    fn index(self) -> usize {
        Cause::ALL.iter().position(|c| *c == self).unwrap_or(0)
    }

    /// Bucket an opaque output field by the name Postgres gave it.
    pub fn classify_opaque(field_name: &str, snapshot: &Snapshot) -> Cause {
        if field_name == "?column?" {
            return Cause::OpaqueAnonymous;
        }
        let lower = field_name.to_ascii_lowercase();
        if AGGREGATES.contains(&lower.as_str()) {
            return Cause::OpaqueAggregate;
        }
        // Checked before the generic function bucket: a set operation keeps the
        // source column's name, and that is the signal we most want to see.
        if snapshot.classified_column_names().contains(field_name) {
            return Cause::OpaqueNamedLikeColumn;
        }
        Cause::OpaqueFunction
    }
}

/// Register the Prometheus metric names and their help text.
///
/// Called once at startup when an exporter is configured. Describing them up
/// front means a metric that has not fired yet still appears in the scrape with
/// its documentation, rather than materialising the first time something goes
/// wrong — which is exactly when you do not want to be guessing what it means.
pub fn describe() {
    metrics::describe_counter!(
        "pgmask_result_sets_masked_total",
        "Result sets in which at least one field was masked"
    );
    metrics::describe_counter!(
        "pgmask_fields_masked_total",
        "Columns carrying a mask, summed over result sets — not values rewritten"
    );
    metrics::describe_counter!(
        "pgmask_values_masked_total",
        "Individual values rewritten by a mask, summed over sessions"
    );
    metrics::describe_counter!("pgmask_sessions_total", "Client connections closed");
    metrics::describe_counter!(
        "pgmask_rejections_total",
        "Result sets refused, labelled by cause"
    );
    metrics::describe_counter!(
        "pgmask_fields_rescued_total",
        "Opaque fields released as provably carrying no column value; each is a rejection that did not happen"
    );
}

/// Process-wide counters. Cheap enough to touch on every rejection.
///
/// These atomics stay even though every event is also emitted to the `metrics`
/// crate, because the two answer different questions. The `metrics` crate has
/// no read-back API, and the periodic summary line must work when no exporter
/// is configured — which is the common case for a local run, and how the
/// rejection-cause question got answered in the first place.
#[derive(Debug, Default)]
pub struct Metrics {
    // Sized from the enum, not from a literal. `[AtomicU64; 11]` indexed by
    // `Cause::index()` was correct only for as long as nobody added a variant,
    // and the failure would have been a panic on the rejection path — the one
    // place the proxy most needs to keep working.
    counters: [AtomicU64; Cause::ALL.len()],
    result_sets_masked: AtomicU64,
    fields_masked: AtomicU64,
    /// Opaque fields passed through because they were positively identified as
    /// carrying no column value. Each one is a rejection that did not happen.
    fields_rescued: AtomicU64,
}

impl Metrics {
    pub fn record(&self, cause: Cause) {
        if let Some(counter) = self.counters.get(cause.index()) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        // A label rather than a metric per cause, so a new `Cause` variant
        // needs no exporter change and queries can sum across causes.
        metrics::counter!("pgmask_rejections_total", "cause" => cause.label()).increment(1);
    }

    pub fn record_rescued(&self) {
        self.fields_rescued.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("pgmask_fields_rescued_total").increment(1);
    }

    /// Emitted once per session rather than per value.
    ///
    /// The per-value site runs for every field of every row, and the `metrics`
    /// macros do a registry lookup on each call. Benchmarking already showed
    /// this proxy is syscall-bound, and adding a lookup to the innermost loop
    /// to count something a session can total up itself is not a trade worth
    /// making.
    pub fn record_session_end(&self, values_masked: u64) {
        metrics::counter!("pgmask_sessions_total").increment(1);
        if values_masked > 0 {
            metrics::counter!("pgmask_values_masked_total").increment(values_masked);
        }
    }

    pub fn record_masked_result_set(&self, fields: u64) {
        self.result_sets_masked.fetch_add(1, Ordering::Relaxed);
        self.fields_masked.fetch_add(fields, Ordering::Relaxed);
        metrics::counter!("pgmask_result_sets_masked_total").increment(1);
        metrics::counter!("pgmask_fields_masked_total").increment(fields);
    }

    pub fn total_rejections(&self) -> u64 {
        self.counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }

    pub fn count(&self, cause: Cause) -> u64 {
        self.counters
            .get(cause.index())
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// One line, zero-valued causes omitted. Empty when nothing has happened.
    pub fn report(&self) -> Option<String> {
        let total = self.total_rejections();
        let masked = self.result_sets_masked.load(Ordering::Relaxed);
        if total == 0 && masked == 0 {
            return None;
        }
        let mut parts = vec![
            format!("result_sets_masked={masked}"),
            format!(
                "fields_masked={}",
                self.fields_masked.load(Ordering::Relaxed)
            ),
            format!("rejections={total}"),
            format!(
                "fields_rescued={}",
                self.fields_rescued.load(Ordering::Relaxed)
            ),
        ];
        for cause in Cause::ALL {
            let n = self
                .counters
                .get(cause.index())
                .map_or(0, |c| c.load(Ordering::Relaxed));
            if n > 0 {
                parts.push(format!("{}={n}", cause.label()));
            }
        }
        // The number the Phase 6 decision actually turns on.
        if total > 0 {
            let setop = self
                .counters
                .get(Cause::OpaqueNamedLikeColumn.index())
                .map_or(0, |c| c.load(Ordering::Relaxed));
            parts.push(format!(
                "set_op_like_share={:.0}%",
                (setop as f64 / total as f64) * 100.0
            ));
        }
        Some(parts.join(" "))
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
    use crate::mask::Mask;

    #[test]
    fn metric_help_text_survives_the_source_formatting() {
        // A `\`-continued string literal keeps the indentation of the next
        // line, and the run of spaces went out over the scrape endpoint. Cheap
        // to assert, invisible until someone reads /metrics.
        let source = include_str!("metrics.rs");
        for line in source.lines() {
            let line = line.trim();
            if line.starts_with('"') && line.contains("  ") && !line.contains("//") {
                panic!("collapsed whitespace in a string literal: {line}");
            }
        }
    }

    fn snapshot_with(name: &str) -> Snapshot {
        let mut s = Snapshot::default();
        s.insert_for_test(1, 1, Mask::Redact, name);
        s
    }

    #[test]
    fn anonymous_expressions_are_bucketed_apart() {
        let s = snapshot_with("public.t.email");
        assert_eq!(
            Cause::classify_opaque("?column?", &s),
            Cause::OpaqueAnonymous
        );
    }

    #[test]
    fn aggregates_are_bucketed_apart() {
        let s = snapshot_with("public.t.email");
        assert_eq!(Cause::classify_opaque("count", &s), Cause::OpaqueAggregate);
        assert_eq!(
            Cause::classify_opaque("string_agg", &s),
            Cause::OpaqueAggregate
        );
    }

    #[test]
    fn a_preserved_column_name_signals_a_set_operation() {
        // `SELECT email ... UNION ...` keeps the name but loses provenance.
        let s = snapshot_with("public.t.email");
        assert_eq!(
            Cause::classify_opaque("email", &s),
            Cause::OpaqueNamedLikeColumn
        );
    }

    #[test]
    fn other_function_calls_fall_through() {
        let s = snapshot_with("public.t.email");
        assert_eq!(Cause::classify_opaque("lower", &s), Cause::OpaqueFunction);
    }

    #[test]
    fn report_is_silent_until_something_happens() {
        let m = Metrics::default();
        assert!(m.report().is_none());
        m.record(Cause::OpaqueAnonymous);
        let line = m.report().expect("should report");
        assert!(line.contains("opaque_anonymous=1"));
        assert!(!line.contains("copy_stream"), "zero causes are omitted");
    }

    #[test]
    fn report_surfaces_the_share_that_drives_the_phase_6_decision() {
        let m = Metrics::default();
        for _ in 0..3 {
            m.record(Cause::OpaqueNamedLikeColumn);
        }
        m.record(Cause::OpaqueAnonymous);
        let line = m.report().unwrap();
        assert!(line.contains("set_op_like_share=75%"), "got: {line}");
    }
}
