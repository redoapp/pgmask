//! Coverage-guided oracle for the extended-query protocol state machine.
//!
//! Every other campaign in this repo fuzzes SQL *shapes* — what a statement
//! says. None of them fuzzes the order the client says it in, and a disclosure
//! lived there: a simple query issued while a `Describe` was still in flight
//! cleared the describe queue, so the backend's answer to the `Describe` was
//! read as the simple query's `RowDescription` and classified under the simple
//! query's text. `SELECT (SELECT a FROM users LIMIT 1) AS x`, described and
//! executed ahead of a `SELECT 1`, then had its masked value served verbatim —
//! found live, three ways, on the wire.
//!
//! The fix is structural: Describes and simple queries share one FIFO of
//! description entries in stream order, each carrying the SQL it was created
//! from, and nothing is cleared early. Every `RowDescription` matches the
//! message at the head of that queue, so a query cannot displace a Describe's
//! answer, and two simple queries cannot substitute each other's text.
//!
//! No amount of SQL-shape generation reaches that. It is an interleaving.
//!
//! This module is a *child* of `plan_state`, deliberately, and reached through
//! `#[path]` rather than by moving the production file. Rust privacy makes a
//! sibling module unable to see `PlanState`'s fields, and the oracle needs
//! them: the whole question is "which Describe is at the head of the queue, and
//! what SQL did `describe` record for it". A test that had to infer that from
//! the outside would be inferring it from `described_sql` — the function under
//! test — and would agree with any answer it gave.
//!
//! # What the oracle knows
//!
//! Two things, kept strictly apart:
//!
//! * **Ground truth**, read straight off the private fields: which entry is at
//!   the head of `pending_descriptions` — a Describe or a simple Query — and
//!   the epochs on each queue. These are written by `describe`,
//!   `begin_simple_query`, `parse`, `bind` and `sync` — never by the functions
//!   whose answers are being checked.
//! * **A monotone shadow**, maintained here: the set of SQL texts ever parsed
//!   under each statement name, the set of statements each portal was ever
//!   bound to, the set of texts ever issued as a simple query, and which
//!   Describe target each plan was built for.
//!
//! The shadow is deliberately *monotone* — sets that only grow, never a replay
//! of `discard_failed_epoch`'s retention rules. Reimplementing those would make
//! the oracle a second copy of the code it is checking, and a wrong copy reports
//! false violations, which is how a fuzz target gets turned off. Monotone sets
//! can only ever be a superset of what is legitimate, so every violation this
//! reports is real. It gives up the ability to notice a *stale but
//! same-name* answer, and buys the guarantee that a failure is a bug.
//!
//! # Invariants
//!
//! | | |
//! |---|---|
//! | `described_sql` provenance | the text returned must be the one the head entry was created with — a simple query's text can never answer for a pending Describe, and vice versa |
//! | plan origin | a plan served by `execute` must have been described for that portal, or for a statement that portal was bound to — never a simple result's plan |
//! | queue honesty | a simple query enqueues its own entry and never displaces an earlier Describe; a `RowDescription`, `NoData`, `EmptyQueryResponse`, or no-row `CommandComplete` only ever consumes the entry it belongs to |
//! | catalog generation | a plan served after a catalog refresh must have been built after it |
//! | epoch ordering | queue epochs are non-decreasing and never exceed `sync_epoch` |
//! | no panic | every sequence, including nonsense ones |
//!
//! # What this cannot see
//!
//! Written down because the failure being guarded against is a probe that
//! reports clean while looking somewhere else, and the only defence against
//! that is being explicit about where it is not looking.
//!
//! * **Stale-but-same-name.** The shadow is monotone, so if `described_sql`
//!   returned an *older* text that had genuinely been parsed under that same
//!   statement name, this passes. That is the exact shape of
//!   `plan_state::tests::a_rejected_reparse_cannot_replace_the_backends_sql_identity`,
//!   which is a hand-written test for that reason. Catching it here would mean
//!   replaying `discard_failed_epoch`'s retention rules in the oracle — a second
//!   copy of the code under test, and a wrong copy reports violations that are
//!   not there, which is how a fuzz target gets switched off.
//! * **Sequencing by `Session`.** This drives `PlanState` directly. It says
//!   nothing about whether `session.rs` calls the right method for a given
//!   backend message — only that no ordering of those calls can confuse the
//!   state machine.
//! * **What a plan *means*.** Plans here are opaque markers. Whether the
//!   classification behind one is correct is what every other campaign in this
//!   repository is for.
//! * **Concurrency.** One session, one thread. Cross-session bleed is
//!   `crates/fuzz/src/bin/roles.rs`.

// Assertions are the point of this module, and it is compiled only under the
// `fuzzing` feature — it is never in the proxy binary.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;

use super::{FieldPlan, PendingDescription, Plan, PlanState};
use crate::mask::{Mask, MaskSpec};
use crate::protocol::DescribeTarget;

/// Statement and portal names, shared between both namespaces on purpose.
///
/// Small so the fuzzer collides them constantly — reuse of a name across a
/// failed epoch is the situation `discard_failed_epoch` exists for. `""` is the
/// unnamed statement and the unnamed portal, which is what almost every real
/// driver actually uses.
const NAMES: [&str; 4] = ["", "a", "b", "c"];

/// Texts a `Parse` can carry. Disjoint from [`SIMPLE_SQL`], and each one
/// unique, so the answer to `described_sql` identifies its own origin.
const PARSE_SQL: [&str; 6] = [
    "SELECT upper(email) FROM users",
    "SELECT ssn FROM people",
    "SELECT id, token FROM sessions",
    "SELECT 1",
    "UPDATE t SET a = 1",
    "SELECT card_number FROM cards",
];

/// Texts a simple `Query` can carry.
///
/// `SELECT 1, 2` is the exact text from the disclosure: two integer literals,
/// no provenance, nothing to mask — which is why substituting it as another
/// statement's identity releases that statement's fields.
const SIMPLE_SQL: [&str; 4] = ["SELECT 1, 2", "SELECT now()", "SELECT 42", "BEGIN"];

/// A Describe target, as the oracle records it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Statement(&'static str),
    Portal(&'static str),
    /// A plan built for a simple query's result. It may only serve that
    /// result, never an Execute's.
    Simple,
}

fn name_of(index: u8) -> &'static str {
    NAMES[index as usize % NAMES.len()]
}

fn bytes_of(name: &'static str) -> Bytes {
    Bytes::from_static(name.as_bytes())
}

/// A `PlanState` plus everything needed to judge its answers.
pub struct ProtocolModel {
    state: PlanState,

    /// Monotonically increasing operation counter, used to order events.
    step: usize,

    /// Shadow of the catalog generation last handed to `invalidate_if_stale`.
    generation: u64,
    /// Step at which a refresh last actually dropped the cached plans.
    last_invalidation: Option<usize>,

    /// Every text ever parsed under a statement name.
    parsed_under: BTreeMap<&'static str, BTreeSet<&'static str>>,
    /// Every statement a portal was ever bound to.
    bound_from: BTreeMap<&'static str, BTreeSet<&'static str>>,
    /// Every text ever issued as a simple query.
    simple_texts: BTreeSet<&'static str>,

    next_plan_id: u32,
    /// Describe targets each plan was built for.
    plan_targets: BTreeMap<u32, BTreeSet<Target>>,
    /// Step at which each plan was built.
    plan_built: BTreeMap<u32, usize>,

    /// Mirrors `Session::suppressing`, so `finish_suppressed_epoch` can be
    /// driven with the epoch the proxy would really pass it.
    suppressing: Option<u64>,
}

impl Default for ProtocolModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolModel {
    pub fn new() -> Self {
        Self {
            state: PlanState::default(),
            step: 0,
            generation: 0,
            last_invalidation: None,
            parsed_under: BTreeMap::new(),
            bound_from: BTreeMap::new(),
            simple_texts: BTreeSet::new(),
            next_plan_id: 1,
            plan_targets: BTreeMap::new(),
            plan_built: BTreeMap::new(),
            suppressing: None,
        }
    }

    // ---- frontend messages -------------------------------------------------

    pub fn parse(&mut self, name: u8, sql: u8) {
        let name = name_of(name);
        let sql = PARSE_SQL[sql as usize % PARSE_SQL.len()];
        self.parsed_under.entry(name).or_default().insert(sql);
        self.state.parse(bytes_of(name), sql.to_string());
        self.after_step();
    }

    /// A `Parse` the proxy could not decode.
    ///
    /// `protocol::parse_parse` returns `None` for a non-UTF-8 client encoding
    /// and `handle_frontend` then forwards the message without telling
    /// `PlanState` — so the backend has a prepared statement the proxy has no
    /// SQL for. That is the precondition for the disclosure, and it needs to be
    /// a first-class operation rather than something the fuzzer has to
    /// stumble into by describing a name nobody parsed.
    pub fn parse_undecodable(&mut self) {
        // Nothing recorded, by construction. Present so the op alphabet mirrors
        // the real message set rather than the subset PlanState hears about.
        self.after_step();
    }

    pub fn bind(&mut self, portal: u8, statement: u8, formats: Option<Vec<i16>>) {
        let portal = name_of(portal);
        let statement = name_of(statement);
        self.bound_from.entry(portal).or_default().insert(statement);
        self.state
            .bind(bytes_of(portal), bytes_of(statement), formats);
        self.after_step();
    }

    pub fn describe_statement(&mut self, name: u8) {
        self.state
            .describe(DescribeTarget::Statement(bytes_of(name_of(name))));
        self.after_step();
    }

    pub fn describe_portal(&mut self, portal: u8) {
        self.state
            .describe(DescribeTarget::Portal(bytes_of(name_of(portal))));
        self.after_step();
    }

    pub fn execute(&mut self, portal: u8) {
        let portal = name_of(portal);
        self.state.execute(&bytes_of(portal));

        // The moment a plan is handed to a result set. Everything about "served
        // for something it was not described for" is decided here.
        if let Some(id) = self.active_plan_id() {
            let built_for = self.plan_targets.get(&id).cloned().unwrap_or_default();
            assert!(
                !built_for.contains(&Target::Simple),
                "step {}: Execute on portal {portal:?} activated plan {id}, built for a simple \
                 query's result. A simple result's plan must never reach an Execute's result set.",
                self.step
            );
            let described_for_this_portal = built_for.contains(&Target::Portal(portal))
                || self
                    .bound_from
                    .get(portal)
                    .into_iter()
                    .flatten()
                    .any(|statement| built_for.contains(&Target::Statement(statement)));
            assert!(
                described_for_this_portal,
                "step {}: Execute on portal {portal:?} activated plan {id}, which was described \
                 for {built_for:?}. A plan may only reach a result set through the portal it was \
                 described for, or through a statement that portal was bound to.",
                self.step
            );

            let built = self.plan_built[&id];
            if let Some(refreshed) = self.last_invalidation {
                assert!(
                    built > refreshed,
                    "step {}: Execute on portal {portal:?} served plan {id}, built at step \
                     {built}, across the catalog refresh at step {refreshed}. A refresh \
                     re-resolves names to OIDs and PostgreSQL recycles them, so a plan from the \
                     previous snapshot can be a different column's mask.",
                    self.step
                );
            }
        }

        self.after_step();
    }

    pub fn sync(&mut self) {
        self.state.sync();
        self.after_step();
    }

    pub fn close_statement(&mut self, name: u8) {
        self.state
            .close(DescribeTarget::Statement(bytes_of(name_of(name))));
        self.after_step();
    }

    pub fn close_portal(&mut self, portal: u8) {
        self.state
            .close(DescribeTarget::Portal(bytes_of(name_of(portal))));
        self.after_step();
    }

    /// A simple `Query`. `sql = None` models a body the proxy could not decode.
    pub fn simple_query(&mut self, sql: Option<u8>) {
        let before = self.state.pending_descriptions.len();
        let text = sql.map(|index| SIMPLE_SQL[index as usize % SIMPLE_SQL.len()]);
        if let Some(text) = text {
            self.simple_texts.insert(text);
        }
        self.state.begin_simple_query(text.map(str::to_string));
        assert_eq!(
            self.state.pending_descriptions.len(),
            before + 1,
            "step {}: a simple Query must enqueue its own result and never displace earlier \
             Describes or queries — a Describe still in flight is answered before this result",
            self.step
        );
        self.after_step();
    }

    // ---- backend replies ---------------------------------------------------

    pub fn finish_parse(&mut self) {
        self.state.finish_parse();
        self.after_step();
    }

    pub fn finish_bind(&mut self) {
        self.state.finish_bind();
        self.after_step();
    }

    /// A `RowDescription` the proxy turned into a plan.
    ///
    /// `fields` is clamped to at least one, because the plan's identity is
    /// carried in each field's `type_oid` — `bind` re-stamps `format` but
    /// clones everything else, so the marker survives the round trip through a
    /// portal.
    pub fn finish_description(&mut self, fields: u8) {
        let id = self.next_plan_id;
        self.next_plan_id += 1;
        let width = 1 + (fields as usize % 3);

        let make_plan = |id: u32, width: usize| -> Plan {
            Arc::new(
                (0..width)
                    .map(|_| FieldPlan {
                        spec: MaskSpec::new(Mask::None),
                        type_oid: id,
                        format: 0,
                        lenient: false,
                    })
                    .collect(),
            )
        };

        // A RowDescription that answered a simple query streams it right now;
        // one that answered a Describe arms a *future* result set.
        let (expected_simple, target) = match self.state.pending_descriptions.front() {
            Some(PendingDescription::Describe(pending)) => {
                let target = match &pending.target {
                    DescribeTarget::Statement(name) => Target::Statement(static_name(name)),
                    DescribeTarget::Portal(name) => Target::Portal(static_name(name)),
                };
                (false, target)
            }
            Some(PendingDescription::Simple(_)) => (true, Target::Simple),
            None => {
                // A RowDescription with nothing queued is a desync the proxy
                // refuses: consuming it as a simple result would classify it
                // under a text it was not asked with — exactly the
                // misattribution this fix exists to refuse.
                assert!(
                    self.state.finish_description(make_plan(id, width)).is_err(),
                    "step {}: finish_description accepted a RowDescription with no pending \
                     Describe or Query",
                    self.step
                );
                self.after_step();
                return;
            }
        };
        self.plan_targets.entry(id).or_default().insert(target);
        self.plan_built.insert(id, self.step);

        let plan = make_plan(id, width);
        self.state
            .finish_description(plan)
            .expect("a queued description must be accepted");

        assert!(
            self.state.streaming_simple_result == expected_simple,
            "step {}: finish_description set streaming_simple_result for a result set that was \
             not the one streaming — a Describe was at the head of the queue, or a simple query was",
            self.step
        );
        assert_eq!(
            self.active_plan_id(),
            Some(id),
            "step {}: finish_description must activate the plan it was given",
            self.step
        );
        self.after_step();
    }

    pub fn finish_no_data(&mut self) {
        let expect_ok = matches!(
            self.state.pending_descriptions.front(),
            Some(PendingDescription::Describe(_))
        );
        let result = self.state.finish_no_data();
        assert_eq!(
            result.is_ok(),
            expect_ok,
            "step {}: finish_no_data consumed {} — NoData belongs only to a Describe",
            self.step,
            if expect_ok {
                "a Describe"
            } else {
                "the wrong entry"
            }
        );
        self.after_step();
    }

    /// An `EmptyQueryResponse`: an empty simple query's answer. It consumes
    /// the simple query's own entry and ends the never-started result set in
    /// one step — no streaming-simple flag survives it. It can never belong to
    /// a Describe.
    pub fn finish_empty_query(&mut self) {
        let expect_ok = matches!(
            self.state.pending_descriptions.front(),
            Some(PendingDescription::Simple(_))
        );
        let result = self.state.finish_empty_query();
        assert_eq!(
            result.is_ok(),
            expect_ok,
            "step {}: finish_empty_query consumed {} — EmptyQueryResponse belongs only to a \
             simple query",
            self.step,
            if expect_ok {
                "a simple Query"
            } else {
                "the wrong entry"
            }
        );
        if expect_ok {
            assert!(
                !self.state.streaming_simple_result,
                "step {}: an EmptyQueryResponse left a simple result streaming",
                self.step
            );
        }
        self.after_step();
    }

    /// A `CommandComplete`: one result set ended.
    ///
    /// The streaming-simple flag is set by a RowDescription that answered a
    /// simple query; a no-row simple command still has its pending description
    /// at the queue head. An EmptyQueryResponse ends an empty simple query on
    /// its own. This must consume the oldest simple Query or Execute owner,
    /// without spending a later operation's slot.
    pub fn finish_result_set(&mut self) {
        let descriptions_before = self.state.pending_descriptions.len();
        let executes_before = self.state.pending_executes.len();
        let was_streaming_simple = self.state.streaming_simple_result;
        let simple_order = match self.state.pending_descriptions.front() {
            Some(PendingDescription::Simple(pending)) => Some(pending.order),
            _ => None,
        };
        let execute_order = self
            .state
            .pending_executes
            .front()
            .map(|pending| pending.order);
        let expected_simple = !was_streaming_simple
            && simple_order
                .is_some_and(|simple| execute_order.is_none_or(|execute| simple < execute));

        self.state.finish_result_set();
        assert!(
            !self.state.streaming_simple_result,
            "step {}: a result set that just ended is still streaming as simple",
            self.step
        );
        if was_streaming_simple {
            assert_eq!(self.state.pending_descriptions.len(), descriptions_before);
            assert_eq!(self.state.pending_executes.len(), executes_before);
        } else if expected_simple {
            assert_eq!(
                self.state.pending_descriptions.len() + 1,
                descriptions_before,
                "step {}: a no-row simple command did not consume its own pending slot",
                self.step
            );
            assert_eq!(self.state.pending_executes.len(), executes_before);
        } else if execute_order.is_some() {
            assert_eq!(self.state.pending_descriptions.len(), descriptions_before);
            assert_eq!(
                self.state.pending_executes.len() + 1,
                executes_before,
                "step {}: CommandComplete did not consume its Execute owner",
                self.step
            );
        } else {
            assert_eq!(self.state.pending_descriptions.len(), descriptions_before);
            assert_eq!(self.state.pending_executes.len(), executes_before);
        }
        self.after_step();
    }

    pub fn discard_description(&mut self) {
        self.state.discard_description();
        self.after_step();
    }

    /// An `ErrorResponse`.
    pub fn discard_failed_epoch(&mut self) {
        self.state.discard_failed_epoch();
        assert!(
            !self.state.streaming_simple_result,
            "step {}: a backend error left a simple result streaming",
            self.step
        );
        self.after_step();
    }

    // ---- proxy-initiated ---------------------------------------------------

    /// `Session::reject`: refuse this result set and start swallowing the
    /// backend's replies until its `ReadyForQuery`.
    pub fn reject(&mut self) {
        self.suppressing = Some(self.state.rejection_epoch());
        self.state.clear_active();
        self.after_step();
    }

    /// The `ReadyForQuery` that ends a suppressed exchange.
    ///
    /// `epoch` is used only when nothing is being suppressed, so the fuzzer can
    /// still reach the arbitrary-argument case; the realistic path replays the
    /// epoch `reject` captured.
    pub fn finish_suppressed_epoch(&mut self, epoch: u8) {
        let epoch = self.suppressing.take().unwrap_or(u64::from(epoch));
        self.state.finish_suppressed_epoch(epoch);
        assert!(
            !self.state.streaming_simple_result,
            "step {}: suppression ended with a simple result still streaming",
            self.step
        );
        self.after_step();
    }

    pub fn clear_active(&mut self) {
        self.state.clear_active();
        self.after_step();
    }

    /// A catalog refresh. `generation` is small so the fuzzer hits both the
    /// "unchanged, keep the cache" and "moved, drop it" arms.
    pub fn invalidate_if_stale(&mut self, generation: u8) {
        let generation = u64::from(generation % 3);
        let moved = generation != self.generation;
        self.generation = generation;
        self.state.invalidate_if_stale(generation);
        if moved {
            self.last_invalidation = Some(self.step);
        }
        self.after_step();
    }

    // ---- oracle ------------------------------------------------------------

    fn after_step(&mut self) {
        self.check_described_sql();
        self.check_active_plan_is_real();
        self.check_epoch_ordering();
        self.step += 1;
    }

    /// **The disclosure invariant.**
    ///
    /// `described_sql` names the statement whose fields are about to be
    /// classified. Whatever it returns has to be the text the entry at the
    /// head of the queue was created with.
    ///
    /// The two kinds share one queue but disjoint text pools, so the answer
    /// carries its own provenance:
    ///
    /// * a Describe is at the head — the answer must be a text parsed under
    ///   that name (or, for a portal, under a statement that portal was bound
    ///   to). A simple query's text is not in that set, and neither is another
    ///   statement's.
    /// * a simple Query is at the head — the answer must be a text some `Query`
    ///   actually carried. A prepared statement's text answering here is the
    ///   same substitution in the other direction.
    ///
    /// `None` always passes: unknown is the fail-closed answer, and the caller
    /// refuses on it.
    fn check_described_sql(&self) {
        let Some(answer) = self.state.described_sql() else {
            return;
        };
        let answer = answer.as_str();

        match self.state.pending_descriptions.front() {
            Some(PendingDescription::Describe(pending)) => {
                let (what, allowed) = match &pending.target {
                    DescribeTarget::Statement(name) => {
                        let name = static_name(name);
                        (
                            format!("statement {name:?}"),
                            self.parsed_under.get(name).cloned().unwrap_or_default(),
                        )
                    }
                    DescribeTarget::Portal(portal) => {
                        let portal = static_name(portal);
                        let mut allowed = BTreeSet::new();
                        for statement in self.bound_from.get(portal).into_iter().flatten() {
                            allowed.extend(
                                self.parsed_under
                                    .get(statement)
                                    .cloned()
                                    .unwrap_or_default(),
                            );
                        }
                        (format!("portal {portal:?}"), allowed)
                    }
                };
                assert!(
                    allowed.contains(answer),
                    "step {}: a Describe for {what} is at the head of the queue, and \
                     described_sql() answered {answer:?} — which was never parsed under it. \
                     Texts it could legitimately carry: {allowed:?}. The analysis is about to \
                     judge one statement's fields using another statement's SQL.",
                    self.step
                );
            }
            Some(PendingDescription::Simple(_)) => {
                assert!(
                    self.simple_texts.contains(answer),
                    "step {}: a simple Query is at the head of the queue, so described_sql() is \
                     answering for it, and it returned {answer:?} — which no Query ever carried. \
                     Known simple texts: {:?}.",
                    self.step,
                    self.simple_texts
                );
            }
            // described_sql() answers from the queue head alone, so it cannot
            // answer while the queue is empty. If it ever does, the source of
            // the text is unknown and must fail closed.
            None => panic!(
                "step {}: described_sql() answered {answer:?} with an empty description queue",
                self.step
            ),
        }
    }

    /// A plan that is active must be one this harness built, whole.
    ///
    /// Every field of a plan carries the same marker, so a plan stitched
    /// together from two result sets — a field-count mismatch resolved by
    /// reusing part of an older description — shows up as a mixed marker rather
    /// than having to be caught downstream in the decoder.
    fn check_active_plan_is_real(&self) {
        let Some(plan) = self.state.active_plan() else {
            return;
        };
        let Some(first) = plan.first() else {
            panic!("step {}: an empty plan is active", self.step);
        };
        assert!(
            plan.iter().all(|field| field.type_oid == first.type_oid),
            "step {}: the active plan mixes fields from more than one description",
            self.step
        );
        assert!(
            self.plan_built.contains_key(&first.type_oid),
            "step {}: plan {} is active but was never built by a finish_description",
            self.step,
            first.type_oid
        );
    }

    /// Epochs are stamped from `sync_epoch` when a message is queued, and
    /// `sync_epoch` only grows, so every queue is sorted and bounded by it.
    /// Popping the wrong end, or a `retain` that drops the wrong predicate's
    /// worth, breaks one of these before it breaks anything visible.
    fn check_epoch_ordering(&self) {
        let now = self.state.sync_epoch;

        let describes: Vec<u64> = self
            .state
            .pending_descriptions
            .iter()
            .map(|p| match p {
                PendingDescription::Describe(p) => p.epoch,
                PendingDescription::Simple(p) => p.epoch,
            })
            .collect();
        let parses: Vec<u64> = self.state.pending_parses.iter().map(|p| p.epoch).collect();
        let binds: Vec<u64> = self.state.pending_binds.iter().map(|p| p.epoch).collect();
        let executes: Vec<u64> = self
            .state
            .pending_executes
            .iter()
            .map(|p| p.epoch)
            .collect();

        let result_orders: Vec<u64> = self
            .state
            .pending_descriptions
            .iter()
            .filter_map(|pending| match pending {
                PendingDescription::Simple(pending) => Some(pending.order),
                PendingDescription::Describe(_) => None,
            })
            .chain(
                self.state
                    .pending_executes
                    .iter()
                    .map(|pending| pending.order),
            )
            .collect();
        assert!(
            result_orders
                .iter()
                .all(|order| *order < self.state.next_result_order),
            "step {}: pending result order is not below next_result_order {}: {result_orders:?}",
            self.step,
            self.state.next_result_order
        );
        assert_eq!(
            result_orders.iter().copied().collect::<BTreeSet<_>>().len(),
            result_orders.len(),
            "step {}: pending simple Query and Execute owners share an order: {result_orders:?}",
            self.step
        );

        for (queue, epochs) in [
            ("pending_descriptions", &describes),
            ("pending_parses", &parses),
            ("pending_binds", &binds),
            ("pending_executes", &executes),
        ] {
            assert!(
                epochs.windows(2).all(|pair| pair[0] <= pair[1]),
                "step {}: {queue} is out of epoch order: {epochs:?}",
                self.step
            );
            assert!(
                epochs.iter().all(|epoch| *epoch <= now),
                "step {}: {queue} holds an epoch from the future (sync_epoch is {now}): \
                 {epochs:?}",
                self.step
            );
        }

        if let Some(active) = self.state.active_epoch {
            assert!(
                active <= now,
                "step {}: active_epoch {active} is ahead of sync_epoch {now}",
                self.step
            );
        }
        let rejection = self.state.rejection_epoch();
        assert!(
            rejection <= now,
            "step {}: rejection_epoch() returned {rejection}, ahead of sync_epoch {now} — \
             suppression would run to a boundary that has not happened",
            self.step
        );
    }

    fn active_plan_id(&self) -> Option<u32> {
        self.state
            .active_plan()
            .and_then(|plan| plan.first().map(|field| field.type_oid))
    }
}

/// Recover the `&'static str` a name was built from.
///
/// Every name in play came out of [`NAMES`], so this is total for anything this
/// harness produced. It exists because `PlanState` stores `Bytes` and the
/// shadow is keyed by the pool entry.
fn static_name(raw: &Bytes) -> &'static str {
    NAMES
        .iter()
        .copied()
        .find(|candidate| candidate.as_bytes() == raw.as_ref())
        .unwrap_or_else(|| panic!("name {raw:?} is not from the pool"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sequence the fuzzer found, kept as a unit test so the bug cannot
    /// come back without `cargo test` saying so — the fuzz target needs nightly
    /// and is not on the release gate.
    ///
    /// A simple Query issued while a Describe is still in flight must enqueue
    /// behind it, never displace it. The backend answers in message order, so
    /// the Describe's RowDescription arrives first and must be matched to the
    /// Describe — before this fix the queue was cleared and that answer was
    /// classified under the simple query's text. Proven live on the wire as a
    /// masked value served in cleartext.
    #[test]
    fn a_simple_query_does_not_displace_a_pending_describe() {
        let mut model = ProtocolModel::new();
        // P s1; Describe s1; Q "SELECT 1, 2", pipelined.
        model.parse(1, 0);
        model.describe_statement(1);
        model.simple_query(Some(0));
        // The Describe was issued first, so its RowDescription answers first.
        // It arms a *future* execute's result — it must not read as simple.
        model.finish_description(2);
        assert!(
            !model.state.streaming_simple_result,
            "a Describe's RowDescription must not stream as a simple result"
        );
        // The simple query's own RowDescription comes next, and streams simple.
        model.finish_description(2);
        assert!(
            model.state.streaming_simple_result,
            "the simple query's RowDescription streams its own result"
        );
    }

    /// An undecodable Parse (non-UTF-8 client encoding) leaves a pending
    /// Describe with no SQL of its own. Its answer is still matched in stream
    /// order — the simple query that preceded it consumes its own entry first —
    /// and the SQL-less Describe stays unknown rather than borrowing any text.
    #[test]
    fn an_undecodable_parse_leaves_a_describe_with_no_sql_of_its_own() {
        let mut model = ProtocolModel::new();
        model.simple_query(Some(0));
        model.parse_undecodable();
        model.describe_statement(1);
        // The simple query's result answers first, from its own entry.
        model.finish_description(1);
        // The Describe's NoData answers next; it has no SQL of its own.
        model.finish_no_data();
    }

    /// The oracle has to be able to see a plan crossing portals, not just take
    /// it on faith. Describe statement `a`, then execute a portal that was only
    /// ever bound to `b`.
    #[test]
    fn a_plan_reaches_only_the_portal_it_was_described_for() {
        let mut model = ProtocolModel::new();
        model.parse(1, 0);
        model.describe_statement(1);
        model.finish_description(1);
        model.bind(2, 1, None);
        model.execute(2);
    }

    /// A short smoke sequence over the whole alphabet, so a signature change
    /// that breaks the harness fails `cargo test` rather than only failing the
    /// next time somebody runs the fuzzer.
    #[test]
    fn the_whole_alphabet_applies_cleanly() {
        let mut model = ProtocolModel::new();
        // Two pipelined simple queries: each consumes its own entry in order.
        model.simple_query(Some(0));
        model.simple_query(None);
        model.finish_description(2);
        model.finish_result_set();
        model.finish_description(2);
        model.finish_result_set();
        model.parse(0, 0);
        model.parse_undecodable();
        model.finish_parse();
        model.bind(1, 0, Some(vec![1, 0]));
        model.finish_bind();
        model.describe_statement(0);
        model.finish_description(2);
        model.describe_portal(1);
        model.finish_no_data();
        model.execute(1);
        model.finish_result_set();
        model.sync();
        model.describe_statement(0);
        model.discard_description();
        model.describe_statement(0);
        model.discard_failed_epoch();
        model.reject();
        model.finish_suppressed_epoch(0);
        model.invalidate_if_stale(1);
        model.execute(1);
        model.close_portal(1);
        model.close_statement(0);
        model.clear_active();
    }

    /// A pipelined simple query followed by a queued Execute: the simple
    /// result's end must not spend the Execute's slot, and the flag must track
    /// which result set is really streaming.
    #[test]
    fn a_simple_result_end_does_not_spend_the_queued_executes_slot() {
        let mut model = ProtocolModel::new();

        // Q ...; Sync; Parse(bad) Bind(p bad) Execute(p); Sync, all pipelined.
        model.simple_query(Some(0));
        model.sync();
        model.execute(1);
        // The simple RowDescription arrives before the Execute's rows. It
        // answered no Describe, so its result streams as the simple result.
        model.finish_description(2);
        assert!(
            model.state.streaming_simple_result,
            "the simple result must be streaming"
        );
        // Its CommandComplete ends it — the queued Execute owns the next result.
        model.finish_result_set();
        assert!(
            !model.state.streaming_simple_result,
            "the end must clear the flag"
        );
        assert_eq!(
            model.state.result_owner().as_deref(),
            Some(&b"a"[..]),
            "the simple result must not spend the Execute's slot"
        );
        assert!(
            model.state.portal_plan(&bytes_of("a")).is_none(),
            "the never-described statement leaves the Execute with no plan"
        );
        // Its CommandComplete spends the slot; the next result set is the
        // simple query's again, exactly when a query enqueues its own entry.
        model.finish_result_set();
        assert_eq!(model.state.result_owner(), None);
        model.simple_query(Some(1));
        model.finish_description(1);
        assert!(
            model.state.streaming_simple_result,
            "a simple query's own entry arms its result"
        );
    }

    /// Psycopg opens an implicit transaction with a simple `BEGIN`, which has
    /// no RowDescription. Its CommandComplete must consume the Query owner and
    /// leave a later Execute queued.
    #[test]
    fn a_no_row_simple_command_consumes_its_own_slot() {
        let mut model = ProtocolModel::new();
        model.simple_query(Some(3)); // BEGIN
        model.execute(1);

        model.finish_result_set();
        assert!(model.state.pending_descriptions.is_empty());
        assert_eq!(model.state.result_owner().as_deref(), Some(&b"a"[..]));
    }
}
