//! Extended-query plan lifecycle.
//!
//! PostgreSQL names prepared statements and portals independently, permits
//! pipelining across `Sync` boundaries, and answers `Describe` asynchronously.
//! Every map and queue needed to preserve those relationships lives here so
//! invalidation and ordering rules cannot drift across session message arms.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use bytes::Bytes;

use crate::mask::MaskSpec;
use crate::protocol::{self, DescribeTarget};

/// Protocol-sequence fuzz harness. See that module for why it is a child of
/// this one rather than a sibling: the oracle reads `PlanState`'s private
/// fields for ground truth, and a sibling module cannot. `#[path]` keeps the
/// production file where it is instead of turning `plan_state.rs` into a
/// directory for the sake of a test-only module.
#[cfg(feature = "fuzzing")]
#[path = "plan_state_fuzz.rs"]
pub mod fuzz;

/// What to do with one output field.
#[derive(Debug, Clone)]
pub(crate) struct FieldPlan {
    pub(crate) spec: MaskSpec,
    pub(crate) type_oid: u32,
    pub(crate) format: i16,
}

pub(crate) type Plan = Arc<Vec<FieldPlan>>;

/// A `Describe` the backend has not answered yet, and the SQL it was for.
struct PendingDescribe {
    target: DescribeTarget,
    sql: Option<String>,
    /// How many `Sync`s the client had sent when this was issued.
    ///
    /// An `ErrorResponse` makes the backend skip every remaining message up to
    /// the next `Sync`, so exactly the Describes sharing the failing one's
    /// epoch are dead. Anything after that `Sync` remains live.
    epoch: u64,
}

/// A frontend mutation that has not yet received its backend acknowledgement.
///
/// Parse and Bind state is provisionally useful to later pipelined messages,
/// but must be invalidated if the backend rejects the command. Otherwise the
/// proxy and backend can assign different SQL or plans to the same name.
struct PendingMutation {
    name: Bytes,
    epoch: u64,
}

/// All state that binds SQL, statements, portals, descriptions, and row plans.
#[derive(Default)]
pub(crate) struct PlanState {
    statement_plans: HashMap<Bytes, Plan>,
    statement_sql: HashMap<Bytes, String>,
    portal_statement: HashMap<Bytes, Bytes>,
    portal_plans: HashMap<Bytes, Plan>,
    /// Result-format codes each portal was bound with.
    ///
    /// Kept separately from `portal_plans` because a Bind can arrive *before*
    /// the plan it applies to exists. A client that pipelines
    /// `Parse, Describe(Statement), Bind, Execute` in one flush sends all four
    /// before reading anything, so the proxy sees the Bind while the backend's
    /// RowDescription is still in flight. The formats were dropped on the floor
    /// there, and the plan later built from the Describe said *text* — which is
    /// all a statement-level Describe can say, since formats are not chosen
    /// until Bind. The binary DataRows that followed then failed to decode:
    ///
    /// ```text
    /// pgmask: value of type OID 1082 did not decode in text format
    /// ```
    ///
    /// (Fenced as `text`, not indented. An indented block in a doc comment is a
    /// Rust code block, and rustdoc compiles it — `cargo test --lib` does not
    /// run doctests, so this only surfaced in CI's `--workspace` sweep.)
    ///
    /// Fail-closed, so nothing leaked, and text-family types were unaffected
    /// because their text and binary encodings are identical. But it refused
    /// legitimate traffic from any driver that pipelines with binary results,
    /// and a proxy that errors on valid queries is one an operator routes
    /// around.
    portal_formats: HashMap<Bytes, Option<Vec<i16>>>,
    active_plan: Option<Plan>,
    /// Portal named by the most recent Execute, so a plan that only becomes
    /// known later can still be activated for the rows it produces.
    active_portal: Option<Bytes>,
    active_epoch: Option<u64>,
    pending_describes: VecDeque<PendingDescribe>,
    pending_parses: VecDeque<PendingMutation>,
    pending_binds: VecDeque<PendingMutation>,
    simple_sql: Option<String>,
    sync_epoch: u64,
    /// Catalog generation the cached plans were built under.
    generation: u64,
}

impl PlanState {
    /// Drop cached plans built before a catalog refresh.
    ///
    /// A plan is a decision made against one snapshot, and statement and portal
    /// plans outlive the result set they were described for — that is the point
    /// of caching them.
    ///
    /// A refresh does not re-read the catalog *file* (that needs a restart), so
    /// this is not about an operator editing a rule. It re-resolves names to
    /// OIDs, and DDL moves those: `DROP TABLE; CREATE TABLE` gives a new OID,
    /// and PostgreSQL reuses OIDs. A plan cached across that boundary applies
    /// the previous mapping's classification — which, when an OID has been
    /// recycled onto a different relation, is the wrong column's mask.
    ///
    /// The in-flight `active_plan` is deliberately kept: its rows are already
    /// being described and served, and that is bounded by one result set. What
    /// is dropped is everything a *later* Bind or Execute would reuse, so the
    /// next one has no plan and fails closed until a fresh Describe rebuilds
    /// it against the new snapshot.
    pub(crate) fn invalidate_if_stale(&mut self, current: u64) {
        if self.generation == current {
            return;
        }
        self.generation = current;
        self.statement_plans.clear();
        self.portal_plans.clear();
        // Not portal_formats: the portal is still bound and still has the
        // formats the client chose. What a refresh invalidates is the
        // classification, which a fresh Describe rebuilds — and that rebuild
        // needs these formats to stamp the new plan correctly.
    }

    pub(crate) fn active_plan(&self) -> Option<Plan> {
        self.active_plan.clone()
    }

    pub(crate) fn clear_active(&mut self) {
        self.active_plan = None;
        self.active_epoch = None;
    }

    pub(crate) fn begin_simple_query(&mut self, sql: Option<String>) {
        self.active_plan = None;
        self.active_epoch = None;
        self.pending_describes.clear();
        self.simple_sql = sql;
    }

    pub(crate) fn parse(&mut self, name: Bytes, sql: String) {
        // A genuinely different statement invalidates every plan derived from
        // the old SQL. Some drivers re-Parse the unnamed statement with the
        // same SQL and reuse its described result metadata, which remains valid.
        if self.statement_sql.get(&name) != Some(&sql) {
            self.statement_plans.remove(&name);
            let stale_portals: Vec<Bytes> = self
                .portal_statement
                .iter()
                .filter(|(_, statement)| **statement == name)
                .map(|(portal, _)| portal.clone())
                .collect();
            for portal in stale_portals {
                self.portal_plans.remove(&portal);
                self.portal_formats.remove(&portal);
            }
        }
        self.statement_sql.insert(name.clone(), sql);
        self.pending_parses.push_back(PendingMutation {
            name,
            epoch: self.sync_epoch,
        });
    }

    pub(crate) fn bind(&mut self, portal: Bytes, statement: Bytes, formats: Option<Vec<i16>>) {
        self.portal_statement
            .insert(portal.clone(), statement.clone());
        self.pending_binds.push_back(PendingMutation {
            name: portal.clone(),
            epoch: self.sync_epoch,
        });
        self.portal_formats.insert(portal.clone(), formats.clone());
        let Some(statement_plan) = self.statement_plans.get(&statement) else {
            // The statement has no plan yet — the Describe's RowDescription is
            // still in flight. The formats are remembered above and applied by
            // `finish_description` when it lands.
            self.portal_plans.remove(&portal);
            return;
        };

        // Describe(Statement) reports text because result formats are not chosen
        // until Bind. Re-stamp the plan with this portal's actual formats.
        // An unparseable Bind keeps the described format. A wrong format then
        // fails decoding and refuses the result set rather than guessing.
        let portal_plan = Self::stamp(statement_plan, formats.as_ref());
        self.portal_plans.insert(portal, portal_plan);
    }

    pub(crate) fn describe(&mut self, target: DescribeTarget) {
        let sql = match &target {
            DescribeTarget::Statement(name) => self.statement_sql.get(name).cloned(),
            DescribeTarget::Portal(portal) => self
                .portal_statement
                .get(portal)
                .and_then(|statement| self.statement_sql.get(statement))
                .cloned(),
        };
        self.pending_describes.push_back(PendingDescribe {
            target,
            sql,
            epoch: self.sync_epoch,
        });
    }

    pub(crate) fn execute(&mut self, portal: &Bytes) {
        self.active_plan = self.portal_plans.get(portal).cloned();
        self.active_epoch = Some(self.sync_epoch);
        self.active_portal = Some(portal.clone());
    }

    /// Build a portal's plan from its statement's plan and the formats its Bind
    /// chose. One definition, because this now happens at two different times:
    /// at Bind when the statement is already described, and at BindComplete
    /// when it was not.
    fn stamp(plan: &Plan, formats: Option<&Vec<i16>>) -> Plan {
        match formats {
            Some(formats) => Arc::new(
                plan.iter()
                    .enumerate()
                    .map(|(index, field)| FieldPlan {
                        format: protocol::format_for(formats, index),
                        ..field.clone()
                    })
                    .collect(),
            ),
            None => plan.clone(),
        }
    }

    /// Mirror PostgreSQL's resource lifetime after a frontend `Close`.
    /// Closing a statement also closes every portal constructed from it.
    ///
    /// The active plan deliberately survives: an Execute may precede its Close
    /// in the same pipeline, and those rows arrive before `CloseComplete`.
    pub(crate) fn close(&mut self, target: DescribeTarget) {
        match target {
            DescribeTarget::Statement(statement) => {
                self.statement_sql.remove(&statement);
                self.statement_plans.remove(&statement);

                let portals: Vec<Bytes> = self
                    .portal_statement
                    .iter()
                    .filter(|(_, bound_statement)| **bound_statement == statement)
                    .map(|(portal, _)| portal.clone())
                    .collect();
                for portal in portals {
                    self.portal_statement.remove(&portal);
                    self.portal_plans.remove(&portal);
                    self.portal_formats.remove(&portal);
                }
            }
            DescribeTarget::Portal(portal) => {
                self.portal_statement.remove(&portal);
                self.portal_plans.remove(&portal);
                self.portal_formats.remove(&portal);
            }
        }
    }

    pub(crate) fn sync(&mut self) {
        self.sync_epoch = self.sync_epoch.saturating_add(1);
    }

    pub(crate) fn finish_parse(&mut self) {
        self.pending_parses.pop_front();
    }

    /// BindComplete. In a pipelined batch this is the first moment the portal's
    /// plan *can* be built: the client sent Parse/Describe/Bind/Execute in one
    /// flush, so `bind` ran before the backend's RowDescription existed and had
    /// no statement plan to stamp. The RowDescription has arrived by now.
    ///
    /// Activating it here is what makes the rows decode. `execute` already ran,
    /// found no portal plan, and left `active_plan` empty; `finish_description`
    /// then set it to the *statement* plan, whose formats are text because a
    /// statement-level Describe cannot know what a later Bind will choose.
    pub(crate) fn finish_bind(&mut self) {
        let Some(pending) = self.pending_binds.pop_front() else {
            return;
        };
        let portal = pending.name;
        // Build the portal's plan if Bind could not (statement not yet
        // described then). Not an early return when it already exists: the
        // activation below is the point, and `finish_description` may have
        // built the plan a moment ago while leaving `active_plan` set to the
        // statement's text-format one.
        if !self.portal_plans.contains_key(&portal) {
            if let Some(statement_plan) = self
                .portal_statement
                .get(&portal)
                .and_then(|statement| self.statement_plans.get(statement))
            {
                let stamped = Self::stamp(
                    statement_plan,
                    self.portal_formats.get(&portal).and_then(Option::as_ref),
                );
                self.portal_plans.insert(portal.clone(), stamped);
            }
        }
        // The rows about to arrive belong to this portal, not to the statement.
        if self.active_portal.as_ref() == Some(&portal) {
            if let Some(plan) = self.portal_plans.get(&portal) {
                self.active_plan = Some(plan.clone());
            }
        }
    }

    /// Epoch whose backend traffic must be suppressed after a local refusal.
    pub(crate) fn rejection_epoch(&self) -> u64 {
        self.pending_describes
            .front()
            .map_or(self.active_epoch.unwrap_or(self.sync_epoch), |pending| {
                pending.epoch
            })
    }

    /// Finish one locally suppressed exchange without deleting later
    /// pipelined work. Unlike [`discard_failed_epoch`](Self::discard_failed_epoch),
    /// the backend did execute these mutations; only their responses were
    /// suppressed, so their provisional state remains valid.
    pub(crate) fn finish_suppressed_epoch(&mut self, epoch: u64) {
        self.pending_describes
            .retain(|pending| pending.epoch != epoch);
        self.pending_parses.retain(|pending| pending.epoch != epoch);
        self.pending_binds.retain(|pending| pending.epoch != epoch);
    }

    /// Remove provisional state from a failed exchange while preserving later
    /// pipelined exchanges that have already crossed a `Sync`.
    pub(crate) fn discard_failed_epoch(&mut self) {
        let failed_epoch = [
            self.pending_describes.front().map(|p| p.epoch),
            self.pending_parses.front().map(|p| p.epoch),
            self.pending_binds.front().map(|p| p.epoch),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(failed_epoch) = failed_epoch else {
            return;
        };

        // A later pipelined epoch may already have reused the same name. Keep
        // its provisional state; its own acknowledgement or error will decide
        // whether it survives.
        let later_statements: HashSet<Bytes> = self
            .pending_parses
            .iter()
            .filter(|pending| pending.epoch > failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        let failed_statements: Vec<Bytes> = self
            .pending_parses
            .iter()
            .filter(|pending| pending.epoch == failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        for statement in failed_statements {
            if !later_statements.contains(&statement) {
                self.statement_sql.remove(&statement);
                self.statement_plans.remove(&statement);
            }
        }

        let later_portals: HashSet<Bytes> = self
            .pending_binds
            .iter()
            .filter(|pending| pending.epoch > failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        let failed_portals: Vec<Bytes> = self
            .pending_binds
            .iter()
            .filter(|pending| pending.epoch == failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        for portal in failed_portals {
            if !later_portals.contains(&portal) {
                self.portal_statement.remove(&portal);
                self.portal_plans.remove(&portal);
            }
        }

        self.pending_describes
            .retain(|pending| pending.epoch != failed_epoch);
        self.pending_parses
            .retain(|pending| pending.epoch != failed_epoch);
        self.pending_binds
            .retain(|pending| pending.epoch != failed_epoch);
    }

    pub(crate) fn finish_no_data(&mut self) {
        self.pending_describes.pop_front();
    }

    /// The SQL for *this* result set.
    ///
    /// A `match`, not `and_then(..).or_else(..)`. Those collapse two different
    /// situations into one branch: "no Describe is outstanding, so this is the
    /// simple query" and "a Describe is outstanding but its SQL was never
    /// recorded". The second must stay unknown — falling back substitutes some
    /// earlier simple query's text as the identity of a different statement,
    /// and the analysis then judges the wrong SQL. `SELECT 1, 2` reads as two
    /// literals and would release fields belonging to `SELECT upper(email), …`.
    ///
    /// That is the same failure the pipelined-Describe fix in 0.1.8 closed, on
    /// a path that fix did not cover. A pending Describe carries no SQL when
    /// `parse_parse` could not decode the statement — a non-UTF-8 client
    /// encoding — while the backend accepted the Parse regardless.
    pub(crate) fn described_sql(&self) -> Option<String> {
        match self.pending_describes.front() {
            Some(pending) => pending.sql.clone(),
            None => self.simple_sql.clone(),
        }
    }

    pub(crate) fn discard_description(&mut self) {
        self.pending_describes.pop_front();
    }

    /// Bind a completed plan to the described target and activate it for the
    /// DataRows that follow the RowDescription.
    pub(crate) fn finish_description(&mut self, plan: Plan) {
        let pending = self.pending_describes.pop_front();
        let epoch = pending
            .as_ref()
            .map_or(self.sync_epoch, |pending| pending.epoch);
        match pending.map(|p| p.target) {
            Some(DescribeTarget::Statement(name)) => {
                self.statement_plans.insert(name.clone(), plan.clone());
                // Any portal already bound to this statement was bound before
                // this plan existed, so its Bind could not be applied then.
                // Apply it now, or those portals keep the text formats a
                // statement-level Describe always reports.
                let waiting: Vec<Bytes> = self
                    .portal_statement
                    .iter()
                    .filter(|(_, bound)| **bound == name)
                    .map(|(portal, _)| portal.clone())
                    .collect();
                for portal in waiting {
                    let stamped = Self::stamp(
                        &plan,
                        self.portal_formats.get(&portal).and_then(Option::as_ref),
                    );
                    self.portal_plans.insert(portal, stamped);
                }
            }
            Some(DescribeTarget::Portal(name)) => {
                self.portal_plans.insert(name, plan.clone());
            }
            None => {}
        }
        self.active_plan = Some(plan);
        self.active_epoch = Some(epoch);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::mask::Mask;

    fn plan() -> Plan {
        Arc::new(vec![FieldPlan {
            spec: MaskSpec::new(Mask::None),
            type_oid: 25,
            format: 0,
        }])
    }

    fn name(value: &'static str) -> Bytes {
        Bytes::from_static(value.as_bytes())
    }

    /// A catalog refresh drops every cached plan.
    ///
    /// A refresh re-resolves names to OIDs, and DDL moves those. A plan cached
    /// across a refresh applies the previous mapping — which, once an OID has
    /// been recycled onto another relation, is a different column's mask.
    /// Every other DDL direction already failed closed; this was the one that
    /// did not.
    #[test]
    fn a_catalog_refresh_invalidates_cached_plans() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT secret FROM t".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());

        // Same generation: the cached plan is still reusable.
        state.invalidate_if_stale(0);
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_some(),
            "no refresh, so the plan stands"
        );

        // The catalog refreshed underneath the session.
        state.invalidate_if_stale(1);
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_none(),
            "a plan built against the previous snapshot must not be reused"
        );

        // A fresh Describe rebuilds it against the new snapshot.
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_some(),
            "re-describing must restore it"
        );
    }

    #[test]
    fn different_sql_invalidates_but_identical_sql_preserves_a_plan() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());

        state.parse(name("s"), "SELECT 1".into());
        state.bind(name("p"), name("s"), Some(vec![1]));
        state.execute(&name("p"));
        assert_eq!(state.active_plan().unwrap().first().unwrap().format, 1);

        state.parse(name("s"), "SELECT secret FROM t".into());
        state.bind(name("p"), name("s"), Some(vec![0]));
        state.execute(&name("p"));
        assert!(state.active_plan().is_none());
    }

    #[test]
    fn a_failed_epoch_does_not_discard_a_later_pipelined_describe() {
        let mut state = PlanState::default();
        state.parse(name("bad"), "SELECT bad".into());
        state.describe(DescribeTarget::Statement(name("bad")));
        state.sync();
        state.parse(name("good"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("good")));

        state.discard_failed_epoch();
        assert_eq!(state.described_sql().as_deref(), Some("SELECT 1"));
    }

    #[test]
    fn a_locally_suppressed_epoch_preserves_later_pipelined_describes() {
        let mut state = PlanState::default();
        state.parse(name("reject"), "SELECT lower(secret) FROM t".into());
        state.describe(DescribeTarget::Statement(name("reject")));
        state.sync();
        state.parse(name("later"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("later")));

        state.finish_suppressed_epoch(0);
        assert_eq!(state.described_sql().as_deref(), Some("SELECT 1"));
    }

    #[test]
    fn a_rejected_reparse_cannot_replace_the_backends_sql_identity() {
        let mut state = PlanState::default();
        // A simple query first, so the fallback has something to reach for.
        // Without this the assertion below held for the wrong reason —
        // `simple_sql` was `None`, so `or_else` had nothing to substitute and
        // the test passed while the fallback it exists to forbid was live.
        state.begin_simple_query(Some("SELECT 1, 2".into()));
        state.parse(name("s"), "SELECT lower(secret) FROM t".into());
        state.finish_parse();

        state.parse(name("s"), "SELECT 1".into());
        state.sync();
        state.discard_failed_epoch();
        state.describe(DescribeTarget::Statement(name("s")));

        assert_eq!(
            state.described_sql(),
            None,
            "after a rejected Parse, unknown is safer than analyzing the old backend statement as the new SQL"
        );
    }

    #[test]
    fn close_releases_proxy_state_without_discarding_in_flight_rows() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());
        state.bind(name("p"), name("s"), Some(vec![0]));
        state.execute(&name("p"));

        state.close(DescribeTarget::Statement(name("s")));
        assert!(
            state.active_plan().is_some(),
            "an Execute pipelined before Close still has rows in flight"
        );

        state.clear_active();
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_none(),
            "closing a statement must implicitly release its portals"
        );
    }
    /// A pipelined `Parse, Describe(Statement), Bind, Execute` must still decode
    /// in the format the Bind chose.
    ///
    /// Found by attacking a live proxy with a raw wire client, not by any test
    /// here. The client sends all four before reading anything, so `bind` runs
    /// while the backend's RowDescription is still in flight and has no
    /// statement plan to stamp; `execute` then finds no portal plan; and
    /// `finish_description` sets the active plan to the *statement's*, whose
    /// formats are text because a statement-level Describe cannot know what a
    /// later Bind will pick. The binary rows that followed failed to decode:
    /// "value of type OID 1082 did not decode in text format".
    ///
    /// Fail-closed, so nothing leaked — but it refused legitimate traffic from
    /// any driver that pipelines with binary results.
    #[test]
    fn a_pipelined_bind_keeps_its_binary_format() {
        let mut state = PlanState::default();
        state.parse(name("stmt"), "SELECT birth_date FROM t".to_string());
        state.describe(DescribeTarget::Statement(name("stmt")));
        // Bind arrives before the RowDescription: no statement plan exists yet.
        state.bind(name("portal"), name("stmt"), Some(vec![1]));
        state.execute(&name("portal"));
        assert!(
            state.active_plan().is_none(),
            "nothing can be active before the description arrives"
        );

        state.finish_parse();
        state.finish_description(plan()); // RowDescription, text formats
        state.finish_bind(); // BindComplete — the first moment this is knowable

        let active = state.active_plan().expect("a plan for the rows");
        assert_eq!(
            active.first().map(|f| f.format),
            Some(1),
            "the rows are binary because the Bind said so; the described \
             format is text and must not win"
        );
    }

    /// The same ordering, with the Bind asking for text, must stay text —
    /// otherwise the fix above would just be a different wrong answer.
    #[test]
    fn a_pipelined_text_bind_stays_text() {
        let mut state = PlanState::default();
        state.parse(name("stmt"), "SELECT birth_date FROM t".to_string());
        state.describe(DescribeTarget::Statement(name("stmt")));
        state.bind(name("portal"), name("stmt"), Some(vec![0]));
        state.execute(&name("portal"));
        state.finish_parse();
        state.finish_description(plan());
        state.finish_bind();
        assert_eq!(
            state
                .active_plan()
                .and_then(|p| p.first().map(|f| f.format)),
            Some(0)
        );
    }

    /// A Bind whose formats could not be parsed keeps the described format
    /// rather than guessing, and the pipelined path must not quietly change
    /// that to binary.
    #[test]
    fn a_pipelined_unparseable_bind_keeps_the_described_format() {
        let mut state = PlanState::default();
        state.parse(name("stmt"), "SELECT birth_date FROM t".to_string());
        state.describe(DescribeTarget::Statement(name("stmt")));
        state.bind(name("portal"), name("stmt"), None);
        state.execute(&name("portal"));
        state.finish_parse();
        state.finish_description(plan());
        state.finish_bind();
        assert_eq!(
            state
                .active_plan()
                .and_then(|p| p.first().map(|f| f.format)),
            Some(0),
            "an unparseable Bind must not be read as binary"
        );
    }

    /// Executing a portal that was never bound stays fail-closed. The fix adds
    /// an activation path, and this is the one it must not open.
    #[test]
    fn an_unbound_portal_still_has_no_plan() {
        let mut state = PlanState::default();
        state.parse(name("stmt"), "SELECT birth_date FROM t".to_string());
        state.execute(&name("ghost"));
        state.finish_parse();
        state.finish_bind();
        assert!(
            state.active_plan().is_none(),
            "no Bind, no Describe, no plan"
        );
    }
}
