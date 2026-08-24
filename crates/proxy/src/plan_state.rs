//! Extended-query plan lifecycle.
//!
//! PostgreSQL names prepared statements and portals independently, permits
//! pipelining across `Sync` boundaries, and answers `Describe` asynchronously.
//! Every map and queue needed to preserve those relationships lives here so
//! invalidation and ordering rules cannot drift across session message arms.
//!
//! Result sets are owned too. The backend answers `Execute`s in message order,
//! so the portal whose rows arrive next is tracked here, and a simple query's
//! result is recognised because it enqueued its own description entry — which
//! is also what keeps a Describe still in flight from being answered by a
//! simple query's text: the two share one FIFO in stream order, each carrying
//! its own SQL.

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
    /// The spec is the *type-aware fallback* for an unclassified nullable (or
    /// catalog-unresolved) column, not an operator's choice. A fallback mask
    /// that cannot be applied to some value or format degrades that field to
    /// NULL — strictly less disclosure — instead of refusing the result set.
    /// Declared NOT NULL sources and configured masks stay fail-closed.
    pub(crate) lenient: bool,
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

/// A simple `Query` whose result the backend has not described yet.
struct PendingSimple {
    sql: Option<String>,
    epoch: u64,
    /// Frontend order among row-producing or command-completing operations.
    order: u64,
}

/// A message whose backend answer is still owed: a `Describe` that will be
/// answered by a `RowDescription` or `NoData`, or a simple `Query` answered by
/// a `RowDescription`, `EmptyQueryResponse`, or (for a command with no rows)
/// `CommandComplete`.
///
/// Both answer with a `RowDescription`, so they share one FIFO in stream order.
/// The backend replies in message order, so the front of this queue is always
/// the description the backend's next `RowDescription` belongs to — every
/// forwarded Describe and query enqueues here, and nothing is ever cleared
/// early, so a simple query issued while a Describe is still in flight cannot
/// steal that Describe's answer.
enum PendingDescription {
    Describe(PendingDescribe),
    Simple(PendingSimple),
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

/// An Execute whose CommandComplete is still owed.
struct PendingExecute {
    name: Bytes,
    epoch: u64,
    /// Frontend order shared with simple Query messages.
    order: u64,
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
    pending_descriptions: VecDeque<PendingDescription>,
    pending_parses: VecDeque<PendingMutation>,
    pending_binds: VecDeque<PendingMutation>,
    /// Portals executed since the last result-set completion, in Execute
    /// order. PostgreSQL answers Executes in message order, each emitting one
    /// result set ended by `CommandComplete`, so the front of this queue is
    /// the portal whose rows arrive next. Rows are vetted with *that* portal's
    /// own plan, never the single `active_plan`: a pipelined client can have
    /// several result sets in flight, and the last Execute is not the one
    /// whose rows come first.
    pending_executes: VecDeque<PendingExecute>,
    /// True while the result set streaming from the backend is a simple
    /// query's — armed by its own RowDescription and ended by its own
    /// CommandComplete, which spends no executed-portal slot. Extended
    /// describes arm a *future* result set, not the one streaming, so their
    /// RowDescriptions clear this.
    streaming_simple_result: bool,
    sync_epoch: u64,
    next_result_order: u64,
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
        let order = self.next_result_order;
        self.next_result_order = self.next_result_order.saturating_add(1);
        // The backend answers in message order, so this query's RowDescription
        // (or EmptyQueryResponse) comes after the answers to whatever Describes
        // and queries precede it. Enqueue it rather than clearing earlier
        // entries: a Describe still in flight is answered *before* this
        // result, and clearing its slot here would let this simple query's
        // text answer for its fields. Each simple query also carries its own
        // SQL, so a later query cannot substitute its text for this one's.
        self.pending_descriptions
            .push_back(PendingDescription::Simple(PendingSimple {
                sql,
                epoch: self.sync_epoch,
                order,
            }));
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
        self.pending_descriptions
            .push_back(PendingDescription::Describe(PendingDescribe {
                target,
                sql,
                epoch: self.sync_epoch,
            }));
    }

    pub(crate) fn execute(&mut self, portal: &Bytes) {
        self.active_plan = self.portal_plans.get(portal).cloned();
        self.active_epoch = Some(self.sync_epoch);
        self.active_portal = Some(portal.clone());
        // This Execute owns the next result set. A suspended portal (max_rows)
        // is resumed by re-executing it, and PostgreSQL refuses to run any
        // other portal while one is suspended, so a front entry already naming
        // this portal can only be the resume of a result still in flight.
        if !self
            .pending_executes
            .front()
            .is_some_and(|pending| pending.name == *portal)
        {
            let order = self.next_result_order;
            self.next_result_order = self.next_result_order.saturating_add(1);
            self.pending_executes.push_back(PendingExecute {
                name: portal.clone(),
                epoch: self.sync_epoch,
                order,
            });
        }
    }

    /// The portal whose result set the backend is streaming, if an Execute
    /// started one that has not ended yet. A simple query's result has no
    /// owner: its rows are governed by the plan its RowDescription armed.
    pub(crate) fn result_owner(&self) -> Option<Bytes> {
        self.pending_executes
            .front()
            .map(|pending| pending.name.clone())
    }

    pub(crate) fn portal_plan(&self, portal: &Bytes) -> Option<Plan> {
        self.portal_plans.get(portal).cloned()
    }

    /// The plan that governs the backend's next `DataRow`.
    ///
    /// One result set streams at a time. A simple query's is governed by the
    /// plan its own RowDescription armed; an Execute's by the executed
    /// portal's own plan — never the single `active_plan`, which a pipelined
    /// client can have armed for a result set still to come.
    pub(crate) fn streaming_plan(&self) -> Option<Plan> {
        if self.streaming_simple_result {
            return self.active_plan();
        }
        match self.result_owner() {
            // A missing portal plan must stay missing — falling back to
            // `active_plan` would judge these rows with a *different* result
            // set's description. The caller refuses on `None`.
            Some(owner) => self.portal_plan(&owner),
            None => self.active_plan(),
        }
    }

    /// One result set or no-row command ended (`CommandComplete`).
    ///
    /// A simple `BEGIN`, `SET`, or other command has no RowDescription, so its
    /// pending description is still at the head of the queue when this arrives.
    /// Psycopg sends exactly that shape before its first transactional extended
    /// query. Leaving the slot behind relabels the next RowDescription as
    /// `BEGIN`, and every computed field is then refused as provenance-free.
    ///
    /// Simple Query and Execute share a monotonic frontend order, so comparing
    /// the queue heads preserves protocol order even when a client pipelines
    /// them in either direction. Error-recovery epochs stay independent: a
    /// Query is a synchronization boundary, but changing epoch assignment here
    /// would alter which provisional Parse/Bind state an ErrorResponse removes.
    pub(crate) fn finish_result_set(&mut self) {
        if self.streaming_simple_result {
            self.streaming_simple_result = false;
            return;
        }

        let simple_order = match self.pending_descriptions.front() {
            Some(PendingDescription::Simple(pending)) => Some(pending.order),
            _ => None,
        };
        let execute_order = self.pending_executes.front().map(|pending| pending.order);

        if simple_order.is_some_and(|simple| execute_order.is_none_or(|execute| simple < execute)) {
            self.pending_descriptions.pop_front();
        } else {
            self.pending_executes.pop_front();
        }
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

    /// SQL text bound into this portal, when we still have it.
    pub(crate) fn sql_for_portal(&self, portal: &Bytes) -> Option<&str> {
        self.portal_statement
            .get(portal)
            .and_then(|statement| self.statement_sql.get(statement))
            .map(String::as_str)
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
        self.pending_descriptions.front().map_or(
            self.active_epoch.unwrap_or(self.sync_epoch),
            |pending| match pending {
                PendingDescription::Describe(pending) => pending.epoch,
                PendingDescription::Simple(pending) => pending.epoch,
            },
        )
    }

    /// Finish one locally suppressed exchange without deleting later
    /// pipelined work. Unlike [`discard_failed_epoch`](Self::discard_failed_epoch),
    /// the backend did execute these mutations; only their responses were
    /// suppressed, so their provisional state remains valid.
    pub(crate) fn finish_suppressed_epoch(&mut self, epoch: u64) {
        self.pending_descriptions.retain(|pending| match pending {
            PendingDescription::Describe(pending) => pending.epoch != epoch,
            PendingDescription::Simple(pending) => pending.epoch != epoch,
        });
        self.pending_parses.retain(|pending| pending.epoch != epoch);
        self.pending_binds.retain(|pending| pending.epoch != epoch);
        // The refused exchange's Executes never completed — their
        // CommandCompletes were swallowed with everything else.
        self.pending_executes
            .retain(|pending| pending.epoch != epoch);
        self.streaming_simple_result = false;
    }

    /// Remove provisional state from a failed exchange while preserving later
    /// pipelined exchanges that have already crossed a `Sync`.
    pub(crate) fn discard_failed_epoch(&mut self) {
        // Whatever was streaming died with the backend's error.
        self.streaming_simple_result = false;
        let failed_epoch = [
            self.pending_descriptions
                .front()
                .map(|pending| match pending {
                    PendingDescription::Describe(pending) => pending.epoch,
                    PendingDescription::Simple(pending) => pending.epoch,
                }),
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

        self.pending_descriptions.retain(|pending| match pending {
            PendingDescription::Describe(pending) => pending.epoch != failed_epoch,
            PendingDescription::Simple(pending) => pending.epoch != failed_epoch,
        });
        self.pending_parses
            .retain(|pending| pending.epoch != failed_epoch);
        self.pending_binds
            .retain(|pending| pending.epoch != failed_epoch);
        self.pending_executes
            .retain(|pending| pending.epoch != failed_epoch);
    }

    /// A `NoData` answers a `Describe` whose statement returns no rows. It can
    /// never answer a simple query, which is refused rather than guessed at.
    pub(crate) fn finish_no_data(&mut self) -> Result<(), ()> {
        match self.pending_descriptions.front() {
            Some(PendingDescription::Describe(_)) => {
                self.pending_descriptions.pop_front();
                Ok(())
            }
            _ => Err(()),
        }
    }

    /// The SQL for *this* result set, read from the entry whose answer is
    /// next — the Describe at the head of the queue, or the simple query
    /// ahead of it.
    ///
    /// Each entry carries the SQL it was created from, so the answer is
    /// structurally attached to the message that caused it: a Describe can
    /// only answer with the statement's own text, a simple query with its own.
    /// An outstanding Describe whose SQL was never recorded (`parse_parse`
    /// could not decode a non-UTF-8 statement) returns `None` rather than
    /// falling back to some other text — that substitution judged one
    /// statement's fields by another's authority.
    pub(crate) fn described_sql(&self) -> Option<String> {
        match self.pending_descriptions.front() {
            Some(PendingDescription::Describe(pending)) => pending.sql.clone(),
            Some(PendingDescription::Simple(pending)) => pending.sql.clone(),
            None => None,
        }
    }

    pub(crate) fn discard_description(&mut self) {
        self.pending_descriptions.pop_front();
    }

    /// Bind a completed plan to the described target and activate it for the
    /// DataRows that follow the RowDescription.
    ///
    /// `Err` when the RowDescription answered nothing this proxy forwarded —
    /// unreachable in a sane stream, and refused rather than read as a simple
    /// result: guessing lets one message's description govern another's rows.
    pub(crate) fn finish_description(&mut self, plan: Plan) -> Result<(), ()> {
        let pending = self.pending_descriptions.pop_front();
        let (epoch, target) = match pending {
            Some(PendingDescription::Describe(pending)) => {
                self.streaming_simple_result = false;
                (pending.epoch, Some(pending.target))
            }
            // A RowDescription that answered a simple query: its whole result
            // set streams as one unit. An extended Describe's RowDescription
            // merely arms a plan for an Execute that is still to come, so it
            // must not mark the current result simple.
            Some(PendingDescription::Simple(pending)) => {
                self.streaming_simple_result = true;
                (pending.epoch, None)
            }
            None => return Err(()),
        };
        match target {
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
        Ok(())
    }

    /// An `EmptyQueryResponse` answers a simple query with no statements — and
    /// ends its result set in one step.
    ///
    /// An empty query produces no RowDescription, so no `finish_result_set`
    /// follows its end the way one follows a described simple result. This
    /// clears the streaming flag and spends no queued Execute's slot on its
    /// own, so the caller cannot forget the pairing or get the order wrong.
    /// Describes are never answered this way, and an Execute never is.
    pub(crate) fn finish_empty_query(&mut self) -> Result<(), ()> {
        match self.pending_descriptions.front() {
            Some(PendingDescription::Simple(_)) => {
                self.pending_descriptions.pop_front();
                self.streaming_simple_result = false;
                Ok(())
            }
            _ => Err(()),
        }
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
            lenient: false,
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
        state.finish_description(plan()).unwrap();

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
        state.finish_description(plan()).unwrap();
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
        state.finish_description(plan()).unwrap();

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
        state.finish_description(plan()).unwrap();
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

    /// A pipelined simple query streams its own result before a queued
    /// Execute's rows, and its CommandComplete spends no Execute slot.
    ///
    /// `Q ...; Sync; Parse(bad) Bind(p bad) Execute(p); Sync` queues `p`
    /// before the simple RowDescription arrives. The simple result is armed by
    /// it and must be vetted by *that* plan; and when it ends, the queued
    /// Execute must still own the *next* result set. Without the
    /// streaming-simple flag, the simple CommandComplete popped `p` and the
    /// simple result, mistaking one innocent result for another.
    #[test]
    fn a_pipelined_simple_result_spends_no_execute_slot() {
        let mut state = PlanState::default();
        state.begin_simple_query(Some("SELECT 1 AS x".into()));
        state.parse(name("sm"), "SELECT a FROM fz.t1 LIMIT 2".into());
        state.bind(name("p"), name("sm"), None);
        state.execute(&name("p"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));

        // The simple RowDescription lands: its own plan governs the rows —
        // the queued Execute's missing plan must not swallow them.
        state.finish_description(plan()).unwrap();
        assert_eq!(
            state.streaming_plan().map(|p| p.len()),
            Some(1),
            "a RowDescription that answered no Describe is a simple result"
        );
        assert!(
            state.portal_plan(&name("p")).is_none(),
            "the never-described statement leaves the Execute with no plan"
        );

        // The simple CommandComplete ends its own result, not the Execute's.
        state.finish_result_set();
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"p"[..]),
            "the simple result must not spend the Execute's queued slot"
        );
        assert!(
            state.streaming_plan().is_none(),
            "the Execute's rows have no plan and must be refused"
        );
    }

    /// A Describe's RowDescription arms a plan for an Execute still to come;
    /// it must not govern the rows already streaming. An Execute result is
    /// vetted by the executed portal's own plan even when that plan is none —
    /// never by the just-armed `active_plan`.
    #[test]
    fn a_describe_row_description_does_not_arm_the_streaming_result() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.execute(&name("p"));
        state.finish_description(plan()).unwrap();
        assert!(
            state.streaming_plan().is_none(),
            "the describe's plan belongs to a result set still to come"
        );
    }

    /// A suspended portal (`max_rows`) is resumed by re-executing it; the
    /// resume must not queue a second owner for a result set still streaming.
    #[test]
    fn a_suspended_portal_resume_does_not_requeue() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan()).unwrap();
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        state.execute(&name("p")); // resume: the front already names p
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));

        // A suspended portal is never followed by another portal's result, so
        // one CommandComplete ends it and one pop frees the slot.
        state.finish_result_set();
        assert_eq!(
            state.result_owner(),
            None,
            "the resume must not have queued a second owner"
        );
    }

    /// A `CommandComplete` ends an Execute's result set and spends its queued
    /// slot, even when zero rows were returned. (An Execute is never answered
    /// with `EmptyQueryResponse` — that belongs to an empty simple query.)
    #[test]
    fn a_command_complete_spends_the_executes_slot() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan()).unwrap();
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));

        state.finish_result_set();
        assert_eq!(
            state.result_owner(),
            None,
            "the ended result must be charged to its Execute"
        );
    }

    /// An `EmptyQueryResponse` answers an empty simple query and ends it in
    /// one step: it must not spend a queued Execute's slot, because that
    /// Execute was pipelined *behind* the query and its result is still to
    /// come. The empty result also must not leave the streaming flag set.
    #[test]
    fn an_empty_query_response_does_not_spend_a_pipelined_executes_slot() {
        let mut state = PlanState::default();
        // Q("") Parse Describe Bind Execute, pipelined in one flush.
        state.begin_simple_query(Some(String::new()));
        state.parse(name("s"), "SELECT 1 AS x".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));

        // The empty query's own result answers first, with no RowDescription.
        state.finish_empty_query().unwrap();
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"p"[..]),
            "the empty query's end must not spend the Execute's slot"
        );
        assert!(
            !state.streaming_simple_result,
            "the empty result must not leave a simple result streaming"
        );
        // The Describe's answer comes next and still arms the Execute.
        assert_eq!(
            state.described_sql().as_deref(),
            Some("SELECT 1 AS x"),
            "the queue head must be the Describe after the empty query is consumed"
        );
        state.finish_description(plan()).unwrap();
        assert!(state.active_plan().is_some());
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));
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
        state.finish_description(plan()).unwrap(); // RowDescription, text formats
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
        state.finish_description(plan()).unwrap();
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
        state.finish_description(plan()).unwrap();
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

    /// A result set belongs to the portal that was executed, in Execute order.
    ///
    /// `execute` used to overwrite one global `active_plan`, so in a pipelined
    /// `Execute p1, Execute p2` the second plan governed the first portal's
    /// rows — a passthrough plan for `p2` released `p1`'s masked columns.
    #[test]
    fn each_execute_owns_its_own_result_set() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT 1".into());
        state.parse(name("s2"), "SELECT 2".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state.finish_description(plan()).unwrap();
        state.describe(DescribeTarget::Statement(name("s2")));
        state.finish_description(plan()).unwrap();

        state.bind(name("p1"), name("s1"), None);
        state.execute(&name("p1"));
        state.bind(name("p2"), name("s2"), None);
        state.execute(&name("p2"));

        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"p1"[..]),
            "p1's rows come first: the backend executes in message order"
        );
        assert!(state.portal_plan(&name("p1")).is_some());

        state.finish_result_set(); // p1's CommandComplete
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"p2"[..]),
            "the next Execute owns the next result set"
        );

        state.finish_result_set();
        assert_eq!(state.result_owner(), None);
    }

    /// A never-described statement has no portal plan, so the rows its Execute
    /// produces have an owner with no plan and must fail closed.
    #[test]
    fn an_undescribed_execute_owns_rows_without_a_plan() {
        let mut state = PlanState::default();
        state.parse(name("sm"), "SELECT secret FROM t".into());
        state.bind(name("p"), name("sm"), None);
        state.execute(&name("p"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));
        assert!(
            state.portal_plan(&name("p")).is_none(),
            "a statement that was never described has no masking plan"
        );
    }

    /// A locally refused exchange dies without its Executes ever reaching
    /// CommandComplete, so its queued result-set owners must go too.
    #[test]
    fn a_suppressed_epoch_drops_its_executed_portals() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan()).unwrap();
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));

        state.finish_suppressed_epoch(0);
        assert_eq!(
            state.result_owner(),
            None,
            "a swallowed result set never completes, so its owner must not linger"
        );
    }

    /// Same for an exchange the *backend* rejected: it skips to Sync and never
    /// emits CommandComplete for the Executes it was asked to run.
    #[test]
    fn a_failed_epoch_drops_its_executed_portals() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan()).unwrap();
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        state.sync();
        state.discard_failed_epoch();
        assert_eq!(
            state.result_owner(),
            None,
            "a backend error aborts the exchange before any CommandComplete"
        );
    }
}
