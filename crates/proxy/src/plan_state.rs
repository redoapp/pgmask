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

use crate::mask::{JsonProjection, MaskSpec};
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
    /// Present only when this value is a JSON subtree extracted from the
    /// classified document. This is value provenance, not mask configuration.
    pub(crate) json_projection: Option<JsonProjection>,
    pub(crate) type_oid: u32,
    pub(crate) format: i16,
    /// The spec is the *type-aware fallback* for an unclassified nullable (or
    /// catalog-unresolved) column, not an operator's choice. A fallback mask
    /// that cannot be applied to some value or format degrades that field to
    /// NULL — strictly less disclosure — instead of refusing the result set.
    /// Declared NOT NULL sources and configured masks stay fail-closed.
    pub(crate) lenient: bool,
    /// HMAC state with this spec's pseudonym domain already absorbed, built
    /// once when the plan is bound. The domain is fixed for the plan's
    /// lifetime, and re-absorbing 20-60 domain bytes per value pushed most
    /// short pseudonym inputs from one SHA-256 compression block to two.
    /// `None` for masks that do not digest; always safe to ignore.
    pub(crate) primed: Option<crate::mask::PrimedMac>,
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
    /// Plan that governed this Execute when it was issued.
    ///
    /// Bind of the same portal name overwrites `portal_plans` immediately.
    /// Looking that map up by owner name then judges in-flight DataRows with
    /// the *new* binding's plan. A classified first result plus a same-arity
    /// all-passthrough rebind took `Vetted::unmasked_row`. Snapshotting here
    /// is what keeps those rows bound to the Execute that produced them.
    /// `None` when the statement was not yet described; filled in when the
    /// plan lands, but only if this slot's [`bind_generation`] still matches
    /// the portal's current one.
    plan: Option<Plan>,
    /// Bind generation this Execute ran against. Resume of the same portal
    /// shares an owner only when this still matches; a Bind in between bumps
    /// it, and the next Execute is a new result set.
    bind_generation: u64,
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
    /// How many times each portal name has been Bound.
    ///
    /// `execute` treats a second Execute of the same name as a resume of one
    /// result set — two `Execute p` before PortalSuspended share an owner.
    /// A Bind in between is not a resume: it replaces the portal. Without
    /// this counter the second Execute of a reused name skipped the queue,
    /// `portal_plans[p]` already held the new plan, and in-flight DataRows
    /// were judged with it. See [`PendingExecute::bind_generation`].
    ///
    /// Close must not reset this counter. `Close P p` dropped the map
    /// entry; a later Bind of the same name started at generation 1 again
    /// and collided with an in-flight `PendingExecute` that still held 1.
    /// In one Sync, Execute runs before Describe is answered, so
    /// `pending.plan` is still `None`. `streaming_plan` saw a matching
    /// generation and fell back to the rebound all-passthrough plan;
    /// same-arity classified DataRows took `Vetted::unmasked_row`. Without
    /// Close the second Bind bumps to 2 and the proxy refuses. Close S of
    /// the statement implicitly closes its portals and leaked the same
    /// way. Unnamed portal `""` and binary Bind too. The generation is
    /// how many times the *name* has been Bound, not a Close-able
    /// resource. A Bind never reuses a generation an unfinished
    /// `PendingExecute` still holds.
    portal_bind_generations: HashMap<Bytes, u64>,
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
    ///
    /// `PortalSuspended` is not completion. A limited Execute leaves its owner
    /// here so a resume of the *same* portal does not re-queue, but a later
    /// Execute of a *different* portal is a new result set — Postgres runs it.
    /// See [`PlanState::suspend_result`].
    ///
    /// A sibling without PortalSuspended: two full Executes (`max_rows=0`)
    /// that reuse one portal name. Bind of the second statement overwrites
    /// `portal_plans` before the first DataRows are judged. `execute` treated
    /// the second Execute as a resume (the front already named that portal),
    /// so `streaming_plan` applied the new all-passthrough plan to the
    /// classified first result. `Vetted::unmasked_row` released the poison
    /// row. Unnamed portal `""` and binary Bind leaked the same way.
    /// Pass-then-class over-masked (fail-closed). Two different portal names
    /// in one Sync, and a Sync between the two PBEs, were already safe.
    ///
    /// Each owner snapshotted its plan at Execute. Bind bumps a per-portal
    /// generation so a later Execute of the same name after a rebind is a
    /// new result set, not a resume. Unknown (no snapshot, generation no
    /// longer current) refuses DataRows rather than unmasking.
    ///
    /// A sibling of that rebind: `Close` of the portal (or of the
    /// statement that created it) used to drop the generation, so the
    /// next Bind of the same name started at 1 again and aliased the
    /// unfinished Execute. Same leak, same Sync, no second Execute
    /// required. Close must not reset a generation an unfinished
    /// owner still holds.
    pending_executes: VecDeque<PendingExecute>,
    /// The front of `pending_executes` is a portal that has emitted
    /// `PortalSuspended` and is not the result currently streaming.
    ///
    /// Distinguishes "Execute p1 then Execute p2, both in flight" (p1 still
    /// owns the next DataRows) from "Execute p1, PortalSuspended, Execute p2"
    /// (p2 owns them). Without the flag those are the same queue shape, and
    /// the second used the first's plan.
    suspended: bool,
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
                self.portal_bind_generations.remove(&portal);
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
        // Bump first so any in-flight Execute of this name keeps its
        // snapshot. The new plan is for the *next* Execute, not the rows
        // already owed.
        self.bump_bind_generation(&portal);
        let Some(portal_plan) = self
            .statement_plans
            .get(&statement)
            .map(|statement_plan| Self::stamp(statement_plan, formats.as_ref()))
        else {
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
        self.install_portal_plan(portal, portal_plan);
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
        // is resumed by re-executing it. The next lines used to say PostgreSQL
        // refuses to run any other portal while one is suspended, so a front
        // entry already naming this portal could only be that resume. That
        // refusal is false — we measured it. After PortalSuspended the backend
        // will run a *different* named portal, and CommandComplete then popped
        // the still-queued suspended owner, so those DataRows were vetted with
        // the stale plan. An all-passthrough plan takes `Vetted::unmasked_row`
        // and released email, salary, birth, uuid, phone, IP, notes, address
        // (same arity as the suspended result). A mixed plan leaked only the
        // passthrough slots.
        //
        // Resume of the *same* portal still must not re-queue: two Execute(p)
        // messages before PortalSuspended arrives share one owner. A different
        // portal after we have seen PortalSuspended must not inherit that
        // owner — `suspend_result` marks the pause, and the branch below
        // discards it so `streaming_plan` is this portal's, or none.
        //
        // A sibling of that leak: resume of the *same* portal after Sync,
        // without BEGIN. Sync ends the implicit transaction; Postgres
        // destroys the named portal (SQLSTATE 34000). This branch clears
        // `suspended` and returns, so the destroyed portal stays the owner.
        // `discard_failed_epoch` used to return early (no pending
        // Parse/Bind/Describe) and leave that all-passthrough plan on
        // `pending_executes`. The next portal queued behind the zombie;
        // same-arity classified DataRows went out via `Vetted::unmasked_row`.
        //
        // A sibling without PortalSuspended: two full Executes (`max_rows=0`)
        // that reuse one portal name. Bind overwrites `portal_plans` before
        // the first DataRows are judged; the second Execute was treated as a
        // resume (the front already named that portal), so `streaming_plan`
        // applied the new all-passthrough plan to the classified first
        // result. `Vetted::unmasked_row` released the poison row. Unnamed
        // portal `""` and binary Bind leaked the same way. Pass-then-class
        // over-masked (fail-closed). Two different portal names, and a Sync
        // between the two PBEs, were already safe. Resume still shares an
        // owner only when the name *and* bind generation match; the owner's
        // plan is snapshotted at Execute. Unknown refuses DataRows.
        //
        // A sibling of that rebind: Close of the portal (or of its
        // statement) reset the generation. The next Bind of the same name
        // started at 1 again and collided with this Execute. In one Sync
        // `pending.plan` is still `None` (Describe unanswered), so
        // `streaming_plan` treated the rebound all-passthrough plan as
        // current. Close must not alias an unfinished owner.
        if self.suspended {
            self.suspended = false;
            if self.is_resume(portal) {
                // Stamp the resume onto this Sync's epoch so a 34000
                // ErrorResponse discards *this* exchange, not only the
                // original limited Execute's.
                //
                // That stamp closed only A's own Execute. A later-epoch
                // ErrorResponse that is not that Execute — simple Query
                // `1/0` (H10a), Describe of the dead portal (H5b, 34000
                // on Describe not resume), Parse `SELECT !!!`, Bind of a
                // missing statement — still left the original slot on
                // `pending_executes`. [`PlanState::ready_for_query`] Idle
                // discards the owner because the implicit transaction
                // ended; [`PlanState::discard_failed_epoch`] also drops
                // older-epoch Executes while `suspended`.
                if let Some(pending) = self.pending_executes.front_mut() {
                    pending.epoch = self.sync_epoch;
                }
                return;
            }
            let _ = self.pending_executes.pop_front();
        } else if self.is_resume(portal) {
            return;
        }
        let order = self.next_result_order;
        self.next_result_order = self.next_result_order.saturating_add(1);
        self.pending_executes.push_back(PendingExecute {
            name: portal.clone(),
            epoch: self.sync_epoch,
            order,
            plan: self.portal_plans.get(portal).cloned(),
            bind_generation: self.bind_generation(portal),
        });
    }

    /// `PortalSuspended`: the streaming Execute paused; it has not completed.
    ///
    /// Found live: after `Execute p_pass max_rows=1` the next DataRows of a
    /// different named portal (`SELECT email, name`, same arity) were judged
    /// with `p_pass`'s all-passthrough plan and forwarded by
    /// `Vetted::unmasked_row`. The comment on [`PlanState::execute`] that
    /// Postgres refuses a second portal while one is suspended was wrong —
    /// it runs it. `CommandComplete` then popped the *suspended* owner.
    ///
    /// A resume of the same portal (pipelined `Execute p; Execute p`) shares
    /// one owner and must keep it. A later Execute already queued, or one
    /// that arrives after this message, is a different result set: drop the
    /// paused owner so `streaming_plan` cannot inherit it. Resume re-queues.
    /// Unknown (no remaining owner) refuses DataRows rather than falling
    /// back to the suspended plan.
    ///
    /// Resume after Sync, without BEGIN, is a sibling: Postgres destroys the
    /// named portal (SQLSTATE 34000). That ErrorResponse must discard the
    /// owner — see [`PlanState::discard_failed_epoch`] — or the next portal
    /// inherits this all-passthrough plan the same way.
    ///
    /// After `PortalSuspended`, `ReadyForQuery Idle` means those named
    /// portals are already gone — see [`PlanState::ready_for_query`]. Do
    /// not wait for a later-epoch error to notice. The resume-only stamp
    /// missed H10a (`SELECT 1/0`) and H5b (34000 on Describe).
    pub(crate) fn suspend_result(&mut self) {
        if self.pending_executes.len() > 1 {
            let _ = self.pending_executes.pop_front();
            self.suspended = false;
        } else {
            self.suspended = true;
        }
    }

    /// `ReadyForQuery` after `PortalSuspended`.
    ///
    /// Postgres destroys named portals of an implicit transaction at
    /// transaction end. After `PortalSuspended`, `ReadyForQuery Idle`
    /// (`Z` status `I`) means those portals are gone — discard the
    /// suspended result owner. A later-epoch ErrorResponse that is not
    /// the paused portal's own Execute (H10a: simple Query `1/0`; H5b:
    /// 34000 on Describe of the dead portal, not resume Execute; Parse
    /// `SELECT !!!`; Bind of a missing statement) used to leave that
    /// all-passthrough plan on `pending_executes`. The next same-arity
    /// portal inherited it via `Vetted::unmasked_row`. The resume-only
    /// epoch stamp closed only 34000 on A's own Execute.
    ///
    /// `ReadyForQuery InTxn` (`T`) must not discard: `BEGIN; suspend;
    /// Sync` keeps the portal. InFailedTxn (`E`) is left to
    /// [`PlanState::discard_failed_epoch`], which has already run.
    pub(crate) fn ready_for_query(&mut self, status: u8) {
        if !self.suspended || status != b'I' {
            return;
        }
        // Implicit transaction ended; every queued Execute's portal is gone.
        self.pending_executes.clear();
        self.suspended = false;
        self.active_plan = None;
        self.active_portal = None;
        self.active_epoch = None;
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

    fn bind_generation(&self, portal: &Bytes) -> u64 {
        self.portal_bind_generations
            .get(portal)
            .copied()
            .unwrap_or(0)
    }

    fn bump_bind_generation(&mut self, portal: &Bytes) {
        let mut next = self.bind_generation(portal).saturating_add(1);
        // Close of this name used to drop the map entry so `next` became 1
        // again and collided with an unfinished Execute that still held 1.
        // Never reuse a generation a pending owner still names.
        while self
            .pending_executes
            .iter()
            .any(|pending| pending.name == *portal && pending.bind_generation == next)
        {
            let bumped = next.saturating_add(1);
            if bumped == next {
                break;
            }
            next = bumped;
        }
        self.portal_bind_generations.insert(portal.clone(), next);
    }

    /// Same portal name *and* the same Bind. A Bind in between is a new
    /// result set, not a resume.
    fn is_resume(&self, portal: &Bytes) -> bool {
        self.pending_executes.front().is_some_and(|pending| {
            pending.name == *portal && pending.bind_generation == self.bind_generation(portal)
        })
    }

    fn fill_pending_plan(&mut self, portal: &Bytes, plan: &Plan) {
        let generation = self.bind_generation(portal);
        for pending in &mut self.pending_executes {
            if pending.name == *portal
                && pending.bind_generation == generation
                && pending.plan.is_none()
            {
                pending.plan = Some(plan.clone());
            }
        }
    }

    fn install_portal_plan(&mut self, portal: Bytes, plan: Plan) {
        self.fill_pending_plan(&portal, &plan);
        self.portal_plans.insert(portal, plan);
    }

    /// The plan that governs the backend's next `DataRow`.
    ///
    /// One result set streams at a time. A simple query's is governed by the
    /// plan its own RowDescription armed; an Execute's by the executed
    /// portal's own plan — never the single `active_plan`, which a pipelined
    /// client can have armed for a result set still to come.
    ///
    /// That "own plan" is the snapshot on the owner slot, not a lookup of
    /// `portal_plans` by name. Bind of the same portal overwrites the map
    /// before the first DataRows are judged; looking it up then applied a
    /// later all-passthrough plan to a classified result (`unmasked_row`).
    /// A missing snapshot falls back to the map only while this Execute's
    /// bind generation is still current — otherwise unknown, and the caller
    /// refuses rather than unmasking. Close must not make a later Bind look
    /// current by resetting that counter.
    pub(crate) fn streaming_plan(&self) -> Option<Plan> {
        if self.streaming_simple_result {
            return self.active_plan();
        }
        if self.result_owner().is_none() {
            // After PortalSuspended with no remaining owner there is no
            // streaming result. Falling back to `active_plan` would re-apply
            // the suspended portal's plan to the next portal's DataRows —
            // the 0.1.97 leak (`unmasked_row` under an all-passthrough plan).
            if self.suspended {
                return None;
            }
            return self.active_plan();
        }
        // A missing portal plan must stay missing — falling back to
        // `active_plan` would judge these rows with a *different* result
        // set's description. The caller refuses on `None`.
        let pending = self.pending_executes.front()?;
        if let Some(plan) = pending.plan.clone() {
            return Some(plan);
        }
        let generation = pending.bind_generation;
        let name = pending.name.clone();
        if generation == self.bind_generation(&name) {
            self.portal_plan(&name)
        } else {
            None
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
        // This CommandComplete ended an Execute's result, not a pause.
        // A simple result above can interleave after PortalSuspended and
        // must leave `suspended` set so a later different portal still
        // cannot inherit the paused owner.
        self.suspended = false;

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
    ///
    /// Bind generation also survives. It is how many times this *name*
    /// has been Bound, not a Postgres resource. Removing it here reset
    /// the counter so a later Bind reused generation 1 and
    /// `streaming_plan` attached the rebound all-passthrough plan to
    /// classified DataRows still owed (`unmasked_row`). Close S of the
    /// classified statement leaked the same way. The map entry for the
    /// portal is dropped; the name's generation is not.
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
                    // Not portal_bind_generations: see the comment above.
                }
            }
            DescribeTarget::Portal(portal) => {
                self.portal_statement.remove(&portal);
                self.portal_plans.remove(&portal);
                self.portal_formats.remove(&portal);
                // Not portal_bind_generations: see the comment above.
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
            let stamped = self
                .portal_statement
                .get(&portal)
                .and_then(|statement| self.statement_plans.get(statement))
                .map(|statement_plan| {
                    Self::stamp(
                        statement_plan,
                        self.portal_formats.get(&portal).and_then(Option::as_ref),
                    )
                });
            if let Some(stamped) = stamped {
                self.install_portal_plan(portal.clone(), stamped);
            }
        } else if let Some(plan) = self.portal_plans.get(&portal).cloned() {
            // Execute already ran and snapshotted nothing; the plan exists
            // now. Fill only this binding — a later Bind bumped generation.
            self.fill_pending_plan(&portal, &plan);
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
        self.suspended = false;
    }

    /// Remove provisional state from a failed exchange while preserving later
    /// pipelined exchanges that have already crossed a `Sync`.
    pub(crate) fn discard_failed_epoch(&mut self) {
        // Whatever was streaming died with the backend's error.
        self.streaming_simple_result = false;
        // Do not clear `suspended` before the retain below. Clearing it
        // first left an older-epoch Execute on `pending_executes` when
        // the ErrorResponse belonged to a later Parse/Bind/Describe/
        // simple Query. H10a: Query `SELECT 1/0` after PortalSuspended
        // + Idle. H5b: 34000 on Describe of the dead portal, not on
        // resume Execute. The resume-only epoch stamp missed both.
        let was_suspended = self.suspended;
        // An ErrorResponse that completes an Execute must not leave
        // `streaming_plan` pointing at a portal that no longer exists. The
        // comment on [`PlanState::execute`] that Postgres refuses a second
        // portal while one is suspended was wrong — we measured it. A sibling:
        // resume after Sync, without BEGIN. Sync ends the implicit
        // transaction; Postgres destroys the named portal (SQLSTATE 34000).
        // Resume clears `suspended` but leaves that portal as owner. There is
        // no pending Parse/Bind/Describe, so the early return below used to
        // keep the all-passthrough plan on `pending_executes`. The next
        // portal queued behind the zombie; same-arity classified DataRows
        // went out via `Vetted::unmasked_row`.
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
        .min()
        .or_else(|| self.pending_executes.front().map(|pending| pending.epoch));
        // The destroyed portal's plan must not govern the next DataRows via
        // `streaming_plan`'s `active_plan` fallback.
        self.active_plan = None;
        self.active_portal = None;
        self.active_epoch = None;
        let Some(failed_epoch) = failed_epoch else {
            self.suspended = false;
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
        self.pending_executes.retain(|pending| {
            if pending.epoch == failed_epoch {
                return false;
            }
            // A paused portal whose epoch predates this error cannot
            // produce further rows. Keep later-epoch Executes.
            if was_suspended && pending.epoch < failed_epoch {
                return false;
            }
            true
        });
        self.suspended = false;
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
                    self.install_portal_plan(portal, stamped);
                }
            }
            Some(DescribeTarget::Portal(name)) => {
                self.install_portal_plan(name, plan.clone());
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
            json_projection: None,
            type_oid: 25,
            format: 0,
            lenient: false,
            primed: None,
        }])
    }

    fn marked_plan(oid: u32, spec: Mask) -> Plan {
        Arc::new(vec![
            FieldPlan {
                spec: MaskSpec::new(spec),
                json_projection: None,
                type_oid: oid,
                format: 0,
                lenient: false,
                primed: None,
            },
            FieldPlan {
                spec: MaskSpec::new(spec),
                json_projection: None,
                type_oid: oid,
                format: 0,
                lenient: false,
                primed: None,
            },
        ])
    }

    fn mixed_plan(oid: u32) -> Plan {
        Arc::new(vec![
            FieldPlan {
                spec: MaskSpec::new(Mask::None),
                json_projection: None,
                type_oid: oid,
                format: 0,
                lenient: false,
                primed: None,
            },
            FieldPlan {
                spec: MaskSpec::new(Mask::Redact),
                json_projection: None,
                type_oid: oid,
                format: 0,
                lenient: false,
                primed: None,
            },
        ])
    }

    fn plan_oid(plan: &[FieldPlan]) -> u32 {
        plan.first().map(|field| field.type_oid).unwrap()
    }

    fn streaming_oid(state: &PlanState) -> Option<u32> {
        state
            .streaming_plan()
            .and_then(|plan| plan.first().map(|field| field.type_oid))
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

    /// A refresh must not unmask an in-flight result.
    ///
    /// `invalidate_if_stale` drops cached statement/portal plans so the next
    /// Bind/Execute fails closed until re-Describe. The rows already streaming
    /// keep the plan their RowDescription armed — including a masked plan that
    /// a new snapshot would now pass through. Switching those rows to
    /// `Vetted::unmasked_row` mid-result would be a leak.
    #[test]
    fn a_catalog_refresh_does_not_unmask_in_flight_rows() {
        let mut state = PlanState::default();
        state.begin_simple_query(Some("SELECT secret FROM t".into()));
        let masked = marked_plan(25, Mask::Redact);
        state.finish_description(masked.clone()).unwrap();
        assert!(
            state
                .streaming_plan()
                .is_some_and(|plan| plan.iter().all(|field| !field.spec.is_passthrough())),
            "the result started masked"
        );

        state.invalidate_if_stale(1);
        let streaming = state
            .streaming_plan()
            .expect("in-flight rows keep their plan across a refresh");
        assert_eq!(
            streaming.len(),
            masked.len(),
            "the in-flight plan is the one the RowDescription armed"
        );
        assert!(
            streaming.iter().all(|field| !field.spec.is_passthrough()),
            "a refresh must not switch in-flight rows to passthrough"
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

        // A *resume* of the same portal is never followed by another portal's
        // result on this owner: one CommandComplete ends it and one pop frees
        // the slot. (A *different* portal after PortalSuspended is a different
        // result set — see
        // `a_different_portal_after_suspend_does_not_inherit_the_stale_plan`.)
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

    /// After PortalSuspended, a different named portal's DataRows must not
    /// inherit the paused owner's plan.
    ///
    /// Measured live: `Execute p_pass max_rows=1` (city, id — all passthrough)
    /// then `Execute p_mask` (`email, name`, same arity) served the canaries
    /// through `Vetted::unmasked_row`. `pending_executes` still named `p_pass`,
    /// and CommandComplete popped that owner rather than `p_mask`. The comment
    /// that Postgres refuses the second portal was wrong.
    #[test]
    fn a_different_portal_after_suspend_does_not_inherit_the_stale_plan() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();

        state.bind(name("p1"), name("s1"), None);
        state.execute(&name("p1"));
        assert_eq!(
            streaming_oid(&state),
            Some(1),
            "the limited Execute's own rows use its plan"
        );

        state.suspend_result();
        state.bind(name("p2"), name("s2"), None);
        state.execute(&name("p2"));
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"p2"[..]),
            "the next portal owns the next result set"
        );
        assert_eq!(
            streaming_oid(&state),
            Some(2),
            "those DataRows must not inherit the suspended all-passthrough plan"
        );

        state.finish_result_set();
        assert_eq!(
            state.result_owner(),
            None,
            "CommandComplete spends the portal that actually completed, not the paused one"
        );

        // Resume re-queues the paused portal; it was discarded, not completed.
        state.execute(&name("p1"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p1"[..]));
        assert_eq!(streaming_oid(&state), Some(1));
    }

    /// Same leak with a mixed plan: only the passthrough *slots* released.
    /// The second portal's plan must govern every slot, not just the masked
    /// ones of the first.
    #[test]
    fn a_mixed_stale_plan_after_suspend_does_not_release_passthrough_slots() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, note FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state.finish_description(mixed_plan(1)).unwrap();
        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();

        state.bind(name("p1"), name("s1"), None);
        state.execute(&name("p1"));
        state.suspend_result();
        state.bind(name("p2"), name("s2"), None);
        state.execute(&name("p2"));

        let streaming = state.streaming_plan().expect("p2 has a plan");
        assert_eq!(plan_oid(&streaming), 2);
        assert!(
            streaming.iter().all(|field| !field.spec.is_passthrough()),
            "a passthrough slot from the suspended plan must not survive onto p2"
        );
    }

    /// Pipelined `Execute p1 max_rows=1; Execute p2` — PortalSuspended arrives
    /// with both owners queued. Postgres then streams p2; p1 must not still
    /// own those rows.
    #[test]
    fn a_pipelined_execute_after_a_limited_execute_switches_on_suspend() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();

        state.bind(name("p1"), name("s1"), None);
        state.execute(&name("p1"));
        state.bind(name("p2"), name("s2"), None);
        state.execute(&name("p2"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p1"[..]));
        assert_eq!(streaming_oid(&state), Some(1));

        state.suspend_result();
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"p2"[..]),
            "after PortalSuspended the already-queued Execute owns the stream"
        );
        assert_eq!(streaming_oid(&state), Some(2));

        state.finish_result_set();
        assert_eq!(state.result_owner(), None);
    }

    /// Resume after we have seen PortalSuspended keeps the paused owner and
    /// does not queue a second slot.
    #[test]
    fn a_resume_after_portal_suspended_keeps_the_owner() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan()).unwrap();
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        state.suspend_result();
        state.execute(&name("p"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"p"[..]));
        state.finish_result_set();
        assert_eq!(state.result_owner(), None);
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

    /// Failed resume of a suspended named portal after Sync must not leave
    /// that portal as a zombie result owner.
    ///
    /// Measured live: `Execute A max_rows=1 Sync` (PortalSuspended, city|id
    /// passthrough), then `Execute A max_rows=0 Sync`. Sync without BEGIN
    /// ended the implicit transaction; Postgres destroyed A (SQLSTATE 34000).
    /// Resume cleared `suspended` but left A on `pending_executes`.
    /// `discard_failed_epoch` returned early — no pending Parse/Bind/Describe.
    /// Execute B (`email, name`, same arity) queued behind the zombie and
    /// `streaming_plan` used A's all-passthrough plan; `Vetted::unmasked_row`
    /// released the canaries. Sibling of the 0.1.97 leak: the comment that
    /// Postgres refuses a second portal while one is suspended was wrong.
    #[test]
    fn a_failed_resume_after_sync_does_not_leave_a_zombie_owner() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.finish_parse();
        state.bind(name("A"), name("s1"), None);
        state.finish_bind();
        state.execute(&name("A"));
        state.suspend_result();
        state.sync();

        // Resume: the portal is gone on the backend. This is the early-return
        // path — Parse/Bind/Describe already completed.
        state.execute(&name("A"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"A"[..]));
        assert!(
            state.pending_parses.is_empty()
                && state.pending_binds.is_empty()
                && state.pending_descriptions.is_empty(),
            "the 34000 path has no pending Parse/Bind/Describe"
        );
        state.discard_failed_epoch();
        assert_eq!(
            state.result_owner(),
            None,
            "a 34000 must not leave the destroyed portal as result owner"
        );
        assert!(
            state.streaming_plan().is_none(),
            "streaming_plan must not still name the destroyed portal's plan"
        );

        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.bind(name("B"), name("s2"), None);
        state.execute(&name("B"));
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"B"[..]),
            "the next portal must own its own result set, not queue behind A"
        );
        assert_eq!(
            streaming_oid(&state),
            Some(2),
            "those DataRows must not inherit the zombie all-passthrough plan"
        );
    }

    /// H10a: a later-epoch simple Query error after PortalSuspended + Idle
    /// must not leave the paused portal as result owner.
    ///
    /// Measured live: `Execute A max_rows=1 Sync` (PortalSuspended,
    /// ReadyForQuery Idle), `Query SELECT 1/0` (22012), then Execute B
    /// (`email, name`, same arity). The resume-only epoch stamp closed
    /// only 34000 on A's own Execute. This error is not that Execute;
    /// `discard_failed_epoch` used to drop only the Query's epoch and
    /// leave A's all-passthrough plan queued. `Vetted::unmasked_row`
    /// released the canaries.
    #[test]
    fn a_simple_query_error_after_suspend_idle_does_not_leave_a_zombie_owner() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.finish_parse();
        state.bind(name("A"), name("s1"), None);
        state.finish_bind();
        state.execute(&name("A"));
        state.suspend_result();
        state.sync();
        state.ready_for_query(b'I');
        assert_eq!(
            state.result_owner(),
            None,
            "ReadyForQuery Idle after PortalSuspended must discard the \
             destroyed portal — Postgres ended the implicit transaction"
        );
        assert!(
            state.streaming_plan().is_none(),
            "streaming_plan must not still name the destroyed portal's plan"
        );

        state.begin_simple_query(Some("SELECT 1/0".into()));
        state.discard_failed_epoch();
        assert_eq!(
            state.result_owner(),
            None,
            "a 22012 on a later simple Query must not restore the paused owner"
        );

        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.bind(name("B"), name("s2"), None);
        state.execute(&name("B"));
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"B"[..]),
            "the next portal must own its own result set, not queue behind A"
        );
        assert_eq!(
            streaming_oid(&state),
            Some(2),
            "those DataRows must not inherit the zombie all-passthrough plan"
        );
    }

    /// H5b: Describe of the dead portal (34000) after suspend+Idle.
    ///
    /// Same owner leak as H10a; the ErrorResponse is on Describe, not
    /// resume Execute, so the resume-only stamp never saw it.
    #[test]
    fn describe_of_a_dead_portal_after_suspend_idle_does_not_leave_a_zombie_owner() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.finish_parse();
        state.bind(name("A"), name("s1"), None);
        state.finish_bind();
        state.execute(&name("A"));
        state.suspend_result();
        state.sync();
        state.ready_for_query(b'I');
        assert_eq!(state.result_owner(), None);

        state.describe(DescribeTarget::Portal(name("A")));
        state.discard_failed_epoch();
        assert_eq!(
            state.result_owner(),
            None,
            "34000 on Describe of the dead portal must not restore the paused owner"
        );

        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.bind(name("B"), name("s2"), None);
        state.execute(&name("B"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"B"[..]));
        assert_eq!(streaming_oid(&state), Some(2));
    }

    /// `discard_failed_epoch` must not clear `suspended` while leaving
    /// an older-epoch Execute in the queue — the RFQ Idle path is not
    /// the only way a later error arrives (pipelined Query before the
    /// backend's ReadyForQuery is processed).
    #[test]
    fn a_later_epoch_error_while_suspended_drops_the_older_owner() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.finish_parse();
        state.bind(name("A"), name("s1"), None);
        state.finish_bind();
        state.execute(&name("A"));
        state.suspend_result();
        state.sync();
        // No ready_for_query: the ErrorResponse is the first notice.
        state.begin_simple_query(Some("SELECT 1/0".into()));
        assert_eq!(state.result_owner().as_deref(), Some(&b"A"[..]));
        state.discard_failed_epoch();
        assert_eq!(
            state.result_owner(),
            None,
            "a later-epoch error while suspended must drop the paused owner, \
             not only the failing Query's epoch"
        );
        assert!(
            !state.suspended,
            "suspended must not stay set after the paused owner is gone"
        );

        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.bind(name("B"), name("s2"), None);
        state.execute(&name("B"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"B"[..]));
        assert_eq!(streaming_oid(&state), Some(2));
    }

    /// `BEGIN; suspend; Sync` keeps the portal. ReadyForQuery InTxn
    /// must not discard the owner; a different portal still uses its
    /// own plan, and resume of A still sees A's.
    #[test]
    fn ready_for_query_in_txn_keeps_the_suspended_owner() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();

        state.bind(name("A"), name("s1"), None);
        state.execute(&name("A"));
        state.suspend_result();
        state.sync();
        state.ready_for_query(b'T');
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"A"[..]),
            "ReadyForQuery InTxn must keep the suspended portal — BEGIN did"
        );
        assert_eq!(streaming_oid(&state), Some(1));

        state.bind(name("B"), name("s2"), None);
        state.execute(&name("B"));
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"B"[..]),
            "a different portal after suspend still owns its own result set"
        );
        assert_eq!(
            streaming_oid(&state),
            Some(2),
            "B's DataRows must use B's plan, not A's"
        );

        state.finish_result_set();
        state.execute(&name("A"));
        assert_eq!(state.result_owner().as_deref(), Some(&b"A"[..]));
        assert_eq!(
            streaming_oid(&state),
            Some(1),
            "resume of A inside the transaction must still see A's plan"
        );
    }

    /// Rebinding the same portal before CommandComplete must not judge
    /// in-flight DataRows with the new plan.
    ///
    /// Measured live: `Bind p s_class; Execute p 0; Bind p s_pass; Execute p 0;
    /// Sync`. The second Bind overwrote `portal_plans[p]`; the second Execute
    /// was treated as a resume; `streaming_plan` applied the all-passthrough
    /// plan to the classified first row. `Vetted::unmasked_row` released
    /// email. Unnamed portal `""` leaked the same way. Pass-then-class
    /// over-masked (fail-closed). Two different portal names were already
    /// safe.
    #[test]
    fn rebinding_the_same_portal_does_not_release_inflight_classified_rows() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.parse(name("s2"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();

        state.bind(name("p"), name("s1"), None);
        state.execute(&name("p"));
        assert_eq!(streaming_oid(&state), Some(2));

        state.bind(name("p"), name("s2"), None);
        assert_eq!(
            streaming_oid(&state),
            Some(2),
            "Bind of the same portal must not replace the in-flight Execute's plan"
        );
        assert!(
            state
                .streaming_plan()
                .is_some_and(|plan| plan.iter().all(|field| !field.spec.is_passthrough())),
            "classified in-flight rows must not see the rebound all-passthrough plan"
        );

        state.execute(&name("p"));
        assert_eq!(
            state.result_owner().as_deref(),
            Some(&b"p"[..]),
            "the first Execute still owns the stream"
        );
        assert_eq!(streaming_oid(&state), Some(2));

        state.finish_result_set();
        assert_eq!(
            streaming_oid(&state),
            Some(1),
            "the second Execute owns the next result set with its own plan"
        );
    }

    /// Unnamed portal `""` is the JDBC/psycopg reuse pattern.
    #[test]
    fn rebinding_the_unnamed_portal_does_not_release_inflight_classified_rows() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.parse(name("s2"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();

        state.bind(name(""), name("s1"), None);
        state.execute(&name(""));
        state.bind(name(""), name("s2"), None);
        state.execute(&name(""));
        assert_eq!(streaming_oid(&state), Some(2));
        state.finish_result_set();
        assert_eq!(streaming_oid(&state), Some(1));
    }

    /// Binary Bind of the passthrough rebind is the same leak.
    #[test]
    fn rebinding_the_same_portal_with_binary_formats_does_not_release() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.parse(name("s2"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();

        state.bind(name("p"), name("s1"), Some(vec![1]));
        state.execute(&name("p"));
        state.bind(name("p"), name("s2"), Some(vec![1]));
        state.execute(&name("p"));
        assert_eq!(streaming_oid(&state), Some(2));
        let streaming = state.streaming_plan().expect("classified snapshot");
        assert!(streaming.iter().all(|field| !field.spec.is_passthrough()));
        assert_eq!(streaming.first().map(|field| field.format), Some(1));
    }

    /// Two different portal names in one Sync keep their own plans. Control
    /// for the same-name rebind leak.
    #[test]
    fn different_portal_names_in_one_sync_keep_their_own_plans() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state.parse(name("s2"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();

        state.bind(name("p1"), name("s1"), None);
        state.execute(&name("p1"));
        state.bind(name("p2"), name("s2"), None);
        state.execute(&name("p2"));
        assert_eq!(streaming_oid(&state), Some(2));
        state.finish_result_set();
        assert_eq!(streaming_oid(&state), Some(1));
    }

    /// Pass-then-class on the same name is fail-closed: classified rows
    /// must not inherit the passthrough plan. Over-mask of the first
    /// result is acceptable.
    #[test]
    fn rebinding_passthrough_then_classified_same_portal_is_fail_closed() {
        let mut state = PlanState::default();
        state.parse(name("s1"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("s1")));
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.parse(name("s2"), "SELECT email, name FROM t".into());
        state.describe(DescribeTarget::Statement(name("s2")));
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();

        state.bind(name("p"), name("s1"), None);
        state.execute(&name("p"));
        state.bind(name("p"), name("s2"), None);
        state.execute(&name("p"));

        let first = streaming_oid(&state);
        assert!(
            first == Some(1) || first == Some(2) || first.is_none(),
            "in-flight passthrough rows may stay passthrough, over-mask, or refuse"
        );

        state.finish_result_set();
        let second = streaming_oid(&state);
        assert_ne!(
            second,
            Some(1),
            "classified DataRows must not inherit the passthrough plan"
        );
        assert!(
            second == Some(2) || second.is_none(),
            "the rebound classified Execute owns its rows, or they are refused"
        );
    }

    /// Close of a portal must not reset bind generation so a later Bind
    /// of the same name aliases the in-flight Execute.
    ///
    /// Measured live: `Bind p sc; Execute p 0; Close P p; Bind p sp; Sync`
    /// in one flush. Execute ran before Describe was answered, so
    /// `pending.plan` was `None`. Close dropped generation 1; the rebind
    /// started at 1 again. `streaming_plan` treated the rebound
    /// all-passthrough plan as current; `Vetted::unmasked_row` released
    /// email. No second Execute required. Without Close the second Bind
    /// bumps to 2 and the proxy refuses (0.1.97).
    fn assert_inflight_not_rebound_passthrough(state: &PlanState, what: &str) {
        assert_ne!(
            streaming_oid(state),
            Some(1),
            "{what}: must not judge in-flight rows with the rebound passthrough plan"
        );
        if let Some(plan) = state.streaming_plan() {
            assert!(
                plan.iter().all(|field| !field.spec.is_passthrough()),
                "{what}: classified in-flight rows must not see an all-passthrough plan"
            );
        }
    }

    fn pipeline_class_then_pass_undescribed(state: &mut PlanState) {
        state.parse(name("sc"), "SELECT email, name FROM t".into());
        state.parse(name("sp"), "SELECT city, id FROM t".into());
        state.describe(DescribeTarget::Statement(name("sc")));
        state.describe(DescribeTarget::Statement(name("sp")));
    }

    fn answer_pipelined_class_then_pass(state: &mut PlanState) {
        state
            .finish_description(marked_plan(2, Mask::Redact))
            .unwrap();
        state
            .finish_description(marked_plan(1, Mask::None))
            .unwrap();
        state.finish_bind();
    }

    #[test]
    fn close_then_rebind_same_portal_does_not_release_inflight_classified_rows() {
        let mut state = PlanState::default();
        pipeline_class_then_pass_undescribed(&mut state);
        state.bind(name("p"), name("sc"), None);
        state.execute(&name("p"));
        state.close(DescribeTarget::Portal(name("p")));
        state.bind(name("p"), name("sp"), None);
        answer_pipelined_class_then_pass(&mut state);
        assert_inflight_not_rebound_passthrough(
            &state,
            "Close P then Bind of the same portal in one Sync",
        );
    }

    #[test]
    fn close_statement_then_rebind_portal_does_not_release_inflight_classified_rows() {
        let mut state = PlanState::default();
        pipeline_class_then_pass_undescribed(&mut state);
        state.bind(name("p"), name("sc"), None);
        state.execute(&name("p"));
        state.close(DescribeTarget::Statement(name("sc")));
        state.bind(name("p"), name("sp"), None);
        answer_pipelined_class_then_pass(&mut state);
        assert_inflight_not_rebound_passthrough(
            &state,
            "Close S of the classified statement then Bind of the same portal",
        );
    }

    #[test]
    fn close_then_rebind_unnamed_portal_does_not_release_inflight_classified_rows() {
        let mut state = PlanState::default();
        pipeline_class_then_pass_undescribed(&mut state);
        state.bind(name(""), name("sc"), None);
        state.execute(&name(""));
        state.close(DescribeTarget::Portal(name("")));
        state.bind(name(""), name("sp"), None);
        answer_pipelined_class_then_pass(&mut state);
        assert_inflight_not_rebound_passthrough(&state, "Close P then Bind of the unnamed portal");
    }

    #[test]
    fn close_then_rebind_binary_classified_execute_does_not_release() {
        let mut state = PlanState::default();
        pipeline_class_then_pass_undescribed(&mut state);
        state.bind(name("p"), name("sc"), Some(vec![1]));
        state.execute(&name("p"));
        state.close(DescribeTarget::Portal(name("p")));
        state.bind(name("p"), name("sp"), Some(vec![1]));
        answer_pipelined_class_then_pass(&mut state);
        assert_inflight_not_rebound_passthrough(
            &state,
            "Close then binary Bind of the same portal",
        );
    }

    /// Control: the same one-Sync pipeline without Close is still
    /// fail-closed (0.1.97). Describe unanswered, so no snapshot.
    #[test]
    fn rebinding_same_portal_in_one_sync_without_close_is_still_fail_closed() {
        let mut state = PlanState::default();
        pipeline_class_then_pass_undescribed(&mut state);
        state.bind(name("p"), name("sc"), None);
        state.execute(&name("p"));
        state.bind(name("p"), name("sp"), None);
        answer_pipelined_class_then_pass(&mut state);
        assert_inflight_not_rebound_passthrough(
            &state,
            "class-then-pass same portal without Close",
        );
    }
}
