//! The per-connection state machine.
//!
//! One client connection, one backend connection, no multiplexing. Both
//! directions are driven from a single `select!` loop so all state lives in one
//! place with no locking — for a security boundary, "where is the plan right
//! now" should have exactly one answer.
//!
//! # The governing rule
//!
//! **The masking plan is bound to the `RowDescription`, never to the statement.**
//!
//! Every row-producing path in the protocol emits a `RowDescription` first —
//! extended-protocol portals, multi-statement simple queries, resumed
//! statements. So they are all covered without special handling. SQL
//! `DECLARE`/`FETCH`/`CLOSE` are refused as a statement class (use Parse/Bind
//! instead). The only two paths that emit rows *without* a `RowDescription`,
//! `COPY ... TO STDOUT` and the legacy `FunctionCall`, are refused outright.
//!
//! Corollary, enforced below: a `DataRow` with no active plan is a bug or an
//! attack. It is never forwarded.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::analysis::{self, Safety};
use crate::catalog::{Lineage, Posture, Summaries, SystemCatalogs};
use crate::lineage::{self, Verdict};
use crate::mask::{Mask, MaskSpec};
use crate::metrics::Cause;
use crate::plan_state::{FieldPlan, PlanState};
use crate::policy::{resolve_expression_policies, FieldAnalysis, Policy, Rejection};
use crate::protocol::{self, FrameReader, Message};
use crate::tls::{BackendTls, BoxStream};

/// Bytes cleared for the client.
///
/// The core invariant of this proxy is "no row reaches the client without
/// passing through a masking plan". That was previously enforced by discipline
/// inside `handle_data_row`. It is now enforced by the compiler: `Batch::client`
/// accepts only a `Vetted`, and the constructors below are the complete list of
/// ways to make one. Adding a new "just forward it" path is a type error, not a
/// code-review question.
///
/// The module boundary is load-bearing — the field is private, so nothing
/// outside this file can mint one.
pub struct Vetted(Bytes);

impl Vetted {
    /// A message whose bytes originated with the backend and carry no row data.
    ///
    /// Correct for control and metadata messages. Never correct for `DataRow`,
    /// and `vet_data_row` is the only way to clear one of those.
    fn control(msg: &Message) -> Self {
        debug_assert_ne!(
            msg.tag,
            protocol::B_DATA_ROW,
            "DataRow must go through vet_data_row"
        );
        Self(msg.encode())
    }

    /// A row whose every field was run through the active plan.
    ///
    /// Takes the finished frame rather than the field values: the masking loop
    /// in `handle_data_row` encodes each field as it clears, so by the time a
    /// row can be vetted it is already wire-shaped. That loop is the only
    /// caller, which is what keeps this constructor's claim true.
    fn masked_row(frame: BytesMut) -> Self {
        Self(frame.freeze())
    }

    /// A row we are forwarding unchanged because the plan masks nothing in it.
    ///
    /// Takes the plan to make the claim checkable rather than assumed.
    ///
    /// The plan must be `streaming_plan` for *this* result set. After
    /// `PortalSuspended`, a different portal's DataRows used to arrive here
    /// under the suspended portal's all-passthrough plan (0.1.97) — same
    /// arity, so the field-count check passed and classified values went out
    /// in the clear. A sibling: resume after Sync, without BEGIN, 34000s
    /// (portal gone) but left that same passthrough plan as a zombie owner;
    /// the next portal's rows took this path too. A later-epoch error that
    /// is not A's own Execute — H10a `SELECT 1/0`, H5b 34000 on Describe —
    /// left the same zombie; the resume-only stamp missed those. Another
    /// sibling without PortalSuspended: two full Executes that reuse one
    /// portal name. Bind of the second statement overwrote `portal_plans`
    /// before the first DataRows; `execute` treated the second Execute as a
    /// resume, so this path forwarded the classified row under the new
    /// all-passthrough plan. Unnamed portal `""` and binary Bind leaked the
    /// same way.
    fn unmasked_row(msg: &Message, plan: &[FieldPlan]) -> Self {
        debug_assert!(
            plan.iter().all(|f| f.spec.is_passthrough()),
            "unmasked_row called with a plan that masks something"
        );
        Self(msg.encode())
    }

    /// A message pgmask generated itself: errors, notices we rebuilt.
    fn synthetic(msg: &Message) -> Self {
        Self(msg.encode())
    }
}

/// Outbound bytes accumulated across a whole read batch.
///
/// Contiguous buffers, not `Vec<Bytes>`: a vector of frames still costs one
/// `write` syscall per frame, which on a bulk result set is a syscall per row.
/// Copying each frame into one buffer and issuing a single write is far cheaper
/// than the syscalls it replaces — that change alone took per-row overhead from
/// ~2.1us to well under a microsecond.
#[derive(Default)]
struct Batch {
    to_client: BytesMut,
    to_backend: BytesMut,
    close: bool,
}

impl Batch {
    /// The only way bytes reach the client.
    fn client(&mut self, vetted: Vetted) {
        self.to_client.put_slice(&vetted.0);
    }
    /// The backend direction needs no vetting: it carries queries, not results.
    fn backend(&mut self, bytes: Bytes) {
        self.to_backend.put_slice(&bytes);
    }
    fn is_empty(&self) -> bool {
        self.to_client.is_empty() && self.to_backend.is_empty()
    }
}

pub struct Session {
    policy: Arc<Policy>,
    /// Extended-query statement, portal, Describe, and active-plan lifecycle.
    plans: PlanState,
    /// Exchange whose backend traffic is discarded after a local refusal,
    /// until its `ReadyForQuery`.
    suppressing: Option<u64>,
    pub masked_fields: u64,
    pub rejected_result_sets: u64,
    /// Whether this client connection is itself TLS. Decides whether channel
    /// binding is even in play.
    client_tls: bool,
    /// Roles held by the verified principal. Empty until `AuthenticationOk`, so
    /// an unauthenticated session can only ever get the default (most
    /// restrictive) classification.
    roles: HashSet<String>,
    /// The username from `StartupMessage`. Claimed until Postgres vouches.
    principal: String,
    pub authenticated: bool,
    /// Last `ReadyForQuery` transaction status byte (`I`/`T`/`E`). Needed when
    /// a simple-query rate-limit refusal synthesises its own ReadyForQuery —
    /// inventing `I` inside an open transaction would desync the client.
    txn_status: u8,
    /// Notices forwarded since the last `ReadyForQuery`. Reset there so a
    /// multi-statement simple query shares one budget, matching how a dense
    /// `DO` encodes a value inside one exchange.
    notices_this_exchange: u32,
}

impl Session {
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            plans: PlanState::default(),
            suppressing: None,
            masked_fields: 0,
            rejected_result_sets: 0,
            client_tls: false,
            roles: HashSet::new(),
            principal: String::new(),
            authenticated: false,
            txn_status: b'I',
            notices_this_exchange: 0,
        }
    }

    /// The username the client claimed at startup. Not trusted until
    /// `AuthenticationOk`; see `note_backend_auth`.
    pub fn with_principal(mut self, principal: &str) -> Self {
        self.principal = principal.to_string();
        self
    }

    /// Postgres has vouched for the username — only now may it select a policy.
    ///
    /// This lives in `handle_backend` rather than in the pump loop because the
    /// pump drains several messages per read, and `AuthenticationOk` usually
    /// arrives in the same TCP segment as the SASL final message. Detecting it
    /// only on the first message of a read silently skipped it, so every session
    /// ran with no roles. Same shape as the CopyData bug: logic in the outer
    /// read that the drain loop never saw.
    fn note_backend_auth(&mut self, msg: &Message) {
        if self.authenticated || msg.tag != protocol::B_AUTHENTICATION {
            return;
        }
        // AuthenticationOk is sub-code 0. A body too short to carry the sub-code
        // is not one, so the session stays unauthenticated and keeps the empty
        // role set — the most restrictive classification.
        let Some(&[c0, c1, c2, c3]) = msg.body.get(..4) else {
            return;
        };
        if i32::from_be_bytes([c0, c1, c2, c3]) != 0 {
            return;
        }
        self.authenticated = true;
        self.roles = self.policy.roles_of(&self.principal);
    }

    pub fn with_client_tls(mut self, client_tls: bool) -> Self {
        self.client_tls = client_tls;
        self
    }

    /// Refuse the in-flight result set: tell the client, swallow the backend's
    /// rows, and let the real `ReadyForQuery` through so transaction state stays
    /// consistent.
    fn reject(&mut self, rejection: Rejection, out: &mut Batch) {
        self.suppressing = Some(self.plans.rejection_epoch());
        self.plans.clear_active();
        // Counters saturate rather than wrap: a wrapped rejection count would
        // under-report a refusal, and a u64 cannot reach the ceiling in a
        // connection's lifetime anyway.
        self.rejected_result_sets = self.rejected_result_sets.saturating_add(1);
        self.policy.metrics.record(rejection.cause);
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            &rejection.message,
            rejection.hint.as_deref(),
        );
        out.client(Vetted::synthetic(&err));
    }

    /// Spend one statement token, or refuse. Unauthenticated traffic is not
    /// charged: burning the victim's budget before `AuthenticationOk` would
    /// turn a failed login into a DoS against a real session.
    fn allow_statement(&self) -> bool {
        match &self.policy.rate_limit() {
            None => true,
            Some(_) if !self.authenticated || self.principal.is_empty() => true,
            Some(lim) => lim.try_acquire(&self.principal),
        }
    }

    /// Local refusal that never reached the backend. Simple queries need a
    /// synthetic `ReadyForQuery` so the client is not left waiting; extended
    /// `Execute` waits for the client's `Sync`, which still goes through.
    fn refuse_rate_limited(&mut self, out: &mut Batch, with_ready: bool) {
        self.policy.metrics.record(Cause::RateLimited);
        let err = protocol::build_error(
            protocol::SQLSTATE_PROGRAM_LIMIT_EXCEEDED,
            "pgmask: statement rate limit exceeded for this user",
            Some("Wait and retry, or raise rate_limit_per_minute / rate_limit_burst."),
        );
        out.client(Vetted::synthetic(&err));
        if with_ready {
            let ready = Message::new(
                protocol::B_READY_FOR_QUERY,
                Bytes::copy_from_slice(&[self.txn_status]),
            );
            out.client(Vetted::synthetic(&ready));
        }
    }

    /// SQL `PREPARE`/`DECLARE` and the statements that only exist to use them.
    fn refuse_sql_prepare_or_cursor(&mut self, out: &mut Batch, with_ready: bool) {
        self.policy.metrics.record(Cause::SqlPrepareCursor);
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            "pgmask: SQL PREPARE, EXECUTE, DEALLOCATE, DECLARE, FETCH, and CLOSE are not permitted",
            Some(
                "Use ordinary SELECT, or the extended protocol Parse/Bind/Execute. \
                 SELECT ... FETCH FIRST n ROWS is a limit clause and is allowed.",
            ),
        );
        out.client(Vetted::synthetic(&err));
        if with_ready {
            self.synthetic_ready(out);
        }
    }

    /// DML / DDL / `DO` / `CALL` — pgmask never writes.
    fn refuse_write(&mut self, out: &mut Batch, with_ready: bool) {
        self.policy.metrics.record(Cause::WriteRefused);
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            "pgmask: read-only — writes, DDL, DO, and CALL are not permitted",
            Some(
                "pgmask is a masking proxy for SELECT. Mutating SQL and anonymous \
                 blocks are refused on every posture.",
            ),
        );
        out.client(Vetted::synthetic(&err));
        if with_ready {
            self.synthetic_ready(out);
        }
    }

    fn refuse_untrusted_function(&mut self, out: &mut Batch, with_ready: bool) {
        self.policy.metrics.record(Cause::UntrustedFunction);
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            "pgmask: only trusted pg_catalog functions may be called",
            Some(
                "User-defined and schema-qualified functions can run before their \
                 result is masked (timing and side effects). Call only built-ins, \
                 or set system_catalogs = \"allow\" for metadata-only catalog SQL.",
            ),
        );
        out.client(Vetted::synthetic(&err));
        if with_ready {
            self.synthetic_ready(out);
        }
    }

    fn synthetic_ready(&self, out: &mut Batch) {
        let ready = Message::new(
            protocol::B_READY_FOR_QUERY,
            Bytes::copy_from_slice(&[self.txn_status]),
        );
        out.client(Vetted::synthetic(&ready));
    }

    /// Frontend gates that must run before the statement reaches Postgres.
    fn refuse_frontend_sql(&mut self, sql: &str, out: &mut Batch, with_ready: bool) -> bool {
        let inspection = analysis::StatementInspection::new(sql);
        if inspection.is_write_statement() {
            self.refuse_write(out, with_ready);
            return true;
        }
        if inspection.is_sql_prepare_or_cursor() {
            self.refuse_sql_prepare_or_cursor(out, with_ready);
            return true;
        }
        if inspection.calls_untrusted_function() {
            self.refuse_untrusted_function(out, with_ready);
            return true;
        }
        if inspection.touches_leaky_system_catalog() {
            self.refuse_leaky_catalog(out, with_ready);
            return true;
        }
        // Hostile masked-column use must not reach Postgres: execute-then-refuse
        // on RowDescription still ran the statement (timing / error-presence
        // oracles on WHERE and CASE). Refuse here with the same rule the
        // RowDescription path uses.
        if self.policy.posture() == Posture::Hostile {
            let snapshot = self.policy.catalog.snapshot();
            let masked = snapshot.masked_bare_names_for_roles(&self.roles);
            let relations = snapshot.relation_columns_map();
            if inspection.masked_exceeds_outer_projection(&masked)
                || inspection.hostile_uses_whole_row(relations)
                || inspection.hostile_join_or_rename_masked(relations, &masked)
            {
                self.refuse_hostile_masked_use(out, with_ready);
                return true;
            }
        }
        false
    }

    fn refuse_leaky_catalog(&mut self, out: &mut Batch, with_ready: bool) {
        self.policy.metrics.record(Cause::LeakyCatalog);
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            "pgmask: refusing catalog that can carry user data",
            Some(
                "pg_stats, pg_statistic, pg_stat_activity, pg_authid and similar \
                 hold sampled values, other sessions' SQL, or secrets. They are \
                 refused on every posture.",
            ),
        );
        out.client(Vetted::synthetic(&err));
        if with_ready {
            self.synthetic_ready(out);
        }
    }

    fn refuse_hostile_masked_use(&mut self, out: &mut Batch, with_ready: bool) {
        self.policy.metrics.record(Cause::HostileMaskedUse);
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            "pgmask: posture = \"hostile\" refuses use of a masked \
             column outside a bare SELECT list",
            Some(
                "Masked columns may be projected (and will be masked) and may \
                 appear in ORDER BY, but not in WHERE, HAVING, expressions, \
                 aggregates, or whole-row casts (t::text). Set posture = \
                 \"default\" for the looser analyst threat model.",
            ),
        );
        out.client(Vetted::synthetic(&err));
        if with_ready {
            self.synthetic_ready(out);
        }
    }

    fn note_txn_status(&mut self, msg: &Message) {
        if msg.tag != protocol::B_READY_FOR_QUERY {
            return;
        }
        if let Some(&status) = msg.body.first() {
            self.txn_status = status;
        }
        self.notices_this_exchange = 0;
    }

    /// Forward a notice, or drop it once this exchange is over budget.
    fn handle_notice(&mut self, msg: Message, out: &mut Batch) {
        // Saturating: a u32 cannot overflow from notices in any real session,
        // and wrapping would re-admit traffic after a flood.
        self.notices_this_exchange = self.notices_this_exchange.saturating_add(1);
        if let Some(max) = self.policy.max_notices_per_exchange() {
            if self.notices_this_exchange > max {
                // One metric event per crossing, not per dropped notice — a
                // 1600-notice DO would otherwise drown the counters.
                if self.notices_this_exchange == max.saturating_add(1) {
                    self.policy.metrics.record(Cause::NoticeFlood);
                }
                return;
            }
        }
        match protocol::scrub_notice(&msg.body) {
            Some(scrubbed) => out.client(Vetted::synthetic(&Message::new(msg.tag, scrubbed))),
            None => out.client(Vetted::control(&msg)),
        }
    }

    /// Drop cached plans and refresh roles when catalog or file generation moved.
    fn sync_policy(&mut self) {
        if self.plans.invalidate_if_stale(self.policy.generation()) && self.authenticated {
            self.roles = self.policy.roles_of(&self.principal);
        }
    }

    fn handle_frontend(&mut self, msg: Message, out: &mut Batch) {
        // A cached plan is a decision made against one catalog snapshot; a
        // refresh can tighten a classification underneath it.
        self.sync_policy();
        match msg.tag {
            // Emits rows with no RowDescription. One of exactly two such paths.
            protocol::F_FUNCTION_CALL => {
                self.policy.metrics.record(Cause::FunctionCallMessage);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: the legacy FunctionCall protocol message is not permitted",
                    Some("It returns data without a RowDescription, so it cannot be masked."),
                );
                {
                    out.client(Vetted::synthetic(&err));
                    out.close = true;
                }
            }

            // A new simple query invalidates everything: if the backend does not
            // describe the next result set, we must not mask it with a stale plan.
            protocol::F_QUERY => {
                let sql = protocol::parse_simple_query(&msg.body);
                if let Some(sql) = sql.as_deref() {
                    if self.refuse_frontend_sql(sql, out, true) {
                        return;
                    }
                }
                if !self.allow_statement() {
                    return self.refuse_rate_limited(out, true);
                }
                self.plans.begin_simple_query(sql);
                out.backend(msg.encode())
            }

            protocol::F_PARSE => {
                if let Some((name, sql)) = protocol::parse_parse(&msg.body) {
                    if self.refuse_frontend_sql(&sql, out, false) {
                        return;
                    }
                    self.plans.parse(name, sql);
                }
                out.backend(msg.encode())
            }

            protocol::F_BIND => {
                if let Some((portal, statement)) = protocol::parse_bind(&msg.body) {
                    let formats = protocol::parse_bind_result_formats(&msg.body);
                    self.plans.bind(portal, statement, formats);
                }
                out.backend(msg.encode())
            }

            protocol::F_CLOSE => {
                if let Some(target) = protocol::parse_close(&msg.body) {
                    self.plans.close(target);
                }
                out.backend(msg.encode())
            }

            protocol::F_DESCRIBE => {
                if let Some(target) = protocol::parse_describe(&msg.body) {
                    self.plans.describe(target);
                }
                out.backend(msg.encode())
            }

            protocol::F_EXECUTE => {
                if let Some(portal) = protocol::parse_execute(&msg.body) {
                    let portal_sql = self.plans.sql_for_portal(&portal).map(str::to_owned);
                    if let Some(sql) = portal_sql.as_deref() {
                        if self.refuse_frontend_sql(sql, out, false) {
                            return;
                        }
                    }
                    if !self.allow_statement() {
                        return self.refuse_rate_limited(out, false);
                    }
                    self.plans.execute(&portal);
                } else if !self.allow_statement() {
                    return self.refuse_rate_limited(out, false);
                }
                out.backend(msg.encode())
            }

            protocol::F_SYNC => {
                self.plans.sync();
                out.backend(msg.encode())
            }

            protocol::F_TERMINATE => {
                out.backend(msg.encode());
                out.close = true;
            }

            _ => out.backend(msg.encode()),
        }
    }

    fn handle_backend(&mut self, msg: Message, out: &mut Batch) {
        self.note_backend_auth(&msg);
        self.note_txn_status(&msg);

        // While suppressing, everything is dropped until the cycle ends.
        if let Some(suppressed_epoch) = self.suppressing {
            if msg.tag == protocol::B_READY_FOR_QUERY {
                self.suppressing = None;
                self.plans.finish_suppressed_epoch(suppressed_epoch);
                return out.client(Vetted::control(&msg));
            }
            return;
        }

        match msg.tag {
            // A plaintext client cannot be offered channel binding at all:
            // libpq aborts with "server offered SCRAM-SHA-256-PLUS
            // authentication over a non-SSL connection" rather than falling
            // back. Strip it, and the client sends the gs2 flag `n`, which the
            // server accepts. This is what makes pgmask usable in front of a
            // TLS-only managed Postgres such as Neon.
            protocol::B_AUTHENTICATION
                if !self.client_tls
                    && protocol::sasl_mechanisms(&msg.body)
                        .iter()
                        .any(|m| m.ends_with("-PLUS")) =>
            {
                match protocol::strip_channel_binding(&msg.body) {
                    Some(filtered) if protocol::sasl_mechanisms(&filtered).is_empty() => {
                        self.policy.metrics.record(Cause::ChannelBinding);
                        let err = protocol::build_error(
                            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                            "pgmask: the server offers only channel-binding SASL mechanisms",
                            Some("Enable plain SCRAM-SHA-256 on the server."),
                        );
                        out.client(Vetted::synthetic(&err));
                        out.close = true;
                    }
                    Some(filtered) => {
                        out.client(Vetted::synthetic(&Message::new(msg.tag, filtered)));
                    }
                    None => out.client(Vetted::control(&msg)),
                }
            }

            // With TLS on both legs there is no fix: stripping makes the client
            // send `y`, which the server correctly reads as a downgrade attack.
            // Say so plainly rather than letting the client hit an opaque
            // protocol error that gives no hint about the proxy in the middle.
            protocol::B_AUTHENTICATION
                if self.client_tls
                    && protocol::sasl_mechanisms(&msg.body)
                        .iter()
                        .any(|m| m.ends_with("-PLUS")) =>
            {
                self.policy.metrics.record(Cause::ChannelBinding);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: the server offers SCRAM channel binding, which cannot work \
                     through a proxy that terminates TLS",
                    Some(
                        "Set backend_tls = \"disable\" so Postgres advertises plain \
                         SCRAM-SHA-256, and place pgmask on a trusted segment next to the \
                         database. See protocol::sasl_mechanisms for why stripping the \
                         mechanism does not work.",
                    ),
                );
                out.client(Vetted::synthetic(&err));
                out.close = true;
            }

            protocol::B_ROW_DESCRIPTION => self.handle_row_description(msg, out),
            protocol::B_DATA_ROW => self.handle_data_row(msg, out),
            protocol::B_PARSE_COMPLETE => {
                self.plans.finish_parse();
                out.client(Vetted::control(&msg));
            }
            protocol::B_BIND_COMPLETE => {
                self.plans.finish_bind();
                out.client(Vetted::control(&msg));
            }

            // The other path that emits rows with no RowDescription. Unrecoverable
            // mid-stream, so the connection goes down rather than the data out.
            protocol::B_COPY_OUT_RESPONSE | protocol::B_COPY_BOTH_RESPONSE => {
                self.rejected_result_sets = self.rejected_result_sets.saturating_add(1);
                self.policy.metrics.record(Cause::CopyStream);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: COPY ... TO is not permitted",
                    Some(
                        "COPY streams rows with no RowDescription, so they cannot be masked. \
                          Use a SELECT.",
                    ),
                );
                {
                    out.client(Vetted::synthetic(&err));
                    out.close = true;
                }
            }

            // Every free-text diagnostic field can be SQL-controlled (`RAISE`
            // accepts expressions for Message, Detail, Hint and object names),
            // so rebuild the message from constrained fields plus fixed text.
            // An errored `Describe` never produces a `RowDescription` or
            // `NoData`, so its slot used to sit in the FIFO forever and the
            // next result set's plan was filed under that stale name: describe
            // a statement that does not exist, then describe a harmless one,
            // and its passthrough plan lands on a name of your choosing.
            //
            // The backend skips to the next `Sync` after an error, so exactly
            // the Describes sharing the failing exchange's epoch are dead.
            // Clearing the whole queue instead looked right and was not —
            // under pipelining a `ReadyForQuery` for an earlier exchange
            // arrives after a later `Describe` is already queued, and dropping
            // that live slot left a real result set with no plan.
            // A `ParameterStatus` for a GUC whose value a client can fill from
            // a row. `set_config('application_name', (SELECT email …), false)`
            // put a masked address in one, outside any RowDescription.
            protocol::B_PARAMETER_STATUS => {
                if protocol::parameter_status_is_safe(&msg.body) {
                    out.client(Vetted::control(&msg));
                }
            }

            // Channel and payload are both arbitrary SQL expressions with no
            // provenance to classify, so there is no sound mask to apply.
            // `pg_notify('c', (SELECT email …))` delivered the address verbatim.
            protocol::B_NOTIFICATION_RESPONSE => {}

            protocol::B_ERROR_RESPONSE => {
                self.plans.discard_failed_epoch();
                match protocol::scrub_error(&msg.body) {
                    Some(scrubbed) => {
                        out.client(Vetted::synthetic(&Message::new(msg.tag, scrubbed)))
                    }
                    None => out.client(Vetted::control(&msg)),
                }
            }

            protocol::B_NOTICE_RESPONSE => self.handle_notice(msg, out),

            // No result set for this Describe; consume its slot. NoData can
            // only answer a Describe — a simple query's result is a
            // RowDescription or EmptyQueryResponse — so if the queue head is
            // not a Describe the backend has described something the proxy
            // never saw requested, and that is refused rather than guessed at.
            b'n' => {
                if let Err(()) = self.plans.finish_no_data() {
                    return self.reject(
                        Rejection {
                            cause: Cause::Malformed,
                            message: "pgmask: NoData answered no pending Describe".into(),
                            hint: None,
                        },
                        out,
                    );
                }
                out.client(Vetted::control(&msg))
            }

            // Copy-stream payload. Reachable only if a CopyOutResponse slipped
            // past, but this is the byte-carrying message, so it is denied on
            // its own account rather than trusting the earlier check.
            protocol::B_COPY_DATA | protocol::B_COPY_DONE => {
                self.rejected_result_sets = self.rejected_result_sets.saturating_add(1);
                self.policy.metrics.record(Cause::CopyStream);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: COPY data stream is not permitted",
                    None,
                );
                out.client(Vetted::synthetic(&err));
                out.close = true;
            }

            // One result set ended. Its Execute — if any — is done; the next
            // rows belong to the next queued Execute.
            protocol::B_COMMAND_COMPLETE => {
                self.plans.finish_result_set();
                out.client(Vetted::control(&msg))
            }

            // A limited Execute paused; it has not completed. The next
            // DataRows may belong to a *different* portal — Postgres runs
            // that Execute (the comment that it refuses was wrong, and the
            // stale plan took `unmasked_row`). See `PlanState::suspend_result`.
            protocol::B_PORTAL_SUSPENDED => {
                self.plans.suspend_result();
                out.client(Vetted::control(&msg))
            }

            // After PortalSuspended, ReadyForQuery Idle means the implicit
            // transaction ended and named portals are gone. Discard the
            // paused owner here — a later-epoch ErrorResponse that is not
            // A's own Execute (H10a, H5b) used to leave it queued.
            // InTxn (`T`) keeps the portal (`BEGIN; suspend; Sync`).
            protocol::B_READY_FOR_QUERY => {
                if let Some(&status) = msg.body.first() {
                    self.plans.ready_for_query(status);
                }
                out.client(Vetted::control(&msg))
            }

            // An empty simple query (or one with only comments) answers with
            // EmptyQueryResponse instead of a RowDescription. It consumes its
            // own description entry and ends its result set in one step;
            // refusing first means a desync is rejected before any state has
            // been spent. A Describe never answers this way.
            protocol::B_EMPTY_QUERY_RESPONSE => {
                if let Err(()) = self.plans.finish_empty_query() {
                    return self.reject(
                        Rejection {
                            cause: Cause::Malformed,
                            message: "pgmask: EmptyQueryResponse answered no forwarded Query"
                                .into(),
                            hint: None,
                        },
                        out,
                    );
                }
                out.client(Vetted::control(&msg))
            }

            // Explicit allowlist. The backend direction gets no catch-all: an
            // unrecognised message might carry row data, and forwarding it
            // because we do not know what it is inverts the whole design.
            //
            // Found by the canary test — CopyData was being forwarded through a
            // `_ =>` arm that existed only because it seemed harmless.
            tag if protocol::BACKEND_CONTROL_TAGS.contains(&tag) => {
                out.client(Vetted::control(&msg))
            }

            unknown => {
                self.rejected_result_sets = self.rejected_result_sets.saturating_add(1);
                self.policy.metrics.record(Cause::UnknownBackendMessage);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    &format!(
                        "pgmask: refusing to forward unrecognised backend message '{}'",
                        unknown as char
                    ),
                    Some("pgmask fails closed on protocol messages it cannot classify."),
                );
                out.client(Vetted::synthetic(&err));
                out.close = true;
            }
        }
    }

    fn handle_row_description(&mut self, msg: Message, out: &mut Batch) {
        // A reload can land after Query/Parse and before this description.
        self.sync_policy();
        let live = self.policy.live();
        let fields = match protocol::parse_row_description(&msg.body) {
            Ok(fields) => fields,
            Err(err) => {
                return self.reject(
                    Rejection {
                        cause: Cause::Malformed,
                        message: format!("pgmask: could not parse RowDescription: {err}"),
                        hint: None,
                    },
                    out,
                )
            }
        };

        // Every decision for one RowDescription must observe one catalog
        // generation. A refresh can swap the live snapshot at any time; loading
        // it separately for system-catalog checks, opaque-view checks, lineage,
        // and final mask lookup could otherwise combine mutually inconsistent
        // generations into one plan.
        let snapshot = self.policy.catalog.snapshot();

        // Only consulted for fields with no provenance, and only ever able to
        // turn a refusal into a passthrough for a positively-identified shape.
        // A statement that reads only metadata-only system catalogs carries
        // nothing from a user table, so every field is released — including the
        // ones that DO have provenance, which point at catalog relations no
        // catalog file lists and which default-deny would otherwise mask. The
        // OID becomes NULL, which breaks `\d`: psql feeds it into
        // the next and gets `invalid input syntax for type oid: ""`.
        // Two independent gates, and both must hold.
        //
        // The parse tree covers what OIDs cannot see: a user table in a
        // subquery that never becomes an output field, and functions like
        // `query_to_xml` that take their query as a string.
        //
        // The OIDs cover what the parse tree cannot: whether a name actually
        // resolved to a system catalog. Harlequin writes `from pg_database`
        // unqualified, `CREATE TABLE public.pg_database` is allowed, and
        // `search_path` is the client's to set — so the name is a hint and the
        // OID in the RowDescription is the fact.
        // The SQL for *this* result set: the Describe at the head of the
        // queue, or the simple query if there is no Describe outstanding.
        let described_sql = self.plans.described_sql();
        let inspection = described_sql
            .as_deref()
            .map(analysis::StatementInspection::new);

        let system_catalog = live.system_catalogs == SystemCatalogs::Allow
            && inspection
                .as_ref()
                .is_some_and(analysis::StatementInspection::reads_only_server_metadata)
            && {
                // The OID check below only inspects fields that have
                // provenance, so for a computed field the text check stands
                // alone — and it walks a tree with known gaps. This closes the
                // one that was demonstrable.
                let mentions_user_relation = inspection.as_ref().is_some_and(|inspection| {
                    snapshot.inspection_mentions_user_relation(inspection)
                });
                let mut provenanced = 0usize;
                let all_system = fields.iter().filter(|f| f.has_provenance()).all(|f| {
                    // Bounded by `fields.len()`, so the saturation is unreachable.
                    provenanced = provenanced.saturating_add(1);
                    snapshot.is_system_relation(f.table_oid)
                });
                // A result set of nothing but expressions gives the OID
                // check no purchase, so it is only trusted when the parse
                // tree named every relation with an explicit schema. `SHOW`
                // reads no relation at all and is handled there.
                !mentions_user_relation
                    && all_system
                    && (provenanced > 0
                        || inspection.as_ref().is_some_and(
                            analysis::StatementInspection::every_relation_is_qualified,
                        ))
            };

        // A grouping that yields one row per group turns a released summary
        // back into the value it summarised: `SELECT id, sum(salary) … GROUP BY
        // id` returned every salary in the demo fixture exactly, in one query.
        // Treating such a statement as if `summaries = "refuse"` is the whole
        // fix. `count(*)` and the relation-size functions are released above
        // that gate and stay released, because a row count per group discloses
        // nothing.
        //
        // A grouping the reader cannot reduce to names falls back to the
        // lexical backstop rather than to a flat refusal. Refusing outright was
        // the first attempt and it cost too much: `date_trunc` over a coarse
        // literal unit is deliberately released, so
        //
        //   SELECT date_trunc('month', ts), sum(amount) FROM orders GROUP BY 1
        //
        // — time-bucketed aggregation, the most ordinary analytics query there
        // is — was served before the guard existed and refused after it. The
        // grouping is an expression, and an expression is unreadable.
        //
        // The backstop asks the weaker question the lexer can answer soundly:
        // does the *statement* name every column of some unique key? A grouping
        // can only reference a column the statement mentions, so a key no part
        // of the text names is a key the grouping cannot cover. `GROUP BY
        // id::text` mentions `id` and is refused; the `date_trunc` query
        // mentions no key column and is served. It over-refuses when a key
        // column appears elsewhere — `WHERE id > 100` with an expression
        // grouping — which is narrow and explainable.
        //
        // Deliberately the lexer and not a walk of the expression. Collecting
        // columns beneath an arbitrary node means an exhaustive traversal, and
        // missing one node type here releases a value. Deparsing the clause and
        // lexing that was tried and rejected for a harder reason: `deparse` on a
        // synthetic tree aborts the process from C on a malformed enum, which
        // turns a grouping we cannot read into a crash.
        //
        // This is the *key* half of the problem only. The other half — a
        // summary of a column the query groups on, which is that column — is
        // decided in `analysis`, where the aggregate's argument is visible.
        let singleton_groups = inspection.as_ref().is_some_and(|inspection| {
            match inspection.group_by_columns() {
                Some(grouped) => {
                    !grouped.is_empty() && snapshot.grouping_covers_a_unique_key(&grouped)
                }
                None => match inspection.identifiers() {
                    Some(named) => snapshot.grouping_covers_a_unique_key(named),
                    // A statement we cannot even lex is one we cannot clear.
                    None => true,
                },
            }
        });
        let allow_summaries = live.summaries == Summaries::Allow && !singleton_groups;

        // Hostile posture: a masked column may only appear as a bare outermost
        // SELECT-list ColumnRef (ORDER BY mentions are credited — cleartext
        // sort order of masked values is accepted). Whole-row casts/refs
        // (`t::text`) are refused — they embed cleartext without naming
        // columns. Closes WHERE/LIKE, single-row aggregates and the
        // error-channel CASE — see analysis/.
        if live.posture == Posture::Hostile {
            let masked = snapshot.masked_bare_names_for_roles(&self.roles);
            let relations = snapshot.relation_columns_map();
            let empty = analysis::StatementInspection::new("");
            let hostile = inspection.as_ref().unwrap_or(&empty);
            if hostile.masked_exceeds_outer_projection(&masked)
                || hostile.hostile_uses_whole_row(relations)
                || hostile.hostile_join_or_rename_masked(relations, &masked)
            {
                self.plans.discard_description();
                return self.reject(
                    Rejection {
                        cause: Cause::HostileMaskedUse,
                        message: "pgmask: posture = \"hostile\" refuses use of a masked \
                                  column outside a bare SELECT list"
                            .into(),
                        hint: Some(
                            "Masked columns may be projected (and will be masked) and may \
                             appear in ORDER BY, but not in WHERE, HAVING, expressions, \
                             aggregates, or whole-row casts (t::text). Set posture = \
                             \"default\" for the looser analyst threat model."
                                .into(),
                        ),
                    },
                    out,
                );
            }
        }

        // `date_trunc` to a unit finer than a year can return more than a date
        // mask allows — `date_trunc('day', birth_date)` returned the whole
        // value through a year-masked column. Year and coarser are safe
        // unconditionally; finer only when the statement names nothing masked,
        // which is what keeps `date_trunc('month', placed_at)` working on a
        // column the operator released with `mask = "none"`.
        let fine_date_trunc = inspection.as_ref().is_some_and(|inspection| {
            !snapshot.inspection_references_masked_column(inspection, &self.roles)
        });
        let allow = crate::analysis::Relaxations {
            summaries: allow_summaries,
            fine_date_trunc,
        };

        let safety = match &inspection {
            Some(inspection) => inspection.output_safety(fields.len(), allow),
            None => vec![Safety::Unknown; fields.len()],
        };
        // Engines disagree about this: Postgres zeroes provenance for set
        // operations, CockroachDB reports it on the simple-query path only.
        // Deciding from the statement rather than from the engine makes the
        // behaviour the same on both.
        //
        // The statement alone is not enough. `SELECT v FROM v_union` contains no
        // set operation and CockroachDB still reports the first branch's
        // provenance, because the union is in the view. A shape sweep found that
        // leak after the statement-level check had already been shipped, which
        // is the argument for the sweep and not for the check.
        let trust_provenance = match inspection.as_ref() {
            // Missing statement identity means provenance cannot be checked
            // against set operations or opaque views. Treat it as unknown,
            // especially on engines that report one branch's OID for a UNION.
            None => false,
            Some(inspection) => {
                inspection.provenance_is_trustworthy()
                    && !snapshot.inspection_touches_opaque_view(inspection)
            }
        };

        // Only computed when something would otherwise be refused: a query whose
        // every field either has provenance or is already released by shape
        // never pays for the analysis.
        //
        // "Has provenance" is not the same question as "will be planned from
        // provenance" — a distrusted set-op field is treated as opaque even
        // though the engine reported an OID, and needs lineage exactly as much
        // as a genuinely computed one. Asking only the first question left
        // CockroachDB refusing unions that Postgres serves, because there the
        // fields carry provenance right up until we decline to believe it.
        let needs_lineage = live.lineage == Lineage::Allow
            && fields.iter().zip(&safety).any(|(field, safety)| {
                (!field.has_provenance() || !trust_provenance) && *safety != Safety::Releasable
            });
        let lineage_verdicts: Vec<Verdict> = match (&inspection, needs_lineage) {
            (Some(inspection), true) => {
                lineage::resolve_inspected(inspection, fields.len(), &snapshot, &self.roles)
            }
            _ => Vec::new(),
        };

        // Syntax-verified expression shapes share one catalog-policy slot.
        // A summary and a JSON extract have different parsers, but plan_for
        // only receives Released / Masked / Opaque after unique attribution.
        let expression_policies = resolve_expression_policies(
            inspection.as_ref(),
            fields.len(),
            &safety,
            &snapshot,
            &self.roles,
        );

        let planned = if system_catalog {
            Ok(Arc::new(
                fields
                    .iter()
                    .map(|field| FieldPlan {
                        spec: MaskSpec::new(Mask::None),
                        json_projection: None,
                        type_oid: field.type_oid,
                        format: field.format,
                        lenient: false,
                        primed: None,
                    })
                    .collect::<Vec<_>>(),
            ))
        } else {
            self.policy.plan_for_with(
                &live,
                &snapshot,
                &fields,
                &self.roles,
                &FieldAnalysis {
                    safety: &safety,
                    lineage: &lineage_verdicts,
                    expression: &expression_policies,
                    trust_provenance,
                },
            )
        };
        let plan = match planned {
            Ok(plan) => plan,
            Err(rejection) => {
                self.plans.discard_description();
                return self.reject(rejection, out);
            }
        };

        // Successful result sets are the denominator: a rejection share is
        // meaningless without knowing how much traffic sails through.
        let masking = plan.iter().filter(|f| !f.spec.is_passthrough()).count();
        if masking > 0 {
            self.policy.metrics.record_masked_result_set(masking as u64);
        }

        // Bind the plan to whatever this RowDescription answers, and make it
        // active — which also covers pipelined Bind-before-Describe ordering.
        //
        // A RowDescription that answered nothing this proxy forwarded is a
        // desync the queue cannot explain. Failing closed here beats reading
        // it as a simple result: that guess let one message's description
        // govern another's rows.
        if let Err(()) = self.plans.finish_description(plan) {
            return self.reject(
                Rejection {
                    cause: Cause::Malformed,
                    message: "pgmask: RowDescription answered no forwarded Describe or Query"
                        .into(),
                    hint: Some(
                        "The backend described a result set the proxy never saw requested, so \
                         its shape cannot be trusted."
                            .into(),
                    ),
                },
                out,
            );
        }
        out.client(Vetted::control(&msg))
    }

    fn handle_data_row(&mut self, msg: Message, out: &mut Batch) {
        // One result set streams at a time, each with exactly one governing
        // plan. A stream with none — a statement that was never described —
        // is refused rather than guessed at.
        let Some(plan) = self.plans.streaming_plan() else {
            // Rows we were never given the shape of. Refuse rather than guess.
            return self.reject(
                Rejection {
                    cause: Cause::NoActivePlan,
                    message: "pgmask: received a data row with no described result set".into(),
                    hint: Some(
                        "The statement produced rows without a RowDescription, so no masking plan \
                         could be built."
                            .into(),
                    ),
                },
                out,
            );
        };

        // One fused pass: decode each field, mask it, and append it straight to
        // the outbound frame. The previous shape collected every parsed field
        // into a `Vec`, collected every masked field into a second `Vec`, and
        // then encoded those into a third buffer — two allocations and a full
        // extra traversal per row, on the hottest path in the proxy. The
        // framing rules `parse_data_row` enforced (declared count, no
        // truncation, no trailing bytes) are enforced identically by
        // `DataRowReader`, including on the all-passthrough path below.
        let malformed = |err: &anyhow::Error| Rejection {
            cause: Cause::Malformed,
            message: format!("pgmask: could not parse DataRow: {err}"),
            hint: None,
        };
        let mut reader = match protocol::DataRowReader::new(&msg.body) {
            Ok(reader) => reader,
            Err(err) => return self.reject(malformed(&err), out),
        };

        if reader.field_count() != plan.len() {
            return self.reject(
                Rejection {
                    cause: Cause::Malformed,
                    message: format!(
                        "pgmask: row has {} fields but the described result set has {}",
                        reader.field_count(),
                        plan.len()
                    ),
                    hint: None,
                },
                out,
            );
        }

        // A plan that masks nothing forwards the original bytes untouched —
        // after walking the frame, so a malformed row is still refused rather
        // than relayed. This is what every row of a fully released result set
        // costs.
        if plan.iter().all(|field| field.spec.is_passthrough()) {
            loop {
                match reader.next_field() {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(err) => return self.reject(malformed(&err), out),
                }
            }
            return out.client(Vetted::unmasked_row(&msg, &plan));
        }

        // Tag + length placeholder + field count; the length is patched once
        // the masked sizes are known. Capacity is a hint — masks keep values
        // in the same size class, so the input size is the right guess.
        let mut frame = BytesMut::with_capacity(msg.body.len().saturating_add(16));
        frame.put_u8(protocol::B_DATA_ROW);
        frame.put_i32(0);
        frame.put_i16(plan.len() as i16);
        for field in plan.iter() {
            // The count was checked against the plan above, so a missing field
            // here is a framing violation, not a shorter row.
            let value = match reader.next_field() {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return self.reject(
                        Rejection {
                            cause: Cause::Malformed,
                            message: "pgmask: DataRow ended before its declared field count".into(),
                            hint: None,
                        },
                        out,
                    )
                }
                Err(err) => return self.reject(malformed(&err), out),
            };
            let masked = if field.spec.is_passthrough() {
                value
            } else {
                match self.policy.masker().apply_planned(
                    &field.spec,
                    field.primed.as_ref(),
                    field.json_projection.as_ref(),
                    field.type_oid,
                    field.format,
                    value,
                ) {
                    Ok(masked) => {
                        self.masked_fields = self.masked_fields.saturating_add(1);
                        masked
                    }
                    // A type-aware *fallback* mask that cannot honour this
                    // value nulls the field — strictly less disclosure —
                    // rather than killing the stream. The old unclassified
                    // default was NULL unconditionally, and values it handled
                    // fine ('infinity' timestamps, `SET datestyle` output, a
                    // Bind that flipped the portal to a binary format the mask
                    // cannot decode) must not become mid-stream rejections now.
                    Err(_) if field.lenient => {
                        self.masked_fields = self.masked_fields.saturating_add(1);
                        None
                    }
                    Err(err) => {
                        return self.reject(
                            Rejection {
                                cause: Cause::MaskTypeMismatch,
                                message: format!("pgmask: {err}"),
                                hint: None,
                            },
                            out,
                        )
                    }
                }
            };
            match masked {
                None => frame.put_i32(-1),
                Some(bytes) => {
                    frame.put_i32(i32::try_from(bytes.len()).unwrap_or(i32::MAX));
                    frame.put_slice(&bytes);
                }
            }
        }
        // The declared count is exhausted; this is the trailing-bytes check.
        if let Err(err) = reader.next_field() {
            return self.reject(malformed(&err), out);
        }

        // Patch the length: everything after the tag byte, including the
        // length field itself, exactly as `Message::encode` frames it.
        let body_len = i32::try_from(frame.len().saturating_sub(1)).unwrap_or(i32::MAX);
        let Some(slot) = frame.get_mut(1..5) else {
            // Unreachable — the header was written seven lines up — but a
            // refusal beats a panic on the one path that must not die.
            return self.reject(
                Rejection {
                    cause: Cause::Malformed,
                    message: "pgmask: could not frame masked DataRow".into(),
                    hint: None,
                },
                out,
            );
        };
        slot.copy_from_slice(&body_len.to_be_bytes());
        out.client(Vetted::masked_row(frame));
    }
}

/// Read one untagged startup packet straight off the socket.
///
/// Startup cannot go through `FrameReader`, because answering `SSLRequest`
/// means replacing the whole stream with a TLS session — a buffered reader that
/// already owned the socket would strand any bytes it had read ahead. Clients
/// wait for the single-byte reply before sending anything more, so reading
/// exactly one packet at a time here is safe.
async fn read_startup_packet<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> Result<Option<protocol::StartupPacket>> {
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = i32::from_be_bytes(len_bytes);
    if !(8..=1_048_576).contains(&len) {
        anyhow::bail!("implausible startup packet length {len}");
    }
    // `len` counts its own four bytes, so the remainder is `len - 4`. The range
    // check above already guarantees at least four bytes remain; subtracting
    // through `checked_sub` keeps the bound and the arithmetic from drifting
    // apart if that check is ever loosened.
    let body_len = usize::try_from(len)
        .ok()
        .and_then(|n| n.checked_sub(4))
        .ok_or_else(|| anyhow::anyhow!("implausible startup packet length {len}"))?;
    let mut rest = vec![0u8; body_len];
    stream.read_exact(&mut rest).await?;
    // Those four bytes are the request code. Refuse rather than guess one: the
    // code is what decides SSLRequest vs CancelRequest vs StartupMessage.
    let Some(&[c0, c1, c2, c3]) = rest.get(..4) else {
        anyhow::bail!("startup packet too short to carry a request code");
    };
    let code = i32::from_be_bytes([c0, c1, c2, c3]);
    Ok(Some(protocol::StartupPacket {
        code,
        body: Bytes::from(rest).slice(4..),
    }))
}

/// The principal, or `None` if the packet is ambiguous about who that is.
///
/// PostgreSQL keeps the *last* value for a duplicated startup parameter, and
/// this used to take the first — so `user=alice\0…\0user=mallory\0`
/// authenticated as `mallory` while pgmask resolved `alice`'s roles. A role's
/// mask *replaces* the default and can be looser, so that is a grant the
/// database never made.
///
/// Matching Postgres's last-wins would fix the observed case and leave the
/// real defect in place: the principal would still come from an independent
/// parse of a packet the backend re-parses, and the two would only agree for
/// as long as this matches an implementation detail of the server. A packet
/// that names the user twice is refused instead, so they cannot disagree.
fn startup_principal(startup: &protocol::StartupPacket) -> Option<String> {
    let mut users = startup
        .parameters()
        .into_iter()
        .filter(|(key, _)| key == "user")
        .map(|(_, value)| value);
    let first = users.next()?;
    if users.next().is_some() {
        return None;
    }
    Some(first)
}

/// Startup negotiation on both legs, then the message pump.
pub async fn handle_connection(
    client: TcpStream,
    backend_addr: &str,
    policy: Arc<Policy>,
) -> Result<()> {
    client.set_nodelay(true).ok();
    let mut client_stream: BoxStream = Box::new(client);

    // --- Client-side TLS negotiation ----------------------------------------
    // Postgres has no ALPN and no separate TLS port: the client asks with an
    // SSLRequest packet and we answer with one byte before any TLS bytes flow.
    let mut client_tls = false;
    let startup = loop {
        let Some(packet) = read_startup_packet(&mut client_stream).await? else {
            return Ok(());
        };
        match packet.code {
            protocol::SSL_REQUEST_CODE => match policy.tls_acceptor() {
                Some(acceptor) => {
                    client_stream.write_all(b"S").await?;
                    client_stream.flush().await?;
                    // `TlsAcceptor` needs a concrete stream, and we still hold a
                    // box; downcasting is not available, so the acceptor is
                    // applied to the boxed stream directly.
                    let tls = acceptor
                        .accept(client_stream)
                        .await
                        .context("client TLS handshake failed")?;
                    client_stream = Box::new(tls);
                    client_tls = true;
                }
                None => {
                    client_stream.write_all(b"N").await?;
                    client_stream.flush().await?;
                }
            },
            // We never offer GSSAPI encryption.
            protocol::GSSENC_REQUEST_CODE => {
                client_stream.write_all(b"N").await?;
                client_stream.flush().await?;
            }
            _ => break packet,
        }
    };

    // --- The certificate is only a boundary if it is required ----------------
    // Postgres has no ALPN and no TLS port. A client that never sends
    // `SSLRequest` — `sslmode=disable`, one flag — reaches here with
    // `client_tls == false` and, before this check existed, went on to a fully
    // working plaintext session against a proxy whose startup log said
    // `tls=true`. Masking held; confidentiality did not. Partial masks are
    // partial on purpose, pseudonyms are stable identifiers, and the SCRAM
    // exchange crosses the same wire.
    //
    // The refusal is deliberately *not* the code path that strips channel
    // binding for plaintext clients above. That path exists so pgmask can sit
    // in front of a TLS-only managed Postgres, and it makes the plaintext
    // client work smoothly — which is exactly why the downgrade needed its own
    // gate rather than being left to friction.
    if !client_tls && policy.client_tls_required() {
        policy.metrics.record(Cause::PlaintextRefused);
        // A CancelRequest is a fire-and-forget packet: the client sends it and
        // closes without reading a reply, so an ErrorResponse would go into a
        // socket nobody reads. Drop it. It carries the backend's cancel key,
        // which is precisely something not to hand over in plaintext.
        if startup.code != protocol::CANCEL_REQUEST_CODE {
            let err = protocol::build_error(
                protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                "pgmask: this connection is not using TLS",
                Some(
                    "pgmask serves masked data, which is not public data. Connect with \
                     sslmode=require or stronger. An operator who wants plaintext \
                     sessions must set require_client_tls = false.",
                ),
            );
            client_stream.write_all(&err.encode()).await?;
            client_stream.flush().await?;
        }
        return Ok(());
    }
    if !client_tls {
        // Allowed by policy, but never silent: this is the only signal that
        // tells "a certificate is configured" apart from "a certificate is used".
        policy.metrics.record_plaintext_session();
    }

    // --- Backend connection -------------------------------------------------
    let backend = TcpStream::connect(backend_addr)
        .await
        .with_context(|| format!("connecting to backend {backend_addr}"))?;
    backend.set_nodelay(true).ok();
    let backend_tls = policy.backend_tls();
    let backend_ca = policy.backend_ca();
    let mut backend_stream: BoxStream = match backend_tls {
        BackendTls::Disable => Box::new(backend),
        BackendTls::Require | BackendTls::VerifyFull => {
            // Strip the port: SNI carries a hostname, never host:port.
            let host = backend_addr
                .rsplit_once(':')
                .map_or(backend_addr, |(h, _)| h);
            crate::tls::upgrade_backend(backend, host, backend_tls, backend_ca.as_deref()).await?
        }
    };

    backend_stream.write_all(&startup.encode()).await?;
    backend_stream.flush().await?;

    // A CancelRequest is its own short-lived connection carrying the backend's
    // own key (we forward BackendKeyData verbatim, so the client holds the real
    // one). Forward and hang up.
    if startup.code == protocol::CANCEL_REQUEST_CODE {
        return Ok(());
    }

    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let (backend_read, mut backend_write) = tokio::io::split(backend_stream);
    let mut client_frames = FrameReader::new(client_read);
    let mut backend_frames = FrameReader::new(backend_read);

    // A packet that names the user twice is refused rather than guessed at.
    let Some(user) = startup_principal(&startup) else {
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            "pgmask: the startup packet names \"user\" more than once",
            Some(
                "pgmask resolves masking policy from the authenticated principal. A packet \
                 that names two cannot be resolved to one, so the connection is refused.",
            ),
        );
        client_write.write_all(&err.encode()).await.ok();
        client_write.flush().await.ok();
        return Ok(());
    };

    // --- Message pump -------------------------------------------------------
    let mut session = Session::new(policy)
        .with_client_tls(client_tls)
        .with_principal(&user);

    // Accumulate a whole batch before touching the sockets. One `read_buf`
    // typically carries hundreds of DataRows; flushing per message turned that
    // into a syscall per row and dominated bulk throughput.
    let mut out = Batch::default();

    'pump: loop {
        tokio::select! {
            // One `handle_frontend` call site, deliberately. The obvious
            // shape — handle the first message, then loop over the rest — gives
            // each handler *two* call sites, and anything added to only one of
            // them silently applies to a subset of messages. That mistake was
            // made twice here: CopyData escaped through the drain after a
            // refusal, and AuthenticationOk went unseen because it usually
            // shares a TCP segment with the SASL final message, so no session
            // ever resolved a principal. Neither was caught by a type; both were
            // caught by luck. Do not reintroduce the asymmetry.
            msg = client_frames.read_message() => {
                let mut current = msg?;
                while let Some(msg) = current {
                    session.handle_frontend(msg, &mut out);
                    if out.close {
                        break;
                    }
                    current = client_frames.try_buffered_message()?;
                }
                if client_frames.saw_eof() {
                    break 'pump;
                }
            },
            msg = backend_frames.read_message() => {
                let mut current = msg?;
                while let Some(msg) = current {
                    session.handle_backend(msg, &mut out);
                    if out.close {
                        break;
                    }
                    current = backend_frames.try_buffered_message()?;
                }
                if backend_frames.saw_eof() {
                    break 'pump;
                }
            },
        }

        if !out.is_empty() {
            if !out.to_backend.is_empty() {
                backend_write.write_all(&out.to_backend).await?;
                backend_write.flush().await?;
                out.to_backend.clear();
            }
            if !out.to_client.is_empty() {
                client_write.write_all(&out.to_client).await?;
                client_write.flush().await?;
                out.to_client.clear();
            }
        }
        if out.close {
            break;
        }
    }

    session
        .policy
        .metrics
        .record_session_end(session.masked_fields);
    if session.masked_fields > 0 || session.rejected_result_sets > 0 {
        tracing::info!(
            %user,
            authenticated = session.authenticated,
            roles = session.roles.len(),
            masked_fields = session.masked_fields,
            rejected_result_sets = session.rejected_result_sets,
            "session closed"
        );
    }
    Ok(())
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
    use crate::catalog::{Opaque, Unclassified};
    use crate::plan_state::Plan;
    use crate::policy::roles_by_principal;
    use crate::policy::test_support::{
        policy, policy_with_lineage_allow, policy_with_notice_cap, policy_with_rate_limit,
    };

    /// Regression: AuthenticationOk usually shares a TCP segment with the SASL
    /// final message, so it reaches `handle_backend` via the drain loop rather
    /// than as the first message of a read. Detecting it only in the pump meant
    /// no session ever resolved a principal, and every user silently got the
    /// default policy.
    #[test]
    fn authentication_ok_is_detected_even_when_it_is_not_the_first_message() {
        use crate::catalog::Role;

        let p = policy(Unclassified::Allow, Opaque::Reject);
        p.set_roles_for_test(roles_by_principal(&[Role {
            name: "support".into(),
            members: vec!["sam".into()],
        }]));

        let mut session = Session::new(p).with_principal("sam");
        let mut out = Batch::default();

        // SASLFinal (Authentication sub-code 12) — not AuthenticationOk.
        let mut sasl_final = bytes::BytesMut::new();
        bytes::BufMut::put_i32(&mut sasl_final, 12);
        session.handle_backend(
            Message::new(protocol::B_AUTHENTICATION, sasl_final.freeze()),
            &mut out,
        );
        assert!(!session.authenticated, "12 is not AuthenticationOk");
        assert!(session.roles.is_empty());

        // AuthenticationOk arriving second, as it does on the wire.
        let mut ok = bytes::BytesMut::new();
        bytes::BufMut::put_i32(&mut ok, 0);
        session.handle_backend(
            Message::new(protocol::B_AUTHENTICATION, ok.freeze()),
            &mut out,
        );
        assert!(session.authenticated, "AuthenticationOk must be seen");
        assert!(
            session.roles.contains("support"),
            "the verified principal's roles must be resolved"
        );
    }

    #[test]
    fn an_unclaimed_principal_gets_no_roles() {
        use crate::catalog::Role;
        let p = policy(Unclassified::Allow, Opaque::Reject);
        p.set_roles_for_test(roles_by_principal(&[Role {
            name: "support".into(),
            members: vec!["sam".into()],
        }]));
        let mut session = Session::new(p).with_principal("mallory");
        let mut ok = bytes::BytesMut::new();
        bytes::BufMut::put_i32(&mut ok, 0);
        session.handle_backend(
            Message::new(protocol::B_AUTHENTICATION, ok.freeze()),
            &mut Batch::default(),
        );
        assert!(session.authenticated);
        assert!(session.roles.is_empty(), "unknown principals get nothing");
    }

    /// A packet naming the user twice is ambiguous, so it is refused.
    ///
    /// Postgres keeps the last value and pgmask used to take the first, so
    /// `user=privileged … user=actual` authenticated as `actual` while masking
    /// policy resolved `privileged`'s roles — and a role's mask replaces the
    /// default, so it can be looser. Matching last-wins would fix this case and
    /// leave the principal depending on two parsers agreeing.
    #[test]
    fn a_startup_packet_naming_two_users_has_no_principal() {
        let startup = protocol::StartupPacket {
            code: 196_608,
            body: Bytes::from_static(b"user\0privileged\0database\0db\0user\0actual\0\0"),
        };
        assert_eq!(startup_principal(&startup), None);

        let single = protocol::StartupPacket {
            code: 196_608,
            body: Bytes::from_static(b"user\0actual\0database\0db\0\0"),
        };
        assert_eq!(startup_principal(&single), Some("actual".to_string()));

        let none = protocol::StartupPacket {
            code: 196_608,
            body: Bytes::from_static(b"database\0db\0\0"),
        };
        assert_eq!(startup_principal(&none), None);
    }

    #[test]
    fn an_unauthenticated_session_gets_the_default_classification() {
        // Roles are only ever populated from a username Postgres verified, so a
        // session that never authenticated cannot pick up a looser mask.
        let session = Session::new(policy(Unclassified::Mask, Opaque::Reject));
        assert!(session.roles.is_empty());
    }

    fn sample_notice() -> Message {
        let mut body = bytes::BytesMut::new();
        for (tag, value) in [
            (b'S', "NOTICE"),
            (b'V', "NOTICE"),
            (b'C', "00000"),
            (b'M', "x"),
        ] {
            bytes::BufMut::put_u8(&mut body, tag);
            bytes::BufMut::put_slice(&mut body, value.as_bytes());
            bytes::BufMut::put_u8(&mut body, 0);
        }
        bytes::BufMut::put_u8(&mut body, 0);
        Message::new(protocol::B_NOTICE_RESPONSE, body.freeze())
    }

    /// The live demo cannot reach this backend-message path: `LISTEN` and
    /// `DO`/`NOTIFY` are refused before Postgres, so absence of a payload there
    /// only proves that no notification was generated. Drive the real dispatch
    /// directly so removing the `B_NOTIFICATION_RESPONSE` arm's drop would
    /// make this test fail with the client-chosen payload in `to_client`.
    #[test]
    fn a_notification_response_is_dropped_whatever_its_payload() {
        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_i32(&mut body, 42);
        bytes::BufMut::put_slice(&mut body, b"updates\0");
        bytes::BufMut::put_slice(&mut body, b"user1@example.com\0");

        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_NOTIFICATION_RESPONSE, body.freeze()),
            &mut out,
        );

        assert!(
            out.to_client.is_empty(),
            "notification payload reached client"
        );
        assert!(out.to_backend.is_empty());
        assert!(
            !out.close,
            "dropping an async notification keeps the session usable"
        );
    }

    #[test]
    fn simple_query_rate_limit_refuses_after_burst() {
        let mut session = Session::new(policy_with_rate_limit(60, 2)).with_principal("alice");
        session.authenticated = true;

        for i in 0..2 {
            let mut out = Batch::default();
            session.handle_frontend(
                Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1\0")),
                &mut out,
            );
            assert!(
                !out.to_backend.is_empty(),
                "query {i} under burst must reach the backend"
            );
            assert!(out.to_client.is_empty());
        }

        let mut out = Batch::default();
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1\0")),
            &mut out,
        );
        assert!(
            out.to_backend.is_empty(),
            "over-budget Query must not reach the backend"
        );
        let text = String::from_utf8_lossy(&out.to_client);
        assert!(text.contains("rate limit"), "got: {text}");
        assert!(text.contains("54000"), "SQLSTATE 54000 expected: {text}");
        // Synthetic ReadyForQuery so the client is not left hanging.
        assert!(
            out.to_client.contains(&protocol::B_READY_FOR_QUERY),
            "simple-query refusal must synthesise ReadyForQuery"
        );
        assert_eq!(
            session.policy.metrics.count(Cause::RateLimited),
            1,
            "metric must fire once"
        );
    }

    #[test]
    fn execute_rate_limit_refuses_without_ready_for_query() {
        let mut session = Session::new(policy_with_rate_limit(60, 1)).with_principal("alice");
        session.authenticated = true;

        // Spend the single token.
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1\0")),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        let mut exec = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut exec, b"\0"); // unnamed portal
        bytes::BufMut::put_i32(&mut exec, 0); // no row limit
        session.handle_frontend(Message::new(protocol::F_EXECUTE, exec.freeze()), &mut out);
        assert!(out.to_backend.is_empty());
        let text = String::from_utf8_lossy(&out.to_client);
        assert!(text.contains("rate limit"), "got: {text}");
        assert!(
            !out.to_client.contains(&protocol::B_READY_FOR_QUERY),
            "Execute refusal waits for the client's Sync"
        );
    }

    #[test]
    fn unauthenticated_queries_are_not_rate_limited() {
        // Burning the claimed username's budget before AuthenticationOk would
        // turn a failed login into a DoS against a real session.
        let mut session = Session::new(policy_with_rate_limit(60, 1)).with_principal("alice");
        assert!(!session.authenticated);
        for _ in 0..3 {
            let mut out = Batch::default();
            session.handle_frontend(
                Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1\0")),
                &mut out,
            );
            assert!(!out.to_backend.is_empty());
            assert!(out.to_client.is_empty());
        }
    }

    #[test]
    fn notice_cap_drops_excess_and_resets_on_ready() {
        let mut session = Session::new(policy_with_notice_cap(2));
        let notice = sample_notice();

        for i in 0..2 {
            let mut out = Batch::default();
            session.handle_backend(notice.clone(), &mut out);
            assert!(
                !out.to_client.is_empty(),
                "notice {i} under the cap must be forwarded"
            );
        }

        let mut out = Batch::default();
        session.handle_backend(notice.clone(), &mut out);
        assert!(
            out.to_client.is_empty(),
            "notice over the cap must be dropped"
        );
        assert_eq!(session.policy.metrics.count(Cause::NoticeFlood), 1);

        // Further excess notices do not re-fire the metric.
        session.handle_backend(notice.clone(), &mut Batch::default());
        assert_eq!(session.policy.metrics.count(Cause::NoticeFlood), 1);

        // ReadyForQuery replenishes the budget.
        session.handle_backend(
            Message::new(protocol::B_READY_FOR_QUERY, Bytes::from_static(b"I")),
            &mut Batch::default(),
        );
        let mut out = Batch::default();
        session.handle_backend(notice, &mut out);
        assert!(
            !out.to_client.is_empty(),
            "a new exchange must admit notices again"
        );
    }

    #[test]
    fn read_only_refuses_writes_and_do_before_the_backend() {
        // Read-only applies on every posture, including default.
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        for sql in [
            "INSERT INTO t VALUES (1)\0",
            "UPDATE t SET x=1\0",
            "DELETE FROM t\0",
            "CREATE TABLE t (id int)\0",
            "DO $$ BEGIN RAISE NOTICE 'x'; END $$\0",
            "CALL demo.do_thing()\0",
        ] {
            let mut out = Batch::default();
            session.handle_frontend(
                Message::new(protocol::F_QUERY, Bytes::from(sql.as_bytes().to_vec())),
                &mut out,
            );
            assert!(out.to_backend.is_empty(), "must not reach Postgres: {sql}");
            let text = String::from_utf8_lossy(&out.to_client);
            assert!(text.contains("read-only"), "got: {text} for {sql}");
        }
        assert!(session.policy.metrics.count(Cause::WriteRefused) >= 6);

        // Ordinary SELECT still goes through.
        let mut out = Batch::default();
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1\0")),
            &mut out,
        );
        assert!(!out.to_backend.is_empty());
        assert!(out.to_client.is_empty());
    }

    #[test]
    fn sql_prepare_and_cursors_are_refused_before_the_backend() {
        // Statement class, every posture — not a write, and not hostile-only.
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        for sql in [
            "PREPARE q AS SELECT 1\0",
            "EXECUTE q\0",
            "DEALLOCATE q\0",
            "DECLARE c CURSOR FOR SELECT 1\0",
            "FETCH ALL FROM c\0",
            "CLOSE c\0",
        ] {
            let mut out = Batch::default();
            session.handle_frontend(
                Message::new(protocol::F_QUERY, Bytes::from(sql.as_bytes().to_vec())),
                &mut out,
            );
            assert!(out.to_backend.is_empty(), "must not reach Postgres: {sql}");
            let text = String::from_utf8_lossy(&out.to_client);
            assert!(
                text.contains("SQL PREPARE") || text.contains("DECLARE"),
                "got: {text} for {sql}"
            );
            assert!(
                !text.contains("read-only"),
                "must be a dedicated cause, not write_refused: {text}"
            );
        }
        assert!(session.policy.metrics.count(Cause::SqlPrepareCursor) >= 6);
        assert_eq!(session.policy.metrics.count(Cause::WriteRefused), 0);

        // Ordinary SELECT, including FETCH FIRST as a limit, still goes through.
        for sql in [
            &b"SELECT 1\0"[..],
            &b"SELECT 1 FETCH FIRST 1 ROW ONLY\0"[..],
        ] {
            let mut out = Batch::default();
            session.handle_frontend(
                Message::new(protocol::F_QUERY, Bytes::copy_from_slice(sql)),
                &mut out,
            );
            assert!(
                !out.to_backend.is_empty(),
                "SELECT must still reach Postgres: {}",
                String::from_utf8_lossy(sql)
            );
            assert!(out.to_client.is_empty());
        }
    }

    #[test]
    fn untrusted_functions_never_reach_the_backend() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let mut out = Batch::default();
        session.handle_frontend(
            Message::new(
                protocol::F_QUERY,
                Bytes::from_static(b"SELECT demo.sleep_if(1, 'u')\0"),
            ),
            &mut out,
        );
        assert!(out.to_backend.is_empty());
        let text = String::from_utf8_lossy(&out.to_client);
        assert!(text.contains("trusted pg_catalog"), "got: {text}");
        assert_eq!(session.policy.metrics.count(Cause::UntrustedFunction), 1);
    }

    #[test]
    fn a_data_row_with_no_plan_is_never_forwarded() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let row = protocol::build_data_row(&[Some(Bytes::from_static(b"alice@example.com"))]);
        let mut out = Batch::default();
        session.handle_data_row(row, &mut out);
        assert!(!out.to_client.is_empty());
        let text = String::from_utf8_lossy(&out.to_client).to_string();
        assert!(
            !text.contains("alice@example.com"),
            "leaked an unmasked value"
        );
        assert!(text.contains("no described result set"));
        assert!(
            session.suppressing.is_some(),
            "must swallow the rest of the result set"
        );
    }

    #[test]
    fn missing_statement_sql_distrusts_reported_provenance() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_i16(&mut body, 1);
        bytes::BufMut::put_slice(&mut body, b"city\0");
        bytes::BufMut::put_u32(&mut body, 16_391);
        bytes::BufMut::put_i16(&mut body, 1);
        bytes::BufMut::put_u32(&mut body, 25);
        bytes::BufMut::put_i16(&mut body, -1);
        bytes::BufMut::put_i32(&mut body, -1);
        bytes::BufMut::put_i16(&mut body, 0);

        let mut out = Batch::default();
        session.handle_row_description(
            Message::new(protocol::B_ROW_DESCRIPTION, body.freeze()),
            &mut out,
        );

        assert!(session.suppressing.is_some());
        assert!(
            String::from_utf8_lossy(&out.to_client).contains("no column provenance"),
            "without SQL, a reported OID cannot be checked for set-operation ambiguity"
        );
    }

    #[test]
    fn suppression_swallows_rows_and_releases_on_ready_for_query() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        session.suppressing = Some(0);

        let row = protocol::build_data_row(&[Some(Bytes::from_static(b"secret"))]);
        let mut out = Batch::default();
        session.handle_backend(row, &mut out);
        assert!(out.to_client.is_empty());

        let ready = Message::new(protocol::B_READY_FOR_QUERY, Bytes::from_static(b"I"));
        let mut out = Batch::default();
        session.handle_backend(ready, &mut out);
        assert!(!out.to_client.is_empty());
        assert!(session.suppressing.is_none());
    }

    #[test]
    fn copy_out_is_refused_and_closes_the_connection() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let copy = Message::new(
            protocol::B_COPY_OUT_RESPONSE,
            Bytes::from_static(&[0, 0, 0]),
        );
        let mut out = Batch::default();
        session.handle_backend(copy, &mut out);
        assert!(out.close);
        assert!(String::from_utf8_lossy(&out.to_client).contains("COPY"));
    }

    #[test]
    fn function_call_is_refused() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let msg = Message::new(protocol::F_FUNCTION_CALL, Bytes::from_static(b""));
        let mut out = Batch::default();
        session.handle_frontend(msg, &mut out);
        assert!(out.close);
        assert!(out.to_backend.is_empty(), "must never reach the backend");
    }

    #[test]
    fn a_simple_query_invalidates_the_previous_plan() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        session.plans.parse("s".into(), "SELECT 1".into());
        session
            .plans
            .describe(protocol::DescribeTarget::Statement(Bytes::from_static(
                b"s",
            )));
        session
            .plans
            .finish_description(Arc::new(vec![FieldPlan {
                spec: MaskSpec::new(Mask::None),
                json_projection: None,
                type_oid: 25,
                format: 0,
                lenient: false,
                primed: None,
            }]))
            .unwrap();
        assert!(
            session.plans.active_plan().is_some(),
            "a described result set must be armed before the query arrives"
        );
        let query = Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1\0"));
        session.handle_frontend(query, &mut Batch::default());
        assert!(
            session.plans.active_plan().is_none(),
            "stale plans must not survive a new query"
        );
    }

    #[test]
    fn bind_carries_the_statement_plan_to_the_portal() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let plan: Plan = Arc::new(vec![FieldPlan {
            spec: MaskSpec::new(Mask::None),
            json_projection: None,
            type_oid: 25,
            format: 0,
            lenient: false,
            primed: None,
        }]);
        session.plans.parse("s1".into(), "SELECT 1".into());
        session
            .plans
            .describe(protocol::DescribeTarget::Statement(Bytes::from_static(
                b"s1",
            )));
        session.plans.finish_description(plan).unwrap();

        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut body, b"p1\0s1\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, body.freeze()),
            &mut Batch::default(),
        );
        let mut exec = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut exec, b"p1\0");
        bytes::BufMut::put_i32(&mut exec, 0);
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec.freeze()),
            &mut Batch::default(),
        );
        assert!(
            session.plans.active_plan().is_some(),
            "re-executing a prepared statement must work"
        );
    }

    #[test]
    fn binding_an_undescribed_statement_leaves_no_plan() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut body, b"p1\0unknown\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, body.freeze()),
            &mut Batch::default(),
        );

        let mut exec = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut exec, b"p1\0");
        bytes::BufMut::put_i32(&mut exec, 0);
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec.freeze()),
            &mut Batch::default(),
        );
        assert!(session.plans.active_plan().is_none(), "fail closed");
    }

    /// A reload is not one atomic instruction: changing column rules can wait
    /// on `pg_class` between its pre-swap and post-swap generations. A
    /// RowDescription arriving in that window rebuilds a plan from the old
    /// policy but stamps it with the pre-swap generation.
    ///
    /// The post-swap bump must invalidate that exact plan before Bind/Execute.
    /// This is a deterministic wire-state reproduction of the race; removing
    /// `PolicyChange::drop` makes `LEAKME` reach `to_client`.
    #[test]
    fn a_plan_built_during_reload_cannot_survive_the_swap() {
        let policy = policy(Unclassified::Allow, Opaque::Reject);
        let mut session = Session::new(policy.clone());

        session.handle_frontend(
            Message::new(
                protocol::F_PARSE,
                parse_body(b"s\0SELECT secret FROM public.t\0"),
            ),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss\0")),
            &mut Batch::default(),
        );

        // This is the point at which a real reload can be waiting on
        // Catalog::replace_spec. The RowDescription misses the empty test
        // catalog and `unclassified = allow` therefore builds passthrough.
        let change = policy.begin_change_for_test();
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut Batch::default(),
        );
        session.handle_backend(
            row_description(&[("secret", 16_384, 1, 25)]),
            &mut Batch::default(),
        );

        // The actual swap tightens default-deny, then dropping the bracket
        // publishes the post-swap generation.
        policy.set_unclassified_for_test(Unclassified::Mask);
        drop(change);

        let mut bind = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut bind, b"p\0s\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, bind.freeze()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p")),
            &mut Batch::default(),
        );

        let canary = Bytes::from_static(b"LEAKME");
        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_BIND_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(protocol::build_data_row(&[Some(canary.clone())]), &mut out);
        assert!(
            !out.to_client
                .windows(canary.len())
                .any(|window| window == &canary[..]),
            "a plan built from the old policy during reload survived the swap"
        );
        assert!(
            String::from_utf8_lossy(&out.to_client).contains("no described result set"),
            "the stale plan must be absent, so Execute fails closed: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    fn parse_body(name_sql: &[u8]) -> Bytes {
        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut body, name_sql);
        bytes::BufMut::put_i16(&mut body, 0);
        body.freeze()
    }

    fn exec_body(portal: &[u8]) -> Bytes {
        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut body, portal);
        bytes::BufMut::put_u8(&mut body, 0);
        bytes::BufMut::put_i32(&mut body, 0);
        body.freeze()
    }

    fn row_description(fields: &[(&str, u32, i16, u32)]) -> Message {
        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_i16(&mut body, fields.len() as i16);
        for (name, table_oid, column_id, type_oid) in fields {
            bytes::BufMut::put_slice(&mut body, name.as_bytes());
            bytes::BufMut::put_u8(&mut body, 0);
            bytes::BufMut::put_i32(&mut body, *table_oid as i32);
            bytes::BufMut::put_i16(&mut body, *column_id);
            bytes::BufMut::put_i32(&mut body, *type_oid as i32);
            bytes::BufMut::put_i16(&mut body, -1); // typlen
            bytes::BufMut::put_i32(&mut body, -1); // typmod
            bytes::BufMut::put_i16(&mut body, 0); // text format
        }
        Message::new(protocol::B_ROW_DESCRIPTION, body.freeze())
    }

    /// A RowDescription that completes an unrelated statement must not arm the
    /// plan for the Execute that is actually streaming.
    ///
    /// The client pipelines one exchange: `Parse(s1) Describe(s1) Parse(sm)
    /// Bind(p sm) Execute(p) Sync`. The frontend runs to completion before any
    /// backend response, so when the RowDescription for `s1` finally lands,
    /// Execute has already armed `p`. Before this fix, that description's
    /// passthrough plan became `active_plan`, and the never-described `sm`'s
    /// rows — which arrive with no RowDescription of their own — were cleared
    /// through it.
    #[test]
    fn a_lagging_row_description_does_not_arm_an_unrelated_execute() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        session.handle_frontend(
            Message::new(protocol::F_PARSE, parse_body(b"s1\0SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss1\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(
                protocol::F_PARSE,
                parse_body(b"sm\0SELECT a FROM fz.t1 LIMIT 2\0"),
            ),
            &mut Batch::default(),
        );
        let mut bind = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut bind, b"p\0sm\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, bind.freeze()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_BIND_COMPLETE, Bytes::new()),
            &mut out,
        );

        let canary = Bytes::from_static(b"LEAKME");
        session.handle_backend(protocol::build_data_row(&[Some(canary.clone())]), &mut out);
        assert!(
            !out.to_client
                .windows(canary.len())
                .any(|w| w == &canary[..]),
            "the never-described Execute's row must not reach the client"
        );
        assert!(
            String::from_utf8_lossy(&out.to_client).contains("no described result set"),
            "the refusal must be reported: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    /// Two Executes pipelined in one exchange are each vetted by their own
    /// portal's plan. A single `active_plan` used to be overwritten by the
    /// second Execute, so the first portal's rows were judged against the
    /// second statement's description.
    #[test]
    fn each_execute_is_vetted_by_its_own_portal() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));

        // Exchange 1: describe both statements.
        session.handle_frontend(
            Message::new(protocol::F_PARSE, parse_body(b"s1\0SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(
                protocol::F_PARSE,
                parse_body(b"s2\0SELECT 1 AS a, 2 AS b\0"),
            ),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss1\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss2\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );
        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        session.handle_backend(
            row_description(&[("a", 0, 0, 25), ("b", 0, 0, 25)]),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_READY_FOR_QUERY, Bytes::from_static(b"I")),
            &mut out,
        );

        // Exchange 2: bind and execute both, pipelined with no Sync between.
        session.handle_frontend(
            Message::new(protocol::F_BIND, Bytes::from_static(b"p1\0s1\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p1")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_BIND, Bytes::from_static(b"p2\0s2\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p2")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_BIND_COMPLETE, Bytes::new()),
            &mut out,
        );
        // p1's row has one field; the old code judged it with p2's two-field
        // plan and refused it as malformed.
        session.handle_backend(
            protocol::build_data_row(&[Some(Bytes::from_static(b"V1"))]),
            &mut out,
        );
        session.handle_backend(
            Message::new(
                protocol::B_COMMAND_COMPLETE,
                Bytes::from_static(b"SELECT 1\0"),
            ),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_BIND_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(
            protocol::build_data_row(&[
                Some(Bytes::from_static(b"V2A")),
                Some(Bytes::from_static(b"V2B")),
            ]),
            &mut out,
        );
        session.handle_backend(
            Message::new(
                protocol::B_COMMAND_COMPLETE,
                Bytes::from_static(b"SELECT 2\0"),
            ),
            &mut out,
        );

        assert!(
            out.to_client.windows(2).any(|w| w == b"V1"),
            "p1's row must be served by p1's plan: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        assert!(
            out.to_client.windows(3).any(|w| w == b"V2A"),
            "p2's row must be served by p2's plan: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        assert!(
            !String::from_utf8_lossy(&out.to_client).contains("no described result set"),
            "both described Executes are legitimate and must not be refused"
        );
    }

    /// Rows that follow no Execute still fall back to the plan the
    /// RowDescription armed — the simple-query path is unchanged.
    #[test]
    fn a_simple_query_result_is_still_vetted_by_its_row_description() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1 AS x\0")),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        session.handle_backend(
            protocol::build_data_row(&[Some(Bytes::from_static(b"1"))]),
            &mut out,
        );
        assert!(
            out.to_client.windows(1).any(|w| w == b"1"),
            "a simple query's own row must be served"
        );
    }

    /// Beekeeper Studio's first query after TCP connect. `CURRENT_SCHEMA()` is
    /// a context function: no stored column, no provenance. Production defaults
    /// (`opaque = reject`, `lineage = refuse`, `system_catalogs = refuse`) must
    /// still rescue it, or the GUI never finishes connecting.
    #[test]
    fn beekeeper_current_schema_is_served_under_default_policy() {
        let mut session = Session::new(policy(Unclassified::Mask, Opaque::Reject));
        session.handle_frontend(
            Message::new(
                protocol::F_QUERY,
                Bytes::from_static(b"SELECT CURRENT_SCHEMA() AS schema\0"),
            ),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        session.handle_backend(row_description(&[("schema", 0, 0, 19)]), &mut out);
        assert!(
            !String::from_utf8_lossy(&out.to_client).contains("no column provenance"),
            "Beekeeper's connect query must be rescued: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        session.handle_backend(
            protocol::build_data_row(&[Some(Bytes::from_static(b"public"))]),
            &mut out,
        );
        assert!(
            out.to_client.windows(6).any(|w| w == b"public"),
            "the current schema name must reach the client: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    /// node-postgres sends Parse/Describe of the unnamed statement, not Query.
    /// The rescue has to find the SQL on that path too.
    #[test]
    fn beekeeper_current_schema_is_served_over_the_unnamed_extended_protocol() {
        let mut session = Session::new(policy(Unclassified::Mask, Opaque::Reject));
        session.handle_frontend(
            Message::new(
                protocol::F_PARSE,
                parse_body(b"\0SELECT CURRENT_SCHEMA() AS schema\0"),
            ),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"S\0")),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(row_description(&[("schema", 0, 0, 19)]), &mut out);
        assert!(
            !String::from_utf8_lossy(&out.to_client).contains("no column provenance"),
            "unnamed Parse/Describe must still rescue CURRENT_SCHEMA(): {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    /// A simple query pipelined ahead of a never-described Execute still has
    /// its own result served, and the Execute's rows are still refused.
    ///
    /// Before the streaming-simple flag, the queued Execute made the simple
    /// result indistinguishable from an Execute result: the simple
    /// CommandComplete was mistaken for the Execute's and popped its slot, so
    /// the harmless `SELECT 1` row was refused as undescribable.
    #[test]
    fn a_pipelined_simple_result_is_served_before_a_refused_execute() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(
                protocol::F_PARSE,
                parse_body(b"sm\0SELECT a FROM fz.t1 LIMIT 2\0"),
            ),
            &mut Batch::default(),
        );
        let mut bind = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut bind, b"p\0sm\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, bind.freeze()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        // The simple query's own result streams first.
        let mut out = Batch::default();
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        let simple_row = protocol::build_data_row(&[Some(Bytes::from_static(b"1"))]);
        session.handle_backend(simple_row.clone(), &mut out);
        session.handle_backend(
            Message::new(
                protocol::B_COMMAND_COMPLETE,
                Bytes::from_static(b"SELECT 1\0"),
            ),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_READY_FOR_QUERY, Bytes::from_static(b"I")),
            &mut out,
        );
        assert!(
            out.to_client
                .windows(simple_row.encode().len())
                .any(|w| w == &simple_row.encode()[..]),
            "the simple query's row must be served: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        assert!(
            !String::from_utf8_lossy(&out.to_client).contains("no described result set"),
            "the simple row is legitimate and must not be refused: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );

        // The never-described Execute's row has no plan and must be refused,
        // even though the simple CommandComplete already ran.
        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_BIND_COMPLETE, Bytes::new()),
            &mut out,
        );
        let canary = Bytes::from_static(b"LEAKME");
        session.handle_backend(protocol::build_data_row(&[Some(canary.clone())]), &mut out);
        assert!(
            !out.to_client
                .windows(canary.len())
                .any(|w| w == &canary[..]),
            "the never-described Execute's row must not reach the client"
        );
        assert!(
            String::from_utf8_lossy(&out.to_client).contains("no described result set"),
            "the Execute's row must be refused: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    /// An Execute pipelined ahead of a simple query keeps its own portal's
    /// plan, even though the simple query invalidates the active plan before
    /// the Execute's rows stream. This is the ordering that must *not* mark
    /// the streaming result simple at `begin_simple_query`: the Execute's
    /// rows come first and belong to their own portal.
    #[test]
    fn an_execute_pipelined_before_a_simple_query_keeps_its_own_plan() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        // One flush: Parse, Describe, Bind, Execute, then a simple query.
        session.handle_frontend(
            Message::new(protocol::F_PARSE, parse_body(b"s\0SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss\0")),
            &mut Batch::default(),
        );
        let mut bind = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut bind, b"p\0s\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, bind.freeze()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        // The describe's RowDescription and BindComplete, then the Execute's
        // result, then the simple query's own result.
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_BIND_COMPLETE, Bytes::new()),
            &mut out,
        );
        let p_row = protocol::build_data_row(&[Some(Bytes::from_static(b"V1"))]);
        session.handle_backend(p_row.clone(), &mut out);
        session.handle_backend(
            Message::new(
                protocol::B_COMMAND_COMPLETE,
                Bytes::from_static(b"SELECT 1\0"),
            ),
            &mut out,
        );
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        let simple_row = protocol::build_data_row(&[Some(Bytes::from_static(b"1"))]);
        session.handle_backend(simple_row.clone(), &mut out);
        session.handle_backend(
            Message::new(
                protocol::B_COMMAND_COMPLETE,
                Bytes::from_static(b"SELECT 1\0"),
            ),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_READY_FOR_QUERY, Bytes::from_static(b"I")),
            &mut out,
        );

        assert!(
            out.to_client
                .windows(p_row.encode().len())
                .any(|w| w == &p_row.encode()[..]),
            "the Execute's row must be vetted by its own portal's plan: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        assert!(
            out.to_client
                .windows(simple_row.encode().len())
                .any(|w| w == &simple_row.encode()[..]),
            "the simple query's row must be served too: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        assert!(
            !String::from_utf8_lossy(&out.to_client).contains("no described result set"),
            "neither result may be refused"
        );
    }

    /// The live leak this fix closes: `Parse(s1) Describe(s1) Bind(p)
    /// Execute(p) Q("SELECT 1") Sync` pipelined in one flush.
    ///
    /// A simple Query used to clear the pending-describe queue even though the
    /// backend still owed the Describe's RowDescription. That answer then
    /// arrived with nothing to match, was read as the simple query's result,
    /// and its plan was built from the simple query's text — so the Execute's
    /// rows, streamed by the Describe's now-forgotten statement, were vetted by
    /// the wrong plan. On the wire this served a masked value verbatim.
    ///
    /// Under the correct SQL the subquery over `fz.t1` is refused at the
    /// RowDescription; under the simple query's text it reads as a literal and
    /// passes straight through.
    #[test]
    fn a_pipelined_simple_query_cannot_reclassify_a_pending_describe() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        session.handle_frontend(
            Message::new(
                protocol::F_PARSE,
                parse_body(b"s1\0SELECT (SELECT a FROM fz.t1 LIMIT 1) AS x\0"),
            ),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss1\0")),
            &mut Batch::default(),
        );
        let mut bind = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut bind, b"p\0s1\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, bind.freeze()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p")),
            &mut Batch::default(),
        );
        // The simple query runs *after* the Describe, but the proxy processes
        // it before the backend answers anything.
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        // The RowDescription that answers s1 arrives after the Query was
        // processed. It must be matched to the Describe, not to the query.
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        assert!(
            String::from_utf8_lossy(&out.to_client).contains("no column provenance"),
            "s1's own RowDescription must be classified under s1's SQL and refused, not read \
             as the simple query's literal: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        let canary = Bytes::from_static(b"CANARY-T1-A-1");
        session.handle_backend(protocol::build_data_row(&[Some(canary.clone())]), &mut out);
        assert!(
            !out.to_client
                .windows(canary.len())
                .any(|w| w == &canary[..]),
            "the Execute's row must not reach the client after the refusal: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    /// The reverse interleaving: a simple query pipelined ahead of a
    /// Describe-and-Execute. The simple query's RowDescription answers first
    /// and must be matched to the query's own entry, not to the Describe
    /// queued behind it — and the Describe's RowDescription must still be
    /// classified under its own statement's SQL.
    #[test]
    fn a_pending_describe_is_not_consumed_by_an_earlier_simple_result() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(
                protocol::F_PARSE,
                parse_body(b"s2\0SELECT (SELECT a FROM fz.t1 LIMIT 1) AS x\0"),
            ),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss2\0")),
            &mut Batch::default(),
        );
        let mut bind = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut bind, b"p\0s2\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, bind.freeze()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        // The simple query's result streams first, matched to its own entry.
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        session.handle_backend(
            protocol::build_data_row(&[Some(Bytes::from_static(b"1"))]),
            &mut out,
        );
        session.handle_backend(
            Message::new(
                protocol::B_COMMAND_COMPLETE,
                Bytes::from_static(b"SELECT 1\0"),
            ),
            &mut out,
        );
        assert!(
            out.to_client.windows(1).any(|w| w == b"1"),
            "the simple query's own row must be served: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        assert!(
            !String::from_utf8_lossy(&out.to_client).contains("no column provenance"),
            "the simple result must not be judged by s2's SQL: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        // The Describe's answer comes next, classified under its own SQL.
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        assert!(
            String::from_utf8_lossy(&out.to_client).contains("no column provenance"),
            "s2's RowDescription must be refused under s2's SQL: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        let canary = Bytes::from_static(b"CANARY-T1-A-1");
        session.handle_backend(protocol::build_data_row(&[Some(canary.clone())]), &mut out);
        assert!(
            !out.to_client
                .windows(canary.len())
                .any(|w| w == &canary[..]),
            "the Execute's row must not reach the client after the refusal: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    /// Two simple queries pipelined in one flush: each RowDescription is
    /// matched to its own query's entry and SQL, so the first result is not
    /// classified under the second query's text.
    #[test]
    fn two_simple_queries_each_keep_their_own_text() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        session.handle_frontend(
            Message::new(
                protocol::F_QUERY,
                Bytes::from_static(b"SELECT (SELECT a FROM fz.t1 LIMIT 1) AS x\0"),
            ),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        // The first query's RowDescription answers first. Under its own SQL it
        // is refused; before this fix it was read as the second query's literal
        // and passed straight through.
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        assert!(
            String::from_utf8_lossy(&out.to_client).contains("no column provenance"),
            "the first result must be classified under its own SQL: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        let canary = Bytes::from_static(b"CANARY-T1-A-1");
        session.handle_backend(protocol::build_data_row(&[Some(canary.clone())]), &mut out);
        assert!(
            !out.to_client
                .windows(canary.len())
                .any(|w| w == &canary[..]),
            "the first query's masked value must not reach the client: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        // The second query's result streams next and is served normally.
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        session.handle_backend(
            protocol::build_data_row(&[Some(Bytes::from_static(b"1"))]),
            &mut out,
        );
        assert!(
            out.to_client.windows(1).any(|w| w == b"1"),
            "the second query's row must be served: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }

    /// An empty simple query answers with `EmptyQueryResponse`, which carries
    /// no RowDescription — so its own queue entry is the only bookkeeping that
    /// should fire. An Execute pipelined behind it must not lose its slot to
    /// the empty query's result-set end: its rows still stream, vetted by its
    /// own statement's plan.
    #[test]
    fn an_empty_simple_query_does_not_spend_a_pipelined_executes_slot() {
        let mut session = Session::new(policy_with_lineage_allow(
            Unclassified::Allow,
            Opaque::Reject,
        ));
        // Q("") Parse(s) Describe(s) Bind(p) Execute(p) Sync, pipelined.
        session.handle_frontend(
            Message::new(protocol::F_QUERY, Bytes::from_static(b"\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_PARSE, parse_body(b"s\0SELECT 1 AS x\0")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_DESCRIBE, Bytes::from_static(b"Ss\0")),
            &mut Batch::default(),
        );
        let mut bind = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut bind, b"p\0s\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, bind.freeze()),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec_body(b"p")),
            &mut Batch::default(),
        );
        session.handle_frontend(
            Message::new(protocol::F_SYNC, Bytes::new()),
            &mut Batch::default(),
        );

        let mut out = Batch::default();
        // The empty query's exchange answers first, entirely without a
        // RowDescription: EmptyQueryResponse then ReadyForQuery.
        session.handle_backend(
            Message::new(protocol::B_EMPTY_QUERY_RESPONSE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(
            Message::new(protocol::B_READY_FOR_QUERY, Bytes::from_static(b"I")),
            &mut out,
        );
        // The Describe's exchange follows: ParseComplete, its RowDescription,
        // BindComplete, the Execute's rows, CommandComplete.
        session.handle_backend(
            Message::new(protocol::B_PARSE_COMPLETE, Bytes::new()),
            &mut out,
        );
        session.handle_backend(row_description(&[("x", 0, 0, 25)]), &mut out);
        session.handle_backend(
            Message::new(protocol::B_BIND_COMPLETE, Bytes::new()),
            &mut out,
        );
        let row = protocol::build_data_row(&[Some(Bytes::from_static(b"1"))]);
        session.handle_backend(row.clone(), &mut out);
        session.handle_backend(
            Message::new(
                protocol::B_COMMAND_COMPLETE,
                Bytes::from_static(b"SELECT 1\0"),
            ),
            &mut out,
        );

        let served = out
            .to_client
            .windows(row.encode().len())
            .any(|w| w == &row.encode()[..]);
        assert!(
            served,
            "the Execute's row must be served by its own plan: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
        assert!(
            !String::from_utf8_lossy(&out.to_client).contains("no described result set"),
            "the Execute's result must not be refused by the empty query's result-set end: {:?}",
            String::from_utf8_lossy(&out.to_client)
        );
    }
}
