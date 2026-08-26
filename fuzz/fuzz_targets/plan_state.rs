//! Fuzz the order, not the SQL.
//!
//! Every other campaign in this repository generates statements and asks
//! whether the analysis judged them correctly. This one generates *protocol
//! interleavings* — Parse, Bind, Describe, Execute, Sync, Close, simple Query,
//! EmptyQueryResponse, and the backend replies that acknowledge or reject
//! them — and asks whether the proxy still knows which SQL and which plan
//! belong to which result set.
//!
//! The disclosure that prompted it was reachable in two messages and no
//! generated statement could have found it, because both statements involved
//! were ordinary.
//!
//! Run it with `../scripts/test-plan-state-fuzz.sh`. It needs a nightly
//! toolchain; the release gate does not depend on it.
//!
//! The operation set here is one-to-one with the methods `Session` calls on
//! `PlanState`, and the invariants live next to `PlanState` itself, in
//! `pgmask::plan_state_fuzz` — the oracle reads private fields for ground
//! truth, because inferring the queue's head from `described_sql` would mean
//! checking the function under test against itself.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pgmask::plan_state_fuzz::ProtocolModel;

/// One protocol event.
///
/// Names and SQL texts are indices into small pools inside the harness rather
/// than free-form bytes. The interesting inputs are *collisions* — the same
/// statement name reused across a failed epoch, a portal rebound to a different
/// statement — and a fuzzer handed 63 bytes of name would spend its budget
/// proving that two random names differ.
#[derive(Arbitrary, Debug)]
enum Op {
    // --- frontend ---
    Parse {
        name: u8,
        sql: u8,
    },
    /// A Parse the proxy could not decode, so the backend has a prepared
    /// statement whose SQL the proxy never saw. Non-UTF-8 client encoding.
    ParseUndecodable,
    Bind {
        portal: u8,
        statement: u8,
        formats: Option<Vec<i16>>,
    },
    DescribeStatement {
        name: u8,
    },
    DescribePortal {
        portal: u8,
    },
    Execute {
        portal: u8,
    },
    Sync,
    CloseStatement {
        name: u8,
    },
    ClosePortal {
        portal: u8,
    },
    /// `sql: None` is a simple Query whose body would not decode.
    SimpleQuery {
        sql: Option<u8>,
    },

    // --- backend ---
    ParseComplete,
    BindComplete,
    /// RowDescription, turned into a plan of `fields` columns.
    RowDescription {
        fields: u8,
    },
    /// NoData: this Describe has no result set.
    NoData,
    /// The proxy refused the described result set and dropped its plan.
    DiscardDescription,
    /// ErrorResponse: the backend skips to the next Sync.
    ErrorResponse,
    /// CommandComplete: one result set ended.
    ResultSetEnd,
    /// PortalSuspended: the streaming Execute paused; the next DataRows may
    /// belong to a different already-queued portal.
    PortalSuspended,
    /// EmptyQueryResponse: one *empty simple query's* result ended, with no
    /// RowDescription of its own.
    EmptyQueryResponse,

    // --- proxy-initiated ---
    /// `Session::reject` — refuse locally and start swallowing backend replies.
    Reject,
    /// The ReadyForQuery that ends a locally suppressed exchange.
    ReadyForQuery {
        epoch: u8,
    },
    /// Backend ReadyForQuery Idle: implicit transaction ended.
    ReadyForQueryIdle,
    /// Backend ReadyForQuery InTxn: BEGIN keeps a suspended portal.
    ReadyForQueryInTxn,
    ClearActive,
    /// A catalog refresh landing between two messages.
    CatalogRefresh {
        generation: u8,
    },
}

/// Sequences longer than this stop teaching the fuzzer anything and just slow
/// the loop down; the state machine's whole depth is a handful of pipelined
/// exchanges.
const MAX_OPS: usize = 128;

fuzz_target!(|ops: Vec<Op>| {
    let mut model = ProtocolModel::new();
    for op in ops.into_iter().take(MAX_OPS) {
        match op {
            Op::Parse { name, sql } => model.parse(name, sql),
            Op::ParseUndecodable => model.parse_undecodable(),
            Op::Bind {
                portal,
                statement,
                formats,
            } => model.bind(portal, statement, formats),
            Op::DescribeStatement { name } => model.describe_statement(name),
            Op::DescribePortal { portal } => model.describe_portal(portal),
            Op::Execute { portal } => model.execute(portal),
            Op::Sync => model.sync(),
            Op::CloseStatement { name } => model.close_statement(name),
            Op::ClosePortal { portal } => model.close_portal(portal),
            Op::SimpleQuery { sql } => model.simple_query(sql),

            Op::ParseComplete => model.finish_parse(),
            Op::BindComplete => model.finish_bind(),
            Op::RowDescription { fields } => model.finish_description(fields),
            Op::NoData => model.finish_no_data(),
            Op::DiscardDescription => model.discard_description(),
            Op::ErrorResponse => model.discard_failed_epoch(),
            Op::ResultSetEnd => model.finish_result_set(),
            Op::PortalSuspended => model.suspend_result(),
            Op::EmptyQueryResponse => model.finish_empty_query(),

            Op::Reject => model.reject(),
            Op::ReadyForQuery { epoch } => model.finish_suppressed_epoch(epoch),
            Op::ReadyForQueryIdle => model.ready_for_query(b'I'),
            Op::ReadyForQueryInTxn => model.ready_for_query(b'T'),
            Op::ClearActive => model.clear_active(),
            Op::CatalogRefresh { generation } => model.invalidate_if_stale(generation),
        }
    }
});
