//! pgmask — a fail-closed column masking proxy for Postgres.
//!
//! See `docs/handoff.md` for the design and `docs/mvp.md` for scope. The short
//! version: Postgres's `RowDescription` tells us which stored column each output
//! field came from, so we mask what we can identify and refuse what we cannot.

pub mod analysis;
pub mod catalog;
mod json_path;
pub mod lineage;
pub mod mask;
pub mod metrics;
mod plan_state;
pub(crate) mod policy;
pub mod protocol;
pub mod rate_limit;
pub mod session;
pub mod tls;

pub use catalog::{Catalog, Config};
pub use policy::{Policy, ReloadReport};
pub use session::handle_connection;

/// Extended-query protocol state machine, exposed for the sequence fuzzer.
///
/// Behind a feature so the ordinary build, and the ordinary dependency graph,
/// are untouched. `fuzz/` is its own workspace for the same reason: nothing
/// libFuzzer needs is reachable from `cargo build`.
#[cfg(feature = "fuzzing")]
pub use plan_state::fuzz as plan_state_fuzz;
