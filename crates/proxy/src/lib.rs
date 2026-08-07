//! pgmask — a fail-closed column masking proxy for Postgres.
//!
//! See `docs/handoff.md` for the design and `docs/mvp.md` for scope. The short
//! version: Postgres's `RowDescription` tells us which stored column each output
//! field came from, so we mask what we can identify and refuse what we cannot.

pub mod analysis;
pub mod catalog;
pub mod mask;
pub mod metrics;
pub mod protocol;
pub mod session;
pub mod tls;

pub use catalog::{Catalog, Config};
pub use session::{handle_connection, Policy};
