//! Per-principal statement rate limits.
//!
//! The notice-channel oracle under `posture = "hostile"` recovers a full email
//! in a few hundred `DO` blocks: each is a simple query that never projects a
//! masked column, so the projection gate has nothing to refuse. Rate-limiting
//! authenticated principals is the blunt instrument that makes that campaign
//! expensive without inventing a PL/pgSQL interpreter.
//!
//! Keyed on the Postgres username after `AuthenticationOk` — the same principal
//! masking policy already trusts. Off by default (`rate_limit_per_minute = 0`)
//! so existing deployments and the inference suite keep their measured numbers.

use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::{bail, Result};
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

type KeyedLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Shared across sessions so one user with many connections shares one budget.
#[derive(Clone)]
pub struct PrincipalRateLimit {
    limiter: Arc<KeyedLimiter>,
    per_minute: u32,
    burst: u32,
}

impl PrincipalRateLimit {
    pub fn new(per_minute: u32, burst: u32) -> Result<Self> {
        let Some(per_min) = NonZeroU32::new(per_minute) else {
            bail!("rate_limit_per_minute must be > 0 when constructing a limiter");
        };
        let Some(burst) = NonZeroU32::new(burst) else {
            bail!("rate_limit_burst must be > 0 when rate limiting is enabled");
        };
        let quota = Quota::per_minute(per_min).allow_burst(burst);
        Ok(Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
            per_minute,
            burst: burst.get(),
        })
    }

    pub fn per_minute(&self) -> u32 {
        self.per_minute
    }

    pub fn burst(&self) -> u32 {
        self.burst
    }

    /// Spend one statement token for this principal.
    ///
    /// `true` means the statement may proceed. `false` means it is over budget.
    pub fn try_acquire(&self, principal: &str) -> bool {
        self.limiter.check_key(&principal.to_string()).is_ok()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn burst_then_refuse() {
        let lim = PrincipalRateLimit::new(60, 3).unwrap();
        assert!(lim.try_acquire("alice"));
        assert!(lim.try_acquire("alice"));
        assert!(lim.try_acquire("alice"));
        assert!(
            !lim.try_acquire("alice"),
            "fourth within the burst must refuse"
        );
        // A different principal has its own bucket.
        assert!(lim.try_acquire("bob"));
    }
}
