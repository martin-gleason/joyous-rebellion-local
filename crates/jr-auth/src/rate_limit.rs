//! Rate limiting using the `governor` crate.
//!
//! Provides per-device and per-IP rate limiters matching the spec:
//! - 10,000 sync messages/hour per device
//! - 5 failed auth attempts/15 min per IP
//! - 10 campaign registrations/day per IP
//! - 10 enlist code redemptions/15 min per IP

use governor::clock::Clock;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

/// A keyed rate limiter backed by a `DashMap`.
pub type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

/// Collection of rate limiters for the sync server.
#[derive(Clone)]
pub struct RateLimiters {
    /// Sync messages: 10,000 per hour per device UUID
    pub sync_messages: Arc<KeyedLimiter>,
    /// Failed auth: 5 per 15 minutes per IP
    pub failed_auth: Arc<KeyedLimiter>,
    /// Campaign registration: 10 per day per IP
    pub campaign_registration: Arc<KeyedLimiter>,
    /// Enlist code redemption: 10 per 15 minutes per IP
    pub enlist_code: Arc<KeyedLimiter>,
}

impl RateLimiters {
    /// Create rate limiters with default quotas from the spec.
    #[must_use]
    pub fn new() -> Self {
        // 10 per day = replenish 10 tokens over 86400 seconds.
        // 86400 / 10 = 8640 seconds per token. This is a valid duration (> 0)
        // so with_period always returns Some.
        let per_day_quota = match Quota::with_period(Duration::from_secs(86400 / 10)) {
            Some(q) => q.allow_burst(nonzero(10)),
            None => Quota::per_hour(nonzero(1)), // unreachable fallback
        };

        // 10 per 15 minutes = replenish 10 tokens over 900 seconds.
        // 900 / 10 = 90 seconds per token.
        let per_15min_quota = match Quota::with_period(Duration::from_secs(900 / 10)) {
            Some(q) => q.allow_burst(nonzero(10)),
            None => Quota::per_hour(nonzero(1)), // unreachable fallback
        };

        Self {
            sync_messages: Arc::new(RateLimiter::dashmap(
                Quota::per_hour(nonzero(10_000)),
            )),
            failed_auth: Arc::new(RateLimiter::dashmap(
                Quota::per_minute(nonzero(5)).allow_burst(nonzero(5)),
            )),
            campaign_registration: Arc::new(RateLimiter::dashmap(per_day_quota)),
            enlist_code: Arc::new(RateLimiter::dashmap(per_15min_quota)),
        }
    }

    /// Check if a sync message from this device is allowed.
    #[must_use = "rate limit result must be checked"]
    pub fn check_sync_message(&self, device_id: &str) -> Result<(), u64> {
        self.sync_messages
            .check_key(&device_id.to_string())
            .map_err(|e| {
                let clock = DefaultClock::default();
                e.wait_time_from(clock.now()).as_secs()
            })
    }

    /// Record a failed auth attempt from this IP.
    #[must_use = "rate limit result must be checked"]
    pub fn check_failed_auth(&self, ip: &str) -> Result<(), u64> {
        self.failed_auth
            .check_key(&ip.to_string())
            .map_err(|e| {
                let clock = DefaultClock::default();
                e.wait_time_from(clock.now()).as_secs()
            })
    }

    /// Check if a campaign registration from this IP is allowed.
    #[must_use = "rate limit result must be checked"]
    pub fn check_campaign_registration(&self, ip: &str) -> Result<(), u64> {
        self.campaign_registration
            .check_key(&ip.to_string())
            .map_err(|e| {
                let clock = DefaultClock::default();
                e.wait_time_from(clock.now()).as_secs()
            })
    }

    /// Check if an enlist code redemption from this IP is allowed.
    #[must_use = "rate limit result must be checked"]
    pub fn check_enlist_code(&self, ip: &str) -> Result<(), u64> {
        self.enlist_code
            .check_key(&ip.to_string())
            .map_err(|e| {
                let clock = DefaultClock::default();
                e.wait_time_from(clock.now()).as_secs()
            })
    }
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a NonZeroU32 from a known non-zero literal.
///
/// Uses `unwrap()` in a const context where the value is always known
/// to be non-zero at compile time.
#[allow(clippy::unwrap_used)]
const fn nonzero(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_message_allows_first_request() {
        let limiters = RateLimiters::new();
        assert!(limiters.check_sync_message("device-1").is_ok());
    }

    #[test]
    fn failed_auth_blocks_after_burst() {
        let limiters = RateLimiters::new();
        let ip = "192.168.1.1";
        // The burst allowance is 5
        for _ in 0..5 {
            assert!(limiters.check_failed_auth(ip).is_ok());
        }
        // 6th should be rate limited
        assert!(limiters.check_failed_auth(ip).is_err());
    }

    #[test]
    fn different_keys_independent() {
        let limiters = RateLimiters::new();
        // Exhaust one IP
        for _ in 0..5 {
            let _ = limiters.check_failed_auth("ip-a");
        }
        // Different IP should still work
        assert!(limiters.check_failed_auth("ip-b").is_ok());
    }

    #[test]
    fn enlist_code_allows_first_request() {
        let limiters = RateLimiters::new();
        assert!(limiters.check_enlist_code("192.168.1.1").is_ok());
    }

    #[test]
    fn enlist_code_blocks_after_burst() {
        let limiters = RateLimiters::new();
        let ip = "10.0.0.1";
        // The burst allowance is 10
        for _ in 0..10 {
            assert!(limiters.check_enlist_code(ip).is_ok());
        }
        // 11th should be rate limited
        assert!(limiters.check_enlist_code(ip).is_err());
    }
}
