//! Per-peer rate limiting for DOS protection.
//!
//! Bitcoin Core rate-limits certain message types to prevent peers from
//! flooding the node.  This module provides a simple token-bucket style
//! rate limiter with per-message-type limits.

use std::collections::HashMap;
use std::time::Instant;

/// Maximum rate for `addr` messages (messages per second).
pub const MAX_ADDR_RATE: f64 = 0.1;

/// Maximum rate for `inv` messages (messages per second).
pub const MAX_INV_RATE: f64 = 5.0;

/// Maximum rate for `getdata` messages (messages per second).
pub const MAX_GETDATA_RATE: f64 = 5.0;

/// Get the rate limit for a message type.  Returns `None` if the message
/// type is not rate-limited.
pub fn rate_for_message(msg_type: &str) -> Option<f64> {
    match msg_type {
        "addr" | "addrv2" => Some(MAX_ADDR_RATE),
        "inv" => Some(MAX_INV_RATE),
        "getdata" => Some(MAX_GETDATA_RATE),
        _ => None,
    }
}

/// Per-message-type token bucket.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Tokens available (can go negative when rate-limited).
    tokens: f64,
    /// Maximum tokens (burst capacity).
    max_tokens: f64,
    /// Tokens added per second.
    rate: f64,
    /// Last time tokens were replenished.
    last_update: Instant,
}

impl TokenBucket {
    fn new(rate: f64) -> Self {
        // Allow a small burst of 5 messages before rate limiting kicks in.
        let burst = (rate * 10.0).max(5.0);
        Self {
            tokens: burst,
            max_tokens: burst,
            rate,
            last_update: Instant::now(),
        }
    }

    /// Replenish tokens based on elapsed time, then try to consume one.
    /// Returns `true` if the message should be allowed.
    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-peer rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Per-message-type token buckets.
    buckets: HashMap<String, TokenBucket>,
}

impl RateLimiter {
    /// Create a new rate limiter for a peer.
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// Check whether a message of the given type should be rate-limited.
    /// Returns `true` if the message is rate-limited (i.e., should be dropped).
    pub fn is_rate_limited(&mut self, msg_type: &str) -> bool {
        let Some(rate) = rate_for_message(msg_type) else {
            return false; // not a rate-limited message type
        };

        let now = Instant::now();
        let bucket = self
            .buckets
            .entry(msg_type.to_string())
            .or_insert_with(|| TokenBucket::new(rate));

        !bucket.try_consume(now)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_limited_messages_pass() {
        let mut rl = RateLimiter::new();
        for _ in 0..100 {
            assert!(!rl.is_rate_limited("block"));
            assert!(!rl.is_rate_limited("tx"));
            assert!(!rl.is_rate_limited("ping"));
            assert!(!rl.is_rate_limited("headers"));
        }
    }

    #[test]
    fn addr_rate_limited_after_burst() {
        let mut rl = RateLimiter::new();
        // Initial burst should pass (burst capacity = max(0.1*10, 5) = 5)
        let mut passed = 0;
        for _ in 0..20 {
            if !rl.is_rate_limited("addr") {
                passed += 1;
            }
        }
        // Should have allowed roughly the burst capacity (5) then started limiting
        assert!(passed >= 4, "expected at least 4 addr messages to pass, got {passed}");
        assert!(passed < 10, "expected fewer than 10 addr messages to pass, got {passed}");
    }

    #[test]
    fn inv_rate_limited_after_burst() {
        let mut rl = RateLimiter::new();
        // inv burst capacity = max(5.0*10, 5) = 50
        let mut passed = 0;
        for _ in 0..100 {
            if !rl.is_rate_limited("inv") {
                passed += 1;
            }
        }
        assert!(passed >= 40, "expected at least 40 inv messages to pass, got {passed}");
        assert!(passed < 60, "expected fewer than 60 inv messages to pass, got {passed}");
    }

    #[test]
    fn rate_for_message_known_types() {
        assert_eq!(rate_for_message("addr"), Some(MAX_ADDR_RATE));
        assert_eq!(rate_for_message("addrv2"), Some(MAX_ADDR_RATE));
        assert_eq!(rate_for_message("inv"), Some(MAX_INV_RATE));
        assert_eq!(rate_for_message("getdata"), Some(MAX_GETDATA_RATE));
        assert_eq!(rate_for_message("block"), None);
        assert_eq!(rate_for_message("tx"), None);
    }

    #[test]
    fn separate_peer_rate_limiters() {
        let mut rl1 = RateLimiter::new();
        let mut rl2 = RateLimiter::new();
        // Exhaust rl1's addr budget
        for _ in 0..20 {
            rl1.is_rate_limited("addr");
        }
        // rl2 should still have full budget
        assert!(!rl2.is_rate_limited("addr"));
    }

    #[test]
    fn default_impl() {
        let rl = RateLimiter::default();
        assert!(rl.buckets.is_empty());
    }
}
