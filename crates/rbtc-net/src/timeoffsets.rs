//! Peer clock offset tracking (mirrors Bitcoin Core's `node/timeoffsets.h`).
//!
//! We collect the time offset from each outbound peer's version message and
//! maintain a bounded sample set.  The median offset is used to detect when
//! the local clock is significantly off, triggering a warning log.

use std::collections::VecDeque;
use tracing::warn;

/// Maximum number of outbound peer offsets we track.
/// Bitcoin Core uses 50 (TimeOffsets::MAX_SIZE).
const MAX_SAMPLES: usize = 50;

/// If the median offset exceeds ±10 minutes we warn.
/// Matches Bitcoin Core's `WARN_THRESHOLD` in timeoffsets.cpp.
const WARN_THRESHOLD_SECS: i64 = 10 * 60;

/// Tracks clock offsets from outbound peers and computes the median.
#[derive(Debug, Clone)]
pub struct TimeOffsets {
    offsets: VecDeque<i64>,
    warned: bool,
}

impl TimeOffsets {
    pub fn new() -> Self {
        Self {
            offsets: VecDeque::with_capacity(MAX_SAMPLES),
            warned: false,
        }
    }

    /// Add a peer time offset (seconds).  Only outbound peers should be added
    /// to prevent an attacker from manipulating the median via inbound floods.
    pub fn add(&mut self, offset_secs: i64) {
        if self.offsets.len() >= MAX_SAMPLES {
            self.offsets.pop_front();
        }
        self.offsets.push_back(offset_secs);
        self.check_warning();
    }

    /// Number of samples currently stored.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Whether any samples have been collected.
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Return the median offset, or 0 if fewer than 5 samples.
    /// Bitcoin Core requires ≥5 outbound peers before acting on the median.
    pub fn median(&self) -> i64 {
        if self.offsets.len() < 5 {
            return 0;
        }
        let mut sorted: Vec<i64> = self.offsets.iter().copied().collect();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    fn check_warning(&mut self) {
        let m = self.median();
        if m.abs() > WARN_THRESHOLD_SECS && !self.warned {
            warn!(
                "Your clock may be wrong! Median peer time offset is {} seconds. \
                 Please check your system clock.",
                m
            );
            self.warned = true;
        }
        // Reset warning flag if clock is back to normal
        if m.abs() <= WARN_THRESHOLD_SECS && self.warned {
            self.warned = false;
        }
    }
}

impl Default for TimeOffsets {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_requires_five_samples() {
        let mut t = TimeOffsets::new();
        for i in 1..=4 {
            t.add(i * 100);
        }
        assert_eq!(t.median(), 0);
        t.add(500);
        assert_ne!(t.median(), 0);
    }

    #[test]
    fn median_computed_correctly() {
        let mut t = TimeOffsets::new();
        for v in [10, -20, 30, -5, 15] {
            t.add(v);
        }
        // sorted: [-20, -5, 10, 15, 30] → median = 10
        assert_eq!(t.median(), 10);
    }

    #[test]
    fn max_samples_bounded() {
        let mut t = TimeOffsets::new();
        for i in 0..100 {
            t.add(i);
        }
        assert_eq!(t.len(), MAX_SAMPLES);
    }

    #[test]
    fn empty_returns_zero_median() {
        let t = TimeOffsets::new();
        assert_eq!(t.median(), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn warning_threshold() {
        let mut t = TimeOffsets::new();
        // Add 5 large offsets to trigger warning
        for _ in 0..5 {
            t.add(WARN_THRESHOLD_SECS + 60);
        }
        assert!(t.warned);
        // Reset by adding normal offsets until median normalizes
        for _ in 0..10 {
            t.add(0);
        }
        assert!(!t.warned);
    }

    #[test]
    fn negative_offsets_handled() {
        let mut t = TimeOffsets::new();
        for v in [-100, -200, -150, -50, -300] {
            t.add(v);
        }
        // sorted: [-300, -200, -150, -100, -50] → median = -150
        assert_eq!(t.median(), -150);
    }
}
