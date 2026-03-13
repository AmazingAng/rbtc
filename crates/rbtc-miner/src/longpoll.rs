use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Tracks the current long-poll ID and notifies waiting GBT clients
/// when the template should be refreshed (new block tip, new mempool tx).
pub struct LongPollState {
    inner: Mutex<LongPollInner>,
    notify: Condvar,
}

struct LongPollInner {
    /// Current long-poll ID (tip_hash hex + mempool_sequence).
    current_id: String,
    /// Monotonically increasing generation counter.
    generation: u64,
}

impl LongPollState {
    /// Create a new `LongPollState` with the given initial long-poll ID.
    pub fn new(initial_id: String) -> Self {
        Self {
            inner: Mutex::new(LongPollInner {
                current_id: initial_id,
                generation: 0,
            }),
            notify: Condvar::new(),
        }
    }

    /// Get the current long-poll ID.
    pub fn current_id(&self) -> String {
        self.inner.lock().unwrap().current_id.clone()
    }

    /// Get the current generation number.
    pub fn generation(&self) -> u64 {
        self.inner.lock().unwrap().generation
    }

    /// Update the long-poll ID, increment the generation counter, and wake
    /// all threads blocked in [`wait_for_change`](Self::wait_for_change).
    pub fn notify_new_template(&self, new_id: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.current_id = new_id;
        inner.generation += 1;
        self.notify.notify_all();
    }

    /// Block until the long-poll ID differs from `known_id` or `timeout`
    /// elapses.
    ///
    /// Returns `Some(new_id)` if the ID changed, or `None` on timeout.
    pub fn wait_for_change(&self, known_id: &str, timeout: Duration) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();

        // If the ID already changed before we even started waiting, return
        // immediately.
        if inner.current_id != known_id {
            return Some(inner.current_id.clone());
        }

        let mut remaining = timeout;
        loop {
            let start = std::time::Instant::now();
            let (guard, wait_result) = self.notify.wait_timeout(inner, remaining).unwrap();
            inner = guard;

            if inner.current_id != known_id {
                return Some(inner.current_id.clone());
            }

            if wait_result.timed_out() {
                return None;
            }

            // Spurious wake-up: subtract elapsed time and keep waiting.
            let elapsed = start.elapsed();
            remaining = remaining.saturating_sub(elapsed);
            if remaining.is_zero() {
                return None;
            }
        }
    }

    /// Convenience method for a tip change: updates the long-poll ID to
    /// `tip_hash` and wakes all waiters.
    pub fn notify_new_tip(&self, tip_hash: &str) {
        self.notify_new_template(tip_hash.to_string());
    }

    /// Convenience method for a mempool change: increments the generation
    /// counter, updates the long-poll ID to reflect the new generation, and
    /// wakes all waiters.
    pub fn notify_mempool_change(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.generation += 1;
        // Append the generation to the existing base ID so the ID actually
        // changes (waiters compare by string equality).
        let base = inner.current_id.split(':').next().unwrap_or("").to_string();
        inner.current_id = format!("{}:{}", base, inner.generation);
        self.notify.notify_all();
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn longpoll_initial_state() {
        let state = LongPollState::new("abc123".to_string());
        assert_eq!(state.current_id(), "abc123");
        assert_eq!(state.generation(), 0);
    }

    #[test]
    fn longpoll_notify_wakes_waiter() {
        let state = Arc::new(LongPollState::new("id0".to_string()));
        let state2 = Arc::clone(&state);

        let handle = thread::spawn(move || {
            // Wait up to 5 seconds for a change from "id0".
            state2.wait_for_change("id0", Duration::from_secs(5))
        });

        // Give the spawned thread a moment to start waiting.
        thread::sleep(Duration::from_millis(50));
        state.notify_new_template("id1".to_string());

        let result = handle.join().unwrap();
        assert_eq!(result, Some("id1".to_string()));
    }

    #[test]
    fn longpoll_timeout_returns_none() {
        let state = LongPollState::new("id_unchanged".to_string());
        let result = state.wait_for_change("id_unchanged", Duration::from_millis(50));
        assert!(result.is_none());
    }

    #[test]
    fn longpoll_generation_increments() {
        let state = LongPollState::new("g0".to_string());
        assert_eq!(state.generation(), 0);

        state.notify_new_template("g1".to_string());
        assert_eq!(state.generation(), 1);

        state.notify_new_template("g2".to_string());
        assert_eq!(state.generation(), 2);

        state.notify_new_template("g3".to_string());
        assert_eq!(state.generation(), 3);
    }
}
