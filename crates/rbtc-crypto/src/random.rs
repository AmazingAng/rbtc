//! Centralized RNG module for the rbtc workspace.
//!
//! Mirrors Bitcoin Core's `random.h` / `random.cpp` design: a single module
//! that all crates use for randomness, making audit and future hardening
//! (entropy mixing, deterministic test mode) straightforward.
//!
//! Two tiers of randomness:
//! - **Strong** (`get_strong_rand_bytes`, `random_bytes`): backed by OS entropy
//!   via `OsRng`. Use for key material, nonces, salts — anything security‑critical.
//! - **Fast** (`fast_random_u64`, `fast_random_u32`, `fast_random_bool`,
//!   `fast_random_shuffle`): backed by `thread_rng()` (ChaCha‑based CSPRNG seeded
//!   from OS entropy). Suitable for non‑secret protocol randomness such as
//!   shuffling peer lists, coin‑selection ordering, and garbage padding.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};

// ---------------------------------------------------------------------------
// Strong randomness (OS entropy) — equivalent to Bitcoin Core GetStrongRandBytes
// ---------------------------------------------------------------------------

/// Fill `buf` with cryptographically‑strong random bytes from the OS.
///
/// This is the recommended primitive for key material, nonces, and salts.
#[inline]
pub fn get_strong_rand_bytes(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// Convenience alias — identical to [`get_strong_rand_bytes`].
#[inline]
pub fn random_bytes(buf: &mut [u8]) {
    get_strong_rand_bytes(buf);
}

/// Return 32 bytes of strong randomness.
pub fn random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    get_strong_rand_bytes(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Fast randomness (thread‑local CSPRNG) — equivalent to Bitcoin Core GetRandBytes
// ---------------------------------------------------------------------------

/// Fill `buf` with random bytes from the fast thread‑local CSPRNG.
#[inline]
pub fn get_rand_bytes(buf: &mut [u8]) {
    rand::thread_rng().fill_bytes(buf);
}

/// Return a random `u64` from the fast CSPRNG.
#[inline]
pub fn fast_random_u64() -> u64 {
    rand::thread_rng().gen()
}

/// Return a random `u32` from the fast CSPRNG.
#[inline]
pub fn fast_random_u32() -> u32 {
    rand::thread_rng().gen()
}

/// Return `true` with probability `p` (0.0 ..= 1.0).
#[inline]
pub fn fast_random_bool(p: f64) -> bool {
    rand::thread_rng().gen_bool(p)
}

/// Return a random `u64` in `0..range`.
#[inline]
pub fn fast_random_range(range: u64) -> u64 {
    rand::thread_rng().gen_range(0..range)
}

/// Shuffle `slice` in‑place using the fast CSPRNG.
pub fn fast_random_shuffle<T>(slice: &mut [T]) {
    slice.shuffle(&mut rand::thread_rng());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_rand_bytes_fills_buffer() {
        let mut buf = [0u8; 64];
        get_strong_rand_bytes(&mut buf);
        // Overwhelmingly unlikely that 64 random bytes are all zero.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn random_bytes_32_not_zero() {
        let a = random_bytes_32();
        let b = random_bytes_32();
        assert_ne!(a, [0u8; 32]);
        // Two independent 256‑bit draws must differ (collision probability ~2^-256).
        assert_ne!(a, b);
    }

    #[test]
    fn get_rand_bytes_fills_buffer() {
        let mut buf = [0u8; 64];
        get_rand_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn fast_random_u64_varies() {
        // Draw two values; equality probability is 2^-64.
        assert_ne!(fast_random_u64(), fast_random_u64());
    }

    #[test]
    fn fast_random_u32_varies() {
        assert_ne!(fast_random_u32(), fast_random_u32());
    }

    #[test]
    fn fast_random_range_bounded() {
        for _ in 0..100 {
            let v = fast_random_range(10);
            assert!(v < 10);
        }
    }

    #[test]
    fn fast_random_bool_returns_both() {
        // With p=0.5 and 200 trials the probability of never seeing one side is ~2^-200.
        let mut saw_true = false;
        let mut saw_false = false;
        for _ in 0..200 {
            if fast_random_bool(0.5) {
                saw_true = true;
            } else {
                saw_false = true;
            }
            if saw_true && saw_false {
                break;
            }
        }
        assert!(saw_true && saw_false);
    }

    #[test]
    fn fast_random_shuffle_permutes() {
        let mut v: Vec<u32> = (0..20).collect();
        let original = v.clone();
        fast_random_shuffle(&mut v);
        // A 20‑element shuffle matching the identity has probability 1/20! ≈ 4e-19.
        assert_ne!(v, original);
    }

    #[test]
    fn empty_buffer_is_noop() {
        // Must not panic on zero‑length slices.
        let mut buf = [];
        get_strong_rand_bytes(&mut buf);
        get_rand_bytes(&mut buf);
    }

    #[test]
    fn empty_shuffle_is_noop() {
        let mut v: Vec<u32> = vec![];
        fast_random_shuffle(&mut v);
        assert!(v.is_empty());
    }
}
