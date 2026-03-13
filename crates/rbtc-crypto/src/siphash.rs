//! Thin wrapper around SipHash-2-4, matching Bitcoin Core's `CSipHasher` / `PresaltedSipHasher`.

use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// Compute SipHash-2-4 of arbitrary data with a 128-bit key `(k0, k1)`.
///
/// Equivalent to `CSipHasher(k0, k1).Write(data).Finalize()` in Bitcoin Core.
#[inline]
pub fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut h = SipHasher24::new_with_keys(k0, k1);
    h.write(data);
    h.finish()
}

/// Compute SipHash-2-4 of a 256-bit value with a 128-bit key `(k0, k1)`.
///
/// Equivalent to `PresaltedSipHasher(k0, k1)(uint256)` in Bitcoin Core.
#[inline]
pub fn siphash_2_4_u256(k0: u64, k1: u64, data: &[u8; 32]) -> u64 {
    siphash_2_4(k0, k1, data)
}

/// Compute SipHash-2-4 of a 256-bit value plus a 32-bit extra word.
///
/// Equivalent to `PresaltedSipHasher(k0, k1)(uint256, extra)` in Bitcoin Core.
#[inline]
pub fn siphash_2_4_u256_extra(k0: u64, k1: u64, data: &[u8; 32], extra: u32) -> u64 {
    let mut h = SipHasher24::new_with_keys(k0, k1);
    h.write(data);
    h.write(&extra.to_le_bytes());
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siphash_2_4_empty() {
        // SipHash-2-4 with zero key and empty input should produce a deterministic value.
        let h = siphash_2_4(0, 0, &[]);
        // Verify determinism: same inputs always produce same output.
        assert_eq!(h, siphash_2_4(0, 0, &[]));
        // Different key should produce a different hash.
        assert_ne!(h, siphash_2_4(1, 0, &[]));
    }

    #[test]
    fn test_siphash_2_4_known_vector() {
        // Official SipHash-2-4 test vector from the paper (Aumasson & Bernstein).
        // Key: 00 01 02 .. 0f, Message: 00 01 02 .. 0e (15 bytes).
        let k0 = u64::from_le_bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let k1 = u64::from_le_bytes([0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        let msg: Vec<u8> = (0u8..15).collect();
        let result = siphash_2_4(k0, k1, &msg);
        assert_eq!(result, 0xa129ca6149be45e5);
    }

    #[test]
    fn test_siphash_2_4_u256_and_extra() {
        let k0 = 0xdeadbeef_u64;
        let k1 = 0xcafebabe_u64;
        let data = [0xab_u8; 32];

        // u256 variant should match generic variant for same 32-byte input.
        assert_eq!(
            siphash_2_4_u256(k0, k1, &data),
            siphash_2_4(k0, k1, &data),
        );

        // With extra, the result should differ from without.
        let h_plain = siphash_2_4_u256(k0, k1, &data);
        let h_extra = siphash_2_4_u256_extra(k0, k1, &data, 42);
        assert_ne!(h_plain, h_extra);
    }
}
