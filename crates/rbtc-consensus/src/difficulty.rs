use rbtc_primitives::{
    block::{nbits_to_target, target_to_nbits, BlockHeader},
    constants::{DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_TIMESPAN},
};

/// Compute the required nBits for the next difficulty adjustment period.
///
/// `first_header`: The header at the start of the current period (height % 2016 == 0)
/// `last_header`:  The header at the end of the current period (height % 2016 == 2015)
pub fn next_bits(first_header: &BlockHeader, last_header: &BlockHeader) -> u32 {
    let mut actual_timespan = last_header.time.saturating_sub(first_header.time) as u64;

    // Clamp to ±4× of the target
    let min_timespan = TARGET_TIMESPAN / 4;
    let max_timespan = TARGET_TIMESPAN * 4;
    actual_timespan = actual_timespan.clamp(min_timespan, max_timespan);

    // new_target = old_target * actual_timespan / target_timespan
    let old_target = nbits_to_target(last_header.bits);

    // Perform 256-bit-safe arithmetic using u128 + carry
    let new_target = scale_target(&old_target, actual_timespan, TARGET_TIMESPAN);

    // Cap at maximum allowed target (minimum difficulty).
    // This is essential for early Bitcoin where hashrate was so low that the
    // difficulty would otherwise be calculated to decrease below the minimum.
    let max = max_target();
    if target_gt(&new_target, &max) {
        return target_to_nbits(&max);
    }

    target_to_nbits(&new_target)
}

/// Scale a 32-byte target by (numerator / denominator)
fn scale_target(target: &[u8; 32], numerator: u64, denominator: u64) -> [u8; 32] {
    // Represent target as four u64 limbs (little-endian), then compute
    // result = target * numerator / denominator using schoolbook big-int arithmetic.
    let mut src = [0u64; 4];
    for i in 0..4 {
        let chunk = &target[i*8..(i+1)*8];
        src[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    // Multiply by numerator (little-endian order)
    let mut carry = 0u128;
    let mut product = [0u64; 5];
    for i in 0..4 {
        let val = (src[i] as u128) * (numerator as u128) + carry;
        product[i] = val as u64;
        carry = val >> 64;
    }
    product[4] = carry as u64;

    // Divide by denominator
    let mut rem = 0u128;
    for i in (0..5).rev() {
        let val = (rem << 64) | (product[i] as u128);
        product[i] = (val / denominator as u128) as u64;
        rem = val % denominator as u128;
    }

    // Convert back to bytes (little-endian)
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i*8..(i+1)*8].copy_from_slice(&product[i].to_le_bytes());
    }
    out
}

/// Compare two 32-byte little-endian targets: returns true if a > b.
fn target_gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false
}

/// Check if a difficulty adjustment is due at this height
pub fn is_adjustment_height(height: u32) -> bool {
    height > 0 && height % DIFFICULTY_ADJUSTMENT_INTERVAL as u32 == 0
}

/// Maximum allowed target (minimum difficulty) – Bitcoin mainnet value.
///
/// Corresponds to nBits = 0x1d00ffff.
/// In little-endian 32-byte form: nbits_to_target(0x1d00ffff).
pub fn max_target() -> [u8; 32] {
    // 0x00000000ffff0000000000000000000000000000000000000000000000000000
    // big-endian: byte 4=0xff, byte 5=0xff → little-endian index 27=0xff, index 26=0xff
    let mut t = [0u8; 32];
    t[26] = 0xff;
    t[27] = 0xff;
    t
}

/// Convert work (chainwork) from bits
pub fn bits_to_work(bits: u32) -> u128 {
    let target = nbits_to_target(bits);
    // work ≈ 2^256 / (target + 1)  – simplified to u128
    let mut val = 0u128;
    for i in (16..32).rev() {
        val = val.saturating_mul(256).saturating_add(target[i] as u128);
    }
    if val == 0 { u128::MAX } else { u128::MAX / val }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;

    fn header(time: u32, bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            time,
            bits,
            nonce: 0,
        }
    }

    #[test]
    fn next_bits_normal_timespan() {
        let first = header(1000, 0x1d00ffff);
        let last = header(1000 + 14 * 24 * 60 * 60, 0x1d00ffff);
        let bits = next_bits(&first, &last);
        assert!(bits > 0);
    }

    #[test]
    fn next_bits_clamp_min() {
        let first = header(1000, 0x1d00ffff);
        let last = header(1001, 0x1d00ffff);
        let bits = next_bits(&first, &last);
        assert!(bits > 0);
    }

    #[test]
    fn next_bits_clamp_max() {
        let first = header(1000, 0x1d00ffff);
        let last = header(1000 + (TARGET_TIMESPAN * 5) as u32, 0x1d00ffff);
        let bits = next_bits(&first, &last);
        assert!(bits > 0);
    }

    #[test]
    fn is_adjustment_height_() {
        assert!(!is_adjustment_height(0));
        assert!(!is_adjustment_height(1));
        assert!(is_adjustment_height(2016));
        assert!(!is_adjustment_height(2017));
    }

    #[test]
    fn max_target_() {
        let t = max_target();
        // max_target == nbits_to_target(0x1d00ffff): index 26=0xff, index 27=0xff
        assert_eq!(t[26], 0xff);
        assert_eq!(t[27], 0xff);
        assert_eq!(t[28], 0x00);
        assert_eq!(t[29], 0x00);
        // Verify round-trip
        assert_eq!(target_to_nbits(&t), 0x1d00ffff);
    }

    #[test]
    fn bits_to_work_() {
        let w = bits_to_work(0x1d00ffff);
        assert!(w > 0);
    }
}
