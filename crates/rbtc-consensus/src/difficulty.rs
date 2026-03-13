use rbtc_primitives::{
    block::{nbits_to_target, target_to_nbits, BlockHeader},
    constants::DIFFICULTY_ADJUSTMENT_INTERVAL,
};

/// Default target timespan for mainnet (two weeks).
const DEFAULT_TARGET_TIMESPAN: u64 = 14 * 24 * 60 * 60;

/// Compute the required nBits for the next difficulty adjustment period.
///
/// Uses the default (mainnet) target timespan. For network-aware code, prefer
/// `next_bits_bip94` with an explicit `pow_target_timespan`.
pub fn next_bits(first_header: &BlockHeader, last_header: &BlockHeader) -> u32 {
    next_bits_bip94(first_header, last_header, false, DEFAULT_TARGET_TIMESPAN)
}

/// Compute the required nBits with explicit BIP94 and timespan control.
///
/// `pow_target_timespan`: from `ConsensusParams::pow_target_timespan` (seconds).
/// When `enforce_bip94` is true, the base target is taken from `first_header.bits`
/// (matching Bitcoin Core's `CalculateNextWorkRequired` with `enforce_BIP94`).
/// Otherwise, `last_header.bits` is used (standard behavior).
pub fn next_bits_bip94(
    first_header: &BlockHeader,
    last_header: &BlockHeader,
    enforce_bip94: bool,
    pow_target_timespan: u64,
) -> u32 {
    let mut actual_timespan = last_header.time.saturating_sub(first_header.time) as u64;

    // Clamp to ±4× of the target
    let min_timespan = pow_target_timespan / 4;
    let max_timespan = pow_target_timespan * 4;
    actual_timespan = actual_timespan.clamp(min_timespan, max_timespan);

    // BIP94: use first block's nBits (preserves real difficulty at period start).
    // Standard: use last block's nBits.
    let base_bits = if enforce_bip94 {
        first_header.bits
    } else {
        last_header.bits
    };
    let old_target = nbits_to_target(base_bits);

    // Perform 256-bit-safe arithmetic using u128 + carry
    let new_target = scale_target(&old_target, actual_timespan, pow_target_timespan);

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
        let chunk = &target[i * 8..(i + 1) * 8];
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
        out[i * 8..(i + 1) * 8].copy_from_slice(&product[i].to_le_bytes());
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
    height > 0 && height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL as u32)
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

/// Convert work (chainwork) from bits.
///
/// Returns `(~target / (target + 1)) + 1` as a 256-bit unsigned integer,
/// matching Bitcoin Core's `GetBlockProof()` in `chain.cpp`.
pub fn bits_to_work(bits: u32) -> rbtc_primitives::uint256::U256 {
    use rbtc_primitives::uint256::U256;
    let target_bytes = nbits_to_target(bits);
    let target = U256::from_le_bytes(target_bytes);
    if target.is_zero() {
        return U256::MAX;
    }
    // (~target / (target + 1)) + 1
    let not_target = U256([!target.0[0], !target.0[1], !target.0[2], !target.0[3]]);
    let target_plus_one = target.saturating_add(U256::from_u64(1));
    match not_target.checked_div(target_plus_one) {
        Some(q) => q.saturating_add(U256::from_u64(1)),
        None => U256::MAX,
    }
}

/// Testnet4 (and testnet3) 20-minute exception: if no block has been found
/// for 20 minutes, the next block is allowed at minimum difficulty (nBits = 0x1d00ffff).
///
/// Returns the nBits value to use for a block at `height` with timestamp `time`.
/// `prev_time` is the timestamp of the previous block.
/// `prev_bits` is the nBits of the previous block.
///
/// If the block is at a difficulty adjustment boundary, the caller should use
/// `next_bits` instead. This function handles non-boundary blocks on testnet.
///
/// `get_ancestor` returns (time, bits) for a given height.
pub fn testnet_min_difficulty_bits(
    height: u32,
    time: u32,
    prev_time: u32,
    prev_bits: u32,
    get_ancestor: impl Fn(u32) -> (u32, u32),
) -> u32 {
    const MIN_DIFFICULTY_BITS: u32 = 0x1d00ffff;
    const TWENTY_MINUTES: u32 = 20 * 60;

    // At difficulty adjustment boundaries, normal rules apply
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL as u32 == 0 {
        return prev_bits;
    }

    // If 20+ minutes since last block, allow minimum difficulty
    if time > prev_time + TWENTY_MINUTES {
        return MIN_DIFFICULTY_BITS;
    }

    // Otherwise, walk back to find the last block that wasn't a min-difficulty exception
    let mut h = height - 1;
    while h > 0 && h % DIFFICULTY_ADJUSTMENT_INTERVAL as u32 != 0 {
        let (_, bits) = get_ancestor(h);
        if bits != MIN_DIFFICULTY_BITS {
            return bits;
        }
        h -= 1;
    }
    let (_, bits) = get_ancestor(h);
    bits
}

/// BIP94 timewarp mitigation: at a difficulty adjustment boundary
/// (height % 2016 == 0), the block timestamp must not be more than
/// 600 seconds before the previous block's timestamp.
///
/// This prevents an attacker from manipulating timestamps at retarget
/// boundaries to artificially lower difficulty.
///
/// Returns `Ok(())` if the timestamp is acceptable, or an error message
/// if it violates the timewarp rule.
pub fn check_timewarp(height: u32, block_time: u32, prev_time: u32) -> Result<(), String> {
    const MAX_TIMEWARP: u32 = 600;
    if height > 0 && height % DIFFICULTY_ADJUSTMENT_INTERVAL as u32 == 0 {
        if block_time + MAX_TIMEWARP < prev_time {
            return Err(format!(
                "BIP94: block at retarget height {} has timestamp {} which is more than \
                 600s before previous block timestamp {}",
                height, block_time, prev_time,
            ));
        }
    }
    Ok(())
}

/// Compute the minimum allowed timestamp at a given height.
///
/// At difficulty adjustment boundaries (height % 2016 == 0), the minimum
/// is `prev_time - 600` (BIP94 timewarp rule). Otherwise returns 0
/// (the standard MTP rule applies separately).
pub fn get_minimum_time(height: u32, prev_time: u32) -> u32 {
    const MAX_TIMEWARP: u32 = 600;
    if height > 0 && height % DIFFICULTY_ADJUSTMENT_INTERVAL as u32 == 0 {
        prev_time.saturating_sub(MAX_TIMEWARP)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::{BlockHash, Hash256};

    fn header(time: u32, bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
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
        let last = header(1000 + (DEFAULT_TARGET_TIMESPAN * 5) as u32, 0x1d00ffff);
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
        assert!(!w.is_zero());
    }

    #[test]
    fn testnet_20min_exception_triggers() {
        // Block at height 100, 25 minutes after previous block → min difficulty
        let bits = testnet_min_difficulty_bits(
            100,
            1000 + 25 * 60, // current time
            1000,           // prev time
            0x1c0fffff,     // prev bits (higher difficulty)
            |_h| (0, 0x1c0fffff),
        );
        assert_eq!(bits, 0x1d00ffff, "should return min difficulty after 20 min");
    }

    #[test]
    fn testnet_20min_exception_no_trigger() {
        // Block at height 100, only 5 minutes after previous block → walk back
        let bits = testnet_min_difficulty_bits(
            100,
            1000 + 5 * 60,
            1000,
            0x1c0fffff,
            |_h| (0, 0x1c0fffff),
        );
        assert_eq!(bits, 0x1c0fffff, "should return real difficulty when under 20 min");
    }

    #[test]
    fn testnet_20min_skips_exception_blocks() {
        // Walk back should skip min-difficulty blocks
        let bits = testnet_min_difficulty_bits(
            100,
            1000 + 5 * 60,
            1000,
            0x1d00ffff, // prev was a min-difficulty exception
            |h| {
                if h >= 98 { (0, 0x1d00ffff) } // heights 98,99 are exceptions
                else { (0, 0x1c0fffff) }        // height 97 is real
            },
        );
        assert_eq!(bits, 0x1c0fffff, "should walk back past exception blocks");
    }

    #[test]
    fn timewarp_allows_normal_timestamp() {
        // At retarget height 2016, block_time > prev_time → ok
        assert!(check_timewarp(2016, 1_000_000, 999_000).is_ok());
    }

    #[test]
    fn timewarp_allows_slight_decrease() {
        // Block timestamp 500s before prev → within 600s allowance
        assert!(check_timewarp(2016, 999_400, 999_900).is_ok());
    }

    #[test]
    fn timewarp_rejects_large_decrease() {
        // Block timestamp 700s before prev → exceeds 600s allowance
        assert!(check_timewarp(2016, 999_200, 999_900).is_err());
    }

    #[test]
    fn timewarp_only_at_retarget() {
        // Not a retarget height → no check, always ok even with large decrease
        assert!(check_timewarp(2017, 100, 999_000).is_ok());
        assert!(check_timewarp(100, 100, 999_000).is_ok());
    }

    #[test]
    fn get_minimum_time_at_retarget() {
        assert_eq!(get_minimum_time(2016, 10_000), 10_000 - 600);
        assert_eq!(get_minimum_time(4032, 1000), 400);
    }

    #[test]
    fn get_minimum_time_non_retarget() {
        assert_eq!(get_minimum_time(100, 10_000), 0);
        assert_eq!(get_minimum_time(2017, 10_000), 0);
    }

    #[test]
    fn bip94_uses_first_header_bits() {
        // When enforce_bip94 is true, the base target should come from
        // first_header.bits, not last_header.bits.
        // Use different bits for first vs last to distinguish.
        let first = header(1000, 0x1c0fffff); // higher difficulty
        let last = header(1000 + 14 * 24 * 60 * 60, 0x1d00ffff); // min difficulty

        // Without BIP94: uses last_header.bits (0x1d00ffff) as base
        let bits_standard = next_bits_bip94(&first, &last, false, DEFAULT_TARGET_TIMESPAN);
        // With BIP94: uses first_header.bits (0x1c0fffff) as base
        let bits_bip94 = next_bits_bip94(&first, &last, true, DEFAULT_TARGET_TIMESPAN);

        // The two results must differ because the base targets differ
        assert_ne!(bits_standard, bits_bip94,
            "BIP94 should produce a different result when first and last bits differ");
    }

    #[test]
    fn bip94_same_bits_matches_standard() {
        // When both headers have the same bits, BIP94 and standard produce
        // identical results (the base target is the same either way).
        let first = header(1000, 0x1d00ffff);
        let last = header(1000 + 14 * 24 * 60 * 60, 0x1d00ffff);

        let bits_standard = next_bits_bip94(&first, &last, false, DEFAULT_TARGET_TIMESPAN);
        let bits_bip94 = next_bits_bip94(&first, &last, true, DEFAULT_TARGET_TIMESPAN);
        assert_eq!(bits_standard, bits_bip94);
    }

    #[test]
    fn bip94_wrapper_backward_compat() {
        // The zero-argument `next_bits()` wrapper should behave as enforce_bip94=false
        let first = header(1000, 0x1c0fffff);
        let last = header(1000 + 14 * 24 * 60 * 60, 0x1d00ffff);

        let bits_wrapper = next_bits(&first, &last);
        let bits_explicit = next_bits_bip94(&first, &last, false, DEFAULT_TARGET_TIMESPAN);
        assert_eq!(bits_wrapper, bits_explicit);
    }
}
