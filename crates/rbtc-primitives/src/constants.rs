/// Maximum block weight (BIP 141)
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Maximum serialized block size in bytes (legacy limit)
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 4_000_000;

/// Pre-BIP141 maximum block size in bytes (1 MB).
/// Before SegWit activation, blocks cannot exceed this base-serialization size.
pub const LEGACY_MAX_BLOCK_SIZE: u64 = 1_000_000;

/// Maximum block sigops cost
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// SegWit witness scale factor
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Number of blocks before coinbase outputs can be spent
pub const COINBASE_MATURITY: u32 = 100;

/// Initial block subsidy (50 BTC in satoshis)
pub const INITIAL_SUBSIDY: i64 = 50 * super::transaction::COIN;

/// Halving interval in blocks (mainnet default).
///
/// **Prefer `ConsensusParams::subsidy_halving_interval`** which is per-network
/// (regtest uses 150). This constant is retained for backward compatibility.
pub const SUBSIDY_HALVING_INTERVAL: u64 = 210_000;

/// Difficulty adjustment interval in blocks (mainnet default).
///
/// **Prefer `ConsensusParams::difficulty_adjustment_interval()`** which derives
/// the value from per-network `pow_target_timespan / pow_target_spacing`.
/// This constant is retained for backward compatibility.
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Target timespan for difficulty adjustment (mainnet default: 2 weeks).
///
/// **Prefer `ConsensusParams::pow_target_timespan`** which is per-network
/// (regtest uses 24h). This constant is retained for backward compatibility.
pub const TARGET_TIMESPAN: u64 = 14 * 24 * 60 * 60;

/// Target block time (10 minutes in seconds)
pub const TARGET_BLOCK_TIME: u64 = 10 * 60;

/// Maximum future timestamp allowed (2 hours in seconds)
pub const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;

/// Number of past blocks to use for median time calculation
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Maximum standard transaction size (policy, not consensus)
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Maximum script element size
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum script size
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum number of stack items
pub const MAX_STACK_SIZE: usize = 1_000;

/// Maximum number of non-push operations per script
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum number of public keys per multisig
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Maximum number of public keys per tapscript multi-sig (OP_CHECKSIGADD, BIP342)
pub const MAX_PUBKEYS_PER_MULTI_A: usize = 999;

/// Threshold for interpreting nLockTime: values below are block heights,
/// values >= are Unix timestamps. Matches Bitcoin Core's LOCKTIME_THRESHOLD.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Maximum value for nLockTime (u32::MAX). Matches Bitcoin Core usage where
/// the nLockTime field is a 32-bit unsigned integer.
pub const LOCKTIME_MAX: u32 = 0xFFFF_FFFF;

/// BIP341 Taproot annex tag byte. If the last witness stack item starts with
/// this byte (0x50), it is treated as an annex and excluded from script execution.
pub const ANNEX_TAG: u8 = 0x50;

/// BIP342: Signature operation cost in validation weight units per successful
/// OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD in tapscript.
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

/// BIP342: Base offset added to the validation weight budget.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Minimum non-witness transaction size (policy, prevents 64-byte tx attack)
pub const MIN_STANDARD_TX_NONWITNESS_SIZE: usize = 65;

/// Minimum weight for a valid transaction (consensus).
/// 60 is the lower bound for the size of a valid serialized CTransaction,
/// multiplied by WITNESS_SCALE_FACTOR. Matches Bitcoin Core's
/// `MIN_TRANSACTION_WEIGHT` in `src/consensus/consensus.h`.
pub const MIN_TRANSACTION_WEIGHT: u64 = WITNESS_SCALE_FACTOR * 60;

/// Minimum weight for a serializable transaction.
/// 10 is the lower bound for the size of a serialized CTransaction,
/// multiplied by WITNESS_SCALE_FACTOR. Matches Bitcoin Core's
/// `MIN_SERIALIZABLE_TRANSACTION_WEIGHT` in `src/consensus/consensus.h`.
pub const MIN_SERIALIZABLE_TRANSACTION_WEIGHT: u64 = WITNESS_SCALE_FACTOR * 10;

/// BIP68 sequence lock verification flag. When set, enables relative lock-time
/// enforcement as defined in BIP68/BIP112. Matches Bitcoin Core's
/// `LOCKTIME_VERIFY_SEQUENCE` in `src/consensus/consensus.h`.
pub const LOCKTIME_VERIFY_SEQUENCE: u32 = 1 << 0;

/// Maximum allowed time difference (in seconds) for timewarp attack mitigation
/// (BIP94). At difficulty adjustment boundaries, the new block's timestamp must
/// not be more than MAX_TIMEWARP seconds before its parent. Matches Bitcoin
/// Core's `MAX_TIMEWARP` in `src/consensus/consensus.h`.
pub const MAX_TIMEWARP: i64 = 600;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_transaction_weight_matches_core() {
        assert_eq!(MIN_TRANSACTION_WEIGHT, 240);
        assert_eq!(MIN_TRANSACTION_WEIGHT, WITNESS_SCALE_FACTOR * 60);
    }

    #[test]
    fn min_serializable_transaction_weight_matches_core() {
        assert_eq!(MIN_SERIALIZABLE_TRANSACTION_WEIGHT, 40);
        assert_eq!(MIN_SERIALIZABLE_TRANSACTION_WEIGHT, WITNESS_SCALE_FACTOR * 10);
    }

    #[test]
    fn locktime_verify_sequence_flag() {
        assert_eq!(LOCKTIME_VERIFY_SEQUENCE, 1);
        assert_eq!(LOCKTIME_VERIFY_SEQUENCE, 1 << 0);
    }

    #[test]
    fn max_timewarp_matches_core() {
        assert_eq!(MAX_TIMEWARP, 600);
    }

    #[test]
    fn locktime_threshold_matches_core() {
        assert_eq!(LOCKTIME_THRESHOLD, 500_000_000);
    }

    #[test]
    fn locktime_max_is_u32_max() {
        assert_eq!(LOCKTIME_MAX, u32::MAX);
        assert_eq!(LOCKTIME_MAX, 0xFFFF_FFFF);
    }
}
