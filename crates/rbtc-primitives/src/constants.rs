/// Maximum block weight (BIP 141)
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Maximum serialized block size in bytes (legacy limit)
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 4_000_000;

/// Maximum block sigops cost
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// SegWit witness scale factor
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Number of blocks before coinbase outputs can be spent
pub const COINBASE_MATURITY: u32 = 100;

/// Satoshis per bitcoin
pub const COIN: u64 = 100_000_000;

/// Initial block subsidy (50 BTC in satoshis)
pub const INITIAL_SUBSIDY: u64 = 50 * COIN;

/// Halving interval in blocks
pub const SUBSIDY_HALVING_INTERVAL: u64 = 210_000;

/// Difficulty adjustment interval in blocks
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Target timespan for difficulty adjustment (2 weeks in seconds)
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

/// Maximum number of inputs/outputs in a transaction
pub const MAX_TX_IN_SEQUENCE_NUM: u32 = 0xffffffff;

/// Sequence number that enables RBF (BIP125)
pub const SEQUENCE_RBF_SIGNAL: u32 = 0xfffffffe;

/// Sequence number disable flag (for nLockTime)
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// Sequence type flag
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Sequence mask
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
