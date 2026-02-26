use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ConsensusError {
    // Block errors
    #[error("invalid block hash (PoW failure)")]
    BadProofOfWork,
    #[error("block timestamp too old (< MTP)")]
    TimestampTooOld,
    #[error("block timestamp too far in the future")]
    TimestampTooNew,
    #[error("invalid merkle root")]
    BadMerkleRoot,
    #[error("block too large: weight {0} > {1}")]
    BlockTooLarge(u64, u64),
    #[error("block sigops too high: {0} > {1}")]
    TooManySignatureOps(u64, u64),
    #[error("first transaction must be coinbase")]
    FirstTxNotCoinbase,
    #[error("duplicate coinbase")]
    DuplicateCoinbase,
    #[error("invalid coinbase witness commitment")]
    BadCoinbaseWitnessCommitment,
    #[error("invalid coinbase witness reserved value")]
    BadCoinbaseWitnessReservedValue,
    #[error("block subsidy mismatch: got {0}, allowed {1}")]
    BadCoinbaseAmount(u64, u64),
    #[error("bad bits: {0:#010x}")]
    BadBits(u32),
    #[error("duplicate transaction")]
    DuplicateTx,
    #[error("orphan block: unknown parent {0}")]
    UnknownParent(String),

    // Transaction errors
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("output value overflow")]
    OutputValueOverflow,
    #[error("input value overflow")]
    InputValueOverflow,
    #[error("fee underflow: inputs < outputs")]
    NegativeFee,
    #[error("UTXO not found: {0}:{1}")]
    MissingUtxo(String, u32),
    #[error("coinbase output not mature (height {0}, current {1})")]
    CoinbaseNotMature(u32, u32),
    #[error("script verification failed: {0}")]
    ScriptError(String),
    #[error("nLockTime not satisfied")]
    LockTimeNotSatisfied,
    #[error("BIP68 sequence lock not satisfied")]
    SequenceLockNotSatisfied,
    #[error("BIP30 conflict: txid {0} has unspent outputs")]
    Bip30Conflict(String),
    #[error("invalid transaction: {0}")]
    InvalidTx(String),

    // Chain errors
    #[error("block already known")]
    AlreadyKnown,
    #[error("genesis block mismatch")]
    GenesisMismatch,

    // Codec / IO errors
    #[error("decode error: {0}")]
    Decode(String),
}
