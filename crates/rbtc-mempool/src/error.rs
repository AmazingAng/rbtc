use thiserror::Error;

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("transaction already in mempool")]
    AlreadyKnown,

    #[error("coinbase transactions are not accepted into the mempool")]
    Coinbase,

    #[error("fee rate too low: {0} sat/vbyte (minimum {1})")]
    FeeTooLow(u64, u64),

    #[error("missing input UTXO: {0}:{1}")]
    MissingInput(String, u32),

    #[error("consensus validation error: {0}")]
    Consensus(#[from] rbtc_consensus::error::ConsensusError),

    #[error("outputs exceed inputs (negative fee)")]
    NegativeFee,

    // ── RBF (BIP125) ──────────────────────────────────────────────────────────

    #[error("conflicting transaction in mempool (input already spent) and original does not signal RBF")]
    RbfNotSignaling,

    #[error("RBF replacement fee rate {0} sat/vbyte insufficient (original {1} + relay {2} required)")]
    RbfInsufficientFee(u64, u64, u64),

    #[error("RBF replacement would evict too many transactions ({0} > 100)")]
    TooManyReplacements(usize),

    #[error("conflicting transaction in mempool (no RBF)")]
    ConflictingTx,

    // ── Eviction ──────────────────────────────────────────────────────────────

    #[error("mempool is full and incoming transaction fee rate is below eviction threshold")]
    MempoolFull,
}
