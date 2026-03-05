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

    #[error("non-standard transaction: {0}")]
    NonStandard(String),

    #[error("dust output #{0}: value {1} below threshold {2}")]
    Dust(usize, u64, u64),

    #[error("v3 transaction policy violation: {0}")]
    V3Policy(String),

    // ── RBF (BIP125) ──────────────────────────────────────────────────────────

    #[error("conflicting transaction in mempool (input already spent) and original does not signal RBF")]
    RbfNotSignaling,

    #[error("RBF replacement fee rate {0} sat/vbyte insufficient (original {1} + relay {2} required)")]
    RbfInsufficientFee(u64, u64, u64),

    #[error("RBF replacement would evict too many transactions ({0} > 100)")]
    TooManyReplacements(usize),

    #[error("RBF replacement absolute fee {0} sat too low (must exceed {1} sat total of replaced txs)")]
    RbfAbsoluteFeeTooLow(u64, u64),

    #[error("conflicting transaction in mempool (no RBF)")]
    ConflictingTx,

    // ── Eviction ──────────────────────────────────────────────────────────────

    #[error("mempool is full and incoming transaction fee rate is below eviction threshold")]
    MempoolFull,

    #[error("too many in-mempool ancestors: {0} (limit {1})")]
    TooManyAncestors(u64, u64),

    #[error("too many in-mempool descendants: {0} (limit {1})")]
    TooManyDescendants(u64, u64),
}
