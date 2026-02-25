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
}
