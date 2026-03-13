use thiserror::Error;

#[derive(Debug, Error)]
pub enum MinerError {
    #[error("no output address specified")]
    NoAddress,

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("block weight {0} exceeds limit {1}")]
    BlockFull(u64, u64),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("wallet error: {0}")]
    Wallet(String),

    #[error("template validation failed: {0}")]
    TemplateInvalid(String),
}
