use thiserror::Error;

#[derive(Debug, Error)]
pub enum PsbtError {
    #[error("invalid PSBT magic")]
    InvalidMagic,
    #[error("invalid PSBT version: {0}")]
    UnsupportedVersion(u32),
    #[error("key-value decode error: {0}")]
    Decode(String),
    #[error("base64 error: {0}")]
    Base64(String),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("input count mismatch: tx has {tx}, psbt has {psbt}")]
    InputCountMismatch { tx: usize, psbt: usize },
    #[error("output count mismatch: tx has {tx}, psbt has {psbt}")]
    OutputCountMismatch { tx: usize, psbt: usize },
    #[error("signing error: {0}")]
    Signing(String),
    #[error("not all inputs are finalized")]
    NotFullySigned,
}

pub type Result<T> = std::result::Result<T, PsbtError>;
