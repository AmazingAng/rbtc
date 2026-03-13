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
    #[error("duplicate key in PSBT map: {0}")]
    DuplicateKey(String),
    #[error("combiner: unsigned transactions do not match")]
    TransactionMismatch,
    #[error("not all inputs are finalized")]
    NotFullySigned,
    #[error("non_witness_utxo txid mismatch for input {index}: expected {expected}, got {got}")]
    NonWitnessUtxoTxidMismatch {
        index: usize,
        expected: String,
        got: String,
    },
    #[error("inputs are not modifiable (TX_MODIFIABLE bit 0 not set)")]
    InputsNotModifiable,
    #[error("outputs are not modifiable (TX_MODIFIABLE bit 1 not set)")]
    OutputsNotModifiable,
    #[error("invalid key size for {field}: expected {expected}, got {got}")]
    InvalidKeySize {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("invalid signature length for {field}: expected 64-65 bytes, got {got}")]
    InvalidSignatureLength {
        field: &'static str,
        got: usize,
    },
    #[error("invalid MuSig2 pubkey in {field}: {reason}")]
    InvalidMusig2Pubkey {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid value size for {field}: expected {expected}, got {got}")]
    InvalidValueSize {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("invalid Taproot control block size: {got} bytes (must be 33 + 32*k)")]
    InvalidControlBlockSize { got: usize },
    #[error("Taproot tree leaf depth {depth} exceeds maximum of 128")]
    TapTreeDepthExceeded { depth: u8 },
    #[error("Taproot tree leaf version 0x{leaf_ver:02x} has odd bits set (must be even)")]
    TapTreeInvalidLeafVersion { leaf_ver: u8 },
    #[error("Taproot tree is empty")]
    TapTreeEmpty,
    #[error("Taproot tree is malformed (not a complete binary tree)")]
    TapTreeMalformed,
    #[error("Taproot tree truncated")]
    TapTreeTruncated,
}

pub type Result<T> = std::result::Result<T, PsbtError>;
