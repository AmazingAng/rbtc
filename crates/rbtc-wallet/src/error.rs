use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    #[error("invalid key material")]
    InvalidKey,

    #[error("invalid WIF private key")]
    InvalidWif,

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("address encoding error: {0}")]
    AddressEncoding(String),

    #[error("insufficient funds: need {needed} sat, have {available} sat")]
    InsufficientFunds { needed: u64, available: u64 },

    #[error("no UTXOs available for coin selection")]
    NoUtxos,

    #[error("coin selection failed: target too large")]
    CoinSelectionFailed,

    #[error("fee too high: fee {fee} >= output value {value}")]
    FeeTooHigh { fee: u64, value: u64 },

    #[error("wallet encryption error")]
    EncryptionError,

    #[error("wallet decryption failed (wrong passphrase?)")]
    DecryptionFailed,

    #[error("wallet not loaded")]
    NotLoaded,

    #[error("address not found in wallet")]
    AddressNotFound,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}
