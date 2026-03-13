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

    #[error("watch-only wallet cannot sign transactions")]
    WatchOnly,

    #[error("transaction does not signal RBF (all input sequences >= 0xfffffffe)")]
    RbfNotSignaled,

    #[error("transaction has descendants in the wallet")]
    HasWalletDescendants,

    #[error("transaction has already been bumped by {0}")]
    AlreadyBumped(String),

    #[error("inputs exceed maximum transaction weight")]
    MaxWeightExceeded,

    #[error("wallet is locked (encrypted and not unlocked)")]
    WalletLocked,

    #[error("wallet is not encrypted")]
    WalletNotEncrypted,

    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("external signer error: {0}")]
    ExternalSigner(String),

    #[error("external signer fingerprint mismatch: signer {signer} does not match any input")]
    SignerFingerprintMismatch { signer: String },

    #[error("external signer process failed: {0}")]
    SignerProcess(String),

    #[error("gap limit exceeded: {0} consecutive unused addresses")]
    GapLimitExceeded(u32),

    #[error("keypool exhausted — call top_up()")]
    KeypoolExhausted,

    #[error("wallet is already encrypted")]
    AlreadyEncrypted,

    #[error("unlock timeout must be positive")]
    InvalidTimeout,

    #[error("{0}")]
    Other(String),
}
