pub mod account;
pub mod external_signer;
pub mod address;
pub mod descriptor;
pub mod error;
pub mod hd;
pub mod keypool;
pub mod mnemonic;
pub mod multisig;
pub mod tx_builder;
pub mod tx_store;
pub mod wallet;
pub mod wallet_db;
pub mod wallet_store;
pub mod watch_only;
pub mod wif;
#[cfg(test)]
mod tx_analysis_tests;
#[cfg(test)]
mod trusted_tests;

pub use account::{AccountManager, WalletAccount};
pub use address::{p2sh_address, p2sh_p2wpkh_address, p2sh_p2wpkh_address_from_pubkey, p2sh_p2wpkh_script, p2sh_p2wsh_address, p2wsh_address, AddressType};
pub use descriptor::{Descriptor, DescriptorKey, DescriptorWallet, KeyOrigin, expand_multipath};
pub use error::WalletError;
pub use hd::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, HARDENED};
pub use mnemonic::Mnemonic;
pub use multisig::{create_multisig_script, p2sh_multisig_address};
pub use tx_builder::{estimate_vsize, sign_transaction, CoinSelector, SigningInput, TxBuilder};
pub use keypool::{KeyPool, KeyPoolEntry, DEFAULT_KEYPOOL_SIZE};
pub use wallet::{
    AddressBookEntry, AddressPurpose, CoinControl, FeeEstimateProvider, OutputEntry,
    ReservedAddress, Wallet, WalletAddressInfo, WalletBalance, WalletUtxo, COINBASE_MATURITY,
    WALLET_FLAG_AVOID_REUSE, WALLET_FLAG_KEY_ORIGIN_METADATA,
    WALLET_FLAG_LAST_HARDENED_XPUB_CACHED, WALLET_FLAG_DISABLE_PRIVATE_KEYS,
    WALLET_FLAG_BLANK_WALLET, WALLET_FLAG_DESCRIPTORS, WALLET_FLAG_EXTERNAL_SIGNER,
    KNOWN_WALLET_FLAGS, MUTABLE_WALLET_FLAGS,
    DEFAULT_TRANSACTION_MINFEE, DEFAULT_FALLBACK_FEE, DEFAULT_DISCARD_FEE,
    DEFAULT_TX_CONFIRM_TARGET, MIN_RELAY_TX_FEE, DUST_RELAY_TX_FEE,
    WALLET_INCREMENTAL_RELAY_FEE,
};
pub use tx_store::{WalletTx, WalletTxStore};
pub use wallet_db::{EncryptedKey, WalletDb};
pub use wallet_store::CF_WALLET;
pub use watch_only::WatchOnlyWallet;
pub use wif::{from_wif, to_wif};
pub use external_signer::{ExternalSigner, ProcessExternalSigner, SignerChain, SignerDevice, SignerDescriptors};
