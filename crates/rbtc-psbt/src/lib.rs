//! `rbtc-psbt` — BIP174 Partially Signed Bitcoin Transactions (v0).
//!
//! ## Roles
//!
//! | Role       | Method / function                          |
//! |------------|--------------------------------------------|
//! | Creator    | [`Psbt::create`]                           |
//! | Updater    | [`Psbt::add_witness_utxo`], etc.           |
//! | Signer     | [`Psbt::sign_input`]                       |
//! | Combiner   | [`Psbt::combine`]                          |
//! | Finalizer  | [`Psbt::finalize`]                         |
//! | Extractor  | [`Psbt::extract_tx`]                       |
//!
//! ## Serialization
//!
//! ```no_run
//! # use rbtc_psbt::Psbt;
//! # fn make() -> Psbt { unimplemented!() }
//! let psbt = make();
//! let b64 = psbt.to_base64();
//! let decoded = Psbt::from_base64(&b64).unwrap();
//! ```

pub mod error;
pub mod roles;
pub mod serialize;
pub mod signer;
pub mod types;

pub use error::{PsbtError, Result};
pub use types::{
    Psbt, PsbtGlobal, PsbtInput, PsbtOutput, TapTreeLeaf,
    PSBT_TXMOD_INPUTS, PSBT_TXMOD_OUTPUTS, PSBT_TXMOD_HAS_SIGHASH_SINGLE,
};
