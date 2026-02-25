//! PSBT v0 (BIP174) data structures.
//!
//! Key-value encoding: each map entry is `<key_len><key><val_len><val>`.
//! A zero-byte `<key_len>` signals the end of the map.
//!
//! Global separators / type bytes:
//!   0x00 = PSBT_GLOBAL_UNSIGNED_TX
//!
//! Per-input type bytes:
//!   0x00 = PSBT_IN_NON_WITNESS_UTXO
//!   0x01 = PSBT_IN_WITNESS_UTXO
//!   0x02 = PSBT_IN_PARTIAL_SIG
//!   0x03 = PSBT_IN_SIGHASH_TYPE
//!   0x04 = PSBT_IN_REDEEM_SCRIPT
//!   0x05 = PSBT_IN_WITNESS_SCRIPT
//!   0x06 = PSBT_IN_BIP32_DERIVATION
//!   0x07 = PSBT_IN_FINAL_SCRIPTSIG
//!   0x08 = PSBT_IN_FINAL_SCRIPTWITNESS
//!
//! Per-output type bytes:
//!   0x02 = PSBT_OUT_REDEEM_SCRIPT
//!   0x03 = PSBT_OUT_WITNESS_SCRIPT

use std::collections::BTreeMap;

use rbtc_primitives::{
    script::Script,
    transaction::{Transaction, TxOut},
};

/// Global PSBT section.
#[derive(Debug, Clone)]
pub struct PsbtGlobal {
    /// The unsigned transaction.
    pub unsigned_tx: Transaction,
    /// PSBT format version (always 0 for BIP174).
    pub version: u32,
    /// Unknown/proprietary key-value entries.
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Per-input PSBT data.
#[derive(Debug, Clone, Default)]
pub struct PsbtInput {
    /// Full previous transaction (legacy signing).
    pub non_witness_utxo: Option<Transaction>,
    /// Specific output being spent (SegWit / Taproot signing).
    pub witness_utxo: Option<TxOut>,
    /// Partial signatures: `pubkey (33 bytes) → DER-encoded sig + sighash_type`.
    pub partial_sigs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Requested sighash type (SIGHASH_ALL = 1 by default).
    pub sighash_type: Option<u32>,
    /// P2SH redeem script.
    pub redeem_script: Option<Script>,
    /// P2WSH witness script.
    pub witness_script: Option<Script>,
    /// Finalized scriptSig (set by Finalizer).
    pub final_script_sig: Option<Script>,
    /// Finalized witness stack (set by Finalizer).
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    /// BIP32 derivation info: pubkey → (fingerprint, path).
    pub bip32_derivation: BTreeMap<Vec<u8>, (Vec<u8>, Vec<u32>)>,
    /// Unknown entries.
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Per-output PSBT data.
#[derive(Debug, Clone, Default)]
pub struct PsbtOutput {
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
    pub bip32_derivation: BTreeMap<Vec<u8>, (Vec<u8>, Vec<u32>)>,
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// A complete Partially Signed Bitcoin Transaction.
#[derive(Debug, Clone)]
pub struct Psbt {
    pub global: PsbtGlobal,
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutput>,
}

impl PsbtInput {
    /// True if this input has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() || self.final_script_witness.is_some()
    }
}
