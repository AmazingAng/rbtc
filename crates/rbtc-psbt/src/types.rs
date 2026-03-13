//! PSBT v0 (BIP174) and v2 (BIP370) data structures.
//!
//! Key-value encoding: each map entry is `<key_len><key><val_len><val>`.
//! A zero-byte `<key_len>` signals the end of the map.
//!
//! ## Global type bytes
//!   0x00 = PSBT_GLOBAL_UNSIGNED_TX          (v0 only)
//!   0x02 = PSBT_GLOBAL_TX_VERSION           (v2 only)
//!   0x03 = PSBT_GLOBAL_FALLBACK_LOCKTIME    (v2 only)
//!   0x04 = PSBT_GLOBAL_INPUT_COUNT          (v2 only)
//!   0x05 = PSBT_GLOBAL_OUTPUT_COUNT         (v2 only)
//!   0x06 = PSBT_GLOBAL_TX_MODIFIABLE        (v2 only)
//!   0xfb = PSBT_GLOBAL_VERSION
//!
//! ## Per-input type bytes
//!   0x00 = PSBT_IN_NON_WITNESS_UTXO
//!   0x01 = PSBT_IN_WITNESS_UTXO
//!   0x02 = PSBT_IN_PARTIAL_SIG
//!   0x03 = PSBT_IN_SIGHASH_TYPE
//!   0x04 = PSBT_IN_REDEEM_SCRIPT
//!   0x05 = PSBT_IN_WITNESS_SCRIPT
//!   0x06 = PSBT_IN_BIP32_DERIVATION
//!   0x07 = PSBT_IN_FINAL_SCRIPTSIG
//!   0x08 = PSBT_IN_FINAL_SCRIPTWITNESS
//!   0x0e = PSBT_IN_PREVIOUS_TXID           (v2 only)
//!   0x0f = PSBT_IN_OUTPUT_INDEX            (v2 only)
//!   0x10 = PSBT_IN_SEQUENCE                (v2 only)
//!   0x11 = PSBT_IN_REQUIRED_TIME_LOCKTIME  (v2 only)
//!   0x12 = PSBT_IN_REQUIRED_HEIGHT_LOCKTIME(v2 only)
//!   0x13 = PSBT_IN_TAP_KEY_SIG            (BIP371)
//!   0x14 = PSBT_IN_TAP_SCRIPT_SIG        (BIP371)
//!   0x15 = PSBT_IN_TAP_LEAF_SCRIPT       (BIP371)
//!   0x16 = PSBT_IN_TAP_BIP32_DERIVATION  (BIP371)
//!   0x17 = PSBT_IN_TAP_INTERNAL_KEY      (BIP371)
//!   0x18 = PSBT_IN_TAP_MERKLE_ROOT       (BIP371)
//!   0x1a = PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (BIP373)
//!   0x1b = PSBT_IN_MUSIG2_PUB_NONCE          (BIP373)
//!   0x1c = PSBT_IN_MUSIG2_PARTIAL_SIG        (BIP373)
//!
//! ## Per-output type bytes
//!   0x00 = PSBT_OUT_REDEEM_SCRIPT
//!   0x01 = PSBT_OUT_WITNESS_SCRIPT
//!   0x02 = PSBT_OUT_BIP32_DERIVATION
//!   0x03 = PSBT_OUT_AMOUNT                 (v2 only)
//!   0x04 = PSBT_OUT_SCRIPT                 (v2 only)
//!   0x05 = PSBT_OUT_TAP_INTERNAL_KEY      (BIP371)
//!   0x06 = PSBT_OUT_TAP_TREE              (BIP371)
//!   0x07 = PSBT_OUT_TAP_BIP32_DERIVATION  (BIP371)
//!   0x08 = PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (BIP373)

use std::collections::{BTreeMap, BTreeSet};

/// Structured proprietary key-value entry (type 0xFC).
///
/// Wire key format: `0xFC || compact_size(identifier.len()) || identifier || subtype || key_data`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProprietaryKey {
    /// Namespace identifier (e.g. company name).
    pub identifier: Vec<u8>,
    /// Sub-type within the namespace.
    pub subtype: u64,
    /// Additional key data after the subtype.
    pub key_data: Vec<u8>,
}

use rbtc_primitives::{
    hash::Txid,
    script::Script,
    transaction::{Transaction, TxOut},
};

/// Global PSBT section.
#[derive(Debug, Clone)]
pub struct PsbtGlobal {
    /// The unsigned transaction (v0 only; None for v2).
    pub unsigned_tx: Option<Transaction>,
    /// PSBT format version (0 for BIP174, 2 for BIP370).
    pub version: u32,
    /// Transaction version (v2 only).
    pub tx_version: Option<i32>,
    /// Fallback locktime (v2 only). Used if no input has a required locktime.
    pub fallback_locktime: Option<u32>,
    /// Number of inputs (v2 only).
    pub input_count: Option<u64>,
    /// Number of outputs (v2 only).
    pub output_count: Option<u64>,
    /// Bitmap of modifiable flags (v2 only).
    /// Bit 0 = inputs modifiable, bit 1 = outputs modifiable, bit 2 = has SIGHASH_SINGLE.
    pub tx_modifiable: Option<u8>,
    /// BIP174 PSBT_GLOBAL_XPUB (type 0x01): maps extended public key (78 bytes)
    /// to (master fingerprint 4 bytes, derivation path).
    pub xpub: BTreeMap<Vec<u8>, (Vec<u8>, Vec<u32>)>,
    /// Proprietary key-value entries (type 0xFC).
    pub proprietary: BTreeMap<ProprietaryKey, Vec<u8>>,
    /// Unknown key-value entries.
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
    // ── BIP174 Preimage fields ─────────────────────────────────────────────
    /// PSBT_IN_RIPEMD160 (0x0A): hash (20 bytes) -> preimage.
    pub ripemd160_preimages: BTreeMap<Vec<u8>, Vec<u8>>,
    /// PSBT_IN_SHA256 (0x0B): hash (32 bytes) -> preimage.
    pub sha256_preimages: BTreeMap<Vec<u8>, Vec<u8>>,
    /// PSBT_IN_HASH160 (0x0C): hash (20 bytes) -> preimage.
    pub hash160_preimages: BTreeMap<Vec<u8>, Vec<u8>>,
    /// PSBT_IN_HASH256 (0x0D): hash (32 bytes) -> preimage.
    pub hash256_preimages: BTreeMap<Vec<u8>, Vec<u8>>,
    // ── v2 (BIP370) fields ──────────────────────────────────────────────────
    /// Previous transaction ID (v2 only).
    pub previous_txid: Option<Txid>,
    /// Output index in previous transaction (v2 only).
    pub output_index: Option<u32>,
    /// nSequence value (v2 only). Defaults to 0xffffffff.
    pub sequence: Option<u32>,
    /// Required time-based locktime (v2 only).
    pub required_time_locktime: Option<u32>,
    /// Required height-based locktime (v2 only).
    pub required_height_locktime: Option<u32>,
    // ── BIP371 (Taproot) fields ─────────────────────────────────────────────
    /// BIP371: Taproot key-path signature (64 or 65 bytes).
    pub tap_key_sig: Option<Vec<u8>>,
    /// BIP371: Taproot script-path signatures. Key = x-only pubkey (32) || leaf_hash (32), Value = signature.
    pub tap_script_sig: BTreeMap<Vec<u8>, Vec<u8>>,
    /// BIP371: Taproot leaf scripts. Key = control block, Value = (script, leaf_version).
    pub tap_leaf_script: BTreeMap<Vec<u8>, (Vec<u8>, u8)>,
    /// BIP371: Taproot BIP32 derivation. Key = x-only pubkey (32 bytes),
    /// Value = (leaf_hashes: BTreeSet<[u8;32]>, fingerprint: [u8;4], path: Vec<u32>).
    /// Leaf hashes use BTreeSet to match Bitcoin Core's `set<uint256>` (sorted, no duplicates).
    pub tap_bip32_derivation: BTreeMap<Vec<u8>, (BTreeSet<Vec<u8>>, Vec<u8>, Vec<u32>)>,
    /// BIP371: Taproot internal key (32-byte x-only pubkey).
    pub tap_internal_key: Option<Vec<u8>>,
    /// BIP371: Taproot merkle root (32 bytes).
    pub tap_merkle_root: Option<Vec<u8>>,
    // ── BIP373 (MuSig2) fields ────────────────────────────────────────────────
    /// PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a): aggregate pubkey (33 bytes) →
    /// list of participant compressed pubkeys (N × 33 bytes).
    pub musig2_participant_pubkeys: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
    /// PSBT_IN_MUSIG2_PUB_NONCE (0x1b): (participant_pubkey 33 || aggregate_pubkey 33 || leaf_hash 32)
    /// → public nonce (66 bytes).
    pub musig2_pub_nonce: BTreeMap<Vec<u8>, Vec<u8>>,
    /// PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c): (participant_pubkey 33 || aggregate_pubkey 33 || leaf_hash 32)
    /// → partial signature (32 bytes).
    pub musig2_partial_sig: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Proprietary key-value entries (type 0xFC).
    pub proprietary: BTreeMap<ProprietaryKey, Vec<u8>>,
    /// Unknown entries.
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// A single leaf in a Taproot tree (BIP371 PSBT_OUT_TAP_TREE).
///
/// Serialized as `depth(u8) + leaf_ver(u8) + compact_size(script.len()) + script`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapTreeLeaf {
    /// Depth of this leaf in the Merkle tree (0..=128).
    pub depth: u8,
    /// Leaf version (must be even, i.e. `leaf_ver & 1 == 0`).
    pub leaf_version: u8,
    /// The leaf script.
    pub script: Vec<u8>,
}

/// Per-output PSBT data.
#[derive(Debug, Clone, Default)]
pub struct PsbtOutput {
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
    pub bip32_derivation: BTreeMap<Vec<u8>, (Vec<u8>, Vec<u32>)>,
    // ── v2 (BIP370) fields ──────────────────────────────────────────────────
    /// Output amount in satoshis (v2 only).
    pub amount: Option<i64>,
    /// Output script (v2 only).
    pub script: Option<Script>,
    // ── BIP371 (Taproot) fields ─────────────────────────────────────────────
    /// BIP371: Taproot internal key for output (32-byte x-only pubkey).
    pub tap_internal_key: Option<Vec<u8>>,
    /// BIP371: Taproot tree — parsed and validated `(depth, leaf_ver, script)` tuples.
    pub tap_tree: Option<Vec<TapTreeLeaf>>,
    /// BIP371: Taproot BIP32 derivation for output key.
    /// Leaf hashes use BTreeSet to match Bitcoin Core's `set<uint256>` (sorted, no duplicates).
    pub tap_bip32_derivation: BTreeMap<Vec<u8>, (BTreeSet<Vec<u8>>, Vec<u8>, Vec<u32>)>,
    // ── BIP373 (MuSig2) output fields ─────────────────────────────────────────
    /// PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x08): aggregate pubkey (33 bytes) →
    /// list of participant compressed pubkeys (N × 33 bytes).
    pub musig2_participant_pubkeys: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
    /// Proprietary key-value entries (type 0xFC).
    pub proprietary: BTreeMap<ProprietaryKey, Vec<u8>>,
    /// Unknown entries.
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// A complete Partially Signed Bitcoin Transaction.
#[derive(Debug, Clone)]
pub struct Psbt {
    pub global: PsbtGlobal,
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutput>,
}

// ── BIP370 TX_MODIFIABLE flag bits ────────────────────────────────────────────

/// Bit 0: inputs may be added or removed.
pub const PSBT_TXMOD_INPUTS: u8 = 0x01;
/// Bit 1: outputs may be added or removed.
pub const PSBT_TXMOD_OUTPUTS: u8 = 0x02;
/// Bit 2: at least one signer has signed with SIGHASH_SINGLE,
/// so the number of inputs and outputs must remain equal from that point.
pub const PSBT_TXMOD_HAS_SIGHASH_SINGLE: u8 = 0x04;

impl Psbt {
    /// Returns the PSBT version (0 or 2).
    pub fn version(&self) -> u32 {
        self.global.version
    }

    /// Returns true if this is a v2 (BIP370) PSBT.
    pub fn is_v2(&self) -> bool {
        self.global.version == 2
    }

    // ── BIP370 modifiable flag helpers ──────────────────────────────────────

    /// Returns `true` if inputs may be added or removed (bit 0 of TX_MODIFIABLE).
    pub fn inputs_modifiable(&self) -> bool {
        self.global
            .tx_modifiable
            .map_or(false, |f| f & PSBT_TXMOD_INPUTS != 0)
    }

    /// Returns `true` if outputs may be added or removed (bit 1 of TX_MODIFIABLE).
    pub fn outputs_modifiable(&self) -> bool {
        self.global
            .tx_modifiable
            .map_or(false, |f| f & PSBT_TXMOD_OUTPUTS != 0)
    }

    /// Returns `true` if a signer has used SIGHASH_SINGLE (bit 2 of TX_MODIFIABLE).
    pub fn has_sighash_single(&self) -> bool {
        self.global
            .tx_modifiable
            .map_or(false, |f| f & PSBT_TXMOD_HAS_SIGHASH_SINGLE != 0)
    }

    /// Set the TX_MODIFIABLE flags byte.
    pub fn set_tx_modifiable(&mut self, flags: u8) {
        self.global.tx_modifiable = Some(flags);
    }

    /// For v0: returns a reference to the unsigned transaction.
    /// For v2: reconstructs the unsigned transaction from per-input/output fields.
    pub fn unsigned_tx(&self) -> Option<Transaction> {
        if let Some(ref tx) = self.global.unsigned_tx {
            return Some(tx.clone());
        }
        // v2: reconstruct from per-input/output fields
        if self.global.version >= 2 {
            return self.reconstruct_tx();
        }
        None
    }

    /// Reconstruct a Transaction from v2 per-input/output fields.
    fn reconstruct_tx(&self) -> Option<Transaction> {
        use rbtc_primitives::transaction::{OutPoint, TxIn};

        let version = self.global.tx_version.unwrap_or(2);
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for inp in &self.inputs {
            let txid = inp.previous_txid?;
            let vout = inp.output_index?;
            inputs.push(TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: Script::new(),
                sequence: inp.sequence.unwrap_or(0xffff_ffff),
                witness: vec![],
            });
        }
        let mut outputs = Vec::with_capacity(self.outputs.len());
        for out in &self.outputs {
            outputs.push(TxOut {
                value: out.amount.unwrap_or(0),
                script_pubkey: out.script.clone().unwrap_or_else(Script::new),
            });
        }
        // Compute locktime: max of all required locktimes, or fallback
        let locktime = self.compute_locktime();
        Some(Transaction::from_parts(version, inputs, outputs, locktime))
    }

    /// BIP370: compute the transaction locktime from input requirements.
    fn compute_locktime(&self) -> u32 {
        let has_time = self.inputs.iter().any(|i| i.required_time_locktime.is_some());
        let has_height = self.inputs.iter().any(|i| i.required_height_locktime.is_some());

        if has_height && !has_time {
            self.inputs
                .iter()
                .filter_map(|i| i.required_height_locktime)
                .max()
                .unwrap_or(0)
        } else if has_time {
            self.inputs
                .iter()
                .filter_map(|i| i.required_time_locktime)
                .max()
                .unwrap_or(0)
        } else {
            self.global.fallback_locktime.unwrap_or(0)
        }
    }
}

impl PsbtInput {
    /// True if this input has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() || self.final_script_witness.is_some()
    }
}
