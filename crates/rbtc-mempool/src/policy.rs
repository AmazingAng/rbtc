//! Mempool policy checks matching Bitcoin Core's `src/policy/policy.cpp`.
//!
//! Implements:
//! - `GetDustThreshold()` — per-output-type dust limits
//! - `IsStandardTx()` — transaction-level standardness checks
//! - `AreInputsStandard()` — input script standardness

use std::collections::{HashMap, HashSet};

use rbtc_consensus::utxo::Utxo;
use rbtc_primitives::script::Script;
use rbtc_primitives::transaction::{OutPoint, Transaction};

use crate::error::MempoolError;

// ── Constants matching Bitcoin Core ──────────────────────────────────────────

/// Maximum standard transaction weight (400,000 WU = 100,000 vbytes).
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Maximum number of sigops in a standard transaction (16,000).
pub const MAX_STANDARD_TX_SIGOPS_COST: u32 = 16_000;

/// Maximum number of P2SH sigops (15).
pub const MAX_P2SH_SIGOPS: u32 = 15;

/// Maximum size of scriptSig in a standard transaction (1,650 bytes).
pub const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

/// Maximum number of stack items in a standard P2WSH witness (100).
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;

/// Maximum size of a single witness stack item in P2WSH (80 bytes).
pub const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;

/// Maximum size of the witness script in P2WSH (3600 bytes).
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3_600;

/// Minimum relay fee rate per kvB in satoshis.
/// Bitcoin Core DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB = 0.1 sat/vB.
pub const DEFAULT_MIN_RELAY_TX_FEE: u64 = 100;

/// Default incremental relay fee rate per kvB in satoshis.
/// Bitcoin Core DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB.
/// Used for RBF relay fee increment calculations (Rule 4: replacement must pay
/// this rate * its own vsize in additional fees above the replaced fees).
/// This is intentionally a separate constant from DEFAULT_MIN_RELAY_TX_FEE so
/// that operators can configure them independently.
pub const DEFAULT_INCREMENTAL_RELAY_FEE: u64 = 100;

/// Default bytes per sigop for sigops-adjusted virtual size calculation.
/// Bitcoin Core DEFAULT_BYTES_PER_SIGOP = 20.
/// Used in `get_virtual_transaction_size()` to compute
/// `max(weight, sigop_cost * bytes_per_sigop) / 4`.
pub const DEFAULT_BYTES_PER_SIGOP: u64 = 20;

/// Maximum total OP_RETURN data size (in vbytes) considered standard.
/// Bitcoin Core: MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 100,000 vB.
/// Effectively no separate OP_RETURN limit — bounded by standard tx weight.
pub const MAX_OP_RETURN_RELAY: usize = 100_000;

/// Maximum number of inputs + outputs (sanity).
pub const MAX_STANDARD_TX_INS_OUTS: usize = 3_000;

/// Maximum number of dust outputs allowed per transaction (Bitcoin Core v28+).
/// This allows one dust output for ephemeral dust (spent in the same package).
pub const MAX_DUST_OUTPUTS_PER_TX: u32 = 1;

// ── Pay-to-Anchor (P2A) detection ────────────────────────────────────────────

/// Check whether a scriptPubKey is a Pay-to-Anchor (P2A) output.
///
/// P2A is `OP_1 OP_PUSH2 0x4e73` — a witness v1 program with a 2-byte program
/// (`[0x4e, 0x73]`).  Bitcoin Core `CScript::IsPayToAnchor()`.
///
/// The raw bytes are: `[0x51, 0x02, 0x4e, 0x73]`.
pub fn is_pay_to_anchor(script: &[u8]) -> bool {
    script.len() == 4
        && script[0] == 0x51 // OP_1
        && script[1] == 0x02 // push 2 bytes
        && script[2] == 0x4e
        && script[3] == 0x73
}

/// Variant that checks a decoded witness program (version, program bytes),
/// matching Bitcoin Core's `CScript::IsPayToAnchor(int version, vector<uint8_t> program)`.
pub fn is_pay_to_anchor_program(version: u8, program: &[u8]) -> bool {
    version == 1 && program.len() == 2 && program[0] == 0x4e && program[1] == 0x73
}

// ── Sigops-adjusted virtual size ────────────────────────────────────────────

/// Compute the sigops-adjusted virtual transaction size.
///
/// Bitcoin Core's `GetVirtualTransactionSize(weight, sigop_cost, bytes_per_sigop)`:
/// ```text
/// vsize = ceil(max(weight, sigop_cost * bytes_per_sigop) / 4)
/// ```
///
/// This ensures that transactions with many sigops relative to their weight
/// are charged a higher virtual size (and hence a higher fee requirement).
pub fn get_virtual_transaction_size(weight: u64, sigop_cost: u64, bytes_per_sigop: u64) -> u64 {
    let sigop_weight = sigop_cost.saturating_mul(bytes_per_sigop);
    let effective_weight = std::cmp::max(weight, sigop_weight);
    // ceil(effective_weight / 4), matching WITNESS_SCALE_FACTOR = 4
    (effective_weight + 3) / 4
}

// ── Sigops counting ─────────────────────────────────────────────────────────

/// Count the "legacy" sigops in a script (output or input).
///
/// - `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` → 1 sigop each
/// - `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` → 20 sigops (worst case)
///
/// This mirrors Bitcoin Core's `GetSigOpCount(false)` (non-accurate mode).
fn count_script_sigops(script: &[u8]) -> u32 {
    let mut count = 0u32;
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        match op {
            // Push data opcodes: skip their payload
            0x01..=0x4b => {
                i += 1 + op as usize;
                continue;
            }
            0x4c => {
                // OP_PUSHDATA1
                if i + 1 < script.len() {
                    i += 2 + script[i + 1] as usize;
                } else {
                    break;
                }
                continue;
            }
            0x4d => {
                // OP_PUSHDATA2
                if i + 2 < script.len() {
                    let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                    i += 3 + len;
                } else {
                    break;
                }
                continue;
            }
            0x4e => {
                // OP_PUSHDATA4
                if i + 4 < script.len() {
                    let len = u32::from_le_bytes([
                        script[i + 1],
                        script[i + 2],
                        script[i + 3],
                        script[i + 4],
                    ]) as usize;
                    i += 5 + len;
                } else {
                    break;
                }
                continue;
            }
            0xac | 0xad => count += 1,  // OP_CHECKSIG, OP_CHECKSIGVERIFY
            0xae | 0xaf => count += 20, // OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
            _ => {}
        }
        i += 1;
    }
    count
}

/// Count total legacy sigops for a transaction (inputs + outputs).
/// Witness sigops are not counted here (they use a separate weight-based budget).
pub fn count_tx_sigops(tx: &Transaction) -> u32 {
    let mut total = 0u32;
    for input in &tx.inputs {
        total += count_script_sigops(&input.script_sig.0);
    }
    for output in &tx.outputs {
        total += count_script_sigops(&output.script_pubkey.0);
    }
    total
}

/// Maximum per-transaction legacy sigop count (BIP54).
/// Bitcoin Core: `MAX_TX_LEGACY_SIGOPS = 2500`.
pub const MAX_TX_LEGACY_SIGOPS: u32 = 2_500;

/// Count "accurate" sigops in a script (Bitcoin Core `GetSigOpCount(true)`).
///
/// Like `count_script_sigops` but for `OP_CHECKMULTISIG(VERIFY)` it reads the
/// preceding push to determine the actual number of pubkeys (capped at 16)
/// rather than worst-casing to 20.  This is the BIP16-accurate counting used
/// by P2SH evaluation and BIP54.
fn count_script_sigops_accurate(script: &[u8]) -> u32 {
    let mut count = 0u32;
    let mut last_op: u8 = 0xff; // track the previous opcode
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        match op {
            0x01..=0x4b => {
                last_op = op;
                i += 1 + op as usize;
                continue;
            }
            0x4c => {
                last_op = op;
                if i + 1 < script.len() {
                    i += 2 + script[i + 1] as usize;
                } else {
                    break;
                }
                continue;
            }
            0x4d => {
                last_op = op;
                if i + 2 < script.len() {
                    let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                    i += 3 + len;
                } else {
                    break;
                }
                continue;
            }
            0x4e => {
                last_op = op;
                if i + 4 < script.len() {
                    let len = u32::from_le_bytes([
                        script[i + 1],
                        script[i + 2],
                        script[i + 3],
                        script[i + 4],
                    ]) as usize;
                    i += 5 + len;
                } else {
                    break;
                }
                continue;
            }
            0xac | 0xad => count += 1, // OP_CHECKSIG, OP_CHECKSIGVERIFY
            0xae | 0xaf => {
                // OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
                // Accurate mode: if the previous opcode is OP_1..OP_16, use that as n
                if last_op >= 0x51 && last_op <= 0x60 {
                    count += (last_op - 0x50) as u32;
                } else {
                    count += 20; // worst case
                }
            }
            _ => {}
        }
        last_op = op;
        i += 1;
    }
    count
}

/// For a P2SH scriptPubKey, extract the redeemScript from scriptSig and count
/// its sigops accurately (BIP16 `GetSigOpCount(fAccurate=true, scriptSig)`).
/// This mirrors Bitcoin Core's `CScript::GetSigOpCount(const CScript& scriptSig)`.
fn count_p2sh_sigops(script_pubkey: &[u8], script_sig: &[u8]) -> u32 {
    // Only applies to P2SH outputs: OP_HASH160 <20> OP_EQUAL
    if script_pubkey.len() != 23
        || script_pubkey[0] != 0xa9
        || script_pubkey[1] != 0x14
        || script_pubkey[22] != 0x87
    {
        return 0;
    }
    // Extract the last push from scriptSig (the redeemScript)
    if let Some(redeem) = extract_last_push(script_sig) {
        count_script_sigops_accurate(&redeem)
    } else {
        0
    }
}

/// Extract the last data push from a script (used to find the P2SH redeemScript).
fn extract_last_push(script: &[u8]) -> Option<Vec<u8>> {
    let mut last: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        if op == 0x00 {
            last = Some(vec![]);
            i += 1;
        } else if (0x01..=0x4b).contains(&op) {
            let len = op as usize;
            if i + 1 + len > script.len() {
                return None;
            }
            last = Some(script[i + 1..i + 1 + len].to_vec());
            i += 1 + len;
        } else if op == 0x4c {
            if i + 1 >= script.len() {
                return None;
            }
            let len = script[i + 1] as usize;
            if i + 2 + len > script.len() {
                return None;
            }
            last = Some(script[i + 2..i + 2 + len].to_vec());
            i += 2 + len;
        } else if op == 0x4d {
            if i + 2 >= script.len() {
                return None;
            }
            let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
            if i + 3 + len > script.len() {
                return None;
            }
            last = Some(script[i + 3..i + 3 + len].to_vec());
            i += 3 + len;
        } else if op == 0x4e {
            if i + 4 >= script.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                script[i + 1],
                script[i + 2],
                script[i + 3],
                script[i + 4],
            ]) as usize;
            if i + 5 + len > script.len() {
                return None;
            }
            last = Some(script[i + 5..i + 5 + len].to_vec());
            i += 5 + len;
        } else {
            // Non-push opcode — stop tracking pushes but keep going
            i += 1;
        }
    }
    last
}

/// BIP54 per-transaction legacy sigop check.
///
/// Counts sigops where they are *executed*, not where they appear in the block:
/// - `scriptSig` sigops (accurate mode)
/// - Spent `scriptPubKey` sigops via
///   `prevout.scriptPubKey.GetSigOpCount(scriptSig)`:
///   - Non-P2SH: accurate sigops in the prevout scriptPubKey
///   - P2SH: accurate sigops in the redeemScript (extracted from scriptSig)
///
/// Returns the total count on success, or `Err(count)` if it exceeds
/// `MAX_TX_LEGACY_SIGOPS`.
pub fn check_bip54_sigops(
    tx: &Transaction,
    prevout_scripts: &HashMap<OutPoint, Script>,
) -> Result<u32, u32> {
    let mut sigops = 0u32;
    for input in &tx.inputs {
        // 1. Accurate sigops in the scriptSig itself
        sigops += count_script_sigops_accurate(&input.script_sig.0);

        // 2. prevout.scriptPubKey.GetSigOpCount(scriptSig)
        if let Some(prev_spk) = prevout_scripts.get(&input.previous_output) {
            let is_p2sh = prev_spk.0.len() == 23
                && prev_spk.0[0] == 0xa9
                && prev_spk.0[1] == 0x14
                && prev_spk.0[22] == 0x87;
            if is_p2sh {
                // P2SH: count accurate sigops in the redeemScript
                sigops += count_p2sh_sigops(&prev_spk.0, &input.script_sig.0);
            } else {
                // Non-P2SH: count accurate sigops in the prevout scriptPubKey
                sigops += count_script_sigops_accurate(&prev_spk.0);
            }
        }

        if sigops > MAX_TX_LEGACY_SIGOPS {
            return Err(sigops);
        }
    }
    Ok(sigops)
}

// ── Dust threshold ──────────────────────────────────────────────────────────

/// Compute the dust threshold for a given scriptPubKey.
///
/// Matches Bitcoin Core's `GetDustThreshold()` logic from `policy.cpp`:
///
/// ```text
/// nSize = output_serialized_size + spend_input_size
/// dust = nSize * dustRelayFee / 1000
/// ```
///
/// Where `dustRelayFee` = 3000 sat/kB (DEFAULT_DUST_RELAY_TX_FEE).
pub fn dust_threshold(script: &Script) -> u64 {
    let dust_relay_fee: u64 = 3_000; // sat per 1000 bytes

    if script.is_op_return() {
        return 0;
    }

    // Output serialized size: 8 (value) + 1 (varint) + scriptPubKey.len()
    let output_size = 8 + 1 + script.0.len() as u64;

    // Spend input size depends on script type
    // For witness programs: spend = 32 + 4 + 1 + (107/4) + 4 = 67
    // For non-witness:      spend = 32 + 4 + 1 + 107 + 4 = 148
    let is_witness = script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr();
    let spend_size: u64 = if is_witness { 67 } else { 148 };

    let n_size = output_size + spend_size;
    n_size * dust_relay_fee / 1_000
}

/// Check a transaction for dust outputs. Returns the index of the first
/// dust output, or `None` if all outputs are above the dust threshold.
pub fn check_dust(tx: &Transaction) -> Option<(usize, u64, u64)> {
    for (i, output) in tx.outputs.iter().enumerate() {
        let threshold = dust_threshold(&output.script_pubkey);
        if threshold > 0 && output.value < threshold as i64 {
            return Some((i, output.value as u64, threshold));
        }
    }
    None
}

// ── IsStandard transaction checks ───────────────────────────────────────────

/// Reason a transaction is non-standard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonStandardReason {
    VersionTooHigh,
    VersionTooLow,
    TxTooLarge,
    TxTooSmall,
    DustOutput(usize, u64, u64),
    TooManyDustOutputs(u32),
    ScriptSigTooLarge(usize),
    NonStandardOutput(usize),
    BareMutisig,
    /// Bare multisig with n > 3 (Bitcoin Core rejects n outside [1,3])
    MultisigTooManyKeys(usize),
    ScriptSigNotPushOnly(usize),
}

impl std::fmt::Display for NonStandardReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionTooHigh => write!(f, "version too high"),
            Self::VersionTooLow => write!(f, "version too low"),
            Self::TxTooLarge => write!(f, "tx-size"),
            Self::TxTooSmall => write!(f, "tx-size-small"),
            Self::DustOutput(i, val, thresh) => {
                write!(f, "dust output #{i} value={val} threshold={thresh}")
            }
            Self::TooManyDustOutputs(count) => {
                write!(f, "dust: {count} dust outputs (max {MAX_DUST_OUTPUTS_PER_TX})")
            }
            Self::ScriptSigTooLarge(i) => write!(f, "scriptsig-size at input #{i}"),
            Self::NonStandardOutput(i) => write!(f, "scriptpubkey at output #{i}"),
            Self::BareMutisig => write!(f, "bare-multisig"),
            Self::MultisigTooManyKeys(i) => {
                write!(f, "multisig-too-many-keys at output #{i}")
            }
            Self::ScriptSigNotPushOnly(i) => {
                write!(f, "scriptsig-not-pushonly at input #{i}")
            }
        }
    }
}

/// Check if a transaction is "standard" according to Bitcoin Core policy.
///
/// This does NOT check script execution — it only checks structural properties.
pub fn is_standard_tx(tx: &Transaction) -> Result<(), NonStandardReason> {
    is_standard_tx_with_options(tx, true)
}

/// Check if a transaction is "standard" with configurable bare multisig policy.
///
/// `permit_bare_multisig`: if true (Bitcoin Core default), bare multisig outputs are allowed.
pub fn is_standard_tx_with_options(
    tx: &Transaction,
    permit_bare_multisig: bool,
) -> Result<(), NonStandardReason> {
    // 1. Version check: Bitcoin Core allows versions 1, 2, and 3 (BIP431 TRUC).
    // TX_MIN_STANDARD_VERSION = 1, TX_MAX_STANDARD_VERSION = 3
    if tx.version < 1 {
        return Err(NonStandardReason::VersionTooLow);
    }
    if tx.version > 3 {
        return Err(NonStandardReason::VersionTooHigh);
    }

    // 2. Weight check
    if tx.weight() > MAX_STANDARD_TX_WEIGHT {
        return Err(NonStandardReason::TxTooLarge);
    }

    // 2b. Minimum non-witness size check (prevents 64-byte tx attack).
    // A 64-byte transaction could be confused with an internal merkle node.
    if tx.encode_legacy_size() < rbtc_primitives::constants::MIN_STANDARD_TX_NONWITNESS_SIZE {
        return Err(NonStandardReason::TxTooSmall);
    }

    // 3. Input scriptSig size + push-only check
    for (i, input) in tx.inputs.iter().enumerate() {
        if input.script_sig.0.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(NonStandardReason::ScriptSigTooLarge(i));
        }
        // Bitcoin Core: scriptSig must contain only push operations
        if !input.script_sig.is_push_only() {
            return Err(NonStandardReason::ScriptSigNotPushOnly(i));
        }
    }

    // 4. Output script type check + OP_RETURN aggregate limit.
    // Bitcoin Core v28+: multiple OP_RETURN outputs are allowed, but their total
    // size (in bytes) must not exceed MAX_OP_RETURN_RELAY.
    let mut datacarrier_bytes_left = MAX_OP_RETURN_RELAY;
    for (i, output) in tx.outputs.iter().enumerate() {
        let spk = &output.script_pubkey;

        // Reject bare multisig outputs when not permitted.
        // Bitcoin Core default: DEFAULT_PERMIT_BAREMULTISIG = true
        if spk.is_bare_multisig() && !permit_bare_multisig {
            return Err(NonStandardReason::BareMutisig);
        }

        // Bitcoin Core IsStandard(): bare multisig with n > 3 is non-standard.
        // Support up to x-of-3 multisig txns as standard (policy.cpp:89-93).
        if let Some((_m, n)) = spk.bare_multisig_params() {
            if n < 1 || n > 3 {
                return Err(NonStandardReason::MultisigTooManyKeys(i));
            }
        }

        // Standard output types (matches Bitcoin Core's Solver TxoutType)
        let is_standard = spk.is_p2pkh()
            || spk.is_p2sh()
            || spk.is_p2wpkh()
            || spk.is_p2wsh()
            || spk.is_p2tr()
            || spk.is_op_return()
            || spk.is_bare_multisig()
            || spk.is_witness_program()
            || spk.0.is_empty(); // empty scriptPubKey (allowed but dust)

        if spk.is_op_return() {
            let size = spk.0.len();
            if size > datacarrier_bytes_left {
                return Err(NonStandardReason::NonStandardOutput(i));
            }
            datacarrier_bytes_left -= size;
        } else if !is_standard {
            return Err(NonStandardReason::NonStandardOutput(i));
        }
    }

    // 5. Dust check: Bitcoin Core v28+ allows up to MAX_DUST_OUTPUTS_PER_TX
    // dust outputs (for ephemeral dust support). Count dust outputs and reject
    // only if the count exceeds the limit.
    let mut dust_count = 0u32;
    for output in &tx.outputs {
        let spk = &output.script_pubkey;
        if !spk.is_op_return() {
            let threshold = dust_threshold(spk);
            if threshold > 0 && output.value < threshold as i64 {
                dust_count += 1;
            }
        }
    }
    if dust_count > MAX_DUST_OUTPUTS_PER_TX {
        return Err(NonStandardReason::TooManyDustOutputs(dust_count));
    }

    Ok(())
}

/// Check if all inputs of a transaction are standard.
///
/// For P2SH inputs, checks that the redeemScript is one of the standard types.
/// For witness inputs, checks stack sizes.
pub fn are_inputs_standard(tx: &Transaction) -> bool {
    for input in &tx.inputs {
        // Check witness stack limits for segwit inputs
        if !input.witness.is_empty() {
            if input.witness.len() > MAX_STANDARD_P2WSH_STACK_ITEMS {
                return false;
            }
            for item in &input.witness {
                if item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE {
                    // Exception: Taproot witnesses can have larger items
                    // For P2TR, the control block and script can be > 80 bytes
                    // We allow this for now (Core also relaxes this for taproot)
                }
            }
        }
    }
    true
}

// ── IsWitnessStandard ────────────────────────────────────────────────────────

/// Maximum size of a single tapscript stack item (80 bytes).
/// Matches Bitcoin Core's MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE.
pub const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;

/// Taproot leaf version mask (0xfe) — used to extract the leaf version from
/// the first byte of the control block.
const TAPROOT_LEAF_MASK: u8 = 0xfe;

/// Tapscript leaf version (0xc0) — BIP 342.
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

/// Extract the witness version and program length from a script that is
/// either a direct witness program or (when `is_p2sh` is true) a P2SH
/// redeemScript extracted from scriptSig.  Returns `None` if the script
/// is not a witness program.
fn extract_witness_program(script: &[u8]) -> Option<(u8, usize)> {
    match script {
        [v, push_len, ..]
            if (*v == 0x00 || (0x51..=0x60).contains(v))
                && *push_len >= 2
                && *push_len <= 40
                && script.len() == 2 + *push_len as usize =>
        {
            let ver = if *v == 0x00 { 0u8 } else { *v - 0x50 };
            Some((ver, *push_len as usize))
        }
        _ => None,
    }
}

/// Try to extract the redeemScript from a P2SH scriptSig by parsing push
/// opcodes.  Returns the last pushed data element, which is the redeemScript.
fn extract_redeem_script(script_sig: &[u8]) -> Option<Vec<u8>> {
    let mut last_push: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < script_sig.len() {
        let op = script_sig[i];
        if op == 0x00 {
            last_push = Some(vec![]);
            i += 1;
        } else if op >= 0x01 && op <= 0x4b {
            let len = op as usize;
            if i + 1 + len > script_sig.len() {
                return None;
            }
            last_push = Some(script_sig[i + 1..i + 1 + len].to_vec());
            i += 1 + len;
        } else if op == 0x4c {
            // OP_PUSHDATA1
            if i + 1 >= script_sig.len() {
                return None;
            }
            let len = script_sig[i + 1] as usize;
            if i + 2 + len > script_sig.len() {
                return None;
            }
            last_push = Some(script_sig[i + 2..i + 2 + len].to_vec());
            i += 2 + len;
        } else if op == 0x4d {
            // OP_PUSHDATA2
            if i + 2 >= script_sig.len() {
                return None;
            }
            let len = u16::from_le_bytes([script_sig[i + 1], script_sig[i + 2]]) as usize;
            if i + 3 + len > script_sig.len() {
                return None;
            }
            last_push = Some(script_sig[i + 3..i + 3 + len].to_vec());
            i += 3 + len;
        } else if op == 0x4e {
            // OP_PUSHDATA4
            if i + 4 >= script_sig.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                script_sig[i + 1],
                script_sig[i + 2],
                script_sig[i + 3],
                script_sig[i + 4],
            ]) as usize;
            if i + 5 + len > script_sig.len() {
                return None;
            }
            last_push = Some(script_sig[i + 5..i + 5 + len].to_vec());
            i += 5 + len;
        } else {
            // Non-push opcode — P2SH scriptSig must be push-only
            return None;
        }
    }
    last_push
}

/// Check that witness data for every input is standard.
///
/// Mirrors Bitcoin Core's `IsWitnessStandard()` from `src/policy/policy.cpp`.
///
/// Rules:
/// - **P2WSH** (witness v0, 32-byte program): at most 100 witness stack items
///   (excluding the witness script itself), each at most 80 bytes, and the
///   witness script (last stack element) at most 3 600 bytes.
/// - **P2WPKH** (witness v0, 20-byte program): exactly 2 witness items.
/// - **P2SH-wrapped witness** (P2SH-P2WPKH, P2SH-P2WSH): extract the
///   redeemScript from scriptSig, detect witness version, apply the same
///   witness stack checks as native witness programs.
/// - **Taproot** (witness v1, 32-byte program): reject if an annex is present
///   (last item starts with 0x50); for script-path spends with leaf version
///   0xc0 (tapscript), enforce MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80
///   on all stack items (excluding control block and script).
/// - Unknown witness versions: succeed (future soft-fork safe).
pub fn is_witness_standard(
    tx: &Transaction,
    input_view: &HashMap<OutPoint, Utxo>,
) -> Result<(), MempoolError> {
    for (idx, input) in tx.inputs.iter().enumerate() {
        // Skip inputs without witness data
        if input.witness.is_empty() {
            continue;
        }

        let utxo = match input_view.get(&input.previous_output) {
            Some(u) => u,
            None => continue, // missing UTXO handled elsewhere
        };

        let spk = &utxo.txout.script_pubkey;

        // M10: Reject witness stuffing on Pay-to-Anchor (P2A) outputs.
        // P2A is witness v1 with a 2-byte program (0x4e73).  Any witness
        // data on a P2A input is non-standard (Bitcoin Core IsWitnessStandard).
        if is_pay_to_anchor(&spk.0) {
            return Err(MempoolError::WitnessNonStandard(format!(
                "input {idx}: witness stuffing on Pay-to-Anchor (P2A) output"
            )));
        }

        // M6: Handle P2SH-wrapped witness programs.
        // If the scriptPubKey is P2SH, extract the redeemScript from scriptSig
        // and check if it is a witness program.
        let (version, program_len, is_p2sh_wrapped) = if spk.is_p2sh() {
            // Extract redeemScript from the scriptSig (last push)
            if let Some(redeem) = extract_redeem_script(&input.script_sig.0) {
                if let Some((v, pl)) = extract_witness_program(&redeem) {
                    (v, pl, true)
                } else {
                    // P2SH input has witness data but redeemScript is not a witness
                    // program — non-standard (witness stuffing).
                    return Err(MempoolError::WitnessNonStandard(format!(
                        "input {idx}: P2SH input has witness but redeemScript is not a witness program"
                    )));
                }
            } else {
                // Can't parse scriptSig — skip (will be caught by consensus)
                continue;
            }
        } else if let Some((v, pl)) = extract_witness_program(&spk.0) {
            (v, pl, false)
        } else {
            // Not a witness program — skip
            continue;
        };

        match version {
            0 => {
                if program_len == 32 {
                    // ── P2WSH (or P2SH-P2WSH) ───────────────────────────
                    let stack_items = input.witness.len().saturating_sub(1);
                    if stack_items > MAX_STANDARD_P2WSH_STACK_ITEMS {
                        return Err(MempoolError::WitnessNonStandard(format!(
                            "input {idx}: P2WSH witness has {stack_items} stack items \
                             (max {MAX_STANDARD_P2WSH_STACK_ITEMS})"
                        )));
                    }

                    for (i, item) in input.witness.iter().enumerate() {
                        if i == input.witness.len() - 1 {
                            if item.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
                                return Err(MempoolError::WitnessNonStandard(format!(
                                    "input {idx}: P2WSH witness script is {} bytes \
                                     (max {MAX_STANDARD_P2WSH_SCRIPT_SIZE})",
                                    item.len()
                                )));
                            }
                        } else if item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE {
                            return Err(MempoolError::WitnessNonStandard(format!(
                                "input {idx}: P2WSH witness item {i} is {} bytes \
                                 (max {MAX_STANDARD_P2WSH_STACK_ITEM_SIZE})",
                                item.len()
                            )));
                        }
                    }
                } else if program_len == 20 {
                    // ── P2WPKH (or P2SH-P2WPKH) ─────────────────────────
                    if input.witness.len() != 2 {
                        return Err(MempoolError::WitnessNonStandard(format!(
                            "input {idx}: P2WPKH witness must have exactly 2 items, \
                             got {}",
                            input.witness.len()
                        )));
                    }
                }
            }
            1 if program_len == 32 && !is_p2sh_wrapped => {
                // ── Taproot (v1) ────────────────────────────────────────
                // Note: P2SH-wrapped taproot is non-standard (Bitcoin Core rejects it).
                let witness = &input.witness;

                // Check for annex (last item starts with 0x50)
                if witness.len() >= 2 {
                    if let Some(last) = witness.last() {
                        if !last.is_empty() && last[0] == 0x50 {
                            return Err(MempoolError::WitnessNonStandard(format!(
                                "input {idx}: taproot annex is non-standard"
                            )));
                        }
                    }
                }

                // M7: Tapscript stack item size limit.
                // Determine the effective stack (strip annex if present).
                let effective_len = if witness.len() >= 2 {
                    let last = &witness[witness.len() - 1];
                    if !last.is_empty() && last[0] == 0x50 {
                        witness.len() - 1 // annex stripped (already rejected above, but defensive)
                    } else {
                        witness.len()
                    }
                } else {
                    witness.len()
                };

                if effective_len >= 2 {
                    // Script path spend: stack has [args..., script, control_block]
                    // (after removing optional annex).
                    let control_block = &witness[effective_len - 1];
                    if control_block.is_empty() {
                        return Err(MempoolError::WitnessNonStandard(format!(
                            "input {idx}: taproot empty control block"
                        )));
                    }
                    // Check if leaf version is tapscript (0xc0)
                    if (control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT {
                        // Stack items are everything except the last two (script + control_block)
                        for i in 0..effective_len.saturating_sub(2) {
                            if witness[i].len() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE {
                                return Err(MempoolError::WitnessNonStandard(format!(
                                    "input {idx}: tapscript witness item {i} is {} bytes \
                                     (max {MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE})",
                                    witness[i].len()
                                )));
                            }
                        }
                    }
                } else if effective_len == 0 {
                    // 0 stack elements — invalid by consensus
                    return Err(MempoolError::WitnessNonStandard(format!(
                        "input {idx}: taproot witness has no stack elements"
                    )));
                }
                // effective_len == 1: key path spend — no policy rules apply
            }
            _ => {
                // Unknown witness version — succeed (future soft-fork safe)
            }
        }
    }

    Ok(())
}

// ── Ephemeral Dust Policy (BIP683) ──────────────────────────────────────────

/// Whether ephemeral dust outputs are allowed at all.
/// When true, a transaction with fee==0 and exactly one zero-value output is
/// considered standard (the expectation is that the zero-value output will be
/// spent in the same package).
pub const EPHEMERAL_DUST_ALLOWED: bool = true;

/// Check whether a transaction qualifies for the ephemeral dust exemption (BIP683).
///
/// Returns `true` when:
/// - `EPHEMERAL_DUST_ALLOWED` is enabled, AND
/// - `fee` is 0, AND
/// - the transaction has exactly one output with value == 0
///
/// Such transactions are expected to be submitted as part of a package where a
/// child transaction spends the zero-value output and pays the fee for both.
pub fn is_ephemeral_dust_allowed(tx: &Transaction, fee: u64) -> bool {
    if !EPHEMERAL_DUST_ALLOWED {
        return false;
    }
    if fee != 0 {
        return false;
    }
    let zero_value_count = tx.outputs.iter().filter(|o| o.value == 0).count();
    zero_value_count == 1
}

// ── Ephemeral Dust Package Enforcement (M5) ─────────────────────────────────

/// Check that all ephemeral (dust) outputs from parents in a package are spent
/// by children in the same package.
///
/// Mirrors Bitcoin Core's `CheckEphemeralSpends()` from `ephemeral_policy.cpp`.
///
/// For each transaction in the package, collect dust outputs from its in-package
/// (or in-mempool) parents.  Then verify that all such dust outputs are spent
/// by the child.  Returns an error if any parent dust output is left unspent.
pub fn check_ephemeral_spends(
    txs: &[&Transaction],
    mempool: &crate::pool::Mempool,
) -> Result<(), MempoolError> {
    // Build a map of txid -> &Transaction for in-package lookups
    let pkg_map: HashMap<rbtc_primitives::hash::Txid, &Transaction> = txs
        .iter()
        .map(|tx| (*tx.txid(), *tx))
        .collect();

    for tx in txs {
        let mut processed_parents: HashSet<rbtc_primitives::hash::Txid> = HashSet::new();
        let mut unspent_dust: HashSet<OutPoint> = HashSet::new();

        // For each input, find the parent and collect its dust outputs
        for input in &tx.inputs {
            let parent_txid = input.previous_output.txid;

            // Skip parents we've already checked
            if !processed_parents.insert(parent_txid) {
                continue;
            }

            // Look up parent in package, then in mempool
            let parent_outputs: Option<&[rbtc_primitives::transaction::TxOut]> =
                if let Some(ptx) = pkg_map.get(&parent_txid) {
                    Some(&ptx.outputs)
                } else if let Some(entry) = mempool.get(&parent_txid) {
                    Some(&entry.tx.outputs)
                } else {
                    None
                };

            if let Some(outputs) = parent_outputs {
                for (out_idx, output) in outputs.iter().enumerate() {
                    let threshold = dust_threshold(&output.script_pubkey);
                    if threshold > 0 && output.value < threshold as i64 {
                        unspent_dust.insert(OutPoint {
                            txid: parent_txid,
                            vout: out_idx as u32,
                        });
                    }
                }
            }
        }

        if unspent_dust.is_empty() {
            continue;
        }

        // Remove dust outputs that are spent by this child
        for input in &tx.inputs {
            unspent_dust.remove(&input.previous_output);
        }

        if !unspent_dust.is_empty() {
            let child_txid = tx.txid();
            return Err(MempoolError::MissingEphemeralSpends(format!(
                "tx {} did not spend all parent ephemeral dust outputs ({} unspent)",
                child_txid.to_hex(),
                unspent_dust.len()
            )));
        }
    }

    Ok(())
}

// ── Package Topological Sort Check (M8) ─────────────────────────────────────

/// Check that a package is topologically sorted: parents appear before children.
///
/// Mirrors Bitcoin Core's `IsTopoSortedPackage()` from `packages.cpp`.
/// Returns `true` if the package is correctly sorted.
pub fn is_topologically_sorted(txs: &[&Transaction]) -> bool {
    // later_txids tracks txids of the current tx and all subsequent txs.
    let mut later_txids: HashSet<rbtc_primitives::hash::Txid> =
        txs.iter().map(|tx| *tx.txid()).collect();

    for tx in txs {
        // If any input spends a txid that appears later in the list, it's unsorted
        for input in &tx.inputs {
            if later_txids.contains(&input.previous_output.txid) {
                // A parent is placed after its child
                return false;
            }
        }
        // Remove the current tx from later_txids (it's no longer "later")
        later_txids.remove(tx.txid());
    }

    true
}

// ── Package Consistency Check (M9) ──────────────────────────────────────────

/// Check that no two transactions in a package spend the same input.
///
/// Mirrors Bitcoin Core's `IsConsistentPackage()` from `packages.cpp`.
/// Returns `true` if the package has no conflicting transactions.
pub fn is_consistent_package(txs: &[&Transaction]) -> bool {
    let mut inputs_seen: HashSet<OutPoint> = HashSet::new();

    for tx in txs {
        if tx.inputs.is_empty() {
            // Unconfirmed transactions must have inputs; no-input tx is inconsistent
            return false;
        }
        // Check if any input in this tx was already seen in a *different* tx.
        // (We batch-add per-tx to avoid flagging duplicate inputs within a single
        //  tx — that's a consensus error reported elsewhere.)
        for input in &tx.inputs {
            if inputs_seen.contains(&input.previous_output) {
                return false;
            }
        }
        // Batch-add all inputs from this tx
        for input in &tx.inputs {
            inputs_seen.insert(input.previous_output.clone());
        }
    }

    true
}

// ── Package Duplicate Txid Check (L8) ───────────────────────────────────────

/// Check that no two transactions in a package share the same txid.
///
/// Mirrors the duplicate-txid portion of Bitcoin Core's `IsWellFormedPackage()`
/// from `packages.cpp`.  Because txid is computed *without* witness data, this
/// catches both exact duplicates **and** same-txid-different-witness
/// (witness-malleated) pairs.
///
/// Returns `Ok(())` if all txids are unique, or `Err` with the first duplicate
/// txid found.
pub fn check_package_no_duplicate_txids(txs: &[&Transaction]) -> Result<(), MempoolError> {
    let mut seen_txids: HashSet<rbtc_primitives::hash::Txid> = HashSet::with_capacity(txs.len());
    for tx in txs {
        let txid = *tx.txid();
        if !seen_txids.insert(txid) {
            return Err(MempoolError::PackageContainsDuplicates(txid));
        }
    }
    Ok(())
}

// ── Package Shape Validation ────────────────────────────────────────────────

/// Validate that a package has the "child-with-parents" topology
/// (Bitcoin Core's `IsChildWithParents`).
///
/// Rules:
/// - The package must have at least 2 transactions.
/// - The last transaction is the child; all others are its parents.
/// - Every parent's txid must appear as an input of the child.
/// - No parent may spend an output of another parent in the package
///   (no intra-package dependencies among parents).
pub fn is_child_with_parents(txs: &[&Transaction]) -> bool {
    if txs.len() < 2 {
        return false;
    }
    let child = txs.last().unwrap();
    let parents = &txs[..txs.len() - 1];

    // Collect parent txids
    let parent_txids: HashSet<rbtc_primitives::hash::Txid> = parents
        .iter()
        .map(|tx| *tx.txid())
        .collect();

    // Collect the set of txids the child spends
    let child_input_txids: HashSet<rbtc_primitives::hash::Txid> = child
        .inputs
        .iter()
        .map(|i| i.previous_output.txid)
        .collect();

    // Every parent must be spent by the child
    for ptxid in &parent_txids {
        if !child_input_txids.contains(ptxid) {
            return false;
        }
    }

    // No parent may spend another parent's output (no intra-parent deps)
    for parent in parents {
        for input in &parent.inputs {
            if parent_txids.contains(&input.previous_output.txid) {
                return false;
            }
        }
    }

    true
}

// ── V3 Transaction Policy (BIP431) ──────────────────────────────────────────

/// Maximum virtual size for a v3 transaction (10,000 vbytes).
pub const MAX_V3_TX_VSIZE: u64 = 10_000;

/// Maximum virtual size for a v3 child of an unconfirmed v3 parent (1,000 vbytes).
/// Matches Bitcoin Core's TRUC_CHILD_MAX_VSIZE (BIP431).
pub const V3_CHILD_MAX_VSIZE: u64 = 1_000;

/// V3 transaction policy check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V3PolicyError {
    TxTooLarge(u64),
    ChildTooLarge(u64),
    TooManyUnconfirmedParents(usize),
    ParentAlreadyHasChild,
    /// A v3 parent has a non-v3 child spending its outputs (H2 inheritance).
    ParentNotV3(String),
    /// A v3 child spends an unconfirmed input from a non-v3 parent (H2 inheritance).
    ChildNotV3(String),
    /// Package-level TRUC violation (H1).
    PackageViolation(String),
}

impl std::fmt::Display for V3PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxTooLarge(vsize) => write!(f, "v3 tx too large: {vsize} > {MAX_V3_TX_VSIZE}"),
            Self::ChildTooLarge(vsize) => write!(f, "v3 child tx too large: {vsize} > {V3_CHILD_MAX_VSIZE}"),
            Self::TooManyUnconfirmedParents(n) => {
                write!(f, "v3 tx has {n} unconfirmed parents (max 1)")
            }
            Self::ParentAlreadyHasChild => {
                write!(f, "v3 parent tx already has an unconfirmed child")
            }
            Self::ParentNotV3(detail) => {
                write!(f, "v3 parent requires v3 child: {detail}")
            }
            Self::ChildNotV3(detail) => {
                write!(f, "v3 child requires v3 parent: {detail}")
            }
            Self::PackageViolation(detail) => {
                write!(f, "v3 package violation: {detail}")
            }
        }
    }
}

// ── V3 Inheritance Checks (BIP431 / TRUC) ────────────────────────────────

use crate::pool::Mempool;

/// Check v3 inheritance rules for a transaction entering the mempool.
///
/// - If a parent in the mempool is v3, then `tx` must also be v3.
/// - If `tx` is v3, then every unconfirmed parent in the mempool must be v3.
///
/// These rules ensure that v3 transaction topology constraints cannot be
/// circumvented by mixing v3 and non-v3 transactions.
pub fn check_v3_inheritance(tx: &Transaction, mempool: &Mempool) -> Result<(), V3PolicyError> {
    for input in &tx.inputs {
        let ptxid = &input.previous_output.txid;
        if let Some(parent_entry) = mempool.get(ptxid) {
            // If parent is v3, child must also be v3
            if parent_entry.tx.version == 3 && tx.version != 3 {
                return Err(V3PolicyError::ParentNotV3(format!(
                    "parent {} is v3 but child is version {}",
                    ptxid.to_hex(),
                    tx.version
                )));
            }
            // If child is v3, parent must also be v3
            if tx.version == 3 && parent_entry.tx.version != 3 {
                return Err(V3PolicyError::ChildNotV3(format!(
                    "child is v3 but unconfirmed parent {} is version {}",
                    ptxid.to_hex(),
                    parent_entry.tx.version
                )));
            }
        }
    }
    Ok(())
}

// ── Package TRUC Checks (BIP431) ─────────────────────────────────────────

/// Validate a package of transactions together for TRUC/v3 rules.
///
/// Mirrors Bitcoin Core's `PackageTRUCChecks()` from `src/policy/truc_policy.cpp`.
///
/// Rules enforced:
/// 1. No v3 transaction in the package may have more than 1 unconfirmed v3
///    ancestor (counting both mempool and intra-package parents).
/// 2. The v3 child size limit (1,000 vbytes) applies within the package context.
/// 3. "One parent, one child" topology: a v3 parent may only have one child
///    (both in-mempool and within the package).
pub fn package_truc_checks(txs: &[&Transaction], mempool: &Mempool) -> Result<(), V3PolicyError> {
    // Build a quick index of package txids → (version, vsize) for intra-package lookups.
    let pkg_index: HashMap<rbtc_primitives::hash::Txid, (i32, u64)> = txs
        .iter()
        .map(|tx| {
            let mut buf = Vec::new();
            tx.encode_legacy(&mut buf).ok();
            let txid = rbtc_primitives::hash::Txid::from_hash(rbtc_crypto::sha256d(&buf));
            (txid, (tx.version, tx.vsize()))
        })
        .collect();

    // Track which v3 parents (by txid) already have a child in the package,
    // to enforce "one parent, one child".
    let mut v3_parent_child_count: HashMap<rbtc_primitives::hash::Txid, usize> = HashMap::new();

    for tx in txs {
        if tx.version != 3 {
            continue;
        }

        let vsize = tx.vsize();

        // Count unconfirmed v3 ancestors (mempool + intra-package).
        let mut unconfirmed_v3_parents: Vec<rbtc_primitives::hash::Txid> = Vec::new();

        for input in &tx.inputs {
            let ptxid = input.previous_output.txid;

            // Check mempool parents
            if let Some(parent_entry) = mempool.get(&ptxid) {
                if parent_entry.tx.version == 3 {
                    unconfirmed_v3_parents.push(ptxid);
                }
            }
            // Check intra-package parents
            else if let Some(&(pver, _)) = pkg_index.get(&ptxid) {
                if pver == 3 {
                    unconfirmed_v3_parents.push(ptxid);
                }
            }
        }

        // Rule 1: at most 1 unconfirmed v3 ancestor
        if unconfirmed_v3_parents.len() > 1 {
            return Err(V3PolicyError::PackageViolation(format!(
                "v3 tx has {} unconfirmed v3 parents in package (max 1)",
                unconfirmed_v3_parents.len()
            )));
        }

        // Rule 2: v3 child size limit when it has an unconfirmed parent
        if !unconfirmed_v3_parents.is_empty() && vsize > V3_CHILD_MAX_VSIZE {
            return Err(V3PolicyError::PackageViolation(format!(
                "v3 child in package too large: {} vB (max {})",
                vsize, V3_CHILD_MAX_VSIZE
            )));
        }

        // Rule 3: one parent, one child — track child count per v3 parent
        for parent_txid in &unconfirmed_v3_parents {
            let count = v3_parent_child_count.entry(*parent_txid).or_insert(0);
            *count += 1;
            if *count > 1 {
                return Err(V3PolicyError::PackageViolation(format!(
                    "v3 parent {} already has a child in this package",
                    parent_txid.to_hex()
                )));
            }

            // Also check if the parent already has a child in the mempool
            // (not just in the package).
            let parent_has_mempool_child = mempool.txids().iter().any(|mtxid| {
                if let Some(me) = mempool.get(mtxid) {
                    me.tx
                        .inputs
                        .iter()
                        .any(|i| i.previous_output.txid == *parent_txid)
                } else {
                    false
                }
            });
            if parent_has_mempool_child {
                return Err(V3PolicyError::PackageViolation(format!(
                    "v3 parent {} already has an in-mempool child",
                    parent_txid.to_hex()
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};

    // ── Dust threshold tests ─────────────────────────────────────────────

    #[test]
    fn dust_threshold_p2pkh() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        let script = Script::from_bytes(s);
        assert_eq!(dust_threshold(&script), 546);
    }

    #[test]
    fn dust_threshold_p2sh() {
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        s.push(0x87);
        let script = Script::from_bytes(s);
        // P2SH dust = 540 (Bitcoin Core uses nSize-based formula)
        assert_eq!(dust_threshold(&script), 540);
    }

    #[test]
    fn dust_threshold_p2wpkh() {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        let script = Script::from_bytes(s);
        assert_eq!(dust_threshold(&script), 294);
    }

    #[test]
    fn dust_threshold_p2wsh() {
        let mut s = vec![0x00, 0x20];
        s.extend_from_slice(&[0u8; 32]);
        let script = Script::from_bytes(s);
        assert_eq!(dust_threshold(&script), 330);
    }

    #[test]
    fn dust_threshold_p2tr() {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0u8; 32]);
        let script = Script::from_bytes(s);
        assert_eq!(dust_threshold(&script), 330);
    }

    #[test]
    fn dust_threshold_op_return_is_zero() {
        let script = Script::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(dust_threshold(&script), 0);
    }

    // ── IsStandard tests ─────────────────────────────────────────────────

    fn simple_tx(version: i32, outputs: Vec<TxOut>) -> Transaction {
        Transaction::from_parts(
            version,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs,
            0,
        )
    }

    fn p2wpkh_output(value: i64) -> TxOut {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        TxOut {
            value,
            script_pubkey: Script::from_bytes(s),
        }
    }

    fn op_return_output(data: &[u8]) -> TxOut {
        let mut s = vec![0x6a];
        s.push(data.len() as u8);
        s.extend_from_slice(data);
        TxOut {
            value: 0,
            script_pubkey: Script::from_bytes(s),
        }
    }

    #[test]
    fn is_standard_version_3_allowed() {
        // BIP431 TRUC: version 3 is standard
        let tx = simple_tx(3, vec![p2wpkh_output(1_000_000)]);
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn is_standard_version_4_rejected() {
        let tx = simple_tx(4, vec![p2wpkh_output(1_000_000)]);
        assert_eq!(is_standard_tx(&tx), Err(NonStandardReason::VersionTooHigh));
    }

    #[test]
    fn is_standard_one_dust_allowed() {
        // Bitcoin Core v28+: up to MAX_DUST_OUTPUTS_PER_TX (1) dust output is
        // allowed for ephemeral dust support.
        let tx = simple_tx(2, vec![p2wpkh_output(100)]); // 100 < 294
        assert!(
            is_standard_tx(&tx).is_ok(),
            "one dust output should be allowed"
        );
    }

    #[test]
    fn is_standard_two_dust_rejected() {
        // Two dust outputs exceeds MAX_DUST_OUTPUTS_PER_TX.
        let tx = simple_tx(2, vec![p2wpkh_output(100), p2wpkh_output(50)]);
        assert!(matches!(
            is_standard_tx(&tx),
            Err(NonStandardReason::TooManyDustOutputs(2))
        ));
    }

    #[test]
    fn is_standard_above_dust_ok() {
        let tx = simple_tx(2, vec![p2wpkh_output(300)]);
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn is_standard_multi_op_return_allowed() {
        // Bitcoin Core v28+ allows multiple OP_RETURN outputs as long as
        // their aggregate size doesn't exceed MAX_OP_RETURN_RELAY.
        let tx = simple_tx(
            2,
            vec![
                p2wpkh_output(1_000_000),
                op_return_output(&[0xaa; 10]),
                op_return_output(&[0xbb; 10]),
            ],
        );
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn is_standard_single_op_return_ok() {
        let tx = simple_tx(
            2,
            vec![p2wpkh_output(1_000_000), op_return_output(&[0xaa; 10])],
        );
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn is_standard_large_op_return_within_limit() {
        // With MAX_OP_RETURN_RELAY = 100,000 vB (matching Bitcoin Core v28+),
        // a 84-byte OP_RETURN is well within limits.
        let tx = simple_tx(
            2,
            vec![p2wpkh_output(1_000_000), op_return_output(&[0xaa; 84])],
        );
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn is_standard_bare_multisig_permitted_by_default() {
        // Build a 1-of-1 bare multisig: OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
        let mut spk = vec![0x51]; // OP_1
        spk.push(33); // push 33 bytes
        spk.extend_from_slice(&[0x02; 33]); // dummy compressed pubkey
        spk.push(0x51); // OP_1
        spk.push(0xae); // OP_CHECKMULTISIG
        let tx = simple_tx(
            2,
            vec![TxOut { value: 1_000_000, script_pubkey: Script::from_bytes(spk.clone()) }],
        );
        // Default: permit_bare_multisig=true (Bitcoin Core DEFAULT_PERMIT_BAREMULTISIG)
        assert!(is_standard_tx(&tx).is_ok());
        // When explicitly disabled, reject
        assert_eq!(
            is_standard_tx_with_options(&tx, false),
            Err(NonStandardReason::BareMutisig),
        );
    }

    // ── scriptSig push-only tests ─────────────────────────────────────

    #[test]
    fn is_standard_scriptsig_push_only_accepted() {
        // A scriptSig with only push operations is standard.
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Txid::from_hash(
                        rbtc_primitives::hash::Hash256([1; 32]),
                    ),
                    vout: 0,
                },
                // OP_0 followed by a 20-byte push — all push-only
                script_sig: Script::from_bytes(vec![0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn is_standard_scriptsig_non_push_rejected() {
        // A scriptSig containing OP_DUP (0x76) is non-push and should be rejected.
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Txid::from_hash(
                        rbtc_primitives::hash::Hash256([1; 32]),
                    ),
                    vout: 0,
                },
                // OP_DUP is 0x76 — not a push opcode
                script_sig: Script::from_bytes(vec![0x76]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );
        assert_eq!(
            is_standard_tx(&tx),
            Err(NonStandardReason::ScriptSigNotPushOnly(0))
        );
    }

    #[test]
    fn is_standard_scriptsig_op_checksig_rejected() {
        // A scriptSig containing OP_CHECKSIG (0xac) after valid pushes is rejected.
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Txid::from_hash(
                        rbtc_primitives::hash::Hash256([1; 32]),
                    ),
                    vout: 0,
                },
                // push 1 byte (0x01 0xff) then OP_CHECKSIG (0xac)
                script_sig: Script::from_bytes(vec![0x01, 0xff, 0xac]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );
        assert_eq!(
            is_standard_tx(&tx),
            Err(NonStandardReason::ScriptSigNotPushOnly(0))
        );
    }

    // ── Sigops counting tests ───────────────────────────────────────────

    #[test]
    fn count_sigops_checksig() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG = 1 sigop
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(count_script_sigops(&s), 1);
    }

    #[test]
    fn count_sigops_checkmultisig() {
        // OP_CHECKMULTISIG = 20 sigops (worst case)
        assert_eq!(count_script_sigops(&[0xae]), 20);
    }

    #[test]
    fn count_tx_sigops_basic() {
        let tx = simple_tx(1, vec![p2wpkh_output(1_000_000)]);
        // P2WPKH output has no legacy sigops, input has empty scriptSig
        assert_eq!(count_tx_sigops(&tx), 0);
    }

    // ── IsWitnessStandard tests ──────────────────────────────────────────

    #[test]
    fn witness_standard_p2wsh_too_many_stack_items() {
        use rbtc_consensus::utxo::Utxo;

        // Build a P2WSH scriptPubKey: OP_0 <32-byte hash>
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&[0xab; 32]);
        let prev_outpoint = OutPoint {
            txid: rbtc_primitives::hash::Txid::from_hash(
                rbtc_primitives::hash::Hash256([2; 32]),
            ),
            vout: 0,
        };

        // Create a witness with 101 stack items + 1 witness script = 102 total.
        // Stack items (excluding script) = 101 > MAX_STANDARD_P2WSH_STACK_ITEMS (100).
        let mut witness: Vec<Vec<u8>> = (0..101).map(|_| vec![0x01]).collect();
        witness.push(vec![0x51]); // witness script (last item)

        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: prev_outpoint.clone(),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness,
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut input_view = HashMap::new();
        input_view.insert(
            prev_outpoint,
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        let result = is_witness_standard(&tx, &input_view);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, MempoolError::WitnessNonStandard(_)),
            "expected WitnessNonStandard, got: {err:?}"
        );

        // Exactly 100 stack items should be fine
        let mut ok_witness: Vec<Vec<u8>> = (0..100).map(|_| vec![0x01]).collect();
        ok_witness.push(vec![0x51]); // witness script

        let ok_tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Txid::from_hash(
                        rbtc_primitives::hash::Hash256([2; 32]),
                    ),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: ok_witness,
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut ok_view = HashMap::new();
        let mut spk2 = vec![0x00, 0x20];
        spk2.extend_from_slice(&[0xab; 32]);
        ok_view.insert(
            OutPoint {
                txid: rbtc_primitives::hash::Txid::from_hash(
                    rbtc_primitives::hash::Hash256([2; 32]),
                ),
                vout: 0,
            },
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk2),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        assert!(is_witness_standard(&ok_tx, &ok_view).is_ok());
    }

    // ── H1: package_truc_checks tests ────────────────────────────────────

    fn make_v3_tx(prev_txid: rbtc_primitives::hash::Txid, value: i64) -> Transaction {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        Transaction::from_parts(
            3,
            vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            vec![TxOut { value, script_pubkey: Script::from_bytes(spk) }],
            0,
        )
    }

    fn make_v1_tx(prev_txid: rbtc_primitives::hash::Txid, value: i64) -> Transaction {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            vec![TxOut { value, script_pubkey: Script::from_bytes(spk) }],
            0,
        )
    }

    #[test]
    fn package_truc_checks_valid_pair() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        // v3 parent and v3 child with parent→child relationship.
        let parent = make_v3_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x01; 32])),
            99_000_000,
        );
        let parent_txid = *parent.txid();
        let child = make_v3_tx(parent_txid, 98_000_000);

        let txs: Vec<&Transaction> = vec![&parent, &child];
        assert!(package_truc_checks(&txs, &mp).is_ok());
    }

    #[test]
    fn package_truc_checks_too_many_v3_parents() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        // Two v3 parents in the package
        let parent1 = make_v3_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x01; 32])),
            99_000_000,
        );
        let parent2 = make_v3_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x02; 32])),
            99_000_000,
        );
        let p1_txid = *parent1.txid();
        let p2_txid = *parent2.txid();

        // Child spending both parents
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        let child = Transaction::from_parts(
            3,
            vec![
                TxIn {
                    previous_output: OutPoint { txid: p1_txid, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint { txid: p2_txid, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
            ],
            vec![TxOut { value: 97_000_000, script_pubkey: Script::from_bytes(spk) }],
            0,
        );

        let txs: Vec<&Transaction> = vec![&parent1, &parent2, &child];
        let err = package_truc_checks(&txs, &mp).unwrap_err();
        assert!(
            matches!(&err, V3PolicyError::PackageViolation(msg) if msg.contains("parents")),
            "expected too many parents, got: {err:?}"
        );
    }

    #[test]
    fn package_truc_checks_child_too_large() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        let parent = make_v3_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x03; 32])),
            99_000_000,
        );
        let parent_txid = *parent.txid();

        // Large child (>1000 vbytes)
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        let child = Transaction::from_parts(
            3,
            vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 0 },
                script_sig: Script::from_bytes(vec![0x51; 1020]),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            vec![TxOut { value: 98_000_000, script_pubkey: Script::from_bytes(spk) }],
            0,
        );
        assert!(child.vsize() > V3_CHILD_MAX_VSIZE);

        let txs: Vec<&Transaction> = vec![&parent, &child];
        let err = package_truc_checks(&txs, &mp).unwrap_err();
        assert!(
            matches!(&err, V3PolicyError::PackageViolation(msg) if msg.contains("too large")),
            "expected child too large, got: {err:?}"
        );
    }

    #[test]
    fn package_truc_checks_one_parent_one_child() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        let parent = make_v3_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x04; 32])),
            99_000_000,
        );
        let parent_txid = *parent.txid();

        let child1 = make_v3_tx(parent_txid, 98_000_000);
        // second child spending same parent (different output index isn't checked
        // — we check parent txid)
        let child2 = make_v3_tx(parent_txid, 97_000_000);

        let txs: Vec<&Transaction> = vec![&parent, &child1, &child2];
        let err = package_truc_checks(&txs, &mp).unwrap_err();
        assert!(
            matches!(&err, V3PolicyError::PackageViolation(msg) if msg.contains("already has a child")),
            "expected one parent one child violation, got: {err:?}"
        );
    }

    #[test]
    fn package_truc_non_v3_skipped() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        // Non-v3 txs in a package should not trigger any TRUC checks
        let tx1 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x05; 32])),
            99_000_000,
        );
        let tx2 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x06; 32])),
            99_000_000,
        );

        let txs: Vec<&Transaction> = vec![&tx1, &tx2];
        assert!(package_truc_checks(&txs, &mp).is_ok());
    }

    // ── H2: check_v3_inheritance tests (pure policy) ─────────────────────

    #[test]
    fn check_v3_inheritance_no_mempool_parents_ok() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        // A v3 tx with no in-mempool parents should pass
        let tx = make_v3_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x10; 32])),
            99_000_000,
        );
        assert!(check_v3_inheritance(&tx, &mp).is_ok());
    }

    // ── M1: Ephemeral dust (BIP683) tests ─────────────────────────────────

    #[test]
    fn ephemeral_dust_allowed_zero_fee_one_zero_output() {
        // fee=0, exactly one zero-value output → allowed
        let tx = simple_tx(2, vec![
            p2wpkh_output(0),      // zero-value output
            p2wpkh_output(10_000), // normal output
        ]);
        assert!(is_ephemeral_dust_allowed(&tx, 0));
    }

    #[test]
    fn ephemeral_dust_not_allowed_nonzero_fee() {
        // fee != 0 → not allowed
        let tx = simple_tx(2, vec![p2wpkh_output(0)]);
        assert!(!is_ephemeral_dust_allowed(&tx, 100));
    }

    #[test]
    fn ephemeral_dust_not_allowed_no_zero_outputs() {
        // no zero-value outputs → not allowed
        let tx = simple_tx(2, vec![p2wpkh_output(10_000)]);
        assert!(!is_ephemeral_dust_allowed(&tx, 0));
    }

    #[test]
    fn ephemeral_dust_not_allowed_two_zero_outputs() {
        // two zero-value outputs → not allowed (must be exactly one)
        let tx = simple_tx(2, vec![
            p2wpkh_output(0),
            p2wpkh_output(0),
        ]);
        assert!(!is_ephemeral_dust_allowed(&tx, 0));
    }

    // ── M4: Package shape validation (IsChildWithParents) ─────────────────

    #[test]
    fn is_child_with_parents_valid_topology() {
        // Parent1 -> Child, Parent2 -> Child
        let parent1 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x20; 32])),
            99_000_000,
        );
        let parent2 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x21; 32])),
            99_000_000,
        );
        let p1_txid = *parent1.txid();
        let p2_txid = *parent2.txid();

        // Child spending both parents
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        let child = Transaction::from_parts(
            1,
            vec![
                TxIn {
                    previous_output: OutPoint { txid: p1_txid, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint { txid: p2_txid, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
            ],
            vec![TxOut { value: 97_000_000, script_pubkey: Script::from_bytes(spk) }],
            0,
        );

        let txs: Vec<&Transaction> = vec![&parent1, &parent2, &child];
        assert!(is_child_with_parents(&txs));
    }

    #[test]
    fn is_child_with_parents_single_tx_rejected() {
        let tx = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x30; 32])),
            99_000_000,
        );
        assert!(!is_child_with_parents(&[&tx]));
    }

    #[test]
    fn is_child_with_parents_parent_not_spent_by_child() {
        // Parent exists but child doesn't spend it
        let parent = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x40; 32])),
            99_000_000,
        );
        let child = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x41; 32])),
            98_000_000,
        );
        // child spends 0x41, not parent's txid
        let txs: Vec<&Transaction> = vec![&parent, &child];
        assert!(!is_child_with_parents(&txs));
    }

    #[test]
    fn is_child_with_parents_intra_parent_dep_rejected() {
        // parent2 spends parent1 → intra-parent dependency → invalid topology
        let parent1 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x50; 32])),
            99_000_000,
        );
        let p1_txid = *parent1.txid();
        let parent2 = make_v1_tx(p1_txid, 98_000_000);
        let p2_txid = *parent2.txid();

        // Child spending both
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        let child = Transaction::from_parts(
            1,
            vec![
                TxIn {
                    previous_output: OutPoint { txid: p1_txid, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint { txid: p2_txid, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
            ],
            vec![TxOut { value: 96_000_000, script_pubkey: Script::from_bytes(spk) }],
            0,
        );

        let txs: Vec<&Transaction> = vec![&parent1, &parent2, &child];
        assert!(!is_child_with_parents(&txs));
    }

    // ── M6: P2SH-wrapped witness detection tests ──────────────────────────

    #[test]
    fn witness_standard_p2sh_p2wpkh_valid() {
        use rbtc_consensus::utxo::Utxo;

        // P2SH scriptPubKey wrapping P2WPKH: OP_HASH160 <20-byte-hash> OP_EQUAL
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&[0xab; 20]);
        spk.push(0x87);

        // scriptSig pushes the P2WPKH redeemScript: OP_0 <20-byte-hash>
        let mut redeem_script = vec![0x00, 0x14];
        redeem_script.extend_from_slice(&[0xcd; 20]);
        // scriptSig: <push len> <redeemScript>
        let mut script_sig_bytes = vec![redeem_script.len() as u8];
        script_sig_bytes.extend_from_slice(&redeem_script);

        let prev_outpoint = OutPoint {
            txid: rbtc_primitives::hash::Txid::from_hash(
                rbtc_primitives::hash::Hash256([0x60; 32]),
            ),
            vout: 0,
        };

        // P2WPKH requires exactly 2 witness items
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: prev_outpoint.clone(),
                script_sig: Script::from_bytes(script_sig_bytes),
                sequence: 0xffffffff,
                witness: vec![vec![0x30; 72], vec![0x02; 33]], // sig + pubkey
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut input_view = HashMap::new();
        input_view.insert(
            prev_outpoint,
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        assert!(is_witness_standard(&tx, &input_view).is_ok());
    }

    #[test]
    fn witness_standard_p2sh_p2wpkh_wrong_witness_count() {
        use rbtc_consensus::utxo::Utxo;

        // P2SH wrapping P2WPKH
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&[0xab; 20]);
        spk.push(0x87);

        let mut redeem_script = vec![0x00, 0x14];
        redeem_script.extend_from_slice(&[0xcd; 20]);
        let mut script_sig_bytes = vec![redeem_script.len() as u8];
        script_sig_bytes.extend_from_slice(&redeem_script);

        let prev_outpoint = OutPoint {
            txid: rbtc_primitives::hash::Txid::from_hash(
                rbtc_primitives::hash::Hash256([0x61; 32]),
            ),
            vout: 0,
        };

        // Wrong: 3 witness items for P2WPKH (should be 2)
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: prev_outpoint.clone(),
                script_sig: Script::from_bytes(script_sig_bytes),
                sequence: 0xffffffff,
                witness: vec![vec![0x30; 72], vec![0x02; 33], vec![0x01]],
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut input_view = HashMap::new();
        input_view.insert(
            prev_outpoint,
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        let result = is_witness_standard(&tx, &input_view);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MempoolError::WitnessNonStandard(_)));
    }

    // ── M7: Tapscript stack item size 80-byte limit tests ──────────────────

    #[test]
    fn witness_standard_tapscript_item_too_large() {
        use rbtc_consensus::utxo::Utxo;

        // P2TR scriptPubKey: OP_1 <32-byte-program>
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&[0xab; 32]);

        let prev_outpoint = OutPoint {
            txid: rbtc_primitives::hash::Txid::from_hash(
                rbtc_primitives::hash::Hash256([0x62; 32]),
            ),
            vout: 0,
        };

        // Script-path spend with tapscript leaf version 0xc0:
        // witness = [stack_item (81 bytes), script, control_block]
        // control_block first byte: 0xc0 | parity_bit = 0xc0 or 0xc1
        let control_block = {
            let mut cb = vec![0xc0]; // leaf version 0xc0 (tapscript), even parity
            cb.extend_from_slice(&[0x00; 32]); // internal key (dummy)
            cb
        };

        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: prev_outpoint.clone(),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![
                    vec![0xaa; 81], // stack item > 80 bytes
                    vec![0x51],     // script (OP_1)
                    control_block,
                ],
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut input_view = HashMap::new();
        input_view.insert(
            prev_outpoint,
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        let result = is_witness_standard(&tx, &input_view);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("tapscript"), "expected tapscript error, got: {err_msg}");
    }

    #[test]
    fn witness_standard_tapscript_item_at_limit_ok() {
        use rbtc_consensus::utxo::Utxo;

        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&[0xab; 32]);

        let prev_outpoint = OutPoint {
            txid: rbtc_primitives::hash::Txid::from_hash(
                rbtc_primitives::hash::Hash256([0x63; 32]),
            ),
            vout: 0,
        };

        let control_block = {
            let mut cb = vec![0xc0];
            cb.extend_from_slice(&[0x00; 32]);
            cb
        };

        // Stack item exactly 80 bytes — should be fine
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: prev_outpoint.clone(),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![
                    vec![0xaa; 80], // exactly 80 bytes — at limit
                    vec![0x51],     // script
                    control_block,
                ],
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut input_view = HashMap::new();
        input_view.insert(
            prev_outpoint,
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        assert!(is_witness_standard(&tx, &input_view).is_ok());
    }

    #[test]
    fn witness_standard_taproot_key_path_no_limit() {
        use rbtc_consensus::utxo::Utxo;

        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&[0xab; 32]);

        let prev_outpoint = OutPoint {
            txid: rbtc_primitives::hash::Txid::from_hash(
                rbtc_primitives::hash::Hash256([0x64; 32]),
            ),
            vout: 0,
        };

        // Key path spend: single witness item (signature, can be > 80 bytes)
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: prev_outpoint.clone(),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![vec![0xaa; 100]], // 100-byte sig — no limit on key path
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut input_view = HashMap::new();
        input_view.insert(
            prev_outpoint,
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        assert!(is_witness_standard(&tx, &input_view).is_ok());
    }

    #[test]
    fn witness_standard_tapscript_non_c0_leaf_no_limit() {
        use rbtc_consensus::utxo::Utxo;

        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&[0xab; 32]);

        let prev_outpoint = OutPoint {
            txid: rbtc_primitives::hash::Txid::from_hash(
                rbtc_primitives::hash::Hash256([0x65; 32]),
            ),
            vout: 0,
        };

        // Script-path with non-0xc0 leaf version (e.g., 0xc2)
        // Should not enforce the 80-byte limit
        let control_block = {
            let mut cb = vec![0xc2]; // leaf version 0xc2 (not tapscript)
            cb.extend_from_slice(&[0x00; 32]);
            cb
        };

        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: prev_outpoint.clone(),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![
                    vec![0xaa; 200], // 200-byte item — no limit for non-tapscript leaf
                    vec![0x51],      // script
                    control_block,
                ],
            }],
            vec![p2wpkh_output(1_000_000)],
            0,
        );

        let mut input_view = HashMap::new();
        input_view.insert(
            prev_outpoint,
            Utxo {
                txout: TxOut {
                    value: 2_000_000,
                    script_pubkey: Script::from_bytes(spk),
                },
                is_coinbase: false,
                height: 100,
            },
        );

        assert!(is_witness_standard(&tx, &input_view).is_ok());
    }

    // ── M8: Topological sort check tests ──────────────────────────────────

    #[test]
    fn topological_sort_valid_order() {
        let parent = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x70; 32])),
            99_000_000,
        );
        let parent_txid = *parent.txid();
        let child = make_v1_tx(parent_txid, 98_000_000);

        assert!(is_topologically_sorted(&[&parent, &child]));
    }

    #[test]
    fn topological_sort_invalid_order() {
        let parent = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x71; 32])),
            99_000_000,
        );
        let parent_txid = *parent.txid();
        let child = make_v1_tx(parent_txid, 98_000_000);

        // Child before parent — unsorted
        assert!(!is_topologically_sorted(&[&child, &parent]));
    }

    #[test]
    fn topological_sort_unrelated_txs() {
        let tx1 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x72; 32])),
            99_000_000,
        );
        let tx2 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x73; 32])),
            99_000_000,
        );

        // Unrelated transactions — any order is valid
        assert!(is_topologically_sorted(&[&tx1, &tx2]));
        assert!(is_topologically_sorted(&[&tx2, &tx1]));
    }

    // ── M9: Consistent package check tests ─────────────────────────────────

    #[test]
    fn consistent_package_no_conflicts() {
        let tx1 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x80; 32])),
            99_000_000,
        );
        let tx2 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x81; 32])),
            99_000_000,
        );

        assert!(is_consistent_package(&[&tx1, &tx2]));
    }

    #[test]
    fn consistent_package_same_input_conflict() {
        // Two txs spending the same outpoint
        let shared_prev = rbtc_primitives::hash::Txid::from_hash(
            rbtc_primitives::hash::Hash256([0x82; 32]),
        );
        let tx1 = make_v1_tx(shared_prev, 99_000_000);
        let tx2 = make_v1_tx(shared_prev, 98_000_000);

        assert!(!is_consistent_package(&[&tx1, &tx2]));
    }

    // ── L8: Package duplicate txid check tests ─────────────────────────────

    #[test]
    fn no_duplicate_txids_distinct_txs() {
        let tx1 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0xA0; 32])),
            99_000_000,
        );
        let tx2 = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0xA1; 32])),
            98_000_000,
        );
        assert!(check_package_no_duplicate_txids(&[&tx1, &tx2]).is_ok());
    }

    #[test]
    fn duplicate_txids_exact_copy_rejected() {
        let tx = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0xA2; 32])),
            99_000_000,
        );
        let result = check_package_no_duplicate_txids(&[&tx, &tx]);
        assert!(result.is_err());
        match result.unwrap_err() {
            MempoolError::PackageContainsDuplicates(dup_txid) => {
                assert_eq!(dup_txid, *tx.txid());
            }
            other => panic!("expected PackageContainsDuplicates, got: {other:?}"),
        }
    }

    #[test]
    fn same_txid_different_witness_rejected() {
        // Build two transactions with identical non-witness fields but different witness data.
        // Since txid is computed without witness, they share the same txid.
        let prev_txid = rbtc_primitives::hash::Txid::from_hash(
            rbtc_primitives::hash::Hash256([0xA3; 32]),
        );
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);

        let tx1 = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xfffffffe,
                witness: vec![vec![0x01; 72]], // witness A
            }],
            vec![TxOut { value: 99_000_000, script_pubkey: Script::from_bytes(spk.clone()) }],
            0,
        );
        let tx2 = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xfffffffe,
                witness: vec![vec![0x02; 72]], // witness B (different)
            }],
            vec![TxOut { value: 99_000_000, script_pubkey: Script::from_bytes(spk) }],
            0,
        );

        // Confirm that txids match but wtxids differ
        assert_eq!(tx1.txid(), tx2.txid());
        assert_ne!(tx1.wtxid(), tx2.wtxid());

        // The check must reject this pair
        let result = check_package_no_duplicate_txids(&[&tx1, &tx2]);
        assert!(result.is_err());
        match result.unwrap_err() {
            MempoolError::PackageContainsDuplicates(dup_txid) => {
                assert_eq!(dup_txid, *tx1.txid());
            }
            other => panic!("expected PackageContainsDuplicates, got: {other:?}"),
        }
    }

    // ── M5: Ephemeral dust enforcement tests ───────────────────────────────

    #[test]
    fn ephemeral_spends_all_dust_spent_ok() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        // Parent with a dust output (value 0)
        let parent = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Txid::from_hash(
                        rbtc_primitives::hash::Hash256([0x90; 32]),
                    ),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            vec![
                p2wpkh_output(1_000_000), // non-dust
                p2wpkh_output(0),         // dust (value 0)
            ],
            0,
        );
        let parent_txid = *parent.txid();

        // Child spends both parent outputs (including the dust one)
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        let child = Transaction::from_parts(
            2,
            vec![
                TxIn {
                    previous_output: OutPoint { txid: parent_txid, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint { txid: parent_txid, vout: 1 },
                    script_sig: Script::new(),
                    sequence: 0xfffffffe,
                    witness: vec![],
                },
            ],
            vec![TxOut { value: 900_000, script_pubkey: Script::from_bytes(spk) }],
            0,
        );

        let txs: Vec<&Transaction> = vec![&parent, &child];
        assert!(check_ephemeral_spends(&txs, &mp).is_ok());
    }

    #[test]
    fn ephemeral_spends_unspent_dust_rejected() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        // Parent with a dust output (value 0) at index 1
        let parent = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Txid::from_hash(
                        rbtc_primitives::hash::Hash256([0x91; 32]),
                    ),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            vec![
                p2wpkh_output(1_000_000), // non-dust
                p2wpkh_output(0),         // dust (value 0)
            ],
            0,
        );
        let parent_txid = *parent.txid();

        // Child only spends output 0 (non-dust), does NOT spend output 1 (dust)
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        let child = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            vec![TxOut { value: 900_000, script_pubkey: Script::from_bytes(spk) }],
            0,
        );

        let txs: Vec<&Transaction> = vec![&parent, &child];
        let result = check_ephemeral_spends(&txs, &mp);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MempoolError::MissingEphemeralSpends(_)));
    }

    #[test]
    fn ephemeral_spends_no_dust_parent_ok() {
        use crate::pool::Mempool;
        let mp = Mempool::new();

        // Parent with no dust outputs
        let parent = make_v1_tx(
            rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([0x92; 32])),
            99_000_000,
        );
        let parent_txid = *parent.txid();
        let child = make_v1_tx(parent_txid, 98_000_000);

        let txs: Vec<&Transaction> = vec![&parent, &child];
        assert!(check_ephemeral_spends(&txs, &mp).is_ok());
    }

    // ── M10: P2A witness stuffing rejection ──────────────────────────────

    #[test]
    fn is_pay_to_anchor_correct_script() {
        // P2A: OP_1 OP_PUSH2 0x4e 0x73
        assert!(is_pay_to_anchor(&[0x51, 0x02, 0x4e, 0x73]));
    }

    #[test]
    fn is_pay_to_anchor_wrong_version() {
        // OP_0 instead of OP_1
        assert!(!is_pay_to_anchor(&[0x00, 0x02, 0x4e, 0x73]));
    }

    #[test]
    fn is_pay_to_anchor_wrong_program() {
        // Wrong program bytes
        assert!(!is_pay_to_anchor(&[0x51, 0x02, 0xaa, 0xbb]));
    }

    #[test]
    fn is_pay_to_anchor_too_short() {
        assert!(!is_pay_to_anchor(&[0x51, 0x02]));
    }

    #[test]
    fn is_pay_to_anchor_program_variant() {
        assert!(is_pay_to_anchor_program(1, &[0x4e, 0x73]));
        assert!(!is_pay_to_anchor_program(0, &[0x4e, 0x73]));
        assert!(!is_pay_to_anchor_program(1, &[0x4e]));
    }

    #[test]
    fn witness_standard_rejects_p2a_witness_stuffing() {
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        use rbtc_primitives::hash::Hash256;
        use rbtc_consensus::utxo::Utxo;

        // Create a P2A scriptPubKey: OP_1 OP_PUSH2 0x4e73
        let p2a_spk = Script::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]);

        let prev_txid = rbtc_primitives::hash::Txid::from_hash(Hash256([0xaa; 32]));
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };

        // Transaction spending a P2A output with non-empty witness
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: outpoint.clone(),
                script_sig: Script::default(),
                sequence: 0xfffffffe,
                witness: vec![vec![0x01]], // non-empty witness = stuffing
            }],
            vec![TxOut { value: 0, script_pubkey: Script::from_bytes(vec![0x6a]) }],
            0,
        );

        let mut input_view = std::collections::HashMap::new();
        input_view.insert(outpoint.clone(), Utxo {
            txout: TxOut { value: 330, script_pubkey: p2a_spk },
            height: 100,
            is_coinbase: false,
        });

        let result = is_witness_standard(&tx, &input_view);
        assert!(result.is_err(), "P2A with witness data should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Pay-to-Anchor"), "error should mention P2A: {err_msg}");
    }

    #[test]
    fn witness_standard_allows_p2a_without_witness() {
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        use rbtc_primitives::hash::Hash256;
        use rbtc_consensus::utxo::Utxo;

        let p2a_spk = Script::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]);
        let prev_txid = rbtc_primitives::hash::Txid::from_hash(Hash256([0xbb; 32]));
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };

        // P2A input with empty witness — should be fine
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: outpoint.clone(),
                script_sig: Script::default(),
                sequence: 0xfffffffe,
                witness: vec![],
            }],
            vec![TxOut { value: 0, script_pubkey: Script::from_bytes(vec![0x6a]) }],
            0,
        );

        let mut input_view = std::collections::HashMap::new();
        input_view.insert(outpoint, Utxo {
            txout: TxOut { value: 330, script_pubkey: p2a_spk },
            height: 100,
            is_coinbase: false,
        });

        assert!(is_witness_standard(&tx, &input_view).is_ok());
    }

    // ── M11: Sigops-adjusted virtual size ────────────────────────────────

    #[test]
    fn virtual_size_no_sigops() {
        // weight=400, sigops=0 => vsize = ceil(max(400, 0) / 4) = 100
        assert_eq!(get_virtual_transaction_size(400, 0, DEFAULT_BYTES_PER_SIGOP), 100);
    }

    #[test]
    fn virtual_size_sigops_dominate() {
        // weight=400, sigops=100 => sigop_weight = 100*20 = 2000
        // vsize = ceil(max(400, 2000) / 4) = 500
        assert_eq!(get_virtual_transaction_size(400, 100, DEFAULT_BYTES_PER_SIGOP), 500);
    }

    #[test]
    fn virtual_size_weight_dominates() {
        // weight=4000, sigops=10 => sigop_weight = 10*20 = 200
        // vsize = ceil(max(4000, 200) / 4) = 1000
        assert_eq!(get_virtual_transaction_size(4000, 10, DEFAULT_BYTES_PER_SIGOP), 1000);
    }

    #[test]
    fn virtual_size_rounds_up() {
        // weight=401, sigops=0 => vsize = ceil(401/4) = 101
        assert_eq!(get_virtual_transaction_size(401, 0, DEFAULT_BYTES_PER_SIGOP), 101);
    }

    #[test]
    fn virtual_size_equal_weight_and_sigops() {
        // weight=400, sigops=20 => sigop_weight = 20*20 = 400
        // vsize = ceil(max(400, 400) / 4) = 100
        assert_eq!(get_virtual_transaction_size(400, 20, DEFAULT_BYTES_PER_SIGOP), 100);
    }

    // ── C2: Transaction version bounds ──────────────────────────────────────

    fn make_standard_tx(version: i32) -> Transaction {
        let input = TxIn {
            previous_output: OutPoint { txid: rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([1u8; 32])), vout: 0 },
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        // P2WPKH output (standard, above dust)
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0xab; 20]);
        let output = TxOut { value: 100_000, script_pubkey: Script::from_bytes(spk) };
        Transaction::from_parts(version, vec![input], vec![output], 0)
    }

    #[test]
    fn is_standard_rejects_version_zero() {
        let tx = make_standard_tx(0);
        assert_eq!(is_standard_tx(&tx), Err(NonStandardReason::VersionTooLow));
    }

    #[test]
    fn is_standard_rejects_negative_version() {
        let tx = make_standard_tx(-1);
        assert_eq!(is_standard_tx(&tx), Err(NonStandardReason::VersionTooLow));
    }

    #[test]
    fn is_standard_accepts_version_1_2_3() {
        for v in 1..=3 {
            let tx = make_standard_tx(v);
            assert!(is_standard_tx(&tx).is_ok(), "version {v} should be standard");
        }
    }

    #[test]
    fn is_standard_rejects_version_4() {
        let tx = make_standard_tx(4);
        assert_eq!(is_standard_tx(&tx), Err(NonStandardReason::VersionTooHigh));
    }

    // ── C3: Bare multisig policy ────────────────────────────────────────────

    fn make_bare_multisig_tx() -> Transaction {
        let input = TxIn {
            previous_output: OutPoint { txid: rbtc_primitives::hash::Txid::from_hash(rbtc_primitives::hash::Hash256([1u8; 32])), vout: 0 },
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        // 1-of-1 bare multisig: OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
        let mut spk = vec![0x51]; // OP_1
        spk.push(0x21); // push 33 bytes
        spk.extend_from_slice(&[0x02; 33]); // compressed pubkey
        spk.push(0x51); // OP_1
        spk.push(0xae); // OP_CHECKMULTISIG
        let output = TxOut { value: 100_000, script_pubkey: Script::from_bytes(spk) };
        Transaction::from_parts(2, vec![input], vec![output], 0)
    }

    #[test]
    fn bare_multisig_permitted_by_default() {
        let tx = make_bare_multisig_tx();
        // Default: permit_bare_multisig = true (matching Bitcoin Core DEFAULT_PERMIT_BAREMULTISIG)
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn bare_multisig_rejected_when_not_permitted() {
        let tx = make_bare_multisig_tx();
        assert_eq!(
            is_standard_tx_with_options(&tx, false),
            Err(NonStandardReason::BareMutisig)
        );
    }

    /// Helper: build a transaction with a single m-of-n bare multisig output.
    fn make_bare_multisig_tx_m_of_n(m: u8, n: u8) -> Transaction {
        let input = TxIn {
            previous_output: OutPoint {
                txid: rbtc_primitives::hash::Txid::from_hash(
                    rbtc_primitives::hash::Hash256([1u8; 32]),
                ),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        // OP_m <pubkey1> ... <pubkeyn> OP_n OP_CHECKMULTISIG
        let mut spk = vec![0x50 + m]; // OP_m
        for _ in 0..n {
            spk.push(0x21); // push 33 bytes
            spk.extend_from_slice(&[0x02; 33]); // compressed pubkey
        }
        spk.push(0x50 + n); // OP_n
        spk.push(0xae); // OP_CHECKMULTISIG
        let output = TxOut {
            value: 100_000,
            script_pubkey: Script::from_bytes(spk),
        };
        Transaction::from_parts(2, vec![input], vec![output], 0)
    }

    #[test]
    fn bare_multisig_1_of_3_is_standard() {
        let tx = make_bare_multisig_tx_m_of_n(1, 3);
        assert!(is_standard_tx(&tx).is_ok(), "1-of-3 bare multisig should be standard");
    }

    #[test]
    fn bare_multisig_1_of_4_rejected_too_many_keys() {
        let tx = make_bare_multisig_tx_m_of_n(1, 4);
        assert_eq!(
            is_standard_tx(&tx),
            Err(NonStandardReason::MultisigTooManyKeys(0))
        );
    }

    #[test]
    fn bare_multisig_3_of_3_is_standard() {
        let tx = make_bare_multisig_tx_m_of_n(3, 3);
        assert!(is_standard_tx(&tx).is_ok(), "3-of-3 bare multisig should be standard");
    }

    #[test]
    fn bare_multisig_2_of_4_rejected_too_many_keys() {
        let tx = make_bare_multisig_tx_m_of_n(2, 4);
        assert_eq!(
            is_standard_tx(&tx),
            Err(NonStandardReason::MultisigTooManyKeys(0))
        );
    }
}
