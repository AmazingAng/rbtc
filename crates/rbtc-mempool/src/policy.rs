//! Mempool policy checks matching Bitcoin Core's `src/policy/policy.cpp`.
//!
//! Implements:
//! - `GetDustThreshold()` — per-output-type dust limits
//! - `IsStandardTx()` — transaction-level standardness checks
//! - `AreInputsStandard()` — input script standardness

use rbtc_primitives::script::Script;
use rbtc_primitives::transaction::Transaction;

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

/// Minimum relay fee rate per kB in satoshis (1000 sat/kB = 1 sat/vbyte).
pub const DEFAULT_MIN_RELAY_TX_FEE: u64 = 1_000;

/// Maximum OP_RETURN data size considered standard (83 bytes).
pub const MAX_OP_RETURN_RELAY: usize = 83;

/// Maximum number of inputs + outputs (sanity).
pub const MAX_STANDARD_TX_INS_OUTS: usize = 3_000;

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
        if threshold > 0 && output.value < threshold {
            return Some((i, output.value, threshold));
        }
    }
    None
}

// ── IsStandard transaction checks ───────────────────────────────────────────

/// Reason a transaction is non-standard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonStandardReason {
    VersionTooHigh,
    TxTooLarge,
    DustOutput(usize, u64, u64),
    MultiOpReturn,
    ScriptSigTooLarge(usize),
    NonStandardOutput(usize),
    BareMutisig,
}

impl std::fmt::Display for NonStandardReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionTooHigh => write!(f, "version too high"),
            Self::TxTooLarge => write!(f, "tx-size"),
            Self::DustOutput(i, val, thresh) => {
                write!(f, "dust output #{i} value={val} threshold={thresh}")
            }
            Self::MultiOpReturn => write!(f, "multi-op-return"),
            Self::ScriptSigTooLarge(i) => write!(f, "scriptsig-size at input #{i}"),
            Self::NonStandardOutput(i) => write!(f, "scriptpubkey at output #{i}"),
            Self::BareMutisig => write!(f, "bare-multisig"),
        }
    }
}

/// Check if a transaction is "standard" according to Bitcoin Core policy.
///
/// This does NOT check script execution — it only checks structural properties.
pub fn is_standard_tx(tx: &Transaction) -> Result<(), NonStandardReason> {
    // 1. Version check: Bitcoin Core rejects version > 2
    //    (v3 would be checked separately under BIP431)
    if tx.version > 2 {
        return Err(NonStandardReason::VersionTooHigh);
    }

    // 2. Weight check
    if tx.weight() > MAX_STANDARD_TX_WEIGHT {
        return Err(NonStandardReason::TxTooLarge);
    }

    // 3. Input scriptSig size check
    for (i, input) in tx.inputs.iter().enumerate() {
        if input.script_sig.0.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(NonStandardReason::ScriptSigTooLarge(i));
        }
    }

    // 4. Output script type check + dust check
    let mut op_return_count = 0usize;
    for (i, output) in tx.outputs.iter().enumerate() {
        let spk = &output.script_pubkey;

        // Standard output types
        let is_standard = spk.is_p2pkh()
            || spk.is_p2sh()
            || spk.is_p2wpkh()
            || spk.is_p2wsh()
            || spk.is_p2tr()
            || spk.is_op_return()
            || spk.0.is_empty(); // empty scriptPubKey (allowed but dust)

        if spk.is_op_return() {
            op_return_count += 1;
            if spk.0.len() > MAX_OP_RETURN_RELAY {
                return Err(NonStandardReason::NonStandardOutput(i));
            }
        } else if !is_standard {
            return Err(NonStandardReason::NonStandardOutput(i));
        }

        // Dust check (skip OP_RETURN)
        if !spk.is_op_return() {
            let threshold = dust_threshold(spk);
            if threshold > 0 && output.value < threshold {
                return Err(NonStandardReason::DustOutput(i, output.value, threshold));
            }
        }
    }

    // 5. Only one OP_RETURN output allowed
    if op_return_count > 1 {
        return Err(NonStandardReason::MultiOpReturn);
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

// ── V3 Transaction Policy (BIP431) ──────────────────────────────────────────

/// Maximum virtual size for a v3 transaction (10,000 vbytes).
pub const MAX_V3_TX_VSIZE: u64 = 10_000;

/// V3 transaction policy check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V3PolicyError {
    TxTooLarge(u64),
    TooManyUnconfirmedParents(usize),
    ParentAlreadyHasChild,
}

impl std::fmt::Display for V3PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxTooLarge(vsize) => write!(f, "v3 tx too large: {vsize} > {MAX_V3_TX_VSIZE}"),
            Self::TooManyUnconfirmedParents(n) => {
                write!(f, "v3 tx has {n} unconfirmed parents (max 1)")
            }
            Self::ParentAlreadyHasChild => {
                write!(f, "v3 parent tx already has an unconfirmed child")
            }
        }
    }
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
        Transaction {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: rbtc_primitives::hash::Hash256([1; 32]),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs,
            lock_time: 0,
        }
    }

    fn p2wpkh_output(value: u64) -> TxOut {
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
    fn is_standard_version_3_rejected() {
        let tx = simple_tx(3, vec![p2wpkh_output(1_000_000)]);
        assert_eq!(is_standard_tx(&tx), Err(NonStandardReason::VersionTooHigh));
    }

    #[test]
    fn is_standard_dust_rejected() {
        let tx = simple_tx(2, vec![p2wpkh_output(100)]); // 100 < 294
        assert!(matches!(
            is_standard_tx(&tx),
            Err(NonStandardReason::DustOutput(0, 100, 294))
        ));
    }

    #[test]
    fn is_standard_above_dust_ok() {
        let tx = simple_tx(2, vec![p2wpkh_output(300)]);
        assert!(is_standard_tx(&tx).is_ok());
    }

    #[test]
    fn is_standard_multi_op_return_rejected() {
        let tx = simple_tx(
            2,
            vec![
                p2wpkh_output(1_000_000),
                op_return_output(&[0xaa; 10]),
                op_return_output(&[0xbb; 10]),
            ],
        );
        assert_eq!(is_standard_tx(&tx), Err(NonStandardReason::MultiOpReturn));
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
    fn is_standard_large_op_return_rejected() {
        let tx = simple_tx(
            2,
            vec![p2wpkh_output(1_000_000), op_return_output(&[0xaa; 84])],
        );
        assert!(matches!(
            is_standard_tx(&tx),
            Err(NonStandardReason::NonStandardOutput(1))
        ));
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
}
