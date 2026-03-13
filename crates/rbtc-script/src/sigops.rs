//! SigOp pre-counting functions (without executing the script).
//!
//! These mirror Bitcoin Core's `GetLegacySigOpCount()`, `GetP2SHSigOpCount()`,
//! and `CountWitnessSigOps()`.  They are used for block and mempool sigop
//! limit enforcement.

use rbtc_primitives::script::Script;

// ── helpers ──────────────────────────────────────────────────────────────

/// Parse a witness program from a scriptPubKey.
/// Returns `(version, program_bytes)` or `None`.
fn parse_witness_program(script: &Script) -> Option<(u8, &[u8])> {
    let bytes = script.as_bytes();
    if !(4..=42).contains(&bytes.len()) {
        return None;
    }
    let version = match bytes[0] {
        0x00 => 0,
        0x51..=0x60 => bytes[0] - 0x50,
        _ => return None,
    };
    let program_len = bytes[1] as usize;
    if !(2..=40).contains(&program_len) || program_len + 2 != bytes.len() {
        return None;
    }
    Some((version, &bytes[2..]))
}

/// Extract the last push-data element from a script (used to find the
/// serialized redeem script inside a P2SH scriptSig).
fn extract_last_push_data(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    let mut pc = 0usize;
    let mut last: Option<&[u8]> = None;
    while pc < bytes.len() {
        let op = bytes[pc];
        pc += 1;
        match op {
            0x00 => last = Some(&[]),
            0x01..=0x4b => {
                let len = op as usize;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(&bytes[pc..pc + len]);
                pc += len;
            }
            0x4c => {
                // OP_PUSHDATA1
                if pc >= bytes.len() {
                    return None;
                }
                let len = bytes[pc] as usize;
                pc += 1;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(&bytes[pc..pc + len]);
                pc += len;
            }
            0x4d => {
                // OP_PUSHDATA2
                if pc + 1 >= bytes.len() {
                    return None;
                }
                let len = u16::from_le_bytes([bytes[pc], bytes[pc + 1]]) as usize;
                pc += 2;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(&bytes[pc..pc + len]);
                pc += len;
            }
            0x4e => {
                // OP_PUSHDATA4
                if pc + 3 >= bytes.len() {
                    return None;
                }
                let len = u32::from_le_bytes([
                    bytes[pc],
                    bytes[pc + 1],
                    bytes[pc + 2],
                    bytes[pc + 3],
                ]) as usize;
                pc += 4;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(&bytes[pc..pc + len]);
                pc += len;
            }
            0x4f => last = None, // OP_1NEGATE — not a push-data
            0x51..=0x60 => {
                // OP_1..OP_16 — small integers, not raw pushes
                last = None;
            }
            _ => {
                // Any other opcode resets the "last push" tracker
                last = None;
            }
        }
    }
    last.map(|s| s.to_vec())
}

// ── public API ───────────────────────────────────────────────────────────

/// Count legacy (non-accurate) sigops in a single script.
///
/// This is equivalent to Bitcoin Core's per-script `GetSigOpCount(false)`:
/// - OP_CHECKSIG / OP_CHECKSIGVERIFY → 1
/// - OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY → 20 (worst case)
///
/// The caller should sum over all inputs' `script_sig` and all outputs'
/// `script_pubkey` to get the transaction-level legacy sigop count, which
/// corresponds to `GetLegacySigOpCount()`.
pub fn count_legacy_sigops(script: &Script) -> u32 {
    script.count_sigops() as u32
}

/// Count P2SH sigops for a single input.
///
/// If `script_pubkey` is P2SH, deserializes the redeem script from the
/// last push in `script_sig` and returns its *accurate* sigop count
/// (CHECKMULTISIG uses the preceding small-integer key count rather than
/// the worst-case 20).
///
/// For non-P2SH outputs, returns 0.
///
/// Corresponds to one input's contribution in Bitcoin Core's
/// `GetP2SHSigOpCount()`.
pub fn count_p2sh_sigops(script_sig: &Script, script_pubkey: &Script) -> u32 {
    if !script_pubkey.is_p2sh() {
        return 0;
    }
    // script_sig must be push-only for valid P2SH
    if !script_sig.is_push_only() {
        return 0;
    }
    let Some(redeem_bytes) = extract_last_push_data(script_sig) else {
        return 0;
    };
    let redeem = Script::from_bytes(redeem_bytes);
    redeem.count_sigops_accurate(true) as u32
}

/// Count witness sigops for a single input.
///
/// Handles:
/// - P2WPKH (v0, 20-byte program) → 1
/// - P2WSH  (v0, 32-byte program) → accurate count of the witness script
///   (last witness item)
/// - P2SH-P2WPKH / P2SH-P2WSH (nested) → unwraps the redeem script from
///   script_sig and recurses on the witness program
///
/// Returns 0 for all witness versions other than 0, including taproot (v1).
/// Tapscript sigops (BIP342) are enforced via the validation weight budget
/// in the script interpreter, not the block/tx sigop limit.
///
/// Corresponds to Bitcoin Core's `CountWitnessSigOps()`.
pub fn count_witness_sigops(
    script_sig: &Script,
    script_pubkey: &Script,
    witness: &[Vec<u8>],
) -> u32 {
    // Direct witness program in scriptPubKey
    if let Some((version, program)) = parse_witness_program(script_pubkey) {
        return witness_program_sigops(version, program, witness);
    }
    // P2SH-wrapped witness (e.g. P2SH-P2WPKH, P2SH-P2WSH)
    if script_pubkey.is_p2sh() {
        let Some(redeem_bytes) = extract_last_push_data(script_sig) else {
            return 0;
        };
        let redeem = Script::from_bytes(redeem_bytes);
        if let Some((version, program)) = parse_witness_program(&redeem) {
            return witness_program_sigops(version, program, witness);
        }
    }
    0
}

fn witness_program_sigops(version: u8, program: &[u8], witness: &[Vec<u8>]) -> u32 {
    if version == 0 {
        // P2WPKH: always 1 sigop
        if program.len() == 20 {
            return 1;
        }
        // P2WSH: count sigops in witness script (last stack item)
        if program.len() == 32 && !witness.is_empty() {
            let ws = Script::from_bytes(witness.last().cloned().unwrap_or_default());
            return ws.count_sigops_accurate(true) as u32;
        }
    }
    // All other witness versions (including v1 taproot): 0 sigops.
    // Tapscript sigops are enforced via the validation weight budget.
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a P2PKH scriptPubKey
    fn p2pkh_script() -> Script {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[0xaa; 20]);
        s.push(0x88); // OP_EQUALVERIFY
        s.push(0xac); // OP_CHECKSIG
        Script::from_bytes(s)
    }

    // Helper: build a P2SH scriptPubKey
    fn p2sh_script() -> Script {
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(&[0xbb; 20]);
        s.push(0x87); // OP_EQUAL
        Script::from_bytes(s)
    }

    // Helper: build a P2WPKH scriptPubKey
    fn p2wpkh_script() -> Script {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[0xcc; 20]);
        Script::from_bytes(s)
    }

    // Helper: build a P2WSH scriptPubKey
    fn p2wsh_script() -> Script {
        let mut s = vec![0x00, 0x20];
        s.extend_from_slice(&[0xdd; 32]);
        Script::from_bytes(s)
    }

    // Helper: build a P2TR scriptPubKey
    fn p2tr_script() -> Script {
        let mut s = vec![0x51, 0x20]; // OP_1 PUSH32
        s.extend_from_slice(&[0xee; 32]);
        Script::from_bytes(s)
    }

    // ── count_legacy_sigops ──────────────────────────────────────────

    #[test]
    fn legacy_sigops_empty() {
        assert_eq!(count_legacy_sigops(&Script::new()), 0);
    }

    #[test]
    fn legacy_sigops_p2pkh() {
        // P2PKH has one OP_CHECKSIG
        assert_eq!(count_legacy_sigops(&p2pkh_script()), 1);
    }

    #[test]
    fn legacy_sigops_checksig_and_checksigverify() {
        // OP_CHECKSIG OP_CHECKSIGVERIFY
        let s = Script::from_bytes(vec![0xac, 0xad]);
        assert_eq!(count_legacy_sigops(&s), 2);
    }

    #[test]
    fn legacy_sigops_checkmultisig() {
        // OP_CHECKMULTISIG — legacy counts as 20
        let s = Script::from_bytes(vec![0xae]);
        assert_eq!(count_legacy_sigops(&s), 20);
    }

    #[test]
    fn legacy_sigops_checkmultisigverify() {
        // OP_CHECKMULTISIGVERIFY — legacy counts as 20
        let s = Script::from_bytes(vec![0xaf]);
        assert_eq!(count_legacy_sigops(&s), 20);
    }

    #[test]
    fn legacy_sigops_multisig_with_pushdata() {
        // OP_2 <33-byte push> <33-byte push> OP_2 OP_CHECKMULTISIG
        let mut s = vec![0x52]; // OP_2
        s.push(0x21); // push 33 bytes
        s.extend_from_slice(&[0x02; 33]);
        s.push(0x21);
        s.extend_from_slice(&[0x03; 33]);
        s.push(0x52); // OP_2
        s.push(0xae); // OP_CHECKMULTISIG
        // Legacy count does NOT use accurate counting → 20
        assert_eq!(count_legacy_sigops(&Script::from_bytes(s)), 20);
    }

    // ── count_p2sh_sigops ────────────────────────────────────────────

    #[test]
    fn p2sh_sigops_non_p2sh_output() {
        // Non-P2SH output → 0
        let sig = Script::from_bytes(vec![0x00]);
        assert_eq!(count_p2sh_sigops(&sig, &p2pkh_script()), 0);
    }

    #[test]
    fn p2sh_sigops_with_checksig_redeem() {
        // Redeem script = OP_CHECKSIG (0xac)
        let redeem = vec![0xac];
        // scriptSig: push the redeem script
        let mut sig = Vec::new();
        sig.push(redeem.len() as u8); // push 1 byte
        sig.extend_from_slice(&redeem);
        let sig = Script::from_bytes(sig);
        assert_eq!(count_p2sh_sigops(&sig, &p2sh_script()), 1);
    }

    #[test]
    fn p2sh_sigops_with_multisig_redeem() {
        // Redeem script: OP_2 <key1> <key2> OP_2 OP_CHECKMULTISIG
        let mut redeem = vec![0x52]; // OP_2
        redeem.push(0x21);
        redeem.extend_from_slice(&[0x02; 33]);
        redeem.push(0x21);
        redeem.extend_from_slice(&[0x03; 33]);
        redeem.push(0x52); // OP_2
        redeem.push(0xae); // OP_CHECKMULTISIG

        // scriptSig: push some dummy sig data then push the redeem script
        let mut sig = Vec::new();
        sig.push(0x00); // OP_0 (dummy for CHECKMULTISIG bug)
        // push a dummy signature
        sig.push(0x47); // push 71 bytes
        sig.extend_from_slice(&[0x30; 71]);
        // push the redeem script using OP_PUSHDATA1 since len > 75
        sig.push(0x4c); // OP_PUSHDATA1
        sig.push(redeem.len() as u8);
        sig.extend_from_slice(&redeem);

        let sig = Script::from_bytes(sig);
        // Accurate count: OP_2 before CHECKMULTISIG → 2 sigops
        assert_eq!(count_p2sh_sigops(&sig, &p2sh_script()), 2);
    }

    #[test]
    fn p2sh_sigops_non_pushonly_scriptsig() {
        // scriptSig with a non-push opcode (OP_DUP) → 0
        let sig = Script::from_bytes(vec![0x76, 0x01, 0xac]);
        assert_eq!(count_p2sh_sigops(&sig, &p2sh_script()), 0);
    }

    // ── count_witness_sigops ─────────────────────────────────────────

    #[test]
    fn witness_sigops_p2wpkh() {
        let sig = Script::new();
        let witness = vec![vec![0x30; 72], vec![0x02; 33]];
        assert_eq!(count_witness_sigops(&sig, &p2wpkh_script(), &witness), 1);
    }

    #[test]
    fn witness_sigops_p2wsh_with_checksig() {
        let sig = Script::new();
        // Witness script = OP_CHECKSIG
        let ws = vec![0xac];
        let witness = vec![vec![0x30; 72], ws];
        assert_eq!(count_witness_sigops(&sig, &p2wsh_script(), &witness), 1);
    }

    #[test]
    fn witness_sigops_p2wsh_with_multisig() {
        let sig = Script::new();
        // Witness script: OP_1 <key> OP_1 OP_CHECKMULTISIG
        let mut ws = vec![0x51]; // OP_1
        ws.push(0x21);
        ws.extend_from_slice(&[0x02; 33]);
        ws.push(0x51); // OP_1
        ws.push(0xae); // OP_CHECKMULTISIG
        let witness = vec![vec![0x00], vec![0x30; 72], ws];
        // Accurate: OP_1 before CHECKMULTISIG → 1
        assert_eq!(count_witness_sigops(&sig, &p2wsh_script(), &witness), 1);
    }

    #[test]
    fn witness_sigops_p2sh_p2wpkh() {
        // P2SH-wrapped P2WPKH
        let wpkh = p2wpkh_script();
        // scriptSig pushes the serialized P2WPKH script
        let mut sig_bytes = Vec::new();
        sig_bytes.push(wpkh.len() as u8);
        sig_bytes.extend_from_slice(wpkh.as_bytes());
        let sig = Script::from_bytes(sig_bytes);

        let witness = vec![vec![0x30; 72], vec![0x02; 33]];
        assert_eq!(count_witness_sigops(&sig, &p2sh_script(), &witness), 1);
    }

    #[test]
    fn witness_sigops_p2sh_p2wsh() {
        // P2SH-wrapped P2WSH
        let wsh = p2wsh_script();
        let mut sig_bytes = Vec::new();
        sig_bytes.push(wsh.len() as u8);
        sig_bytes.extend_from_slice(wsh.as_bytes());
        let sig = Script::from_bytes(sig_bytes);

        // Witness script: OP_CHECKSIG OP_CHECKSIGVERIFY → 2
        let ws = vec![0xac, 0xad];
        let witness = vec![vec![0x30; 72], ws];
        assert_eq!(count_witness_sigops(&sig, &p2sh_script(), &witness), 2);
    }

    #[test]
    fn witness_sigops_non_witness_output() {
        let sig = Script::new();
        let witness: Vec<Vec<u8>> = vec![];
        assert_eq!(count_witness_sigops(&sig, &p2pkh_script(), &witness), 0);
    }

    #[test]
    fn witness_sigops_p2tr_keypath_returns_zero() {
        // Taproot key-path: sigops are NOT counted toward block sigop limit.
        // They are enforced via the BIP342 validation weight budget instead.
        let sig = Script::new();
        let witness = vec![vec![0x30; 64]];
        assert_eq!(count_witness_sigops(&sig, &p2tr_script(), &witness), 0);
    }

    #[test]
    fn witness_sigops_p2tr_scriptpath_returns_zero() {
        // Taproot script-path: sigops are NOT counted toward block sigop limit.
        // Tapscript: OP_CHECKSIG OP_CHECKSIGADD OP_CHECKSIGVERIFY
        let tapscript = vec![0xac, 0xba, 0xad];
        let control_block = vec![0xc0; 33]; // minimal control block
        let witness = vec![vec![0x30; 64], tapscript, control_block];
        let sig = Script::new();
        assert_eq!(count_witness_sigops(&sig, &p2tr_script(), &witness), 0);
    }

    #[test]
    fn witness_sigops_unknown_version() {
        // Witness v2 (future) → 0 sigops
        let mut s = vec![0x52, 0x20]; // OP_2 PUSH32
        s.extend_from_slice(&[0xff; 32]);
        let script = Script::from_bytes(s);
        let witness = vec![vec![0x30; 64]];
        assert_eq!(count_witness_sigops(&Script::new(), &script, &witness), 0);
    }
}
