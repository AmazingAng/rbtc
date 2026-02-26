use rbtc_primitives::{
    script::Script,
    transaction::{Transaction, TxOut},
};
use rbtc_crypto::{
    digest::{hash160, sha256d, tagged_hash},
    sig::{verify_ecdsa_with_policy, verify_schnorr},
    sighash::{sighash_segwit_v0, sighash_taproot, SighashType},
};

use crate::engine::{ScriptEngine, ScriptError, ScriptFlags};

/// Context for script verification
pub struct ScriptContext<'a> {
    pub tx: &'a Transaction,
    pub input_index: usize,
    pub prevout: &'a TxOut,
    pub flags: ScriptFlags,
    /// All previous outputs (needed for Taproot sighash)
    pub all_prevouts: &'a [TxOut],
}

/// Top-level input verification – dispatches to the correct script type
pub fn verify_input(ctx: &ScriptContext<'_>) -> Result<(), ScriptError> {
    let input = &ctx.tx.inputs[ctx.input_index];
    let script_pubkey = &ctx.prevout.script_pubkey;
    let engine = ScriptEngine::new(ctx.flags);

    // ── Segwit v0 (native) ────────────────────────────────────────────────
    if ctx.flags.verify_witness {
        if script_pubkey.is_p2wpkh() {
            let pubkey_hash = script_pubkey.p2wpkh_pubkey_hash().unwrap();
            return verify_p2wpkh(ctx, pubkey_hash);
        }
        if script_pubkey.is_p2wsh() {
            let script_hash = script_pubkey.p2wsh_script_hash().unwrap();
            return verify_p2wsh(ctx, script_hash);
        }
        if script_pubkey.is_p2tr() {
            let output_key = script_pubkey.p2tr_output_key().unwrap();
            return verify_p2tr(ctx, output_key);
        }
    }

    // ── P2SH ──────────────────────────────────────────────────────────────
    if ctx.flags.verify_p2sh && script_pubkey.is_p2sh() {
        let expected_hash = script_pubkey.p2sh_script_hash().unwrap();
        return verify_p2sh(ctx, expected_hash, &engine);
    }

    // ── Legacy P2PKH / P2PK / others ─────────────────────────────────────
    let mut stack: Vec<Vec<u8>> = Vec::new();

    // Execute scriptSig
    engine.execute(
        &input.script_sig,
        &mut stack,
        ctx.tx,
        ctx.input_index,
        ctx.prevout.value,
        &input.script_sig,
    )?;

    // Execute scriptPubKey
    engine.execute(
        script_pubkey,
        &mut stack,
        ctx.tx,
        ctx.input_index,
        ctx.prevout.value,
        script_pubkey,
    )?;

    check_stack_true(&stack)?;

    if ctx.flags.verify_cleanstack && stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }

    Ok(())
}

/// Verify P2WPKH (native SegWit v0, 20-byte key hash)
fn verify_p2wpkh(ctx: &ScriptContext<'_>, pubkey_hash: &[u8; 20]) -> Result<(), ScriptError> {
    let witness = &ctx.tx.inputs[ctx.input_index].witness;
    if witness.len() != 2 {
        return Err(ScriptError::WitnessProgramMismatch);
    }
    let sig = &witness[0];
    let pubkey = &witness[1];

    // Verify pubkey hash
    if hash160(pubkey).0 != *pubkey_hash {
        return Err(ScriptError::WitnessProgramMismatch);
    }

    // Build P2PKH script code: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut sc_bytes = vec![0x76u8, 0xa9, 0x14];
    sc_bytes.extend_from_slice(pubkey_hash);
    sc_bytes.extend_from_slice(&[0x88, 0xac]);
    let script_code = Script::from_bytes(sc_bytes);

    if sig.is_empty() {
        return Err(ScriptError::SigCheckFailed);
    }
    let sighash_type = SighashType::from_u32(*sig.last().unwrap() as u32)
        .unwrap_or(SighashType::All);
    let hash = sighash_segwit_v0(ctx.tx, ctx.input_index, &script_code, ctx.prevout.value, sighash_type);

    verify_ecdsa_with_policy(pubkey, &sig[..sig.len() - 1], &hash.0, ctx.flags.verify_dersig)
        .map_err(|_| ScriptError::SigCheckFailed)
}

/// Verify P2WSH (native SegWit v0, 32-byte script hash)
fn verify_p2wsh(ctx: &ScriptContext<'_>, script_hash: &[u8; 32]) -> Result<(), ScriptError> {
    let witness = &ctx.tx.inputs[ctx.input_index].witness;
    if witness.is_empty() {
        return Err(ScriptError::WitnessProgramMismatch);
    }

    let witness_script_bytes = witness.last().unwrap();
    // Verify script hash
    if sha256d(witness_script_bytes).0 != *script_hash {
        return Err(ScriptError::WitnessProgramMismatch);
    }

    let witness_script = Script::from_bytes(witness_script_bytes.clone());

    // Stack is all witness items except the last (the script itself)
    let mut stack: Vec<Vec<u8>> = witness[..witness.len()-1].to_vec();

    let engine = ScriptEngine::new(ctx.flags);
    engine.execute(
        &witness_script,
        &mut stack,
        ctx.tx,
        ctx.input_index,
        ctx.prevout.value,
        &witness_script,
    )?;

    check_stack_true(&stack)
}

/// Verify P2TR (Taproot, BIP341)
fn verify_p2tr(ctx: &ScriptContext<'_>, output_key: &[u8; 32]) -> Result<(), ScriptError> {
    let witness = &ctx.tx.inputs[ctx.input_index].witness;

    // Annex detection: last witness item starts with 0x50
    let (witness_without_annex, annex) = if witness.len() >= 2
        && witness.last().map(|a| a.first() == Some(&0x50)).unwrap_or(false)
    {
        (&witness[..witness.len()-1], Some(witness.last().unwrap().as_slice()))
    } else {
        (witness.as_slice(), None)
    };

    if witness_without_annex.is_empty() {
        return Err(ScriptError::WitnessProgramMismatch);
    }

    // Key path spend: single 64 or 65 byte signature
    if witness_without_annex.len() == 1 {
        let sig = &witness_without_annex[0];
        let sighash_type = if sig.len() == 65 {
            SighashType::from_u32(sig[64] as u32).ok_or(ScriptError::SigCheckFailed)?
        } else {
            SighashType::TaprootDefault
        };
        let hash = sighash_taproot(
            ctx.tx,
            ctx.input_index,
            ctx.all_prevouts,
            sighash_type,
            None,
            annex,
        );
        let sig_bytes = if sig.len() == 65 { &sig[..64] } else { sig.as_slice() };
        return verify_schnorr(output_key, sig_bytes, &hash.0)
            .map_err(|_| ScriptError::SigCheckFailed);
    }

    // Script path spend: witness = [inputs...] [script] [control_block]
    let control_block = witness_without_annex.last().unwrap();
    let script_bytes = &witness_without_annex[witness_without_annex.len()-2];
    let _inputs = &witness_without_annex[..witness_without_annex.len()-2];

    if control_block.is_empty() {
        return Err(ScriptError::Taproot("empty control block".into()));
    }

    // Compute leaf hash: tagged_hash("TapLeaf", version || compact_script)
    let leaf_version = control_block[0] & 0xfe;
    let mut leaf_data = vec![leaf_version];
    // varint-encode script length
    let script_len = script_bytes.len();
    if script_len < 0xfd {
        leaf_data.push(script_len as u8);
    } else {
        leaf_data.push(0xfd);
        leaf_data.extend_from_slice(&(script_len as u16).to_le_bytes());
    }
    leaf_data.extend_from_slice(script_bytes);
    let leaf_hash = tagged_hash(b"TapLeaf", &leaf_data);

    // Verify Merkle inclusion proof
    let mut merkle_node = leaf_hash.0;
    let path = &control_block[33..];
    for chunk in path.chunks(32) {
        if chunk.len() != 32 { return Err(ScriptError::Taproot("invalid control block length".into())); }
        let chunk_arr: [u8; 32] = chunk.try_into().unwrap();
        let mut branch_data = [0u8; 64];
        // Lexicographic ordering
        if merkle_node <= chunk_arr {
            branch_data[..32].copy_from_slice(&merkle_node);
            branch_data[32..].copy_from_slice(&chunk_arr);
        } else {
            branch_data[..32].copy_from_slice(&chunk_arr);
            branch_data[32..].copy_from_slice(&merkle_node);
        }
        merkle_node = tagged_hash(b"TapBranch", &branch_data).0;
    }

    // Verify tweaked key: output_key = internal_key + hash(internal_key || merkle_root) * G
    let internal_key = &control_block[1..33];
    let mut tweak_data = Vec::with_capacity(64);
    tweak_data.extend_from_slice(internal_key);
    tweak_data.extend_from_slice(&merkle_node);
    let tweak = tagged_hash(b"TapTweak", &tweak_data);

    // Use secp256k1 to verify the tweak
    use secp256k1::{Secp256k1, XOnlyPublicKey};
    let secp = Secp256k1::verification_only();
    let internal_key_arr: [u8; 32] = internal_key
        .try_into()
        .map_err(|_| ScriptError::Taproot("invalid internal key length".into()))?;
    let internal_xonly = XOnlyPublicKey::from_byte_array(internal_key_arr)
        .map_err(|_| ScriptError::Taproot("invalid internal key".into()))?;
    let scalar = secp256k1::Scalar::from_be_bytes(tweak.0)
        .map_err(|_| ScriptError::Taproot("invalid tweak scalar".into()))?;
    let (tweaked_key, _parity) = internal_xonly
        .add_tweak(&secp, &scalar)
        .map_err(|_| ScriptError::Taproot("tweak failed".into()))?;

    let tweaked_bytes = tweaked_key.serialize();
    if tweaked_bytes != *output_key {
        return Err(ScriptError::Taproot("output key mismatch".into()));
    }

    // Execute the tapscript
    let tapscript = Script::from_bytes(script_bytes.clone());
    let mut stack: Vec<Vec<u8>> = _inputs.to_vec();

    // Tapscript execution uses BIP342 rules
    execute_tapscript(ctx, &tapscript, &mut stack, &leaf_hash.0)
}

/// Execute a tapscript (BIP342) – simplified, handles OP_CHECKSIGADD
fn execute_tapscript(
    ctx: &ScriptContext<'_>,
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    leaf_hash: &[u8; 32],
) -> Result<(), ScriptError> {
    let bytes = script.as_bytes();
    let mut pc = 0;

    while pc < bytes.len() {
        let op = bytes[pc]; pc += 1;

        match op {
            // OP_CHECKSIGADD (BIP342)
            0xba => {
                if stack.len() < 3 { return Err(ScriptError::StackUnderflow); }
                let pubkey = stack.pop().unwrap();
                let n_bytes = stack.pop().unwrap();
                let sig = stack.pop().unwrap();

                let n = crate::engine::decode_script_int(&n_bytes, 8)?;

                if sig.is_empty() {
                    // empty sig: push n
                    stack.push(crate::engine::encode_script_int(n));
                    continue;
                }

                let sighash_type = if sig.len() == 65 {
                    SighashType::from_u32(sig[64] as u32).ok_or(ScriptError::SigCheckFailed)?
                } else {
                    SighashType::TaprootDefault
                };

                let hash = sighash_taproot(
                    ctx.tx,
                    ctx.input_index,
                    ctx.all_prevouts,
                    sighash_type,
                    Some(leaf_hash),
                    None,
                );

                let sig_bytes = if sig.len() == 65 { &sig[..64] } else { &sig[..] };
                let ok = verify_schnorr(&pubkey, sig_bytes, &hash.0).is_ok();
                stack.push(crate::engine::encode_script_int(n + if ok { 1 } else { 0 }));
            }
            // OP_CHECKSIG in tapscript
            0xac => {
                if stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                let pubkey = stack.pop().unwrap();
                let sig = stack.pop().unwrap();

                if sig.is_empty() {
                    stack.push(Vec::new());
                    continue;
                }

                let sighash_type = if sig.len() == 65 {
                    SighashType::from_u32(sig[64] as u32).ok_or(ScriptError::SigCheckFailed)?
                } else {
                    SighashType::TaprootDefault
                };

                let hash = sighash_taproot(
                    ctx.tx,
                    ctx.input_index,
                    ctx.all_prevouts,
                    sighash_type,
                    Some(leaf_hash),
                    None,
                );

                let sig_bytes = if sig.len() == 65 { &sig[..64] } else { &sig[..] };
                let ok = verify_schnorr(&pubkey, sig_bytes, &hash.0).is_ok();
                stack.push(if ok { vec![1u8] } else { Vec::new() });
            }
            // Data pushes
            0x01..=0x4b => {
                let len = op as usize;
                if pc + len > bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                stack.push(bytes[pc..pc+len].to_vec());
                pc += len;
            }
            0x4c => {
                if pc >= bytes.len() { return Err(ScriptError::ScriptFailed("truncated".into())); }
                let len = bytes[pc] as usize; pc += 1;
                stack.push(bytes[pc..pc+len].to_vec()); pc += len;
            }
            0x00 => stack.push(Vec::new()),
            0x61 => {} // OP_NOP
            0x69 => {
                // OP_VERIFY
                let top = stack.pop().ok_or(ScriptError::StackUnderflow)?;
                if !crate::engine::cast_to_bool_pub(&top) {
                    return Err(ScriptError::ScriptFailed("OP_VERIFY failed".into()));
                }
            }
            _ => {}
        }
    }

    check_stack_true(stack)
}

fn check_stack_true(stack: &[Vec<u8>]) -> Result<(), ScriptError> {
    match stack.last() {
        None => Err(ScriptError::ScriptFailed("empty stack".into())),
        Some(top) => {
            if !crate::engine::cast_to_bool_pub(top) {
                Err(ScriptError::ScriptFailed("top of stack is false".into()))
            } else {
                Ok(())
            }
        }
    }
}

/// Verify P2SH (BIP16)
fn verify_p2sh(
    ctx: &ScriptContext<'_>,
    expected_hash: &[u8; 20],
    engine: &ScriptEngine,
) -> Result<(), ScriptError> {
    let input = &ctx.tx.inputs[ctx.input_index];

    // scriptSig must only contain push ops (policy rule made consensus by BIP16)
    if !is_push_only(&input.script_sig) {
        return Err(ScriptError::ScriptFailed("P2SH: scriptSig not push-only".into()));
    }

    let mut stack: Vec<Vec<u8>> = Vec::new();
    engine.execute(
        &input.script_sig,
        &mut stack,
        ctx.tx,
        ctx.input_index,
        ctx.prevout.value,
        &input.script_sig,
    )?;

    // Verify the redeem script hash
    let redeem_script_bytes = stack.last().ok_or(ScriptError::StackUnderflow)?.clone();
    if hash160(&redeem_script_bytes).0 != *expected_hash {
        return Err(ScriptError::ScriptFailed("P2SH: redeem script hash mismatch".into()));
    }

    let redeem_script = Script::from_bytes(redeem_script_bytes);

    // P2SH-wrapped SegWit (P2SH-P2WPKH, P2SH-P2WSH)
    if ctx.flags.verify_witness {
        if redeem_script.is_p2wpkh() {
            let pkh = redeem_script.p2wpkh_pubkey_hash().unwrap();
            return verify_p2wpkh(ctx, pkh);
        }
        if redeem_script.is_p2wsh() {
            let sh = redeem_script.p2wsh_script_hash().unwrap();
            return verify_p2wsh(ctx, sh);
        }
    }

    // Remove the redeem script from stack, then execute it
    stack.pop();
    engine.execute(
        &redeem_script,
        &mut stack,
        ctx.tx,
        ctx.input_index,
        ctx.prevout.value,
        &redeem_script,
    )?;

    check_stack_true(&stack)
}

fn is_push_only(script: &Script) -> bool {
    let bytes = script.as_bytes();
    let mut pc = 0;
    while pc < bytes.len() {
        let op = bytes[pc]; pc += 1;
        match op {
            0x00..=0x60 => {
                // push ops (OP_0 through OP_16)
                match op {
                    0x4c => { if pc < bytes.len() { let l = bytes[pc] as usize; pc += 1 + l; } }
                    0x4d => {
                        if pc + 1 < bytes.len() {
                            let l = u16::from_le_bytes([bytes[pc], bytes[pc+1]]) as usize;
                            pc += 2 + l;
                        }
                    }
                    0x4e => {
                        if pc + 3 < bytes.len() {
                            let l = u32::from_le_bytes([bytes[pc], bytes[pc+1], bytes[pc+2], bytes[pc+3]]) as usize;
                            pc += 4 + l;
                        }
                    }
                    0x01..=0x4b => { pc += op as usize; }
                    _ => {}
                }
            }
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::codec::Decodable;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use std::io::Cursor;

    fn decode_hex(s: &str) -> Vec<u8> {
        fn nibble(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex"),
            }
        }
        let bytes = s.as_bytes();
        assert!(bytes.len().is_multiple_of(2), "hex length must be even");
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            out.push((nibble(bytes[i]) << 4) | nibble(bytes[i + 1]));
            i += 2;
        }
        out
    }

    #[test]
    fn verify_input_legacy_true() {
        let tx = rbtc_primitives::transaction::Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::from_bytes(vec![0x51]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: 0,
        };
        let prevout = tx.outputs[0].clone();
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_cleanstack: false, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(verify_input(&ctx).is_ok());
    }

    #[test]
    fn verify_input_cleanstack_fail() {
        let tx = rbtc_primitives::transaction::Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::from_bytes(vec![0x51, 0x51]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: 0,
        };
        let prevout = tx.outputs[0].clone();
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags::standard(),
            all_prevouts: &[prevout.clone()],
        };
        let r = verify_input(&ctx);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), crate::engine::ScriptError::CleanStack));
    }

    #[test]
    fn verify_input_legacy_multisig_with_codeseparator() {
        // Real mainnet case from block 163685 that failed in rbtc:
        // CHECKMULTISIG in scriptSig with OP_CODESEPARATOR must hash from
        // the last code separator for signature verification.
        let spend_hex = "01000000024de8b0c4c2582db95fa6b3567a989b664484c7ad6672c85a3da413773e63fdb8000000006b48304502205b282fbc9b064f3bc823a23edcc0048cbb174754e7aa742e3c9f483ebe02911c022100e4b0b3a117d36cab5a67404dddbf43db7bea3c1530e0fe128ebc15621bd69a3b0121035aa98d5f77cd9a2d88710e6fc66212aff820026f0dad8f32d1f7ce87457dde50ffffffff4de8b0c4c2582db95fa6b3567a989b664484c7ad6672c85a3da413773e63fdb8010000006f004730440220276d6dad3defa37b5f81add3992d510d2f44a317fd85e04f93a1e2daea64660202200f862a0da684249322ceb8ed842fb8c859c0cb94c81e1c5308b4868157a428ee01ab51210232abdc893e7f0631364d7fd01cb33d24da45329a00357b3a7886211ab414d55a51aeffffffff02e0fd1c00000000001976a914380cb3c594de4e7e9b8e18db182987bebb5a4f7088acc0c62d000000000017142a9bc5447d664c1d0141392a842d23dba45c4f13b17500000000";
        let prev_hex = "01000000017ea56cd68c74b4cd1a2f478f361b8a67c15a6629d73d95ef21d96ae213eb5b2d010000006a4730440220228e4deb3bc5b47fc526e2a7f5e9434a52616f8353b55dbc820ccb69d5fbded502206a2874f7f84b20015614694fe25c4d76f10e31571f03c240e3e4bbf1f9985be201210232abdc893e7f0631364d7fd01cb33d24da45329a00357b3a7886211ab414d55affffffff0230c11d00000000001976a914709dcb44da534c550dacf4296f75cba1ba3b317788acc0c62d000000000017142a9bc5447d664c1d0141392a842d23dba45c4f13b17500000000";

        let spend_bytes = decode_hex(spend_hex);
        let prev_bytes = decode_hex(prev_hex);
        let spend = Transaction::decode(&mut Cursor::new(spend_bytes)).expect("decode spend tx");
        let prev = Transaction::decode(&mut Cursor::new(prev_bytes)).expect("decode prev tx");

        let all_prevouts = vec![prev.outputs[0].clone(), prev.outputs[1].clone()];
        let prevout = prev.outputs[1].clone();
        let ctx = ScriptContext {
            tx: &spend,
            input_index: 1,
            prevout: &prevout,
            flags: ScriptFlags {
                verify_p2sh: true,
                verify_dersig: false,
                verify_witness: true,
                verify_nulldummy: false,
                verify_cleanstack: true,
                verify_checklocktimeverify: false,
                verify_checksequenceverify: false,
                verify_taproot: true,
            },
            all_prevouts: &all_prevouts,
        };
        assert!(verify_input(&ctx).is_ok());
    }
}
