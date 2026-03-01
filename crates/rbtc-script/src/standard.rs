use rbtc_primitives::{
    constants::{MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE},
    script::Script,
    transaction::{Transaction, TxOut},
};
use rbtc_crypto::{
    digest::{hash160, sha256, tagged_hash},
    sig::{verify_ecdsa_with_policy, verify_schnorr},
    sighash::{sighash_segwit_v0_with_u32, sighash_taproot, SighashType},
};

use crate::engine::{ScriptEngine, ScriptError, ScriptFlags, SigVersion};

fn push_compact_size(dst: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => dst.push(n as u8),
        0xfd..=0xffff => {
            dst.push(0xfd);
            dst.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            dst.push(0xfe);
            dst.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            dst.push(0xff);
            dst.extend_from_slice(&(n as u64).to_le_bytes());
        }
    }
}

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
    let mut had_witness = false;

    // ── P2SH ──────────────────────────────────────────────────────────────
    if ctx.flags.verify_p2sh && script_pubkey.is_p2sh() {
        let expected_hash = script_pubkey.p2sh_script_hash().unwrap();
        had_witness = verify_p2sh(ctx, expected_hash, &engine)?;
    } else if ctx.flags.verify_witness {
        // ── Bare witness program ──────────────────────────────────────────
        if let Some((version, program)) = parse_witness_program(script_pubkey) {
            had_witness = true;
            if !input.script_sig.is_empty() {
                return Err(ScriptError::WitnessMalleated);
            }
            verify_witness_program(ctx, version, program.as_slice(), false)?;
        } else {
            // ── Legacy P2PKH / P2PK / others ─────────────────────────────
            let mut stack: Vec<Vec<u8>> = Vec::new();
            engine.execute(
                &input.script_sig,
                &mut stack,
                ctx.tx,
                ctx.input_index,
                ctx.prevout.value,
                &input.script_sig,
                SigVersion::Base,
                None,
            )?;
            engine.execute(
                script_pubkey,
                &mut stack,
                ctx.tx,
                ctx.input_index,
                ctx.prevout.value,
                script_pubkey,
                SigVersion::Base,
                None,
            )?;
            check_stack_true(&stack)?;
            if ctx.flags.verify_cleanstack && stack.len() != 1 {
                return Err(ScriptError::CleanStack);
            }
        }
    } else {
        // ── Legacy path when witness flag disabled ───────────────────────
        let mut stack: Vec<Vec<u8>> = Vec::new();
        engine.execute(
            &input.script_sig,
            &mut stack,
            ctx.tx,
            ctx.input_index,
            ctx.prevout.value,
            &input.script_sig,
            SigVersion::Base,
            None,
        )?;
        engine.execute(
            script_pubkey,
            &mut stack,
            ctx.tx,
            ctx.input_index,
            ctx.prevout.value,
            script_pubkey,
            SigVersion::Base,
            None,
        )?;
        check_stack_true(&stack)?;
        if ctx.flags.verify_cleanstack && stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }
    }

    if ctx.flags.verify_witness && !had_witness && !input.witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }

    Ok(())
}

fn parse_witness_program(script: &Script) -> Option<(u8, Vec<u8>)> {
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
    if program_len < 2 || program_len > 40 || program_len + 2 != bytes.len() {
        return None;
    }
    Some((version, bytes[2..].to_vec()))
}

fn verify_witness_program(
    ctx: &ScriptContext<'_>,
    version: u8,
    program: &[u8],
    is_p2sh: bool,
) -> Result<(), ScriptError> {
    if version == 0 {
        match program.len() {
            20 => {
                let mut pkh = [0u8; 20];
                pkh.copy_from_slice(program);
                verify_p2wpkh(ctx, &pkh)
            }
            32 => {
                let mut sh = [0u8; 32];
                sh.copy_from_slice(program);
                verify_p2wsh(ctx, &sh)
            }
            _ => Err(ScriptError::WitnessProgramWrongLength),
        }
    } else if version == 1 && program.len() == 32 && !is_p2sh {
        if !ctx.flags.verify_taproot {
            return Ok(());
        }
        let mut out_key = [0u8; 32];
        out_key.copy_from_slice(program);
        verify_p2tr(ctx, &out_key)
    } else {
        // Future witness versions are consensus-valid (soft-fork forward compat).
        Ok(())
    }
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
    let sighash_u32 = *sig.last().unwrap() as u32;
    let hash = sighash_segwit_v0_with_u32(
        ctx.tx,
        ctx.input_index,
        &script_code,
        ctx.prevout.value,
        sighash_u32,
    );

    verify_ecdsa_with_policy(pubkey, &sig[..sig.len() - 1], &hash.0, ctx.flags.verify_dersig)
        .map_err(|_| ScriptError::SigCheckFailed)
}

/// Verify P2WSH (native SegWit v0, 32-byte script hash)
fn verify_p2wsh(ctx: &ScriptContext<'_>, script_hash: &[u8; 32]) -> Result<(), ScriptError> {
    let witness = &ctx.tx.inputs[ctx.input_index].witness;
    if witness.is_empty() {
        return Err(ScriptError::WitnessProgramWitnessEmpty);
    }

    let witness_script_bytes = witness.last().unwrap();
    // BIP141: P2WSH commits to SHA256(witness_script), not SHA256d.
    if sha256(witness_script_bytes).0 != *script_hash {
        return Err(ScriptError::WitnessProgramMismatch);
    }
    if witness_script_bytes.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptTooLarge);
    }

    let witness_script = Script::from_bytes(witness_script_bytes.clone());

    // Stack is all witness items except the last (the script itself)
    let mut stack: Vec<Vec<u8>> = witness[..witness.len()-1].to_vec();
    if stack.iter().any(|item| item.len() > MAX_SCRIPT_ELEMENT_SIZE) {
        return Err(ScriptError::PushSizeExceeded);
    }

    let engine = ScriptEngine::new(ctx.flags);
    engine.execute(
        &witness_script,
        &mut stack,
        ctx.tx,
        ctx.input_index,
        ctx.prevout.value,
        &witness_script,
        SigVersion::WitnessV0,
        None,
    )?;

    check_stack_true(&stack)?;
    if stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }
    Ok(())
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
        let (sig_bytes, sighash_type) = parse_taproot_sig_and_hashtype(sig)?;
        let hash = sighash_taproot(
            ctx.tx,
            ctx.input_index,
            ctx.all_prevouts,
            sighash_type,
            None,
            annex,
            0,
            u32::MAX,
        );
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
    push_compact_size(&mut leaf_data, script_bytes.len());
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
    execute_tapscript(ctx, &tapscript, &mut stack, &leaf_hash.0, annex)
}

/// Execute a tapscript (BIP342) – simplified, handles OP_CHECKSIGADD
fn execute_tapscript(
    ctx: &ScriptContext<'_>,
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    leaf_hash: &[u8; 32],
    annex: Option<&[u8]>,
) -> Result<(), ScriptError> {
    let engine = ScriptEngine::new(ctx.flags);
    engine.execute_tapscript(
        ctx.tx,
        ctx.input_index,
        ctx.all_prevouts,
        script,
        stack,
        leaf_hash,
        annex,
    )
}

fn parse_taproot_sig_and_hashtype(sig: &[u8]) -> Result<(&[u8], SighashType), ScriptError> {
    match sig.len() {
        64 => Ok((sig, SighashType::TaprootDefault)),
        65 => {
            let hash_type = sig[64] as u32;
            if hash_type == 0 {
                return Err(ScriptError::TaprootInvalidSighashType);
            }
            let parsed =
                SighashType::from_u32(hash_type).ok_or(ScriptError::TaprootInvalidSighashType)?;
            Ok((&sig[..64], parsed))
        }
        _ => Err(ScriptError::SigCheckFailed),
    }
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
) -> Result<bool, ScriptError> {
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
        SigVersion::Base,
        None,
    )?;

    // Verify the redeem script hash
    let redeem_script_bytes = stack.last().ok_or(ScriptError::StackUnderflow)?.clone();
    if hash160(&redeem_script_bytes).0 != *expected_hash {
        return Err(ScriptError::ScriptFailed("P2SH: redeem script hash mismatch".into()));
    }

    let redeem_script = Script::from_bytes(redeem_script_bytes);

    // P2SH-wrapped SegWit (P2SH-P2WPKH, P2SH-P2WSH)
    if ctx.flags.verify_witness {
        if let Some((version, program)) = parse_witness_program(&redeem_script) {
            // Core rule: scriptSig must be exactly a single push of redeemScript.
            if !script_sig_is_exact_push(&input.script_sig, redeem_script.as_bytes()) {
                return Err(ScriptError::WitnessMalleatedP2sh);
            }
            verify_witness_program(ctx, version, program.as_slice(), true)?;
            return Ok(true);
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
        SigVersion::Base,
        None,
    )?;

    check_stack_true(&stack)?;
    Ok(false)
}

fn script_sig_is_exact_push(script_sig: &Script, data: &[u8]) -> bool {
    script_sig.as_bytes() == encode_single_push(data).as_slice()
}

fn encode_single_push(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = data.len();
    if len <= 0x4b {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x4c);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(len as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
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
    use serde::Deserialize;
    use secp256k1::{Parity, Scalar, Secp256k1, XOnlyPublicKey};
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

    #[test]
    fn verify_input_legacy_p2pkh_nonstandard_sighash_byte() {
        // Real mainnet case around height 260788:
        // signature has hashtype byte 0x04 (non-standard but consensus-valid).
        let spend_hex = "01000000017047d51eb2671f08be60033dc273da6bf165aeae6f0d2b2c901ccedc592fc84e000000008b48304502210085807b5a614a1a2faf0209c7d95bf046393c19bbbdb2ccafd8cf1e87b906429e02204405c1b759e7a44bdfdd053198f5307f07830e54110bac58c36b40a19ad8cd3a044104bb8f7ebe793c32e49c8f2b929b09ca09ee2b4f121b32c9dfca121450bc2b6762c75ece327c6724c30bfd14430ab4803371185e9060721deff8bdfa7f2ce5d751ffffffff0100710200000000001976a9141e2f6af9a8564c0cb58b8662dc2c63e70bd8b35288ac00000000";
        let prev_hex = "0100000001329846caf4e3eb2c9b78a8b0de8b5ef3240acc690247c3a382376584957d01fd000000008b483045022100ef20a65ed276ac219f9ebda34708c1290090a7dffaed96527a077cd4594e97a7022053945a0d02d4c71f48349ec6a9ac7c42be5e9cecf5ee896ff5fd86d21277d4590141049df8f56621346ecd7a1672269e2f3fffc940974514a86c4c70293a3b35df40d75ee1486965a0a1372af7070d7b49fec555fd84feab29453125422184792e9014ffffffff0250340300000000001976a914a7a120d4358dd1e8bc9566329ead42c4f394ccfc88ac01921600000000001976a91414bdd0c36e430f0fd14643f7df6ce02b53874e3c88ac00000000";

        let spend = Transaction::decode(&mut Cursor::new(decode_hex(spend_hex))).expect("decode spend");
        let prev = Transaction::decode(&mut Cursor::new(decode_hex(prev_hex))).expect("decode prev");
        let prevout = prev.outputs[0].clone();
        let ctx = ScriptContext {
            tx: &spend,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags {
                verify_p2sh: true,
                verify_dersig: false,
                verify_witness: true,
                verify_nulldummy: false,
                verify_cleanstack: false,
                verify_checklocktimeverify: false,
                verify_checksequenceverify: false,
                verify_taproot: true,
            },
            all_prevouts: &[prevout.clone()],
        };
        assert!(verify_input(&ctx).is_ok());
    }

    #[test]
    fn verify_input_witness_malleated_non_empty_scriptsig() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::from_bytes(vec![0x51]),
                sequence: 0xffff_ffff,
                witness: vec![vec![1], vec![2]],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let prevout = TxOut {
            value: 1000,
            script_pubkey: Script::from_bytes({
                let mut s = vec![0x00, 0x14];
                s.extend_from_slice(&[0x11; 20]);
                s
            }),
        };
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_witness: true, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(matches!(verify_input(&ctx), Err(ScriptError::WitnessMalleated)));
    }

    #[test]
    fn verify_input_p2sh_witness_malleated_scriptsig_shape() {
        let redeem = Script::from_bytes({
            let mut s = vec![0x00, 0x20];
            s.extend_from_slice(&[0x22; 32]);
            s
        });
        let mut p2sh_spk = vec![0xa9, 0x14];
        p2sh_spk.extend_from_slice(&hash160(redeem.as_bytes()).0);
        p2sh_spk.push(0x87);
        let prevout = TxOut {
            value: 1000,
            script_pubkey: Script::from_bytes(p2sh_spk),
        };
        // scriptSig pushes junk then redeemScript (not exact single push redeemScript).
        let mut sig = vec![0x01, 0x01];
        sig.extend_from_slice(&encode_single_push(redeem.as_bytes()));
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::from_bytes(sig),
                sequence: 0xffff_ffff,
                witness: vec![vec![0x01], vec![0x02]],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_p2sh: true, verify_witness: true, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(matches!(verify_input(&ctx), Err(ScriptError::WitnessMalleatedP2sh)));
    }

    #[test]
    fn verify_input_witness_unexpected_for_legacy_spk() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::from_bytes(vec![0x51]),
                sequence: 0xffff_ffff,
                witness: vec![vec![0x01]],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let prevout = TxOut { value: 1000, script_pubkey: Script::from_bytes(vec![0x51]) };
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_witness: true, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(matches!(verify_input(&ctx), Err(ScriptError::WitnessUnexpected)));
    }

    #[test]
    fn verify_input_unknown_witness_version_consensus_ok() {
        // OP_2 <32-byte-program>, unknown version: consensus-valid by forward-compat.
        let mut spk = vec![0x52, 0x20];
        spk.extend_from_slice(&[0x33; 32]);
        let prevout = TxOut { value: 1000, script_pubkey: Script::from_bytes(spk) };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![vec![1, 2, 3]],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_witness: true, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(verify_input(&ctx).is_ok());
    }

    #[test]
    fn verify_input_p2wsh_enforces_cleanstack() {
        let witness_script = vec![0x51, 0x51]; // leaves two true elements on stack
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&sha256(&witness_script).0);
        let prevout = TxOut {
            value: 1000,
            script_pubkey: Script::from_bytes(spk),
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![witness_script.clone()],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_witness: true, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(matches!(verify_input(&ctx), Err(ScriptError::CleanStack)));
    }

    #[test]
    fn verify_input_p2wsh_witness_empty_error() {
        let witness_script = vec![0x51];
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&sha256(&witness_script).0);
        let prevout = TxOut {
            value: 1000,
            script_pubkey: Script::from_bytes(spk),
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_witness: true, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(matches!(verify_input(&ctx), Err(ScriptError::WitnessProgramWitnessEmpty)));
    }

    #[test]
    fn verify_input_p2wsh_rejects_oversized_witness_element() {
        let witness_script = vec![0x75, 0x51]; // OP_DROP OP_TRUE
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&sha256(&witness_script).0);
        let prevout = TxOut {
            value: 1000,
            script_pubkey: Script::from_bytes(spk),
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![vec![0u8; MAX_SCRIPT_ELEMENT_SIZE + 1], witness_script.clone()],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let ctx = ScriptContext {
            tx: &tx,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags { verify_witness: true, ..ScriptFlags::default() },
            all_prevouts: &[prevout.clone()],
        };
        assert!(matches!(verify_input(&ctx), Err(ScriptError::PushSizeExceeded)));
    }

    #[test]
    fn verify_input_segwit_vectors() {
        #[derive(Deserialize)]
        struct FixtureCase {
            name: String,
            prevout_value: u64,
            prevout_script_pubkey_hex: String,
            script_sig_hex: String,
            witness_hex: Vec<String>,
            expected: String,
        }

        fn build_tx(script_sig: Script, witness: Vec<Vec<u8>>) -> Transaction {
            Transaction {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                    script_sig,
                    sequence: 0xffff_ffff,
                    witness,
                }],
                outputs: vec![],
                lock_time: 0,
            }
        }

        fn expected_from_str(s: &str) -> Option<ScriptError> {
            match s {
                "ok" => None,
                "WitnessMalleated" => Some(ScriptError::WitnessMalleated),
                "WitnessProgramWitnessEmpty" => Some(ScriptError::WitnessProgramWitnessEmpty),
                "CleanStack" => Some(ScriptError::CleanStack),
                "WitnessMalleatedP2sh" => Some(ScriptError::WitnessMalleatedP2sh),
                "WitnessUnexpected" => Some(ScriptError::WitnessUnexpected),
                "WitnessProgramWrongLength" => Some(ScriptError::WitnessProgramWrongLength),
                other => panic!("unknown expected value in fixture: {other}"),
            }
        }

        let fixture_text = include_str!("../tests/fixtures/segwit_vectors.json");
        let cases: Vec<FixtureCase> = serde_json::from_str(fixture_text).expect("parse segwit fixture");
        let flags = ScriptFlags { verify_p2sh: true, verify_witness: true, ..ScriptFlags::default() };

        for case in cases {
            let prevout = TxOut {
                value: case.prevout_value,
                script_pubkey: Script::from_bytes(decode_hex(&case.prevout_script_pubkey_hex)),
            };
            let tx = build_tx(
                Script::from_bytes(decode_hex(&case.script_sig_hex)),
                case.witness_hex.iter().map(|h| decode_hex(h)).collect(),
            );
            let all_prevouts = [prevout.clone()];
            let ctx = ScriptContext {
                tx: &tx,
                input_index: 0,
                prevout: &prevout,
                flags,
                all_prevouts: &all_prevouts,
            };
            match expected_from_str(&case.expected) {
                None => assert!(verify_input(&ctx).is_ok(), "case failed: {}", case.name),
                Some(expected) => {
                    let got = verify_input(&ctx).expect_err(&case.name);
                    assert_eq!(got, expected, "case: {}", case.name);
                }
            }
        }
    }

    #[test]
    fn verify_input_taproot_vectors() {
        #[derive(Deserialize)]
        struct FixtureCase {
            name: String,
            mode: String,
            output_key_hex: Option<String>,
            internal_key_hex: Option<String>,
            tapscript_hex: Option<String>,
            witness_stack_hex: Option<Vec<String>>,
            annex_hex: Option<String>,
            sig_hex: Option<String>,
            tamper_control_block: Option<bool>,
            expected: String,
        }

        fn tapleaf_hash(script: &[u8], leaf_version: u8) -> [u8; 32] {
            let mut leaf_data = vec![leaf_version];
            push_compact_size(&mut leaf_data, script.len());
            leaf_data.extend_from_slice(script);
            tagged_hash(b"TapLeaf", &leaf_data).0
        }

        fn build_script_path_case(
            internal_key_hex: &str,
            tapscript_hex: &str,
            witness_stack_hex: &[String],
            annex_hex: Option<&str>,
            tamper_control_block: bool,
        ) -> (TxOut, Vec<Vec<u8>>) {
            let internal_key_bytes = decode_hex(internal_key_hex);
            let internal_arr: [u8; 32] = internal_key_bytes.try_into().expect("internal key length");
            let tapscript = decode_hex(tapscript_hex);
            let leaf_version = 0xc0u8;
            let leaf = tapleaf_hash(&tapscript, leaf_version);

            let secp = Secp256k1::verification_only();
            let internal =
                XOnlyPublicKey::from_byte_array(internal_arr).expect("valid internal xonly");
            let mut tweak_data = Vec::with_capacity(64);
            tweak_data.extend_from_slice(&internal_arr);
            tweak_data.extend_from_slice(&leaf);
            let tweak = tagged_hash(b"TapTweak", &tweak_data);
            let scalar = Scalar::from_be_bytes(tweak.0).expect("valid tweak scalar");
            let (output_key, parity) = internal.add_tweak(&secp, &scalar).expect("tweak");
            let output_key_bytes = output_key.serialize();

            let mut control_block = vec![leaf_version | if parity == Parity::Odd { 1 } else { 0 }];
            control_block.extend_from_slice(&internal_arr);
            if tamper_control_block {
                control_block[1] ^= 0x01;
            }

            let mut spk = vec![0x51, 0x20];
            spk.extend_from_slice(&output_key_bytes);
            let prevout = TxOut {
                value: 1000,
                script_pubkey: Script::from_bytes(spk),
            };

            let mut witness: Vec<Vec<u8>> = witness_stack_hex.iter().map(|h| decode_hex(h)).collect();
            witness.push(tapscript);
            witness.push(control_block);
            if let Some(a) = annex_hex {
                witness.push(decode_hex(a));
            }
            (prevout, witness)
        }

        let fixture_text = include_str!("../tests/fixtures/taproot_vectors.json");
        let cases: Vec<FixtureCase> = serde_json::from_str(fixture_text).expect("parse taproot fixture");
        let flags = ScriptFlags {
            verify_p2sh: true,
            verify_dersig: true,
            verify_witness: true,
            verify_nulldummy: true,
            verify_cleanstack: false,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_taproot: true,
        };

        for case in cases {
            let (prevout, witness) = match case.mode.as_str() {
                "key_path" => {
                    let output_key = decode_hex(case.output_key_hex.as_deref().expect("output key"));
                    let mut spk = vec![0x51, 0x20];
                    spk.extend_from_slice(&output_key);
                    let prevout = TxOut {
                        value: 1000,
                        script_pubkey: Script::from_bytes(spk),
                    };
                    let witness = vec![decode_hex(case.sig_hex.as_deref().expect("sig"))];
                    (prevout, witness)
                }
                "script_path" => build_script_path_case(
                    case.internal_key_hex.as_deref().expect("internal key"),
                    case.tapscript_hex.as_deref().expect("tapscript"),
                    case.witness_stack_hex.as_deref().unwrap_or(&[]),
                    case.annex_hex.as_deref(),
                    case.tamper_control_block.unwrap_or(false),
                ),
                other => panic!("unknown mode in fixture: {other}"),
            };

            let tx = Transaction {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xffff_ffff,
                    witness,
                }],
                outputs: vec![],
                lock_time: 0,
            };
            let all_prevouts = [prevout.clone()];
            let ctx = ScriptContext {
                tx: &tx,
                input_index: 0,
                prevout: &prevout,
                flags,
                all_prevouts: &all_prevouts,
            };

            match case.expected.as_str() {
                "ok" => assert!(verify_input(&ctx).is_ok(), "case failed: {}", case.name),
                "TaprootInvalidSighashType" => {
                    let got = verify_input(&ctx).expect_err(&case.name);
                    assert_eq!(got, ScriptError::TaprootInvalidSighashType, "case: {}", case.name);
                }
                "TaprootAny" => {
                    let got = verify_input(&ctx).expect_err(&case.name);
                    assert!(matches!(got, ScriptError::Taproot(_)), "case {} got {:?}", case.name, got);
                }
                other => panic!("unknown expected value in taproot fixture: {other}"),
            }
        }
    }

    #[test]
    fn verify_input_p2sh_p2wsh_multisig_mainnet_481831() {
        // Real mainnet case from block 481831 that must pass under SegWit v0 rules.
        let spend_hex = "020000000001019bbf31fbb9a42002e74df46681d3640d38a226e6e6fbd952c52b39536b37b796000000002322002072ea6fe4c9b3300191453285354759756372db15b2810502adfda44dba6712ebffffffff01f07e0e00000000001976a9148387657820562980220f07eab2f69ba2a5fb9f0788ac040047304402204ca5c77afba63786071312608ba751ffa56dfdc9e0abdcdbfe3cddacddae9baf0220225ec69ce8e65e95a052a7a48d17a89085b095a601e29dd3a2ce960f40a222d1014830450221008d94de6d3477cbbb7086e566aae224287dd4c7d773f9c0f24f63eed257041837022011df8307187f70ff74a1650fe9057ca06d6ab2928dc4d1c66643c5890fa88f1101475221027d37fabfdae7f06bd97cc0c635b1f24d7607c98bf9baf8d09dcfa5722e81772821039edd051cf2d2a1e06efb7ada59f447f3ab04825eed43b9f248fc569681fc25ec52ae00000000";
        let spend = Transaction::decode(&mut Cursor::new(decode_hex(spend_hex))).expect("decode spend");
        let prevout = TxOut {
            value: 1_000_000,
            script_pubkey: Script::from_bytes(decode_hex("a9144775f70c3d367dd339b920da8ad41b6cef7bf59487")),
        };
        let ctx = ScriptContext {
            tx: &spend,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags {
                verify_p2sh: true,
                verify_dersig: true,
                verify_witness: true,
                verify_nulldummy: true,
                verify_cleanstack: false,
                verify_checklocktimeverify: true,
                verify_checksequenceverify: true,
                verify_taproot: false,
            },
            all_prevouts: &[prevout.clone()],
        };
        assert!(verify_input(&ctx).is_ok());
    }

    #[test]
    fn verify_input_p2sh_p2wpkh_nonstandard_sighash_mainnet_508011() {
        // Real mainnet case from block 508011:
        // witness signature uses sighash byte 0x65 (non-standard but consensus-valid).
        let spend_hex = "01000000000101447e208868dbc8e930fc6eba4fe0d0abfe0d9dc2db4ba70542e02467f00205c90100000017160014e20c60563894174c253ae937ba59ace46ab9ffb1ffffffff010845f305000000001976a91414ac7fc2a782bde1555b753d75ff4ed146683cae88ac024730440220120003c32cca7eabf07bad5c31125accc09d13c39546fa93833b8b69a2c72ed7022057083dc2ed348156874b8af859ac7a9c16e5ce39353f3f1ac2226b49c2b319af652103f73386ac6e567581f8d0611ad7a8536c3cd0253e535f6fc4707514b2ab54198700000000";
        let spend = Transaction::decode(&mut Cursor::new(decode_hex(spend_hex))).expect("decode spend");
        let prevout = TxOut {
            value: 99_830_000,
            script_pubkey: Script::from_bytes(decode_hex("a914e93f9e95f6d5cb1736a94de992d0d18819072fa587")),
        };
        let ctx = ScriptContext {
            tx: &spend,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags {
                verify_p2sh: true,
                verify_dersig: true,
                verify_witness: true,
                verify_nulldummy: true,
                verify_cleanstack: false,
                verify_checklocktimeverify: true,
                verify_checksequenceverify: true,
                verify_taproot: false,
            },
            all_prevouts: &[prevout.clone()],
        };
        assert!(verify_input(&ctx).is_ok());
    }

    #[test]
    fn verify_input_legacy_p2sh_find_and_delete_case() {
        // Real mainnet case (block 290329): redeemScript embeds a signature-like
        // push, requiring legacy FindAndDelete behavior for BASE CHECKMULTISIG.
        let spend_hex = "0100000002f9cbafc519425637ba4227f8d0a0b7160b4e65168193d5af39747891de98b5b5000000006b4830450221008dd619c563e527c47d9bd53534a770b102e40faa87f61433580e04e271ef2f960220029886434e18122b53d5decd25f1f4acb2480659fea20aabd856987ba3c3907e0121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffff42e7988254800876b69f24676b3e0205b77be476512ca4d970707dd5c60598ab00000000fd260100483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30b33c72c121c5a877d922e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fefbab9e9c7176844a187a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7153aeffffffff01a08601000000000017a914d8dacdadb7462ae15cd906f1878706d0da8660e68700000000";
        let prev_hex = "01000000016caf76a1d325b9645d8e52f1ef2d33af3d8787531268cfb6b8f43cef0aae05200f0000006b483045022100d67682b1279ac29ce8d60ef3e672f6b6d097df6307398745891a068814e9b48302203c41a2ea49541b8be3baa8d9ae1c74f3afe57c51c964a0f541f731c9b1763f71012103fee179251dff4b8dda512c0b0a515be9d79657328d34009a63f6dc320945c4a4ffffffff02a08601000000000017a914d8dacdadb7462ae15cd906f1878706d0da8660e687e0fd1c00000000001976a914a61f26bca505466527129f75909c06c6d778887088ac00000000";

        let spend = Transaction::decode(&mut Cursor::new(decode_hex(spend_hex))).expect("decode spend");
        let prev = Transaction::decode(&mut Cursor::new(decode_hex(prev_hex))).expect("decode prev");
        let prevout = prev.outputs[0].clone();
        let all_prevouts = vec![prevout.clone(), prev.outputs[1].clone()];
        let ctx = ScriptContext {
            tx: &spend,
            input_index: 1,
            prevout: &prevout,
            flags: ScriptFlags {
                verify_p2sh: true,
                verify_dersig: false,
                verify_witness: false,
                verify_nulldummy: false,
                verify_cleanstack: false,
                verify_checklocktimeverify: false,
                verify_checksequenceverify: false,
                verify_taproot: false,
            },
            all_prevouts: &all_prevouts,
        };
        assert!(verify_input(&ctx).is_ok());
    }

    #[test]
    fn verify_input_legacy_p2sh_empty_sig_multisig_not_case() {
        // Real mainnet case (block 299506): redeemScript = OP_CHECKMULTISIG OP_NOT.
        // Core treats empty sig in CHECKMULTISIG as a failed signature check (not skipped),
        // then OP_NOT flips it to true.
        let spend_hex = "01000000019cc2a6fbf645a81cc42317673ca33d500059f34080d64f333bf72379420687b70000000008000051005102ae91ffffffff0150c300000000000002ae9100000000";
        let prev_hex = "01000000023904cd3644c6d440a6d752c95f07737c46f5e70fb6fbb28f00aa17e281868b7b010000006b483045022100ac455750dc430957942e9766f88aecfe6eb17d4244eb2cb50ca4a25336fd4dd702202640cc943f4fe8f2166b03005bed3bd024f4762767322b60bf471ecf8e3f3ede012102348d4cad0084f88c4c02bdc1bf90cc6c0893a0b97af76ef644daf72e6786b4afffffffffb84057ae61ad22ac17c02635ee1b37d170ef785847ec28efe848a5607331568e020000006b483045022100d7fee595d7a1f9969767098f8582e7a563f08437f461f0a25395f35c1833839302205f565ab12d343478471a78669c4c3476714032f7758a781d7deab19f160784e0012102ea69c47753d8e0228c0c426294a6b4dc926aebbeb8561248d40be37d257d94e0ffffffff01a08601000000000017a91438430c4d1c214bf11d2c0c3dea8e5e9a5d11aab08700000000";

        let spend = Transaction::decode(&mut Cursor::new(decode_hex(spend_hex))).expect("decode spend");
        let prev = Transaction::decode(&mut Cursor::new(decode_hex(prev_hex))).expect("decode prev");
        let prevout = prev.outputs[0].clone();
        let all_prevouts = vec![prevout.clone()];
        let ctx = ScriptContext {
            tx: &spend,
            input_index: 0,
            prevout: &prevout,
            flags: ScriptFlags {
                verify_p2sh: true,
                verify_dersig: false,
                verify_witness: false,
                verify_nulldummy: false,
                verify_cleanstack: false,
                verify_checklocktimeverify: false,
                verify_checksequenceverify: false,
                verify_taproot: false,
            },
            all_prevouts: &all_prevouts,
        };
        assert!(verify_input(&ctx).is_ok());
    }

    #[test]
    fn tapleaf_hash_large_script_uses_full_compact_size() {
        let script = vec![0x51; 104_169];
        let mut leaf_data = vec![0xc0];
        push_compact_size(&mut leaf_data, script.len());
        leaf_data.extend_from_slice(&script);
        let good = tagged_hash(b"TapLeaf", &leaf_data);

        // Old buggy path encoded length with 0xfd + u16 and truncated for values > 0xffff.
        let mut old_leaf_data = vec![0xc0, 0xfd];
        old_leaf_data.extend_from_slice(&(script.len() as u16).to_le_bytes());
        old_leaf_data.extend_from_slice(&script);
        let old = tagged_hash(b"TapLeaf", &old_leaf_data);

        assert_ne!(good, old);
    }
}
