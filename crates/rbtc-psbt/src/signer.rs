//! BIP174 PSBT Signer – reuses rbtc-wallet signing logic.
//!
//! Supports:
//!   - P2WPKH (SegWit v0, ECDSA): uses BIP143 sighash
//!   - P2PKH (legacy, ECDSA): uses legacy sighash
//!   - P2TR (Taproot, Schnorr): uses BIP341 sighash
//!
//! The caller provides a secp256k1 secret key.  The signer:
//!   1. Determines input type from `witness_utxo` / `non_witness_utxo`.
//!   2. Computes the correct sighash.
//!   3. Appends to `partial_sigs`.

use rand::RngCore;
use secp256k1::{Keypair, Secp256k1, SecretKey};

use rbtc_crypto::sighash::{sighash_taproot, SighashType};
use rbtc_crypto::tagged_hash;
use rbtc_primitives::{hash::Hash256, script::Script, transaction::TxOut};

/// Compute the taproot tweaked keypair and x-only output key.
/// Equivalent to rbtc_wallet::address::taproot_output_key but inlined here
/// to avoid a circular dependency (psbt -> wallet -> psbt).
fn taproot_output_key(
    keypair: &Keypair,
) -> std::result::Result<(Keypair, secp256k1::XOnlyPublicKey), crate::error::PsbtError> {
    let secp = Secp256k1::new();
    let (xonly, _parity) = keypair.x_only_public_key();
    let tweak_bytes = tagged_hash(b"TapTweak", &xonly.serialize());
    let tweak_scalar = secp256k1::scalar::Scalar::from_be_bytes(tweak_bytes.0)
        .map_err(|_| crate::error::PsbtError::Signing("invalid tweak scalar".into()))?;
    let tweaked = keypair
        .add_xonly_tweak(&secp, &tweak_scalar)
        .map_err(|_| crate::error::PsbtError::Signing("tweak failed".into()))?;
    let (tweaked_xonly, _) = tweaked.x_only_public_key();
    Ok((tweaked, tweaked_xonly))
}

use crate::{
    error::{PsbtError, Result},
    types::Psbt,
};

impl Psbt {
    /// **Signer**: sign input `index` with `secret_key`.
    ///
    /// The public key is derived automatically.  The sighash type defaults to
    /// `SIGHASH_ALL` (1) unless overridden by `psbt_input.sighash_type`.
    pub fn sign_input(&mut self, index: usize, secret_key: &SecretKey) -> Result<()> {
        let secp = Secp256k1::signing_only();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, secret_key);
        let pubkey_bytes = pubkey.serialize().to_vec(); // 33-byte compressed

        let sighash_type = self
            .inputs
            .get(index)
            .and_then(|i| i.sighash_type)
            .unwrap_or(1); // SIGHASH_ALL

        if let Some(txout) = self
            .inputs
            .get(index)
            .and_then(|i| i.witness_utxo.as_ref())
            .cloned()
        {
            if txout.script_pubkey.is_p2tr() {
                // Check if this input has tap_leaf_script entries for script-path signing
                let has_leaf_scripts = !self
                    .inputs
                    .get(index)
                    .map(|i| i.tap_leaf_script.is_empty())
                    .unwrap_or(true);
                if has_leaf_scripts {
                    // Taproot script-path spend (BIP341 + BIP371)
                    return self.sign_input_taproot_script_path(index, secret_key);
                }
                // Taproot key-path spend (BIP341 + BIP371)
                return self.sign_input_taproot(index, secret_key, &txout);
            }
            // SegWit v0 path: derive P2WPKH sighash (BIP143)
            let script_code = p2wpkh_script_code(&pubkey_bytes)?;
            let sighash = compute_p2wpkh_sighash(
                &self.unsigned_tx().ok_or(PsbtError::MissingField("unsigned_tx"))?,
                index,
                &script_code,
                txout.value as u64,
                sighash_type,
            )?;
            let sig_bytes = ecdsa_sign(&secp, secret_key, &sighash, sighash_type);
            self.inputs[index]
                .partial_sigs
                .insert(pubkey_bytes, sig_bytes);
        } else if self
            .inputs
            .get(index)
            .and_then(|i| i.non_witness_utxo.as_ref())
            .is_some()
        {
            // Legacy P2PKH path
            let sighash = compute_legacy_sighash(
                &self.unsigned_tx().ok_or(PsbtError::MissingField("unsigned_tx"))?,
                index,
                &p2pkh_script_code(&pubkey_bytes),
                sighash_type,
            )?;
            let sig_bytes = ecdsa_sign(&secp, secret_key, &sighash, sighash_type);
            self.inputs[index]
                .partial_sigs
                .insert(pubkey_bytes, sig_bytes);
        } else {
            return Err(PsbtError::MissingField("witness_utxo or non_witness_utxo"));
        }

        Ok(())
    }

    /// Sign a P2TR (Taproot) key-path input using BIP341 sighash + Schnorr.
    fn sign_input_taproot(
        &mut self,
        index: usize,
        secret_key: &SecretKey,
        _witness_utxo: &TxOut,
    ) -> Result<()> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);

        // Apply BIP341 TapTweak
        let (tweaked_kp, _tweaked_xonly) =
            taproot_output_key(&keypair).map_err(|_| PsbtError::MissingField("taproot tweak"))?;

        // Collect all prevouts from witness_utxo fields (required for Taproot sighash)
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(self.inputs.len());
        for inp in self.inputs.iter() {
            let txout = inp.witness_utxo.clone().ok_or(PsbtError::MissingField(
                "witness_utxo required for all inputs when signing Taproot",
            ))?;
            prevouts.push(txout);
        }

        let sighash_type_u32 = self.inputs[index].sighash_type.unwrap_or(0);
        let sighash_type = if sighash_type_u32 == 0 {
            SighashType::TaprootDefault
        } else {
            SighashType::from_u32(sighash_type_u32)
                .ok_or(PsbtError::Decode("invalid taproot sighash type".into()))?
        };

        let sighash = sighash_taproot(
            &self.unsigned_tx().ok_or(PsbtError::MissingField("unsigned_tx"))?,
            index,
            &prevouts,
            sighash_type,
            None,     // key-path spend: no leaf hash
            None,     // no annex
            0,        // key_version = 0
            u32::MAX, // code_separator_pos
        );

        let mut aux_rand = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut aux_rand);
        let sig = secp.sign_schnorr_with_aux_rand(&sighash.0, &tweaked_kp, &aux_rand);

        // Build signature: 64 bytes for TaprootDefault, 65 bytes otherwise
        let mut sig_bytes = sig.as_ref().to_vec();
        if sighash_type != SighashType::TaprootDefault {
            sig_bytes.push(sighash_type_u32 as u8);
        }

        // Store as BIP371 tap_key_sig
        self.inputs[index].tap_key_sig = Some(sig_bytes);
        // Store internal key
        let (xonly, _) = keypair.x_only_public_key();
        self.inputs[index].tap_internal_key = Some(xonly.serialize().to_vec());

        Ok(())
    }

    /// Sign a P2TR (Taproot) script-path input using BIP341 sighash + Schnorr.
    ///
    /// For script-path spends we:
    /// 1. Iterate each leaf in `tap_leaf_script`
    /// 2. Compute the BIP341 leaf hash: `tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script)`
    /// 3. Compute the sighash with that leaf hash
    /// 4. Sign with the **untweaked** keypair (script-path uses the raw key, not the tweaked key)
    /// 5. Store in `tap_script_sig` keyed by `x_only_pubkey (32) || leaf_hash (32)`
    fn sign_input_taproot_script_path(
        &mut self,
        index: usize,
        secret_key: &SecretKey,
    ) -> Result<()> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret_key);
        let (xonly_pubkey, _parity) = keypair.x_only_public_key();
        let xonly_bytes = xonly_pubkey.serialize();

        // Collect all prevouts from witness_utxo fields (required for Taproot sighash)
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(self.inputs.len());
        for inp in self.inputs.iter() {
            let txout = inp.witness_utxo.clone().ok_or(PsbtError::MissingField(
                "witness_utxo required for all inputs when signing Taproot",
            ))?;
            prevouts.push(txout);
        }

        let sighash_type_u32 = self.inputs[index].sighash_type.unwrap_or(0);
        let sighash_type = if sighash_type_u32 == 0 {
            SighashType::TaprootDefault
        } else {
            SighashType::from_u32(sighash_type_u32)
                .ok_or(PsbtError::Decode("invalid taproot sighash type".into()))?
        };

        // Collect leaf scripts so we can iterate without borrowing self
        let leaf_scripts: Vec<(Vec<u8>, Vec<u8>, u8)> = self.inputs[index]
            .tap_leaf_script
            .iter()
            .map(|(cb, (script, ver))| (cb.clone(), script.clone(), *ver))
            .collect();

        let tx = self
            .unsigned_tx()
            .ok_or(PsbtError::MissingField("unsigned_tx"))?;

        for (_control_block, leaf_script, leaf_version) in &leaf_scripts {
            // Compute BIP341 leaf hash:
            // tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script)
            let mut leaf_data = vec![*leaf_version];
            push_compact_size(&mut leaf_data, leaf_script.len());
            leaf_data.extend_from_slice(leaf_script);
            let leaf_hash = tagged_hash(b"TapLeaf", &leaf_data);

            // Compute sighash with leaf hash
            let sighash = sighash_taproot(
                &tx,
                index,
                &prevouts,
                sighash_type,
                Some(&leaf_hash.0), // script-path: pass leaf hash
                None,               // no annex
                0,                  // key_version = 0 for tapscript
                u32::MAX,           // code_separator_pos
            );

            // Sign with the untweaked keypair (script-path uses raw key)
            let mut aux_rand = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut aux_rand);
            let sig = secp.sign_schnorr_with_aux_rand(&sighash.0, &keypair, &aux_rand);

            // Build signature bytes
            let mut sig_bytes = sig.as_ref().to_vec();
            if sighash_type != SighashType::TaprootDefault {
                sig_bytes.push(sighash_type_u32 as u8);
            }

            // Composite key: x-only pubkey (32 bytes) || leaf_hash (32 bytes)
            let mut composite_key = Vec::with_capacity(64);
            composite_key.extend_from_slice(&xonly_bytes);
            composite_key.extend_from_slice(&leaf_hash.0);

            self.inputs[index]
                .tap_script_sig
                .insert(composite_key, sig_bytes);
        }

        Ok(())
    }
}

/// Encode a length as Bitcoin compact size (varint).
fn push_compact_size(dst: &mut Vec<u8>, n: usize) {
    if n < 0xfd {
        dst.push(n as u8);
    } else if n <= 0xffff {
        dst.push(0xfd);
        dst.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        dst.push(0xfe);
        dst.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        dst.push(0xff);
        dst.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

// ── Sighash helpers ───────────────────────────────────────────────────────────

/// Build the BIP143 P2WPKH script code from a compressed pubkey.
fn p2wpkh_script_code(pubkey: &[u8]) -> Result<Script> {
    // script_code = OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    let hash = rbtc_crypto::hash160(pubkey);
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&hash.0);
    script.extend_from_slice(&[0x88, 0xac]);
    Ok(Script::from_bytes(script))
}

fn p2pkh_script_code(pubkey: &[u8]) -> Script {
    let hash = rbtc_crypto::hash160(pubkey);
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&hash.0);
    script.extend_from_slice(&[0x88, 0xac]);
    Script::from_bytes(script)
}

/// BIP143 P2WPKH sighash.
fn compute_p2wpkh_sighash(
    tx: &rbtc_primitives::transaction::Transaction,
    input_index: usize,
    script_code: &Script,
    amount: u64,
    sighash_type: u32,
) -> Result<Hash256> {
    use rbtc_crypto::sha256d;
    use rbtc_primitives::codec::Encodable;

    let mut buf = Vec::new();
    // version
    tx.version.encode(&mut buf).ok();
    // hashPrevouts
    let mut prevouts_buf = Vec::new();
    for inp in &tx.inputs {
        inp.previous_output.txid.0.0.encode(&mut prevouts_buf).ok();
        inp.previous_output.vout.encode(&mut prevouts_buf).ok();
    }
    let hash_prevouts = sha256d(&prevouts_buf);
    buf.extend_from_slice(&hash_prevouts.0);
    // hashSequence
    let mut seq_buf = Vec::new();
    for inp in &tx.inputs {
        inp.sequence.encode(&mut seq_buf).ok();
    }
    let hash_seq = sha256d(&seq_buf);
    buf.extend_from_slice(&hash_seq.0);
    // outpoint
    let inp = tx
        .inputs
        .get(input_index)
        .ok_or(PsbtError::MissingField("input"))?;
    inp.previous_output.txid.0.0.encode(&mut buf).ok();
    inp.previous_output.vout.encode(&mut buf).ok();
    // script_code
    script_code.encode(&mut buf).ok();
    // amount
    amount.encode(&mut buf).ok();
    // sequence
    inp.sequence.encode(&mut buf).ok();
    // hashOutputs
    let mut out_buf = Vec::new();
    for out in &tx.outputs {
        out.value.encode(&mut out_buf).ok();
        out.script_pubkey.encode(&mut out_buf).ok();
    }
    let hash_outputs = sha256d(&out_buf);
    buf.extend_from_slice(&hash_outputs.0);
    // locktime + sighash_type
    tx.lock_time.encode(&mut buf).ok();
    sighash_type.encode(&mut buf).ok();

    Ok(sha256d(&buf))
}

/// Legacy P2PKH sighash.
fn compute_legacy_sighash(
    tx: &rbtc_primitives::transaction::Transaction,
    input_index: usize,
    script_code: &Script,
    sighash_type: u32,
) -> Result<Hash256> {
    use rbtc_crypto::sha256d;
    use rbtc_primitives::codec::Encodable;

    let mut tx_copy = tx.clone();
    // Clear all scriptSigs
    for inp in &mut tx_copy.inputs {
        inp.script_sig = Script::new();
    }
    // Set the script for the input being signed
    if let Some(inp) = tx_copy.inputs.get_mut(input_index) {
        inp.script_sig = script_code.clone();
    } else {
        return Err(PsbtError::MissingField("input"));
    }

    let mut buf = Vec::new();
    tx_copy.encode_legacy(&mut buf).ok();
    sighash_type.encode(&mut buf).ok();

    Ok(sha256d(&buf))
}

/// ECDSA sign and DER-encode with sighash byte appended.
fn ecdsa_sign(
    secp: &Secp256k1<secp256k1::SignOnly>,
    secret_key: &SecretKey,
    sighash: &Hash256,
    sighash_type: u32,
) -> Vec<u8> {
    let msg = secp256k1::Message::from_digest(sighash.0);
    let sig = secp.sign_ecdsa(msg, secret_key);
    let mut der = sig.serialize_der().to_vec();
    der.push(sighash_type as u8);
    der
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        hash::Hash256,
        script::Script,
        transaction::{OutPoint, Transaction, TxIn, TxOut},
        Txid,
    };
    use secp256k1::{Secp256k1, SecretKey};

    fn make_psbt() -> Psbt {
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 49_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut psbt = Psbt::create(tx);
        // Attach a witness UTXO so sign_input uses P2WPKH path
        let mut wpkh_script = vec![0x00u8, 0x14];
        wpkh_script.extend_from_slice(&[0u8; 20]);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::from_bytes(wpkh_script),
        });
        psbt
    }

    #[test]
    fn sign_input_adds_partial_sig() {
        let mut psbt = make_psbt();
        let _secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([1u8; 32]).unwrap();
        psbt.sign_input(0, &sk).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    /// Encode a length as Bitcoin compact size (varint) – test helper matching
    /// the `push_compact_size` used in production code.
    fn test_push_compact_size(dst: &mut Vec<u8>, n: usize) {
        if n < 0xfd {
            dst.push(n as u8);
        } else if n <= 0xffff {
            dst.push(0xfd);
            dst.extend_from_slice(&(n as u16).to_le_bytes());
        } else if n <= 0xffff_ffff {
            dst.push(0xfe);
            dst.extend_from_slice(&(n as u32).to_le_bytes());
        } else {
            dst.push(0xff);
            dst.extend_from_slice(&(n as u64).to_le_bytes());
        }
    }

    #[test]
    fn sign_input_taproot_key_path() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([2u8; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (_, output_xonly) = taproot_output_key(&keypair).unwrap();

        // Build a P2TR scriptPubKey: OP_1 <32 bytes>
        let mut p2tr_spk = vec![0x51, 0x20];
        p2tr_spk.extend_from_slice(&output_xonly.serialize());

        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 49_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut psbt = Psbt::create(tx);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::from_bytes(p2tr_spk),
        });

        psbt.sign_input(0, &sk).unwrap();

        // P2TR signing stores tap_key_sig, not partial_sigs
        assert!(psbt.inputs[0].tap_key_sig.is_some());
        assert!(psbt.inputs[0].tap_internal_key.is_some());
        // Default sighash → 64-byte sig (no sighash byte appended)
        assert_eq!(psbt.inputs[0].tap_key_sig.as_ref().unwrap().len(), 64);
        assert!(psbt.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn sign_input_taproot_script_path() {
        use rbtc_crypto::tagged_hash;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([3u8; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly_pubkey, _) = keypair.x_only_public_key();
        let xonly_bytes = xonly_pubkey.serialize();

        // Use the internal key to compute the tweaked output key for the P2TR scriptPubKey.
        // For script-path, we need a real taproot output with a script tree.
        // Build a simple leaf script: <xonly_pubkey> OP_CHECKSIG
        let mut leaf_script = Vec::new();
        leaf_script.push(0x20); // push 32 bytes
        leaf_script.extend_from_slice(&xonly_bytes);
        leaf_script.push(0xac); // OP_CHECKSIG

        let leaf_version: u8 = 0xc0;

        // Compute leaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script)
        let mut leaf_data = vec![leaf_version];
        test_push_compact_size(&mut leaf_data, leaf_script.len());
        leaf_data.extend_from_slice(&leaf_script);
        let leaf_hash = tagged_hash(b"TapLeaf", &leaf_data);

        // Compute the merkle root (single leaf => merkle_root = leaf_hash)
        let merkle_root = leaf_hash.0;

        // Compute the tweaked output key using the merkle root
        let mut tweak_data = Vec::with_capacity(64);
        tweak_data.extend_from_slice(&xonly_bytes);
        tweak_data.extend_from_slice(&merkle_root);
        let tweak_hash = tagged_hash(b"TapTweak", &tweak_data);

        let internal_xonly =
            secp256k1::XOnlyPublicKey::from_byte_array(xonly_bytes).unwrap();
        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash.0).unwrap();
        let (output_key, _parity) = internal_xonly.add_tweak(&secp, &tweak).unwrap();

        // Build a P2TR scriptPubKey: OP_1 <32-byte output key>
        let mut p2tr_spk = vec![0x51, 0x20];
        p2tr_spk.extend_from_slice(&output_key.serialize());

        // Build control block: leaf_version | internal_key (32 bytes)
        let mut control_block = vec![leaf_version];
        control_block.extend_from_slice(&xonly_bytes);

        // Build the PSBT
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 49_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut psbt = Psbt::create(tx);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::from_bytes(p2tr_spk),
        });

        // Set up the tap leaf script (key = control_block, value = (script, leaf_version))
        psbt.inputs[0]
            .tap_leaf_script
            .insert(control_block.clone(), (leaf_script.clone(), leaf_version));

        // Sign
        psbt.sign_input(0, &sk).unwrap();

        // Verify: tap_script_sig should have one entry
        assert_eq!(psbt.inputs[0].tap_script_sig.len(), 1);
        // tap_key_sig should NOT be set (we did script-path, not key-path)
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        // partial_sigs should be empty
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        // The composite key should be xonly_pubkey (32) || leaf_hash (32)
        let mut expected_composite_key = Vec::with_capacity(64);
        expected_composite_key.extend_from_slice(&xonly_bytes);
        expected_composite_key.extend_from_slice(&leaf_hash.0);

        assert!(psbt.inputs[0]
            .tap_script_sig
            .contains_key(&expected_composite_key));

        let sig_bytes = psbt.inputs[0]
            .tap_script_sig
            .get(&expected_composite_key)
            .unwrap();
        // Default sighash (TaprootDefault) => 64-byte signature (no sighash byte appended)
        assert_eq!(sig_bytes.len(), 64);

        // Verify the signature is valid using Schnorr verification
        let sighash_type = rbtc_crypto::sighash::SighashType::TaprootDefault;
        let prevouts = vec![psbt.inputs[0].witness_utxo.clone().unwrap()];
        let sighash = rbtc_crypto::sighash::sighash_taproot(
            &psbt
                .unsigned_tx()
                .unwrap(),
            0,
            &prevouts,
            sighash_type,
            Some(&leaf_hash.0),
            None,
            0,
            u32::MAX,
        );

        let secp_verify = Secp256k1::verification_only();
        let schnorr_sig =
            secp256k1::schnorr::Signature::from_byte_array(sig_bytes[..64].try_into().unwrap());
        assert!(secp_verify
            .verify_schnorr(&schnorr_sig, &sighash.0, &xonly_pubkey)
            .is_ok());
    }

    #[test]
    fn sign_input_taproot_script_path_full_roundtrip() {
        // Test the full flow: sign -> finalize -> extract_tx
        use rbtc_crypto::tagged_hash;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([4u8; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly_pubkey, _) = keypair.x_only_public_key();
        let xonly_bytes = xonly_pubkey.serialize();

        // Build leaf script: <xonly_pubkey> OP_CHECKSIG
        let mut leaf_script = Vec::new();
        leaf_script.push(0x20);
        leaf_script.extend_from_slice(&xonly_bytes);
        leaf_script.push(0xac);

        let leaf_version: u8 = 0xc0;

        // Compute leaf hash
        let mut leaf_data = vec![leaf_version];
        test_push_compact_size(&mut leaf_data, leaf_script.len());
        leaf_data.extend_from_slice(&leaf_script);
        let leaf_hash = tagged_hash(b"TapLeaf", &leaf_data);

        // Compute tweaked output key
        let mut tweak_data = Vec::with_capacity(64);
        tweak_data.extend_from_slice(&xonly_bytes);
        tweak_data.extend_from_slice(&leaf_hash.0);
        let tweak_hash = tagged_hash(b"TapTweak", &tweak_data);

        let internal_xonly =
            secp256k1::XOnlyPublicKey::from_byte_array(xonly_bytes).unwrap();
        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash.0).unwrap();
        let (output_key, _parity) = internal_xonly.add_tweak(&secp, &tweak).unwrap();

        let mut p2tr_spk = vec![0x51, 0x20];
        p2tr_spk.extend_from_slice(&output_key.serialize());

        let mut control_block = vec![leaf_version];
        control_block.extend_from_slice(&xonly_bytes);

        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 49_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut psbt = Psbt::create(tx);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 50_000,
            script_pubkey: Script::from_bytes(p2tr_spk),
        });
        psbt.inputs[0]
            .tap_leaf_script
            .insert(control_block.clone(), (leaf_script.clone(), leaf_version));

        // Sign
        psbt.sign_input(0, &sk).unwrap();
        assert_eq!(psbt.inputs[0].tap_script_sig.len(), 1);

        // Finalize
        psbt.finalize().unwrap();
        assert!(psbt.inputs[0].final_script_witness.is_some());
        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        // Witness for script-path: [sig, script, control_block]
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0].len(), 64); // 64-byte Schnorr sig (default sighash)
        assert_eq!(witness[1], leaf_script);
        assert_eq!(witness[2], control_block);

        // All tap signing metadata should be cleared
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_script_sig.is_empty());
        assert!(psbt.inputs[0].tap_leaf_script.is_empty());

        // Extract final transaction
        let final_tx = psbt.extract_tx().unwrap();
        assert_eq!(final_tx.inputs[0].witness.len(), 3);
    }
}
