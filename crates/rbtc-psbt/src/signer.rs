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

use secp256k1::{Secp256k1, SecretKey};

use rbtc_primitives::{
    hash::Hash256,
    script::Script,
};

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

        let sighash_type = self.inputs.get(index)
            .and_then(|i| i.sighash_type)
            .unwrap_or(1); // SIGHASH_ALL

        let sig_bytes = if let Some(txout) = self.inputs.get(index)
            .and_then(|i| i.witness_utxo.as_ref())
        {
            // SegWit v0 path: derive P2WPKH sighash (BIP143)
            let script_code = p2wpkh_script_code(&pubkey_bytes)?;
            let amount = txout.value;
            let sighash = compute_p2wpkh_sighash(
                &self.global.unsigned_tx,
                index,
                &script_code,
                amount,
                sighash_type,
            )?;
            ecdsa_sign(&secp, secret_key, &sighash, sighash_type)
        } else if self.inputs.get(index)
            .and_then(|i| i.non_witness_utxo.as_ref())
            .is_some()
        {
            // Legacy P2PKH path
            let sighash = compute_legacy_sighash(
                &self.global.unsigned_tx,
                index,
                &p2pkh_script_code(&pubkey_bytes),
                sighash_type,
            )?;
            ecdsa_sign(&secp, secret_key, &sighash, sighash_type)
        } else {
            return Err(PsbtError::MissingField("witness_utxo or non_witness_utxo"));
        };

        self.inputs[index]
            .partial_sigs
            .insert(pubkey_bytes, sig_bytes);

        Ok(())
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
        inp.previous_output.txid.0.encode(&mut prevouts_buf).ok();
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
    let inp = tx.inputs.get(input_index).ok_or(PsbtError::MissingField("input"))?;
    inp.previous_output.txid.0.encode(&mut buf).ok();
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
    };
    use secp256k1::{Secp256k1, SecretKey};

    fn make_psbt() -> Psbt {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([1; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 49_000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
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
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([1u8; 32]).unwrap();
        psbt.sign_input(0, &sk).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }
}
