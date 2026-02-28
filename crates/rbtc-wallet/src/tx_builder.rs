//! Transaction building, coin selection, and signing.

use rand::RngCore;
use secp256k1::{Keypair, Message, SecretKey};

use rbtc_crypto::sighash::{sighash_legacy, sighash_segwit_v0, sighash_taproot, SighashType};
use rbtc_primitives::{
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};

use crate::{
    address::{p2wpkh_script_code, taproot_output_key},
    error::WalletError,
    wallet::WalletUtxo,
};

// ── CoinSelector ──────────────────────────────────────────────────────────────

/// Greedy coin selection (largest-first).
/// Returns selected UTXOs or an error if funds are insufficient.
pub struct CoinSelector;

impl CoinSelector {
    /// Select UTXOs to cover `target_sat` plus a fee estimated at `fee_rate`
    /// sat/vbyte. Returns `(selected, estimated_fee)`.
    ///
    /// Uses a simple largest-first heuristic. Branch-and-bound is planned.
    pub fn select(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        if utxos.is_empty() {
            return Err(WalletError::NoUtxos);
        }

        // Sort largest-value first
        let mut sorted: Vec<&WalletUtxo> = utxos.iter().collect();
        sorted.sort_by(|a, b| b.value.cmp(&a.value));

        // Estimate a base fee (rough: 1 input + 2 outputs * rate)
        let estimate_fee = |n_inputs: usize| -> u64 {
            let vbytes = 10 + n_inputs as u64 * 68 + 2 * 31;
            (vbytes as f64 * fee_rate).ceil() as u64
        };

        let mut selected = Vec::new();
        let mut total = 0u64;

        for utxo in sorted {
            selected.push(utxo.clone());
            total += utxo.value;
            let fee = estimate_fee(selected.len());
            if total >= target_sat + fee {
                return Ok((selected, fee));
            }
        }

        Err(WalletError::InsufficientFunds {
            needed: target_sat,
            available: total,
        })
    }
}

// ── TxBuilder ────────────────────────────────────────────────────────────────

/// Unsigned transaction builder.
pub struct TxBuilder {
    version: i32,
    inputs: Vec<(OutPoint, u32)>, // (outpoint, sequence)
    outputs: Vec<TxOut>,
    lock_time: u32,
}

impl TxBuilder {
    pub fn new() -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    pub fn add_input(mut self, outpoint: OutPoint) -> Self {
        self.inputs.push((outpoint, 0xffff_fffe));
        self
    }

    pub fn add_output(mut self, value: u64, script_pubkey: Script) -> Self {
        self.outputs.push(TxOut { value, script_pubkey });
        self
    }

    pub fn lock_time(mut self, lt: u32) -> Self {
        self.lock_time = lt;
        self
    }

    /// Build the unsigned `Transaction` (all scriptSigs and witnesses empty).
    pub fn build(self) -> Transaction {
        Transaction {
            version: self.version,
            inputs: self
                .inputs
                .into_iter()
                .map(|(previous_output, sequence)| TxIn {
                    previous_output,
                    script_sig: Script::new(),
                    sequence,
                    witness: vec![],
                })
                .collect(),
            outputs: self.outputs,
            lock_time: self.lock_time,
        }
    }
}

impl Default for TxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Signing ──────────────────────────────────────────────────────────────────

/// Information about a wallet key required to sign one input.
pub struct SigningInput {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: Script,
    pub secret_key: SecretKey,
}

/// Sign a transaction that has been built with `TxBuilder`.
///
/// `signing_inputs` must be in the same order as the transaction inputs.
pub fn sign_transaction(
    tx: &Transaction,
    signing_inputs: &[SigningInput],
) -> Result<Transaction, WalletError> {
    assert_eq!(
        tx.inputs.len(),
        signing_inputs.len(),
        "signing_inputs length must match tx.inputs"
    );

    let secp = secp256k1::Secp256k1::new();
    let mut signed = tx.clone();

    // Collect all prevouts (needed for Taproot sighash)
    let all_prevouts: Vec<TxOut> = signing_inputs
        .iter()
        .map(|si| TxOut {
            value: si.value,
            script_pubkey: si.script_pubkey.clone(),
        })
        .collect();

    for (i, si) in signing_inputs.iter().enumerate() {
        let spk = &si.script_pubkey;

        if spk.is_p2pkh() {
            // Legacy P2PKH
            let sighash = sighash_legacy(tx, i, spk, SighashType::All);
            let msg = Message::from_digest(sighash.0);
            let sig = secp.sign_ecdsa(msg, &si.secret_key);
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(0x01); // SIGHASH_ALL

            let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &si.secret_key);
            let pub_bytes = pubkey.serialize();

            // scriptSig: <sig> <pubkey>
            let mut script_sig = Vec::new();
            script_sig.push(sig_bytes.len() as u8);
            script_sig.extend_from_slice(&sig_bytes);
            script_sig.push(pub_bytes.len() as u8);
            script_sig.extend_from_slice(&pub_bytes);
            signed.inputs[i].script_sig = Script::from_bytes(script_sig);
        } else if spk.is_p2wpkh() {
            // Native SegWit P2WPKH
            let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &si.secret_key);
            let script_code = p2wpkh_script_code(&pubkey);
            let sighash = sighash_segwit_v0(tx, i, &script_code, si.value, SighashType::All);
            let msg = Message::from_digest(sighash.0);
            let sig = secp.sign_ecdsa(msg, &si.secret_key);
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(0x01); // SIGHASH_ALL

            let pub_bytes = pubkey.serialize();
            signed.inputs[i].script_sig = Script::new();
            signed.inputs[i].witness = vec![sig_bytes, pub_bytes.to_vec()];
        } else if spk.is_p2tr() {
            // Taproot key-path spend (P2TR)
            let keypair = Keypair::from_secret_key(&secp, &si.secret_key);
            let (tweaked_kp, _) = taproot_output_key(&keypair)?;

            let sighash = sighash_taproot(
                tx,
                i,
                &all_prevouts,
                SighashType::TaprootDefault,
                None,
                None,
                0,
                u32::MAX,
            );

            let mut aux_rand = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut aux_rand);
            // sign_schnorr_with_aux_rand takes &[u8] for the message
            let sig = secp.sign_schnorr_with_aux_rand(&sighash.0, &tweaked_kp, &aux_rand);

            signed.inputs[i].script_sig = Script::new();
            signed.inputs[i].witness = vec![sig.as_ref().to_vec()];
        } else {
            // Unsupported script type — leave unsigned, caller can handle
            tracing::warn!(
                "sign_transaction: unsupported input script type for input {i}"
            );
        }
    }

    Ok(signed)
}

// ── Fee estimation ────────────────────────────────────────────────────────────

/// Estimate virtual size (vbytes) of a transaction with the given inputs and
/// outputs. Assumes P2WPKH inputs and P2WPKH/P2TR outputs as a baseline.
pub fn estimate_vsize(n_inputs: usize, n_outputs: usize) -> u64 {
    // Overhead: version(4) + marker+flag(2) + locktime(4) + varint counts(2)
    let base = 4 + 4 + 1 + 1; // version, locktime, input count varint, output count varint
    // Per-input (P2WPKH): outpoint(36) + script_sig_len(1) + sequence(4) = 41 non-witness
    //                      witness: varint(1) + sig_len(1) + sig(72) + pub_len(1) + pub(33) = 108
    let input_base = n_inputs * 41;
    let input_witness = n_inputs * 108; // charged at 1/4 weight
    // Per-output (P2WPKH 31 bytes): value(8) + script_len(1) + script(22)
    let output_base = n_outputs * 31;

    let weight = (base + input_base + output_base) * 4 + input_witness + 2; // +2 for segwit overhead
    ((weight as u64) + 3) / 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{p2wpkh_script, AddressType},
        hd::ExtendedPrivKey,
        wallet::WalletUtxo,
    };
    use rbtc_primitives::hash::Hash256;

    fn sample_utxos() -> Vec<WalletUtxo> {
        let spk = p2wpkh_script(
            &ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key(),
        );
        vec![
            WalletUtxo {
                outpoint: OutPoint { txid: Hash256([1u8; 32]), vout: 0 },
                value: 100_000,
                script_pubkey: spk.clone(),
                height: 100,
                address: "bc1qtest".into(),
                confirmed: true,
                addr_type: AddressType::SegWit,
            },
            WalletUtxo {
                outpoint: OutPoint { txid: Hash256([2u8; 32]), vout: 0 },
                value: 200_000,
                script_pubkey: spk,
                height: 101,
                address: "bc1qtest2".into(),
                confirmed: true,
                addr_type: AddressType::SegWit,
            },
        ]
    }

    #[test]
    fn coin_select_success() {
        let utxos = sample_utxos();
        let (selected, fee) = CoinSelector::select(&utxos, 150_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 150_000 + fee);
    }

    #[test]
    fn coin_select_insufficient() {
        let utxos = sample_utxos();
        assert!(CoinSelector::select(&utxos, 1_000_000, 1.0).is_err());
    }

    #[test]
    fn tx_builder_builds_correct_structure() {
        let op = OutPoint { txid: Hash256([0u8; 32]), vout: 0 };
        let spk = Script::from_bytes(vec![0x51]); // OP_1
        let tx = TxBuilder::new()
            .add_input(op.clone())
            .add_output(50_000, spk)
            .build();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.inputs[0].previous_output.txid, op.txid);
        assert_eq!(tx.outputs[0].value, 50_000);
    }

    #[test]
    fn estimate_vsize_nonzero() {
        assert!(estimate_vsize(1, 2) > 0);
        assert!(estimate_vsize(2, 3) > estimate_vsize(1, 2));
    }
}
