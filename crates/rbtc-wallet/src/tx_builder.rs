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

/// Coin selection implementing Bitcoin Core's Branch-and-Bound (BnB) algorithm
/// with a largest-first greedy fallback.
///
/// BnB tries to find a subset of UTXOs that matches the target + fees exactly
/// (or within a small "cost of change" window), avoiding the creation of change
/// outputs. If no exact match is found, falls back to largest-first greedy.
pub struct CoinSelector;

/// Cost of creating + spending a change output (approx. 68 vbytes spend + 31 vbytes output).
const CHANGE_COST: u64 = 99;

/// Maximum BnB search iterations to prevent combinatorial explosion.
const BNB_MAX_TRIES: u32 = 100_000;

/// Long-term fee rate (sat/vbyte) for waste metric calculation.
/// Bitcoin Core uses 10 sat/vbyte as the default long-term estimate.
const LONG_TERM_FEE_RATE: f64 = 10.0;

/// Estimated input weight in vbytes (P2WPKH: ~68 vbytes).
const INPUT_VBYTES: f64 = 68.0;

impl CoinSelector {
    /// Select UTXOs to cover `target_sat` plus a fee estimated at `fee_rate`
    /// sat/vbyte. Returns `(selected, estimated_fee)`.
    ///
    /// First attempts Branch-and-Bound for a changeless transaction, then
    /// falls back to largest-first greedy if BnB fails.
    pub fn select(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        if utxos.is_empty() {
            return Err(WalletError::NoUtxos);
        }

        let estimate_fee = |n_inputs: usize| -> u64 {
            let vbytes = 10 + n_inputs as u64 * 68 + 2 * 31;
            (vbytes as f64 * fee_rate).ceil() as u64
        };

        // Try BnB first (changeless transaction)
        if let Some(result) = Self::branch_and_bound(utxos, target_sat, fee_rate) {
            return Ok(result);
        }

        // Fallback: largest-first greedy (with change)
        Self::largest_first(utxos, target_sat, &estimate_fee)
    }

    /// Branch-and-Bound coin selection.
    ///
    /// Searches for a UTXO subset whose total value is within
    /// [target + fees, target + fees + cost_of_change].
    /// This produces a changeless transaction when successful.
    fn branch_and_bound(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
    ) -> Option<(Vec<WalletUtxo>, u64)> {
        // Sort descending by effective value
        let mut sorted: Vec<(usize, u64)> = utxos
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let input_fee = (68.0 * fee_rate).ceil() as u64;
                let eff = u.value.saturating_sub(input_fee);
                (i, eff)
            })
            .filter(|(_, eff)| *eff > 0)
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        if sorted.is_empty() {
            return None;
        }

        // Base fee for a changeless tx (no change output, so only 1 output)
        let base_fee = (10.0 * fee_rate + 31.0 * fee_rate).ceil() as u64;
        let target_with_fee = target_sat + base_fee;
        let cost_of_change = (CHANGE_COST as f64 * fee_rate).ceil() as u64;

        // Sum of all effective values (for pruning)
        let suffix_sums: Vec<u64> = {
            let mut sums = vec![0u64; sorted.len() + 1];
            for i in (0..sorted.len()).rev() {
                sums[i] = sums[i + 1] + sorted[i].1;
            }
            sums
        };

        if suffix_sums[0] < target_with_fee {
            return None; // Not enough funds even with all UTXOs
        }

        let mut best: Option<(Vec<usize>, f64)> = None;
        let mut current_selection: Vec<bool> = vec![false; sorted.len()];
        let mut current_value = 0u64;
        let mut tries = 0u32;

        // Depth-first branch-and-bound
        let mut depth = 0usize;
        let mut backtrack = false;

        loop {
            if tries >= BNB_MAX_TRIES {
                break;
            }
            tries += 1;

            if backtrack {
                // Backtrack: find the last included UTXO and exclude it
                loop {
                    if depth == 0 {
                        return best.map(|(indices, _total)| {
                            let fee = {
                                let vbytes = 10 + indices.len() as u64 * 68 + 31;
                                (vbytes as f64 * fee_rate).ceil() as u64
                            };
                            let selected: Vec<WalletUtxo> = indices
                                .iter()
                                .map(|&i| utxos[sorted[i].0].clone())
                                .collect();
                            (selected, fee)
                        });
                    }
                    depth -= 1;
                    if current_selection[depth] {
                        current_selection[depth] = false;
                        current_value -= sorted[depth].1;
                        depth += 1;
                        backtrack = false;
                        break;
                    }
                }
                if backtrack {
                    continue;
                }
            }

            if depth >= sorted.len() {
                backtrack = true;
                continue;
            }

            // Include this UTXO
            current_selection[depth] = true;
            current_value += sorted[depth].1;

            if current_value >= target_with_fee {
                if current_value <= target_with_fee + cost_of_change {
                    // Found an acceptable solution — compute waste metric
                    // waste = Σ(input_fee - long_term_fee) + excess
                    let n_selected = current_selection.iter().filter(|&&s| s).count() as f64;
                    let input_fees = n_selected * INPUT_VBYTES * fee_rate;
                    let long_term_fees = n_selected * INPUT_VBYTES * LONG_TERM_FEE_RATE;
                    let excess = (current_value - target_with_fee) as f64;
                    let waste = (input_fees - long_term_fees) + excess;

                    let is_better = match &best {
                        None => true,
                        Some((_, prev_waste)) => waste < *prev_waste,
                    };
                    if is_better {
                        let indices: Vec<usize> = current_selection
                            .iter()
                            .enumerate()
                            .filter(|(_, &s)| s)
                            .map(|(i, _)| i)
                            .collect();
                        best = Some((indices, waste));
                    }
                }
                // Backtrack (we exceeded or found a match)
                backtrack = true;
                current_selection[depth] = false;
                current_value -= sorted[depth].1;
                continue;
            }

            // Prune: if including all remaining can't reach target, skip
            if current_value + suffix_sums[depth + 1] < target_with_fee {
                backtrack = true;
                current_selection[depth] = false;
                current_value -= sorted[depth].1;
                continue;
            }

            // Go deeper
            depth += 1;
        }

        best.map(|(indices, _waste)| {
            let fee = {
                let vbytes = 10 + indices.len() as u64 * 68 + 31;
                (vbytes as f64 * fee_rate).ceil() as u64
            };
            let selected: Vec<WalletUtxo> = indices
                .iter()
                .map(|&i| utxos[sorted[i].0].clone())
                .collect();
            (selected, fee)
        })
    }

    /// Fallback: largest-first greedy coin selection.
    fn largest_first(
        utxos: &[WalletUtxo],
        target_sat: u64,
        estimate_fee: &dyn Fn(usize) -> u64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        let mut sorted: Vec<&WalletUtxo> = utxos.iter().collect();
        sorted.sort_by(|a, b| b.value.cmp(&a.value));

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
        self.outputs.push(TxOut {
            value,
            script_pubkey,
        });
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
    /// For P2WSH inputs: the witness script (e.g. multisig OP_k <pks> OP_n OP_CHECKMULTISIG).
    /// When set, signs using this script as the BIP143 script_code.
    pub witness_script: Option<Script>,
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
        } else if spk.is_p2wsh() {
            // P2WSH — requires witness_script in the SigningInput
            if let Some(ref ws) = si.witness_script {
                let sighash = sighash_segwit_v0(tx, i, ws, si.value, SighashType::All);
                let msg = Message::from_digest(sighash.0);
                let sig = secp.sign_ecdsa(msg, &si.secret_key);
                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(0x01); // SIGHASH_ALL

                // For multisig, build witness: OP_0 <sig1> ... <sigN> <witness_script>
                // Here we provide just our signature; the caller must combine sigs
                // for multi-party multisig. For single-signer or threshold cases
                // where this key suffices, we build a complete witness.
                signed.inputs[i].script_sig = Script::new();
                // Detect multisig: OP_k ... OP_n OP_CHECKMULTISIG (0xae at end)
                let ws_bytes = ws.as_bytes();
                if ws_bytes.last() == Some(&0xae) {
                    // Multisig witness: OP_0 <sig> <witness_script>
                    signed.inputs[i].witness = vec![
                        vec![], // OP_0 dummy (CHECKMULTISIG bug)
                        sig_bytes,
                        ws_bytes.to_vec(),
                    ];
                } else {
                    // Generic P2WSH: <sig> <pubkey> <witness_script>
                    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &si.secret_key);
                    signed.inputs[i].witness =
                        vec![sig_bytes, pubkey.serialize().to_vec(), ws_bytes.to_vec()];
                }
            } else {
                tracing::warn!("sign_transaction: P2WSH input {i} missing witness_script");
            }
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
            tracing::warn!("sign_transaction: unsupported input script type for input {i}");
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
    (weight as u64).div_ceil(4)
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
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        vec![
            WalletUtxo {
                outpoint: OutPoint {
                    txid: Hash256([1u8; 32]),
                    vout: 0,
                },
                value: 100_000,
                script_pubkey: spk.clone(),
                height: 100,
                address: "bc1qtest".into(),
                confirmed: true,
                addr_type: AddressType::SegWit,
            },
            WalletUtxo {
                outpoint: OutPoint {
                    txid: Hash256([2u8; 32]),
                    vout: 0,
                },
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
        let op = OutPoint {
            txid: Hash256([0u8; 32]),
            vout: 0,
        };
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

    #[test]
    fn bnb_finds_exact_match() {
        // Create UTXOs that can exactly cover 150_000 + fees
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |val: u64, id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256([id; 32]),
                vout: 0,
            },
            value: val,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
        };
        let utxos = vec![
            make(50_000, 1),
            make(60_000, 2),
            make(90_000, 3),
            make(100_000, 4),
        ];
        // BnB should find a subset; either way total >= target + fee
        let (selected, fee) = CoinSelector::select(&utxos, 50_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 50_000 + fee);
    }

    #[test]
    fn bnb_falls_back_to_greedy() {
        // With a high fee rate, BnB may not find a changeless solution
        let utxos = sample_utxos();
        let (selected, fee) = CoinSelector::select(&utxos, 50_000, 50.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 50_000 + fee);
    }

    #[test]
    fn bnb_empty_utxos_error() {
        let result = CoinSelector::select(&[], 1_000, 1.0);
        assert!(result.is_err());
    }

    #[test]
    fn largest_first_selects_fewest_utxos() {
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |val: u64, id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Hash256([id; 32]),
                vout: 0,
            },
            value: val,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
        };
        let utxos = vec![make(10_000, 1), make(20_000, 2), make(500_000, 3)];
        let estimate_fee = |n: usize| -> u64 { 10 + n as u64 * 68 + 2 * 31 };
        let (selected, _fee) = CoinSelector::largest_first(&utxos, 100_000, &estimate_fee).unwrap();
        // Should pick the 500k UTXO first (largest), which alone covers 100k
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 500_000);
    }
}
