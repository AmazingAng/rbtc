//! BIP174 PSBT roles: Creator, Updater, Signer, Combiner, Finalizer, Extractor.

use rbtc_primitives::{
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
};

use crate::{
    error::{PsbtError, Result},
    types::{Psbt, PsbtGlobal, PsbtInput, PsbtOutput},
};

// ── Creator ───────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Creator**: build a brand-new unsigned PSBT from a template transaction.
    ///
    /// All scriptSigs and witnesses in `tx` are cleared to produce the unsigned
    /// transaction stored in the PSBT global map.
    pub fn create(tx: Transaction) -> Self {
        let input_count = tx.inputs.len();
        let output_count = tx.outputs.len();

        // Strip any scriptSig / witness (the tx stored in PSBT must be unsigned)
        let unsigned_tx = Transaction {
            version: tx.version,
            lock_time: tx.lock_time,
            inputs: tx
                .inputs
                .into_iter()
                .map(|inp| TxIn {
                    previous_output: inp.previous_output,
                    script_sig: Script::new(),
                    sequence: inp.sequence,
                    witness: vec![],
                })
                .collect(),
            outputs: tx.outputs,
        };

        Psbt {
            global: PsbtGlobal {
                unsigned_tx,
                version: 0,
                unknown: Default::default(),
            },
            inputs: vec![PsbtInput::default(); input_count],
            outputs: vec![PsbtOutput::default(); output_count],
        }
    }
}

// ── Updater ───────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Updater**: attach a full previous transaction for input `index`.
    ///
    /// Used for legacy (non-SegWit) inputs.  Script verification during signing
    /// requires the full prevout transaction.
    pub fn add_non_witness_utxo(&mut self, index: usize, tx: Transaction) -> Result<()> {
        let n = self.inputs.len();
        self.inputs
            .get_mut(index)
            .ok_or(PsbtError::InputCountMismatch { tx: n, psbt: n })?
            .non_witness_utxo = Some(tx);
        Ok(())
    }

    /// **Updater**: attach a specific TxOut for input `index`.
    ///
    /// Used for SegWit (P2WPKH / P2WSH) and Taproot inputs.
    pub fn add_witness_utxo(&mut self, index: usize, txout: TxOut) -> Result<()> {
        let n = self.inputs.len();
        self.inputs
            .get_mut(index)
            .ok_or(PsbtError::InputCountMismatch { tx: n, psbt: n })?
            .witness_utxo = Some(txout);
        Ok(())
    }

    /// **Updater**: set the sighash type for input `index`.
    pub fn set_sighash_type(&mut self, index: usize, sighash_type: u32) -> Result<()> {
        let n = self.inputs.len();
        self.inputs
            .get_mut(index)
            .ok_or(PsbtError::InputCountMismatch { tx: n, psbt: n })?
            .sighash_type = Some(sighash_type);
        Ok(())
    }
}

// ── Combiner ──────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Combiner**: merge another PSBT's per-input and per-output data into this one.
    ///
    /// Both PSBTs must describe the same unsigned transaction.
    pub fn combine(&mut self, other: Psbt) -> Result<()> {
        if self.inputs.len() != other.inputs.len() {
            return Err(PsbtError::InputCountMismatch {
                tx: self.inputs.len(),
                psbt: other.inputs.len(),
            });
        }
        for (dst, src) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            if dst.non_witness_utxo.is_none() {
                dst.non_witness_utxo = src.non_witness_utxo;
            }
            if dst.witness_utxo.is_none() {
                dst.witness_utxo = src.witness_utxo;
            }
            for (pk, sig) in src.partial_sigs {
                dst.partial_sigs.entry(pk).or_insert(sig);
            }
            if dst.sighash_type.is_none() {
                dst.sighash_type = src.sighash_type;
            }
            if dst.redeem_script.is_none() {
                dst.redeem_script = src.redeem_script;
            }
            if dst.witness_script.is_none() {
                dst.witness_script = src.witness_script;
            }
            if dst.final_script_sig.is_none() {
                dst.final_script_sig = src.final_script_sig;
            }
            if dst.final_script_witness.is_none() {
                dst.final_script_witness = src.final_script_witness;
            }
            for (k, v) in src.unknown {
                dst.unknown.entry(k).or_insert(v);
            }
        }
        for (dst, src) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            if dst.redeem_script.is_none() {
                dst.redeem_script = src.redeem_script;
            }
            if dst.witness_script.is_none() {
                dst.witness_script = src.witness_script;
            }
            for (k, v) in src.unknown {
                dst.unknown.entry(k).or_insert(v);
            }
        }
        Ok(())
    }
}

// ── Finalizer ─────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Finalizer**: move partial signatures into `final_script_sig` /
    /// `final_script_witness` and clear signing-time metadata.
    ///
    /// Supports P2WPKH (single-sig SegWit v0) finalization.  Other input types
    /// (P2PKH, P2SH, P2WSH, Taproot) require the caller to set
    /// `final_script_sig` / `final_script_witness` directly.
    pub fn finalize(&mut self) -> Result<()> {
        for inp in &mut self.inputs {
            if inp.is_finalized() {
                continue;
            }
            // P2WPKH: witness_utxo present, exactly one partial sig
            if inp.witness_utxo.is_some() && inp.partial_sigs.len() == 1 {
                let (pk, sig) = inp.partial_sigs.iter().next().unwrap();
                inp.final_script_witness = Some(vec![sig.clone(), pk.clone()]);
                inp.partial_sigs.clear();
                inp.sighash_type = None;
                inp.witness_utxo = None;
                continue;
            }
            // P2PKH / P2SH: non_witness_utxo present, exactly one partial sig
            if inp.non_witness_utxo.is_some() && inp.partial_sigs.len() == 1 {
                let (pk, sig) = inp.partial_sigs.iter().next().unwrap();
                let mut script = Vec::new();
                // <sig_push>
                script.push(sig.len() as u8);
                script.extend_from_slice(sig);
                // <pk_push>
                script.push(pk.len() as u8);
                script.extend_from_slice(pk);
                inp.final_script_sig = Some(Script::from_bytes(script));
                inp.partial_sigs.clear();
                inp.sighash_type = None;
                inp.non_witness_utxo = None;
                continue;
            }
        }
        Ok(())
    }
}

// ── Extractor ─────────────────────────────────────────────────────────────────

impl Psbt {
    /// **Extractor**: produce the final signed `Transaction`.
    ///
    /// Fails if any input has not been finalized.
    pub fn extract_tx(mut self) -> Result<Transaction> {
        for inp in &self.inputs {
            if !inp.is_finalized() {
                return Err(PsbtError::NotFullySigned);
            }
        }

        let mut tx = self.global.unsigned_tx.clone();
        for (tx_in, psbt_in) in tx.inputs.iter_mut().zip(self.inputs.iter_mut()) {
            if let Some(sig) = psbt_in.final_script_sig.take() {
                tx_in.script_sig = sig;
            }
            if let Some(witness) = psbt_in.final_script_witness.take() {
                tx_in.witness = witness;
            }
        }

        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        hash::Hash256,
        transaction::{OutPoint, TxIn},
    };

    fn simple_tx() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256([0xaa; 32]),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 10_000,
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn creator_strips_witnesses() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: Script::from_bytes(vec![1, 2, 3]),
                sequence: 0,
                witness: vec![vec![4, 5]],
            }],
            outputs: vec![TxOut {
                value: 0,
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        };
        let psbt = Psbt::create(tx);
        assert!(psbt.global.unsigned_tx.inputs[0].script_sig.is_empty());
        assert!(psbt.global.unsigned_tx.inputs[0].witness.is_empty());
    }

    #[test]
    fn combiner_merges_partial_sigs() {
        let tx = simple_tx();
        let mut a = Psbt::create(tx.clone());
        let mut b = Psbt::create(tx);

        a.inputs[0].partial_sigs.insert(vec![0x01], vec![0xaa]);
        b.inputs[0].partial_sigs.insert(vec![0x02], vec![0xbb]);

        a.combine(b).unwrap();
        assert_eq!(a.inputs[0].partial_sigs.len(), 2);
    }

    #[test]
    fn extract_tx_fails_without_finalize() {
        let psbt = Psbt::create(simple_tx());
        assert!(psbt.extract_tx().is_err());
    }
}
