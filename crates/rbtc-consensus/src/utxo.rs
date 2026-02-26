use std::collections::HashMap;

use rbtc_primitives::{
    hash::TxId,
    transaction::{OutPoint, Transaction, TxOut},
};

/// Trait for looking up UTXOs by `OutPoint`.
///
/// Implementations may be pure in-memory (`UtxoSet`) or cache-backed
/// (`CachedUtxoSet` in `rbtc-node`).  The `Sync` bound is required because
/// Rayon's parallel script verifier captures a `&impl UtxoLookup` across threads.
pub trait UtxoLookup: Sync {
    /// Return the UTXO for `outpoint`, or `None` if it does not exist / is spent.
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<Utxo>;
    /// Return true if any unspent output exists for `txid`.
    fn has_unspent_txid(&self, txid: &TxId) -> bool;
}

/// A single UTXO entry
#[derive(Debug, Clone)]
pub struct Utxo {
    pub txout: TxOut,
    /// True if from a coinbase transaction
    pub is_coinbase: bool,
    /// Block height where this output was created
    pub height: u32,
}

/// In-memory UTXO set (backed by storage layer in production)
#[derive(Debug, Default)]
pub struct UtxoSet {
    coins: HashMap<OutPoint, Utxo>,
}

impl UtxoLookup for UtxoSet {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        self.coins.get(outpoint).cloned()
    }

    fn has_unspent_txid(&self, txid: &TxId) -> bool {
        self.coins.keys().any(|outpoint| &outpoint.txid == txid)
    }
}

impl UtxoSet {
    pub fn new() -> Self {
        Self { coins: HashMap::new() }
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<&Utxo> {
        self.coins.get(outpoint)
    }

    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.coins.contains_key(outpoint)
    }

    /// Add all outputs of a transaction
    pub fn add_tx(&mut self, txid: TxId, tx: &Transaction, height: u32) {
        let is_coinbase = tx.is_coinbase();
        for (vout, txout) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint { txid, vout: vout as u32 };
            self.coins.insert(
                outpoint,
                Utxo { txout: txout.clone(), is_coinbase, height },
            );
        }
    }

    /// Remove inputs (spend UTXOs) of a transaction
    /// Returns the spent UTXOs for undo purposes
    pub fn spend_tx(&mut self, tx: &Transaction) -> Vec<(OutPoint, Utxo)> {
        let mut spent = Vec::new();
        if tx.is_coinbase() {
            return spent;
        }
        for input in &tx.inputs {
            if let Some(utxo) = self.coins.remove(&input.previous_output) {
                spent.push((input.previous_output.clone(), utxo));
            }
        }
        spent
    }

    /// Apply a block: spend inputs, add outputs
    pub fn connect_block(&mut self, txids: &[TxId], txs: &[Transaction], height: u32) {
        for (txid, tx) in txids.iter().zip(txs.iter()) {
            if !tx.is_coinbase() {
                self.spend_tx(tx);
            }
            self.add_tx(*txid, tx, height);
        }
    }

    /// Undo a block (for reorg): remove outputs, re-add inputs
    pub fn disconnect_block(&mut self, txids: &[TxId], txs: &[Transaction], undo: Vec<Vec<(OutPoint, Utxo)>>) {
        // Process in reverse order
        for ((txid, tx), spent) in txids.iter().zip(txs.iter()).rev().zip(undo.into_iter().rev()) {
            // Remove outputs we added
            for vout in 0..tx.outputs.len() {
                self.coins.remove(&OutPoint { txid: *txid, vout: vout as u32 });
            }
            // Restore spent inputs
            for (outpoint, utxo) in spent {
                self.coins.insert(outpoint, utxo);
            }
        }
    }

    /// Directly insert a UTXO (used when loading from persistent storage).
    pub fn insert(&mut self, outpoint: OutPoint, utxo: Utxo) {
        self.coins.insert(outpoint, utxo);
    }

    /// Like `connect_block` but also returns per-tx undo data (spent UTXOs per tx).
    /// Index `i` of the returned Vec corresponds to tx `i`; coinbase entries are empty.
    pub fn connect_block_with_undo(
        &mut self,
        txids: &[TxId],
        txs: &[Transaction],
        height: u32,
    ) -> Vec<Vec<(OutPoint, Utxo)>> {
        let mut undo: Vec<Vec<(OutPoint, Utxo)>> = Vec::with_capacity(txs.len());
        for (txid, tx) in txids.iter().zip(txs.iter()) {
            let spent = if tx.is_coinbase() {
                Vec::new()
            } else {
                self.spend_tx(tx)
            };
            undo.push(spent);
            self.add_tx(*txid, tx, height);
        }
        undo
    }

    pub fn len(&self) -> usize {
        self.coins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        }
    }

    #[test]
    fn utxo_set_new_empty() {
        let set = UtxoSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn utxo_set_add_tx_get_contains() {
        let mut set = UtxoSet::new();
        let tx = coinbase_tx();
        let txid = Hash256([1; 32]);
        set.add_tx(txid, &tx, 0);
        assert_eq!(set.len(), 1);
        let op = OutPoint { txid, vout: 0 };
        assert!(set.contains(&op));
        let u = set.get(&op).unwrap();
        assert!(u.is_coinbase);
        assert_eq!(u.height, 0);
    }

    #[test]
    fn utxo_set_spend_tx() {
        let mut set = UtxoSet::new();
        let txid = Hash256([1; 32]);
        set.add_tx(txid, &coinbase_tx(), 0);
        let spend_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let spent = set.spend_tx(&spend_tx);
        assert_eq!(spent.len(), 1);
        assert!(set.get(&OutPoint { txid, vout: 0 }).is_none());
    }

    #[test]
    fn utxo_set_spend_tx_missing_input_ignored() {
        let mut set = UtxoSet::new();
        let txid1 = Hash256([1; 32]);
        let txid2 = Hash256([2; 32]);
        set.add_tx(txid1, &coinbase_tx(), 0);
        let spend_tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint { txid: txid1, vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint { txid: txid2, vout: 99 },
                    script_sig: Script::new(),
                    sequence: 0,
                    witness: vec![],
                },
            ],
            outputs: vec![TxOut { value: 500, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let spent = set.spend_tx(&spend_tx);
        assert_eq!(spent.len(), 1);
        assert!(set.get(&OutPoint { txid: txid1, vout: 0 }).is_none());
    }

    #[test]
    fn utxo_set_connect_disconnect_block() {
        let mut set = UtxoSet::new();
        let txid1 = Hash256([1; 32]);
        let txid2 = Hash256([2; 32]);
        let cb = coinbase_tx();
        let tx2 = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        set.connect_block(&[txid1, txid2], &[cb.clone(), tx2.clone()], 1);
        assert!(set.len() >= 2);
        set.disconnect_block(&[txid1, txid2], &[cb, tx2], vec![vec![], vec![]]);
        assert!(set.is_empty());
    }

    #[test]
    fn utxo_set_insert() {
        let mut set = UtxoSet::new();
        let op = OutPoint { txid: Hash256([5; 32]), vout: 1 };
        let utxo = Utxo {
            txout: TxOut { value: 500, script_pubkey: Script::new() },
            is_coinbase: false,
            height: 10,
        };
        set.insert(op.clone(), utxo);
        assert_eq!(set.len(), 1);
        let got = set.get(&op).unwrap();
        assert_eq!(got.txout.value, 500);
    }

    #[test]
    fn utxo_set_connect_block_with_undo() {
        let mut set = UtxoSet::new();
        let txid1 = Hash256([1; 32]);
        let txid2 = Hash256([2; 32]);
        let cb = coinbase_tx();
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: txid1, vout: 0 },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 500, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        set.add_tx(txid1, &cb, 0);
        let undo = set.connect_block_with_undo(&[txid1, txid2], &[cb, tx2], 1);
        assert_eq!(undo.len(), 2);
        assert!(undo[0].is_empty());
        assert_eq!(undo[1].len(), 1);
    }
}
