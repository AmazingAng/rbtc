use std::collections::HashMap;

use rbtc_consensus::{
    tx_verify::verify_transaction,
    utxo::UtxoSet,
};
use rbtc_primitives::{
    hash::TxId,
    transaction::{OutPoint, Transaction},
};
use rbtc_script::ScriptFlags;
use tracing::{debug, info};

use crate::{entry::MempoolEntry, error::MempoolError};

/// In-memory transaction pool
pub struct Mempool {
    entries: HashMap<TxId, MempoolEntry>,
    /// UTXOs created by mempool transactions (for chained-tx validation)
    mempool_utxos: UtxoSet,
    /// Minimum relay fee rate in sat/vbyte (default 1)
    min_relay_fee_rate: u64,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            mempool_utxos: UtxoSet::new(),
            min_relay_fee_rate: 1,
        }
    }

    /// Try to accept a transaction into the mempool.
    ///
    /// Validates consensus rules and fee rate. On success returns the txid.
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        chain_utxos: &UtxoSet,
        chain_height: u32,
    ) -> Result<TxId, MempoolError> {
        // Compute txid (legacy serialisation for the witness-stripped hash)
        let txid = {
            let mut buf = Vec::new();
            tx.encode_legacy(&mut buf).ok();
            rbtc_crypto::sha256d(&buf)
        };

        if tx.is_coinbase() {
            return Err(MempoolError::Coinbase);
        }

        if self.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyKnown);
        }

        // Build a minimal UTXO view that covers exactly the inputs of this tx
        let mut input_view = UtxoSet::new();
        for input in &tx.inputs {
            let op = &input.previous_output;
            if let Some(u) = chain_utxos.get(op) {
                input_view.insert(op.clone(), u.clone());
            } else if let Some(u) = self.mempool_utxos.get(op) {
                input_view.insert(op.clone(), u.clone());
            } else {
                return Err(MempoolError::MissingInput(op.txid.to_hex(), op.vout));
            }
        }

        // Full consensus validation
        let fee = verify_transaction(&tx, &input_view, chain_height, ScriptFlags::standard())?;

        let vsize = tx.vsize();
        let fee_rate = fee / vsize.max(1);

        if fee_rate < self.min_relay_fee_rate {
            return Err(MempoolError::FeeTooLow(fee_rate, self.min_relay_fee_rate));
        }

        // Track outputs in our mempool UTXO set for chained-tx support
        self.mempool_utxos.add_tx(txid, &tx, chain_height);

        info!("mempool: accepted tx {} fee={fee} sat vsize={vsize} rate={fee_rate}", txid.to_hex());

        let entry = MempoolEntry {
            tx,
            txid,
            fee,
            vsize,
            fee_rate,
            added_at: std::time::Instant::now(),
        };
        self.entries.insert(txid, entry);

        Ok(txid)
    }

    /// Remove a set of transactions that were confirmed in a block.
    pub fn remove_confirmed(&mut self, txids: &[TxId]) {
        let mut removed = 0usize;
        for txid in txids {
            if self.entries.remove(txid).is_some() {
                removed += 1;
            }
        }
        if removed > 0 {
            debug!("mempool: removed {removed} confirmed transactions");
            self.rebuild_mempool_utxos();
        }
    }

    pub fn contains(&self, txid: &TxId) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn get(&self, txid: &TxId) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all txids sorted by descending fee rate (highest priority first).
    pub fn txids_by_fee_rate(&self) -> Vec<TxId> {
        let mut v: Vec<_> = self.entries.values().collect();
        v.sort_unstable_by(|a, b| b.fee_rate.cmp(&a.fee_rate));
        v.iter().map(|e| e.txid).collect()
    }

    /// Return all txids (unordered)
    pub fn txids(&self) -> Vec<TxId> {
        self.entries.keys().copied().collect()
    }

    /// Iterate all (txid, tx) pairs in the mempool (used by BIP152 compact block reconstruction).
    pub fn transactions(&self) -> HashMap<TxId, rbtc_primitives::transaction::Transaction> {
        self.entries
            .iter()
            .map(|(txid, entry)| (*txid, entry.tx.clone()))
            .collect()
    }

    /// Total mempool size in virtual bytes
    pub fn total_vsize(&self) -> u64 {
        self.entries.values().map(|e| e.vsize).sum()
    }

    /// Check whether an outpoint is spent by an in-mempool transaction.
    pub fn has_spend(&self, outpoint: &OutPoint) -> bool {
        self.entries.values().any(|e| {
            e.tx.inputs.iter().any(|i| &i.previous_output == outpoint)
        })
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn rebuild_mempool_utxos(&mut self) {
        self.mempool_utxos = UtxoSet::new();
        for (txid, entry) in &self.entries {
            self.mempool_utxos.add_tx(*txid, &entry.tx, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        hash::Hash256,
        script::Script,
        transaction::{TxIn, TxOut},
    };
    use rbtc_consensus::utxo::Utxo;

    fn simple_coinbase_tx(txid: TxId) -> Transaction {
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

    /// scriptPubKey = OP_TRUE (0x51 = OP_1), scriptSig = empty → always succeeds
    fn spend_tx(prev_txid: TxId, value_out: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: value_out, script_pubkey: Script::new() }],
            lock_time: 0,
        }
    }

    /// Returns a UTXO set containing one output with scriptPubKey = OP_1 (always-valid).
    fn utxo_set_with(outpoint: OutPoint, value: u64) -> UtxoSet {
        let mut set = UtxoSet::new();
        // OP_1 (0x51) pushes 1 → stack is [1] → truthy → script succeeds
        set.insert(
            outpoint,
            Utxo {
                txout: TxOut { value, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: false,
                height: 100,
            },
        );
        set
    }

    #[test]
    fn accept_coinbase_rejected() {
        let mut mp = Mempool::new();
        let tx = simple_coinbase_tx(Hash256([1; 32]));
        let chain = UtxoSet::new();
        assert!(matches!(mp.accept_tx(tx, &chain, 200), Err(MempoolError::Coinbase)));
    }

    #[test]
    fn accept_missing_input() {
        let mut mp = Mempool::new();
        let tx = spend_tx(Hash256([1; 32]), 1000);
        let chain = UtxoSet::new(); // empty
        assert!(matches!(mp.accept_tx(tx, &chain, 200), Err(MempoolError::MissingInput(_, _))));
    }

    #[test]
    fn accept_and_remove_confirmed() {
        let mut mp = Mempool::new();
        let prev_txid = Hash256([42; 32]);
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };
        let chain = utxo_set_with(outpoint, 50_0000_0000);
        // value_out < value_in so fee > 0
        let tx = spend_tx(prev_txid, 49_9999_0000);
        let txid = mp.accept_tx(tx, &chain, 200).unwrap();
        assert!(mp.contains(&txid));
        assert_eq!(mp.len(), 1);
        mp.remove_confirmed(&[txid]);
        assert!(!mp.contains(&txid));
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn duplicate_rejected() {
        let mut mp = Mempool::new();
        let prev_txid = Hash256([7; 32]);
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };
        let chain = utxo_set_with(outpoint, 50_0000_0000);
        let tx = spend_tx(prev_txid, 49_9999_0000);
        mp.accept_tx(tx.clone(), &chain, 200).unwrap();
        let err = mp.accept_tx(tx, &chain, 200).unwrap_err();
        assert!(matches!(err, MempoolError::AlreadyKnown));
    }
}
