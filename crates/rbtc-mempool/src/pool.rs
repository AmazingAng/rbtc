use std::collections::{HashMap, HashSet};

use rbtc_consensus::{
    tx_verify::verify_transaction,
    utxo::{UtxoLookup, UtxoSet},
};
use rbtc_primitives::{
    hash::TxId,
    transaction::{OutPoint, Transaction},
};
use rbtc_script::ScriptFlags;
use tracing::{debug, info, warn};

use crate::{
    entry::MempoolEntry,
    error::MempoolError,
    policy::{is_standard_tx, V3PolicyError, MAX_V3_TX_VSIZE},
};

/// Default maximum total vsize (~300 MB).
const DEFAULT_MAX_VSIZE: u64 = 300_000_000;

/// Bitcoin Core default: max ancestor/descendant count (including the tx itself).
const DEFAULT_MAX_ANCESTOR_COUNT: u64 = 25;
const DEFAULT_MAX_DESCENDANT_COUNT: u64 = 25;

/// Bitcoin Core default: mempool transaction expiry time (336 hours = 14 days).
const DEFAULT_MEMPOOL_EXPIRY: std::time::Duration = std::time::Duration::from_secs(336 * 3600);

/// In-memory transaction pool
pub struct Mempool {
    entries: HashMap<TxId, MempoolEntry>,
    /// UTXOs created by mempool transactions (for chained-tx validation)
    mempool_utxos: UtxoSet,
    /// Minimum relay fee rate in sat/vbyte (default 1)
    min_relay_fee_rate: u64,
    /// Maximum total virtual size of all transactions in the pool.
    max_vsize: u64,
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
            max_vsize: DEFAULT_MAX_VSIZE,
        }
    }

    pub fn with_max_vsize(max_vsize: u64) -> Self {
        Self { max_vsize, ..Self::new() }
    }

    /// Try to accept a transaction into the mempool.
    ///
    /// Implements BIP125 Replace-by-Fee when conflicting inputs are detected.
    /// On success returns the txid.
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        chain_utxos: &impl UtxoLookup,
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

        // ── Standardness checks (E4) ────────────────────────────────────
        if let Err(reason) = is_standard_tx(&tx) {
            return Err(MempoolError::NonStandard(reason.to_string()));
        }

        let new_signals_rbf = signals_rbf(&tx);

        // Collect the set of outpoints spent by this transaction
        let tx_spends: HashSet<&OutPoint> = tx.inputs.iter()
            .map(|i| &i.previous_output)
            .collect();

        // ── BIP125 conflict detection ──────────────────────────────────────
        let conflicting: Vec<TxId> = self.entries.values()
            .filter(|e| e.tx.inputs.iter().any(|i| tx_spends.contains(&i.previous_output)))
            .map(|e| e.txid)
            .collect();

        if !conflicting.is_empty() {
            // All conflicting transactions must signal RBF
            for cid in &conflicting {
                if !self.entries[cid].signals_rbf {
                    return Err(MempoolError::RbfNotSignaling);
                }
            }
            if conflicting.len() > 100 {
                return Err(MempoolError::TooManyReplacements(conflicting.len()));
            }
        }

        // Build a minimal UTXO view that covers exactly the inputs of this tx
        let mut input_view = UtxoSet::new();
        for input in &tx.inputs {
            let op = &input.previous_output;
            if let Some(u) = chain_utxos.get_utxo(op) {
                input_view.insert(op.clone(), u);
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

        // ── RBF fee bump check ────────────────────────────────────────────
        if !conflicting.is_empty() {
            // New fee rate must exceed the highest conflicting rate + relay fee
            let max_conflict_rate = conflicting.iter()
                .map(|cid| self.entries[cid].fee_rate)
                .max()
                .unwrap_or(0);
            let required = max_conflict_rate.saturating_add(self.min_relay_fee_rate);
            if fee_rate < required {
                return Err(MempoolError::RbfInsufficientFee(fee_rate, max_conflict_rate, self.min_relay_fee_rate));
            }

            // Remove all conflicting transactions
            for cid in &conflicting {
                self.entries.remove(cid);
            }
            info!(
                "mempool: RBF replaced {} tx(s) with {} fee_rate={fee_rate}",
                conflicting.len(),
                txid.to_hex()
            );
            self.rebuild_mempool_utxos();
        }

        // ── V3 transaction policy (BIP431 / E2) ─────────────────────────
        if tx.version == 3 {
            if vsize > MAX_V3_TX_VSIZE {
                return Err(MempoolError::V3Policy(
                    V3PolicyError::TxTooLarge(vsize).to_string(),
                ));
            }
            // Count unconfirmed parents
            let unconfirmed_parents: Vec<TxId> = tx
                .inputs
                .iter()
                .filter_map(|i| {
                    let ptxid = i.previous_output.txid;
                    if self.entries.contains_key(&ptxid) {
                        Some(ptxid)
                    } else {
                        None
                    }
                })
                .collect();
            if unconfirmed_parents.len() > 1 {
                return Err(MempoolError::V3Policy(
                    V3PolicyError::TooManyUnconfirmedParents(unconfirmed_parents.len()).to_string(),
                ));
            }
            // If there's one unconfirmed parent, check it doesn't already have an
            // in-mempool child
            if let Some(parent_txid) = unconfirmed_parents.first() {
                let has_existing_child = self.entries.values().any(|e| {
                    e.txid != txid
                        && e.tx.inputs.iter().any(|i| i.previous_output.txid == *parent_txid)
                });
                if has_existing_child {
                    return Err(MempoolError::V3Policy(
                        V3PolicyError::ParentAlreadyHasChild.to_string(),
                    ));
                }
            }
        }

        // ── CPFP ancestor fee rate ────────────────────────────────────────
        let ancestor_fee_rate = self.compute_ancestor_fee_rate(&tx, fee, vsize);

        // Track outputs in our mempool UTXO set for chained-tx support
        self.mempool_utxos.add_tx(txid, &tx, chain_height);

        info!(
            "mempool: accepted tx {} fee={fee} sat vsize={vsize} rate={fee_rate} ancestor_rate={ancestor_fee_rate}",
            txid.to_hex()
        );

        // Compute ancestor stats (including self)
        let (anc_fee, anc_vsize) = self.ancestor_package(&txid);
        // ancestor_package won't find our tx yet, so add self manually
        let ancestor_fees = anc_fee + fee;
        let ancestor_vsize_total = anc_vsize + vsize;
        let ancestor_count = {
            let mut visited = HashSet::new();
            self.count_ancestors_inner(&tx, &mut visited) + 1
        };

        // ── Ancestor/descendant count limits (Bitcoin Core default: 25) ──
        if ancestor_count > DEFAULT_MAX_ANCESTOR_COUNT {
            return Err(MempoolError::TooManyAncestors(
                ancestor_count,
                DEFAULT_MAX_ANCESTOR_COUNT,
            ));
        }

        // Check that adding this tx won't push any parent's descendant count over the limit
        for input in &tx.inputs {
            let ptxid = &input.previous_output.txid;
            if let Some(parent) = self.entries.get(ptxid) {
                // parent.descendant_count doesn't include the new tx yet, so +1
                if parent.descendant_count + 1 >= DEFAULT_MAX_DESCENDANT_COUNT {
                    return Err(MempoolError::TooManyDescendants(
                        parent.descendant_count + 1,
                        DEFAULT_MAX_DESCENDANT_COUNT,
                    ));
                }
            }
        }

        let entry = MempoolEntry {
            tx,
            txid,
            fee,
            vsize,
            fee_rate,
            signals_rbf: new_signals_rbf,
            ancestor_fee_rate,
            ancestor_count: ancestor_count as u64,
            ancestor_vsize: ancestor_vsize_total,
            ancestor_fees,
            descendant_count: 0,
            descendant_vsize: vsize,
            descendant_fees: fee,
            added_at: std::time::Instant::now(),
        };
        self.entries.insert(txid, entry);

        // Update descendant stats of all ancestors
        self.update_ancestor_descendants(txid, fee, vsize);

        // ── Size cap eviction ─────────────────────────────────────────────
        if self.total_vsize() > self.max_vsize {
            self.evict_below_fee_rate(fee_rate)?;
        }

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

    /// Return all txids sorted by descending ancestor fee rate (highest priority first).
    pub fn txids_by_fee_rate(&self) -> Vec<TxId> {
        let mut v: Vec<_> = self.entries.values().collect();
        v.sort_unstable_by(|a, b| b.ancestor_fee_rate.cmp(&a.ancestor_fee_rate));
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

    /// Return the minimum fee_rate (sat/vbyte) of any entry currently in the pool,
    /// or `min_relay_fee_rate` when the pool is empty.  Used by `estimatesmartfee`.
    pub fn min_fee_rate(&self) -> u64 {
        self.entries.values().map(|e| e.fee_rate).min()
            .unwrap_or(self.min_relay_fee_rate)
    }

    /// Remove transactions that have been in the mempool longer than the expiry
    /// duration (default 336 hours / 14 days, matching Bitcoin Core).
    /// Returns the number of expired transactions removed.
    pub fn expire_old_transactions(&mut self) -> usize {
        let now = std::time::Instant::now();
        let expired: Vec<TxId> = self
            .entries
            .values()
            .filter(|e| now.duration_since(e.added_at) >= DEFAULT_MEMPOOL_EXPIRY)
            .map(|e| e.txid)
            .collect();
        let count = expired.len();
        if count > 0 {
            for txid in &expired {
                self.entries.remove(txid);
            }
            self.rebuild_mempool_utxos();
            info!("mempool: expired {count} old transactions");
        }
        count
    }

    // ── CPFP ancestor computation ─────────────────────────────────────────────

    /// Recursively collect unconfirmed ancestor transactions and return
    /// `(total_ancestor_fee, total_ancestor_vsize)` including `tx` itself.
    pub fn ancestor_package(&self, txid: &TxId) -> (u64, u64) {
        let mut visited = HashSet::new();
        self.collect_ancestors(txid, &mut visited)
    }

    fn collect_ancestors(&self, txid: &TxId, visited: &mut HashSet<TxId>) -> (u64, u64) {
        if !visited.insert(*txid) {
            return (0, 0);
        }
        let Some(entry) = self.entries.get(txid) else { return (0, 0); };
        let mut total_fee = entry.fee;
        let mut total_vsize = entry.vsize;
        for input in &entry.tx.inputs {
            let parent_txid = &input.previous_output.txid;
            if self.entries.contains_key(parent_txid) {
                let (f, v) = self.collect_ancestors(parent_txid, visited);
                total_fee += f;
                total_vsize += v;
            }
        }
        (total_fee, total_vsize)
    }

    /// Compute the effective (ancestor) fee rate for a transaction that is
    /// about to be inserted but not yet in `self.entries`.
    fn compute_ancestor_fee_rate(&self, tx: &Transaction, own_fee: u64, own_vsize: u64) -> u64 {
        let mut visited: HashSet<TxId> = HashSet::new();
        let mut total_fee = own_fee;
        let mut total_vsize = own_vsize;

        for input in &tx.inputs {
            let parent_txid = &input.previous_output.txid;
            if self.entries.contains_key(parent_txid) {
                let (f, v) = self.collect_ancestors(parent_txid, &mut visited);
                total_fee += f;
                total_vsize += v;
            }
        }

        total_fee / total_vsize.max(1)
    }

    // ── Eviction ──────────────────────────────────────────────────────────────

    /// Evict lowest-ancestor-fee-rate transactions until `total_vsize ≤ max_vsize`.
    /// Uses ancestor fee rate for eviction priority (matching Bitcoin Core).
    /// If the just-inserted transaction has the lowest rate, it is rejected.
    fn evict_below_fee_rate(&mut self, new_fee_rate: u64) -> Result<(), MempoolError> {
        // Sort ascending by ancestor_fee_rate → evict cheapest first (E5)
        let mut by_rate: Vec<(TxId, u64)> = self.entries.values()
            .map(|e| (e.txid, e.ancestor_fee_rate))
            .collect();
        by_rate.sort_unstable_by_key(|&(_, r)| r);

        for (evict_id, evict_rate) in &by_rate {
            if self.total_vsize() <= self.max_vsize {
                break;
            }
            if *evict_rate >= new_fee_rate {
                self.entries.remove(evict_id);
                self.rebuild_mempool_utxos();
                return Err(MempoolError::MempoolFull);
            }
            warn!("mempool: evicting {} (ancestor_fee_rate={evict_rate}) due to size limit", evict_id.to_hex());
            self.entries.remove(evict_id);
        }
        self.rebuild_mempool_utxos();
        Ok(())
    }

    // ── Ancestor/descendant helpers ─────────────────────────────────────

    /// Count in-mempool ancestors of a transaction (not yet inserted).
    fn count_ancestors_inner(
        &self,
        tx: &Transaction,
        visited: &mut HashSet<TxId>,
    ) -> u64 {
        let mut count = 0u64;
        for input in &tx.inputs {
            let ptxid = input.previous_output.txid;
            if !visited.insert(ptxid) {
                continue;
            }
            if let Some(parent) = self.entries.get(&ptxid) {
                count += 1;
                count += self.count_ancestors_inner(&parent.tx.clone(), visited);
            }
        }
        count
    }

    /// After inserting a new entry, update descendant stats of all its ancestors.
    fn update_ancestor_descendants(&mut self, new_txid: TxId, fee: u64, vsize: u64) {
        let tx = match self.entries.get(&new_txid) {
            Some(e) => e.tx.clone(),
            None => return,
        };
        let mut visited = HashSet::new();
        let mut stack: Vec<TxId> = tx
            .inputs
            .iter()
            .filter_map(|i| {
                let ptxid = i.previous_output.txid;
                if self.entries.contains_key(&ptxid) {
                    Some(ptxid)
                } else {
                    None
                }
            })
            .collect();
        while let Some(ancestor_id) = stack.pop() {
            if !visited.insert(ancestor_id) {
                continue;
            }
            if let Some(ancestor) = self.entries.get_mut(&ancestor_id) {
                ancestor.descendant_count += 1;
                ancestor.descendant_vsize += vsize;
                ancestor.descendant_fees += fee;
                let parent_tx = ancestor.tx.clone();
                for inp in &parent_tx.inputs {
                    if self.entries.contains_key(&inp.previous_output.txid) {
                        stack.push(inp.previous_output.txid);
                    }
                }
            }
        }
    }

    /// Accept a package of transactions (parent + children) together (E1).
    ///
    /// This allows child-pays-for-parent where the child's fee compensates
    /// for a low-fee parent that would not be accepted individually.
    pub fn accept_package(
        &mut self,
        txs: Vec<Transaction>,
        chain_utxos: &impl UtxoLookup,
        chain_height: u32,
    ) -> Result<Vec<TxId>, MempoolError> {
        // Sort topologically: parents before children
        let mut sorted = Vec::with_capacity(txs.len());
        let mut remaining: Vec<Transaction> = txs;
        let mut accepted_txids: HashSet<TxId> = HashSet::new();

        let max_rounds = remaining.len() + 1;
        for _ in 0..max_rounds {
            if remaining.is_empty() {
                break;
            }
            let mut next_remaining = Vec::new();
            let mut made_progress = false;
            for tx in remaining {
                let all_parents_available = tx.inputs.iter().all(|i| {
                    let ptxid = i.previous_output.txid;
                    chain_utxos.get_utxo(&i.previous_output).is_some()
                        || self.entries.contains_key(&ptxid)
                        || accepted_txids.contains(&ptxid)
                });
                if all_parents_available {
                    let mut buf = Vec::new();
                    tx.encode_legacy(&mut buf).ok();
                    let txid = rbtc_crypto::sha256d(&buf);
                    sorted.push(tx);
                    accepted_txids.insert(txid);
                    made_progress = true;
                } else {
                    next_remaining.push(tx);
                }
            }
            remaining = next_remaining;
            if !made_progress {
                return Err(MempoolError::MissingInput(
                    "package has unresolvable dependencies".to_string(),
                    0,
                ));
            }
        }

        let mut result = Vec::new();
        for tx in sorted {
            let txid = self.accept_tx(tx, chain_utxos, chain_height)?;
            result.push(txid);
        }
        Ok(result)
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn rebuild_mempool_utxos(&mut self) {
        self.mempool_utxos = UtxoSet::new();
        for (txid, entry) in &self.entries {
            self.mempool_utxos.add_tx(*txid, &entry.tx, 0);
        }
    }
}

/// BIP125: a transaction signals opt-in RBF if any input has nSequence < 0xFFFFFFFE.
fn signals_rbf(tx: &Transaction) -> bool {
    tx.inputs.iter().any(|i| i.sequence < 0xFFFFFFFE)
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

    fn simple_coinbase_tx() -> Transaction {
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

    /// Create a spending tx with a standard P2WPKH output.
    fn spend_tx(prev_txid: TxId, value_out: u64) -> Transaction {
        // P2WPKH scriptPubKey: OP_0 <20 bytes>
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: value_out, script_pubkey: Script::from_bytes(spk) }],
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
        let tx = simple_coinbase_tx();
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
