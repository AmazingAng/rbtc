//! Orphan transaction pool.
//!
//! Temporarily stores transactions whose inputs are not yet available
//! (TX_MISSING_INPUTS). When a new block arrives or a transaction is
//! accepted into the mempool, the orphan pool is checked for children
//! whose missing parents may now be available.
//!
//! Matches Bitcoin Core's `TxOrphanage` in `src/node/txorphanage.cpp`.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rbtc_primitives::hash::{Txid, Wtxid};
use rbtc_primitives::transaction::{OutPoint, Transaction};

/// Maximum number of orphan transactions kept in memory.
/// Bitcoin Core uses weight-based limits; we use a simple count for now.
const MAX_ORPHAN_TRANSACTIONS: usize = 100;

/// Maximum weight of an individual orphan transaction (400,000 WU = standard tx limit).
const MAX_ORPHAN_TX_WEIGHT: u64 = 400_000;

/// Orphan transactions are expired after 20 minutes.
const ORPHAN_TX_EXPIRE_TIME: Duration = Duration::from_secs(20 * 60);

/// An orphan transaction waiting for its parent(s).
#[derive(Debug, Clone)]
struct OrphanEntry {
    tx: Transaction,
    txid: Txid,
    wtxid: Wtxid,
    /// Peer that sent us this orphan.
    from_peer: u64,
    /// Time when the orphan was added.
    added_at: Instant,
}

/// A pool of orphan transactions (missing one or more parent inputs).
#[derive(Debug)]
pub struct OrphanPool {
    /// Orphans indexed by wtxid (primary key, matching Bitcoin Core).
    entries: HashMap<Wtxid, OrphanEntry>,
    /// Index from parent outpoint → set of orphan wtxids that need it.
    by_prev: HashMap<OutPoint, HashSet<Wtxid>>,
    /// Index from txid → wtxid for deduplication.
    txid_to_wtxid: HashMap<Txid, Wtxid>,
}

/// Result of adding an orphan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOrphanResult {
    /// Successfully added.
    Added,
    /// Already known (duplicate txid or wtxid).
    AlreadyKnown,
    /// Rejected: too large, pool full, etc.
    Rejected(&'static str),
}

impl OrphanPool {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            by_prev: HashMap::new(),
            txid_to_wtxid: HashMap::new(),
        }
    }

    /// Number of orphan transactions in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if we already have this orphan (by txid).
    pub fn have_tx(&self, txid: &Txid) -> bool {
        self.txid_to_wtxid.contains_key(txid)
    }

    /// Add an orphan transaction. Returns the result.
    pub fn add_tx(&mut self, tx: Transaction, from_peer: u64) -> AddOrphanResult {
        let txid = *tx.txid();
        let wtxid = *tx.wtxid();

        // Already known?
        if self.txid_to_wtxid.contains_key(&txid) || self.entries.contains_key(&wtxid) {
            return AddOrphanResult::AlreadyKnown;
        }

        // Reject if too large
        if tx.weight() > MAX_ORPHAN_TX_WEIGHT {
            return AddOrphanResult::Rejected("orphan tx too large");
        }

        // Reject coinbase
        if tx.is_coinbase() {
            return AddOrphanResult::Rejected("coinbase cannot be orphan");
        }

        // Evict expired entries first
        self.expire();

        // Limit pool size — evict a random entry if full
        if self.entries.len() >= MAX_ORPHAN_TRANSACTIONS {
            self.evict_random();
        }

        // Index by parent outpoints
        for input in &tx.inputs {
            self.by_prev
                .entry(input.previous_output.clone())
                .or_default()
                .insert(wtxid);
        }

        self.txid_to_wtxid.insert(txid, wtxid);
        self.entries.insert(
            wtxid,
            OrphanEntry {
                tx,
                txid,
                wtxid,
                from_peer,
                added_at: Instant::now(),
            },
        );

        AddOrphanResult::Added
    }

    /// Remove an orphan by wtxid.
    pub fn erase_tx(&mut self, wtxid: &Wtxid) -> bool {
        if let Some(entry) = self.entries.remove(wtxid) {
            self.txid_to_wtxid.remove(&entry.txid);
            // Remove from by_prev index
            for input in &entry.tx.inputs {
                if let Some(set) = self.by_prev.get_mut(&input.previous_output) {
                    set.remove(wtxid);
                    if set.is_empty() {
                        self.by_prev.remove(&input.previous_output);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Remove all orphans from a specific peer.
    pub fn erase_for_peer(&mut self, peer_id: u64) -> usize {
        let to_remove: Vec<Wtxid> = self
            .entries
            .values()
            .filter(|e| e.from_peer == peer_id)
            .map(|e| e.wtxid)
            .collect();
        let count = to_remove.len();
        for wtxid in &to_remove {
            self.erase_tx(wtxid);
        }
        count
    }

    /// Get the set of orphan transactions that spend outputs of the given txid.
    /// Returns (Transaction, from_peer) pairs that can now be retried.
    pub fn get_children_of(&self, parent_txid: &Txid) -> Vec<(Transaction, u64)> {
        let mut children = Vec::new();
        // Check all possible vout indices. We scan the by_prev index for
        // outpoints matching this txid.
        let matching_wtxids: HashSet<Wtxid> = self
            .by_prev
            .iter()
            .filter(|(op, _)| op.txid == *parent_txid)
            .flat_map(|(_, wtxids)| wtxids.iter().copied())
            .collect();

        for wtxid in matching_wtxids {
            if let Some(entry) = self.entries.get(&wtxid) {
                children.push((entry.tx.clone(), entry.from_peer));
            }
        }
        children
    }

    /// Remove orphans that conflict with a confirmed block's transactions.
    /// Any orphan that spends an outpoint also spent by a block tx is removed.
    pub fn erase_for_block(&mut self, block_txids: &[Txid], block_txs: &[Transaction]) -> usize {
        let mut removed = 0usize;

        // 1. Remove orphans whose txid appears in the block (they got confirmed).
        for txid in block_txids {
            if let Some(wtxid) = self.txid_to_wtxid.get(txid).copied() {
                self.erase_tx(&wtxid);
                removed += 1;
            }
        }

        // 2. Remove orphans that conflict with block transactions (spending same outpoint).
        let mut block_spent: HashSet<OutPoint> = HashSet::new();
        for tx in block_txs {
            for input in &tx.inputs {
                block_spent.insert(input.previous_output.clone());
            }
        }

        let conflicting: Vec<Wtxid> = self
            .by_prev
            .iter()
            .filter(|(op, _)| block_spent.contains(op))
            .flat_map(|(_, wtxids)| wtxids.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for wtxid in &conflicting {
            if self.erase_tx(wtxid) {
                removed += 1;
            }
        }

        removed
    }

    /// Expire orphans older than ORPHAN_TX_EXPIRE_TIME.
    fn expire(&mut self) {
        let now = Instant::now();
        let expired: Vec<Wtxid> = self
            .entries
            .values()
            .filter(|e| now.duration_since(e.added_at) >= ORPHAN_TX_EXPIRE_TIME)
            .map(|e| e.wtxid)
            .collect();
        for wtxid in &expired {
            self.erase_tx(wtxid);
        }
    }

    /// Evict one random orphan to make room.
    fn evict_random(&mut self) {
        // Pick the oldest entry as a simple deterministic strategy
        if let Some(oldest_wtxid) = self
            .entries
            .values()
            .min_by_key(|e| e.added_at)
            .map(|e| e.wtxid)
        {
            self.erase_tx(&oldest_wtxid);
        }
    }
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};

    fn make_tx(prev_txid: Hash256, prev_vout: u32) -> Transaction {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0u8; 20]);
        Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_hash(prev_txid),
                    vout: prev_vout,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 1_000_000,
                script_pubkey: Script::from_bytes(spk),
            }],
            0,
        )
    }

    #[test]
    fn add_and_retrieve_orphan() {
        let mut pool = OrphanPool::new();
        let parent_hash = Hash256([1u8; 32]);
        let tx = make_tx(parent_hash, 0);
        let txid = *tx.txid();

        assert_eq!(pool.add_tx(tx.clone(), 42), AddOrphanResult::Added);
        assert_eq!(pool.len(), 1);
        assert!(pool.have_tx(&txid));

        // Children lookup
        let parent_txid = Txid::from_hash(parent_hash);
        let children = pool.get_children_of(&parent_txid);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].1, 42); // from_peer
    }

    #[test]
    fn duplicate_rejected() {
        let mut pool = OrphanPool::new();
        let tx = make_tx(Hash256([2u8; 32]), 0);
        assert_eq!(pool.add_tx(tx.clone(), 1), AddOrphanResult::Added);
        assert_eq!(pool.add_tx(tx, 2), AddOrphanResult::AlreadyKnown);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn erase_for_peer() {
        let mut pool = OrphanPool::new();
        pool.add_tx(make_tx(Hash256([3u8; 32]), 0), 10);
        pool.add_tx(make_tx(Hash256([4u8; 32]), 0), 20);
        pool.add_tx(make_tx(Hash256([5u8; 32]), 0), 10);
        assert_eq!(pool.len(), 3);

        let removed = pool.erase_for_peer(10);
        assert_eq!(removed, 2);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn erase_for_block_removes_conflicts() {
        let mut pool = OrphanPool::new();
        let parent_hash = Hash256([6u8; 32]);
        pool.add_tx(make_tx(parent_hash, 0), 1);
        assert_eq!(pool.len(), 1);

        // Block tx spends the same outpoint
        let block_tx = make_tx(parent_hash, 0);
        let removed = pool.erase_for_block(&[], &[block_tx]);
        assert_eq!(removed, 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn pool_limits_size() {
        let mut pool = OrphanPool::new();
        for i in 0..(MAX_ORPHAN_TRANSACTIONS + 10) {
            let mut h = [0u8; 32];
            h[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            pool.add_tx(make_tx(Hash256(h), 0), 1);
        }
        // Should be capped at MAX_ORPHAN_TRANSACTIONS
        assert!(pool.len() <= MAX_ORPHAN_TRANSACTIONS);
    }
}
