//! Orphan transaction pool.
//!
//! Transactions whose parent(s) are not yet known are cached here.
//! When a new transaction or block arrives and provides a missing parent,
//! the orphans that depend on it are re-tried for mempool acceptance.
//!
//! Matches Bitcoin Core's `TxOrphanage` (net_processing.cpp).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use rbtc_primitives::hash::Txid;
use rbtc_primitives::transaction::Transaction;

/// Maximum number of orphan transactions to keep.
const MAX_ORPHAN_TRANSACTIONS: usize = 100;

/// Orphan transactions expire after 20 minutes.
const ORPHAN_TX_EXPIRE: Duration = Duration::from_secs(20 * 60);

/// Maximum orphan transactions any single peer can contribute.
const MAX_ORPHANS_PER_PEER: usize = 5;

/// Maximum missing parents an orphan can declare.
const MAX_ORPHAN_ANCESTORS: usize = 25;

/// An orphan transaction with metadata.
#[derive(Debug, Clone)]
struct OrphanTx {
    tx: Transaction,
    txid: Txid,
    /// When the orphan was added.
    added_at: Instant,
    /// Which peer sent it (for DoS tracking).
    from_peer: u64,
    /// Parent txids we are missing.
    missing_parents: HashSet<Txid>,
}

/// Pool of orphan transactions awaiting parent confirmation.
#[derive(Debug)]
pub struct OrphanPool {
    /// txid → orphan entry
    orphans: HashMap<Txid, OrphanTx>,
    /// parent_txid → set of orphan txids that need this parent.
    /// This is the key index for efficient "which orphans can be retried?"
    by_parent: HashMap<Txid, HashSet<Txid>>,
    /// FIFO insertion order for eviction when pool is full.
    insertion_order: VecDeque<Txid>,
    /// Number of orphans contributed by each peer (for DoS limits).
    per_peer_count: HashMap<u64, usize>,
}

impl OrphanPool {
    pub fn new() -> Self {
        Self {
            orphans: HashMap::new(),
            by_parent: HashMap::new(),
            insertion_order: VecDeque::new(),
            per_peer_count: HashMap::new(),
        }
    }

    /// Number of orphans currently held.
    pub fn len(&self) -> usize {
        self.orphans.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.orphans.is_empty()
    }

    /// Check if a transaction is already in the orphan pool.
    pub fn contains(&self, txid: &Txid) -> bool {
        self.orphans.contains_key(txid)
    }

    /// Add an orphan transaction with the set of missing parent txids.
    ///
    /// Returns `true` if the orphan was added, `false` if it was already present
    /// or the pool is full (after eviction attempt).
    pub fn add_tx(
        &mut self,
        tx: Transaction,
        txid: Txid,
        missing_parents: HashSet<Txid>,
        from_peer: u64,
    ) -> bool {
        if self.orphans.contains_key(&txid) {
            return false;
        }

        // Reject orphans declaring too many missing parents.
        if missing_parents.len() > MAX_ORPHAN_ANCESTORS {
            return false;
        }

        // Reject if this peer already contributed too many orphans.
        let peer_count = self.per_peer_count.get(&from_peer).copied().unwrap_or(0);
        if peer_count >= MAX_ORPHANS_PER_PEER {
            return false;
        }

        // Expire old orphans first.
        self.expire();

        // Evict oldest if at capacity.
        if self.orphans.len() >= MAX_ORPHAN_TRANSACTIONS {
            self.evict_oldest();
        }

        if self.orphans.len() >= MAX_ORPHAN_TRANSACTIONS {
            return false;
        }

        // Index by parent.
        for parent in &missing_parents {
            self.by_parent.entry(*parent).or_default().insert(txid);
        }

        self.orphans.insert(
            txid,
            OrphanTx {
                tx,
                txid,
                added_at: Instant::now(),
                from_peer,
                missing_parents,
            },
        );
        self.insertion_order.push_back(txid);
        *self.per_peer_count.entry(from_peer).or_insert(0) += 1;
        true
    }

    /// Remove an orphan by txid. Returns the transaction if it was present.
    pub fn remove_tx(&mut self, txid: &Txid) -> Option<Transaction> {
        let orphan = self.orphans.remove(txid)?;
        // Clean up parent index.
        for parent in &orphan.missing_parents {
            if let Some(set) = self.by_parent.get_mut(parent) {
                set.remove(txid);
                if set.is_empty() {
                    self.by_parent.remove(parent);
                }
            }
        }
        self.insertion_order.retain(|t| t != txid);
        // Decrement per-peer count.
        if let Some(count) = self.per_peer_count.get_mut(&orphan.from_peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_peer_count.remove(&orphan.from_peer);
            }
        }
        Some(orphan.tx)
    }

    /// When a parent transaction is confirmed/accepted, return orphan txids
    /// that were waiting for it and may now be eligible for mempool acceptance.
    ///
    /// Returns `Vec<(Txid, Transaction, u64)>` — (orphan_txid, tx, from_peer).
    pub fn get_children_of(&mut self, parent_txid: &Txid) -> Vec<(Txid, Transaction, u64)> {
        let child_txids = match self.by_parent.remove(parent_txid) {
            Some(set) => set,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        for child_txid in &child_txids {
            if let Some(orphan) = self.orphans.get_mut(child_txid) {
                orphan.missing_parents.remove(parent_txid);
                if orphan.missing_parents.is_empty() {
                    // All parents now available — return for retry.
                    if let Some(orphan) = self.orphans.remove(child_txid) {
                        self.insertion_order.retain(|t| t != child_txid);
                        // Decrement per-peer count.
                        if let Some(count) = self.per_peer_count.get_mut(&orphan.from_peer) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                self.per_peer_count.remove(&orphan.from_peer);
                            }
                        }
                        result.push((orphan.txid, orphan.tx, orphan.from_peer));
                    }
                }
            }
        }
        result
    }

    /// Expire orphans older than ORPHAN_TX_EXPIRE.
    fn expire(&mut self) {
        let now = Instant::now();
        let expired: Vec<Txid> = self
            .orphans
            .iter()
            .filter(|(_, o)| now.duration_since(o.added_at) > ORPHAN_TX_EXPIRE)
            .map(|(txid, _)| *txid)
            .collect();
        for txid in expired {
            self.remove_tx(&txid);
        }
    }

    /// Evict the oldest orphan (FIFO).
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self.insertion_order.front().copied() {
            self.remove_tx(&oldest);
        }
    }

    /// Remove all orphans from a specific peer (when peer is banned).
    pub fn remove_for_peer(&mut self, peer_id: u64) {
        let to_remove: Vec<Txid> = self
            .orphans
            .iter()
            .filter(|(_, o)| o.from_peer == peer_id)
            .map(|(txid, _)| *txid)
            .collect();
        for txid in to_remove {
            self.remove_tx(&txid);
        }
    }

    /// Get the set of missing parent txids for requesting from peers.
    pub fn missing_parents(&self) -> HashSet<Txid> {
        self.by_parent.keys().copied().collect()
    }

    /// Return the number of orphans contributed by a given peer.
    pub fn peer_orphan_count(&self, peer_id: u64) -> usize {
        self.per_peer_count.get(&peer_id).copied().unwrap_or(0)
    }
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;

    fn make_txid(n: u8) -> Txid {
        Txid(Hash256([n; 32]))
    }

    fn dummy_tx() -> Transaction {
        Transaction::from_parts(1, vec![], vec![], 0)
    }

    #[test]
    fn add_and_contains() {
        let mut pool = OrphanPool::new();
        let txid = make_txid(1);
        let parent = make_txid(2);
        let mut parents = HashSet::new();
        parents.insert(parent);
        assert!(pool.add_tx(dummy_tx(), txid, parents, 1));
        assert!(pool.contains(&txid));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn duplicate_rejected() {
        let mut pool = OrphanPool::new();
        let txid = make_txid(1);
        let parent = make_txid(2);
        let parents: HashSet<_> = [parent].into_iter().collect();
        assert!(pool.add_tx(dummy_tx(), txid, parents.clone(), 1));
        assert!(!pool.add_tx(dummy_tx(), txid, parents, 1));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn get_children_when_parent_confirmed() {
        let mut pool = OrphanPool::new();
        let parent = make_txid(10);
        let child = make_txid(1);
        let parents: HashSet<_> = [parent].into_iter().collect();
        pool.add_tx(dummy_tx(), child, parents, 1);

        let children = pool.get_children_of(&parent);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].0, child);
        assert!(pool.is_empty());
    }

    #[test]
    fn child_with_two_parents_waits_for_both() {
        let mut pool = OrphanPool::new();
        let p1 = make_txid(10);
        let p2 = make_txid(11);
        let child = make_txid(1);
        let parents: HashSet<_> = [p1, p2].into_iter().collect();
        pool.add_tx(dummy_tx(), child, parents, 1);

        // First parent confirmed — child not ready yet.
        let children = pool.get_children_of(&p1);
        assert!(children.is_empty());
        assert!(pool.contains(&child));

        // Second parent confirmed — child ready.
        let children = pool.get_children_of(&p2);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].0, child);
    }

    #[test]
    fn remove_for_peer() {
        let mut pool = OrphanPool::new();
        let parents: HashSet<_> = [make_txid(10)].into_iter().collect();
        pool.add_tx(dummy_tx(), make_txid(1), parents.clone(), 1);
        pool.add_tx(dummy_tx(), make_txid(2), parents.clone(), 2);
        pool.add_tx(dummy_tx(), make_txid(3), parents.clone(), 1);
        assert_eq!(pool.len(), 3);

        pool.remove_for_peer(1);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&make_txid(2)));
    }

    #[test]
    fn eviction_at_capacity() {
        let mut pool = OrphanPool::new();
        let parents: HashSet<_> = [make_txid(200)].into_iter().collect();
        for i in 0..MAX_ORPHAN_TRANSACTIONS + 5 {
            let txid = Txid(Hash256({
                let mut h = [0u8; 32];
                h[0] = (i & 0xff) as u8;
                h[1] = ((i >> 8) & 0xff) as u8;
                h
            }));
            // Use a unique peer per orphan to avoid per-peer limits.
            pool.add_tx(dummy_tx(), txid, parents.clone(), i as u64);
        }
        assert!(pool.len() <= MAX_ORPHAN_TRANSACTIONS);
    }

    #[test]
    fn per_peer_limit_enforced() {
        let mut pool = OrphanPool::new();
        let parents: HashSet<_> = [make_txid(200)].into_iter().collect();
        for i in 0..MAX_ORPHANS_PER_PEER {
            let txid = make_txid(i as u8);
            assert!(pool.add_tx(dummy_tx(), txid, parents.clone(), 42));
        }
        assert_eq!(pool.peer_orphan_count(42), MAX_ORPHANS_PER_PEER);
        // Next add from same peer should be rejected.
        let txid = make_txid(MAX_ORPHANS_PER_PEER as u8);
        assert!(!pool.add_tx(dummy_tx(), txid, parents.clone(), 42));
        assert_eq!(pool.len(), MAX_ORPHANS_PER_PEER);
        // A different peer can still add.
        assert!(pool.add_tx(dummy_tx(), make_txid(100), parents.clone(), 99));
    }

    #[test]
    fn ancestor_limit_enforced() {
        let mut pool = OrphanPool::new();
        // Build a set of MAX_ORPHAN_ANCESTORS + 1 missing parents.
        let too_many: HashSet<_> = (0..=(MAX_ORPHAN_ANCESTORS as u8))
            .map(|i| make_txid(i))
            .collect();
        assert!(too_many.len() > MAX_ORPHAN_ANCESTORS);
        assert!(!pool.add_tx(dummy_tx(), make_txid(250), too_many, 1));
        assert!(pool.is_empty());
        // Exactly MAX_ORPHAN_ANCESTORS should be fine.
        let ok: HashSet<_> = (0..(MAX_ORPHAN_ANCESTORS as u8))
            .map(|i| make_txid(i))
            .collect();
        assert!(pool.add_tx(dummy_tx(), make_txid(251), ok, 1));
    }

    #[test]
    fn peer_count_decrements_on_remove() {
        let mut pool = OrphanPool::new();
        let parents: HashSet<_> = [make_txid(200)].into_iter().collect();
        pool.add_tx(dummy_tx(), make_txid(1), parents.clone(), 7);
        pool.add_tx(dummy_tx(), make_txid(2), parents.clone(), 7);
        assert_eq!(pool.peer_orphan_count(7), 2);

        pool.remove_tx(&make_txid(1));
        assert_eq!(pool.peer_orphan_count(7), 1);

        pool.remove_tx(&make_txid(2));
        assert_eq!(pool.peer_orphan_count(7), 0);
    }
}
