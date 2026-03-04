//! Write-back UTXO cache with configurable hot-cache size and RocksDB fallback.
//!
//! # Architecture
//!
//! ```text
//!  Block connect ──►  dirty (HashMap)  ──► flush_dirty() ──► WriteBatch → RocksDB
//!                                                         └──► promote to hot
//!  verify_block  ──►  get_utxo():
//!                      1. dirty (includes deletion markers)
//!                      2. hot   (size-limited, recently flushed entries)
//!                      3. RocksDB fallback (cold storage)
//! ```
//!
//! When the hot cache exceeds `max_bytes`, `evict_cold()` removes clean entries
//! (those not currently in `dirty`) until usage is ≤ 80% of the limit.

use std::{collections::HashMap, sync::Arc};

use tracing::debug;

use rbtc_consensus::{Utxo, UtxoLookup};
use rbtc_primitives::{
    hash::TxId,
    transaction::{OutPoint, Transaction},
};
use rbtc_storage::{Database, StoredUtxo, UtxoStore, WriteBatch};

/// Conservative estimate of memory used per cached UTXO entry.
/// OutPoint ≈ 36 B, Utxo header ≈ 16 B, TxOut ≈ 50 B, script average ≈ 25 B,
/// HashMap overhead ≈ 24 B → ~150 B total.
const BYTES_PER_UTXO: u64 = 150;

/// A write-back UTXO cache that limits in-memory size and falls back to RocksDB.
///
/// This type implements [`UtxoLookup`] (required by `verify_block`) and provides
/// the same mutation operations as `UtxoSet` (`connect_block` / `flush_dirty`).
///
/// When `max_bytes` is `None` the hot cache is unbounded and behaves identically
/// to loading all UTXOs into memory up-front.
pub struct CachedUtxoSet {
    /// Entries modified in the current (unflushed) block window.
    /// `None` = UTXO was spent / deleted.
    dirty: HashMap<OutPoint, Option<Utxo>>,
    /// Clean entries promoted from previous block flushes.
    /// May be evicted when `hot_bytes > max_bytes`.
    hot: HashMap<OutPoint, Utxo>,
    db: Arc<Database>,
    /// Upper bound for the hot cache in bytes.  `None` = unlimited.
    max_bytes: Option<u64>,
    /// Running estimate of bytes used by the hot cache.
    hot_bytes: u64,
}

impl CachedUtxoSet {
    /// Create a new cache backed by `db`.  Pass `None` for unlimited memory.
    pub fn new(db: Arc<Database>, max_bytes: Option<u64>) -> Self {
        Self {
            dirty: HashMap::new(),
            hot: HashMap::new(),
            db,
            max_bytes,
            hot_bytes: 0,
        }
    }

    /// Pre-populate the hot cache by iterating all entries in RocksDB.
    /// Only appropriate when `max_bytes` is `None` (unlimited mode), so that
    /// the node behaves identically to the previous always-in-memory approach.
    pub fn load_all(&mut self) {
        let store = UtxoStore::new(&self.db);
        for (op, stored) in store.iter_all() {
            self.hot.insert(op, stored_to_utxo(&stored));
            self.hot_bytes += BYTES_PER_UTXO;
        }
        debug!(
            "utxo_cache: loaded {} entries ({} MB) from RocksDB",
            self.hot.len(),
            self.hot_bytes / 1_000_000
        );
    }

    /// Apply a connected block to the dirty layer (does NOT write to RocksDB).
    /// Call this immediately after `verify_block` succeeds and before `flush_dirty`.
    pub fn connect_block(&mut self, txids: &[TxId], txs: &[Transaction], height: u32) {
        for (txid, tx) in txids.iter().zip(txs.iter()) {
            let is_coinbase = tx.is_coinbase();
            if !is_coinbase {
                for input in &tx.inputs {
                    // Mark the spent outpoint as deleted.
                    self.dirty.insert(input.previous_output.clone(), None);
                    // Remove from hot to avoid stale reads.
                    if self.hot.remove(&input.previous_output).is_some() {
                        self.hot_bytes = self.hot_bytes.saturating_sub(BYTES_PER_UTXO);
                    }
                }
            }
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint { txid: *txid, vout: vout as u32 };
                self.dirty.insert(
                    outpoint,
                    Some(Utxo {
                        txout: txout.clone(),
                        is_coinbase,
                        height,
                    }),
                );
            }
        }
    }

    /// Like `connect_block` but also returns per-tx undo data (spent UTXOs).
    pub fn connect_block_with_undo(
        &mut self,
        txids: &[TxId],
        txs: &[Transaction],
        height: u32,
    ) -> Vec<Vec<(OutPoint, Utxo)>> {
        let mut undo: Vec<Vec<(OutPoint, Utxo)>> = Vec::with_capacity(txs.len());
        for (txid, tx) in txids.iter().zip(txs.iter()) {
            let mut spent = Vec::new();
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let outpoint = input.previous_output.clone();
                    if let Some(utxo) = self.get_utxo(&outpoint) {
                        spent.push((outpoint.clone(), utxo));
                    }
                    // Mark as spent in dirty and remove stale hot entry.
                    self.dirty.insert(outpoint.clone(), None);
                    if self.hot.remove(&outpoint).is_some() {
                        self.hot_bytes = self.hot_bytes.saturating_sub(BYTES_PER_UTXO);
                    }
                }
            }
            undo.push(spent);
            let is_coinbase = tx.is_coinbase();
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                };
                self.dirty.insert(
                    outpoint,
                    Some(Utxo {
                        txout: txout.clone(),
                        is_coinbase,
                        height,
                    }),
                );
            }
        }
        undo
    }

    /// Undo a connected block (for reorg): remove created outputs, restore spent inputs.
    pub fn disconnect_block(
        &mut self,
        txids: &[TxId],
        txs: &[Transaction],
        undo: Vec<Vec<(OutPoint, Utxo)>>,
    ) {
        for ((txid, tx), spent) in txids.iter().zip(txs.iter()).rev().zip(undo.into_iter().rev()) {
            // Remove outputs created by this transaction.
            for vout in 0..tx.outputs.len() {
                let outpoint = OutPoint { txid: *txid, vout: vout as u32 };
                self.dirty.insert(outpoint.clone(), None);
                if self.hot.remove(&outpoint).is_some() {
                    self.hot_bytes = self.hot_bytes.saturating_sub(BYTES_PER_UTXO);
                }
            }
            // Restore spent outputs.
            for (outpoint, utxo) in spent {
                self.dirty.insert(outpoint, Some(utxo));
            }
        }
    }

    /// Write all dirty entries into `batch` (which the caller will atomically commit)
    /// and promote live entries to the hot cache.  Clears the dirty layer.
    pub fn flush_dirty(
        &mut self,
        batch: &mut WriteBatch,
    ) -> std::result::Result<(), rbtc_storage::StorageError> {
        let store = UtxoStore::new(&self.db);
        let mut to_add: Vec<(OutPoint, StoredUtxo)> = Vec::new();
        let mut to_remove: Vec<OutPoint> = Vec::new();

        for (op, maybe_utxo) in self.dirty.drain() {
            match maybe_utxo {
                Some(utxo) => {
                    if !self.hot.contains_key(&op) {
                        self.hot_bytes += BYTES_PER_UTXO;
                    }
                    self.hot.insert(op.clone(), utxo.clone());
                    to_add.push((op, utxo_to_stored(&utxo)));
                }
                None => {
                    if self.hot.remove(&op).is_some() {
                        self.hot_bytes = self.hot_bytes.saturating_sub(BYTES_PER_UTXO);
                    }
                    to_remove.push(op);
                }
            }
        }

        store.fill_batch(batch, &to_add, &to_remove)?;
        Ok(())
    }

    /// Evict clean (non-dirty) entries from the hot cache until usage is at or
    /// below 80% of `max_bytes`.  No-op when `max_bytes` is `None`.
    pub fn evict_cold(&mut self) {
        let Some(max) = self.max_bytes else { return };
        if self.hot_bytes <= max {
            return;
        }
        let target = (max as f64 * 0.8) as u64;

        // Collect eviction candidates (not in dirty) until budget is met.
        // HashMap iteration order is arbitrary; acceptable for a simple eviction policy.
        let mut to_evict: Vec<OutPoint> = Vec::new();
        let mut freed: u64 = 0;
        for op in self.hot.keys() {
            if self.hot_bytes - freed <= target {
                break;
            }
            if !self.dirty.contains_key(op) {
                to_evict.push(op.clone());
                freed += BYTES_PER_UTXO;
            }
        }

        let evicted = to_evict.len();
        for op in to_evict {
            self.hot.remove(&op);
        }
        self.hot_bytes = self.hot_bytes.saturating_sub(freed);
        if evicted > 0 {
            debug!(
                "utxo_cache: evicted {} entries, hot_bytes={} MB",
                evicted,
                self.hot_bytes / 1_000_000
            );
        }
    }

    /// Number of entries in the hot cache.
    pub fn hot_len(&self) -> usize {
        self.hot.len()
    }

    /// Number of pending dirty entries.
    #[allow(dead_code)]
    pub fn dirty_len(&self) -> usize {
        self.dirty.len()
    }

    /// Estimated memory used by the hot cache in bytes.
    #[allow(dead_code)]
    pub fn estimated_bytes(&self) -> u64 {
        self.hot_bytes
    }
}

impl UtxoLookup for CachedUtxoSet {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        // 1. Dirty layer (includes deletion markers: None means spent).
        if let Some(maybe) = self.dirty.get(outpoint) {
            return maybe.clone();
        }
        // 2. Hot cache (recently flushed / pre-loaded entries).
        if let Some(utxo) = self.hot.get(outpoint) {
            return Some(utxo.clone());
        }
        // 3. RocksDB fallback for cache misses.
        UtxoStore::new(&self.db)
            .get(outpoint)
            .ok()
            .flatten()
            .map(|s| stored_to_utxo(&s))
    }

    fn has_unspent_txid(&self, txid: &TxId) -> bool {
        if self
            .dirty
            .iter()
            .any(|(op, maybe)| &op.txid == txid && maybe.is_some())
        {
            return true;
        }

        for op in self.hot.keys() {
            if &op.txid != txid {
                continue;
            }
            if let Some(maybe) = self.dirty.get(op) {
                if maybe.is_none() {
                    continue;
                }
            }
            return true;
        }

        let rows = self
            .db
            .iter_cf_prefix(rbtc_storage::db::CF_UTXO, &txid.0)
            .unwrap_or_default();
        for (k, _) in rows {
            if k.len() != 36 {
                continue;
            }
            let vout = u32::from_le_bytes([k[32], k[33], k[34], k[35]]);
            let outpoint = OutPoint { txid: *txid, vout };
            if let Some(maybe) = self.dirty.get(&outpoint) {
                if maybe.is_none() {
                    continue;
                }
            }
            return true;
        }
        false
    }
}

// SAFETY: `CachedUtxoSet` contains `HashMap` (not `Sync` by default due to
// `UnsafeCell` in raw table) and `Arc<Database>` (Sync because DB is thread-safe).
// We only call `get_utxo` from Rayon threads during `verify_block`, which holds a
// shared `&CachedUtxoSet` and never mutates it.  All mutations happen sequentially
// in the node event loop before/after parallelism.  Rayon's `par_iter` requires
// the closure to be `Send`; `&CachedUtxoSet` is `Send + Sync` when the fields are.
// `HashMap<K,V>` is `Sync` when K and V are `Send + Sync`.
unsafe impl Sync for CachedUtxoSet {}

// ── Conversion helpers ────────────────────────────────────────────────────────

fn stored_to_utxo(s: &StoredUtxo) -> Utxo {
    Utxo {
        txout: s.to_txout(),
        is_coinbase: s.is_coinbase,
        height: s.height,
    }
}

fn utxo_to_stored(u: &Utxo) -> StoredUtxo {
    StoredUtxo {
        value: u.txout.value,
        script_pubkey: u.txout.script_pubkey.clone(),
        height: u.height,
        is_coinbase: u.is_coinbase,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_consensus::UtxoLookup;
    use rbtc_primitives::{hash::Hash256, script::Script, transaction::{OutPoint, TxOut}};

    fn make_utxo(value: u64) -> Utxo {
        Utxo {
            txout: TxOut { value, script_pubkey: Script::new() },
            is_coinbase: false,
            height: 1,
        }
    }

    fn dummy_outpoint(n: u8) -> OutPoint {
        OutPoint { txid: Hash256([n; 32]), vout: 0 }
    }

    #[test]
    fn dirty_lookup_returns_inserted_utxo() {
        // Build a CachedUtxoSet using a temporary database
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, Some(1_000_000));

        let op = dummy_outpoint(1);
        cache.dirty.insert(op.clone(), Some(make_utxo(1000)));

        let got = cache.get_utxo(&op).unwrap();
        assert_eq!(got.txout.value, 1000);
    }

    #[test]
    fn dirty_deletion_marker_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, Some(1_000_000));

        let op = dummy_outpoint(2);
        // First insert into hot
        cache.hot.insert(op.clone(), make_utxo(5000));
        cache.hot_bytes += BYTES_PER_UTXO;
        // Mark as spent in dirty
        cache.dirty.insert(op.clone(), None);

        assert!(cache.get_utxo(&op).is_none());
    }

    #[test]
    fn evict_cold_stays_under_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let limit = BYTES_PER_UTXO * 10;
        let mut cache = CachedUtxoSet::new(db, Some(limit));

        // Insert 20 entries into hot (double the limit)
        for i in 0u8..20 {
            let op = dummy_outpoint(i);
            cache.hot.insert(op, make_utxo(i as u64 * 100));
            cache.hot_bytes += BYTES_PER_UTXO;
        }
        assert_eq!(cache.hot.len(), 20);

        cache.evict_cold();

        // After eviction we should be at or below 80% of the limit
        assert!(cache.hot_bytes <= (limit as f64 * 0.8) as u64 + BYTES_PER_UTXO);
    }

    #[test]
    fn flush_dirty_promotes_to_hot() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, None);

        let op = dummy_outpoint(3);
        cache.dirty.insert(op.clone(), Some(make_utxo(777)));

        let mut batch = WriteBatch::default();
        cache.flush_dirty(&mut batch).unwrap();

        assert!(cache.dirty.is_empty());
        assert!(cache.hot.contains_key(&op));
        assert_eq!(cache.hot[&op].txout.value, 777);
    }

    #[test]
    fn flush_dirty_evicts_deletions_from_hot() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, None);

        let op = dummy_outpoint(4);
        cache.hot.insert(op.clone(), make_utxo(9999));
        cache.hot_bytes += BYTES_PER_UTXO;
        cache.dirty.insert(op.clone(), None);

        let mut batch = WriteBatch::default();
        cache.flush_dirty(&mut batch).unwrap();

        assert!(!cache.hot.contains_key(&op));
    }

}
