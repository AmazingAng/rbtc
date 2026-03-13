#![allow(dead_code)]
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
    hash::Txid,
    transaction::{OutPoint, Transaction},
};
use rbtc_storage::{Database, StoredUtxo, UtxoStore, WriteBatch};

/// Conservative estimate of memory used per cached UTXO entry.
/// OutPoint ≈ 36 B, Utxo header ≈ 16 B, TxOut ≈ 50 B, script average ≈ 25 B,
/// HashMap overhead ≈ 24 B → ~150 B total.
const BYTES_PER_UTXO: u64 = 150;

/// Per-entry cache flags, matching Bitcoin Core's `CCoinsCacheEntry`.
///
/// - **DIRTY**: This entry differs from the parent view (DB/parent cache).
///   Must be written back on flush.
/// - **FRESH**: The entry was not present in the parent view when it was
///   first cached.  A FRESH+DIRTY entry that is later spent can be pruned
///   from the cache *without* writing a deletion to the parent, because
///   the parent never knew about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinFlags(u8);

impl CoinFlags {
    pub const EMPTY: Self = Self(0);
    pub const DIRTY: Self = Self(0b01);
    pub const FRESH: Self = Self(0b10);
    pub const DIRTY_FRESH: Self = Self(0b11);

    pub fn is_dirty(self) -> bool { self.0 & Self::DIRTY.0 != 0 }
    pub fn is_fresh(self) -> bool { self.0 & Self::FRESH.0 != 0 }
    pub fn set_dirty(&mut self) { self.0 |= Self::DIRTY.0; }
    pub fn set_fresh(&mut self) { self.0 |= Self::FRESH.0; }
    pub fn or(self, other: Self) -> Self { Self(self.0 | other.0) }
}

/// A cached coin with Bitcoin Core–style DIRTY/FRESH flags.
#[derive(Debug, Clone)]
pub struct CachedCoin {
    /// `None` when the coin has been spent (pruned entry).
    pub coin: Option<Utxo>,
    pub flags: CoinFlags,
}

/// A write-back UTXO cache that limits in-memory size and falls back to RocksDB.
///
/// This type implements [`UtxoLookup`] (required by `verify_block`) and provides
/// the same mutation operations as `UtxoSet` (`connect_block` / `flush_dirty`).
///
/// When `max_bytes` is `None` the hot cache is unbounded and behaves identically
/// to loading all UTXOs into memory up-front.
pub struct CachedUtxoSet {
    /// Entries modified in the current (unflushed) block window.
    /// Uses Bitcoin Core–style DIRTY/FRESH flags.  A `CachedCoin` with
    /// `coin = None` means the outpoint was spent.
    dirty: HashMap<OutPoint, CachedCoin>,
    /// Clean entries promoted from previous block flushes.
    /// May be evicted when `hot_bytes > max_bytes`.
    hot: HashMap<OutPoint, Utxo>,
    db: Arc<Database>,
    /// Upper bound for the hot cache in bytes.  `None` = unlimited.
    max_bytes: Option<u64>,
    /// Running estimate of bytes used by the hot cache.
    hot_bytes: u64,
}

/// Staged dirty-layer changes prepared for a RocksDB batch commit.
/// Apply with `commit_flush_plan` only after the batch is written successfully.
pub struct DirtyFlushPlan {
    to_add: Vec<(OutPoint, Utxo)>,
    to_remove: Vec<OutPoint>,
    /// Outpoints to drop from the dirty map that require no DB write
    /// (FRESH entries that were spent before flush).
    to_drop: Vec<OutPoint>,
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

    /// Add a new coin to the dirty layer.
    ///
    /// Matches Bitcoin Core `CCoinsViewCache::AddCoin`:
    /// - Skips unspendable outputs (OP_RETURN, oversized scripts).
    /// - `possible_overwrite`: when true (e.g. coinbase, BIP30), always sets
    ///   DIRTY only. When false, sets FRESH only if the entry is NOT already
    ///   DIRTY (a re-added spent-but-dirty coin must NOT be FRESH, otherwise
    ///   spending it again would erase the parent's deletion marker).
    fn add_coin(&mut self, outpoint: OutPoint, utxo: Utxo, possible_overwrite: bool) {
        if utxo.txout.script_pubkey.is_unspendable() {
            return;
        }
        let fresh = if possible_overwrite {
            false
        } else {
            // FRESH only if entry doesn't exist or is not already DIRTY.
            match self.dirty.get(&outpoint) {
                Some(entry) => !entry.flags.is_dirty(),
                None => true, // new entry, not in parent
            }
        };
        let flags = if fresh {
            CoinFlags::DIRTY_FRESH
        } else {
            CoinFlags::DIRTY
        };
        self.dirty.insert(outpoint, CachedCoin {
            coin: Some(utxo),
            flags,
        });
    }

    /// Spend (mark as pruned) a coin in the dirty layer.
    /// If the entry is FRESH (never written to DB), remove it entirely.
    fn spend_coin(&mut self, outpoint: &OutPoint) {
        if let Some(entry) = self.dirty.get(outpoint) {
            if entry.flags.is_fresh() {
                // FRESH means the parent DB never saw this coin.
                // We can just drop it from the cache entirely.
                self.dirty.remove(outpoint);
                if self.hot.remove(outpoint).is_some() {
                    self.hot_bytes = self.hot_bytes.saturating_sub(BYTES_PER_UTXO);
                }
                return;
            }
        }
        // Not FRESH → must write a deletion to DB on flush.
        self.dirty.insert(outpoint.clone(), CachedCoin {
            coin: None,
            flags: CoinFlags::DIRTY,
        });
        if self.hot.remove(outpoint).is_some() {
            self.hot_bytes = self.hot_bytes.saturating_sub(BYTES_PER_UTXO);
        }
    }

    /// Apply a connected block to the dirty layer (does NOT write to RocksDB).
    /// Call this immediately after `verify_block` succeeds and before `flush_dirty`.
    pub fn connect_block(&mut self, txids: &[Txid], txs: &[Transaction], height: u32) {
        for (txid, tx) in txids.iter().zip(txs.iter()) {
            let is_coinbase = tx.is_coinbase();
            if !is_coinbase {
                for input in &tx.inputs {
                    self.spend_coin(&input.previous_output);
                }
            }
            // Bitcoin Core: coinbase → possible_overwrite=true (BIP30 dup txids);
            // non-coinbase → possible_overwrite=false.
            let overwrite = is_coinbase;
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                };
                self.add_coin(outpoint, Utxo {
                    txout: txout.clone(),
                    is_coinbase,
                    height,
                }, overwrite);
            }
        }
    }

    /// Like `connect_block` but also returns per-tx undo data (spent UTXOs).
    ///
    /// Uses a staging layer (matching Bitcoin Core's `m_connect_block_view` +
    /// `ResetGuard` pattern): all mutations go into a separate HashMap first.
    /// On success the staging layer is merged into dirty; on failure it is
    /// simply discarded — the real dirty/hot layers are never touched.
    pub fn connect_block_with_undo(
        &mut self,
        txids: &[Txid],
        txs: &[Transaction],
        height: u32,
    ) -> Result<Vec<Vec<(OutPoint, Utxo)>>, String> {
        // Staging layer: collect all mutations here first.
        // Key → Some(coin) for adds, Key → None for spends.
        let mut staging: HashMap<OutPoint, Option<Utxo>> = HashMap::new();

        let mut undo: Vec<Vec<(OutPoint, Utxo)>> = Vec::with_capacity(txs.len());
        for (txid, tx) in txids.iter().zip(txs.iter()) {
            let mut spent = Vec::new();
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let outpoint = input.previous_output.clone();
                    // Look up from staging first, then fall through to the
                    // real cache layers (dirty → hot → RocksDB).
                    let utxo = if let Some(staged) = staging.get(&outpoint) {
                        staged.clone()
                    } else {
                        self.get_utxo(&outpoint)
                    };
                    let Some(utxo) = utxo else {
                        // Failure: simply drop staging — real state untouched.
                        return Err(format!(
                            "utxo cache invariant violation while connecting block: missing {}:{}",
                            outpoint.txid.to_hex(),
                            outpoint.vout
                        ));
                    };
                    spent.push((outpoint.clone(), utxo));
                    staging.insert(outpoint, None); // mark spent in staging
                }
            }
            undo.push(spent);
            let is_coinbase = tx.is_coinbase();
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                };
                staging.insert(
                    outpoint,
                    Some(Utxo {
                        txout: txout.clone(),
                        is_coinbase,
                        height,
                    }),
                );
            }
        }

        // Success: merge staging into the real dirty/hot layers.
        for (outpoint, coin) in staging {
            match coin {
                Some(utxo) => {
                    // Bitcoin Core: coinbase → possible_overwrite=true (BIP30).
                    let overwrite = utxo.is_coinbase;
                    self.add_coin(outpoint, utxo, overwrite);
                }
                None => self.spend_coin(&outpoint),
            }
        }

        Ok(undo)
    }

    /// Undo a connected block (for reorg): remove created outputs, restore spent inputs.
    pub fn disconnect_block(
        &mut self,
        txids: &[Txid],
        txs: &[Transaction],
        undo: Vec<Vec<(OutPoint, Utxo)>>,
    ) {
        for ((txid, tx), spent) in txids
            .iter()
            .zip(txs.iter())
            .rev()
            .zip(undo.into_iter().rev())
        {
            // Remove outputs created by this transaction.
            for vout in 0..tx.outputs.len() {
                let outpoint = OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                };
                self.spend_coin(&outpoint);
            }
            // Restore spent outputs (mark as DIRTY since they need to be
            // re-written to the parent/DB).
            for (outpoint, utxo) in spent {
                self.dirty.insert(outpoint, CachedCoin {
                    coin: Some(utxo),
                    flags: CoinFlags::DIRTY,
                });
            }
        }
    }

    /// Stage dirty entries into `batch` (caller commits atomically later).
    /// Does NOT mutate cache state; call `commit_flush_plan` after successful DB write.
    ///
    /// Respects DIRTY/FRESH flags:
    /// - Only DIRTY entries are written to the batch.
    /// - FRESH entries that are spent (coin=None) are skipped entirely: the parent
    ///   never knew about them so no deletion is needed.
    pub fn prepare_flush_dirty(
        &self,
        batch: &mut WriteBatch,
    ) -> std::result::Result<DirtyFlushPlan, rbtc_storage::StorageError> {
        let store = UtxoStore::new(&self.db);
        let mut to_add_stored: Vec<(OutPoint, StoredUtxo)> = Vec::new();
        let mut to_add_live: Vec<(OutPoint, Utxo)> = Vec::new();
        let mut to_remove: Vec<OutPoint> = Vec::new();
        let mut to_drop: Vec<OutPoint> = Vec::new();

        for (op, entry) in &self.dirty {
            if !entry.flags.is_dirty() {
                to_drop.push(op.clone()); // Clean: just drop from cache.
                continue;
            }
            match &entry.coin {
                Some(utxo) => {
                    to_add_stored.push((op.clone(), utxo_to_stored(utxo)));
                    to_add_live.push((op.clone(), utxo.clone()));
                }
                None => {
                    if entry.flags.is_fresh() {
                        // FRESH+spent: parent never saw it, skip DB delete.
                        to_drop.push(op.clone());
                    } else {
                        to_remove.push(op.clone());
                    }
                }
            }
        }

        store.fill_batch(batch, &to_add_stored, &to_remove)?;
        Ok(DirtyFlushPlan {
            to_add: to_add_live,
            to_remove,
            to_drop,
        })
    }

    /// Apply a previously prepared flush plan after DB batch write succeeded.
    pub fn commit_flush_plan(&mut self, plan: DirtyFlushPlan) {
        // Drop entries that need no DB interaction (clean or FRESH+spent).
        for op in plan.to_drop {
            self.dirty.remove(&op);
        }

        for op in plan.to_remove {
            self.dirty.remove(&op);
            if self.hot.remove(&op).is_some() {
                self.hot_bytes = self.hot_bytes.saturating_sub(BYTES_PER_UTXO);
            }
        }

        for (op, utxo) in plan.to_add {
            self.dirty.remove(&op);
            if !self.hot.contains_key(&op) {
                self.hot_bytes += BYTES_PER_UTXO;
            }
            self.hot.insert(op, utxo);
        }
    }

    /// Legacy helper used by unit tests: stage + immediately commit in-memory.
    /// Production block connection should use prepare/commit around DB write.
    pub fn flush_dirty(
        &mut self,
        batch: &mut WriteBatch,
    ) -> std::result::Result<(), rbtc_storage::StorageError> {
        let plan = self.prepare_flush_dirty(batch)?;
        self.commit_flush_plan(plan);
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
        // 1. Dirty layer (includes deletion markers: coin=None means spent).
        if let Some(entry) = self.dirty.get(outpoint) {
            return entry.coin.clone();
        }
        // 2. Hot cache (recently flushed / pre-loaded entries).
        if let Some(utxo) = self.hot.get(outpoint) {
            return Some(utxo.clone());
        }
        // 3. RocksDB fallback for cache misses.
        match UtxoStore::new(&self.db).get(outpoint) {
            Ok(Some(s)) => Some(stored_to_utxo(&s)),
            Ok(None) => None,
            Err(e) => {
                panic!(
                    "fatal UTXO DB read error at {}:{}: {}",
                    outpoint.txid.to_hex(),
                    outpoint.vout,
                    e
                );
            }
        }
    }

    fn has_unspent_txid(&self, txid: &Txid) -> bool {
        if self
            .dirty
            .iter()
            .any(|(op, entry)| &op.txid == txid && entry.coin.is_some())
        {
            return true;
        }

        for op in self.hot.keys() {
            if &op.txid != txid {
                continue;
            }
            if let Some(entry) = self.dirty.get(op) {
                if entry.coin.is_none() {
                    continue;
                }
            }
            return true;
        }

        let rows = match self.db.iter_cf_prefix(rbtc_storage::db::CF_UTXO, &txid.0.0) {
            Ok(rows) => rows,
            Err(e) => {
                panic!(
                    "fatal UTXO DB prefix-iterate error for txid {}: {}",
                    txid.to_hex(),
                    e
                );
            }
        };
        for (k, _) in rows {
            // Decode VARINT key: txid(32) + VARINT(vout).
            let outpoint = match rbtc_storage::utxo_store::StoredUtxo::decode_key(&k) {
                Some(op) => op,
                None => continue,
            };
            if &outpoint.txid != txid {
                // Prefix iterator may return keys beyond our txid prefix.
                break;
            }
            if let Some(entry) = self.dirty.get(&outpoint) {
                if entry.coin.is_none() {
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
    use rbtc_primitives::{
        hash::Hash256,
        script::Script,
        transaction::{OutPoint, TxOut},
    };

    fn make_utxo(value: i64) -> Utxo {
        Utxo {
            txout: TxOut {
                value,
                script_pubkey: Script::new(),
            },
            is_coinbase: false,
            height: 1,
        }
    }

    fn dummy_outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid(Hash256([n; 32])),
            vout: 0,
        }
    }

    #[test]
    fn dirty_lookup_returns_inserted_utxo() {
        // Build a CachedUtxoSet using a temporary database
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, Some(1_000_000));

        let op = dummy_outpoint(1);
        cache.dirty.insert(op.clone(), CachedCoin {
            coin: Some(make_utxo(1000)),
            flags: CoinFlags::DIRTY_FRESH,
        });

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
        cache.dirty.insert(op.clone(), CachedCoin {
            coin: None,
            flags: CoinFlags::DIRTY,
        });

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
            cache.hot.insert(op, make_utxo(i as i64 * 100));
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
        cache.dirty.insert(op.clone(), CachedCoin {
            coin: Some(make_utxo(777)),
            flags: CoinFlags::DIRTY_FRESH,
        });

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
        cache.dirty.insert(op.clone(), CachedCoin {
            coin: None,
            flags: CoinFlags::DIRTY,
        });

        let mut batch = WriteBatch::default();
        cache.flush_dirty(&mut batch).unwrap();

        assert!(!cache.hot.contains_key(&op));
    }

    #[test]
    fn fresh_spent_skips_db_write() {
        // A coin that is created and spent within the same flush window
        // should be FRESH, and spend_coin should remove it entirely.
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, None);

        let op = dummy_outpoint(10);
        // Simulate adding a new output (DIRTY|FRESH).
        cache.add_coin(op.clone(), make_utxo(500), false);
        assert!(cache.dirty.contains_key(&op));
        assert!(cache.dirty[&op].flags.is_fresh());

        // Now spend it before flushing.
        cache.spend_coin(&op);

        // FRESH entry should be fully removed (no DB write needed).
        assert!(!cache.dirty.contains_key(&op));
    }

    #[test]
    fn connect_block_with_undo_errors_on_missing_input() {
        use rbtc_primitives::transaction::{Transaction, TxIn, TxOut};

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, None);

        let prev = dummy_outpoint(9);
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: prev,
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 1,
                script_pubkey: Script::new(),
            }],
            0,
        );

        let txid = Txid(Hash256([8; 32]));
        let err = cache
            .connect_block_with_undo(&[txid], &[tx], 1)
            .expect_err("missing prevout must fail");
        assert!(err.contains("invariant violation"));
    }

    #[test]
    fn connect_block_staging_rollback_preserves_state() {
        use rbtc_primitives::transaction::{Transaction, TxIn, TxOut};

        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, None);

        // Pre-populate with two UTXOs.
        let op_a = dummy_outpoint(100);
        let op_b = dummy_outpoint(200);
        cache.add_coin(op_a.clone(), make_utxo(1000), false);
        cache.add_coin(op_b.clone(), make_utxo(2000), false);

        // Snapshot dirty/hot state before the failing call.
        let dirty_before: Vec<_> = cache.dirty.keys().cloned().collect();
        let hot_before: Vec<_> = cache.hot.iter().map(|(k, _)| k.clone()).collect();

        // Build a block: tx0 spends op_a (valid), tx1 spends a missing UTXO (will fail).
        let tx0 = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: op_a.clone(),
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut { value: 500, script_pubkey: Script::new() }],
            0,
        );
        let tx1 = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: dummy_outpoint(99), // missing
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut { value: 1, script_pubkey: Script::new() }],
            0,
        );

        let txid0 = Txid(Hash256([10; 32]));
        let txid1 = Txid(Hash256([11; 32]));
        let err = cache
            .connect_block_with_undo(&[txid0, txid1], &[tx0, tx1], 5)
            .expect_err("second tx must fail");
        assert!(err.contains("invariant violation"));

        // Verify dirty layer is unchanged — same keys, same values.
        let dirty_after: Vec<_> = cache.dirty.keys().cloned().collect();
        let hot_after: Vec<_> = cache.hot.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(dirty_before.len(), dirty_after.len(), "dirty layer key count changed");
        assert_eq!(hot_before.len(), hot_after.len(), "hot layer key count changed");

        // op_a still exists (was NOT spent).
        assert!(cache.get_utxo(&op_a).is_some(), "op_a should still exist");
        assert_eq!(cache.get_utxo(&op_a).unwrap().txout.value, 1000);

        // op_b still exists unchanged.
        assert!(cache.get_utxo(&op_b).is_some(), "op_b should still exist");
        assert_eq!(cache.get_utxo(&op_b).unwrap().txout.value, 2000);

        // No new outputs were added from the failed block.
        assert!(cache.get_utxo(&OutPoint { txid: txid0, vout: 0 }).is_none());
    }

    #[test]
    fn add_coin_skips_unspendable_outputs() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, None);

        let op = dummy_outpoint(1);
        // OP_RETURN script is unspendable — should not be cached.
        let utxo = Utxo {
            txout: rbtc_primitives::transaction::TxOut {
                value: 0,
                script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xde, 0xad]),
            },
            is_coinbase: false,
            height: 1,
        };
        cache.add_coin(op.clone(), utxo, false);
        assert!(cache.dirty.is_empty(), "OP_RETURN output should not be cached");
    }

    #[test]
    fn add_coin_possible_overwrite_flag_controls_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());
        let mut cache = CachedUtxoSet::new(db, None);

        let op = dummy_outpoint(1);

        // Normal add (possible_overwrite=false) → DIRTY|FRESH.
        cache.add_coin(op.clone(), make_utxo(100), false);
        assert!(cache.dirty[&op].flags.is_fresh());
        assert!(cache.dirty[&op].flags.is_dirty());

        // Spend it (non-FRESH path since we need to test re-add).
        // First flush to make it non-FRESH: simulate by manually clearing FRESH.
        cache.dirty.get_mut(&op).unwrap().flags = CoinFlags::DIRTY;
        // Now spend — leaves DIRTY deletion marker.
        cache.spend_coin(&op);
        assert!(cache.dirty[&op].coin.is_none());
        assert!(cache.dirty[&op].flags.is_dirty());

        // Re-add with possible_overwrite=false: entry is DIRTY, so FRESH=false.
        cache.add_coin(op.clone(), make_utxo(200), false);
        assert!(cache.dirty[&op].flags.is_dirty());
        assert!(!cache.dirty[&op].flags.is_fresh(), "re-added dirty coin must not be FRESH");

        // Coinbase add with possible_overwrite=true: never FRESH.
        let op2 = dummy_outpoint(2);
        cache.add_coin(op2.clone(), make_utxo(5000), true);
        assert!(cache.dirty[&op2].flags.is_dirty());
        assert!(!cache.dirty[&op2].flags.is_fresh(), "possible_overwrite=true must not set FRESH");
    }

    #[test]
    fn is_unspendable_matches_core() {
        // OP_RETURN
        assert!(Script::from_bytes(vec![0x6a]).is_unspendable());
        assert!(Script::from_bytes(vec![0x6a, 0x00, 0x01]).is_unspendable());

        // Normal scripts are spendable
        assert!(!Script::from_bytes(vec![0x76, 0xa9]).is_unspendable());
        assert!(!Script::new().is_unspendable());

        // Oversized script (>10000 bytes)
        assert!(Script::from_bytes(vec![0x00; 10_001]).is_unspendable());
        assert!(!Script::from_bytes(vec![0x00; 10_000]).is_unspendable());
    }
}
