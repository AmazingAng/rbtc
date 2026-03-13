use std::collections::{HashMap, HashSet};

use rbtc_primitives::{
    codec::{Decodable, Encodable, VarInt},
    constants::MAX_SCRIPT_SIZE,
    hash::{Hash256, Txid},
    script::Script,
    transaction::{OutPoint, TxOut},
};
use rocksdb::WriteBatch;

use crate::{
    compress::{
        compress_amount, compress_script_parts, decompress_amount, decompress_script_parts,
        read_varint, read_varint_from, special_script_size, write_varint, write_varint_to,
    },
    db::{Database, CF_UTXO},
    error::{Result, StorageError},
};

/// Bitcoin Core's DB_COIN key prefix byte (0x43 = 'C').
///
/// In Bitcoin Core, all UTXO keys in the coins DB are prefixed with this byte
/// to distinguish them from other entries (e.g. DB_HEAD_BLOCKS, DB_BEST_BLOCK).
/// In rbtc, UTXOs live in a dedicated column family (`CF_UTXO`), so the prefix
/// byte is not required for key separation.  This constant is kept for
/// documentation and cross-reference purposes only.
///
/// N/A due to CF separation — rbtc uses `CF_UTXO` column family instead of
/// a key-prefix scheme.
pub const DB_COIN: u8 = b'C';

/// A UTXO entry as stored on disk
#[derive(Debug, Clone)]
pub struct StoredUtxo {
    pub value: i64,
    pub script_pubkey: Script,
    pub height: u32,
    pub is_coinbase: bool,
}

impl StoredUtxo {
    pub fn to_txout(&self) -> TxOut {
        TxOut {
            value: self.value,
            script_pubkey: self.script_pubkey.clone(),
        }
    }

    /// Returns `true` if the output is provably unspendable and should NOT be
    /// stored in the UTXO set.  Matches Bitcoin Core's `CScript::IsUnspendable`:
    ///   - starts with OP_RETURN (0x6a), OR
    ///   - script size exceeds MAX_SCRIPT_SIZE (10,000 bytes).
    pub fn is_unspendable(&self) -> bool {
        self.script_pubkey.is_op_return()
            || self.script_pubkey.as_bytes().len() > MAX_SCRIPT_SIZE
    }

    /// Encode UTXO key: `txid(32) + VARINT(vout)`.
    ///
    /// Matches Bitcoin Core's `CoinEntry` serialization (`VARINT(outpoint->n)`).
    /// Old rbtc databases used fixed 4-byte LE vout — detect via `needs_key_upgrade()`
    /// and run `--reindex-chainstate` to migrate.
    pub(crate) fn encode_key(outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(33); // 32 + 1 byte varint for small vout
        key.extend_from_slice(&outpoint.txid.0 .0);
        write_varint(&mut key, outpoint.vout as u64);
        key
    }

    /// Decode UTXO key: `txid(32) + VARINT(vout)`.
    pub fn decode_key(key: &[u8]) -> Option<OutPoint> {
        if key.len() < 33 {
            return None; // 32 txid + at least 1 varint byte
        }
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&key[..32]);
        let (vout, _) = read_varint(&key[32..]);
        Some(OutPoint {
            txid: Txid(Hash256(txid_bytes)),
            vout: vout as u32,
        })
    }

    /// Encode matching Bitcoin Core's `Coin::Serialize`:
    ///   `VARINT(height * 2 + coinbase) + VARINT(compressed_amount) +
    ///    VARINT(script_type) + script_payload`
    ///
    /// All VARINTs use Bitcoin Core's base-128 encoding (not compact-size).
    pub fn encode_value(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Code = height * 2 + coinbase (Bitcoin Core `Coin::Serialize`)
        let code = (self.height as u64) * 2 + (self.is_coinbase as u64);
        write_varint_to(&mut buf, code).ok();
        // Compressed amount (Bitcoin Core `AmountCompression`)
        let compressed_val = compress_amount(self.value as u64);
        write_varint_to(&mut buf, compressed_val).ok();
        // Compressed script (Bitcoin Core `ScriptCompression`)
        let (script_type, payload) = compress_script_parts(self.script_pubkey.as_bytes());
        write_varint_to(&mut buf, script_type).ok();
        buf.extend_from_slice(&payload);
        buf
    }

    /// Decode matching Bitcoin Core's `Coin::Unserialize`.
    pub fn decode_value(bytes: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(bytes);
        // Code = height * 2 + coinbase
        let code = read_varint_from(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let height = (code >> 1) as u32;
        let is_coinbase = (code & 1) != 0;
        // Compressed amount
        let compressed_val = read_varint_from(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let value = decompress_amount(compressed_val) as i64;
        // Compressed script: read type, then determine payload size
        let script_type = read_varint_from(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let payload_len = if script_type < 6 {
            special_script_size(script_type)
        } else {
            (script_type - 6) as usize
        };
        let mut payload = vec![0u8; payload_len];
        use std::io::Read;
        cur.read_exact(&mut payload)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let script_bytes = decompress_script_parts(script_type, &payload);
        let script_pubkey = Script::from_bytes(script_bytes);
        Ok(Self {
            value,
            script_pubkey,
            height,
            is_coinbase,
        })
    }
}

/// Pluggable backend abstraction matching Bitcoin Core's `CCoinsView`.
///
/// This trait enables testing with mock backends and composing layered
/// views (e.g. cache on top of persistent storage).
pub trait CoinsView {
    /// Retrieve a UTXO by outpoint.
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<StoredUtxo>>;

    /// Check whether a UTXO exists without deserializing the full value.
    fn have_coin(&self, outpoint: &OutPoint) -> Result<bool> {
        Ok(self.get_coin(outpoint)?.is_some())
    }
}

/// Persistent UTXO set backed by RocksDB
pub struct UtxoStore<'db> {
    db: &'db Database,
}

impl<'db> UtxoStore<'db> {
    pub fn new(db: &'db Database) -> Self {
        Self { db }
    }

    /// Detect old-format (4-byte LE vout) UTXO keys in the database.
    ///
    /// Mirrors Bitcoin Core's `CCoinsViewDB::NeedsUpgrade()` which checks for
    /// the deprecated `DB_COINS` prefix. Here we detect legacy 36-byte keys
    /// (32 txid + 4 vout LE) that predate the VARINT migration.
    ///
    /// Returns `true` if old keys are found and `--reindex-chainstate` is needed.
    pub fn needs_key_upgrade(&self) -> bool {
        let iter = match self.db.iter_cf(CF_UTXO) {
            Ok(i) => i,
            Err(_) => return false,
        };
        for (k, _) in iter.into_iter().take(1) {
            // VARINT keys are 33 bytes for vout < 128 (the vast majority).
            // Legacy keys are always exactly 36 bytes (32 txid + 4 LE).
            // A 36-byte key could be VARINT with a very large vout (>= 2^28),
            // but that's astronomically unlikely. The definitive check: if the
            // first entry is 36 bytes and bytes [32..36] decode as a valid
            // small LE u32, it's legacy format.
            if k.len() == 36 {
                let vout = u32::from_le_bytes([k[32], k[33], k[34], k[35]]);
                // Legacy keys have small vouts. VARINT 4-byte keys would need
                // vout >= 2^21 (~2M), which doesn't exist on-chain.
                if vout < 100_000 {
                    return true;
                }
            }
        }
        false
    }

    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<StoredUtxo>> {
        self.get_coin(outpoint)
    }

    pub fn contains(&self, outpoint: &OutPoint) -> Result<bool> {
        self.have_coin(outpoint)
    }

    pub fn put(&self, outpoint: &OutPoint, utxo: &StoredUtxo) -> Result<()> {
        let key = StoredUtxo::encode_key(outpoint);
        self.db.put_cf(CF_UTXO, &key, &utxo.encode_value())
    }

    pub fn delete(&self, outpoint: &OutPoint) -> Result<()> {
        let key = StoredUtxo::encode_key(outpoint);
        self.db.delete_cf(CF_UTXO, &key)
    }

    /// Atomically apply a batch of UTXO changes (connect block)
    pub fn apply_batch(
        &self,
        to_add: &[(OutPoint, StoredUtxo)],
        to_remove: &[OutPoint],
    ) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.fill_batch(&mut batch, to_add, to_remove)?;
        self.db.write_batch(batch)
    }

    /// Fill an externally-owned `WriteBatch` with UTXO deletes and puts.
    /// Callers can then add further CF writes (e.g. tx_index, addr_index) and
    /// commit the whole batch in one atomic RocksDB write.
    pub fn fill_batch(
        &self,
        batch: &mut WriteBatch,
        to_add: &[(OutPoint, StoredUtxo)],
        to_remove: &[OutPoint],
    ) -> Result<()> {
        for outpoint in to_remove {
            let key = StoredUtxo::encode_key(outpoint);
            self.db.batch_delete_cf(batch, CF_UTXO, &key)?;
        }
        for (outpoint, utxo) in to_add {
            let key = StoredUtxo::encode_key(outpoint);
            self.db
                .batch_put_cf(batch, CF_UTXO, &key, &utxo.encode_value())?;
        }
        Ok(())
    }

    /// Process a connected block: spend inputs, add outputs (self-contained batch).
    pub fn connect_block(
        &self,
        txids: &[Txid],
        txs: &[rbtc_primitives::transaction::Transaction],
        height: u32,
    ) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.connect_block_into_batch(&mut batch, txids, txs, height)?;
        self.db.write_batch(batch)
    }

    /// Like `connect_block` but fills an externally-owned `WriteBatch` so the
    /// caller can combine UTXO writes with tx_index / addr_index writes and
    /// commit everything atomically.
    pub fn connect_block_into_batch(
        &self,
        batch: &mut WriteBatch,
        txids: &[Txid],
        txs: &[rbtc_primitives::transaction::Transaction],
        height: u32,
    ) -> Result<()> {
        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();

        for (txid, tx) in txids.iter().zip(txs.iter()) {
            let is_coinbase = tx.is_coinbase();

            if !is_coinbase {
                for input in &tx.inputs {
                    to_remove.push(input.previous_output.clone());
                }
            }

            for (vout, txout) in tx.outputs.iter().enumerate() {
                let utxo = StoredUtxo {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey.clone(),
                    height,
                    is_coinbase,
                };
                // Skip provably unspendable outputs (OP_RETURN, oversized scripts).
                // Matches Bitcoin Core's CCoinsViewCache::AddCoin:
                //   `if (coin.out.scriptPubKey.IsUnspendable()) return;`
                if utxo.is_unspendable() {
                    continue;
                }
                let outpoint = OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                };
                to_add.push((outpoint, utxo));
            }
        }

        self.fill_batch(batch, &to_add, &to_remove)
    }

    /// Iterate all stored UTXOs (used to reload the in-memory UTXO set on startup).
    pub fn iter_all(&self) -> Vec<(OutPoint, StoredUtxo)> {
        match self.db.iter_cf(CF_UTXO) {
            Ok(iter) => iter
                .into_iter()
                .filter_map(|(k, v)| {
                    let outpoint = StoredUtxo::decode_key(&k)?;
                    let utxo = StoredUtxo::decode_value(&v).ok()?;
                    Some((outpoint, utxo))
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Process a disconnected block (reorg undo)
    pub fn disconnect_block(
        &self,
        txids: &[Txid],
        txs: &[rbtc_primitives::transaction::Transaction],
        undo_data: &[(OutPoint, StoredUtxo)],
    ) -> Result<()> {
        let mut to_remove = Vec::new();
        let to_add = undo_data.to_vec();

        for (txid, tx) in txids.iter().zip(txs.iter()).rev() {
            for vout in 0..tx.outputs.len() {
                to_remove.push(OutPoint {
                    txid: *txid,
                    vout: vout as u32,
                });
            }
        }

        self.apply_batch(&to_add, &to_remove)
    }

    /// Compute aggregate statistics over the entire UTXO set.
    ///
    /// Iterates every entry in `CF_UTXO`, decoding each `StoredUtxo` to
    /// accumulate the total count, sum of values, and serialized byte size.
    /// This matches Bitcoin Core's `gettxoutsetinfo` RPC.
    pub fn get_utxo_stats(&self) -> Result<UtxoStats> {
        let entries = self.db.iter_cf(CF_UTXO)?;
        let mut stats = UtxoStats {
            num_utxos: 0,
            total_amount: 0,
            serialized_size: 0,
        };
        for (k, v) in &entries {
            if k.len() < 33 {
                continue; // 32 txid + at least 1 varint byte
            }
            stats.serialized_size += (k.len() + v.len()) as u64;
            if let Ok(utxo) = StoredUtxo::decode_value(v) {
                stats.num_utxos += 1;
                stats.total_amount += utxo.value as u64;
            }
        }
        Ok(stats)
    }
}

impl<'db> CoinsView for UtxoStore<'db> {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<StoredUtxo>> {
        let key = StoredUtxo::encode_key(outpoint);
        match self.db.get_cf(CF_UTXO, &key)? {
            Some(bytes) => Ok(Some(StoredUtxo::decode_value(&bytes)?)),
            None => Ok(None),
        }
    }

    fn have_coin(&self, outpoint: &OutPoint) -> Result<bool> {
        let key = StoredUtxo::encode_key(outpoint);
        Ok(self.db.get_cf(CF_UTXO, &key)?.is_some())
    }
}

/// Aggregate statistics over the UTXO set, matching Bitcoin Core's
/// `gettxoutsetinfo` RPC output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoStats {
    /// Total number of unspent transaction outputs.
    pub num_utxos: u64,
    /// Sum of all UTXO values in satoshis.
    pub total_amount: u64,
    /// Total serialized size (key + value bytes) across all entries.
    pub serialized_size: u64,
}

/// In-memory UTXO cache wrapping a persistent [`UtxoStore`], matching Bitcoin
/// Core's `CCoinsViewCache` pattern.
///
/// Reads check the in-memory `cache` first; on miss they fall through to the
/// underlying DB store.  Writes go only to the cache and are marked *dirty*.
/// [`flush`](Self::flush) atomically writes all dirty entries to the DB via a
/// `WriteBatch`.
///
/// A `None` value in the cache represents a *known-missing* (spent/deleted)
/// outpoint, avoiding repeated DB lookups.
pub struct UtxoCache<'db> {
    store: UtxoStore<'db>,
    /// `None` = known-missing (spent/deleted).
    cache: HashMap<(Txid, u32), Option<StoredUtxo>>,
    /// Entries modified since the last flush.
    dirty: HashSet<(Txid, u32)>,
    /// Entries that were created in this cache layer and do NOT exist in the
    /// parent (persistent DB).  Matches Bitcoin Core's `CCoinsCacheEntry::FRESH`
    /// flag.
    ///
    /// **Optimization**: when a FRESH entry is spent before the cache is
    /// flushed, we can simply erase it from the cache without writing a
    /// delete to the DB, because the DB never knew about it.
    fresh: HashSet<(Txid, u32)>,
}

impl<'db> UtxoCache<'db> {
    /// Create a new empty cache backed by the given `UtxoStore`.
    pub fn new(store: UtxoStore<'db>) -> Self {
        Self {
            store,
            cache: HashMap::new(),
            dirty: HashSet::new(),
            fresh: HashSet::new(),
        }
    }

    /// Look up a UTXO.  Returns from the in-memory cache if present; otherwise
    /// falls through to the database.  A cache miss from the DB is *not*
    /// cached (callers should use [`put`] or [`remove`] to populate it).
    pub fn get(&mut self, outpoint: &OutPoint) -> Result<Option<StoredUtxo>> {
        let key = (outpoint.txid, outpoint.vout);
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached.clone());
        }
        // Cache miss — read from DB
        let result = self.store.get(outpoint)?;
        // Cache the DB result so subsequent reads are fast
        self.cache.insert(key, result.clone());
        Ok(result)
    }

    /// Insert or update a UTXO in the cache and mark it dirty.
    ///
    /// If the entry does not already exist in the cache (i.e. it was never
    /// fetched from the DB), it is also marked FRESH.  A FRESH coin that is
    /// later spent can be erased without writing a delete to the DB.
    ///
    /// Matches Bitcoin Core's `CCoinsViewCache::AddCoin` FRESH logic:
    /// a coin is marked FRESH unless it exists in this cache as a spent+dirty
    /// entry (which means its spentness hasn't been flushed to the parent yet).
    pub fn put(&mut self, outpoint: &OutPoint, utxo: StoredUtxo) {
        let key = (outpoint.txid, outpoint.vout);
        // Determine FRESH eligibility before inserting.
        // If the key doesn't exist in the cache yet, or it exists but is NOT
        // dirty, we can mark it FRESH.  If it's a spent+dirty entry, we must
        // NOT mark it FRESH (Bitcoin Core coins.cpp lines 100-113).
        let is_dirty = self.dirty.contains(&key);
        let was_absent = !self.cache.contains_key(&key);
        self.cache.insert(key, Some(utxo));
        self.dirty.insert(key);
        if was_absent || !is_dirty {
            self.fresh.insert(key);
        }
    }

    /// Mark a UTXO as spent (known-missing) in the cache.
    ///
    /// If the entry is FRESH (never existed in the parent DB), we can erase
    /// it entirely from the cache — no need to write a delete on flush.
    /// This matches Bitcoin Core's FRESH+spent optimization.
    pub fn remove(&mut self, outpoint: &OutPoint) {
        let key = (outpoint.txid, outpoint.vout);
        if self.fresh.remove(&key) {
            // FRESH+spent: the DB never knew about this coin, so we can just
            // drop it from the cache entirely.
            self.cache.remove(&key);
            self.dirty.remove(&key);
        } else {
            // Not FRESH: the DB has (or may have) this coin, so we must
            // record the deletion.
            self.cache.insert(key, None);
            self.dirty.insert(key);
        }
    }

    /// Flush all dirty entries to the database via an atomic `WriteBatch`.
    ///
    /// After a successful flush the dirty set is cleared but the cache
    /// entries remain (they are still valid reads).
    pub fn flush(&mut self) -> Result<()> {
        if self.dirty.is_empty() {
            return Ok(());
        }
        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();
        for &(txid, vout) in &self.dirty {
            let outpoint = OutPoint { txid, vout };
            match self.cache.get(&(txid, vout)) {
                Some(Some(utxo)) => to_add.push((outpoint, utxo.clone())),
                Some(None) => to_remove.push(outpoint),
                None => {} // shouldn't happen
            }
        }
        self.store.apply_batch(&to_add, &to_remove)?;
        self.dirty.clear();
        self.fresh.clear();
        Ok(())
    }

    /// Drop all cached entries and the dirty set.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.dirty.clear();
        self.fresh.clear();
    }

    /// Number of entries currently held in the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Number of dirty (unflushed) entries.
    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    /// Number of FRESH entries (created in this cache, not yet in the DB).
    pub fn fresh_count(&self) -> usize {
        self.fresh.len()
    }

    /// Access the underlying store (e.g. for `iter_all`).
    pub fn store(&self) -> &UtxoStore<'db> {
        &self.store
    }
}

impl<'db> CoinsView for UtxoCache<'db> {
    /// Read-only coin lookup: checks in-memory cache first, then falls
    /// through to the persistent store.  Unlike [`UtxoCache::get`], this
    /// does NOT populate the cache on a miss (because `&self` is immutable).
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<StoredUtxo>> {
        let key = (outpoint.txid, outpoint.vout);
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached.clone());
        }
        self.store.get_coin(outpoint)
    }

    fn have_coin(&self, outpoint: &OutPoint) -> Result<bool> {
        let key = (outpoint.txid, outpoint.vout);
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached.is_some());
        }
        self.store.have_coin(outpoint)
    }
}

/// Legacy undo data format version (stores redundant txid+vout per spent coin).
const UNDO_DATA_VERSION_V1: u8 = 0x01;

/// Current undo data format version.
///
/// v2 omits the OutPoint (txid+vout) for each spent coin, matching Bitcoin
/// Core's CTxUndo design.  The outpoints are redundant because they can be
/// reconstructed from the block's transactions: for each non-coinbase tx `i`,
/// input `j` already carries its `previous_output`.  This saves 36 bytes per
/// spent input.
///
/// NOTE: This version marker is an rbtc-specific framing byte — Bitcoin Core
/// does not use a version byte in its undo data.  See `encode_block_undo`
/// doc-comment for the full format divergence table.
const UNDO_DATA_VERSION: u8 = 0x02;

/// Checksum length in bytes (first 4 bytes of SHA256d).
const UNDO_CHECKSUM_LEN: usize = 4;

/// Encode per-block undo data (list of per-tx spent UTXOs) into bytes.
///
/// # Format divergence from Bitcoin Core
///
/// rbtc's undo format is NOT byte-compatible with Bitcoin Core's `rev*.dat`
/// files.  The differences are:
///
/// | Aspect              | Bitcoin Core (`CBlockUndo`)           | rbtc                                   |
/// |---------------------|---------------------------------------|----------------------------------------|
/// | Container           | Raw serialized `vector<CTxUndo>`      | `version(1) \| payload \| checksum(4)` |
/// | Coin header         | `VARINT(height*2+cb)` + dummy version| `VARINT(height*2+cb)` (no dummy)       |
/// | Coin body           | `TxOutCompression` (bare)             | Same encoding, length-prefixed         |
/// | Integrity check     | Hash stored in block index            | Inline 4-byte SHA256d checksum         |
/// | Version marker      | None (implicit)                       | Leading byte (`0x02`)                  |
///
/// The key semantic difference is that Bitcoin Core's `TxInUndoFormatter`
/// writes a dummy `VARINT(0)` version field after the code when `height > 0`
/// (for backward compatibility with pre-0.15 undo data).  rbtc omits this
/// dummy field because it reuses the same `StoredUtxo::encode_value` for both
/// DB coins and undo data.
///
/// Making the formats byte-identical would require a separate undo-specific
/// serializer with the dummy version field, plus removing the version byte
/// and inline checksum.  This is deferred as a LOW priority item — the
/// current format is self-consistent and checksummed.
///
/// # Current format
///
/// Format v2 (current): version(1) | payload | checksum(4)
///   payload = varint(num_txs) | for each tx: varint(num_spent) | coin_value*
///   coin_value = varint(val_len) | encoded_coin_bytes
///   checksum = first 4 bytes of SHA256d(version + payload)
///
/// OutPoints are NOT stored — they are reconstructed from the block's
/// transactions at decode time, matching Bitcoin Core's CTxUndo design.
pub fn encode_block_undo(undo: &[Vec<(OutPoint, StoredUtxo)>]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Version byte
    buf.push(UNDO_DATA_VERSION);
    // Payload
    VarInt(undo.len() as u64).encode(&mut buf).ok();
    for tx_undo in undo {
        VarInt(tx_undo.len() as u64).encode(&mut buf).ok();
        for (_outpoint, utxo) in tx_undo {
            let val = utxo.encode_value();
            VarInt(val.len() as u64).encode(&mut buf).ok();
            buf.extend_from_slice(&val);
        }
    }
    // Checksum: first 4 bytes of SHA256d(version + payload)
    let hash = rbtc_crypto::sha256d(&buf);
    buf.extend_from_slice(&hash.0[..UNDO_CHECKSUM_LEN]);
    buf
}

/// Decode undo data and reconstruct OutPoints from the block's transactions.
///
/// Handles both v1 (legacy, with stored OutPoints) and v2 (current, without).
/// For v2, the `txs` slice is required to reconstruct outpoints: for each
/// non-coinbase transaction at index `i`, the `j`-th spent coin corresponds
/// to `txs[i].inputs[j].previous_output`.
///
/// The `txs` parameter is only used for v2 decoding and can be empty if the
/// data is known to be v1.
pub fn decode_block_undo(
    bytes: &[u8],
    txs: &[rbtc_primitives::transaction::Transaction],
) -> Result<Vec<Vec<(OutPoint, StoredUtxo)>>> {
    // Minimum size: 1 (version) + 1 (at least one varint byte) + 4 (checksum)
    if bytes.len() < 1 + UNDO_CHECKSUM_LEN {
        return Err(StorageError::Decode(
            "undo data too short".to_string(),
        ));
    }

    let version = bytes[0];
    if version != UNDO_DATA_VERSION_V1 && version != UNDO_DATA_VERSION {
        return Err(StorageError::Decode(format!(
            "unsupported undo data version: {}",
            version
        )));
    }

    // Split data (version + payload) from checksum
    let (data, checksum) = bytes.split_at(bytes.len() - UNDO_CHECKSUM_LEN);

    // Verify checksum
    let hash = rbtc_crypto::sha256d(data);
    if &hash.0[..UNDO_CHECKSUM_LEN] != checksum {
        return Err(StorageError::Decode(
            "undo data checksum mismatch".to_string(),
        ));
    }

    // Skip version byte, decode payload
    let payload = &data[1..];
    let mut cur = std::io::Cursor::new(payload);
    let VarInt(num_txs) =
        VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
    let mut undo = Vec::with_capacity(num_txs as usize);

    match version {
        UNDO_DATA_VERSION_V1 => {
            // Legacy format: each entry stores (36-byte outpoint key + coin value)
            for _ in 0..num_txs {
                let VarInt(num_spent) =
                    VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
                let mut tx_undo = Vec::with_capacity(num_spent as usize);
                for _ in 0..num_spent {
                    let mut key = [0u8; 36];
                    use std::io::Read;
                    cur.read_exact(&mut key)
                        .map_err(|e| StorageError::Decode(e.to_string()))?;
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&key[..32]);
                    let vout = u32::from_le_bytes(key[32..36].try_into().unwrap());
                    let outpoint = OutPoint {
                        txid: Txid(Hash256(txid_bytes)),
                        vout,
                    };
                    let VarInt(val_len) =
                        VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
                    let mut val = vec![0u8; val_len as usize];
                    cur.read_exact(&mut val)
                        .map_err(|e| StorageError::Decode(e.to_string()))?;
                    let utxo = StoredUtxo::decode_value(&val)?;
                    tx_undo.push((outpoint, utxo));
                }
                undo.push(tx_undo);
            }
        }
        UNDO_DATA_VERSION => {
            // v2: reconstruct OutPoints from the block's transactions
            if (num_txs as usize) > txs.len() {
                return Err(StorageError::Decode(format!(
                    "undo v2 has {} tx entries but only {} transactions supplied",
                    num_txs,
                    txs.len()
                )));
            }
            for tx_idx in 0..num_txs as usize {
                let VarInt(num_spent) =
                    VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
                let mut tx_undo = Vec::with_capacity(num_spent as usize);
                for input_idx in 0..num_spent as usize {
                    // Reconstruct outpoint from the block's transaction inputs
                    let outpoint = if tx_idx < txs.len()
                        && input_idx < txs[tx_idx].inputs.len()
                    {
                        txs[tx_idx].inputs[input_idx].previous_output.clone()
                    } else {
                        // Coinbase tx or empty undo entry — should not reach here
                        // if data is well-formed, but be defensive.
                        OutPoint {
                            txid: Txid(Hash256([0u8; 32])),
                            vout: 0,
                        }
                    };
                    let VarInt(val_len) =
                        VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
                    let mut val = vec![0u8; val_len as usize];
                    use std::io::Read;
                    cur.read_exact(&mut val)
                        .map_err(|e| StorageError::Decode(e.to_string()))?;
                    let utxo = StoredUtxo::decode_value(&val)?;
                    tx_undo.push((outpoint, utxo));
                }
                undo.push(tx_undo);
            }
        }
        _ => unreachable!(),
    }
    Ok(undo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use rbtc_primitives::hash::{Hash256, Txid};
    use tempfile::TempDir;

    #[test]
    fn utxo_store_put_get_delete() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let outpoint = OutPoint {
            txid: Txid(Hash256([1; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 1000,
            script_pubkey: Script::new(),
            height: 1,
            is_coinbase: false,
        };
        store.put(&outpoint, &utxo).unwrap();
        assert!(store.contains(&outpoint).unwrap());
        let got = store.get(&outpoint).unwrap().unwrap();
        assert_eq!(got.value, 1000);
        store.delete(&outpoint).unwrap();
        assert!(store.get(&outpoint).unwrap().is_none());
    }

    #[test]
    fn utxo_store_apply_batch() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let op = OutPoint {
            txid: Txid(Hash256([2; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 2000,
            script_pubkey: Script::new(),
            height: 2,
            is_coinbase: true,
        };
        store.apply_batch(&[(op.clone(), utxo)], &[]).unwrap();
        assert_eq!(store.get(&op).unwrap().unwrap().value, 2000);
    }

    #[test]
    fn utxo_store_fill_batch_and_connect_block_into_batch() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut batch = db.new_batch();
        let op = OutPoint {
            txid: Txid(Hash256([3; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 3000,
            script_pubkey: Script::new(),
            height: 3,
            is_coinbase: false,
        };
        store
            .fill_batch(&mut batch, &[(op.clone(), utxo)], &[])
            .unwrap();
        db.write_batch(batch).unwrap();
        assert_eq!(store.get(&op).unwrap().unwrap().value, 3000);
    }

    #[test]
    fn utxo_store_connect_block_into_batch_iter_all() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        use rbtc_primitives::transaction::{Transaction, TxIn};
        let txid = Txid(Hash256([4; 32]));
        let cb = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut batch = db.new_batch();
        store
            .connect_block_into_batch(&mut batch, &[txid], &[cb], 0)
            .unwrap();
        db.write_batch(batch).unwrap();
        let all = store.iter_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1.value, 50_0000_0000);
    }

    /// Helper: build a mock transaction with given previous_outputs on its inputs.
    fn mock_tx_with_inputs(prev_outs: &[OutPoint]) -> rbtc_primitives::transaction::Transaction {
        use rbtc_primitives::transaction::TxIn;
        let inputs = prev_outs
            .iter()
            .map(|op| TxIn {
                previous_output: op.clone(),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            })
            .collect();
        rbtc_primitives::transaction::Transaction::from_parts(1, inputs, vec![], 0)
    }

    #[test]
    fn encode_decode_block_undo_roundtrip() {
        let op = OutPoint {
            txid: Txid(Hash256([7; 32])),
            vout: 1,
        };
        let utxo = StoredUtxo {
            value: 100,
            script_pubkey: Script::new(),
            height: 1,
            is_coinbase: false,
        };
        let undo = vec![vec![], vec![(op.clone(), utxo)]];
        // Build mock txs matching the undo structure
        let txs = vec![
            mock_tx_with_inputs(&[]),       // tx 0: 0 spent inputs
            mock_tx_with_inputs(&[op]),      // tx 1: 1 spent input
        ];
        let bytes = encode_block_undo(&undo);
        let decoded = decode_block_undo(&bytes, &txs).unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(decoded[0].is_empty());
        assert_eq!(decoded[1].len(), 1);
        assert_eq!(decoded[1][0].0.txid.0.0, [7; 32]);
    }

    #[test]
    fn undo_data_roundtrip_with_checksum() {
        let op1 = OutPoint {
            txid: Txid(Hash256([0xAA; 32])),
            vout: 0,
        };
        let utxo1 = StoredUtxo {
            value: 50_000,
            script_pubkey: Script::from_bytes(vec![0x76, 0xa9]),
            height: 100,
            is_coinbase: true,
        };
        let op2 = OutPoint {
            txid: Txid(Hash256([0xBB; 32])),
            vout: 3,
        };
        let utxo2 = StoredUtxo {
            value: 25_000,
            script_pubkey: Script::new(),
            height: 200,
            is_coinbase: false,
        };
        let undo = vec![vec![(op1.clone(), utxo1)], vec![(op2.clone(), utxo2)]];
        let txs = vec![
            mock_tx_with_inputs(&[op1]),
            mock_tx_with_inputs(&[op2]),
        ];
        let encoded = encode_block_undo(&undo);

        // Verify version byte is present
        assert_eq!(encoded[0], UNDO_DATA_VERSION);

        // Decode and verify contents
        let decoded = decode_block_undo(&encoded, &txs).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].len(), 1);
        assert_eq!(decoded[0][0].1.value, 50_000);
        assert!(decoded[0][0].1.is_coinbase);
        assert_eq!(decoded[1].len(), 1);
        assert_eq!(decoded[1][0].1.value, 25_000);
        assert_eq!(decoded[1][0].0.vout, 3);
    }

    #[test]
    fn undo_data_corrupted_checksum_fails() {
        let op = OutPoint {
            txid: Txid(Hash256([0xCC; 32])),
            vout: 2,
        };
        let utxo = StoredUtxo {
            value: 999,
            script_pubkey: Script::new(),
            height: 42,
            is_coinbase: false,
        };
        let undo = vec![vec![(op, utxo)]];
        let mut encoded = encode_block_undo(&undo);

        // Flip a byte in the middle of the payload
        let mid = encoded.len() / 2;
        encoded[mid] ^= 0xFF;

        let result = decode_block_undo(&encoded, &[]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("checksum mismatch"),
            "expected checksum mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn undo_data_truncated_fails() {
        let op = OutPoint {
            txid: Txid(Hash256([0xDD; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 500,
            script_pubkey: Script::new(),
            height: 10,
            is_coinbase: false,
        };
        let undo = vec![vec![(op, utxo)]];
        let encoded = encode_block_undo(&undo);

        // Truncate to just a few bytes (shorter than minimum)
        let truncated = &encoded[..3];
        let result = decode_block_undo(truncated, &[]);
        assert!(result.is_err());

        // Truncate removing part of the checksum
        let truncated2 = &encoded[..encoded.len() - 2];
        let result2 = decode_block_undo(truncated2, &[]);
        assert!(result2.is_err());
        let err_msg = format!("{}", result2.unwrap_err());
        assert!(
            err_msg.contains("checksum mismatch"),
            "expected checksum mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn undo_v2_omits_outpoints_saves_space() {
        // v2 should NOT embed raw txid bytes — they are reconstructed from txs
        let op = OutPoint {
            txid: Txid(Hash256([0xFA; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 7777,
            script_pubkey: Script::new(),
            height: 10,
            is_coinbase: false,
        };
        let undo = vec![vec![(op.clone(), utxo)]];
        let encoded = encode_block_undo(&undo);
        // The 32-byte txid pattern should NOT appear in the v2 encoded data
        let fa_pattern = [0xFA; 32];
        let contains_txid = encoded.windows(32).any(|w| w == &fa_pattern[..]);
        assert!(
            !contains_txid,
            "v2 undo data must not contain raw outpoint txids"
        );
    }

    #[test]
    fn undo_v1_backward_compat() {
        // Manually encode v1 format and verify decode_block_undo can still read it
        let op = OutPoint {
            txid: Txid(Hash256([0xEE; 32])),
            vout: 5,
        };
        let utxo = StoredUtxo {
            value: 12345,
            script_pubkey: Script::new(),
            height: 50,
            is_coinbase: false,
        };
        // Build v1 data manually
        let mut buf = Vec::new();
        buf.push(UNDO_DATA_VERSION_V1);
        VarInt(1).encode(&mut buf).ok(); // 1 tx
        VarInt(1).encode(&mut buf).ok(); // 1 spent coin
        // V1 undo format uses fixed 36-byte outpoint (txid + vout_LE4)
        buf.extend_from_slice(&op.txid.0 .0);
        buf.extend_from_slice(&op.vout.to_le_bytes());
        let val = utxo.encode_value();
        VarInt(val.len() as u64).encode(&mut buf).ok();
        buf.extend_from_slice(&val);
        // Checksum
        let hash = rbtc_crypto::sha256d(&buf);
        buf.extend_from_slice(&hash.0[..UNDO_CHECKSUM_LEN]);

        // Decode with empty txs (v1 doesn't need them)
        let decoded = decode_block_undo(&buf, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].len(), 1);
        assert_eq!(decoded[0][0].0.txid.0.0, [0xEE; 32]);
        assert_eq!(decoded[0][0].0.vout, 5);
        assert_eq!(decoded[0][0].1.value, 12345);
    }

    #[test]
    fn stored_utxo_coin_format_p2pkh_roundtrip() {
        // Bitcoin Core Coin format: VARINT(code) + VARINT(compressed_amount) + VARINT(script_type) + payload
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0x55; 20]);
        p2pkh.push(0x88);
        p2pkh.push(0xac);

        let utxo = StoredUtxo {
            value: 100_000_000, // 1 BTC
            script_pubkey: Script::from_bytes(p2pkh.clone()),
            height: 500_000,
            is_coinbase: false,
        };
        let encoded = utxo.encode_value();
        let decoded = StoredUtxo::decode_value(&encoded).unwrap();
        assert_eq!(decoded.value, 100_000_000);
        assert_eq!(decoded.script_pubkey.as_bytes(), &p2pkh);
        assert_eq!(decoded.height, 500_000);
        assert!(!decoded.is_coinbase);
    }

    #[test]
    fn stored_utxo_coin_format_coinbase() {
        let utxo = StoredUtxo {
            value: 50_0000_0000,
            script_pubkey: Script::new(),
            height: 0,
            is_coinbase: true,
        };
        let encoded = utxo.encode_value();
        let decoded = StoredUtxo::decode_value(&encoded).unwrap();
        assert_eq!(decoded.value, 50_0000_0000);
        assert_eq!(decoded.height, 0);
        assert!(decoded.is_coinbase);
    }

    #[test]
    fn stored_utxo_coin_format_code_encoding() {
        // Verify code = height * 2 + coinbase
        let utxo = StoredUtxo {
            value: 1000,
            script_pubkey: Script::new(),
            height: 42,
            is_coinbase: true,
        };
        let encoded = utxo.encode_value();
        // First byte(s) should be VARINT(42 * 2 + 1 = 85 = 0x55)
        assert_eq!(encoded[0], 0x55);

        let decoded = StoredUtxo::decode_value(&encoded).unwrap();
        assert_eq!(decoded.height, 42);
        assert!(decoded.is_coinbase);
    }

    #[test]
    fn stored_utxo_coin_format_various_scripts() {
        // P2SH
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[0x22; 20]);
        p2sh.push(0x87);
        let utxo = StoredUtxo {
            value: 50_000,
            script_pubkey: Script::from_bytes(p2sh.clone()),
            height: 100,
            is_coinbase: false,
        };
        let decoded = StoredUtxo::decode_value(&utxo.encode_value()).unwrap();
        assert_eq!(decoded.script_pubkey.as_bytes(), &p2sh);

        // Non-standard / raw script
        let raw = vec![0x51, 0x52, 0x93, 0x87];
        let utxo2 = StoredUtxo {
            value: 1,
            script_pubkey: Script::from_bytes(raw.clone()),
            height: 999_999,
            is_coinbase: false,
        };
        let decoded2 = StoredUtxo::decode_value(&utxo2.encode_value()).unwrap();
        assert_eq!(decoded2.script_pubkey.as_bytes(), &raw);
        assert_eq!(decoded2.value, 1);
        assert_eq!(decoded2.height, 999_999);
    }

    #[test]
    fn stored_utxo_coin_format_saves_space() {
        // 1 BTC to P2PKH: Bitcoin Core format should be very compact
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0x55; 20]);
        p2pkh.push(0x88);
        p2pkh.push(0xac);

        let utxo = StoredUtxo {
            value: 100_000_000,
            script_pubkey: Script::from_bytes(p2pkh),
            height: 100,
            is_coinbase: false,
        };
        let encoded = utxo.encode_value();
        // Old uncompressed: 8 (i64) + 1 (varint) + 25 (script) + 4 (u32) + 1 (flag) = 39 bytes
        // Bitcoin Core format: ~1 (code) + ~1 (amount) + 1 (type=0) + 20 (hash) = ~23 bytes
        assert!(encoded.len() < 30, "Coin format len {} should be < 30", encoded.len());
    }

    // ── M8: DB_COIN constant test ──────────────────────────────────────

    #[test]
    fn db_coin_prefix_constant() {
        // DB_COIN matches Bitcoin Core's DB_COIN = 'C' = 0x43
        assert_eq!(DB_COIN, b'C');
        assert_eq!(DB_COIN, 0x43);
    }

    // ── M12: UtxoCache tests ─────────────────────────────────────────

    #[test]
    fn utxo_cache_hit() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store);

        let op = OutPoint {
            txid: Txid(Hash256([0xC1; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 5000,
            script_pubkey: Script::new(),
            height: 10,
            is_coinbase: false,
        };
        cache.put(&op, utxo.clone());
        // Should read from cache, not DB
        let got = cache.get(&op).unwrap().unwrap();
        assert_eq!(got.value, 5000);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.dirty_count(), 1);
    }

    #[test]
    fn utxo_cache_miss_falls_through_to_db() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        // Pre-populate DB directly
        let store = UtxoStore::new(&db);
        let op = OutPoint {
            txid: Txid(Hash256([0xC2; 32])),
            vout: 1,
        };
        let utxo = StoredUtxo {
            value: 7777,
            script_pubkey: Script::new(),
            height: 20,
            is_coinbase: true,
        };
        store.put(&op, &utxo).unwrap();

        // Now create a cache and look up — should fall through to DB
        let store2 = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store2);
        let got = cache.get(&op).unwrap().unwrap();
        assert_eq!(got.value, 7777);
        assert!(got.is_coinbase);
        // After lookup, cache should hold the entry but it should NOT be dirty
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn utxo_cache_flush_writes_to_db() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store);

        let op = OutPoint {
            txid: Txid(Hash256([0xC3; 32])),
            vout: 2,
        };
        let utxo = StoredUtxo {
            value: 9999,
            script_pubkey: Script::new(),
            height: 30,
            is_coinbase: false,
        };
        cache.put(&op, utxo);
        // Before flush, DB should not have it
        let direct = UtxoStore::new(&db);
        assert!(direct.get(&op).unwrap().is_none());

        cache.flush().unwrap();
        assert_eq!(cache.dirty_count(), 0);

        // After flush, DB should have it
        let got = direct.get(&op).unwrap().unwrap();
        assert_eq!(got.value, 9999);
    }

    #[test]
    fn utxo_cache_remove_marks_as_none() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();

        // Put a UTXO in the DB first
        let store = UtxoStore::new(&db);
        let op = OutPoint {
            txid: Txid(Hash256([0xC4; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 1234,
            script_pubkey: Script::new(),
            height: 5,
            is_coinbase: false,
        };
        store.put(&op, &utxo).unwrap();

        // Create cache, remove the entry, should return None even though DB has it
        let store2 = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store2);
        cache.remove(&op);
        assert!(cache.get(&op).unwrap().is_none());

        // After flush, DB should no longer have it
        cache.flush().unwrap();
        let direct = UtxoStore::new(&db);
        assert!(direct.get(&op).unwrap().is_none());
    }

    #[test]
    fn utxo_cache_clear_drops_everything() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store);

        let op = OutPoint {
            txid: Txid(Hash256([0xC5; 32])),
            vout: 0,
        };
        cache.put(
            &op,
            StoredUtxo {
                value: 1,
                script_pubkey: Script::new(),
                height: 0,
                is_coinbase: false,
            },
        );
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.dirty_count(), 0);
    }

    // ── M14: UtxoStats tests ─────────────────────────────────────────

    #[test]
    fn utxo_stats_empty() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let stats = store.get_utxo_stats().unwrap();
        assert_eq!(stats.num_utxos, 0);
        assert_eq!(stats.total_amount, 0);
        assert_eq!(stats.serialized_size, 0);
    }

    #[test]
    fn utxo_stats_with_entries() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);

        let op1 = OutPoint {
            txid: Txid(Hash256([0xD1; 32])),
            vout: 0,
        };
        let utxo1 = StoredUtxo {
            value: 50_0000_0000, // 50 BTC
            script_pubkey: Script::new(),
            height: 0,
            is_coinbase: true,
        };
        let op2 = OutPoint {
            txid: Txid(Hash256([0xD2; 32])),
            vout: 1,
        };
        let utxo2 = StoredUtxo {
            value: 10_0000_0000, // 10 BTC
            script_pubkey: Script::new(),
            height: 100,
            is_coinbase: false,
        };
        store.put(&op1, &utxo1).unwrap();
        store.put(&op2, &utxo2).unwrap();

        let stats = store.get_utxo_stats().unwrap();
        assert_eq!(stats.num_utxos, 2);
        assert_eq!(stats.total_amount, 60_0000_0000);
        assert!(stats.serialized_size > 0);
        // Each key is 33+ bytes (32 txid + varint vout); serialized_size should include both keys + values
        assert!(stats.serialized_size >= 66);
    }

    // ── L9: CoinsView trait tests ───────────────────────────────────────

    #[test]
    fn coins_view_utxo_store() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let op = OutPoint {
            txid: Txid(Hash256([0xAA; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 5000,
            script_pubkey: Script::new(),
            height: 10,
            is_coinbase: false,
        };

        // Not present initially
        assert!(!store.have_coin(&op).unwrap());
        assert!(store.get_coin(&op).unwrap().is_none());

        store.put(&op, &utxo).unwrap();

        // Now present via trait methods
        assert!(store.have_coin(&op).unwrap());
        let got = store.get_coin(&op).unwrap().unwrap();
        assert_eq!(got.value, 5000);
    }

    #[test]
    fn coins_view_utxo_cache() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let op = OutPoint {
            txid: Txid(Hash256([0xBB; 32])),
            vout: 1,
        };
        let utxo = StoredUtxo {
            value: 9999,
            script_pubkey: Script::new(),
            height: 20,
            is_coinbase: true,
        };

        // Put via DB store so cache can see it
        store.put(&op, &utxo).unwrap();

        let mut cache = UtxoCache::new(store);

        // Read via CoinsView trait (immutable) — falls through to DB
        let view: &dyn CoinsView = &cache;
        assert!(view.have_coin(&op).unwrap());
        assert_eq!(view.get_coin(&op).unwrap().unwrap().value, 9999);

        // Remove via cache, then check trait sees the removal
        cache.remove(&op);
        let view: &dyn CoinsView = &cache;
        assert!(!view.have_coin(&op).unwrap());
        assert!(view.get_coin(&op).unwrap().is_none());
    }

    #[test]
    fn coins_view_cache_put_visible() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store);

        let op = OutPoint {
            txid: Txid(Hash256([0xCC; 32])),
            vout: 2,
        };
        let utxo = StoredUtxo {
            value: 42,
            script_pubkey: Script::new(),
            height: 1,
            is_coinbase: false,
        };

        // Not in DB or cache
        let view: &dyn CoinsView = &cache;
        assert!(!view.have_coin(&op).unwrap());

        // Put into cache
        cache.put(&op, utxo);

        // Now visible via CoinsView
        let view: &dyn CoinsView = &cache;
        assert!(view.have_coin(&op).unwrap());
        assert_eq!(view.get_coin(&op).unwrap().unwrap().value, 42);
    }

    // ── M15: OP_RETURN / unspendable outputs skipped from UTXO set ────

    #[test]
    fn is_unspendable_op_return() {
        let utxo = StoredUtxo {
            value: 0,
            script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xde, 0xad]),
            height: 100,
            is_coinbase: false,
        };
        assert!(utxo.is_unspendable());
    }

    #[test]
    fn is_unspendable_oversized_script() {
        let utxo = StoredUtxo {
            value: 1000,
            script_pubkey: Script::from_bytes(vec![0x00; MAX_SCRIPT_SIZE + 1]),
            height: 100,
            is_coinbase: false,
        };
        assert!(utxo.is_unspendable());
    }

    #[test]
    fn is_spendable_normal_script() {
        let utxo = StoredUtxo {
            value: 5000,
            script_pubkey: Script::from_bytes(vec![0x76, 0xa9]),
            height: 100,
            is_coinbase: false,
        };
        assert!(!utxo.is_unspendable());
    }

    #[test]
    fn connect_block_skips_op_return_outputs() {
        use rbtc_primitives::transaction::{Transaction, TxIn};
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);

        let txid = Txid(Hash256([0xF0; 32]));
        // Coinbase tx with two outputs: one normal, one OP_RETURN
        let cb = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![
                TxOut {
                    value: 50_0000_0000,
                    script_pubkey: Script::from_bytes(vec![0x76, 0xa9]), // spendable
                },
                TxOut {
                    value: 0,
                    script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xde, 0xad]), // OP_RETURN
                },
            ],
            0,
        );

        let mut batch = db.new_batch();
        store
            .connect_block_into_batch(&mut batch, &[txid], &[cb], 100)
            .unwrap();
        db.write_batch(batch).unwrap();

        // Normal output should be in the UTXO set
        let op0 = OutPoint { txid, vout: 0 };
        assert!(store.get(&op0).unwrap().is_some());

        // OP_RETURN output should NOT be in the UTXO set
        let op1 = OutPoint { txid, vout: 1 };
        assert!(store.get(&op1).unwrap().is_none());
    }

    #[test]
    fn connect_block_skips_oversized_script_outputs() {
        use rbtc_primitives::transaction::{Transaction, TxIn};
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);

        let txid = Txid(Hash256([0xF1; 32]));
        let cb = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![
                TxOut {
                    value: 50_0000_0000,
                    script_pubkey: Script::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: 1000,
                    script_pubkey: Script::from_bytes(vec![0x00; MAX_SCRIPT_SIZE + 1]),
                },
            ],
            0,
        );

        let mut batch = db.new_batch();
        store
            .connect_block_into_batch(&mut batch, &[txid], &[cb], 200)
            .unwrap();
        db.write_batch(batch).unwrap();

        assert!(store.get(&OutPoint { txid, vout: 0 }).unwrap().is_some());
        assert!(store.get(&OutPoint { txid, vout: 1 }).unwrap().is_none());
    }

    // ── M16: FRESH flag optimization in UTXO cache ────────────────────

    #[test]
    fn utxo_cache_fresh_flag_on_new_entry() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store);

        let op = OutPoint {
            txid: Txid(Hash256([0xF2; 32])),
            vout: 0,
        };
        cache.put(
            &op,
            StoredUtxo {
                value: 1000,
                script_pubkey: Script::new(),
                height: 1,
                is_coinbase: false,
            },
        );
        // New entry should be both dirty and fresh
        assert_eq!(cache.dirty_count(), 1);
        assert_eq!(cache.fresh_count(), 1);
    }

    #[test]
    fn utxo_cache_fresh_spent_erased_no_db_delete() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store);

        let op = OutPoint {
            txid: Txid(Hash256([0xF3; 32])),
            vout: 0,
        };
        // Add a coin (FRESH)
        cache.put(
            &op,
            StoredUtxo {
                value: 2000,
                script_pubkey: Script::new(),
                height: 5,
                is_coinbase: false,
            },
        );
        assert_eq!(cache.fresh_count(), 1);
        assert_eq!(cache.dirty_count(), 1);

        // Spend it — FRESH+spent should erase entirely
        cache.remove(&op);
        assert_eq!(cache.len(), 0); // erased from cache
        assert_eq!(cache.dirty_count(), 0); // no dirty entry to flush
        assert_eq!(cache.fresh_count(), 0);

        // Flush should be a no-op (nothing to write)
        cache.flush().unwrap();

        // DB should NOT have the entry (it was never flushed)
        let direct = UtxoStore::new(&db);
        assert!(direct.get(&op).unwrap().is_none());
    }

    #[test]
    fn utxo_cache_non_fresh_spent_writes_delete() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();

        // Pre-populate DB
        let store = UtxoStore::new(&db);
        let op = OutPoint {
            txid: Txid(Hash256([0xF4; 32])),
            vout: 0,
        };
        store
            .put(
                &op,
                &StoredUtxo {
                    value: 3000,
                    script_pubkey: Script::new(),
                    height: 10,
                    is_coinbase: false,
                },
            )
            .unwrap();

        // Create cache, fetch from DB (not fresh), then remove
        let store2 = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store2);
        cache.get(&op).unwrap(); // populate cache from DB
        assert_eq!(cache.fresh_count(), 0); // fetched from DB, not fresh

        cache.remove(&op);
        // Should be dirty (need to write delete) but not fresh
        assert_eq!(cache.dirty_count(), 1);
        assert_eq!(cache.fresh_count(), 0);

        cache.flush().unwrap();

        // DB should no longer have it
        let direct = UtxoStore::new(&db);
        assert!(direct.get(&op).unwrap().is_none());
    }

    #[test]
    fn utxo_cache_flush_clears_fresh() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let mut cache = UtxoCache::new(store);

        let op = OutPoint {
            txid: Txid(Hash256([0xF5; 32])),
            vout: 0,
        };
        cache.put(
            &op,
            StoredUtxo {
                value: 4000,
                script_pubkey: Script::new(),
                height: 15,
                is_coinbase: false,
            },
        );
        assert_eq!(cache.fresh_count(), 1);

        cache.flush().unwrap();
        // After flush, fresh set should be cleared
        assert_eq!(cache.fresh_count(), 0);
        assert_eq!(cache.dirty_count(), 0);
    }

    // ── M17: Undo format version marker ───────────────────────────────

    #[test]
    fn undo_format_has_version_marker() {
        let op = OutPoint {
            txid: Txid(Hash256([0xF6; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 100,
            script_pubkey: Script::new(),
            height: 1,
            is_coinbase: false,
        };
        let encoded = encode_block_undo(&[vec![(op, utxo)]]);
        // First byte must be the version marker
        assert_eq!(encoded[0], UNDO_DATA_VERSION);
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn undo_format_has_checksum() {
        let op = OutPoint {
            txid: Txid(Hash256([0xF7; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 100,
            script_pubkey: Script::new(),
            height: 1,
            is_coinbase: false,
        };
        let encoded = encode_block_undo(&[vec![(op, utxo)]]);
        // Last 4 bytes are checksum; verify they match SHA256d of the rest
        let (data, checksum) = encoded.split_at(encoded.len() - UNDO_CHECKSUM_LEN);
        let hash = rbtc_crypto::sha256d(data);
        assert_eq!(&hash.0[..UNDO_CHECKSUM_LEN], checksum);
    }
}
