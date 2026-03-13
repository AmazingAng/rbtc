use rbtc_primitives::{
    block::{Block, BlockHeader},
    codec::{Decodable, Encodable},
    hash::{BlockHash, Hash256},
};

use crate::{
    block_status::BlockStatus,
    db::{
        Database, CF_BLOCK_DATA, CF_BLOCK_FILTERS, CF_BLOCK_INDEX, CF_FILTER_HEADERS,
        CF_HEIGHT_INDEX, CF_UNDO,
    },
    error::{Result, StorageError},
};

/// Stored block header with metadata
#[derive(Debug, Clone)]
pub struct StoredBlockIndex {
    pub header: BlockHeader,
    pub height: u32,
    pub chainwork_lo: u64,
    pub chainwork_hi: u64,
    pub status: BlockStatus,
}

impl StoredBlockIndex {
    pub fn chainwork(&self) -> rbtc_primitives::uint256::U256 {
        rbtc_primitives::uint256::U256([self.chainwork_lo, self.chainwork_hi, 0, 0])
    }

    /// Set chainwork from a U256.  Only the low 128 bits are persisted on disk
    /// (sufficient for millions of years of mainnet work).
    pub fn set_chainwork(&mut self, w: &rbtc_primitives::uint256::U256) {
        self.chainwork_lo = w.0[0];
        self.chainwork_hi = w.0[1];
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.header.encode(&mut buf).ok();
        self.height.encode(&mut buf).ok();
        self.chainwork_lo.encode(&mut buf).ok();
        self.chainwork_hi.encode(&mut buf).ok();
        buf.extend_from_slice(&self.status.raw().to_le_bytes());
        buf
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(bytes);
        let header =
            BlockHeader::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        let height = u32::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        let chainwork_lo =
            u64::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        let chainwork_hi =
            u64::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        // Try to read 4 bytes (u32 LE) for new format; fall back to 1 byte (u8) for legacy data.
        let mut status_buf = [0u8; 4];
        use std::io::Read;
        let bytes_read = cur.read(&mut status_buf)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let status = if bytes_read == 4 {
            BlockStatus::from_raw(u32::from_le_bytes(status_buf))
        } else if bytes_read == 1 {
            BlockStatus::from_u8(status_buf[0])
        } else {
            return Err(StorageError::Decode("unexpected status field length".into()));
        };
        Ok(Self {
            header,
            height,
            chainwork_lo,
            chainwork_hi,
            status,
        })
    }
}

/// Block header and full block storage
pub struct BlockStore<'db> {
    db: &'db Database,
}

impl<'db> BlockStore<'db> {
    pub fn new(db: &'db Database) -> Self {
        Self { db }
    }

    pub fn get_index(&self, hash: &BlockHash) -> Result<Option<StoredBlockIndex>> {
        match self.db.get_cf(CF_BLOCK_INDEX, &hash.0.0)? {
            Some(bytes) => Ok(Some(StoredBlockIndex::decode_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_index(&self, hash: &BlockHash, index: &StoredBlockIndex) -> Result<()> {
        self.db
            .put_cf(CF_BLOCK_INDEX, &hash.0.0, &index.encode_bytes())
    }

    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        match self.db.get_cf(CF_BLOCK_DATA, &hash.0.0)? {
            Some(bytes) => {
                let block = Block::decode_from_slice(&bytes)
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    pub fn put_block(&self, hash: &BlockHash, block: &Block) -> Result<()> {
        let bytes = block.encode_to_vec();
        self.db.put_cf(CF_BLOCK_DATA, &hash.0.0, &bytes)
    }

    /// Atomically write a block header + block data
    pub fn put_block_atomic(
        &self,
        hash: &BlockHash,
        index: &StoredBlockIndex,
        block: &Block,
    ) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.db
            .batch_put_cf(&mut batch, CF_BLOCK_INDEX, &hash.0.0, &index.encode_bytes())?;
        self.db
            .batch_put_cf(&mut batch, CF_BLOCK_DATA, &hash.0.0, &block.encode_to_vec())?;
        self.db.write_batch(batch)
    }

    pub fn has_block(&self, hash: &BlockHash) -> Result<bool> {
        Ok(self.db.get_cf(CF_BLOCK_DATA, &hash.0.0)?.is_some())
    }

    pub fn has_index(&self, hash: &BlockHash) -> Result<bool> {
        Ok(self.db.get_cf(CF_BLOCK_INDEX, &hash.0.0)?.is_some())
    }

    /// Iterate all stored block index entries (sorted by key / hash order, not height).
    /// Call `.sort_by_key(|(_, idx)| idx.height)` on the result before rebuilding ChainState.
    pub fn iter_all_indices(&self) -> Vec<(BlockHash, StoredBlockIndex)> {
        match self.db.iter_cf(CF_BLOCK_INDEX) {
            Ok(iter) => iter
                .into_iter()
                .filter_map(|(k, v)| {
                    if k.len() != 32 {
                        return None;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&k);
                    let idx = StoredBlockIndex::decode_bytes(&v).ok()?;
                    Some((BlockHash(Hash256(arr)), idx))
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    // ── Height → Hash index ────────────────────────────────────────────────────

    /// Store a height → block hash mapping.
    pub fn put_height_hash(&self, height: u32, hash: &BlockHash) -> Result<()> {
        self.db
            .put_cf(CF_HEIGHT_INDEX, &height.to_le_bytes(), &hash.0.0)
    }

    /// Look up the block hash at a given height.
    pub fn get_hash_by_height(&self, height: u32) -> Result<Option<BlockHash>> {
        match self.db.get_cf(CF_HEIGHT_INDEX, &height.to_le_bytes())? {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(BlockHash(Hash256(arr))))
            }
            Some(_) => Err(StorageError::Corruption(
                "invalid height index entry".into(),
            )),
            None => Ok(None),
        }
    }

    /// Delete a height → hash mapping (used during reorg).
    pub fn delete_height_hash(&self, height: u32) -> Result<()> {
        self.db.delete_cf(CF_HEIGHT_INDEX, &height.to_le_bytes())
    }

    /// Batch-insert a height → hash mapping.
    pub fn batch_put_height_hash(
        &self,
        batch: &mut rocksdb::WriteBatch,
        height: u32,
        hash: &BlockHash,
    ) -> Result<()> {
        self.db
            .batch_put_cf(batch, CF_HEIGHT_INDEX, &height.to_le_bytes(), &hash.0.0)
    }

    // ── Undo data (spent UTXOs per block, needed for reorg) ───────────────────

    pub fn put_undo(&self, hash: &BlockHash, undo_bytes: &[u8]) -> Result<()> {
        self.db.put_cf(CF_UNDO, &hash.0.0, undo_bytes)
    }

    pub fn get_undo(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>> {
        self.db.get_cf(CF_UNDO, &hash.0.0)
    }

    // ── Pruning ───────────────────────────────────────────────────────────────

    // ── BIP157 compact block filters ────────────────────────────────────────

    /// Store a BIP157 compact block filter.
    /// Key layout: `filter_type(1) || block_hash(32)`.
    pub fn put_filter(&self, filter_type: u8, hash: &BlockHash, filter: &[u8]) -> Result<()> {
        let mut key = Vec::with_capacity(33);
        key.push(filter_type);
        key.extend_from_slice(&hash.0.0);
        self.db.put_cf(CF_BLOCK_FILTERS, &key, filter)
    }

    /// Retrieve a BIP157 compact block filter.
    pub fn get_filter(&self, filter_type: u8, hash: &BlockHash) -> Result<Option<Vec<u8>>> {
        let mut key = Vec::with_capacity(33);
        key.push(filter_type);
        key.extend_from_slice(&hash.0.0);
        self.db.get_cf(CF_BLOCK_FILTERS, &key)
    }

    /// Store a BIP157 filter header (32-byte hash).
    pub fn put_filter_header(
        &self,
        filter_type: u8,
        hash: &BlockHash,
        header: &[u8; 32],
    ) -> Result<()> {
        let mut key = Vec::with_capacity(33);
        key.push(filter_type);
        key.extend_from_slice(&hash.0.0);
        self.db.put_cf(CF_FILTER_HEADERS, &key, header)
    }

    /// Retrieve a BIP157 filter header.
    pub fn get_filter_header(&self, filter_type: u8, hash: &BlockHash) -> Result<Option<[u8; 32]>> {
        let mut key = Vec::with_capacity(33);
        key.push(filter_type);
        key.extend_from_slice(&hash.0.0);
        match self.db.get_cf(CF_FILTER_HEADERS, &key)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            Some(_) => Err(StorageError::Corruption(
                "invalid filter header length".into(),
            )),
            None => Ok(None),
        }
    }

    // ── Pruning ───────────────────────────────────────────────────────────────

    /// Delete raw block data (`CF_BLOCK_DATA`) for all blocks at height ≤ `max_height`.
    ///
    /// The block headers (`CF_BLOCK_INDEX`) and undo data (`CF_UNDO`) are **kept**
    /// so that the node can still serve headers and detect reorgs.  The on-disk
    /// status of pruned blocks is updated to `BlockStatus::Pruned` (4).
    ///
    /// Returns the number of blocks pruned.
    pub fn prune_blocks_below(&self, max_height: u32) -> Result<usize> {
        let indices = self.iter_all_indices();
        let mut count = 0usize;

        for (hash, mut idx) in indices {
            if idx.height > max_height {
                continue;
            }
            // Skip already-pruned entries and blocks we don't have data for
            if idx.status.raw() == 4 {
                continue;
            }
            if self.db.get_cf(CF_BLOCK_DATA, &hash.0.0)?.is_none() {
                continue;
            }

            // Delete the raw block bytes
            self.db.delete_cf(CF_BLOCK_DATA, &hash.0.0)?;

            // Update the on-disk status to Pruned (4)
            idx.status = BlockStatus::from_raw(4); // Pruned
            self.put_index(&hash, &idx)?;

            count += 1;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::transaction::Transaction;
    use tempfile::TempDir;

    #[test]
    fn block_store_put_get_index() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([1; 32]));
        let index = StoredBlockIndex {
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 0,
            chainwork_lo: 1,
            chainwork_hi: 0,
            status: BlockStatus::new(),
        };
        store.put_index(&hash, &index).unwrap();
        let got = store.get_index(&hash).unwrap().unwrap();
        assert_eq!(got.height, 0);
        assert!(store.has_index(&hash).unwrap());
    }

    #[test]
    fn block_store_put_get_block() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([2; 32]));
        use rbtc_primitives::script::Script;
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        let block = Block::new(
            BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            vec![Transaction::from_parts(
                1,
                vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![2, 0, 0]),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                vec![TxOut {
                    value: 0,
                    script_pubkey: Script::new(),
                }],
                0,
            )],
        );
        store.put_block(&hash, &block).unwrap();
        let got = store.get_block(&hash).unwrap().unwrap();
        assert_eq!(got.transactions.len(), 1);
        assert!(store.has_block(&hash).unwrap());
    }

    #[test]
    fn block_store_get_missing() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([99; 32]));
        assert!(store.get_index(&hash).unwrap().is_none());
        assert!(store.get_block(&hash).unwrap().is_none());
    }

    #[test]
    fn block_store_iter_all_indices_put_undo_get_undo() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([10; 32]));
        let index = StoredBlockIndex {
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 5,
            chainwork_lo: 1,
            chainwork_hi: 0,
            status: BlockStatus::from_raw(1),
        };
        store.put_index(&hash, &index).unwrap();
        let indices = store.iter_all_indices();
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0].1.height, 5);

        store.put_undo(&hash, b"undo_data").unwrap();
        let got = store.get_undo(&hash).unwrap().unwrap();
        assert_eq!(got, b"undo_data");
    }

    #[test]
    fn block_store_put_block_atomic() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([15; 32]));
        let index = StoredBlockIndex {
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 0,
            chainwork_lo: 1,
            chainwork_hi: 0,
            status: BlockStatus::new(),
        };
        use rbtc_primitives::script::Script;
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        let block = Block::new(
            index.header.clone(),
            vec![Transaction::from_parts(
                1,
                vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![2, 0, 0]),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                vec![TxOut {
                    value: 0,
                    script_pubkey: Script::new(),
                }],
                0,
            )],
        );
        store.put_block_atomic(&hash, &index, &block).unwrap();
        assert!(store.get_index(&hash).unwrap().is_some());
        assert!(store.get_block(&hash).unwrap().is_some());
    }

    #[test]
    fn block_store_get_index_decode_error() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([16; 32]));
        db.put_cf(CF_BLOCK_INDEX, &hash.0.0, b"truncated").unwrap();
        let r = store.get_index(&hash);
        assert!(r.is_err());
    }

    #[test]
    fn block_store_prune_blocks_below() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        use rbtc_primitives::script::Script;
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        let hash: BlockHash = BlockHash(Hash256([20; 32]));
        let index = StoredBlockIndex {
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 1,
            chainwork_lo: 1,
            chainwork_hi: 0,
            status: BlockStatus::from_raw(2),
        };
        let block = Block::new(
            index.header.clone(),
            vec![Transaction::from_parts(
                1,
                vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![2, 0, 0]),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                vec![TxOut {
                    value: 0,
                    script_pubkey: Script::new(),
                }],
                0,
            )],
        );
        store.put_index(&hash, &index).unwrap();
        store.put_block(&hash, &block).unwrap();
        let count = store.prune_blocks_below(1).unwrap();
        assert_eq!(count, 1);
        assert!(store.get_block(&hash).unwrap().is_none());
        let idx = store.get_index(&hash).unwrap().unwrap();
        assert_eq!(idx.status.raw(), 4);
    }

    #[test]
    fn block_index_u32_status_roundtrip() {
        // Status with BLOCK_OPT_WITNESS (128) + BLOCK_VALID_SCRIPTS (5) + BLOCK_HAVE_DATA (8)
        let status = BlockStatus::new()
            .with_validity(5)
            .with_data()
            .with_opt_witness();
        assert_eq!(status.raw(), 5 | 8 | 128);

        let index = StoredBlockIndex {
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 1000,
                bits: 0x1d00ffff,
                nonce: 42,
            },
            height: 100_000,
            chainwork_lo: 999,
            chainwork_hi: 0,
            status,
        };
        let bytes = index.encode_bytes();
        let decoded = StoredBlockIndex::decode_bytes(&bytes).unwrap();
        assert_eq!(decoded.status.raw(), status.raw());
        assert!(decoded.status.has_opt_witness());
        assert!(decoded.status.have_data());
        assert_eq!(decoded.status.validity(), 5);
        assert_eq!(decoded.height, 100_000);
    }

    #[test]
    fn block_index_u32_status_preserves_high_bits() {
        // Test that flags above 255 survive the roundtrip (would be lost with u8)
        let status = BlockStatus::from_raw(0x0000_0185); // validity=5, data=8, witness=128, + bit 8 (256)
        let index = StoredBlockIndex {
            header: BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 0,
            chainwork_lo: 0,
            chainwork_hi: 0,
            status,
        };
        let bytes = index.encode_bytes();
        let decoded = StoredBlockIndex::decode_bytes(&bytes).unwrap();
        assert_eq!(decoded.status.raw(), 0x0000_0185);
    }
}
