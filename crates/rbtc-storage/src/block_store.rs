use rbtc_primitives::{
    block::{Block, BlockHeader},
    codec::{Decodable, Encodable},
    hash::{BlockHash, Hash256},
};

use crate::{
    db::{Database, CF_BLOCK_DATA, CF_BLOCK_INDEX, CF_UNDO},
    error::{Result, StorageError},
};

/// Stored block header with metadata
#[derive(Debug, Clone)]
pub struct StoredBlockIndex {
    pub header: BlockHeader,
    pub height: u32,
    pub chainwork_lo: u64,
    pub chainwork_hi: u64,
    pub status: u8,
}

impl StoredBlockIndex {
    pub fn chainwork(&self) -> u128 {
        (self.chainwork_hi as u128) << 64 | (self.chainwork_lo as u128)
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.header.encode(&mut buf).ok();
        self.height.encode(&mut buf).ok();
        self.chainwork_lo.encode(&mut buf).ok();
        self.chainwork_hi.encode(&mut buf).ok();
        buf.push(self.status);
        buf
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(bytes);
        let header = BlockHeader::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let height = u32::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let chainwork_lo = u64::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let chainwork_hi = u64::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let mut status_byte = [0u8; 1];
        use std::io::Read;
        cur.read_exact(&mut status_byte).map_err(|e| StorageError::Decode(e.to_string()))?;
        Ok(Self { header, height, chainwork_lo, chainwork_hi, status: status_byte[0] })
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
        match self.db.get_cf(CF_BLOCK_INDEX, &hash.0)? {
            Some(bytes) => Ok(Some(StoredBlockIndex::decode_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_index(&self, hash: &BlockHash, index: &StoredBlockIndex) -> Result<()> {
        self.db.put_cf(CF_BLOCK_INDEX, &hash.0, &index.encode_bytes())
    }

    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        match self.db.get_cf(CF_BLOCK_DATA, &hash.0)? {
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
        self.db.put_cf(CF_BLOCK_DATA, &hash.0, &bytes)
    }

    /// Atomically write a block header + block data
    pub fn put_block_atomic(&self, hash: &BlockHash, index: &StoredBlockIndex, block: &Block) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.db.batch_put_cf(&mut batch, CF_BLOCK_INDEX, &hash.0, &index.encode_bytes())?;
        self.db.batch_put_cf(&mut batch, CF_BLOCK_DATA, &hash.0, &block.encode_to_vec())?;
        self.db.write_batch(batch)
    }

    pub fn has_block(&self, hash: &BlockHash) -> Result<bool> {
        Ok(self.db.get_cf(CF_BLOCK_DATA, &hash.0)?.is_some())
    }

    pub fn has_index(&self, hash: &BlockHash) -> Result<bool> {
        Ok(self.db.get_cf(CF_BLOCK_INDEX, &hash.0)?.is_some())
    }

    /// Iterate all stored block index entries (sorted by key / hash order, not height).
    /// Call `.sort_by_key(|(_, idx)| idx.height)` on the result before rebuilding ChainState.
    pub fn iter_all_indices(&self) -> Vec<(BlockHash, StoredBlockIndex)> {
        match self.db.iter_cf(CF_BLOCK_INDEX) {
            Ok(iter) => iter
                .filter_map(|(k, v)| {
                    if k.len() != 32 {
                        return None;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&k);
                    let idx = StoredBlockIndex::decode_bytes(&v).ok()?;
                    Some((Hash256(arr), idx))
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    // ── Undo data (spent UTXOs per block, needed for reorg) ───────────────────

    pub fn put_undo(&self, hash: &BlockHash, undo_bytes: &[u8]) -> Result<()> {
        self.db.put_cf(CF_UNDO, &hash.0, undo_bytes)
    }

    pub fn get_undo(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>> {
        self.db.get_cf(CF_UNDO, &hash.0)
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
            if idx.status == 4 {
                continue;
            }
            if self.db.get_cf(CF_BLOCK_DATA, &hash.0)?.is_none() {
                continue;
            }

            // Delete the raw block bytes
            self.db.delete_cf(CF_BLOCK_DATA, &hash.0)?;

            // Update the on-disk status to Pruned (4)
            idx.status = 4; // BlockStatus::Pruned
            self.put_index(&hash, &idx)?;

            count += 1;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::transaction::Transaction;
    use tempfile::TempDir;
    use crate::db::Database;

    #[test]
    fn block_store_put_get_index() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = BlockStore::new(&db);
        let hash: BlockHash = Hash256([1; 32]);
        let index = StoredBlockIndex {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            height: 0,
            chainwork_lo: 1,
            chainwork_hi: 0,
            status: 0,
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
        let hash: BlockHash = Hash256([2; 32]);
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        use rbtc_primitives::script::Script;
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![2, 0, 0]),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                outputs: vec![TxOut { value: 0, script_pubkey: Script::new() }],
                lock_time: 0,
            }],
        };
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
        let hash: BlockHash = Hash256([99; 32]);
        assert!(store.get_index(&hash).unwrap().is_none());
        assert!(store.get_block(&hash).unwrap().is_none());
    }
}
