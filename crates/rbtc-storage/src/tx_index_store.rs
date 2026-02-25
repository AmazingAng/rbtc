//! Transaction index: maps txid → (block_hash, tx_offset_in_block).
//!
//! Column family: CF_TX_INDEX
//! Key  : txid          (32 bytes)
//! Value: block_hash    (32 bytes)
//!        + tx_offset   (4 bytes little-endian)
//!        = 36 bytes total

use rocksdb::WriteBatch;
use rbtc_primitives::hash::Hash256;

use crate::{
    db::{Database, CF_TX_INDEX},
    error::{Result, StorageError},
};

pub struct TxIndexStore<'a> {
    db: &'a Database,
}

impl<'a> TxIndexStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Index a transaction: `txid` lives in `block_hash` at position `tx_offset`.
    pub fn put(&self, txid: &Hash256, block_hash: &Hash256, tx_offset: u32) -> Result<()> {
        let key = txid.0;
        let mut value = [0u8; 36];
        value[..32].copy_from_slice(&block_hash.0);
        value[32..].copy_from_slice(&tx_offset.to_le_bytes());
        self.db.put_cf(CF_TX_INDEX, &key, &value)
    }

    /// Look up a txid. Returns `(block_hash, tx_offset)` if found.
    pub fn get(&self, txid: &Hash256) -> Result<Option<(Hash256, u32)>> {
        match self.db.get_cf(CF_TX_INDEX, &txid.0)? {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != 36 {
                    return Err(StorageError::Corruption(format!(
                        "tx_index: bad value length {} for txid {}",
                        bytes.len(),
                        txid.to_hex()
                    )));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&bytes[..32]);
                let offset = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
                Ok(Some((Hash256(hash_bytes), offset)))
            }
        }
    }

    /// Remove the index entry for `txid` (used during chain reorganization).
    pub fn remove(&self, txid: &Hash256) -> Result<()> {
        self.db.delete_cf(CF_TX_INDEX, &txid.0)
    }

    /// Accumulate a `put` into an externally-owned `WriteBatch`.
    pub fn batch_put(
        &self,
        batch: &mut WriteBatch,
        txid: &Hash256,
        block_hash: &Hash256,
        tx_offset: u32,
    ) -> Result<()> {
        let key = txid.0;
        let mut value = [0u8; 36];
        value[..32].copy_from_slice(&block_hash.0);
        value[32..].copy_from_slice(&tx_offset.to_le_bytes());
        self.db.batch_put_cf(batch, CF_TX_INDEX, &key, &value)
    }

    /// Accumulate a `remove` into an externally-owned `WriteBatch`.
    pub fn batch_remove(&self, batch: &mut WriteBatch, txid: &Hash256) -> Result<()> {
        self.db.batch_delete_cf(batch, CF_TX_INDEX, &txid.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::db::Database;

    fn make_hash(b: u8) -> Hash256 {
        Hash256([b; 32])
    }

    #[test]
    fn put_get_remove() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = TxIndexStore::new(&db);

        let txid = make_hash(0xaa);
        let block_hash = make_hash(0xbb);

        assert!(store.get(&txid).unwrap().is_none());
        store.put(&txid, &block_hash, 3).unwrap();

        let (got_hash, got_offset) = store.get(&txid).unwrap().unwrap();
        assert_eq!(got_hash.0, block_hash.0);
        assert_eq!(got_offset, 3);

        store.remove(&txid).unwrap();
        assert!(store.get(&txid).unwrap().is_none());
    }
}
