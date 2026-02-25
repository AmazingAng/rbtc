//! Address (script) index: maps script_pubkey → list of (block_height, tx_offset, txid).
//!
//! Column family: CF_ADDR_INDEX
//!
//! Key layout (variable length, designed for prefix iteration):
//!   [script_len : 1 byte]
//!   [script_pubkey : script_len bytes]
//!   [height    : 4 bytes big-endian]   ← big-endian for lexicographic ordering
//!   [tx_offset : 4 bytes big-endian]
//!
//! Value: txid (32 bytes)
//!
//! To enumerate all transactions touching a given scriptPubKey, issue a
//! prefix scan over the `[script_len][script_pubkey]` prefix.  Entries are
//! returned in ascending (height, tx_offset) order thanks to big-endian
//! encoding.

use rocksdb::WriteBatch;
use rbtc_primitives::hash::Hash256;

use crate::{
    db::{Database, CF_ADDR_INDEX},
    error::{Result, StorageError},
};

/// One entry returned by `iter_by_script`.
#[derive(Debug, Clone)]
pub struct AddrEntry {
    pub height: u32,
    pub tx_offset: u32,
    pub txid: Hash256,
}

pub struct AddrIndexStore<'a> {
    db: &'a Database,
}

impl<'a> AddrIndexStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Record that `txid` (at position `tx_offset` inside block at `height`)
    /// sends output to `script`.
    pub fn put(
        &self,
        script: &[u8],
        height: u32,
        tx_offset: u32,
        txid: &Hash256,
    ) -> Result<()> {
        let key = make_addr_key(script, height, tx_offset);
        self.db.put_cf(CF_ADDR_INDEX, &key, &txid.0)
    }

    /// Return all index entries for `script`, in ascending (height, tx_offset) order.
    pub fn iter_by_script(&self, script: &[u8]) -> Result<Vec<AddrEntry>> {
        let prefix = make_addr_prefix(script);
        let mut entries = Vec::new();

        for (key, value) in self.db.iter_cf_prefix(CF_ADDR_INDEX, &prefix)? {
            if value.len() != 32 {
                return Err(StorageError::Corruption(format!(
                    "addr_index: bad value length {}",
                    value.len()
                )));
            }
            // Decode height + tx_offset from key tail
            let tail_start = prefix.len();
            if key.len() < tail_start + 8 {
                return Err(StorageError::Corruption(
                    "addr_index: key too short".to_string(),
                ));
            }
            let height =
                u32::from_be_bytes(key[tail_start..tail_start + 4].try_into().unwrap());
            let tx_offset =
                u32::from_be_bytes(key[tail_start + 4..tail_start + 8].try_into().unwrap());

            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&value);
            entries.push(AddrEntry {
                height,
                tx_offset,
                txid: Hash256(txid_bytes),
            });
        }

        Ok(entries)
    }

    /// Remove the index entry (used when disconnecting a block during reorg).
    pub fn remove(&self, script: &[u8], height: u32, tx_offset: u32) -> Result<()> {
        let key = make_addr_key(script, height, tx_offset);
        self.db.delete_cf(CF_ADDR_INDEX, &key)
    }

    /// Accumulate a `put` into an externally-owned `WriteBatch`.
    pub fn batch_put(
        &self,
        batch: &mut WriteBatch,
        script: &[u8],
        height: u32,
        tx_offset: u32,
        txid: &Hash256,
    ) -> Result<()> {
        let key = make_addr_key(script, height, tx_offset);
        self.db.batch_put_cf(batch, CF_ADDR_INDEX, &key, &txid.0)
    }

    /// Accumulate a `remove` into an externally-owned `WriteBatch`.
    pub fn batch_remove(
        &self,
        batch: &mut WriteBatch,
        script: &[u8],
        height: u32,
        tx_offset: u32,
    ) -> Result<()> {
        let key = make_addr_key(script, height, tx_offset);
        self.db.batch_delete_cf(batch, CF_ADDR_INDEX, &key)
    }
}

// ── Key helpers ───────────────────────────────────────────────────────────────

/// Build the full key: [script_len(1)][script][height(4BE)][tx_offset(4BE)]
fn make_addr_key(script: &[u8], height: u32, tx_offset: u32) -> Vec<u8> {
    let mut key = make_addr_prefix(script);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&tx_offset.to_be_bytes());
    key
}

/// Prefix used for scanning: [script_len(1)][script]
fn make_addr_prefix(script: &[u8]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(1 + script.len());
    // Cap script_len at 255 (standard scriptPubKeys are well under this limit)
    prefix.push(script.len().min(255) as u8);
    prefix.extend_from_slice(&script[..script.len().min(255)]);
    prefix
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
    fn put_iter_remove() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = AddrIndexStore::new(&db);

        let script = b"\x76\xa9\x14\xde\xad\xbe\xef\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x88\xac";
        let txid1 = make_hash(0x01);
        let txid2 = make_hash(0x02);

        store.put(script, 100, 0, &txid1).unwrap();
        store.put(script, 200, 1, &txid2).unwrap();

        let entries = store.iter_by_script(script).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].height, 100);
        assert_eq!(entries[0].tx_offset, 0);
        assert_eq!(entries[0].txid.0, txid1.0);
        assert_eq!(entries[1].height, 200);
        assert_eq!(entries[1].txid.0, txid2.0);

        store.remove(script, 100, 0).unwrap();
        let entries = store.iter_by_script(script).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].height, 200);
    }

    #[test]
    fn different_scripts_dont_interfere() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = AddrIndexStore::new(&db);

        let script_a = b"\x00\x14\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
        let script_b = b"\x00\x14\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb";

        store.put(script_a, 1, 0, &make_hash(0xaa)).unwrap();
        store.put(script_b, 1, 0, &make_hash(0xbb)).unwrap();

        assert_eq!(store.iter_by_script(script_a).unwrap().len(), 1);
        assert_eq!(store.iter_by_script(script_b).unwrap().len(), 1);
    }

    #[test]
    fn batch_put_batch_remove() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = AddrIndexStore::new(&db);
        let script = b"\x76\xa9\x14\xcc";
        let mut batch = db.new_batch();
        store.batch_put(&mut batch, script, 50, 0, &make_hash(0x50)).unwrap();
        store.batch_put(&mut batch, script, 51, 1, &make_hash(0x51)).unwrap();
        db.write_batch(batch).unwrap();
        assert_eq!(store.iter_by_script(script).unwrap().len(), 2);
        let mut batch2 = db.new_batch();
        store.batch_remove(&mut batch2, script, 50, 0).unwrap();
        db.write_batch(batch2).unwrap();
        assert_eq!(store.iter_by_script(script).unwrap().len(), 1);
    }

    #[test]
    fn iter_by_script_bad_value_length() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        // key = [1][0xdd][height_be][tx_offset_be] = 1+1+4+4 = 10 bytes
        let bad_key = vec![1u8, 0xdd, 0, 0, 0, 100, 0, 0, 0, 0];
        db.put_cf(crate::db::CF_ADDR_INDEX, &bad_key, b"short").unwrap();
        let store = AddrIndexStore::new(&db);
        let r = store.iter_by_script(&[0xdd]);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("bad value length"));
    }

    #[test]
    fn iter_by_script_key_too_short() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        // prefix for script [0xee] is [1][0xee], len 2. key must have at least 2+8=10 bytes.
        let too_short_key = vec![1u8, 0xee, 0, 0]; // only 4 bytes
        db.put_cf(
            crate::db::CF_ADDR_INDEX,
            &too_short_key,
            &[0u8; 32],
        ).unwrap();
        let store = AddrIndexStore::new(&db);
        let r = store.iter_by_script(&[0xee]);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("key too short"));
    }
}
