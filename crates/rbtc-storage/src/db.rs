use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use std::path::Path;

use crate::error::{Result, StorageError};

/// Column family names
pub const CF_BLOCK_INDEX: &str = "block_index";
pub const CF_UTXO: &str = "utxo";
pub const CF_CHAIN_STATE: &str = "chain_state";
pub const CF_BLOCK_DATA: &str = "block_data";
pub const CF_TX_INDEX: &str = "tx_index";
pub const CF_ADDR_INDEX: &str = "addr_index";
pub const CF_UNDO: &str = "undo";
pub const CF_WALLET: &str = "wallet";
/// Peer ban list: key = IP bytes (4 or 16), value = expiry Unix timestamp (u64 LE)
pub const CF_PEER_BANS: &str = "peer_bans";
/// Peer address book: key = IP:port (18 bytes), value = last_seen u64 LE + services u64 LE
pub const CF_PEER_ADDRS: &str = "peer_addrs";
/// Height-to-hash index: key = height (4 bytes LE), value = block hash (32 bytes)
pub const CF_HEIGHT_INDEX: &str = "height_index";
/// BIP157 compact block filters: key = filter_type(1) || block_hash(32), value = filter bytes
pub const CF_BLOCK_FILTERS: &str = "block_filters";
/// BIP157 filter headers: key = filter_type(1) || block_hash(32), value = filter header (32 bytes)
pub const CF_FILTER_HEADERS: &str = "filter_headers";

/// Wrapper around RocksDB with Bitcoin-specific column families
pub struct Database {
    db: DB,
}

impl Database {
    /// Open (or create) the database at the given path
    pub fn open(path: &Path) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCK_INDEX, Options::default()),
            ColumnFamilyDescriptor::new(CF_UTXO, Options::default()),
            ColumnFamilyDescriptor::new(CF_CHAIN_STATE, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCK_DATA, Options::default()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX, Options::default()),
            ColumnFamilyDescriptor::new(CF_ADDR_INDEX, Options::default()),
            ColumnFamilyDescriptor::new(CF_UNDO, Options::default()),
            ColumnFamilyDescriptor::new(CF_WALLET, Options::default()),
            ColumnFamilyDescriptor::new(CF_PEER_BANS, Options::default()),
            ColumnFamilyDescriptor::new(CF_PEER_ADDRS, Options::default()),
            ColumnFamilyDescriptor::new(CF_HEIGHT_INDEX, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCK_FILTERS, Options::default()),
            ColumnFamilyDescriptor::new(CF_FILTER_HEADERS, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db })
    }

    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(cf_name)?;
        self.db.get_cf(cf, key).map_err(StorageError::Rocks)
    }

    pub fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db.put_cf(cf, key, value).map_err(StorageError::Rocks)
    }

    pub fn delete_cf(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db.delete_cf(cf, key).map_err(StorageError::Rocks)
    }

    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        self.db.write(batch).map_err(StorageError::Rocks)
    }

    pub fn new_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    pub fn batch_put_cf(&self, batch: &mut WriteBatch, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        batch.put_cf(cf, key, value);
        Ok(())
    }

    pub fn batch_delete_cf(&self, batch: &mut WriteBatch, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        batch.delete_cf(cf, key);
        Ok(())
    }

    pub fn iter_cf(&self, cf_name: &str) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_> {
        let cf = self.cf(cf_name)?;
        let iter = self.db
            .iterator_cf(cf, IteratorMode::Start)
            .filter_map(|item| item.ok());
        Ok(iter)
    }

    /// Iterate all entries whose key starts with `prefix`, in lexicographic order.
    /// Returns a collected `Vec` so the borrow on `self` is not held across await points.
    pub fn iter_cf_prefix(&self, cf_name: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self.cf(cf_name)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, rocksdb::Direction::Forward));
        let mut result = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(StorageError::Rocks)?;
            if !k.starts_with(prefix) {
                break;
            }
            result.push((k.to_vec(), v.to_vec()));
        }
        Ok(result)
    }

    fn cf(&self, name: &str) -> Result<&ColumnFamily> {
        self.db.cf_handle(name).ok_or_else(|| {
            StorageError::Corruption(format!("column family '{name}' not found"))
        })
    }

    /// Delete all keys in `[from, to)` for the given column family.
    /// Uses RocksDB's efficient range-deletion tombstone.
    pub fn delete_range_cf(&self, cf_name: &str, from: &[u8], to: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        let mut batch = WriteBatch::default();
        batch.delete_range_cf(cf, from, to);
        self.db.write(batch).map_err(StorageError::Rocks)
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush().map_err(StorageError::Rocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn db_open_put_get_delete() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_BLOCK_INDEX, b"key1", b"val1").unwrap();
        assert_eq!(db.get_cf(CF_BLOCK_INDEX, b"key1").unwrap(), Some(b"val1".to_vec()));
        db.delete_cf(CF_BLOCK_INDEX, b"key1").unwrap();
        assert_eq!(db.get_cf(CF_BLOCK_INDEX, b"key1").unwrap(), None);
    }

    #[test]
    fn db_write_batch() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let mut batch = db.new_batch();
        db.batch_put_cf(&mut batch, CF_UTXO, b"k", b"v").unwrap();
        db.write_batch(batch).unwrap();
        assert_eq!(db.get_cf(CF_UTXO, b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn db_invalid_cf() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let r = db.get_cf("no_such_cf", b"x");
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), StorageError::Corruption(_)));
    }

    #[test]
    fn db_iter_cf_prefix() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_UTXO, b"aa\x00\x01", b"v1").unwrap();
        db.put_cf(CF_UTXO, b"aa\x00\x02", b"v2").unwrap();
        db.put_cf(CF_UTXO, b"ab\x00\x00", b"v3").unwrap();
        let rows = db.iter_cf_prefix(CF_UTXO, b"aa").unwrap();
        assert_eq!(rows.len(), 2);
        let rows_ab = db.iter_cf_prefix(CF_UTXO, b"ab").unwrap();
        assert_eq!(rows_ab.len(), 1);
    }

    #[test]
    fn db_delete_range_cf() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_UTXO, b"r1", b"v1").unwrap();
        db.put_cf(CF_UTXO, b"r2", b"v2").unwrap();
        db.put_cf(CF_UTXO, b"r3", b"v3").unwrap();
        db.delete_range_cf(CF_UTXO, b"r1", b"r3").unwrap();
        assert!(db.get_cf(CF_UTXO, b"r1").unwrap().is_none());
        assert!(db.get_cf(CF_UTXO, b"r2").unwrap().is_none());
        assert_eq!(db.get_cf(CF_UTXO, b"r3").unwrap(), Some(b"v3".to_vec()));
    }
}
