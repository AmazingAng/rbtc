use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;

use crate::error::{Result, StorageError};

/// Column family names
pub const CF_BLOCK_INDEX: &str = "block_index";
pub const CF_UTXO: &str = "utxo";
pub const CF_CHAIN_STATE: &str = "chain_state";
pub const CF_BLOCK_DATA: &str = "block_data";
pub const CF_TX_INDEX: &str = "tx_index";

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
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .filter_map(|item| item.ok());
        Ok(iter)
    }

    fn cf(&self, name: &str) -> Result<&ColumnFamily> {
        self.db.cf_handle(name).ok_or_else(|| {
            StorageError::Corruption(format!("column family '{name}' not found"))
        })
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush().map_err(StorageError::Rocks)
    }
}
