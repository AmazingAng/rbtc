use rocksdb::{
    checkpoint::Checkpoint, ColumnFamily, ColumnFamilyDescriptor, FlushOptions, IteratorMode,
    Options, WriteBatch, WriteOptions, DB,
};
use std::path::Path;

use crate::error::{Result, StorageError};

/// Key under which the obfuscation key is stored (in default CF).
/// Matches Bitcoin Core's `\000obfuscate_key`.
const OBFUSCATE_KEY_KEY: &[u8] = b"\x00obfuscate_key";

/// Length of the obfuscation key (matches Bitcoin Core's 8 bytes).
const OBFUSCATE_KEY_LEN: usize = 8;

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
/// AddrMan metadata: key = "secret_key", value = 32 bytes
pub const CF_ADDRMAN_META: &str = "addrman_meta";
/// BIP157 compact block filters: key = filter_type(1) || block_hash(32), value = filter bytes
pub const CF_BLOCK_FILTERS: &str = "block_filters";
/// BIP157 filter headers: key = filter_type(1) || block_hash(32), value = filter header (32 bytes)
pub const CF_FILTER_HEADERS: &str = "filter_headers";

/// All column family names, used for bulk operations (flush, compaction, etc.).
const ALL_CFS: &[&str] = &[
    CF_BLOCK_INDEX,
    CF_UTXO,
    CF_CHAIN_STATE,
    CF_BLOCK_DATA,
    CF_TX_INDEX,
    CF_ADDR_INDEX,
    CF_UNDO,
    CF_WALLET,
    CF_PEER_BANS,
    CF_PEER_ADDRS,
    CF_HEIGHT_INDEX,
    CF_ADDRMAN_META,
    CF_BLOCK_FILTERS,
    CF_FILTER_HEADERS,
];

/// Wrapper around RocksDB with Bitcoin-specific column families.
///
/// All values in column families are XOR-obfuscated with a random 8-byte key
/// (matching Bitcoin Core's `CDBWrapper` obfuscation). The key is generated on
/// first open and persisted in the default column family under `\000obfuscate_key`.
pub struct Database {
    db: DB,
    /// 8-byte XOR obfuscation key (all zeros = no obfuscation, for tests).
    obfuscate_key: [u8; OBFUSCATE_KEY_LEN],
}

impl Database {
    /// Open (or create) the database at the given path.
    ///
    /// On first open, generates a random 8-byte obfuscation key and persists it.
    /// On subsequent opens, reads the existing key.
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
            ColumnFamilyDescriptor::new(CF_ADDRMAN_META, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;

        // Read or create the obfuscation key (stored unobfuscated in default CF).
        let obfuscate_key = match db.get(OBFUSCATE_KEY_KEY).map_err(StorageError::Rocks)? {
            Some(existing) if existing.len() == OBFUSCATE_KEY_LEN => {
                let mut key = [0u8; OBFUSCATE_KEY_LEN];
                key.copy_from_slice(&existing);
                key
            }
            _ => {
                // Generate a new key using system entropy.
                let mut key = [0u8; OBFUSCATE_KEY_LEN];
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let pid = std::process::id() as u128;
                let combined = seed ^ (pid << 64);
                key.copy_from_slice(&combined.to_le_bytes()[..OBFUSCATE_KEY_LEN]);
                db.put(OBFUSCATE_KEY_KEY, &key)
                    .map_err(StorageError::Rocks)?;
                key
            }
        };

        Ok(Self { db, obfuscate_key })
    }

    /// Open without obfuscation (for tests that need deterministic values).
    #[cfg(test)]
    pub fn open_unobfuscated(path: &Path) -> Result<Self> {
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
            ColumnFamilyDescriptor::new(CF_ADDRMAN_META, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self {
            db,
            obfuscate_key: [0u8; OBFUSCATE_KEY_LEN],
        })
    }

    /// XOR-obfuscate/deobfuscate a value in-place using the rotating key.
    fn xor_obfuscate(&self, data: &mut [u8]) {
        if self.obfuscate_key == [0u8; OBFUSCATE_KEY_LEN] {
            return;
        }
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.obfuscate_key[i % OBFUSCATE_KEY_LEN];
        }
    }

    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(cf_name)?;
        match self.db.get_cf(cf, key).map_err(StorageError::Rocks)? {
            Some(mut v) => {
                self.xor_obfuscate(&mut v);
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    pub fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        let mut obf = value.to_vec();
        self.xor_obfuscate(&mut obf);
        self.db.put_cf(cf, key, &obf).map_err(StorageError::Rocks)
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

    pub fn batch_put_cf(
        &self,
        batch: &mut WriteBatch,
        cf_name: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let cf = self.cf(cf_name)?;
        let mut obf = value.to_vec();
        self.xor_obfuscate(&mut obf);
        batch.put_cf(cf, key, &obf);
        Ok(())
    }

    pub fn batch_delete_cf(&self, batch: &mut WriteBatch, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        batch.delete_cf(cf, key);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn iter_cf(
        &self,
        cf_name: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self.cf(cf_name)?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item.map_err(StorageError::Rocks)?;
            let mut val = v.to_vec();
            self.xor_obfuscate(&mut val);
            result.push((k.to_vec(), val));
        }
        Ok(result)
    }

    /// Iterate all entries whose key starts with `prefix`, in lexicographic order.
    /// Returns a collected `Vec` so the borrow on `self` is not held across await points.
    pub fn iter_cf_prefix(&self, cf_name: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self.cf(cf_name)?;
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(prefix, rocksdb::Direction::Forward));
        let mut result = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(StorageError::Rocks)?;
            if !k.starts_with(prefix) {
                break;
            }
            let mut val = v.to_vec();
            self.xor_obfuscate(&mut val);
            result.push((k.to_vec(), val));
        }
        Ok(result)
    }

    fn cf(&self, name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::Corruption(format!("column family '{name}' not found")))
    }

    /// Delete all keys in `[from, to)` for the given column family.
    /// Uses RocksDB's efficient range-deletion tombstone.
    pub fn delete_range_cf(&self, cf_name: &str, from: &[u8], to: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        let mut batch = WriteBatch::default();
        batch.delete_range_cf(cf, from, to);
        self.db.write(batch).map_err(StorageError::Rocks)
    }

    /// Flush all column-family memtables (plus the default CF) to SST files on disk.
    ///
    /// This ensures all in-memory data is persisted, which is a prerequisite for
    /// consistent snapshots across column families.
    pub fn flush(&self) -> Result<()> {
        // Flush the default column family first.
        self.db.flush().map_err(StorageError::Rocks)?;
        // Flush every named column family.
        let flush_opts = FlushOptions::default();
        for cf_name in ALL_CFS {
            let cf = self.cf(cf_name)?;
            self.db
                .flush_cf_opt(cf, &flush_opts)
                .map_err(StorageError::Rocks)?;
        }
        Ok(())
    }

    /// Force-sync the Write-Ahead Log to disk.
    ///
    /// After this call returns, all data that was written to the WAL is durable
    /// even in the event of a power failure.
    pub fn sync_wal(&self) -> Result<()> {
        self.db.flush_wal(true).map_err(StorageError::Rocks)
    }

    /// Create an atomic point-in-time checkpoint of the entire database at `path`.
    ///
    /// The checkpoint directory must not already exist.  The resulting snapshot
    /// is consistent across all column families — it can be opened as a
    /// standalone RocksDB database for backup or analysis.
    pub fn create_checkpoint(&self, path: &str) -> Result<()> {
        let cp = Checkpoint::new(&self.db).map_err(StorageError::Rocks)?;
        cp.create_checkpoint(path).map_err(StorageError::Rocks)
    }

    /// Convenience: flush every column family, then sync the WAL.
    ///
    /// This is the recommended call before taking a filesystem-level snapshot
    /// or before graceful shutdown.
    pub fn flush_and_sync(&self) -> Result<()> {
        self.flush()?;
        self.sync_wal()
    }

    /// Trigger a manual full compaction for the named column family.
    ///
    /// Passing `None` for both start and end compacts the entire key range.
    /// This is expensive and should only be used during maintenance windows.
    pub fn compact_range(&self, cf_name: &str) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db
            .compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
        Ok(())
    }

    /// Write a `WriteBatch` with WAL sync enabled (durability on every write).
    ///
    /// This is slower than [`write_batch`](Self::write_batch) but guarantees
    /// that the data is on stable storage when the call returns.
    pub fn write_batch_sync(&self, batch: WriteBatch) -> Result<()> {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .map_err(StorageError::Rocks)
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
        assert_eq!(
            db.get_cf(CF_BLOCK_INDEX, b"key1").unwrap(),
            Some(b"val1".to_vec())
        );
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

    #[test]
    fn obfuscation_key_persists_across_opens() {
        let dir = TempDir::new().unwrap();
        let key1;
        {
            let db = Database::open(dir.path()).unwrap();
            key1 = db.obfuscate_key;
            // Key should be non-zero (with overwhelming probability).
            assert_ne!(key1, [0u8; OBFUSCATE_KEY_LEN]);
            db.put_cf(CF_UTXO, b"test", b"hello").unwrap();
        }
        {
            let db = Database::open(dir.path()).unwrap();
            assert_eq!(db.obfuscate_key, key1, "key should persist");
            assert_eq!(
                db.get_cf(CF_UTXO, b"test").unwrap(),
                Some(b"hello".to_vec())
            );
        }
    }

    #[test]
    fn flush_succeeds() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_BLOCK_INDEX, b"fk1", b"fv1").unwrap();
        db.put_cf(CF_UTXO, b"fk2", b"fv2").unwrap();
        db.put_cf(CF_CHAIN_STATE, b"fk3", b"fv3").unwrap();
        // flush all CFs — should not error
        db.flush().unwrap();
        // data should still be readable after flush
        assert_eq!(
            db.get_cf(CF_BLOCK_INDEX, b"fk1").unwrap(),
            Some(b"fv1".to_vec())
        );
    }

    #[test]
    fn flush_and_sync_succeeds() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_UTXO, b"sk1", b"sv1").unwrap();
        db.put_cf(CF_BLOCK_DATA, b"sk2", b"sv2").unwrap();
        db.flush_and_sync().unwrap();
        assert_eq!(
            db.get_cf(CF_UTXO, b"sk1").unwrap(),
            Some(b"sv1".to_vec())
        );
    }

    #[test]
    fn write_batch_sync_persists() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let mut batch = db.new_batch();
        db.batch_put_cf(&mut batch, CF_UTXO, b"bs1", b"bv1")
            .unwrap();
        db.batch_put_cf(&mut batch, CF_BLOCK_INDEX, b"bs2", b"bv2")
            .unwrap();
        db.write_batch_sync(batch).unwrap();
        assert_eq!(
            db.get_cf(CF_UTXO, b"bs1").unwrap(),
            Some(b"bv1".to_vec())
        );
        assert_eq!(
            db.get_cf(CF_BLOCK_INDEX, b"bs2").unwrap(),
            Some(b"bv2".to_vec())
        );
    }

    #[test]
    fn create_checkpoint_creates_dir() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_UTXO, b"cpk", b"cpv").unwrap();
        let cp_path = dir.path().join("my_checkpoint");
        db.create_checkpoint(cp_path.to_str().unwrap()).unwrap();
        assert!(cp_path.exists(), "checkpoint directory should exist");
        assert!(cp_path.is_dir(), "checkpoint should be a directory");
    }

    #[test]
    fn obfuscation_xors_on_disk() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let plaintext = b"secret_data_1234";
        db.put_cf(CF_UTXO, b"key", plaintext).unwrap();
        // Read raw bytes from RocksDB bypassing deobfuscation.
        let cf = db.cf(CF_UTXO).unwrap();
        let raw = db.db.get_cf(cf, b"key").unwrap().unwrap();
        if db.obfuscate_key != [0u8; OBFUSCATE_KEY_LEN] {
            assert_ne!(&raw[..], plaintext, "on-disk value must be obfuscated");
        }
        // But get_cf should return the original plaintext.
        assert_eq!(
            db.get_cf(CF_UTXO, b"key").unwrap(),
            Some(plaintext.to_vec())
        );
    }
}
