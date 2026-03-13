use rbtc_primitives::{
    codec::{Decodable, Encodable},
    hash::BlockHash,
};
use rocksdb::WriteBatch;

use crate::{
    db::{Database, CF_CHAIN_STATE},
    error::{Result, StorageError},
};

const KEY_BEST_BLOCK: &[u8] = b"best_block";
const KEY_BEST_HEIGHT: &[u8] = b"best_height";
const KEY_CHAINWORK: &[u8] = b"chainwork";
const KEY_NETWORK: &[u8] = b"network";
const KEY_INDEXED_HEIGHT: &[u8] = b"indexed_height";
/// Bitcoin Core's DB_HEAD_BLOCKS: stores `old_hash || new_hash` (64 bytes)
/// while a block connect/disconnect is in progress.  If present on startup
/// the previous operation was interrupted and we must rewind to `old_hash`.
const KEY_HEAD_BLOCKS: &[u8] = b"head_blocks";
/// UTXO serialisation format version.  Absent = legacy (uncompressed),
/// 1 = Bitcoin Core-compatible compressed (base-128 VARINT + Coin format).
const KEY_UTXO_FORMAT: &[u8] = b"utxo_format";
/// Database schema version key.  Checked on startup to detect whether the
/// database needs migration before it can be used.
const KEY_DB_VERSION: &[u8] = b"db_version";

/// Current UTXO serialisation format version written after (re)index.
pub const UTXO_FORMAT_COMPRESSED: u32 = 1;

/// Current database schema version.  Bump this when the on-disk format changes
/// in a way that requires migration (analogous to Bitcoin Core's `DB_VERSION`
/// check in `NeedsUpgrade()`).
pub const DB_VERSION: u32 = 1;

/// Persists chain state metadata (tip, height, chainwork)
pub struct ChainStore<'db> {
    db: &'db Database,
}

impl<'db> ChainStore<'db> {
    pub fn new(db: &'db Database) -> Self {
        Self { db }
    }

    pub fn get_best_block(&self) -> Result<Option<BlockHash>> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_BEST_BLOCK)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                use rbtc_primitives::hash::Hash256;
                Ok(Some(BlockHash(Hash256(arr))))
            }
            Some(_) => Err(StorageError::Corruption("invalid best block hash".into())),
            None => Ok(None),
        }
    }

    pub fn set_best_block(&self, hash: &BlockHash) -> Result<()> {
        self.db.put_cf(CF_CHAIN_STATE, KEY_BEST_BLOCK, &hash.0.0)
    }

    pub fn get_best_height(&self) -> Result<Option<u32>> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_BEST_HEIGHT)? {
            Some(bytes) => {
                let h = u32::decode_from_slice(&bytes)
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                Ok(Some(h))
            }
            None => Ok(None),
        }
    }

    pub fn set_best_height(&self, height: u32) -> Result<()> {
        let bytes = height.encode_to_vec();
        self.db.put_cf(CF_CHAIN_STATE, KEY_BEST_HEIGHT, &bytes)
    }

    pub fn get_chainwork(&self) -> Result<rbtc_primitives::uint256::U256> {
        use rbtc_primitives::uint256::U256;
        match self.db.get_cf(CF_CHAIN_STATE, KEY_CHAINWORK)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(U256::from_le_bytes(arr))
            }
            // Backward compat: old DBs stored 16 bytes (u128)
            Some(bytes) if bytes.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                Ok(U256::from_u128(u128::from_le_bytes(arr)))
            }
            Some(_) => Err(StorageError::Corruption("invalid chainwork".into())),
            None => Ok(U256::ZERO),
        }
    }

    pub fn set_chainwork(&self, work: &rbtc_primitives::uint256::U256) -> Result<()> {
        self.db
            .put_cf(CF_CHAIN_STATE, KEY_CHAINWORK, &work.to_le_bytes())
    }

    pub fn get_network_magic(&self) -> Result<Option<[u8; 4]>> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_NETWORK)? {
            Some(bytes) if bytes.len() == 4 => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            Some(_) => Err(StorageError::Corruption("invalid network magic".into())),
            None => Ok(None),
        }
    }

    pub fn set_network_magic(&self, magic: &[u8; 4]) -> Result<()> {
        self.db.put_cf(CF_CHAIN_STATE, KEY_NETWORK, magic)
    }

    pub fn get_indexed_height(&self) -> Result<Option<u32>> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_INDEXED_HEIGHT)? {
            Some(bytes) => {
                let h = u32::decode_from_slice(&bytes)
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                Ok(Some(h))
            }
            None => Ok(None),
        }
    }

    pub fn set_indexed_height(&self, height: u32) -> Result<()> {
        self.db
            .put_cf(CF_CHAIN_STATE, KEY_INDEXED_HEIGHT, &height.encode_to_vec())
    }

    pub fn update_indexed_height_batch(&self, batch: &mut WriteBatch, height: u32) -> Result<()> {
        self.db.batch_put_cf(
            batch,
            CF_CHAIN_STATE,
            KEY_INDEXED_HEIGHT,
            &height.encode_to_vec(),
        )
    }

    /// Write the head-blocks marker before starting a block connect/disconnect.
    /// `old_hash` is the current tip; `new_hash` is the tip we are moving to.
    /// If the process crashes while the marker is present, startup must rewind
    /// to `old_hash` (the safe, fully-written state).
    pub fn set_head_blocks(
        &self,
        old_hash: &BlockHash,
        new_hash: &BlockHash,
    ) -> Result<()> {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&old_hash.0 .0);
        buf[32..].copy_from_slice(&new_hash.0 .0);
        self.db.put_cf(CF_CHAIN_STATE, KEY_HEAD_BLOCKS, &buf)
    }

    /// Write the head-blocks marker into an existing WriteBatch.
    pub fn set_head_blocks_batch(
        &self,
        batch: &mut WriteBatch,
        old_hash: &BlockHash,
        new_hash: &BlockHash,
    ) -> Result<()> {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&old_hash.0 .0);
        buf[32..].copy_from_slice(&new_hash.0 .0);
        self.db.batch_put_cf(batch, CF_CHAIN_STATE, KEY_HEAD_BLOCKS, &buf)
    }

    /// Clear the head-blocks marker after a successful connect/disconnect.
    pub fn clear_head_blocks(&self) -> Result<()> {
        self.db.delete_cf(CF_CHAIN_STATE, KEY_HEAD_BLOCKS)
    }

    /// Clear the head-blocks marker inside an existing WriteBatch.
    pub fn clear_head_blocks_batch(&self, batch: &mut WriteBatch) -> Result<()> {
        self.db.batch_delete_cf(batch, CF_CHAIN_STATE, KEY_HEAD_BLOCKS)
    }

    /// Returns `true` if the `HEAD_BLOCKS` marker exists, meaning the previous
    /// shutdown was unclean (crash or kill during a UTXO flush).  The caller
    /// should trigger a reindex of the chainstate when this returns `true`.
    ///
    /// This mirrors Bitcoin Core's startup check: if `DB_HEAD_BLOCKS` is present
    /// in the coins DB, the UTXO set may be inconsistent and must be rebuilt.
    pub fn needs_recovery(&self) -> Result<bool> {
        Ok(self.db.get_cf(CF_CHAIN_STATE, KEY_HEAD_BLOCKS)?.is_some())
    }

    /// Read the head-blocks marker.  Returns `Some((old_tip, new_tip))` if the
    /// previous block connect/disconnect was interrupted.
    pub fn get_head_blocks(&self) -> Result<Option<(BlockHash, BlockHash)>> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_HEAD_BLOCKS)? {
            Some(bytes) if bytes.len() == 64 => {
                let mut old = [0u8; 32];
                let mut new = [0u8; 32];
                old.copy_from_slice(&bytes[..32]);
                new.copy_from_slice(&bytes[32..]);
                use rbtc_primitives::hash::Hash256;
                Ok(Some((BlockHash(Hash256(old)), BlockHash(Hash256(new)))))
            }
            Some(_) => Err(StorageError::Corruption("invalid head_blocks marker".into())),
            None => Ok(None),
        }
    }

    /// Read the database schema version.  `None` means the version key has
    /// never been written (i.e. a very old or fresh database).
    pub fn get_db_version(&self) -> Result<Option<u32>> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_DB_VERSION)? {
            Some(bytes) if bytes.len() == 4 => {
                Ok(Some(u32::from_le_bytes(bytes[..4].try_into().unwrap())))
            }
            Some(_) => Err(StorageError::Corruption("invalid db_version".into())),
            None => Ok(None),
        }
    }

    /// Write the database schema version.
    pub fn set_db_version(&self, version: u32) -> Result<()> {
        self.db
            .put_cf(CF_CHAIN_STATE, KEY_DB_VERSION, &version.to_le_bytes())
    }

    /// Check whether the database needs an upgrade (migration) before it can
    /// be used.  Returns `true` when the stored version is absent or older than
    /// the current [`DB_VERSION`].
    ///
    /// This mirrors Bitcoin Core's `NeedsUpgrade()` check: on startup the node
    /// compares the persisted DB version against the running software's version.
    /// If the DB is behind, the caller must trigger `--reindex-chainstate` (or
    /// an equivalent migration path) before proceeding.
    pub fn needs_upgrade(&self) -> Result<bool> {
        match self.get_db_version()? {
            Some(v) => Ok(v < DB_VERSION),
            None => {
                // No version key at all.  If there is chain data (best_block
                // is set), the database predates versioning and needs upgrade.
                // A completely fresh database does NOT need an upgrade — the
                // caller should simply call `set_db_version(DB_VERSION)`.
                Ok(self.get_best_block()?.is_some())
            }
        }
    }

    /// Read the UTXO serialisation format version.  `None` = legacy (pre-compression).
    pub fn get_utxo_format(&self) -> Result<Option<u32>> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_UTXO_FORMAT)? {
            Some(bytes) if bytes.len() == 4 => {
                Ok(Some(u32::from_le_bytes(bytes[..4].try_into().unwrap())))
            }
            Some(_) => Err(StorageError::Corruption("invalid utxo_format".into())),
            None => Ok(None),
        }
    }

    /// Write the UTXO serialisation format version.
    pub fn set_utxo_format(&self, version: u32) -> Result<()> {
        self.db
            .put_cf(CF_CHAIN_STATE, KEY_UTXO_FORMAT, &version.to_le_bytes())
    }

    /// Atomically update tip + height + chainwork (self-contained batch).
    pub fn update_tip(&self, hash: &BlockHash, height: u32, chainwork: &rbtc_primitives::uint256::U256) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.update_tip_batch(&mut batch, hash, height, chainwork)?;
        self.db.write_batch(batch)
    }

    /// Fill an externally-owned `WriteBatch` with tip/height/chainwork updates.
    pub fn update_tip_batch(
        &self,
        batch: &mut WriteBatch,
        hash: &BlockHash,
        height: u32,
        chainwork: &rbtc_primitives::uint256::U256,
    ) -> Result<()> {
        self.db
            .batch_put_cf(batch, CF_CHAIN_STATE, KEY_BEST_BLOCK, &hash.0.0)?;
        self.db.batch_put_cf(
            batch,
            CF_CHAIN_STATE,
            KEY_BEST_HEIGHT,
            &height.encode_to_vec(),
        )?;
        self.db.batch_put_cf(
            batch,
            CF_CHAIN_STATE,
            KEY_CHAINWORK,
            &chainwork.to_le_bytes(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::uint256::U256;
    use tempfile::TempDir;

    #[test]
    fn chain_store_best_block_height_chainwork() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        assert!(store.get_best_block().unwrap().is_none());
        assert!(store.get_best_height().unwrap().is_none());
        assert_eq!(store.get_chainwork().unwrap(), U256::ZERO);

        let hash: BlockHash = BlockHash(Hash256([1; 32]));
        store.set_best_block(&hash).unwrap();
        store.set_best_height(100).unwrap();
        store.set_chainwork(&U256::from_u64(1000)).unwrap();
        assert_eq!(store.get_best_block().unwrap(), Some(hash));
        assert_eq!(store.get_best_height().unwrap(), Some(100));
        assert_eq!(store.get_chainwork().unwrap(), U256::from_u64(1000));
    }

    #[test]
    fn chain_store_update_tip() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([2; 32]));
        store.update_tip(&hash, 200, &U256::from_u64(2000)).unwrap();
        assert_eq!(store.get_best_block().unwrap(), Some(hash));
        assert_eq!(store.get_best_height().unwrap(), Some(200));
        assert_eq!(store.get_chainwork().unwrap(), U256::from_u64(2000));
    }

    #[test]
    fn chain_store_update_tip_batch() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        let hash: BlockHash = BlockHash(Hash256([3; 32]));
        let mut batch = db.new_batch();
        store
            .update_tip_batch(&mut batch, &hash, 300, &U256::from_u64(3000))
            .unwrap();
        db.write_batch(batch).unwrap();
        assert_eq!(store.get_best_block().unwrap(), Some(hash));
        assert_eq!(store.get_best_height().unwrap(), Some(300));
        assert_eq!(store.get_chainwork().unwrap(), U256::from_u64(3000));
    }

    #[test]
    fn chain_store_invalid_best_block_hash_length() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(crate::db::CF_CHAIN_STATE, b"best_block", b"short")
            .unwrap();
        let store = ChainStore::new(&db);
        let r = store.get_best_block();
        assert!(r.is_err());
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("invalid best block hash"));
    }

    #[test]
    fn chain_store_invalid_chainwork_length() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(crate::db::CF_CHAIN_STATE, b"chainwork", b"x")
            .unwrap();
        let store = ChainStore::new(&db);
        let r = store.get_chainwork();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid chainwork"));
    }

    #[test]
    fn chain_store_invalid_network_magic_length() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(crate::db::CF_CHAIN_STATE, b"network", b"xy")
            .unwrap();
        let store = ChainStore::new(&db);
        let r = store.get_network_magic();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid network magic"));
    }

    #[test]
    fn chain_store_head_blocks_roundtrip() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);

        // Initially no marker
        assert!(store.get_head_blocks().unwrap().is_none());

        let old_tip = BlockHash(Hash256([0xAA; 32]));
        let new_tip = BlockHash(Hash256([0xBB; 32]));

        // Set the marker
        store.set_head_blocks(&old_tip, &new_tip).unwrap();
        let (old, new) = store.get_head_blocks().unwrap().unwrap();
        assert_eq!(old, old_tip);
        assert_eq!(new, new_tip);

        // Clear the marker
        store.clear_head_blocks().unwrap();
        assert!(store.get_head_blocks().unwrap().is_none());
    }

    #[test]
    fn chain_store_head_blocks_batch() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);

        let old_tip = BlockHash(Hash256([0xCC; 32]));
        let new_tip = BlockHash(Hash256([0xDD; 32]));

        // Set via batch
        let mut batch = db.new_batch();
        store.set_head_blocks_batch(&mut batch, &old_tip, &new_tip).unwrap();
        db.write_batch(batch).unwrap();
        assert!(store.get_head_blocks().unwrap().is_some());

        // Clear via batch
        let mut batch = db.new_batch();
        store.clear_head_blocks_batch(&mut batch).unwrap();
        db.write_batch(batch).unwrap();
        assert!(store.get_head_blocks().unwrap().is_none());
    }

    #[test]
    fn chain_store_head_blocks_invalid_length() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_CHAIN_STATE, b"head_blocks", b"short").unwrap();
        let store = ChainStore::new(&db);
        let r = store.get_head_blocks();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid head_blocks"));
    }

    #[test]
    fn needs_recovery_false_on_fresh_db() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        assert!(!store.needs_recovery().unwrap());
    }

    #[test]
    fn needs_recovery_true_after_set_head_blocks() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);

        let old_tip = BlockHash(Hash256([0x11; 32]));
        let new_tip = BlockHash(Hash256([0x22; 32]));
        store.set_head_blocks(&old_tip, &new_tip).unwrap();

        // Marker present => unclean shutdown
        assert!(store.needs_recovery().unwrap());
    }

    #[test]
    fn needs_recovery_false_after_set_then_clear() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);

        let old_tip = BlockHash(Hash256([0x33; 32]));
        let new_tip = BlockHash(Hash256([0x44; 32]));
        store.set_head_blocks(&old_tip, &new_tip).unwrap();
        assert!(store.needs_recovery().unwrap());

        store.clear_head_blocks().unwrap();
        assert!(!store.needs_recovery().unwrap());
    }

    #[test]
    fn needs_recovery_survives_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let db = Database::open(dir.path()).unwrap();
            let store = ChainStore::new(&db);
            let old_tip = BlockHash(Hash256([0x55; 32]));
            let new_tip = BlockHash(Hash256([0x66; 32]));
            store.set_head_blocks(&old_tip, &new_tip).unwrap();
        }
        // Reopen — simulates restart after crash
        {
            let db = Database::open(dir.path()).unwrap();
            let store = ChainStore::new(&db);
            assert!(store.needs_recovery().unwrap());

            // Recovery would clear the marker
            store.clear_head_blocks().unwrap();
            assert!(!store.needs_recovery().unwrap());
        }
    }

    #[test]
    fn chain_store_indexed_height_roundtrip() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        assert_eq!(store.get_indexed_height().unwrap(), None);
        store.set_indexed_height(42).unwrap();
        assert_eq!(store.get_indexed_height().unwrap(), Some(42));
    }

    // ── M9: DB version / needs_upgrade tests ──────────────────────────

    #[test]
    fn db_version_roundtrip() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        assert_eq!(store.get_db_version().unwrap(), None);
        store.set_db_version(1).unwrap();
        assert_eq!(store.get_db_version().unwrap(), Some(1));
        store.set_db_version(2).unwrap();
        assert_eq!(store.get_db_version().unwrap(), Some(2));
    }

    #[test]
    fn needs_upgrade_fresh_db_no_chain_data() {
        // A completely fresh database (no best_block) does NOT need upgrade
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        assert!(!store.needs_upgrade().unwrap());
    }

    #[test]
    fn needs_upgrade_old_db_with_chain_data() {
        // A database that has chain data but no version key needs upgrade
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        store
            .set_best_block(&BlockHash(Hash256([0xEE; 32])))
            .unwrap();
        assert!(store.needs_upgrade().unwrap());
    }

    #[test]
    fn needs_upgrade_false_when_current() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        store
            .set_best_block(&BlockHash(Hash256([0xEE; 32])))
            .unwrap();
        store.set_db_version(super::DB_VERSION).unwrap();
        assert!(!store.needs_upgrade().unwrap());
    }

    #[test]
    fn needs_upgrade_true_when_behind() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = ChainStore::new(&db);
        store
            .set_best_block(&BlockHash(Hash256([0xEE; 32])))
            .unwrap();
        // Simulate an older version
        store.set_db_version(0).unwrap();
        assert!(store.needs_upgrade().unwrap());
    }

    #[test]
    fn needs_upgrade_survives_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let db = Database::open(dir.path()).unwrap();
            let store = ChainStore::new(&db);
            store
                .set_best_block(&BlockHash(Hash256([0xFF; 32])))
                .unwrap();
            // Don't set version — simulates old database
        }
        {
            let db = Database::open(dir.path()).unwrap();
            let store = ChainStore::new(&db);
            assert!(store.needs_upgrade().unwrap());
            // "Perform upgrade" by setting version
            store.set_db_version(super::DB_VERSION).unwrap();
            assert!(!store.needs_upgrade().unwrap());
        }
    }

    #[test]
    fn db_version_invalid_length_is_corruption() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        db.put_cf(CF_CHAIN_STATE, b"db_version", b"xy").unwrap();
        let store = ChainStore::new(&db);
        let r = store.get_db_version();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid db_version"));
    }
}
