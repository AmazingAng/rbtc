use std::io::{self, Read, Write};
use std::path::Path;

use rbtc_primitives::codec::{Encodable, VarInt};
use rbtc_primitives::hash::{BlockHash, Hash256, Txid};
use rbtc_primitives::script::Script;
use rbtc_primitives::transaction::OutPoint;

use crate::chain_store::ChainStore;
use crate::db::{Database, CF_CHAIN_STATE, CF_UTXO};
use crate::error::{Result, StorageError};
use crate::utxo_store::{StoredUtxo, UtxoStore};

/// File magic bytes identifying a UTXO snapshot (matches Bitcoin Core's
/// `SNAPSHOT_MAGIC_BYTES` = {'u','t','x','o', 0xff}, 5 bytes).
const SNAPSHOT_MAGIC: [u8; 5] = [0x75, 0x74, 0x78, 0x6f, 0xff];

/// Legacy 5-byte magic used in older rbtc snapshots before aligning with
/// Bitcoin Core v28+ (`"utxo\0"`).  Accepted on load for backward compat.
const SNAPSHOT_MAGIC_V2_LEGACY: [u8; 5] = *b"utxo\0";

/// Legacy 4-byte magic used in snapshot format version 1.
const SNAPSHOT_MAGIC_V1: [u8; 4] = *b"UTXO";

/// Current snapshot format version.
///
/// - Version 1: original format (4-byte magic "UTXO").
/// - Version 2: 5-byte magic "utxo\xff" (matching Bitcoin Core v28+), adds a
///   32-byte metadata hash after the header fields.
/// - Version 3: adds 8-byte `total_amount` field after `num_utxos`.
///   The metadata hash now includes `total_amount` as well.
const SNAPSHOT_VERSION: u16 = 3;

/// Metadata extracted from (or written into) a snapshot file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMetadata {
    pub block_hash: BlockHash,
    pub height: u32,
    pub num_utxos: u64,
    /// Sum of all UTXO values in satoshis (version 3+).
    /// `None` for snapshots written before total_amount tracking.
    pub total_amount: Option<u64>,
    /// SHA256d of the header metadata fields (version 2 only).
    /// `None` for version-1 snapshots.
    pub metadata_hash: Option<Hash256>,
}

/// Write a UTXO snapshot of the current database state to `path`.
///
/// The snapshot captures all entries in `CF_UTXO` along with the chain tip
/// from `CF_CHAIN_STATE`.  A trailing SHA256d checksum protects against
/// corruption.
pub fn write_snapshot(db: &Database, path: &Path, network_magic: [u8; 4]) -> Result<SnapshotMetadata> {
    let chain = ChainStore::new(db);
    let block_hash = chain
        .get_best_block()?
        .ok_or_else(|| StorageError::Corruption("no best block in chain state".into()))?;
    let height = chain
        .get_best_height()?
        .ok_or_else(|| StorageError::Corruption("no best height in chain state".into()))?;

    let utxo_store = UtxoStore::new(db);
    let utxos = utxo_store.iter_all();

    let file = std::fs::File::create(path)
        .map_err(|e| StorageError::Decode(format!("cannot create snapshot file: {e}")))?;
    let mut w = io::BufWriter::new(file);

    let mut hasher = Sha256dWriter::new();

    // Header (version 2: 5-byte magic)
    write_both(&mut w, &mut hasher, &SNAPSHOT_MAGIC)?;
    write_both(&mut w, &mut hasher, &SNAPSHOT_VERSION.to_le_bytes())?;
    write_both(&mut w, &mut hasher, &network_magic)?;
    write_both(&mut w, &mut hasher, &block_hash.0 .0)?;
    write_both(&mut w, &mut hasher, &height.to_le_bytes())?;
    let num_utxos = utxos.len() as u64;
    write_both(&mut w, &mut hasher, &num_utxos.to_le_bytes())?;

    // Version 3: accumulate total UTXO value
    let total_amount: u64 = utxos
        .iter()
        .map(|(_, utxo)| utxo.value as u64)
        .sum();
    write_both(&mut w, &mut hasher, &total_amount.to_le_bytes())?;

    // Metadata hash = SHA256d(network_magic || block_hash || height || num_utxos || total_amount)
    let metadata_hash = {
        let mut meta_buf = Vec::new();
        meta_buf.extend_from_slice(&network_magic);
        meta_buf.extend_from_slice(&block_hash.0 .0);
        meta_buf.extend_from_slice(&height.to_le_bytes());
        meta_buf.extend_from_slice(&num_utxos.to_le_bytes());
        meta_buf.extend_from_slice(&total_amount.to_le_bytes());
        rbtc_crypto::sha256d(&meta_buf)
    };
    write_both(&mut w, &mut hasher, &metadata_hash.0)?;

    // UTXO entries
    for (outpoint, utxo) in &utxos {
        write_utxo_entry(&mut w, &mut hasher, outpoint, utxo)?;
    }

    // Checksum: SHA256d of everything before this point
    let checksum = hasher.finish();
    w.write_all(&checksum.0)
        .map_err(|e| StorageError::Decode(format!("write error: {e}")))?;
    w.flush()
        .map_err(|e| StorageError::Decode(format!("flush error: {e}")))?;

    Ok(SnapshotMetadata {
        block_hash,
        height,
        num_utxos,
        total_amount: Some(total_amount),
        metadata_hash: Some(metadata_hash),
    })
}

/// Load a UTXO snapshot from `path` into the database.
///
/// Validates magic, version, network, and checksum.  Clears `CF_UTXO` and
/// `CF_CHAIN_STATE` before bulk-loading, then sets the chain tip to the
/// snapshot's block.
pub fn load_snapshot(db: &Database, path: &Path, expected_network: [u8; 4]) -> Result<SnapshotMetadata> {
    let meta = validate_snapshot(path)?;

    // Verify network
    let file = std::fs::File::open(path)
        .map_err(|e| StorageError::Decode(format!("cannot open snapshot: {e}")))?;
    let mut r = io::BufReader::new(file);

    // Detect magic size: v1 uses 4 bytes ("UTXO"), v2+ uses 5 bytes ("utxo\xff" or legacy "utxo\0")
    let mut magic5 = [0u8; 5];
    r.read_exact(&mut magic5).map_err(read_err)?;

    let is_v2_magic = magic5 == SNAPSHOT_MAGIC || magic5 == SNAPSHOT_MAGIC_V2_LEGACY;
    let is_v1_magic = magic5[..4] == SNAPSHOT_MAGIC_V1;

    // Read version bytes — for v1 magic we already consumed one extra byte
    let version_val = if is_v2_magic {
        let mut version = [0u8; 2];
        r.read_exact(&mut version).map_err(read_err)?;
        u16::from_le_bytes(version)
    } else if is_v1_magic {
        // The 5th byte we read is actually the first byte of the version field
        let mut version_byte2 = [0u8; 1];
        r.read_exact(&mut version_byte2).map_err(read_err)?;
        u16::from_le_bytes([magic5[4], version_byte2[0]])
    } else {
        return Err(StorageError::Decode(format!(
            "invalid snapshot magic: {:?}",
            &magic5
        )));
    };

    let mut network = [0u8; 4];
    r.read_exact(&mut network).map_err(read_err)?;
    if network != expected_network {
        return Err(StorageError::Decode(format!(
            "network mismatch: expected {:?}, got {:?}",
            expected_network, network
        )));
    }

    let mut hash_bytes = [0u8; 32];
    r.read_exact(&mut hash_bytes).map_err(read_err)?;

    let mut height_bytes = [0u8; 4];
    r.read_exact(&mut height_bytes).map_err(read_err)?;
    let _height = u32::from_le_bytes(height_bytes);

    let mut num_utxos_bytes = [0u8; 8];
    r.read_exact(&mut num_utxos_bytes).map_err(read_err)?;
    let num_utxos = u64::from_le_bytes(num_utxos_bytes);

    // Version 3+: read total_amount
    let mut total_amount_bytes = [0u8; 8];
    let stored_total_amount = if version_val >= 3 {
        r.read_exact(&mut total_amount_bytes).map_err(read_err)?;
        Some(u64::from_le_bytes(total_amount_bytes))
    } else {
        None
    };

    // Version 2+: read and verify metadata hash
    if version_val >= 2 {
        let mut stored_meta_hash = [0u8; 32];
        r.read_exact(&mut stored_meta_hash).map_err(read_err)?;
        // Recompute expected metadata hash
        let mut meta_buf = Vec::new();
        meta_buf.extend_from_slice(&network);
        meta_buf.extend_from_slice(&hash_bytes);
        meta_buf.extend_from_slice(&height_bytes);
        meta_buf.extend_from_slice(&num_utxos_bytes);
        if version_val >= 3 {
            meta_buf.extend_from_slice(&total_amount_bytes);
        }
        let expected_hash = rbtc_crypto::sha256d(&meta_buf);
        if stored_meta_hash != expected_hash.0 {
            return Err(StorageError::Decode(
                "snapshot metadata hash mismatch".into(),
            ));
        }
    }

    // Bulk-load UTXOs in batches and accumulate total for validation
    let batch_size = 10_000u64;
    let mut batch = db.new_batch();
    let mut count = 0u64;
    let mut loaded_total: u64 = 0;

    for _ in 0..num_utxos {
        let (outpoint, utxo) = read_utxo_entry(&mut r)?;
        loaded_total += utxo.value as u64;
        let key = utxo_key(&outpoint);
        db.batch_put_cf(&mut batch, CF_UTXO, &key, &utxo.encode_value())?;
        count += 1;
        if count % batch_size == 0 {
            db.write_batch(batch)?;
            batch = db.new_batch();
        }
    }
    if count % batch_size != 0 {
        db.write_batch(batch)?;
    }

    // Validate total_amount if present in the snapshot
    if let Some(expected) = stored_total_amount {
        if loaded_total != expected {
            return Err(StorageError::Decode(format!(
                "snapshot total_amount mismatch: header says {}, loaded UTXOs sum to {}",
                expected, loaded_total
            )));
        }
    }

    // Set chain tip
    let chain = ChainStore::new(db);
    chain.set_best_block(&meta.block_hash)?;
    chain.set_best_height(meta.height)?;

    // Store snapshot metadata marker
    db.put_cf(CF_CHAIN_STATE, b"snapshot_base", &hash_bytes)?;

    Ok(meta)
}

/// Validate a snapshot file: check magic, version, and SHA256d checksum.
/// Returns the metadata on success.
///
/// Supports version 1 (4-byte magic "UTXO"), version 2+ with current magic
/// "utxo\xff", and legacy "utxo\0" (pre-v28 alignment).
pub fn validate_snapshot(path: &Path) -> Result<SnapshotMetadata> {
    let data = std::fs::read(path)
        .map_err(|e| StorageError::Decode(format!("cannot read snapshot: {e}")))?;

    // Minimum: magic(4) + version(2) + network(4) + hash(32) + height(4) + num_utxos(8) + checksum(32) = 86
    if data.len() < 86 {
        return Err(StorageError::Decode("snapshot file too short".into()));
    }

    // Detect magic: try v2 (5 bytes) first, then v1 (4 bytes)
    let (_magic_len, version, version_offset) = if data.len() >= 5 && (data[0..5] == SNAPSHOT_MAGIC || data[0..5] == SNAPSHOT_MAGIC_V2_LEGACY) {
        // v2+ magic: "utxo\xff" (current) or "utxo\0" (legacy), 5 bytes
        let ver = u16::from_le_bytes([data[5], data[6]]);
        (5usize, ver, 5usize)
    } else if data[0..4] == SNAPSHOT_MAGIC_V1 {
        // v1 magic: "UTXO" (4 bytes)
        let ver = u16::from_le_bytes([data[4], data[5]]);
        (4usize, ver, 4usize)
    } else {
        return Err(StorageError::Decode(format!(
            "invalid snapshot magic: {:?}",
            &data[0..5.min(data.len())]
        )));
    };

    // Check version
    if version > SNAPSHOT_VERSION {
        return Err(StorageError::Decode(format!(
            "unsupported snapshot version: {version}"
        )));
    }

    // Split payload from checksum (last 32 bytes)
    let (payload, checksum) = data.split_at(data.len() - 32);
    let computed = rbtc_crypto::sha256d(payload);
    if computed.0 != checksum {
        return Err(StorageError::Decode("snapshot checksum mismatch".into()));
    }

    // Parse header fields — offset depends on magic length
    let header_start = version_offset + 2; // skip version u16
    // network(4) + hash(32) + height(4) + num_utxos(8)
    let network_end = header_start + 4;
    let hash_start = network_end;
    let hash_end = hash_start + 32;
    let height_start = hash_end;
    let num_utxos_start = height_start + 4;
    let num_utxos_end = num_utxos_start + 8;

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&payload[hash_start..hash_end]);
    let height = u32::from_le_bytes(
        payload[height_start..height_start + 4].try_into().unwrap(),
    );
    let num_utxos = u64::from_le_bytes(
        payload[num_utxos_start..num_utxos_end].try_into().unwrap(),
    );

    // Version 3+: read total_amount
    let (total_amount, total_amount_end) = if version >= 3 {
        let ta_start = num_utxos_end;
        let ta_end = ta_start + 8;
        if payload.len() < ta_end {
            return Err(StorageError::Decode(
                "snapshot too short for v3 total_amount".into(),
            ));
        }
        let ta = u64::from_le_bytes(payload[ta_start..ta_end].try_into().unwrap());
        (Some(ta), ta_end)
    } else {
        (None, num_utxos_end)
    };

    // Version 2+: verify metadata hash
    let metadata_hash = if version >= 2 {
        let meta_hash_start = total_amount_end;
        let meta_hash_end = meta_hash_start + 32;
        if payload.len() < meta_hash_end {
            return Err(StorageError::Decode(
                "snapshot too short for metadata hash".into(),
            ));
        }
        let mut stored = [0u8; 32];
        stored.copy_from_slice(&payload[meta_hash_start..meta_hash_end]);

        // Recompute expected metadata hash
        let mut meta_buf = Vec::new();
        meta_buf.extend_from_slice(&payload[header_start..network_end]);
        meta_buf.extend_from_slice(&hash_bytes);
        meta_buf.extend_from_slice(&payload[height_start..height_start + 4]);
        meta_buf.extend_from_slice(&payload[num_utxos_start..num_utxos_end]);
        if version >= 3 {
            meta_buf.extend_from_slice(&payload[num_utxos_end..total_amount_end]);
        }
        let expected = rbtc_crypto::sha256d(&meta_buf);
        if stored != expected.0 {
            return Err(StorageError::Decode(
                "snapshot metadata hash mismatch".into(),
            ));
        }
        Some(Hash256(stored))
    } else {
        None
    };

    Ok(SnapshotMetadata {
        block_hash: BlockHash(Hash256(hash_bytes)),
        height,
        num_utxos,
        total_amount,
        metadata_hash,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn write_utxo_entry(
    w: &mut impl Write,
    h: &mut Sha256dWriter,
    outpoint: &OutPoint,
    utxo: &StoredUtxo,
) -> Result<()> {
    // txid (32) + vout (4)
    write_both(w, h, &outpoint.txid.0 .0)?;
    write_both(w, h, &outpoint.vout.to_le_bytes())?;
    // value (8) + height (4) + is_coinbase (1)
    write_both(w, h, &utxo.value.to_le_bytes())?;
    write_both(w, h, &utxo.height.to_le_bytes())?;
    write_both(w, h, &[if utxo.is_coinbase { 1 } else { 0 }])?;
    // script: varint length + bytes
    let script_bytes = utxo.script_pubkey.as_bytes();
    let mut varint_buf = Vec::new();
    VarInt(script_bytes.len() as u64)
        .encode(&mut varint_buf)
        .map_err(|e| StorageError::Decode(format!("varint encode error: {e}")))?;
    write_both(w, h, &varint_buf)?;
    write_both(w, h, script_bytes)?;
    Ok(())
}

fn read_utxo_entry(r: &mut impl Read) -> Result<(OutPoint, StoredUtxo)> {
    let mut txid = [0u8; 32];
    r.read_exact(&mut txid).map_err(read_err)?;
    let mut vout = [0u8; 4];
    r.read_exact(&mut vout).map_err(read_err)?;

    let mut value = [0u8; 8];
    r.read_exact(&mut value).map_err(read_err)?;
    let mut height = [0u8; 4];
    r.read_exact(&mut height).map_err(read_err)?;
    let mut cb = [0u8; 1];
    r.read_exact(&mut cb).map_err(read_err)?;

    // Read varint-encoded script length
    let script_len = read_varint(r)?;
    let mut script = vec![0u8; script_len as usize];
    r.read_exact(&mut script).map_err(read_err)?;

    let outpoint = OutPoint {
        txid: Txid(Hash256(txid)),
        vout: u32::from_le_bytes(vout),
    };
    let utxo = StoredUtxo {
        value: i64::from_le_bytes(value),
        script_pubkey: Script::from_bytes(script),
        height: u32::from_le_bytes(height),
        is_coinbase: cb[0] != 0,
    };
    Ok((outpoint, utxo))
}

fn read_varint(r: &mut impl Read) -> Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first).map_err(read_err)?;
    match first[0] {
        0..=0xfc => Ok(first[0] as u64),
        0xfd => {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf).map_err(read_err)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf).map_err(read_err)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf).map_err(read_err)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

fn read_err(e: io::Error) -> StorageError {
    StorageError::Decode(format!("read error: {e}"))
}

fn write_both(w: &mut impl Write, h: &mut Sha256dWriter, data: &[u8]) -> Result<()> {
    w.write_all(data)
        .map_err(|e| StorageError::Decode(format!("write error: {e}")))?;
    h.update(data);
    Ok(())
}

fn utxo_key(outpoint: &OutPoint) -> Vec<u8> {
    use crate::compress::write_varint;
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(&outpoint.txid.0 .0);
    write_varint(&mut key, outpoint.vout as u64);
    key
}

/// Incremental SHA256d hasher that accumulates data then double-hashes on finish.
struct Sha256dWriter {
    buf: Vec<u8>,
}

impl Sha256dWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn finish(self) -> Hash256 {
        rbtc_crypto::sha256d(&self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use tempfile::TempDir;

    fn setup_db_with_utxos(count: usize) -> (TempDir, Database) {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();

        // Set chain state
        let chain = ChainStore::new(&db);
        let hash = BlockHash(Hash256([0xAB; 32]));
        chain.set_best_block(&hash).unwrap();
        chain.set_best_height(1000).unwrap();
        chain.set_network_magic(&[0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        // Add UTXOs
        let store = UtxoStore::new(&db);
        for i in 0..count {
            let mut txid = [0u8; 32];
            txid[0] = i as u8;
            txid[1] = (i >> 8) as u8;
            let op = OutPoint {
                txid: Txid(Hash256(txid)),
                vout: 0,
            };
            let utxo = StoredUtxo {
                value: (i as i64 + 1) * 1000,
                script_pubkey: Script::from_bytes(vec![0x76, 0xa9, i as u8]),
                height: i as u32,
                is_coinbase: i == 0,
            };
            store.put(&op, &utxo).unwrap();
        }

        (dir, db)
    }

    #[test]
    fn snapshot_metadata_roundtrip() {
        let meta = SnapshotMetadata {
            block_hash: BlockHash(Hash256([0x42; 32])),
            height: 500_000,
            num_utxos: 70_000_000,
            total_amount: None,
            metadata_hash: None,
        };
        // Just verify the struct can be cloned and compared
        let meta2 = meta.clone();
        assert_eq!(meta, meta2);
    }

    #[test]
    fn write_and_validate_snapshot() {
        let (_dir, db) = setup_db_with_utxos(5);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("test.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert_eq!(meta.height, 1000);
        assert_eq!(meta.num_utxos, 5);
        assert_eq!(meta.block_hash, BlockHash(Hash256([0xAB; 32])));

        let validated = validate_snapshot(&snap_path).unwrap();
        assert_eq!(validated, meta);
    }

    #[test]
    fn corrupted_snapshot_fails_checksum() {
        let (_dir, db) = setup_db_with_utxos(3);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("corrupt.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        // Flip a byte in the middle
        let mut data = std::fs::read(&snap_path).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&snap_path, &data).unwrap();

        let result = validate_snapshot(&snap_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn wrong_network_magic_rejected() {
        let (_dir, db) = setup_db_with_utxos(1);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("net.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        // Load with testnet magic
        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        let result = load_snapshot(&db2, &snap_path, [0x0b, 0x11, 0x09, 0x07]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("network mismatch"));
    }

    #[test]
    fn empty_utxo_set_snapshot() {
        let (_dir, db) = setup_db_with_utxos(0);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("empty.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert_eq!(meta.num_utxos, 0);

        let validated = validate_snapshot(&snap_path).unwrap();
        assert_eq!(validated.num_utxos, 0);
    }

    #[test]
    fn single_utxo_snapshot() {
        let (_dir, db) = setup_db_with_utxos(1);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("single.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert_eq!(meta.num_utxos, 1);

        let validated = validate_snapshot(&snap_path).unwrap();
        assert_eq!(validated, meta);
    }

    #[test]
    fn load_snapshot_populates_utxo_cf() {
        let (_dir, db) = setup_db_with_utxos(5);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("load.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        // Load into a fresh database
        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        let loaded = load_snapshot(&db2, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert_eq!(loaded, meta);

        // Verify UTXOs are present
        let store2 = UtxoStore::new(&db2);
        let all = store2.iter_all();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn load_snapshot_sets_chain_tip() {
        let (_dir, db) = setup_db_with_utxos(2);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("tip.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        load_snapshot(&db2, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        let chain2 = ChainStore::new(&db2);
        assert_eq!(
            chain2.get_best_block().unwrap(),
            Some(BlockHash(Hash256([0xAB; 32])))
        );
        assert_eq!(chain2.get_best_height().unwrap(), Some(1000));
    }

    #[test]
    fn validate_returns_correct_metadata() {
        let (_dir, db) = setup_db_with_utxos(10);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("meta.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        let validated = validate_snapshot(&snap_path).unwrap();

        assert_eq!(validated.block_hash, meta.block_hash);
        assert_eq!(validated.height, meta.height);
        assert_eq!(validated.num_utxos, meta.num_utxos);
    }

    #[test]
    fn large_script_varint_encoding() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();

        let chain = ChainStore::new(&db);
        chain.set_best_block(&BlockHash(Hash256([0x11; 32]))).unwrap();
        chain.set_best_height(42).unwrap();

        // Add a UTXO with a script > 252 bytes (requires 3-byte varint)
        let big_script = vec![0x42u8; 300];
        let store = UtxoStore::new(&db);
        let op = OutPoint {
            txid: Txid(Hash256([0x99; 32])),
            vout: 0,
        };
        let utxo = StoredUtxo {
            value: 50000,
            script_pubkey: Script::from_bytes(big_script.clone()),
            height: 42,
            is_coinbase: false,
        };
        store.put(&op, &utxo).unwrap();

        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("bigscript.snap");
        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        // Load and verify the big script survived
        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        load_snapshot(&db2, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        let store2 = UtxoStore::new(&db2);
        let loaded = store2.get(&op).unwrap().unwrap();
        assert_eq!(loaded.script_pubkey.as_bytes(), &big_script);
    }

    #[test]
    fn snapshot_base_stored_in_chain_state() {
        let (_dir, db) = setup_db_with_utxos(1);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("base.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        load_snapshot(&db2, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        let base = db2.get_cf(CF_CHAIN_STATE, b"snapshot_base").unwrap();
        assert!(base.is_some());
        assert_eq!(base.unwrap(), [0xAB; 32].to_vec());
    }

    #[test]
    fn invalid_magic_rejected() {
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("bad_magic.snap");

        // Write a file with wrong magic
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"NOPE");
        std::fs::write(&snap_path, &data).unwrap();

        let result = validate_snapshot(&snap_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid snapshot magic"));
    }

    // ── M10/M11: v2 snapshot magic and metadata hash tests ────────────

    #[test]
    fn snapshot_v2_magic_is_five_bytes() {
        let (_dir, db) = setup_db_with_utxos(1);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v2magic.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        let data = std::fs::read(&snap_path).unwrap();
        // v2+ magic is "utxo\xff" (matching Bitcoin Core v28+)
        assert_eq!(&data[0..5], &[0x75, 0x74, 0x78, 0x6f, 0xff]);
    }

    #[test]
    fn snapshot_v2_has_metadata_hash() {
        let (_dir, db) = setup_db_with_utxos(3);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v2meta.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert!(
            meta.metadata_hash.is_some(),
            "v2 snapshot must have metadata_hash"
        );
    }

    #[test]
    fn snapshot_v2_version_field() {
        let (_dir, db) = setup_db_with_utxos(1);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v2ver.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        let data = std::fs::read(&snap_path).unwrap();
        // Version field at offset 5 (after 5-byte magic), u16 LE
        let version = u16::from_le_bytes([data[5], data[6]]);
        assert_eq!(version, 3);
    }

    #[test]
    fn snapshot_v2_metadata_hash_verified_on_load() {
        let (_dir, db) = setup_db_with_utxos(2);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v2tamper.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        // Tamper with the metadata hash (located after header fields)
        // Header: magic(5) + version(2) + network(4) + hash(32) + height(4) + num_utxos(8) + total_amount(8) = 63
        // Metadata hash starts at offset 63
        let mut data = std::fs::read(&snap_path).unwrap();
        let meta_hash_offset = 63;
        data[meta_hash_offset] ^= 0xFF;
        // Also fix the trailing checksum so it doesn't fail first
        let payload = &data[..data.len() - 32];
        let new_checksum = rbtc_crypto::sha256d(payload);
        let len = data.len();
        data[len - 32..].copy_from_slice(&new_checksum.0);
        std::fs::write(&snap_path, &data).unwrap();

        let result = validate_snapshot(&snap_path);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("metadata hash mismatch"),
            "expected metadata hash mismatch error"
        );
    }

    #[test]
    fn snapshot_v2_write_load_roundtrip() {
        let (_dir, db) = setup_db_with_utxos(5);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v2round.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        // Load into fresh DB
        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        let loaded = load_snapshot(&db2, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert_eq!(loaded, meta);

        let store2 = UtxoStore::new(&db2);
        assert_eq!(store2.iter_all().len(), 5);
    }

    // ── L11: total_amount tests ─────────────────────────────────────────

    #[test]
    fn snapshot_v3_total_amount_present() {
        let (_dir, db) = setup_db_with_utxos(5);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v3total.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert!(meta.total_amount.is_some(), "v3 snapshot must have total_amount");
        // UTXOs have values 1*1000, 2*1000, 3*1000, 4*1000, 5*1000 = 15000
        assert_eq!(meta.total_amount.unwrap(), 15_000);
    }

    #[test]
    fn snapshot_v3_total_amount_validated_on_load() {
        let (_dir, db) = setup_db_with_utxos(3);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v3load.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        // total = 1000 + 2000 + 3000 = 6000
        assert_eq!(meta.total_amount, Some(6000));

        // Load into fresh DB — should succeed
        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        let loaded = load_snapshot(&db2, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert_eq!(loaded.total_amount, Some(6000));
    }

    #[test]
    fn snapshot_v3_empty_total_amount_zero() {
        let (_dir, db) = setup_db_with_utxos(0);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v3empty.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        assert_eq!(meta.total_amount, Some(0));
    }

    #[test]
    fn snapshot_v3_validate_returns_total_amount() {
        let (_dir, db) = setup_db_with_utxos(2);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("v3val.snap");

        let meta = write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();
        let validated = validate_snapshot(&snap_path).unwrap();
        assert_eq!(validated.total_amount, meta.total_amount);
    }

    // ── C2: snapshot magic 0xff alignment with Bitcoin Core v28+ ──────

    #[test]
    fn snapshot_magic_matches_bitcoin_core_v28() {
        // Bitcoin Core v28+ uses {'u','t','x','o', 0xff}
        assert_eq!(SNAPSHOT_MAGIC, [0x75, 0x74, 0x78, 0x6f, 0xff]);
    }

    #[test]
    fn snapshot_legacy_magic_utxo_nul_accepted() {
        // Write a snapshot, then patch magic from 0xff to 0x00 (legacy),
        // fix the trailing checksum, and verify it still loads.
        let (_dir, db) = setup_db_with_utxos(2);
        let snap_dir = TempDir::new().unwrap();
        let snap_path = snap_dir.path().join("legacy_magic.snap");

        write_snapshot(&db, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]).unwrap();

        let mut data = std::fs::read(&snap_path).unwrap();
        // Patch byte 4 from 0xff to 0x00
        assert_eq!(data[4], 0xff);
        data[4] = 0x00;
        // Recompute trailing SHA256d checksum over the modified payload
        let payload_len = data.len() - 32;
        let new_checksum = rbtc_crypto::sha256d(&data[..payload_len]);
        data[payload_len..].copy_from_slice(&new_checksum.0);
        std::fs::write(&snap_path, &data).unwrap();

        // validate_snapshot should accept legacy magic
        let result = validate_snapshot(&snap_path);
        assert!(result.is_ok(), "legacy utxo\\0 magic must be accepted: {:?}", result.err());

        // load_snapshot should also accept it
        let db2_dir = TempDir::new().unwrap();
        let db2 = Database::open(db2_dir.path()).unwrap();
        let loaded = load_snapshot(&db2, &snap_path, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert!(loaded.is_ok(), "legacy utxo\\0 magic must load: {:?}", loaded.err());
    }
}
