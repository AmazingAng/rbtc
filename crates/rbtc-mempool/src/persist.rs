//! Mempool persistence: save to / load from a `mempool.dat` file.
//!
//! Format (version 1, matching the spirit of Bitcoin Core's format):
//!
//! ```text
//! [version: u64 LE = 1]
//! [count: u64 LE]
//! for each entry:
//!     [tx_len: u64 LE][tx_bytes: N bytes (full witness serialization)]
//!     [fee_delta: i64 LE]
//! [fee_deltas_count: u64 LE]
//! for each extra fee delta (not in mempool):
//!     [txid: 32 bytes][delta: i64 LE]
//! ```

use std::io::{self, Read, Write};
use std::path::Path;

use rbtc_primitives::codec::{Decodable, Encodable};
use rbtc_primitives::hash::Txid;
use rbtc_primitives::transaction::Transaction;

const MEMPOOL_DAT_VERSION: u64 = 1;

/// A single persisted mempool entry (tx + fee delta).
#[derive(Debug, Clone)]
pub struct PersistedEntry {
    pub tx: Transaction,
    pub fee_delta: i64,
}

/// Extra fee deltas for transactions not currently in the pool
/// (from `prioritisetransaction` RPC).
#[derive(Debug, Clone)]
pub struct PersistedFeeDelta {
    pub txid: Txid,
    pub delta: i64,
}

/// Result of loading a mempool.dat file.
#[derive(Debug)]
pub struct LoadedMempool {
    pub entries: Vec<PersistedEntry>,
    pub fee_deltas: Vec<PersistedFeeDelta>,
}

/// Dump mempool transactions and fee deltas to a file.
pub fn dump_mempool(
    path: &Path,
    entries: &[PersistedEntry],
    fee_deltas: &[PersistedFeeDelta],
) -> io::Result<()> {
    let mut buf = Vec::new();

    // Version
    buf.extend_from_slice(&MEMPOOL_DAT_VERSION.to_le_bytes());

    // Transaction count
    buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());

    // Each transaction
    for entry in entries {
        let tx_bytes = entry.tx.encode_to_vec();
        buf.extend_from_slice(&(tx_bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(&tx_bytes);
        buf.extend_from_slice(&entry.fee_delta.to_le_bytes());
    }

    // Extra fee deltas
    buf.extend_from_slice(&(fee_deltas.len() as u64).to_le_bytes());
    for fd in fee_deltas {
        buf.extend_from_slice(&fd.txid.0 .0);
        buf.extend_from_slice(&fd.delta.to_le_bytes());
    }

    // Atomic write: write to .tmp then rename
    let tmp_path = path.with_extension("dat.tmp");
    std::fs::write(&tmp_path, &buf)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Load mempool transactions from a file.
///
/// Returns `Ok(None)` if the file doesn't exist.
/// Returns an error if the file exists but is corrupt.
pub fn load_mempool(path: &Path) -> io::Result<Option<LoadedMempool>> {
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read(path)?;
    let mut cursor = io::Cursor::new(&data);

    // Version
    let mut ver_buf = [0u8; 8];
    cursor.read_exact(&mut ver_buf)?;
    let version = u64::from_le_bytes(ver_buf);
    if version != MEMPOOL_DAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported mempool.dat version: {version}"),
        ));
    }

    // Transaction count
    let mut count_buf = [0u8; 8];
    cursor.read_exact(&mut count_buf)?;
    let count = u64::from_le_bytes(count_buf);

    let mut entries = Vec::with_capacity(count.min(100_000) as usize);
    for _ in 0..count {
        // tx_len
        let mut len_buf = [0u8; 8];
        cursor.read_exact(&mut len_buf)?;
        let tx_len = u64::from_le_bytes(len_buf) as usize;

        if tx_len > 4_000_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction too large in mempool.dat",
            ));
        }

        // tx bytes
        let mut tx_bytes = vec![0u8; tx_len];
        cursor.read_exact(&mut tx_bytes)?;
        let tx = Transaction::decode_from_slice(&tx_bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad tx: {e}"))
        })?;

        // fee delta
        let mut delta_buf = [0u8; 8];
        cursor.read_exact(&mut delta_buf)?;
        let fee_delta = i64::from_le_bytes(delta_buf);

        entries.push(PersistedEntry { tx, fee_delta });
    }

    // Extra fee deltas
    let mut fd_count_buf = [0u8; 8];
    let fee_deltas = if cursor.read_exact(&mut fd_count_buf).is_ok() {
        let fd_count = u64::from_le_bytes(fd_count_buf);
        let mut fds = Vec::with_capacity(fd_count.min(10_000) as usize);
        for _ in 0..fd_count {
            let mut txid_buf = [0u8; 32];
            cursor.read_exact(&mut txid_buf)?;
            let mut delta_buf = [0u8; 8];
            cursor.read_exact(&mut delta_buf)?;
            fds.push(PersistedFeeDelta {
                txid: Txid(rbtc_primitives::hash::Hash256(txid_buf)),
                delta: i64::from_le_bytes(delta_buf),
            });
        }
        fds
    } else {
        Vec::new()
    };

    Ok(Some(LoadedMempool {
        entries,
        fee_deltas,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};

    fn make_tx(value: i64) -> Transaction {
        Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x01, value as u8]),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut {
                value,
                script_pubkey: Script::new(),
            }],
            0,
        )
    }

    #[test]
    fn roundtrip_empty() {
        let dir = std::env::temp_dir().join("rbtc_mempool_test_empty");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mempool.dat");

        dump_mempool(&path, &[], &[]).unwrap();
        let loaded = load_mempool(&path).unwrap().unwrap();
        assert!(loaded.entries.is_empty());
        assert!(loaded.fee_deltas.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrip_with_entries() {
        let dir = std::env::temp_dir().join("rbtc_mempool_test_entries");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mempool.dat");

        let tx1 = make_tx(1000);
        let tx2 = make_tx(2000);
        let entries = vec![
            PersistedEntry { tx: tx1.clone(), fee_delta: 0 },
            PersistedEntry { tx: tx2.clone(), fee_delta: 500 },
        ];

        dump_mempool(&path, &entries, &[]).unwrap();
        let loaded = load_mempool(&path).unwrap().unwrap();
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries[0].fee_delta, 0);
        assert_eq!(loaded.entries[1].fee_delta, 500);

        // Verify tx data survived
        assert_eq!(loaded.entries[0].tx.outputs[0].value, 1000);
        assert_eq!(loaded.entries[1].tx.outputs[0].value, 2000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrip_with_fee_deltas() {
        let dir = std::env::temp_dir().join("rbtc_mempool_test_deltas");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mempool.dat");

        let txid = Txid(Hash256([0xAB; 32]));
        let fee_deltas = vec![PersistedFeeDelta { txid, delta: -1000 }];

        dump_mempool(&path, &[], &fee_deltas).unwrap();
        let loaded = load_mempool(&path).unwrap().unwrap();
        assert!(loaded.entries.is_empty());
        assert_eq!(loaded.fee_deltas.len(), 1);
        assert_eq!(loaded.fee_deltas[0].txid, txid);
        assert_eq!(loaded.fee_deltas[0].delta, -1000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_file_returns_none() {
        let path = std::path::Path::new("/tmp/rbtc_nonexistent_mempool.dat");
        let result = load_mempool(path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_bad_version_returns_error() {
        let dir = std::env::temp_dir().join("rbtc_mempool_test_badver");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mempool.dat");

        // Write a file with version 99
        let mut data = Vec::new();
        data.extend_from_slice(&99u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        std::fs::write(&path, &data).unwrap();

        let result = load_mempool(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_truncated_returns_error() {
        let dir = std::env::temp_dir().join("rbtc_mempool_test_trunc");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mempool.dat");

        // Write version + count=1 but no actual tx data
        let mut data = Vec::new();
        data.extend_from_slice(&MEMPOOL_DAT_VERSION.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes()); // claims 1 tx
        std::fs::write(&path, &data).unwrap();

        let result = load_mempool(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
