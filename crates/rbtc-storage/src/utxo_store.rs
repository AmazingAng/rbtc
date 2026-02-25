use rocksdb::WriteBatch;
use rbtc_primitives::{
    codec::{Decodable, Encodable, VarInt},
    hash::{Hash256, TxId},
    script::Script,
    transaction::{OutPoint, TxOut},
};

use crate::{
    db::{Database, CF_UTXO},
    error::{Result, StorageError},
};

/// A UTXO entry as stored on disk
#[derive(Debug, Clone)]
pub struct StoredUtxo {
    pub value: u64,
    pub script_pubkey: Script,
    pub height: u32,
    pub is_coinbase: bool,
}

impl StoredUtxo {
    pub fn to_txout(&self) -> TxOut {
        TxOut { value: self.value, script_pubkey: self.script_pubkey.clone() }
    }

    fn encode_key(outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(&outpoint.txid.0);
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    pub fn encode_value(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.value.encode(&mut buf).ok();
        self.script_pubkey.encode(&mut buf).ok();
        self.height.encode(&mut buf).ok();
        buf.push(if self.is_coinbase { 1 } else { 0 });
        buf
    }

    pub fn decode_value(bytes: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(bytes);
        let value = u64::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        let script_pubkey = Script::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        let height = u32::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        let mut flag = [0u8; 1];
        use std::io::Read;
        cur.read_exact(&mut flag).map_err(|e| StorageError::Decode(e.to_string()))?;
        Ok(Self { value, script_pubkey, height, is_coinbase: flag[0] != 0 })
    }
}

/// Persistent UTXO set backed by RocksDB
pub struct UtxoStore<'db> {
    db: &'db Database,
}

impl<'db> UtxoStore<'db> {
    pub fn new(db: &'db Database) -> Self {
        Self { db }
    }

    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<StoredUtxo>> {
        let key = StoredUtxo::encode_key(outpoint);
        match self.db.get_cf(CF_UTXO, &key)? {
            Some(bytes) => Ok(Some(StoredUtxo::decode_value(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn contains(&self, outpoint: &OutPoint) -> Result<bool> {
        let key = StoredUtxo::encode_key(outpoint);
        Ok(self.db.get_cf(CF_UTXO, &key)?.is_some())
    }

    pub fn put(&self, outpoint: &OutPoint, utxo: &StoredUtxo) -> Result<()> {
        let key = StoredUtxo::encode_key(outpoint);
        self.db.put_cf(CF_UTXO, &key, &utxo.encode_value())
    }

    pub fn delete(&self, outpoint: &OutPoint) -> Result<()> {
        let key = StoredUtxo::encode_key(outpoint);
        self.db.delete_cf(CF_UTXO, &key)
    }

    /// Atomically apply a batch of UTXO changes (connect block)
    pub fn apply_batch(
        &self,
        to_add: &[(OutPoint, StoredUtxo)],
        to_remove: &[OutPoint],
    ) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.fill_batch(&mut batch, to_add, to_remove)?;
        self.db.write_batch(batch)
    }

    /// Fill an externally-owned `WriteBatch` with UTXO deletes and puts.
    /// Callers can then add further CF writes (e.g. tx_index, addr_index) and
    /// commit the whole batch in one atomic RocksDB write.
    pub fn fill_batch(
        &self,
        batch: &mut WriteBatch,
        to_add: &[(OutPoint, StoredUtxo)],
        to_remove: &[OutPoint],
    ) -> Result<()> {
        for outpoint in to_remove {
            let key = StoredUtxo::encode_key(outpoint);
            self.db.batch_delete_cf(batch, CF_UTXO, &key)?;
        }
        for (outpoint, utxo) in to_add {
            let key = StoredUtxo::encode_key(outpoint);
            self.db.batch_put_cf(batch, CF_UTXO, &key, &utxo.encode_value())?;
        }
        Ok(())
    }

    /// Process a connected block: spend inputs, add outputs (self-contained batch).
    pub fn connect_block(
        &self,
        txids: &[TxId],
        txs: &[rbtc_primitives::transaction::Transaction],
        height: u32,
    ) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.connect_block_into_batch(&mut batch, txids, txs, height)?;
        self.db.write_batch(batch)
    }

    /// Like `connect_block` but fills an externally-owned `WriteBatch` so the
    /// caller can combine UTXO writes with tx_index / addr_index writes and
    /// commit everything atomically.
    pub fn connect_block_into_batch(
        &self,
        batch: &mut WriteBatch,
        txids: &[TxId],
        txs: &[rbtc_primitives::transaction::Transaction],
        height: u32,
    ) -> Result<()> {
        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();

        for (txid, tx) in txids.iter().zip(txs.iter()) {
            let is_coinbase = tx.is_coinbase();

            if !is_coinbase {
                for input in &tx.inputs {
                    to_remove.push(input.previous_output.clone());
                }
            }

            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint { txid: *txid, vout: vout as u32 };
                to_add.push((outpoint, StoredUtxo {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey.clone(),
                    height,
                    is_coinbase,
                }));
            }
        }

        self.fill_batch(batch, &to_add, &to_remove)
    }

    /// Iterate all stored UTXOs (used to reload the in-memory UTXO set on startup).
    pub fn iter_all(&self) -> Vec<(OutPoint, StoredUtxo)> {
        match self.db.iter_cf(CF_UTXO) {
            Ok(iter) => iter
                .filter_map(|(k, v)| {
                    if k.len() != 36 {
                        return None;
                    }
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&k[..32]);
                    let vout = u32::from_le_bytes(k[32..36].try_into().ok()?);
                    let utxo = StoredUtxo::decode_value(&v).ok()?;
                    Some((OutPoint { txid: Hash256(txid_bytes), vout }, utxo))
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Process a disconnected block (reorg undo)
    pub fn disconnect_block(
        &self,
        txids: &[TxId],
        txs: &[rbtc_primitives::transaction::Transaction],
        undo_data: &[(OutPoint, StoredUtxo)],
    ) -> Result<()> {
        let mut to_remove = Vec::new();
        let to_add = undo_data.to_vec();

        for (txid, tx) in txids.iter().zip(txs.iter()).rev() {
            for vout in 0..tx.outputs.len() {
                to_remove.push(OutPoint { txid: *txid, vout: vout as u32 });
            }
        }

        self.apply_batch(&to_add, &to_remove)
    }
}

/// Encode per-block undo data (list of per-tx spent UTXOs) into bytes.
/// Format: varint(num_txs) | for each tx: varint(num_spent) | (36-byte key + value)*
pub fn encode_block_undo(undo: &[Vec<(OutPoint, StoredUtxo)>]) -> Vec<u8> {
    let mut buf = Vec::new();
    VarInt(undo.len() as u64).encode(&mut buf).ok();
    for tx_undo in undo {
        VarInt(tx_undo.len() as u64).encode(&mut buf).ok();
        for (outpoint, utxo) in tx_undo {
            let key = StoredUtxo::encode_key(outpoint);
            buf.extend_from_slice(&key);
            let val = utxo.encode_value();
            VarInt(val.len() as u64).encode(&mut buf).ok();
            buf.extend_from_slice(&val);
        }
    }
    buf
}

/// Decode undo data encoded by `encode_block_undo`.
pub fn decode_block_undo(bytes: &[u8]) -> Result<Vec<Vec<(OutPoint, StoredUtxo)>>> {
    let mut cur = std::io::Cursor::new(bytes);
    let VarInt(num_txs) = VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
    let mut undo = Vec::with_capacity(num_txs as usize);
    for _ in 0..num_txs {
        let VarInt(num_spent) = VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
        let mut tx_undo = Vec::with_capacity(num_spent as usize);
        for _ in 0..num_spent {
            let mut key = [0u8; 36];
            use std::io::Read;
            cur.read_exact(&mut key).map_err(|e| StorageError::Decode(e.to_string()))?;
            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&key[..32]);
            let vout = u32::from_le_bytes(key[32..36].try_into().unwrap());
            let outpoint = OutPoint { txid: Hash256(txid_bytes), vout };
            let VarInt(val_len) = VarInt::decode(&mut cur).map_err(|e| StorageError::Decode(e.to_string()))?;
            let mut val = vec![0u8; val_len as usize];
            cur.read_exact(&mut val).map_err(|e| StorageError::Decode(e.to_string()))?;
            let utxo = StoredUtxo::decode_value(&val)?;
            tx_undo.push((outpoint, utxo));
        }
        undo.push(tx_undo);
    }
    Ok(undo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;
    use tempfile::TempDir;
    use crate::db::Database;

    #[test]
    fn utxo_store_put_get_delete() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let outpoint = OutPoint { txid: Hash256([1; 32]), vout: 0 };
        let utxo = StoredUtxo {
            value: 1000,
            script_pubkey: Script::new(),
            height: 1,
            is_coinbase: false,
        };
        store.put(&outpoint, &utxo).unwrap();
        assert!(store.contains(&outpoint).unwrap());
        let got = store.get(&outpoint).unwrap().unwrap();
        assert_eq!(got.value, 1000);
        store.delete(&outpoint).unwrap();
        assert!(store.get(&outpoint).unwrap().is_none());
    }

    #[test]
    fn utxo_store_apply_batch() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let store = UtxoStore::new(&db);
        let op = OutPoint { txid: Hash256([2; 32]), vout: 0 };
        let utxo = StoredUtxo {
            value: 2000,
            script_pubkey: Script::new(),
            height: 2,
            is_coinbase: true,
        };
        store.apply_batch(&[(op.clone(), utxo)], &[]).unwrap();
        assert_eq!(store.get(&op).unwrap().unwrap().value, 2000);
    }
}
