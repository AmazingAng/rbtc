use rbtc_primitives::{
    codec::{Decodable, Encodable},
    hash::TxId,
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

        for outpoint in to_remove {
            let key = StoredUtxo::encode_key(outpoint);
            self.db.batch_delete_cf(&mut batch, CF_UTXO, &key)?;
        }

        for (outpoint, utxo) in to_add {
            let key = StoredUtxo::encode_key(outpoint);
            self.db.batch_put_cf(&mut batch, CF_UTXO, &key, &utxo.encode_value())?;
        }

        self.db.write_batch(batch)
    }

    /// Process a connected block: spend inputs, add outputs
    pub fn connect_block(
        &self,
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

        self.apply_batch(&to_add, &to_remove)
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
