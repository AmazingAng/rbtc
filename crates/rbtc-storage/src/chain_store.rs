use rbtc_primitives::{codec::{Decodable, Encodable}, hash::BlockHash};

use crate::{
    db::{Database, CF_CHAIN_STATE},
    error::{Result, StorageError},
};

const KEY_BEST_BLOCK: &[u8] = b"best_block";
const KEY_BEST_HEIGHT: &[u8] = b"best_height";
const KEY_CHAINWORK: &[u8] = b"chainwork";
const KEY_NETWORK: &[u8] = b"network";

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
                Ok(Some(Hash256(arr)))
            }
            Some(_) => Err(StorageError::Corruption("invalid best block hash".into())),
            None => Ok(None),
        }
    }

    pub fn set_best_block(&self, hash: &BlockHash) -> Result<()> {
        self.db.put_cf(CF_CHAIN_STATE, KEY_BEST_BLOCK, &hash.0)
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

    pub fn get_chainwork(&self) -> Result<u128> {
        match self.db.get_cf(CF_CHAIN_STATE, KEY_CHAINWORK)? {
            Some(bytes) if bytes.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                Ok(u128::from_le_bytes(arr))
            }
            Some(_) => Err(StorageError::Corruption("invalid chainwork".into())),
            None => Ok(0),
        }
    }

    pub fn set_chainwork(&self, work: u128) -> Result<()> {
        self.db.put_cf(CF_CHAIN_STATE, KEY_CHAINWORK, &work.to_le_bytes())
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

    /// Atomically update tip + height + chainwork
    pub fn update_tip(&self, hash: &BlockHash, height: u32, chainwork: u128) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.db.batch_put_cf(&mut batch, CF_CHAIN_STATE, KEY_BEST_BLOCK, &hash.0)?;
        self.db.batch_put_cf(&mut batch, CF_CHAIN_STATE, KEY_BEST_HEIGHT, &height.encode_to_vec())?;
        self.db.batch_put_cf(&mut batch, CF_CHAIN_STATE, KEY_CHAINWORK, &chainwork.to_le_bytes())?;
        self.db.write_batch(batch)
    }
}
