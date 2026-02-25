use rbtc_primitives::{
    block::{Block, BlockHeader},
    codec::{Decodable, Encodable},
    hash::BlockHash,
};

use crate::{
    db::{Database, CF_BLOCK_DATA, CF_BLOCK_INDEX},
    error::{Result, StorageError},
};

/// Stored block header with metadata
#[derive(Debug, Clone)]
pub struct StoredBlockIndex {
    pub header: BlockHeader,
    pub height: u32,
    pub chainwork_lo: u64,
    pub chainwork_hi: u64,
    pub status: u8,
}

impl StoredBlockIndex {
    pub fn chainwork(&self) -> u128 {
        (self.chainwork_hi as u128) << 64 | (self.chainwork_lo as u128)
    }

    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.header.encode(&mut buf).ok();
        self.height.encode(&mut buf).ok();
        self.chainwork_lo.encode(&mut buf).ok();
        self.chainwork_hi.encode(&mut buf).ok();
        buf.push(self.status);
        buf
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = std::io::Cursor::new(bytes);
        let header = BlockHeader::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let height = u32::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let chainwork_lo = u64::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let chainwork_hi = u64::decode(&mut cur)
            .map_err(|e| StorageError::Decode(e.to_string()))?;
        let mut status_byte = [0u8; 1];
        use std::io::Read;
        cur.read_exact(&mut status_byte).map_err(|e| StorageError::Decode(e.to_string()))?;
        Ok(Self { header, height, chainwork_lo, chainwork_hi, status: status_byte[0] })
    }
}

/// Block header and full block storage
pub struct BlockStore<'db> {
    db: &'db Database,
}

impl<'db> BlockStore<'db> {
    pub fn new(db: &'db Database) -> Self {
        Self { db }
    }

    pub fn get_index(&self, hash: &BlockHash) -> Result<Option<StoredBlockIndex>> {
        match self.db.get_cf(CF_BLOCK_INDEX, &hash.0)? {
            Some(bytes) => Ok(Some(StoredBlockIndex::decode_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_index(&self, hash: &BlockHash, index: &StoredBlockIndex) -> Result<()> {
        self.db.put_cf(CF_BLOCK_INDEX, &hash.0, &index.encode_bytes())
    }

    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        match self.db.get_cf(CF_BLOCK_DATA, &hash.0)? {
            Some(bytes) => {
                let block = Block::decode_from_slice(&bytes)
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    pub fn put_block(&self, hash: &BlockHash, block: &Block) -> Result<()> {
        let bytes = block.encode_to_vec();
        self.db.put_cf(CF_BLOCK_DATA, &hash.0, &bytes)
    }

    /// Atomically write a block header + block data
    pub fn put_block_atomic(&self, hash: &BlockHash, index: &StoredBlockIndex, block: &Block) -> Result<()> {
        let mut batch = self.db.new_batch();
        self.db.batch_put_cf(&mut batch, CF_BLOCK_INDEX, &hash.0, &index.encode_bytes())?;
        self.db.batch_put_cf(&mut batch, CF_BLOCK_DATA, &hash.0, &block.encode_to_vec())?;
        self.db.write_batch(batch)
    }

    pub fn has_block(&self, hash: &BlockHash) -> Result<bool> {
        Ok(self.db.get_cf(CF_BLOCK_DATA, &hash.0)?.is_some())
    }

    pub fn has_index(&self, hash: &BlockHash) -> Result<bool> {
        Ok(self.db.get_cf(CF_BLOCK_INDEX, &hash.0)?.is_some())
    }
}
