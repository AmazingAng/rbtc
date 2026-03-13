use crate::{
    codec::{decode_list, encode_list, Decodable, Encodable, Result, VarInt},
    hash::{BlockHash, Hash256},
    transaction::{sha256d, Transaction},
};
use std::fmt;
use std::io::{Read, Write};

// ---------------------------------------------------------------------------
// BlockHeader (matches Bitcoin Core CBlockHeader)
// ---------------------------------------------------------------------------

/// 80-byte Bitcoin block header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block: BlockHash,
    /// Merkle root of all transactions in this block
    pub merkle_root: Hash256,
    /// Unix timestamp
    pub time: u32,
    /// Compact target (nBits)
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub const SIZE: usize = 80;

    /// Set all fields to zero / null (matches `CBlockHeader::SetNull`).
    pub fn set_null(&mut self) {
        self.version = 0;
        self.prev_block = BlockHash::ZERO;
        self.merkle_root = Hash256::ZERO;
        self.time = 0;
        self.bits = 0;
        self.nonce = 0;
    }

    /// A header is null if nBits is zero (matches `CBlockHeader::IsNull`).
    pub fn is_null(&self) -> bool {
        self.bits == 0
    }

    /// Compute the block hash (SHA256d of the 80-byte header).
    /// Matches `CBlockHeader::GetHash`.
    pub fn get_hash(&self) -> BlockHash {
        let data = self.encode_to_vec();
        BlockHash(Hash256(sha256d(&data)))
    }

    /// Block time as i64 (matches `CBlockHeader::GetBlockTime`).
    pub fn get_block_time(&self) -> i64 {
        self.time as i64
    }

    // -----------------------------------------------------------------------
    // PoW helpers.  In Bitcoin Core these live in pow.cpp, not in the
    // primitives header.  We keep them here for convenience but they could
    // be moved to rbtc-consensus.
    // -----------------------------------------------------------------------

    /// Expand nBits into a 256-bit target as a 32-byte array (little-endian)
    pub fn target(&self) -> [u8; 32] {
        nbits_to_target(self.bits)
    }

    /// True if hash < target (valid PoW)
    pub fn meets_target(&self, hash: &BlockHash) -> bool {
        let target = self.target();
        for i in (0..32).rev() {
            match hash.0 .0[i].cmp(&target[i]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => {}
            }
        }
        true
    }

    /// Compute the block work (2^256 / (target + 1))
    pub fn work(&self) -> u128 {
        let target = self.target();
        let mut val = 0u128;
        for i in (16..32).rev() {
            val = val.saturating_mul(256).saturating_add(target[i] as u128);
        }
        if val == 0 {
            return u128::MAX;
        }
        u128::MAX / val
    }
}

/// Expand nBits compact representation to 256-bit target (little-endian)
pub fn nbits_to_target(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mantissa = bits & 0x007fffff;

    let mut target = [0u8; 32];
    if exp == 0 || exp > 34 {
        return target;
    }

    let start = exp.saturating_sub(3);
    if start < 32 {
        target[start] = (mantissa & 0xff) as u8;
    }
    if start + 1 < 32 {
        target[start + 1] = ((mantissa >> 8) & 0xff) as u8;
    }
    if start + 2 < 32 {
        target[start + 2] = ((mantissa >> 16) & 0xff) as u8;
    }
    target
}

/// Compute compact nBits from a 32-byte target (little-endian).
pub fn target_to_nbits(target: &[u8; 32]) -> u32 {
    let mut msb = 31usize;
    while msb > 0 && target[msb] == 0 {
        msb -= 1;
    }
    if target[msb] == 0 {
        return 0;
    }

    let mut exp = msb + 1;
    let mut mantissa = if msb >= 2 {
        ((target[msb] as u32) << 16) | ((target[msb - 1] as u32) << 8) | (target[msb - 2] as u32)
    } else if msb == 1 {
        ((target[msb] as u32) << 16) | ((target[msb - 1] as u32) << 8)
    } else {
        (target[msb] as u32) << 16
    };

    if mantissa & 0x00800000 != 0 {
        mantissa >>= 8;
        exp += 1;
    }

    ((exp as u32) << 24) | (mantissa & 0x007fffff)
}

impl Encodable for BlockHeader {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.version.encode(w)?;
        n += self.prev_block.0 .0.encode(w)?;
        n += self.merkle_root.0.encode(w)?;
        n += self.time.encode(w)?;
        n += self.bits.encode(w)?;
        n += self.nonce.encode(w)?;
        Ok(n)
    }
}

impl Decodable for BlockHeader {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let version = i32::decode(r)?;
        let prev_block = BlockHash(Hash256(<[u8; 32]>::decode(r)?));
        let merkle_root = Hash256(<[u8; 32]>::decode(r)?);
        let time = u32::decode(r)?;
        let bits = u32::decode(r)?;
        let nonce = u32::decode(r)?;
        Ok(Self {
            version,
            prev_block,
            merkle_root,
            time,
            bits,
            nonce,
        })
    }
}

// ---------------------------------------------------------------------------
// Block (matches Bitcoin Core CBlock)
// ---------------------------------------------------------------------------

/// Full Bitcoin block
#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,

    // Memory-only caching flags (matches Bitcoin Core CBlock).
    // Not serialized. Used to skip redundant validation.
    pub checked: std::cell::Cell<bool>,
    pub checked_witness_commitment: std::cell::Cell<bool>,
    pub checked_merkle_root: std::cell::Cell<bool>,
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Self {
            header,
            transactions,
            checked: std::cell::Cell::new(false),
            checked_witness_commitment: std::cell::Cell::new(false),
            checked_merkle_root: std::cell::Cell::new(false),
        }
    }

    pub fn set_null(&mut self) {
        self.header.set_null();
        self.transactions.clear();
        self.checked.set(false);
        self.checked_witness_commitment.set(false);
        self.checked_merkle_root.set(false);
    }

    /// Total weight of the block including header and tx count varint.
    pub fn weight(&self) -> u64 {
        let header_weight = (BlockHeader::SIZE as u64) * 4;
        // tx count varint is non-witness data, so ×4
        let txcount_varint_weight = (VarInt(self.transactions.len() as u64).len() as u64) * 4;
        let tx_weight: u64 = self.transactions.iter().map(|tx| tx.weight()).sum();
        header_weight + txcount_varint_weight + tx_weight
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.transactions == other.transactions
    }
}
impl Eq for Block {}

impl Encodable for Block {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.header.encode(w)?;
        n += encode_list(&self.transactions, w)?;
        Ok(n)
    }
}

impl Decodable for Block {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let header = BlockHeader::decode(r)?;
        let transactions = decode_list::<Transaction, _>(r)?;
        Ok(Block::new(header, transactions))
    }
}

// ---------------------------------------------------------------------------
// BlockLocator (matches Bitcoin Core CBlockLocator)
// ---------------------------------------------------------------------------

/// Describes a place in the block chain to another node such that if the
/// other node doesn't have the same branch, it can find a recent common trunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLocator {
    pub hashes: Vec<BlockHash>,
}

impl BlockLocator {
    pub const DUMMY_VERSION: i32 = 70016;

    pub fn new(hashes: Vec<BlockHash>) -> Self {
        Self { hashes }
    }

    pub fn is_null(&self) -> bool {
        self.hashes.is_empty()
    }
}

impl Encodable for BlockLocator {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = Self::DUMMY_VERSION.encode(w)?;
        n += encode_list(&self.hashes, w)?;
        Ok(n)
    }
}

impl Encodable for BlockHash {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        self.0 .0.encode(w)
    }
}

impl Decodable for BlockHash {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        Ok(BlockHash(Hash256(<[u8; 32]>::decode(r)?)))
    }
}

impl Decodable for BlockLocator {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let _version = i32::decode(r)?;
        let hashes = decode_list::<BlockHash, _>(r)?;
        Ok(Self { hashes })
    }
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BlockHeader(hash={}, prev={}, time={}, bits={:#010x}, nonce={})",
            self.get_hash(),
            self.prev_block,
            self.time,
            self.bits,
            self.nonce,
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block(hash={}, txs={}, weight={})",
            self.header.get_hash(),
            self.transactions.len(),
            self.weight(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decodable, Encodable};
    use crate::transaction::{MutableTransaction, TxIn, TxOut, OutPoint};
    use crate::script::Script;

    #[test]
    fn block_header_size() {
        assert_eq!(BlockHeader::SIZE, 80);
    }

    #[test]
    fn block_header_set_null_is_null() {
        let mut h = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        assert!(!h.is_null());
        h.set_null();
        assert!(h.is_null());
        assert_eq!(h.version, 0);
    }

    #[test]
    fn block_header_get_hash() {
        let h = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let hash = h.get_hash();
        assert!(!hash.is_null());
    }

    #[test]
    fn nbits_to_target_exp_zero() {
        let t = nbits_to_target(0);
        assert_eq!(t, [0u8; 32]);
    }

    #[test]
    fn nbits_to_target_exp_gt_34() {
        let t = nbits_to_target(0x35000000);
        assert_eq!(t, [0u8; 32]);
    }

    #[test]
    fn nbits_to_target_normal() {
        let bits = 0x1d00ffff;
        let t = nbits_to_target(bits);
        assert_ne!(t, [0u8; 32]);
    }

    #[test]
    fn target_to_nbits_msb_0() {
        let mut target = [0u8; 32];
        target[0] = 0x80;
        let bits = target_to_nbits(&target);
        assert_eq!((bits >> 24) as u8, 2);
        assert!(bits != 0);
    }

    #[test]
    fn target_to_nbits_msb_1() {
        let mut target = [0u8; 32];
        target[1] = 0x40;
        target[0] = 0x01;
        let bits = target_to_nbits(&target);
        assert_eq!((bits >> 24) as u8, 2);
    }

    #[test]
    fn block_header_meets_target() {
        let h = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let target = h.target();
        let hash_less = {
            let mut t = target;
            t[31] = t[31].saturating_sub(1);
            BlockHash(Hash256(t))
        };
        assert!(h.meets_target(&hash_less));
        assert!(h.meets_target(&BlockHash(Hash256(target))));
        let hash_more = {
            let mut t = target;
            if t[0] < 255 {
                t[0] += 1;
            } else {
                t[1] += 1;
            }
            BlockHash(Hash256(t))
        };
        assert!(!h.meets_target(&hash_more));
    }

    #[test]
    fn block_header_work() {
        let h = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let w = h.work();
        assert!(w > 0);
        let h2 = BlockHeader { bits: 0, ..h };
        assert_eq!(h2.work(), u128::MAX);
    }

    #[test]
    fn block_header_encode_decode() {
        let h = BlockHeader {
            version: 2,
            prev_block: BlockHash(Hash256([1; 32])),
            merkle_root: Hash256([2; 32]),
            time: 12345,
            bits: 0x1d00ffff,
            nonce: 42,
        };
        let buf = h.encode_to_vec();
        assert_eq!(buf.len(), 80);
        let d = BlockHeader::decode_from_slice(&buf).unwrap();
        assert_eq!(d.version, h.version);
        assert_eq!(d.nonce, 42);
    }

    #[test]
    fn block_weight() {
        let tx = Transaction::from_mutable(MutableTransaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        });
        let block = Block::new(
            BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            vec![tx],
        );
        let w = block.weight();
        // header (320) + txcount varint (1*4=4) + tx weight
        assert!(w >= 324);
    }

    #[test]
    fn block_encode_decode() {
        let block = Block::new(
            BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            vec![],
        );
        let buf = block.encode_to_vec();
        let d = Block::decode_from_slice(&buf).unwrap();
        assert_eq!(d.header.bits, block.header.bits);
        assert!(d.transactions.is_empty());
    }

    #[test]
    fn block_locator_encode_decode() {
        let loc = BlockLocator::new(vec![
            BlockHash(Hash256([1; 32])),
            BlockHash(Hash256([2; 32])),
        ]);
        let buf = loc.encode_to_vec();
        let d = BlockLocator::decode_from_slice(&buf).unwrap();
        assert_eq!(d.hashes.len(), 2);
        assert_eq!(d.hashes[0].0, Hash256([1; 32]));
    }

    #[test]
    fn block_locator_is_null() {
        assert!(BlockLocator::new(vec![]).is_null());
        assert!(!BlockLocator::new(vec![BlockHash::ZERO]).is_null());
    }

    #[test]
    fn block_header_display() {
        let h = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };
        let s = format!("{h}");
        assert!(s.starts_with("BlockHeader(hash="));
        assert!(s.contains("time=1231006505"));
        assert!(s.contains("bits=0x1d00ffff"));
    }

    #[test]
    fn block_display() {
        let h = BlockHeader {
            version: 1,
            prev_block: BlockHash::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let coinbase = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: crate::hash::Txid(Hash256::ZERO),
                    vout: 0xffffffff,
                },
                script_sig: Script::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            0,
        );
        let block = Block::new(h, vec![coinbase]);
        let s = format!("{block}");
        assert!(s.starts_with("Block(hash="));
        assert!(s.contains("txs=1"));
        assert!(s.contains("weight="));
    }

    #[test]
    fn transaction_display() {
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: crate::hash::Txid(Hash256::ZERO),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut { value: 10_000, script_pubkey: Script::new() }],
            0,
        );
        let s = format!("{tx}");
        assert!(s.starts_with("Transaction(txid="));
        assert!(s.contains("inputs=1"));
        assert!(s.contains("outputs=1"));
        assert!(s.contains("weight="));
    }
}
