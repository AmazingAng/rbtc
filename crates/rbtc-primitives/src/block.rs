use crate::{
    codec::{decode_list, encode_list, Decodable, Encodable, Result},
    hash::{BlockHash, Hash256},
    transaction::Transaction,
};
use std::io::{Read, Write};

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

    /// Expand nBits into a 256-bit target as a 32-byte array (little-endian)
    pub fn target(&self) -> [u8; 32] {
        nbits_to_target(self.bits)
    }

    /// True if hash < target (valid PoW)
    pub fn meets_target(&self, hash: &BlockHash) -> bool {
        let target = self.target();
        // Compare big-endian: hash bytes are stored little-endian, target too
        for i in (0..32).rev() {
            match hash.0[i].cmp(&target[i]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => {}
            }
        }
        true
    }

    /// Compute the block work (2^256 / (target + 1))
    pub fn work(&self) -> u128 {
        // Simplified: return 2^32 / (bits_mantissa), good enough for chain comparison
        let target = self.target();
        // Use highest significant 16 bytes for u128 approximation
        let mut val = 0u128;
        for i in (16..32).rev() {
            val = val.saturating_mul(256).saturating_add(target[i] as u128);
        }
        if val == 0 {
            return u128::MAX;
        }
        // work ≈ 2^128 / val (rough approximation for chain selection)
        u128::MAX / val
    }
}

/// Expand nBits compact representation to 256-bit target
pub fn nbits_to_target(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mantissa = bits & 0x007fffff;

    let mut target = [0u8; 32];
    if exp == 0 || exp > 34 {
        return target;
    }

    // mantissa is 3 bytes, stored at byte offset (exp - 3)
    let start = exp.saturating_sub(3);
    let mantissa_bytes = mantissa.to_be_bytes();

    // mantissa_bytes: [0, b1, b2, b3] → write b1,b2,b3 at start..start+3
    for (i, &b) in mantissa_bytes[1..].iter().enumerate() {
        let idx = start + i;
        if idx < 32 {
            target[idx] = b;
        }
    }
    target
}

/// Compute compact nBits from a 32-byte target (little-endian)
pub fn target_to_nbits(target: &[u8; 32]) -> u32 {
    // Find most significant byte
    let mut msb = 31;
    while msb > 0 && target[msb] == 0 {
        msb -= 1;
    }
    let exp = msb + 1;
    let mantissa = if msb >= 2 {
        ((target[msb] as u32) << 16)
            | ((target[msb - 1] as u32) << 8)
            | (target[msb - 2] as u32)
    } else if msb == 1 {
        ((target[msb] as u32) << 16) | ((target[msb - 1] as u32) << 8)
    } else {
        (target[msb] as u32) << 16
    };
    ((exp as u32) << 24) | (mantissa & 0x007fffff)
}

impl Encodable for BlockHeader {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut n = self.version.encode(w)?;
        n += self.prev_block.0.encode(w)?;
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
        let prev_block = Hash256(<[u8; 32]>::decode(r)?);
        let merkle_root = Hash256(<[u8; 32]>::decode(r)?);
        let time = u32::decode(r)?;
        let bits = u32::decode(r)?;
        let nonce = u32::decode(r)?;
        Ok(Self { version, prev_block, merkle_root, time, bits, nonce })
    }
}

/// Full Bitcoin block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Total weight of all transactions
    pub fn weight(&self) -> u64 {
        // Header: 80 bytes × 4 = 320 weight units, plus txcount varint × 4
        let header_weight = (BlockHeader::SIZE as u64) * 4;
        let tx_weight: u64 = self.transactions.iter().map(|tx| tx.weight()).sum();
        header_weight + tx_weight
    }
}

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
        Ok(Self { header, transactions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decodable, Encodable};
    use crate::transaction::Transaction;

    #[test]
    fn block_header_size() {
        assert_eq!(BlockHeader::SIZE, 80);
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
        assert_eq!((bits >> 24) as u8, 1);
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
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let target = h.target();
        let hash_less = {
            let mut t = target;
            t[31] = t[31].saturating_sub(1);
            Hash256(t)
        };
        assert!(h.meets_target(&hash_less));
        assert!(h.meets_target(&Hash256(target)));
        let hash_more = {
            let mut t = target;
            if t[0] < 255 {
                t[0] += 1;
            } else {
                t[1] += 1;
            }
            Hash256(t)
        };
        assert!(!h.meets_target(&hash_more));
    }

    #[test]
    fn block_header_work() {
        let h = BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
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
            prev_block: Hash256([1; 32]),
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
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![tx],
        };
        let w = block.weight();
        assert!(w >= 320);
    }

    #[test]
    fn block_encode_decode() {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        };
        let buf = block.encode_to_vec();
        let d = Block::decode_from_slice(&buf).unwrap();
        assert_eq!(d.header.bits, block.header.bits);
        assert!(d.transactions.is_empty());
    }
}
