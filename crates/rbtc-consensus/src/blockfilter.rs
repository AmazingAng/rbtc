//! BIP158 compact block filters (basic filter construction).
//!
//! Implements the Golomb-Coded Set (GCS) encoding and basic filter
//! construction used by BIP157/158 for light client filtering.

use std::collections::HashSet;
use std::hash::Hasher;

use siphasher::sip::SipHasher24;

use rbtc_crypto::sha256d;
use rbtc_primitives::block::Block;

/// Golomb-Rice parameter P for basic filters.
pub const BASIC_FILTER_P: u8 = 19;
/// BIP158 M parameter for basic filters.
pub const BASIC_FILTER_M: u64 = 784931;

/// Filter type byte for basic filters (BIP157).
pub const BASIC_FILTER_TYPE: u8 = 0x00;

// ── GCS primitives ──────────────────────────────────────────────────────────

/// FastRange64: maps a 64-bit hash uniformly into [0, n) without division.
fn fast_range64(x: u64, n: u64) -> u64 {
    ((x as u128 * n as u128) >> 64) as u64
}

/// SipHash-2-4 of data with key (k0, k1).
fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(data);
    hasher.finish()
}

/// Golomb-Rice encode a value with parameter P into a bit writer.
fn golomb_rice_encode(bits: &mut BitWriter, p: u8, x: u64) {
    let q = x >> p;
    for _ in 0..q {
        bits.write_bit(1);
    }
    bits.write_bit(0);
    bits.write_bits(x, p);
}

/// Bit writer that accumulates a bitstream into bytes.
#[derive(Default)]
pub struct BitWriter {
    data: Vec<u8>,
    current: u8,
    bits_used: u8,
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_bit(&mut self, bit: u8) {
        self.current |= (bit & 1) << (7 - self.bits_used);
        self.bits_used += 1;
        if self.bits_used == 8 {
            self.data.push(self.current);
            self.current = 0;
            self.bits_used = 0;
        }
    }

    pub fn write_bits(&mut self, value: u64, count: u8) {
        for i in (0..count).rev() {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.bits_used > 0 {
            self.data.push(self.current);
        }
        self.data
    }
}

/// Encode N as Bitcoin CompactSize.
fn compact_size_encode(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Construct a BIP158 basic filter for a block.
///
/// `block_hash` must be in internal byte order (LE).
/// `prev_output_scripts` are the scriptPubKeys of the outputs spent by
/// this block's non-coinbase inputs.
pub fn build_basic_filter(
    block_hash: &[u8; 32],
    block: &Block,
    prev_output_scripts: &[Vec<u8>],
) -> Vec<u8> {
    let mut elements = HashSet::new();

    // Collect non-empty, non-OP_RETURN output scripts
    for tx in &block.transactions {
        for output in &tx.outputs {
            let script = output.script_pubkey.as_bytes();
            if script.is_empty() || script[0] == 0x6a {
                continue;
            }
            elements.insert(script.to_vec());
        }
    }

    // Collect previous output scripts (spent by this block's inputs)
    for script in prev_output_scripts {
        if !script.is_empty() {
            elements.insert(script.clone());
        }
    }

    let n = elements.len() as u64;
    if n == 0 {
        return compact_size_encode(0);
    }

    // Derive SipHash key from block hash (LE bytes 0–7 and 8–15)
    let k0 = u64::from_le_bytes(block_hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(block_hash[8..16].try_into().unwrap());

    // Hash each element to [0, N*M)
    let f = n * BASIC_FILTER_M;
    let mut hashed: Vec<u64> = elements
        .iter()
        .map(|elem| fast_range64(siphash_2_4(k0, k1, elem), f))
        .collect();

    hashed.sort_unstable();

    // Delta-encode + Golomb-Rice encode
    let mut bits = BitWriter::new();
    let mut prev = 0u64;
    for &val in &hashed {
        golomb_rice_encode(&mut bits, BASIC_FILTER_P, val - prev);
        prev = val;
    }

    let mut result = compact_size_encode(n);
    result.extend_from_slice(&bits.finish());
    result
}

/// Compute a filter header: `SHA256d(filter_hash || prev_header)`.
///
/// Both `filter_hash` and `prev_header` are 32-byte internal byte order.
pub fn compute_filter_header(filter_bytes: &[u8], prev_header: &[u8; 32]) -> [u8; 32] {
    let filter_hash = sha256d(filter_bytes);
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&filter_hash.0);
    preimage.extend_from_slice(prev_header);
    sha256d(&preimage).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_elements_produces_compact_zero() {
        let hash = [0u8; 32];
        let block = Block::new(rbtc_primitives::block::BlockHeader {
                version: 1,
                prev_block: rbtc_primitives::hash::BlockHash::ZERO,
                merkle_root: rbtc_primitives::hash::Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            }, vec![]);
        let filter = build_basic_filter(&hash, &block, &[]);
        assert_eq!(filter, vec![0x00]); // CompactSize(0)
    }

    #[test]
    fn filter_header_chain() {
        let filter = vec![0x00]; // empty filter
        let prev = [0u8; 32]; // genesis prev header
        let header = compute_filter_header(&filter, &prev);
        assert_ne!(header, [0u8; 32]); // non-trivial hash
    }
}
