use rbtc_crypto::sha256d;
/// BIP158 compact block filter test vectors from Bitcoin Core.
///
/// Format: [height, block_hash, raw_block_hex, [prev_output_scripts], prev_basic_header,
///          basic_filter_hex, basic_header_hex, notes]
///
/// Tests:
/// 1. Construct basic filter from block data + prev output scripts
/// 2. Verify filter matches expected hex
/// 3. Verify filter header chain
use rbtc_primitives::{
    codec::{Decodable, VarInt},
    transaction::Transaction,
};
use serde_json::Value;
use siphasher::sip::SipHasher24;
use std::collections::HashSet;
use std::hash::Hasher;

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex '{s}': {e}"))
}

// ── BIP158 GCS implementation ─────────────────────────────────────────────────

const BASIC_FILTER_P: u8 = 19;
const BASIC_FILTER_M: u64 = 784931;

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
struct BitWriter {
    data: Vec<u8>,
    current: u8,
    bits_used: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            current: 0,
            bits_used: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) {
        self.current |= (bit & 1) << (7 - self.bits_used);
        self.bits_used += 1;
        if self.bits_used == 8 {
            self.data.push(self.current);
            self.current = 0;
            self.bits_used = 0;
        }
    }

    fn write_bits(&mut self, value: u64, count: u8) {
        for i in (0..count).rev() {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }

    fn finish(mut self) -> Vec<u8> {
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

/// Construct a BIP158 basic filter for a block.
fn build_basic_filter(
    block_hash: &[u8; 32],
    output_scripts: &[Vec<u8>],
    prev_output_scripts: &[Vec<u8>],
) -> Vec<u8> {
    // Collect unique elements: non-empty, non-OP_RETURN output scripts + prev output scripts
    let mut elements = HashSet::new();
    for script in output_scripts {
        if script.is_empty() || script[0] == 0x6a {
            continue;
        }
        elements.insert(script.clone());
    }
    for script in prev_output_scripts {
        if script.is_empty() {
            continue;
        }
        elements.insert(script.clone());
    }

    let n = elements.len() as u64;
    if n == 0 {
        return compact_size_encode(0);
    }

    // Derive SipHash key from block hash (LE bytes 0-7 and 8-15)
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

#[test]
fn bip158_blockfilter_vectors() {
    let json_text = include_str!("data/blockfilters.json");
    let data: Value = serde_json::from_str(json_text).expect("parse blockfilters.json");
    let cases = data.as_array().unwrap();

    let mut total = 0usize;
    let mut failures = Vec::<String>::new();

    for (i, case) in cases.iter().enumerate() {
        let arr = case.as_array().unwrap();

        // Skip header row
        if arr[0].is_string() {
            continue;
        }

        let height = arr[0].as_u64().unwrap();
        let block_hash_hex = arr[1].as_str().unwrap();
        let raw_block_hex = arr[2].as_str().unwrap();
        let prev_scripts_arr = arr[3].as_array().unwrap();
        let prev_basic_header_hex = arr[4].as_str().unwrap();
        let expected_filter_hex = arr[5].as_str().unwrap();
        let expected_header_hex = arr[6].as_str().unwrap();

        total += 1;

        // Parse block hash (display order → internal LE)
        let block_hash_display = decode_hex(block_hash_hex);
        let mut block_hash = [0u8; 32];
        for j in 0..32 {
            block_hash[j] = block_hash_display[31 - j];
        }

        // Parse transactions from raw block (skip 80-byte header)
        let block_bytes = decode_hex(raw_block_hex);
        let mut cursor = std::io::Cursor::new(&block_bytes[80..]);
        let VarInt(tx_count) = VarInt::decode(&mut cursor).unwrap();
        let mut txs = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            txs.push(Transaction::decode(&mut cursor).unwrap());
        }

        // Collect all output scriptPubKeys
        let output_scripts: Vec<Vec<u8>> = txs
            .iter()
            .flat_map(|tx| {
                tx.outputs
                    .iter()
                    .map(|o| o.script_pubkey.as_bytes().to_vec())
            })
            .collect();

        // Parse previous output scripts from test vector
        let prev_output_scripts: Vec<Vec<u8>> = prev_scripts_arr
            .iter()
            .map(|s| decode_hex(s.as_str().unwrap()))
            .collect();

        // Build the filter
        let got_filter = build_basic_filter(&block_hash, &output_scripts, &prev_output_scripts);
        let got_filter_hex = hex::encode(&got_filter);

        if got_filter_hex != expected_filter_hex {
            failures.push(format!(
                "[{i}] height={height}: filter mismatch\n  expected={expected_filter_hex}\n  got     ={got_filter_hex}"
            ));
            continue;
        }

        // Verify filter header: sha256d(filter_hash || prev_header)
        // Test vector stores prev_header and expected_header in display order (reversed).
        // We need to reverse prev_header to get internal byte order for computation.
        let filter_hash = sha256d(&got_filter);
        let mut prev_header_bytes = decode_hex(prev_basic_header_hex);
        prev_header_bytes.reverse(); // display → internal
        let mut header_preimage = Vec::with_capacity(64);
        header_preimage.extend_from_slice(&filter_hash.0);
        header_preimage.extend_from_slice(&prev_header_bytes);
        let got_header = sha256d(&header_preimage);

        // Reverse result back to display order for comparison
        let mut got_header_display = got_header.0;
        got_header_display.reverse();
        let got_header_hex = hex::encode(got_header_display);

        if got_header_hex != expected_header_hex {
            failures.push(format!(
                "[{i}] height={height}: header mismatch\n  expected={expected_header_hex}\n  got     ={got_header_hex}"
            ));
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  FAIL: {f}");
        }
        panic!("{} / {total} blockfilter cases failed", failures.len());
    }

    println!("blockfilters.json: {total} cases all passed");
}
