use std::time::{SystemTime, UNIX_EPOCH};

use rbtc_crypto::sha256d;
use rbtc_primitives::{block::{Block, BlockHeader}, codec::Encodable};

use crate::template::BlockTemplate;

/// Get the current Unix timestamp in seconds (as u32).
fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

/// Serialize an 80-byte block header into a fixed-size buffer.
fn header_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    header.encode(&mut buf).unwrap_or_default();
    buf
}

/// CPU PoW miner.
///
/// Searches for a `nonce` (and occasionally increments `extra_nonce` when
/// the 32-bit nonce space is exhausted) until the block hash meets the
/// difficulty target encoded in `template.bits`.
///
/// For regtest (bits = `0x207fffff`) this completes in nanoseconds.
/// For mainnet this would run for a very long time without ASICs.
pub fn mine_block(template: &BlockTemplate) -> Block {
    let mut extra_nonce: u32 = 0;

    loop {
        // Rebuild the Merkle root once per extra_nonce (coinbase changes).
        let merkle_root = template.compute_merkle_root(extra_nonce);

        let mut time = now_secs();
        let mut iters: u64 = 0;

        for nonce in 0u32..=u32::MAX {
            // Refresh the timestamp every 1 000 000 iterations so we don't
            // produce a stale block time for slow miners.
            if iters > 0 && iters % 1_000_000 == 0 {
                time = now_secs();
            }

            let header = BlockHeader {
                version: template.version,
                prev_block: template.prev_hash,
                merkle_root,
                time,
                bits: template.bits,
                nonce,
            };

            let hash = sha256d(&header_bytes(&header));

            if header.meets_target(&hash) {
                // Reconstruct the full block with this winning nonce.
                let mut block = template.build_block(extra_nonce, time, nonce);
                // Ensure header fields match what we solved.
                block.header.time = time;
                block.header.nonce = nonce;
                return block;
            }

            iters += 1;
        }

        // All 2^32 nonces exhausted → increment extra_nonce and retry.
        extra_nonce = extra_nonce.wrapping_add(1);
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{hash::Hash256, script::Script};
    use crate::template::BlockTemplate;
    use rbtc_consensus::chain::header_hash;

    fn regtest_template() -> BlockTemplate {
        BlockTemplate::new(
            0x2000_0000,
            Hash256::ZERO,
            0x207f_ffff, // regtest: trivially easy
            1,
            0,
            vec![],
            Script::new(),
        )
    }

    #[test]
    fn mine_block_finds_solution_regtest() {
        let template = regtest_template();
        let block = mine_block(&template);

        // The block header must meet the target
        let hash = header_hash(&block.header);
        assert!(
            block.header.meets_target(&hash),
            "mined block does not meet target"
        );
    }

    #[test]
    fn mined_block_has_coinbase() {
        let template = regtest_template();
        let block = mine_block(&template);
        assert!(!block.transactions.is_empty());
        assert!(block.transactions[0].is_coinbase());
    }

    #[test]
    fn mined_block_correct_prev_hash() {
        let template = regtest_template();
        let block = mine_block(&template);
        assert_eq!(block.header.prev_block, Hash256::ZERO);
    }
}
