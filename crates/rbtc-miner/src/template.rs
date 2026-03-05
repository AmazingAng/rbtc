use rbtc_consensus::tx_verify::block_subsidy;
use rbtc_crypto::{merkle::merkle_root, sha256d};
use rbtc_primitives::{
    block::{nbits_to_target, Block, BlockHeader},
    hash::{BlockHash, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};

/// Encode block height as a CScriptNum push for BIP34 coinbase scriptSig.
///
/// Returns bytes: `[push_len, byte0, byte1, ...]` in little-endian.
/// Heights 0–127 → 1 byte value; 128–32767 → 2 bytes (with sign-safe padding).
pub fn encode_height_push(height: u32) -> Vec<u8> {
    if height == 0 {
        // CScriptNum(0) = empty, but coinbase scriptSig must be ≥ 2 bytes.
        // Use `01 00` (push 1 byte, value 0x00).
        return vec![0x01, 0x00];
    }

    // Convert to little-endian, strip trailing zeros
    let mut bytes: Vec<u8> = height.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }

    // If the most-significant byte has its high bit set, Bitcoin CScriptNum
    // requires an extra 0x00 byte to distinguish positive from negative.
    if bytes.last().map(|&b| b & 0x80 != 0).unwrap_or(false) {
        bytes.push(0x00);
    }

    let mut script = vec![bytes.len() as u8];
    script.extend_from_slice(&bytes);
    script
}

/// Build a coinbase transaction.
///
/// The scriptSig is:
///   `<height_push> <0x04 extra_nonce_bytes> <0x05 "rbtc\0">`
/// This is always in the 2–100 byte range for any practical block height.
pub fn build_coinbase(
    height: u32,
    extra_nonce: u32,
    value: u64,
    output_script: &Script,
) -> Transaction {
    let height_push = encode_height_push(height);

    // extra_nonce push: opcode 0x04 = push 4 bytes
    let en_bytes = extra_nonce.to_le_bytes();
    let mut extra_nonce_push = vec![0x04];
    extra_nonce_push.extend_from_slice(&en_bytes);

    // Optional coinbase tag (5 bytes)
    let tag: &[u8] = &[0x05, b'r', b'b', b't', b'c', 0x00];

    let mut script_sig_bytes = Vec::new();
    script_sig_bytes.extend_from_slice(&height_push);
    script_sig_bytes.extend_from_slice(&extra_nonce_push);
    script_sig_bytes.extend_from_slice(tag);

    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(script_sig_bytes),
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: output_script.clone(),
        }],
        lock_time: 0,
    }
}

/// Compute the txid (double-SHA256 of legacy serialization) for a transaction.
pub fn compute_txid(tx: &Transaction) -> Hash256 {
    let mut buf = Vec::new();
    tx.encode_legacy(&mut buf).unwrap_or_default();
    sha256d(&buf)
}

/// A block template ready for PoW mining.
///
/// Contains everything needed to build candidate blocks except `nonce`
/// and `extra_nonce`. Call [`BlockTemplate::build_block`] to produce a
/// full [`Block`] for a given `(extra_nonce, time, nonce)` triple.
#[derive(Clone)]
pub struct BlockTemplate {
    pub version: i32,
    pub prev_hash: BlockHash,
    pub bits: u32,
    pub height: u32,
    /// Total coinbase reward = subsidy + fees
    pub coinbase_value: u64,
    /// Non-coinbase transactions selected from the mempool
    pub transactions: Vec<Transaction>,
    /// Total fees from selected transactions (satoshis)
    pub fees: u64,
    /// Script to pay the coinbase reward to (miner's address)
    pub output_script: Script,
}

impl BlockTemplate {
    /// Create a new block template.
    ///
    /// `fees` and `transactions` come from [`crate::selector::TxSelector`].
    pub fn new(
        version: i32,
        prev_hash: BlockHash,
        bits: u32,
        height: u32,
        fees: u64,
        transactions: Vec<Transaction>,
        output_script: Script,
    ) -> Self {
        let coinbase_value = block_subsidy(height) + fees;
        Self {
            version,
            prev_hash,
            bits,
            height,
            coinbase_value,
            transactions,
            fees,
            output_script,
        }
    }

    /// Expand `bits` to the 32-byte little-endian target.
    pub fn target(&self) -> [u8; 32] {
        nbits_to_target(self.bits)
    }

    /// Serialize the `bits` as an 8-character hex string (e.g. `"207fffff"`).
    pub fn bits_hex(&self) -> String {
        format!("{:08x}", self.bits)
    }

    /// Return the target as a 64-character big-endian hex string.
    ///
    /// Bitcoin target is stored little-endian internally; external display
    /// (and BIP22) uses big-endian.
    pub fn target_hex(&self) -> String {
        let mut t = self.target();
        t.reverse();
        hex::encode(t)
    }

    /// Compute the Merkle root for the given `extra_nonce` without building
    /// the full block.  Used in the mining hot-path.
    pub fn compute_merkle_root(&self, extra_nonce: u32) -> Hash256 {
        let coinbase = build_coinbase(
            self.height,
            extra_nonce,
            self.coinbase_value,
            &self.output_script,
        );
        let coinbase_txid = compute_txid(&coinbase);

        let mut txids = vec![coinbase_txid];
        for tx in &self.transactions {
            txids.push(compute_txid(tx));
        }

        merkle_root(&txids).unwrap_or(Hash256::ZERO)
    }

    /// Build a complete candidate [`Block`] for the given PoW parameters.
    pub fn build_block(&self, extra_nonce: u32, time: u32, nonce: u32) -> Block {
        let coinbase = build_coinbase(
            self.height,
            extra_nonce,
            self.coinbase_value,
            &self.output_script,
        );
        let coinbase_txid = compute_txid(&coinbase);

        let mut txids = vec![coinbase_txid];
        for tx in &self.transactions {
            txids.push(compute_txid(tx));
        }

        let root = merkle_root(&txids).unwrap_or(Hash256::ZERO);

        let mut transactions = vec![coinbase];
        transactions.extend_from_slice(&self.transactions);

        Block {
            header: BlockHeader {
                version: self.version,
                prev_block: self.prev_hash,
                merkle_root: root,
                time,
                bits: self.bits,
                nonce,
            },
            transactions,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;

    #[test]
    fn encode_height_push_zero() {
        let p = encode_height_push(0);
        // Must be `01 00`
        assert_eq!(p, vec![0x01, 0x00]);
        // Total len ≥ 2
        assert!(p.len() >= 2);
    }

    #[test]
    fn encode_height_push_small() {
        // Height 1 → `01 01`
        let p = encode_height_push(1);
        assert_eq!(p[0], 0x01); // push 1 byte
        assert_eq!(p[1], 0x01); // value 1

        // Height 127 → `01 7f` (no sign extension needed)
        let p = encode_height_push(127);
        assert_eq!(p[0], 0x01);
        assert_eq!(p[1], 0x7f);
    }

    #[test]
    fn encode_height_push_sign_extension() {
        // Height 128 = 0x80 needs sign extension → `02 80 00`
        let p = encode_height_push(128);
        assert_eq!(p[0], 0x02); // push 2 bytes
        assert_eq!(p[1], 0x80);
        assert_eq!(p[2], 0x00);
    }

    #[test]
    fn encode_height_push_large() {
        // Height 100_000
        let p = encode_height_push(100_000);
        assert!(p.len() >= 2);
        // Decode back
        let push_len = p[0] as usize;
        let mut h = 0u32;
        for i in 0..push_len {
            h |= (p[1 + i] as u32) << (8 * i);
        }
        assert_eq!(h, 100_000);
    }

    #[test]
    fn build_coinbase_structure() {
        let script = Script::new();
        let tx = build_coinbase(100, 0, 50_0000_0000, &script);
        assert!(tx.is_coinbase());
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 50_0000_0000);

        // scriptSig length must be 2–100 bytes
        let sig_len = tx.inputs[0].script_sig.len();
        assert!(sig_len >= 2, "scriptSig too short: {sig_len}");
        assert!(sig_len <= 100, "scriptSig too long: {sig_len}");
    }

    #[test]
    fn build_coinbase_height_encoded() {
        let script = Script::new();
        // Height 200 needs sign extension (0xC8 has MSB set)
        let tx = build_coinbase(200, 0, 0, &script);
        let script_bytes = tx.inputs[0].script_sig.as_bytes();
        let push_len = script_bytes[0] as usize;
        assert!(push_len >= 1 && push_len <= 4);
        let mut h = 0u32;
        for i in 0..push_len {
            h |= (script_bytes[1 + i] as u32) << (8 * i);
        }
        assert_eq!(h, 200);
    }

    #[test]
    fn block_template_build_block() {
        let template = BlockTemplate::new(
            0x2000_0000,
            Hash256::ZERO,
            0x207f_ffff, // regtest
            1,
            0,
            vec![],
            Script::new(),
        );
        let block = template.build_block(0, 1_700_000_000, 0);
        assert_eq!(block.transactions.len(), 1); // coinbase only
        assert!(block.transactions[0].is_coinbase());
        assert_eq!(block.header.bits, 0x207f_ffff);
        assert_eq!(block.header.nonce, 0);
    }

    #[test]
    fn block_template_coinbase_value() {
        let template = BlockTemplate::new(
            1,
            Hash256::ZERO,
            0x207f_ffff,
            0, // genesis height → 50 BTC subsidy
            1000,
            vec![],
            Script::new(),
        );
        // subsidy(0) = 50_0000_0000, fees = 1000
        assert_eq!(template.coinbase_value, 50_0000_0000 + 1000);
    }

    #[test]
    fn block_template_target_hex_length() {
        let template =
            BlockTemplate::new(1, Hash256::ZERO, 0x207f_ffff, 0, 0, vec![], Script::new());
        let hex = template.target_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }
}
