use std::collections::HashSet;

use rbtc_consensus::tx_verify::block_subsidy;
use rbtc_crypto::{merkle::merkle_root, sha256d};
use rbtc_primitives::{
    block::{nbits_to_target, Block, BlockHeader},
    codec::Encodable,
    constants::{MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR},
    hash::{BlockHash, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};

use rbtc_consensus::versionbits::{
    deployment_state, deployments, ThresholdState, VersionBitsBlockInfo,
};
use rbtc_primitives::network::Network;

use crate::error::MinerError;

/// Compute the block version by examining BIP9 deployment states.
///
/// Starts with the base version `0x20000000` and sets the signaling bit
/// for every deployment that is currently in `STARTED` or `LOCKED_IN` state.
pub fn compute_block_version(
    network: Network,
    height: u32,
    chain: &dyn VersionBitsBlockInfo,
) -> i32 {
    let mut version = 0x2000_0000i32;
    for dep in deployments(network) {
        let state = deployment_state(&dep, height, network, chain);
        if state == ThresholdState::Started || state == ThresholdState::LockedIn {
            version |= 1i32 << dep.bit;
        }
    }
    version
}

/// BIP141 witness commitment header: 0xaa21a9ed
const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// 32-byte zero witness reserved value (default nonce).
const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

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
///
/// If `witness_commitment` is provided, a BIP141 OP_RETURN output with the
/// witness commitment is appended, and the coinbase witness field is set to
/// the 32-byte reserved value.
pub fn build_coinbase(
    height: u32,
    extra_nonce: u32,
    value: i64,
    output_script: &Script,
    witness_commitment: Option<Hash256>,
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

    // Coinbase witness: 32-byte reserved value (BIP141)
    let witness = if witness_commitment.is_some() {
        vec![WITNESS_RESERVED_VALUE.to_vec()]
    } else {
        vec![]
    };

    let mut outputs = vec![TxOut {
        value,
        script_pubkey: output_script.clone(),
    }];

    // Witness commitment OP_RETURN output (BIP141)
    if let Some(commitment) = witness_commitment {
        let mut script_bytes = Vec::with_capacity(38);
        script_bytes.push(0x6a); // OP_RETURN
        script_bytes.push(0x24); // push 36 bytes
        script_bytes.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        script_bytes.extend_from_slice(&commitment.0);
        outputs.push(TxOut {
            value: 0,
            script_pubkey: Script::from_bytes(script_bytes),
        });
    }

    Transaction::from_parts(
        1,
        vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(script_sig_bytes),
            sequence: 0xffff_fffe, // MAX_SEQUENCE_NONFINAL — ensures timelock enforcement
            witness,
        }],
        outputs,
        height.saturating_sub(1), // anti-fee-sniping locktime (Bitcoin Core: nHeight - 1)
    )
}

/// Compute the BIP141 witness commitment for a block.
///
/// `commitment = SHA256d(witness_merkle_root || witness_reserved_value)`
///
/// The witness merkle root is computed from wtxids of all transactions,
/// with the coinbase wtxid replaced by the zero hash.
pub fn compute_witness_commitment(txs: &[Transaction]) -> Hash256 {
    let mut wtxids = Vec::with_capacity(txs.len() + 1);
    // Coinbase wtxid is always zero hash
    wtxids.push(Hash256::ZERO);
    for tx in txs {
        let mut buf = Vec::new();
        tx.encode(&mut buf).ok();
        wtxids.push(sha256d(&buf));
    }

    let (witness_root, _) = merkle_root(&wtxids);
    let witness_root = witness_root.unwrap_or(Hash256::ZERO);

    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&witness_root.0);
    preimage.extend_from_slice(&WITNESS_RESERVED_VALUE);
    sha256d(&preimage)
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
    /// Subsidy halving interval for the active network (210 000 mainnet, 150 regtest).
    pub halving_interval: u64,
    /// Total coinbase reward = subsidy + fees
    pub coinbase_value: i64,
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
        halving_interval: u64,
        fees: u64,
        transactions: Vec<Transaction>,
        output_script: Script,
    ) -> Self {
        let coinbase_value = block_subsidy(height, halving_interval) as i64 + fees as i64;
        Self {
            version,
            prev_hash,
            bits,
            height,
            halving_interval,
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

    /// Returns true if any non-coinbase transaction has witness data.
    fn has_witness_data(&self) -> bool {
        self.transactions.iter().any(|tx| tx.has_witness())
    }

    /// Compute the witness commitment if needed, or None if no witness data.
    fn witness_commitment(&self) -> Option<Hash256> {
        if self.has_witness_data() {
            Some(compute_witness_commitment(&self.transactions))
        } else {
            None
        }
    }

    /// Compute the Merkle root for the given `extra_nonce` without building
    /// the full block.  Used in the mining hot-path.
    pub fn compute_merkle_root(&self, extra_nonce: u32) -> Hash256 {
        let commitment = self.witness_commitment();
        let coinbase = build_coinbase(
            self.height,
            extra_nonce,
            self.coinbase_value,
            &self.output_script,
            commitment,
        );
        let coinbase_txid = compute_txid(&coinbase);

        let mut txids = vec![coinbase_txid];
        for tx in &self.transactions {
            txids.push(compute_txid(tx));
        }

        merkle_root(&txids).0.unwrap_or(Hash256::ZERO)
    }

    /// Validate the block template (TestBlockValidity equivalent).
    ///
    /// Performs structural checks on the assembled template without requiring
    /// a UTXO set.  Matches Bitcoin Core's `CheckBlock()` + `ContextualCheckBlock()`
    /// subset that doesn't need coin data:
    ///
    /// 1. Block weight within `MAX_BLOCK_WEIGHT`
    /// 2. Sigops cost within `MAX_BLOCK_SIGOPS_COST`
    /// 3. No duplicate txids
    /// 4. Coinbase value doesn't exceed subsidy + fees
    /// 5. Witness commitment (if present) is correct
    pub fn validate(&self) -> Result<(), MinerError> {
        // Build a test block to check weight
        let test_block = self.build_block(0, 0, 0);

        // 1. Weight check
        let weight = test_block.weight();
        if weight > MAX_BLOCK_WEIGHT {
            return Err(MinerError::TemplateInvalid(format!(
                "block weight {weight} exceeds limit {MAX_BLOCK_WEIGHT}"
            )));
        }

        // 2. Sigops cost check
        let mut total_sigops: u64 = 0;
        for tx in &test_block.transactions {
            let mut count = 0usize;
            for input in &tx.inputs {
                count += input.script_sig.count_sigops();
            }
            for output in &tx.outputs {
                count += output.script_pubkey.count_sigops();
            }
            total_sigops += (count as u64) * WITNESS_SCALE_FACTOR;
        }
        if total_sigops > MAX_BLOCK_SIGOPS_COST as u64 {
            return Err(MinerError::TemplateInvalid(format!(
                "sigops cost {total_sigops} exceeds limit {MAX_BLOCK_SIGOPS_COST}"
            )));
        }

        // 3. No duplicate txids
        let mut txids = HashSet::new();
        for tx in &test_block.transactions {
            let txid = compute_txid(tx);
            if !txids.insert(txid) {
                return Err(MinerError::TemplateInvalid(
                    "duplicate txid in block".into(),
                ));
            }
        }

        // 4. Coinbase value check
        let subsidy = block_subsidy(self.height, self.halving_interval) as i64;
        let max_value = subsidy + self.fees as i64;
        if self.coinbase_value > max_value {
            return Err(MinerError::TemplateInvalid(format!(
                "coinbase value {} exceeds subsidy {} + fees {}",
                self.coinbase_value, subsidy, self.fees
            )));
        }

        // 5. Witness commitment correctness (if any tx has witness)
        if self.has_witness_data() {
            let expected = compute_witness_commitment(&self.transactions);
            let coinbase = &test_block.transactions[0];
            let has_commitment = coinbase.outputs.iter().any(|out| {
                let s = out.script_pubkey.as_bytes();
                s.len() >= 38
                    && s[0] == 0x6a
                    && s[1] == 0x24
                    && s[2..6] == WITNESS_COMMITMENT_HEADER
                    && s[6..38] == expected.0
            });
            if !has_commitment {
                return Err(MinerError::TemplateInvalid(
                    "missing or incorrect witness commitment".into(),
                ));
            }
        }

        Ok(())
    }

    /// Build a complete candidate [`Block`] for the given PoW parameters.
    pub fn build_block(&self, extra_nonce: u32, time: u32, nonce: u32) -> Block {
        let commitment = self.witness_commitment();
        let coinbase = build_coinbase(
            self.height,
            extra_nonce,
            self.coinbase_value,
            &self.output_script,
            commitment,
        );
        let coinbase_txid = compute_txid(&coinbase);

        let mut txids = vec![coinbase_txid];
        for tx in &self.transactions {
            txids.push(compute_txid(tx));
        }

        let root = merkle_root(&txids).0.unwrap_or(Hash256::ZERO);

        let mut transactions = vec![coinbase];
        transactions.extend_from_slice(&self.transactions);

        Block::new(
            BlockHeader {
                version: self.version,
                prev_block: self.prev_hash,
                merkle_root: root,
                time,
                bits: self.bits,
                nonce,
            },
            transactions,
        )
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::BlockHash;

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
        let tx = build_coinbase(100, 0, 50_0000_0000, &script, None);
        assert!(tx.is_coinbase());
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 50_0000_0000);

        // scriptSig length must be 2–100 bytes
        let sig_len = tx.inputs[0].script_sig.len();
        assert!(sig_len >= 2, "scriptSig too short: {sig_len}");
        assert!(sig_len <= 100, "scriptSig too long: {sig_len}");
    }

    #[test]
    fn build_coinbase_with_witness_commitment() {
        let script = Script::new();
        let commitment = Hash256([0xab; 32]);
        let tx = build_coinbase(100, 0, 50_0000_0000, &script, Some(commitment));
        assert!(tx.is_coinbase());
        // Should have 2 outputs: reward + witness commitment OP_RETURN
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, 50_0000_0000);
        assert_eq!(tx.outputs[1].value, 0);
        // Check OP_RETURN structure
        let op_return = tx.outputs[1].script_pubkey.as_bytes();
        assert_eq!(op_return[0], 0x6a); // OP_RETURN
        assert_eq!(op_return[1], 0x24); // push 36 bytes
        assert_eq!(&op_return[2..6], &[0xaa, 0x21, 0xa9, 0xed]);
        assert_eq!(&op_return[6..38], &commitment.0);
        // Coinbase witness should be 32-byte reserved value
        assert_eq!(tx.inputs[0].witness.len(), 1);
        assert_eq!(tx.inputs[0].witness[0].len(), 32);
    }

    #[test]
    fn build_coinbase_height_encoded() {
        let script = Script::new();
        // Height 200 needs sign extension (0xC8 has MSB set)
        let tx = build_coinbase(200, 0, 0, &script, None);
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
            BlockHash::ZERO,
            0x207f_ffff, // regtest
            1,
            210_000,
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
            BlockHash::ZERO,
            0x207f_ffff,
            0, // genesis height → 50 BTC subsidy
            210_000,
            1000,
            vec![],
            Script::new(),
        );
        // subsidy(0) = 50_0000_0000, fees = 1000
        assert_eq!(template.coinbase_value, 50_0000_0000 + 1000);
    }

    #[test]
    fn block_template_validate_ok() {
        let template = BlockTemplate::new(
            0x2000_0000,
            BlockHash::ZERO,
            0x207f_ffff,
            1,
            210_000,
            0,
            vec![],
            Script::new(),
        );
        assert!(template.validate().is_ok());
    }

    #[test]
    fn block_template_validate_bad_coinbase_value() {
        let mut template = BlockTemplate::new(
            0x2000_0000,
            BlockHash::ZERO,
            0x207f_ffff,
            1,
            210_000,
            0,
            vec![],
            Script::new(),
        );
        // Artificially inflate coinbase value beyond subsidy + fees
        template.coinbase_value = i64::MAX;
        assert!(template.validate().is_err());
    }

    #[test]
    fn block_template_target_hex_length() {
        let template =
            BlockTemplate::new(1, BlockHash(Hash256::ZERO), 0x207f_ffff, 0, 210_000, 0, vec![], Script::new());
        let hex = template.target_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }

    // ── compute_block_version tests ──────────────────────────────────────

    /// A mock chain for testing compute_block_version.
    struct MockChainInfo {
        versions: Vec<i32>,
        mtps: Vec<u32>,
    }

    impl VersionBitsBlockInfo for MockChainInfo {
        fn median_time_past(&self, height: u32) -> u32 {
            self.mtps.get(height as usize).copied().unwrap_or(0)
        }
        fn block_version(&self, height: u32) -> i32 {
            self.versions.get(height as usize).copied().unwrap_or(1)
        }
    }

    #[test]
    fn compute_block_version_regtest_always_active() {
        // On regtest all deployments are "always active" (start_time=0),
        // so no bits should be set beyond the base version.
        let chain = MockChainInfo {
            versions: vec![],
            mtps: vec![],
        };
        let v = compute_block_version(Network::Regtest, 100, &chain);
        assert_eq!(v, 0x2000_0000);
    }

    #[test]
    fn compute_block_version_sets_bit_for_started_deployment() {
        // Create a deployment on mainnet that is in the STARTED state.
        // CSV deployment (bit 0): start_time=1462060800.
        // We need MTP past start_time but before timeout.
        // Period 0: 0..2015 with low MTP -> DEFINED
        // Period 1: MTP[2015] >= start_time -> STARTED
        // We query at height 4032 (period 2), where we need MTP[4031] < timeout
        // and count in period 1 below threshold -> remains STARTED.
        let mut mtps = vec![1_400_000_000u32; 2016]; // period 0: before start
        mtps.extend(vec![1_463_000_000u32; 2016]);    // period 1: after CSV start
        mtps.extend(vec![1_464_000_000u32; 2016]);    // period 2: still before timeout
        // No signaling (old-style version=1, no BIP9 top bits)
        let versions = vec![1i32; 6048];
        let chain = MockChainInfo { versions, mtps };

        let v = compute_block_version(Network::Mainnet, 4032, &chain);
        // CSV bit (0) should be set because deployment is STARTED
        assert_ne!(v & (1 << 0), 0, "CSV bit should be set");
        // Base version bits preserved
        assert_eq!(v & 0x2000_0000, 0x2000_0000);
    }

    #[test]
    fn compute_block_version_base_version_when_all_active() {
        // On mainnet at a very late height where all deployments are ACTIVE
        // or FAILED, no signaling bits should be set.
        // All deployments have timeout < 2_000_000_000, so with high MTP
        // and no signaling, they should all be FAILED (not meeting threshold).
        // Actually CSV/segwit/taproot all have real timeouts, and without
        // signaling they'd be FAILED. FAILED does not set bits.
        let mtps = vec![2_000_000_000u32; 100_000];
        let versions = vec![1i32; 100_000]; // no signaling
        let chain = MockChainInfo { versions, mtps };

        let v = compute_block_version(Network::Mainnet, 90_000, &chain);
        // All deployments should be FAILED -> no bits set
        assert_eq!(v, 0x2000_0000);
    }

    // ── M18: coinbase sequence 0xFFFFFFFE ──────────────────────────────

    #[test]
    fn coinbase_sequence_is_nonfinal() {
        // Bitcoin Core sets coinbase vin[0].nSequence = 0xFFFFFFFE
        // (MAX_SEQUENCE_NONFINAL) to ensure timelock enforcement.
        let script = Script::new();
        let tx = build_coinbase(100, 0, 50_0000_0000, &script, None);
        assert_eq!(
            tx.inputs[0].sequence, 0xffff_fffe,
            "coinbase sequence must be 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL)"
        );
    }

    // ── M19: coinbase locktime = height - 1 ────────────────────────────

    #[test]
    fn coinbase_locktime_anti_fee_sniping() {
        // Bitcoin Core sets coinbaseTx.nLockTime = nHeight - 1.
        let script = Script::new();
        let tx = build_coinbase(500, 0, 50_0000_0000, &script, None);
        assert_eq!(
            tx.lock_time, 499,
            "coinbase locktime must be height - 1 for anti-fee-sniping"
        );
    }

    #[test]
    fn coinbase_locktime_genesis_safety() {
        // At height 0, saturating_sub(1) should yield 0 (no underflow).
        let script = Script::new();
        let tx = build_coinbase(0, 0, 50_0000_0000, &script, None);
        assert_eq!(tx.lock_time, 0, "locktime at genesis must be 0");
    }

    #[test]
    fn coinbase_locktime_height_one() {
        let script = Script::new();
        let tx = build_coinbase(1, 0, 50_0000_0000, &script, None);
        assert_eq!(tx.lock_time, 0, "locktime at height 1 must be 0");
    }
}
