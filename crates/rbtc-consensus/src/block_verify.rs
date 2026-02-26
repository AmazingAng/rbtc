use std::collections::HashMap;
use rbtc_primitives::{
    block::Block,
    codec::Encodable,
    constants::{MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, MAX_FUTURE_BLOCK_TIME, WITNESS_SCALE_FACTOR},
    hash::Hash256,
    Network,
};
use rbtc_crypto::{merkle_root, sha256d};
use rbtc_script::ScriptFlags;

use crate::{
    error::ConsensusError,
    tx_verify::{block_subsidy, verify_coinbase, verify_transaction_with_lock_rules, MedianTimeProvider},
    utxo::{Utxo, UtxoLookup},
};

/// A layered UTXO view: newly-created outputs from earlier txs in the same
/// block are visible here, falling back to the real UTXO set for older coins.
struct BlockUtxoView<'a, U: UtxoLookup> {
    /// Outputs produced by transactions already verified in this block.
    in_block: HashMap<rbtc_primitives::transaction::OutPoint, Utxo>,
    /// The persistent UTXO set (CachedUtxoSet / UtxoSet).
    base: &'a U,
}

impl<U: UtxoLookup> UtxoLookup for BlockUtxoView<'_, U> {
    fn get_utxo(&self, outpoint: &rbtc_primitives::transaction::OutPoint) -> Option<Utxo> {
        self.in_block.get(outpoint).cloned().or_else(|| self.base.get_utxo(outpoint))
    }

    fn has_unspent_txid(&self, txid: &rbtc_primitives::hash::TxId) -> bool {
        self.in_block.keys().any(|outpoint| &outpoint.txid == txid) || self.base.has_unspent_txid(txid)
    }
}

/// Context needed for full block validation
pub struct BlockValidationContext<'a> {
    /// The block to validate
    pub block: &'a Block,
    /// Height of this block
    pub height: u32,
    /// Previous 11 block timestamps for MTP (oldest first)
    pub median_time_past: u32,
    /// Current network time (for future timestamp check)
    pub network_time: u32,
    /// Expected nBits (already validated by caller or from chain)
    pub expected_bits: u32,
    /// Script verification flags
    pub flags: ScriptFlags,
    /// Network (for BIP34 and other consensus params)
    pub network: Network,
    /// Chain MTP lookup by height (used by BIP68 relative time locks).
    pub mtp_provider: &'a dyn MedianTimeProvider,
}

/// Verify a complete block against the UTXO set.
/// Returns total fees collected on success.
pub fn verify_block(
    ctx: &BlockValidationContext<'_>,
    utxos: &impl UtxoLookup,
) -> Result<u64, ConsensusError> {
    let block = ctx.block;
    let header = &block.header;

    // ── Header checks ────────────────────────────────────────────────────
    verify_block_header(header, ctx.expected_bits, ctx.median_time_past, ctx.network_time)?;

    // ── Structural checks ────────────────────────────────────────────────
    if block.transactions.is_empty() {
        return Err(ConsensusError::FirstTxNotCoinbase);
    }

    // First tx must be coinbase, no other tx may be coinbase
    if !block.transactions[0].is_coinbase() {
        return Err(ConsensusError::FirstTxNotCoinbase);
    }
    for tx in &block.transactions[1..] {
        if tx.is_coinbase() {
            return Err(ConsensusError::DuplicateCoinbase);
        }
    }

    // ── Merkle root ──────────────────────────────────────────────────────
    let txids: Vec<Hash256> = block.transactions.iter().map(compute_txid).collect();
    let computed_root = merkle_root(&txids).unwrap_or(Hash256::ZERO);
    if computed_root != header.merkle_root {
        return Err(ConsensusError::BadMerkleRoot);
    }

    // ── Block weight ─────────────────────────────────────────────────────
    let weight = block.weight();
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ConsensusError::BlockTooLarge(weight, MAX_BLOCK_WEIGHT));
    }

    // ── Witness commitment (BIP141) ──────────────────────────────────────
    if ctx.flags.verify_witness {
        verify_witness_commitment(block)?;
    }

    // ── BIP30 duplicate-txid check ────────────────────────────────────────
    enforce_bip30(block, ctx.height, ctx.network, utxos)?;

    // ── Transaction verification + sigops + fees ─────────────────────────
    let subsidy = block_subsidy(ctx.height);

    // Verify coinbase (sequential, must be first)
    verify_coinbase(&block.transactions[0], ctx.height, u64::MAX, ctx.network)?;
    let coinbase_sigops = count_block_sigops(&block.transactions[0]) as u64;

    // Sequential verification of non-coinbase transactions.
    //
    // Transactions within a block may spend outputs created by earlier
    // transactions in the same block ("intra-block chaining").  We maintain a
    // `BlockUtxoView` that layers newly-verified outputs on top of the
    // persistent UTXO set so that later transactions can see them.
    let non_coinbase = &block.transactions[1..];

    let mut block_view = BlockUtxoView { in_block: HashMap::new(), base: utxos };
    let mut total_fees: u64 = 0;
    let mut non_coinbase_sigops: u64 = 0;

    for tx in non_coinbase {
        let lock_time_cutoff = if ctx.flags.verify_checksequenceverify {
            ctx.median_time_past
        } else {
            block.header.time
        };
        let fee = verify_transaction_with_lock_rules(
            tx,
            &block_view,
            ctx.height,
            ctx.flags,
            lock_time_cutoff,
            ctx.mtp_provider,
            true,
        )?;
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(ConsensusError::InputValueOverflow)?;
        non_coinbase_sigops += count_block_sigops(tx) as u64 * WITNESS_SCALE_FACTOR;

        // Add this transaction's outputs to the in-block view so that
        // subsequent transactions in the same block can spend them.
        let txid = compute_txid(tx);
        for (vout, txout) in tx.outputs.iter().enumerate() {
            let outpoint = rbtc_primitives::transaction::OutPoint { txid, vout: vout as u32 };
            block_view.in_block.insert(outpoint, Utxo {
                txout: txout.clone(),
                is_coinbase: false,
                height: ctx.height,
            });
        }
    }

    let total_sigops = coinbase_sigops + non_coinbase_sigops;
    if total_sigops > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::TooManySignatureOps(total_sigops, MAX_BLOCK_SIGOPS_COST));
    }

    // Check coinbase value does not exceed subsidy + fees
    let max_allowed = subsidy.checked_add(total_fees).unwrap_or(u64::MAX);
    let coinbase_out: u64 = block.transactions[0].outputs.iter().map(|o| o.value).sum();
    if coinbase_out > max_allowed {
        return Err(ConsensusError::BadCoinbaseAmount(coinbase_out, max_allowed));
    }

    Ok(total_fees)
}

/// Verify block header (PoW, timestamp, nBits)
pub fn verify_block_header(
    header: &rbtc_primitives::block::BlockHeader,
    expected_bits: u32,
    median_time_past: u32,
    network_time: u32,
) -> Result<(), ConsensusError> {
    // PoW check
    let header_bytes = encode_block_header(header);
    let hash = sha256d(&header_bytes);

    if !header.meets_target(&hash) {
        return Err(ConsensusError::BadProofOfWork);
    }

    // nBits must match expected
    if header.bits != expected_bits {
        return Err(ConsensusError::BadBits(header.bits));
    }

    // Timestamp must be > MTP
    if header.time <= median_time_past {
        return Err(ConsensusError::TimestampTooOld);
    }

    // Timestamp must be < network_time + 2 hours
    if header.time > network_time.saturating_add(MAX_FUTURE_BLOCK_TIME as u32) {
        return Err(ConsensusError::TimestampTooNew);
    }

    Ok(())
}

/// Count sigops in a transaction (base cost, not witness-scaled)
fn count_block_sigops(tx: &rbtc_primitives::transaction::Transaction) -> usize {
    let mut count = 0;
    for input in &tx.inputs {
        count += input.script_sig.count_sigops();
    }
    for output in &tx.outputs {
        count += output.script_pubkey.count_sigops();
    }
    count
}

/// BIP141 witness commitment verification
fn verify_witness_commitment(block: &Block) -> Result<(), ConsensusError> {
    let coinbase = &block.transactions[0];

    // Find OP_RETURN output with witness commitment
    let commitment_output = coinbase.outputs.iter().rev().find(|o| {
        let bytes = o.script_pubkey.as_bytes();
        bytes.len() >= 38
            && bytes[0] == 0x6a  // OP_RETURN
            && bytes[1] == 0x24  // push 36 bytes
            && bytes[2] == 0xaa  // commitment header
            && bytes[3] == 0x21
            && bytes[4] == 0xa9
            && bytes[5] == 0xed
    });

    // If no witness data in the block, commitment is optional
    let has_witness = block.transactions.iter().any(|tx| tx.has_witness());
    if !has_witness {
        return Ok(());
    }

    let commitment_output = commitment_output
        .ok_or(ConsensusError::BadCoinbaseWitnessCommitment)?;

    let expected_commitment = &commitment_output.script_pubkey.as_bytes()[6..38];

    // Compute witness txids (wtxids)
    let mut wtxids = Vec::with_capacity(block.transactions.len());
    // Coinbase wtxid is always the zero hash
    wtxids.push(Hash256::ZERO);
    for tx in &block.transactions[1..] {
        let mut buf = Vec::new();
        use rbtc_primitives::codec::Encodable;
        tx.encode(&mut buf).ok();
        wtxids.push(sha256d(&buf));
    }

    let witness_merkle_root = rbtc_crypto::merkle_root(&wtxids).unwrap_or(Hash256::ZERO);

    // commitment = SHA256d(witness_merkle_root || witness_reserved_value)
    // witness_reserved_value is in coinbase input witness[0] (should be 32 zero bytes)
    let reserved = coinbase.inputs[0].witness.first()
        .map(|w| w.as_slice())
        .unwrap_or(&[0u8; 32]);

    let mut commit_preimage = Vec::with_capacity(64);
    commit_preimage.extend_from_slice(&witness_merkle_root.0);
    commit_preimage.extend_from_slice(reserved);
    let commitment = sha256d(&commit_preimage);

    if commitment.0 != expected_commitment {
        return Err(ConsensusError::BadCoinbaseWitnessCommitment);
    }

    Ok(())
}

fn compute_txid(tx: &rbtc_primitives::transaction::Transaction) -> Hash256 {
    let mut buf = Vec::new();
    tx.encode_legacy(&mut buf).ok();
    sha256d(&buf)
}

fn enforce_bip30(
    block: &Block,
    height: u32,
    network: Network,
    utxos: &impl UtxoLookup,
) -> Result<(), ConsensusError> {
    // Mainnet historical exceptions (pre-BIP34 duplicate-coinbase blocks).
    if network == Network::Mainnet && (height == 91_842 || height == 91_880) {
        return Ok(());
    }
    for tx in block.transactions.iter().skip(1) {
        let txid = compute_txid(tx);
        if utxos.has_unspent_txid(&txid) {
            return Err(ConsensusError::Bip30Conflict(txid.to_hex()));
        }
    }
    Ok(())
}

pub fn encode_block_header(header: &rbtc_primitives::block::BlockHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    header.version.encode(&mut buf).ok();
    header.prev_block.0.encode(&mut buf).ok();
    header.merkle_root.0.encode(&mut buf).ok();
    header.time.encode(&mut buf).ok();
    header.bits.encode(&mut buf).ok();
    header.nonce.encode(&mut buf).ok();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::block::{Block, BlockHeader};
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use rbtc_primitives::Network;
    use rbtc_script::ScriptFlags;
    use crate::utxo::UtxoSet;

    struct TestMtpProvider;
    impl MedianTimeProvider for TestMtpProvider {
        fn median_time_past_at_height(&self, _height: u32) -> u32 {
            0
        }
    }

    fn header_with_bits(bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            time: 100000,
            bits,
            nonce: 0,
        }
    }

    fn header_with_valid_pow(bits: u32) -> BlockHeader {
        let mut header = header_with_bits(bits);
        for nonce in 0..=u32::MAX {
            header.nonce = nonce;
            let encoded = encode_block_header(&header);
            let hash = sha256d(&encoded);
            if header.meets_target(&hash) {
                return header;
            }
        }
        panic!("failed to find nonce meeting target for bits={bits:#x}");
    }

    #[test]
    fn verify_block_header_timestamp_too_new() {
        let h = header_with_valid_pow(0x207fffff);
        // header.time (100000) must be <= network_time + 7200; use network_time=90000 so 97200 < 100000 -> too new
        let r = verify_block_header(&h, h.bits, 0, 90000);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::TimestampTooNew));
    }

    #[test]
    fn verify_block_empty_txs() {
        let h = header_with_valid_pow(0x207fffff);
        let block = Block { header: h, transactions: vec![] };
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 0,
            network_time: 200000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
        };
        let r = verify_block(&ctx, &UtxoSet::new());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::FirstTxNotCoinbase));
    }

    #[test]
    fn verify_block_first_not_coinbase() {
        let h = header_with_valid_pow(0x207fffff);
        let non_cb = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([1; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 0, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        assert!(!non_cb.is_coinbase());
        let block = Block { header: h, transactions: vec![non_cb] };
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 0,
            network_time: 200000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
        };
        let r = verify_block(&ctx, &UtxoSet::new());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::FirstTxNotCoinbase));
    }

    #[test]
    fn verify_block_duplicate_coinbase() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let h = header_with_valid_pow(0x207fffff);
        let block = Block { header: h, transactions: vec![coinbase.clone(), coinbase] };
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 0,
            network_time: 200000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
        };
        let r = verify_block(&ctx, &UtxoSet::new());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::DuplicateCoinbase));
    }

    #[test]
    fn verify_block_bad_merkle_root() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let mut h = header_with_valid_pow(0x207fffff);
        h.merkle_root = Hash256([0xff; 32]); // wrong root
        let block = Block { header: h, transactions: vec![coinbase] };
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 0,
            network_time: 200000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
        };
        let r = verify_block(&ctx, &UtxoSet::new());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::BadMerkleRoot));
    }

    #[test]
    fn verify_block_bad_coinbase_amount() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 100_0000_0000, script_pubkey: Script::new() }], // > subsidy
            lock_time: 0,
        };
        let mut buf = Vec::new();
        coinbase.encode_legacy(&mut buf).ok();
        let txid = sha256d(&buf);
        let merkle = rbtc_crypto::merkle_root(&[txid]).unwrap();
        let mut h = header_with_bits(0x207fffff);
        h.merkle_root = merkle;
        for nonce in 0..=0x10000u32 {
            h.nonce = nonce;
            let enc = encode_block_header(&h);
            let hash = sha256d(&enc);
            if h.meets_target(&hash) {
                break;
            }
        }
        let block = Block { header: h, transactions: vec![coinbase] };
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
        };
        let r = verify_block(&ctx, &UtxoSet::new());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::BadCoinbaseAmount(_, _)));
    }

    #[test]
    fn verify_block_ok_minimal() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let mut buf = Vec::new();
        coinbase.encode_legacy(&mut buf).ok();
        let txid = sha256d(&buf);
        let merkle = rbtc_crypto::merkle_root(&[txid]).unwrap();
        let mut h = header_with_bits(0x207fffff);
        h.merkle_root = merkle;
        h.time = 100000;
        for nonce in 0..=0x10000u32 {
            h.nonce = nonce;
            let enc = encode_block_header(&h);
            let hash = sha256d(&enc);
            if h.meets_target(&hash) {
                break;
            }
        }
        let block = Block { header: h, transactions: vec![coinbase] };
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
        };
        let fees = verify_block(&ctx, &UtxoSet::new()).unwrap();
        assert_eq!(fees, 0);
    }

    #[test]
    fn verify_block_header_bad_pow() {
        let h = header_with_bits(0x1d00ffff);
        let r = verify_block_header(&h, 0x1d00ffff, 0, 200000);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::BadProofOfWork));
    }

    #[test]
    fn verify_block_header_bad_bits() {
        let h = header_with_valid_pow(0x207fffff);
        let r = verify_block_header(&h, 0x207ffffe, 0, 200000);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::BadBits(_)));
    }

    #[test]
    fn verify_block_header_timestamp_too_old() {
        let h = header_with_valid_pow(0x207fffff);
        let r = verify_block_header(&h, h.bits, 100001, 200000);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::TimestampTooOld));
    }

    #[test]
    fn bip30_rejects_when_unspent_duplicate_txid_exists() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([3; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1_000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let txid = compute_txid(&spend);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid, vout: 0 },
            Utxo {
                txout: TxOut { value: 123, script_pubkey: Script::new() },
                is_coinbase: false,
                height: 1,
            },
        );
        let block = Block {
            header: header_with_valid_pow(0x207fffff),
            transactions: vec![coinbase, spend],
        };
        let r = enforce_bip30(&block, 300_000, Network::Mainnet, &utxos);
        assert!(matches!(r, Err(ConsensusError::Bip30Conflict(_))));
    }

    #[test]
    fn bip30_allows_when_no_unspent_duplicate_txid_exists() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([4; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1_000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = Block {
            header: header_with_valid_pow(0x207fffff),
            transactions: vec![coinbase, spend],
        };
        let utxos = UtxoSet::new();
        assert!(enforce_bip30(&block, 300_000, Network::Mainnet, &utxos).is_ok());
    }

    #[test]
    fn encode_block_header_len() {
        let h = header_with_bits(0);
        let buf = encode_block_header(&h);
        assert_eq!(buf.len(), 80);
    }
}
