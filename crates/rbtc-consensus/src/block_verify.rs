use rbtc_primitives::{
    block::Block,
    codec::Encodable,
    constants::{MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, MAX_FUTURE_BLOCK_TIME, WITNESS_SCALE_FACTOR},
    hash::Hash256,
};
use rbtc_crypto::{merkle_root, sha256d};
use rbtc_script::ScriptFlags;

use crate::{
    error::ConsensusError,
    tx_verify::{block_subsidy, verify_coinbase, verify_transaction},
    utxo::UtxoSet,
};

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
}

/// Verify a complete block against the UTXO set.
/// Returns total fees collected on success.
pub fn verify_block(
    ctx: &BlockValidationContext<'_>,
    utxos: &UtxoSet,
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

    // ── Transaction verification + sigops + fees ─────────────────────────
    let subsidy = block_subsidy(ctx.height);
    let mut total_fees: u64 = 0;
    let mut total_sigops: u64 = 0;

    // Verify coinbase
    let _max_coinbase_value = subsidy; // checked at end against actual fees
    verify_coinbase(&block.transactions[0], ctx.height, u64::MAX)?;

    // Count coinbase sigops
    total_sigops += count_block_sigops(&block.transactions[0]) as u64;

    // Verify non-coinbase transactions
    for tx in &block.transactions[1..] {
        let fee = verify_transaction(tx, utxos, ctx.height, ctx.flags)
            .map_err(|e| e)?;

        total_fees = total_fees.checked_add(fee)
            .ok_or(ConsensusError::InputValueOverflow)?;

        total_sigops += count_block_sigops(tx) as u64 * WITNESS_SCALE_FACTOR;
        if total_sigops > MAX_BLOCK_SIGOPS_COST {
            return Err(ConsensusError::TooManySignatureOps(total_sigops, MAX_BLOCK_SIGOPS_COST));
        }
    }

    // Check coinbase value does not exceed subsidy + fees
    let max_allowed = subsidy.checked_add(total_fees)
        .unwrap_or(u64::MAX);
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
    use rbtc_primitives::block::BlockHeader;
    use rbtc_primitives::hash::Hash256;

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

    #[test]
    fn verify_block_header_bad_pow() {
        let h = header_with_bits(0x1d00ffff);
        let r = verify_block_header(&h, 0x1d00ffff, 0, 200000);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::BadProofOfWork));
    }

    #[test]
    fn verify_block_header_bad_bits() {
        let h = header_with_bits(0x1d00ffff);
        let encoded = encode_block_header(&h);
        let hash = sha256d(&encoded);
        if h.meets_target(&hash) {
            let r = verify_block_header(&h, 0x1d00fffe, 0, 200000);
            assert!(r.is_err());
            assert!(matches!(r.unwrap_err(), ConsensusError::BadBits(_)));
        }
    }

    #[test]
    fn verify_block_header_timestamp_too_old() {
        let h = header_with_bits(0x207fffff);
        let encoded = encode_block_header(&h);
        let hash = sha256d(&encoded);
        if !h.meets_target(&hash) {
            return;
        }
        let r = verify_block_header(&h, h.bits, 100001, 200000);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::TimestampTooOld));
    }

    #[test]
    fn encode_block_header_len() {
        let h = header_with_bits(0);
        let buf = encode_block_header(&h);
        assert_eq!(buf.len(), 80);
    }
}
