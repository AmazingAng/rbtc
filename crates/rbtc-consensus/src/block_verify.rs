use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;
use rbtc_primitives::{
    block::Block,
    codec::Encodable,
    constants::{MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, MAX_FUTURE_BLOCK_TIME, WITNESS_SCALE_FACTOR},
    hash::Hash256,
    Network,
};
use rbtc_crypto::{merkle_root, sha256d};
use rbtc_script::ScriptFlags;
use rayon::prelude::*;
use tracing::debug;

use crate::{
    error::ConsensusError,
    script_exec_cache::metrics_snapshot as script_cache_metrics,
    tx_verify::{
        block_subsidy,
        load_transaction_inputs,
        verify_coinbase,
        verify_transaction_scripts_with_prevouts,
        verify_transaction_with_lock_rules_preloaded,
        MedianTimeProvider,
    },
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

static SCRIPT_PRECHECK_POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();

fn precheck_pool() -> Option<&'static rayon::ThreadPool> {
    SCRIPT_PRECHECK_POOL
        .get_or_init(|| {
            let Some(raw) = std::env::var("RBTC_SCRIPT_THREADS").ok() else {
                return None;
            };
            let Ok(n) = raw.parse::<usize>() else {
                return None;
            };
            if n == 0 {
                return None;
            }
            rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("rbtc-script-{i}"))
                .build()
                .ok()
        })
        .as_ref()
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
    verify_block_with_options(ctx, utxos, false)
}

pub fn verify_block_with_options(
    ctx: &BlockValidationContext<'_>,
    utxos: &impl UtxoLookup,
    skip_script_verification: bool,
) -> Result<u64, ConsensusError> {
    let verify_started = Instant::now();
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
    let block_hash = sha256d(&encode_block_header(header));
    enforce_bip30(block, block_hash, ctx.height, ctx.network, utxos)?;

    // ── Transaction verification + sigops + fees ─────────────────────────
    let subsidy = block_subsidy(ctx.height);

    // Verify coinbase (sequential, must be first)
    verify_coinbase(&block.transactions[0], ctx.height, u64::MAX, ctx.network)?;
    let coinbase_sigops = count_legacy_sigops(&block.transactions[0]) as u64 * WITNESS_SCALE_FACTOR;

    // Sequential verification of non-coinbase transactions.
    //
    // Transactions within a block may spend outputs created by earlier
    // transactions in the same block ("intra-block chaining").  We maintain a
    // `BlockUtxoView` that layers newly-verified outputs on top of the
    // persistent UTXO set so that later transactions can see them.
    let non_coinbase = &block.transactions[1..];
    let txids_by_index: Vec<Hash256> = block.transactions.iter().map(compute_txid).collect();
    let non_coinbase_txids = &txids_by_index[1..];

    // Stage A: conservative parallel precheck (script + base UTXO presence only).
    // Skip txs that spend outputs from earlier txs in the same block, because those
    // require the in-block layered view and are validated in Stage B.
    let precheck_started = Instant::now();
    let mut in_block_txid_pos: HashMap<Hash256, usize> = HashMap::new();
    for (pos, txid) in non_coinbase_txids.iter().enumerate() {
        in_block_txid_pos.insert(*txid, pos);
    }
    let precheck_candidates: Vec<(usize, &rbtc_primitives::transaction::Transaction)> = non_coinbase
        .iter()
        .enumerate()
        .filter_map(|(pos, tx)| {
            let spends_earlier_in_block = tx.inputs.iter().any(|input| {
                in_block_txid_pos
                    .get(&input.previous_output.txid)
                    .map(|earlier_pos| *earlier_pos < pos)
                    .unwrap_or(false)
            });
            if spends_earlier_in_block {
                None
            } else {
                Some((pos, tx))
            }
        })
        .collect();
    let mut prechecked_inputs: HashMap<usize, Vec<Utxo>> = HashMap::new();
    if !skip_script_verification {
        let flags = ctx.flags;
        let run_precheck = || {
            precheck_candidates
                .par_iter()
                .map(|(pos, tx)| {
                    let loaded = load_transaction_inputs(tx, utxos)?;
                    let prevouts: Vec<rbtc_primitives::transaction::TxOut> =
                        loaded.iter().map(|u| u.txout.clone()).collect();
                    verify_transaction_scripts_with_prevouts(tx, &prevouts, flags)?;
                    Ok((*pos, loaded))
                })
                .collect::<Vec<Result<(usize, Vec<Utxo>), ConsensusError>>>()
        };
        let precheck_results: Vec<Result<(usize, Vec<Utxo>), ConsensusError>> = if let Some(pool) = precheck_pool() {
            pool.install(run_precheck)
        } else {
            run_precheck()
        };
        for item in precheck_results {
            let (pos, loaded) = item?;
            prechecked_inputs.insert(pos, loaded);
        }
    }
    let precheck_elapsed = precheck_started.elapsed();

    let mut block_view = BlockUtxoView { in_block: HashMap::new(), base: utxos };
    let mut total_fees: u64 = 0;
    let mut non_coinbase_sigops: u64 = 0;
    let serial_started = Instant::now();

    for (pos, tx) in non_coinbase.iter().enumerate() {
        let lock_time_cutoff = if ctx.flags.verify_checksequenceverify {
            ctx.median_time_past
        } else {
            block.header.time
        };
        let preloaded = prechecked_inputs.get(&pos).map(Vec::as_slice);
        let fee = verify_transaction_with_lock_rules_preloaded(
            tx,
            &block_view,
            ctx.height,
            ctx.flags,
            lock_time_cutoff,
            ctx.mtp_provider,
            true,
            preloaded,
            skip_script_verification || preloaded.is_some(),
        )?;
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(ConsensusError::InputValueOverflow)?;
        non_coinbase_sigops += count_legacy_sigops(tx) as u64 * WITNESS_SCALE_FACTOR;
        non_coinbase_sigops += count_witness_sigops(tx, &block_view, ctx.flags) as u64;

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

    let serial_elapsed = serial_started.elapsed();
    let cache_metrics = script_cache_metrics();
    let cache_hit_rate = if cache_metrics.lookups == 0 {
        0.0
    } else {
        (cache_metrics.hits as f64 / cache_metrics.lookups as f64) * 100.0
    };
    debug!(
        "verify timing: height={} txs={} script_precheck_ms={} script_serial_ms={} verify_total_ms={} script_cache_lookups={} script_cache_hits={} script_cache_hit_rate={:.2}% script_cache_inserts={} script_cache_evictions={}",
        ctx.height,
        block.transactions.len(),
        precheck_elapsed.as_millis(),
        serial_elapsed.as_millis(),
        verify_started.elapsed().as_millis(),
        cache_metrics.lookups,
        cache_metrics.hits,
        cache_hit_rate,
        cache_metrics.inserts,
        cache_metrics.evictions
    );

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
fn count_legacy_sigops(tx: &rbtc_primitives::transaction::Transaction) -> usize {
    let mut count = 0;
    for input in &tx.inputs {
        count += input.script_sig.count_sigops();
    }
    for output in &tx.outputs {
        count += output.script_pubkey.count_sigops();
    }
    count
}

fn count_witness_sigops(
    tx: &rbtc_primitives::transaction::Transaction,
    utxos: &impl UtxoLookup,
    flags: ScriptFlags,
) -> usize {
    if !flags.verify_witness {
        return 0;
    }
    let mut total = 0usize;
    for input in &tx.inputs {
        let Some(prevout) = utxos.get_utxo(&input.previous_output) else {
            continue;
        };
        total += witness_sigops_for_input(
            &input.script_sig,
            &prevout.txout.script_pubkey,
            &input.witness,
        );
    }
    total
}

fn witness_sigops_for_input(
    script_sig: &rbtc_primitives::script::Script,
    script_pubkey: &rbtc_primitives::script::Script,
    witness: &[Vec<u8>],
) -> usize {
    if let Some((version, program)) = parse_witness_program(script_pubkey) {
        return witness_program_sigops(version, &program, witness);
    }
    if script_pubkey.is_p2sh() {
        let Some(redeem) = extract_last_push_data(script_sig) else {
            return 0;
        };
        let redeem_script = rbtc_primitives::script::Script::from_bytes(redeem);
        if let Some((version, program)) = parse_witness_program(&redeem_script) {
            return witness_program_sigops(version, &program, witness);
        }
    }
    0
}

fn parse_witness_program(script: &rbtc_primitives::script::Script) -> Option<(u8, Vec<u8>)> {
    let bytes = script.as_bytes();
    if !(4..=42).contains(&bytes.len()) {
        return None;
    }
    let version = match bytes[0] {
        0x00 => 0,
        0x51..=0x60 => bytes[0] - 0x50,
        _ => return None,
    };
    let program_len = bytes[1] as usize;
    if program_len < 2 || program_len > 40 || program_len + 2 != bytes.len() {
        return None;
    }
    Some((version, bytes[2..].to_vec()))
}

fn witness_program_sigops(version: u8, program: &[u8], witness: &[Vec<u8>]) -> usize {
    if version != 0 {
        return 0;
    }
    if program.len() == 20 {
        return 1;
    }
    if program.len() == 32 && !witness.is_empty() {
        let ws = rbtc_primitives::script::Script::from_bytes(
            witness.last().cloned().unwrap_or_default(),
        );
        return ws.count_sigops_accurate(true);
    }
    0
}

fn extract_last_push_data(script: &rbtc_primitives::script::Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    let mut pc = 0usize;
    let mut last: Option<Vec<u8>> = None;
    while pc < bytes.len() {
        let op = bytes[pc];
        pc += 1;
        match op {
            0x00 => last = Some(Vec::new()),
            0x01..=0x4b => {
                let len = op as usize;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(bytes[pc..pc + len].to_vec());
                pc += len;
            }
            0x4c => {
                if pc >= bytes.len() {
                    return None;
                }
                let len = bytes[pc] as usize;
                pc += 1;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(bytes[pc..pc + len].to_vec());
                pc += len;
            }
            0x4d => {
                if pc + 1 >= bytes.len() {
                    return None;
                }
                let len = u16::from_le_bytes([bytes[pc], bytes[pc + 1]]) as usize;
                pc += 2;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(bytes[pc..pc + len].to_vec());
                pc += len;
            }
            0x4e => {
                if pc + 3 >= bytes.len() {
                    return None;
                }
                let len = u32::from_le_bytes([bytes[pc], bytes[pc + 1], bytes[pc + 2], bytes[pc + 3]]) as usize;
                pc += 4;
                if pc + len > bytes.len() {
                    return None;
                }
                last = Some(bytes[pc..pc + len].to_vec());
                pc += len;
            }
            _ => return None,
        }
    }
    last
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
    // witness_reserved_value must be exactly 32 bytes at coinbase witness[0].
    let reserved = coinbase.inputs[0]
        .witness
        .first()
        .ok_or(ConsensusError::BadCoinbaseWitnessReservedValue)?;
    if reserved.len() != 32 {
        return Err(ConsensusError::BadCoinbaseWitnessReservedValue);
    }

    let mut commit_preimage = Vec::with_capacity(64);
    commit_preimage.extend_from_slice(&witness_merkle_root.0);
    commit_preimage.extend_from_slice(reserved.as_slice());
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
    block_hash: Hash256,
    height: u32,
    network: Network,
    utxos: &impl UtxoLookup,
) -> Result<(), ConsensusError> {
    // After BIP34 activation, duplicate-coinbase style collisions are prevented.
    // Keep BIP30 checks only for pre-BIP34 historical range.
    if height >= network.consensus_params().bip34_height {
        return Ok(());
    }
    // Mainnet historical exceptions (pre-BIP34 duplicate-coinbase blocks).
    // Core equivalent: IsBIP30Repeat(height, hash).
    let is_bip30_repeat = network == Network::Mainnet
        && ((height == 91_842
            && block_hash.to_hex()
                == "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
            || (height == 91_880
                && block_hash.to_hex()
                    == "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
    if is_bip30_repeat {
        return Ok(());
    }
    for tx in &block.transactions {
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
    fn verify_witness_commitment_rejects_bad_reserved_value() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffff_ffff,
                witness: vec![vec![0u8; 31]],
            }],
            outputs: vec![TxOut {
                value: 0,
                script_pubkey: Script::from_bytes({
                    let mut s = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
                    s.extend_from_slice(&[0u8; 32]);
                    s
                }),
            }],
            lock_time: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([1; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![vec![1u8]],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let block = Block {
            header: header_with_valid_pow(0x207fffff),
            transactions: vec![coinbase, spend],
        };
        let r = verify_witness_commitment(&block);
        assert!(matches!(r, Err(ConsensusError::BadCoinbaseWitnessReservedValue)));
    }

    #[test]
    fn verify_witness_commitment_rejects_mismatched_commitment() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffff_ffff,
                witness: vec![vec![0u8; 32]],
            }],
            outputs: vec![TxOut {
                value: 0,
                script_pubkey: Script::from_bytes({
                    let mut s = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
                    s.extend_from_slice(&[0u8; 32]);
                    s
                }),
            }],
            lock_time: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([2; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![vec![2u8]],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let block = Block {
            header: header_with_valid_pow(0x207fffff),
            transactions: vec![coinbase, spend],
        };
        let r = verify_witness_commitment(&block);
        assert!(matches!(r, Err(ConsensusError::BadCoinbaseWitnessCommitment)));
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
        let r = enforce_bip30(
            &block,
            sha256d(&encode_block_header(&block.header)),
            100_000,
            Network::Mainnet,
            &utxos,
        );
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
        assert!(enforce_bip30(
            &block,
            sha256d(&encode_block_header(&block.header)),
            100_000,
            Network::Mainnet,
            &utxos
        )
        .is_ok());
    }

    #[test]
    fn bip30_exception_requires_matching_hash_not_just_height() {
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
                previous_output: OutPoint { txid: Hash256([5; 32]), vout: 0 },
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
        // Height matches historical repeat, but hash does not.
        let r = enforce_bip30(
            &block,
            sha256d(&encode_block_header(&block.header)),
            91_842,
            Network::Mainnet,
            &utxos,
        );
        assert!(matches!(r, Err(ConsensusError::Bip30Conflict(_))));
    }

    #[test]
    fn encode_block_header_len() {
        let h = header_with_bits(0);
        let buf = encode_block_header(&h);
        assert_eq!(buf.len(), 80);
    }

    #[test]
    fn verify_block_handles_intra_block_dependency_with_parallel_precheck() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![1, 1]),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };

        let funding_txid = Hash256([0x11; 32]);
        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: funding_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 4_000,
                script_pubkey: Script::from_bytes(vec![0x51]), // OP_TRUE
            }],
            lock_time: 0,
        };
        let tx1id = compute_txid(&tx1);
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: tx1id, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 3_000,
                script_pubkey: Script::from_bytes(vec![0x51]), // OP_TRUE
            }],
            lock_time: 0,
        };

        let txids = vec![compute_txid(&coinbase), tx1id, compute_txid(&tx2)];
        let merkle = rbtc_crypto::merkle_root(&txids).unwrap();
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
        let block = Block {
            header: h,
            transactions: vec![coinbase, tx1, tx2],
        };

        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid: funding_txid, vout: 0 },
            Utxo {
                txout: TxOut { value: 5_000, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: false,
                height: 0,
            },
        );

        let ctx = BlockValidationContext {
            block: &block,
            height: 1,
            median_time_past: 0,
            network_time: 200000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
        };

        let fees = verify_block(&ctx, &utxos).unwrap();
        assert_eq!(fees, 2_000);
    }
}
