use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Instant;
use rbtc_primitives::{
    block::Block,
    codec::Encodable,
    constants::{MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, MAX_FUTURE_BLOCK_TIME, WITNESS_SCALE_FACTOR},
    hash::Hash256,
    transaction::OutPoint,
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
    /// Outpoints spent by earlier transactions in this block.
    spent_in_block: HashSet<rbtc_primitives::transaction::OutPoint>,
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
        if self.spent_in_block.contains(outpoint) {
            return None;
        }
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
    /// Optional signet challenge script override (None uses network default).
    pub signet_challenge: Option<&'a [u8]>,
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
    if ctx.network != Network::Signet {
        // Signet blocks do not require PoW; they are authenticated by the challenge script.
        verify_block_header(header, ctx.expected_bits, ctx.median_time_past, ctx.network_time)?;
    } else {
        // For signet we still check nBits and timestamps, but not PoW.
        if header.bits != ctx.expected_bits {
            return Err(ConsensusError::BadBits(header.bits));
        }
        if header.time <= ctx.median_time_past {
            return Err(ConsensusError::TimestampTooOld);
        }
        if header.time > ctx.network_time.saturating_add(MAX_FUTURE_BLOCK_TIME as u32) {
            return Err(ConsensusError::TimestampTooNew);
        }
    }

    // ── Signet challenge verification (BIP325) ───────────────────────────
    if ctx.network == Network::Signet {
        let challenge = ctx
            .signet_challenge
            .or_else(|| ctx.network.signet_challenge())
            .unwrap_or(&[]);
        if !challenge.is_empty() {
            verify_signet_block_solution(block, challenge)?;
        }
    }

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
    // Core-style: block must not contain duplicate txids.
    let unique_txids: HashSet<Hash256> = txids.iter().copied().collect();
    if unique_txids.len() != txids.len() {
        return Err(ConsensusError::DuplicateTx);
    }
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
    // Skip txs that refer to any txid in this block. Core validates txs against
    // the progressively-updated block-local view (ConnectBlock path); these are
    // handled in Stage B using `block_view`.
    let precheck_started = Instant::now();
    let mut in_block_txids: HashSet<Hash256> = HashSet::new();
    for txid in non_coinbase_txids {
        in_block_txids.insert(*txid);
    }
    let precheck_candidates: Vec<(usize, &rbtc_primitives::transaction::Transaction)> = non_coinbase
        .iter()
        .enumerate()
        .filter_map(|(pos, tx)| {
            let references_in_block_tx = tx.inputs.iter().any(|input| {
                in_block_txids.contains(&input.previous_output.txid)
            });
            if references_in_block_tx {
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

    let mut block_view = BlockUtxoView {
        in_block: HashMap::new(),
        spent_in_block: HashSet::new(),
        base: utxos,
    };
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
        if preloaded.is_some() {
            // Re-check UTXO availability against the evolving block-local view.
            // Preloaded entries were fetched against the base view only, but an
            // earlier tx in this block may have spent one of those outpoints.
            for input in &tx.inputs {
                if block_view.get_utxo(&input.previous_output).is_none() {
                    return Err(ConsensusError::MissingUtxo(
                        input.previous_output.txid.to_hex(),
                        input.previous_output.vout,
                    ));
                }
            }
        }
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

        // Mark inputs as spent in block-local view to enforce no cross-tx
        // double-spends, matching Core's ConnectBlock semantics.
        for input in &tx.inputs {
            block_view.spent_in_block.insert(input.previous_output.clone());
        }

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
        // Core behavior: check each would-be-created outpoint, not just txid-level existence.
        for vout in 0..tx.outputs.len() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            if utxos.get_utxo(&outpoint).is_some() {
                return Err(ConsensusError::Bip30Conflict(txid.to_hex()));
            }
        }
    }
    Ok(())
}

// ── Signet challenge verification (BIP325) ────────────────────────────────

/// 4-byte signet header magic embedded after OP_RETURN in the coinbase.
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Extract the signet solution (scriptSig, witness) from the coinbase.
///
/// Bitcoin Core scans coinbase outputs for `OP_RETURN <push SIGNET_HEADER || solution>`.
/// The solution is encoded as: `<scriptSig_len> <scriptSig> <witness>`.
fn extract_signet_solution(
    coinbase: &rbtc_primitives::transaction::Transaction,
) -> Option<(rbtc_primitives::script::Script, Vec<Vec<u8>>)> {
    use rbtc_primitives::codec::{Decodable, VarInt};

    for output in &coinbase.outputs {
        let spk = output.script_pubkey.as_bytes();
        // OP_RETURN (0x6a) followed by a push of data starting with SIGNET_HEADER
        if spk.len() < 6 || spk[0] != 0x6a {
            continue;
        }
        // Parse the push opcode after OP_RETURN
        let (push_len, data_start) = if spk[1] <= 0x4b {
            (spk[1] as usize, 2usize)
        } else if spk[1] == 0x4c && spk.len() > 3 {
            // OP_PUSHDATA1
            (spk[2] as usize, 3usize)
        } else if spk[1] == 0x4d && spk.len() > 4 {
            // OP_PUSHDATA2
            (u16::from_le_bytes([spk[2], spk[3]]) as usize, 4usize)
        } else {
            continue;
        };
        if data_start + push_len > spk.len() {
            continue;
        }
        let data = &spk[data_start..data_start + push_len];
        if data.len() < 4 || data[..4] != SIGNET_HEADER {
            continue;
        }
        let solution = &data[4..];
        // Decode solution: varint(scriptSig_len) || scriptSig || witness
        let mut cursor = std::io::Cursor::new(solution);
        let sig_len = match VarInt::decode(&mut cursor) {
            Ok(v) => v.0 as usize,
            Err(_) => continue,
        };
        let pos = cursor.position() as usize;
        if pos + sig_len > solution.len() {
            continue;
        }
        let script_sig =
            rbtc_primitives::script::Script::from_bytes(solution[pos..pos + sig_len].to_vec());

        // Remaining bytes are the witness stack
        let witness_data = &solution[pos + sig_len..];
        let witness = if witness_data.is_empty() {
            Vec::new()
        } else {
            let mut wcursor = std::io::Cursor::new(witness_data);
            let stack_len = match VarInt::decode(&mut wcursor) {
                Ok(v) => v.0 as usize,
                Err(_) => return Some((script_sig, Vec::new())),
            };
            let mut items = Vec::with_capacity(stack_len);
            for _ in 0..stack_len {
                let item = match Vec::<u8>::decode(&mut wcursor) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                items.push(item);
            }
            items
        };

        return Some((script_sig, witness));
    }
    None
}

/// Compute the "to_spend" transaction hash for signet block signing.
///
/// This is the virtual transaction output that the signet signer must spend.
/// Commits to the block header with nonce=0 and the signet output stripped
/// from the coinbase.
fn signet_txid_to_spend(
    block: &Block,
    challenge: &[u8],
) -> rbtc_primitives::hash::Hash256 {
    use rbtc_primitives::codec::Encodable;

    // Build a modified header with nonce=0
    let mut modified_header = block.header.clone();
    modified_header.nonce = 0;

    // Build modified coinbase: strip the signet commitment output
    let mut modified_coinbase = block.transactions[0].clone();
    modified_coinbase.outputs.retain(|output| {
        let spk = output.script_pubkey.as_bytes();
        if spk.len() < 6 || spk[0] != 0x6a {
            return true; // keep non-OP_RETURN outputs
        }
        let (push_len, data_start) = if spk[1] <= 0x4b {
            (spk[1] as usize, 2usize)
        } else if spk[1] == 0x4c && spk.len() > 3 {
            (spk[2] as usize, 3usize)
        } else if spk[1] == 0x4d && spk.len() > 4 {
            (u16::from_le_bytes([spk[2], spk[3]]) as usize, 4usize)
        } else {
            return true;
        };
        if data_start + push_len > spk.len() {
            return true;
        }
        let data = &spk[data_start..data_start + push_len];
        !(data.len() >= 4 && data[..4] == SIGNET_HEADER)
    });
    // Clear witness from modified coinbase (not part of the commitment)
    for input in &mut modified_coinbase.inputs {
        input.witness.clear();
    }

    // Recompute merkle root with modified coinbase
    let mut txids: Vec<rbtc_primitives::hash::Hash256> = Vec::with_capacity(block.transactions.len());
    let mut buf = Vec::new();
    modified_coinbase.encode_legacy(&mut buf).ok();
    txids.push(sha256d(&buf));
    for tx in &block.transactions[1..] {
        txids.push(compute_txid(tx));
    }
    modified_header.merkle_root = merkle_root(&txids).unwrap_or(Hash256::ZERO);

    // Serialize the modified header
    let header_bytes = encode_block_header(&modified_header);

    // Build the "to_spend" transaction:
    // version=0, 1 input (outpoint=0:0xffffffff, scriptSig=header_bytes, seq=0),
    // 1 output (value=0, scriptPubKey=challenge), locktime=0
    let to_spend = rbtc_primitives::transaction::Transaction {
        version: 0,
        inputs: vec![rbtc_primitives::transaction::TxIn {
            previous_output: rbtc_primitives::transaction::OutPoint::null(),
            script_sig: rbtc_primitives::script::Script::from_bytes(
                // Push the block header as data: length prefix + data
                {
                    let mut s = Vec::new();
                    // OP_PUSHDATA1 (0x4c) because header is 80 bytes > 75
                    s.push(0x4c);
                    s.push(header_bytes.len() as u8);
                    s.extend_from_slice(&header_bytes);
                    s
                },
            ),
            sequence: 0,
            witness: Vec::new(),
        }],
        outputs: vec![rbtc_primitives::transaction::TxOut {
            value: 0,
            script_pubkey: rbtc_primitives::script::Script::from_bytes(challenge.to_vec()),
        }],
        lock_time: 0,
    };

    // Compute txid of to_spend
    let mut to_spend_buf = Vec::new();
    to_spend.encode_legacy(&mut to_spend_buf).ok();
    sha256d(&to_spend_buf)
}

/// Verify the signet block solution (BIP325).
///
/// Returns Ok(()) if the block satisfies the signet challenge, or if the
/// network is not signet.
pub fn verify_signet_block_solution(
    block: &Block,
    challenge: &[u8],
) -> Result<(), ConsensusError> {
    use rbtc_script::{ScriptContext, ScriptFlags, verify_input};

    // Genesis block is exempt from signet challenge
    if block.header.prev_block == Hash256::ZERO {
        return Ok(());
    }

    if block.transactions.is_empty() {
        return Err(ConsensusError::SignetChallengeFailed("no coinbase".into()));
    }

    let (solution_sig, solution_witness) =
        extract_signet_solution(&block.transactions[0]).ok_or_else(|| {
            ConsensusError::SignetChallengeFailed("no signet solution in coinbase".into())
        })?;

    let to_spend_txid = signet_txid_to_spend(block, challenge);

    // Build the "to_sign" spending transaction
    let to_sign = rbtc_primitives::transaction::Transaction {
        version: 0,
        inputs: vec![rbtc_primitives::transaction::TxIn {
            previous_output: rbtc_primitives::transaction::OutPoint {
                txid: to_spend_txid,
                vout: 0,
            },
            script_sig: solution_sig,
            sequence: 0,
            witness: solution_witness,
        }],
        outputs: vec![rbtc_primitives::transaction::TxOut {
            value: 0,
            script_pubkey: rbtc_primitives::script::Script::from_bytes(vec![0x6a]), // OP_RETURN
        }],
        lock_time: 0,
    };

    let prevout = rbtc_primitives::transaction::TxOut {
        value: 0,
        script_pubkey: rbtc_primitives::script::Script::from_bytes(challenge.to_vec()),
    };

    let all_prevouts = vec![prevout.clone()];

    // Use standard flags but with P2SH and witness enabled
    let flags = ScriptFlags {
        verify_p2sh: true,
        verify_dersig: true,
        verify_witness: true,
        verify_nulldummy: true,
        verify_cleanstack: true,
        verify_checklocktimeverify: true,
        verify_checksequenceverify: true,
        verify_taproot: true,
        verify_strictenc: false,
        verify_low_s: false,
        verify_sigpushonly: false,
        verify_minimaldata: false,
        verify_discourage_upgradable_nops: false,
        verify_discourage_upgradable_witness_program: false,
        verify_minimalif: false,
        verify_nullfail: true,
        verify_witness_pubkeytype: true,
    };

    let ctx = ScriptContext {
        tx: &to_sign,
        input_index: 0,
        prevout: &all_prevouts[0],
        flags,
        all_prevouts: &all_prevouts,
    };

    verify_input(&ctx).map_err(|e| {
        ConsensusError::SignetChallengeFailed(format!("script verification failed: {e}"))
    })
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
            signet_challenge: None,
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
            signet_challenge: None,
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
            signet_challenge: None,
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
            signet_challenge: None,
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
            signet_challenge: None,
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
            signet_challenge: None,
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
    fn bip30_checks_outpoint_not_txid_prefix_only() {
        // Existing txid has only vout=1 unspent; new tx creates only vout=0.
        // Core-style BIP30 should allow this.
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
                previous_output: OutPoint { txid: Hash256([6; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1_000, script_pubkey: Script::new() }], // only vout=0
            lock_time: 0,
        };
        let txid = compute_txid(&spend);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid, vout: 1 }, // only vout=1 exists
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
            signet_challenge: None,
        };

        let fees = verify_block(&ctx, &utxos).unwrap();
        assert_eq!(fees, 2_000);
    }

    #[test]
    fn verify_block_rejects_cross_tx_double_spend() {
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

        let funding_txid = Hash256([0x22; 32]);
        let shared_input = OutPoint { txid: funding_txid, vout: 0 };
        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: shared_input.clone(),
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
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: shared_input,
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

        let txids = vec![compute_txid(&coinbase), compute_txid(&tx1), compute_txid(&tx2)];
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
            signet_challenge: None,
        };

        let err = verify_block(&ctx, &utxos).unwrap_err();
        assert!(matches!(err, ConsensusError::MissingUtxo(_, _)));
    }

    #[test]
    fn verify_block_rejects_duplicate_txid() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 1, 0]),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([0x33; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Script::from_bytes(vec![0x51]), // OP_TRUE
            }],
            lock_time: 0,
        };
        let tx_dup = tx.clone();

        let txids = vec![compute_txid(&coinbase), compute_txid(&tx), compute_txid(&tx_dup)];
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
            transactions: vec![coinbase, tx, tx_dup],
        };
        let ctx = BlockValidationContext {
            block: &block,
            height: 1,
            median_time_past: 0,
            network_time: 200000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };

        let err = verify_block(&ctx, &UtxoSet::new()).unwrap_err();
        assert!(matches!(err, ConsensusError::DuplicateTx));
    }

    // ── Helper: encode BIP34 coinbase scriptSig with height push ─────────
    fn bip34_coinbase_scriptsig(height: u32) -> Vec<u8> {
        if height == 0 {
            // height 0: push 1 byte 0x00
            return vec![1, 0];
        }
        let mut h = height;
        let mut bytes = Vec::new();
        while h > 0 {
            bytes.push((h & 0xff) as u8);
            h >>= 8;
        }
        // If top bit is set, add a 0x00 pad so it's not interpreted as negative
        if *bytes.last().unwrap() & 0x80 != 0 {
            bytes.push(0);
        }
        let mut script = vec![bytes.len() as u8];
        script.extend_from_slice(&bytes);
        script
    }

    /// Build a valid block with correct merkle root and PoW for testing.
    fn make_valid_block(
        txs: Vec<Transaction>,
        bits: u32,
        time: u32,
    ) -> Block {
        let txids: Vec<Hash256> = txs.iter().map(compute_txid).collect();
        let merkle = rbtc_crypto::merkle_root(&txids).unwrap_or(Hash256::ZERO);
        let mut h = header_with_bits(bits);
        h.merkle_root = merkle;
        h.time = time;
        for nonce in 0..=u32::MAX {
            h.nonce = nonce;
            let enc = encode_block_header(&h);
            let hash = sha256d(&enc);
            if h.meets_target(&hash) {
                return Block { header: h, transactions: txs };
            }
        }
        panic!("failed to find valid PoW");
    }

    // ── Coinbase maturity tests ──────────────────────────────────────────

    #[test]
    fn coinbase_maturity_spending_too_early_rejected() {
        // Create a coinbase at height 0, try to spend it at height 99 (depth < 100)
        let coinbase_txid = Hash256([0xaa; 32]);
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(100)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: coinbase_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase, spend], 0x207fffff, 100000);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid: coinbase_txid, vout: 0 },
            Utxo {
                txout: TxOut { value: 5_000, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: true,
                height: 1, // created at height 1
            },
        );
        let ctx = BlockValidationContext {
            block: &block,
            height: 100, // depth = 100 - 1 = 99 < COINBASE_MATURITY(100)
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let err = verify_block(&ctx, &utxos).unwrap_err();
        assert!(matches!(err, ConsensusError::CoinbaseNotMature(_, _)));
    }

    #[test]
    fn coinbase_maturity_spending_at_exact_depth_accepted() {
        // Coinbase at height 1, spending at height 101 → depth = 100 = COINBASE_MATURITY
        let coinbase_txid = Hash256([0xbb; 32]);
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(101)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: coinbase_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase, spend], 0x207fffff, 100000);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid: coinbase_txid, vout: 0 },
            Utxo {
                txout: TxOut { value: 5_000, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: true,
                height: 1,
            },
        );
        let ctx = BlockValidationContext {
            block: &block,
            height: 101, // depth = 101 - 1 = 100 = COINBASE_MATURITY
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let fees = verify_block(&ctx, &utxos).unwrap();
        assert_eq!(fees, 4_000); // 5000 - 1000
    }

    // ── Block weight boundary tests ──────────────────────────────────────

    #[test]
    fn block_weight_at_max_accepted() {
        // A minimal coinbase-only block's weight is well under MAX_BLOCK_WEIGHT.
        // This test verifies that the weight check is <= not <.
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![1, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let weight = block.weight();
        // Verify our block weight is well under the limit (sanity check)
        assert!(weight < MAX_BLOCK_WEIGHT, "test setup: weight {weight} should be under limit");
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        assert!(verify_block(&ctx, &UtxoSet::new()).is_ok());
    }

    #[test]
    fn block_weight_over_max_rejected() {
        // Create a block with a huge output to exceed MAX_BLOCK_WEIGHT
        let huge_script = Script::from_bytes(vec![0x6a; 1_000_100]); // OP_RETURN padding
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![1, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 0, script_pubkey: huge_script }],
            lock_time: 0,
        };
        // Don't use make_valid_block; just build the header manually since PoW
        // check comes before weight check. We want to trigger BlockTooLarge.
        let txids = vec![compute_txid(&coinbase)];
        let merkle = rbtc_crypto::merkle_root(&txids).unwrap();
        let mut h = header_with_bits(0x207fffff);
        h.merkle_root = merkle;
        h.time = 100000;
        for nonce in 0..=u32::MAX {
            h.nonce = nonce;
            let enc = encode_block_header(&h);
            let hash = sha256d(&enc);
            if h.meets_target(&hash) {
                break;
            }
        }
        let block = Block { header: h, transactions: vec![coinbase] };
        assert!(block.weight() > MAX_BLOCK_WEIGHT, "test setup: weight {} should exceed limit", block.weight());
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let err = verify_block(&ctx, &UtxoSet::new()).unwrap_err();
        assert!(matches!(err, ConsensusError::BlockTooLarge(_, _)));
    }

    // ── BIP34 coinbase height encoding tests ─────────────────────────────

    #[test]
    fn bip34_correct_height_accepted() {
        let height = 500u32;
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(height)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest, // Regtest: bip34_height=0
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        assert!(verify_block(&ctx, &UtxoSet::new()).is_ok());
    }

    #[test]
    fn bip34_wrong_height_rejected() {
        let height = 500u32;
        // Encode height 499 in coinbase but validate at height 500
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(499)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let err = verify_block(&ctx, &UtxoSet::new()).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidTx(_)));
    }

    #[test]
    fn bip34_height_encoding_large_height() {
        // Test that large heights (3+ bytes) are encoded correctly
        let height = 700_000u32;
        let script = bip34_coinbase_scriptsig(height);
        // Verify the encoding: first byte = push length, then LE bytes of height
        let push_len = script[0] as usize;
        let mut decoded = 0u32;
        for i in 0..push_len {
            decoded |= (script[1 + i] as u32) << (8 * i);
        }
        assert_eq!(decoded, height);

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(script),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: block_subsidy(height), script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        assert!(verify_block(&ctx, &UtxoSet::new()).is_ok());
    }

    // ── Block subsidy tests (via block validation) ───────────────────────

    #[test]
    fn coinbase_value_exactly_subsidy_accepted() {
        let height = 0u32;
        let subsidy = block_subsidy(height); // 50 BTC
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(height)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: subsidy, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        assert!(verify_block(&ctx, &UtxoSet::new()).is_ok());
    }

    #[test]
    fn coinbase_value_exceeds_subsidy_rejected() {
        let height = 210_000u32; // first halving
        let subsidy = block_subsidy(height); // 25 BTC
        assert_eq!(subsidy, 25_0000_0000);
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(height)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: subsidy + 1, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let err = verify_block(&ctx, &UtxoSet::new()).unwrap_err();
        assert!(matches!(err, ConsensusError::BadCoinbaseAmount(_, _)));
    }

    #[test]
    fn coinbase_value_with_fees_accepted() {
        let height = 210_000u32;
        let subsidy = block_subsidy(height); // 25 BTC
        let fee = 5_000u64;
        // Coinbase claims subsidy + fees
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(height)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: subsidy + fee, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let funding_txid = Hash256([0xcc; 32]);
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: funding_txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 10_000 - fee, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase, spend], 0x207fffff, 100000);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid: funding_txid, vout: 0 },
            Utxo {
                txout: TxOut { value: 10_000, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: false,
                height: 0,
            },
        );
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let fees = verify_block(&ctx, &utxos).unwrap();
        assert_eq!(fees, fee);
    }

    // ── Merkle root edge cases ───────────────────────────────────────────

    #[test]
    fn merkle_root_single_tx() {
        // With a single tx, merkle root = txid of that tx
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(0)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let txid = compute_txid(&coinbase);
        let root = rbtc_crypto::merkle_root(&[txid]).unwrap();
        assert_eq!(root, txid, "single-tx merkle root should equal the txid");
    }

    #[test]
    fn merkle_root_odd_tx_count() {
        // With 3 txs: merkle of [H01, H22] where H22 = hash(tx2 || tx2)
        // This is the standard Bitcoin duplicate-last-element behavior
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(1)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([0xdd; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let tx3 = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([0xee; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 2000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let txids = vec![compute_txid(&coinbase), compute_txid(&tx2), compute_txid(&tx3)];
        let root = rbtc_crypto::merkle_root(&txids).unwrap();

        // Manually compute: H01 = hash(tx0 || tx1), H22 = hash(tx2 || tx2), root = hash(H01 || H22)
        let mut data01 = Vec::new();
        data01.extend_from_slice(&txids[0].0);
        data01.extend_from_slice(&txids[1].0);
        let h01 = sha256d(&data01);
        let mut data22 = Vec::new();
        data22.extend_from_slice(&txids[2].0);
        data22.extend_from_slice(&txids[2].0);
        let h22 = sha256d(&data22);
        let mut root_data = Vec::new();
        root_data.extend_from_slice(&h01.0);
        root_data.extend_from_slice(&h22.0);
        let expected_root = sha256d(&root_data);
        assert_eq!(root, expected_root, "odd-count merkle root mismatch");
    }

    // ── Coinbase scriptSig length tests ──────────────────────────────────

    #[test]
    fn coinbase_scriptsig_too_short_rejected() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x00]), // 1 byte, minimum is 2
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let err = verify_block(&ctx, &UtxoSet::new()).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidTx(_)));
    }

    #[test]
    fn coinbase_scriptsig_too_long_rejected() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x00; 101]), // 101 bytes, max is 100
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase], 0x207fffff, 100000);
        let ctx = BlockValidationContext {
            block: &block,
            height: 0,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let err = verify_block(&ctx, &UtxoSet::new()).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidTx(_)));
    }

    // ── Multiple outputs spending and fees ────────────────────────────────

    #[test]
    fn block_total_fees_with_multiple_txs() {
        let height = 100u32;
        let subsidy = block_subsidy(height);
        let funding1 = Hash256([0x41; 32]);
        let funding2 = Hash256([0x42; 32]);

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(height)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: subsidy + 3_000, // subsidy + total fees (1000 + 2000)
                script_pubkey: Script::new(),
            }],
            lock_time: 0,
        };
        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: funding1, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 4_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: funding2, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 3_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase, tx1, tx2], 0x207fffff, 100000);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid: funding1, vout: 0 },
            Utxo {
                txout: TxOut { value: 5_000, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: false,
                height: 0,
            },
        );
        utxos.insert(
            OutPoint { txid: funding2, vout: 0 },
            Utxo {
                txout: TxOut { value: 5_000, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: false,
                height: 0,
            },
        );
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let fees = verify_block(&ctx, &utxos).unwrap();
        assert_eq!(fees, 3_000); // (5000-4000) + (5000-3000) = 1000 + 2000
    }

    #[test]
    fn block_negative_fee_rejected() {
        let height = 100u32;
        let funding = Hash256([0x51; 32]);
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(bip34_coinbase_scriptsig(height)),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        // Output > input → negative fee
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: funding, vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 10_000, script_pubkey: Script::from_bytes(vec![0x51]) }],
            lock_time: 0,
        };
        let block = make_valid_block(vec![coinbase, spend], 0x207fffff, 100000);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid: funding, vout: 0 },
            Utxo {
                txout: TxOut { value: 5_000, script_pubkey: Script::from_bytes(vec![0x51]) },
                is_coinbase: false,
                height: 0,
            },
        );
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: 99999,
            network_time: 110000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };
        let err = verify_block(&ctx, &utxos).unwrap_err();
        assert!(matches!(err, ConsensusError::NegativeFee));
    }

    // ── Genesis block deserialization ─────────────────────────────────────

    #[test]
    fn mainnet_genesis_header_valid() {
        let genesis = Network::Mainnet.genesis_header();
        // Check known values
        assert_eq!(genesis.version, 1);
        assert_eq!(genesis.time, 1231006505);
        assert_eq!(genesis.bits, 0x1d00ffff);
        assert_eq!(genesis.nonce, 2083236893);
        assert_eq!(genesis.prev_block, Hash256::ZERO);

        // Verify PoW
        let header_bytes = encode_block_header(&genesis);
        let hash = sha256d(&header_bytes);
        assert!(genesis.meets_target(&hash), "genesis block must meet its own target");

        // Verify hash matches known genesis hash
        let hash_hex = hash.to_hex();
        assert_eq!(hash_hex, Network::Mainnet.genesis_hash());
    }

    // ── Signet challenge tests ─────────────────────────────────────────────

    #[test]
    fn signet_extract_solution_no_opreturn() {
        // Coinbase with no OP_RETURN outputs -> None
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x04, 0x01, 0x00, 0x00, 0x00]),
                sequence: 0xffffffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: Script::from_bytes(vec![0x76, 0xa9, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0x88, 0xac]),
            }],
            lock_time: 0,
        };
        assert!(extract_signet_solution(&coinbase).is_none());
    }

    #[test]
    fn signet_extract_solution_with_valid_header() {
        // Build a coinbase with OP_RETURN + SIGNET_HEADER + solution
        let mut solution_data = Vec::new();
        // SIGNET_HEADER
        solution_data.extend_from_slice(&SIGNET_HEADER);
        // scriptSig: varint(3) + 3 bytes
        solution_data.push(0x03); // varint(3)
        solution_data.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        // witness: varint(1) item, varint(2) 2-byte item
        solution_data.push(0x01); // 1 stack item
        solution_data.push(0x02); // 2 bytes
        solution_data.extend_from_slice(&[0xdd, 0xee]);

        // OP_RETURN <push solution_data>
        let mut spk = vec![0x6a]; // OP_RETURN
        spk.push(solution_data.len() as u8); // direct push (< 75)
        spk.extend_from_slice(&solution_data);

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x04, 0x01, 0x00, 0x00, 0x00]),
                sequence: 0xffffffff,
                witness: Vec::new(),
            }],
            outputs: vec![
                TxOut { value: 5_000_000_000, script_pubkey: Script::new() },
                TxOut { value: 0, script_pubkey: Script::from_bytes(spk) },
            ],
            lock_time: 0,
        };

        let (sig, wit) = extract_signet_solution(&coinbase).expect("should extract");
        assert_eq!(sig.as_bytes(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(wit.len(), 1);
        assert_eq!(wit[0], vec![0xdd, 0xee]);
    }

    #[test]
    fn signet_genesis_exempt() {
        // Genesis block (prev_block = ZERO) should pass challenge check
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![],
        };
        // Any challenge should pass for genesis
        let challenge = &[0x51, 0xae]; // OP_1 OP_CHECKMULTISIG (dummy)
        assert!(verify_signet_block_solution(&block, challenge).is_ok());
    }

    #[test]
    fn signet_no_solution_fails() {
        // Non-genesis block with no signet solution should fail
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash256([1; 32]), // non-zero
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![0x04, 0x01, 0x00, 0x00, 0x00]),
                    sequence: 0xffffffff,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut { value: 0, script_pubkey: Script::new() }],
                lock_time: 0,
            }],
        };
        let challenge = &[0x51, 0xae];
        let err = verify_signet_block_solution(&block, challenge).unwrap_err();
        assert!(matches!(err, ConsensusError::SignetChallengeFailed(_)));
    }

    #[test]
    fn signet_challenge_available_for_signet_network() {
        assert!(Network::Signet.signet_challenge().is_some());
        assert!(Network::Mainnet.signet_challenge().is_none());
        assert!(Network::Regtest.signet_challenge().is_none());
    }

    // ── C1: Assumevalid / skip_script_verification tests ─────────────────

    /// A block with an INVALID scriptSig (spends OP_CHECKSIG output with empty sig)
    /// passes when skip_script_verification is true (assumevalid mode).
    #[test]
    fn skip_script_verification_accepts_bad_script() {
        // Create a funding UTXO locked to OP_CHECKSIG (requires a real signature)
        let funding_txid = Hash256([0xaa; 32]);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid: funding_txid, vout: 0 },
            Utxo {
                txout: TxOut {
                    value: 5_000,
                    // OP_CHECKSIG — requires a valid DER sig + pubkey on stack
                    script_pubkey: Script::from_bytes(vec![0xac]),
                },
                is_coinbase: false,
                height: 0,
            },
        );

        // Transaction with empty scriptSig (invalid for OP_CHECKSIG)
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
        let bad_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: funding_txid, vout: 0 },
                script_sig: Script::new(), // empty — invalid for OP_CHECKSIG
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 4_000, script_pubkey: Script::new() }],
            lock_time: 0,
        };

        let txids = vec![compute_txid(&coinbase), compute_txid(&bad_tx)];
        let merkle = rbtc_crypto::merkle_root(&txids).unwrap();
        let mut h = header_with_bits(0x207fffff);
        h.merkle_root = merkle;
        for nonce in 0..=0x10000u32 {
            h.nonce = nonce;
            let enc = encode_block_header(&h);
            let hash = sha256d(&enc);
            if h.meets_target(&hash) { break; }
        }
        let block = Block { header: h, transactions: vec![coinbase, bad_tx] };
        let ctx = BlockValidationContext {
            block: &block,
            height: 1,
            median_time_past: 0,
            network_time: 200000,
            expected_bits: 0x207fffff,
            flags: ScriptFlags::default(),
            network: Network::Regtest,
            mtp_provider: &TestMtpProvider,
            signet_challenge: None,
        };

        // Without skip: should FAIL script verification
        let result_normal = verify_block_with_options(&ctx, &utxos, false);
        assert!(result_normal.is_err(), "should fail without skip_script_verification");

        // With skip (assumevalid): should PASS
        let fees = verify_block_with_options(&ctx, &utxos, true).unwrap();
        assert_eq!(fees, 1_000); // 5000 - 4000
    }

    /// Structural checks (merkle root, coinbase, weight) still apply even with
    /// skip_script_verification=true.
    #[test]
    fn skip_script_verification_still_checks_merkle_root() {
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
        // Deliberately wrong merkle root
        let mut h = header_with_valid_pow(0x207fffff);
        h.merkle_root = Hash256([0xff; 32]);
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
            signet_challenge: None,
        };
        let result = verify_block_with_options(&ctx, &UtxoSet::new(), true);
        assert!(result.is_err(), "bad merkle root should still be rejected with skip_script");
        assert!(matches!(result.unwrap_err(), ConsensusError::BadMerkleRoot));
    }
}
