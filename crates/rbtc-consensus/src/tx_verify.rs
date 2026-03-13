use std::collections::HashSet;

#[cfg(feature = "experimental-input-parallel")]
use rayon::prelude::*;
use rbtc_crypto::sha256d;
use rbtc_primitives::{
    constants::{COINBASE_MATURITY, INITIAL_SUBSIDY},
    hash::Hash256,
    transaction::{Transaction, TxOut, COIN},
    Network,
};
use rbtc_script::{verify_input, ScriptContext, ScriptFlags};

use crate::{
    error::ConsensusError,
    script_exec_cache::{cache_contains, cache_insert, make_script_exec_key},
    utxo::{Utxo, UtxoLookup},
};

/// Provides MedianTimePast lookups for a given block height.
pub trait MedianTimeProvider {
    fn median_time_past_at_height(&self, height: u32) -> u32;
}

/// Compute the block subsidy for a given height and halving interval.
///
/// `halving_interval` is the number of blocks between halvings
/// (210 000 for mainnet/testnet, 150 for regtest).
/// Use `ConsensusParams::subsidy_halving_interval` from the active network.
pub fn block_subsidy(height: u32, halving_interval: u64) -> u64 {
    let halvings = height as u64 / halving_interval;
    if halvings >= 64 {
        return 0;
    }
    (INITIAL_SUBSIDY >> halvings) as u64
}

/// Maximum allowed output value
const MAX_MONEY: i64 = 21_000_000 * COIN;

/// Verify a non-coinbase transaction against the UTXO set.
/// Returns the transaction fee (satoshis) on success.
pub fn verify_transaction(
    tx: &Transaction,
    utxos: &impl UtxoLookup,
    current_height: u32,
    flags: ScriptFlags,
) -> Result<u64, ConsensusError> {
    struct NoopMtp;
    impl MedianTimeProvider for NoopMtp {
        fn median_time_past_at_height(&self, _height: u32) -> u32 {
            0
        }
    }
    verify_transaction_with_lock_rules(tx, utxos, current_height, flags, u32::MAX, &NoopMtp, false)
}

pub fn verify_transaction_with_lock_rules(
    tx: &Transaction,
    utxos: &impl UtxoLookup,
    current_height: u32,
    flags: ScriptFlags,
    lock_time_cutoff: u32,
    mtp_provider: &dyn MedianTimeProvider,
    enforce_lock_rules: bool,
) -> Result<u64, ConsensusError> {
    verify_transaction_with_lock_rules_preloaded(
        tx,
        utxos,
        current_height,
        flags,
        lock_time_cutoff,
        mtp_provider,
        enforce_lock_rules,
        None,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_transaction_with_lock_rules_preloaded(
    tx: &Transaction,
    utxos: &impl UtxoLookup,
    current_height: u32,
    flags: ScriptFlags,
    lock_time_cutoff: u32,
    mtp_provider: &dyn MedianTimeProvider,
    enforce_lock_rules: bool,
    preloaded_utxos: Option<&[Utxo]>,
    skip_script_verification: bool,
) -> Result<u64, ConsensusError> {
    if tx.inputs.is_empty() {
        return Err(ConsensusError::NoInputs);
    }
    if tx.outputs.is_empty() {
        return Err(ConsensusError::NoOutputs);
    }

    // CVE-2018-17144: Check for duplicate inputs
    {
        let mut seen = HashSet::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            if !seen.insert(&input.previous_output) {
                return Err(ConsensusError::DuplicateInput(
                    input.previous_output.txid.to_hex(),
                    input.previous_output.vout,
                ));
            }
        }
    }

    // Check output amounts (matches Bitcoin Core CheckTransaction order)
    let mut output_sum: i64 = 0;
    for out in &tx.outputs {
        if out.value < 0 {
            return Err(ConsensusError::NegativeOutputValue);
        }
        if out.value > MAX_MONEY {
            return Err(ConsensusError::OutputValueOverflow);
        }
        output_sum = output_sum
            .checked_add(out.value)
            .ok_or(ConsensusError::OutputValueOverflow)?;
        if output_sum > MAX_MONEY {
            return Err(ConsensusError::OutputValueOverflow);
        }
    }

    // BIP113 finality (MTP-based locktime cutoff after CSV deployment).
    if enforce_lock_rules && !is_final_tx(tx, current_height, lock_time_cutoff) {
        return Err(ConsensusError::LockTimeNotSatisfied);
    }

    // Gather inputs from UTXO set (or from preloaded entries).
    let mut input_sum: i64 = 0;
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    let mut input_heights = Vec::with_capacity(tx.inputs.len());
    let loaded: Vec<Utxo> = match preloaded_utxos {
        Some(entries) => {
            if entries.len() != tx.inputs.len() {
                return Err(ConsensusError::InvalidTx(
                    "preloaded input count mismatch".into(),
                ));
            }
            entries.to_vec()
        }
        None => load_transaction_inputs(tx, utxos)?,
    };

    for utxo in &loaded {
        // Coinbase maturity check
        if utxo.is_coinbase {
            let depth = current_height.saturating_sub(utxo.height);
            if depth < COINBASE_MATURITY {
                return Err(ConsensusError::CoinbaseNotMature(
                    utxo.height,
                    current_height,
                ));
            }
        }

        let val = utxo.txout.value;
        if val > MAX_MONEY {
            return Err(ConsensusError::InputValueOverflow);
        }
        input_sum = input_sum
            .checked_add(val)
            .ok_or(ConsensusError::InputValueOverflow)?;
        prevouts.push(utxo.txout.clone());
        input_heights.push(utxo.height);
    }

    // BIP68 relative lock-times (enabled with CSV deployment).
    if enforce_lock_rules
        && flags.verify_checksequenceverify
        && !sequence_locks_satisfied(
            tx,
            &input_heights,
            current_height,
            lock_time_cutoff,
            mtp_provider,
        )
    {
        return Err(ConsensusError::SequenceLockNotSatisfied);
    }

    if input_sum < output_sum {
        return Err(ConsensusError::NegativeFee);
    }
    let fee = (input_sum - output_sum) as u64;

    // Script verification for each input
    if !skip_script_verification {
        verify_transaction_scripts_with_prevouts(tx, &prevouts, flags)?;
    }

    Ok(fee)
}

pub fn load_transaction_inputs(
    tx: &Transaction,
    utxos: &impl UtxoLookup,
) -> Result<Vec<Utxo>, ConsensusError> {
    let mut loaded = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let utxo: Utxo = utxos.get_utxo(&input.previous_output).ok_or_else(|| {
            ConsensusError::MissingUtxo(
                input.previous_output.txid.to_hex(),
                input.previous_output.vout,
            )
        })?;
        loaded.push(utxo);
    }
    Ok(loaded)
}

pub fn verify_transaction_scripts_with_prevouts(
    tx: &Transaction,
    prevouts: &[TxOut],
    flags: ScriptFlags,
) -> Result<(), ConsensusError> {
    let txid = compute_txid(tx);
    for (i, prevout) in prevouts.iter().enumerate() {
        let key = make_script_exec_key(
            &txid.0,
            i,
            script_flags_mask(flags),
            prevout.value as u64,
            prevout.script_pubkey.as_bytes(),
            tx.inputs[i].script_sig.as_bytes(),
            &tx.inputs[i].witness,
        );
        if cache_contains(key) {
            continue;
        }
        let ctx = ScriptContext {
            tx,
            input_index: i,
            prevout,
            flags,
            all_prevouts: prevouts,
        };
        verify_input(&ctx)
            .map_err(|e| script_error_for_input(tx, &txid, i, prevout, flags, &e.to_string()))?;
        cache_insert(key);
    }
    Ok(())
}

fn script_flags_mask(flags: ScriptFlags) -> u16 {
    let mut m = 0u16;
    if flags.verify_p2sh {
        m |= 1 << 0;
    }
    if flags.verify_dersig {
        m |= 1 << 1;
    }
    if flags.verify_witness {
        m |= 1 << 2;
    }
    if flags.verify_nulldummy {
        m |= 1 << 3;
    }
    if flags.verify_cleanstack {
        m |= 1 << 4;
    }
    if flags.verify_checklocktimeverify {
        m |= 1 << 5;
    }
    if flags.verify_checksequenceverify {
        m |= 1 << 6;
    }
    if flags.verify_taproot {
        m |= 1 << 7;
    }
    m
}

pub fn verify_transaction_scripts_only(
    tx: &Transaction,
    utxos: &impl UtxoLookup,
    flags: ScriptFlags,
) -> Result<(), ConsensusError> {
    let prevouts: Vec<TxOut> = load_transaction_inputs(tx, utxos)?
        .into_iter()
        .map(|u| u.txout)
        .collect();
    verify_transaction_scripts_with_prevouts(tx, &prevouts, flags)
}

#[cfg(feature = "experimental-input-parallel")]
pub fn verify_transaction_scripts_parallel_inputs(
    tx: &Transaction,
    utxos: &impl UtxoLookup,
    flags: ScriptFlags,
) -> Result<(), ConsensusError> {
    let prevouts: Vec<TxOut> = load_transaction_inputs(tx, utxos)?
        .into_iter()
        .map(|u| u.txout)
        .collect();
    let txid = compute_txid(tx);
    let errors: Vec<ConsensusError> = prevouts
        .par_iter()
        .enumerate()
        .filter_map(|(i, prevout)| {
            let ctx = ScriptContext {
                tx,
                input_index: i,
                prevout,
                flags,
                all_prevouts: &prevouts,
            };
            verify_input(&ctx)
                .err()
                .map(|e| script_error_for_input(tx, &txid, i, prevout, flags, &e.to_string()))
        })
        .collect();
    if let Some(first) = errors.into_iter().next() {
        return Err(first);
    }
    Ok(())
}

pub fn is_final_tx(tx: &Transaction, block_height: u32, lock_time_cutoff: u32) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    let lock_time_threshold = 500_000_000u32;
    let cmp_target = if tx.lock_time < lock_time_threshold {
        block_height
    } else {
        lock_time_cutoff
    };
    if tx.lock_time < cmp_target {
        return true;
    }
    tx.inputs.iter().all(|input| input.sequence == 0xffff_ffff)
}

fn sequence_locks_satisfied(
    tx: &Transaction,
    input_heights: &[u32],
    block_height: u32,
    prev_block_mtp: u32,
    mtp_provider: &dyn MedianTimeProvider,
) -> bool {
    if tx.version < 2 || tx.is_coinbase() {
        return true;
    }
    if input_heights.len() != tx.inputs.len() {
        return false;
    }

    const SEQUENCE_LOCKTIME_GRANULARITY: i64 = 9;
    const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
    const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
    const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

    let mut min_height: i64 = -1;
    let mut min_time: i64 = -1;

    for (input, &coin_height_u32) in tx.inputs.iter().zip(input_heights.iter()) {
        let seq = input.sequence;
        if (seq & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
            continue;
        }
        let coin_height = i64::from(coin_height_u32);
        let relative = i64::from(seq & SEQUENCE_LOCKTIME_MASK);
        if (seq & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0 {
            let base_height = coin_height_u32.saturating_sub(1);
            let coin_mtp = i64::from(mtp_provider.median_time_past_at_height(base_height));
            let required = coin_mtp + (relative << SEQUENCE_LOCKTIME_GRANULARITY) - 1;
            min_time = min_time.max(required);
        } else {
            let required = coin_height + relative - 1;
            min_height = min_height.max(required);
        }
    }

    min_height < i64::from(block_height) && min_time < i64::from(prev_block_mtp)
}

fn compute_txid(tx: &Transaction) -> Hash256 {
    let mut buf = Vec::new();
    tx.encode_legacy(&mut buf).ok();
    sha256d(&buf)
}

fn classify_script(script: &rbtc_primitives::script::Script) -> &'static str {
    if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_p2wpkh() {
        "p2wpkh"
    } else if script.is_p2wsh() {
        "p2wsh"
    } else if script.is_p2tr() {
        "p2tr"
    } else if script.is_op_return() {
        "op_return"
    } else {
        "nonstandard/legacy"
    }
}

fn preview_script_bytes(bytes: &[u8], max: usize) -> String {
    let mut s = String::new();
    let take = bytes.len().min(max);
    for b in &bytes[..take] {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{:02x}", b);
    }
    if bytes.len() > max {
        s.push_str("...");
    }
    s
}

fn format_flags(flags: ScriptFlags) -> String {
    format!(
        "p2sh={} dersig={} witness={} nulldummy={} cltv={} csv={} taproot={} cleanstack={}",
        flags.verify_p2sh,
        flags.verify_dersig,
        flags.verify_witness,
        flags.verify_nulldummy,
        flags.verify_checklocktimeverify,
        flags.verify_checksequenceverify,
        flags.verify_taproot,
        flags.verify_cleanstack
    )
}

fn script_error_for_input(
    tx: &Transaction,
    txid: &Hash256,
    input_index: usize,
    prevout: &TxOut,
    flags: ScriptFlags,
    err_msg: &str,
) -> ConsensusError {
    let script_kind = classify_script(&prevout.script_pubkey);
    let spk_preview = preview_script_bytes(prevout.script_pubkey.as_bytes(), 24);
    ConsensusError::ScriptError(format!(
        "txid={} vin={} prevout={}:{} kind={} spk_len={} spk={} flags=[{}]: {}",
        txid.to_hex(),
        input_index,
        tx.inputs[input_index].previous_output.txid.to_hex(),
        tx.inputs[input_index].previous_output.vout,
        script_kind,
        prevout.script_pubkey.len(),
        spk_preview,
        format_flags(flags),
        err_msg
    ))
}

/// Verify a coinbase transaction structure
pub fn verify_coinbase(
    tx: &Transaction,
    block_height: u32,
    expected_subsidy: u64,
    network: Network,
) -> Result<(), ConsensusError> {
    if !tx.is_coinbase() {
        return Err(ConsensusError::FirstTxNotCoinbase);
    }
    if tx.outputs.is_empty() {
        return Err(ConsensusError::NoOutputs);
    }

    // Coinbase scriptSig length: 2–100 bytes
    let sig_len = tx.inputs[0].script_sig.len();
    if !(2..=100).contains(&sig_len) {
        return Err(ConsensusError::InvalidTx(format!(
            "coinbase scriptSig length {sig_len} out of range [2, 100]"
        )));
    }

    // BIP34: block height must be first element of scriptSig for block ≥ bip34_height
    let bip34_height = network.consensus_params().bip34_height;
    if block_height >= bip34_height {
        check_coinbase_height(tx, block_height)?;
    }

    // Validate individual output amounts (same checks as non-coinbase)
    let mut total_out_i64: i64 = 0;
    for out in &tx.outputs {
        if out.value < 0 {
            return Err(ConsensusError::NegativeOutputValue);
        }
        if out.value > MAX_MONEY {
            return Err(ConsensusError::OutputValueOverflow);
        }
        total_out_i64 = total_out_i64
            .checked_add(out.value)
            .ok_or(ConsensusError::OutputValueOverflow)?;
        if total_out_i64 > MAX_MONEY {
            return Err(ConsensusError::OutputValueOverflow);
        }
    }

    // Total output value ≤ subsidy + fees (checked at block level)
    let total_out = total_out_i64 as u64;
    if total_out > expected_subsidy {
        return Err(ConsensusError::BadCoinbaseAmount(
            total_out,
            expected_subsidy,
        ));
    }

    Ok(())
}

fn check_coinbase_height(tx: &Transaction, height: u32) -> Result<(), ConsensusError> {
    let script = tx.inputs[0].script_sig.as_bytes();
    if script.is_empty() {
        return Err(ConsensusError::InvalidTx(
            "coinbase missing height push".into(),
        ));
    }
    let push_len = script[0] as usize;
    if push_len == 0 || push_len > 4 || 1 + push_len > script.len() {
        return Err(ConsensusError::InvalidTx(
            "invalid coinbase height push".into(),
        ));
    }
    let mut h = 0u32;
    for i in 0..push_len {
        h |= (script[1 + i] as u32) << (8 * i);
    }
    if h != height {
        return Err(ConsensusError::InvalidTx(format!(
            "coinbase height {h} != expected {height}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::UtxoSet;
    use rbtc_primitives::hash::{Hash256, Txid};
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use rbtc_primitives::Network;
    use rbtc_script::ScriptFlags;

    struct TestMtpProvider;
    impl MedianTimeProvider for TestMtpProvider {
        fn median_time_past_at_height(&self, _height: u32) -> u32 {
            0
        }
    }

    struct LinearMtpProvider;
    impl MedianTimeProvider for LinearMtpProvider {
        fn median_time_past_at_height(&self, height: u32) -> u32 {
            height.saturating_mul(1000)
        }
    }

    #[test]
    fn block_subsidy_halvings() {
        // Mainnet halving interval
        assert_eq!(block_subsidy(0, 210_000), 50_0000_0000);
        assert_eq!(block_subsidy(209999, 210_000), 50_0000_0000);
        assert_eq!(block_subsidy(210000, 210_000), 25_0000_0000);
        assert_eq!(block_subsidy(420000, 210_000), 12_5000_0000);
        assert_eq!(block_subsidy(64 * 210_000, 210_000), 0);
    }

    #[test]
    fn block_subsidy_regtest_halving() {
        // Regtest halving interval is 150
        assert_eq!(block_subsidy(0, 150), 50_0000_0000);
        assert_eq!(block_subsidy(149, 150), 50_0000_0000);
        assert_eq!(block_subsidy(150, 150), 25_0000_0000);
        assert_eq!(block_subsidy(300, 150), 12_5000_0000);
    }

    #[test]
    fn verify_transaction_no_inputs() {
        let tx = Transaction::from_parts(
            1,
            vec![],
            vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let utxos = UtxoSet::new();
        let r = verify_transaction(&tx, &utxos, 0, ScriptFlags::default());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::NoInputs));
    }

    #[test]
    fn verify_transaction_duplicate_inputs_rejected() {
        // CVE-2018-17144: a transaction spending the same outpoint twice must be rejected.
        let dup_outpoint = OutPoint {
            txid: Txid(Hash256([0xAA; 32])),
            vout: 0,
        };
        let tx = Transaction::from_parts(
            1,
            vec![
                TxIn {
                    previous_output: dup_outpoint.clone(),
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                },
                TxIn {
                    previous_output: dup_outpoint.clone(),
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                },
            ],
            vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let utxos = UtxoSet::new();
        let r = verify_transaction(&tx, &utxos, 100, ScriptFlags::default());
        assert!(r.is_err());
        assert!(
            matches!(r.unwrap_err(), ConsensusError::DuplicateInput(..)),
            "expected DuplicateInput error"
        );
    }

    #[test]
    fn verify_transaction_distinct_inputs_pass_dup_check() {
        // Two different outpoints should pass the duplicate check (may fail later on UTXO lookup).
        let tx = Transaction::from_parts(
            1,
            vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid(Hash256([0xBB; 32])),
                        vout: 0,
                    },
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid(Hash256([0xBB; 32])),
                        vout: 1, // different vout
                    },
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                },
            ],
            vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let utxos = UtxoSet::new();
        let r = verify_transaction(&tx, &utxos, 100, ScriptFlags::default());
        // Should NOT be DuplicateInput — will fail with MissingUtxo instead
        assert!(r.is_err());
        assert!(
            matches!(r.unwrap_err(), ConsensusError::MissingUtxo(..)),
            "expected MissingUtxo error, not DuplicateInput"
        );
    }

    #[test]
    fn verify_transaction_no_outputs() {
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            vec![],
            0,
        );
        let mut utxos = UtxoSet::new();
        utxos.add_tx(
            Txid::ZERO,
            &Transaction::from_parts(
                1,
                vec![],
                vec![TxOut {
                    value: 1000,
                    script_pubkey: Script::new(),
                }],
                0,
            ),
            0,
        );
        let r = verify_transaction(&tx, &utxos, 0, ScriptFlags::default());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::NoOutputs));
    }

    #[test]
    fn verify_coinbase_not_coinbase() {
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([1; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let r = verify_coinbase(&tx, 0, 50_0000_0000, Network::Regtest);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::FirstTxNotCoinbase));
    }

    #[test]
    fn verify_coinbase_script_sig_too_short() {
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![1]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let r = verify_coinbase(&tx, 0, 50_0000_0000, Network::Regtest);
        assert!(r.is_err());
    }

    #[test]
    fn verify_coinbase_ok() {
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 25_0000_0000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        assert!(verify_coinbase(&tx, 0, 50_0000_0000, Network::Regtest).is_ok());
    }

    #[test]
    fn verify_transaction_negative_output_value_rejected() {
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([0xCC; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: -1,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let utxos = UtxoSet::new();
        let r = verify_transaction(&tx, &utxos, 100, ScriptFlags::default());
        assert!(r.is_err());
        assert!(
            matches!(r.unwrap_err(), ConsensusError::NegativeOutputValue),
            "expected NegativeOutputValue error for negative output"
        );
    }

    #[test]
    fn verify_transaction_negative_output_bypasses_max_money() {
        // Ensure a large negative value (which is < MAX_MONEY as i64) is still caught
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([0xDD; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: i64::MIN,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let utxos = UtxoSet::new();
        let r = verify_transaction(&tx, &utxos, 100, ScriptFlags::default());
        assert!(r.is_err());
        assert!(
            matches!(r.unwrap_err(), ConsensusError::NegativeOutputValue),
            "expected NegativeOutputValue error for i64::MIN output"
        );
    }

    #[test]
    fn verify_transaction_bip113_locktime_not_satisfied() {
        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([9; 32])),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(),
            }],
            100,
        );
        let utxos = UtxoSet::new();
        let r = verify_transaction_with_lock_rules(
            &tx,
            &utxos,
            1,
            ScriptFlags::default(),
            100,
            &TestMtpProvider,
            true,
        );
        assert!(matches!(r, Err(ConsensusError::LockTimeNotSatisfied)));
    }

    #[test]
    fn verify_transaction_bip68_height_lock_not_satisfied() {
        let txid = Txid(Hash256([7; 32]));
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid, vout: 0 },
            Utxo {
                txout: TxOut {
                    value: 2_000,
                    script_pubkey: Script::new(),
                },
                is_coinbase: false,
                height: 100,
            },
        );
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 1,
                witness: vec![],
            }],
            vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut flags = ScriptFlags::default();
        flags.verify_checksequenceverify = true;
        let r = verify_transaction_with_lock_rules(
            &tx,
            &utxos,
            100,
            flags,
            1000,
            &LinearMtpProvider,
            true,
        );
        assert!(matches!(r, Err(ConsensusError::SequenceLockNotSatisfied)));
    }

    #[test]
    fn verify_transaction_bip68_time_lock_not_satisfied() {
        let txid = Txid(Hash256([8; 32]));
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid, vout: 0 },
            Utxo {
                txout: TxOut {
                    value: 2_000,
                    script_pubkey: Script::new(),
                },
                is_coinbase: false,
                height: 100,
            },
        );
        let tx = Transaction::from_parts(
            2,
            vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: Script::new(),
                sequence: (1 << 22) | 1,
                witness: vec![],
            }],
            vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(),
            }],
            0,
        );
        let mut flags = ScriptFlags::default();
        flags.verify_checksequenceverify = true;
        // coin height 100 -> base MTP at 99 = 99000; required min_time = 99000 + 512 - 1 = 99511
        let r = verify_transaction_with_lock_rules(
            &tx,
            &utxos,
            200,
            flags,
            99_511,
            &LinearMtpProvider,
            true,
        );
        assert!(matches!(r, Err(ConsensusError::SequenceLockNotSatisfied)));
    }
}
