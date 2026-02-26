use rbtc_primitives::{
    constants::{COIN, COINBASE_MATURITY, INITIAL_SUBSIDY, SUBSIDY_HALVING_INTERVAL},
    hash::Hash256,
    transaction::Transaction,
    Network,
};
use rbtc_crypto::sha256d;
use rbtc_script::{ScriptContext, ScriptFlags, verify_input};

use crate::{error::ConsensusError, utxo::{Utxo, UtxoLookup}};

/// Provides MedianTimePast lookups for a given block height.
pub trait MedianTimeProvider {
    fn median_time_past_at_height(&self, height: u32) -> u32;
}

/// Compute the block subsidy for a given height
pub fn block_subsidy(height: u32) -> u64 {
    let halvings = height as u64 / SUBSIDY_HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}

/// Maximum allowed output value
const MAX_MONEY: u64 = 21_000_000 * COIN;

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
        fn median_time_past_at_height(&self, _height: u32) -> u32 { 0 }
    }
    verify_transaction_with_lock_rules(
        tx,
        utxos,
        current_height,
        flags,
        u32::MAX,
        &NoopMtp,
        false,
    )
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
    let txid = compute_txid(tx);

    if tx.inputs.is_empty() {
        return Err(ConsensusError::NoInputs);
    }
    if tx.outputs.is_empty() {
        return Err(ConsensusError::NoOutputs);
    }

    // Check output amounts
    let mut output_sum: u64 = 0;
    for out in &tx.outputs {
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

    // Gather inputs from UTXO set
    let mut input_sum: u64 = 0;
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    let mut input_heights = Vec::with_capacity(tx.inputs.len());

    for input in &tx.inputs {
        let utxo: Utxo = utxos.get_utxo(&input.previous_output).ok_or_else(|| {
            ConsensusError::MissingUtxo(
                input.previous_output.txid.to_hex(),
                input.previous_output.vout,
            )
        })?;

        // Coinbase maturity check
        if utxo.is_coinbase {
            let depth = current_height.saturating_sub(utxo.height);
            if depth < COINBASE_MATURITY {
                return Err(ConsensusError::CoinbaseNotMature(utxo.height, current_height));
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
        && !sequence_locks_satisfied(tx, &input_heights, current_height, lock_time_cutoff, mtp_provider)
    {
        return Err(ConsensusError::SequenceLockNotSatisfied);
    }

    if input_sum < output_sum {
        return Err(ConsensusError::NegativeFee);
    }
    let fee = input_sum - output_sum;

    // Script verification for each input
    for (i, prevout) in prevouts.iter().enumerate() {
        let ctx = ScriptContext {
            tx,
            input_index: i,
            prevout,
            flags,
            all_prevouts: &prevouts,
        };
        verify_input(&ctx).map_err(|e| {
            let script_kind = classify_script(&prevout.script_pubkey);
            let spk_preview = preview_script_bytes(prevout.script_pubkey.as_bytes(), 24);
            ConsensusError::ScriptError(format!(
                "txid={} vin={} prevout={}:{} kind={} spk_len={} spk={} flags=[{}]: {}",
                txid.to_hex(),
                i,
                tx.inputs[i].previous_output.txid.to_hex(),
                tx.inputs[i].previous_output.vout,
                script_kind,
                prevout.script_pubkey.len(),
                spk_preview,
                format_flags(flags),
                e
            ))
        })?;
    }

    Ok(fee)
}

fn is_final_tx(tx: &Transaction, block_height: u32, lock_time_cutoff: u32) -> bool {
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
    if sig_len < 2 || sig_len > 100 {
        return Err(ConsensusError::InvalidTx(format!(
            "coinbase scriptSig length {sig_len} out of range [2, 100]"
        )));
    }

    // BIP34: block height must be first element of scriptSig for block ≥ bip34_height
    let bip34_height = network.consensus_params().bip34_height;
    if block_height >= bip34_height {
        check_coinbase_height(tx, block_height)?;
    }

    // Total output value ≤ subsidy + fees (checked at block level)
    let total_out: u64 = tx.outputs.iter().map(|o| o.value).sum();
    if total_out > expected_subsidy {
        return Err(ConsensusError::BadCoinbaseAmount(total_out, expected_subsidy));
    }

    Ok(())
}

fn check_coinbase_height(tx: &Transaction, height: u32) -> Result<(), ConsensusError> {
    let script = tx.inputs[0].script_sig.as_bytes();
    if script.is_empty() {
        return Err(ConsensusError::InvalidTx("coinbase missing height push".into()));
    }
    let push_len = script[0] as usize;
    if push_len == 0 || push_len > 4 || 1 + push_len > script.len() {
        return Err(ConsensusError::InvalidTx("invalid coinbase height push".into()));
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
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::Network;
    use rbtc_primitives::script::Script;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use rbtc_script::ScriptFlags;
    use crate::utxo::UtxoSet;

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
        assert_eq!(block_subsidy(0), 50_0000_0000);
        assert_eq!(block_subsidy(209999), 50_0000_0000);
        assert_eq!(block_subsidy(210000), 25_0000_0000);
        assert_eq!(block_subsidy(420000), 12_5000_0000);
        assert_eq!(block_subsidy(64 * 210_000), 0);
    }

    #[test]
    fn verify_transaction_no_inputs() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let utxos = UtxoSet::new();
        let r = verify_transaction(&tx, &utxos, 0, ScriptFlags::default());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::NoInputs));
    }

    #[test]
    fn verify_transaction_no_outputs() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let mut utxos = UtxoSet::new();
        utxos.add_tx(Hash256::ZERO, &Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::new() }],
            lock_time: 0,
        }, 0);
        let r = verify_transaction(&tx, &utxos, 0, ScriptFlags::default());
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::NoOutputs));
    }

    #[test]
    fn verify_coinbase_not_coinbase() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([1; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let r = verify_coinbase(&tx, 0, 50_0000_0000, Network::Regtest);
        assert!(r.is_err());
        assert!(matches!(r.unwrap_err(), ConsensusError::FirstTxNotCoinbase));
    }

    #[test]
    fn verify_coinbase_script_sig_too_short() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![1]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 50_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        let r = verify_coinbase(&tx, 0, 50_0000_0000, Network::Regtest);
        assert!(r.is_err());
    }

    #[test]
    fn verify_coinbase_ok() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![2, 0, 0]),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 25_0000_0000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
        assert!(verify_coinbase(&tx, 0, 50_0000_0000, Network::Regtest).is_ok());
    }

    #[test]
    fn verify_transaction_bip113_locktime_not_satisfied() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256([9; 32]), vout: 0 },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1000, script_pubkey: Script::new() }],
            lock_time: 100,
        };
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
        let txid = Hash256([7; 32]);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid, vout: 0 },
            Utxo {
                txout: TxOut { value: 2_000, script_pubkey: Script::new() },
                is_coinbase: false,
                height: 100,
            },
        );
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: Script::new(),
                sequence: 1,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1_000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
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
        let txid = Hash256([8; 32]);
        let mut utxos = UtxoSet::new();
        utxos.insert(
            OutPoint { txid, vout: 0 },
            Utxo {
                txout: TxOut { value: 2_000, script_pubkey: Script::new() },
                is_coinbase: false,
                height: 100,
            },
        );
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: Script::new(),
                sequence: (1 << 22) | 1,
                witness: vec![],
            }],
            outputs: vec![TxOut { value: 1_000, script_pubkey: Script::new() }],
            lock_time: 0,
        };
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
