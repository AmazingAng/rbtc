use rbtc_primitives::{
    constants::{COIN, COINBASE_MATURITY, INITIAL_SUBSIDY, SUBSIDY_HALVING_INTERVAL},
    transaction::Transaction,
    Network,
};
use rbtc_script::{ScriptContext, ScriptFlags, verify_input};

use crate::{error::ConsensusError, utxo::{Utxo, UtxoLookup}};

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

    // Gather inputs from UTXO set
    let mut input_sum: u64 = 0;
    let mut prevouts = Vec::with_capacity(tx.inputs.len());

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
        verify_input(&ctx).map_err(|e| ConsensusError::ScriptError(e.to_string()))?;
    }

    Ok(fee)
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
}
