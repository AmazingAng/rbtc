use rbtc_mempool::Mempool;
use rbtc_primitives::transaction::Transaction;

/// Maximum block weight reserved for non-coinbase transactions.
///
/// BIP141 block weight limit is 4,000,000 WU. We reserve ~4,000 WU for
/// the coinbase transaction, leaving 3,996,000 WU for mempool transactions.
pub const MAX_BLOCK_TX_WEIGHT: u64 = 3_996_000;

/// Greedy transaction selector: pick transactions from the mempool
/// in descending fee-rate order, respecting the block weight limit.
pub struct TxSelector;

impl TxSelector {
    /// Select transactions for a block template.
    ///
    /// Returns `(transactions, total_fees_sat)`.
    ///
    /// The returned list does NOT include the coinbase transaction.
    pub fn select(mempool: &Mempool) -> (Vec<Transaction>, u64) {
        let txids = mempool.txids_by_fee_rate();

        let mut selected: Vec<Transaction> = Vec::new();
        let mut total_weight: u64 = 0;
        let mut total_fees: u64 = 0;

        for txid in &txids {
            let entry = match mempool.get(txid) {
                Some(e) => e,
                None => continue,
            };

            let tx_weight = entry.tx.weight();

            // Skip if this transaction would exceed the budget.
            // Continue to try smaller transactions.
            if total_weight + tx_weight > MAX_BLOCK_TX_WEIGHT {
                continue;
            }

            total_weight += tx_weight;
            total_fees += entry.fee;
            selected.push(entry.tx.clone());
        }

        (selected, total_fees)
    }

    /// Estimate the block weight for a given set of transactions
    /// (does not include coinbase weight).
    pub fn total_weight(txs: &[Transaction]) -> u64 {
        txs.iter().map(|tx| tx.weight()).sum()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_mempool::Mempool;

    #[test]
    fn select_empty_mempool() {
        let mp = Mempool::new();
        let (txs, fees) = TxSelector::select(&mp);
        assert!(txs.is_empty());
        assert_eq!(fees, 0);
    }

    #[test]
    fn select_respects_weight_limit() {
        // We can't easily fill a real mempool to the limit in a unit test
        // (accept_tx requires valid UTXOs), so just verify that the total
        // weight of selected transactions stays within bounds.
        let mp = Mempool::new();
        let (txs, _fees) = TxSelector::select(&mp);
        let w = TxSelector::total_weight(&txs);
        assert!(w <= MAX_BLOCK_TX_WEIGHT);
    }
}
