use std::time::Instant;

use rbtc_primitives::{hash::TxId, transaction::Transaction};

/// A validated, unconfirmed transaction held in the mempool
#[derive(Debug)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub txid: TxId,
    /// Fee paid in satoshis
    pub fee: u64,
    /// Virtual size in virtual bytes (weight / 4, rounded up)
    pub vsize: u64,
    /// Fee rate in satoshis per virtual byte
    pub fee_rate: u64,
    /// Wall-clock time when the entry was accepted
    pub added_at: Instant,
}
