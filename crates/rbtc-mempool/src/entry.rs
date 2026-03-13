use std::time::Instant;

use rbtc_primitives::{hash::{Txid, Wtxid}, transaction::Transaction};

/// Cached transaction finality information for BIP68 relative timelocks.
/// Matches Bitcoin Core's LockPoints struct.
#[derive(Debug, Clone, Default)]
pub struct LockPoints {
    /// Block height at which the transaction can be included (max of all input heights + CSV delays).
    pub height: u32,
    /// Earliest time at which the transaction can be included (max of all input MTP + CSV delays).
    pub time: i64,
    /// The tip used to calculate the lock points. If the chain tip changes,
    /// lock points may need recalculation.
    pub max_input_block_height: u32,
}

/// A validated, unconfirmed transaction held in the mempool
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub txid: Txid,
    /// Witness transaction ID (double-SHA256 of the full serialized tx including witness).
    /// Equal to txid when the transaction has no witness data.
    pub wtxid: Wtxid,
    /// Fee paid in satoshis
    pub fee: u64,
    /// Virtual size in virtual bytes (weight / 4, rounded up)
    pub vsize: u64,
    /// Fee rate in satoshis per virtual byte
    pub fee_rate: u64,
    /// BIP125: true if any input has nSequence < 0xFFFFFFFE
    pub signals_rbf: bool,
    /// True if any input spends a coinbase output
    pub spends_coinbase: bool,
    /// Effective fee rate including unconfirmed ancestors (CPFP).
    /// Equals `fee_rate` when all inputs are confirmed.
    pub ancestor_fee_rate: u64,
    /// Total ancestor count (including self)
    pub ancestor_count: u64,
    /// Total ancestor virtual size (including self)
    pub ancestor_vsize: u64,
    /// Total ancestor fees (including self)
    pub ancestor_fees: u64,
    /// Number of in-mempool descendants (excluding self)
    pub descendant_count: u64,
    /// Total descendant virtual size (including self)
    pub descendant_vsize: u64,
    /// Total descendant fees (including self)
    pub descendant_fees: u64,
    /// Sigops cost for this transaction (legacy sigops × WITNESS_SCALE_FACTOR).
    /// Used for block-level sigops limit enforcement.
    pub sigops_cost: u64,
    /// Wall-clock time when the entry was accepted
    pub added_at: Instant,
    /// Cached BIP68 lock-point data (relative timelocks).
    pub lock_points: LockPoints,
}
