//! Fee rate estimation following Bitcoin Core's `CBlockPolicyEstimator`.
//!
//! The estimator tracks confirmed transactions across exponential fee-rate
//! buckets and three time-horizon "scales" (short / medium / long).  When
//! asked for an estimate it finds the lowest fee-rate bucket where the
//! historical confirmation probability within `conf_target` blocks meets a
//! minimum success threshold.

use std::collections::HashMap;

use rbtc_primitives::hash::Txid;

// ── Constants (matching Bitcoin Core `policy/fees.cpp`) ───────────────────

/// Minimum fee rate tracked (1 sat/vB).
const MIN_BUCKET_FEERATE: f64 = 1.0;
/// Maximum fee rate tracked (10_000 sat/vB).
const MAX_BUCKET_FEERATE: f64 = 10_000.0;
/// Each bucket boundary is `FEE_SPACING` times the previous one.
const FEE_SPACING: f64 = 1.05;
/// Decay factor per block for the short-horizon window.
const SHORT_DECAY: f64 = 0.962;
/// Decay factor per block for the medium-horizon window.
const MED_DECAY: f64 = 0.9952;
/// Decay factor per block for the long-horizon window.
const LONG_DECAY: f64 = 0.99931;
/// Short-horizon scale (number of buckets of confirmation targets).
const SHORT_SCALE: usize = 1;
/// Medium-horizon scale.
const MED_SCALE: usize = 2;
/// Long-horizon scale.
const LONG_SCALE: usize = 24;
/// Minimum success probability to consider a bucket viable.
const SUCCESS_PCT: f64 = 0.85;
/// Require at least this many tx-block data points in a bucket before
/// using it for an estimate.
const SUFFICIENT_FEETXS: f64 = 0.1;
/// Maximum confirmation target we track.
const MAX_CONF_TARGET: usize = 1008;

/// Index into the three estimation horizons.
#[derive(Debug, Clone, Copy)]
enum Horizon {
    Short,
    Med,
    Long,
}

/// One estimation horizon, tracking fee-rate buckets over time.
#[derive(Debug, Clone)]
struct TxConfirmStats {
    /// Exponential decay factor applied every block.
    decay: f64,
    /// `scale`: how many blocks each target bucket represents.
    scale: usize,
    /// Number of fee-rate buckets.
    num_buckets: usize,
    /// Upper boundary of each fee-rate bucket (sat/vB).
    bucket_upper: Vec<f64>,
    /// Maximum number of confirmation-target periods we track.
    max_periods: usize,
    /// `confirm[period][bucket]` — decayed count of txs confirmed within
    /// `<= (period+1)*scale` blocks that fell in this fee-rate bucket.
    confirm: Vec<Vec<f64>>,
    /// `fail[period][bucket]` — decayed count of txs that were NOT confirmed
    /// within `<= (period+1)*scale` blocks.
    fail: Vec<Vec<f64>>,
    /// `avg[bucket]` — decayed running total of fee rates in this bucket
    /// (for computing average fee rate of successful txs).
    avg: Vec<f64>,
    /// `tx_ct[bucket]` — decayed count of all txs that entered this bucket.
    tx_ct: Vec<f64>,
}

impl TxConfirmStats {
    fn new(bucket_upper: &[f64], max_periods: usize, decay: f64, scale: usize) -> Self {
        let n = bucket_upper.len();
        Self {
            decay,
            scale,
            num_buckets: n,
            bucket_upper: bucket_upper.to_vec(),
            max_periods,
            confirm: vec![vec![0.0; n]; max_periods],
            fail: vec![vec![0.0; n]; max_periods],
            avg: vec![0.0; n],
            tx_ct: vec![0.0; n],
        }
    }

    /// Apply exponential decay to all counters (called once per block).
    fn decay_counters(&mut self) {
        for bucket in 0..self.num_buckets {
            for period in 0..self.max_periods {
                self.confirm[period][bucket] *= self.decay;
                self.fail[period][bucket] *= self.decay;
            }
            self.avg[bucket] *= self.decay;
            self.tx_ct[bucket] *= self.decay;
        }
    }

    /// Record a confirmed transaction.
    fn record_confirmed(&mut self, bucket: usize, blocks_to_confirm: usize) {
        let period_idx = if self.scale == 0 {
            0
        } else {
            (blocks_to_confirm.saturating_sub(1)) / self.scale
        };
        // Every period at or above the confirmation period gets +1 success.
        for p in period_idx..self.max_periods {
            self.confirm[p][bucket] += 1.0;
        }
        self.tx_ct[bucket] += 1.0;
    }

    /// Record a failure for all periods whose window has been exceeded.
    /// `blocks_in_mempool` is how many blocks the tx has been pending.
    fn update_unconfirmed(&mut self, bucket: usize, blocks_in_mempool: usize) {
        // For each period whose window this tx has exceeded, record a failure.
        let max_period_exceeded = if self.scale == 0 {
            return;
        } else {
            // periods 0..max_period have windows (1*scale)..(max_period+1)*scale
            // A tx pending for `blocks_in_mempool` has failed periods where
            // (period+1)*scale <= blocks_in_mempool
            blocks_in_mempool / self.scale
        };
        for p in 0..max_period_exceeded.min(self.max_periods) {
            self.fail[p][bucket] += 1.0;
        }
    }

    /// Estimate the lowest fee rate that achieves `SUCCESS_PCT` confirmation
    /// within `conf_target` blocks.  Returns `None` if insufficient data.
    fn estimate_fee(&self, conf_target: usize) -> Option<f64> {
        let period = if self.scale == 0 {
            return None;
        } else {
            (conf_target.saturating_sub(1)) / self.scale
        };
        if period >= self.max_periods {
            return None;
        }

        // Walk buckets from high to low, accumulating pass/fail.
        // As long as the running success rate stays above the threshold,
        // the current bucket is the best (lowest-fee) viable answer.
        // Once the rate drops below the threshold, stop — the previous
        // passing bucket is the answer.
        let mut pass_total = 0.0f64;
        let mut fail_total = 0.0f64;
        let mut best_bucket: Option<usize> = None;
        let mut found_answer = false;

        for bucket in (0..self.num_buckets).rev() {
            pass_total += self.confirm[period][bucket];
            fail_total += self.fail[period][bucket];
            let total = pass_total + fail_total;
            if total > SUFFICIENT_FEETXS {
                if pass_total / total >= SUCCESS_PCT {
                    if !found_answer {
                        found_answer = true;
                    }
                    best_bucket = Some(bucket);
                } else if found_answer {
                    // Success rate dropped — stop scanning.
                    break;
                }
            }
        }

        best_bucket.map(|b| self.bucket_upper[b])
    }
}

/// Per-transaction tracking data stored while the tx is in the mempool.
#[derive(Debug, Clone)]
struct TxStatsInfo {
    /// Fee-rate bucket index at entry time.
    bucket_index: usize,
    /// Block height when the tx entered the mempool.
    block_height: u32,
    /// Fee rate in sat/vB.
    fee_rate: f64,
}

/// Bitcoin Core–style block policy fee estimator.
///
/// Call [`process_block`] after every connected block, and
/// [`estimate_smart_fee`] to obtain an estimate.
#[derive(Debug, Clone)]
pub struct FeeEstimator {
    /// Upper boundary of each fee-rate bucket (sat/vB).
    buckets: Vec<f64>,
    /// Short-horizon stats (scale=1 block, decay≈0.962).
    short_stats: TxConfirmStats,
    /// Medium-horizon stats (scale=2 blocks, decay≈0.9952).
    med_stats: TxConfirmStats,
    /// Long-horizon stats (scale=24 blocks, decay≈0.99931).
    long_stats: TxConfirmStats,
    /// Txs currently in the mempool that we're tracking.
    tracked: HashMap<Txid, TxStatsInfo>,
    /// Current best block height.
    best_height: u32,
}

impl FeeEstimator {
    pub fn new() -> Self {
        let buckets = build_buckets();
        let n = buckets.len();
        // max_periods = ceil(MAX_CONF_TARGET / scale)
        let short_periods = MAX_CONF_TARGET / SHORT_SCALE;
        let med_periods = MAX_CONF_TARGET / MED_SCALE;
        let long_periods = MAX_CONF_TARGET / LONG_SCALE;

        Self {
            short_stats: TxConfirmStats::new(&buckets, short_periods, SHORT_DECAY, SHORT_SCALE),
            med_stats: TxConfirmStats::new(&buckets, med_periods, MED_DECAY, MED_SCALE),
            long_stats: TxConfirmStats::new(&buckets, long_periods, LONG_DECAY, LONG_SCALE),
            buckets,
            tracked: HashMap::new(),
            best_height: 0,
        }
    }

    /// Record a transaction entering the mempool.
    pub fn process_transaction(&mut self, txid: Txid, fee_rate: f64) {
        let bucket = bucket_index(&self.buckets, fee_rate);
        self.tracked.insert(
            txid,
            TxStatsInfo {
                bucket_index: bucket,
                block_height: self.best_height,
                fee_rate,
            },
        );
    }

    /// Process a newly connected block.  `confirmed_txids` is the list of
    /// txids that were confirmed in this block.
    pub fn process_block(&mut self, height: u32, confirmed_txids: &[Txid]) {
        self.best_height = height;

        // Decay all horizons.
        self.short_stats.decay_counters();
        self.med_stats.decay_counters();
        self.long_stats.decay_counters();

        for txid in confirmed_txids {
            if let Some(info) = self.tracked.remove(txid) {
                let blocks_to_confirm = height.saturating_sub(info.block_height) as usize;
                if blocks_to_confirm == 0 {
                    continue;
                }
                self.short_stats
                    .record_confirmed(info.bucket_index, blocks_to_confirm);
                self.med_stats
                    .record_confirmed(info.bucket_index, blocks_to_confirm);
                self.long_stats
                    .record_confirmed(info.bucket_index, blocks_to_confirm);
            }
        }

        // For every still-unconfirmed tx, record failures for elapsed periods.
        let mut to_remove = Vec::new();
        for (txid, info) in &self.tracked {
            let age = height.saturating_sub(info.block_height) as usize;
            if age > 0 {
                self.short_stats
                    .update_unconfirmed(info.bucket_index, age);
                self.med_stats
                    .update_unconfirmed(info.bucket_index, age);
                self.long_stats
                    .update_unconfirmed(info.bucket_index, age);
            }
            if age > MAX_CONF_TARGET {
                to_remove.push(*txid);
            }
        }
        for txid in &to_remove {
            self.tracked.remove(txid);
        }
    }

    /// Remove a transaction (e.g. evicted or conflicted, not confirmed).
    pub fn remove_tx(&mut self, txid: &Txid) {
        self.tracked.remove(txid);
    }

    /// Check whether a transaction is currently being tracked by the estimator.
    pub fn is_tracking(&self, txid: &Txid) -> bool {
        self.tracked.contains_key(txid)
    }

    /// Estimate the fee rate (sat/vB) needed to confirm within `conf_target`
    /// blocks.  Returns `None` if insufficient data.
    pub fn estimate_smart_fee(&self, conf_target: usize) -> Option<f64> {
        let target = conf_target.clamp(1, MAX_CONF_TARGET);

        // Try each horizon in order of accuracy for the target range.
        // Short is best for small targets, long for large.
        let horizons: &[(Horizon, &TxConfirmStats)] = &[
            (Horizon::Short, &self.short_stats),
            (Horizon::Med, &self.med_stats),
            (Horizon::Long, &self.long_stats),
        ];

        let mut best: Option<f64> = None;

        for &(_h, stats) in horizons {
            if let Some(rate) = stats.estimate_fee(target) {
                match best {
                    None => best = Some(rate),
                    Some(prev) => {
                        // Take the higher (more conservative) estimate.
                        if rate > prev {
                            best = Some(rate);
                        }
                    }
                }
            }
        }

        // If the requested target is small and we have no data, try
        // progressively larger targets.
        if best.is_none() && target < MAX_CONF_TARGET {
            for t in (target + 1)..=MAX_CONF_TARGET.min(target * 2) {
                for &(_h, stats) in horizons {
                    if let Some(rate) = stats.estimate_fee(t) {
                        return Some(rate);
                    }
                }
            }
        }

        best
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the exponential fee-rate bucket boundaries.
fn build_buckets() -> Vec<f64> {
    let mut buckets = Vec::new();
    let mut val = MIN_BUCKET_FEERATE;
    while val <= MAX_BUCKET_FEERATE {
        buckets.push(val);
        val *= FEE_SPACING;
    }
    buckets
}

/// Find the bucket index for a given fee rate.
fn bucket_index(buckets: &[f64], fee_rate: f64) -> usize {
    match buckets.binary_search_by(|b| b.partial_cmp(&fee_rate).unwrap()) {
        Ok(i) => i,
        Err(i) => {
            if i >= buckets.len() {
                buckets.len() - 1
            } else {
                i
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::{Hash256, Txid};

    fn make_txid(n: u8) -> Txid {
        Txid(Hash256([n; 32]))
    }

    #[test]
    fn buckets_are_exponential() {
        let buckets = build_buckets();
        assert!(buckets.len() > 50);
        assert!(buckets[0] >= MIN_BUCKET_FEERATE);
        assert!(*buckets.last().unwrap() <= MAX_BUCKET_FEERATE * FEE_SPACING);
        for w in buckets.windows(2) {
            let ratio = w[1] / w[0];
            assert!((ratio - FEE_SPACING).abs() < 1e-9);
        }
    }

    #[test]
    fn bucket_index_finds_correct_bucket() {
        let buckets = build_buckets();
        assert_eq!(bucket_index(&buckets, 0.5), 0);
        assert_eq!(bucket_index(&buckets, 100_000.0), buckets.len() - 1);
    }

    #[test]
    fn estimate_returns_none_initially() {
        let est = FeeEstimator::new();
        assert!(est.estimate_smart_fee(6).is_none());
    }

    #[test]
    fn estimate_after_confirmed_blocks() {
        let mut est = FeeEstimator::new();

        // Simulate 100 blocks with two classes of txs:
        // - 10 txs at 20 sat/vB per block (all confirmed next block)
        // - 5 txs at 2 sat/vB per block (never confirmed → tracked,
        //   eventually purged as failures when > MAX_CONF_TARGET)
        let mut counter = 0u16;
        let mut next_txid = || {
            let mut hash = [0u8; 32];
            hash[0] = (counter & 0xff) as u8;
            hash[1] = (counter >> 8) as u8;
            counter += 1;
            Txid(Hash256(hash))
        };

        let mut pending_good = Vec::new();
        for height in 1..=100u32 {
            // Confirm the 20 sat/vB txs from previous block.
            est.process_block(height, &pending_good);
            pending_good.clear();

            // Add 20 sat/vB txs that will confirm next block.
            for _ in 0..10 {
                let txid = next_txid();
                est.process_transaction(txid, 20.0);
                pending_good.push(txid);
            }
            // Add 2 sat/vB txs that will NOT confirm (stay in tracked).
            for _ in 0..5 {
                let txid = next_txid();
                est.process_transaction(txid, 2.0);
            }
        }
        // Flush the last batch.
        est.process_block(101, &pending_good);

        // Should produce an estimate for 1-block target.
        let fee = est.estimate_smart_fee(1);
        assert!(fee.is_some(), "expected an estimate");
        let rate = fee.unwrap();
        // The estimate should be a reasonable fee rate, not zero or absurdly high.
        assert!(rate >= 1.0 && rate <= 30.0, "unexpected rate: {rate}");
    }

    #[test]
    fn remove_tx_stops_tracking() {
        let mut est = FeeEstimator::new();
        let txid = make_txid(1);
        est.process_transaction(txid, 10.0);
        assert!(est.tracked.contains_key(&txid));
        est.remove_tx(&txid);
        assert!(!est.tracked.contains_key(&txid));
    }
}
