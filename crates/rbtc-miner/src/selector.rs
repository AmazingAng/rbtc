use std::collections::{BinaryHeap, HashMap, HashSet};

use rbtc_consensus::is_final_tx;
use rbtc_mempool::linearize::{Chunk, Cluster, linearize_cluster};
use rbtc_mempool::Mempool;
use rbtc_primitives::{
    constants::{MAX_BLOCK_WEIGHT, MAX_BLOCK_SIGOPS_COST},
    hash::Txid,
    transaction::Transaction,
};

/// Weight reserved for the block header and coinbase transaction.
///
/// Matches Bitcoin Core's `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000` (policy.h).
/// This covers the block header (320 WU), tx count varint (~4 WU), and a
/// conservative coinbase tx estimate including witness commitment output.
pub const BLOCK_RESERVED_WEIGHT: u64 = 8_000;

/// Default minimum transaction fee rate for block inclusion, in satoshis per
/// 1000 virtual bytes (sat/kvB).
///
/// Matches Bitcoin Core's `DEFAULT_BLOCK_MIN_TX_FEE = 1` (policy.h).
/// `CFeeRate(1)` stores a rate of 1 sat per 1000 vB internally.
///
/// Our score function computes `fees * 1000 / vsize` which is in sat/kvB,
/// so the threshold value is `1`.
pub const DEFAULT_BLOCK_MIN_TX_FEE: u64 = 1;

/// Maximum additional sigops that the pool will add in coinbase transaction
/// outputs.
///
/// Matches Bitcoin Core's `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400`
/// (policy.h).  This reserves sigop budget in the block for the coinbase
/// transaction, which is not known at transaction-selection time.
pub const DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS: u64 = 400;

/// Maximum block weight available for non-coinbase transactions.
pub const MAX_BLOCK_TX_WEIGHT: u64 = MAX_BLOCK_WEIGHT - BLOCK_RESERVED_WEIGHT;

/// Runtime configuration for the block assembler / transaction selector.
///
/// Mirrors Bitcoin Core's `BlockAssembler::Options` struct (miner.h:81-88).
/// All three fields are independently configurable and correspond to Bitcoin
/// Core's `-blockmaxweight`, `-blockmintxfee`, and `-blockreservedweight`
/// command-line arguments.
#[derive(Debug, Clone)]
pub struct BlockAssemblerOptions {
    /// Maximum total block weight (including reserved weight).
    ///
    /// Default: `MAX_BLOCK_WEIGHT` (4,000,000 WU).
    /// Bitcoin Core: `nBlockMaxWeight` from `-blockmaxweight`.
    pub max_block_weight: u64,

    /// Minimum fee rate in sat/kvB for a transaction to be included.
    ///
    /// Default: `DEFAULT_BLOCK_MIN_TX_FEE` (1 sat/kvB).
    /// Bitcoin Core: `blockMinFeeRate` from `-blockmintxfee`.
    /// Transactions whose package feerate (score) is below this value are
    /// skipped.  The score function returns `fee * 1000 / vsize` (sat/kvB).
    pub min_fee_rate_kvb: u64,

    /// Weight reserved for block header and coinbase transaction.
    ///
    /// Default: `BLOCK_RESERVED_WEIGHT` (8,000 WU).
    /// Bitcoin Core: `block_reserved_weight` from `-blockreservedweight`.
    pub reserved_weight: u64,

    /// Maximum additional sigops reserved for the coinbase transaction.
    ///
    /// Default: `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS` (400).
    /// Bitcoin Core: `coinbase_output_max_additional_sigops` in
    /// `BlockCreateOptions` (node/types.h).
    ///
    /// This value is subtracted from `MAX_BLOCK_SIGOPS_COST` to determine the
    /// sigop budget available for non-coinbase transactions.  The coinbase
    /// transaction is not known at selection time, so we must reserve space
    /// for it.
    pub coinbase_max_additional_sigops: u64,
}

impl Default for BlockAssemblerOptions {
    fn default() -> Self {
        Self {
            max_block_weight: MAX_BLOCK_WEIGHT,
            min_fee_rate_kvb: DEFAULT_BLOCK_MIN_TX_FEE,
            reserved_weight: BLOCK_RESERVED_WEIGHT,
            coinbase_max_additional_sigops: DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS,
        }
    }
}

impl BlockAssemblerOptions {
    /// Compute the maximum weight available for non-coinbase transactions.
    ///
    /// This clamps `max_block_weight` to `[reserved_weight, MAX_BLOCK_WEIGHT]`
    /// (matching Bitcoin Core's `std::clamp` in `BlockAssembler` constructor)
    /// then subtracts `reserved_weight`.
    pub fn max_tx_weight(&self) -> u64 {
        let clamped = self.max_block_weight.clamp(self.reserved_weight, MAX_BLOCK_WEIGHT);
        clamped.saturating_sub(self.reserved_weight)
    }

    /// Compute the maximum sigops cost available for non-coinbase transactions.
    ///
    /// Matches Bitcoin Core's initialization:
    /// ```text
    /// nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;
    /// ```
    /// followed by the limit check `nBlockSigOpsCost + chunk_sigops >= MAX_BLOCK_SIGOPS_COST`.
    ///
    /// The reservation is clamped to `[0, MAX_BLOCK_SIGOPS_COST]` (matching
    /// Bitcoin Core's `std::clamp` on the option).
    pub fn max_tx_sigops(&self) -> u64 {
        let clamped = self
            .coinbase_max_additional_sigops
            .min(MAX_BLOCK_SIGOPS_COST);
        MAX_BLOCK_SIGOPS_COST.saturating_sub(clamped)
    }
}

/// Transaction selector for block template assembly.
///
/// Provides two selection strategies:
///
/// ## Ancestor-set selection (`select` / `select_with_fees`)
/// The legacy algorithm (pre-cluster-mempool):
/// 1. Score each transaction by `ancestor_fees / ancestor_vsize`.
/// 2. Pop the highest-scoring package from the heap.
/// 3. Include the transaction (and any unselected ancestors).
/// 4. Update descendant scores by subtracting included ancestor fee/vsize.
///
/// ## Cluster chunk selection (`cluster_select` / `cluster_select_with_fees`)
/// Matches Bitcoin Core's current `BlockAssembler::addChunks()` algorithm:
/// 1. Partition mempool transactions into connected components (clusters).
/// 2. Linearize each cluster into feerate-sorted chunks.
/// 3. Greedily select chunks by descending feerate.
///
/// The cluster approach can produce strictly better results in cases where
/// the ancestor-set heuristic makes suboptimal grouping decisions. Both
/// strategies are topologically valid (parents before children).
///
/// All selection methods accept an optional [`BlockAssemblerOptions`] to
/// control maximum block weight, minimum fee rate, and reserved weight.
/// When `None` is passed, the defaults match Bitcoin Core.
pub struct TxSelector;

/// Mutable per-tx scoring state used during selection.
#[derive(Clone)]
struct PackageState {
    txid: Txid,
    tx: Transaction,
    fee: u64,
    vsize: u64,
    /// Pre-computed sigops cost from mempool entry (full GetTransactionSigOpCost).
    sigops_cost: u64,
    /// Running ancestor fee total (decremented as ancestors are selected).
    ancestor_fees: u64,
    /// Running ancestor vsize total (decremented as ancestors are selected).
    ancestor_vsize: u64,
}

impl PackageState {
    fn score(&self) -> u64 {
        if self.ancestor_vsize == 0 {
            0
        } else {
            self.ancestor_fees * 1000 / self.ancestor_vsize
        }
    }
}

/// Max-heap entry keyed on ancestor package score.
struct HeapEntry {
    score: u64,
    txid: Txid,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool { self.score == other.score }
}
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score.cmp(&other.score)
    }
}

impl TxSelector {
    /// Select transactions for a block template using CPFP-aware ancestor
    /// package scoring.
    ///
    /// Returns `(transactions, total_fees_sat)`.
    ///
    /// The returned list does NOT include the coinbase transaction.
    /// Non-final transactions (per BIP113 locktime rules) are skipped.
    ///
    /// `reserved_weight` overrides the default [`BLOCK_RESERVED_WEIGHT`] (8000 WU)
    /// that is set aside for the block header and coinbase transaction.
    pub fn select(
        mempool: &Mempool,
        block_height: u32,
        median_time_past: u32,
        reserved_weight: Option<u64>,
    ) -> (Vec<Transaction>, u64) {
        let opts = match reserved_weight {
            Some(rw) => BlockAssemblerOptions {
                reserved_weight: rw,
                ..Default::default()
            },
            None => BlockAssemblerOptions::default(),
        };
        let (txs, _, _, total) = Self::select_with_options(mempool, block_height, median_time_past, &opts);
        (txs, total)
    }

    /// Like [`select`] but also returns per-transaction fees and per-transaction
    /// sigop costs (in the same order as the returned transaction list).
    ///
    /// Returns `(transactions, per_tx_fees, per_tx_sigops, total_fees)`.
    ///
    /// `reserved_weight` overrides the default [`BLOCK_RESERVED_WEIGHT`] (8000 WU)
    /// that is set aside for the block header and coinbase transaction.
    pub fn select_with_fees(
        mempool: &Mempool,
        block_height: u32,
        median_time_past: u32,
        reserved_weight: Option<u64>,
    ) -> (Vec<Transaction>, Vec<u64>, Vec<u64>, u64) {
        let opts = match reserved_weight {
            Some(rw) => BlockAssemblerOptions {
                reserved_weight: rw,
                ..Default::default()
            },
            None => BlockAssemblerOptions::default(),
        };
        Self::select_with_options(mempool, block_height, median_time_past, &opts)
    }

    /// Ancestor-set selection with full [`BlockAssemblerOptions`] control.
    ///
    /// This is the main entry point for configurable block assembly.
    /// Transactions whose ancestor-package fee rate (score) falls below
    /// `options.min_fee_rate_kvb` are skipped.
    ///
    /// Returns `(transactions, per_tx_fees, per_tx_sigops, total_fees)`.
    pub fn select_with_options(
        mempool: &Mempool,
        block_height: u32,
        median_time_past: u32,
        options: &BlockAssemblerOptions,
    ) -> (Vec<Transaction>, Vec<u64>, Vec<u64>, u64) {
        let max_tx_weight = options.max_tx_weight();

        let all_entries = mempool.all_entries();
        if all_entries.is_empty() {
            return (Vec::new(), Vec::new(), Vec::new(), 0);
        }

        // Build mutable state and parent/child maps.
        let mut states: HashMap<Txid, PackageState> = HashMap::new();
        let mut children: HashMap<Txid, Vec<Txid>> = HashMap::new();

        for entry in &all_entries {
            states.insert(entry.txid, PackageState {
                txid: entry.txid,
                tx: entry.tx.clone(),
                fee: entry.fee,
                vsize: entry.vsize,
                sigops_cost: entry.sigops_cost,
                ancestor_fees: entry.ancestor_fees,
                ancestor_vsize: entry.ancestor_vsize,
            });
            // Build child relationships from inputs.
            for input in &entry.tx.inputs {
                let parent_txid = input.previous_output.txid;
                if mempool.get(&parent_txid).is_some() {
                    children.entry(parent_txid).or_default().push(entry.txid);
                }
            }
        }

        // Build initial max-heap.
        let mut heap = BinaryHeap::new();
        for state in states.values() {
            heap.push(HeapEntry {
                score: state.score(),
                txid: state.txid,
            });
        }

        let mut selected: Vec<Transaction> = Vec::new();
        let mut per_tx_fees: Vec<u64> = Vec::new();
        let mut per_tx_sigops: Vec<u64> = Vec::new();
        let mut total_weight: u64 = 0;
        let mut total_fees: u64 = 0;
        let mut total_sigops: u64 = 0;
        let mut in_block: HashSet<Txid> = HashSet::new();
        // Reserve sigops for coinbase (configurable, default 400).
        let max_sigops = options.max_tx_sigops();

        while let Some(entry) = heap.pop() {
            if in_block.contains(&entry.txid) {
                continue;
            }

            let state = match states.get(&entry.txid) {
                Some(s) => s.clone(),
                None => continue,
            };

            // Check if the score is stale (state was updated since heap push).
            if state.score() != entry.score {
                // Re-push with updated score.
                heap.push(HeapEntry {
                    score: state.score(),
                    txid: state.txid,
                });
                continue;
            }

            // Skip transactions whose ancestor-package fee rate is below the
            // minimum block inclusion threshold (Bitcoin Core: blockMinFeeRate).
            // Since the heap is sorted by descending score, once we see a score
            // below the minimum everything remaining will also be below it.
            if state.score() < options.min_fee_rate_kvb {
                break;
            }

            let tx_weight = state.tx.weight();
            if total_weight + tx_weight > max_tx_weight {
                continue;
            }

            // Use pre-computed sigops cost from mempool entry (full GetTransactionSigOpCost)
            let tx_sigops = state.sigops_cost;
            if total_sigops + tx_sigops > max_sigops {
                continue;
            }

            // Skip non-final transactions (BIP113 locktime rules)
            if !is_final_tx(&state.tx, block_height, median_time_past) {
                continue;
            }

            // Include this transaction.
            total_weight += tx_weight;
            total_fees += state.fee;
            total_sigops += tx_sigops;
            selected.push(state.tx.clone());
            per_tx_fees.push(state.fee);
            per_tx_sigops.push(tx_sigops);
            in_block.insert(state.txid);

            // Update descendants: subtract this tx's fee/vsize from their
            // ancestor totals.
            if let Some(kids) = children.get(&state.txid) {
                for kid_txid in kids {
                    if in_block.contains(kid_txid) {
                        continue;
                    }
                    if let Some(kid_state) = states.get_mut(kid_txid) {
                        kid_state.ancestor_fees =
                            kid_state.ancestor_fees.saturating_sub(state.fee);
                        kid_state.ancestor_vsize =
                            kid_state.ancestor_vsize.saturating_sub(state.vsize);
                    }
                }
            }
        }

        (selected, per_tx_fees, per_tx_sigops, total_fees)
    }

    /// Estimate the block weight for a given set of transactions
    /// (does not include coinbase weight).
    pub fn total_weight(txs: &[Transaction]) -> u64 {
        txs.iter().map(|tx| tx.weight()).sum()
    }

    // ── Cluster chunk selection (matches Bitcoin Core's addChunks) ────────

    /// Select transactions using cluster-based chunk selection.
    ///
    /// This matches Bitcoin Core's current `BlockAssembler::addChunks()`:
    /// 1. Partition mempool into connected components (clusters).
    /// 2. Linearize each cluster into feerate-ordered chunks.
    /// 3. Greedily pick chunks by descending feerate, skipping chunks that
    ///    don't fit or contain non-final transactions.
    ///
    /// Returns `(transactions, total_fees_sat)`.
    pub fn cluster_select(
        mempool: &Mempool,
        block_height: u32,
        median_time_past: u32,
        reserved_weight: Option<u64>,
    ) -> (Vec<Transaction>, u64) {
        let opts = match reserved_weight {
            Some(rw) => BlockAssemblerOptions {
                reserved_weight: rw,
                ..Default::default()
            },
            None => BlockAssemblerOptions::default(),
        };
        let (txs, _, _, total) = Self::cluster_select_with_options(mempool, block_height, median_time_past, &opts);
        (txs, total)
    }

    /// Like [`cluster_select`] but also returns per-transaction fees and
    /// per-transaction sigop costs.
    ///
    /// Returns `(transactions, per_tx_fees, per_tx_sigops, total_fees)`.
    pub fn cluster_select_with_fees(
        mempool: &Mempool,
        block_height: u32,
        median_time_past: u32,
        reserved_weight: Option<u64>,
    ) -> (Vec<Transaction>, Vec<u64>, Vec<u64>, u64) {
        let opts = match reserved_weight {
            Some(rw) => BlockAssemblerOptions {
                reserved_weight: rw,
                ..Default::default()
            },
            None => BlockAssemblerOptions::default(),
        };
        Self::cluster_select_with_options(mempool, block_height, median_time_past, &opts)
    }

    /// Cluster chunk selection with full [`BlockAssemblerOptions`] control.
    ///
    /// This is the main entry point for configurable cluster-based block
    /// assembly.  Chunks whose feerate falls below `options.min_fee_rate_kvb`
    /// are skipped.
    ///
    /// Returns `(transactions, per_tx_fees, per_tx_sigops, total_fees)`.
    pub fn cluster_select_with_options(
        mempool: &Mempool,
        block_height: u32,
        median_time_past: u32,
        options: &BlockAssemblerOptions,
    ) -> (Vec<Transaction>, Vec<u64>, Vec<u64>, u64) {
        let max_tx_weight = options.max_tx_weight();

        let all_entries = mempool.all_entries();
        if all_entries.is_empty() {
            return (Vec::new(), Vec::new(), Vec::new(), 0);
        }

        // Index entries by txid for quick lookup.
        let entry_map: HashMap<Txid, &_> = all_entries.iter().map(|e| (e.txid, e)).collect();
        let txid_set: HashSet<Txid> = entry_map.keys().copied().collect();

        // ── Step 1: Find connected components (clusters) ─────────────────
        let clusters = find_clusters(&all_entries, &txid_set);

        // ── Step 2: Linearize each cluster into chunks ───────────────────
        let mut all_chunks: Vec<ScoredChunk> = Vec::new();
        for cluster_txids in &clusters {
            let cluster_entries: Vec<&_> = cluster_txids
                .iter()
                .filter_map(|txid| entry_map.get(txid).copied())
                .collect();

            let cluster = Cluster::from_entries(&cluster_entries);
            let chunks = linearize_cluster(&cluster);

            for chunk in chunks {
                let weight: u64 = chunk
                    .txids
                    .iter()
                    .filter_map(|id| entry_map.get(id))
                    .map(|e| e.tx.weight())
                    .sum();
                let sigops: u64 = chunk
                    .txids
                    .iter()
                    .filter_map(|id| entry_map.get(id))
                    .map(|e| e.sigops_cost)
                    .sum();

                all_chunks.push(ScoredChunk {
                    chunk,
                    weight,
                    sigops,
                });
            }
        }

        // ── Step 3: Sort chunks by feerate (descending) ──────────────────
        all_chunks.sort_by(|a, b| {
            let rate_a = a.chunk.feerate();
            let rate_b = b.chunk.feerate();
            rate_b
                .partial_cmp(&rate_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // ── Step 4: Greedily select chunks ───────────────────────────────
        // Reserve sigops for coinbase (configurable, default 400).
        let max_sigops = options.max_tx_sigops();
        let mut selected: Vec<Transaction> = Vec::new();
        let mut per_tx_fees: Vec<u64> = Vec::new();
        let mut per_tx_sigops: Vec<u64> = Vec::new();
        let mut total_weight: u64 = 0;
        let mut total_fees: u64 = 0;
        let mut total_sigops: u64 = 0;

        // Bitcoin Core limits consecutive failures near block-full.
        const MAX_CONSECUTIVE_FAILURES: u32 = 1000;
        const BLOCK_FULL_ENOUGH_DELTA: u64 = 4000;
        let mut consecutive_failures: u32 = 0;

        for scored in &all_chunks {
            // Check minimum fee rate (Bitcoin Core: blockMinFeeRate).
            // Chunks are sorted by descending feerate, so once we see a chunk
            // below the minimum, all remaining chunks will also be below it.
            // Compare as integers: fee * 1000 < min_rate_kvb * vsize
            if scored.chunk.vsize > 0
                && scored.chunk.fee * 1000 < options.min_fee_rate_kvb * scored.chunk.vsize
            {
                break;
            }

            // Check weight
            if total_weight + scored.weight > max_tx_weight {
                consecutive_failures += 1;
                if consecutive_failures > MAX_CONSECUTIVE_FAILURES
                    && total_weight + BLOCK_FULL_ENOUGH_DELTA > max_tx_weight
                {
                    break;
                }
                continue;
            }

            // Check sigops
            if total_sigops + scored.sigops > max_sigops {
                consecutive_failures += 1;
                continue;
            }

            // Check finality of all transactions in the chunk.
            let all_final = scored.chunk.txids.iter().all(|id| {
                entry_map
                    .get(id)
                    .map(|e| is_final_tx(&e.tx, block_height, median_time_past))
                    .unwrap_or(false)
            });
            if !all_final {
                consecutive_failures += 1;
                continue;
            }

            // Include the chunk.  We must emit transactions in topological
            // order (parents before children) within each chunk.
            let ordered = topo_sort_chunk(&scored.chunk, &entry_map);

            for id in &ordered {
                if let Some(entry) = entry_map.get(id) {
                    selected.push(entry.tx.clone());
                    per_tx_fees.push(entry.fee);
                    per_tx_sigops.push(entry.sigops_cost);
                }
            }

            total_weight += scored.weight;
            total_fees += scored.chunk.fee;
            total_sigops += scored.sigops;
            consecutive_failures = 0;
        }

        (selected, per_tx_fees, per_tx_sigops, total_fees)
    }
}


/// A chunk annotated with pre-computed weight and sigops for the greedy loop.
struct ScoredChunk {
    chunk: Chunk,
    weight: u64,
    sigops: u64,
}

/// Partition mempool entries into connected components (clusters).
///
/// Two transactions are in the same cluster if one spends an output of the
/// other (directly or transitively).  Uses union-find on txids.
fn find_clusters(
    entries: &[rbtc_mempool::MempoolEntry],
    txid_set: &HashSet<Txid>,
) -> Vec<HashSet<Txid>> {
    // Simple union-find via HashMap<Txid, Txid> (parent pointers).
    let mut parent: HashMap<Txid, Txid> = HashMap::new();
    for e in entries {
        parent.insert(e.txid, e.txid);
    }

    fn find(parent: &mut HashMap<Txid, Txid>, mut x: Txid) -> Txid {
        while parent[&x] != x {
            let px = parent[&x];
            parent.insert(x, parent[&px]); // path compression
            x = px;
        }
        x
    }

    fn union(parent: &mut HashMap<Txid, Txid>, a: Txid, b: Txid) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent.insert(ra, rb);
        }
    }

    for e in entries {
        for input in &e.tx.inputs {
            let ptxid = input.previous_output.txid;
            if txid_set.contains(&ptxid) && ptxid != e.txid {
                union(&mut parent, e.txid, ptxid);
            }
        }
    }

    // Group by root.
    let mut groups: HashMap<Txid, HashSet<Txid>> = HashMap::new();
    for e in entries {
        let root = find(&mut parent, e.txid);
        groups.entry(root).or_default().insert(e.txid);
    }

    groups.into_values().collect()
}

/// Topologically sort the transactions in a chunk (parents before children).
fn topo_sort_chunk(
    chunk: &Chunk,
    entry_map: &HashMap<Txid, &rbtc_mempool::MempoolEntry>,
) -> Vec<Txid> {
    let chunk_set: HashSet<Txid> = chunk.txids.iter().copied().collect();
    let mut in_degree: HashMap<Txid, usize> = HashMap::new();
    let mut children_map: HashMap<Txid, Vec<Txid>> = HashMap::new();

    for &txid in &chunk.txids {
        in_degree.insert(txid, 0);
    }

    for &txid in &chunk.txids {
        if let Some(entry) = entry_map.get(&txid) {
            for input in &entry.tx.inputs {
                let ptxid = input.previous_output.txid;
                if chunk_set.contains(&ptxid) && ptxid != txid {
                    *in_degree.entry(txid).or_insert(0) += 1;
                    children_map.entry(ptxid).or_default().push(txid);
                }
            }
        }
    }

    let mut queue: Vec<Txid> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();
    let mut result = Vec::with_capacity(chunk.txids.len());

    while let Some(txid) = queue.pop() {
        result.push(txid);
        if let Some(kids) = children_map.get(&txid) {
            for &kid in kids {
                if let Some(deg) = in_degree.get_mut(&kid) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(kid);
                    }
                }
            }
        }
    }

    result
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_mempool::linearize::{Cluster, ClusterTx, linearize_cluster};
    use rbtc_mempool::Mempool;
    use rbtc_primitives::hash::{Hash256, Txid};

    #[test]
    fn select_empty_mempool() {
        let mp = Mempool::new();
        let (txs, fees) = TxSelector::select(&mp, 800_000, 1_700_000_000, None);
        assert!(txs.is_empty());
        assert_eq!(fees, 0);
    }

    #[test]
    fn select_respects_weight_limit() {
        // We can't easily fill a real mempool to the limit in a unit test
        // (accept_tx requires valid UTXOs), so just verify that the total
        // weight of selected transactions stays within bounds.
        let mp = Mempool::new();
        let (txs, _fees) = TxSelector::select(&mp, 800_000, 1_700_000_000, None);
        let w = TxSelector::total_weight(&txs);
        assert!(w <= MAX_BLOCK_TX_WEIGHT);
    }

    #[test]
    fn select_custom_reserved_weight() {
        let mp = Mempool::new();
        // With a very large reserved weight, the available space shrinks.
        let custom_reserved = 10_000u64;
        let (txs, _, _, fees) =
            TxSelector::select_with_fees(&mp, 800_000, 1_700_000_000, Some(custom_reserved));
        assert!(txs.is_empty());
        assert_eq!(fees, 0);

        // Verify the max available weight is correctly reduced.
        let max_tx_weight = MAX_BLOCK_WEIGHT.saturating_sub(custom_reserved);
        assert_eq!(max_tx_weight, MAX_BLOCK_WEIGHT - 10_000);

        // Default reserved weight should match the constant.
        let (txs2, _) = TxSelector::select(&mp, 800_000, 1_700_000_000, None);
        assert!(txs2.is_empty());
    }

    // ── Cluster selection tests ──────────────────────────────────────────

    #[test]
    fn cluster_select_empty_mempool() {
        let mp = Mempool::new();
        let (txs, fees) = TxSelector::cluster_select(&mp, 800_000, 1_700_000_000, None);
        assert!(txs.is_empty());
        assert_eq!(fees, 0);
    }

    #[test]
    fn cluster_select_with_fees_empty() {
        let mp = Mempool::new();
        let (txs, per_fees, per_sigops, total) =
            TxSelector::cluster_select_with_fees(&mp, 800_000, 1_700_000_000, None);
        assert!(txs.is_empty());
        assert!(per_fees.is_empty());
        assert!(per_sigops.is_empty());
        assert_eq!(total, 0);
    }

    // ── find_clusters unit tests ─────────────────────────────────────────

    /// Helper: make a Txid from a byte.
    fn txid(b: u8) -> Txid {
        let mut h = [0u8; 32];
        h[0] = b;
        Txid(Hash256(h))
    }

    /// Helper: make a minimal MempoolEntry (for cluster tests).
    fn make_entry(id: u8, fee: u64, vsize: u64, parent_ids: &[u8]) -> rbtc_mempool::MempoolEntry {
        use rbtc_primitives::transaction::{OutPoint, TxIn, TxOut};
        use std::time::Instant;

        let inputs: Vec<TxIn> = if parent_ids.is_empty() {
            // No in-mempool parents — use a dummy outpoint that won't match
            // any mempool txid.
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256([0xff; 32])),
                    vout: 0,
                },
                script_sig: rbtc_primitives::script::Script::new(),
                sequence: 0xffff_fffe,
                witness: vec![],
            }]
        } else {
            parent_ids
                .iter()
                .map(|&pid| TxIn {
                    previous_output: OutPoint {
                        txid: txid(pid),
                        vout: 0,
                    },
                    script_sig: rbtc_primitives::script::Script::new(),
                    sequence: 0xffff_fffe,
                    witness: vec![],
                })
                .collect()
        };

        let tx = Transaction::from_parts(
            2,
            inputs,
            vec![TxOut {
                value: 0,
                script_pubkey: rbtc_primitives::script::Script::new(),
            }],
            0,
        );

        rbtc_mempool::MempoolEntry {
            tx,
            txid: txid(id),
            wtxid: rbtc_primitives::hash::Wtxid(txid(id).0),
            fee,
            vsize,
            fee_rate: if vsize > 0 { fee / vsize } else { 0 },
            signals_rbf: true,
            spends_coinbase: false,
            ancestor_fee_rate: if vsize > 0 { fee / vsize } else { 0 },
            ancestor_count: 1,
            ancestor_vsize: vsize,
            ancestor_fees: fee,
            descendant_count: 0,
            descendant_vsize: vsize,
            descendant_fees: fee,
            sigops_cost: 0,
            added_at: Instant::now(),
            lock_points: rbtc_mempool::entry::LockPoints::default(),
        }
    }

    #[test]
    fn find_clusters_independent_txs() {
        // Three unrelated transactions should form three singleton clusters.
        let entries = vec![
            make_entry(1, 500, 100, &[]),
            make_entry(2, 600, 100, &[]),
            make_entry(3, 700, 100, &[]),
        ];
        let txid_set: HashSet<Txid> = entries.iter().map(|e| e.txid).collect();
        let clusters = find_clusters(&entries, &txid_set);
        assert_eq!(clusters.len(), 3, "three independent txs = three clusters");
        for c in &clusters {
            assert_eq!(c.len(), 1);
        }
    }

    #[test]
    fn find_clusters_chain() {
        // A -> B -> C should form one cluster.
        let entries = vec![
            make_entry(1, 500, 100, &[]),
            make_entry(2, 600, 100, &[1]),
            make_entry(3, 700, 100, &[2]),
        ];
        let txid_set: HashSet<Txid> = entries.iter().map(|e| e.txid).collect();
        let clusters = find_clusters(&entries, &txid_set);
        assert_eq!(clusters.len(), 1, "chain A->B->C = one cluster");
        assert_eq!(clusters[0].len(), 3);
    }

    #[test]
    fn find_clusters_two_components() {
        // A -> B, C (independent): two clusters.
        let entries = vec![
            make_entry(1, 500, 100, &[]),
            make_entry(2, 600, 100, &[1]),
            make_entry(3, 700, 100, &[]),
        ];
        let txid_set: HashSet<Txid> = entries.iter().map(|e| e.txid).collect();
        let clusters = find_clusters(&entries, &txid_set);
        assert_eq!(clusters.len(), 2, "A->B plus C = two clusters");
    }

    #[test]
    fn topo_sort_preserves_parent_before_child() {
        // A -> B -> C: topo sort must yield A before B, B before C.
        let entries = vec![
            make_entry(1, 500, 100, &[]),
            make_entry(2, 600, 100, &[1]),
            make_entry(3, 700, 100, &[2]),
        ];
        let entry_map: HashMap<Txid, &_> = entries.iter().map(|e| (e.txid, e)).collect();
        let chunk = Chunk {
            txids: vec![txid(1), txid(2), txid(3)],
            fee: 1800,
            vsize: 300,
        };

        let sorted = topo_sort_chunk(&chunk, &entry_map);
        let pos = |id: u8| sorted.iter().position(|t| *t == txid(id)).unwrap();
        assert!(pos(1) < pos(2), "parent A must come before child B");
        assert!(pos(2) < pos(3), "parent B must come before child C");
    }

    // ── Ancestor-set vs cluster comparison ───────────────────────────────

    #[test]
    fn cluster_linearization_diamond_topology() {
        // Diamond: A -> B, A -> C, B -> D, C -> D.
        //
        // Feerates: A=1, B=10, C=2, D=5
        // Ancestor-set might pick B+A first (rate ~5.5), then D+C (rate ~3.5)
        // Cluster linearization considers the whole diamond and can produce
        // different (potentially better) chunking.
        //
        // We just verify the cluster approach produces valid chunks that
        // cover all four transactions.
        let a = ClusterTx {
            txid: txid(1),
            fee: 100,
            vsize: 100,
            parents: HashSet::new(),
        };
        let b = ClusterTx {
            txid: txid(2),
            fee: 1000,
            vsize: 100,
            parents: [txid(1)].into_iter().collect(),
        };
        let c = ClusterTx {
            txid: txid(3),
            fee: 200,
            vsize: 100,
            parents: [txid(1)].into_iter().collect(),
        };
        let d = ClusterTx {
            txid: txid(4),
            fee: 500,
            vsize: 100,
            parents: [txid(2), txid(3)].into_iter().collect(),
        };

        let cluster = Cluster::from_txs(vec![a, b, c, d]);
        let chunks = linearize_cluster(&cluster);

        // All four txids must appear exactly once across chunks.
        let mut all_txids: Vec<Txid> = chunks.iter().flat_map(|c| c.txids.iter().copied()).collect();
        all_txids.sort_by_key(|t| t.0 .0);
        all_txids.dedup();
        assert_eq!(all_txids.len(), 4, "all 4 txids must be covered");

        // Total fee across chunks must equal sum of individual fees.
        let total_fee: u64 = chunks.iter().map(|c| c.fee).sum();
        assert_eq!(total_fee, 1800); // 100 + 1000 + 200 + 500

        // Chunks must be in non-increasing feerate order.
        for w in chunks.windows(2) {
            assert!(
                w[0].feerate() >= w[1].feerate() - 1e-9,
                "chunks must be in descending feerate order: {} vs {}",
                w[0].feerate(),
                w[1].feerate()
            );
        }
    }

    #[test]
    fn cluster_select_custom_reserved_weight() {
        let mp = Mempool::new();
        let custom_reserved = 10_000u64;
        let (txs, _, _, fees) =
            TxSelector::cluster_select_with_fees(&mp, 800_000, 1_700_000_000, Some(custom_reserved));
        assert!(txs.is_empty());
        assert_eq!(fees, 0);
    }

    // ── M20: reserved weight matches Bitcoin Core ─────────────────────

    #[test]
    fn block_reserved_weight_matches_bitcoin_core() {
        // Bitcoin Core DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 (policy.h).
        assert_eq!(
            BLOCK_RESERVED_WEIGHT, 8_000,
            "BLOCK_RESERVED_WEIGHT must match Bitcoin Core's DEFAULT_BLOCK_RESERVED_WEIGHT"
        );
    }

    #[test]
    fn max_block_tx_weight_accounts_for_reserved() {
        assert_eq!(
            MAX_BLOCK_TX_WEIGHT,
            MAX_BLOCK_WEIGHT - 8_000,
            "MAX_BLOCK_TX_WEIGHT must be MAX_BLOCK_WEIGHT minus reserved weight"
        );
    }

    // ── M5: BlockAssemblerOptions struct and integration ──────────────

    #[test]
    fn default_block_min_tx_fee_matches_bitcoin_core() {
        // Bitcoin Core: DEFAULT_BLOCK_MIN_TX_FEE = 1 (policy.h)
        // CFeeRate(1) = 1 sat/kvB.
        assert_eq!(
            DEFAULT_BLOCK_MIN_TX_FEE, 1,
            "DEFAULT_BLOCK_MIN_TX_FEE must be 1 sat/kvB"
        );
    }

    #[test]
    fn block_assembler_options_default_values() {
        let opts = BlockAssemblerOptions::default();
        assert_eq!(opts.max_block_weight, MAX_BLOCK_WEIGHT);
        assert_eq!(opts.min_fee_rate_kvb, DEFAULT_BLOCK_MIN_TX_FEE);
        assert_eq!(opts.reserved_weight, BLOCK_RESERVED_WEIGHT);
    }

    #[test]
    fn block_assembler_options_max_tx_weight() {
        let opts = BlockAssemblerOptions::default();
        assert_eq!(opts.max_tx_weight(), MAX_BLOCK_WEIGHT - BLOCK_RESERVED_WEIGHT);

        // Custom reserved weight
        let opts2 = BlockAssemblerOptions {
            reserved_weight: 10_000,
            ..Default::default()
        };
        assert_eq!(opts2.max_tx_weight(), MAX_BLOCK_WEIGHT - 10_000);

        // Reduced max block weight
        let opts3 = BlockAssemblerOptions {
            max_block_weight: 2_000_000,
            ..Default::default()
        };
        assert_eq!(opts3.max_tx_weight(), 2_000_000 - BLOCK_RESERVED_WEIGHT);
    }

    #[test]
    fn block_assembler_options_clamp_behavior() {
        // max_block_weight below reserved_weight gets clamped up
        let opts = BlockAssemblerOptions {
            max_block_weight: 1_000,
            reserved_weight: 8_000,
            ..Default::default()
        };
        // clamped to reserved_weight, then subtract reserved => 0
        assert_eq!(opts.max_tx_weight(), 0);

        // max_block_weight above consensus MAX_BLOCK_WEIGHT gets clamped down
        let opts2 = BlockAssemblerOptions {
            max_block_weight: 10_000_000,
            ..Default::default()
        };
        assert_eq!(opts2.max_tx_weight(), MAX_BLOCK_WEIGHT - BLOCK_RESERVED_WEIGHT);
    }

    #[test]
    fn select_with_options_empty_mempool() {
        let mp = Mempool::new();
        let opts = BlockAssemblerOptions::default();
        let (txs, per_fees, per_sigops, total) =
            TxSelector::select_with_options(&mp, 800_000, 1_700_000_000, &opts);
        assert!(txs.is_empty());
        assert!(per_fees.is_empty());
        assert!(per_sigops.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn select_with_options_custom_max_weight() {
        let mp = Mempool::new();
        let opts = BlockAssemblerOptions {
            max_block_weight: 100_000, // much smaller block
            ..Default::default()
        };
        let (txs, _, _, _) = TxSelector::select_with_options(&mp, 800_000, 1_700_000_000, &opts);
        let w = TxSelector::total_weight(&txs);
        assert!(w <= opts.max_tx_weight());
    }

    #[test]
    fn cluster_select_with_options_empty_mempool() {
        let mp = Mempool::new();
        let opts = BlockAssemblerOptions::default();
        let (txs, per_fees, per_sigops, total) =
            TxSelector::cluster_select_with_options(&mp, 800_000, 1_700_000_000, &opts);
        assert!(txs.is_empty());
        assert!(per_fees.is_empty());
        assert!(per_sigops.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn cluster_chunk_below_min_fee_rate_rejected() {
        // Build a cluster with a single tx whose feerate is below the minimum.
        // DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB.
        // A tx with fee=0 and vsize=100 has feerate 0 sat/kvB < 1 sat/kvB.
        let low_fee_tx = ClusterTx {
            txid: txid(1),
            fee: 0,   // 0 sat/vB -- below the minimum
            vsize: 100,
            parents: HashSet::new(),
        };
        let cluster = Cluster::from_txs(vec![low_fee_tx]);
        let chunks = linearize_cluster(&cluster);
        assert_eq!(chunks.len(), 1);

        // Verify the chunk fee rate is below the minimum.
        let chunk = &chunks[0];
        assert!(
            chunk.fee * 1000 < DEFAULT_BLOCK_MIN_TX_FEE * chunk.vsize,
            "chunk feerate must be below minimum for this test"
        );
    }

    #[test]
    fn cluster_chunk_at_exact_min_fee_rate_accepted() {
        // A tx with fee=1 and vsize=1000 has feerate 1 sat/kvB.
        // This is exactly at the minimum and should NOT be rejected.
        let exact_tx = ClusterTx {
            txid: txid(1),
            fee: 1,
            vsize: 1000,
            parents: HashSet::new(),
        };
        let cluster = Cluster::from_txs(vec![exact_tx]);
        let chunks = linearize_cluster(&cluster);
        assert_eq!(chunks.len(), 1);

        let chunk = &chunks[0];
        // fee*1000 = 1*1000 = 1000, min*vsize = 1*1000 = 1000
        // 1000 < 1000 is false, so chunk is NOT rejected (accepted).
        assert!(
            !(chunk.fee * 1000 < DEFAULT_BLOCK_MIN_TX_FEE * chunk.vsize),
            "chunk at exactly the minimum fee rate must be accepted"
        );
    }

    #[test]
    fn ancestor_score_below_min_fee_rate_breaks() {
        // PackageState::score() returns ancestor_fees * 1000 / ancestor_vsize
        // which is in sat/kvB. A score below DEFAULT_BLOCK_MIN_TX_FEE (1)
        // means the tx should be skipped.
        let state = PackageState {
            txid: txid(1),
            tx: Transaction::from_parts(
                2,
                vec![rbtc_primitives::transaction::TxIn {
                    previous_output: rbtc_primitives::transaction::OutPoint {
                        txid: Txid(Hash256([0xff; 32])),
                        vout: 0,
                    },
                    script_sig: rbtc_primitives::script::Script::new(),
                    sequence: 0xffff_fffe,
                    witness: vec![],
                }],
                vec![rbtc_primitives::transaction::TxOut {
                    value: 0,
                    script_pubkey: rbtc_primitives::script::Script::new(),
                }],
                0,
            ),
            fee: 0,
            vsize: 100,
            sigops_cost: 0,
            // ancestor feerate = 0 * 1000 / 100 = 0 sat/kvB < 1
            ancestor_fees: 0,
            ancestor_vsize: 100,
        };

        assert_eq!(state.score(), 0);
        assert!(
            state.score() < DEFAULT_BLOCK_MIN_TX_FEE,
            "score 0 sat/kvB must be below minimum 1 sat/kvB"
        );
    }

    #[test]
    fn custom_high_min_fee_rate_via_options() {
        // Verify that a custom high min_fee_rate_kvb in options is respected.
        // Set it to 10000 sat/kvB = 10 sat/vB. A tx with score 5000 (5 sat/vB)
        // should be rejected.
        let opts = BlockAssemblerOptions {
            min_fee_rate_kvb: 10_000,
            ..Default::default()
        };

        // Score of 5000 sat/kvB < 10000 sat/kvB -- should be rejected
        let state = PackageState {
            txid: txid(1),
            tx: Transaction::from_parts(
                2,
                vec![rbtc_primitives::transaction::TxIn {
                    previous_output: rbtc_primitives::transaction::OutPoint {
                        txid: Txid(Hash256([0xff; 32])),
                        vout: 0,
                    },
                    script_sig: rbtc_primitives::script::Script::new(),
                    sequence: 0xffff_fffe,
                    witness: vec![],
                }],
                vec![rbtc_primitives::transaction::TxOut {
                    value: 0,
                    script_pubkey: rbtc_primitives::script::Script::new(),
                }],
                0,
            ),
            fee: 500,
            vsize: 100,
            sigops_cost: 0,
            ancestor_fees: 500,
            ancestor_vsize: 100,
        };

        assert_eq!(state.score(), 5000);
        assert!(
            state.score() < opts.min_fee_rate_kvb,
            "score 5000 sat/kvB must be below custom minimum 10000 sat/kvB"
        );
    }

    // ── M2: Configurable coinbase sigops reservation ──────────────────

    #[test]
    fn default_coinbase_sigops_reservation_matches_bitcoin_core() {
        // Bitcoin Core: DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400
        assert_eq!(
            DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS, 400,
            "default coinbase sigops reservation must be 400"
        );
    }

    #[test]
    fn block_assembler_options_default_coinbase_sigops() {
        let opts = BlockAssemblerOptions::default();
        assert_eq!(
            opts.coinbase_max_additional_sigops,
            DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS
        );
    }

    #[test]
    fn max_tx_sigops_default() {
        let opts = BlockAssemblerOptions::default();
        assert_eq!(
            opts.max_tx_sigops(),
            MAX_BLOCK_SIGOPS_COST - 400,
            "default max_tx_sigops must reserve 400 for coinbase"
        );
    }

    #[test]
    fn max_tx_sigops_custom_reservation() {
        let opts = BlockAssemblerOptions {
            coinbase_max_additional_sigops: 1000,
            ..Default::default()
        };
        assert_eq!(
            opts.max_tx_sigops(),
            MAX_BLOCK_SIGOPS_COST - 1000,
            "custom 1000 sigops reservation"
        );
    }

    #[test]
    fn max_tx_sigops_zero_reservation() {
        // With zero reservation, all sigops budget goes to transactions.
        let opts = BlockAssemblerOptions {
            coinbase_max_additional_sigops: 0,
            ..Default::default()
        };
        assert_eq!(opts.max_tx_sigops(), MAX_BLOCK_SIGOPS_COST);
    }

    #[test]
    fn max_tx_sigops_clamped_to_max() {
        // If reservation exceeds MAX_BLOCK_SIGOPS_COST, clamp it so
        // max_tx_sigops doesn't underflow.
        let opts = BlockAssemblerOptions {
            coinbase_max_additional_sigops: MAX_BLOCK_SIGOPS_COST + 1000,
            ..Default::default()
        };
        assert_eq!(
            opts.max_tx_sigops(),
            0,
            "reservation exceeding limit must clamp to zero available sigops"
        );
    }
}
