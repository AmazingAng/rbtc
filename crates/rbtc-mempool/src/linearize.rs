//! Cluster mempool linearization and feerate diagram comparison.
//!
//! Implements ancestor-set-based linearization (the approach Bitcoin Core used
//! before full cluster linearization) and piecewise-linear feerate diagram
//! comparison matching the spirit of `CompareChunks` in Bitcoin Core's
//! `util/feefrac.cpp`.

use std::collections::{HashMap, HashSet};

use rbtc_primitives::hash::Txid;

use crate::entry::MempoolEntry;

// ── Chunk ────────────────────────────────────────────────────────────────────

/// A chunk in a linearized cluster: one or more transactions grouped together
/// (e.g. a high-feerate child merged with its lower-feerate parent via CPFP).
#[derive(Debug, Clone)]
pub struct Chunk {
    pub txids: Vec<Txid>,
    pub fee: u64,
    pub vsize: u64,
}

impl Chunk {
    /// Fee rate in satoshis per virtual byte (as f64 for diagram comparison).
    pub fn feerate(&self) -> f64 {
        if self.vsize == 0 {
            return 0.0;
        }
        self.fee as f64 / self.vsize as f64
    }
}

// ── Cluster ──────────────────────────────────────────────────────────────────

/// A set of related mempool transactions connected by parent-child spending
/// relationships (the connected component in the dependency graph).
#[derive(Debug, Clone)]
pub struct Cluster {
    /// The transactions in this cluster, keyed by txid.
    pub txs: HashMap<Txid, ClusterTx>,
}

/// A single transaction within a cluster, with its fee/vsize and parent set.
#[derive(Debug, Clone)]
pub struct ClusterTx {
    pub txid: Txid,
    pub fee: u64,
    pub vsize: u64,
    /// Direct in-cluster parents (transactions whose outputs this tx spends).
    pub parents: HashSet<Txid>,
}

impl Cluster {
    /// Build a cluster from a slice of mempool entries.  Parent relationships
    /// are inferred: if entry A spends an outpoint whose txid matches entry B
    /// (and B is in the set), then B is a parent of A.
    pub fn from_entries(entries: &[&MempoolEntry]) -> Self {
        let txid_set: HashSet<Txid> = entries.iter().map(|e| e.txid).collect();
        let mut txs = HashMap::with_capacity(entries.len());

        for entry in entries {
            let parents: HashSet<Txid> = entry
                .tx
                .inputs
                .iter()
                .map(|inp| inp.previous_output.txid)
                .filter(|ptxid| txid_set.contains(ptxid) && *ptxid != entry.txid)
                .collect();

            txs.insert(
                entry.txid,
                ClusterTx {
                    txid: entry.txid,
                    fee: entry.fee,
                    vsize: entry.vsize,
                    parents,
                },
            );
        }

        Self { txs }
    }

    /// Create a cluster from explicit `ClusterTx` entries (useful for tests).
    pub fn from_txs(cluster_txs: Vec<ClusterTx>) -> Self {
        let txs = cluster_txs.into_iter().map(|ct| (ct.txid, ct)).collect();
        Self { txs }
    }
}

// ── Ancestor-set based linearization ─────────────────────────────────────────

/// Compute the ancestor set of `txid` (including itself) within `remaining`.
fn ancestor_set(txid: Txid, txs: &HashMap<Txid, ClusterTx>, remaining: &HashSet<Txid>) -> HashSet<Txid> {
    let mut ancestors = HashSet::new();
    let mut stack = vec![txid];
    while let Some(cur) = stack.pop() {
        if !remaining.contains(&cur) || !ancestors.insert(cur) {
            continue;
        }
        if let Some(ct) = txs.get(&cur) {
            for &p in &ct.parents {
                if remaining.contains(&p) {
                    stack.push(p);
                }
            }
        }
    }
    ancestors
}

/// Ancestor-set feerate: total fee / total vsize of the ancestor set.
fn ancestor_set_feerate(
    anc: &HashSet<Txid>,
    txs: &HashMap<Txid, ClusterTx>,
) -> (u64, u64, f64) {
    let mut total_fee = 0u64;
    let mut total_vsize = 0u64;
    for id in anc {
        if let Some(ct) = txs.get(id) {
            total_fee += ct.fee;
            total_vsize += ct.vsize;
        }
    }
    let rate = if total_vsize > 0 {
        total_fee as f64 / total_vsize as f64
    } else {
        0.0
    };
    (total_fee, total_vsize, rate)
}

/// Produce a linearization of the cluster as a sequence of [`Chunk`]s.
///
/// Uses the *ancestor-set-based* algorithm: repeatedly pick the transaction
/// whose ancestor set has the highest feerate, emit that ancestor set as a
/// chunk, and remove it from the remaining set.  This naturally handles CPFP
/// (a high-fee child pulls in its low-fee parent).
pub fn linearize_cluster(cluster: &Cluster) -> Vec<Chunk> {
    if cluster.txs.is_empty() {
        return Vec::new();
    }

    let mut remaining: HashSet<Txid> = cluster.txs.keys().copied().collect();
    let mut chunks = Vec::new();

    while !remaining.is_empty() {
        // Find the transaction whose ancestor-set feerate is highest.
        let mut best_txid = None;
        let mut best_anc = HashSet::new();
        let mut best_rate = f64::NEG_INFINITY;
        let mut best_fee = 0u64;
        let mut best_vsize = 0u64;

        for &txid in &remaining {
            let anc = ancestor_set(txid, &cluster.txs, &remaining);
            let (fee, vsize, rate) = ancestor_set_feerate(&anc, &cluster.txs);
            if rate > best_rate || (rate == best_rate && vsize < best_vsize) {
                best_rate = rate;
                best_fee = fee;
                best_vsize = vsize;
                best_anc = anc;
                best_txid = Some(txid);
            }
        }

        let _best = best_txid.expect("remaining is non-empty");

        // Remove the ancestor set from remaining and emit a chunk.
        for id in &best_anc {
            remaining.remove(id);
        }

        chunks.push(Chunk {
            txids: best_anc.into_iter().collect(),
            fee: best_fee,
            vsize: best_vsize,
        });
    }

    chunks
}

// ── Feerate diagram ──────────────────────────────────────────────────────────

/// Build a feerate diagram from a list of chunks.
///
/// Returns cumulative `(vsize, fee)` points starting at `(0, 0)`.  Each
/// subsequent point adds the chunk's vsize and fee to the running totals.
/// The chunks are assumed to already be in linearization order (decreasing
/// feerate).
pub fn build_feerate_diagram(chunks: &[Chunk]) -> Vec<(u64, u64)> {
    let mut diagram = Vec::with_capacity(chunks.len() + 1);
    diagram.push((0u64, 0u64));

    let mut cum_vsize = 0u64;
    let mut cum_fee = 0u64;
    for chunk in chunks {
        cum_vsize += chunk.vsize;
        cum_fee += chunk.fee;
        diagram.push((cum_vsize, cum_fee));
    }

    diagram
}

/// Interpolate the fee at a given vsize on a piecewise-linear diagram.
///
/// The diagram is a sequence of `(cumulative_vsize, cumulative_fee)` points
/// starting at `(0, 0)`.  Between any two adjacent points the fee increases
/// linearly.  Beyond the last point the diagram is flat (fee stays constant).
fn interpolate(diagram: &[(u64, u64)], at_vsize: u64) -> f64 {
    if diagram.is_empty() {
        return 0.0;
    }
    // Beyond the last point: constant fee.
    if at_vsize >= diagram.last().unwrap().0 {
        return diagram.last().unwrap().1 as f64;
    }
    // Find the segment containing at_vsize.
    for w in diagram.windows(2) {
        let (s0, f0) = w[0];
        let (s1, f1) = w[1];
        if at_vsize >= s0 && at_vsize <= s1 {
            if s1 == s0 {
                return f1 as f64;
            }
            let frac = (at_vsize - s0) as f64 / (s1 - s0) as f64;
            return f0 as f64 + frac * (f1 as f64 - f0 as f64);
        }
    }
    diagram.last().unwrap().1 as f64
}

/// Compare two feerate diagrams.  Returns `true` if `new_diagram` is
/// **strictly better** than `old_diagram` — meaning the new diagram's
/// cumulative fee is >= the old diagram's fee at every point, and strictly
/// greater at at least one point.
///
/// This matches the semantics of Bitcoin Core's `CompareChunks` returning
/// `std::partial_ordering::greater` (new > old).
///
/// Both diagrams are piecewise-linear curves from `(0,0)`.  We evaluate
/// at every "corner" (point) of both diagrams and verify the invariant.
pub fn compare_diagrams(old: &[(u64, u64)], new: &[(u64, u64)]) -> bool {
    // Collect all distinct vsize values from both diagrams as evaluation points.
    let mut eval_points: Vec<u64> = Vec::new();
    for &(s, _) in old.iter().chain(new.iter()) {
        eval_points.push(s);
    }
    eval_points.sort_unstable();
    eval_points.dedup();

    // Also check a point slightly beyond the larger diagram to compare tails.
    let max_vsize = eval_points.last().copied().unwrap_or(0);
    if max_vsize > 0 {
        eval_points.push(max_vsize + 1);
    }

    let mut strictly_better = false;

    for &vs in &eval_points {
        let old_fee = interpolate(old, vs);
        let new_fee = interpolate(new, vs);

        if new_fee < old_fee - 1e-9 {
            // Regression at this point — replacement is not strictly better.
            return false;
        }
        if new_fee > old_fee + 1e-9 {
            strictly_better = true;
        }
    }

    strictly_better
}

// ── Public helper for RBF ────────────────────────────────────────────────────

/// Check whether replacing `old_entries` with a single new transaction
/// (described by `new_fee` and `new_vsize`) improves the feerate diagram.
///
/// Returns `Ok(())` if the replacement is an improvement, or `Err(msg)` if
/// the diagram regresses at any point.
pub fn check_rbf_diagram(
    old_entries: &[&MempoolEntry],
    new_fee: u64,
    new_vsize: u64,
) -> Result<(), String> {
    // Build chunks for the old cluster.
    let old_cluster = Cluster::from_entries(old_entries);
    let old_chunks = linearize_cluster(&old_cluster);
    let old_diagram = build_feerate_diagram(&old_chunks);

    // The new "cluster" is just the single replacement transaction.
    let new_diagram = vec![(0u64, 0u64), (new_vsize, new_fee)];

    if compare_diagrams(&old_diagram, &new_diagram) {
        Ok(())
    } else {
        Err("replacement does not improve feerate diagram".to_string())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::{Hash256, Txid};

    /// Helper: create a Txid from a single byte.
    fn txid(b: u8) -> Txid {
        let mut h = [0u8; 32];
        h[0] = b;
        Txid(Hash256(h))
    }

    /// Helper: build a simple ClusterTx.
    fn cluster_tx(id: u8, fee: u64, vsize: u64, parents: &[u8]) -> ClusterTx {
        ClusterTx {
            txid: txid(id),
            fee,
            vsize,
            parents: parents.iter().map(|&p| txid(p)).collect(),
        }
    }

    #[test]
    fn single_tx_cluster_one_chunk() {
        let cluster = Cluster::from_txs(vec![cluster_tx(1, 1000, 100, &[])]);
        let chunks = linearize_cluster(&cluster);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].fee, 1000);
        assert_eq!(chunks[0].vsize, 100);
        assert!(chunks[0].txids.contains(&txid(1)));
    }

    #[test]
    fn parent_child_cpfp_merge() {
        // Parent: low fee.  Child: high fee.
        // The child's ancestor set includes the parent, so they should merge
        // into a single chunk if the child's ancestor-set feerate is the best.
        let parent = cluster_tx(1, 100, 100, &[]); // 1 sat/vB
        let child = cluster_tx(2, 5000, 100, &[1]); // 50 sat/vB individually
        // Ancestor set of child = {parent, child}: fee=5100, vsize=200 => 25.5 sat/vB
        // Ancestor set of parent = {parent}: fee=100, vsize=100 => 1 sat/vB
        // Best is child's ancestor set (25.5 > 1), so they merge into one chunk.
        let cluster = Cluster::from_txs(vec![parent, child]);
        let chunks = linearize_cluster(&cluster);
        assert_eq!(chunks.len(), 1, "CPFP should merge parent+child into one chunk");
        assert_eq!(chunks[0].fee, 5100);
        assert_eq!(chunks[0].vsize, 200);
    }

    #[test]
    fn diagram_strictly_better_passes() {
        let old = vec![(0, 0), (100, 500)];
        let new = vec![(0, 0), (100, 600)];
        assert!(compare_diagrams(&old, &new));
    }

    #[test]
    fn diagram_regression_fails() {
        // New diagram is worse: lower fee at the same vsize.
        let old = vec![(0, 0), (100, 500)];
        let new = vec![(0, 0), (100, 400)];
        assert!(!compare_diagrams(&old, &new));
    }

    #[test]
    fn diagram_equal_not_strictly_better() {
        let old = vec![(0, 0), (100, 500)];
        let new = vec![(0, 0), (100, 500)];
        assert!(!compare_diagrams(&old, &new), "equal diagrams should not pass strict check");
    }

    #[test]
    fn empty_cluster_no_chunks() {
        let cluster = Cluster::from_txs(vec![]);
        let chunks = linearize_cluster(&cluster);
        assert!(chunks.is_empty());
    }

    #[test]
    fn three_tx_chain_linearization_order() {
        // A -> B -> C, where A is root.
        // All same individual feerate, so ancestor-set feerate of A (root) is highest
        // because it has no baggage.  Then B's remaining ancestor set is just B, etc.
        let a = cluster_tx(1, 300, 100, &[]); // 3 sat/vB
        let b = cluster_tx(2, 300, 100, &[1]); // 3 sat/vB
        let c = cluster_tx(3, 300, 100, &[2]); // 3 sat/vB

        let cluster = Cluster::from_txs(vec![a, b, c]);
        let chunks = linearize_cluster(&cluster);

        // With equal feerates, ancestor sets are:
        //   A: {A} => 3 sat/vB
        //   B: {A,B} => 3 sat/vB
        //   C: {A,B,C} => 3 sat/vB
        // All have the same rate; tiebreak favors smaller vsize, so A is selected
        // first, then B, then C.
        assert_eq!(chunks.len(), 3);
        // Each chunk should have exactly one tx.
        for chunk in &chunks {
            assert_eq!(chunk.txids.len(), 1);
            assert_eq!(chunk.fee, 300);
            assert_eq!(chunk.vsize, 100);
        }
    }

    #[test]
    fn rbf_with_improved_diagram_accepted() {
        // Old: single tx, 500 fee, 100 vsize (5 sat/vB).
        // New: single tx, 800 fee, 100 vsize (8 sat/vB).
        let old_entry = make_entry(txid(1), 500, 100);
        let old_refs: Vec<&MempoolEntry> = vec![&old_entry];
        assert!(check_rbf_diagram(&old_refs, 800, 100).is_ok());
    }

    #[test]
    fn rbf_with_regressed_diagram_rejected() {
        // Old: single tx, 500 fee, 100 vsize (5 sat/vB).
        // New: single tx, 300 fee, 100 vsize (3 sat/vB).
        let old_entry = make_entry(txid(1), 500, 100);
        let old_refs: Vec<&MempoolEntry> = vec![&old_entry];
        assert!(check_rbf_diagram(&old_refs, 300, 100).is_err());
    }

    #[test]
    fn chunk_feerate_calculation() {
        let chunk = Chunk {
            txids: vec![txid(1), txid(2)],
            fee: 1000,
            vsize: 250,
        };
        let rate = chunk.feerate();
        assert!((rate - 4.0).abs() < 1e-9, "1000/250 = 4.0 sat/vB");
    }

    #[test]
    fn chunk_feerate_zero_vsize() {
        let chunk = Chunk {
            txids: vec![],
            fee: 0,
            vsize: 0,
        };
        assert_eq!(chunk.feerate(), 0.0);
    }

    #[test]
    fn build_diagram_cumulative_points() {
        let chunks = vec![
            Chunk { txids: vec![txid(1)], fee: 500, vsize: 100 },
            Chunk { txids: vec![txid(2)], fee: 300, vsize: 200 },
        ];
        let diagram = build_feerate_diagram(&chunks);
        assert_eq!(diagram.len(), 3);
        assert_eq!(diagram[0], (0, 0));
        assert_eq!(diagram[1], (100, 500));
        assert_eq!(diagram[2], (300, 800));
    }

    #[test]
    fn diagram_regression_at_midpoint() {
        // Old has two chunks: high-fee small, then low-fee large.
        // New has one chunk that is better overall but worse at a midpoint.
        let old = vec![(0, 0), (50, 500), (200, 600)];
        // At vsize=50, old fee=500.  New at vsize=50: interpolate 50/200*550=137.5.
        let new = vec![(0, 0), (200, 550)];
        assert!(!compare_diagrams(&old, &new), "regression at vsize=50");
    }

    /// Helper: create a minimal MempoolEntry for testing.
    fn make_entry(id: Txid, fee: u64, vsize: u64) -> MempoolEntry {
        use rbtc_primitives::transaction::Transaction;
        use std::time::Instant;

        let tx = Transaction::from_parts(2, vec![], vec![], 0);
        MempoolEntry {
            tx,
            txid: id,
            wtxid: rbtc_primitives::hash::Wtxid(id.0),
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
            lock_points: crate::entry::LockPoints::default(),
        }
    }
}
