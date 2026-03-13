use rbtc_primitives::hash::Hash256;

use crate::digest::sha256d;

/// Compute the witness Merkle root from a list of wtxids.
///
/// This matches Bitcoin Core's `BlockWitnessMerkleRoot()`.  The coinbase
/// wtxid is always replaced with 0x00..00 (the caller must pass the
/// already-substituted list, or use `witness_merkle_root_with_coinbase`
/// which does the substitution internally).
///
/// Returns `(None, false)` when the list is empty.
/// The `bool` is the CVE-2012-2459 mutation flag, identical to
/// `merkle_root`.
pub fn witness_merkle_root(wtxids: &[Hash256]) -> (Option<Hash256>, bool) {
    if wtxids.is_empty() {
        return (None, false);
    }
    // The witness merkle tree uses the same double-SHA256 construction as
    // the regular merkle tree; only the leaf values differ (wtxid instead
    // of txid, with 0x00..00 for the coinbase).
    merkle_root(wtxids)
}

/// Convenience: compute the witness Merkle root, automatically replacing
/// the first entry (coinbase) with `Hash256::default()` (all zeros).
///
/// `wtxids` should contain the wtxid of *every* transaction including the
/// coinbase; this function clones the slice so the caller's data is not
/// modified.
pub fn witness_merkle_root_with_coinbase(wtxids: &[Hash256]) -> (Option<Hash256>, bool) {
    if wtxids.is_empty() {
        return (None, false);
    }
    let mut leaves = wtxids.to_vec();
    leaves[0] = Hash256::default();
    merkle_root(&leaves)
}

/// Compute the Merkle root of a list of txids.
/// Returns `(None, false)` if the list is empty.
/// Uses Bitcoin's standard double-SHA256 Merkle tree algorithm.
///
/// The returned `bool` is `true` when a mutation was detected: two adjacent
/// hashes at the same tree level were identical *before* the odd-element
/// duplication step.  This matches Bitcoin Core's CVE-2012-2459 protection
/// (`ComputeMerkleRoot` with a `mutated` out-parameter).
pub fn merkle_root(txids: &[Hash256]) -> (Option<Hash256>, bool) {
    if txids.is_empty() {
        return (None, false);
    }

    let mut current_level: Vec<Hash256> = txids.to_vec();
    let mut mutation = false;

    while current_level.len() > 1 {
        // Check for duplicate adjacent pairs BEFORE padding.
        // This detects CVE-2012-2459 style mutations.
        let pair_end = current_level.len() & !1; // round down to even
        for pos in (0..pair_end).step_by(2) {
            if current_level[pos] == current_level[pos + 1] {
                mutation = true;
            }
        }

        // If odd number of elements, duplicate the last one
        if !current_level.len().is_multiple_of(2) {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0].0);
            combined[32..].copy_from_slice(&pair[1].0);
            next_level.push(sha256d(&combined));
        }
        current_level = next_level;
    }

    (Some(current_level[0]), mutation)
}

/// Compute Merkle branch (proof) for a given leaf index
pub fn merkle_branch(txids: &[Hash256], index: usize) -> Vec<Hash256> {
    let mut branch = Vec::new();
    let mut current_level: Vec<Hash256> = txids.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        if !current_level.len().is_multiple_of(2) {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        let sibling = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        branch.push(current_level[sibling]);

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0].0);
            combined[32..].copy_from_slice(&pair[1].0);
            next_level.push(sha256d(&combined));
        }
        current_level = next_level;
        idx /= 2;
    }

    branch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_tx_merkle_root() {
        let txid = Hash256([1u8; 32]);
        let (root, mutated) = merkle_root(&[txid]);
        assert_eq!(root.unwrap(), txid);
        assert!(!mutated);
    }

    #[test]
    fn test_two_tx_merkle_root() {
        let t1 = Hash256([1u8; 32]);
        let t2 = Hash256([2u8; 32]);
        let (root, mutated) = merkle_root(&[t1, t2]);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&t1.0);
        combined[32..].copy_from_slice(&t2.0);
        let expected = sha256d(&combined);
        assert_eq!(root.unwrap(), expected);
        assert!(!mutated);
    }

    #[test]
    fn test_empty_returns_none() {
        let (root, mutated) = merkle_root(&[]);
        assert!(root.is_none());
        assert!(!mutated);
    }

    #[test]
    fn test_duplicate_adjacent_pair_is_mutated() {
        let t1 = Hash256([1u8; 32]);
        let t2 = Hash256([1u8; 32]); // same as t1
        let (_root, mutated) = merkle_root(&[t1, t2]);
        assert!(mutated);
    }

    #[test]
    fn test_odd_duplication_is_not_mutation() {
        // Three distinct elements: the last one gets duplicated for padding,
        // but that is NOT a mutation.
        let t1 = Hash256([1u8; 32]);
        let t2 = Hash256([2u8; 32]);
        let t3 = Hash256([3u8; 32]);
        let (_root, mutated) = merkle_root(&[t1, t2, t3]);
        assert!(!mutated);
    }

    #[test]
    fn test_merkle_branch_single() {
        let txid = Hash256([1u8; 32]);
        let branch = merkle_branch(&[txid], 0);
        assert!(branch.is_empty());
    }

    #[test]
    fn test_merkle_branch_two() {
        let t1 = Hash256([1u8; 32]);
        let t2 = Hash256([2u8; 32]);
        let branch0 = merkle_branch(&[t1, t2], 0);
        let branch1 = merkle_branch(&[t1, t2], 1);
        assert_eq!(branch0.len(), 1);
        assert_eq!(branch1.len(), 1);
        assert_eq!(branch0[0], t2);
        assert_eq!(branch1[0], t1);
    }

    #[test]
    fn test_merkle_branch_three_odd() {
        let t1 = Hash256([1u8; 32]);
        let t2 = Hash256([2u8; 32]);
        let t3 = Hash256([3u8; 32]);
        let branch = merkle_branch(&[t1, t2, t3], 1);
        assert!(!branch.is_empty());
    }

    // ---- witness merkle root tests ----

    #[test]
    fn test_witness_merkle_root_empty() {
        let (root, mutated) = witness_merkle_root(&[]);
        assert!(root.is_none());
        assert!(!mutated);
    }

    #[test]
    fn test_witness_merkle_root_single_coinbase() {
        // With a single tx (coinbase only), the witness merkle root
        // should be Hash256::default() (all zeros) when using
        // witness_merkle_root_with_coinbase.
        let coinbase_wtxid = Hash256([0xab; 32]);
        let (root, mutated) = witness_merkle_root_with_coinbase(&[coinbase_wtxid]);
        assert_eq!(root.unwrap(), Hash256::default());
        assert!(!mutated);
    }

    #[test]
    fn test_witness_merkle_root_two_txs() {
        // coinbase wtxid gets replaced with zeros, second tx keeps its wtxid
        let coinbase_wtxid = Hash256([0xff; 32]);
        let tx1_wtxid = Hash256([0x42; 32]);

        let (root, mutated) = witness_merkle_root_with_coinbase(&[coinbase_wtxid, tx1_wtxid]);
        assert!(!mutated);

        // Manually compute expected: merkle_root([0x00..00, 0x42..42])
        let zero = Hash256::default();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&zero.0);
        combined[32..].copy_from_slice(&tx1_wtxid.0);
        let expected = sha256d(&combined);
        assert_eq!(root.unwrap(), expected);
    }

    #[test]
    fn test_witness_merkle_root_matches_regular_on_same_input() {
        // witness_merkle_root delegates to merkle_root, so passing
        // the same data should produce the same result.
        let hashes: Vec<Hash256> = (0..5u8).map(|i| Hash256([i; 32])).collect();
        let (wr, wm) = witness_merkle_root(&hashes);
        let (mr, mm) = merkle_root(&hashes);
        assert_eq!(wr, mr);
        assert_eq!(wm, mm);
    }

    #[test]
    fn test_witness_merkle_root_with_coinbase_replaces_first() {
        let t1 = Hash256([0xaa; 32]);
        let t2 = Hash256([0xbb; 32]);
        let t3 = Hash256([0xcc; 32]);

        let (root_with, _) = witness_merkle_root_with_coinbase(&[t1, t2, t3]);

        // Manually construct expected leaves
        let leaves = vec![Hash256::default(), t2, t3];
        let (root_manual, _) = merkle_root(&leaves);

        assert_eq!(root_with, root_manual);
    }
}
