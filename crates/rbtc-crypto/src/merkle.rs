use rbtc_primitives::hash::Hash256;

use crate::digest::sha256d;

/// Compute the Merkle root of a list of txids.
/// Returns None if the list is empty.
/// Uses Bitcoin's standard double-SHA256 Merkle tree algorithm.
pub fn merkle_root(txids: &[Hash256]) -> Option<Hash256> {
    if txids.is_empty() {
        return None;
    }

    let mut current_level: Vec<Hash256> = txids.to_vec();

    while current_level.len() > 1 {
        // If odd number of elements, duplicate the last one
        if current_level.len() % 2 != 0 {
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

    Some(current_level[0])
}

/// Compute Merkle branch (proof) for a given leaf index
pub fn merkle_branch(txids: &[Hash256], index: usize) -> Vec<Hash256> {
    let mut branch = Vec::new();
    let mut current_level: Vec<Hash256> = txids.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        if current_level.len() % 2 != 0 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
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
        let root = merkle_root(&[txid]).unwrap();
        assert_eq!(root, txid);
    }

    #[test]
    fn test_two_tx_merkle_root() {
        let t1 = Hash256([1u8; 32]);
        let t2 = Hash256([2u8; 32]);
        let root = merkle_root(&[t1, t2]).unwrap();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&t1.0);
        combined[32..].copy_from_slice(&t2.0);
        let expected = sha256d(&combined);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_empty_returns_none() {
        assert!(merkle_root(&[]).is_none());
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
}
