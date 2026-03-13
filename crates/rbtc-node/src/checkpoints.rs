//! Hardcoded blockchain checkpoints for fast header validation.
//!
//! When a header arrives at a checkpoint height, the node verifies that its
//! hash matches the expected value.  This prevents an attacker from feeding a
//! longer (but invalid) alternate chain during initial block download.

use std::collections::BTreeMap;

use rbtc_primitives::hash::BlockHash;

/// A set of (height, expected-hash) checkpoints.
pub struct Checkpoints {
    points: BTreeMap<u32, BlockHash>,
}

impl Checkpoints {
    /// Mainnet checkpoints taken from Bitcoin Core `src/kernel/chainparams.cpp`.
    pub fn mainnet() -> Self {
        let raw: &[(u32, &str)] = &[
            (11111,  "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
            (33333,  "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
            (74000,  "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
            (105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
            (134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
            (168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
            (193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
            (210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
            (216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
            (225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
            (250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
            (279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
            (295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632473f"),
        ];

        let mut points = BTreeMap::new();
        for &(height, hex) in raw {
            let hash = BlockHash::from_hex(hex).expect("hardcoded checkpoint hash must be valid");
            points.insert(height, hash);
        }
        Self { points }
    }

    /// Empty checkpoint set (for testnet / regtest / signet where we don't
    /// enforce hardcoded checkpoints).
    pub fn none() -> Self {
        Self {
            points: BTreeMap::new(),
        }
    }

    /// Look up the expected hash at a given height (if any).
    pub fn get(&self, height: u32) -> Option<&BlockHash> {
        self.points.get(&height)
    }

    /// Returns `true` if there is no checkpoint at `height`, or if the
    /// checkpoint hash matches `hash`.
    pub fn verify(&self, height: u32, hash: &BlockHash) -> bool {
        match self.points.get(&height) {
            Some(expected) => expected == hash,
            None => true,
        }
    }

    /// Height of the highest checkpoint, or 0 if there are none.
    pub fn last_checkpoint_height(&self) -> u32 {
        self.points.keys().next_back().copied().unwrap_or(0)
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_checkpoints_loaded() {
        let cp = Checkpoints::mainnet();
        assert_eq!(cp.points.len(), 13);
        assert_eq!(cp.last_checkpoint_height(), 295000);
    }

    #[test]
    fn verify_known_checkpoint() {
        let cp = Checkpoints::mainnet();
        let hash = BlockHash::from_hex(
            "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
        )
        .unwrap();
        assert!(cp.verify(11111, &hash));
    }

    #[test]
    fn verify_wrong_hash_fails() {
        let cp = Checkpoints::mainnet();
        let bad = BlockHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert!(!cp.verify(11111, &bad));
    }

    #[test]
    fn verify_non_checkpoint_height_passes() {
        let cp = Checkpoints::mainnet();
        let any = BlockHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert!(cp.verify(12345, &any));
    }

    #[test]
    fn empty_checkpoints() {
        let cp = Checkpoints::none();
        assert!(cp.is_empty());
        assert_eq!(cp.last_checkpoint_height(), 0);
        assert!(cp.verify(11111, &BlockHash::ZERO));
    }

    #[test]
    fn get_returns_correct_hash() {
        let cp = Checkpoints::mainnet();
        let expected = BlockHash::from_hex(
            "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
        )
        .unwrap();
        assert_eq!(cp.get(250000), Some(&expected));
        assert_eq!(cp.get(999999), None);
    }
}
