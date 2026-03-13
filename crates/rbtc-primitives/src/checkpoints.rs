//! Hardcoded checkpoint block hashes for IBD (Initial Block Download) validation.
//!
//! During IBD, blocks at checkpoint heights are validated against these known
//! hashes to prevent long-range attacks. This is a defense-in-depth measure
//! matching Bitcoin Core's `chainparams.cpp` checkpoints.

use crate::hash::BlockHash;
use crate::network::Network;

/// Static checkpoint entry: (block height, block hash hex in big-endian display order).
type Checkpoint = (u32, &'static str);

/// Bitcoin mainnet checkpoints (from Bitcoin Core `chainparams.cpp`).
const MAINNET_CHECKPOINTS: &[Checkpoint] = &[
    (11111, "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
    (33333, "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
    (74000, "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
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

/// Testnet3 checkpoints (historical, from Bitcoin Core `chainparams.cpp`).
const TESTNET3_CHECKPOINTS: &[Checkpoint] = &[
    (546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"),
];

/// Testnet4 has no historical checkpoints yet (new network).
const TESTNET4_CHECKPOINTS: &[Checkpoint] = &[];

/// Regtest has no checkpoints.
const REGTEST_CHECKPOINTS: &[Checkpoint] = &[];

/// Signet has no checkpoints.
const SIGNET_CHECKPOINTS: &[Checkpoint] = &[];

/// Returns the list of checkpoints for a given network.
fn checkpoints_for(network: Network) -> &'static [Checkpoint] {
    match network {
        Network::Mainnet => MAINNET_CHECKPOINTS,
        Network::Testnet3 => TESTNET3_CHECKPOINTS,
        Network::Testnet4 => TESTNET4_CHECKPOINTS,
        Network::Regtest => REGTEST_CHECKPOINTS,
        Network::Signet => SIGNET_CHECKPOINTS,
    }
}

/// Returns the checkpoint hash for a given height and network, if one exists.
pub fn checkpoint_hash(network: Network, height: u32) -> Option<BlockHash> {
    let checkpoints = checkpoints_for(network);
    for &(h, hex) in checkpoints {
        if h == height {
            return BlockHash::from_hex(hex).ok();
        }
    }
    None
}

/// Verify a block hash against the checkpoint database.
///
/// Returns `true` if:
/// - No checkpoint exists at that height (no constraint), OR
/// - A checkpoint exists and the hash matches.
///
/// Returns `false` only if a checkpoint exists at that height and the hash
/// does NOT match.
pub fn verify_checkpoint(network: Network, height: u32, hash: &BlockHash) -> bool {
    match checkpoint_hash(network, height) {
        Some(expected) => *hash == expected,
        None => true,
    }
}

/// Returns the highest checkpoint height for the given network, or `None`
/// if the network has no checkpoints.
pub fn last_checkpoint_height(network: Network) -> Option<u32> {
    checkpoints_for(network).last().map(|&(h, _)| h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_checkpoint_lookup_known_height() {
        let hash = checkpoint_hash(Network::Mainnet, 11111);
        assert!(hash.is_some());
        let hash = hash.unwrap();
        assert_eq!(
            hash.to_hex(),
            "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"
        );
    }

    #[test]
    fn mainnet_checkpoint_lookup_height_250000() {
        let hash = checkpoint_hash(Network::Mainnet, 250000).unwrap();
        assert_eq!(
            hash.to_hex(),
            "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"
        );
    }

    #[test]
    fn mainnet_checkpoint_lookup_unknown_height() {
        assert!(checkpoint_hash(Network::Mainnet, 12345).is_none());
    }

    #[test]
    fn mainnet_checkpoint_all_heights_resolve() {
        let heights = [
            11111, 33333, 74000, 105000, 134444, 168000, 193000, 210000,
            216116, 225430, 250000, 279000, 295000,
        ];
        for h in heights {
            assert!(
                checkpoint_hash(Network::Mainnet, h).is_some(),
                "checkpoint missing for mainnet height {}",
                h
            );
        }
    }

    #[test]
    fn regtest_has_no_checkpoints() {
        assert!(checkpoint_hash(Network::Regtest, 0).is_none());
        assert!(checkpoint_hash(Network::Regtest, 11111).is_none());
    }

    #[test]
    fn signet_has_no_checkpoints() {
        assert!(checkpoint_hash(Network::Signet, 0).is_none());
    }

    #[test]
    fn verify_checkpoint_passes_when_no_checkpoint() {
        // Height 999 has no checkpoint on any network
        let dummy_hash = BlockHash::ZERO;
        assert!(verify_checkpoint(Network::Mainnet, 999, &dummy_hash));
        assert!(verify_checkpoint(Network::Regtest, 999, &dummy_hash));
    }

    #[test]
    fn verify_checkpoint_passes_with_correct_hash() {
        let expected = checkpoint_hash(Network::Mainnet, 11111).unwrap();
        assert!(verify_checkpoint(Network::Mainnet, 11111, &expected));
    }

    #[test]
    fn verify_checkpoint_fails_with_wrong_hash() {
        let wrong_hash = BlockHash::ZERO;
        assert!(!verify_checkpoint(Network::Mainnet, 11111, &wrong_hash));
    }

    #[test]
    fn verify_checkpoint_height_295000() {
        let expected = checkpoint_hash(Network::Mainnet, 295000).unwrap();
        assert!(verify_checkpoint(Network::Mainnet, 295000, &expected));
        assert_eq!(
            expected.to_hex(),
            "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632473f"
        );
    }

    #[test]
    fn last_checkpoint_height_mainnet() {
        assert_eq!(last_checkpoint_height(Network::Mainnet), Some(295000));
    }

    #[test]
    fn last_checkpoint_height_regtest() {
        assert_eq!(last_checkpoint_height(Network::Regtest), None);
    }

    #[test]
    fn last_checkpoint_height_signet() {
        assert_eq!(last_checkpoint_height(Network::Signet), None);
    }
}
