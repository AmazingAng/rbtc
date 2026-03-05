//! Script flags derived from block context (Core-like activation behavior).

use rbtc_primitives::hash::Hash256;
use rbtc_primitives::network::Network;
use rbtc_script::ScriptFlags;

/// Returns the script verification flags to use when validating transactions
/// in a block at the given height and with the given block header time.
/// Matches Bitcoin Core's GetBlockScriptFlags behavior.
pub fn script_flags_for_block(
    network: Network,
    height: u32,
    block_hash: Hash256,
    block_time: u32,
    median_time_past: u32,
) -> ScriptFlags {
    let p = network.consensus_params();

    // Keep P2SH on by default (with known exceptions), while witness/taproot
    // follow activation heights for this implementation.
    let mut verify_p2sh = true;
    let mut verify_witness = p.bip141_height == 0 || height >= p.bip141_height;
    let mut verify_taproot = p.bip341_height == 0 || height >= p.bip341_height;

    let block_hash_hex = block_hash.to_hex();
    if let Some(exception_hash) = p.bip16_exception_hash {
        if block_hash_hex == exception_hash {
            verify_p2sh = false;
            verify_witness = false;
            verify_taproot = false;
        }
    }
    if let Some(exception_hash) = p.taproot_exception_hash {
        if block_hash_hex == exception_hash {
            verify_taproot = false;
        }
    }

    // Keep the historical BIP16 activation-time check as a conservative
    // fallback for non-exception networks where exceptions are unknown.
    if !verify_p2sh {
        let _ = (block_time, median_time_past);
    } else if p.bip16_exception_hash.is_none() {
        let activation_time = if median_time_past == 0 { block_time } else { median_time_past };
        verify_p2sh = activation_time >= p.bip16_time;
    }

    let verify_dersig = p.bip66_height == 0 || height >= p.bip66_height;
    let verify_checklocktimeverify = height >= p.bip65_height;
    let verify_checksequenceverify = p.bip112_height == 0 || height >= p.bip112_height;
    let verify_nulldummy = p.bip141_height == 0 || height >= p.bip141_height;

    ScriptFlags {
        verify_p2sh,
        verify_dersig,
        verify_witness,
        verify_nulldummy,
        // CLEANSTACK is a policy/standardness rule, not a legacy block
        // consensus flag in Bitcoin Core's GetBlockScriptFlags path.
        verify_cleanstack: false,
        verify_checklocktimeverify,
        verify_checksequenceverify,
        verify_taproot,
        // Additional policy flags are not enabled at the consensus (block)
        // validation level; they apply to mempool relay and relay policy.
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{Hash256, Network};

    fn hash(hex: &str) -> Hash256 {
        Hash256::from_hex(hex).expect("valid hash")
    }

    #[test]
    fn mainnet_default_flags_on_before_bip16() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            5065,
            Hash256::ZERO,
            1320000000,
            1320000000,
        );
        assert!(flags.verify_p2sh);
        assert!(!flags.verify_cleanstack);
        assert!(!flags.verify_checklocktimeverify);
        assert!(!flags.verify_checksequenceverify);
        assert!(!flags.verify_witness);
        assert!(!flags.verify_taproot);
        assert!(!flags.verify_dersig);
        assert!(!flags.verify_nulldummy);
    }

    #[test]
    fn mainnet_after_bip16_before_bip65() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            250_000,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        assert!(flags.verify_p2sh);
        assert!(!flags.verify_dersig);
        assert!(!flags.verify_checklocktimeverify);
        assert!(!flags.verify_checksequenceverify);
    }

    #[test]
    fn mainnet_after_bip65_before_csv() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            400_000,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        assert!(flags.verify_p2sh);
        assert!(flags.verify_dersig);
        assert!(flags.verify_checklocktimeverify);
        assert!(!flags.verify_checksequenceverify);
    }

    #[test]
    fn mainnet_after_csv_before_segwit() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            450_000,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        assert!(flags.verify_p2sh);
        assert!(flags.verify_dersig);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(!flags.verify_witness);
    }

    #[test]
    fn mainnet_after_segwit_before_taproot() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            600_000,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        assert!(flags.verify_p2sh);
        assert!(flags.verify_dersig);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(!flags.verify_taproot);
        assert!(flags.verify_nulldummy);
    }

    #[test]
    fn mainnet_after_taproot_has_all() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            750_000,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        assert!(flags.verify_p2sh);
        assert!(flags.verify_dersig);
        assert!(flags.verify_witness);
        assert!(flags.verify_taproot);
        assert!(flags.verify_nulldummy);
    }

    #[test]
    fn mainnet_bip16_exception_block_disables_base_flags() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            170_000,
            hash("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"),
            1333238400,
            1333238400,
        );
        assert!(!flags.verify_p2sh);
        assert!(!flags.verify_witness);
        assert!(!flags.verify_taproot);
    }

    #[test]
    fn mainnet_taproot_exception_disables_taproot_only() {
        let flags = script_flags_for_block(
            Network::Mainnet,
            709_632,
            hash("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"),
            1636500000,
            1636500000,
        );
        assert!(flags.verify_p2sh);
        assert!(flags.verify_witness);
        assert!(!flags.verify_taproot);
    }

    #[test]
    fn mainnet_bip66_height_boundary() {
        let before = script_flags_for_block(
            Network::Mainnet,
            363_724,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        let after = script_flags_for_block(
            Network::Mainnet,
            363_725,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        assert!(!before.verify_dersig);
        assert!(after.verify_dersig);
    }

    #[test]
    fn regtest_all_enabled() {
        let flags = script_flags_for_block(Network::Regtest, 0, Hash256::ZERO, 0, 0);
        assert!(flags.verify_p2sh);
        assert!(flags.verify_dersig);
        assert!(flags.verify_nulldummy);
        assert!(!flags.verify_cleanstack);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(flags.verify_taproot);
    }
}
