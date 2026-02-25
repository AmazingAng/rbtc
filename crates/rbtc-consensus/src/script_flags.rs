//! Script flags derived from block height and time (BIP activation).

use rbtc_primitives::network::Network;
use rbtc_script::ScriptFlags;

/// Returns the script verification flags to use when validating transactions
/// in a block at the given height and with the given block header time.
/// Matches Bitcoin Core's GetBlockScriptFlags behavior.
pub fn script_flags_for_block(network: Network, height: u32, block_time: u32) -> ScriptFlags {
    let p = network.consensus_params();

    let verify_p2sh = block_time >= p.bip16_time;
    let verify_checklocktimeverify = height >= p.bip65_height;
    let verify_checksequenceverify = p.bip112_height == 0 || height >= p.bip112_height;
    let verify_witness = p.bip141_height == 0 || height >= p.bip141_height;
    let verify_taproot = p.bip341_height == 0 || height >= p.bip341_height;

    ScriptFlags {
        verify_p2sh,
        verify_witness,
        verify_cleanstack: true,
        verify_checklocktimeverify,
        verify_checksequenceverify,
        verify_taproot,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::Network;

    #[test]
    fn mainnet_early_block_no_p2sh() {
        let flags = script_flags_for_block(Network::Mainnet, 5065, 1320000000);
        assert!(!flags.verify_p2sh, "block 5065 is before BIP16");
        assert!(flags.verify_cleanstack);
        assert!(!flags.verify_checklocktimeverify);
        assert!(!flags.verify_checksequenceverify);
        assert!(!flags.verify_witness);
        assert!(!flags.verify_taproot);
    }

    #[test]
    fn mainnet_after_bip16_before_bip65() {
        let flags = script_flags_for_block(Network::Mainnet, 250_000, 1333238400);
        assert!(flags.verify_p2sh);
        assert!(!flags.verify_checklocktimeverify);
        assert!(!flags.verify_checksequenceverify);
    }

    #[test]
    fn mainnet_after_bip65_before_csv() {
        let flags = script_flags_for_block(Network::Mainnet, 400_000, 1333238400);
        assert!(flags.verify_p2sh);
        assert!(flags.verify_checklocktimeverify);
        assert!(!flags.verify_checksequenceverify);
    }

    #[test]
    fn mainnet_after_csv_before_segwit() {
        let flags = script_flags_for_block(Network::Mainnet, 450_000, 1333238400);
        assert!(flags.verify_p2sh);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(!flags.verify_witness);
    }

    #[test]
    fn mainnet_after_segwit_before_taproot() {
        let flags = script_flags_for_block(Network::Mainnet, 600_000, 1333238400);
        assert!(flags.verify_p2sh);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(!flags.verify_taproot);
    }

    #[test]
    fn mainnet_after_taproot_has_all() {
        let flags = script_flags_for_block(Network::Mainnet, 750_000, 1333238400);
        assert!(flags.verify_p2sh);
        assert!(flags.verify_witness);
        assert!(flags.verify_taproot);
    }

    #[test]
    fn mainnet_bip16_time_boundary() {
        let before = script_flags_for_block(Network::Mainnet, 227_931, 1333238399);
        let after = script_flags_for_block(Network::Mainnet, 227_931, 1333238400);
        assert!(!before.verify_p2sh);
        assert!(after.verify_p2sh);
    }

    #[test]
    fn regtest_all_enabled() {
        let flags = script_flags_for_block(Network::Regtest, 0, 0);
        assert!(flags.verify_p2sh);
        assert!(flags.verify_cleanstack);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(flags.verify_taproot);
    }
}
