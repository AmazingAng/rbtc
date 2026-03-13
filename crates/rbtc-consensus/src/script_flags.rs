//! Script flags derived from block context (Core-like activation behavior).
//!
//! For historical (buried) deployments — CSV, SegWit, Taproot — this module
//! uses hardcoded activation heights matching Bitcoin Core's `GetBlockScriptFlags`.
//! For future deployments, call [`script_flags_for_block_with_versionbits`] to
//! query the BIP9 state machine.

use rbtc_primitives::hash::Hash256;
use rbtc_primitives::network::{script_verify, Network};
use rbtc_script::ScriptFlags;

use crate::versionbits::{deployment_state, deployments, ThresholdState, VersionBitsBlockInfo};

/// Returns the script verification flags to use when validating transactions
/// in a block at the given height and with the given block header time.
///
/// Matches Bitcoin Core's `GetBlockScriptFlags` behavior:
/// 1. Start with base flags = P2SH | WITNESS | TAPROOT.
/// 2. Look up `script_flag_exceptions` by block hash — if found, replace
///    the base flags with the exception value (flags TO APPLY).
/// 3. Then add DERSIG, CLTV, CSV, NULLDUMMY based on activation heights.
pub fn script_flags_for_block(
    network: Network,
    height: u32,
    block_hash: Hash256,
    _block_time: u32,
    _median_time_past: u32,
) -> ScriptFlags {
    let p = network.consensus_params();

    // Base flags: P2SH | WITNESS | TAPROOT (matching Bitcoin Core).
    let mut base_flags: u32 = script_verify::SCRIPT_VERIFY_P2SH
        | script_verify::SCRIPT_VERIFY_WITNESS
        | script_verify::SCRIPT_VERIFY_TAPROOT;

    // Check script_flag_exceptions — if block hash matches, override base
    // flags entirely (matching Bitcoin Core's `flags = it->second`).
    // Hash256 stores bytes in little-endian internally; hex32() produces
    // big-endian (display order). Reverse for comparison.
    let mut block_hash_be = *block_hash.as_bytes();
    block_hash_be.reverse();
    for exc in p.script_flag_exceptions {
        if exc.block_hash == block_hash_be {
            base_flags = exc.flags_override;
            break;
        }
    }

    let verify_p2sh = base_flags & script_verify::SCRIPT_VERIFY_P2SH != 0;
    let verify_witness = base_flags & script_verify::SCRIPT_VERIFY_WITNESS != 0;
    let verify_taproot = base_flags & script_verify::SCRIPT_VERIFY_TAPROOT != 0;

    // Deployment-based flags added on top (matching Bitcoin Core).
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

/// Like [`script_flags_for_block`], but also queries the BIP9 state machine
/// for non-buried deployments.
///
/// All historical deployments (CSV, SegWit, Taproot) are "buried" and already
/// use hardcoded heights. This function additionally checks for any future
/// BIP9-activated deployment whose state is ACTIVE.
pub fn script_flags_for_block_with_versionbits(
    network: Network,
    height: u32,
    block_hash: Hash256,
    block_time: u32,
    median_time_past: u32,
    chain: &dyn VersionBitsBlockInfo,
) -> ScriptFlags {
    let mut flags = script_flags_for_block(network, height, block_hash, block_time, median_time_past);

    // Query BIP9 deployments. For buried deployments this is redundant (the
    // hardcoded-height approach above is authoritative), but for any future
    // deployment the BIP9 state machine is the source of truth.
    for dep in deployments(network) {
        let state = deployment_state(&dep, height, network, chain);
        match dep.name {
            "csv" => {
                if state == ThresholdState::Active {
                    flags.verify_checksequenceverify = true;
                }
            }
            "segwit" => {
                if state == ThresholdState::Active {
                    flags.verify_witness = true;
                    flags.verify_nulldummy = true;
                }
            }
            "taproot" => {
                if state == ThresholdState::Active {
                    flags.verify_taproot = true;
                }
            }
            _ => {
                // Future deployments: extend here as new soft forks are added
            }
        }
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{Hash256, Network};

    fn hash(hex: &str) -> Hash256 {
        Hash256::from_hex(hex).expect("valid hash")
    }

    #[test]
    fn mainnet_early_block_base_flags() {
        // Early mainnet block: P2SH+WITNESS+TAPROOT always on (base flags),
        // but DERSIG/CLTV/CSV/NULLDUMMY not yet active by height.
        let flags = script_flags_for_block(
            Network::Mainnet,
            5065,
            Hash256::ZERO,
            1320000000,
            1320000000,
        );
        // Base flags always on (matching Bitcoin Core)
        assert!(flags.verify_p2sh);
        assert!(flags.verify_witness);
        assert!(flags.verify_taproot);
        // Height-based flags not yet active
        assert!(!flags.verify_dersig);
        assert!(!flags.verify_checklocktimeverify);
        assert!(!flags.verify_checksequenceverify);
        assert!(!flags.verify_nulldummy);
        assert!(!flags.verify_cleanstack);
    }

    #[test]
    fn mainnet_after_bip66_before_bip65() {
        // Height 363_725: BIP66 (DERSIG) active, BIP65 (CLTV) not yet.
        let flags = script_flags_for_block(
            Network::Mainnet,
            363_725,
            Hash256::ZERO,
            1333238400,
            1333238400,
        );
        assert!(flags.verify_p2sh);
        assert!(flags.verify_witness);
        assert!(flags.verify_taproot);
        assert!(flags.verify_dersig);
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
    fn mainnet_after_csv() {
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
        // WITNESS and TAPROOT always on via base flags
        assert!(flags.verify_witness);
        assert!(flags.verify_taproot);
    }

    #[test]
    fn mainnet_after_segwit() {
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
        assert!(flags.verify_taproot);
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
    fn mainnet_bip16_exception_flags_override_none() {
        // BIP16 exception block: flags_override = VERIFY_NONE (0)
        // All base flags disabled, only height-based flags apply.
        let flags = script_flags_for_block(
            Network::Mainnet,
            170_060,
            hash("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"),
            1333238400,
            1333238400,
        );
        assert!(!flags.verify_p2sh, "P2SH off via VERIFY_NONE override");
        assert!(!flags.verify_witness, "WITNESS off via VERIFY_NONE override");
        assert!(!flags.verify_taproot, "TAPROOT off via VERIFY_NONE override");
        assert!(!flags.verify_nulldummy, "NULLDUMMY off (height < bip141)");
        // DERSIG not yet active at height 170060
        assert!(!flags.verify_dersig);
    }

    #[test]
    fn mainnet_taproot_exception_p2sh_witness_only() {
        // Taproot exception block: flags_override = P2SH | WITNESS
        // P2SH and WITNESS on, TAPROOT off.
        let flags = script_flags_for_block(
            Network::Mainnet,
            709_632,
            hash("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"),
            1636500000,
            1636500000,
        );
        assert!(flags.verify_p2sh);
        assert!(flags.verify_witness);
        assert!(!flags.verify_taproot, "TAPROOT off via P2SH|WITNESS override");
        // Height-based flags active at 709632
        assert!(flags.verify_dersig);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_nulldummy);
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

    #[test]
    fn versionbits_flags_regtest_always_active() {
        use crate::versionbits::VersionBitsBlockInfo;

        struct EmptyChain;
        impl VersionBitsBlockInfo for EmptyChain {
            fn median_time_past(&self, _h: u32) -> u32 { 0 }
            fn block_version(&self, _h: u32) -> i32 { 1 }
        }

        let flags = script_flags_for_block_with_versionbits(
            Network::Regtest, 0, Hash256::ZERO, 0, 0, &EmptyChain,
        );
        // On regtest all BIP9 deployments are "always active"
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(flags.verify_nulldummy);
        assert!(flags.verify_taproot);
    }
}
