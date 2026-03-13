//! BIP9 version bits soft fork deployment state machine.
//!
//! Implements the threshold-based activation mechanism described in BIP9:
//! - Deployments are signaled via block nVersion bits 0–28.
//! - State transitions happen at retarget boundaries (every 2016 blocks on mainnet).
//! - States: DEFINED → STARTED → LOCKED_IN → ACTIVE (or FAILED).
//!
//! Reference: Bitcoin Core `src/versionbits.cpp`

use rbtc_primitives::network::Network;

/// Retarget interval (2016 blocks on mainnet/testnet, 144 on regtest).
pub fn retarget_interval(network: Network) -> u32 {
    match network {
        Network::Regtest => 144,
        _ => 2016,
    }
}

/// BIP9 deployment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdState {
    /// Deployment is defined but not yet reached its start time.
    Defined,
    /// Deployment signaling window is active; miners can signal support.
    Started,
    /// Threshold was met in a retarget period; activation is locked in.
    LockedIn,
    /// Deployment is fully active; new consensus rules are enforced.
    Active,
    /// Deployment timed out without reaching threshold.
    Failed,
}

/// Parameters for a single BIP9 deployment.
#[derive(Debug, Clone, Copy)]
pub struct Bip9Deployment {
    /// Human-readable name for this deployment.
    pub name: &'static str,
    /// The version bit (0–28) used for signaling.
    pub bit: u8,
    /// MTP at which signaling begins (Unix timestamp).
    pub start_time: u64,
    /// MTP at which the deployment times out (Unix timestamp).
    /// Use `u64::MAX` for "always active" deployments.
    pub timeout: u64,
    /// Minimum number of signaling blocks in a retarget period (out of interval).
    /// On mainnet this is typically 1815/2016 = 90%.
    pub threshold: u32,
    /// Minimum activation height (BIP341-style min_activation_height).
    /// The deployment cannot become ACTIVE below this height even if LOCKED_IN.
    pub min_activation_height: u32,
}

/// Trait for looking up block info needed by the versionbits state machine.
pub trait VersionBitsBlockInfo {
    /// Return the median-time-past for the block at the given height.
    fn median_time_past(&self, height: u32) -> u32;
    /// Return the block's nVersion field at the given height.
    fn block_version(&self, height: u32) -> i32;
}

/// Compute the BIP9 deployment state at a given block height.
///
/// `height` is the height of the block being validated (i.e. the *next* block
/// to be connected). The state is computed based on the chain up to `height - 1`.
///
/// This follows Bitcoin Core's `VersionBitsState()` logic:
/// - State transitions happen at retarget boundaries.
/// - Each period's state depends on the previous period's state and data.
pub fn deployment_state(
    deployment: &Bip9Deployment,
    height: u32,
    network: Network,
    chain: &dyn VersionBitsBlockInfo,
) -> ThresholdState {
    let interval = retarget_interval(network);

    // "Always active" sentinel
    if deployment.start_time == 0 {
        return ThresholdState::Active;
    }
    // "Never active" sentinel
    if deployment.start_time == u64::MAX {
        return ThresholdState::Failed;
    }

    // Collect retarget boundary heights up to and including the current period.
    // The state at each boundary is computed from the previous boundary's state.
    // The block at `height` belongs to period `height / interval`.
    let current_period_start = (height / interval) * interval;

    // states[i] = state at the start of period i
    // Period 0 is always DEFINED.
    // Period i+1's state depends on period i's state + what happened in period i.
    let num_periods = (current_period_start / interval) + 1;

    let mut state = ThresholdState::Defined;

    for period in 1..num_periods as u64 + 1 {
        let period_start = period as u32 * interval;
        if period_start > current_period_start {
            break;
        }

        // MTP of the last block in the previous period
        let prev_last_block = period_start - 1;
        let prev_mtp = chain.median_time_past(prev_last_block);

        state = match state {
            ThresholdState::Defined => {
                if prev_mtp as u64 >= deployment.timeout {
                    ThresholdState::Failed
                } else if prev_mtp as u64 >= deployment.start_time {
                    ThresholdState::Started
                } else {
                    ThresholdState::Defined
                }
            }
            ThresholdState::Started => {
                if prev_mtp as u64 >= deployment.timeout {
                    ThresholdState::Failed
                } else {
                    // Count signaling blocks in the previous period
                    let prev_period_start = period_start - interval;
                    let count = count_signaling(deployment, prev_period_start, interval, chain);
                    if count >= deployment.threshold {
                        ThresholdState::LockedIn
                    } else {
                        ThresholdState::Started
                    }
                }
            }
            ThresholdState::LockedIn => {
                if period_start >= deployment.min_activation_height {
                    ThresholdState::Active
                } else {
                    ThresholdState::LockedIn
                }
            }
            ThresholdState::Active | ThresholdState::Failed => state,
        };
    }

    state
}

/// Count how many blocks in a retarget period signal for a deployment.
fn count_signaling(
    deployment: &Bip9Deployment,
    period_start: u32,
    interval: u32,
    chain: &dyn VersionBitsBlockInfo,
) -> u32 {
    let mask = 1i32 << deployment.bit;
    let mut count = 0u32;
    // BIP9: version bits are in bits 0–28, top 3 bits must be exactly 001.
    // Bit 29 = 0x20000000 must be set; bits 30-31 = 0x60000000 complement must be clear.
    let version_top_bits = 0xe0000000u32 as i32; // mask for bits 29-31
    let version_top_expected = 0x20000000i32; // exactly 001 in top 3 bits

    for h in period_start..period_start + interval {
        let version = chain.block_version(h);
        if (version & version_top_bits) == version_top_expected && (version & mask) != 0 {
            count += 1;
        }
    }
    count
}

// ── Known deployments per network ────────────────────────────────────────────

/// Return the BIP9 deployments for this network.
///
/// On mainnet, all historical deployments have already activated at known
/// heights. We define them here for completeness and for networks like
/// signet/testnet where they may be at different states.
pub fn deployments(network: Network) -> Vec<Bip9Deployment> {
    match network {
        Network::Mainnet => vec![
            // CSV (BIP68, BIP112, BIP113) — activated at height 419328
            Bip9Deployment {
                name: "csv",
                bit: 0,
                start_time: 1462060800, // May 1, 2016
                timeout: 1493596800,    // May 1, 2017
                threshold: 1916,        // 95%
                min_activation_height: 0,
            },
            // SegWit (BIP141, BIP143, BIP147) — activated at height 481824
            Bip9Deployment {
                name: "segwit",
                bit: 1,
                start_time: 1479168000, // Nov 15, 2016
                timeout: 1510704000,    // Nov 15, 2017
                threshold: 1916,        // 95%
                min_activation_height: 0,
            },
            // Taproot (BIP340, BIP341, BIP342) — activated at height 709632
            // Uses Speedy Trial (BIP8-like) with min_activation_height
            Bip9Deployment {
                name: "taproot",
                bit: 2,
                start_time: 1619222400, // Apr 24, 2021
                timeout: 1628640000,    // Aug 11, 2021
                threshold: 1815,        // 90%
                min_activation_height: 709_632,
            },
        ],
        Network::Testnet3 | Network::Signet | Network::Regtest => {
            // On signet and regtest, all deployments are "always active"
            // (start_time=0 sentinel).
            vec![
                Bip9Deployment {
                    name: "csv",
                    bit: 0,
                    start_time: 0, // always active
                    timeout: u64::MAX,
                    threshold: 1,
                    min_activation_height: 0,
                },
                Bip9Deployment {
                    name: "segwit",
                    bit: 1,
                    start_time: 0,
                    timeout: u64::MAX,
                    threshold: 1,
                    min_activation_height: 0,
                },
                Bip9Deployment {
                    name: "taproot",
                    bit: 2,
                    start_time: 0,
                    timeout: u64::MAX,
                    threshold: 1,
                    min_activation_height: 0,
                },
            ]
        }
        Network::Testnet4 => vec![
            Bip9Deployment {
                name: "csv",
                bit: 0,
                start_time: 0,
                timeout: u64::MAX,
                threshold: 1,
                min_activation_height: 0,
            },
            Bip9Deployment {
                name: "segwit",
                bit: 1,
                start_time: 0,
                timeout: u64::MAX,
                threshold: 1,
                min_activation_height: 0,
            },
            Bip9Deployment {
                name: "taproot",
                bit: 2,
                start_time: 0,
                timeout: u64::MAX,
                threshold: 1,
                min_activation_height: 0,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockChain {
        versions: Vec<i32>,
        mtps: Vec<u32>,
    }

    impl VersionBitsBlockInfo for MockChain {
        fn median_time_past(&self, height: u32) -> u32 {
            self.mtps.get(height as usize).copied().unwrap_or(0)
        }
        fn block_version(&self, height: u32) -> i32 {
            self.versions.get(height as usize).copied().unwrap_or(1)
        }
    }

    #[test]
    fn always_active_deployment() {
        let d = Bip9Deployment {
            name: "test",
            bit: 0,
            start_time: 0, // always active
            timeout: u64::MAX,
            threshold: 1,
            min_activation_height: 0,
        };
        let chain = MockChain {
            versions: vec![],
            mtps: vec![],
        };
        assert_eq!(
            deployment_state(&d, 0, Network::Mainnet, &chain),
            ThresholdState::Active
        );
        assert_eq!(
            deployment_state(&d, 100_000, Network::Mainnet, &chain),
            ThresholdState::Active
        );
    }

    #[test]
    fn never_active_deployment() {
        let d = Bip9Deployment {
            name: "test",
            bit: 0,
            start_time: u64::MAX,
            timeout: u64::MAX,
            threshold: 1,
            min_activation_height: 0,
        };
        let chain = MockChain {
            versions: vec![],
            mtps: vec![],
        };
        assert_eq!(
            deployment_state(&d, 0, Network::Mainnet, &chain),
            ThresholdState::Failed
        );
    }

    #[test]
    fn defined_before_start_time() {
        let d = Bip9Deployment {
            name: "test",
            bit: 0,
            start_time: 1_000_000,
            timeout: 2_000_000,
            threshold: 108, // 75% of 144
            min_activation_height: 0,
        };
        // All blocks have MTP=500000 (before start_time)
        let mtps = vec![500_000u32; 300];
        let versions = vec![0x20000001i32; 300];
        let chain = MockChain { versions, mtps };

        assert_eq!(
            deployment_state(&d, 144, Network::Regtest, &chain),
            ThresholdState::Defined
        );
    }

    #[test]
    fn started_after_start_time() {
        let d = Bip9Deployment {
            name: "test",
            bit: 0,
            start_time: 1_000_000,
            timeout: 2_000_000,
            threshold: 108,
            min_activation_height: 0,
        };
        // Period 0 (0..143): MTP < start_time → DEFINED
        // Period 1 starts at 144. MTP of block 143 >= start_time → STARTED
        let mut mtps = vec![500_000u32; 144];
        mtps.extend(vec![1_500_000u32; 144]);
        let versions = vec![0x20000001i32; 288];
        let chain = MockChain { versions, mtps };

        // At height 288 (start of period 2), we check state
        assert_eq!(
            deployment_state(&d, 288, Network::Regtest, &chain),
            ThresholdState::Started
        );
    }

    #[test]
    fn locked_in_after_threshold() {
        let d = Bip9Deployment {
            name: "test",
            bit: 0,
            start_time: 1_000_000,
            timeout: 2_000_000,
            threshold: 108, // 75% of 144
            min_activation_height: 0,
        };
        // Period 0: MTP < start_time → DEFINED
        // Period 1: MTP[143] >= start_time → transition to STARTED
        //   Signal: all 144 blocks signal bit 0 → threshold met
        // Period 2: check count from period 1 → LOCKED_IN → ACTIVE
        let mut mtps = vec![500_000u32; 144];
        mtps.extend(vec![1_500_000u32; 144]);
        mtps.extend(vec![1_600_000u32; 144]);
        let versions = vec![0x20000001i32; 432]; // all signal bit 0
        let chain = MockChain { versions, mtps };

        // At height 432 (period 3):
        // - Period 1: MTP[143]=500k < start → DEFINED
        // - Period 2: MTP[287]=1.5M >= start → STARTED
        // - Period 3: count period 2, all signal → LOCKED_IN
        assert_eq!(
            deployment_state(&d, 432, Network::Regtest, &chain),
            ThresholdState::LockedIn
        );

        // At height 576 (period 4): LOCKED_IN → ACTIVE
        assert_eq!(
            deployment_state(&d, 576, Network::Regtest, &chain),
            ThresholdState::Active
        );
    }

    #[test]
    fn failed_after_timeout() {
        let d = Bip9Deployment {
            name: "test",
            bit: 0,
            start_time: 1_000_000,
            timeout: 2_000_000,
            threshold: 108,
            min_activation_height: 0,
        };
        // Period 0: MTP < start → DEFINED
        // Period 1: MTP[143] >= start → STARTED, no signaling
        // Period 2: MTP[287] >= timeout → FAILED
        let mut mtps = vec![500_000u32; 144];
        mtps.extend(vec![1_500_000u32; 144]);
        mtps.extend(vec![2_500_000u32; 144]); // past timeout
        let versions = vec![1i32; 432]; // no signaling (no BIP9 top bits)
        let chain = MockChain { versions, mtps };

        assert_eq!(
            deployment_state(&d, 432, Network::Regtest, &chain),
            ThresholdState::Failed
        );
    }

    #[test]
    fn min_activation_height_delays_active() {
        let d = Bip9Deployment {
            name: "test",
            bit: 0,
            start_time: 1_000_000,
            timeout: 2_000_000,
            threshold: 108,
            min_activation_height: 576, // delayed
        };
        let mut mtps = vec![500_000u32; 144];
        for i in 1..10 {
            mtps.extend(vec![1_500_000u32 + i * 1000; 144]);
        }
        let versions = vec![0x20000001i32; 1440]; // all signal
        let chain = MockChain { versions, mtps };

        // Period 2 (height 288): would be LOCKED_IN
        // Period 3 (height 432): still LOCKED_IN because 432 < 576
        assert_eq!(
            deployment_state(&d, 432, Network::Regtest, &chain),
            ThresholdState::LockedIn
        );

        // Period 4 (height 576): LOCKED_IN → ACTIVE (576 >= min_activation)
        assert_eq!(
            deployment_state(&d, 576, Network::Regtest, &chain),
            ThresholdState::Active
        );
    }

    #[test]
    fn mainnet_deployments_defined() {
        let deps = deployments(Network::Mainnet);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "csv");
        assert_eq!(deps[1].name, "segwit");
        assert_eq!(deps[2].name, "taproot");
    }

    #[test]
    fn regtest_deployments_always_active() {
        let deps = deployments(Network::Regtest);
        let chain = MockChain {
            versions: vec![],
            mtps: vec![],
        };
        for d in &deps {
            assert_eq!(
                deployment_state(d, 0, Network::Regtest, &chain),
                ThresholdState::Active,
                "deployment {} should be always-active on regtest",
                d.name
            );
        }
    }

    #[test]
    fn signet_deployments_always_active() {
        let deps = deployments(Network::Signet);
        let chain = MockChain {
            versions: vec![],
            mtps: vec![],
        };
        for d in &deps {
            assert_eq!(
                deployment_state(d, 0, Network::Signet, &chain),
                ThresholdState::Active,
                "deployment {} should be always-active on signet",
                d.name
            );
        }
    }
}
