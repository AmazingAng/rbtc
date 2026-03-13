/// Parse a 64-char hex string into a big-endian `[u8; 32]` at compile time.
const fn hex32(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = match s[i * 2] {
            b'0'..=b'9' => s[i * 2] - b'0',
            b'a'..=b'f' => s[i * 2] - b'a' + 10,
            b'A'..=b'F' => s[i * 2] - b'A' + 10,
            _ => panic!("invalid hex char"),
        };
        let lo = match s[i * 2 + 1] {
            b'0'..=b'9' => s[i * 2 + 1] - b'0',
            b'a'..=b'f' => s[i * 2 + 1] - b'a' + 10,
            b'A'..=b'F' => s[i * 2 + 1] - b'A' + 10,
            _ => panic!("invalid hex char"),
        };
        out[i] = hi << 4 | lo;
        i += 1;
    }
    out
}

/// Bitcoin Core script verification flag constants (matching `script/interpreter.h`).
/// Used in [`ScriptFlagException`] to specify the flags to *apply* (override)
/// for historically-valid blocks that would otherwise fail modern validation.
pub mod script_verify {
    /// BIP16 (P2SH) flag.
    pub const SCRIPT_VERIFY_P2SH: u32 = 1 << 0;
    /// Strict DER signature encoding (BIP66).
    pub const SCRIPT_VERIFY_DERSIG: u32 = 1 << 2;
    /// CHECKLOCKTIMEVERIFY (BIP65).
    pub const SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
    /// CHECKSEQUENCEVERIFY (BIP112).
    pub const SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;
    /// Segregated Witness (BIP141).
    pub const SCRIPT_VERIFY_WITNESS: u32 = 1 << 11;
    /// Null dummy for CHECKMULTISIG (BIP147).
    pub const SCRIPT_VERIFY_NULLDUMMY: u32 = 1 << 4;
    /// Taproot (BIP341/342).
    pub const SCRIPT_VERIFY_TAPROOT: u32 = 1 << 17;
}

/// A block whose script validation must use an overridden set of flags.
///
/// Bitcoin Core keeps a `script_flag_exceptions` map in `validation.cpp`
/// for historically-valid blocks that would fail under modern script rules.
/// The stored flags are the flags TO APPLY (not flags to exclude).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptFlagException {
    /// Block hash (big-endian, display order).
    pub block_hash: [u8; 32],
    /// Bitmask of script verification flags to *apply* for this block,
    /// replacing the default base flags (P2SH|WITNESS|TAPROOT).
    /// Matches Bitcoin Core's `script_flag_exceptions` semantics.
    pub flags_override: u32,
}

/// Consensus parameters: BIP activation heights and times.
/// Used for script flags and coinbase (BIP34) checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusParams {
    /// BIP16 (P2SH) activation time (Unix timestamp).
    pub bip16_time: u32,
    /// BIP34 (coinbase height) activation block height.
    pub bip34_height: u32,
    /// BIP66 (strict DER signatures) activation block height.
    pub bip66_height: u32,
    /// BIP65 (CHECKLOCKTIMEVERIFY) activation block height.
    pub bip65_height: u32,
    /// BIP112 (CHECKSEQUENCEVERIFY) activation block height.
    pub bip112_height: u32,
    /// BIP141 (SegWit) activation block height.
    pub bip141_height: u32,
    /// BIP341 (Taproot) activation block height.
    pub bip341_height: u32,
    /// Historical block hash that must bypass P2SH (BIP16 exception).
    pub bip16_exception_hash: Option<&'static str>,
    /// Historical block hash that must bypass TAPROOT.
    pub taproot_exception_hash: Option<&'static str>,

    // --- Script flag exceptions (generalized) ---
    /// Blocks that use an overridden set of script verification flags.
    /// Stores flags TO APPLY (not to exclude), matching Bitcoin Core's
    /// `script_flag_exceptions` in `validation.cpp`.
    pub script_flag_exceptions: &'static [ScriptFlagException],

    // --- Economic / interval parameters ---
    /// Number of blocks between subsidy halvings.
    /// Mainnet / testnet: 210 000, regtest: 150. Matches Bitcoin Core
    /// `consensus.nSubsidyHalvingInterval`.
    pub subsidy_halving_interval: u64,

    // --- Proof-of-Work parameters ---
    /// Maximum proof-of-work target (big-endian 32-byte value).
    pub pow_limit: [u8; 32],
    /// Target timespan for difficulty adjustment (seconds).
    /// Mainnet / testnet: 14 * 24 * 60 * 60 (two weeks), regtest: 24 * 60 * 60 (one day).
    /// Matches Bitcoin Core `consensus.nPowTargetTimespan`.
    pub pow_target_timespan: u64,
    /// Whether min-difficulty blocks are allowed (testnet/regtest/signet).
    pub pow_allow_min_difficulty_blocks: bool,
    /// Whether PoW retargeting is disabled (regtest only).
    pub pow_no_retargeting: bool,
    /// Whether BIP94 rules are enforced (Testnet4).
    /// When true, difficulty retarget uses the first block of the period's nBits
    /// instead of the last block's nBits, and the timewarp attack mitigation applies.
    pub enforce_bip94: bool,

    /// Target time between blocks (seconds).
    /// All networks use 600 (10 minutes), matching Bitcoin Core `consensus.nPowTargetSpacing`.
    pub pow_target_spacing: u64,

    // --- Chain validation hints ---
    /// Minimum total chain work to accept a chain (big-endian 32-byte value).
    pub minimum_chain_work: [u8; 32],
    /// Block hash assumed valid — script checks skipped for ancestors (big-endian 32-byte value).
    pub default_assume_valid: [u8; 32],

    // --- Genesis & BIP34 hash ---
    /// Hash of the genesis block (big-endian 32-byte value).
    /// Matches Bitcoin Core `consensus.hashGenesisBlock`.
    pub genesis_hash: [u8; 32],
    /// Hash of the BIP34 activation block (big-endian 32-byte value).
    /// Used to validate the BIP34 activation block itself.
    /// `None` for networks where BIP34 is active from genesis (testnet4, regtest, signet).
    /// Matches Bitcoin Core `consensus.BIP34Hash`.
    pub bip34_hash: Option<[u8; 32]>,

    // --- Warning suppression ---
    /// Minimum height at which unknown BIP9 version bit warnings are emitted.
    /// Prevents warnings about CSV/segwit activations on mainnet/testnet3.
    /// Matches Bitcoin Core `consensus.MinBIP9WarningHeight`.
    pub min_bip9_warning_height: u32,
}

impl ConsensusParams {
    /// Number of blocks per difficulty adjustment period.
    /// Derived as `pow_target_timespan / pow_target_spacing`, matching
    /// Bitcoin Core's `Consensus::Params::DifficultyAdjustmentInterval()`.
    pub const fn difficulty_adjustment_interval(&self) -> u64 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Regtest,
    Signet,
}

/// Mainnet script flag exceptions (matching Bitcoin Core `chainparams.cpp`).
///
/// - Height 170060: BIP16 exception block — flags = VERIFY_NONE (no flags applied).
/// - Height 709632: Taproot exception block — flags = P2SH | WITNESS (no taproot).
static MAINNET_SCRIPT_FLAG_EXCEPTIONS: &[ScriptFlagException] = &[
    // BIP16 exception: SCRIPT_VERIFY_NONE (0)
    ScriptFlagException {
        block_hash: hex32(b"00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"),
        flags_override: 0, // SCRIPT_VERIFY_NONE
    },
    // Taproot exception: SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS
    ScriptFlagException {
        block_hash: hex32(b"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"),
        flags_override: script_verify::SCRIPT_VERIFY_P2SH
            | script_verify::SCRIPT_VERIFY_WITNESS,
    },
];

/// Testnet3 script flag exceptions (matching Bitcoin Core `chainparams.cpp`).
///
/// - BIP16 exception block — flags = VERIFY_NONE (no flags applied).
static TESTNET3_SCRIPT_FLAG_EXCEPTIONS: &[ScriptFlagException] = &[
    ScriptFlagException {
        block_hash: hex32(b"00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"),
        flags_override: 0, // SCRIPT_VERIFY_NONE
    },
];

impl Network {
    /// Consensus parameters for this network (BIP activation points).
    pub fn consensus_params(&self) -> ConsensusParams {
        match self {
            Network::Mainnet => ConsensusParams {
                bip16_time: 1333238400, // 2012-04-01
                bip34_height: 227_931,
                bip66_height: 363_725,
                bip65_height: 388_381,
                bip112_height: 419_328,
                bip141_height: 481_824,
                bip341_height: 709_632,
                bip16_exception_hash: Some(
                    "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22",
                ),
                taproot_exception_hash: Some(
                    "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad",
                ),
                script_flag_exceptions: MAINNET_SCRIPT_FLAG_EXCEPTIONS,
                subsidy_halving_interval: 210_000,
                pow_limit: hex32(b"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                pow_target_timespan: 14 * 24 * 60 * 60,
                pow_allow_min_difficulty_blocks: false,
                pow_no_retargeting: false,
                enforce_bip94: false,
                pow_target_spacing: 10 * 60,
                minimum_chain_work: hex32(b"0000000000000000000000000000000000000000dee8e2a309ad8a9820433c68"),
                default_assume_valid: hex32(b"00000000000000000000611fd22f2df7c8fbd0688745c3a6c3bb5109cc2a12cb"),
                genesis_hash: hex32(b"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
                bip34_hash: Some(hex32(b"000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8")),
                min_bip9_warning_height: 483_840, // segwit activation height (481824) + miner confirmation window (2016)
            },
            Network::Testnet3 => ConsensusParams {
                bip16_time: 1333238400,
                bip34_height: 21_111,
                bip66_height: 330_776,
                bip65_height: 581_885,
                bip112_height: 770_112,
                bip141_height: 834_624,
                bip341_height: 0, // always active on testnet3 (buried)
                bip16_exception_hash: Some(
                    "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105",
                ),
                taproot_exception_hash: None,
                script_flag_exceptions: TESTNET3_SCRIPT_FLAG_EXCEPTIONS,
                subsidy_halving_interval: 210_000,
                pow_limit: hex32(b"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                pow_target_timespan: 14 * 24 * 60 * 60,
                pow_allow_min_difficulty_blocks: true,
                pow_no_retargeting: false,
                enforce_bip94: false,
                pow_target_spacing: 10 * 60,
                minimum_chain_work: hex32(b"0000000000000000000000000000000000000000000016dd270dd94fac1d7632"),
                default_assume_valid: hex32(b"0000000000000065c6c38258e201971a3fdfcc2ceee0dd6e85a6c022d45dee34"),
                genesis_hash: hex32(b"000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
                bip34_hash: Some(hex32(b"0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8")),
                min_bip9_warning_height: 836_640, // segwit activation height (834624) + miner confirmation window (2016)
            },
            Network::Testnet4 => ConsensusParams {
                bip16_time: 0,
                bip34_height: 1,
                bip66_height: 1,
                bip65_height: 1,
                bip112_height: 1,
                bip141_height: 1,
                bip341_height: 0, // always active (BIP9 ALWAYS_ACTIVE)
                bip16_exception_hash: None,
                taproot_exception_hash: None,
                script_flag_exceptions: &[],
                subsidy_halving_interval: 210_000,
                pow_limit: hex32(b"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                pow_target_timespan: 14 * 24 * 60 * 60,
                pow_allow_min_difficulty_blocks: true,
                pow_no_retargeting: false,
                enforce_bip94: true,
                pow_target_spacing: 10 * 60,
                minimum_chain_work: hex32(b"00000000000000000000000000000000000000000000034a4690fe592dc49c7c"),
                default_assume_valid: hex32(b"000000000000000180a58e7fa3b0db84b5ea76377524894f53660d93ac839d9b"),
                genesis_hash: hex32(b"00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
                bip34_hash: None, // BIP34 active from block 1, no specific activation hash
                min_bip9_warning_height: 0,
            },
            Network::Regtest => ConsensusParams {
                bip16_time: 0,
                bip34_height: 0,
                bip66_height: 0,
                bip65_height: 0,
                bip112_height: 0,
                bip141_height: 0,
                bip341_height: 0,
                bip16_exception_hash: None,
                taproot_exception_hash: None,
                script_flag_exceptions: &[],
                subsidy_halving_interval: 150,
                pow_limit: hex32(b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                pow_target_timespan: 24 * 60 * 60, // one day
                pow_allow_min_difficulty_blocks: true,
                pow_no_retargeting: true,
                enforce_bip94: false,
                pow_target_spacing: 10 * 60,
                minimum_chain_work: [0u8; 32],
                default_assume_valid: [0u8; 32],
                genesis_hash: hex32(b"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
                bip34_hash: None, // BIP34 active from genesis, no specific activation hash
                min_bip9_warning_height: 0,
            },
            Network::Signet => ConsensusParams {
                bip16_time: 0,
                bip34_height: 0,
                bip66_height: 0,
                bip65_height: 0,
                bip112_height: 0,
                bip141_height: 0,
                bip341_height: 0,
                bip16_exception_hash: None,
                taproot_exception_hash: None,
                script_flag_exceptions: &[],
                subsidy_halving_interval: 210_000,
                pow_limit: hex32(b"00000377ae000000000000000000000000000000000000000000000000000000"),
                pow_target_timespan: 14 * 24 * 60 * 60,
                pow_allow_min_difficulty_blocks: false,
                pow_no_retargeting: false,
                enforce_bip94: false,
                pow_target_spacing: 10 * 60,
                minimum_chain_work: hex32(b"0000000000000000000000000000000000000000000000000000067d328e681a"),
                default_assume_valid: hex32(b"000000128586e26813922680309f04e1de713c7542fee86ed908f56368aefe2e"),
                genesis_hash: hex32(b"00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
                bip34_hash: None, // BIP34 active from genesis, no specific activation hash
                min_bip9_warning_height: 0,
            },
        }
    }

    /// P2P magic bytes for this network
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
            Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
        }
    }

    /// Default P2P port
    pub fn default_port(&self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet3 => 18333,
            Network::Testnet4 => 48333,
            Network::Regtest => 18444,
            Network::Signet => 38333,
        }
    }

    /// DNS seeds for initial peer discovery
    pub fn dns_seeds(&self) -> &'static [&'static str] {
        match self {
            Network::Mainnet => &[
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.net",
            ],
            Network::Testnet3 => &[], // deprecated network, no active seeds
            Network::Testnet4 => &["seed.testnet4.bitcoin.sprovoost.nl"],
            Network::Regtest => &[],
            Network::Signet => &["seed.signet.bitcoin.sprovoost.nl"],
        }
    }

    /// Genesis block hash
    pub fn genesis_hash(&self) -> &'static str {
        match self {
            Network::Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            Network::Testnet3 => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            Network::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            Network::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            Network::Signet => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
        }
    }

    /// Returns the genesis block header for this network.
    pub fn genesis_header(&self) -> crate::block::BlockHeader {
        use crate::block::BlockHeader;
        use crate::hash::{BlockHash, Hash256};

        match self {
            Network::Mainnet => BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::from_hex(
                    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                )
                .unwrap_or(Hash256::ZERO),
                time: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            Network::Testnet3 => BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::from_hex(
                    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                )
                .unwrap_or(Hash256::ZERO),
                time: 1296688602,
                bits: 0x1d00ffff,
                nonce: 414098458,
            },
            Network::Testnet4 => BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::from_hex(
                    "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e",
                )
                .unwrap_or(Hash256::ZERO),
                time: 1714777860,
                bits: 0x1d00ffff,
                nonce: 393743547,
            },
            Network::Regtest => BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::from_hex(
                    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                )
                .unwrap_or(Hash256::ZERO),
                time: 1296688602,
                bits: 0x207fffff,
                nonce: 2,
            },
            Network::Signet => BlockHeader {
                version: 1,
                prev_block: BlockHash::ZERO,
                merkle_root: Hash256::from_hex(
                    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                )
                .unwrap_or(Hash256::ZERO),
                time: 1598918400,
                bits: 0x1e0377ae,
                nonce: 52613770,
            },
        }
    }

    /// Return the signet challenge script for this network, if applicable.
    ///
    /// The default (public) signet uses a 1-of-2 bare multisig challenge.
    /// Returns `None` for non-signet networks.
    pub fn signet_challenge(&self) -> Option<&'static [u8]> {
        match self {
            // From Bitcoin Core chainparams.cpp for default signet:
            // OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
            Network::Signet => Some(&[
                0x51, // OP_1
                0x21, // OP_PUSHBYTES_33
                0x03, 0xad, 0x5e, 0x0e, 0xda, 0xd1, 0x8c, 0xb1, 0xf0, 0xfc, 0x0d, 0x28, 0xa3, 0xd4,
                0xf1, 0xf3, 0xe4, 0x45, 0x64, 0x03, 0x37, 0x48, 0x9a, 0xbb, 0x10, 0x40, 0x4f, 0x2d,
                0x1e, 0x08, 0x6b, 0xe4, 0x30, 0x21, // OP_PUSHBYTES_33
                0x03, 0x59, 0xef, 0x50, 0x21, 0x96, 0x4f, 0xe2, 0x2d, 0x6f, 0x8e, 0x05, 0xb2, 0x46,
                0x3c, 0x95, 0x40, 0xce, 0x96, 0x88, 0x3f, 0xe3, 0xb2, 0x78, 0x76, 0x0f, 0x04, 0x8f,
                0x51, 0x89, 0xf2, 0xe6, 0xc4, 0x52, // OP_2
                0xae, // OP_CHECKMULTISIG
            ]),
            _ => None,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet3 => write!(f, "testnet3"),
            Network::Testnet4 => write!(f, "testnet4"),
            Network::Regtest => write!(f, "regtest"),
            Network::Signet => write!(f, "signet"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" | "main" => Ok(Network::Mainnet),
            "testnet3" => Ok(Network::Testnet3),
            "testnet4" | "testnet" => Ok(Network::Testnet4),
            "regtest" => Ok(Network::Regtest),
            "signet" => Ok(Network::Signet),
            other => Err(format!("unknown network: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn network_magic() {
        assert_eq!(Network::Mainnet.magic(), [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(Network::Testnet3.magic(), [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(Network::Testnet4.magic(), [0x1c, 0x16, 0x3f, 0x28]);
        assert_eq!(Network::Regtest.magic(), [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(Network::Signet.magic(), [0x0a, 0x03, 0xcf, 0x40]);
    }

    #[test]
    fn network_default_port() {
        assert_eq!(Network::Mainnet.default_port(), 8333);
        assert_eq!(Network::Testnet3.default_port(), 18333);
        assert_eq!(Network::Testnet4.default_port(), 48333);
        assert_eq!(Network::Regtest.default_port(), 18444);
        assert_eq!(Network::Signet.default_port(), 38333);
    }

    #[test]
    fn network_dns_seeds() {
        assert!(!Network::Mainnet.dns_seeds().is_empty());
        assert!(Network::Testnet3.dns_seeds().is_empty()); // deprecated
        assert!(!Network::Testnet4.dns_seeds().is_empty());
        assert!(Network::Regtest.dns_seeds().is_empty());
        assert!(!Network::Signet.dns_seeds().is_empty());
    }

    #[test]
    fn network_genesis_hash() {
        assert!(!Network::Mainnet.genesis_hash().is_empty());
        assert!(!Network::Regtest.genesis_hash().is_empty());
    }

    #[test]
    fn network_display() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Testnet3.to_string(), "testnet3");
        assert_eq!(Network::Testnet4.to_string(), "testnet4");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Signet.to_string(), "signet");
    }

    #[test]
    fn network_from_str() {
        assert_eq!(Network::from_str("mainnet").unwrap(), Network::Mainnet);
        assert_eq!(Network::from_str("main").unwrap(), Network::Mainnet);
        assert_eq!(Network::from_str("testnet3").unwrap(), Network::Testnet3);
        assert_eq!(Network::from_str("testnet4").unwrap(), Network::Testnet4);
        assert_eq!(Network::from_str("testnet").unwrap(), Network::Testnet4);
        assert_eq!(Network::from_str("regtest").unwrap(), Network::Regtest);
        assert_eq!(Network::from_str("signet").unwrap(), Network::Signet);
        assert!(Network::from_str("unknown").is_err());
        assert!(Network::from_str("").is_err());
    }

    #[test]
    fn consensus_params_pow_fields() {
        let main = Network::Mainnet.consensus_params();
        // Mainnet pow_limit starts with 00000000ff...
        assert_eq!(main.pow_limit[0..4], [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(main.pow_limit[4], 0xff);
        assert!(!main.pow_allow_min_difficulty_blocks);
        assert!(!main.pow_no_retargeting);

        let test = Network::Testnet4.consensus_params();
        assert_eq!(test.pow_limit[0..4], [0x00, 0x00, 0x00, 0x00]);
        assert!(test.pow_allow_min_difficulty_blocks);
        assert!(!test.pow_no_retargeting);

        let reg = Network::Regtest.consensus_params();
        assert_eq!(reg.pow_limit[0], 0x7f);
        assert!(reg.pow_allow_min_difficulty_blocks);
        assert!(reg.pow_no_retargeting);

        let sig = Network::Signet.consensus_params();
        assert_eq!(sig.pow_limit[0..3], [0x00, 0x00, 0x03]);
        assert!(!sig.pow_allow_min_difficulty_blocks);
        assert!(!sig.pow_no_retargeting);
    }

    #[test]
    fn consensus_params_chain_work_assume_valid() {
        let main = Network::Mainnet.consensus_params();
        // Mainnet minimum_chain_work is non-zero
        assert_ne!(main.minimum_chain_work, [0u8; 32]);
        // Mainnet default_assume_valid is non-zero
        assert_ne!(main.default_assume_valid, [0u8; 32]);

        let test = Network::Testnet4.consensus_params();
        assert_ne!(test.minimum_chain_work, [0u8; 32]);
        assert_ne!(test.default_assume_valid, [0u8; 32]);

        // Regtest uses zeros (no minimum work, no assume-valid)
        let reg = Network::Regtest.consensus_params();
        assert_eq!(reg.minimum_chain_work, [0u8; 32]);
        assert_eq!(reg.default_assume_valid, [0u8; 32]);

        let sig = Network::Signet.consensus_params();
        assert_ne!(sig.minimum_chain_work, [0u8; 32]);
        assert_ne!(sig.default_assume_valid, [0u8; 32]);
    }

    #[test]
    fn testnet3_magic_and_port() {
        assert_eq!(Network::Testnet3.magic(), [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(Network::Testnet3.default_port(), 18333);
    }

    #[test]
    fn testnet3_genesis_header() {
        let hdr = Network::Testnet3.genesis_header();
        assert_eq!(hdr.time, 1296688602);
        assert_eq!(hdr.nonce, 414098458);
        assert_eq!(hdr.bits, 0x1d00ffff);
        assert_eq!(hdr.version, 1);
    }

    #[test]
    fn testnet3_consensus_params() {
        let p = Network::Testnet3.consensus_params();
        assert_eq!(p.bip34_height, 21_111);
        assert_eq!(p.bip66_height, 330_776);
        assert_eq!(p.bip65_height, 581_885);
        assert!(p.pow_allow_min_difficulty_blocks);
        assert!(!p.pow_no_retargeting);
    }

    #[test]
    fn mainnet_script_flag_exceptions() {
        use super::script_verify::*;

        let p = Network::Mainnet.consensus_params();
        assert_eq!(p.script_flag_exceptions.len(), 2);

        // BIP16 exception block at height 170060: VERIFY_NONE (0)
        let bip16_exc = &p.script_flag_exceptions[0];
        assert_eq!(
            bip16_exc.block_hash,
            hex32(b"00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"),
        );
        assert_eq!(bip16_exc.flags_override, 0, "BIP16 exception = VERIFY_NONE");

        // Taproot exception block at height 709632: P2SH | WITNESS
        let taproot_exc = &p.script_flag_exceptions[1];
        assert_eq!(
            taproot_exc.block_hash,
            hex32(b"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"),
        );
        assert_eq!(
            taproot_exc.flags_override,
            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS,
            "Taproot exception = P2SH | WITNESS"
        );
    }

    #[test]
    fn testnet3_script_flag_exceptions() {
        let p = Network::Testnet3.consensus_params();
        assert_eq!(p.script_flag_exceptions.len(), 1);
        let bip16_exc = &p.script_flag_exceptions[0];
        assert_eq!(
            bip16_exc.block_hash,
            hex32(b"00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"),
        );
        assert_eq!(bip16_exc.flags_override, 0, "testnet3 BIP16 exception = VERIFY_NONE");
    }

    #[test]
    fn testnet4_activation_heights_all_one() {
        let p = Network::Testnet4.consensus_params();
        // Testnet4 has all soft forks active from block 1 (BIP34/65/66/112/141).
        assert_eq!(p.bip34_height, 1, "BIP34 should be 1 on testnet4");
        assert_eq!(p.bip65_height, 1, "BIP65 should be 1 on testnet4");
        assert_eq!(p.bip66_height, 1, "BIP66 should be 1 on testnet4");
        assert_eq!(p.bip112_height, 1, "BIP112 (CSV) should be 1 on testnet4");
        assert_eq!(p.bip141_height, 1, "BIP141 (SegWit) should be 1 on testnet4");
        // Taproot is ALWAYS_ACTIVE via BIP9, represented as height 0.
        assert_eq!(p.bip341_height, 0, "BIP341 (Taproot) should be 0 (always active) on testnet4");
        // No BIP16 exception on testnet4 (fresh chain).
        assert!(p.bip16_exception_hash.is_none(), "testnet4 should have no BIP16 exception");
        // BIP16 active from genesis.
        assert_eq!(p.bip16_time, 0, "BIP16 should be active from genesis on testnet4");
    }

    #[test]
    fn non_mainnet_no_script_flag_exceptions() {
        // Testnet3 has a BIP16 exception (matching Bitcoin Core).
        assert_eq!(Network::Testnet3.consensus_params().script_flag_exceptions.len(), 1);
        // Testnet4, regtest, signet have no exceptions.
        assert!(Network::Testnet4.consensus_params().script_flag_exceptions.is_empty());
        assert!(Network::Regtest.consensus_params().script_flag_exceptions.is_empty());
        assert!(Network::Signet.consensus_params().script_flag_exceptions.is_empty());
    }

    #[test]
    fn subsidy_halving_interval_per_network() {
        // Mainnet, testnet3, testnet4, signet all use 210_000
        assert_eq!(Network::Mainnet.consensus_params().subsidy_halving_interval, 210_000);
        assert_eq!(Network::Testnet3.consensus_params().subsidy_halving_interval, 210_000);
        assert_eq!(Network::Testnet4.consensus_params().subsidy_halving_interval, 210_000);
        assert_eq!(Network::Signet.consensus_params().subsidy_halving_interval, 210_000);
        // Regtest uses 150 (matching Bitcoin Core consensus.nSubsidyHalvingInterval)
        assert_eq!(Network::Regtest.consensus_params().subsidy_halving_interval, 150);
    }

    #[test]
    fn pow_target_timespan_per_network() {
        let two_weeks = 14 * 24 * 60 * 60;
        let one_day = 24 * 60 * 60;
        // Mainnet, testnet3, testnet4, signet all use two weeks
        assert_eq!(Network::Mainnet.consensus_params().pow_target_timespan, two_weeks);
        assert_eq!(Network::Testnet3.consensus_params().pow_target_timespan, two_weeks);
        assert_eq!(Network::Testnet4.consensus_params().pow_target_timespan, two_weeks);
        assert_eq!(Network::Signet.consensus_params().pow_target_timespan, two_weeks);
        // Regtest uses one day (matching Bitcoin Core consensus.nPowTargetTimespan)
        assert_eq!(Network::Regtest.consensus_params().pow_target_timespan, one_day);
    }

    #[test]
    fn enforce_bip94_per_network() {
        // Only Testnet4 enforces BIP94 by default
        assert!(!Network::Mainnet.consensus_params().enforce_bip94);
        assert!(!Network::Testnet3.consensus_params().enforce_bip94);
        assert!(Network::Testnet4.consensus_params().enforce_bip94);
        assert!(!Network::Regtest.consensus_params().enforce_bip94);
        assert!(!Network::Signet.consensus_params().enforce_bip94);
    }

    #[test]
    fn testnet3_chain_work_updated() {
        let p = Network::Testnet3.consensus_params();
        // Updated values from Bitcoin Core (as of block 4550000)
        assert_eq!(
            p.minimum_chain_work,
            hex32(b"0000000000000000000000000000000000000000000016dd270dd94fac1d7632"),
        );
        assert_eq!(
            p.default_assume_valid,
            hex32(b"0000000000000065c6c38258e201971a3fdfcc2ceee0dd6e85a6c022d45dee34"),
        );
    }

    #[test]
    fn consensus_params_genesis_hash() {
        // Each network's ConsensusParams.genesis_hash must match Network::genesis_hash()
        for net in &[Network::Mainnet, Network::Testnet3, Network::Testnet4, Network::Regtest, Network::Signet] {
            let p = net.consensus_params();
            let expected = hex32(net.genesis_hash().as_bytes());
            assert_eq!(p.genesis_hash, expected, "genesis_hash mismatch for {net}");
        }
    }

    #[test]
    fn consensus_params_bip34_hash() {
        let main = Network::Mainnet.consensus_params();
        // Mainnet BIP34 activation block hash (block 227931)
        assert_eq!(
            main.bip34_hash,
            Some(hex32(b"000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8")),
        );

        let test3 = Network::Testnet3.consensus_params();
        // Testnet3 BIP34 activation block hash (block 21111)
        assert_eq!(
            test3.bip34_hash,
            Some(hex32(b"0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8")),
        );

        // Networks where BIP34 is active from genesis/block-1 have no specific hash
        assert!(Network::Testnet4.consensus_params().bip34_hash.is_none());
        assert!(Network::Regtest.consensus_params().bip34_hash.is_none());
        assert!(Network::Signet.consensus_params().bip34_hash.is_none());
    }

    #[test]
    fn pow_target_spacing_per_network() {
        // All networks use 600 seconds (10 minutes), matching Bitcoin Core
        for net in &[Network::Mainnet, Network::Testnet3, Network::Testnet4, Network::Regtest, Network::Signet] {
            let p = net.consensus_params();
            assert_eq!(p.pow_target_spacing, 600, "pow_target_spacing should be 600 for {net}");
        }
    }

    #[test]
    fn difficulty_adjustment_interval_derived() {
        // Mainnet/testnet: 1209600 / 600 = 2016
        let main = Network::Mainnet.consensus_params();
        assert_eq!(main.difficulty_adjustment_interval(), 2016);

        // Regtest: 86400 / 600 = 144
        let reg = Network::Regtest.consensus_params();
        assert_eq!(reg.difficulty_adjustment_interval(), 144);

        // All non-regtest networks should yield 2016
        for net in &[Network::Mainnet, Network::Testnet3, Network::Testnet4, Network::Signet] {
            let p = net.consensus_params();
            assert_eq!(
                p.difficulty_adjustment_interval(), 2016,
                "difficulty_adjustment_interval should be 2016 for {net}"
            );
        }
    }

    #[test]
    fn consensus_params_min_bip9_warning_height() {
        let main = Network::Mainnet.consensus_params();
        // Mainnet: segwit height (481824) + miner confirmation window (2016)
        assert_eq!(main.min_bip9_warning_height, 483_840);

        let test3 = Network::Testnet3.consensus_params();
        // Testnet3: segwit height (834624) + miner confirmation window (2016)
        assert_eq!(test3.min_bip9_warning_height, 836_640);

        // Other networks: 0 (no suppression needed)
        assert_eq!(Network::Testnet4.consensus_params().min_bip9_warning_height, 0);
        assert_eq!(Network::Regtest.consensus_params().min_bip9_warning_height, 0);
        assert_eq!(Network::Signet.consensus_params().min_bip9_warning_height, 0);
    }
}
