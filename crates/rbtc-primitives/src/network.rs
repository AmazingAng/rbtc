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
}

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet4,
    Regtest,
    Signet,
}

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
            },
            Network::Testnet4 => ConsensusParams {
                bip16_time: 1329264000,
                bip34_height: 21_111,
                bip66_height: 330_776,
                bip65_height: 581_885,
                bip112_height: 0,
                bip141_height: 0,
                bip341_height: 0,
                bip16_exception_hash: Some(
                    "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105",
                ),
                taproot_exception_hash: None,
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
            },
        }
    }

    /// P2P magic bytes for this network
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
            Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
        }
    }

    /// Default P2P port
    pub fn default_port(&self) -> u16 {
        match self {
            Network::Mainnet => 8333,
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
            Network::Testnet4 => &["seed.testnet4.bitcoin.sprovoost.nl"],
            Network::Regtest => &[],
            Network::Signet => &["seed.signet.bitcoin.sprovoost.nl"],
        }
    }

    /// Genesis block hash
    pub fn genesis_hash(&self) -> &'static str {
        match self {
            Network::Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            Network::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            Network::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            Network::Signet => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
        }
    }

    /// Returns the genesis block header for this network.
    pub fn genesis_header(&self) -> crate::block::BlockHeader {
        use crate::block::BlockHeader;
        use crate::hash::Hash256;

        match self {
            Network::Mainnet => BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::from_hex(
                    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                )
                .unwrap_or(Hash256::ZERO),
                time: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            Network::Testnet4 => BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
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
                prev_block: Hash256::ZERO,
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
                prev_block: Hash256::ZERO,
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
        assert_eq!(Network::Testnet4.magic(), [0x1c, 0x16, 0x3f, 0x28]);
        assert_eq!(Network::Regtest.magic(), [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(Network::Signet.magic(), [0x0a, 0x03, 0xcf, 0x40]);
    }

    #[test]
    fn network_default_port() {
        assert_eq!(Network::Mainnet.default_port(), 8333);
        assert_eq!(Network::Testnet4.default_port(), 48333);
        assert_eq!(Network::Regtest.default_port(), 18444);
        assert_eq!(Network::Signet.default_port(), 38333);
    }

    #[test]
    fn network_dns_seeds() {
        assert!(!Network::Mainnet.dns_seeds().is_empty());
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
        assert_eq!(Network::Testnet4.to_string(), "testnet4");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Signet.to_string(), "signet");
    }

    #[test]
    fn network_from_str() {
        assert_eq!(Network::from_str("mainnet").unwrap(), Network::Mainnet);
        assert_eq!(Network::from_str("main").unwrap(), Network::Mainnet);
        assert_eq!(Network::from_str("testnet4").unwrap(), Network::Testnet4);
        assert_eq!(Network::from_str("testnet").unwrap(), Network::Testnet4);
        assert_eq!(Network::from_str("regtest").unwrap(), Network::Regtest);
        assert_eq!(Network::from_str("signet").unwrap(), Network::Signet);
        assert!(Network::from_str("unknown").is_err());
        assert!(Network::from_str("").is_err());
    }
}
