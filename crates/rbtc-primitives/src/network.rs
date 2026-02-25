/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet4,
    Regtest,
    Signet,
}

impl Network {
    /// P2P magic bytes for this network
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet  => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Regtest  => [0xfa, 0xbf, 0xb5, 0xda],
            Network::Signet   => [0x0a, 0x03, 0xcf, 0x40],
        }
    }

    /// Default P2P port
    pub fn default_port(&self) -> u16 {
        match self {
            Network::Mainnet  => 8333,
            Network::Testnet4 => 48333,
            Network::Regtest  => 18444,
            Network::Signet   => 38333,
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
            Network::Testnet4 => &[
                "seed.testnet4.bitcoin.sprovoost.nl",
            ],
            Network::Regtest => &[],
            Network::Signet  => &["seed.signet.bitcoin.sprovoost.nl"],
        }
    }

    /// Genesis block hash
    pub fn genesis_hash(&self) -> &'static str {
        match self {
            Network::Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            Network::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            Network::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            Network::Signet  => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet  => write!(f, "mainnet"),
            Network::Testnet4 => write!(f, "testnet4"),
            Network::Regtest  => write!(f, "regtest"),
            Network::Signet   => write!(f, "signet"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" | "main"     => Ok(Network::Mainnet),
            "testnet4" | "testnet" => Ok(Network::Testnet4),
            "regtest"              => Ok(Network::Regtest),
            "signet"               => Ok(Network::Signet),
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
