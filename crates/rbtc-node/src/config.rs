use std::path::PathBuf;

use clap::Parser;
use rbtc_primitives::network::Network;

#[derive(Parser, Debug)]
#[command(name = "rbtc", about = "Bitcoin node written in Rust", version)]
pub struct Args {
    /// Bitcoin network to connect to
    #[arg(
        long,
        default_value = "mainnet",
        value_parser = parse_network
    )]
    pub network: Network,

    /// Data directory for blockchain storage
    #[arg(long, value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    /// Maximum number of outbound peer connections
    #[arg(long, default_value = "8")]
    pub max_outbound: usize,

    /// Additional seed nodes to connect to (host:port)
    #[arg(long = "addnode", value_name = "HOST:PORT")]
    pub add_nodes: Vec<String>,

    /// Listen port for inbound connections (0 = disabled)
    #[arg(long, default_value = "0")]
    pub listen_port: u16,

    /// Disable DNS seed lookup
    #[arg(long)]
    pub no_dns_seeds: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// JSON-RPC server port (0 = disabled)
    #[arg(long, default_value = "8332")]
    pub rpc_port: u16,

    /// Connect to only these nodes (disables all other connection attempts)
    #[arg(long = "connect", value_name = "HOST:PORT")]
    pub connect_only: Vec<String>,

    /// Path to the wallet file (defaults to $datadir/wallet.dat).
    /// If not specified the node runs without a wallet.
    #[arg(long, value_name = "FILE")]
    pub wallet: Option<std::path::PathBuf>,

    /// Passphrase for wallet encryption / decryption.
    #[arg(long, value_name = "PASS", default_value = "")]
    pub wallet_passphrase: String,

    /// Generate a new wallet and print the mnemonic, then exit.
    #[arg(long)]
    pub create_wallet: bool,

    /// Enable block pruning.  Specify the target disk budget in MiB for raw
    /// block data (minimum 550 MiB, Bitcoin Core convention).
    /// 0 = disabled (keep all block data, the default).
    ///
    /// When pruning is enabled the node deletes `CF_BLOCK_DATA` for blocks
    /// more than 288 confirmations deep (~2 days of blocks).  Block headers,
    /// UTXO set, tx-index, and addr-index are never pruned.
    /// Note: `getrawtransaction` will return an error for pruned blocks.
    #[arg(long, value_name = "MiB", default_value = "0")]
    pub prune: u64,
}

impl Args {
    pub fn data_dir(&self) -> PathBuf {
        if let Some(ref d) = self.datadir {
            return d.clone();
        }
        let home = dirs_home();
        match self.network {
            Network::Mainnet  => home.join(".rbtc"),
            Network::Testnet4 => home.join(".rbtc").join("testnet4"),
            Network::Regtest  => home.join(".rbtc").join("regtest"),
            Network::Signet   => home.join(".rbtc").join("signet"),
        }
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    s.parse::<Network>()
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_mainnet() {
        let args = Args::parse_from(["rbtc", "--network", "mainnet"]);
        assert_eq!(args.network, Network::Mainnet);
    }

    #[test]
    fn parse_network_regtest() {
        let args = Args::parse_from(["rbtc", "--network", "regtest"]);
        assert_eq!(args.network, Network::Regtest);
    }

    #[test]
    fn data_dir_default() {
        let args = Args::parse_from(["rbtc"]);
        let d = args.data_dir();
        assert!(d.to_string_lossy().contains("rbtc"));
    }

    #[test]
    fn parse_addnode() {
        let args = Args::parse_from(["rbtc", "--addnode", "127.0.0.1:18444"]);
        assert_eq!(args.add_nodes.len(), 1);
        assert_eq!(args.add_nodes[0], "127.0.0.1:18444");
    }
}
