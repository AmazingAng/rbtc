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

    /// Maximum mempool size in megabytes (default 300 MB).
    /// When the limit is exceeded, the lowest-fee-rate transactions are evicted.
    #[arg(long, value_name = "MB", default_value = "300")]
    pub mempool_size: u64,

    /// UTXO hot-cache size in megabytes.
    /// Core-style lazy cache: misses always fall back to RocksDB.
    /// 0 = unlimited in-memory hot cache (not recommended on constrained hosts).
    #[arg(long, value_name = "MB", default_value = "2048")]
    pub utxo_cache: u64,

    /// Rebuild chainstate (UTXO + tip metadata) from stored blocks and indices.
    /// Similar to Bitcoin Core's -reindex-chainstate.
    #[arg(long = "reindex-chainstate", default_value_t = false)]
    pub reindex_chainstate: bool,

    /// Script precheck worker threads (0 = use rayon default).
    #[arg(long, value_name = "N", default_value = "0")]
    pub script_threads: usize,

    /// Assumevalid block hash (hex). When set, IBD may skip script verification
    /// for ancestors of this block on the active header chain.
    #[arg(long, value_name = "BLOCKHASH")]
    pub assumevalid: Option<String>,

    /// Minimum cumulative chainwork required before assumevalid can activate.
    /// Accepts decimal or 0x-prefixed hex.
    #[arg(long, value_name = "WORK", value_parser = parse_u128_work)]
    pub min_chain_work: Option<u128>,

    /// Always verify all scripts (disables assumevalid skip path).
    #[arg(long, default_value_t = false)]
    pub check_all_scripts: bool,

    /// Custom signet challenge script (hex). Overrides the default signet
    /// challenge. Only used when --network=signet.
    #[arg(long, value_name = "HEX")]
    pub signet_challenge: Option<String>,

    /// Script execution cache size (entries). 0 disables script execution cache.
    #[arg(long, value_name = "N", default_value = "100000")]
    pub script_cache_size: usize,

    /// Fixed global IBD window ahead of tip. 0 enables adaptive mode.
    #[arg(long, value_name = "N", default_value = "0")]
    pub ibd_global_window: u32,

    /// Per-peer IBD in-flight window minimum.
    #[arg(long, value_name = "N", default_value = "4")]
    pub ibd_peer_window_min: u32,

    /// Per-peer IBD in-flight window maximum.
    #[arg(long, value_name = "N", default_value = "24")]
    pub ibd_peer_window_max: u32,
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

fn parse_u128_work(s: &str) -> Result<u128, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).map_err(|e| format!("invalid hex work: {e}"))
    } else {
        s.parse::<u128>().map_err(|e| format!("invalid work: {e}"))
    }
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

    #[test]
    fn parse_reindex_chainstate_flag() {
        let args = Args::parse_from(["rbtc", "--reindex-chainstate"]);
        assert!(args.reindex_chainstate);
    }
}
