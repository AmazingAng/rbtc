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

    /// Connect to only these nodes (disables all other connection attempts)
    #[arg(long = "connect", value_name = "HOST:PORT")]
    pub connect_only: Vec<String>,
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
