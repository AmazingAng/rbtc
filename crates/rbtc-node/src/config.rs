use std::collections::HashMap;
use std::path::PathBuf;

use clap::Parser;
use rbtc_primitives::network::Network;

#[derive(Parser, Debug)]
#[command(name = "rbtc", about = "Bitcoin node written in Rust", version)]
pub struct Args {
    /// Path to configuration file (default: ~/.rbtc/rbtc.conf)
    #[arg(long = "conf", value_name = "FILE")]
    pub conf: Option<PathBuf>,

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
    /// Skips script verification for known blocks (faster than --reindex).
    #[arg(long = "reindex-chainstate", default_value_t = false)]
    pub reindex_chainstate: bool,

    /// Full re-validation from genesis: rebuilds chainstate AND re-runs
    /// script verification for every block.  Similar to Bitcoin Core's -reindex.
    /// This is slower than --reindex-chainstate but re-validates all signatures.
    #[arg(long = "reindex", default_value_t = false)]
    pub reindex: bool,

    /// Disable mempool persistence (skip dump on shutdown and load on startup).
    /// Default behaviour is to persist mempool to mempool.dat.
    #[arg(long = "no-persist-mempool", default_value_t = false)]
    pub no_persist_mempool: bool,

    /// Script precheck worker threads (0 = use rayon default).
    #[arg(long, value_name = "N", default_value = "0")]
    pub script_threads: usize,

    /// Assumevalid block hash (hex). When set, IBD may skip script verification
    /// for ancestors of this block on the active header chain.
    #[arg(long, value_name = "BLOCKHASH")]
    pub assumevalid: Option<String>,

    /// Minimum cumulative chainwork required before assumevalid can activate.
    /// Accepts decimal or 0x-prefixed hex (up to 256-bit).
    #[arg(long, value_name = "WORK", value_parser = parse_u256_work)]
    pub min_chain_work: Option<rbtc_primitives::uint256::U256>,

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

    /// Load a UTXO snapshot file (AssumeUTXO) and start from snapshot height.
    #[arg(long = "loadutxo", value_name = "FILE")]
    pub load_utxo: Option<PathBuf>,

    /// Dump the current UTXO set to a snapshot file, then exit.
    #[arg(long = "dumputxo", value_name = "FILE")]
    pub dump_utxo: Option<PathBuf>,

    /// RPC username for Basic authentication.
    #[arg(long, value_name = "USER")]
    pub rpcuser: Option<String>,

    /// RPC password for Basic authentication (plain-text; prefer --rpcauth).
    #[arg(long, value_name = "PASS")]
    pub rpcpassword: Option<String>,

    /// Pre-hashed RPC credentials in the format `username:salt$hash`
    /// where hash = hex(HMAC-SHA256(salt, password)).
    /// Can be specified multiple times for multiple users.
    #[arg(long, value_name = "USER:SALT$HASH")]
    pub rpcauth: Vec<String>,

    /// Disable the default cookie-based authentication file.
    /// When set, no `.cookie` file is written and only explicit
    /// --rpcuser/--rpcpassword or --rpcauth credentials are accepted.
    #[arg(long, default_value_t = false)]
    pub no_rpc_cookie: bool,
}

impl Args {
    pub fn data_dir(&self) -> PathBuf {
        if let Some(ref d) = self.datadir {
            return d.clone();
        }
        let home = dirs_home();
        match self.network {
            Network::Mainnet => home.join(".rbtc"),
            Network::Testnet3 => home.join(".rbtc").join("testnet3"),
            Network::Testnet4 => home.join(".rbtc").join("testnet4"),
            Network::Regtest => home.join(".rbtc").join("regtest"),
            Network::Signet => home.join(".rbtc").join("signet"),
        }
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    s.parse::<Network>()
}

fn parse_u256_work(s: &str) -> Result<rbtc_primitives::uint256::U256, String> {
    use rbtc_primitives::uint256::U256;
    let hex_str = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        hex.to_string()
    } else {
        // Decimal: parse as u128 (sufficient for CLI input)
        let val = s.parse::<u128>().map_err(|e| format!("invalid work: {e}"))?;
        return Ok(U256::from_u128(val));
    };
    // Parse hex string into U256 (big-endian hex)
    if hex_str.len() > 64 {
        return Err("chainwork hex too long (max 64 hex chars / 256 bits)".into());
    }
    let padded = format!("{:0>64}", hex_str);
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[31 - i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex: {e}"))?;
    }
    Ok(U256::from_le_bytes(bytes))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// Config file parsing (bitcoin.conf-style key=value)
// ---------------------------------------------------------------------------

/// Parse a config file into a map of key -> list of values.
///
/// Format:
/// - Lines starting with `#` (after optional whitespace) are comments.
/// - Empty / whitespace-only lines are skipped.
/// - `key=value` sets a value (whitespace around `=` is trimmed).
/// - `key` alone (no `=`) is treated as a boolean flag (`key=1`).
/// - Keys may appear multiple times (for addnode, connect, etc.).
pub fn parse_config_file(content: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, value) = if let Some(eq_pos) = trimmed.find('=') {
            let k = trimmed[..eq_pos].trim();
            let v = trimmed[eq_pos + 1..].trim();
            (k, v)
        } else {
            // Boolean flag with no value
            (trimmed, "1")
        };
        if key.is_empty() {
            continue;
        }
        // Normalise key: config files use underscores or hyphens interchangeably
        let norm_key = key.replace('_', "-");
        map.entry(norm_key).or_default().push(value.to_string());
    }
    map
}

/// Default config file path: `~/.rbtc/rbtc.conf`.
pub fn default_conf_path() -> PathBuf {
    dirs_home().join(".rbtc").join("rbtc.conf")
}

/// Determine which CLI args were explicitly provided by the user (not defaults).
fn explicit_cli_args() -> std::collections::HashSet<String> {
    let raw_args: Vec<String> = std::env::args().collect();
    let mut explicit = std::collections::HashSet::new();
    for arg in &raw_args[1..] {
        if let Some(stripped) = arg.strip_prefix("--") {
            // Handle --key=value and --key (next arg is the value)
            let key = stripped.split('=').next().unwrap_or(stripped);
            explicit.insert(key.to_string());
        }
    }
    explicit
}

impl Args {
    /// Parse CLI args and merge with config file.
    /// CLI arguments take precedence over config file values.
    pub fn parse_with_config() -> Self {
        let mut args = Args::parse();
        let explicit = explicit_cli_args();

        // Determine config file path
        let conf_path = if let Some(ref p) = args.conf {
            p.clone()
        } else {
            default_conf_path()
        };

        // Read and parse config file (missing file is not an error)
        let conf_map = match std::fs::read_to_string(&conf_path) {
            Ok(content) => {
                tracing::info!("loaded config from {}", conf_path.display());
                parse_config_file(&content)
            }
            Err(_) => {
                // Only warn if user explicitly specified --conf
                if args.conf.is_some() {
                    tracing::warn!(
                        "config file not found: {}",
                        conf_path.display()
                    );
                }
                HashMap::new()
            }
        };

        if conf_map.is_empty() {
            return args;
        }

        args.apply_config(&conf_map, &explicit);
        args
    }

    /// Parse from explicit iterator and config file content — used for testing.
    #[cfg(test)]
    pub fn parse_with_config_from<I, T>(
        cli_iter: I,
        config_content: Option<&str>,
    ) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // Collect CLI args to determine explicit set
        let cli_args: Vec<String> = cli_iter
            .into_iter()
            .map(|a| {
                let os: std::ffi::OsString = a.into();
                os.to_string_lossy().to_string()
            })
            .collect();

        let mut explicit = std::collections::HashSet::new();
        for arg in &cli_args[1..] {
            if let Some(stripped) = arg.strip_prefix("--") {
                let key = stripped.split('=').next().unwrap_or(stripped);
                explicit.insert(key.to_string());
            }
        }

        let mut args = Args::parse_from(&cli_args);

        if let Some(content) = config_content {
            let conf_map = parse_config_file(content);
            args.apply_config(&conf_map, &explicit);
        }

        args
    }

    /// Apply config file values for fields not explicitly set on CLI.
    fn apply_config(
        &mut self,
        conf: &HashMap<String, Vec<String>>,
        explicit: &std::collections::HashSet<String>,
    ) {
        // Helper: get first value for key if not in explicit set
        let get = |key: &str| -> Option<&str> {
            if explicit.contains(key) {
                return None;
            }
            conf.get(key).and_then(|v| v.first()).map(|s| s.as_str())
        };

        // Helper: get all values for key if not in explicit set (for Vec fields)
        let get_all = |key: &str| -> Option<&Vec<String>> {
            if explicit.contains(key) {
                return None;
            }
            conf.get(key)
        };

        if let Some(v) = get("network") {
            if let Ok(n) = v.parse::<Network>() {
                self.network = n;
            }
        }
        if let Some(v) = get("datadir") {
            self.datadir = Some(PathBuf::from(v));
        }
        if let Some(v) = get("max-outbound") {
            if let Ok(n) = v.parse() {
                self.max_outbound = n;
            }
        }
        if let Some(vals) = get_all("addnode") {
            if self.add_nodes.is_empty() {
                self.add_nodes = vals.clone();
            }
        }
        if let Some(v) = get("listen-port") {
            if let Ok(n) = v.parse() {
                self.listen_port = n;
            }
        }
        if let Some(v) = get("no-dns-seeds") {
            self.no_dns_seeds = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = get("log-level") {
            self.log_level = v.to_string();
        }
        if let Some(v) = get("rpc-port") {
            if let Ok(n) = v.parse() {
                self.rpc_port = n;
            }
        }
        if let Some(vals) = get_all("connect") {
            if self.connect_only.is_empty() {
                self.connect_only = vals.clone();
            }
        }
        if let Some(v) = get("wallet") {
            self.wallet = Some(PathBuf::from(v));
        }
        if let Some(v) = get("wallet-passphrase") {
            self.wallet_passphrase = v.to_string();
        }
        if let Some(v) = get("create-wallet") {
            self.create_wallet = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = get("prune") {
            if let Ok(n) = v.parse() {
                self.prune = n;
            }
        }
        if let Some(v) = get("mempool-size") {
            if let Ok(n) = v.parse() {
                self.mempool_size = n;
            }
        }
        if let Some(v) = get("utxo-cache") {
            if let Ok(n) = v.parse() {
                self.utxo_cache = n;
            }
        }
        if let Some(v) = get("reindex-chainstate") {
            self.reindex_chainstate = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = get("reindex") {
            self.reindex = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = get("no-persist-mempool") {
            self.no_persist_mempool = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = get("script-threads") {
            if let Ok(n) = v.parse() {
                self.script_threads = n;
            }
        }
        if let Some(v) = get("assumevalid") {
            self.assumevalid = Some(v.to_string());
        }
        if let Some(v) = get("check-all-scripts") {
            self.check_all_scripts = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = get("signet-challenge") {
            self.signet_challenge = Some(v.to_string());
        }
        if let Some(v) = get("script-cache-size") {
            if let Ok(n) = v.parse() {
                self.script_cache_size = n;
            }
        }
        if let Some(v) = get("ibd-global-window") {
            if let Ok(n) = v.parse() {
                self.ibd_global_window = n;
            }
        }
        if let Some(v) = get("ibd-peer-window-min") {
            if let Ok(n) = v.parse() {
                self.ibd_peer_window_min = n;
            }
        }
        if let Some(v) = get("ibd-peer-window-max") {
            if let Ok(n) = v.parse() {
                self.ibd_peer_window_max = n;
            }
        }
        if let Some(v) = get("loadutxo") {
            self.load_utxo = Some(PathBuf::from(v));
        }
        if let Some(v) = get("dumputxo") {
            self.dump_utxo = Some(PathBuf::from(v));
        }
        if let Some(v) = get("rpcuser") {
            self.rpcuser = Some(v.to_string());
        }
        if let Some(v) = get("rpcpassword") {
            self.rpcpassword = Some(v.to_string());
        }
        if let Some(vals) = get_all("rpcauth") {
            if self.rpcauth.is_empty() {
                self.rpcauth = vals.clone();
            }
        }
        if let Some(v) = get("no-rpc-cookie") {
            self.no_rpc_cookie = v == "1" || v.eq_ignore_ascii_case("true");
        }
    }
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

    #[test]
    fn parse_reindex_flag() {
        let args = Args::parse_from(["rbtc", "--reindex"]);
        assert!(args.reindex);
        // --reindex does NOT imply --reindex-chainstate
        assert!(!args.reindex_chainstate);
    }

    #[test]
    fn parse_no_persist_mempool_flag() {
        let args = Args::parse_from(["rbtc", "--no-persist-mempool"]);
        assert!(args.no_persist_mempool);
    }

    #[test]
    fn no_persist_mempool_default_false() {
        let args = Args::parse_from(["rbtc"]);
        assert!(!args.no_persist_mempool);
    }

    // -----------------------------------------------------------------------
    // Config file parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_parse_basic_key_value() {
        let content = "network=regtest\nrpc-port=18443\n";
        let map = parse_config_file(content);
        assert_eq!(map["network"], vec!["regtest"]);
        assert_eq!(map["rpc-port"], vec!["18443"]);
    }

    #[test]
    fn config_parse_comments_and_blank_lines() {
        let content = "\
# This is a comment
   # indented comment

network=testnet3

# another comment
rpc-port=18332
";
        let map = parse_config_file(content);
        assert_eq!(map.len(), 2);
        assert_eq!(map["network"], vec!["testnet3"]);
        assert_eq!(map["rpc-port"], vec!["18332"]);
    }

    #[test]
    fn config_parse_whitespace_around_equals() {
        let content = "network = regtest\n  rpc-port  =  18443  \n";
        let map = parse_config_file(content);
        assert_eq!(map["network"], vec!["regtest"]);
        assert_eq!(map["rpc-port"], vec!["18443"]);
    }

    #[test]
    fn config_parse_boolean_flag_no_value() {
        let content = "no-dns-seeds\nreindex\n";
        let map = parse_config_file(content);
        assert_eq!(map["no-dns-seeds"], vec!["1"]);
        assert_eq!(map["reindex"], vec!["1"]);
    }

    #[test]
    fn config_parse_multiple_values() {
        let content = "addnode=1.2.3.4:8333\naddnode=5.6.7.8:8333\n";
        let map = parse_config_file(content);
        assert_eq!(map["addnode"].len(), 2);
        assert_eq!(map["addnode"][0], "1.2.3.4:8333");
        assert_eq!(map["addnode"][1], "5.6.7.8:8333");
    }

    #[test]
    fn config_parse_underscore_normalisation() {
        let content = "rpc_port=9999\nmax_outbound=12\n";
        let map = parse_config_file(content);
        assert_eq!(map["rpc-port"], vec!["9999"]);
        assert_eq!(map["max-outbound"], vec!["12"]);
    }

    #[test]
    fn config_parse_empty_content() {
        let map = parse_config_file("");
        assert!(map.is_empty());

        let map2 = parse_config_file("  \n\n  # only comments\n");
        assert!(map2.is_empty());
    }

    #[test]
    fn config_apply_basic() {
        let args = Args::parse_with_config_from(
            ["rbtc"],
            Some("network=regtest\nrpc-port=18443\nlog-level=debug\n"),
        );
        assert_eq!(args.network, Network::Regtest);
        assert_eq!(args.rpc_port, 18443);
        assert_eq!(args.log_level, "debug");
    }

    #[test]
    fn config_cli_overrides_config_file() {
        let args = Args::parse_with_config_from(
            ["rbtc", "--network", "signet", "--rpc-port", "38332"],
            Some("network=regtest\nrpc-port=18443\nlog-level=debug\n"),
        );
        // CLI wins for network and rpc-port
        assert_eq!(args.network, Network::Signet);
        assert_eq!(args.rpc_port, 38332);
        // Config file applies for log-level (not on CLI)
        assert_eq!(args.log_level, "debug");
    }

    #[test]
    fn config_apply_boolean_flags() {
        let args = Args::parse_with_config_from(
            ["rbtc"],
            Some("no-dns-seeds=1\nreindex=true\n"),
        );
        assert!(args.no_dns_seeds);
        assert!(args.reindex);
    }

    #[test]
    fn config_apply_addnode() {
        let args = Args::parse_with_config_from(
            ["rbtc"],
            Some("addnode=1.2.3.4:8333\naddnode=5.6.7.8:8333\n"),
        );
        assert_eq!(args.add_nodes.len(), 2);
        assert_eq!(args.add_nodes[0], "1.2.3.4:8333");
        assert_eq!(args.add_nodes[1], "5.6.7.8:8333");
    }

    #[test]
    fn config_apply_datadir() {
        let args = Args::parse_with_config_from(
            ["rbtc"],
            Some("datadir=/tmp/mybtc\n"),
        );
        assert_eq!(args.datadir, Some(PathBuf::from("/tmp/mybtc")));
    }

    #[test]
    fn config_apply_prune_mempool_utxo() {
        let args = Args::parse_with_config_from(
            ["rbtc"],
            Some("prune=1000\nmempool-size=100\nutxo-cache=512\n"),
        );
        assert_eq!(args.prune, 1000);
        assert_eq!(args.mempool_size, 100);
        assert_eq!(args.utxo_cache, 512);
    }

    #[test]
    fn config_no_file_returns_defaults() {
        let args = Args::parse_with_config_from(["rbtc"], None);
        assert_eq!(args.network, Network::Mainnet);
        assert_eq!(args.rpc_port, 8332);
    }

    #[test]
    fn config_file_roundtrip_with_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("rbtc.conf");
        std::fs::write(
            &conf_path,
            "network=regtest\nrpc-port=18443\naddnode=127.0.0.1:18444\n",
        )
        .unwrap();

        // Verify we can parse the file we wrote
        let content = std::fs::read_to_string(&conf_path).unwrap();
        let map = parse_config_file(&content);
        assert_eq!(map["network"], vec!["regtest"]);
        assert_eq!(map["rpc-port"], vec!["18443"]);
        assert_eq!(map["addnode"], vec!["127.0.0.1:18444"]);
    }

    #[test]
    fn config_default_conf_path() {
        let p = default_conf_path();
        assert!(p.to_string_lossy().ends_with("rbtc.conf"));
        assert!(p.to_string_lossy().contains(".rbtc"));
    }

    #[test]
    fn config_apply_rpc_auth_fields() {
        let args = Args::parse_with_config_from(
            ["rbtc"],
            Some("rpcuser=alice\nrpcpassword=secret123\nrpcauth=bob:abc$def\n"),
        );
        assert_eq!(args.rpcuser, Some("alice".to_string()));
        assert_eq!(args.rpcpassword, Some("secret123".to_string()));
        assert_eq!(args.rpcauth, vec!["bob:abc$def"]);
    }

    #[test]
    fn config_apply_connect_only() {
        let args = Args::parse_with_config_from(
            ["rbtc"],
            Some("connect=10.0.0.1:8333\nconnect=10.0.0.2:8333\n"),
        );
        assert_eq!(args.connect_only.len(), 2);
        assert_eq!(args.connect_only[0], "10.0.0.1:8333");
    }
}
