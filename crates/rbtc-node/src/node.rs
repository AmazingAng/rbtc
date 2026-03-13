use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    os::unix::io::AsRawFd,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use tokio::sync::{mpsc, watch, RwLock};
use tracing::{debug, error, info, warn};

use rbtc_consensus::{
    block_verify::{check_block, connect_block_with_options, BlockValidationContext},
    chain::{header_hash, BlockIndex, BlockStatus, ChainState},
    script_flags_for_block,
    tx_verify::MedianTimeProvider,
};
use rbtc_primitives::block_status::{
    BLOCK_VALID_SCRIPTS, BLOCK_VALID_TRANSACTIONS, BLOCK_VALID_TREE,
};
use rbtc_crypto::sha256d;
use rbtc_mempool::Mempool;
use rbtc_net::{
    block_download::BlockDownloadTracker,
    compact::{reconstruct_block, short_txid, CompactBlock, GetBlockTxn},
    message::{InvType, Inventory, NetworkMessage},
    peer_manager::{NodeEvent, PeerManager, PeerManagerConfig, BAN_DURATION},
};
use rbtc_primitives::codec::Encodable;
use rbtc_primitives::hash::{BlockHash, Txid};
use rbtc_primitives::uint256::U256;
use rbtc_storage::{
    decode_block_undo, encode_block_undo, AddrIndexStore,
    BlockStore, ChainStore, Database, PeerStore, StoredBlockIndex, StoredUtxo, TxIndexStore,
    UtxoStore,
};
use rbtc_miner::LongPollState;
use rbtc_wallet::Wallet;

use crate::{
    config::Args,
    headers_sync::{HeadersSyncState, ProcessResult, SyncPhase},
    ibd::{build_locator, IbdPhase, IbdState, SEGMENT_SIZE, STALL_TIMEOUT},
    rpc::{start_rpc_server, RpcNodeCommand, RpcState},
    utxo_cache::CachedUtxoSet,
    validation_interface::{MempoolRemovalReason, ValidationEvent, ValidationNotifier},
};

/// Peer ID used when a block is submitted locally (via RPC).
const LOCAL_PEER_ID: u64 = 0;
const INDEX_BATCH_SIZE: usize = 64;
const INDEX_QUEUE_FILL_CHUNK: u32 = 512;
const UTXO_EVICT_INTERVAL_BLOCKS: u32 = 16;
/// How often to check for extra outbound peers to evict (Bitcoin Core: 45s).
const EVICT_EXTRA_OUTBOUND_INTERVAL: Duration = Duration::from_secs(45);
const MIN_DYNAMIC_GLOBAL_WINDOW_BLOCKS: u32 = 256;
const MAX_DYNAMIC_GLOBAL_WINDOW_BLOCKS: u32 = 4096;
const ADAPTIVE_TIMEOUT_SOFT: Duration = Duration::from_secs(20);
const ADAPTIVE_TIMEOUT_HARD: Duration = Duration::from_secs(45);

#[derive(Clone, Copy)]
struct IndexTask {
    height: u32,
    block_hash: BlockHash,
}

struct IndexBatchOutcome {
    processed: usize,
    last_indexed_height: Option<u32>,
    retry_tasks: Vec<IndexTask>,
}

#[derive(Default, Clone, Copy)]
struct PeerIbdStats {
    delivered_blocks: u64,
    timeout_strikes: u32,
    last_delivery_at: Option<Instant>,
    delivery_interval_ema_ms: f64,
}

struct ChainMtpProvider<'a> {
    chain: &'a ChainState,
}

impl MedianTimeProvider for ChainMtpProvider<'_> {
    fn median_time_past_at_height(&self, height: u32) -> u32 {
        self.chain.median_time_past(height)
    }
}

/// The main Bitcoin node
pub struct Node {
    args: Args,
    /// Process lock file held for the lifetime of the node to prevent
    /// multiple instances from using the same data directory concurrently.
    /// The advisory lock is released automatically when this `File` is dropped.
    _lock_file: std::fs::File,
    db: Arc<Database>,
    /// Chain state, shared with the RPC server via Arc<RwLock>
    chain: Arc<RwLock<ChainState>>,
    /// Mempool, shared with the RPC server via Arc<RwLock>
    mempool: Arc<RwLock<Mempool>>,
    /// Optional HD wallet, shared with the RPC server via Arc<RwLock>
    wallet: Option<Arc<RwLock<Wallet>>>,
    ibd: IbdState,
    /// Canonical header chain built from block_index when entering block-download
    /// phase. Maps height → block hash. Empty until all headers are downloaded.
    canonical_header_chain: Vec<BlockHash>,
    /// Write-back UTXO cache (hot + dirty layers with RocksDB fallback).
    /// Used unconditionally for verification, mempool admission and block
    /// connection state transitions.
    utxo_cache: CachedUtxoSet,
    peer_manager: PeerManager,
    node_event_rx: mpsc::UnboundedReceiver<NodeEvent>,
    /// Sender half given to the RPC server for `submitblock` / `generatetoaddress`.
    submit_block_tx: mpsc::UnboundedSender<rbtc_primitives::block::Block>,
    /// Receiver for blocks submitted via the RPC `submitblock` / `generatetoaddress`.
    submit_block_rx: mpsc::UnboundedReceiver<rbtc_primitives::block::Block>,
    /// Receiver for node-management commands coming from RPC layer.
    rpc_control_rx: mpsc::UnboundedReceiver<RpcNodeCommand>,
    /// Sender passed to RPC layer for node-management commands.
    rpc_control_tx: mpsc::UnboundedSender<RpcNodeCommand>,
    /// BIP152: partially-reconstructed compact blocks awaiting `blocktxn` responses.
    /// Key = block_hash, Value = (compact block, list of already-filled tx slots).
    pending_compact: HashMap<
        rbtc_primitives::hash::Hash256,
        (
            CompactBlock,
            Vec<Option<rbtc_primitives::transaction::Transaction>>,
        ),
    >,
    /// Out-of-order blocks received during parallel IBD, waiting for predecessors.
    /// Key = block height, Value = candidate blocks for that height.
    /// We keep multiple candidates to avoid dropping the valid chain block when
    /// an alternative block at the same height arrives first.
    pending_blocks: HashMap<u32, Vec<(u64, rbtc_primitives::block::Block)>>,
    /// Timestamp of last peer address persistence flush
    last_peer_persist: std::time::Instant,
    /// Peers that have been asked to disconnect but haven't emitted
    /// `PeerDisconnected` yet. Excluded from new IBD assignments.
    disconnecting_peers: HashSet<u64>,
    /// Deferred index tasks processed by a background worker.
    index_queue: VecDeque<IndexTask>,
    /// Catch-up replay range for deferred indexing after IBD completes.
    index_catchup_next_height: Option<u32>,
    index_catchup_target_height: u32,
    index_catchup_initialized: bool,
    /// JoinHandle for currently-running background index write task.
    index_worker: Option<tokio::task::JoinHandle<anyhow::Result<IndexBatchOutcome>>>,
    /// Throttle hot-cache eviction; evicting every block is expensive at high heights.
    blocks_since_utxo_evict: u32,
    /// Optional assumevalid block hash (Core-style IBD scriptcheck fast path).
    assumevalid_hash: Option<BlockHash>,
    /// Optional minimum cumulative chain work required before assumevalid activates.
    min_chain_work: Option<U256>,
    /// Force full script verification even when assumevalid is set.
    check_all_scripts: bool,
    /// Log guard to avoid spamming assumevalid activation message.
    assumevalid_announced: bool,
    /// Metrics for assumevalid effectiveness.
    assumevalid_skipped_blocks: u64,
    assumevalid_saved_verify_ms: u128,
    assumevalid_last_height: Option<u32>,
    /// Optional custom signet challenge script (from --signet-challenge).
    signet_challenge: Option<Vec<u8>>,
    /// Per-peer delivery/timeout stats for adaptive IBD scheduling.
    peer_ibd_stats: HashMap<u64, PeerIbdStats>,
    /// Global block download tracker with stall detection and exponential backoff.
    block_tracker: BlockDownloadTracker,
    /// Orphan transaction pool for txs with missing inputs.
    orphan_pool: rbtc_mempool::OrphanPool,
    /// GBT long-poll state shared with the RPC server (BIP22).
    longpoll: Arc<LongPollState>,
    /// Broadcast-based validation event notifier (CValidationInterface equivalent).
    notifier: ValidationNotifier,
    /// Hardcoded checkpoints for header validation (M25).
    checkpoints: crate::checkpoints::Checkpoints,
    /// Shared IBD flag readable from RPC without holding the node lock.
    is_ibd: Arc<std::sync::atomic::AtomicBool>,
    /// Watch channel sender for new-tip notifications (used by `waitfornewblock` RPC).
    new_tip_tx: watch::Sender<(String, u32)>,
}

impl Node {
    /// Subscribe to validation events (block connected/disconnected, mempool
    /// changes, tip updates, chain state flushes).
    pub fn subscribe_validation_events(&self) -> tokio::sync::broadcast::Receiver<ValidationEvent> {
        self.notifier.subscribe()
    }

    fn is_block_connected(chain: &ChainState, hash: &BlockHash) -> bool {
        let Some(bi) = chain.block_index.get(hash) else {
            return false;
        };
        chain.active_chain.get(bi.height as usize).copied() == Some(*hash)
    }

    pub async fn new(args: Args) -> Result<Self> {
        let data_dir = args.data_dir();
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create data dir: {data_dir:?}"))?;

        info!("data directory: {data_dir:?}");

        // Acquire an exclusive advisory lock on a lock file inside the data
        // directory.  This prevents a second node process from accidentally
        // using the same data directory, which would corrupt the database.
        // The lock is held for the entire lifetime of the `Node` (the `File`
        // handle lives in `self._lock_file`) and is released automatically
        // when the handle is dropped during shutdown.
        let lock_path = data_dir.join("rbtc.pid");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open lock file: {lock_path:?}"))?;

        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                anyhow::bail!(
                    "another rbtc instance is already running with data directory {data_dir:?}"
                );
            }
            return Err(err)
                .with_context(|| format!("failed to lock {lock_path:?}"));
        }

        // Write our PID so operators can identify the owning process.
        use std::io::Write as _;
        lock_file.set_len(0).ok();
        (&lock_file)
            .write_all(format!("{}\n", std::process::id()).as_bytes())
            .ok();

        info!("process lock acquired: {lock_path:?} (pid {})", std::process::id());

        let db_path = data_dir.join("chaindata");
        let db = Arc::new(
            Database::open(&db_path)
                .with_context(|| format!("failed to open database at {db_path:?}"))?,
        );
        info!("database opened at {db_path:?}");

        // Disk space warning at startup
        if let Some(avail) = check_disk_space(&data_dir) {
            if avail < MIN_DISK_SPACE_WARNING {
                warn!(
                    "low disk space: only {} MiB available in {}",
                    avail / 1_048_576,
                    data_dir.display()
                );
            } else {
                info!("disk space: {} MiB available", avail / 1_048_576);
            }
        }

        // Check UTXO format version — require reindex if legacy (like Bitcoin Core NeedsUpgrade)
        {
            let chain_store = rbtc_storage::chain_store::ChainStore::new(&db);
            let utxo_format = chain_store.get_utxo_format()?;
            if args.reindex {
                // Full reindex: rebuild UTXO AND re-verify all scripts from genesis
                reindex_chainstate_full(&db, args.network, true)?;
            } else if args.reindex_chainstate {
                reindex_chainstate_full(&db, args.network, false)?;
            } else if utxo_format.is_none() {
                // Check if there is existing chain data (empty/fresh DB is fine)
                let has_chain_data = chain_store.get_best_height()?.is_some();
                if has_chain_data {
                    anyhow::bail!(
                        "UTXO database uses legacy format. \
                         Run with --reindex-chainstate to upgrade to compressed format."
                    );
                }
                // Fresh DB — mark as compressed from the start
                chain_store.set_utxo_format(
                    rbtc_storage::chain_store::UTXO_FORMAT_COMPRESSED,
                )?;
            } else {
                // Even if utxo_format is set, detect old key encoding (4-byte LE vout
                // vs VARINT). Mirrors Bitcoin Core's NeedsUpgrade() which checks for
                // deprecated key prefixes on every startup.
                let utxo_store = rbtc_storage::UtxoStore::new(&db);
                if utxo_store.needs_key_upgrade() {
                    anyhow::bail!(
                        "UTXO database uses legacy key encoding (4-byte LE vout). \
                         Run with --reindex-chainstate to upgrade to VARINT format."
                    );
                }
            }
        }

        // Dump UTXO snapshot and exit if requested
        if let Some(ref dump_path) = args.dump_utxo {
            let network_magic = args.network.magic();
            let meta = rbtc_storage::snapshot::write_snapshot(&db, dump_path, network_magic)
                .with_context(|| format!("failed to dump UTXO snapshot to {dump_path:?}"))?;
            info!(
                "UTXO snapshot written: {} UTXOs at height {} to {dump_path:?}",
                meta.num_utxos, meta.height
            );
            std::process::exit(0);
        }

        // Load UTXO snapshot if requested
        if let Some(ref load_path) = args.load_utxo {
            let network_magic = args.network.magic();
            let meta = rbtc_storage::snapshot::load_snapshot(&db, load_path, network_magic)
                .with_context(|| format!("failed to load UTXO snapshot from {load_path:?}"))?;
            info!(
                "UTXO snapshot loaded: {} UTXOs at height {}",
                meta.num_utxos, meta.height
            );
        }

        // Load or initialize chain state from persistent storage
        let mut chain = ChainState::new(args.network);
        load_chain_state(&mut chain, &db)?;

        info!(
            "chain state loaded: height={} tip={:?}",
            chain.height(),
            chain.best_hash().map(|h| h.to_hex())
        );

        let chain = Arc::new(RwLock::new(chain));
        // Mempool size limit: convert MB to bytes (vsize ≈ bytes for legacy txs)
        let mempool_max_vsize = args.mempool_size * 1_000_000;
        let mempool = Arc::new(RwLock::new(Mempool::with_max_vsize(mempool_max_vsize)));

        // Optionally load the wallet
        let wallet = load_wallet(&args, Arc::clone(&db));

        // Channel for RPC-submitted blocks (submitblock / generatetoaddress)
        let (submit_block_tx, submit_block_rx) = mpsc::unbounded_channel();
        // Channel for RPC node-management commands (invalidate/reconsider).
        let (rpc_control_tx, rpc_control_rx) = mpsc::unbounded_channel();

        // Create peer manager
        let (node_event_tx, node_event_rx) = mpsc::unbounded_channel();
        let pm_config = PeerManagerConfig {
            network: args.network,
            max_outbound: args.max_outbound,
            listen_port: args.listen_port,
            ..Default::default()
        };
        let current_height = chain.read().await.height() as i32;
        let mut peer_manager = PeerManager::new(pm_config, node_event_tx, current_height);

        // Load persisted peer addresses and ban list
        {
            let peer_store = PeerStore::new(&db);
            // Expire stale bans first
            peer_store.expire_bans().ok();
            // Restore addrman secret key (or generate a new one)
            if let Ok(Some(key)) = peer_store.load_addrman_key() {
                peer_manager.set_addrman_key(key);
            } else {
                // First run: persist the randomly-generated key
                peer_store.save_addrman_key(peer_manager.addrman().secret_key()).ok();
            }
            // Load addresses into addrman (try extended format first, fall back to legacy)
            if let Ok(entries) = peer_store.load_addrman_entries() {
                if !entries.is_empty() {
                    let addr_infos: Vec<rbtc_net::addrman::AddrInfo> = entries
                        .into_iter()
                        .map(|e| rbtc_net::addrman::AddrInfo {
                            addr: e.addr,
                            services: e.services,
                            last_seen: e.last_seen,
                            last_try: e.last_try,
                            last_success: e.last_success,
                            n_attempts: e.n_attempts,
                            source: e.source,
                            in_tried: e.in_tried,
                            ref_count: 0,
                        })
                        .collect();
                    peer_manager.seed_addrman(addr_infos);
                }
            }
        }

        // Build UTXO cache based on --utxo-cache flag.
        // Core-style: always lazy-load from RocksDB on misses (no full preload).
        let max_bytes = if args.utxo_cache == 0 {
            None // unlimited
        } else {
            Some(args.utxo_cache * 1_000_000)
        };
        let utxo_cache = CachedUtxoSet::new(Arc::clone(&db), max_bytes);
        info!(
            "utxo_cache: lazy mode, limit={} MB (0 = unlimited)",
            args.utxo_cache
        );

        let assumevalid_hash = match args.assumevalid.as_ref() {
            Some(h) => {
                Some(BlockHash::from_hex(h).map_err(|_| anyhow!("invalid --assumevalid hash"))?)
            }
            None => None,
        };
        let min_chain_work = args.min_chain_work;
        let check_all_scripts = args.check_all_scripts;
        let signet_challenge = args
            .signet_challenge
            .as_ref()
            .and_then(|h| hex::decode(h).ok());

        let checkpoints = match args.network {
            rbtc_primitives::network::Network::Mainnet => crate::checkpoints::Checkpoints::mainnet(),
            _ => crate::checkpoints::Checkpoints::none(),
        };

        Ok(Self {
            args,
            _lock_file: lock_file,
            db,
            chain,
            mempool,
            wallet,
            ibd: IbdState::new(),
            canonical_header_chain: Vec::new(),
            utxo_cache,
            peer_manager,
            node_event_rx,
            submit_block_tx,
            submit_block_rx,
            rpc_control_rx,
            rpc_control_tx,
            pending_compact: HashMap::new(),
            pending_blocks: HashMap::new(),
            last_peer_persist: std::time::Instant::now(),
            disconnecting_peers: HashSet::new(),
            index_queue: VecDeque::new(),
            index_catchup_next_height: None,
            index_catchup_target_height: 0,
            index_catchup_initialized: false,
            index_worker: None,
            blocks_since_utxo_evict: 0,
            assumevalid_hash,
            min_chain_work,
            check_all_scripts,
            assumevalid_announced: false,
            assumevalid_skipped_blocks: 0,
            assumevalid_saved_verify_ms: 0,
            assumevalid_last_height: None,
            signet_challenge,
            peer_ibd_stats: HashMap::new(),
            block_tracker: BlockDownloadTracker::new(),
            orphan_pool: rbtc_mempool::OrphanPool::new(),
            longpoll: Arc::new(LongPollState::new("0".repeat(64))),
            notifier: ValidationNotifier::new(),
            checkpoints,
            is_ibd: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            new_tip_tx: watch::Sender::new(("0".repeat(64), 0)),
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!("starting node on network: {}", self.args.network);

        // Start inbound connection listener if a port is configured
        self.peer_manager.start_inbound_listener().await.ok();

        // Initialise RPC authentication.
        let rpc_auth = crate::rpc_auth::init_rpc_auth(
            &self.args.data_dir(),
            self.args.rpcuser.as_deref(),
            self.args.rpcpassword.as_deref(),
            &self.args.rpcauth,
            self.args.no_rpc_cookie,
        )
        .map_err(|e| anyhow::anyhow!("RPC auth init failed: {e}"))?;

        // Start JSON-RPC server
        let rpc_addr = format!("127.0.0.1:{}", self.args.rpc_port);
        let rpc_state = RpcState {
            chain: Arc::clone(&self.chain),
            mempool: Arc::clone(&self.mempool),
            db: Arc::clone(&self.db),
            network_name: self.args.network.to_string(),
            wallet: self.wallet.as_ref().map(Arc::clone),
            submit_block_tx: self.submit_block_tx.clone(),
            control_tx: self.rpc_control_tx.clone(),
            longpoll: Arc::clone(&self.longpoll),
            data_dir: self.args.data_dir(),
            prune_budget: self.args.prune,
            is_ibd: Arc::clone(&self.is_ibd),
            new_tip_rx: self.new_tip_tx.subscribe(),
        };
        tokio::spawn(async move {
            if let Err(e) = start_rpc_server(&rpc_addr, rpc_state, rpc_auth).await {
                error!("RPC server error: {e}");
            }
        });

        // Recover IBD phase from persisted chain state so that a restarted node
        // doesn't re-download headers it already has stored in block_index.
        {
            let chain = self.chain.read().await;
            let bi_height = chain
                .block_index
                .values()
                .map(|bi| bi.height)
                .max()
                .unwrap_or(0);
            let active_height = chain.height();
            drop(chain);
            if bi_height > active_height {
                // We have unconnected headers from before the restart.
                // Rebuild canonical chain and partition into download segments.
                info!(
                    "detected {} unconnected headers (block_index tip={bi_height}, active_chain tip={active_height}); resuming Blocks phase",
                    bi_height - active_height
                );
                self.ibd.phase = IbdPhase::Blocks;
                // build_canonical_header_chain also calls partition_ranges.
                self.build_canonical_header_chain().await;
            } else if active_height > 0 {
                // Verify that actual block data exists (not just headers).
                // An old or incompatible DB might have headers indexed but no
                // block data, making the chain hollow.
                let has_block_data = {
                    let chain = self.chain.read().await;
                    let tip_hash = chain.best_tip.unwrap_or(BlockHash::ZERO);
                    drop(chain);
                    let block_store = BlockStore::new(&self.db);
                    block_store.has_block(&tip_hash).unwrap_or(false)
                };
                if has_block_data {
                    info!("chain tip={active_height}; checking if fully synced");
                } else {
                    // Headers exist but block data is missing. Reset active
                    // chain to genesis so block download covers the full range.
                    warn!(
                        "chain tip={active_height} but block data missing; \
                         resetting active chain and resuming Blocks phase"
                    );
                    {
                        let mut chain = self.chain.write().await;
                        let genesis = chain
                            .active_chain
                            .first()
                            .copied()
                            .unwrap_or(BlockHash::ZERO);
                        // Reset block statuses: clear data flags since block
                        // data is missing.
                        for bi in chain.block_index.values_mut() {
                            bi.status = BlockStatus::new().with_validity(BLOCK_VALID_TREE);
                        }
                        chain.active_chain.clear();
                        chain.active_chain.push(genesis);
                        chain.best_tip = None;
                    }
                    self.ibd.phase = IbdPhase::Blocks;
                    self.build_canonical_header_chain().await;
                }
            }
        }

        // Load persisted mempool from disk (unless --no-persist-mempool)
        if !self.args.no_persist_mempool {
            let mempool_path = self.args.data_dir().join("mempool.dat");
            match rbtc_mempool::load_mempool(&mempool_path) {
                Ok(Some(loaded)) => {
                    let chain_height = self.chain.read().await.height();
                    let mut mempool = self.mempool.write().await;
                    let mut accepted = 0usize;
                    let total = loaded.entries.len();

                    // Apply extra fee deltas first
                    for fd in &loaded.fee_deltas {
                        mempool.prioritise_transaction(fd.txid, fd.delta);
                    }

                    // Re-validate each transaction against current UTXO set
                    for entry in loaded.entries {
                        if entry.fee_delta != 0 {
                            let txid = *entry.tx.txid();
                            mempool.prioritise_transaction(txid, entry.fee_delta);
                        }
                        match mempool.accept_tx(
                            entry.tx,
                            &self.utxo_cache,
                            chain_height,
                        ) {
                            Ok(_) => accepted += 1,
                            Err(_) => {} // silently skip stale/invalid txs
                        }
                    }
                    info!("loaded {accepted}/{total} mempool transactions from {}", mempool_path.display());
                }
                Ok(None) => {} // no file, nothing to load
                Err(e) => warn!("failed to load mempool.dat: {e}"),
            }
        }

        // Connect to seeds / explicit nodes
        if !self.args.connect_only.is_empty() {
            for addr in self.args.connect_only.clone() {
                self.peer_manager.connect(&addr).await;
            }
        } else {
            if !self.args.no_dns_seeds {
                self.peer_manager.connect_to_seeds().await;
            }
            for addr in self.args.add_nodes.clone() {
                self.peer_manager.connect(&addr).await;
            }
        }

        // Main event loop
        let mut stats_timer = tokio::time::interval(Duration::from_secs(30));
        // Tick frequently during IBD so we keep the block-download pipeline full.
        let mut ibd_timer = tokio::time::interval(Duration::from_secs(1));
        let mut persist_timer = tokio::time::interval(Duration::from_secs(5 * 60));
        // Retry DNS seeds if we have no peers (e.g. after all connections drop).
        let mut seed_retry_timer = tokio::time::interval(Duration::from_secs(10));
        // Background index writer ticker.
        let mut index_timer = tokio::time::interval(Duration::from_millis(500));
        // Evict worst-performing extra outbound peers (M26, Bitcoin Core: every 45s).
        let mut evict_timer = tokio::time::interval(EVICT_EXTRA_OUTBOUND_INTERVAL);
        seed_retry_timer.tick().await; // consume the immediate first tick
        evict_timer.tick().await; // consume the immediate first tick

        // Graceful shutdown signal handling
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;

        loop {
            tokio::select! {
                _ = self.process_pending_events() => {}

                _ = stats_timer.tick() => {
                    self.log_stats().await;
                }

                _ = ibd_timer.tick() => {
                    self.check_ibd_progress().await;
                }

                _ = persist_timer.tick() => {
                    self.persist_peer_addrs();
                }

                _ = seed_retry_timer.tick() => {
                    if self.peer_manager.peer_count() == 0 && !self.args.no_dns_seeds {
                        info!("no peers; retrying DNS seeds");
                        self.peer_manager.connect_to_seeds().await;
                    }
                }

                _ = index_timer.tick() => {
                    self.tick_index_worker().await;
                }

                _ = evict_timer.tick() => {
                    self.evict_extra_outbound_peers();
                }

                _ = tokio::signal::ctrl_c() => {
                    info!("received SIGINT, initiating graceful shutdown");
                    break;
                }

                _ = sigterm.recv() => {
                    info!("received SIGTERM, initiating graceful shutdown");
                    break;
                }
            }
        }

        // Flush UTXO cache to disk before exit
        info!("flushing UTXO cache to disk...");
        let dirty_count = self.utxo_cache.dirty_len();
        if dirty_count > 0 {
            let mut batch = self.db.new_batch();
            self.utxo_cache
                .flush_dirty(&mut batch)
                .context("failed to flush UTXO cache during shutdown")?;
            self.db
                .write_batch(batch)
                .context("failed to write UTXO batch during shutdown")?;
            info!("flushed {dirty_count} dirty UTXO entries to disk");
        } else {
            info!("UTXO cache clean, nothing to flush");
        }

        // Dump mempool to disk (unless --no-persist-mempool)
        if !self.args.no_persist_mempool {
            let mempool_path = self.args.data_dir().join("mempool.dat");
            let mempool = self.mempool.read().await;
            let entries: Vec<rbtc_mempool::PersistedEntry> = mempool
                .all_entries()
                .into_iter()
                .map(|e| {
                    let fee_delta = mempool.get_fee_delta(&e.txid);
                    rbtc_mempool::PersistedEntry {
                        tx: e.tx.clone(),
                        fee_delta,
                    }
                })
                .collect();
            let extra_deltas: Vec<rbtc_mempool::PersistedFeeDelta> = mempool
                .all_fee_deltas()
                .iter()
                .filter(|(txid, _)| !mempool.contains(txid))
                .map(|(txid, delta)| rbtc_mempool::PersistedFeeDelta {
                    txid: *txid,
                    delta: *delta,
                })
                .collect();
            drop(mempool);
            match rbtc_mempool::dump_mempool(&mempool_path, &entries, &extra_deltas) {
                Ok(()) => info!("saved {} mempool transactions to {}", entries.len(), mempool_path.display()),
                Err(e) => warn!("failed to save mempool: {e}"),
            }
        }

        info!("shutdown complete");
        Ok(())
    }

    fn should_defer_indexes(&self) -> bool {
        self.ibd.phase != IbdPhase::Complete
    }

    async fn prepare_index_catchup_if_needed(&mut self) {
        if self.ibd.phase != IbdPhase::Complete || self.index_catchup_initialized {
            return;
        }
        let chain_height = self.chain.read().await.height();
        let indexed_height = ChainStore::new(&self.db)
            .get_indexed_height()
            .ok()
            .flatten()
            .unwrap_or(0);
        if indexed_height >= chain_height {
            self.index_catchup_initialized = true;
            return;
        }
        self.index_catchup_next_height = Some(indexed_height.saturating_add(1));
        self.index_catchup_target_height = chain_height;
        self.index_catchup_initialized = true;
        info!(
            "index catch-up scheduled: heights {}..={}",
            indexed_height.saturating_add(1),
            chain_height
        );
    }

    async fn fill_index_queue_from_catchup(&mut self) {
        let Some(mut next_height) = self.index_catchup_next_height else {
            return;
        };
        if next_height > self.index_catchup_target_height {
            self.index_catchup_next_height = None;
            return;
        }

        let end = next_height
            .saturating_add(INDEX_QUEUE_FILL_CHUNK)
            .saturating_sub(1)
            .min(self.index_catchup_target_height);
        let chain = self.chain.read().await;
        while next_height <= end {
            if let Some(hash) = chain.get_ancestor_hash(next_height) {
                self.index_queue.push_back(IndexTask {
                    height: next_height,
                    block_hash: hash,
                });
            }
            next_height = next_height.saturating_add(1);
        }
        drop(chain);
        self.index_catchup_next_height = if next_height > self.index_catchup_target_height {
            None
        } else {
            Some(next_height)
        };
    }

    fn enqueue_index_task(&mut self, height: u32, block_hash: BlockHash) {
        self.index_queue.push_back(IndexTask { height, block_hash });
    }

    async fn tick_index_worker(&mut self) {
        self.prepare_index_catchup_if_needed().await;
        if self.index_queue.len() < INDEX_BATCH_SIZE {
            self.fill_index_queue_from_catchup().await;
        }
        self.poll_index_worker().await;
        self.spawn_index_worker_if_idle();
    }

    async fn poll_index_worker(&mut self) {
        let finished = self
            .index_worker
            .as_ref()
            .map(|h| h.is_finished())
            .unwrap_or(false);
        if !finished {
            return;
        }
        let handle = self.index_worker.take().expect("index_worker exists");
        match handle.await {
            Ok(Ok(outcome)) => {
                if let Some(last) = outcome.last_indexed_height {
                    debug!(
                        "index worker: processed={} last_height={} queue_remaining={}",
                        outcome.processed,
                        last,
                        self.index_queue.len()
                    );
                }
                if !outcome.retry_tasks.is_empty() {
                    if outcome.processed > 0 {
                        // Some tasks succeeded; re-queue remaining for later.
                        warn!(
                            "index worker paused; re-queueing {} task(s)",
                            outcome.retry_tasks.len()
                        );
                        for task in outcome.retry_tasks.into_iter().rev() {
                            self.index_queue.push_front(task);
                        }
                    } else {
                        // No tasks succeeded — block data not available.
                        // Drop tasks and stop catch-up to avoid infinite retry.
                        warn!(
                            "index worker: stopping catch-up, {} task(s) with missing block data (first height={})",
                            outcome.retry_tasks.len(),
                            outcome.retry_tasks[0].height
                        );
                        self.index_queue.clear();
                        self.index_catchup_next_height = None;
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("index worker failed: {e}");
            }
            Err(e) => {
                warn!("index worker join error: {e}");
            }
        }
    }

    fn spawn_index_worker_if_idle(&mut self) {
        if self.should_defer_indexes() || self.index_worker.is_some() || self.index_queue.is_empty()
        {
            return;
        }
        let mut tasks = Vec::new();
        while tasks.len() < INDEX_BATCH_SIZE {
            let Some(task) = self.index_queue.pop_front() else {
                break;
            };
            tasks.push(task);
        }
        if tasks.is_empty() {
            return;
        }
        let db = Arc::clone(&self.db);
        self.index_worker = Some(tokio::task::spawn_blocking(move || {
            write_index_batch(db, tasks)
        }));
    }

    async fn process_pending_events(&mut self) {
        self.peer_manager.process_events().await;

        while let Ok(event) = self.node_event_rx.try_recv() {
            if let Err(e) = self.handle_node_event(event).await {
                error!("event handling error: {e}");
            }
        }

        // Process any blocks submitted via the RPC layer (submitblock /
        // generatetoaddress).
        while let Ok(block) = self.submit_block_rx.try_recv() {
            if let Err(e) = self.handle_block(LOCAL_PEER_ID, block).await {
                error!("submitted block error: {e}");
            }
        }

        while let Ok(cmd) = self.rpc_control_rx.try_recv() {
            match cmd {
                RpcNodeCommand::InvalidateBlock { hash, reply } => {
                    let result = self
                        .handle_invalidate_block(BlockHash(hash))
                        .await
                        .map_err(|e| e.to_string());
                    let _ = reply.send(result);
                }
                RpcNodeCommand::ReconsiderBlock { hash, reply } => {
                    let result = self
                        .handle_reconsider_block(BlockHash(hash))
                        .await
                        .map_err(|e| e.to_string());
                    let _ = reply.send(result);
                }
                RpcNodeCommand::GetPeerInfo { reply } => {
                    let _ = reply.send(self.peer_manager.peer_stats());
                }
                RpcNodeCommand::GetMempoolInfo { reply } => {
                    let mp = self.mempool.read().await;
                    let data = crate::rpc::MempoolInfoData {
                        size: mp.len(),
                        bytes: mp.total_vsize(),
                        total_fee: mp.all_entries().iter().map(|e| e.fee).sum(),
                        maxmempool: self.args.mempool_size as u64 * 1_000_000,
                        mempoolminfee: mp.min_fee_rate(),
                    };
                    let _ = reply.send(data);
                }
                RpcNodeCommand::GetConnectionCount { reply } => {
                    let _ = reply.send(self.peer_manager.peer_count());
                }
                RpcNodeCommand::GetNetTotals { reply } => {
                    // TODO: Track actual bytes sent/received in PeerManager.
                    // For now return zeroes — the RPC shape is correct.
                    let millis = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let _ = reply.send(crate::rpc::NetTotalsData {
                        total_bytes_recv: 0,
                        total_bytes_sent: 0,
                        time_millis: millis,
                    });
                }
                RpcNodeCommand::SetBan { ip, command, reply } => {
                    let result = match command.as_str() {
                        "add" => {
                            self.peer_manager.add_ban(ip);
                            Ok(())
                        }
                        "remove" => {
                            self.peer_manager.remove_ban(&ip);
                            Ok(())
                        }
                        _ => Err(format!("Unknown setban command: {command}")),
                    };
                    let _ = reply.send(result);
                }
                RpcNodeCommand::ListBanned { reply } => {
                    let _ = reply.send(self.peer_manager.banned_list());
                }
                RpcNodeCommand::ClearBanned { reply } => {
                    self.peer_manager.clear_bans();
                    let _ = reply.send(());
                }
                RpcNodeCommand::AddNode { addr, reply } => {
                    self.peer_manager.add_candidate_addr(addr);
                    let _ = reply.send(Ok(()));
                }
                RpcNodeCommand::GetBlockFromPeer { block_hash, peer_id, reply } => {
                    // Send a getdata(MSG_WITNESS_BLOCK) to the specified peer.
                    self.peer_manager.request_block(peer_id, BlockHash(block_hash));
                    let _ = reply.send(Ok(()));
                }
                RpcNodeCommand::PruneBlockchain { height, reply } => {
                    let block_store = BlockStore::new(&self.db);
                    match block_store.prune_blocks_below(height) {
                        Ok(count) => {
                            if count > 0 {
                                info!("pruneblockchain: pruned {count} block(s) up to height {height}");
                            }
                            let _ = reply.send(Ok(height));
                        }
                        Err(e) => {
                            let _ = reply.send(Err(format!("prune failed: {e}")));
                        }
                    }
                }
                RpcNodeCommand::Ping { reply } => {
                    // Send a ping message with a random nonce to every connected peer.
                    let nonce: u64 = rand::random();
                    self.peer_manager.broadcast(NetworkMessage::Ping(nonce));
                    let _ = reply.send(());
                }
                RpcNodeCommand::DisconnectNode { address, nodeid, reply } => {
                    let result = if let Some(addr_str) = address {
                        // Find peer by address string.
                        let stats = self.peer_manager.peer_stats();
                        if let Some(ps) = stats.iter().find(|s| s.addr == addr_str) {
                            self.peer_manager.disconnect(ps.id);
                            Ok(())
                        } else {
                            Err(format!("Node not found in connected nodes: {addr_str}"))
                        }
                    } else if let Some(id) = nodeid {
                        let stats = self.peer_manager.peer_stats();
                        if stats.iter().any(|s| s.id == id) {
                            self.peer_manager.disconnect(id);
                            Ok(())
                        } else {
                            Err(format!("Node not found by id: {id}"))
                        }
                    } else {
                        Err("Need an address or a nodeid".to_string())
                    };
                    let _ = reply.send(result);
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    async fn handle_node_event(&mut self, event: NodeEvent) -> Result<()> {
        match event {
            NodeEvent::PeerConnected {
                peer_id,
                addr,
                best_height,
            } => {
                // If peer IDs are recycled, make sure stale disconnect marks
                // don't block fresh assignments.
                self.disconnecting_peers.remove(&peer_id);
                info!("peer {peer_id} connected from {addr}, height={best_height}");
                let our_height = self.chain.read().await.height() as i32;
                if best_height > our_height {
                    if self.ibd.phase == IbdPhase::Blocks {
                        // Assign a pending block range to the newly connected peer.
                        self.assign_blocks_to_peers().await;
                    } else if self.ibd.sync_peer.is_none() {
                        self.ibd.sync_peer = Some(peer_id);
                        self.ibd.record_progress();
                        // Create per-peer headers sync state for anti-spam protection.
                        let min_work = self.min_chain_work.unwrap_or(U256::ZERO);
                        let nonce = Self::random_nonce();
                        self.ibd.per_peer_sync.insert(
                            peer_id,
                            HeadersSyncState::new(min_work, nonce),
                        );
                        self.request_headers(peer_id).await;
                    }
                }
            }

            NodeEvent::PeerDisconnected { peer_id } => {
                self.disconnecting_peers.remove(&peer_id);
                let orphaned = self.block_tracker.remove_peer(peer_id);
                let tx_orphans_removed = self.orphan_pool.erase_for_peer(peer_id);
                info!("peer {peer_id} disconnected ({} blocks orphaned, {tx_orphans_removed} tx orphans removed)", orphaned.len());
                self.ibd.per_peer_sync.remove(&peer_id);
                if self.ibd.phase == IbdPhase::Blocks {
                    // Return the peer's unfinished range to the work queue.
                    self.ibd.release_peer(peer_id);
                    // Try to assign to a remaining connected peer.
                    self.assign_blocks_to_peers().await;
                } else if self.ibd.sync_peer == Some(peer_id) {
                    self.ibd.sync_peer = None;
                    if let Some(new_peer) = self.peer_manager.best_peer() {
                        self.ibd.sync_peer = Some(new_peer);
                        self.ibd.record_progress();
                        let min_work = self.min_chain_work.unwrap_or(U256::ZERO);
                        let nonce = Self::random_nonce();
                        self.ibd.per_peer_sync.insert(
                            new_peer,
                            HeadersSyncState::new(min_work, nonce),
                        );
                        self.request_headers(new_peer).await;
                    }
                }
            }

            NodeEvent::HeadersReceived { peer_id, headers } => {
                let count = headers.len();
                info!("received {count} headers from peer {peer_id}");
                self.handle_headers(peer_id, headers).await?;
            }

            NodeEvent::BlockReceived { peer_id, block } => {
                let height = self.chain.read().await.height();
                info!("received block from peer {peer_id}, our height={height}");
                self.handle_block(peer_id, block).await?;
            }

            NodeEvent::TxReceived { peer_id, tx } => {
                self.handle_tx(peer_id, tx).await;
            }

            NodeEvent::CmpctBlockReceived { peer_id, cmpct } => {
                self.handle_cmpct_block(peer_id, cmpct).await?;
            }

            NodeEvent::GetBlockTxnReceived { peer_id, req } => {
                self.handle_get_block_txn(peer_id, req).await;
            }

            NodeEvent::BlockTxnReceived { peer_id, resp } => {
                self.handle_block_txn(peer_id, resp).await?;
            }

            NodeEvent::BanPeer { ip } => {
                self.handle_ban_peer(ip);
            }

            NodeEvent::NotFound { peer_id, items } => {
                warn!(
                    "peer {peer_id}: notfound for {} item(s) – likely pruned; re-assigning range",
                    items.len()
                );
                if self.ibd.phase == IbdPhase::Blocks {
                    self.ibd.release_peer(peer_id);
                    self.request_peer_disconnect(peer_id);
                    self.assign_blocks_to_peers().await;
                } else if self.ibd.sync_peer == Some(peer_id) {
                    self.ibd.sync_peer = None;
                    self.request_peer_disconnect(peer_id);
                    if let Some(new_peer) = self.peer_manager.best_peer() {
                        self.ibd.sync_peer = Some(new_peer);
                        self.ibd.record_progress();
                        self.request_headers(new_peer).await;
                    }
                }
            }

            NodeEvent::AddrReceived { peer_id: _, addrs } => {
                self.handle_addr_received(addrs);
            }

            NodeEvent::MempoolRequested { peer_id } => {
                // BIP35: send inv for all txids in our mempool
                let inv_type = if self.peer_manager.peer_wtxid_relay(peer_id) {
                    InvType::WitnessTx
                } else {
                    InvType::Tx
                };
                let mp = self.mempool.read().await;
                let inv_items: Vec<Inventory> = mp
                    .txids()
                    .iter()
                    .map(|txid| Inventory {
                        inv_type,
                        hash: txid.0,
                    })
                    .collect();
                drop(mp);
                // BIP35: batch at most 50000 inv items per message
                for chunk in inv_items.chunks(50000) {
                    self.peer_manager
                        .send_to(peer_id, NetworkMessage::Inv(chunk.to_vec()));
                }
            }

            NodeEvent::Addrv2Received { peer_id: _, msg } => {
                // Convert addrv2 IPv4/IPv6 entries to socket addresses for persistence
                for entry in &msg.addrs {
                    let ip: Option<std::net::IpAddr> = match entry.net_id {
                        1 if entry.addr.len() == 4 => {
                            let octets: [u8; 4] = entry.addr[..4].try_into().unwrap();
                            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
                        }
                        2 if entry.addr.len() == 16 => {
                            let octets: [u8; 16] = entry.addr[..16].try_into().unwrap();
                            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                        }
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        let addr = std::net::SocketAddr::new(ip, entry.port);
                        self.peer_manager.add_candidate_addr(addr);
                    }
                }
            }

            NodeEvent::InvReceived { peer_id, items } => {
                // Matching Bitcoin Core's inv handler (net_processing.cpp:4125-4213):
                // - For blocks: record best_block, send getheaders only (NO getdata).
                //   Block data is fetched later via headers_direct_fetch_blocks().
                // - For transactions: collect and send getdata.
                let mut best_block: Option<BlockHash> = None;
                let mut tx_to_request: Vec<Inventory> = Vec::new();

                let chain = self.chain.read().await;
                let mp = self.mempool.read().await;

                for item in items {
                    match item.inv_type {
                        InvType::Block | InvType::WitnessBlock => {
                            let bh = BlockHash(item.hash);
                            if !chain.block_index.contains_key(&bh)
                                && !self.block_tracker.is_in_flight(&bh)
                            {
                                // Like Core: only track the last (highest) unknown
                                // block hash.  We'll send getheaders below.
                                best_block = Some(bh);
                            }
                        }
                        InvType::Tx | InvType::WitnessTx => {
                            if !mp.contains(&Txid(item.hash)) {
                                tx_to_request.push(Inventory {
                                    inv_type: InvType::WitnessTx,
                                    hash: item.hash,
                                });
                            }
                        }
                        _ => {}
                    }
                }
                drop(chain);
                drop(mp);

                if best_block.is_some() {
                    // Bitcoin Core: on block inv, send getheaders to learn
                    // the chain.  Block data is fetched later in
                    // headers_direct_fetch_blocks() after headers arrive.
                    self.request_headers(peer_id).await;
                }
                if !tx_to_request.is_empty() {
                    self.peer_manager
                        .send_to(peer_id, NetworkMessage::GetData(tx_to_request));
                }
            }
        }

        Ok(())
    }

    async fn handle_headers(
        &mut self,
        peer_id: u64,
        headers: Vec<rbtc_primitives::block::BlockHeader>,
    ) -> Result<()> {
        // Feed headers through per-peer sync state if one exists.
        if let Some(sync_state) = self.ibd.per_peer_sync.get_mut(&peer_id) {
            match sync_state.current_phase() {
                SyncPhase::Presync => {
                    let result = sync_state.process_presync(&headers);
                    match &result {
                        ProcessResult::Invalid(reason) => {
                            warn!("headers sync: peer {peer_id} invalid during presync: {reason}");
                            self.ibd.per_peer_sync.remove(&peer_id);
                            self.request_peer_disconnect(peer_id);
                            return Ok(());
                        }
                        ProcessResult::StartRedownload => {
                            info!(
                                "headers sync: peer {peer_id} presync complete ({} headers, work sufficient); starting redownload",
                                sync_state.presync_header_count()
                            );
                            // Presync is done. Continue to add headers to block_index below.
                        }
                        ProcessResult::Continue(_) => {
                            debug!(
                                "headers sync: peer {peer_id} presync progress ({} headers)",
                                sync_state.presync_header_count()
                            );
                        }
                        _ => {}
                    }
                }
                SyncPhase::Redownload => {
                    let result = sync_state.process_redownload(&headers);
                    match &result {
                        ProcessResult::Invalid(reason) => {
                            warn!("headers sync: peer {peer_id} invalid during redownload: {reason}");
                            self.ibd.per_peer_sync.remove(&peer_id);
                            self.request_peer_disconnect(peer_id);
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                SyncPhase::Done => {
                    self.ibd.per_peer_sync.remove(&peer_id);
                }
            }
        }

        if headers.is_empty() {
            if self.ibd.phase == IbdPhase::Headers {
                self.ibd.per_peer_sync.remove(&peer_id);
                self.ibd.phase = IbdPhase::Blocks;
                info!("IBD: entering block download phase");
                self.build_canonical_header_chain().await;
                self.assign_blocks_to_peers().await;
            }
            return Ok(());
        }

        self.ibd.record_progress();
        let last_header = headers.last().cloned();
        let block_store = BlockStore::new(&self.db);
        let mut chain = self.chain.write().await;

        for header in &headers {
            match chain.add_header(header.clone()) {
                Ok(hash) => {
                    // Checkpoint verification (M25): reject headers whose hash
                    // doesn't match a hardcoded checkpoint at that height.
                    if let Some(bi) = chain.get_block_index(&hash) {
                        if !self.checkpoints.verify(bi.height, &hash) {
                            warn!(
                                "header from peer {peer_id} at height {} fails checkpoint (got {})",
                                bi.height,
                                hash.to_hex()
                            );
                            continue;
                        }
                    }

                    // Persist the header to block_store if it's new
                    if block_store.get_index(&hash).ok().flatten().is_none() {
                        if let Some(bi) = chain.get_block_index(&hash) {
                            let stored = StoredBlockIndex {
                                header: header.clone(),
                                height: bi.height,
                                chainwork_lo: bi.chainwork.0[0],
                                chainwork_hi: bi.chainwork.0[1],
                                status: bi.status,
                            };
                            block_store.put_index(&hash, &stored).ok();
                        }
                    }
                }
                Err(e) => {
                    warn!("header from peer {peer_id}: {e}");
                }
            }
        }
        drop(chain);

        let last_hash = last_header
            .map(|h| header_hash(&h))
            .unwrap_or(BlockHash::ZERO);

        if headers.len() == 2000 {
            self.peer_manager.send_to(
                peer_id,
                NetworkMessage::GetHeaders(rbtc_net::message::GetBlocksMessage {
                    version: 70016,
                    locator_hashes: vec![last_hash],
                    stop_hash: BlockHash::ZERO,
                }),
            );
        } else {
            self.ibd.per_peer_sync.remove(&peer_id);
            self.ibd.phase = IbdPhase::Blocks;
            // Build canonical header chain from block_index and partition into
            // per-peer download segments.
            self.build_canonical_header_chain().await;
            self.assign_blocks_to_peers().await;
        }

        // Bitcoin Core: HeadersDirectFetchBlocks() — immediately request
        // block data for headers we just learned about, if we're close to
        // caught up.
        if last_hash != BlockHash::ZERO {
            self.headers_direct_fetch_blocks(peer_id, last_hash).await;
        }

        Ok(())
    }

    /// Matching Bitcoin Core's `HeadersDirectFetchBlocks()`:
    /// After processing a headers message, walk backwards from the last
    /// header we received and request block data for headers that don't
    /// have data yet and aren't already in-flight.
    ///
    /// Only active when we're "close to synced" (CanDirectFetch equivalent:
    /// tip time within 20 * target_spacing of now).
    async fn headers_direct_fetch_blocks(&mut self, peer_id: u64, last_hash: BlockHash) {
        let chain = self.chain.read().await;

        // CanDirectFetch: tip time must be within 20 * 600s of now.
        let tip_time = chain
            .best_tip
            .and_then(|h| chain.block_index.get(&h))
            .map(|bi| bi.header.time as i64)
            .unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if now - tip_time > 20 * 600 {
            return; // Still in IBD, don't direct-fetch.
        }

        // Walk backwards from last_hash, collecting blocks we need.
        let mut to_fetch: Vec<BlockHash> = Vec::new();
        let mut cursor = last_hash;

        while to_fetch.len() < rbtc_net::block_download::BLOCK_DOWNLOAD_WINDOW {
            let bi = match chain.block_index.get(&cursor) {
                Some(bi) => bi,
                None => break,
            };

            // Stop when we reach a block on our active chain.
            let on_active = chain
                .active_chain
                .get(bi.height as usize)
                .map(|h| *h == cursor)
                .unwrap_or(false);
            if on_active {
                break;
            }

            if !bi.status.have_data() && !self.block_tracker.is_in_flight(&cursor) {
                to_fetch.push(cursor);
            }

            cursor = bi.header.prev_block;
        }
        drop(chain);

        if to_fetch.is_empty() {
            return;
        }

        // Request from earliest to latest (reverse the backwards walk).
        to_fetch.reverse();
        let invs: Vec<Inventory> = to_fetch
            .iter()
            .map(|h| {
                self.block_tracker.mark_requested(peer_id, *h);
                Inventory {
                    inv_type: InvType::WitnessBlock,
                    hash: h.0,
                }
            })
            .collect();

        debug!(
            "headers_direct_fetch: requesting {} blocks from peer {peer_id}",
            invs.len()
        );
        self.peer_manager
            .send_to(peer_id, NetworkMessage::GetData(invs));
    }

    /// Walk block_index backwards from the best-chainwork tip to build a
    /// height-indexed vec of canonical hashes.  Called once when header sync
    /// is complete and we switch to the block-download phase.
    /// Also partitions the remaining un-downloaded height range into segments
    /// for multi-peer parallel download.
    async fn build_canonical_header_chain(&mut self) {
        let chain = self.chain.read().await;
        let best = chain.block_index.values().max_by_key(|bi| bi.chainwork);
        let Some(tip) = best else { return };
        let tip_height = tip.height as usize;
        let active_height = chain.height();
        let mut canonical = vec![BlockHash::ZERO; tip_height + 1];
        let mut cur = tip.hash;
        while let Some(bi) = chain.block_index.get(&cur) {
            canonical[bi.height as usize] = cur;
            if bi.height == 0 {
                break;
            }
            cur = bi.header.prev_block;
        }
        let tip_u32 = tip.height;
        drop(chain);
        info!("canonical header chain built: {} headers", canonical.len());
        self.canonical_header_chain = canonical;

        // Partition the un-downloaded height range into fixed-size segments.
        let start = active_height + 1;
        if start <= tip_u32 {
            self.ibd.partition_ranges(start, tip_u32, SEGMENT_SIZE);
        }
    }

    // ── BIP152 Compact Block handlers ─────────────────────────────────────────

    async fn handle_cmpct_block(&mut self, peer_id: u64, cmpct: CompactBlock) -> Result<()> {
        let block_hash = {
            let mut buf = Vec::with_capacity(80);
            buf.extend_from_slice(&cmpct.header.version.to_le_bytes());
            buf.extend_from_slice(&cmpct.header.prev_block.0.0);
            buf.extend_from_slice(&cmpct.header.merkle_root.0);
            buf.extend_from_slice(&cmpct.header.time.to_le_bytes());
            buf.extend_from_slice(&cmpct.header.bits.to_le_bytes());
            buf.extend_from_slice(&cmpct.header.nonce.to_le_bytes());
            rbtc_crypto::sha256d(&buf)
        };

        // Build a mempool lookup by short_id for this compact block's nonce/header
        let mempool_lookup: HashMap<u64, rbtc_primitives::transaction::Transaction> = {
            let mp = self.mempool.read().await;
            mp.transactions()
                .iter()
                .map(|(txid, tx)| {
                    let sid = short_txid(&cmpct.header, cmpct.nonce, &txid.0);
                    (sid, tx.clone())
                })
                .collect()
        };

        let (maybe_block, missing) = reconstruct_block(&cmpct, &mempool_lookup);

        if let Some(block) = maybe_block {
            // Full reconstruction succeeded without a round-trip
            self.handle_block(peer_id, block).await?;
        } else {
            // Request missing transactions from the peer
            info!(
                "cmpctblock: {} txs missing, requesting getblocktxn",
                missing.len()
            );
            self.pending_compact.insert(block_hash, (cmpct, vec![]));
            self.peer_manager.send_to(
                peer_id,
                NetworkMessage::GetBlockTxn(GetBlockTxn {
                    block_hash,
                    indexes: missing,
                }),
            );
        }

        Ok(())
    }

    async fn handle_block_txn(
        &mut self,
        peer_id: u64,
        resp: rbtc_net::compact::BlockTxn,
    ) -> Result<()> {
        let Some((cmpct, _)) = self.pending_compact.remove(&resp.block_hash) else {
            return Ok(());
        };

        // Re-build the mempool lookup with the fresh nonce (same as above)
        let mempool_lookup: HashMap<u64, rbtc_primitives::transaction::Transaction> = {
            let mp = self.mempool.read().await;
            mp.transactions()
                .iter()
                .map(|(txid, tx)| {
                    let sid = short_txid(&cmpct.header, cmpct.nonce, &txid.0);
                    (sid, tx.clone())
                })
                .collect()
        };

        // Apply the provided missing transactions on top of the mempool lookup
        let mut augmented = mempool_lookup;
        for (missing_tx, &slot_idx) in resp.txns.iter().zip(
            // We stored the missing indexes in the GetBlockTxn we sent; reconstruct
            // them by a fresh reconstruction pass.
            reconstruct_block(&cmpct, &augmented.clone()).1.iter(),
        ) {
            let sid = short_txid(&cmpct.header, cmpct.nonce, &{
                let mut buf = Vec::new();
                missing_tx.encode_legacy(&mut buf).ok();
                rbtc_crypto::sha256d(&buf)
            });
            augmented.entry(sid).or_insert_with(|| missing_tx.clone());
            let _ = slot_idx; // suppress unused warning
        }

        let (maybe_block, _) = reconstruct_block(&cmpct, &augmented);
        if let Some(block) = maybe_block {
            self.handle_block(peer_id, block).await?;
        } else {
            warn!(
                "blocktxn: still could not reconstruct block {}",
                resp.block_hash.to_hex()
            );
        }

        Ok(())
    }

    /// Respond to a `getblocktxn` request: send back the requested transactions.
    async fn handle_get_block_txn(&self, peer_id: u64, req: GetBlockTxn) {
        use rbtc_storage::BlockStore;
        let block_store = BlockStore::new(&self.db);
        if let Ok(Some(block)) = block_store.get_block(&BlockHash(req.block_hash)) {
            let txns: Vec<_> = req
                .indexes
                .iter()
                .filter_map(|&i| block.transactions.get(i as usize).cloned())
                .collect();
            self.peer_manager.send_to(
                peer_id,
                NetworkMessage::BlockTxn(rbtc_net::compact::BlockTxn {
                    block_hash: req.block_hash,
                    txns,
                }),
            );
        }
    }

    /// Delete raw block data for blocks more than 288 heights below the current tip
    /// when `--prune <MiB>` is enabled.
    async fn maybe_prune(&self, current_height: u32) {
        if self.args.prune == 0 {
            return;
        }
        // Keep the most recent 288 blocks (~2 days); prune everything older.
        let prune_below = current_height.saturating_sub(288);
        let block_store = BlockStore::new(&self.db);
        match block_store.prune_blocks_below(prune_below) {
            Ok(n) if n > 0 => info!("pruned {n} block(s) below height {prune_below}"),
            Err(e) => warn!("pruning error: {e}"),
            _ => {}
        }
    }

    fn best_connectable_hash_at_height(
        &self,
        chain: &ChainState,
        height: u32,
        expected_prev: BlockHash,
    ) -> Option<BlockHash> {
        if let Some(hash) = chain.get_ancestor_hash(height) {
            if let Some(bi) = chain.block_index.get(&hash) {
                if !bi.status.has_failed() && bi.header.prev_block == expected_prev {
                    return Some(hash);
                }
            }
        }

        self.canonical_header_chain
            .get(height as usize)
            .copied()
            .filter(|h| *h != BlockHash::ZERO)
            .and_then(|hash| {
                chain
                    .block_index
                    .get(&hash)
                    .filter(|bi| {
                        !bi.status.has_failed() && bi.header.prev_block == expected_prev
                    })
                    .map(|_| hash)
            })
            .or_else(|| {
                chain
                    .block_index
                    .values()
                    .filter(|bi| {
                        bi.height == height
                            && !bi.status.has_failed()
                            && bi.header.prev_block == expected_prev
                    })
                    .max_by_key(|bi| bi.chainwork)
                    .map(|bi| bi.hash)
            })
    }

    /// Collect connectable, non-invalid hashes for a height range [start, end].
    /// We walk forward from the current active tip and stop at the first gap so
    /// we never request a disjoint tail that cannot connect.
    async fn hashes_for_range(&self, start: u32, end: u32) -> Vec<BlockHash> {
        let chain = self.chain.read().await;
        let mut hashes = Vec::new();
        let mut expected_prev = if start == 0 {
            BlockHash::ZERO
        } else {
            match chain.get_ancestor_hash(start - 1) {
                Some(h) => h,
                None => return hashes,
            }
        };
        for h in start..=end {
            let Some(hash) = self.best_connectable_hash_at_height(&chain, h, expected_prev) else {
                break;
            };
            if Self::is_block_connected(&chain, &hash) {
                expected_prev = hash;
                continue;
            }
            hashes.push(hash);
            expected_prev = hash;
        }
        hashes
    }

    /// Per-peer in-flight request cap (Bitcoin Core defaults to small per-peer windows).
    const PER_PEER_INFLIGHT_BLOCKS: u32 = 16;
    /// Tighter in-flight cap while frontier is pending, to reduce out-of-order flood.
    const PER_PEER_INFLIGHT_BLOCKS_FRONTIER_PENDING: u32 = 4;
    /// If the frontier block is in-flight longer than this, re-request it from
    /// another idle peer (without waiting for full stall timeout).
    const FRONTIER_RETRY_TIMEOUT: Duration = Duration::from_secs(15);
    /// Keep up to this many parallel owners for the frontier block.
    const FRONTIER_REDUNDANT_PEERS: usize = 2;

    fn peer_window_bounds(&self) -> (u32, u32) {
        let min_w = self.args.ibd_peer_window_min.max(1);
        let max_w = self.args.ibd_peer_window_max.max(min_w);
        (min_w, max_w)
    }

    fn adaptive_per_peer_cap(&self, peer_id: u64, frontier_pending: bool) -> u32 {
        let (min_w, max_w) = self.peer_window_bounds();
        let mut base = if frontier_pending {
            Self::PER_PEER_INFLIGHT_BLOCKS_FRONTIER_PENDING.max(min_w)
        } else {
            Self::PER_PEER_INFLIGHT_BLOCKS.max(min_w)
        };
        if let Some(stats) = self.peer_ibd_stats.get(&peer_id) {
            if stats.timeout_strikes >= 3 {
                return min_w;
            }
            // Lower interval EMA means faster delivery rate.
            if stats.delivery_interval_ema_ms > 0.0 {
                if stats.delivery_interval_ema_ms < 120.0 && !frontier_pending {
                    base = base.saturating_add(8);
                } else if stats.delivery_interval_ema_ms > 500.0 {
                    base = base.saturating_sub(4).max(min_w);
                }
            }
        }
        base.min(max_w)
    }

    /// Returns true when we already cached at least one pending block at `height`
    /// that can extend the current active tip immediately.
    async fn has_connectable_pending_at_height(&self, height: u32) -> bool {
        let Some(candidates) = self.pending_blocks.get(&height) else {
            return false;
        };
        let expected_prev = {
            let chain = self.chain.read().await;
            if let Some(tip) = chain.best_hash() {
                tip
            } else if height == 1 {
                match BlockHash::from_hex(chain.network.genesis_hash()) {
                    Ok(h) => h,
                    Err(_) => return false,
                }
            } else {
                return false;
            }
        };
        candidates
            .iter()
            .any(|(_, block)| block.header.prev_block == expected_prev)
    }

    fn adaptive_global_window(&self, peer_count: usize) -> u32 {
        if self.args.ibd_global_window > 0 {
            return self.args.ibd_global_window;
        }
        let mut dynamic = MIN_DYNAMIC_GLOBAL_WINDOW_BLOCKS;
        // Derive a rough throughput estimate from moving average of connect time.
        let connect_ema_ms = self
            .peer_ibd_stats
            .values()
            .filter_map(|s| {
                if s.delivery_interval_ema_ms > 0.0 {
                    Some(s.delivery_interval_ema_ms)
                } else {
                    None
                }
            })
            .fold(None, |acc: Option<f64>, v| match acc {
                Some(cur) => Some(cur * 0.85 + v * 0.15),
                None => Some(v),
            });
        if let Some(ms) = connect_ema_ms {
            let approx_blocks_per_sec = (1000.0 / ms).clamp(0.5, 20.0);
            dynamic = (approx_blocks_per_sec * 25.0) as u32;
        }
        let (min_w, max_w) = self.peer_window_bounds();
        let peer_floor = (peer_count as u32)
            .saturating_mul(max_w.max(min_w))
            .saturating_mul(2);
        dynamic.max(peer_floor).clamp(
            MIN_DYNAMIC_GLOBAL_WINDOW_BLOCKS,
            MAX_DYNAMIC_GLOBAL_WINDOW_BLOCKS,
        )
    }

    fn note_peer_timeout(&mut self, peer_id: u64) {
        let stats = self.peer_ibd_stats.entry(peer_id).or_default();
        stats.timeout_strikes = stats.timeout_strikes.saturating_add(1);
    }

    /// Evict the worst-performing extra outbound peer if we exceed our target
    /// (M26, modelled on Bitcoin Core `CConnman::EvictExtraOutboundPeers`).
    ///
    /// Scoring: lower is worse.  We protect the longest-connected, the one with
    /// the best (most recent) block delivery, and the one with the lowest
    /// delivery interval EMA.  Among the remaining, the peer with the worst
    /// composite score is disconnected.
    fn evict_extra_outbound_peers(&mut self) {
        let outbound = self.peer_manager.outbound_full_relay_peers();
        let target = self.peer_manager.max_outbound_full_relay();
        if outbound.len() <= target {
            return;
        }

        // Gather scoring info for each outbound peer.
        struct Candidate {
            id: u64,
            connected_time: Instant,
            last_delivery: Option<Instant>,
            ema_ms: f64,
        }

        let peer_infos = self.peer_manager.peer_info();
        let info_map: HashMap<u64, _> = peer_infos.into_iter().map(|p| (p.id, p)).collect();

        let mut candidates: Vec<Candidate> = outbound
            .iter()
            .filter_map(|&id| {
                let pi = info_map.get(&id)?;
                let stats = self.peer_ibd_stats.get(&id);
                Some(Candidate {
                    id,
                    connected_time: pi.connected_time,
                    last_delivery: stats.and_then(|s| s.last_delivery_at),
                    ema_ms: stats.map(|s| s.delivery_interval_ema_ms).unwrap_or(f64::MAX),
                })
            })
            .collect();

        if candidates.len() <= 1 {
            return;
        }

        // Protect: longest-connected peer (most established relationship)
        candidates.sort_by_key(|c| c.connected_time);
        candidates.remove(0); // protect earliest

        if candidates.is_empty() {
            return;
        }

        // Protect: most recent block delivery
        if let Some(pos) = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.last_delivery.is_some())
            .max_by_key(|(_, c)| c.last_delivery.unwrap())
            .map(|(i, _)| i)
        {
            candidates.remove(pos);
        }

        if candidates.is_empty() {
            return;
        }

        // Protect: best (lowest) delivery EMA
        if let Some(pos) = candidates
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.ema_ms.partial_cmp(&b.ema_ms).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
        {
            candidates.remove(pos);
        }

        if candidates.is_empty() {
            return;
        }

        // Evict the worst remaining: highest EMA (slowest block delivery).
        let worst = candidates
            .iter()
            .max_by(|a, b| a.ema_ms.partial_cmp(&b.ema_ms).unwrap_or(std::cmp::Ordering::Equal));

        if let Some(victim) = worst {
            info!(
                "evicting extra outbound peer {} (ema={:.0}ms, outbound={}/{})",
                victim.id, victim.ema_ms, outbound.len(), target
            );
            self.request_peer_disconnect(victim.id);
        }
    }

    fn note_peer_delivery(&mut self, peer_id: u64) {
        let now = Instant::now();
        let stats = self.peer_ibd_stats.entry(peer_id).or_default();
        stats.delivered_blocks = stats.delivered_blocks.saturating_add(1);
        if let Some(prev) = stats.last_delivery_at {
            let interval_ms = now.duration_since(prev).as_millis() as f64;
            stats.delivery_interval_ema_ms = if stats.delivery_interval_ema_ms == 0.0 {
                interval_ms
            } else {
                stats.delivery_interval_ema_ms * 0.85 + interval_ms * 0.15
            };
        }
        stats.last_delivery_at = Some(now);
        if stats.timeout_strikes > 0 {
            stats.timeout_strikes -= 1;
        }
    }

    fn request_peer_disconnect(&mut self, peer_id: u64) {
        self.disconnecting_peers.insert(peer_id);
        self.peer_manager.disconnect(peer_id);
    }

    /// Generate a random 32-byte nonce for headers sync commitment.
    fn random_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        // Use a simple approach: hash the current time + a counter.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seed = now.as_nanos().to_le_bytes();
        nonce[..16].copy_from_slice(&seed);
        nonce[16..].copy_from_slice(&sha256d(&seed).0[..16]);
        nonce
    }

    /// Assign pending height-range segments to idle peers.
    /// Called whenever a new peer connects, a batch finishes, or after a stall.
    async fn assign_blocks_to_peers(&mut self) {
        // Collect peers that are not currently handling a batch.
        let our_height = self.chain.read().await.height();
        let ibd_peers = self.peer_manager.peers_for_ibd(our_height + 1);
        let global_window = self.adaptive_global_window(ibd_peers.len());
        let max_assignable_height = our_height.saturating_add(global_window);

        let mut idle_peers: Vec<u64> = self
            .peer_manager
            .peers_for_ibd(our_height + 1)
            .into_iter()
            .filter(|id| !self.disconnecting_peers.contains(id))
            .filter(|id| !self.ibd.peer_downloads.contains_key(id))
            .collect();

        // Frontier guard: ensure height+1 is always actively in-flight.
        let frontier = our_height.saturating_add(1);
        let frontier_hash = {
            let chain = self.chain.read().await;
            let expected_prev = if frontier == 0 {
                BlockHash::ZERO
            } else {
                match chain.get_ancestor_hash(frontier.saturating_sub(1)) {
                    Some(h) => h,
                    None => BlockHash::ZERO,
                }
            };
            self.best_connectable_hash_at_height(&chain, frontier, expected_prev)
        };
        let mut frontier_pending = false;
        let mut frontier_hash_for_preemption: Option<BlockHash> = None;
        if let Some(frontier_hash) = frontier_hash {
            frontier_hash_for_preemption = Some(frontier_hash);
            let frontier_connected = {
                let chain = self.chain.read().await;
                Self::is_block_connected(&chain, &frontier_hash)
            };
            // If frontier block is already cached in pending_blocks, it will be
            // drained automatically once the chain tip advances — no need to
            // treat it as pending or preempt peers for it.
            let frontier_cached = self.has_connectable_pending_at_height(frontier).await;
            if !frontier_connected && !frontier_cached {
                frontier_pending = true;
                let frontier_owners: Vec<(u64, Duration)> = self
                    .ibd
                    .peer_downloads
                    .iter()
                    .filter(|(_, dl)| dl.hashes.iter().any(|h| h == &frontier_hash))
                    .map(|(peer_id, dl)| (*peer_id, dl.requested_at.elapsed()))
                    .collect();
                let stale_owner_exists = frontier_owners
                    .iter()
                    .any(|(_, age)| *age >= Self::FRONTIER_RETRY_TIMEOUT);
                // Only request redundant peers when the current owner is stale;
                // otherwise 1 owner is sufficient and avoids wasting bandwidth.
                let desired_owners = if stale_owner_exists {
                    Self::FRONTIER_REDUNDANT_PEERS
                } else {
                    1
                };
                let mut owners = frontier_owners.len();
                while owners < desired_owners {
                    let Some(peer_id) = idle_peers.first().copied() else {
                        break;
                    };
                    if self.disconnecting_peers.contains(&peer_id) {
                        idle_peers.remove(0);
                        continue;
                    }
                    // Avoid duplicate assignment to an owner that already has frontier.
                    if self
                        .ibd
                        .peer_downloads
                        .get(&peer_id)
                        .map(|dl| dl.hashes.iter().any(|h| h == &frontier_hash))
                        .unwrap_or(false)
                    {
                        idle_peers.remove(0);
                        continue;
                    }
                    info!(
                        "IBD: assigning frontier height {} (1 block) to peer {}",
                        frontier, peer_id
                    );
                    self.ibd
                        .assigned_ranges
                        .insert(peer_id, (frontier, frontier));
                    self.ibd.record_peer_request(peer_id, vec![frontier_hash]);
                    self.block_tracker.mark_requested(peer_id, frontier_hash);
                    self.peer_manager.request_blocks(peer_id, &[frontier_hash]);
                    idle_peers.remove(0);
                    owners += 1;
                }

                if owners == 0 {
                    debug!(
                        "IBD: no frontier owner available for height {}; waiting for peer availability",
                        frontier
                    );
                } else if owners < Self::FRONTIER_REDUNDANT_PEERS {
                    debug!(
                        "IBD: frontier height {} currently has {} owner(s), target {}",
                        frontier,
                        owners,
                        Self::FRONTIER_REDUNDANT_PEERS
                    );
                }

                // Remove frontier from pending_ranges so it won't be re-dispatched
                // again by the generic range assignment loop below.
                if let Some((idx, (start, end))) = self
                    .ibd
                    .pending_ranges
                    .iter()
                    .enumerate()
                    .find(|(_, (start, end))| *start <= frontier && frontier <= *end)
                    .map(|(i, r)| (i, *r))
                {
                    let _ = self.ibd.pending_ranges.remove(idx);
                    if frontier < end {
                        self.ibd.pending_ranges.push_front((frontier + 1, end));
                    }
                    if start < frontier {
                        self.ibd.pending_ranges.push_front((start, frontier - 1));
                    }
                }
            }
        }
        let refill = self.peer_manager.refill_stats();
        let inflight = self.ibd.peer_downloads.len();
        let frontier_owner = frontier_hash_for_preemption.and_then(|fh| {
            self.ibd
                .peer_downloads
                .iter()
                .find(|(_, dl)| dl.hashes.iter().any(|h| h == &fh))
                .map(|(peer_id, _)| *peer_id)
        });
        debug!(
            "IBD scheduler: outbound={} connecting={} candidates={} inflight={} global_window={} frontier_pending={} frontier_owner={:?}",
            refill.outbound,
            refill.connecting,
            refill.candidates,
            inflight,
            global_window,
            frontier_pending,
            frontier_owner
        );

        // If frontier is still pending but no idle peer exists, preempt one
        // far-ahead busy peer by cancelling its assignment (without disconnecting!)
        // and immediately reassigning it to the frontier block.
        if frontier_pending && idle_peers.is_empty() {
            let frontier_hash = frontier_hash_for_preemption;
            let victim = self
                .ibd
                .assigned_ranges
                .iter()
                .filter(|(peer_id, _)| !self.disconnecting_peers.contains(peer_id))
                .filter(|(peer_id, _)| {
                    // Do not preempt the current frontier owner (if any).
                    if let Some(frontier_hash) = frontier_hash {
                        if let Some(dl) = self.ibd.peer_downloads.get(peer_id) {
                            return !dl.hashes.iter().any(|h| h == &frontier_hash);
                        }
                    }
                    true
                })
                .max_by_key(|(_, (_, end))| *end)
                .map(|(peer_id, _)| *peer_id);
            if let Some(victim_peer) = victim {
                if let Some(fh) = frontier_hash {
                    debug!(
                        "IBD: reassigning peer {} from ahead-work to frontier height {}",
                        victim_peer, frontier
                    );
                    // Release ahead-assignment (re-queues the range for later).
                    self.ibd.release_peer(victim_peer);
                    // Immediately assign frontier to this peer instead of disconnecting.
                    self.ibd
                        .assigned_ranges
                        .insert(victim_peer, (frontier, frontier));
                    self.ibd.record_peer_request(victim_peer, vec![fh]);
                    self.block_tracker.mark_requested(victim_peer, fh);
                    self.peer_manager.request_blocks(victim_peer, &[fh]);
                }
            }
        }

        // Keep one peer idle while frontier is still pending so failover can
        // immediately switch owners instead of waiting for another connection.
        let range_assign_limit = if frontier_pending && !idle_peers.is_empty() {
            idle_peers.len().saturating_sub(1)
        } else {
            idle_peers.len()
        };

        if frontier_pending && range_assign_limit < idle_peers.len() {
            debug!(
                "IBD: reserving 1 idle peer for frontier failover (idle={}, assignable={})",
                idle_peers.len(),
                range_assign_limit
            );
        }

        for peer_id in idle_peers.into_iter().take(range_assign_limit) {
            let per_peer_cap = self.adaptive_per_peer_cap(peer_id, frontier_pending);
            // Always dispatch the smallest-start (frontier-nearest) segment first.
            // `pending_ranges` can be perturbed by stall/release re-queue ordering,
            // so pop_front() may accidentally prioritize farther-ahead ranges.
            let mut best_idx: Option<usize> = None;
            let mut best_start = u32::MAX;
            for (idx, (start, _)) in self.ibd.pending_ranges.iter().enumerate() {
                if *start <= max_assignable_height && *start < best_start {
                    best_start = *start;
                    best_idx = Some(idx);
                }
            }
            let Some(best_idx) = best_idx else { break };
            let Some(range) = self.ibd.pending_ranges.remove(best_idx) else {
                continue;
            };
            let (start, end) = range;

            // Per-peer inflight cap: split large segments into smaller requests.
            let capped_end = end.min(start.saturating_add(per_peer_cap - 1));

            let hashes = self.hashes_for_range(start, capped_end).await;
            if hashes.is_empty() {
                // If this segment is already behind our connected height, it's done.
                // Otherwise we likely hit a header gap; re-queue this range and stop
                // assigning farther ranges so the frontier is retried first.
                let cur_height = self.chain.read().await.height();
                if cur_height < end {
                    self.ibd.pending_ranges.push_front(range);
                    break;
                }
                continue;
            }
            let requested_end = start.saturating_add(hashes.len() as u32).saturating_sub(1);
            if requested_end < end {
                self.ibd
                    .pending_ranges
                    .push_front((requested_end.saturating_add(1), end));
            }

            info!(
                "IBD: assigning heights {}..={} ({} blocks) to peer {}",
                start,
                requested_end,
                hashes.len(),
                peer_id
            );
            self.ibd
                .assigned_ranges
                .insert(peer_id, (start, requested_end));
            self.ibd.record_peer_request(peer_id, hashes.clone());
            for h in &hashes {
                self.block_tracker.mark_requested(peer_id, *h);
            }
            self.peer_manager.request_blocks(peer_id, &hashes);
        }

        // If no pending ranges remain and no peer has inflight work, IBD is done.
        if self.ibd.phase == IbdPhase::Blocks && self.ibd.all_ranges_complete() {
            // Double-check by looking for un-downloaded heights.
            let tip = {
                let chain = self.chain.read().await;
                chain
                    .block_index
                    .values()
                    .map(|bi| bi.height)
                    .max()
                    .unwrap_or(0)
            };
            let connected_height = self.chain.read().await.height();
            if connected_height >= tip {
                self.ibd.mark_complete();
                self.is_ibd.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Mark `block_hash` connected for all peers that had it in-flight.
    /// This is important when frontier is requested from multiple peers.
    async fn ibd_mark_connected_all(&mut self, block_hash: &BlockHash) {
        if self.ibd.is_complete() {
            return;
        }
        let owners: Vec<u64> = self
            .ibd
            .peer_downloads
            .iter()
            .filter(|(_, dl)| dl.hashes.iter().any(|h| h == block_hash))
            .map(|(peer_id, _)| *peer_id)
            .collect();
        let mut any_batch_done = false;
        for peer_id in owners {
            self.note_peer_delivery(peer_id);
            if self.ibd.complete_peer_block(peer_id, block_hash) {
                any_batch_done = true;
            }
        }
        if any_batch_done {
            self.assign_blocks_to_peers().await;
        }
    }

    async fn handle_block(
        &mut self,
        peer_id: u64,
        block: rbtc_primitives::block::Block,
    ) -> Result<()> {
        let block_hash = header_hash(&block.header);

        // Clear from global block download tracker.
        self.block_tracker.mark_received(&block_hash);

        // Skip if already connected or marked invalid.
        let (already_connected, is_invalid) = {
            let chain = self.chain.read().await;
            let connected = Self::is_block_connected(&chain, &block_hash);
            let invalid = chain
                .block_index
                .get(&block_hash)
                .map(|bi| bi.status.has_failed())
                .unwrap_or(false);
            (connected, invalid)
        };
        if already_connected || is_invalid {
            if is_invalid {
                debug!(
                    "skipping invalid block {} from peer {peer_id}",
                    block_hash.to_hex()
                );
            }
            self.ibd_mark_connected_all(&block_hash).await;
            return Ok(());
        }

        // Determine height; add header to index if not yet known.
        let height = {
            let mut chain = self.chain.write().await;
            match chain.block_index.get(&block_hash) {
                Some(bi) => bi.height,
                None => {
                    if let Err(e) = chain.add_header(block.header.clone()) {
                        warn!("unknown block header from peer {peer_id}: {e}");
                        drop(chain);
                        // Bitcoin Core: BLOCK_MISSING_PREV → Misbehaving(peer)
                        // unconditionally (no IBD special case).
                        self.peer_manager.misbehave(peer_id, 10, "block-missing-prev");
                        return Ok(());
                    }
                    chain.block_index[&block_hash].height
                }
            }
        };

        let chain_height = self.chain.read().await.height();

        if height > chain_height + 1 {
            // Out-of-order block: cache it for later connection.
            debug!(
                "cached out-of-order block {} at height {} (tip={}) from peer {}",
                block_hash.to_hex(),
                height,
                chain_height,
                peer_id
            );
            let candidates = self.pending_blocks.entry(height).or_default();
            let already_cached = candidates
                .iter()
                .any(|(_, b)| header_hash(&b.header) == block_hash);
            if !already_cached {
                candidates.push((peer_id, block));
            }
            return Ok(());
        }

        if height <= chain_height {
            // Side-chain or stale block. Store its data so we can reorg to it
            // if its chain accumulates more work than the active chain.
            let already_have_data = BlockStore::new(&self.db).has_block(&block_hash)?;
            if !already_have_data {
                BlockStore::new(&self.db).put_block(&block_hash, &block)?;
                {
                    let mut chain = self.chain.write().await;
                    if let Some(bi) = chain.block_index.get_mut(&block_hash) {
                        if !bi.status.have_data() {
                            bi.status = bi.status.with_validity(BLOCK_VALID_TRANSACTIONS).with_data();
                        }
                    }
                }
                if let Some(mut stored) = BlockStore::new(&self.db).get_index(&block_hash)? {
                    stored.status = BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data();
                    BlockStore::new(&self.db).put_index(&block_hash, &stored)?;
                }
                debug!(
                    "stored side-chain block {} at height {} (tip={})",
                    block_hash.to_hex(),
                    height,
                    chain_height
                );
            }
            self.ibd_mark_connected_all(&block_hash).await;
            self.activate_best_chain().await?;
            return Ok(());
        }

        // height == chain_height + 1: validate and connect immediately, then
        // drain any consecutively-pending blocks that are now unblocked.
        if let Err(e) = self
            .do_connect_block(peer_id, block_hash, block, height)
            .await
        {
            // Block failed validation — already marked Invalid in do_connect_block.
            // Still mark the IBD delivery as complete so the scheduler can move on
            // (it will skip invalid blocks when rebuilding the canonical chain).
            warn!("block connection failed at height {height}: {e}");
            self.ibd_mark_connected_all(&block_hash).await;
            return Ok(());
        }
        self.ibd_mark_connected_all(&block_hash).await;

        loop {
            let next_height = self.chain.read().await.height() + 1;
            let Some(mut candidates) = self.pending_blocks.remove(&next_height) else {
                break;
            };
            let expected_prev = {
                let chain = self.chain.read().await;
                if let Some(tip) = chain.best_hash() {
                    tip
                } else if next_height == 1 {
                    BlockHash::from_hex(chain.network.genesis_hash()).map_err(|_| {
                        anyhow!("invalid genesis hash encoding for {:?}", chain.network)
                    })?
                } else {
                    break;
                }
            };
            let Some((idx, _)) = candidates
                .iter()
                .enumerate()
                .find(|(_, (_, b))| b.header.prev_block == expected_prev)
            else {
                // Keep candidates for retry/diagnostics. If none extend current tip,
                // this height cannot connect yet.
                self.pending_blocks.insert(next_height, candidates);
                break;
            };
            let (p_peer, p_block) = candidates.remove(idx);
            if !candidates.is_empty() {
                self.pending_blocks.insert(next_height, candidates);
            }
            let p_hash = header_hash(&p_block.header);
            if let Err(e) = self
                .do_connect_block(p_peer, p_hash, p_block, next_height)
                .await
            {
                warn!("pending block connection failed at height {next_height}: {e}");
                self.ibd_mark_connected_all(&p_hash).await;
                break;
            }
            // Mark connected here — not at cache time — so peer batch tracking
            // reflects actual chain progress, not just block delivery.
            self.ibd_mark_connected_all(&p_hash).await;
        }

        // Check if any stored side-chain now has more work
        self.activate_best_chain().await?;

        Ok(())
    }

    /// Validate and connect a single block at `height == chain.height() + 1`.
    /// Does NOT update IBD delivery tracking — the caller is responsible.
    async fn do_connect_block(
        &mut self,
        peer_id: u64,
        block_hash: BlockHash,
        block: rbtc_primitives::block::Block,
        height: u32,
    ) -> Result<()> {
        let connect_started = Instant::now();
        let network_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        // Core-style invariant: only connect blocks that extend the current
        // active tip. Side-branch blocks may be indexed, but must not mutate
        // the active chain UTXO state through this path.
        let expected_prev = {
            let chain = self.chain.read().await;
            if let Some(tip) = chain.best_hash() {
                tip
            } else if height == 1 {
                BlockHash::from_hex(chain.network.genesis_hash())
                    .map_err(|_| anyhow!("invalid genesis hash encoding for {:?}", chain.network))?
            } else {
                return Err(anyhow!(
                    "connect invariant violated: missing best tip before height {height}"
                ));
            }
        };
        if block.header.prev_block != expected_prev {
            return Err(anyhow!(
                "block {} does not extend active tip: prev={} expected={} height={} peer={}",
                block_hash.to_hex(),
                block.header.prev_block.to_hex(),
                expected_prev.to_hex(),
                height,
                peer_id
            ));
        }

        // Core-style: query MTP from block index on demand during verification.
        let verify_started = Instant::now();
        let assumevalid_skip_scripts;
        let validation_result = {
            let chain = self.chain.read().await;
            let expected_bits = chain.next_required_bits();
            let mtp = chain.median_time_past(height.saturating_sub(1));
            let network = chain.network;
            let flags = script_flags_for_block(network, height, block_hash.0, block.header.time, mtp);
            let mtp_provider = ChainMtpProvider { chain: &chain };
            assumevalid_skip_scripts =
                self.should_skip_scripts_with_assumevalid(&chain, height, block_hash);

            let ctx = BlockValidationContext {
                block: &block,
                height,
                median_time_past: mtp,
                network_time,
                expected_bits,
                flags,
                network,
                mtp_provider: &mtp_provider,
                signet_challenge: self.signet_challenge.as_deref(),
            };
            // Two-phase validation (Bitcoin Core's CheckBlock + ConnectBlock):
            // Phase 1: context-free structural checks (no UTXO access).
            check_block(&ctx)?;
            // Phase 2: context-dependent checks (UTXO lookups, scripts, fees).
            connect_block_with_options(&ctx, &self.utxo_cache, assumevalid_skip_scripts)
        };
        let verify_elapsed = verify_started.elapsed();
        if assumevalid_skip_scripts && !self.assumevalid_announced {
            self.assumevalid_announced = true;
            info!(
                "assumevalid active: skipping script checks while connecting historical ancestors"
            );
        }
        if assumevalid_skip_scripts {
            self.assumevalid_skipped_blocks = self.assumevalid_skipped_blocks.saturating_add(1);
            self.assumevalid_saved_verify_ms = self
                .assumevalid_saved_verify_ms
                .saturating_add(verify_elapsed.as_millis());
            self.assumevalid_last_height = Some(height);
        }

        match validation_result {
            Ok(fees) => {
                info!(
                    "block {} at height {height} validated (fees={fees} sat)",
                    block_hash.to_hex()
                );

                // Compute txids for UTXO tracking
                let txids: Vec<Txid> = block
                    .transactions
                    .iter()
                    .map(|tx| {
                        let mut buf = Vec::new();
                        tx.encode_legacy(&mut buf).ok();
                        Txid(sha256d(&buf))
                    })
                    .collect();

                // Update UTXO cache and collect per-tx undo.
                let undo = match self
                    .utxo_cache
                    .connect_block_with_undo(&txids, &block.transactions, height)
                {
                    Ok(u) => u,
                    Err(e) => {
                        // connect_block_with_undo rolls back its dirty layer
                        // on failure, so the cache remains consistent.  Mark
                        // the block as failed to prevent infinite retries.
                        warn!(
                            "block {} at height {height} UTXO connect failed: {e}",
                            block_hash.to_hex()
                        );
                        {
                            let mut chain = self.chain.write().await;
                            if let Some(bi) = chain.block_index.get_mut(&block_hash) {
                                bi.status = bi.status.with_failed();
                            }
                        }
                        // Persist failed status to block store (matching Core's
                        // InvalidBlockFound which writes to disk).
                        if let Ok(Some(mut stored)) = BlockStore::new(&self.db).get_index(&block_hash) {
                            stored.status = stored.status.with_failed();
                            let _ = BlockStore::new(&self.db).put_index(&block_hash, &stored);
                        }
                        return Err(anyhow!("failed to connect block UTXO state: {e}"));
                    }
                };
                // Convert undo data to storage format and persist
                let undo_stored: Vec<Vec<(rbtc_primitives::transaction::OutPoint, StoredUtxo)>> =
                    undo.iter()
                        .map(|tx_undo| {
                            tx_undo
                                .iter()
                                .map(|(op, u)| {
                                    (
                                        op.clone(),
                                        StoredUtxo {
                                            value: u.txout.value,
                                            script_pubkey: u.txout.script_pubkey.clone(),
                                            height: u.height,
                                            is_coinbase: u.is_coinbase,
                                        },
                                    )
                                })
                                .collect()
                        })
                        .collect();

                // Persist everything to RocksDB in one atomic WriteBatch:
                // block metadata, UTXO changes (via cache flush), and chain tip.
                let write_started = Instant::now();
                {
                    let chainwork = self.chain.read().await.block_index[&block_hash].chainwork;

                    let stored_idx = StoredBlockIndex {
                        header: block.header.clone(),
                        height,
                        chainwork_lo: chainwork.0[0],
                        chainwork_hi: chainwork.0[1],
                        // Persist as Valid first; only mark InChain in memory after
                        // the chainstate batch commit succeeds.
                        status: BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
                    };
                    // Single WriteBatch for block index/data/undo + UTXO changes
                    // + chain tip. This prevents partial persistence such as
                    // "index exists but raw block is missing" after crashes.
                    let mut batch = self.db.new_batch();
                    self.db.batch_put_cf(
                        &mut batch,
                        rbtc_storage::db::CF_BLOCK_INDEX,
                        &block_hash.0.0,
                        &stored_idx.encode_bytes(),
                    )?;
                    self.db.batch_put_cf(
                        &mut batch,
                        rbtc_storage::db::CF_BLOCK_DATA,
                        &block_hash.0.0,
                        &block.encode_to_vec(),
                    )?;
                    self.db.batch_put_cf(
                        &mut batch,
                        rbtc_storage::db::CF_UNDO,
                        &block_hash.0.0,
                        &encode_block_undo(&undo_stored),
                    )?;

                    // Stage dirty UTXO changes into the same atomic batch.
                    let utxo_flush_plan = self.utxo_cache.prepare_flush_dirty(&mut batch)?;

                    let chain_store = ChainStore::new(&self.db);
                    chain_store.update_tip_batch(&mut batch, &block_hash, height, &chainwork)?;

                    self.db.write_batch(batch)?;
                    self.utxo_cache.commit_flush_plan(utxo_flush_plan);

                    // CValidationInterface: chain state flushed to disk
                    self.notifier.notify(ValidationEvent::ChainStateFlushed {
                        best_hash: block_hash,
                    });

                    // Evicting every block can be expensive at high heights; throttle it.
                    self.blocks_since_utxo_evict = self.blocks_since_utxo_evict.saturating_add(1);
                    if self.blocks_since_utxo_evict >= UTXO_EVICT_INTERVAL_BLOCKS {
                        self.utxo_cache.evict_cold();
                        self.blocks_since_utxo_evict = 0;
                    }
                }
                {
                    let mut chain = self.chain.write().await;
                    if let Some(bi) = chain.block_index.get_mut(&block_hash) {
                        bi.status = bi.status.with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo();
                    }
                    if height as usize >= chain.active_chain.len() {
                        chain
                            .active_chain
                            .resize(height as usize + 1, BlockHash::ZERO);
                    }
                    chain.active_chain[height as usize] = block_hash;
                    let new_work = chain.block_index[&block_hash].chainwork;
                    let cur_work = chain
                        .best_tip
                        .and_then(|h| chain.block_index.get(&h))
                        .map(|bi| bi.chainwork)
                        .unwrap_or(U256::ZERO);
                    if new_work > cur_work {
                        chain.best_tip = Some(block_hash);
                    }
                }
                let write_elapsed = write_started.elapsed();

                // Index writes are deferred during IBD and handled asynchronously once synced.
                if self.should_defer_indexes() {
                    debug!(
                        "index defer: height={} hash={} (IBD phase={:?})",
                        height,
                        block_hash.to_hex(),
                        self.ibd.phase
                    );
                } else {
                    self.enqueue_index_task(height, block_hash);
                }

                // Remove confirmed transactions from the mempool and notify
                {
                    let mut mp = self.mempool.write().await;
                    mp.remove_confirmed(&txids);
                    // Notify: transactions removed from mempool due to block inclusion
                    for txid in &txids[1..] {
                        // Skip coinbase (index 0) — it was never in the mempool
                        self.notifier.notify(ValidationEvent::TransactionRemovedFromMempool {
                            txid: *txid,
                            reason: MempoolRemovalReason::Block,
                        });
                    }
                }

                // Remove orphans that conflict with block transactions
                self.orphan_pool.erase_for_block(&txids, &block.transactions);

                // Update wallet UTXO tracking (incremental block scan)
                if let Some(wallet) = &self.wallet {
                    let mut w = wallet.write().await;
                    w.scan_block(&block, height);
                    w.remove_spent(&block);
                }

                // Update peer manager's best height
                self.peer_manager.set_best_height(height as i32);

                // BIP22 longpoll: notify waiting GBT clients that the tip changed.
                self.longpoll.notify_new_tip(&block_hash.to_hex());

                // Notify waitfornewblock RPC callers.
                let _ = self.new_tip_tx.send((block_hash.to_hex(), height));

                // CValidationInterface notifications
                self.notifier.notify(ValidationEvent::BlockConnected {
                    block: Arc::new(block),
                    height,
                });
                self.notifier.notify(ValidationEvent::UpdatedBlockTip {
                    hash: block_hash,
                    height,
                    is_ibd: !self.ibd.is_complete(),
                });

                // Record progress for IBD stall detection (Headers phase timer)
                if !self.ibd.is_complete() {
                    self.ibd.record_progress();
                }

                // Prune old block data if requested
                self.maybe_prune(height).await;
                debug!(
                    "connect timing: height={} verify_ms={} write_ms={} total_ms={}",
                    height,
                    verify_elapsed.as_millis(),
                    write_elapsed.as_millis(),
                    connect_started.elapsed().as_millis()
                );
            }
            Err(e) => {
                warn!(
                    "block {} at height {height} rejected from peer {peer_id}: {e}",
                    block_hash.to_hex()
                );
                // Core-style: mark the block as invalid so it is never retried.
                {
                    let mut chain = self.chain.write().await;
                    if let Some(bi) = chain.block_index.get_mut(&block_hash) {
                        bi.status = bi.status.with_failed();
                    }
                }
                return Err(anyhow!(
                    "block {} rejected: {e}",
                    block_hash.to_hex()
                ));
            }
        }

        Ok(())
    }

    fn should_skip_scripts_with_assumevalid(
        &self,
        chain: &ChainState,
        height: u32,
        block_hash: BlockHash,
    ) -> bool {
        if self.check_all_scripts {
            return false;
        }
        if self.ibd.phase != IbdPhase::Blocks {
            return false;
        }
        let Some(assumevalid_hash) = self.assumevalid_hash else {
            return false;
        };
        let Some(assumevalid_bi) = chain.block_index.get(&assumevalid_hash) else {
            return false;
        };
        if let Some(min_chain_work) = self.min_chain_work {
            let best_work = chain
                .best_tip
                .and_then(|tip| chain.block_index.get(&tip))
                .map(|bi| bi.chainwork)
                .unwrap_or(U256::ZERO);
            if best_work < min_chain_work {
                return false;
            }
        }
        if chain
            .active_chain
            .get(assumevalid_bi.height as usize)
            .copied()
            != Some(assumevalid_hash)
        {
            return false;
        }
        if height > assumevalid_bi.height {
            return false;
        }
        let Some(canon_hash) = self.canonical_header_chain.get(height as usize) else {
            return false;
        };
        if *canon_hash != block_hash {
            return false;
        }
        let Some(canon_assumevalid) = self
            .canonical_header_chain
            .get(assumevalid_bi.height as usize)
        else {
            return false;
        };
        *canon_assumevalid == assumevalid_hash
    }

    /// Accept an unconfirmed transaction into the mempool and relay it.
    async fn handle_tx(&mut self, peer_id: u64, tx: rbtc_primitives::transaction::Transaction) {
        let txid = *tx.txid();

        // Skip if already in orphan pool.
        if self.orphan_pool.have_tx(&txid) {
            return;
        }

        let height = self.chain.read().await.height();

        // Clone tx before passing ownership to accept_tx, so we can store it
        // in the orphan pool if it fails with MissingInput.
        let tx_for_orphan = tx.clone();
        let mut mp = self.mempool.write().await;

        match mp.accept_tx(tx, &self.utxo_cache, height) {
            Ok(accepted_txid) => {
                info!(
                    "mempool: accepted tx {} from peer {peer_id}",
                    accepted_txid.to_hex()
                );
                // Compute fee rate in sat/kvB for feefilter comparison
                let fee_rate_sat_kvb = mp
                    .get(&accepted_txid)
                    .map(|e| e.fee_rate * 1000)
                    .unwrap_or(0);
                drop(mp);

                // BIP22 longpoll: notify waiting GBT clients that the mempool changed.
                self.longpoll.notify_mempool_change();

                // CValidationInterface: transaction accepted
                self.notifier.notify(ValidationEvent::TransactionAddedToMempool {
                    txid: accepted_txid,
                });

                // Announce to peers whose feefilter allows this tx
                let legacy_hash = {
                    let mut buf = Vec::new();
                    tx_for_orphan.encode_legacy(&mut buf).ok();
                    sha256d(&buf)
                };
                let inv = vec![Inventory {
                    inv_type: InvType::WitnessTx,
                    hash: legacy_hash,
                }];
                self.peer_manager
                    .broadcast_tx_inv(NetworkMessage::Inv(inv), fee_rate_sat_kvb);

                // Check orphan pool for children whose parent just got accepted.
                let children = self.orphan_pool.get_children_of(&accepted_txid);
                for (child_tx, _child_peer) in children {
                    let child_wtxid = *child_tx.wtxid();
                    let child_txid = *child_tx.txid();
                    let mut mp2 = self.mempool.write().await;
                    match mp2.accept_tx(child_tx, &self.utxo_cache, height) {
                        Ok(_) => {
                            info!(
                                "mempool: accepted orphan tx {} (parent {})",
                                child_txid.to_hex(),
                                accepted_txid.to_hex()
                            );
                            self.orphan_pool.erase_tx(&child_wtxid);
                        }
                        Err(_) => {
                            // Still missing inputs or other error — leave in orphan pool
                            // or remove if it's a permanent failure
                            self.orphan_pool.erase_tx(&child_wtxid);
                        }
                    }
                    drop(mp2);
                }
            }
            Err(e) => {
                // AlreadyKnown is not worth logging
                if !matches!(e, rbtc_mempool::MempoolError::AlreadyKnown) {
                    if matches!(e, rbtc_mempool::MempoolError::MissingInput(_, _)) {
                        drop(mp);
                        // Add to orphan pool if missing inputs
                        match self.orphan_pool.add_tx(tx_for_orphan, peer_id) {
                            rbtc_mempool::AddOrphanResult::Added => {
                                debug!(
                                    "orphan pool: added tx {} from peer {peer_id} ({} orphans)",
                                    txid.to_hex(),
                                    self.orphan_pool.len()
                                );
                            }
                            _ => {}
                        }
                    } else {
                        warn!(
                            "mempool: rejected tx {} from peer {peer_id}: {e}",
                            txid.to_hex()
                        );
                    }
                }
            }
        }
    }

    async fn handle_invalidate_block(&mut self, hash: BlockHash) -> Result<()> {
        let descendants = {
            let chain = self.chain.read().await;
            collect_subtree_hashes(&chain, hash)?
        };
        if descendants.is_empty() {
            return Err(anyhow!(
                "invalidateblock: block {} not found",
                hash.to_hex()
            ));
        }

        // Mark target with BLOCK_FAILED_VALID, descendants with BLOCK_FAILED_CHILD
        self.set_status_for_hashes(&descendants[..1], |s| *s = s.with_failed())
            .await?;
        if descendants.len() > 1 {
            self.set_status_for_hashes(&descendants[1..], |s| *s = s.with_failed_child())
                .await?;
        }
        info!(
            "invalidateblock: marked {} block(s) invalid from {}",
            descendants.len(),
            hash.to_hex()
        );

        if let Some(best_valid_tip) = self.select_best_valid_tip().await {
            let current_tip = self.chain.read().await.best_tip;
            if current_tip != Some(best_valid_tip) {
                self.reorganize_to(best_valid_tip).await?;
            }
        }
        Ok(())
    }

    async fn handle_reconsider_block(&mut self, hash: BlockHash) -> Result<()> {
        // Collect descendants
        let descendants = {
            let chain = self.chain.read().await;
            collect_subtree_hashes(&chain, hash)?
        };
        if descendants.is_empty() {
            return Err(anyhow!(
                "reconsiderblock: block {} not found",
                hash.to_hex()
            ));
        }

        // Collect ancestors (walk back to genesis)
        let ancestors = {
            let chain = self.chain.read().await;
            let mut anc = Vec::new();
            let mut cursor = hash;
            while let Some(bi) = chain.block_index.get(&cursor) {
                if bi.height == 0 {
                    break;
                }
                cursor = bi.header.prev_block;
                anc.push(cursor);
            }
            anc
        };

        // Collect all failed blocks among descendants + ancestors
        let to_restore = {
            let chain = self.chain.read().await;
            descendants
                .iter()
                .chain(ancestors.iter())
                .copied()
                .filter(|h| {
                    chain
                        .block_index
                        .get(h)
                        .map(|bi| bi.status.has_failed())
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>()
        };
        // Clear both BLOCK_FAILED_VALID and BLOCK_FAILED_CHILD
        self.set_status_for_hashes(&to_restore, |s| *s = s.without_failed())
            .await?;
        info!(
            "reconsiderblock: restored {} block(s) from {}",
            to_restore.len(),
            hash.to_hex()
        );

        self.activate_best_chain().await?;
        if let Some(best_valid_tip) = self.select_best_valid_tip().await {
            let current_tip = self.chain.read().await.best_tip;
            if current_tip != Some(best_valid_tip) {
                self.reorganize_to(best_valid_tip).await?;
            }
        }
        Ok(())
    }

    async fn select_best_valid_tip(&self) -> Option<BlockHash> {
        let chain = self.chain.read().await;
        chain
            .block_index
            .iter()
            .filter(|(_, bi)| bi.status.is_valid(BLOCK_VALID_TRANSACTIONS))
            .max_by_key(|(_, bi)| bi.chainwork)
            .map(|(h, _)| *h)
    }

    /// Check that all blocks on the path from fork_point to `tip` have block
    /// data available on disk, so that `reorganize_to` can load them.
    async fn chain_data_available(&self, tip: BlockHash) -> Result<bool> {
        let chain = self.chain.read().await;
        let block_store = BlockStore::new(&self.db);
        let mut cursor = tip;
        loop {
            let bi = chain.block_index.get(&cursor).ok_or_else(|| {
                anyhow!("chain_data_available: unknown block {}", cursor.to_hex())
            })?;
            if chain.is_in_active_chain(&cursor) {
                return Ok(true);
            }
            if bi.status.has_failed() || !bi.status.have_data() {
                return Ok(false);
            }
            if !block_store.has_block(&cursor)? {
                return Ok(false);
            }
            cursor = bi.header.prev_block;
        }
    }

    /// Bitcoin Core-style ActivateBestChain: if the most-work valid tip
    /// differs from our active tip, reorganize to it. Loops until stable
    /// (handles cascading reorgs where connecting blocks reveals more work).
    async fn activate_best_chain(&mut self) -> Result<()> {
        loop {
            let best_valid = match self.select_best_valid_tip().await {
                Some(tip) => tip,
                None => return Ok(()),
            };
            let current_tip = self.chain.read().await.best_tip;
            if current_tip == Some(best_valid) {
                return Ok(());
            }
            let (current_work, candidate_work) = {
                let chain = self.chain.read().await;
                let cw = current_tip
                    .and_then(|h| chain.block_index.get(&h))
                    .map(|bi| bi.chainwork)
                    .unwrap_or(U256::ZERO);
                let nw = chain
                    .block_index
                    .get(&best_valid)
                    .map(|bi| bi.chainwork)
                    .unwrap_or(U256::ZERO);
                (cw, nw)
            };
            if candidate_work <= current_work {
                return Ok(());
            }
            if !self.chain_data_available(best_valid).await? {
                debug!(
                    "activate_best_chain: candidate {} missing block data, skipping",
                    best_valid.to_hex()
                );
                return Ok(());
            }
            info!(
                "activate_best_chain: reorging to {} (work {} -> {})",
                best_valid.to_hex(),
                current_work,
                candidate_work
            );
            self.reorganize_to(best_valid).await?;

            // Drain pending_blocks that may now extend the new tip
            loop {
                let next_height = self.chain.read().await.height() + 1;
                let Some(mut candidates) = self.pending_blocks.remove(&next_height) else {
                    break;
                };
                let expected_prev = match self.chain.read().await.best_hash() {
                    Some(tip) => tip,
                    None => {
                        self.pending_blocks.insert(next_height, candidates);
                        break;
                    }
                };
                let pos = candidates
                    .iter()
                    .position(|(_, b)| b.header.prev_block == expected_prev);
                match pos {
                    Some(idx) => {
                        let (peer, blk) = candidates.remove(idx);
                        if !candidates.is_empty() {
                            self.pending_blocks.insert(next_height, candidates);
                        }
                        let h = header_hash(&blk.header);
                        if let Err(e) =
                            self.do_connect_block(peer, h, blk, next_height).await
                        {
                            warn!(
                                "pending block after reorg failed at height {next_height}: {e}"
                            );
                            break;
                        }
                    }
                    None => {
                        self.pending_blocks.insert(next_height, candidates);
                        break;
                    }
                }
            }
        }
    }

    async fn set_status_for_hashes(
        &mut self,
        hashes: &[BlockHash],
        update: impl Fn(&mut BlockStatus),
    ) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        {
            let mut chain = self.chain.write().await;
            for hash in hashes {
                if let Some(bi) = chain.block_index.get_mut(hash) {
                    update(&mut bi.status);
                }
            }
        }
        let block_store = BlockStore::new(&self.db);
        for hash in hashes {
            if let Some(mut stored) = block_store.get_index(hash)? {
                update(&mut stored.status);
                block_store.put_index(hash, &stored)?;
            }
        }
        Ok(())
    }

    /// Reorg: disconnect the current best chain back to `fork_point` and
    /// connect the new chain. Requires undo data to be present in storage.
    async fn reorganize_to(&mut self, new_tip: rbtc_primitives::hash::BlockHash) -> Result<()> {
        if self.chain.read().await.best_tip == Some(new_tip) {
            return Ok(());
        }
        let (fork_point, old_chain, new_chain) = {
            let chain = self.chain.read().await;
            find_fork(&chain, new_tip)?
        };

        info!(
            "reorg: fork at height {fork_point}, disconnecting {} blocks, connecting {} blocks",
            old_chain.len(),
            new_chain.len()
        );

        let tx_idx = TxIndexStore::new(&self.db);
        let addr_idx = AddrIndexStore::new(&self.db);
        let chain_store = ChainStore::new(&self.db);

        // Disconnect old chain (reverse order)
        for hash in old_chain.iter().rev() {
            let block = BlockStore::new(&self.db)
                .get_block(hash)?
                .ok_or_else(|| anyhow::anyhow!("reorg: missing block {}", hash.to_hex()))?;
            let undo_bytes = BlockStore::new(&self.db)
                .get_undo(hash)?
                .ok_or_else(|| anyhow::anyhow!("reorg: missing undo for {}", hash.to_hex()))?;
            let undo = decode_block_undo(&undo_bytes, &block.transactions)?;

            let txids: Vec<Txid> = block
                .transactions
                .iter()
                .map(|tx| {
                    let mut buf = Vec::new();
                    tx.encode_legacy(&mut buf).ok();
                    Txid(sha256d(&buf))
                })
                .collect();

            let disconnected_height = self
                .chain
                .read()
                .await
                .block_index
                .get(hash)
                .map(|bi| bi.height)
                .ok_or_else(|| anyhow!("reorg: missing block index {}", hash.to_hex()))?;

            // In-memory UTXO undo
            let mem_undo: Vec<
                Vec<(
                    rbtc_primitives::transaction::OutPoint,
                    rbtc_consensus::utxo::Utxo,
                )>,
            > = undo
                .iter()
                .map(|tx_undo| {
                    tx_undo
                        .iter()
                        .map(|(op, s)| {
                            use rbtc_primitives::transaction::TxOut;
                            (
                                op.clone(),
                                rbtc_consensus::utxo::Utxo {
                                    txout: TxOut {
                                        value: s.value,
                                        script_pubkey: s.script_pubkey.clone(),
                                    },
                                    is_coinbase: s.is_coinbase,
                                    height: s.height,
                                },
                            )
                        })
                        .collect()
                })
                .collect();

            self.utxo_cache
                .disconnect_block(&txids, &block.transactions, mem_undo);

            let (new_best_tip, new_best_height, new_best_work) = {
                let mut chain = self.chain.write().await;
                chain.disconnect_tip()?;
                let best = chain
                    .best_tip
                    .ok_or_else(|| anyhow!("reorg: missing best tip after disconnect"))?;
                let (best_height, best_work) = chain
                    .block_index
                    .get(&best)
                    .map(|bi| (bi.height, bi.chainwork))
                    .ok_or_else(|| anyhow!("reorg: missing best tip index {}", best.to_hex()))?;
                    // No status change needed on disconnect — validation level preserved
                (best, best_height, best_work)
            };

            if let Some(mut stored_idx) = BlockStore::new(&self.db).get_index(hash)? {
                stored_idx.status = BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data();
                BlockStore::new(&self.db).put_index(hash, &stored_idx)?;
            }

            let mut batch = self.db.new_batch();
            let utxo_flush_plan = self.utxo_cache.prepare_flush_dirty(&mut batch)?;
            for (offset, (tx, txid)) in block.transactions.iter().zip(txids.iter()).enumerate() {
                tx_idx.batch_remove(&mut batch, &txid.0)?;
                for output in &tx.outputs {
                    addr_idx.batch_remove(
                        &mut batch,
                        &output.script_pubkey.0,
                        disconnected_height,
                        offset as u32,
                    )?;
                }
            }
            chain_store.update_tip_batch(
                &mut batch,
                &new_best_tip,
                new_best_height,
                &new_best_work,
            )?;
            self.db.write_batch(batch)?;
            self.utxo_cache.commit_flush_plan(utxo_flush_plan);

            // CValidationInterface: notify block disconnected
            self.notifier.notify(ValidationEvent::BlockDisconnected {
                block: Arc::new(block.clone()),
                height: disconnected_height,
            });

            // M12: Re-add non-coinbase transactions from disconnected blocks to
            // the mempool so they can be mined in the new chain (matching
            // Bitcoin Core's DisconnectTip → MaybeResurrectMempoolTransactions).
            {
                let chain_height = new_best_height;
                let mut mp = self.mempool.write().await;
                for tx in block.transactions.iter().skip(1) {
                    // Best-effort: ignore failures (tx may conflict with new chain).
                    let _ = mp.accept_tx(tx.clone(), &self.utxo_cache, chain_height);
                }
            }
        }

        // Connect new chain (forward order)
        for hash in &new_chain {
            let block = BlockStore::new(&self.db)
                .get_block(hash)?
                .ok_or_else(|| anyhow::anyhow!("reorg: missing block {}", hash.to_hex()))?;
            let height = self
                .chain
                .read()
                .await
                .block_index
                .get(hash)
                .map(|bi| bi.height)
                .ok_or_else(|| anyhow!("reorg: missing block index {}", hash.to_hex()))?;
            if let Err(e) = self
                .do_connect_block(LOCAL_PEER_ID, *hash, block, height)
                .await
            {
                warn!(
                    "reorg: block {} failed validation during connect: {e}",
                    hash.to_hex()
                );
                // Mark the block as Invalid so it won't be selected again
                {
                    let mut chain = self.chain.write().await;
                    if let Some(bi) = chain.block_index.get_mut(hash) {
                        bi.status = bi.status.with_failed();
                    }
                }
                if let Some(mut stored_idx) = BlockStore::new(&self.db).get_index(hash)? {
                    stored_idx.status =
                        BlockStatus::new().with_validity(BLOCK_VALID_TREE).with_failed();
                    BlockStore::new(&self.db).put_index(hash, &stored_idx)?;
                }
                // Return Ok — activate_best_chain's loop will pick the next-best tip
                return Ok(());
            }
        }

        self.peer_manager
            .set_best_height(self.chain.read().await.height() as i32);
        info!("reorg complete; new tip {}", new_tip.to_hex());
        Ok(())
    }

    async fn request_headers(&self, peer_id: u64) {
        let chain = self.chain.read().await;
        let height = chain.height();
        let network = chain.network;
        let mut locator = build_locator(height, |h| chain.get_ancestor_hash(h));

        // block_index may hold more headers than active_chain (e.g. after a restart
        // or mid-download peer disconnect). Always prepend the highest known header
        // hash so peers resume from where we left off rather than re-sending already
        // known headers from the active_chain tip.
        if let Some(best_hash) = chain
            .block_index
            .values()
            .max_by_key(|bi| bi.height)
            .map(|bi| bi.hash)
        {
            if !locator.contains(&best_hash) {
                locator.insert(0, best_hash);
            }
        }

        // Always ensure genesis hash is in the locator so peers know the
        // common ancestor even when the best-header locator entry is unknown.
        if let Ok(genesis) = BlockHash::from_hex(network.genesis_hash()) {
            if !locator.contains(&genesis) {
                locator.push(genesis);
            }
        }
        drop(chain);

        self.peer_manager.send_to(
            peer_id,
            NetworkMessage::GetHeaders(rbtc_net::message::GetBlocksMessage::new(locator)),
        );
        info!("requested headers from peer {peer_id}, our height={height}");
    }

    async fn check_ibd_progress(&mut self) {
        if self.ibd.is_complete() {
            return;
        }

        if self.ibd.phase == IbdPhase::Blocks {
            let mut disconnected_any = false;
            // Frontier-specific fast failover: if the frontier block is still
            // not connected and its in-flight request is stale, recycle that
            // peer immediately instead of waiting for the full stall timeout.
            let frontier = self.chain.read().await.height().saturating_add(1);
            let frontier_hash = {
                let chain = self.chain.read().await;
                let expected_prev = if frontier == 0 {
                    BlockHash::ZERO
                } else {
                    match chain.get_ancestor_hash(frontier.saturating_sub(1)) {
                        Some(h) => h,
                        None => BlockHash::ZERO,
                    }
                };
                self.best_connectable_hash_at_height(&chain, frontier, expected_prev)
            };
            if let Some(frontier_hash) = frontier_hash {
                let frontier_connected = {
                    let chain = self.chain.read().await;
                    Self::is_block_connected(&chain, &frontier_hash)
                };
                // Skip failover if frontier block is already cached and waiting
                // to be drained — it will connect once prior blocks finish.
                let frontier_cached = self.has_connectable_pending_at_height(frontier).await;
                if !frontier_connected && !frontier_cached {
                    let frontier_owner = self
                        .ibd
                        .peer_downloads
                        .iter()
                        .find(|(_, dl)| dl.hashes.iter().any(|h| h == &frontier_hash))
                        .map(|(peer_id, dl)| (*peer_id, dl.requested_at.elapsed()));
                    if let Some((peer_id, age)) = frontier_owner {
                        if age >= ADAPTIVE_TIMEOUT_SOFT {
                            self.note_peer_timeout(peer_id);
                            let strikes = self
                                .peer_ibd_stats
                                .get(&peer_id)
                                .map(|s| s.timeout_strikes)
                                .unwrap_or(0);
                            warn!(
                                "IBD frontier timeout: height {} in-flight on peer {} for {}s; strikes={}; failover",
                                frontier,
                                peer_id,
                                age.as_secs(),
                                strikes
                            );
                            self.ibd.release_peer(peer_id);
                            if age >= ADAPTIVE_TIMEOUT_HARD || strikes >= 2 {
                                self.request_peer_disconnect(peer_id);
                            }
                            disconnected_any = true;
                        }
                    }
                }
            }

            // Global block download tracker stall detection (exponential backoff).
            let tracker_stalled = self.block_tracker.check_stalls();
            for sp in &tracker_stalled {
                debug!(
                    "block_tracker: peer {} stalled for {}s ({} blocks held)",
                    sp.peer_id,
                    sp.stall_duration.as_secs(),
                    sp.blocks_held
                );
            }

            // Per-peer adaptive stall detection: soft reassign first, hard disconnect on repeated timeouts.
            let stalled = self.ibd.stalled_peers(ADAPTIVE_TIMEOUT_SOFT);
            for peer_id in stalled {
                let age = self
                    .ibd
                    .peer_downloads
                    .get(&peer_id)
                    .map(|dl| dl.requested_at.elapsed())
                    .unwrap_or(ADAPTIVE_TIMEOUT_SOFT);
                self.note_peer_timeout(peer_id);
                let strikes = self
                    .peer_ibd_stats
                    .get(&peer_id)
                    .map(|s| s.timeout_strikes)
                    .unwrap_or(0);
                warn!(
                    "IBD stall: peer {} made no progress for {}s; strikes={}; re-assigning range",
                    peer_id,
                    age.as_secs(),
                    strikes
                );
                self.ibd.release_peer(peer_id);
                if age >= ADAPTIVE_TIMEOUT_HARD || strikes >= 2 {
                    self.request_peer_disconnect(peer_id);
                }
                disconnected_any = true;
            }
            // Fill any idle peers with pending segments.
            if !disconnected_any {
                self.assign_blocks_to_peers().await;
            }
        } else {
            // Headers phase: per-peer sync state timeout check.
            let now = Instant::now();
            let timed_out_peers: Vec<u64> = self
                .ibd
                .per_peer_sync
                .iter()
                .filter(|(_, state)| state.is_timed_out(now))
                .map(|(&id, _)| id)
                .collect();
            for peer_id in timed_out_peers {
                warn!("headers sync: peer {peer_id} timed out; disconnecting");
                self.ibd.per_peer_sync.remove(&peer_id);
                if self.ibd.sync_peer == Some(peer_id) {
                    self.ibd.sync_peer = None;
                }
                self.request_peer_disconnect(peer_id);
            }

            // Single-peer stall detection (fallback).
            if self.ibd.is_stalled() {
                if let Some(stale) = self.ibd.sync_peer.take() {
                    warn!(
                        "IBD stall: peer {stale} made no header progress for {}s; switching",
                        STALL_TIMEOUT.as_secs()
                    );
                    self.ibd.per_peer_sync.remove(&stale);
                    self.request_peer_disconnect(stale);
                }
            }

            if self.ibd.sync_peer.is_none() {
                if let Some(peer_id) = self.peer_manager.best_peer() {
                    self.ibd.sync_peer = Some(peer_id);
                    self.ibd.record_progress();
                    let min_work = self.min_chain_work.unwrap_or(U256::ZERO);
                    let nonce = Self::random_nonce();
                    self.ibd.per_peer_sync.insert(
                        peer_id,
                        HeadersSyncState::new(min_work, nonce),
                    );
                    self.request_headers(peer_id).await;
                }
            }
        }
    }

    async fn log_stats(&self) {
        let chain = self.chain.read().await;
        let height = chain.height();
        drop(chain);
        let utxos_hot = self.utxo_cache.hot_len();
        let peers = self.peer_manager.peer_count();
        let best_peer_height = self.peer_manager.best_peer_height();
        let mp_size = self.mempool.read().await.len();
        info!(
            "height={height} peers={peers} best_peer={best_peer_height} utxo_hot={utxos_hot} mempool={mp_size} assumevalid_skipped_blocks={} assumevalid_saved_verify_ms={} assumevalid_last_height={:?}",
            self.assumevalid_skipped_blocks,
            self.assumevalid_saved_verify_ms,
            self.assumevalid_last_height
        );
    }

    /// Persist the ban to RocksDB and update the in-memory ban set.
    fn handle_ban_peer(&self, ip: IpAddr) {
        let peer_store = PeerStore::new(&self.db);
        if let Err(e) = peer_store.ban(ip, BAN_DURATION) {
            warn!("failed to persist ban for {ip}: {e}");
        }
        info!("banned peer IP {ip} for 24h");
    }

    /// Update the candidate address pool from a received `addr` message.
    fn handle_addr_received(&mut self, entries: Vec<(u32, u64, [u8; 16], u16)>) {
        for (_, services, ip_bytes, port) in &entries {
            use std::net::{IpAddr, Ipv6Addr, SocketAddr};
            let v6 = Ipv6Addr::from(*ip_bytes);
            let ip = v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .or_else(|| v6.to_ipv4().map(IpAddr::V4))
                .unwrap_or(IpAddr::V6(v6));
            let addr = SocketAddr::new(ip, *port);
            let _ = services; // services not used here; stored in peer_store
            self.peer_manager.add_candidate_addr(addr);
        }
    }

    /// Flush known peer addresses to RocksDB (called periodically and on startup).
    fn persist_peer_addrs(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_peer_persist) < Duration::from_secs(5 * 60) {
            return;
        }
        self.last_peer_persist = now;

        let addrman = self.peer_manager.addrman();
        if addrman.is_empty() {
            return;
        }

        let entries: Vec<rbtc_storage::peer_store::AddrEntry> = addrman
            .entries()
            .iter()
            .map(|info| rbtc_storage::peer_store::AddrEntry {
                addr: info.addr,
                services: info.services,
                last_seen: info.last_seen,
                last_try: info.last_try,
                last_success: info.last_success,
                n_attempts: info.n_attempts,
                in_tried: info.in_tried,
                source: info.source,
            })
            .collect();

        let peer_store = PeerStore::new(&self.db);
        if let Err(e) = peer_store.save_addrman_entries(&entries) {
            warn!("failed to persist peer addresses: {e}");
        } else {
            info!("persisted {} addrman entries", entries.len());
        }
    }
}

// ── Wallet initialisation ─────────────────────────────────────────────────────

fn load_wallet(args: &Args, db: Arc<Database>) -> Option<Arc<RwLock<Wallet>>> {
    if args.wallet.is_none() && !args.create_wallet {
        return None;
    }

    let passphrase = &args.wallet_passphrase;

    if args.create_wallet {
        // Generate a new mnemonic, print it, and initialise the wallet
        match rbtc_wallet::Mnemonic::generate(12) {
            Ok(mnemonic) => {
                println!("=== NEW WALLET MNEMONIC (keep this safe!) ===");
                println!("{}", mnemonic.phrase());
                println!("==============================================");
                match Wallet::from_mnemonic(&mnemonic, "", passphrase, args.network, db) {
                    Ok(w) => {
                        info!("new wallet created");
                        return Some(Arc::new(RwLock::new(w)));
                    }
                    Err(e) => {
                        error!("failed to create wallet: {e}");
                        return None;
                    }
                }
            }
            Err(e) => {
                error!("failed to generate mnemonic: {e}");
                return None;
            }
        }
    }

    // Try to load existing wallet
    if Wallet::exists(&db) {
        match Wallet::load(passphrase, args.network, db) {
            Ok(w) => {
                info!("wallet loaded");
                Some(Arc::new(RwLock::new(w)))
            }
            Err(e) => {
                error!("failed to load wallet: {e}");
                None
            }
        }
    } else {
        info!("no wallet found at data directory (use --create-wallet to create one)");
        None
    }
}

// ── Chain rebuild from persistent storage ────────────────────────────────────

fn write_index_batch(
    db: Arc<Database>,
    tasks: Vec<IndexTask>,
) -> anyhow::Result<IndexBatchOutcome> {
    if tasks.is_empty() {
        return Ok(IndexBatchOutcome {
            processed: 0,
            last_indexed_height: None,
            retry_tasks: Vec::new(),
        });
    }

    let block_store = BlockStore::new(&db);
    let tx_idx = TxIndexStore::new(&db);
    let addr_idx = AddrIndexStore::new(&db);
    let chain_store = ChainStore::new(&db);
    let mut batch = db.new_batch();
    let mut processed = 0usize;
    let mut last_indexed_height = None;
    let mut retry_tasks: Vec<IndexTask> = Vec::new();

    for (idx, task) in tasks.iter().enumerate() {
        let Some(block) = block_store.get_block(&task.block_hash).ok().flatten() else {
            retry_tasks.extend_from_slice(&tasks[idx..]);
            break;
        };
        let txids: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| {
                let mut buf = Vec::new();
                tx.encode_legacy(&mut buf).ok();
                sha256d(&buf)
            })
            .collect();
        for (offset, (tx, txid)) in block.transactions.iter().zip(txids.iter()).enumerate() {
            tx_idx
                .batch_put(&mut batch, txid, &task.block_hash.0, offset as u32)
                .ok();
            for output in &tx.outputs {
                addr_idx
                    .batch_put(
                        &mut batch,
                        &output.script_pubkey.0,
                        task.height,
                        offset as u32,
                        txid,
                    )
                    .ok();
            }
        }
        last_indexed_height = Some(task.height);
        processed += 1;
    }

    if let Some(h) = last_indexed_height {
        chain_store.update_indexed_height_batch(&mut batch, h).ok();
    }
    db.write_batch(batch).ok();

    Ok(IndexBatchOutcome {
        processed,
        last_indexed_height,
        retry_tasks,
    })
}

/// Minimum disk space (bytes) that triggers a warning at startup (1 GiB).
const MIN_DISK_SPACE_WARNING: u64 = 1_073_741_824;

/// Minimum disk space (bytes) that triggers a warning during operation (500 MiB).
#[allow(dead_code)]
const MIN_DISK_SPACE_RUNTIME_WARNING: u64 = 524_288_000;

/// Returns available disk space in bytes for the filesystem containing `path`,
/// or `None` if the query fails.
fn check_disk_space(path: &std::path::Path) -> Option<u64> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes()).ok()?;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            Some(stat.f_bavail as u64 * stat.f_bsize as u64)
        } else {
            None
        }
    }
}

/// DB-backed UTXO lookup for reindex script verification.
/// Wraps `UtxoStore` to implement `UtxoLookup` (reads committed data from RocksDB).
struct DbUtxoLookup<'a> {
    utxo_store: &'a UtxoStore<'a>,
}

impl rbtc_consensus::utxo::UtxoLookup for DbUtxoLookup<'_> {
    fn get_utxo(&self, outpoint: &rbtc_primitives::transaction::OutPoint) -> Option<rbtc_consensus::utxo::Utxo> {
        self.utxo_store.get(outpoint).ok().flatten().map(|stored| {
            rbtc_consensus::utxo::Utxo {
                txout: stored.to_txout(),
                is_coinbase: stored.is_coinbase,
                height: stored.height,
            }
        })
    }

    fn has_unspent_txid(&self, txid: &rbtc_primitives::hash::Txid) -> bool {
        // This is a slow path but only needed for BIP30 duplicate-txid check.
        // During reindex the chance of hitting this is negligible.
        self.utxo_store
            .get(&rbtc_primitives::transaction::OutPoint { txid: *txid, vout: 0 })
            .ok()
            .flatten()
            .is_some()
    }
}

/// MTP provider for the reindex path (wraps in-memory ChainState).
struct ReindexMtpProvider<'a> {
    chain: &'a ChainState,
}

impl rbtc_consensus::tx_verify::MedianTimeProvider for ReindexMtpProvider<'_> {
    fn median_time_past_at_height(&self, height: u32) -> u32 {
        self.chain.median_time_past(height)
    }
}

/// Rebuild chainstate (UTXO set + tip metadata) from stored blocks.
///
/// When `verify_scripts` is `true` (the `--reindex` path), every block is fully
/// validated including script execution — equivalent to a fresh IBD.
/// When `false` (the `--reindex-chainstate` path), only UTXO accounting is
/// replayed (script checks are skipped, matching Bitcoin Core behaviour).
fn reindex_chainstate_full(
    db: &Database,
    network: rbtc_primitives::network::Network,
    verify_scripts: bool,
) -> Result<()> {
    if verify_scripts {
        info!("reindex: rebuilding UTXO set WITH full script verification from genesis");
    } else {
        info!("reindex-chainstate: rebuilding UTXO set (script verification skipped)");
    }

    let block_store = BlockStore::new(db);
    let chain_store = ChainStore::new(db);
    let utxo_store = UtxoStore::new(db);

    let mut in_memory = ChainState::new(network);
    load_chain_state(&mut in_memory, db)?;

    let chainstore_tip = chain_store.get_best_block()?;
    info!(
        "reindex-chainstate: chainstore_tip={}, block_index entries={}",
        chainstore_tip.as_ref().map(|h| h.to_hex()).unwrap_or_else(|| "None".into()),
        in_memory.block_index.len()
    );
    // Candidate header tip from the full block index by maximum chainwork
    // (excluding explicitly invalid blocks).
    let header_tip = in_memory
        .block_index
        .iter()
        .filter(|(_, bi)| !bi.status.has_failed())
        .max_by_key(|(_, bi)| bi.chainwork)
        .map(|(hash, _)| *hash);
    if let Some(ht) = &header_tip {
        let bi = in_memory.block_index.get(ht).unwrap();
        info!(
            "reindex-chainstate: header_tip={} height={} has_data={}",
            ht.to_hex(), bi.height, bi.status.have_data()
        );
    }

    // Reindex chainstate requires blocks (not just headers). Walk backwards from
    // the best header tip until we find a hash with stored block data.
    // Use the in-memory block status flag (BLOCK_HAVE_DATA) instead of reading
    // full block data from disk — avoids O(N) RocksDB reads for headers-only entries.
    let data_backed_tip = if let Some(mut cursor) = header_tip {
        let mut walked = 0u32;
        loop {
            let Some(bi) = in_memory.block_index.get(&cursor) else {
                break None;
            };
            if bi.height == 0 || bi.status.have_data() {
                if walked > 0 {
                    info!(
                        "reindex-chainstate: best header tip lacked block data for {} ancestors; using height {} hash {}",
                        walked,
                        bi.height,
                        cursor.to_hex()
                    );
                }
                break Some(cursor);
            }
            walked = walked.saturating_add(1);
            cursor = bi.header.prev_block;
        }
    } else {
        None
    };

    let best_tip = match (chainstore_tip, data_backed_tip) {
        (Some(cs), Some(im)) => {
            let cs_work = in_memory
                .block_index
                .get(&cs)
                .map(|bi| bi.chainwork)
                .unwrap_or(U256::ZERO);
            let im_work = in_memory
                .block_index
                .get(&im)
                .map(|bi| bi.chainwork)
                .unwrap_or(U256::ZERO);
            if im_work >= cs_work {
                if im != cs {
                    warn!(
                        "reindex-chainstate: chainstore tip {} (work={}) is behind index tip {} (work={}), using index tip",
                        cs.to_hex(),
                        cs_work,
                        im.to_hex(),
                        im_work
                    );
                }
                im
            } else {
                cs
            }
        }
        (Some(cs), None) => cs,
        (None, Some(im)) => im,
        (None, None) => return Err(anyhow!("reindex-chainstate: no best tip found")),
    };
    if let Some(bi) = in_memory.block_index.get(&best_tip) {
        info!(
            "reindex-chainstate: selected rebuild tip={} height={} chainwork={}",
            best_tip.to_hex(),
            bi.height,
            bi.chainwork
        );
    }

    let mut ordered_chain: Vec<BlockHash> = Vec::new();
    let mut cursor = best_tip;
    loop {
        let bi = in_memory.block_index.get(&cursor).ok_or_else(|| {
            anyhow!(
                "reindex-chainstate: missing block index {}",
                cursor.to_hex()
            )
        })?;
        ordered_chain.push(cursor);
        if bi.height == 0 {
            break;
        }
        cursor = bi.header.prev_block;
    }
    ordered_chain.reverse();
    info!("reindex-chainstate: ordered chain has {} blocks", ordered_chain.len());

    if ordered_chain.is_empty() {
        info!("reindex-chainstate: nothing to rebuild");
        return Ok(());
    }

    // Build replay plan from ordered chain using block index metadata.
    // Block data availability is checked lazily during replay (avoids a slow
    // full-chain preflight read that doubles the I/O).
    let mut replay_plan: Vec<(BlockHash, u32, U256)> = Vec::with_capacity(ordered_chain.len());
    for hash in &ordered_chain {
        // Some older databases may not persist a genesis index entry. Fall back to the
        // in-memory index rebuilt from headers so reindex-chainstate can still proceed.
        let (height, chainwork) = if let Some(stored_idx) = block_store.get_index(hash)? {
            (stored_idx.height, stored_idx.chainwork())
        } else {
            let bi = in_memory.block_index.get(hash).ok_or_else(|| {
                anyhow!("reindex-chainstate: missing block index {}", hash.to_hex())
            })?;
            if bi.height == 0 {
                warn!(
                    "reindex-chainstate: missing stored genesis index {}, using header index fallback",
                    hash.to_hex()
                );
            } else {
                return Err(anyhow!(
                    "reindex-chainstate: missing stored index {} at height {}",
                    hash.to_hex(),
                    bi.height
                ));
            }
            (bi.height, bi.chainwork)
        };
        replay_plan.push((*hash, height, chainwork));
    }

    // Clear chainstate families before replaying blocks.
    let utxo_end = vec![0xffu8; 37];
    let chain_state_end = vec![0xffu8; 64];
    db.delete_range_cf(rbtc_storage::db::CF_UTXO, b"", &utxo_end)?;
    db.delete_range_cf(rbtc_storage::db::CF_CHAIN_STATE, b"", &chain_state_end)?;

    let total_blocks = replay_plan.len();
    let replay_start = std::time::Instant::now();
    let mut last_log = std::time::Instant::now();
    info!("reindex-chainstate: replaying {total_blocks} blocks to rebuild UTXO set");

    // Accumulate UTXO changes into a large WriteBatch and flush periodically,
    // similar to Bitcoin Core's CCoinsViewCache which flushes when the cache
    // approaches its size limit.  Flushing every N blocks amortizes the cost
    // of RocksDB WAL + compaction across many blocks.
    const FLUSH_INTERVAL: usize = 10_000;
    let mut batch = db.new_batch();
    let mut batch_blocks = 0usize;
    let mut last_tip = (BlockHash::ZERO, 0u32, U256::ZERO);

    for (i, (hash, height, chainwork)) in replay_plan.iter().enumerate() {
        if *height == 0 {
            // Genesis coinbase is unspendable and may be absent from pruned datasets.
            continue;
        }
        let Some(block) = block_store.get_block(hash)? else {
            // Flush any pending work before aborting so partial progress is saved.
            if batch_blocks > 0 {
                chain_store.update_tip_batch(&mut batch, &last_tip.0, last_tip.1, &last_tip.2)?;
                chain_store.update_indexed_height_batch(&mut batch, last_tip.1)?;
                db.write_batch(std::mem::replace(&mut batch, db.new_batch()))?;
            }
            return Err(anyhow!(
                "reindex-chainstate: missing block data at height {} hash {}",
                height,
                hash.to_hex()
            ));
        };

        // When verify_scripts is true, run full block validation (structure + scripts).
        // We must flush the batch first so the DB-backed UTXO lookup sees all prior outputs.
        if verify_scripts {
            if batch_blocks > 0 {
                chain_store.update_tip_batch(&mut batch, &last_tip.0, last_tip.1, &last_tip.2)?;
                chain_store.update_indexed_height_batch(&mut batch, last_tip.1)?;
                db.write_batch(std::mem::replace(&mut batch, db.new_batch()))?;
                batch_blocks = 0;
            }
            let mtp = in_memory.median_time_past(*height);
            let blk_hash = header_hash(&block.header);
            let flags = script_flags_for_block(
                network,
                *height,
                blk_hash.0,
                block.header.time,
                mtp,
            );
            let mtp_provider = ReindexMtpProvider { chain: &in_memory };
            let ctx = BlockValidationContext {
                block: &block,
                height: *height,
                median_time_past: mtp,
                network_time: block.header.time,
                expected_bits: block.header.bits,
                flags,
                network,
                mtp_provider: &mtp_provider,
                signet_challenge: None,
            };
            let db_utxo_view = DbUtxoLookup { utxo_store: &utxo_store };
            check_block(&ctx)?;
            connect_block_with_options(&ctx, &db_utxo_view, false)
                .map_err(|e| anyhow!("reindex: script validation failed at height {height}: {e}"))?;
        }

        let txids: Vec<Txid> = block
            .transactions
            .iter()
            .map(|tx| {
                let mut buf = Vec::new();
                tx.encode_legacy(&mut buf).ok();
                Txid(sha256d(&buf))
            })
            .collect();
        utxo_store.connect_block_into_batch(&mut batch, &txids, &block.transactions, *height)?;
        last_tip = (*hash, *height, *chainwork);
        batch_blocks += 1;

        // Flush accumulated batch every FLUSH_INTERVAL blocks (or every block when
        // verify_scripts is true, to keep DB-backed lookups up to date).
        let flush_interval = if verify_scripts { 1 } else { FLUSH_INTERVAL };
        if batch_blocks >= flush_interval {
            chain_store.update_tip_batch(&mut batch, hash, *height, chainwork)?;
            chain_store.update_indexed_height_batch(&mut batch, *height)?;
            db.write_batch(std::mem::replace(&mut batch, db.new_batch()))?;
            batch_blocks = 0;
        }

        // Log progress every 10 seconds
        let now = std::time::Instant::now();
        if now.duration_since(last_log).as_secs() >= 10 {
            let elapsed = replay_start.elapsed().as_secs_f64();
            let pct = (i + 1) as f64 / total_blocks as f64 * 100.0;
            let bps = (i + 1) as f64 / elapsed;
            let eta = if bps > 0.0 {
                (total_blocks - i - 1) as f64 / bps
            } else {
                0.0
            };
            info!(
                "reindex-chainstate: height {height} ({:.1}%) — {:.0} blocks/s, ETA {:.0}s",
                pct, bps, eta
            );
            last_log = now;
        }
    }

    // Flush remaining blocks
    if batch_blocks > 0 {
        chain_store.update_tip_batch(&mut batch, &last_tip.0, last_tip.1, &last_tip.2)?;
        chain_store.update_indexed_height_batch(&mut batch, last_tip.1)?;
        db.write_batch(batch)?;
    }

    // Mark UTXO format as compressed (Bitcoin Core-compatible).
    let chain_store2 = ChainStore::new(db);
    chain_store2.set_utxo_format(rbtc_storage::chain_store::UTXO_FORMAT_COMPRESSED)?;

    db.flush()?;
    let elapsed = replay_start.elapsed();
    info!(
        "reindex-chainstate: completed successfully in {:.1}s ({:.0} blocks/s)",
        elapsed.as_secs_f64(),
        total_blocks as f64 / elapsed.as_secs_f64()
    );
    Ok(())
}

fn load_chain_state(chain: &mut ChainState, db: &Database) -> Result<()> {
    let block_store = BlockStore::new(db);
    let chain_store = ChainStore::new(db);

    // Load all stored block indices
    let mut indices = block_store.iter_all_indices();
    if indices.is_empty() {
        info!("no stored chain state; starting from genesis");
        return Ok(());
    }

    // Sort by height for correct parent-before-child insertion
    indices.sort_by_key(|(_, idx)| idx.height);
    let count = indices.len();
    info!("rebuilding block index from {count} stored entries");

    // Detect legacy DB: old enum values 0-4 never have BLOCK_HAVE_DATA (bit 3) set.
    // If no block has any bit >= 3 set (beyond BLOCK_VALID_MASK), it's a legacy DB.
    let is_legacy = indices.iter().all(|(_, idx)| idx.status.raw() <= 4);
    if is_legacy && count > 1 {
        info!("detected legacy block status format; migrating to bitflags");
    }

    for (hash, stored) in indices {
        let chainwork = stored.chainwork();
        // Prefer recomputed hash to handle legacy DB format mismatches
        let effective_hash = {
            let recomputed = header_hash(&stored.header);
            if recomputed != hash { recomputed } else { hash }
        };
        let status = if is_legacy {
            // Migrate old enum u8: 0=HeaderOnly, 1=Valid, 2=InChain, 3=Invalid, 4=Pruned
            match stored.status.raw() {
                0 => BlockStatus::new().with_validity(BLOCK_VALID_TREE),
                1 => BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
                2 => BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo(),
                3 => BlockStatus::new().with_validity(BLOCK_VALID_TREE).with_failed(),
                4 => BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS),
                _ => stored.status,
            }
        } else {
            stored.status
        };
        let index = BlockIndex {
            hash: effective_hash,
            header: stored.header,
            height: stored.height,
            chainwork,
            status,
        };
        chain.block_index.insert(effective_hash, index);
    }

    // Persist migrated statuses back to DB so future loads don't need migration.
    if is_legacy && count > 1 {
        for (hash, bi) in chain.block_index.iter() {
            if let Some(mut stored_idx) = block_store.get_index(hash)? {
                stored_idx.status = bi.status;
                block_store.put_index(hash, &stored_idx)?;
            }
        }
        info!("legacy status migration complete");
    }

    // Rebuild active chain from persisted chainstate tip (best_block), which is
    // updated atomically with UTXO writes. This avoids trusting possibly stale
    // per-block InChain flags after interrupted writes.
    let best_block = chain_store.get_best_block()?;
    let best_height = chain_store.get_best_height()?;
    // Helper: walk from `tip` back to genesis, returning the path if complete.
    let try_walk_back = |tip: BlockHash| -> Option<Vec<BlockHash>> {
        let mut path = Vec::new();
        let mut cursor = tip;
        loop {
            let bi = chain.block_index.get(&cursor)?;
            path.push(cursor);
            if bi.height == 0 {
                break;
            }
            cursor = bi.header.prev_block;
        }
        path.reverse();
        Some(path)
    };

    // Resolve effective tip: use stored best_block if it has a complete path,
    // otherwise fall back to candidates sorted by chainwork.
    let effective_path = best_block
        .and_then(|tip| try_walk_back(tip))
        .or_else(|| {
            if let Some(tip) = best_block {
                warn!(
                    "stored best_block {} has broken ancestor chain; searching for fallback",
                    tip.to_hex()
                );
            }
            // Sort all non-invalid blocks by descending chainwork and pick the
            // first one with a complete ancestor path back to genesis.
            let mut candidates: Vec<(BlockHash, U256)> = chain
                .block_index
                .iter()
                .filter(|(_, bi)| !bi.status.has_failed())
                .map(|(h, bi)| (*h, bi.chainwork))
                .collect();
            candidates.sort_by(|a, b| b.1.cmp(&a.1));

            for (hash, _work) in &candidates {
                if let Some(path) = try_walk_back(*hash) {
                    info!(
                        "fallback tip: {} at height {}",
                        hash.to_hex(),
                        path.len().saturating_sub(1)
                    );
                    return Some(path);
                }
            }
            None
        });

    if let Some(path_rev) = effective_path {
        let tip = *path_rev.last().unwrap();

        chain.active_chain.clear();
        chain.active_chain.resize(path_rev.len(), BlockHash::ZERO);
        for hash in &path_rev {
            let h = chain
                .block_index
                .get(hash)
                .map(|bi| bi.height as usize)
                .ok_or_else(|| {
                    anyhow!(
                        "missing block index while rebuilding chain {}",
                        hash.to_hex()
                    )
                })?;
            if h >= chain.active_chain.len() {
                chain.active_chain.resize(h + 1, BlockHash::ZERO);
            }
            chain.active_chain[h] = *hash;
        }
        chain.best_tip = Some(tip);

        // Active chain membership is now tracked by the active_chain vec,
        // no need to set status flags for InChain.

        let rebuilt_h = chain.height();
        let rebuilt_work = chain
            .block_index
            .get(&tip)
            .map(|bi| bi.chainwork)
            .unwrap_or(U256::ZERO);

        // Persist corrected tip if it differs from what was stored.
        if best_block != Some(tip) {
            info!(
                "persisting corrected tip {} at height {} (was {:?})",
                tip.to_hex(),
                rebuilt_h,
                best_block.map(|h| h.to_hex())
            );
            chain_store.update_tip(&tip, rebuilt_h, &rebuilt_work)?;
        } else if let Some(h) = best_height {
            if h != rebuilt_h {
                warn!(
                    "chainstate tip height mismatch: chain_store={} rebuilt={} tip={}",
                    h,
                    rebuilt_h,
                    tip.to_hex()
                );
            }
        }
    } else {
        // Fallback for older DBs without chainstate tip metadata.
        // Fully validated blocks (VALID_SCRIPTS + data + undo) were likely in the active chain.
        let in_chain_blocks: Vec<(BlockHash, u32, U256)> = chain
            .block_index
            .iter()
            .filter_map(|(hash, bi)| {
                if bi.status.is_valid(BLOCK_VALID_SCRIPTS) && bi.status.have_data() && bi.status.have_undo() {
                    Some((*hash, bi.height, bi.chainwork))
                } else {
                    None
                }
            })
            .collect();
        for (hash, height, chainwork) in in_chain_blocks {
            let h = height as usize;
            if h >= chain.active_chain.len() {
                chain.active_chain.resize(h + 1, BlockHash::ZERO);
            }
            chain.active_chain[h] = hash;
            let cur_work = chain
                .best_tip
                .and_then(|t| chain.block_index.get(&t))
                .map(|x| x.chainwork)
                .unwrap_or(U256::ZERO);
            if chainwork > cur_work {
                chain.best_tip = Some(hash);
            }
        }
    }

    info!(
        "chain rebuilt: height={} tip={:?} (utxos lazy-loaded)",
        chain.height(),
        chain.best_tip.map(|h| h.to_hex())
    );
    Ok(())
}

// ── Reorg helper ─────────────────────────────────────────────────────────────

fn collect_subtree_hashes(chain: &ChainState, root: BlockHash) -> Result<Vec<BlockHash>> {
    if !chain.block_index.contains_key(&root) {
        return Err(anyhow!("block {} not found in block index", root.to_hex()));
    }
    let mut out = vec![root];
    let mut i = 0usize;
    while i < out.len() {
        let cur = out[i];
        for (hash, bi) in &chain.block_index {
            if bi.header.prev_block == cur && !out.contains(hash) {
                out.push(*hash);
            }
        }
        i += 1;
    }
    Ok(out)
}

/// Find the fork point between the active chain and a new tip.
/// Returns `(fork_height, old_chain_hashes, new_chain_hashes)`.
fn find_fork(
    chain: &ChainState,
    new_tip: rbtc_primitives::hash::BlockHash,
) -> Result<(
    u32,
    Vec<rbtc_primitives::hash::BlockHash>,
    Vec<rbtc_primitives::hash::BlockHash>,
)> {
    let mut old_chain = Vec::new();
    let mut new_chain = Vec::new();

    // Walk new_tip back until we find a block that is InChain
    let mut cursor = new_tip;
    loop {
        let bi = chain
            .block_index
            .get(&cursor)
            .ok_or_else(|| anyhow::anyhow!("fork search: unknown block {}", cursor.to_hex()))?;
        if chain.is_in_active_chain(&cursor) {
            // Found the fork point
            let fork_height = bi.height;
            // Collect old chain from tip to fork
            let best = chain.best_tip.unwrap_or(BlockHash::ZERO);
            let mut old_cursor = best;
            loop {
                let obi = chain.block_index.get(&old_cursor);
                if let Some(obi) = obi {
                    if obi.height <= fork_height {
                        break;
                    }
                    old_chain.push(old_cursor);
                    old_cursor = obi.header.prev_block;
                } else {
                    break;
                }
            }
            new_chain.reverse();
            return Ok((fork_height, old_chain, new_chain));
        }
        new_chain.push(cursor);
        cursor = bi.header.prev_block;
    }
}

// ── Misc helpers ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn tx_legacy_bytes(tx: &rbtc_primitives::transaction::Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    tx.encode_legacy(&mut buf).ok();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::{
        block::{Block, BlockHeader},
        hash::Hash256,
        script::Script,
        transaction::{OutPoint, Transaction, TxIn, TxOut},
        Network,
    };
    use tempfile::TempDir;

    fn coinbase_tx(value: i64) -> Transaction {
        Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x01, 0x01]),
                sequence: 0xffff_ffff,
                witness: vec![],
            }],
            vec![TxOut {
                value,
                script_pubkey: Script::new(),
            }],
            0,
        )
    }

    #[test]
    fn collect_subtree_hashes_returns_descendants() {
        let mut chain = ChainState::new(Network::Regtest);
        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();
        let h1 = BlockHash(Hash256([1; 32]));
        let h2 = BlockHash(Hash256([2; 32]));
        let side = BlockHash(Hash256([3; 32]));

        chain.insert_block_index(
            h1,
            BlockIndex {
                hash: h1,
                header: BlockHeader {
                    version: 1,
                    prev_block: g,
                    merkle_root: Hash256::ZERO,
                    time: 1,
                    bits: 0x207fffff,
                    nonce: 1,
                },
                height: 1,
                chainwork: U256::from_u64(2),
                status: BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
            },
            false,
        );
        chain.insert_block_index(
            h2,
            BlockIndex {
                hash: h2,
                header: BlockHeader {
                    version: 1,
                    prev_block: h1,
                    merkle_root: Hash256::ZERO,
                    time: 2,
                    bits: 0x207fffff,
                    nonce: 2,
                },
                height: 2,
                chainwork: U256::from_u64(3),
                status: BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
            },
            false,
        );
        chain.insert_block_index(
            side,
            BlockIndex {
                hash: side,
                header: BlockHeader {
                    version: 1,
                    prev_block: g,
                    merkle_root: Hash256::ZERO,
                    time: 2,
                    bits: 0x207fffff,
                    nonce: 3,
                },
                height: 1,
                chainwork: U256::from_u64(2),
                status: BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
            },
            false,
        );

        let mut subtree = collect_subtree_hashes(&chain, h1).unwrap();
        subtree.sort();
        assert_eq!(subtree, vec![h1, h2]);
    }

    #[test]
    fn reindex_chainstate_rebuilds_utxo_and_tip() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let network = Network::Regtest;
        let block_store = BlockStore::new(&db);
        let chain_store = ChainStore::new(&db);
        let utxo_store = UtxoStore::new(&db);

        let genesis_header = network.genesis_header();
        let genesis_hash = header_hash(&genesis_header);
        block_store
            .put_index(
                &genesis_hash,
                &StoredBlockIndex {
                    header: genesis_header,
                    height: 0,
                    chainwork_lo: 1,
                    chainwork_hi: 0,
                    status: BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo(),
                },
            )
            .unwrap();

        let tx = coinbase_tx(5_000_000_000);
        let block1 = Block::new(
            BlockHeader {
                version: 1,
                prev_block: genesis_hash,
                merkle_root: Hash256::ZERO,
                time: 10,
                bits: 0x207fffff,
                nonce: 10,
            },
            vec![tx.clone()],
        );
        let hash1 = header_hash(&block1.header);
        block_store
            .put_index(
                &hash1,
                &StoredBlockIndex {
                    header: block1.header.clone(),
                    height: 1,
                    chainwork_lo: 2,
                    chainwork_hi: 0,
                    status: BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo(),
                },
            )
            .unwrap();
        block_store.put_block(&hash1, &block1).unwrap();
        chain_store.update_tip(&hash1, 1, &U256::from_u64(2)).unwrap();

        reindex_chainstate_full(&db, network, false).unwrap();

        let mut tx_buf = Vec::new();
        tx.encode_legacy(&mut tx_buf).unwrap();
        let txid = Txid(sha256d(&tx_buf));
        let outpoint = OutPoint { txid, vout: 0 };
        assert!(utxo_store.get(&outpoint).unwrap().is_some());
        assert_eq!(chain_store.get_best_block().unwrap(), Some(hash1));
        assert_eq!(chain_store.get_best_height().unwrap(), Some(1));
    }

    #[test]
    fn check_disk_space_returns_some_on_valid_path() {
        let dir = TempDir::new().unwrap();
        let result = check_disk_space(dir.path());
        assert!(result.is_some(), "should return available bytes for a valid path");
        assert!(result.unwrap() > 0, "available space should be positive");
    }

    #[test]
    fn check_disk_space_returns_none_on_invalid_path() {
        let result = check_disk_space(std::path::Path::new("/nonexistent_path_9999"));
        assert!(result.is_none(), "should return None for a nonexistent path");
    }

    #[test]
    fn reindex_flag_implies_full_validation_param() {
        // Verify the --reindex flag correctly parses
        use crate::config::Args;
        use clap::Parser;
        let args = Args::parse_from(["rbtc", "--reindex"]);
        assert!(args.reindex);
        assert!(!args.reindex_chainstate);
    }

    #[test]
    fn no_persist_mempool_flag_parses() {
        use crate::config::Args;
        use clap::Parser;
        let args = Args::parse_from(["rbtc", "--no-persist-mempool"]);
        assert!(args.no_persist_mempool);
    }

    // ── ActivateBestChain / auto-reorg tests ─────────────────────────────

    fn make_header(prev: BlockHash, time: u32, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: prev,
            merkle_root: Hash256::ZERO,
            time,
            bits: 0x207fffff,
            nonce,
        }
    }

    #[test]
    fn find_fork_identifies_fork_point() {
        let mut chain = ChainState::new(Network::Regtest);
        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();

        // Build active chain: g -> h1 -> h2
        chain.active_chain.push(g); // genesis at height 0
        chain.block_index.get_mut(&g).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo();

        let hdr1 = make_header(g, 1, 1);
        let h1 = header_hash(&hdr1);
        chain.add_header(hdr1).unwrap();
        chain.block_index.get_mut(&h1).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo();
        chain.active_chain.push(h1);
        chain.best_tip = Some(h1);

        let hdr2 = make_header(h1, 2, 2);
        let h2 = header_hash(&hdr2);
        chain.add_header(hdr2).unwrap();
        chain.block_index.get_mut(&h2).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo();
        chain.active_chain.push(h2);
        chain.best_tip = Some(h2);

        // Build side chain: g -> s1 -> s2 -> s3
        let shdr1 = make_header(g, 10, 10);
        let s1 = header_hash(&shdr1);
        chain.add_header(shdr1).unwrap();
        chain.block_index.get_mut(&s1).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data();

        let shdr2 = make_header(s1, 11, 11);
        let s2 = header_hash(&shdr2);
        chain.add_header(shdr2).unwrap();
        chain.block_index.get_mut(&s2).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data();

        let shdr3 = make_header(s2, 12, 12);
        let s3 = header_hash(&shdr3);
        chain.add_header(shdr3).unwrap();
        chain.block_index.get_mut(&s3).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data();

        // find_fork from s3: fork point is genesis (g), which is in the active chain
        let (fork_height, old_chain, new_chain) = find_fork(&chain, s3).unwrap();
        assert_eq!(fork_height, 0); // forked at genesis
        assert_eq!(old_chain.len(), 2); // h2, h1 (reverse order from tip)
        assert_eq!(new_chain.len(), 3); // s1, s2, s3 (forward order)
        assert_eq!(new_chain[0], s1);
        assert_eq!(new_chain[2], s3);
    }

    #[test]
    fn select_best_valid_tip_picks_highest_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();

        let mut chain = ChainState::new(Network::Regtest);
        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();

        // Active chain block at height 1 with chainwork 100
        let h1 = BlockHash(Hash256([1; 32]));
        chain.insert_block_index(
            h1,
            BlockIndex {
                hash: h1,
                header: make_header(g, 1, 1),
                height: 1,
                chainwork: U256::from_u64(100),
                status: BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo(),
            },
            true,
        );

        // Side chain block at height 1 with chainwork 200
        let s1 = BlockHash(Hash256([2; 32]));
        chain.insert_block_index(
            s1,
            BlockIndex {
                hash: s1,
                header: make_header(g, 2, 2),
                height: 1,
                chainwork: U256::from_u64(200),
                status: BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
            },
            false,
        );

        // HeaderOnly block with chainwork 300 — should NOT be selected
        let ho = BlockHash(Hash256([3; 32]));
        chain.insert_block_index(
            ho,
            BlockIndex {
                hash: ho,
                header: make_header(g, 3, 3),
                height: 1,
                chainwork: U256::from_u64(300),
                status: BlockStatus::new().with_validity(BLOCK_VALID_TREE),
            },
            false,
        );

        let chain_lock = Arc::new(RwLock::new(chain));
        // Manually test select_best_valid_tip logic (replicate inline since it's async on Node)
        rt.block_on(async {
            let chain = chain_lock.read().await;
            let best = chain
                .block_index
                .iter()
                .filter(|(_, bi)| bi.status.is_valid(BLOCK_VALID_TRANSACTIONS))
                .max_by_key(|(_, bi)| bi.chainwork)
                .map(|(h, _)| *h);
            assert_eq!(best, Some(s1)); // s1 has chainwork 200, highest among Valid/InChain
        });
    }

    #[test]
    fn side_chain_block_stored_to_disk() {
        let dir = TempDir::new().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let block_store = BlockStore::new(&db);

        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();

        // Simulate storing a side-chain block
        let hdr = make_header(g, 10, 10);
        let block = Block::new(hdr.clone(), vec![coinbase_tx(5_000_000_000)]);
        let hash = header_hash(&hdr);

        assert!(!block_store.has_block(&hash).unwrap());
        block_store.put_block(&hash, &block).unwrap();
        assert!(block_store.has_block(&hash).unwrap());

        // Retrieve and verify
        let retrieved = block_store.get_block(&hash).unwrap().unwrap();
        assert_eq!(retrieved.transactions.len(), 1);
    }

    #[test]
    fn chain_data_available_false_for_header_only() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());

        let mut chain = ChainState::new(Network::Regtest);
        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();

        // Genesis is in the active chain
        chain.block_index.get_mut(&g).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo();
        chain.active_chain.push(g);
        chain.best_tip = Some(g);

        // Side chain: g -> s1 (Valid, data on disk) -> s2 (HeaderOnly, no data)
        let s1 = BlockHash(Hash256([10; 32]));
        chain.insert_block_index(
            s1,
            BlockIndex {
                hash: s1,
                header: make_header(g, 1, 1),
                height: 1,
                chainwork: U256::from_u64(2),
                status: BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
            },
            false,
        );
        // Store s1 block data
        let block_store = BlockStore::new(&db);
        let block1 = Block::new(make_header(g, 1, 1), vec![coinbase_tx(5_000_000_000)]);
        block_store.put_block(&s1, &block1).unwrap();

        let s2 = BlockHash(Hash256([11; 32]));
        chain.insert_block_index(
            s2,
            BlockIndex {
                hash: s2,
                header: make_header(s1, 2, 2),
                height: 2,
                chainwork: U256::from_u64(3),
                status: BlockStatus::new().with_validity(BLOCK_VALID_TREE), // no data!
            },
            false,
        );

        let chain_lock = Arc::new(RwLock::new(chain));

        rt.block_on(async {
            let chain = chain_lock.read().await;
            // Walk from s2 backward: s2 is HeaderOnly → should return false
            let mut cursor = s2;
            let result = loop {
                let bi = chain.block_index.get(&cursor).unwrap();
                if chain.is_in_active_chain(&cursor) {
                    break true;
                }
                if bi.status.has_failed() || !bi.status.have_data() {
                    break false;
                }
                if !block_store.has_block(&cursor).unwrap() {
                    break false;
                }
                cursor = bi.header.prev_block;
            };
            assert!(!result, "should be false because s2 is HeaderOnly");

            // Walk from s1 backward: s1 is Valid with data, parent g is in active chain → true
            let mut cursor = s1;
            let result = loop {
                let bi = chain.block_index.get(&cursor).unwrap();
                if chain.is_in_active_chain(&cursor) {
                    break true;
                }
                if bi.status.has_failed() || !bi.status.have_data() {
                    break false;
                }
                if !block_store.has_block(&cursor).unwrap() {
                    break false;
                }
                cursor = bi.header.prev_block;
            };
            assert!(result, "should be true because s1 has data and parent is InChain");
        });
    }

    #[test]
    fn find_fork_returns_correct_old_and_new_chains() {
        let mut chain = ChainState::new(Network::Regtest);
        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();
        chain.block_index.get_mut(&g).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo();
        chain.active_chain.push(g); // genesis at height 0

        // Active chain: g -> a1
        let ahdr = make_header(g, 1, 1);
        let a1 = header_hash(&ahdr);
        chain.add_header(ahdr).unwrap();
        chain.block_index.get_mut(&a1).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo();
        chain.active_chain.push(a1);
        chain.best_tip = Some(a1);

        // Side chain: g -> b1 (Valid, more work potential)
        let bhdr = make_header(g, 1, 99);
        let b1 = header_hash(&bhdr);
        chain.add_header(bhdr).unwrap();
        chain.block_index.get_mut(&b1).unwrap().status = BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data();

        let (fork_height, old_chain, new_chain) = find_fork(&chain, b1).unwrap();
        assert_eq!(fork_height, 0);
        assert_eq!(old_chain, vec![a1]);
        assert_eq!(new_chain, vec![b1]);
    }

    // ── Block failure flags tests ────────────────────────────────────────

    #[test]
    fn block_status_failed_valid_preserves_validation_level() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_SCRIPTS)
            .with_data()
            .with_undo()
            .with_failed();
        assert!(s.has_failed());
        assert!(!s.has_failed_parent());
        // Validation level is preserved even after failure
        assert_eq!(s.validity(), BLOCK_VALID_SCRIPTS);
        assert!(s.have_data());
        assert!(s.have_undo());
    }

    #[test]
    fn block_status_failed_child_distinct_from_failed_valid() {
        let target = BlockStatus::new()
            .with_validity(BLOCK_VALID_TRANSACTIONS)
            .with_failed();
        let child = BlockStatus::new()
            .with_validity(BLOCK_VALID_TRANSACTIONS)
            .with_failed_child();
        // Both have has_failed() == true
        assert!(target.has_failed());
        assert!(child.has_failed());
        // Only child has has_failed_parent()
        assert!(!target.has_failed_parent());
        assert!(child.has_failed_parent());
    }

    #[test]
    fn without_failed_clears_both_flags() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_SCRIPTS)
            .with_data()
            .with_failed()
            .with_failed_child();
        assert!(s.has_failed());
        let cleared = s.without_failed();
        assert!(!cleared.has_failed());
        assert!(!cleared.has_failed_parent());
        // Other flags preserved
        assert_eq!(cleared.validity(), BLOCK_VALID_SCRIPTS);
        assert!(cleared.have_data());
    }

    #[test]
    fn select_best_valid_tip_skips_failed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut chain = ChainState::new(Network::Regtest);
        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();

        // Higher-work block that's failed
        let h1 = BlockHash(Hash256([1; 32]));
        chain.insert_block_index(
            h1,
            BlockIndex {
                hash: h1,
                header: make_header(g, 1, 1),
                height: 1,
                chainwork: U256::from_u64(500),
                status: BlockStatus::new()
                    .with_validity(BLOCK_VALID_SCRIPTS)
                    .with_data()
                    .with_failed(),
            },
            false,
        );

        // Lower-work valid block
        let h2 = BlockHash(Hash256([2; 32]));
        chain.insert_block_index(
            h2,
            BlockIndex {
                hash: h2,
                header: make_header(g, 2, 2),
                height: 1,
                chainwork: U256::from_u64(100),
                status: BlockStatus::new()
                    .with_validity(BLOCK_VALID_TRANSACTIONS)
                    .with_data(),
            },
            false,
        );

        let chain_lock = Arc::new(RwLock::new(chain));
        rt.block_on(async {
            let chain = chain_lock.read().await;
            let best = chain
                .block_index
                .iter()
                .filter(|(_, bi)| bi.status.is_valid(BLOCK_VALID_TRANSACTIONS))
                .max_by_key(|(_, bi)| bi.chainwork)
                .map(|(h, _)| *h);
            // h1 is failed so skipped; h2 is selected despite lower work
            assert_eq!(best, Some(h2));
        });
    }

    #[test]
    fn is_in_active_chain_works() {
        let mut chain = ChainState::new(Network::Regtest);
        let g = BlockHash::from_hex(Network::Regtest.genesis_hash()).unwrap();
        chain.active_chain.push(g);

        let hdr1 = make_header(g, 1, 1);
        let h1 = header_hash(&hdr1);
        chain.add_header(hdr1).unwrap();
        chain.active_chain.push(h1);

        let side_hdr = make_header(g, 1, 99);
        let side = header_hash(&side_hdr);
        chain.add_header(side_hdr).unwrap();

        assert!(chain.is_in_active_chain(&g));
        assert!(chain.is_in_active_chain(&h1));
        assert!(!chain.is_in_active_chain(&side));
    }

    #[test]
    fn legacy_status_migration() {
        use rbtc_primitives::block_status::*;

        // Old enum values: 0=HeaderOnly, 1=Valid, 2=InChain, 3=Invalid, 4=Pruned
        let cases = vec![
            (0u8, BLOCK_VALID_TREE, false, false, false),   // HeaderOnly
            (1, BLOCK_VALID_TRANSACTIONS, true, false, false), // Valid (has data)
            (2, BLOCK_VALID_SCRIPTS, true, true, false),     // InChain (has data+undo)
            (3, BLOCK_VALID_TREE, false, false, true),       // Invalid (failed)
            (4, BLOCK_VALID_SCRIPTS, false, false, false),   // Pruned (no data)
        ];
        for (old_val, expected_level, has_data, has_undo, has_failed) in cases {
            let migrated = match old_val as u32 {
                0 => BlockStatus::new().with_validity(BLOCK_VALID_TREE),
                1 => BlockStatus::new().with_validity(BLOCK_VALID_TRANSACTIONS).with_data(),
                2 => BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS).with_data().with_undo(),
                3 => BlockStatus::new().with_validity(BLOCK_VALID_TREE).with_failed(),
                4 => BlockStatus::new().with_validity(BLOCK_VALID_SCRIPTS),
                _ => BlockStatus::from_raw(old_val as u32),
            };
            assert_eq!(
                migrated.validity(), expected_level,
                "wrong level for old enum {old_val}"
            );
            assert_eq!(
                migrated.have_data(), has_data,
                "wrong have_data for old enum {old_val}"
            );
            assert_eq!(
                migrated.have_undo(), has_undo,
                "wrong have_undo for old enum {old_val}"
            );
            assert_eq!(
                migrated.has_failed(), has_failed,
                "wrong has_failed for old enum {old_val}"
            );
        }
    }
}
