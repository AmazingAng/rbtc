use std::{collections::{HashMap, HashSet, VecDeque}, net::IpAddr, sync::Arc, time::{Duration, Instant}};

use anyhow::{Context, Result, anyhow};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use rbtc_consensus::{
    block_verify::{verify_block_with_options, BlockValidationContext},
    chain::{BlockIndex, BlockStatus, ChainState, header_hash},
    tx_verify::MedianTimeProvider,
    script_flags_for_block,
};
use rbtc_crypto::sha256d;
use rbtc_mempool::Mempool;
use rbtc_net::{
    compact::{short_txid, reconstruct_block, CompactBlock, GetBlockTxn},
    message::{Inventory, InvType, NetworkMessage},
    peer_manager::{BAN_DURATION, NodeEvent, PeerManager, PeerManagerConfig},
};
use rbtc_primitives::hash::Hash256;
use rbtc_storage::{
    encode_block_undo, decode_block_undo, AddrIndexStore, BlockStore, ChainStore, Database,
    PeerStore, StoredBlockIndex, StoredUtxo, TxIndexStore, UtxoStore,
};
use rbtc_wallet::Wallet;

use crate::{
    config::Args,
    ibd::{build_locator, IbdPhase, IbdState, SEGMENT_SIZE, STALL_TIMEOUT},
    rpc::{start_rpc_server, RpcState},
    utxo_cache::CachedUtxoSet,
};

/// Peer ID used when a block is submitted locally (via RPC).
const LOCAL_PEER_ID: u64 = 0;
const INDEX_BATCH_SIZE: usize = 64;
const INDEX_QUEUE_FILL_CHUNK: u32 = 512;
const UTXO_EVICT_INTERVAL_BLOCKS: u32 = 16;

#[derive(Clone, Copy)]
struct IndexTask {
    height: u32,
    block_hash: Hash256,
}

struct IndexBatchOutcome {
    processed: usize,
    last_indexed_height: Option<u32>,
    retry_tasks: Vec<IndexTask>,
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
    canonical_header_chain: Vec<Hash256>,
    /// Write-back UTXO cache (hot + dirty layers with RocksDB fallback).
    /// Used by `verify_block` instead of the full in-memory `chain.utxos` when
    /// `--utxo-cache > 0`.  Always present; used unconditionally to keep the
    /// dirty layer in sync with each connected block.
    utxo_cache: CachedUtxoSet,
    peer_manager: PeerManager,
    node_event_rx: mpsc::UnboundedReceiver<NodeEvent>,
    /// Sender half given to the RPC server for `submitblock` / `generatetoaddress`.
    submit_block_tx: mpsc::UnboundedSender<rbtc_primitives::block::Block>,
    /// Receiver for blocks submitted via the RPC `submitblock` / `generatetoaddress`.
    submit_block_rx: mpsc::UnboundedReceiver<rbtc_primitives::block::Block>,
    /// BIP152: partially-reconstructed compact blocks awaiting `blocktxn` responses.
    /// Key = block_hash, Value = (compact block, list of already-filled tx slots).
    pending_compact: HashMap<rbtc_primitives::hash::Hash256, (CompactBlock, Vec<Option<rbtc_primitives::transaction::Transaction>>)>,
    /// Out-of-order blocks received during parallel IBD, waiting for predecessors.
    /// Key = block height, Value = (sender peer_id, block).
    /// Only the first copy for each height is kept (subsequent duplicates are dropped).
    pending_blocks: HashMap<u32, (u64, rbtc_primitives::block::Block)>,
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
    assumevalid_hash: Option<Hash256>,
    /// Log guard to avoid spamming assumevalid activation message.
    assumevalid_announced: bool,
}

impl Node {
    pub async fn new(args: Args) -> Result<Self> {
        let data_dir = args.data_dir();
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create data dir: {data_dir:?}"))?;

        info!("data directory: {data_dir:?}");

        let db_path = data_dir.join("chaindata");
        let db = Arc::new(
            Database::open(&db_path)
                .with_context(|| format!("failed to open database at {db_path:?}"))?,
        );
        info!("database opened at {db_path:?}");

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
            // Load known addresses into candidate pool
            if let Ok(addrs) = peer_store.load_addrs() {
                peer_manager.seed_candidate_addrs(addrs.into_iter().map(|(addr, _, _)| addr));
            }
        }

        // Build UTXO cache based on --utxo-cache flag.
        // When 0 (unlimited), pre-populate from RocksDB (existing behaviour).
        // When >0, start empty and rely on dirty-layer + RocksDB fallback.
        let max_bytes = if args.utxo_cache == 0 {
            None // unlimited
        } else {
            Some(args.utxo_cache * 1_000_000)
        };
        let mut utxo_cache = CachedUtxoSet::new(Arc::clone(&db), max_bytes);
        if max_bytes.is_none() {
            // Pre-load all UTXOs into the hot cache to match pre-Phase-8 behaviour.
            utxo_cache.load_all();
            info!("utxo_cache: pre-loaded {} entries", utxo_cache.hot_len());
        } else {
            info!(
                "utxo_cache: lazy mode, limit={} MB",
                args.utxo_cache
            );
        }

        let assumevalid_hash = match args.assumevalid.as_ref() {
            Some(h) => Some(Hash256::from_hex(h).map_err(|_| anyhow!("invalid --assumevalid hash"))?),
            None => None,
        };

        Ok(Self {
            args,
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
            assumevalid_announced: false,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!("starting node on network: {}", self.args.network);

        // Start inbound connection listener if a port is configured
        self.peer_manager.start_inbound_listener().await.ok();

        // Start JSON-RPC server
        let rpc_addr = format!("127.0.0.1:{}", self.args.rpc_port);
        let rpc_state = RpcState {
            chain: Arc::clone(&self.chain),
            mempool: Arc::clone(&self.mempool),
            db: Arc::clone(&self.db),
            network_name: self.args.network.to_string(),
            wallet: self.wallet.as_ref().map(Arc::clone),
            submit_block_tx: self.submit_block_tx.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = start_rpc_server(&rpc_addr, rpc_state).await {
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
                info!("chain tip={active_height}; checking if fully synced");
                // Will determine whether we're caught up once peers connect.
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
        seed_retry_timer.tick().await; // consume the immediate first tick

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
            }
        }
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

    fn enqueue_index_task(&mut self, height: u32, block_hash: Hash256) {
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
                    warn!(
                        "index worker paused; re-queueing {} task(s)",
                        outcome.retry_tasks.len()
                    );
                    for task in outcome.retry_tasks.into_iter().rev() {
                        self.index_queue.push_front(task);
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
        if self.should_defer_indexes() || self.index_worker.is_some() || self.index_queue.is_empty() {
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
        self.index_worker = Some(tokio::task::spawn_blocking(move || write_index_batch(db, tasks)));
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

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    async fn handle_node_event(&mut self, event: NodeEvent) -> Result<()> {
        match event {
            NodeEvent::PeerConnected { peer_id, addr, best_height } => {
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
                        self.request_headers(peer_id).await;
                    }
                }
            }

            NodeEvent::PeerDisconnected { peer_id } => {
                self.disconnecting_peers.remove(&peer_id);
                info!("peer {peer_id} disconnected");
                if self.ibd.phase == IbdPhase::Blocks {
                    // Return the peer's unfinished range to the work queue.
                    self.ibd.release_peer(peer_id);
                    // Try to assign to a remaining connected peer.
                    self.assign_blocks_to_peers().await;
                } else {
                    if self.ibd.sync_peer == Some(peer_id) {
                        self.ibd.sync_peer = None;
                        if let Some(new_peer) = self.peer_manager.best_peer() {
                            self.ibd.sync_peer = Some(new_peer);
                            self.ibd.record_progress();
                            self.request_headers(new_peer).await;
                        }
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

            NodeEvent::InvReceived { peer_id, items } => {
                let mut to_request: Vec<Inventory> = Vec::new();
                let mut tx_to_request: Vec<Inventory> = Vec::new();

                let chain = self.chain.read().await;
                let mp = self.mempool.read().await;

                for item in items {
                    match item.inv_type {
                        InvType::Block | InvType::WitnessBlock => {
                            if !chain.block_index.contains_key(&item.hash) {
                                to_request.push(Inventory {
                                    inv_type: InvType::WitnessBlock,
                                    hash: item.hash,
                                });
                            }
                        }
                        InvType::Tx | InvType::WitnessTx => {
                            if !mp.contains(&item.hash) {
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

                if !to_request.is_empty() {
                    self.peer_manager
                        .send_to(peer_id, NetworkMessage::GetData(to_request));
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
        if headers.is_empty() {
            if self.ibd.phase == IbdPhase::Headers {
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
                    // Persist the header to block_store if it's new
                    if block_store.get_index(&hash).ok().flatten().is_none() {
                        if let Some(bi) = chain.get_block_index(&hash) {
                            let stored = StoredBlockIndex {
                                header: header.clone(),
                                height: bi.height,
                                chainwork_lo: bi.chainwork as u64,
                                chainwork_hi: (bi.chainwork >> 64) as u64,
                                status: bi.status.as_u8(),
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

        if headers.len() == 2000 {
            let last_hash = last_header.map(|h| header_hash(&h)).unwrap_or(Hash256::ZERO);
            self.peer_manager.send_to(
                peer_id,
                NetworkMessage::GetHeaders(rbtc_net::message::GetBlocksMessage {
                    version: 70016,
                    locator_hashes: vec![last_hash],
                    stop_hash: Hash256::ZERO,
                }),
            );
        } else {
            self.ibd.phase = IbdPhase::Blocks;
            // Build canonical header chain from block_index and partition into
            // per-peer download segments.
            self.build_canonical_header_chain().await;
            self.assign_blocks_to_peers().await;
        }

        Ok(())
    }

    /// Walk block_index backwards from the best-chainwork tip to build a
    /// height-indexed vec of canonical hashes.  Called once when header sync
    /// is complete and we switch to the block-download phase.
    /// Also partitions the remaining un-downloaded height range into segments
    /// for multi-peer parallel download.
    async fn build_canonical_header_chain(&mut self) {
        let chain = self.chain.read().await;
        let best = chain
            .block_index
            .values()
            .max_by_key(|bi| bi.chainwork);
        let Some(tip) = best else { return };
        let tip_height = tip.height as usize;
        let active_height = chain.height();
        let mut canonical = vec![Hash256::ZERO; tip_height + 1];
        let mut cur = tip.hash;
        loop {
            let bi = match chain.block_index.get(&cur) {
                Some(b) => b,
                None => break,
            };
            canonical[bi.height as usize] = cur;
            if bi.height == 0 {
                break;
            }
            cur = bi.header.prev_block;
        }
        let tip_u32 = tip.height;
        drop(chain);
        info!(
            "canonical header chain built: {} headers",
            canonical.len()
        );
        self.canonical_header_chain = canonical;

        // Partition the un-downloaded height range into fixed-size segments.
        let start = active_height + 1;
        if start <= tip_u32 {
            self.ibd.partition_ranges(start, tip_u32, SEGMENT_SIZE);
        }
    }

    // ── BIP152 Compact Block handlers ─────────────────────────────────────────

    async fn handle_cmpct_block(
        &mut self,
        peer_id: u64,
        cmpct: CompactBlock,
    ) -> Result<()> {
        let block_hash = {
            let mut buf = Vec::with_capacity(80);
            buf.extend_from_slice(&cmpct.header.version.to_le_bytes());
            buf.extend_from_slice(&cmpct.header.prev_block.0);
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
                    let sid = short_txid(&cmpct.header, cmpct.nonce, txid);
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
                NetworkMessage::GetBlockTxn(GetBlockTxn { block_hash, indexes: missing }),
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
                    let sid = short_txid(&cmpct.header, cmpct.nonce, txid);
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
            warn!("blocktxn: still could not reconstruct block {}", resp.block_hash.to_hex());
        }

        Ok(())
    }

    /// Respond to a `getblocktxn` request: send back the requested transactions.
    async fn handle_get_block_txn(&self, peer_id: u64, req: GetBlockTxn) {
        use rbtc_storage::BlockStore;
        let block_store = BlockStore::new(&self.db);
        if let Ok(Some(block)) = block_store.get_block(&req.block_hash) {
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

    /// Collect canonical hashes for a height range [start, end], skipping
    /// blocks already in the active chain.
    async fn hashes_for_range(&self, start: u32, end: u32) -> Vec<Hash256> {
        let chain = self.chain.read().await;
        let mut hashes = Vec::new();
        for h in start..=end {
            // Prefer active_chain, fall back to canonical_header_chain.
            let hash = chain
                .get_ancestor_hash(h)
                .or_else(|| {
                    self.canonical_header_chain
                        .get(h as usize)
                        .copied()
                        .filter(|h| *h != Hash256::ZERO)
                });
            // Stop at the first missing height so we never request disjoint tails
            // without their predecessors (which would stall frontier connection).
            let Some(hash) = hash else { break };
            // Skip blocks already connected.
            if chain
                .block_index
                .get(&hash)
                .map(|bi| bi.status == BlockStatus::InChain)
                .unwrap_or(false)
            {
                continue;
            }
            hashes.push(hash);
        }
        hashes
    }

    /// Per-peer in-flight request cap (Bitcoin Core defaults to small per-peer windows).
    const PER_PEER_INFLIGHT_BLOCKS: u32 = 16;
    /// Tighter in-flight cap while frontier is pending, to reduce out-of-order flood.
    const PER_PEER_INFLIGHT_BLOCKS_FRONTIER_PENDING: u32 = 4;
    /// Global download window ahead of connected tip.
    const GLOBAL_WINDOW_BLOCKS: u32 = 1024;
    /// If the frontier block is in-flight longer than this, re-request it from
    /// another idle peer (without waiting for full stall timeout).
    const FRONTIER_RETRY_TIMEOUT: Duration = Duration::from_secs(15);
    /// Keep up to this many parallel owners for the frontier block.
    const FRONTIER_REDUNDANT_PEERS: usize = 2;

    fn request_peer_disconnect(&mut self, peer_id: u64) {
        self.disconnecting_peers.insert(peer_id);
        self.peer_manager.disconnect(peer_id);
    }

    /// Assign pending height-range segments to idle peers.
    /// Called whenever a new peer connects, a batch finishes, or after a stall.
    async fn assign_blocks_to_peers(&mut self) {
        // Collect peers that are not currently handling a batch.
        let our_height = self.chain.read().await.height();
        let max_assignable_height = our_height.saturating_add(Self::GLOBAL_WINDOW_BLOCKS);

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
            chain
                .get_ancestor_hash(frontier)
                .or_else(|| {
                    self.canonical_header_chain
                        .get(frontier as usize)
                        .copied()
                        .filter(|h| *h != Hash256::ZERO)
                })
        };
        let mut frontier_pending = false;
        let mut frontier_hash_for_preemption: Option<Hash256> = None;
        if let Some(frontier_hash) = frontier_hash {
            frontier_hash_for_preemption = Some(frontier_hash);
            let frontier_connected = {
                let chain = self.chain.read().await;
                chain
                    .block_index
                    .get(&frontier_hash)
                    .map(|bi| bi.status == BlockStatus::InChain)
                    .unwrap_or(false)
            };
            if !frontier_connected {
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
                let desired_owners = if stale_owner_exists {
                    Self::FRONTIER_REDUNDANT_PEERS
                } else {
                    Self::FRONTIER_REDUNDANT_PEERS
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
                    self.ibd.assigned_ranges.insert(peer_id, (frontier, frontier));
                    self.ibd.record_peer_request(peer_id, vec![frontier_hash]);
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

        // If frontier is still pending but no idle peer exists, preempt one
        // far-ahead busy peer so the next assignment cycle can immediately
        // dedicate capacity to frontier recovery.
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
                warn!(
                    "IBD: preempting peer {} to free slot for frontier height {}",
                    victim_peer,
                    frontier
                );
                self.ibd.release_peer(victim_peer);
                self.request_peer_disconnect(victim_peer);
                // Wait for disconnect event to avoid immediate re-assignment races.
                return;
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

        let per_peer_cap = if frontier_pending {
            Self::PER_PEER_INFLIGHT_BLOCKS_FRONTIER_PENDING
        } else {
            Self::PER_PEER_INFLIGHT_BLOCKS
        };

        for peer_id in idle_peers.into_iter().take(range_assign_limit) {
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
            let Some(range) = self.ibd.pending_ranges.remove(best_idx) else { continue };
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
            self.ibd.assigned_ranges.insert(peer_id, (start, requested_end));
            self.ibd.record_peer_request(peer_id, hashes.clone());
            self.peer_manager.request_blocks(peer_id, &hashes);
        }

        // If no pending ranges remain and no peer has inflight work, IBD is done.
        if self.ibd.phase == IbdPhase::Blocks && self.ibd.all_ranges_complete() {
            // Double-check by looking for un-downloaded heights.
            let tip = {
                let chain = self.chain.read().await;
                chain.block_index.values().map(|bi| bi.height).max().unwrap_or(0)
            };
            let connected_height = self.chain.read().await.height();
            if connected_height >= tip {
                self.ibd.mark_complete();
            }
        }
    }

    /// Mark `block_hash` connected for all peers that had it in-flight.
    /// This is important when frontier is requested from multiple peers.
    async fn ibd_mark_connected_all(&mut self, block_hash: &Hash256) {
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

        // Skip if already connected.
        let already_connected = {
            let chain = self.chain.read().await;
            chain
                .block_index
                .get(&block_hash)
                .map(|bi| bi.status == BlockStatus::InChain)
                .unwrap_or(false)
        };
        if already_connected {
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
                        return Ok(());
                    }
                    chain.block_index[&block_hash].height
                }
            }
        };

        let chain_height = self.chain.read().await.height();

        if height > chain_height + 1 {
            // Out-of-order block: cache it for later.
            // Do NOT call ibd_mark_connected here — the peer stays "busy" in
            // peer_downloads until its blocks are actually connected to the chain.
            // This prevents the runaway where cached-but-unconnected work triggers
            // ever-further segment assignments.
            debug!(
                "cached out-of-order block {} at height {} (tip={}) from peer {}",
                block_hash.to_hex(),
                height,
                chain_height,
                peer_id
            );
            self.pending_blocks.entry(height).or_insert((peer_id, block));
            return Ok(());
        }

        if height <= chain_height {
            // Stale duplicate or fork block below our tip; nothing to do.
            self.ibd_mark_connected_all(&block_hash).await;
            return Ok(());
        }

        // height == chain_height + 1: validate and connect immediately, then
        // drain any consecutively-pending blocks that are now unblocked.
        self.do_connect_block(peer_id, block_hash, block, height).await?;
        self.ibd_mark_connected_all(&block_hash).await;

        loop {
            let next_height = self.chain.read().await.height() + 1;
            let Some((p_peer, p_block)) = self.pending_blocks.remove(&next_height) else {
                break;
            };
            let p_hash = header_hash(&p_block.header);
            self.do_connect_block(p_peer, p_hash, p_block, next_height).await?;
            // Mark connected here — not at cache time — so peer batch tracking
            // reflects actual chain progress, not just block delivery.
            self.ibd_mark_connected_all(&p_hash).await;
        }

        Ok(())
    }

    /// Validate and connect a single block at `height == chain.height() + 1`.
    /// Does NOT update IBD delivery tracking — the caller is responsible.
    async fn do_connect_block(
        &mut self,
        peer_id: u64,
        block_hash: Hash256,
        block: rbtc_primitives::block::Block,
        height: u32,
    ) -> Result<()> {
        let connect_started = Instant::now();
        let network_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        // Core-style: query MTP from block index on demand during verification.
        let verify_started = Instant::now();
        let assumevalid_skip_scripts;
        let validation_result = {
            let chain = self.chain.read().await;
            let expected_bits = chain.next_required_bits();
            let mtp = chain.median_time_past(height.saturating_sub(1));
            let network = chain.network;
            let flags = script_flags_for_block(network, height, block_hash, block.header.time, mtp);
            let mtp_provider = ChainMtpProvider { chain: &chain };
            assumevalid_skip_scripts = self.should_skip_scripts_with_assumevalid(&chain, height, block_hash);

            let ctx = BlockValidationContext {
                block: &block,
                height,
                median_time_past: mtp,
                network_time,
                expected_bits,
                flags,
                network,
                mtp_provider: &mtp_provider,
            };
            verify_block_with_options(&ctx, &self.utxo_cache, assumevalid_skip_scripts)
        };
        let verify_elapsed = verify_started.elapsed();
        if assumevalid_skip_scripts && !self.assumevalid_announced {
            self.assumevalid_announced = true;
            info!("assumevalid active: skipping script checks while connecting historical ancestors");
        }

        match validation_result {
            Ok(fees) => {
                info!(
                    "block {} at height {height} validated (fees={fees} sat)",
                    block_hash.to_hex()
                );

                // Compute txids for UTXO tracking
                let txids: Vec<_> = block
                    .transactions
                    .iter()
                    .map(|tx| {
                        let mut buf = Vec::new();
                        tx.encode_legacy(&mut buf).ok();
                        sha256d(&buf)
                    })
                    .collect();

                // Connect block to in-memory chain state and collect undo data
                let undo = {
                    let mut chain = self.chain.write().await;
                    let undo = chain.utxos.connect_block_with_undo(
                        &txids,
                        &block.transactions,
                        height,
                    );
                    // Mark block as in-chain in the index
                    if let Some(bi) = chain.block_index.get_mut(&block_hash) {
                        bi.status = BlockStatus::InChain;
                    }
                    // Update active chain
                    if height as usize >= chain.active_chain.len() {
                        chain.active_chain.resize(height as usize + 1, Hash256::ZERO);
                    }
                    chain.active_chain[height as usize] = block_hash;
                    // Update best tip
                    let new_work = chain.block_index[&block_hash].chainwork;
                    let cur_work = chain
                        .best_tip
                        .and_then(|h| chain.block_index.get(&h))
                        .map(|bi| bi.chainwork)
                        .unwrap_or(0);
                    if new_work > cur_work {
                        chain.best_tip = Some(block_hash);
                    }
                    undo
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

                // Update the UTXO cache dirty layer to reflect this block's changes.
                // flush_dirty() will write these to the RocksDB WriteBatch below,
                // replacing the previous `utxo_store.connect_block_into_batch()` call.
                self.utxo_cache.connect_block(&txids, &block.transactions, height);

                // Persist everything to RocksDB in one atomic WriteBatch:
                // block metadata, UTXO changes (via cache flush), and chain tip.
                let write_started = Instant::now();
                {
                    let chainwork = self.chain.read().await.block_index[&block_hash].chainwork;

                    // Block data (large blobs) are written separately; they don't
                    // need to be atomic with the index updates.
                    let block_store = BlockStore::new(&self.db);
                    let stored_idx = StoredBlockIndex {
                        header: block.header.clone(),
                        height,
                        chainwork_lo: chainwork as u64,
                        chainwork_hi: (chainwork >> 64) as u64,
                        status: BlockStatus::InChain.as_u8(),
                    };
                    block_store.put_index(&block_hash, &stored_idx).ok();
                    block_store.put_block(&block_hash, &block).ok();
                    block_store.put_undo(&block_hash, &encode_block_undo(&undo_stored)).ok();

                    // Single WriteBatch for UTXO (flushed from cache) + tx_index
                    // + addr_index + chain tip.
                    let mut batch = self.db.new_batch();

                    // Write dirty UTXO changes and promote them to the hot cache.
                    self.utxo_cache.flush_dirty(&mut batch);

                    let chain_store = ChainStore::new(&self.db);
                    chain_store.update_tip_batch(&mut batch, &block_hash, height, chainwork).ok();

                    self.db.write_batch(batch).ok();

                    // Evicting every block can be expensive at high heights; throttle it.
                    self.blocks_since_utxo_evict = self.blocks_since_utxo_evict.saturating_add(1);
                    if self.blocks_since_utxo_evict >= UTXO_EVICT_INTERVAL_BLOCKS {
                        self.utxo_cache.evict_cold();
                        self.blocks_since_utxo_evict = 0;
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

                // Remove confirmed transactions from the mempool
                {
                    let mut mp = self.mempool.write().await;
                    mp.remove_confirmed(&txids);
                }

                // Update wallet UTXO tracking (incremental block scan)
                if let Some(wallet) = &self.wallet {
                    let mut w = wallet.write().await;
                    w.scan_block(&block, height);
                    w.remove_spent(&block);
                }

                // Update peer manager's best height
                self.peer_manager.set_best_height(height as i32);

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
                warn!("block {} rejected from peer {peer_id}: {e}", block_hash.to_hex());
            }
        }

        Ok(())
    }

    fn should_skip_scripts_with_assumevalid(
        &self,
        chain: &ChainState,
        height: u32,
        block_hash: Hash256,
    ) -> bool {
        if self.ibd.phase != IbdPhase::Blocks {
            return false;
        }
        let Some(assumevalid_hash) = self.assumevalid_hash else {
            return false;
        };
        let Some(assumevalid_bi) = chain.block_index.get(&assumevalid_hash) else {
            return false;
        };
        if height > assumevalid_bi.height {
            return false;
        }
        let Some(canon_hash) = self.canonical_header_chain.get(height as usize) else {
            return false;
        };
        if *canon_hash != block_hash {
            return false;
        }
        let Some(canon_assumevalid) = self.canonical_header_chain.get(assumevalid_bi.height as usize) else {
            return false;
        };
        *canon_assumevalid == assumevalid_hash
    }

    /// Accept an unconfirmed transaction into the mempool and relay it.
    async fn handle_tx(
        &mut self,
        peer_id: u64,
        tx: rbtc_primitives::transaction::Transaction,
    ) {
        let txid = {
            let mut buf = Vec::new();
            tx.encode_legacy(&mut buf).ok();
            sha256d(&buf)
        };

        let chain = self.chain.read().await;
        let height = chain.height();
        let mut mp = self.mempool.write().await;

        match mp.accept_tx(tx, &chain.utxos, height) {
            Ok(accepted_txid) => {
                info!(
                    "mempool: accepted tx {} from peer {peer_id}",
                    accepted_txid.to_hex()
                );
                // Compute fee rate in sat/kvB for feefilter comparison
                let fee_rate_sat_kvb = mp.get(&accepted_txid)
                    .map(|e| e.fee_rate * 1000)
                    .unwrap_or(0);
                drop(mp);
                drop(chain);
                // Announce to peers whose feefilter allows this tx
                let inv = vec![Inventory { inv_type: InvType::WitnessTx, hash: txid }];
                self.peer_manager.broadcast_tx_inv(NetworkMessage::Inv(inv), fee_rate_sat_kvb);
            }
            Err(e) => {
                // AlreadyKnown is not worth logging
                if !matches!(e, rbtc_mempool::MempoolError::AlreadyKnown) {
                    // During IBD, missing-input rejections are expected because peers
                    // announce tip mempool txs that spend outputs we have not synced yet.
                    if self.ibd.phase != IbdPhase::Complete
                        && matches!(e, rbtc_mempool::MempoolError::MissingInput(_, _))
                    {
                        debug!("mempool: rejected tx {} from peer {peer_id}: {e}", txid.to_hex());
                    } else {
                        warn!("mempool: rejected tx {} from peer {peer_id}: {e}", txid.to_hex());
                    }
                }
            }
        }
    }

    /// Reorg: disconnect the current best chain back to `fork_point` and
    /// connect the new chain. Requires undo data to be present in storage.
    #[allow(dead_code)]
    async fn reorganize_to(&mut self, new_tip: rbtc_primitives::hash::BlockHash) -> Result<()> {
        let (fork_point, old_chain, new_chain) = {
            let chain = self.chain.read().await;
            find_fork(&chain, new_tip)?
        };

        info!(
            "reorg: fork at height {fork_point}, disconnecting {} blocks, connecting {} blocks",
            old_chain.len(),
            new_chain.len()
        );

        let block_store = BlockStore::new(&self.db);
        let utxo_store = UtxoStore::new(&self.db);

        let tx_idx = TxIndexStore::new(&self.db);
        let addr_idx = AddrIndexStore::new(&self.db);

        // Disconnect old chain (reverse order)
        for hash in old_chain.iter().rev() {
            let block = block_store
                .get_block(hash)?
                .ok_or_else(|| anyhow::anyhow!("reorg: missing block {}", hash.to_hex()))?;
            let undo_bytes = block_store
                .get_undo(hash)?
                .ok_or_else(|| anyhow::anyhow!("reorg: missing undo for {}", hash.to_hex()))?;
            let undo = decode_block_undo(&undo_bytes)?;

            let txids: Vec<_> = block
                .transactions
                .iter()
                .map(|tx| {
                    let mut buf = Vec::new();
                    tx.encode_legacy(&mut buf).ok();
                    sha256d(&buf)
                })
                .collect();

            // Remove tx and address index entries for this block
            let disconnected_height = self.chain.read().await.block_index[hash].height;
            for (offset, (tx, txid)) in block.transactions.iter().zip(txids.iter()).enumerate() {
                tx_idx.remove(txid).ok();
                for output in &tx.outputs {
                    addr_idx.remove(&output.script_pubkey.0, disconnected_height, offset as u32).ok();
                }
            }

            // In-memory UTXO undo
            let mem_undo: Vec<Vec<(rbtc_primitives::transaction::OutPoint, rbtc_consensus::utxo::Utxo)>> = undo
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

            {
                let mut chain = self.chain.write().await;
                chain.utxos.disconnect_block(&txids, &block.transactions, mem_undo);
                chain.disconnect_tip()?;
            }

            // Persist UTXO undo
            utxo_store.disconnect_block(&txids, &block.transactions, &undo.concat()).ok();
        }

        // Connect new chain (forward order)
        for hash in &new_chain {
            let block = block_store
                .get_block(hash)?
                .ok_or_else(|| anyhow::anyhow!("reorg: missing block {}", hash.to_hex()))?;
            // Re-use handle_block logic would require a lot of restructuring;
            // for now we do a simplified connect without peer context.
            let height = self.chain.read().await.block_index[hash].height;
            let txids: Vec<_> = block
                .transactions
                .iter()
                .map(|tx| {
                    let mut buf = Vec::new();
                    tx.encode_legacy(&mut buf).ok();
                    sha256d(&buf)
                })
                .collect();

            let undo = {
                let mut chain = self.chain.write().await;
                chain.utxos.connect_block_with_undo(&txids, &block.transactions, height)
            };

            let undo_stored: Vec<Vec<(rbtc_primitives::transaction::OutPoint, StoredUtxo)>> = undo
                .iter()
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

            block_store.put_undo(hash, &encode_block_undo(&undo_stored)).ok();
            utxo_store.connect_block(&txids, &block.transactions, height).ok();

            // Write tx + address index for the re-connected block
            for (offset, (tx, txid)) in block.transactions.iter().zip(txids.iter()).enumerate() {
                tx_idx.put(txid, hash, offset as u32).ok();
                for output in &tx.outputs {
                    addr_idx.put(&output.script_pubkey.0, height, offset as u32, txid).ok();
                }
            }

            {
                let mut chain = self.chain.write().await;
                if let Some(bi) = chain.block_index.get_mut(hash) {
                    bi.status = BlockStatus::InChain;
                }
                if height as usize >= chain.active_chain.len() {
                    chain.active_chain.resize(height as usize + 1, Hash256::ZERO);
                }
                chain.active_chain[height as usize] = *hash;
                chain.best_tip = Some(*hash);
            }

            let chainwork = self.chain.read().await.block_index[hash].chainwork;
            let chain_store = ChainStore::new(&self.db);
            chain_store.update_tip(hash, height, chainwork).ok();
        }

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
        if let Ok(genesis) = Hash256::from_hex(network.genesis_hash()) {
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
                chain
                    .get_ancestor_hash(frontier)
                    .or_else(|| {
                        self.canonical_header_chain
                            .get(frontier as usize)
                            .copied()
                            .filter(|h| *h != Hash256::ZERO)
                    })
            };
            if let Some(frontier_hash) = frontier_hash {
                let frontier_connected = {
                    let chain = self.chain.read().await;
                    chain
                        .block_index
                        .get(&frontier_hash)
                        .map(|bi| bi.status == BlockStatus::InChain)
                        .unwrap_or(false)
                };
                if !frontier_connected {
                    let frontier_owner = self
                        .ibd
                        .peer_downloads
                        .iter()
                        .find(|(_, dl)| dl.hashes.iter().any(|h| h == &frontier_hash))
                        .map(|(peer_id, dl)| (*peer_id, dl.requested_at.elapsed()));
                    if let Some((peer_id, age)) = frontier_owner {
                        if age >= Self::FRONTIER_RETRY_TIMEOUT {
                            warn!(
                                "IBD frontier timeout: height {} in-flight on peer {} for {}s; failover",
                                frontier,
                                peer_id,
                                age.as_secs()
                            );
                            self.ibd.release_peer(peer_id);
                            self.request_peer_disconnect(peer_id);
                            disconnected_any = true;
                        }
                    }
                }
            }

            // Per-peer stall detection: disconnect stalled peers and re-queue their ranges.
            let stalled = self.ibd.stalled_peers(STALL_TIMEOUT);
            for peer_id in stalled {
                warn!(
                    "IBD stall: peer {} made no progress for {}s; re-assigning range",
                    peer_id,
                    STALL_TIMEOUT.as_secs()
                );
                self.ibd.release_peer(peer_id);
                self.request_peer_disconnect(peer_id);
                disconnected_any = true;
            }
            // Fill any idle peers with pending segments.
            if !disconnected_any {
                self.assign_blocks_to_peers().await;
            }
        } else {
            // Headers phase: single-peer stall detection.
            if self.ibd.is_stalled() {
                let stale = self.ibd.sync_peer.take().unwrap();
                warn!(
                    "IBD stall: peer {stale} made no header progress for {}s; switching",
                    STALL_TIMEOUT.as_secs()
                );
                self.request_peer_disconnect(stale);
            }

            if self.ibd.sync_peer.is_none() {
                if let Some(peer_id) = self.peer_manager.best_peer() {
                    self.ibd.sync_peer = Some(peer_id);
                    self.ibd.record_progress();
                    self.request_headers(peer_id).await;
                }
            }
        }
    }

    async fn log_stats(&self) {
        let chain = self.chain.read().await;
        let height = chain.height();
        let utxos = chain.utxos.len();
        drop(chain);
        let peers = self.peer_manager.peer_count();
        let best_peer_height = self.peer_manager.best_peer_height();
        let mp_size = self.mempool.read().await.len();
        info!(
            "height={height} peers={peers} best_peer={best_peer_height} utxos={utxos} mempool={mp_size}"
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
            use std::net::{Ipv6Addr, IpAddr, SocketAddr};
            let v6 = Ipv6Addr::from(*ip_bytes);
            let ip = v6.to_ipv4_mapped()
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

        let candidates = self.peer_manager.candidate_addrs_snapshot();
        if candidates.is_empty() {
            return;
        }

        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entries: Vec<_> = candidates.iter()
            .map(|addr| (*addr, unix_now, 1u64))
            .collect();

        let peer_store = PeerStore::new(&self.db);
        if let Err(e) = peer_store.save_addrs(&entries) {
            warn!("failed to persist peer addresses: {e}");
        } else {
            info!("persisted {} candidate peer addresses", entries.len());
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
            tx_idx.batch_put(&mut batch, txid, &task.block_hash, offset as u32).ok();
            for output in &tx.outputs {
                addr_idx.batch_put(
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

fn load_chain_state(chain: &mut ChainState, db: &Database) -> Result<()> {
    let block_store = BlockStore::new(db);
    let utxo_store = UtxoStore::new(db);

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

    for (hash, stored) in indices {
        let status = BlockStatus::from_u8(stored.status);
        let chainwork = stored.chainwork();
        let index = BlockIndex {
            hash,
            header: stored.header,
            height: stored.height,
            chainwork,
            status,
        };
        chain.insert_block_index(hash, index);
    }

    // Load UTXOs from RocksDB into the in-memory UTXO set
    let utxos = utxo_store.iter_all();
    let utxo_count = utxos.len();
    for (outpoint, stored) in utxos {
        use rbtc_consensus::utxo::Utxo;
        chain.utxos.insert(
            outpoint,
            Utxo {
                txout: stored.to_txout(),
                is_coinbase: stored.is_coinbase,
                height: stored.height,
            },
        );
    }

    info!(
        "chain rebuilt: height={} utxos={utxo_count}",
        chain.height()
    );
    Ok(())
}

// ── Reorg helper ─────────────────────────────────────────────────────────────

/// Find the fork point between the active chain and a new tip.
/// Returns `(fork_height, old_chain_hashes, new_chain_hashes)`.
fn find_fork(
    chain: &ChainState,
    new_tip: rbtc_primitives::hash::BlockHash,
) -> Result<(u32, Vec<rbtc_primitives::hash::BlockHash>, Vec<rbtc_primitives::hash::BlockHash>)>
{
    let mut old_chain = Vec::new();
    let mut new_chain = Vec::new();

    // Walk new_tip back until we find a block that is InChain
    let mut cursor = new_tip;
    loop {
        let bi = chain
            .block_index
            .get(&cursor)
            .ok_or_else(|| anyhow::anyhow!("fork search: unknown block {}", cursor.to_hex()))?;
        if bi.status == BlockStatus::InChain {
            // Found the fork point
            let fork_height = bi.height;
            // Collect old chain from tip to fork
            let best = chain.best_tip.unwrap_or(Hash256::ZERO);
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
