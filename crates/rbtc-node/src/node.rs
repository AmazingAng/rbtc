use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use rbtc_consensus::{
    block_verify::{verify_block, BlockValidationContext},
    chain::{BlockIndex, BlockStatus, ChainState, header_hash},
};
use rbtc_crypto::sha256d;
use rbtc_mempool::Mempool;
use rbtc_net::{
    message::{Inventory, InvType, NetworkMessage},
    peer_manager::{NodeEvent, PeerManager, PeerManagerConfig},
};
use rbtc_primitives::hash::Hash256;
use rbtc_script::ScriptFlags;
use rbtc_storage::{
    encode_block_undo, decode_block_undo, AddrIndexStore, BlockStore, ChainStore, Database,
    StoredBlockIndex, StoredUtxo, TxIndexStore, UtxoStore,
};
use rbtc_wallet::Wallet;

use crate::{
    config::Args,
    ibd::{build_locator, IbdPhase, IbdState},
    rpc::{start_rpc_server, RpcState},
};

/// Peer ID used when a block is submitted locally (via RPC).
const LOCAL_PEER_ID: u64 = 0;

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
    peer_manager: PeerManager,
    node_event_rx: mpsc::UnboundedReceiver<NodeEvent>,
    /// Sender half given to the RPC server for `submitblock` / `generatetoaddress`.
    submit_block_tx: mpsc::UnboundedSender<rbtc_primitives::block::Block>,
    /// Receiver for blocks submitted via the RPC `submitblock` / `generatetoaddress`.
    submit_block_rx: mpsc::UnboundedReceiver<rbtc_primitives::block::Block>,
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
        let mempool = Arc::new(RwLock::new(Mempool::new()));

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
        let peer_manager = PeerManager::new(pm_config, node_event_tx, current_height);

        Ok(Self {
            args,
            db,
            chain,
            mempool,
            wallet,
            ibd: IbdState::new(),
            peer_manager,
            node_event_rx,
            submit_block_tx,
            submit_block_rx,
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
        let mut ibd_timer = tokio::time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = self.process_pending_events() => {}

                _ = stats_timer.tick() => {
                    self.log_stats().await;
                }

                _ = ibd_timer.tick() => {
                    self.check_ibd_progress().await;
                }
            }
        }
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
                info!("peer {peer_id} connected from {addr}, height={best_height}");
                let our_height = self.chain.read().await.height() as i32;
                if best_height > our_height && self.ibd.sync_peer.is_none() {
                    self.ibd.sync_peer = Some(peer_id);
                    self.request_headers(peer_id).await;
                }
            }

            NodeEvent::PeerDisconnected { peer_id } => {
                info!("peer {peer_id} disconnected");
                if self.ibd.sync_peer == Some(peer_id) {
                    self.ibd.sync_peer = None;
                    if let Some(new_peer) = self.peer_manager.best_peer() {
                        self.ibd.sync_peer = Some(new_peer);
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
                self.download_blocks(peer_id).await;
            }
            return Ok(());
        }

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
            self.download_blocks(peer_id).await;
        }

        Ok(())
    }

    async fn download_blocks(&mut self, peer_id: u64) {
        let chain = self.chain.read().await;
        let mut current_height = chain.height() + 1;
        let mut hashes = Vec::new();

        while let Some(hash) = chain.get_ancestor_hash(current_height) {
            if chain
                .block_index
                .get(&hash)
                .map(|bi| bi.status == BlockStatus::InChain)
                .unwrap_or(false)
            {
                current_height += 1;
                continue;
            }
            hashes.push(hash);
            if hashes.len() >= 16 {
                break;
            }
            current_height += 1;
        }
        drop(chain);

        if !hashes.is_empty() {
            info!(
                "IBD: requesting {} blocks starting at height {}",
                hashes.len(),
                self.chain.read().await.height() + 1
            );
            self.peer_manager.request_blocks(peer_id, &hashes);
        } else if self.ibd.phase == IbdPhase::Blocks {
            self.ibd.mark_complete();
        }
    }

    async fn handle_block(
        &mut self,
        peer_id: u64,
        block: rbtc_primitives::block::Block,
    ) -> Result<()> {
        let block_hash = header_hash(&block.header);

        // Already in chain?
        {
            let chain = self.chain.read().await;
            if chain
                .block_index
                .get(&block_hash)
                .map(|bi| bi.status == BlockStatus::InChain)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }

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

        let (expected_bits, mtp) = {
            let chain = self.chain.read().await;
            (
                chain.next_required_bits(),
                chain.median_time_past(height.saturating_sub(1)),
            )
        };

        let network_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let flags = ScriptFlags::standard();

        // Validate block (takes read lock on utxos via chain read)
        let validation_result = {
            let chain = self.chain.read().await;
            let ctx = BlockValidationContext {
                block: &block,
                height,
                median_time_past: mtp,
                network_time,
                expected_bits,
                flags,
            };
            verify_block(&ctx, &chain.utxos)
        };

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

                // Persist everything to RocksDB
                {
                    let chainwork = self.chain.read().await.block_index[&block_hash].chainwork;

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

                    let utxo_store = UtxoStore::new(&self.db);
                    utxo_store.connect_block(&txids, &block.transactions, height).ok();

                    let chain_store = ChainStore::new(&self.db);
                    chain_store.update_tip(&block_hash, height, chainwork).ok();
                }

                // Write transaction index and address index
                {
                    let tx_idx = TxIndexStore::new(&self.db);
                    let addr_idx = AddrIndexStore::new(&self.db);
                    for (offset, (tx, txid)) in block.transactions.iter().zip(txids.iter()).enumerate() {
                        tx_idx.put(txid, &block_hash, offset as u32).ok();
                        for output in &tx.outputs {
                            addr_idx.put(&output.script_pubkey.0, height, offset as u32, txid).ok();
                        }
                    }
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

                // Continue IBD
                if !self.ibd.is_complete() {
                    self.download_blocks(peer_id).await;
                }

                // ── Reorg detection ─────────────────────────────────────────
                // If a new block arrives that doesn't extend our current best tip
                // but has more chainwork, initiate a reorganization.
                // (Full reorg logic: handled separately by `reorganize_to` below)
            }
            Err(e) => {
                warn!("block {} rejected from peer {peer_id}: {e}", block_hash.to_hex());
            }
        }

        Ok(())
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
                drop(mp);
                drop(chain);
                // Announce to all other peers
                let inv = vec![Inventory { inv_type: InvType::WitnessTx, hash: txid }];
                self.peer_manager.broadcast(NetworkMessage::Inv(inv));
            }
            Err(e) => {
                // AlreadyKnown is not worth logging
                if !matches!(e, rbtc_mempool::MempoolError::AlreadyKnown) {
                    warn!("mempool: rejected tx {} from peer {peer_id}: {e}", txid.to_hex());
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
        let locator = build_locator(height, |h| chain.get_ancestor_hash(h));
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
        if self.ibd.sync_peer.is_none() {
            if let Some(peer_id) = self.peer_manager.best_peer() {
                self.ibd.sync_peer = Some(peer_id);
                self.request_headers(peer_id).await;
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
