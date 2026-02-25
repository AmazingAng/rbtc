use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use rbtc_consensus::chain::{ChainState, header_hash};
use rbtc_net::{
    message::{Inventory, InvType, NetworkMessage},
    peer_manager::{NodeEvent, PeerManager, PeerManagerConfig},
};
use rbtc_primitives::hash::Hash256;
use rbtc_script::ScriptFlags;
use rbtc_storage::{BlockStore, ChainStore, Database};

use crate::{
    config::Args,
    ibd::{build_locator, IbdPhase, IbdState},
};

/// The main Bitcoin node
pub struct Node {
    args: Args,
    db: Arc<Database>,
    chain: ChainState,
    ibd: IbdState,
    peer_manager: PeerManager,
    node_event_rx: mpsc::UnboundedReceiver<NodeEvent>,
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

        // Load or initialize chain state
        let mut chain = ChainState::new(args.network);
        load_chain_state(&mut chain, &db)?;

        info!(
            "chain state loaded: height={} tip={:?}",
            chain.height(),
            chain.best_hash().map(|h| h.to_hex())
        );

        // Create peer manager
        let (node_event_tx, node_event_rx) = mpsc::unbounded_channel();
        let pm_config = PeerManagerConfig {
            network: args.network,
            max_outbound: args.max_outbound,
            ..Default::default()
        };
        let peer_manager = PeerManager::new(pm_config, node_event_tx, chain.height() as i32);

        Ok(Self {
            args,
            db,
            chain,
            ibd: IbdState::new(),
            peer_manager,
            node_event_rx,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!("starting node on network: {}", self.args.network);

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
                // Process peer events
                _ = self.process_pending_events() => {}

                // Periodic stats logging
                _ = stats_timer.tick() => {
                    self.log_stats();
                }

                // IBD progress / stall detection
                _ = ibd_timer.tick() => {
                    self.check_ibd_progress().await;
                }
            }
        }
    }

    async fn process_pending_events(&mut self) {
        // Drain all pending events
        self.peer_manager.process_events().await;

        while let Ok(event) = self.node_event_rx.try_recv() {
            if let Err(e) = self.handle_node_event(event).await {
                error!("event handling error: {e}");
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    async fn handle_node_event(&mut self, event: NodeEvent) -> Result<()> {
        match event {
            NodeEvent::PeerConnected { peer_id, addr, best_height } => {
                info!("peer {peer_id} connected from {addr}, height={best_height}");

                // Kick off IBD if we're behind
                if best_height > self.chain.height() as i32 && self.ibd.sync_peer.is_none() {
                    self.ibd.sync_peer = Some(peer_id);
                    self.request_headers(peer_id);
                }
            }

            NodeEvent::PeerDisconnected { peer_id } => {
                info!("peer {peer_id} disconnected");
                if self.ibd.sync_peer == Some(peer_id) {
                    self.ibd.sync_peer = None;
                    // Find another peer to sync from
                    if let Some(new_peer) = self.peer_manager.best_peer() {
                        self.ibd.sync_peer = Some(new_peer);
                        self.request_headers(new_peer);
                    }
                }
            }

            NodeEvent::HeadersReceived { peer_id, headers } => {
                let count = headers.len();
                info!("received {count} headers from peer {peer_id}");
                self.handle_headers(peer_id, headers).await?;
            }

            NodeEvent::BlockReceived { peer_id, block } => {
                let height = self.chain.height();
                info!("received block from peer {peer_id}, our height={height}");
                self.handle_block(peer_id, block).await?;
            }

            NodeEvent::TxReceived { peer_id, tx } => {
                // Basic mempool acceptance (not implemented yet)
                let txid = rbtc_crypto::sha256d(&tx_legacy_bytes(&tx));
                info!("received tx {} from peer {peer_id}", txid.to_hex());
            }

            NodeEvent::InvReceived { peer_id, items } => {
                // Request any blocks/txs we don't have
                let mut to_request: Vec<Inventory> = Vec::new();
                for item in items {
                    match item.inv_type {
                        InvType::Block | InvType::WitnessBlock => {
                            if !self.chain.block_index.contains_key(&item.hash) {
                                to_request.push(Inventory {
                                    inv_type: InvType::WitnessBlock,
                                    hash: item.hash,
                                });
                            }
                        }
                        InvType::Tx | InvType::WitnessTx => {
                            // Could request txs for mempool; skip for now
                        }
                        _ => {}
                    }
                }
                if !to_request.is_empty() {
                    self.peer_manager.send_to(peer_id, NetworkMessage::GetData(to_request));
                }
            }
        }

        Ok(())
    }

    async fn handle_headers(&mut self, peer_id: u64, headers: Vec<rbtc_primitives::block::BlockHeader>) -> Result<()> {
        if headers.is_empty() {
            // We're caught up with this peer
            if self.ibd.phase == IbdPhase::Headers {
                self.ibd.phase = IbdPhase::Blocks;
                info!("IBD: entering block download phase");
                // Request blocks for all known headers
                self.download_blocks(peer_id).await;
            }
            return Ok(());
        }

        let last_header = headers.last().cloned();

        // Add headers to our index
        for header in &headers {
            let _hash = header_hash(header);
            match self.chain.add_header(header.clone()) {
                Ok(_) => {}
                Err(e) => {
                    warn!("header validation error from peer {peer_id}: {e}");
                    // Don't break – might just be a fork
                }
            }
        }

        // Request more headers
        if headers.len() == 2000 {
            // Bitcoin sends up to 2000 headers at a time; if we got 2000, request more
            let last_hash = last_header.map(|h| header_hash(&h)).unwrap_or(Hash256::ZERO);
            self.peer_manager.send_to(
                peer_id,
                NetworkMessage::GetHeaders(
                    rbtc_net::message::GetBlocksMessage {
                        version: 70016,
                        locator_hashes: vec![last_hash],
                        stop_hash: Hash256::ZERO,
                    },
                ),
            );
        } else {
            // Fewer than 2000 – we have all headers up to their tip
            self.ibd.phase = IbdPhase::Blocks;
            self.download_blocks(peer_id).await;
        }

        Ok(())
    }

    async fn download_blocks(&mut self, peer_id: u64) {
        // Find blocks in our index that we don't have in the UTXO chain yet
        // Start from our current tip height + 1
        let mut current_height = self.chain.height() + 1;
        let mut hashes = Vec::new();

        while let Some(hash) = self.chain.get_ancestor_hash(current_height) {
            if self.chain.block_index.get(&hash)
                .map(|bi| bi.status == rbtc_consensus::chain::BlockStatus::InChain)
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

        if !hashes.is_empty() {
            info!("IBD: requesting {} blocks starting at height {}", hashes.len(), self.chain.height() + 1);
            self.peer_manager.request_blocks(peer_id, &hashes);
        } else if self.ibd.phase == IbdPhase::Blocks {
            self.ibd.mark_complete();
        }
    }

    async fn handle_block(&mut self, peer_id: u64, block: rbtc_primitives::block::Block) -> Result<()> {
        use rbtc_consensus::block_verify::{verify_block, BlockValidationContext};

        let block_hash = header_hash(&block.header);

        // Check if we already have this block
        if self.chain.block_index.get(&block_hash)
            .map(|bi| bi.status == rbtc_consensus::chain::BlockStatus::InChain)
            .unwrap_or(false)
        {
            return Ok(());
        }

        let height = match self.chain.block_index.get(&block_hash) {
            Some(bi) => bi.height,
            None => {
                // Unknown block – try to add the header first
                if let Err(e) = self.chain.add_header(block.header.clone()) {
                    warn!("unknown block header from peer {peer_id}: {e}");
                    return Ok(());
                }
                self.chain.block_index[&block_hash].height
            }
        };

        let expected_bits = self.chain.next_required_bits();
        let mtp = self.chain.median_time_past(height.saturating_sub(1));
        let network_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let flags = ScriptFlags::standard();
        let ctx = BlockValidationContext {
            block: &block,
            height,
            median_time_past: mtp,
            network_time,
            expected_bits,
            flags,
        };

        match verify_block(&ctx, &self.chain.utxos) {
            Ok(fees) => {
                info!(
                    "block {} at height {height} validated (fees={fees} sat)",
                    block_hash.to_hex()
                );
                self.chain.connect_block(&block, block_hash)?;

                // Persist the new tip
                let chain_store = ChainStore::new(&self.db);
                chain_store.update_tip(
                    &block_hash,
                    height,
                    self.chain.block_index[&block_hash].chainwork,
                ).ok();

                let block_store = BlockStore::new(&self.db);
                block_store.put_block(&block_hash, &block).ok();

                // Continue IBD
                if !self.ibd.is_complete() {
                    self.download_blocks(peer_id).await;
                }
            }
            Err(e) => {
                warn!("block {} rejected from peer {peer_id}: {e}", block_hash.to_hex());
            }
        }

        Ok(())
    }

    fn request_headers(&self, peer_id: u64) {
        let height = self.chain.height();
        let locator = build_locator(height, |h| self.chain.get_ancestor_hash(h));
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
        // If no sync peer, find one
        if self.ibd.sync_peer.is_none() {
            if let Some(peer_id) = self.peer_manager.best_peer() {
                self.ibd.sync_peer = Some(peer_id);
                self.request_headers(peer_id);
            }
        }
    }

    fn log_stats(&self) {
        let height = self.chain.height();
        let peers = self.peer_manager.peer_count();
        let best_peer_height = self.peer_manager.best_peer_height();
        let utxos = self.chain.utxos.len();
        info!(
            "height={height} peers={peers} best_peer_height={best_peer_height} utxos={utxos}"
        );
    }
}

fn load_chain_state(_chain: &mut ChainState, db: &Database) -> Result<()> {
    let chain_store = ChainStore::new(db);
    // If there's a stored best block, we could reload it here
    // For now, we start fresh (IBD will re-sync)
    if let Ok(Some(_tip)) = chain_store.get_best_block() {
        info!("loaded existing chain state from disk");
        // TODO: rebuild in-memory block index from stored block headers
    }
    Ok(())
}

fn tx_legacy_bytes(tx: &rbtc_primitives::transaction::Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    tx.encode_legacy(&mut buf).ok();
    buf
}
