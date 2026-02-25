use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use rbtc_primitives::hash::BlockHash;
use tracing::{debug, info};

/// How long to wait without progress before declaring a stall and switching peers.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Number of block hashes in each parallel download segment.
pub const SEGMENT_SIZE: usize = 512;

/// Per-peer in-flight block download batch.
pub struct PeerDownload {
    /// Block hashes requested from this peer that have not yet been received.
    pub hashes: Vec<BlockHash>,
    /// When the getdata request was sent.
    pub requested_at: Instant,
}

/// State machine for Initial Block Download
pub struct IbdState {
    /// Current IBD phase
    pub phase: IbdPhase,

    // ── Headers phase ──────────────────────────────────────────────────────────
    /// Single sync peer used while downloading headers (one-at-a-time).
    pub sync_peer: Option<u64>,
    /// Last block connected or header received (for Headers-phase stall detection).
    pub last_progress: Instant,

    // ── Blocks phase ───────────────────────────────────────────────────────────
    /// Per-peer inflight block download batches: peer_id → current batch.
    pub peer_downloads: HashMap<u64, PeerDownload>,
    /// Height range work queue: segments of (start, end) not yet dispatched.
    pub pending_ranges: VecDeque<(u32, u32)>,
    /// Ranges currently assigned to a peer: peer_id → (start, end) inclusive.
    pub assigned_ranges: HashMap<u64, (u32, u32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbdPhase {
    /// Downloading headers first
    Headers,
    /// Downloading and validating blocks
    Blocks,
    /// Caught up with the network
    Complete,
}

impl IbdState {
    pub fn new() -> Self {
        Self {
            phase: IbdPhase::Headers,
            sync_peer: None,
            last_progress: Instant::now(),
            peer_downloads: HashMap::new(),
            pending_ranges: VecDeque::new(),
            assigned_ranges: HashMap::new(),
        }
    }

    /// Update the last-progress timestamp (called when a block is connected or
    /// a batch of headers is received).
    pub fn record_progress(&mut self) {
        self.last_progress = Instant::now();
    }

    /// True if we are in the Headers phase, have a sync peer, but haven't made
    /// progress within STALL_TIMEOUT.
    pub fn is_stalled(&self) -> bool {
        self.phase == IbdPhase::Headers
            && self.sync_peer.is_some()
            && self.last_progress.elapsed() > STALL_TIMEOUT
    }

    pub fn is_complete(&self) -> bool {
        self.phase == IbdPhase::Complete
    }

    pub fn mark_complete(&mut self) {
        self.phase = IbdPhase::Complete;
        info!("IBD complete");
    }

    // ── Blocks-phase helpers ───────────────────────────────────────────────────

    /// Record that a getdata for `hashes` was sent to `peer_id`.
    pub fn record_peer_request(&mut self, peer_id: u64, hashes: Vec<BlockHash>) {
        self.peer_downloads.insert(
            peer_id,
            PeerDownload {
                hashes,
                requested_at: Instant::now(),
            },
        );
    }

    /// Mark `hash` as received from `peer_id`.  Returns `true` when the peer's
    /// current batch is now fully received (peer is free for re-assignment).
    pub fn complete_peer_block(&mut self, peer_id: u64, hash: &BlockHash) -> bool {
        if let Some(dl) = self.peer_downloads.get_mut(&peer_id) {
            dl.hashes.retain(|h| h != hash);
            if dl.hashes.is_empty() {
                self.peer_downloads.remove(&peer_id);
                return true;
            }
        }
        false
    }

    /// Return the IDs of all peers whose in-flight request is older than `timeout`.
    pub fn stalled_peers(&self, timeout: Duration) -> Vec<u64> {
        self.peer_downloads
            .iter()
            .filter(|(_, dl)| dl.requested_at.elapsed() > timeout)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Release a peer: remove its in-flight entry and return its assigned range
    /// back to the front of `pending_ranges` so it gets retried first.
    pub fn release_peer(&mut self, peer_id: u64) -> Option<(u32, u32)> {
        self.peer_downloads.remove(&peer_id);
        let range = self.assigned_ranges.remove(&peer_id);
        if let Some(r) = range {
            self.pending_ranges.push_front(r);
        }
        range
    }

    /// Partition [start_height, tip_height] into segments of `segment_size` and
    /// fill `pending_ranges`.  Called once when transitioning to the Blocks phase.
    pub fn partition_ranges(&mut self, start_height: u32, tip_height: u32, segment_size: usize) {
        self.pending_ranges.clear();
        let seg = segment_size as u32;
        let mut h = start_height;
        while h <= tip_height {
            let end = (h + seg - 1).min(tip_height);
            self.pending_ranges.push_back((h, end));
            h = end + 1;
        }
        debug!(
            "IBD: partitioned heights {}..={} into {} segments",
            start_height,
            tip_height,
            self.pending_ranges.len()
        );
    }

    /// True when all ranges have been assigned and all peers have finished.
    pub fn all_ranges_complete(&self) -> bool {
        self.pending_ranges.is_empty() && self.peer_downloads.is_empty()
    }
}

/// Build a block locator from the active chain (exponential backoff)
pub fn build_locator(best_height: u32, get_hash_at: impl Fn(u32) -> Option<BlockHash>) -> Vec<BlockHash> {
    let mut locator = Vec::new();
    let mut step = 1u32;
    let mut height = best_height;

    loop {
        if let Some(hash) = get_hash_at(height) {
            locator.push(hash);
        }
        if height == 0 {
            break;
        }
        if locator.len() >= 10 {
            step *= 2;
        }
        height = height.saturating_sub(step);
    }

    // Always include genesis
    if let Some(genesis) = get_hash_at(0) {
        if !locator.contains(&genesis) {
            locator.push(genesis);
        }
    }

    locator
}
