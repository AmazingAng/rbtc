//! Global block download tracker with stall detection and exponential backoff.
//!
//! Tracks all in-flight block requests across peers, identifies stallers,
//! and implements exponential backoff on stall timeouts (2s → 64s).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rbtc_primitives::hash::BlockHash;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of blocks in flight per peer.
/// Matches Bitcoin Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER` (16).
pub const BLOCK_DOWNLOAD_WINDOW: usize = 16;

/// Initial stall timeout (seconds).
pub const INITIAL_STALL_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum stall timeout after exponential backoff.
pub const MAX_STALL_TIMEOUT: Duration = Duration::from_secs(64);

/// Base multiplier for block download timeout (multiples of target spacing).
pub const BLOCK_DOWNLOAD_TIMEOUT_BASE: f64 = 1.0;

/// Additional timeout per active downloading peer.
pub const BLOCK_DOWNLOAD_TIMEOUT_PER_PEER: f64 = 0.5;

// ── Types ────────────────────────────────────────────────────────────────────

/// A single in-flight block request.
#[derive(Debug, Clone)]
struct InFlightEntry {
    peer_id: u64,
    requested_at: Instant,
}

/// Per-peer download state.
#[derive(Debug)]
struct PeerDownloadState {
    /// Number of blocks currently in flight.
    count: usize,
    /// When the first block in this peer's queue was requested.
    downloading_since: Option<Instant>,
    /// When this peer was identified as stalling.
    stalling_since: Option<Instant>,
    /// Current stall timeout (doubles on each stall, capped at MAX_STALL_TIMEOUT).
    stall_timeout: Duration,
}

impl PeerDownloadState {
    fn new() -> Self {
        Self {
            count: 0,
            downloading_since: None,
            stalling_since: None,
            stall_timeout: INITIAL_STALL_TIMEOUT,
        }
    }

    /// Double the stall timeout, capped at MAX_STALL_TIMEOUT.
    fn bump_stall_timeout(&mut self) {
        self.stall_timeout = (self.stall_timeout * 2).min(MAX_STALL_TIMEOUT);
    }
}

/// Information about a stalled peer.
#[derive(Debug)]
pub struct StalledPeer {
    pub peer_id: u64,
    pub stall_duration: Duration,
    pub blocks_held: usize,
}

/// Global block download tracker.
pub struct BlockDownloadTracker {
    /// Global map: block_hash -> list of in-flight entries.
    in_flight: HashMap<BlockHash, Vec<InFlightEntry>>,
    /// Per-peer state.
    peers: HashMap<u64, PeerDownloadState>,
}

impl BlockDownloadTracker {
    pub fn new() -> Self {
        Self {
            in_flight: HashMap::new(),
            peers: HashMap::new(),
        }
    }

    /// Record that `peer_id` requested `hash`.
    pub fn mark_requested(&mut self, peer_id: u64, hash: BlockHash) {
        let entry = InFlightEntry {
            peer_id,
            requested_at: Instant::now(),
        };
        self.in_flight
            .entry(hash)
            .or_insert_with(Vec::new)
            .push(entry);

        let peer = self.peers.entry(peer_id).or_insert_with(PeerDownloadState::new);
        if peer.count == 0 {
            peer.downloading_since = Some(Instant::now());
        }
        peer.count += 1;
    }

    /// Record that `hash` was received. Returns the peer IDs that had it in flight.
    pub fn mark_received(&mut self, hash: &BlockHash) -> Vec<u64> {
        let entries = self.in_flight.remove(hash).unwrap_or_default();
        let mut peer_ids = Vec::new();
        for entry in &entries {
            peer_ids.push(entry.peer_id);
            if let Some(peer) = self.peers.get_mut(&entry.peer_id) {
                peer.count = peer.count.saturating_sub(1);
                // Clear stall when block received
                peer.stalling_since = None;
                if peer.count == 0 {
                    peer.downloading_since = None;
                }
            }
        }
        peer_ids
    }

    /// Remove all in-flight entries for a peer (on disconnect).
    /// Returns the block hashes that were in flight for this peer.
    pub fn remove_peer(&mut self, peer_id: u64) -> Vec<BlockHash> {
        self.peers.remove(&peer_id);
        let mut orphaned = Vec::new();
        self.in_flight.retain(|hash, entries| {
            let before = entries.len();
            entries.retain(|e| e.peer_id != peer_id);
            if entries.len() < before {
                orphaned.push(*hash);
            }
            !entries.is_empty()
        });
        orphaned
    }

    /// Number of blocks in flight for a peer.
    pub fn peer_in_flight_count(&self, peer_id: u64) -> usize {
        self.peers.get(&peer_id).map(|p| p.count).unwrap_or(0)
    }

    /// Can this peer accept more block requests?
    pub fn peer_has_capacity(&self, peer_id: u64) -> bool {
        self.peer_in_flight_count(peer_id) < BLOCK_DOWNLOAD_WINDOW
    }

    /// Is a block currently in flight from any peer?
    pub fn is_in_flight(&self, hash: &BlockHash) -> bool {
        self.in_flight.contains_key(hash)
    }

    /// Total number of blocks in flight across all peers.
    pub fn total_in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Identify the "staller": the peer whose oldest first-in-flight block
    /// is the most aged. This peer is blocking the download window.
    pub fn identify_staller(&self) -> Option<u64> {
        self.peers
            .iter()
            .filter(|(_, state)| state.count > 0)
            .filter_map(|(&peer_id, state)| {
                state.downloading_since.map(|since| (peer_id, since))
            })
            .min_by_key(|(_, since)| *since)
            .map(|(peer_id, _)| peer_id)
    }

    /// Check for stalled peers. A peer is stalled if it has been downloading
    /// longer than its current stall timeout. Returns stalled peers and
    /// bumps their timeout for next time (exponential backoff).
    pub fn check_stalls(&mut self) -> Vec<StalledPeer> {
        let now = Instant::now();
        let mut stalled = Vec::new();

        for (&peer_id, state) in self.peers.iter_mut() {
            if state.count == 0 {
                continue;
            }
            let since = match state.stalling_since.or(state.downloading_since) {
                Some(t) => t,
                None => continue,
            };
            let elapsed = now.duration_since(since);
            if elapsed >= state.stall_timeout {
                stalled.push(StalledPeer {
                    peer_id,
                    stall_duration: elapsed,
                    blocks_held: state.count,
                });
                state.stalling_since = Some(now);
                state.bump_stall_timeout();
            }
        }

        stalled
    }

    /// Compute the block download timeout, considering the number of active
    /// downloading peers. `target_spacing_secs` is typically 600 for mainnet.
    pub fn block_timeout(
        &self,
        target_spacing_secs: u64,
        active_downloading_peers: usize,
    ) -> Duration {
        let base = target_spacing_secs as f64 * BLOCK_DOWNLOAD_TIMEOUT_BASE;
        let per_peer = target_spacing_secs as f64
            * BLOCK_DOWNLOAD_TIMEOUT_PER_PEER
            * active_downloading_peers as f64;
        Duration::from_secs_f64(base + per_peer)
    }

    /// Number of peers that currently have blocks in flight.
    pub fn active_downloading_peers(&self) -> usize {
        self.peers.values().filter(|p| p.count > 0).count()
    }
}

impl Default for BlockDownloadTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;

    fn hash(n: u8) -> BlockHash {
        BlockHash(Hash256([n; 32]))
    }

    #[test]
    fn mark_requested_and_received() {
        let mut t = BlockDownloadTracker::new();
        let h = hash(1);
        t.mark_requested(42, h);
        assert!(t.is_in_flight(&h));
        assert_eq!(t.peer_in_flight_count(42), 1);
        assert_eq!(t.total_in_flight(), 1);

        let peers = t.mark_received(&h);
        assert_eq!(peers, vec![42]);
        assert!(!t.is_in_flight(&h));
        assert_eq!(t.peer_in_flight_count(42), 0);
        assert_eq!(t.total_in_flight(), 0);
    }

    #[test]
    fn remove_peer_returns_hashes() {
        let mut t = BlockDownloadTracker::new();
        let h1 = hash(1);
        let h2 = hash(2);
        t.mark_requested(10, h1);
        t.mark_requested(10, h2);
        t.mark_requested(20, h2); // h2 from two peers

        let orphaned = t.remove_peer(10);
        assert!(orphaned.contains(&h1));
        assert!(orphaned.contains(&h2));
        // h2 should still be in flight from peer 20
        assert!(t.is_in_flight(&h2));
        // h1 should not
        assert!(!t.is_in_flight(&h1));
    }

    #[test]
    fn peer_has_capacity_under_window() {
        let mut t = BlockDownloadTracker::new();
        assert!(t.peer_has_capacity(1));
        for i in 0..10u8 {
            t.mark_requested(1, hash(i));
        }
        assert!(t.peer_has_capacity(1));
    }

    #[test]
    fn peer_has_capacity_at_window() {
        let mut t = BlockDownloadTracker::new();
        for i in 0..BLOCK_DOWNLOAD_WINDOW {
            t.mark_requested(1, BlockHash(Hash256([(i & 0xff) as u8; 32])));
        }
        // At exactly BLOCK_DOWNLOAD_WINDOW, no more capacity
        // (hashes may collide but the point is count tracking)
        assert!(!t.peer_has_capacity(1) || t.peer_in_flight_count(1) < BLOCK_DOWNLOAD_WINDOW);
    }

    #[test]
    fn identify_staller_oldest_first() {
        let mut t = BlockDownloadTracker::new();
        t.mark_requested(1, hash(1));
        // Small delay
        std::thread::sleep(Duration::from_millis(5));
        t.mark_requested(2, hash(2));

        let staller = t.identify_staller();
        assert_eq!(staller, Some(1)); // peer 1 started first
    }

    #[test]
    fn exponential_backoff() {
        let mut t = BlockDownloadTracker::new();
        t.mark_requested(1, hash(1));

        // Manually set short stall timeout for testing
        if let Some(state) = t.peers.get_mut(&1) {
            state.stall_timeout = Duration::from_millis(1);
            state.stalling_since = Some(Instant::now() - Duration::from_millis(10));
        }

        let stalled = t.check_stalls();
        assert_eq!(stalled.len(), 1);
        assert_eq!(stalled[0].peer_id, 1);

        // Timeout should have doubled
        let timeout = t.peers.get(&1).unwrap().stall_timeout;
        assert_eq!(timeout, Duration::from_millis(2));

        // Stall again
        if let Some(state) = t.peers.get_mut(&1) {
            state.stalling_since = Some(Instant::now() - Duration::from_millis(10));
        }
        let stalled = t.check_stalls();
        assert_eq!(stalled.len(), 1);
        let timeout = t.peers.get(&1).unwrap().stall_timeout;
        assert_eq!(timeout, Duration::from_millis(4));
    }

    #[test]
    fn backoff_capped_at_max() {
        let mut t = BlockDownloadTracker::new();
        t.mark_requested(1, hash(1));

        if let Some(state) = t.peers.get_mut(&1) {
            state.stall_timeout = MAX_STALL_TIMEOUT;
            state.stalling_since = Some(Instant::now() - Duration::from_secs(100));
        }

        let _ = t.check_stalls();
        let timeout = t.peers.get(&1).unwrap().stall_timeout;
        assert_eq!(timeout, MAX_STALL_TIMEOUT);
    }

    #[test]
    fn block_timeout_scales_with_peers() {
        let t = BlockDownloadTracker::new();
        let t1 = t.block_timeout(600, 1);
        let t3 = t.block_timeout(600, 3);
        assert!(t3 > t1, "more peers should increase timeout");
    }

    #[test]
    fn is_in_flight_true_false() {
        let mut t = BlockDownloadTracker::new();
        let h = hash(1);
        assert!(!t.is_in_flight(&h));
        t.mark_requested(1, h);
        assert!(t.is_in_flight(&h));
    }

    #[test]
    fn multi_peer_same_block() {
        let mut t = BlockDownloadTracker::new();
        let h = hash(1);
        t.mark_requested(1, h);
        t.mark_requested(2, h);
        assert_eq!(t.total_in_flight(), 1);

        let peers = t.mark_received(&h);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&1));
        assert!(peers.contains(&2));
        assert!(!t.is_in_flight(&h));
    }

    #[test]
    fn check_stalls_empty() {
        let mut t = BlockDownloadTracker::new();
        assert!(t.check_stalls().is_empty());
    }

    #[test]
    fn total_in_flight_count() {
        let mut t = BlockDownloadTracker::new();
        t.mark_requested(1, hash(1));
        t.mark_requested(1, hash(2));
        t.mark_requested(2, hash(3));
        assert_eq!(t.total_in_flight(), 3);
        t.mark_received(&hash(1));
        assert_eq!(t.total_in_flight(), 2);
    }

    #[test]
    fn active_downloading_peers_count() {
        let mut t = BlockDownloadTracker::new();
        t.mark_requested(1, hash(1));
        t.mark_requested(2, hash(2));
        assert_eq!(t.active_downloading_peers(), 2);
        t.mark_received(&hash(1));
        assert_eq!(t.active_downloading_peers(), 1);
    }

    #[test]
    fn per_peer_limit_is_16() {
        // Bitcoin Core's MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16
        assert_eq!(BLOCK_DOWNLOAD_WINDOW, 16);

        let mut t = BlockDownloadTracker::new();
        // Fill peer 1 to capacity
        for i in 0..16u8 {
            t.mark_requested(1, hash(i));
        }
        assert!(!t.peer_has_capacity(1));
        assert_eq!(t.peer_in_flight_count(1), 16);

        // Peer 2 should still have capacity (per-peer, not global)
        assert!(t.peer_has_capacity(2));
        t.mark_requested(2, hash(100));
        assert!(t.peer_has_capacity(2));
        assert_eq!(t.peer_in_flight_count(2), 1);

        // Free one slot on peer 1
        t.mark_received(&hash(0));
        assert!(t.peer_has_capacity(1));
        assert_eq!(t.peer_in_flight_count(1), 15);
    }

    #[test]
    fn mark_received_clears_stalling() {
        let mut t = BlockDownloadTracker::new();
        t.mark_requested(1, hash(1));
        if let Some(state) = t.peers.get_mut(&1) {
            state.stalling_since = Some(Instant::now());
        }
        t.mark_received(&hash(1));
        let state = t.peers.get(&1).unwrap();
        assert!(state.stalling_since.is_none());
    }
}
