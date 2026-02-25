use std::collections::VecDeque;

use rbtc_primitives::{block::BlockHeader, hash::BlockHash};
use tracing::{debug, info};

/// State machine for Initial Block Download
pub struct IbdState {
    /// Headers we have downloaded but not yet validated/downloaded blocks for
    #[allow(dead_code)]
    pub pending_headers: VecDeque<BlockHeader>,
    /// Block hashes we've requested but not received
    #[allow(dead_code)]
    pub inflight: VecDeque<BlockHash>,
    /// Maximum number of in-flight block requests per peer
    #[allow(dead_code)]
    pub max_inflight: usize,
    /// Current IBD phase
    pub phase: IbdPhase,
    /// Peer we're downloading from
    pub sync_peer: Option<u64>,
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
            pending_headers: VecDeque::new(),
            inflight: VecDeque::new(),
            max_inflight: 128,
            phase: IbdPhase::Headers,
            sync_peer: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.phase == IbdPhase::Complete
    }

    #[allow(dead_code)]
    pub fn add_headers(&mut self, headers: Vec<BlockHeader>) {
        let count = headers.len();
        self.pending_headers.extend(headers);
        debug!("IBD: received {count} headers, pending={}", self.pending_headers.len());
    }

    /// Take up to `n` block hashes from pending headers to request
    #[allow(dead_code)]
    pub fn take_block_requests(&mut self, _n: usize) -> Vec<BlockHash> {
        Vec::new()
    }

    pub fn mark_complete(&mut self) {
        self.phase = IbdPhase::Complete;
        info!("IBD complete");
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
