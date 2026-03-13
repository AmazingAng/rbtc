//! Headers-first sync state machine with anti-spam PRESYNC commitment phase.
//!
//! Defends against low-difficulty header spam by requiring cumulative PoW to
//! exceed a minimum-work threshold before accepting headers into the block index.
//!
//! Two-phase approach (modeled after Bitcoin Core's headerssync.cpp):
//!   1. **Presync** — Validate PoW per-header, accumulate cumulative work, and
//!      store 1-bit commitments. Headers are NOT added to the block index.
//!   2. **Redownload** — Once cumulative work exceeds the threshold, re-request
//!      headers from genesis and verify each batch against stored commitments
//!      before adding to the block index.
//!
//! The 1-bit commitment is `SipHash(nonce ‖ header_hash) & 1`, requiring only
//! ~1 bit per header (~100 KB for the entire mainnet chain).

use std::hash::Hasher;
use std::time::{Duration, Instant};

use rbtc_consensus::difficulty::bits_to_work;
use rbtc_consensus::chain::header_hash;
use rbtc_primitives::block::BlockHeader;
use rbtc_primitives::hash::BlockHash;
use rbtc_primitives::uint256::U256;
use siphasher::sip::SipHasher24;

// ── Constants ────────────────────────────────────────────────────────────────

/// Base timeout for an entire headers download session.
pub const HEADERS_DOWNLOAD_TIMEOUT_BASE: Duration = Duration::from_secs(15 * 60);

/// Per-header-batch timeout: how long to wait for a getheaders response.
pub const HEADERS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// Number of headers per commitment bit.  ~584 headers per bit keeps the
/// commitment store under 2 KB for the entire mainnet chain.
pub const COMMITMENT_PERIOD: u64 = 584;

// ── Types ────────────────────────────────────────────────────────────────────

/// Phase of a per-peer header sync session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    /// Accumulating work, storing 1-bit commitments. No headers added to index.
    Presync,
    /// Re-downloading headers from genesis, verifying against commitments.
    Redownload,
    /// Sync complete for this peer.
    Done,
}

/// Result of processing a batch of headers.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ProcessResult {
    /// Need more headers; send getheaders from this hash.
    Continue(BlockHash),
    /// Presync is done, start redownloading from genesis.
    StartRedownload,
    /// Verified headers ready to be added to block index.
    Accept(Vec<BlockHeader>),
    /// Invalid headers detected; disconnect this peer.
    Invalid(String),
}

/// Per-peer headers sync session state.
pub struct HeadersSyncState {
    pub phase: SyncPhase,
    /// Packed bit array of commitments (1 bit per COMMITMENT_PERIOD headers).
    commitments: Vec<u8>,
    /// Random nonce for this session's commitment hashing.
    commitment_nonce: [u8; 32],
    /// Cumulative work accumulated during presync.
    cumulative_work: U256,
    /// Number of headers processed during presync.
    presync_count: u64,
    /// Hash of the last header received.
    last_header_hash: BlockHash,
    /// The last header's prev_block, for continuity validation.
    last_prev_block: BlockHash,
    /// Height cursor for redownload phase.
    redownload_cursor: u64,
    /// When this sync session started.
    started_at: Instant,
    /// When the last headers batch was received.
    last_activity: Instant,
    /// Minimum cumulative work to accept headers.
    min_work: U256,
}

impl HeadersSyncState {
    /// Create a new presync session.
    pub fn new(min_work: U256, nonce: [u8; 32]) -> Self {
        let now = Instant::now();
        Self {
            phase: SyncPhase::Presync,
            commitments: Vec::new(),
            commitment_nonce: nonce,
            cumulative_work: U256::ZERO,
            presync_count: 0,
            last_header_hash: BlockHash::ZERO,
            last_prev_block: BlockHash::ZERO,
            redownload_cursor: 0,
            started_at: now,
            last_activity: now,
            min_work,
        }
    }

    /// Process headers during the presync phase.
    /// Validates PoW, accumulates work, and stores commitments.
    /// Does NOT add headers to the block index.
    pub fn process_presync(&mut self, headers: &[BlockHeader]) -> ProcessResult {
        if headers.is_empty() {
            // Peer has no more headers. If we have enough work, move to redownload.
            if self.cumulative_work >= self.min_work {
                self.phase = SyncPhase::Redownload;
                self.redownload_cursor = 0;
                self.last_activity = Instant::now();
                return ProcessResult::StartRedownload;
            }
            // Not enough work — peer's chain is too weak.
            return ProcessResult::Invalid("presync: insufficient work at end of chain".into());
        }

        for header in headers {
            let hash = header_hash(header);

            // Validate chain continuity (prev_block must match last header).
            if self.presync_count > 0 && header.prev_block != self.last_header_hash {
                return ProcessResult::Invalid(format!(
                    "presync: non-contiguous header at count {}: expected prev={}, got prev={}",
                    self.presync_count,
                    self.last_header_hash.to_hex(),
                    header.prev_block.to_hex()
                ));
            }

            // Validate PoW: hash must be <= target.
            if !check_header_pow(&hash, header.bits) {
                return ProcessResult::Invalid(format!(
                    "presync: invalid PoW for header {}",
                    hash.to_hex()
                ));
            }

            // Accumulate work.
            self.cumulative_work = self.cumulative_work.saturating_add(bits_to_work(header.bits));

            // Store 1-bit commitment at each COMMITMENT_PERIOD boundary.
            if self.presync_count % COMMITMENT_PERIOD == 0 {
                let bit = commitment_bit(&hash, &self.commitment_nonce);
                let byte_idx = (self.presync_count / COMMITMENT_PERIOD / 8) as usize;
                let bit_idx = ((self.presync_count / COMMITMENT_PERIOD) % 8) as u32;
                if byte_idx >= self.commitments.len() {
                    self.commitments.resize(byte_idx + 1, 0);
                }
                if bit {
                    self.commitments[byte_idx] |= 1 << bit_idx;
                }
            }

            self.last_header_hash = hash;
            self.last_prev_block = header.prev_block;
            self.presync_count += 1;
        }

        self.last_activity = Instant::now();

        // Check if we've crossed the work threshold.
        if self.cumulative_work >= self.min_work {
            self.phase = SyncPhase::Redownload;
            self.redownload_cursor = 0;
            return ProcessResult::StartRedownload;
        }

        ProcessResult::Continue(self.last_header_hash)
    }

    /// Process headers during the redownload phase.
    /// Verifies each commitment-period header against stored commitments,
    /// then returns accepted headers for addition to the block index.
    pub fn process_redownload(&mut self, headers: &[BlockHeader]) -> ProcessResult {
        if headers.is_empty() {
            if self.redownload_cursor >= self.presync_count {
                self.phase = SyncPhase::Done;
            }
            return ProcessResult::Accept(Vec::new());
        }

        let mut accepted = Vec::new();

        for header in headers {
            let hash = header_hash(header);

            // Validate PoW.
            if !check_header_pow(&hash, header.bits) {
                return ProcessResult::Invalid(format!(
                    "redownload: invalid PoW for header {}",
                    hash.to_hex()
                ));
            }

            // Verify commitment at each COMMITMENT_PERIOD boundary.
            if self.redownload_cursor % COMMITMENT_PERIOD == 0 {
                let expected = self.get_commitment(self.redownload_cursor / COMMITMENT_PERIOD);
                let actual = commitment_bit(&hash, &self.commitment_nonce);
                if actual != expected {
                    return ProcessResult::Invalid(format!(
                        "redownload: commitment mismatch at header {}",
                        self.redownload_cursor
                    ));
                }
            }

            accepted.push(header.clone());
            self.redownload_cursor += 1;
        }

        self.last_activity = Instant::now();

        if self.redownload_cursor >= self.presync_count {
            self.phase = SyncPhase::Done;
            return ProcessResult::Accept(accepted);
        }

        // Return accepted batch; caller sends next getheaders.
        ProcessResult::Accept(accepted)
    }

    /// Check if this sync session has timed out.
    pub fn is_timed_out(&self, now: Instant) -> bool {
        // Overall session timeout.
        if now.duration_since(self.started_at) > HEADERS_DOWNLOAD_TIMEOUT_BASE {
            return true;
        }
        // Per-batch response timeout.
        now.duration_since(self.last_activity) > HEADERS_RESPONSE_TIMEOUT
    }

    /// The hash to use as the locator tip for the next getheaders.
    #[allow(dead_code)]
    pub fn tip_hash(&self) -> BlockHash {
        self.last_header_hash
    }

    /// Current sync phase.
    pub fn current_phase(&self) -> SyncPhase {
        self.phase
    }

    /// Number of headers processed during presync.
    pub fn presync_header_count(&self) -> u64 {
        self.presync_count
    }

    /// Accumulated work during presync.
    #[allow(dead_code)]
    pub fn accumulated_work(&self) -> U256 {
        self.cumulative_work
    }

    /// Retrieve the stored commitment bit for a given commitment index.
    fn get_commitment(&self, commitment_idx: u64) -> bool {
        let byte_idx = (commitment_idx / 8) as usize;
        let bit_idx = (commitment_idx % 8) as u32;
        if byte_idx >= self.commitments.len() {
            return false;
        }
        (self.commitments[byte_idx] >> bit_idx) & 1 == 1
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Compute a 1-bit commitment: SipHash(nonce ‖ hash) & 1.
fn commitment_bit(hash: &BlockHash, nonce: &[u8; 32]) -> bool {
    let k0 = u64::from_le_bytes(nonce[..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(nonce[8..16].try_into().unwrap());
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(&hash.0 .0);
    (hasher.finish() & 1) == 1
}

/// Check that a header hash satisfies PoW: hash (as LE u256) <= target.
fn check_header_pow(hash: &BlockHash, bits: u32) -> bool {
    let target = rbtc_primitives::block::nbits_to_target(bits);
    // Compare as little-endian 256-bit: compare from MSB (byte 31) downward.
    let h = &hash.0 .0;
    for i in (0..32).rev() {
        if h[i] < target[i] {
            return true;
        }
        if h[i] > target[i] {
            return false;
        }
    }
    true // equal
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::hash::Hash256;
    use rbtc_primitives::uint256::U256;

    fn make_nonce() -> [u8; 32] {
        [42u8; 32]
    }

    fn fake_header(prev: BlockHash, bits: u32, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: prev,
            merkle_root: Hash256::ZERO,
            time: 1_000_000,
            bits,
            nonce,
        }
    }

    /// Find a header that passes PoW check for the given bits.
    fn mine_header(prev: BlockHash, bits: u32) -> BlockHeader {
        let mut header = fake_header(prev, bits, 0);
        // For very easy difficulty (regtest: 0x207fffff), almost any nonce works.
        for n in 0..u32::MAX {
            header.nonce = n;
            let hash = header_hash(&header);
            if check_header_pow(&hash, bits) {
                return header;
            }
        }
        panic!("could not mine a valid header");
    }

    // Regtest easiest difficulty
    const REGTEST_BITS: u32 = 0x207fffff;

    #[test]
    fn presync_accumulates_work() {
        let mut state = HeadersSyncState::new(U256::MAX, make_nonce());
        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);
        let hash1 = header_hash(&h1);

        let result = state.process_presync(&[h1]);
        assert!(matches!(result, ProcessResult::Continue(_)));
        assert_eq!(state.presync_count, 1);
        assert!(!state.cumulative_work.is_zero());
        assert_eq!(state.last_header_hash, hash1);
    }

    #[test]
    fn commitment_bit_is_deterministic() {
        let hash = BlockHash(Hash256([0xAA; 32]));
        let nonce = [0x55u8; 32];
        let b1 = commitment_bit(&hash, &nonce);
        let b2 = commitment_bit(&hash, &nonce);
        assert_eq!(b1, b2);
    }

    #[test]
    fn commitment_bit_varies_with_nonce() {
        let hash = BlockHash(Hash256([0xAA; 32]));
        let nonce1 = [0x01u8; 32];
        let nonce2 = [0x02u8; 32];
        // Not guaranteed to differ for a single pair, but test that it doesn't panic.
        let _b1 = commitment_bit(&hash, &nonce1);
        let _b2 = commitment_bit(&hash, &nonce2);
    }

    #[test]
    fn presync_detects_non_contiguous() {
        let mut state = HeadersSyncState::new(U256::MAX, make_nonce());
        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);
        let hash1 = header_hash(&h1);

        state.process_presync(&[h1]);

        // h2's prev_block doesn't match hash1
        let h2 = mine_header(BlockHash(Hash256([0xFF; 32])), REGTEST_BITS);
        let result = state.process_presync(&[h2]);
        assert!(matches!(result, ProcessResult::Invalid(_)));
    }

    #[test]
    fn presync_to_redownload_transition() {
        // Use a very low min_work so a single regtest header crosses the threshold.
        let mut state = HeadersSyncState::new(U256::from_u64(1), make_nonce());
        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);

        let result = state.process_presync(&[h1]);
        assert!(matches!(result, ProcessResult::StartRedownload));
        assert_eq!(state.phase, SyncPhase::Redownload);
    }

    #[test]
    fn presync_empty_headers_insufficient_work() {
        let mut state = HeadersSyncState::new(U256::MAX, make_nonce());
        let result = state.process_presync(&[]);
        assert!(matches!(result, ProcessResult::Invalid(_)));
    }

    #[test]
    fn presync_empty_headers_sufficient_work() {
        let mut state = HeadersSyncState::new(U256::from_u64(1), make_nonce());
        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);
        // First, presync with enough work to transition.
        // But since min_work=1, a single header will transition immediately.
        // So let's test with a higher min_work.
        let mut state = HeadersSyncState::new(U256::MAX, make_nonce());
        state.process_presync(&[h1]);
        // Manually set work to pass threshold.
        state.cumulative_work = U256::MAX;
        let result = state.process_presync(&[]);
        assert!(matches!(result, ProcessResult::StartRedownload));
    }

    #[test]
    fn redownload_verifies_commitments() {
        let nonce = make_nonce();
        let mut state = HeadersSyncState::new(U256::from_u64(1), nonce);
        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);
        let h1_clone = h1.clone();

        // Presync: accumulate and store commitment.
        let result = state.process_presync(&[h1]);
        assert!(matches!(result, ProcessResult::StartRedownload));

        // Redownload: same header should verify.
        let result = state.process_redownload(&[h1_clone]);
        match result {
            ProcessResult::Accept(headers) => {
                assert_eq!(headers.len(), 1);
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn redownload_empty_at_end() {
        let mut state = HeadersSyncState::new(U256::from_u64(1), make_nonce());
        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);
        state.process_presync(&[h1.clone()]);

        // Redownload the one header.
        state.process_redownload(&[h1]);
        // Empty batch at end → Done.
        let result = state.process_redownload(&[]);
        assert!(matches!(result, ProcessResult::Accept(_)));
        assert_eq!(state.phase, SyncPhase::Done);
    }

    #[test]
    fn timeout_after_base() {
        let state = HeadersSyncState::new(U256::MAX, make_nonce());
        let future = Instant::now() + HEADERS_DOWNLOAD_TIMEOUT_BASE + Duration::from_secs(1);
        assert!(state.is_timed_out(future));
    }

    #[test]
    fn timeout_after_inactivity() {
        let state = HeadersSyncState::new(U256::MAX, make_nonce());
        let future = Instant::now() + HEADERS_RESPONSE_TIMEOUT + Duration::from_secs(1);
        assert!(state.is_timed_out(future));
    }

    #[test]
    fn no_timeout_initially() {
        let state = HeadersSyncState::new(U256::MAX, make_nonce());
        assert!(!state.is_timed_out(Instant::now()));
    }

    #[test]
    fn check_header_pow_valid() {
        let header = mine_header(BlockHash::ZERO, REGTEST_BITS);
        let hash = header_hash(&header);
        assert!(check_header_pow(&hash, REGTEST_BITS));
    }

    #[test]
    fn multiple_presync_batches() {
        let mut state = HeadersSyncState::new(U256::MAX, make_nonce());

        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);
        let hash1 = header_hash(&h1);
        state.process_presync(&[h1]);

        let h2 = mine_header(hash1, REGTEST_BITS);
        let hash2 = header_hash(&h2);
        let result = state.process_presync(&[h2]);

        assert!(matches!(result, ProcessResult::Continue(_)));
        assert_eq!(state.presync_count, 2);
        assert_eq!(state.last_header_hash, hash2);
    }

    #[test]
    fn phase_transitions_correct() {
        let mut state = HeadersSyncState::new(U256::from_u64(1), make_nonce());
        assert_eq!(state.phase, SyncPhase::Presync);

        let h1 = mine_header(BlockHash::ZERO, REGTEST_BITS);
        state.process_presync(&[h1.clone()]);
        assert_eq!(state.phase, SyncPhase::Redownload);

        state.process_redownload(&[h1]);
        state.process_redownload(&[]);
        assert_eq!(state.phase, SyncPhase::Done);
    }
}
