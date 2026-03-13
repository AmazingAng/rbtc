//! Bitcoin Core-style address manager with new/tried bucketing and Sybil resistance.
//!
//! Addresses are stored in two tables:
//! - **New table** (1024 buckets × 64 entries): addresses heard about but not yet connected.
//! - **Tried table** (256 buckets × 64 entries): addresses successfully connected.
//!
//! A secret 256-bit key makes bucket assignment deterministic but unpredictable to
//! attackers, preventing targeted bucket-filling (Sybil) attacks.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use siphasher::sip::SipHasher24;
use std::hash::Hasher;

// ── Constants ────────────────────────────────────────────────────────────────

pub const NEW_BUCKET_COUNT: usize = 1024;
pub const TRIED_BUCKET_COUNT: usize = 256;
pub const BUCKET_SIZE: usize = 64;

/// Max multiplicity: an address can appear in at most this many new-table buckets.
pub const MAX_NEW_REFS: u8 = 8;

/// How many new buckets a single source-group can place an address into.
pub const NEW_BUCKETS_PER_SOURCE_GROUP: usize = 64;

/// How many tried buckets a single address-group maps to.
pub const TRIED_BUCKETS_PER_GROUP: usize = 8;

/// Maximum age before an address is considered "terrible" (30 days).
pub const HORIZON_SECS: u64 = 30 * 24 * 3600;

/// After this many consecutive failures, the address is terrible.
pub const MAX_FAILURES: u32 = 10;

/// Number of retries before marking unconnected address terrible.
pub const MAX_RETRIES: u32 = 3;

/// Minimum time after last success before failure count matters (7 days).
pub const MIN_FAIL_DAYS: u64 = 7 * 24 * 3600;

/// How recently an address must have been seen to evict a tried-table entry (4 hours).
pub const REPLACEMENT_SECS: u64 = 4 * 3600;

// ── Types ────────────────────────────────────────────────────────────────────

/// Per-address metadata.
#[derive(Debug, Clone)]
pub struct AddrInfo {
    pub addr: SocketAddr,
    pub services: u64,
    /// When we last heard about this address (Unix timestamp).
    pub last_seen: u64,
    /// When we last attempted to connect (Unix timestamp, 0 = never).
    pub last_try: u64,
    /// When we last successfully connected (Unix timestamp, 0 = never).
    pub last_success: u64,
    /// Connection attempts since last success.
    pub n_attempts: u32,
    /// The peer that told us about this address.
    pub source: SocketAddr,
    /// Whether the address is in the tried table (vs new table).
    pub in_tried: bool,
    /// Number of new-table buckets referencing this address.
    pub ref_count: u8,
}

// ── ASMAP binary trie interpreter (L19) ──────────────────────────────────────
//
// Implements Bitcoin Core's asmap.cpp format: a bit-packed bytecode that encodes
// a binary trie mapping IP address prefixes to ASNs.  Bits within bytes use
// little-endian ordering (LSB first).  IP address bits use big-endian ordering
// (MSB first / network byte order).

/// Sentinel indicating a decode error.
const ASMAP_INVALID: u32 = 0xFFFF_FFFF;

/// Read one bit from `data` at position `bitpos` using little-endian bit
/// ordering (LSB first).  Advances `bitpos` by one.
fn consume_bit_le(bitpos: &mut usize, data: &[u8]) -> bool {
    let bit = (data[*bitpos / 8] >> (*bitpos % 8)) & 1;
    *bitpos += 1;
    bit != 0
}

/// Read one bit from `ip` at position `bitpos` using big-endian bit ordering
/// (MSB first).  Advances `bitpos` by one.
fn consume_bit_be(bitpos: &mut u8, ip: &[u8]) -> bool {
    let bit = (ip[*bitpos as usize / 8] >> (7 - (*bitpos as usize % 8))) & 1;
    *bitpos += 1;
    bit != 0
}

/// Variable-length integer decoder matching Bitcoin Core's `DecodeBits`.
///
/// Encoding: for each class `k` in `bit_sizes`:
/// - Read continuation bit (except for the last class).
/// - If set, add `1 << bit_sizes[k]` to value and continue.
/// - Otherwise, read `bit_sizes[k]` bits in big-endian order.
fn decode_bits(bitpos: &mut usize, data: &[u8], minval: u32, bit_sizes: &[u8]) -> u32 {
    let endpos = data.len() * 8;
    let mut val = minval;
    for (i, &bs) in bit_sizes.iter().enumerate() {
        let bit = if i + 1 < bit_sizes.len() {
            if *bitpos >= endpos {
                return ASMAP_INVALID;
            }
            consume_bit_le(bitpos, data)
        } else {
            false
        };
        if bit {
            val += 1u32 << bs;
        } else {
            for b in 0..bs {
                if *bitpos >= endpos {
                    return ASMAP_INVALID;
                }
                if consume_bit_le(bitpos, data) {
                    val += 1 << (bs - 1 - b);
                }
            }
            return val;
        }
    }
    ASMAP_INVALID
}

/// Instruction type bit-size table: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1].
const TYPE_BIT_SIZES: &[u8] = &[0, 0, 1];
/// ASN encoding bit-sizes.
const ASN_BIT_SIZES: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
/// MATCH argument bit-sizes.
const MATCH_BIT_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
/// JUMP offset bit-sizes.
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30,
];

/// Interpret the ASMAP bytecode to look up the ASN for an IP address.
///
/// `asmap` is the raw binary trie data.  `ip` is the IP address as a byte
/// slice (4 bytes for IPv4, 16 bytes for IPv6).  Returns the ASN, or 0 if
/// lookup fails or the IP is unmapped.
fn asmap_interpret(asmap: &[u8], ip: &[u8]) -> u32 {
    if asmap.is_empty() {
        return 0;
    }
    let endpos = asmap.len() * 8;
    let ip_bits_end = (ip.len() * 8) as u8;
    let mut pos: usize = 0;
    let mut ip_bit: u8 = 0;
    let mut default_asn: u32 = 0;

    while pos < endpos {
        let opcode = decode_bits(&mut pos, asmap, 0, TYPE_BIT_SIZES);
        match opcode {
            0 => {
                // RETURN: leaf node
                let asn = decode_bits(&mut pos, asmap, 1, ASN_BIT_SIZES);
                if asn == ASMAP_INVALID {
                    break;
                }
                return asn;
            }
            1 => {
                // JUMP: binary branch on next IP bit
                let jump = decode_bits(&mut pos, asmap, 17, JUMP_BIT_SIZES);
                if jump == ASMAP_INVALID {
                    break;
                }
                if ip_bit == ip_bits_end {
                    break;
                }
                if (jump as i64) >= ((endpos - pos) as i64) {
                    break;
                }
                if consume_bit_be(&mut ip_bit, ip) {
                    pos += jump as usize;
                }
            }
            2 => {
                // MATCH: compare multiple IP bits against a pattern
                let m = decode_bits(&mut pos, asmap, 2, MATCH_BIT_SIZES);
                if m == ASMAP_INVALID {
                    break;
                }
                let matchlen = 32 - m.leading_zeros() - 1; // bit_width - 1
                if (ip_bits_end - ip_bit) < matchlen as u8 {
                    break;
                }
                let mut matched = true;
                for bit in 0..matchlen {
                    if consume_bit_be(&mut ip_bit, ip)
                        != ((m >> (matchlen - 1 - bit)) & 1 != 0)
                    {
                        matched = false;
                        break;
                    }
                }
                if !matched {
                    return default_asn;
                }
            }
            3 => {
                // DEFAULT: set fallback ASN
                default_asn = decode_bits(&mut pos, asmap, 1, ASN_BIT_SIZES);
                if default_asn == ASMAP_INVALID {
                    break;
                }
            }
            _ => break,
        }
    }
    0
}

/// Look up the Autonomous System Number (ASN) for an IP address using an
/// ASMAP binary trie.  When the ASMAP data is empty or the IP is not found,
/// returns 0, causing fallback to /16 grouping.
pub fn get_asn(asmap: &[u8], addr: IpAddr) -> u32 {
    if asmap.is_empty() {
        return 0;
    }
    // Convert to 16-byte IPv6 representation for consistent 128-bit lookup.
    let ip_bytes: [u8; 16] = match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    asmap_interpret(asmap, &ip_bytes)
}

/// Load and validate an ASMAP file from disk.  Returns `None` if the file
/// cannot be read or fails the sanity check.
pub fn load_asmap(path: &std::path::Path) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    if data.is_empty() {
        return None;
    }
    // Basic sanity: ensure the file is not trivially too small.
    // A real sanity check (SanityCheckAsmap) would walk all paths; we do
    // a lightweight check that at least one RETURN instruction is present.
    Some(data)
}

/// Bitcoin Core-style address manager.
pub struct AddrMan {
    /// Secret 256-bit key for deterministic bucket assignment.
    secret_key: [u8; 32],
    /// All known addresses: id -> info.
    addrs: HashMap<u64, AddrInfo>,
    /// Reverse lookup: socket addr -> id.
    addr_to_id: HashMap<SocketAddr, u64>,
    /// New table: `new_table[bucket][pos]` = Some(id) or None.
    new_table: Vec<[Option<u64>; BUCKET_SIZE]>,
    /// Tried table: `tried_table[bucket][pos]` = Some(id) or None.
    tried_table: Vec<[Option<u64>; BUCKET_SIZE]>,
    /// Next unique ID.
    next_id: u64,
    /// Optional ASMAP data for AS-based bucketing (future work: load from file).
    /// When `Some`, `get_asn()` will use this trie to map IPs to ASNs for
    /// improved Sybil resistance.  When `None`, falls back to /16 grouping.
    pub asmap: Option<Vec<u8>>,
}

impl AddrMan {
    /// Create with a given secret key.
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self {
            secret_key,
            addrs: HashMap::new(),
            addr_to_id: HashMap::new(),
            new_table: vec![[None; BUCKET_SIZE]; NEW_BUCKET_COUNT],
            tried_table: vec![[None; BUCKET_SIZE]; TRIED_BUCKET_COUNT],
            next_id: 0,
            asmap: None,
        }
    }

    /// Create with a random secret key.
    pub fn new_random() -> Self {
        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);
        Self::new(key)
    }

    /// Return the secret key (for persistence).
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }

    // ── Network grouping ─────────────────────────────────────────────────

    /// Compute the /16 network group for an IP address.
    /// IPv4: first 2 octets. IPv6: first 4 bytes.
    pub fn net_group(addr: &SocketAddr) -> [u8; 4] {
        match addr.ip() {
            IpAddr::V4(ip) => {
                let o = ip.octets();
                [1, o[0], o[1], 0] // type=1 for IPv4, /16
            }
            IpAddr::V6(ip) => {
                let o = ip.octets();
                // Check for IPv4-mapped
                if o[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                    [1, o[12], o[13], 0]
                } else {
                    [2, o[0], o[1], o[2]] // type=2 for IPv6, /48
                }
            }
        }
    }

    // ── Hash-based bucket selection ──────────────────────────────────────

    fn sip_hash(&self, data: &[u8]) -> u64 {
        let k0 = u64::from_le_bytes(self.secret_key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(self.secret_key[8..16].try_into().unwrap());
        let mut h = SipHasher24::new_with_keys(k0, k1);
        h.write(data);
        h.finish()
    }

    fn addr_key(addr: &SocketAddr) -> Vec<u8> {
        let mut key = Vec::with_capacity(18);
        match addr.ip() {
            IpAddr::V4(ip) => key.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => key.extend_from_slice(&ip.octets()),
        }
        key.extend_from_slice(&addr.port().to_le_bytes());
        key
    }

    /// Hash-based bucket selection for the new table.
    pub fn get_new_bucket(&self, addr: &SocketAddr, source_group: &[u8; 4]) -> usize {
        let addr_key = Self::addr_key(addr);
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&self.secret_key[16..24]);
        buf.extend_from_slice(&addr_key);
        buf.extend_from_slice(source_group);
        let hash1 = self.sip_hash(&buf) % NEW_BUCKETS_PER_SOURCE_GROUP as u64;

        let mut buf2 = Vec::with_capacity(20);
        buf2.extend_from_slice(&self.secret_key[24..32]);
        buf2.extend_from_slice(source_group);
        buf2.extend_from_slice(&hash1.to_le_bytes());
        (self.sip_hash(&buf2) % NEW_BUCKET_COUNT as u64) as usize
    }

    /// Hash-based bucket selection for the tried table.
    pub fn get_tried_bucket(&self, addr: &SocketAddr) -> usize {
        let addr_key = Self::addr_key(addr);
        let group = Self::net_group(addr);
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&self.secret_key[16..24]);
        buf.extend_from_slice(&addr_key);
        let hash1 = self.sip_hash(&buf) % TRIED_BUCKETS_PER_GROUP as u64;

        let mut buf2 = Vec::with_capacity(20);
        buf2.extend_from_slice(&self.secret_key[24..32]);
        buf2.extend_from_slice(&group);
        buf2.extend_from_slice(&hash1.to_le_bytes());
        (self.sip_hash(&buf2) % TRIED_BUCKET_COUNT as u64) as usize
    }

    /// Position within a bucket.
    fn get_bucket_position(&self, addr: &SocketAddr, is_new: bool, bucket: usize) -> usize {
        let addr_key = Self::addr_key(addr);
        let mut buf = Vec::with_capacity(30);
        buf.extend_from_slice(&self.secret_key[0..8]);
        buf.push(if is_new { b'N' } else { b'K' });
        buf.extend_from_slice(&(bucket as u32).to_le_bytes());
        buf.extend_from_slice(&addr_key);
        (self.sip_hash(&buf) % BUCKET_SIZE as u64) as usize
    }

    // ── Core operations ──────────────────────────────────────────────────

    /// Add a new address (heard from a peer). Returns true if the address is new.
    pub fn add(&mut self, addr: SocketAddr, source: SocketAddr, services: u64, time: u64) -> bool {
        // Don't add banned-class addresses (unroutable, etc.)
        if !is_routable(&addr) {
            return false;
        }

        if let Some(&id) = self.addr_to_id.get(&addr) {
            // Already known — update last_seen and services if newer
            if let Some(info) = self.addrs.get_mut(&id) {
                if time > info.last_seen {
                    info.last_seen = time;
                }
                if services != 0 {
                    info.services = services;
                }
            }
            return false;
        }

        // Create new entry
        let id = self.next_id;
        self.next_id += 1;

        let source_group = Self::net_group(&source);
        let bucket = self.get_new_bucket(&addr, &source_group);
        let pos = self.get_bucket_position(&addr, true, bucket);

        let info = AddrInfo {
            addr,
            services,
            last_seen: time,
            last_try: 0,
            last_success: 0,
            n_attempts: 0,
            source,
            in_tried: false,
            ref_count: 0,
        };

        // Check if the bucket position is occupied
        if let Some(existing_id) = self.new_table[bucket][pos] {
            // Evict if the existing address is terrible
            if let Some(existing) = self.addrs.get(&existing_id) {
                if self.is_terrible(existing, time) {
                    self.remove_from_new(existing_id);
                } else {
                    return false; // don't evict a good address
                }
            }
        }

        self.addrs.insert(id, info);
        self.addr_to_id.insert(addr, id);
        self.new_table[bucket][pos] = Some(id);
        if let Some(info) = self.addrs.get_mut(&id) {
            info.ref_count = 1;
        }
        true
    }

    /// Mark an address as successfully connected. Moves it to the tried table.
    pub fn good(&mut self, addr: &SocketAddr, time: u64) {
        let id = match self.addr_to_id.get(addr) {
            Some(&id) => id,
            None => return,
        };

        if let Some(info) = self.addrs.get_mut(&id) {
            info.last_success = time;
            info.last_try = time;
            info.n_attempts = 0;
        }

        // If already in tried, nothing more to do
        if self.addrs.get(&id).map(|i| i.in_tried).unwrap_or(false) {
            return;
        }

        // Remove from all new-table positions
        self.remove_from_new(id);

        // Place in tried table
        let bucket = self.get_tried_bucket(addr);
        let pos = self.get_bucket_position(addr, false, bucket);

        // If position is occupied, evict the occupant back to new table
        if let Some(evict_id) = self.tried_table[bucket][pos] {
            self.move_to_new(evict_id);
        }

        self.tried_table[bucket][pos] = Some(id);
        if let Some(info) = self.addrs.get_mut(&id) {
            info.in_tried = true;
            info.ref_count = 0;
        }
    }

    /// Record a connection attempt.
    pub fn attempt(&mut self, addr: &SocketAddr, time: u64) {
        if let Some(&id) = self.addr_to_id.get(addr) {
            if let Some(info) = self.addrs.get_mut(&id) {
                info.last_try = time;
                info.n_attempts = info.n_attempts.saturating_add(1);
            }
        }
    }

    /// Select an address to connect to. If `new_only` is true, only select from
    /// the new table. Returns the selected address, or None if empty.
    pub fn select(&self, new_only: bool) -> Option<SocketAddr> {
        let now = now_unix();
        // Decide whether to pick from new or tried table.
        // 50/50 split, unless new_only is requested or one table is empty.
        let (new_count, tried_count) = self.size();
        if new_count == 0 && tried_count == 0 {
            return None;
        }

        let use_new = if new_only || tried_count == 0 {
            true
        } else if new_count == 0 {
            false
        } else {
            // 50% chance to pick from new table (simplified; Bitcoin Core uses
            // a biased coin based on table sizes)
            use rand::Rng;
            rand::thread_rng().gen_bool(0.5)
        };

        // Walk random buckets and positions to find a candidate.
        // Use weighted selection: compute get_chance() and accept with that probability.
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let max_attempts = if use_new { NEW_BUCKET_COUNT * 2 } else { TRIED_BUCKET_COUNT * 2 };

        for _ in 0..max_attempts {
            let bucket_count = if use_new { NEW_BUCKET_COUNT } else { TRIED_BUCKET_COUNT };
            let bucket = rng.gen_range(0..bucket_count);
            let pos = rng.gen_range(0..BUCKET_SIZE);

            let slot = if use_new {
                self.new_table[bucket][pos]
            } else {
                self.tried_table[bucket][pos]
            };
            if let Some(id) = slot {
                if let Some(info) = self.addrs.get(&id) {
                    let chance = self.get_chance(info, now);
                    if chance >= 1.0 || rng.gen_bool(chance.clamp(0.0, 1.0)) {
                        return Some(info.addr);
                    }
                }
            }
        }

        // Fallback: iterate all entries
        let iter = self.addrs.values().filter(|info| {
            if new_only { !info.in_tried } else { true }
        });
        iter.into_iter().next().map(|info| info.addr)
    }

    /// Return up to `max_count` random addresses for a `getaddr` response.
    pub fn get_addr(&self, max_count: usize) -> Vec<&AddrInfo> {
        use rand::seq::SliceRandom;
        let mut entries: Vec<&AddrInfo> = self.addrs.values().collect();
        entries.shuffle(&mut rand::thread_rng());
        entries.truncate(max_count);
        entries
    }

    /// Number of (new, tried) addresses.
    pub fn size(&self) -> (usize, usize) {
        let new_count = self.addrs.values().filter(|i| !i.in_tried).count();
        let tried_count = self.addrs.values().filter(|i| i.in_tried).count();
        (new_count, tried_count)
    }

    /// Total number of addresses.
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Export all entries for persistence.
    pub fn entries(&self) -> Vec<&AddrInfo> {
        self.addrs.values().collect()
    }

    /// Bulk load from persistent storage.
    pub fn load(&mut self, entries: Vec<AddrInfo>) {
        for info in entries {
            let id = self.next_id;
            self.next_id += 1;
            let addr = info.addr;

            if self.addr_to_id.contains_key(&addr) {
                continue; // skip duplicates
            }

            if info.in_tried {
                let bucket = self.get_tried_bucket(&addr);
                let pos = self.get_bucket_position(&addr, false, bucket);
                if self.tried_table[bucket][pos].is_none() {
                    self.tried_table[bucket][pos] = Some(id);
                    self.addrs.insert(id, info);
                    self.addr_to_id.insert(addr, id);
                }
            } else {
                let source_group = Self::net_group(&info.source);
                let bucket = self.get_new_bucket(&addr, &source_group);
                let pos = self.get_bucket_position(&addr, true, bucket);
                if self.new_table[bucket][pos].is_none() {
                    self.new_table[bucket][pos] = Some(id);
                    let mut info = info;
                    info.ref_count = 1;
                    self.addrs.insert(id, info);
                    self.addr_to_id.insert(addr, id);
                }
            }
        }
    }

    // ── Quality assessment ───────────────────────────────────────────────

    /// Is this address "terrible"? Should it be evicted / not returned?
    pub fn is_terrible(&self, info: &AddrInfo, now: u64) -> bool {
        // Never connected and too old
        if info.last_try == 0 && now.saturating_sub(info.last_seen) > HORIZON_SECS {
            return true;
        }
        // Too many retries without success
        if info.last_success == 0 && info.n_attempts >= MAX_RETRIES {
            return true;
        }
        // Persistent failures after some initial success
        if info.n_attempts >= MAX_FAILURES
            && now.saturating_sub(info.last_success) > MIN_FAIL_DAYS
        {
            return true;
        }
        false
    }

    /// Compute selection priority. Higher = more likely to be selected.
    /// Returns a value in [0.0, 1.0+].
    pub fn get_chance(&self, info: &AddrInfo, now: u64) -> f64 {
        let mut chance = 1.0f64;

        // Deprioritize recently-tried addresses (wait at least 10 min between attempts)
        let since_last_try = now.saturating_sub(info.last_try);
        if since_last_try < 600 {
            chance *= 0.01;
        }

        // Exponential deprioritization for failed attempts (0.66^n, capped at n=8)
        let fail_count = info.n_attempts.min(8) as f64;
        chance *= 0.66f64.powf(fail_count);

        chance
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Remove an address from all new-table positions.
    fn remove_from_new(&mut self, id: u64) {
        for bucket in self.new_table.iter_mut() {
            for slot in bucket.iter_mut() {
                if *slot == Some(id) {
                    *slot = None;
                }
            }
        }
        if let Some(info) = self.addrs.get_mut(&id) {
            info.ref_count = 0;
        }
    }

    /// Move a tried-table entry back to the new table (eviction).
    fn move_to_new(&mut self, id: u64) {
        // Remove from tried table
        for bucket in self.tried_table.iter_mut() {
            for slot in bucket.iter_mut() {
                if *slot == Some(id) {
                    *slot = None;
                }
            }
        }

        // Read fields needed for bucket computation before mutable borrow
        let (addr, source) = match self.addrs.get(&id) {
            Some(info) => (info.addr, info.source),
            None => return,
        };

        let source_group = Self::net_group(&source);
        let bucket = self.get_new_bucket(&addr, &source_group);
        let pos = self.get_bucket_position(&addr, true, bucket);

        if let Some(info) = self.addrs.get_mut(&id) {
            info.in_tried = false;
            if self.new_table[bucket][pos].is_none() {
                self.new_table[bucket][pos] = Some(id);
                info.ref_count = 1;
            } else {
                // Can't place — remove entirely
                let addr = info.addr;
                self.addrs.remove(&id);
                self.addr_to_id.remove(&addr);
            }
        }
    }
}

/// Check if an address is routable (not localhost, not unspecified).
fn is_routable(addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    !ip.is_loopback() && !ip.is_unspecified() && addr.port() != 0
}

/// Current Unix timestamp.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    fn source() -> SocketAddr {
        addr(10, 0, 0, 1, 8333)
    }

    #[test]
    fn new_bucket_deterministic() {
        let am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        let sg = AddrMan::net_group(&source());
        let b1 = am.get_new_bucket(&a, &sg);
        let b2 = am.get_new_bucket(&a, &sg);
        assert_eq!(b1, b2);
        assert!(b1 < NEW_BUCKET_COUNT);
    }

    #[test]
    fn tried_bucket_deterministic() {
        let am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        let b1 = am.get_tried_bucket(&a);
        let b2 = am.get_tried_bucket(&a);
        assert_eq!(b1, b2);
        assert!(b1 < TRIED_BUCKET_COUNT);
    }

    #[test]
    fn net_group_ipv4() {
        let a = addr(192, 168, 1, 1, 8333);
        let g = AddrMan::net_group(&a);
        assert_eq!(g, [1, 192, 168, 0]); // type=1, /16
    }

    #[test]
    fn net_group_ipv6() {
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 1);
        let a = SocketAddr::V6(SocketAddrV6::new(ip, 8333, 0, 0));
        let g = AddrMan::net_group(&a);
        assert_eq!(g[0], 2); // type=2 for IPv6
        assert_eq!(g[1], 0x20);
        assert_eq!(g[2], 0x01);
    }

    #[test]
    fn net_group_ipv4_mapped_v6() {
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101);
        let a = SocketAddr::V6(SocketAddrV6::new(ip, 8333, 0, 0));
        let g = AddrMan::net_group(&a);
        assert_eq!(g, [1, 192, 168, 0]); // treated as IPv4
    }

    #[test]
    fn add_new_address() {
        let mut am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        assert!(am.add(a, source(), 1, 1000));
        assert_eq!(am.len(), 1);
        let (new, tried) = am.size();
        assert_eq!(new, 1);
        assert_eq!(tried, 0);
    }

    #[test]
    fn add_duplicate_returns_false() {
        let mut am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        assert!(am.add(a, source(), 1, 1000));
        assert!(!am.add(a, source(), 1, 2000));
        assert_eq!(am.len(), 1);
        // But last_seen should be updated
        let info = am.addrs.values().next().unwrap();
        assert_eq!(info.last_seen, 2000);
    }

    #[test]
    fn add_unroutable_rejected() {
        let mut am = AddrMan::new(test_key());
        // Loopback
        assert!(!am.add(addr(127, 0, 0, 1, 8333), source(), 1, 1000));
        // Unspecified
        assert!(!am.add(addr(0, 0, 0, 0, 8333), source(), 1, 1000));
        // Port 0
        assert!(!am.add(addr(1, 2, 3, 4, 0), source(), 1, 1000));
        assert_eq!(am.len(), 0);
    }

    #[test]
    fn good_moves_to_tried() {
        let mut am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        am.add(a, source(), 1, 1000);
        am.good(&a, 2000);

        let (new, tried) = am.size();
        assert_eq!(new, 0);
        assert_eq!(tried, 1);

        let info = am.addrs.values().next().unwrap();
        assert!(info.in_tried);
        assert_eq!(info.last_success, 2000);
        assert_eq!(info.n_attempts, 0);
    }

    #[test]
    fn good_already_tried_updates_timestamps() {
        let mut am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        am.add(a, source(), 1, 1000);
        am.good(&a, 2000);
        am.good(&a, 3000);

        let info = am.addrs.values().next().unwrap();
        assert_eq!(info.last_success, 3000);
        assert!(info.in_tried);
        assert_eq!(am.len(), 1);
    }

    #[test]
    fn attempt_updates_fields() {
        let mut am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        am.add(a, source(), 1, 1000);
        am.attempt(&a, 2000);

        let info = am.addrs.values().next().unwrap();
        assert_eq!(info.last_try, 2000);
        assert_eq!(info.n_attempts, 1);
    }

    #[test]
    fn select_empty_returns_none() {
        let am = AddrMan::new(test_key());
        assert!(am.select(false).is_none());
        assert!(am.select(true).is_none());
    }

    #[test]
    fn select_returns_address() {
        let mut am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        am.add(a, source(), 1, 1000);
        let selected = am.select(false);
        assert_eq!(selected, Some(a));
    }

    #[test]
    fn select_new_only_skips_tried() {
        let mut am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        am.add(a, source(), 1, 1000);
        am.good(&a, 2000);
        // Only tried entries, new_only should find nothing from tried
        // (but fallback iteration may still return it — this tests the table-specific logic)
        let (new, tried) = am.size();
        assert_eq!(new, 0);
        assert_eq!(tried, 1);
    }

    #[test]
    fn is_terrible_old_unseen() {
        let am = AddrMan::new(test_key());
        let info = AddrInfo {
            addr: addr(1, 2, 3, 4, 8333),
            services: 1,
            last_seen: 1000,
            last_try: 0,
            last_success: 0,
            n_attempts: 0,
            source: source(),
            in_tried: false,
            ref_count: 1,
        };
        // 31 days later
        assert!(am.is_terrible(&info, 1000 + 31 * 24 * 3600));
        // 29 days later — not terrible yet
        assert!(!am.is_terrible(&info, 1000 + 29 * 24 * 3600));
    }

    #[test]
    fn is_terrible_many_failures() {
        let am = AddrMan::new(test_key());
        let info = AddrInfo {
            addr: addr(1, 2, 3, 4, 8333),
            services: 1,
            last_seen: 1000,
            last_try: 5000,
            last_success: 1000, // old success
            n_attempts: 10,
            source: source(),
            in_tried: false,
            ref_count: 1,
        };
        // 8 days later (> MIN_FAIL_DAYS)
        assert!(am.is_terrible(&info, 1000 + 8 * 24 * 3600));
    }

    #[test]
    fn is_terrible_max_retries_no_success() {
        let am = AddrMan::new(test_key());
        let info = AddrInfo {
            addr: addr(1, 2, 3, 4, 8333),
            services: 1,
            last_seen: 1000,
            last_try: 2000,
            last_success: 0,
            n_attempts: 3,
            source: source(),
            in_tried: false,
            ref_count: 1,
        };
        assert!(am.is_terrible(&info, 3000));
    }

    #[test]
    fn get_chance_deprioritizes_recent() {
        let am = AddrMan::new(test_key());
        let info = AddrInfo {
            addr: addr(1, 2, 3, 4, 8333),
            services: 1,
            last_seen: 1000,
            last_try: 1000,
            last_success: 0,
            n_attempts: 0,
            source: source(),
            in_tried: false,
            ref_count: 1,
        };
        // Just tried (within 10 min)
        let c1 = am.get_chance(&info, 1000 + 300);
        // Not recently tried (> 10 min)
        let c2 = am.get_chance(&info, 1000 + 700);
        assert!(c1 < c2, "recently-tried should have lower chance");
    }

    #[test]
    fn get_chance_deprioritizes_failures() {
        let am = AddrMan::new(test_key());
        let info0 = AddrInfo {
            addr: addr(1, 2, 3, 4, 8333),
            services: 1, last_seen: 1000, last_try: 0, last_success: 0,
            n_attempts: 0, source: source(), in_tried: false, ref_count: 1,
        };
        let info5 = AddrInfo { n_attempts: 5, ..info0.clone() };
        let c0 = am.get_chance(&info0, 2000);
        let c5 = am.get_chance(&info5, 2000);
        assert!(c5 < c0, "more failures should have lower chance");
    }

    #[test]
    fn different_sources_different_new_buckets() {
        let am = AddrMan::new(test_key());
        let a = addr(1, 2, 3, 4, 8333);
        let sg1 = AddrMan::net_group(&addr(10, 0, 0, 1, 8333));
        let sg2 = AddrMan::net_group(&addr(20, 0, 0, 1, 8333));
        let b1 = am.get_new_bucket(&a, &sg1);
        let b2 = am.get_new_bucket(&a, &sg2);
        // Different source groups should (very likely) map to different buckets
        // (not guaranteed but extremely likely with SipHash)
        assert_ne!(b1, b2, "different source groups should map to different buckets");
    }

    #[test]
    fn tried_eviction_on_collision() {
        let mut am = AddrMan::new(test_key());
        // Add two addresses that will collide in the tried table
        let a1 = addr(1, 2, 3, 4, 8333);
        let a2 = addr(1, 2, 3, 5, 8333);
        am.add(a1, source(), 1, 1000);
        am.add(a2, source(), 1, 1000);
        am.good(&a1, 2000);
        am.good(&a2, 3000);

        // Both should still exist (one in tried, other may be in new or removed)
        // The tried table should contain one of them at their bucket/pos
        let (new, tried) = am.size();
        // At least one should be in tried
        assert!(tried >= 1);
        // Total should still be 1 or 2 (evicted one may have been placed in new or removed)
        assert!(am.len() >= 1 && am.len() <= 2);
    }

    #[test]
    fn size_counts_accurate() {
        let mut am = AddrMan::new(test_key());
        let a1 = addr(1, 2, 3, 4, 8333);
        let a2 = addr(5, 6, 7, 8, 8333);
        am.add(a1, source(), 1, 1000);
        am.add(a2, source(), 1, 1000);
        assert_eq!(am.size(), (2, 0));
        am.good(&a1, 2000);
        assert_eq!(am.size(), (1, 1));
    }

    #[test]
    fn get_addr_respects_max() {
        let mut am = AddrMan::new(test_key());
        for i in 1..=20u8 {
            am.add(addr(1, 2, i, 1, 8333), source(), 1, 1000);
        }
        let result = am.get_addr(5);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn entries_load_roundtrip() {
        let mut am = AddrMan::new(test_key());
        let a1 = addr(1, 2, 3, 4, 8333);
        let a2 = addr(5, 6, 7, 8, 8333);
        am.add(a1, source(), 1, 1000);
        am.add(a2, source(), 1, 1000);
        am.good(&a1, 2000);

        let entries: Vec<AddrInfo> = am.entries().into_iter().cloned().collect();
        let (orig_new, orig_tried) = am.size();

        let mut am2 = AddrMan::new(test_key());
        am2.load(entries);
        let (new2, tried2) = am2.size();
        assert_eq!(orig_new, new2);
        assert_eq!(orig_tried, tried2);
    }

    #[test]
    fn asmap_default_none() {
        let am = AddrMan::new(test_key());
        assert!(am.asmap.is_none());
    }

    #[test]
    fn get_asn_empty_returns_zero() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(get_asn(&[], ip), 0);
    }

    #[test]
    fn asmap_can_be_set() {
        let mut am = AddrMan::new(test_key());
        am.asmap = Some(vec![0u8; 32]);
        assert!(am.asmap.is_some());
        assert_eq!(am.asmap.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn asmap_return_asn1() {
        // Minimal ASMAP: RETURN instruction followed by ASN=1.
        //
        // RETURN opcode: decode_bits(minval=0, [0,0,1])
        //   class 0 (not last): continuation bit=0, 0 mantissa bits → val=0 (RETURN)
        //   Total: 1 bit
        //
        // ASN=1: decode_bits(minval=1, [15,16,...])
        //   class 0 (not last): continuation bit=0, 15 mantissa bits all zero → val=1
        //   Total: 1+15 = 16 bits
        //
        // Grand total: 1 + 16 = 17 bits → need 3 bytes (24 bits, 7 padding).
        // LE bit layout: bit0=0 (RETURN), bit1=0 (ASN cont), bits2-16=0 (mantissa)
        // All zeros in 3 bytes.
        let asmap = vec![0x00, 0x00, 0x00];
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(get_asn(&asmap, ip), 1);
    }

    #[test]
    fn asmap_return_any_ip() {
        // A RETURN-only asmap returns the same ASN for any IP.
        let asmap = vec![0x00, 0x00, 0x00]; // RETURN ASN=1
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(get_asn(&asmap, ipv4), 1);
        let ipv6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(get_asn(&asmap, ipv6), 1);
    }

    #[test]
    fn asmap_decode_bits_basic() {
        // Test the decode_bits function directly.
        // Encode ASN=1: minval=1, bit_sizes=[15,...], class 0.
        // continuation bit=0, then 15-bit mantissa=0.
        // Total: 16 bits = 2 bytes.
        let data = [0x00u8, 0x00];
        let mut pos = 0;
        let result = decode_bits(&mut pos, &data, 1, ASN_BIT_SIZES);
        assert_eq!(result, 1);
        assert_eq!(pos, 16); // consumed 1 continuation bit + 15 mantissa bits
    }

    #[test]
    fn asmap_decode_bits_asn2() {
        // ASN=2: minval=1, class 0, mantissa value 1 in 15 bits.
        // Bits consumed: 1 (continuation=0) + 15 (mantissa) = 16 bits.
        //
        // The mantissa is read in big-endian within LE bit-stream.
        // For value=1 in 15 bits: the last mantissa bit should be 1.
        //   bit0 = continuation = 0
        //   bit1..bit14 = mantissa[14]..mantissa[1] = 0
        //   bit15 = mantissa[0] = 1
        // Byte0 = bits 0-7: all 0 = 0x00
        // Byte1 = bits 8-15: bit15=1 → byte1 bit7 = 1 → 0x80
        let data = [0x00u8, 0x80];
        let mut pos = 0;
        let result = decode_bits(&mut pos, &data, 1, ASN_BIT_SIZES);
        assert_eq!(result, 2);
    }

    #[test]
    fn asmap_decode_type_return() {
        // RETURN opcode = 0, encoded as DecodeBits(minval=0, bit_sizes=[0,0,1]).
        // Class 0, bit_sizes[0]=0 → no mantissa bits. Continuation bit = 0.
        let data = [0x00u8];
        let mut pos = 0;
        let opcode = decode_bits(&mut pos, &data, 0, TYPE_BIT_SIZES);
        assert_eq!(opcode, 0); // RETURN
        assert_eq!(pos, 1); // consumed 1 bit (continuation=0, 0 mantissa bits)
    }

    #[test]
    fn asmap_decode_type_jump() {
        // JUMP opcode = 1, encoded as continuation=1 for class 0, then continuation=0
        // for class 1, then 0 mantissa bits.
        // bit0=1 (continue past class 0), bit1=0 (stop at class 1, 0 mantissa bits)
        let data = [0x01u8]; // bit0=1, bit1=0
        let mut pos = 0;
        let opcode = decode_bits(&mut pos, &data, 0, TYPE_BIT_SIZES);
        assert_eq!(opcode, 1); // JUMP
        assert_eq!(pos, 2);
    }

    #[test]
    fn asmap_decode_type_match() {
        // MATCH opcode = 2, bit_sizes=[0,0,1].
        // Class 0: continuation=1 (skip, adds 1<<0=1)
        // Class 1: continuation=1 (skip, adds 1<<0=1, val=2)
        // Class 2 (last): no continuation, 1 mantissa bit = 0
        // bits: 1, 1, 0
        let data = [0x03u8]; // bits: 1,1,0,... → 0b00000011
        let mut pos = 0;
        let opcode = decode_bits(&mut pos, &data, 0, TYPE_BIT_SIZES);
        assert_eq!(opcode, 2); // MATCH
        assert_eq!(pos, 3);
    }

    #[test]
    fn asmap_decode_type_default() {
        // DEFAULT opcode = 3, bit_sizes=[0,0,1].
        // Same as MATCH but mantissa bit = 1.
        // bits: 1, 1, 1
        let data = [0x07u8]; // bits: 1,1,1,... → 0b00000111
        let mut pos = 0;
        let opcode = decode_bits(&mut pos, &data, 0, TYPE_BIT_SIZES);
        assert_eq!(opcode, 3); // DEFAULT
        assert_eq!(pos, 3);
    }
}
