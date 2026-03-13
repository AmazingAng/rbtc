//! Signature verification cache, modelled after Bitcoin Core's `CSignatureCache`
//! (`src/script/sigcache.h`).
//!
//! Caching avoids redundant ECDSA / Schnorr verification when the same
//! `(signature, pubkey, sighash)` triple is seen more than once (e.g. during
//! block connection after mempool acceptance).
//!
//! This is the **single** signature cache for the entire project.  The script
//! engine (`rbtc-script`) calls verification functions in `rbtc-crypto` which
//! consult this cache transparently.

use crate::digest::sha256d;
use std::collections::HashMap;
use std::sync::RwLock;

/// Default maximum number of entries kept in the cache.
const DEFAULT_MAX_ENTRIES: usize = 32_768;

/// Thread-safe signature-verification cache.
///
/// The cache key is `SHA256d(algo_tag || sig || pubkey || sighash)`, which
/// uniquely identifies a verified signature triple.  Only *successful*
/// verifications should be inserted — the cache never stores failures.
///
/// Uses `RwLock` so that cache lookups (the common path) can proceed in
/// parallel across threads.
pub struct SigCache {
    inner: RwLock<SigCacheInner>,
}

struct SigCacheInner {
    map: HashMap<[u8; 32], ()>,
    max_entries: usize,
}

impl SigCache {
    /// Create a new cache with the default capacity (32 768 entries).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    /// Create a new cache with a custom maximum number of entries.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(SigCacheInner {
                map: HashMap::with_capacity(max_entries.min(1024)),
                max_entries,
            }),
        }
    }

    /// Check whether the given `(sig, pubkey, sighash)` triple has already
    /// been verified.
    pub fn contains(&self, sig: &[u8], pubkey: &[u8], sighash: &[u8]) -> bool {
        let key = Self::cache_key(0, sig, pubkey, sighash);
        let inner = self.inner.read().expect("SigCache lock poisoned");
        inner.map.contains_key(&key)
    }

    /// Record a successful signature verification so that future calls to
    /// [`contains`](Self::contains) with the same triple return `true`.
    ///
    /// If the cache is at capacity, a pseudo-random existing entry is evicted
    /// first (using the new key's bytes to pick the victim, similar to Bitcoin
    /// Core's approach).
    pub fn insert(&self, sig: &[u8], pubkey: &[u8], sighash: &[u8]) {
        let key = Self::cache_key(0, sig, pubkey, sighash);
        self.insert_raw(key);
    }

    /// Check whether the given tagged triple has already been verified.
    /// The `algo_tag` distinguishes ECDSA (0) from Schnorr (1).
    pub(crate) fn contains_tagged(
        &self,
        algo_tag: u8,
        sig: &[u8],
        pubkey: &[u8],
        sighash: &[u8],
    ) -> bool {
        let key = Self::cache_key(algo_tag, sig, pubkey, sighash);
        let inner = self.inner.read().expect("SigCache lock poisoned");
        inner.map.contains_key(&key)
    }

    /// Insert a tagged triple into the cache.
    pub(crate) fn insert_tagged(
        &self,
        algo_tag: u8,
        sig: &[u8],
        pubkey: &[u8],
        sighash: &[u8],
    ) {
        let key = Self::cache_key(algo_tag, sig, pubkey, sighash);
        self.insert_raw(key);
    }

    fn insert_raw(&self, key: [u8; 32]) {
        let mut inner = self.inner.write().expect("SigCache lock poisoned");

        if inner.map.len() >= inner.max_entries {
            // Pseudo-random eviction: derive an index from the new key.
            let idx = eviction_index(&key, inner.map.len());
            if let Some(victim) = inner.map.keys().nth(idx).copied() {
                inner.map.remove(&victim);
            }
        }

        inner.map.insert(key, ());
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) {
        let mut inner = self.inner.write().expect("SigCache lock poisoned");
        inner.map.clear();
    }

    /// Return the current number of cached entries.
    pub fn len(&self) -> usize {
        let inner = self.inner.read().expect("SigCache lock poisoned");
        inner.map.len()
    }

    /// Return `true` when the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ----- private helpers -----

    /// Build the 32-byte cache key: `SHA256d(algo_tag || sig || pubkey || sighash)`.
    fn cache_key(algo_tag: u8, sig: &[u8], pubkey: &[u8], sighash: &[u8]) -> [u8; 32] {
        let mut preimage =
            Vec::with_capacity(1 + sig.len() + pubkey.len() + sighash.len());
        preimage.push(algo_tag);
        preimage.extend_from_slice(sig);
        preimage.extend_from_slice(pubkey);
        preimage.extend_from_slice(sighash);
        sha256d(&preimage).0
    }
}

impl Default for SigCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a deterministic eviction index from the cache key bytes.
fn eviction_index(key: &[u8; 32], len: usize) -> usize {
    // Interpret the first 8 bytes of the key as a little-endian u64 and take
    // modulo the current map length.
    let v = u64::from_le_bytes(key[..8].try_into().unwrap());
    (v as usize) % len
}

// ---------------------------------------------------------------------------
// Global singleton — used by `sig.rs` verification functions.
// ---------------------------------------------------------------------------
use std::sync::OnceLock;

static GLOBAL_SIG_CACHE: OnceLock<SigCache> = OnceLock::new();

/// Return a reference to the process-wide signature cache.
pub fn global_sig_cache() -> &'static SigCache {
    GLOBAL_SIG_CACHE.get_or_init(SigCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_after_insert() {
        let cache = SigCache::new();
        let sig = b"signature_bytes";
        let pubkey = b"pubkey_bytes";
        let sighash = b"sighash_bytes";

        assert!(!cache.contains(sig, pubkey, sighash));
        cache.insert(sig, pubkey, sighash);
        assert!(cache.contains(sig, pubkey, sighash));
    }

    #[test]
    fn cache_miss_for_unknown() {
        let cache = SigCache::new();
        cache.insert(b"sig_a", b"pk_a", b"hash_a");

        // Different triple should not be found.
        assert!(!cache.contains(b"sig_b", b"pk_b", b"hash_b"));
        // Partial overlap should not match either.
        assert!(!cache.contains(b"sig_a", b"pk_a", b"hash_b"));
    }

    #[test]
    fn capacity_eviction() {
        let max = 64;
        let cache = SigCache::with_capacity(max);

        // Insert twice the capacity.
        for i in 0..(max * 2) {
            let data = i.to_le_bytes();
            cache.insert(&data, &data, &data);
        }

        // The cache must never exceed its configured maximum.
        assert!(
            cache.len() <= max,
            "cache size {} exceeds max {}",
            cache.len(),
            max,
        );
    }

    #[test]
    fn clear_empties_cache() {
        let cache = SigCache::new();
        cache.insert(b"s", b"p", b"h");
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn tagged_ecdsa_vs_schnorr_distinct() {
        let cache = SigCache::new();
        let sig = b"some_sig";
        let pk = b"some_pk";
        let hash = b"some_hash________________________"; // 32 bytes

        cache.insert_tagged(0, sig, pk, hash);
        // Same bytes with different algo tag should NOT be found.
        assert!(!cache.contains_tagged(1, sig, pk, hash));
        // Same algo tag should be found.
        assert!(cache.contains_tagged(0, sig, pk, hash));
    }

    #[test]
    fn global_cache_is_shared() {
        let c1 = global_sig_cache();
        let c2 = global_sig_cache();
        // Both references should point to the same instance.
        assert!(std::ptr::eq(c1, c2));
    }
}
