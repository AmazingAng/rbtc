//! Pre-derived key pool for address generation.
//!
//! Mirrors Bitcoin Core's `CKeyPool` / `DEFAULT_KEYPOOL_SIZE` (1000).
//! Maintains separate internal (change) and external (receive) pools.

use std::collections::VecDeque;

use crate::address::AddressType;

/// Default keypool size matching Bitcoin Core's `DEFAULT_KEYPOOL_SIZE`.
pub const DEFAULT_KEYPOOL_SIZE: usize = 1000;

/// A single pre-derived key entry in the pool.
#[derive(Debug, Clone)]
pub struct KeyPoolEntry {
    /// The derived address string.
    pub address: String,
    /// Address type used for derivation.
    pub addr_type: AddressType,
    /// BIP32 derivation index within the chain.
    pub index: u32,
    /// Whether this is an internal (change) key.
    pub internal: bool,
}

/// Pre-derived key pool with separate internal and external queues.
///
/// Keys are reserved (popped from front) on use and can be returned
/// (pushed to front) if the operation that reserved them is cancelled.
pub struct KeyPool {
    /// External (receive) keys — BIP44 chain 0.
    external: VecDeque<KeyPoolEntry>,
    /// Internal (change) keys — BIP44 chain 1.
    internal: VecDeque<KeyPoolEntry>,
    /// Target pool size per chain.
    target_size: usize,
    /// Next derivation index for the external chain (per addr_type key).
    next_external_index: u32,
    /// Next derivation index for the internal chain (per addr_type key).
    next_internal_index: u32,
}

impl KeyPool {
    /// Create a new empty keypool with the given target size.
    pub fn new(target_size: usize) -> Self {
        Self {
            external: VecDeque::new(),
            internal: VecDeque::new(),
            target_size,
            next_external_index: 0,
            next_internal_index: 0,
        }
    }

    /// Create a keypool with the default size (1000).
    pub fn with_default_size() -> Self {
        Self::new(DEFAULT_KEYPOOL_SIZE)
    }

    /// Set the target pool size.
    pub fn set_target_size(&mut self, size: usize) {
        self.target_size = size;
    }

    /// Return the target pool size.
    pub fn target_size(&self) -> usize {
        self.target_size
    }

    /// Number of available keys in the external (receive) pool.
    pub fn external_size(&self) -> usize {
        self.external.len()
    }

    /// Number of available keys in the internal (change) pool.
    pub fn internal_size(&self) -> usize {
        self.internal.len()
    }

    /// Total number of available keys across both pools.
    pub fn keypool_size(&self) -> usize {
        self.external.len() + self.internal.len()
    }

    /// Top up the pool by calling `derive_fn` for each key that needs
    /// to be pre-derived. The closure receives `(internal, index)` and
    /// must return `Ok(KeyPoolEntry)` or an error string.
    ///
    /// Returns the number of keys added.
    pub fn top_up<F>(&mut self, addr_type: AddressType, mut derive_fn: F) -> Result<usize, String>
    where
        F: FnMut(bool, u32) -> Result<KeyPoolEntry, String>,
    {
        let mut added = 0;

        // Top up external pool
        while self.external.len() < self.target_size {
            let idx = self.next_external_index;
            let entry = derive_fn(false, idx)?;
            debug_assert_eq!(entry.addr_type, addr_type);
            debug_assert!(!entry.internal);
            self.external.push_back(entry);
            self.next_external_index = idx + 1;
            added += 1;
        }

        // Top up internal pool
        while self.internal.len() < self.target_size {
            let idx = self.next_internal_index;
            let entry = derive_fn(true, idx)?;
            debug_assert_eq!(entry.addr_type, addr_type);
            debug_assert!(entry.internal);
            self.internal.push_back(entry);
            self.next_internal_index = idx + 1;
            added += 1;
        }

        Ok(added)
    }

    /// Reserve (pop) the next key from the external or internal pool.
    /// Returns `None` if the requested pool is empty — call `top_up` first.
    pub fn reserve_key(&mut self, internal: bool) -> Option<KeyPoolEntry> {
        if internal {
            self.internal.pop_front()
        } else {
            self.external.pop_front()
        }
    }

    /// Return a previously reserved key to the front of its pool.
    /// Used when the operation that reserved the key is cancelled.
    pub fn return_key(&mut self, entry: KeyPoolEntry) {
        if entry.internal {
            self.internal.push_front(entry);
        } else {
            self.external.push_front(entry);
        }
    }

    /// Append a key to the back of the appropriate pool.
    /// Unlike `return_key` (which pushes to front), this preserves
    /// FIFO order for newly derived keys.
    pub fn append_key(&mut self, entry: KeyPoolEntry) {
        if entry.internal {
            self.internal.push_back(entry);
        } else {
            self.external.push_back(entry);
        }
    }

    /// Set the starting derivation index for the external chain.
    /// Used when loading wallet state from disk.
    pub fn set_next_external_index(&mut self, index: u32) {
        self.next_external_index = index;
    }

    /// Set the starting derivation index for the internal chain.
    pub fn set_next_internal_index(&mut self, index: u32) {
        self.next_internal_index = index;
    }

    /// Get the next derivation index for the external chain.
    pub fn next_external_index(&self) -> u32 {
        self.next_external_index
    }

    /// Get the next derivation index for the internal chain.
    pub fn next_internal_index(&self) -> u32 {
        self.next_internal_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(addr_type: AddressType, internal: bool, index: u32) -> KeyPoolEntry {
        KeyPoolEntry {
            address: format!("addr_{}_{}", if internal { "int" } else { "ext" }, index),
            addr_type,
            index,
            internal,
        }
    }

    #[test]
    fn default_size_is_1000() {
        let pool = KeyPool::with_default_size();
        assert_eq!(pool.target_size(), DEFAULT_KEYPOOL_SIZE);
        assert_eq!(pool.keypool_size(), 0);
    }

    #[test]
    fn top_up_fills_both_pools() {
        let mut pool = KeyPool::new(5);
        let added = pool
            .top_up(AddressType::SegWit, |internal, idx| {
                Ok(make_entry(AddressType::SegWit, internal, idx))
            })
            .unwrap();
        assert_eq!(added, 10); // 5 external + 5 internal
        assert_eq!(pool.external_size(), 5);
        assert_eq!(pool.internal_size(), 5);
        assert_eq!(pool.keypool_size(), 10);
    }

    #[test]
    fn reserve_key_pops_from_front() {
        let mut pool = KeyPool::new(3);
        pool.top_up(AddressType::SegWit, |internal, idx| {
            Ok(make_entry(AddressType::SegWit, internal, idx))
        })
        .unwrap();

        let ext = pool.reserve_key(false).unwrap();
        assert_eq!(ext.index, 0);
        assert!(!ext.internal);
        assert_eq!(pool.external_size(), 2);

        let int = pool.reserve_key(true).unwrap();
        assert_eq!(int.index, 0);
        assert!(int.internal);
        assert_eq!(pool.internal_size(), 2);
    }

    #[test]
    fn reserve_empty_returns_none() {
        let mut pool = KeyPool::new(0);
        assert!(pool.reserve_key(false).is_none());
        assert!(pool.reserve_key(true).is_none());
    }

    #[test]
    fn return_key_pushes_to_front() {
        let mut pool = KeyPool::new(2);
        pool.top_up(AddressType::SegWit, |internal, idx| {
            Ok(make_entry(AddressType::SegWit, internal, idx))
        })
        .unwrap();

        // Reserve index 0, then return it
        let entry = pool.reserve_key(false).unwrap();
        assert_eq!(entry.index, 0);
        assert_eq!(pool.external_size(), 1);

        pool.return_key(entry);
        assert_eq!(pool.external_size(), 2);

        // Next reserve should get index 0 again (returned to front)
        let entry = pool.reserve_key(false).unwrap();
        assert_eq!(entry.index, 0);
    }

    #[test]
    fn top_up_is_idempotent_when_full() {
        let mut pool = KeyPool::new(3);
        pool.top_up(AddressType::SegWit, |internal, idx| {
            Ok(make_entry(AddressType::SegWit, internal, idx))
        })
        .unwrap();

        // Second top_up should add 0 keys
        let added = pool
            .top_up(AddressType::SegWit, |internal, idx| {
                Ok(make_entry(AddressType::SegWit, internal, idx))
            })
            .unwrap();
        assert_eq!(added, 0);
    }

    #[test]
    fn top_up_after_reserve_refills() {
        let mut pool = KeyPool::new(3);
        pool.top_up(AddressType::SegWit, |internal, idx| {
            Ok(make_entry(AddressType::SegWit, internal, idx))
        })
        .unwrap();

        // Reserve 2 external keys
        pool.reserve_key(false);
        pool.reserve_key(false);
        assert_eq!(pool.external_size(), 1);

        // Top up should add 2 more
        let added = pool
            .top_up(AddressType::SegWit, |internal, idx| {
                Ok(make_entry(AddressType::SegWit, internal, idx))
            })
            .unwrap();
        assert_eq!(added, 2);
        assert_eq!(pool.external_size(), 3);

        // The new keys should have indices 3, 4 (continuing from where we left off)
        // Skip index 2 (still in pool), get 3 and 4
        pool.reserve_key(false); // index 2
        let e = pool.reserve_key(false).unwrap();
        assert_eq!(e.index, 3);
        let e = pool.reserve_key(false).unwrap();
        assert_eq!(e.index, 4);
    }

    #[test]
    fn set_target_size() {
        let mut pool = KeyPool::new(5);
        pool.set_target_size(10);
        assert_eq!(pool.target_size(), 10);
    }

    #[test]
    fn next_index_tracking() {
        let mut pool = KeyPool::new(3);
        assert_eq!(pool.next_external_index(), 0);
        assert_eq!(pool.next_internal_index(), 0);

        pool.top_up(AddressType::SegWit, |internal, idx| {
            Ok(make_entry(AddressType::SegWit, internal, idx))
        })
        .unwrap();

        assert_eq!(pool.next_external_index(), 3);
        assert_eq!(pool.next_internal_index(), 3);
    }

    #[test]
    fn set_starting_indices() {
        let mut pool = KeyPool::new(2);
        pool.set_next_external_index(100);
        pool.set_next_internal_index(50);

        pool.top_up(AddressType::SegWit, |internal, idx| {
            Ok(make_entry(AddressType::SegWit, internal, idx))
        })
        .unwrap();

        let ext = pool.reserve_key(false).unwrap();
        assert_eq!(ext.index, 100);
        let int = pool.reserve_key(true).unwrap();
        assert_eq!(int.index, 50);
    }
}
