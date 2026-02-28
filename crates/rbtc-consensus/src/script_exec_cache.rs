use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const DEFAULT_SCRIPT_CACHE_CAPACITY: usize = 100_000;

struct ScriptExecCache {
    entries: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl ScriptExecCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn contains(&self, key: u64) -> bool {
        self.entries.contains(&key)
    }

    fn insert(&mut self, key: u64) -> (bool, bool) {
        if !self.entries.insert(key) {
            return (false, false);
        }
        self.order.push_back(key);
        let mut evicted = false;
        if self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
                evicted = true;
            }
        }
        (true, evicted)
    }
}

static SCRIPT_EXEC_CACHE: OnceLock<Option<Mutex<ScriptExecCache>>> = OnceLock::new();
static SCRIPT_CACHE_LOOKUPS: AtomicU64 = AtomicU64::new(0);
static SCRIPT_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static SCRIPT_CACHE_INSERTS: AtomicU64 = AtomicU64::new(0);
static SCRIPT_CACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct ScriptCacheMetrics {
    pub lookups: u64,
    pub hits: u64,
    pub inserts: u64,
    pub evictions: u64,
}

fn script_exec_cache() -> Option<&'static Mutex<ScriptExecCache>> {
    SCRIPT_EXEC_CACHE
        .get_or_init(|| {
            let cap = std::env::var("RBTC_SCRIPT_CACHE_SIZE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_SCRIPT_CACHE_CAPACITY);
            if cap == 0 {
                None
            } else {
                Some(Mutex::new(ScriptExecCache::new(cap)))
            }
        })
        .as_ref()
}

pub fn make_script_exec_key(
    txid: &[u8; 32],
    input_index: usize,
    flags_mask: u16,
    prevout_value: u64,
    prevout_spk: &[u8],
    script_sig: &[u8],
    witness: &[Vec<u8>],
) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    txid.hash(&mut hasher);
    input_index.hash(&mut hasher);
    flags_mask.hash(&mut hasher);
    prevout_value.hash(&mut hasher);
    prevout_spk.hash(&mut hasher);
    script_sig.hash(&mut hasher);
    witness.len().hash(&mut hasher);
    for item in witness {
        item.hash(&mut hasher);
    }
    hasher.finish()
}

pub fn cache_contains(key: u64) -> bool {
    SCRIPT_CACHE_LOOKUPS.fetch_add(1, Ordering::Relaxed);
    let Some(cache) = script_exec_cache() else {
        return false;
    };
    match cache.lock() {
        Ok(cache) => {
            let hit = cache.contains(key);
            if hit {
                SCRIPT_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            }
            hit
        }
        Err(_) => false,
    }
}

pub fn cache_insert(key: u64) {
    let Some(cache) = script_exec_cache() else {
        return;
    };
    if let Ok(mut cache) = cache.lock() {
        let (inserted, evicted) = cache.insert(key);
        if inserted {
            SCRIPT_CACHE_INSERTS.fetch_add(1, Ordering::Relaxed);
        }
        if evicted {
            SCRIPT_CACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn metrics_snapshot() -> ScriptCacheMetrics {
    ScriptCacheMetrics {
        lookups: SCRIPT_CACHE_LOOKUPS.load(Ordering::Relaxed),
        hits: SCRIPT_CACHE_HITS.load(Ordering::Relaxed),
        inserts: SCRIPT_CACHE_INSERTS.load(Ordering::Relaxed),
        evictions: SCRIPT_CACHE_EVICTIONS.load(Ordering::Relaxed),
    }
}
