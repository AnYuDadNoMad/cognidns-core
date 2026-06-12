//! Lock-free Count-Min Sketch for DNS query popularity tracking.
//!
//! Used by the resolver to estimate query frequency without holding a Mutex.
//! Over-counts slightly (false positives) but never under-counts.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::cache::CacheKey;

/// Lock-free Count-Min Sketch for popularity tracking.
/// Replaces `Mutex<HashMap<CacheKey, u32>>` — eliminates one Mutex acquisition
/// on every cache hit. Over-counts slightly (false positives) but never under-counts.
pub(super) struct PopularitySketch {
    counters: Vec<AtomicU32>,
    width: usize,
    depth: usize,
}

impl PopularitySketch {
    pub(super) fn new(width: usize, depth: usize) -> Self {
        let total = width * depth;
        let mut counters = Vec::with_capacity(total);
        for _ in 0..total {
            counters.push(AtomicU32::new(0));
        }
        Self {
            counters,
            width,
            depth,
        }
    }

    pub(super) fn increment(&self, key: &CacheKey) {
        let (h1, h2) = Self::hash_pair(key);
        for row in 0..self.depth {
            let idx = (h1.wrapping_add(row.wrapping_mul(h2))) % self.width + row * self.width;
            let prev = self.counters[idx].fetch_add(1, Ordering::Relaxed);
            // Cap at u32::MAX to prevent overflow in edge cases.
            if prev == u32::MAX {
                self.counters[idx].store(u32::MAX, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn estimate(&self, key: &CacheKey) -> u32 {
        let (h1, h2) = Self::hash_pair(key);
        let mut min = u32::MAX;
        for row in 0..self.depth {
            let idx = (h1.wrapping_add(row.wrapping_mul(h2))) % self.width + row * self.width;
            let val = self.counters[idx].load(Ordering::Relaxed);
            if val < min {
                min = val;
            }
        }
        min
    }

    /// Periodically halve all counters to let cold entries fade out.
    /// Called at the same cadence as the old `popularity.retain()` cleanup.
    pub(super) fn decay_all(&self) {
        for c in &self.counters {
            let val = c.load(Ordering::Relaxed);
            if val > 0 {
                c.store(val / 2, Ordering::Relaxed);
            }
        }
    }

    fn hash_pair(key: &CacheKey) -> (usize, usize) {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let h1 = hasher.finish() as usize;
        // Mix with qname for second hash row seed.
        key.qname.hash(&mut hasher);
        let h2 = hasher.finish() as usize;
        (h1, h2)
    }
}
