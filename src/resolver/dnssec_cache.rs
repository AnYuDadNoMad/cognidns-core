//! DNSSEC validation result cache.
//!
//! Avoids re-validating the same DNS response by caching validation results
//! keyed by hash of (qname, qtype, response) with TTL-based expiration.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::dnssec::ValidationState;
use crate::error::MutexRecover;

/// DNSSEC validation result cache to avoid re-validating the same response.
/// Keyed by hash of (qname, qtype, response) with TTL-based expiration.
#[derive(Debug)]
pub(super) struct DnssecValidationCache {
    entries: Mutex<HashMap<u64, (ValidationState, Instant)>>,
    ttl: Duration,
}

impl DnssecValidationCache {
    pub(super) fn new(ttl_secs: u64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub(super) fn get(&self, key: u64) -> Option<ValidationState> {
        let entries = self.entries.lock().recover("dnssec_validation_cache");
        entries.get(&key).and_then(|(state, expires)| {
            if Instant::now() < *expires {
                Some(*state)
            } else {
                None
            }
        })
    }

    pub(super) fn insert(&self, key: u64, state: ValidationState) {
        let mut entries = self.entries.lock().recover("dnssec_validation_cache");
        entries.insert(key, (state, Instant::now() + self.ttl));
        // Prune expired entries if cache grows too large
        if entries.len() > 1024 {
            entries.retain(|_, (_, expires)| Instant::now() < *expires);
        }
    }

    pub(super) fn make_key(qname: &str, qtype: u16, response: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        qname.hash(&mut hasher);
        qtype.hash(&mut hasher);
        response.hash(&mut hasher);
        hasher.finish()
    }
}

impl crate::traits::DnssecCache for DnssecValidationCache {
    fn get(&self, key: u64) -> Option<crate::dnssec::ValidationState> {
        self.get(key)
    }

    fn insert(&self, key: u64, state: crate::dnssec::ValidationState) {
        self.insert(key, state)
    }

    fn make_key(&self, qname: &str, qtype: u16, response: &[u8]) -> u64 {
        Self::make_key(qname, qtype, response)
    }
}
