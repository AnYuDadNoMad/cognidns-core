//! Trait abstraction layer for CogniDNS subsystems.
//!
//! Defines three traits that decouple the core resolver from its dependencies:
//! - `DnsCache`: response cache (enables mock cache injection for tests)
//! - `UpstreamTransport`: upstream DNS transport (UDP/TCP, enables mock networking)
//! - `DnssecCache`: DNSSEC validation result cache (enables mock DNSSEC behavior)
//!
//! These traits are the first step toward a fully testable, swappable architecture
//! as described in OPTIMIZATION_PLAN.md § "中期计划: 引入 Trait 抽象层".

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;

use crate::cache::{CacheDump, CacheImportResult, CacheKey};
use crate::dnssec::ValidationState;

// ---------------------------------------------------------------------------
// DnsCache — abstract response cache
// ---------------------------------------------------------------------------

/// Abstract cache for DNS responses.
///
/// Enables swapping the cache implementation (in-memory, Redis-backed,
/// no-op for benchmarks, etc.) without changing resolver or admin code.
///
/// All methods take `&self` so the trait is object-safe; implementations
/// are expected to use interior mutability (`RwLock`, `Atomic*`, etc.).
pub trait DnsCache: Send + Sync + fmt::Debug {
    /// Look up a cached response. Returns `None` if absent or expired.
    /// When `freeze_ttl` is true, the expiry check is skipped.
    fn get(&self, key: &CacheKey, freeze_ttl: bool) -> Option<Vec<u8>>;

    /// Return the remaining TTL for a cached key, if present and not expired.
    fn remaining_ttl(&self, key: &CacheKey, freeze_ttl: bool) -> Option<Duration>;

    /// Insert a response into the cache with an explicit TTL.
    fn insert(&self, key: CacheKey, response: Vec<u8>, ttl: Duration);

    /// Remove all entries and return the count of removed items.
    fn clear_all(&self) -> usize;

    /// Remove all entries whose qname matches (or is a subdomain of) `domain`.
    fn clear_domain(&self, domain: &str) -> usize;

    /// Set the maximum number of entries (0 = unbounded).
    fn set_capacity(&self, capacity: usize);

    /// Return the current maximum capacity (0 = unbounded).
    fn capacity(&self) -> usize;

    /// Enable or disable global TTL freeze (TTL does not decay for any entry).
    fn set_freeze_all(&self, enabled: bool);

    /// Freeze or unfreeze TTL for a specific domain. Returns new frozen-domain count.
    fn set_freeze_domain(&self, domain: &str, enabled: bool) -> usize;

    /// Return the number of domains with TTL frozen.
    fn freeze_domain_count(&self) -> usize;

    /// Check whether the given qname has TTL frozen (globally or per-domain).
    fn is_frozen_for_qname(&self, qname: &str) -> bool;

    /// Export the current cache contents as a serializable dump.
    /// `is_frozen` is called for each entry to record its frozen status.
    fn export_dump(&self, is_frozen: &dyn Fn(&str) -> bool) -> CacheDump;

    /// Import entries from a previously exported dump.
    fn import_dump(&self, dump: CacheDump) -> CacheImportResult;

    /// Remove a single key if it has expired (best-effort / opportunistic).
    fn prune_expired(&self, key: &CacheKey);
}

// ---------------------------------------------------------------------------
// UpstreamTransport — abstract DNS transport
// ---------------------------------------------------------------------------

/// Abstract upstream DNS transport (UDP or TCP).
///
/// Implementations own their I/O resources (sockets, connection pools)
/// and are expected to be `Clone + Send + Sync` so they can be shared
/// across tasks via `Arc`.
#[async_trait]
pub trait UpstreamTransport: Send + Sync + fmt::Debug {
    /// Send a raw DNS query and return the raw response.
    /// `timeout` applies to the entire send-receive round-trip.
    async fn query(&self, request: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// DnssecCache — DNSSEC validation cache
// ---------------------------------------------------------------------------

/// Cached DNSSEC validation results to avoid re-validating identical responses.
///
/// Keyed by a hash of (qname, qtype, response bytes).  The cache stores
/// `ValidationState::Secure` / `Insecure` with TTL-based expiration.
pub trait DnssecCache: Send + Sync + fmt::Debug {
    /// Look up a cached validation result by key. Returns `None` if absent or expired.
    fn get(&self, key: u64) -> Option<ValidationState>;

    /// Insert a validation result with the default TTL.
    fn insert(&self, key: u64, state: ValidationState);

    /// Build a cache key from the canonical components of a DNSSEC response.
    fn make_key(&self, qname: &str, qtype: u16, response: &[u8]) -> u64;
}

// ---------------------------------------------------------------------------
// Tests — mock implementations proving mockability
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    // ---- Mock DnsCache --------------------------------------------------

    /// A simple in-memory cache that implements DnsCache for testing.
    #[derive(Debug, Default)]
    struct MockCache {
        entries: Mutex<HashMap<CacheKey, Vec<u8>>>,
        ttl: Mutex<HashMap<CacheKey, Duration>>,
    }

    impl DnsCache for MockCache {
        fn get(&self, key: &CacheKey, _freeze_ttl: bool) -> Option<Vec<u8>> {
            self.entries.lock().unwrap().get(key).cloned()
        }

        fn remaining_ttl(&self, key: &CacheKey, _freeze_ttl: bool) -> Option<Duration> {
            self.ttl.lock().unwrap().get(key).copied()
        }

        fn insert(&self, key: CacheKey, response: Vec<u8>, ttl: Duration) {
            self.entries.lock().unwrap().insert(key.clone(), response);
            self.ttl.lock().unwrap().insert(key, ttl);
        }

        fn clear_all(&self) -> usize {
            let mut entries = self.entries.lock().unwrap();
            let count = entries.len();
            entries.clear();
            self.ttl.lock().unwrap().clear();
            count
        }

        fn clear_domain(&self, _domain: &str) -> usize {
            0
        }

        fn set_capacity(&self, _capacity: usize) {}
        fn capacity(&self) -> usize {
            0
        }

        fn set_freeze_all(&self, _enabled: bool) {}
        fn set_freeze_domain(&self, _domain: &str, _enabled: bool) -> usize {
            0
        }
        fn freeze_domain_count(&self) -> usize {
            0
        }
        fn is_frozen_for_qname(&self, _qname: &str) -> bool {
            false
        }

        fn export_dump(&self, _is_frozen: &dyn Fn(&str) -> bool) -> CacheDump {
            CacheDump {
                exported_at_unix_secs: 0,
                entries: vec![],
            }
        }

        fn import_dump(&self, _dump: CacheDump) -> CacheImportResult {
            CacheImportResult {
                imported: 0,
                skipped: 0,
            }
        }

        fn prune_expired(&self, _key: &CacheKey) {}
    }

    #[test]
    fn mock_cache_insert_and_get() {
        let cache = MockCache::default();
        let key = CacheKey {
            qname: smol_str::SmolStr::from("example.com"),
            qtype: 1,
            dnssec_ok: false,
        };
        let response = vec![0x01, 0x02, 0x03];
        cache.insert(key.clone(), response.clone(), Duration::from_secs(30));
        assert_eq!(cache.get(&key, false), Some(response));
        assert_eq!(
            cache.remaining_ttl(&key, false),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn mock_cache_clear_all() {
        let cache = MockCache::default();
        let key = CacheKey {
            qname: smol_str::SmolStr::from("test.local"),
            qtype: 1,
            dnssec_ok: false,
        };
        cache.insert(key.clone(), vec![0x04], Duration::from_secs(10));
        assert_eq!(cache.clear_all(), 1);
        assert_eq!(cache.get(&key, false), None);
    }

    #[test]
    fn mock_cache_capacity_is_zero_by_default() {
        let cache = MockCache::default();
        assert_eq!(cache.capacity(), 0);
    }

    #[test]
    fn mock_cache_trait_object_works() {
        // Prove that MockCache can be used as a trait object via Arc.
        let cache: Arc<dyn DnsCache> = Arc::new(MockCache::default());
        let key = CacheKey {
            qname: smol_str::SmolStr::from("dyn.test"),
            qtype: 28,
            dnssec_ok: true,
        };
        cache.insert(key.clone(), vec![0xAA], Duration::from_secs(60));
        assert_eq!(cache.get(&key, false), Some(vec![0xAA]));
        assert_eq!(cache.capacity(), 0);
    }

    // ---- Mock UpstreamTransport -----------------------------------------

    /// A mock transport that returns canned responses.
    #[derive(Debug)]
    struct MockTransport {
        response: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl UpstreamTransport for MockTransport {
        async fn query(&self, _request: &[u8], _timeout: Duration) -> anyhow::Result<Vec<u8>> {
            Ok(self.response.lock().unwrap().clone())
        }
    }

    #[tokio::test]
    async fn mock_transport_returns_canned_response() {
        let transport = MockTransport {
            response: Mutex::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let result = transport
            .query(b"fake-query", Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[tokio::test]
    async fn mock_transport_as_trait_object() {
        let transport: Arc<dyn UpstreamTransport> = Arc::new(MockTransport {
            response: Mutex::new(b"hello-dns".to_vec()),
        });
        let result = transport
            .query(b"any-request", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result, b"hello-dns");
    }

    // ---- Mock DnssecCache -----------------------------------------------

    /// A mock DNSSEC cache for testing.
    #[derive(Debug, Default)]
    struct MockDnssecCache {
        entries: Mutex<HashMap<u64, ValidationState>>,
    }

    impl DnssecCache for MockDnssecCache {
        fn get(&self, key: u64) -> Option<ValidationState> {
            self.entries.lock().unwrap().get(&key).copied()
        }

        fn insert(&self, key: u64, state: ValidationState) {
            self.entries.lock().unwrap().insert(key, state);
        }

        fn make_key(&self, qname: &str, qtype: u16, response: &[u8]) -> u64 {
            use std::hash::{DefaultHasher, Hash, Hasher};
            let mut h = DefaultHasher::new();
            qname.hash(&mut h);
            qtype.hash(&mut h);
            response.hash(&mut h);
            h.finish()
        }
    }

    #[test]
    fn mock_dnssec_cache_insert_and_get() {
        let cache = MockDnssecCache::default();
        let key = cache.make_key("secure.test", 1, b"fake-response");
        cache.insert(key, ValidationState::Secure);
        assert_eq!(cache.get(key), Some(ValidationState::Secure));
    }

    #[test]
    fn mock_dnssec_cache_miss_returns_none() {
        let cache = MockDnssecCache::default();
        assert_eq!(cache.get(0xDEAD), None);
    }

    #[test]
    fn mock_dnssec_cache_deterministic_key() {
        let cache = MockDnssecCache::default();
        let k1 = cache.make_key("example.com", 1, b"resp-a");
        let k2 = cache.make_key("example.com", 1, b"resp-a");
        let k3 = cache.make_key("example.com", 1, b"resp-b");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn real_response_cache_implements_dns_cache() {
        // Verify that the production ResponseCache satisfies the DnsCache trait.
        let cache = crate::cache::ResponseCache::new(128);
        let key = CacheKey {
            qname: smol_str::SmolStr::from("real.test"),
            qtype: 1,
            dnssec_ok: false,
        };
        cache.insert(key.clone(), vec![0x42], Duration::from_secs(10));
        assert_eq!(cache.get(&key, false), Some(vec![0x42]));
        // Also verify it works as a trait object.
        let _trait_obj: &dyn DnsCache = &cache;
    }
}
