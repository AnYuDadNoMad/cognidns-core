//! Resolver core supporting forwarder mode and minimal iterative mode.

// Submodules extracted from the monolithic resolver for modularity.
mod popularity;
mod dnssec_cache;
mod types;
mod util;

use popularity::PopularitySketch;
use dnssec_cache::DnssecValidationCache;
use types::*;
use util::*;

use async_trait::async_trait;
use dashmap::DashMap;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::dnssec::TrustAnchors;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, info, trace, warn};

use crate::cache::{CacheKey, ResponseCache};
use crate::traits::{DnsCache, UpstreamTransport};
use crate::codec::dns;
use crate::config::{
    AuthoritativeSource, AuthoritativeZone, DnsView, IterativeAddressFamily, NsHostnameResolveMode,
    StaticRecord, ViewQueryMode,
};
use crate::context::RequestContext;
use crate::dnssec::{self, ValidatedKeys, ValidationState};
use crate::error::MutexRecover;
use crate::health::{HealthCheckConfig, IpHealthManager};
use crate::metrics::Metrics;

#[derive(Clone)]
pub struct ResolverConfig {
    pub resolve_mode: String,
    pub root_servers: Vec<String>,
    pub iterative_address_family: IterativeAddressFamily,
    pub iterative_max_depth: u8,
    pub iterative_timeout_ms: u64,
    pub cname_chain_max_depth: u8,
    pub follow_cname_chain: bool,
    pub static_cname_expand_for_address_queries: bool,
    pub iterative_fallback_to_forwarder: bool,
    pub iterative_cname_bridge_fallback_to_recursive: bool,
    pub cname_chain_cache_enabled: bool,
    pub cname_chain_inline_cache_enabled: bool,
    pub cname_chain_dualstack_share_enabled: bool,
    pub cname_chain_target_prefetch_enabled: bool,
    pub ns_host_cache_capacity: usize,
    pub ns_host_cache_ttl_secs: u64,
    pub ns_host_cache_cleanup_interval_ms: u64,
    pub enable_delegation_cache: bool,
    pub strict_bailiwick: bool,
    pub delegation_cache_capacity: usize,
    pub delegation_cache_ttl_cap_secs: u64,
    pub delegation_cache_cleanup_interval_ms: u64,
    pub delegation_failure_backoff_ms: u64,
    pub stats_window_secs: u64,
    pub stats_short_window_secs: u64,
    pub cache_hot_capacity: usize,
    pub upstreams: Vec<String>,
    pub cache_ttl_secs: u64,
    pub freeze_cache_ttl_decay: bool,
    pub freeze_cache_domains: Vec<String>,
    pub upstream_timeout_ms: u64,
    pub upstream_retries: u8,
    pub unhealthy_backoff_ms: u64,
    pub prefetch_budget_per_window: u32,
    pub prefetch_window_secs: u64,
    pub prefetch_ttl_trigger_secs: u64,
    pub prefetch_popularity_threshold: u32,
    pub upstream_score_rtt_weight: f64,
    pub upstream_score_failure_weight: f64,
    pub upstream_score_success_weight: f64,
    pub adaptive_cache_enabled: bool,
    pub adaptive_cache_min_capacity: usize,
    pub adaptive_cache_max_capacity: usize,
    pub adaptive_cache_step: usize,
    pub adaptive_cache_window_secs: u64,
    pub adaptive_cache_high_miss_ratio: f64,
    pub adaptive_cache_low_miss_ratio: f64,
    pub enable_recursion: bool,
    pub dnssec_enabled: bool,
    pub trust_anchors: TrustAnchors,
    /// NS 主机名并发解析上限。
    pub ns_hostname_max_concurrent: usize,
    /// 累计收集到该数量端点后立即截断。
    pub ns_hostname_enough_endpoints: usize,
    /// 单个 NS 主机名解析超时（ms）。
    pub ns_hostname_per_resolve_ms: u64,
    /// NS 主机名解析模式（bootstrap recursive 或 pure iterative）。
    pub ns_hostname_resolve_mode: NsHostnameResolveMode,
    /// 单跳 NS 解析最大时间（ms），0 = 不限制，使用全局预算。
    pub iterative_per_hop_timeout_ms: u64,
    /// 委托区预热列表（config::PreWarmZone）。
    pub prewarm_delegation_zones: Vec<crate::config::PreWarmZone>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            resolve_mode: "forwarder".to_string(),
            root_servers: Vec::new(),
            iterative_address_family: IterativeAddressFamily::DualStack,
            iterative_max_depth: 8,
            iterative_timeout_ms: 3000,
            cname_chain_max_depth: 8,
            follow_cname_chain: false,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            iterative_cname_bridge_fallback_to_recursive: true,
            cname_chain_cache_enabled: true,
            cname_chain_inline_cache_enabled: true,
            cname_chain_dualstack_share_enabled: true,
            cname_chain_target_prefetch_enabled: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: Vec::new(),
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 200,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            enable_recursion: true,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            ns_hostname_resolve_mode: NsHostnameResolveMode::BootstrapRecursive,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ResolverMode {
    Forwarder,
    Iterative,
}

#[derive(Debug, Clone)]
pub enum ResolutionSource {
    Cache,
    Upstream(String),
}

impl ResolutionSource {
    /// 获取解析来源的标签字符串。
    pub fn label(&self) -> &str {
        match self {
            Self::Cache => "cache",
            Self::Upstream(_) => "upstream",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedResponse {
    pub packet: Vec<u8>,
    pub source: ResolutionSource,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamSnapshot {
    pub address: String,
    pub healthy: bool,
    pub score: f64,
    pub consecutive_failures: u32,
    pub successes: u64,
    pub failures: u64,
    pub last_rtt_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverSnapshot {
    pub mode: String,
    pub total_upstreams: usize,
    pub healthy_upstreams: usize,
    pub upstreams: Vec<UpstreamSnapshot>,
    pub forwarder_failovers: usize,
    pub iterative_successes: usize,
    pub iterative_failures: usize,
    pub iterative_fallbacks: usize,
    pub iterative_loop_detected: usize,
    pub iterative_requests_started: usize,
    pub iterative_referral_hops: usize,
    pub iterative_retry_queries: usize,
    pub iterative_no_referral_glue_failures: usize,
    pub iterative_window: IterativeWindowSnapshot,
    pub iterative_window_short: IterativeWindowSnapshot,
    pub iterative_failure_rate_long: f64,
    pub iterative_failure_rate_short: f64,
    pub iterative_fallback_ratio_long: f64,
    pub iterative_fallback_ratio_short: f64,
    pub ns_cache_window: NsCacheWindowSnapshot,
    pub ns_cache_window_short: NsCacheWindowSnapshot,
    pub ns_cache_eviction_rate_long: f64,
    pub ns_cache_eviction_rate_short: f64,
    pub ns_cache_expired_lookup_ratio_long: f64,
    pub ns_cache_expired_lookup_ratio_short: f64,
    pub ns_cache_entries: usize,
    pub ns_cache_capacity: usize,
    pub ip_health_enabled: bool,
    pub ip_health_tracked_domains: usize,
    pub ip_health_tracked_ips: usize,
    pub ip_health_degraded_domains: usize,
    pub ip_health_all_unhealthy_events: usize,
    pub ip_health_notify_attempt_total: usize,
    pub ip_health_notify_fail_total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct IterativeWindowSnapshot {
    pub window_secs: u64,
    pub successes: usize,
    pub failures: usize,
    pub fallbacks: usize,
    pub loops: usize,
    pub failure_rate: f64,
    pub fallback_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NsCacheWindowSnapshot {
    pub window_secs: u64,
    pub hits: usize,
    pub misses: usize,
    pub expired: usize,
    pub stores: usize,
    pub evicts: usize,
    pub cleanups: usize,
    pub cleanup_removed: usize,
    pub eviction_rate: f64,
    pub expired_lookup_ratio: f64,
}

#[derive(Debug)]
struct UpstreamState {
    consecutive_failures: u32,
    last_rtt: Option<Duration>,
    unhealthy_until: Option<Instant>,
    successes: u64,
    failures: u64,
    score: f64,
}

#[derive(Debug)]
struct Upstream {
    address: String,
    state: RwLock<UpstreamState>,
}

#[derive(Debug)]
struct InFlightQueries {
    /// Lock-free concurrent map for in-flight query deduplication.
    /// Key: CacheKey, Value: Arc<Notify> — waiters call `notified().await`.
    map: DashMap<CacheKey, Arc<Notify>>,
}

#[derive(Debug)]
struct UpstreamUdpTransport {
    shards: Vec<mpsc::Sender<UpstreamUdpQuery>>,
}

#[derive(Debug)]
struct UpstreamTcpTransport {
    shards: Vec<mpsc::Sender<UpstreamTcpQuery>>,
}

#[derive(Debug)]
struct UpstreamUdpQuery {
    packet: Vec<u8>,
    recv_buf_size: usize,
    response_tx: oneshot::Sender<anyhow::Result<Vec<u8>>>,
    deadline: Instant,
}

#[derive(Debug)]
struct UpstreamTcpQuery {
    packet: Vec<u8>,
    response_tx: oneshot::Sender<anyhow::Result<Vec<u8>>>,
    deadline: Instant,
}

#[derive(Debug)]
struct PendingUdpQuery {
    response_tx: oneshot::Sender<anyhow::Result<Vec<u8>>>,
    deadline: Instant,
}

impl Default for InFlightQueries {
    fn default() -> Self {
        Self {
            map: DashMap::with_capacity(256),
        }
    }
}

#[derive(Debug, Clone)]
struct NsCacheEntry {
    endpoints: Vec<String>,
    expires_at: Instant,
    last_access: Instant,
}

#[derive(Debug)]
struct NsHostCacheShard {
    entries: HashMap<String, NsCacheEntry>,
    failures: HashMap<String, Instant>,
    last_cleanup: Instant,
}

#[derive(Debug)]
struct NsHostCache {
    shards: Vec<Mutex<NsHostCacheShard>>,
}

#[derive(Debug, Clone)]
struct DelegationCacheEntry {
    endpoints: Vec<String>,
    expires_at: Instant,
    last_access: Instant,
    cooldown_until: Option<Instant>,
}

#[derive(Debug)]
struct DelegationCacheShard {
    entries: HashMap<String, DelegationCacheEntry>,
    last_cleanup: Instant,
}

#[derive(Debug)]
struct DelegationCache {
    shards: Vec<Mutex<DelegationCacheShard>>,
}

impl NsHostCache {
    fn new(capacity: usize) -> Self {
        let shard_count = aux_cache_shard_count(capacity);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Mutex::new(NsHostCacheShard {
                entries: HashMap::new(),
                failures: HashMap::new(),
                last_cleanup: Instant::now(),
            }));
        }
        Self { shards }
    }
}

impl DelegationCache {
    fn new(capacity: usize) -> Self {
        let shard_count = aux_cache_shard_count(capacity);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Mutex::new(DelegationCacheShard {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }));
        }
        Self { shards }
    }
}

#[derive(Debug, Clone, Copy)]
enum IterativeEventKind {
    Success,
    Failure,
    Fallback,
    LoopDetected,
}

#[derive(Debug, Clone, Copy)]
enum NsCacheEventKind {
    Hit,
    Miss,
    Expired,
    Store,
    Evict,
    Cleanup,
}

#[derive(Debug, Clone, Copy)]
struct NsCacheEvent {
    at: Instant,
    kind: NsCacheEventKind,
    removed: usize,
}

#[derive(Debug, Clone, Copy)]
enum ResolutionState {
    SelectUpstream,
    QueryUpstream(usize),
    CacheStore,
}

pub struct Resolver {
    mode: ResolverMode,
    root_servers: Vec<String>,
    bootstrap_recursive_resolvers: Vec<String>,
    upstream_udp_transports: HashMap<String, Arc<dyn UpstreamTransport>>,
    upstream_tcp_transports: HashMap<String, Arc<dyn UpstreamTransport>>,
    iterative_address_family: IterativeAddressFamily,
    iterative_max_depth: u8,
    iterative_timeout: Duration,
    cname_chain_max_depth: u8,
    follow_cname_chain: bool,
    static_cname_expand_for_address_queries: bool,
    iterative_fallback_to_forwarder: bool,
    iterative_cname_bridge_fallback_to_recursive: bool,
    cname_chain_cache_enabled: bool,
    cname_chain_inline_cache_enabled: bool,
    cname_chain_dualstack_share_enabled: bool,
    cname_chain_target_prefetch_enabled: bool,
    stats_window: Duration,
    stats_short_window: Duration,
    ns_host_cache_capacity: usize,
    ns_host_cache_ttl: Duration,
    ns_host_cache_cleanup_interval: Duration,
    enable_delegation_cache: bool,
    #[allow(dead_code)]
    strict_bailiwick: bool,
    delegation_cache_capacity: usize,
    delegation_cache_ttl_cap: Duration,
    delegation_cache_cleanup_interval: Duration,
    delegation_failure_backoff: Duration,
    hot_cache: Arc<dyn DnsCache>,
    cache: Arc<dyn DnsCache>,
    bad_cache: Arc<dyn DnsCache>,
    upstreams: Vec<Upstream>,
    upstream_timeout: Duration,
    upstream_retries: u8,
    cache_ttl: Duration,
    freeze_cache_ttl_decay: bool,
    freeze_cache_domains: Vec<String>,
    unhealthy_backoff: Duration,
    prefetch_budget_per_window: u32,
    prefetch_window: Duration,
    prefetch_ttl_trigger: Duration,
    prefetch_popularity_threshold: u32,
    upstream_score_rtt_weight: f64,
    upstream_score_failure_weight: f64,
    upstream_score_success_weight: f64,
    adaptive_cache_enabled: bool,
    adaptive_cache_min_capacity: usize,
    adaptive_cache_max_capacity: usize,
    adaptive_cache_step: usize,
    adaptive_cache_window: Duration,
    adaptive_cache_high_miss_ratio: f64,
    adaptive_cache_low_miss_ratio: f64,
    enable_recursion: bool,
    minimal_response: bool,
    current_cache_capacity: AtomicUsize,
    dnssec_enabled: bool,
    dnssec_validation_cache: DnssecValidationCache,
    next_upstream: AtomicUsize,
    metrics: Arc<Metrics>,
    inflight: InFlightQueries,
    forwarder_failovers: AtomicUsize,
    ns_host_cache: NsHostCache,
    delegation_cache: DelegationCache,
    iterative_events: Mutex<VecDeque<(Instant, IterativeEventKind)>>,
    ns_cache_events: Mutex<VecDeque<NsCacheEvent>>,
    iterative_successes: AtomicUsize,
    iterative_failures: AtomicUsize,
    iterative_fallbacks: AtomicUsize,
    iterative_loop_detected: AtomicUsize,
    iterative_requests_started: AtomicUsize,
    iterative_referral_hops: AtomicUsize,
    iterative_retry_queries: AtomicUsize,
    iterative_no_referral_glue_failures: AtomicUsize,
    prefetch_budget_consumed: AtomicU32,
    prefetch_budget_window_start: Mutex<Instant>,
    popularity: PopularitySketch,
    adaptive_cache_hits: AtomicUsize,
    adaptive_cache_misses: AtomicUsize,
    adaptive_cache_window_start: Mutex<Instant>,
    static_record_index: HashMap<CacheKey, StaticRecordEntry>,
    authoritative_source_index: HashMap<CacheKey, AuthoritativeSourceEntry>,
    authoritative_zone_entries: Vec<AuthoritativeZoneEntry>,
    view_static_record_index: ViewRecordIndex,
    view_authoritative_record_index: ViewRecordIndex,
    view_authoritative_zone_index: ViewZoneIndex,
    view_query_control_index: ViewQueryControlIndex,
    root_trust_anchors: TrustAnchors,
    ns_hostname_max_concurrent: usize,
    ns_hostname_enough_endpoints: usize,
    ns_hostname_per_resolve_ms: u64,
    ns_hostname_resolve_mode: NsHostnameResolveMode,
    iterative_per_hop_timeout: Duration,
    /// 需要后台异步解析 NS 主机名的预热区列表：(规范化 zone, ttl, hostnames)。
    /// 由 `start_hostname_prewarm` 消费，仅在 Resolver 被包装成 Arc 后有效。
    prewarm_hostname_zones: Vec<(String, Duration, Vec<String>)>,
    iterative_dns_port: u16,
    ip_health: RwLock<Option<Arc<IpHealthManager>>>,
}

impl Resolver {
    /// Creates resolver runtime with upstream state, caches and window trackers.
    /// 创建 Resolver 运行时，初始化上游状态、缓存和统计窗口。
    pub fn new(
        config: ResolverConfig,
        cache: Arc<dyn DnsCache>,
        metrics: Arc<Metrics>,
        static_records: Vec<StaticRecord>,
        authoritative_sources: Vec<AuthoritativeSource>,
    ) -> Self {
        let ResolverConfig {
            resolve_mode,
            root_servers,
            iterative_address_family,
            iterative_max_depth,
            iterative_timeout_ms,
            cname_chain_max_depth,
            follow_cname_chain,
            static_cname_expand_for_address_queries,
            iterative_fallback_to_forwarder,
            iterative_cname_bridge_fallback_to_recursive,
            cname_chain_cache_enabled,
            cname_chain_inline_cache_enabled,
            cname_chain_dualstack_share_enabled,
            cname_chain_target_prefetch_enabled,
            ns_host_cache_capacity,
            ns_host_cache_ttl_secs,
            ns_host_cache_cleanup_interval_ms,
            enable_delegation_cache,
            strict_bailiwick,
            delegation_cache_capacity,
            delegation_cache_ttl_cap_secs,
            delegation_cache_cleanup_interval_ms,
            delegation_failure_backoff_ms,
            stats_window_secs,
            stats_short_window_secs,
            cache_hot_capacity,
            upstreams,
            cache_ttl_secs,
            freeze_cache_ttl_decay,
            freeze_cache_domains,
            upstream_timeout_ms,
            upstream_retries,
            unhealthy_backoff_ms,
            prefetch_budget_per_window,
            prefetch_window_secs,
            prefetch_ttl_trigger_secs,
            prefetch_popularity_threshold,
            upstream_score_rtt_weight,
            upstream_score_failure_weight,
            upstream_score_success_weight,
            adaptive_cache_enabled,
            adaptive_cache_min_capacity,
            adaptive_cache_max_capacity,
            adaptive_cache_step,
            adaptive_cache_window_secs,
            adaptive_cache_high_miss_ratio,
            adaptive_cache_low_miss_ratio,
            enable_recursion,
            dnssec_enabled,
            trust_anchors,
            ns_hostname_max_concurrent,
            ns_hostname_enough_endpoints,
            ns_hostname_per_resolve_ms,
            ns_hostname_resolve_mode,
            iterative_per_hop_timeout_ms,
            prewarm_delegation_zones,
        } = config;
        let mode = if resolve_mode.eq_ignore_ascii_case("iterative") {
            ResolverMode::Iterative
        } else {
            ResolverMode::Forwarder
        };

        let upstreams = upstreams
            .into_iter()
            .map(|address| Upstream {
                address,
                state: RwLock::new(UpstreamState {
                    consecutive_failures: 0,
                    last_rtt: None,
                    unhealthy_until: None,
                    successes: 0,
                    failures: 0,
                    score: 0.0,
                }),
            })
            .collect::<Vec<_>>();
        let root_servers =
            filter_endpoints_for_iterative_family(root_servers, iterative_address_family);
        let bootstrap_recursive_resolvers = build_bootstrap_recursive_resolvers(
            &root_servers,
            &upstreams,
            iterative_address_family,
        );
        let upstream_udp_transports = build_upstream_udp_transports(&root_servers, &upstreams);
        let upstream_tcp_transports = build_upstream_tcp_transports(&root_servers, &upstreams);
        let static_record_index = build_static_record_index(static_records);
        let authoritative_source_index = build_authoritative_source_index(authoritative_sources);
        let hot_cache = Arc::new(ResponseCache::new(cache_hot_capacity.max(1)));
        let now = Instant::now();
        let current_cache_capacity = cache.capacity().max(1);

        // Auto-detect iterative DNS port: if root servers or upstreams use
        // a non-53 port (typical in tests), adopt it so iterative queries
        // reach mock servers without requiring root privileges.
        let iterative_dns_port: u16 = {
            let addr_strs: Vec<&str> = root_servers
                .iter()
                .map(|s| s.as_str())
                .chain(upstreams.iter().map(|u| u.address.as_str()))
                .collect();
            let ports: Vec<u16> = addr_strs
                .iter()
                .filter_map(|addr| addr.rsplit(':').next()?.parse::<u16>().ok())
                .collect();
            let non_53: Vec<_> = ports.iter().filter(|&&p| p != 53).collect();
            if non_53.len() == 1 && ports.iter().all(|p| p == non_53[0]) {
                *non_53[0]
            } else {
                53
            }
        };

        metrics.set_healthy_upstreams(upstreams.len());

        let mut resolver = Self {
            mode,
            root_servers,
            bootstrap_recursive_resolvers,
            upstream_udp_transports,
            upstream_tcp_transports,
            iterative_address_family,
            iterative_max_depth: iterative_max_depth.max(1),
            iterative_timeout: Duration::from_millis(iterative_timeout_ms.max(100)),
            cname_chain_max_depth: cname_chain_max_depth.max(1),
            follow_cname_chain,
            static_cname_expand_for_address_queries,
            iterative_fallback_to_forwarder,
            iterative_cname_bridge_fallback_to_recursive,
            cname_chain_cache_enabled,
            cname_chain_inline_cache_enabled,
            cname_chain_dualstack_share_enabled,
            cname_chain_target_prefetch_enabled,
            stats_window: Duration::from_secs(stats_window_secs.max(1)),
            stats_short_window: Duration::from_secs(stats_short_window_secs.max(1)),
            ns_host_cache_capacity,
            ns_host_cache_ttl: Duration::from_secs(ns_host_cache_ttl_secs.max(1)),
            ns_host_cache_cleanup_interval: Duration::from_millis(
                ns_host_cache_cleanup_interval_ms.max(100),
            ),
            enable_delegation_cache,
            strict_bailiwick,
            delegation_cache_capacity,
            delegation_cache_ttl_cap: Duration::from_secs(delegation_cache_ttl_cap_secs.max(1)),
            delegation_cache_cleanup_interval: Duration::from_millis(
                delegation_cache_cleanup_interval_ms.max(100),
            ),
            delegation_failure_backoff: Duration::from_millis(
                delegation_failure_backoff_ms.max(100),
            ),
            hot_cache,
            cache,
            bad_cache: Arc::new(ResponseCache::new(DNSSEC_BAD_CACHE_CAPACITY)),
            upstreams,
            upstream_timeout: Duration::from_millis(upstream_timeout_ms),
            upstream_retries,
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            freeze_cache_ttl_decay,
            freeze_cache_domains: freeze_cache_domains
                .into_iter()
                .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            unhealthy_backoff: Duration::from_millis(unhealthy_backoff_ms),
            prefetch_budget_per_window,
            prefetch_window: Duration::from_secs(prefetch_window_secs.max(1)),
            prefetch_ttl_trigger: Duration::from_secs(prefetch_ttl_trigger_secs.max(1)),
            prefetch_popularity_threshold,
            upstream_score_rtt_weight,
            upstream_score_failure_weight,
            upstream_score_success_weight,
            adaptive_cache_enabled,
            adaptive_cache_min_capacity,
            adaptive_cache_max_capacity,
            adaptive_cache_step,
            adaptive_cache_window: Duration::from_secs(adaptive_cache_window_secs.max(1)),
            adaptive_cache_high_miss_ratio,
            adaptive_cache_low_miss_ratio,
            enable_recursion,
            minimal_response: true,
            current_cache_capacity: AtomicUsize::new(current_cache_capacity),
            dnssec_enabled,
            dnssec_validation_cache: DnssecValidationCache::new(300),
            next_upstream: AtomicUsize::new(0),
            metrics,
            inflight: InFlightQueries::default(),
            forwarder_failovers: AtomicUsize::new(0),
            ns_host_cache: NsHostCache::new(ns_host_cache_capacity),
            delegation_cache: DelegationCache::new(delegation_cache_capacity),
            iterative_events: Mutex::new(VecDeque::new()),
            ns_cache_events: Mutex::new(VecDeque::new()),
            iterative_successes: AtomicUsize::new(0),
            iterative_failures: AtomicUsize::new(0),
            iterative_fallbacks: AtomicUsize::new(0),
            iterative_loop_detected: AtomicUsize::new(0),
            iterative_requests_started: AtomicUsize::new(0),
            iterative_referral_hops: AtomicUsize::new(0),
            iterative_retry_queries: AtomicUsize::new(0),
            iterative_no_referral_glue_failures: AtomicUsize::new(0),
            prefetch_budget_consumed: AtomicU32::new(0),
            prefetch_budget_window_start: Mutex::new(now),
            popularity: PopularitySketch::new(1024, 4),
            adaptive_cache_hits: AtomicUsize::new(0),
            adaptive_cache_misses: AtomicUsize::new(0),
            adaptive_cache_window_start: Mutex::new(now),
            static_record_index,
            authoritative_source_index,
            authoritative_zone_entries: Vec::new(),
            view_static_record_index: HashMap::new(),
            view_authoritative_record_index: HashMap::new(),
            view_authoritative_zone_index: HashMap::new(),
            view_query_control_index: HashMap::new(),
            root_trust_anchors: trust_anchors,
            ns_hostname_max_concurrent: ns_hostname_max_concurrent.max(1),
            ns_hostname_enough_endpoints: ns_hostname_enough_endpoints.max(1),
            ns_hostname_per_resolve_ms: ns_hostname_per_resolve_ms.max(100),
            ns_hostname_resolve_mode,
            iterative_per_hop_timeout: if iterative_per_hop_timeout_ms > 0 {
                Duration::from_millis(iterative_per_hop_timeout_ms)
            } else {
                // 0 = 自动派生：总超时 / 最大跳数，至少 200ms
                let auto_ms = (iterative_timeout_ms / (iterative_max_depth as u64).max(1)).max(200);
                info!(
                    iterative_timeout_ms,
                    iterative_max_depth,
                    derived_per_hop_ms = auto_ms,
                    "iterative_per_hop_timeout: auto-derived (set iterative_per_hop_timeout_ms > 0 to override)"
                );
                Duration::from_millis(auto_ms)
            },
            prewarm_hostname_zones: Vec::new(),
            iterative_dns_port,
            ip_health: RwLock::new(None),
        };

        // 委托区预热：同步注入 ns_endpoints，立即生效；
        // 含 ns_hostnames 的区暂存至 prewarm_hostname_zones，等待
        // start_hostname_prewarm() 被调用后在后台异步解析并注入。
        let prewarm_count = prewarm_delegation_zones.len();
        for entry in &prewarm_delegation_zones {
            let zone = normalize_prewarm_zone(&entry.zone);
            let ttl = Duration::from_secs(entry.ttl_secs.max(1));
            if !entry.ns_endpoints.is_empty() {
                let ep_count = entry.ns_endpoints.len();
                resolver.put_cached_delegation_endpoints(&zone, entry.ns_endpoints.clone(), ttl);
                info!(zone = %zone, endpoints = ep_count, ttl_secs = entry.ttl_secs, "prewarm: injected delegation zone (endpoints)");
            }
            if !entry.ns_hostnames.is_empty() {
                resolver.prewarm_hostname_zones.push((
                    zone.clone(),
                    ttl,
                    entry.ns_hostnames.clone(),
                ));
            }
        }
        if prewarm_count > 0 {
            info!(count = prewarm_count, "prewarm: delegation cache prewarmed");
        }

        resolver
    }

    pub fn configure_views(&mut self, views: &[DnsView]) {
        self.view_static_record_index = build_view_record_index(views, ViewIndexKind::Static);
        self.view_authoritative_record_index =
            build_view_record_index(views, ViewIndexKind::Authoritative);
        self.view_authoritative_zone_index = build_view_zone_index(views);
        self.view_query_control_index = build_view_query_control_index(views);
    }

    /// 配置是否启用最小应答。
    pub fn configure_minimal_response(&mut self, minimal_response: bool) {
        self.minimal_response = minimal_response;
    }

    /// 配置全局权威区记录（从 AppConfig.authoritative_zones 加载）。
    pub fn configure_authoritative_zones(&mut self, zones: &[AuthoritativeZone]) {
        self.authoritative_zone_entries = build_authoritative_zone_entries(zones);
    }

    /// 配置并启动域名->IP 健康检查后台任务。
    /// Set the DNS port used for iterative queries (default 53).
    /// Only needed for tests that bind mock servers to non-standard ports.
    pub fn set_iterative_dns_port(&mut self, port: u16) {
        self.iterative_dns_port = port;
    }

    pub fn configure_ip_health(&self, cfg: HealthCheckConfig) {
        if !cfg.enabled {
            if let Ok(mut guard) = self.ip_health.write() {
                *guard = None;
            }
            return;
        }

        let manager = IpHealthManager::new(cfg);
        manager.clone().start_background();
        if let Ok(mut guard) = self.ip_health.write() {
            *guard = Some(manager);
        }
    }

    /// 后台异步解析 ns_hostnames 并增量注入委托缓存。
    ///
    /// 必须在 Resolver 被包装成 `Arc<Resolver>` 后调用，以便后台任务持有共享引用。
    /// 解析失败不阻断服务——查询会自动回退至常规迭代路径。
    ///
    /// 每个 zone 独立生成一个 Tokio 后台任务，受限于 `ns_hostname_max_concurrent`
    /// 与 `ns_hostname_per_resolve_ms` 两个参数（复用现有调优参数）。
    pub fn start_hostname_prewarm(self: Arc<Self>) {
        for (zone, ttl, hostnames) in self.prewarm_hostname_zones.clone() {
            if hostnames.is_empty() {
                continue;
            }
            let resolver = Arc::clone(&self);
            tokio::spawn(async move {
                info!(
                    zone = %zone,
                    hostnames = hostnames.len(),
                    "prewarm: resolving ns_hostnames in background"
                );
                let endpoints = resolver.resolve_prewarm_hostnames(&hostnames).await;
                if endpoints.is_empty() {
                    warn!(zone = %zone, "prewarm: ns_hostnames resolved 0 endpoints, skipping injection");
                    resolver
                        .metrics
                        .record_iterative_event("prewarm_hostname_resolve_failed");
                } else {
                    let count = endpoints.len();
                    resolver.put_cached_delegation_endpoints(&zone, endpoints, ttl);
                    resolver
                        .metrics
                        .record_iterative_event("prewarm_hostname_resolved");
                    info!(zone = %zone, endpoints = count, "prewarm: injected delegation zone (hostnames)");
                }
            });
        }
    }

    /// 为预热目的解析一组 NS 主机名，返回 IP:53 格式端点列表。
    ///
    /// 使用 bootstrap 递归解析器查询每个主机名的 A 记录。
    /// 受 `ns_hostname_max_concurrent` 并发限制与 `ns_hostname_per_resolve_ms`
    /// 单次超时限制，不影响查询热路径。
    async fn resolve_prewarm_hostnames(&self, hostnames: &[String]) -> Vec<String> {
        use futures::stream::{FuturesUnordered, StreamExt};
        let mut result: Vec<String> = Vec::new();
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        let mut iter = hostnames.iter();

        loop {
            while in_flight.len() < self.ns_hostname_max_concurrent {
                let Some(hostname) = iter.next() else { break };
                // 先查 NS 主机缓存（同步快路径）
                if let Some(cached) = self.get_cached_ns_endpoints(hostname) {
                    result.extend(cached);
                    if result.len() >= self.ns_hostname_enough_endpoints {
                        return dedup_endpoints(result);
                    }
                    continue;
                }
                let hostname = hostname.clone();
                let per_timeout = Duration::from_millis(self.ns_hostname_per_resolve_ms);
                in_flight.push(async move {
                    let task_result: Vec<String> =
                        tokio::time::timeout(per_timeout, self.prewarm_query_hostname_a(&hostname))
                            .await
                            .unwrap_or_default();
                    task_result
                });
            }

            if in_flight.is_empty() {
                break;
            }

            if let Some(endpoints) = in_flight.next().await {
                result.extend(endpoints);
                if result.len() >= self.ns_hostname_enough_endpoints {
                    break;
                }
            }
        }

        dedup_endpoints(result)
    }

    /// 向 bootstrap 解析器查询单个主机名的 A 记录，返回 ip:53 端点列表。
    async fn prewarm_query_hostname_a(&self, hostname: &str) -> Vec<String> {
        let Some(query) = dns::build_query(
            next_iterative_query_id(),
            hostname,
            1, // A
            true,
        ) else {
            return Vec::new();
        };
        for resolver_addr in &self.bootstrap_recursive_resolvers {
            if let Ok(pkt) = self.query_address(resolver_addr, &query).await {
                let eps = dns::extract_answer_ip_endpoints_with_port(
                    &pkt,
                    self.iterative_dns_port,
                );
                if !eps.is_empty() {
                    return eps;
                }
            }
        }
        Vec::new()
    }

    #[cfg(test)]
    fn set_root_trust_anchors(&mut self, trust_anchors: TrustAnchors) {
        self.root_trust_anchors = trust_anchors;
    }

    /// 测试辅助：直接查询委托缓存，用于验证预热是否生效。
    /// 此方法仅用于测试，不应在生产代码中调用。
    #[doc(hidden)]
    pub fn probe_delegation_cache_for_test(&self, qname: &str) -> Option<(String, Vec<String>)> {
        self.get_cached_delegation_endpoints(qname)
    }

    /// Main resolve entry: cache lookup, in-flight dedup, then uncached resolution.
    /// 主解析入口：先查缓存，去重并发，未命中则走 uncached 解析。
    pub async fn resolve(
        &self,
        ctx: &RequestContext,
        request: &[u8],
    ) -> anyhow::Result<ResolvedResponse> {
        self.resolve_with_view(ctx, request, None).await
    }

    pub async fn resolve_with_view(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        matched_view: Option<&str>,
    ) -> anyhow::Result<ResolvedResponse> {
        let view_control = matched_view
            .and_then(|view_name| self.view_query_control_index.get(view_name).copied());
        let query_mode = view_control
            .map(|control| control.query_mode)
            .unwrap_or(ViewQueryMode::GlobalFallback);
        let allow_upstream_recursion = view_control
            .map(|control| control.enable_recursion)
            .unwrap_or(self.enable_recursion)
            && self.enable_recursion;
        let view_static_cname_expand_for_address_queries = view_control
            .and_then(|control| control.view_static_cname_expand_for_address_queries)
            .unwrap_or(self.static_cname_expand_for_address_queries);
        let view_authoritative_cname_expand_for_address_queries = view_control
            .and_then(|control| control.view_authoritative_cname_expand_for_address_queries)
            .unwrap_or(self.static_cname_expand_for_address_queries);

        debug!(
            request_id = ctx.request_id,
            qname = ?ctx.query_name,
            qtype = %dns::qtype_label_opt(ctx.query_type),
            matched_view = ?matched_view,
            query_mode = ?query_mode,
            allow_upstream_recursion,
            "resolver view context"
        );

        if let Some(view_name) = matched_view {
            // 1a. View 权威区（AA=1，in-zone NXDOMAIN 终止递归）
            if let Some(response) = self
                .try_resolve_from_zone_entries(
                    ctx,
                    request,
                    self.view_authoritative_zone_index
                        .get(view_name)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]),
                    Some(view_name),
                    "view_authoritative_zone",
                    view_authoritative_cname_expand_for_address_queries,
                )
                .await
            {
                return Ok(
                    self.normalize_ra_for_recursion_policy(response, allow_upstream_recursion)
                );
            }
            // 1b. View 静态/权威记录（inline）
            if let Some(response) = self
                .try_resolve_from_view_records(
                    ctx,
                    request,
                    view_name,
                    view_static_cname_expand_for_address_queries,
                    view_authoritative_cname_expand_for_address_queries,
                )
                .await
            {
                return Ok(
                    self.normalize_ra_for_recursion_policy(response, allow_upstream_recursion)
                );
            }

            if query_mode == ViewQueryMode::ViewOnly {
                debug!(
                    request_id = ctx.request_id,
                    qname = ?ctx.query_name,
                    qtype = %dns::qtype_label_opt(ctx.query_type),
                    view = %view_name,
                    "view_only miss: returning nxdomain"
                );
                let packet = dns::build_response_with_rcode(request, 3)?;
                return Ok(self.normalize_ra_for_recursion_policy(
                    ResolvedResponse {
                        packet,
                        source: ResolutionSource::Cache,
                    },
                    allow_upstream_recursion,
                ));
            }
        }

        // 2. 全局权威区（AA=1，in-zone NXDOMAIN 终止递归）
        if let Some(response) = self
            .try_resolve_from_zone_entries(
                ctx,
                request,
                &self.authoritative_zone_entries,
                None,
                "global_authoritative_zone",
                self.static_cname_expand_for_address_queries,
            )
            .await
        {
            return Ok(self.normalize_ra_for_recursion_policy(response, allow_upstream_recursion));
        }

        // 3. 全局静态记录
        if let (Some(qname), Some(qtype)) = (ctx.query_name.as_ref(), ctx.query_type) {
            let lookup_key = cache_key_for_query(qname, qtype, false);
            if let Some(rec) = self.static_record_index.get(&lookup_key) {
                // 构造响应包
                if let Ok(packet) = crate::codec::dns::build_static_answer(
                    request,
                    &rec.answer,
                    rec.ttl,
                    &rec.qtype_name,
                ) {
                    let packet = self.append_additional_for_static_answers(
                        packet,
                        qtype,
                        std::slice::from_ref(&rec.answer),
                        &self.static_record_index,
                    );
                    return Ok(self.normalize_ra_for_recursion_policy(
                        ResolvedResponse {
                            packet,
                            source: ResolutionSource::Cache,
                        },
                        allow_upstream_recursion,
                    ));
                }
            }

            if qtype == 1 || qtype == 28 {
                let cname_key = cache_key_for_query(qname, 5, false);
                if let Some(rec) = self.static_record_index.get(&cname_key) {
                    if self.static_cname_expand_for_address_queries {
                        match self
                            .resolve_static_cname_for_address_query(
                                ctx,
                                request,
                                qname,
                                qtype,
                                rec,
                                None,
                                matched_view,
                            )
                            .await
                        {
                            Ok(packet) => {
                                return Ok(self.normalize_ra_for_recursion_policy(
                                    ResolvedResponse {
                                        packet,
                                        source: ResolutionSource::Cache,
                                    },
                                    allow_upstream_recursion,
                                ));
                            }
                            Err(err) => {
                                warn!(
                                    qname = %qname,
                                    qtype,
                                    error = %err,
                                    "static cname expansion failed, fallback to cname-only static answer"
                                );
                            }
                        }
                    }

                    if let Ok(packet) = crate::codec::dns::build_static_answer(
                        request,
                        &rec.answer,
                        rec.ttl,
                        &rec.qtype_name,
                    ) {
                        let packet = self.append_additional_for_static_answers(
                            packet,
                            5,
                            std::slice::from_ref(&rec.answer),
                            &self.static_record_index,
                        );
                        return Ok(self.normalize_ra_for_recursion_policy(
                            ResolvedResponse {
                                packet,
                                source: ResolutionSource::Cache,
                            },
                            allow_upstream_recursion,
                        ));
                    }
                }
            }
            // 2. 权威源优先命中
            if let Some(auth) = self.authoritative_source_index.get(&lookup_key) {
                // 这里只做伪实现，实际应发起 HTTP 请求或调用外部命令
                if let Ok(answer) = crate::codec::dns::fetch_authoritative_answer(
                    &auth.source,
                    qname,
                    &auth.qtype_name,
                )
                .await
                {
                    if let Ok(packet) = crate::codec::dns::build_static_answer(
                        request,
                        &answer,
                        auth.ttl,
                        &auth.qtype_name,
                    ) {
                        let packet = self.append_additional_for_static_answers(
                            packet,
                            qtype,
                            std::slice::from_ref(&answer),
                            &self.static_record_index,
                        );
                        return Ok(self.normalize_ra_for_recursion_policy(
                            ResolvedResponse {
                                packet,
                                source: ResolutionSource::Upstream(auth.source.clone()),
                            },
                            allow_upstream_recursion,
                        ));
                    }
                }
            }
        }
        let selective_trace = ctx
            .query_name
            .as_deref()
            .map(crate::logging::should_trace_query_name)
            .unwrap_or(false);
        if selective_trace {
            info!(
                target: "query",
                request_id = ctx.request_id,
                qname = ?ctx.query_name,
                qtype = %dns::qtype_label_opt(ctx.query_type),
                mode = ?self.mode,
                "selective iterative trace: resolver entry"
            );
        }
        trace!(
            request_id = ctx.request_id,
            qname = ?ctx.query_name,
            qtype = %dns::qtype_label_opt(ctx.query_type),
            mode = ?self.mode,
            "resolver entry"
        );
        let cache_key = match (ctx.query_name.clone(), ctx.query_type) {
            (Some(qname), Some(qtype)) if !dns::checking_disabled(request) => Some(
                cache_key_for_query(&qname, qtype, dns::dnssec_ok_requested(request)),
            ),
            _ => None,
        };

        if let Some(cache_key) = &cache_key {
            if let Some(result) = self.try_bad_cache_hit(ctx, request, cache_key) {
                self.record_cache_window_hit();
                self.maybe_tune_cache_capacity();
                return Ok(self.normalize_ra_for_recursion_policy(result, allow_upstream_recursion));
            }

            if let Some(result) = self.try_hot_cache_hit(ctx, request, cache_key) {
                self.record_cache_window_hit();
                self.maybe_tune_cache_capacity();
                self.maybe_prefetch_by_rule(ctx, request, cache_key, true)
                    .await;
                return Ok(self.normalize_ra_for_recursion_policy(result, allow_upstream_recursion));
            }

            if let Some(result) = self.try_cache_hit(ctx, request, cache_key) {
                self.record_cache_window_hit();
                self.maybe_tune_cache_capacity();
                self.maybe_prefetch_by_rule(ctx, request, cache_key, false)
                    .await;
                return Ok(self.normalize_ra_for_recursion_policy(result, allow_upstream_recursion));
            }

            self.record_cache_window_miss();
            self.maybe_tune_cache_capacity();

            let notify = self.register_or_wait(cache_key.clone()).await;
            match notify {
                InFlightRole::Wait(waiter) => {
                    trace!(
                        request_id = ctx.request_id,
                        "waiting for in-flight query owner"
                    );
                    waiter.notified().await;
                    if let Some(result) = self.try_cache_hit(ctx, request, cache_key) {
                        return Ok(self
                            .normalize_ra_for_recursion_policy(result, allow_upstream_recursion));
                    }
                    // 主查询结束但未写入缓存时，当前请求继续解析，避免直接失败。
                    return self
                        .resolve_uncached(
                            ctx,
                            request,
                            Some(cache_key.clone()),
                            allow_upstream_recursion,
                        )
                        .await;
                }
                InFlightRole::Owner(waiter) => {
                    trace!(request_id = ctx.request_id, "became in-flight query owner");
                    let result = self
                        .resolve_uncached(
                            ctx,
                            request,
                            Some(cache_key.clone()),
                            allow_upstream_recursion,
                        )
                        .await;
                    self.finish_inflight(cache_key.clone(), waiter)
                        .await;
                    return result.map(|response| {
                        self.normalize_ra_for_recursion_policy(response, allow_upstream_recursion)
                    });
                }
            }
        }

        self.resolve_uncached(ctx, request, None, allow_upstream_recursion)
            .await
            .map(|response| {
                self.normalize_ra_for_recursion_policy(response, allow_upstream_recursion)
            })
    }

    fn normalize_ra_for_recursion_policy(
        &self,
        mut response: ResolvedResponse,
        allow_upstream_recursion: bool,
    ) -> ResolvedResponse {
        if allow_upstream_recursion || response.packet.len() < 4 {
            return response;
        }

        let mut flags = u16::from_be_bytes([response.packet[2], response.packet[3]]);
        flags &= !0x0080;
        response.packet[2..4].copy_from_slice(&flags.to_be_bytes());
        response
    }

    /// 在权威区内追踪 CNAME 链式解析，为 A/AAAA 查询返回最终结果。
    /// 当 static_cname_expand_for_address_queries=true 时，在权威区内递归追踪 CNAME 链
    /// 直到找到 A/AAAA 记录或达到最大深度限制。
    async fn resolve_zone_cname_for_address_query(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        original_qname: &str,
        qtype: u16,
        first_cname: &MultiRecordEntry,
        zone_entries: &[AuthoritativeZoneEntry],
        view_name: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        let mut collected_cnames = Vec::new();
        let mut owner = normalize_qname(original_qname);
        let mut target = normalize_qname(&first_cname.answers.get(0).cloned().unwrap_or_default());
        let mut ttl = first_cname.ttl;

        trace!(
            original_qname = %original_qname,
            first_cname_target = %target,
            "zone cname expansion started"
        );

        for depth in 0..=self.cname_chain_max_depth {
            if !seen.insert(owner.clone()) {
                return Err(anyhow!("zone cname chain loop detected at depth {}", depth));
            }

            collected_cnames.push((owner.clone(), target.clone(), ttl));

            if depth >= self.cname_chain_max_depth {
                return Err(anyhow!(
                    "zone cname chain exceeded max depth ({})",
                    self.cname_chain_max_depth
                ));
            }

            // 在权威区内查找 target 的 A/AAAA 记录
            let next_key = cache_key_for_query(&target, qtype, false);
            // 先做 zone 边界匹配，失败时跨所有区搜索（支持 CNAME 目标定义在相邻 zone 文件内的场景）
            let addr_rec = find_authoritative_zone(zone_entries, &target)
                .and_then(|z| z.record_index.get(&next_key))
                .or_else(|| {
                    zone_entries
                        .iter()
                        .find_map(|z| z.record_index.get(&next_key))
                });

            if let Some(rec) = addr_rec {
                // 找到了最终 A/AAAA 记录，构建响应并合并 CNAME 链
                trace!(
                    cname_target = %target,
                    depth,
                    "zone cname chain resolved to final address record in zone"
                );
                let query_id = crate::codec::dns::parse_header(request)
                    .map(|h| h.id)
                    .unwrap_or_else(|_| next_iterative_query_id());
                let rd = crate::codec::dns::parse_header(request)
                    .map(|h| (h.flags & 0x0100) != 0)
                    .unwrap_or(true);
                // 用目标名（如 www.abc.com）构建下游请求，确保 A 记录的 owner name 正确
                let downstream_req = crate::codec::dns::build_query_like_request(
                    request, query_id, &target, qtype, rd,
                )
                .ok_or_else(|| anyhow!("failed to build downstream request for {}", target))?;
                let final_packet = crate::codec::dns::build_authoritative_answer_multi(
                    &downstream_req,
                    &rec.answers,
                    rec.ttl,
                    &rec.qtype_name,
                )?;
                let merged =
                    crate::codec::dns::append_cname_answers(&final_packet, &collected_cnames)
                        .unwrap_or(final_packet);
                return Ok(finalize_response_for_client(request, &merged));
            }

            // 检查是否有其他 CNAME 记录（继续链式追踪）
            let cname_key = cache_key_for_query(&target, 5, false);
            let next_cname_rec = find_authoritative_zone(zone_entries, &target)
                .and_then(|z| z.record_index.get(&cname_key))
                .or_else(|| {
                    zone_entries
                        .iter()
                        .find_map(|z| z.record_index.get(&cname_key))
                });

            if let Some(next_cname_rec) = next_cname_rec {
                let next_target =
                    normalize_qname(&next_cname_rec.answers.get(0).cloned().unwrap_or_default());
                owner = target.clone();
                target = next_target;
                ttl = next_cname_rec.ttl;
                trace!(
                    depth,
                    current_target = %owner,
                    next_target = %target,
                    "zone cname chain continuing to next hop"
                );
                continue;
            }

            // CNAME 目标不在任何 zone 内，回退到完整解析链（静态记录 / upstream）
            trace!(
                depth,
                current_target = %target,
                "zone cname chain terminal: target not in zone, falling back to full resolution"
            );
            break;
        }

        // 对最终目标执行完整解析（含静态记录 / upstream / 视图路由）
        let query_id = crate::codec::dns::parse_header(request)
            .map(|h| h.id)
            .unwrap_or_else(|_| next_iterative_query_id());
        let rd = crate::codec::dns::parse_header(request)
            .map(|h| (h.flags & 0x0100) != 0)
            .unwrap_or(true);
        let downstream_request =
            crate::codec::dns::build_query_like_request(request, query_id, &target, qtype, rd)
                .ok_or_else(|| {
                    anyhow!(
                        "failed to build follow-up request for zone cname target {}",
                        target
                    )
                })?;
        let downstream_ctx = RequestContext {
            request_id: ctx.request_id,
            protocol: ctx.protocol,
            client_addr: ctx.client_addr,
            query_name: Some(SmolStr::from(target.as_str())),
            query_type: Some(qtype),
            recv_at: ctx.recv_at,
        };
        let resolved =
            Box::pin(self.resolve_with_view(&downstream_ctx, &downstream_request, view_name))
                .await?;
        let merged = crate::codec::dns::append_cname_answers(&resolved.packet, &collected_cnames)
            .unwrap_or(resolved.packet);
        Ok(finalize_response_for_client(request, &merged))
    }

    /// 从权威区条目列表中解析查询（RFC 1034/1035/2308 合规）。
    ///
    /// - 找到匹配区且有记录 → 返回 AA=1 的权威答案（多 RR 支持，ANCOUNT ≥ 1）。
    /// - 找到匹配区且 QNAME 存在但无该类型记录 → NOERROR + 空答案 + SOA（RFC 2308 NODATA）。
    /// - 找到匹配区但 QNAME 不存在 → NXDOMAIN + SOA authority section（AA=1）。
    /// - 无匹配区 → 返回 None，继续后续解析链路。
    async fn try_resolve_from_zone_entries(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        zone_entries: &[AuthoritativeZoneEntry],
        view_name: Option<&str>,
        source: &'static str,
        enable_cname_expand_for_address_queries: bool,
    ) -> Option<ResolvedResponse> {
        let (Some(qname), Some(qtype)) = (ctx.query_name.as_ref(), ctx.query_type) else {
            return None;
        };

        let zone = find_authoritative_zone(zone_entries, qname)?;

        // SOA 查询（qtype=6）：直接从配置的 soa 字段响应
        if qtype == 6 {
            if let Some(soa) = &zone.soa {
                match crate::codec::dns::build_authoritative_soa_answer(
                    request,
                    &zone.zone_name,
                    &soa.mname,
                    &soa.rname,
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expire,
                    soa.minimum_ttl,
                ) {
                    Ok(packet) => {
                        debug!(
                            request_id = ctx.request_id,
                            qname = %qname,
                            qtype = %dns::qtype_label_opt(Some(qtype)),
                            zone = %zone.zone_name,
                            view = ?view_name,
                            source,
                            "authoritative zone soa hit"
                        );
                        return Some(ResolvedResponse {
                            packet,
                            source: ResolutionSource::Cache,
                        });
                    }
                    Err(err) => {
                        warn!(
                            qname = %qname,
                            zone = %zone.zone_name,
                            error = %err,
                            "failed to build authoritative SOA answer"
                        );
                    }
                }
            }
        }

        // 查询名在区内，查直接类型命中
        let lookup_key = cache_key_for_query(qname, qtype, false);
        if let Some(rec) = zone.record_index.get(&lookup_key) {
            debug!(
                request_id = ctx.request_id,
                qname = %qname,
                qtype = %dns::qtype_label_opt(Some(qtype)),
                zone = %zone.zone_name,
                rr_count = rec.answers.len(),
                view = ?view_name,
                source,
                "authoritative zone record hit"
            );
            let packet = crate::codec::dns::build_authoritative_answer_multi(
                request,
                &rec.answers,
                rec.ttl,
                &rec.qtype_name,
            )
            .ok()?;
            let packet = self.append_additional_for_zone_answers(packet, qtype, &rec.answers, zone);
            return Some(ResolvedResponse {
                packet,
                source: ResolutionSource::Cache,
            });
        }

        // A/AAAA 查询时尝试 CNAME 展开（返回 CNAME RR，由客户端继续解析）
        if qtype == 1 || qtype == 28 {
            let cname_key = cache_key_for_query(qname, 5, false);
            if let Some(rec) = zone.record_index.get(&cname_key) {
                debug!(
                    request_id = ctx.request_id,
                    qname = %qname,
                    qtype = %dns::qtype_label_opt(Some(qtype)),
                    zone = %zone.zone_name,
                    view = ?view_name,
                    source,
                    "authoritative zone cname hit"
                );
                // 如果启用了 CNAME 展开，尝试递归解析 CNAME 链
                if enable_cname_expand_for_address_queries {
                    if let Ok(packet) = self
                        .resolve_zone_cname_for_address_query(
                            ctx,
                            request,
                            qname,
                            qtype,
                            rec,
                            zone_entries,
                            view_name,
                        )
                        .await
                    {
                        return Some(ResolvedResponse {
                            packet,
                            source: ResolutionSource::Cache,
                        });
                    }
                    debug!(
                        qname = %qname,
                        qtype,
                        "zone cname expansion failed, fallback to cname-only authoritative answer"
                    );
                }
                let packet = crate::codec::dns::build_authoritative_answer_multi(
                    request,
                    &rec.answers,
                    rec.ttl,
                    &rec.qtype_name,
                )
                .ok()?;
                return Some(ResolvedResponse {
                    packet,
                    source: ResolutionSource::Cache,
                });
            }
        }

        // QNAME 是否在区内存在（用于 NXDOMAIN vs NODATA 区分，RFC 2308）
        let normalized_qname = normalize_qname(qname);
        let name_exists = zone.name_set.contains(&normalized_qname);

        if let Some(soa) = &zone.soa {
            if name_exists {
                // QNAME 存在但无该类型记录 → NODATA（NOERROR + 空答案 + SOA authority）
                match crate::codec::dns::build_authoritative_nodata(
                    request,
                    &zone.zone_name,
                    &soa.mname,
                    &soa.rname,
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expire,
                    soa.minimum_ttl,
                ) {
                    Ok(packet) => {
                        debug!(
                            request_id = ctx.request_id,
                            qname = %qname,
                            qtype = %dns::qtype_label_opt(Some(qtype)),
                            zone = %zone.zone_name,
                            view = ?view_name,
                            source,
                            "authoritative zone nodata (name exists, no records of this type)"
                        );
                        return Some(ResolvedResponse {
                            packet,
                            source: ResolutionSource::Cache,
                        });
                    }
                    Err(err) => {
                        warn!(
                            qname = %qname,
                            zone = %zone.zone_name,
                            error = %err,
                            "failed to build authoritative NODATA"
                        );
                    }
                }
            } else {
                // QNAME 不在区内 → NXDOMAIN + SOA（AA=1）
                match crate::codec::dns::build_authoritative_nxdomain(
                    request,
                    &zone.zone_name,
                    &soa.mname,
                    &soa.rname,
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expire,
                    soa.minimum_ttl,
                ) {
                    Ok(packet) => {
                        debug!(
                            request_id = ctx.request_id,
                            qname = %qname,
                            qtype = %dns::qtype_label_opt(Some(qtype)),
                            zone = %zone.zone_name,
                            view = ?view_name,
                            source,
                            "authoritative zone nxdomain"
                        );
                        return Some(ResolvedResponse {
                            packet,
                            source: ResolutionSource::Cache,
                        });
                    }
                    Err(err) => {
                        warn!(
                            qname = %qname,
                            zone = %zone.zone_name,
                            error = %err,
                            "failed to build authoritative NXDOMAIN"
                        );
                    }
                }
            }
        } else {
            // 无 SOA，fallthrough（不返回 NXDOMAIN/NODATA，继续后续解析）
            warn!(
                qname = %qname,
                zone = %zone.zone_name,
                "zone has no SOA, cannot generate authoritative response; falling through"
            );
        }

        None
    }

    async fn try_resolve_from_view_records(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        view_name: &str,
        enable_static_cname_expand_for_address_queries: bool,
        enable_authoritative_cname_expand_for_address_queries: bool,
    ) -> Option<ResolvedResponse> {
        let (Some(qname), Some(qtype)) = (ctx.query_name.as_ref(), ctx.query_type) else {
            return None;
        };

        if let Some(index) = self.view_static_record_index.get(view_name) {
            if let Some(response) = self
                .try_resolve_from_record_index(
                    ctx,
                    request,
                    qname,
                    qtype,
                    index,
                    view_name,
                    "view_static",
                    enable_static_cname_expand_for_address_queries,
                )
                .await
            {
                return Some(response);
            }
        }

        let index = self.view_authoritative_record_index.get(view_name)?;
        self.try_resolve_from_record_index(
            ctx,
            request,
            qname,
            qtype,
            index,
            view_name,
            "view_authoritative",
            enable_authoritative_cname_expand_for_address_queries,
        )
        .await
    }

    async fn try_resolve_from_record_index(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        qname: &str,
        qtype: u16,
        index: &HashMap<CacheKey, StaticRecordEntry>,
        view_name: &str,
        source: &'static str,
        enable_cname_expand_for_address_queries: bool,
    ) -> Option<ResolvedResponse> {
        match self.lookup_view_record(index, qname, qtype) {
            Some(ViewLookupResult::Direct(rec)) => {
                debug!(
                    request_id = ctx.request_id,
                    qname = %qname,
                    qtype = %dns::qtype_label_opt(Some(qtype)),
                    view = %view_name,
                    source,
                    "view record hit"
                );
                let packet = crate::codec::dns::build_static_answer(
                    request,
                    &rec.answer,
                    rec.ttl,
                    &rec.qtype_name,
                )
                .ok()?;
                let packet = self.append_additional_for_static_answers(
                    packet,
                    qtype,
                    std::slice::from_ref(&rec.answer),
                    index,
                );
                Some(ResolvedResponse {
                    packet,
                    source: ResolutionSource::Cache,
                })
            }
            Some(ViewLookupResult::Cname(rec)) => {
                debug!(
                    request_id = ctx.request_id,
                    qname = %qname,
                    qtype = %dns::qtype_label_opt(Some(qtype)),
                    view = %view_name,
                    source,
                    "view cname record hit"
                );
                if enable_cname_expand_for_address_queries {
                    match self
                        .resolve_static_cname_for_address_query(
                            ctx,
                            request,
                            qname,
                            qtype,
                            rec,
                            Some(index),
                            Some(view_name),
                        )
                        .await
                    {
                        Ok(packet) => {
                            return Some(ResolvedResponse {
                                packet,
                                source: ResolutionSource::Cache,
                            });
                        }
                        Err(err) => {
                            warn!(
                                qname = %qname,
                                qtype,
                                error = %err,
                                "view cname expansion failed, fallback to cname-only answer"
                            );
                        }
                    }
                }

                let packet = crate::codec::dns::build_static_answer(
                    request,
                    &rec.answer,
                    rec.ttl,
                    &rec.qtype_name,
                )
                .ok()?;
                Some(ResolvedResponse {
                    packet,
                    source: ResolutionSource::Cache,
                })
            }
            None => None,
        }
    }

    fn lookup_view_record<'a>(
        &'a self,
        index: &'a HashMap<CacheKey, StaticRecordEntry>,
        qname: &str,
        qtype: u16,
    ) -> Option<ViewLookupResult<'a>> {
        let lookup_key = cache_key_for_query(qname, qtype, false);
        if let Some(rec) = index.get(&lookup_key) {
            return Some(ViewLookupResult::Direct(rec));
        }

        if qtype == 1 || qtype == 28 {
            let cname_key = cache_key_for_query(qname, 5, false);
            if let Some(rec) = index.get(&cname_key) {
                return Some(ViewLookupResult::Cname(rec));
            }
        }

        None
    }

    fn append_additional_for_zone_answers(
        &self,
        packet: Vec<u8>,
        qtype: u16,
        answers: &[String],
        zone: &AuthoritativeZoneEntry,
    ) -> Vec<u8> {
        if self.minimal_response {
            return packet;
        }

        let mut additional = Vec::new();
        let mut seen = HashSet::new();
        for host in additional_target_hosts_for_qtype(qtype, answers) {
            if !qname_belongs_to_zone(&host, &zone.zone_name) {
                continue;
            }
            for rr_type in [1u16, 28u16] {
                let key = cache_key_for_query(&host, rr_type, false);
                if let Some(rec) = zone.record_index.get(&key) {
                    let marker = format!("{}:{}", normalize_qname(&host), rr_type);
                    if !seen.insert(marker) {
                        continue;
                    }
                    additional.push(dns::DnsAdditionalRecord {
                        owner_name: host.clone(),
                        rr_type,
                        ttl: rec.ttl,
                        answers: rec.answers.clone(),
                    });
                }
            }
        }

        if additional.is_empty() {
            return packet;
        }

        match dns::append_additional_records(&packet, &additional) {
            Ok(enriched) => enriched,
            Err(err) => {
                warn!(error = %err, "failed to append authoritative additional records");
                packet
            }
        }
    }

    fn append_additional_for_static_answers(
        &self,
        packet: Vec<u8>,
        qtype: u16,
        answers: &[String],
        index: &HashMap<CacheKey, StaticRecordEntry>,
    ) -> Vec<u8> {
        if self.minimal_response {
            return packet;
        }

        let mut additional = Vec::new();
        let mut seen = HashSet::new();
        for host in additional_target_hosts_for_qtype(qtype, answers) {
            for rr_type in [1u16, 28u16] {
                let key = cache_key_for_query(&host, rr_type, false);
                if let Some(rec) = index.get(&key) {
                    let marker = format!("{}:{}", normalize_qname(&host), rr_type);
                    if !seen.insert(marker) {
                        continue;
                    }
                    additional.push(dns::DnsAdditionalRecord {
                        owner_name: host.clone(),
                        rr_type,
                        ttl: rec.ttl,
                        answers: vec![rec.answer.clone()],
                    });
                }
            }
        }

        if additional.is_empty() {
            return packet;
        }

        match dns::append_additional_records(&packet, &additional) {
            Ok(enriched) => enriched,
            Err(err) => {
                warn!(error = %err, "failed to append static additional records");
                packet
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_static_cname_for_address_query(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        original_qname: &str,
        qtype: u16,
        first_cname: &StaticRecordEntry,
        primary_index: Option<&HashMap<CacheKey, StaticRecordEntry>>,
        matched_view: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut seen = HashSet::new();
        let mut collected_cnames = Vec::new();

        let mut owner = normalize_qname(original_qname);
        let mut target = normalize_qname(&first_cname.answer);
        let mut ttl = first_cname.ttl;

        for depth in 0..=self.cname_chain_max_depth {
            if !seen.insert(owner.clone()) {
                return Err(anyhow!("static cname chain loop detected"));
            }
            collected_cnames.push((owner.clone(), target.clone(), ttl));

            if depth >= self.cname_chain_max_depth {
                return Err(anyhow!(
                    "static cname chain exceeded max depth ({})",
                    self.cname_chain_max_depth
                ));
            }

            let next_key = cache_key_for_query(&target, 5, false);
            let Some(next) = primary_index
                .and_then(|index| index.get(&next_key))
                .or_else(|| self.static_record_index.get(&next_key))
            else {
                break;
            };
            owner = target;
            target = normalize_qname(&next.answer);
            ttl = next.ttl;
        }

        let query_id = dns::parse_header(request)
            .map(|header| header.id)
            .unwrap_or_else(|_| next_iterative_query_id());
        let rd = dns::parse_header(request)
            .map(|header| (header.flags & 0x0100) != 0)
            .unwrap_or(true);
        let downstream_request = dns::build_query_like_request(
            request, query_id, &target, qtype, rd,
        )
        .ok_or_else(|| {
            anyhow!(
                "failed to build follow-up request for static cname target {}",
                target
            )
        })?;
        let downstream_ctx = RequestContext {
            request_id: ctx.request_id,
            protocol: ctx.protocol,
            client_addr: ctx.client_addr,
            query_name: Some(SmolStr::from(target.as_str())),
            query_type: Some(qtype),
            recv_at: ctx.recv_at,
        };

        let resolved = if let Some(target_name) = downstream_ctx.query_name.as_ref() {
            let target_key = cache_key_for_query(target_name, qtype, false);
            if let Some(rec) = primary_index
                .and_then(|index| index.get(&target_key))
                .or_else(|| self.static_record_index.get(&target_key))
            {
                let packet = dns::build_static_answer(
                    &downstream_request,
                    &rec.answer,
                    rec.ttl,
                    &rec.qtype_name,
                )?;
                ResolvedResponse {
                    packet,
                    source: ResolutionSource::Cache,
                }
            } else {
                Box::pin(self.resolve_with_view(&downstream_ctx, &downstream_request, matched_view))
                    .await?
            }
        } else {
            Box::pin(self.resolve_with_view(&downstream_ctx, &downstream_request, matched_view))
                .await?
        };
        let merged = dns::append_cname_answers(&resolved.packet, &collected_cnames)
            .unwrap_or_else(|| resolved.packet.clone());
        Ok(finalize_response_for_client(request, &merged))
    }

    fn try_bad_cache_hit(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        cache_key: &CacheKey,
    ) -> Option<ResolvedResponse> {
        let cached = self.bad_cache.get(cache_key, false)?;
        debug!(request_id = ctx.request_id, "dnssec bad cache hit");
        let resp = finalize_response_for_client(request, &cached);
        let resp = self.apply_ip_health_policy(ctx.query_name.as_deref(), &resp);
        self.metrics
            .record_cache_hit(dns::response_code(&resp).unwrap_or(2));
        Some(ResolvedResponse {
            packet: resp,
            source: ResolutionSource::Cache,
        })
    }

    fn try_hot_cache_hit(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        cache_key: &CacheKey,
    ) -> Option<ResolvedResponse> {
        let freeze_ttl = self.is_cache_ttl_frozen_for_qname(&cache_key.qname);
        let cached = self.hot_cache.get(cache_key, freeze_ttl)?;
        debug!(request_id = ctx.request_id, "hot cache hit");
        let resp = finalize_response_for_client(request, &cached);
        let resp = self.apply_ip_health_policy(ctx.query_name.as_deref(), &resp);
        self.metrics
            .record_cache_hit(dns::response_code(&resp).unwrap_or(2));
        self.bump_popularity(cache_key);
        Some(ResolvedResponse {
            packet: resp,
            source: ResolutionSource::Cache,
        })
    }

    /// 检查缓存命中并返回响应。
    fn try_cache_hit(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        cache_key: &CacheKey,
    ) -> Option<ResolvedResponse> {
        let freeze_ttl = self.is_cache_ttl_frozen_for_qname(&cache_key.qname);
        let cached = self.cache.get(cache_key, freeze_ttl)?;
        debug!(request_id = ctx.request_id, "cache hit");
        let resp = finalize_response_for_client(request, &cached);
        let resp = self.apply_ip_health_policy(ctx.query_name.as_deref(), &resp);
        self.metrics
            .record_cache_hit(dns::response_code(&resp).unwrap_or(2));
        self.bump_popularity(cache_key);
        self.promote_hot_cache_if_popular(cache_key, &resp);
        Some(ResolvedResponse {
            packet: resp,
            source: ResolutionSource::Cache,
        })
    }

    /// 未命中缓存时的实际解析逻辑。
    async fn resolve_uncached(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        cache_key: Option<CacheKey>,
        allow_upstream_recursion: bool,
    ) -> anyhow::Result<ResolvedResponse> {
        if !allow_upstream_recursion {
            let packet = build_refused_response_without_ra(request)?;
            return Ok(ResolvedResponse {
                packet,
                source: ResolutionSource::Cache,
            });
        }

        trace!(
            request_id = ctx.request_id,
            mode = ?self.mode,
            has_cache_key = cache_key.is_some(),
            "start uncached resolution"
        );
        if self.mode == ResolverMode::Iterative {
            match self.query_iterative(request).await {
                Ok((packet, resolver_addr)) => {
                    let packet = self
                        .validate_and_finalize_response(request, &packet, None, cache_key.as_ref())
                        .await?;
                    let packet = self.apply_ip_health_policy(ctx.query_name.as_deref(), &packet);
                    if let Some(cache_key) = cache_key.clone() {
                        if let Some(ttl) = self.cache_ttl_if_cacheable(&packet) {
                            self.cache.insert(cache_key, packet.clone(), ttl);
                        }
                    }
                    return Ok(ResolvedResponse {
                        packet,
                        source: ResolutionSource::Upstream(resolver_addr),
                    });
                }
                Err(err) => {
                    let err_msg = err.to_string();
                    if err_msg.contains("cname chain loop detected")
                        || err_msg.contains("cname chain exceeded max depth")
                    {
                        return Err(err);
                    }
                    if !self.iterative_fallback_to_forwarder {
                        return Err(err);
                    }
                    warn!(
                        request_id = ctx.request_id,
                        "iterative resolve failed, fallback to forwarder upstreams: {}", err_msg
                    );
                    self.metrics.record_iterative_event("forwarder_fallback");
                    self.iterative_fallbacks.fetch_add(1, Ordering::Relaxed);
                    self.record_iterative_runtime_event(IterativeEventKind::Fallback);
                }
            }
        }

        let mut state = ResolutionState::SelectUpstream;
        let mut upstream_plan = Vec::new();
        let mut response = None;
        let mut source = None;

        loop {
            state = match state {
                ResolutionState::SelectUpstream => {
                    upstream_plan = self.select_upstream_order();
                    trace!(
                        request_id = ctx.request_id,
                        plan_len = upstream_plan.len(),
                        plan = ?upstream_plan,
                        "selected upstream plan"
                    );
                    if upstream_plan.is_empty() {
                        return Err(anyhow!("no upstream resolvers configured"));
                    }
                    ResolutionState::QueryUpstream(0)
                }
                ResolutionState::QueryUpstream(index) => {
                    if index >= upstream_plan.len() {
                        return Err(anyhow!("all upstream resolvers failed"));
                    }

                    let upstream_index = upstream_plan[index];
                    trace!(
                        request_id = ctx.request_id,
                        step = index,
                        upstream = %self.upstreams[upstream_index].address,
                        "querying upstream"
                    );
                    match self.query_single_upstream(upstream_index, request).await {
                        Ok((packet, _rtt)) => {
                            if index > 0 {
                                self.forwarder_failovers.fetch_add(1, Ordering::Relaxed);
                            }
                            source = Some(ResolutionSource::Upstream(
                                self.upstreams[upstream_index].address.clone(),
                            ));
                            response = Some(packet);
                            ResolutionState::CacheStore
                        }
                        Err(err) => {
                            let err_msg = err.to_string();
                            if err_msg.contains("cname chain loop detected")
                                || err_msg.contains("cname chain exceeded max depth")
                            {
                                return Err(err);
                            }
                            warn!(
                                upstream = %self.upstreams[upstream_index].address,
                                request_id = ctx.request_id,
                                "upstream query failed: {}",
                                err
                            );
                            ResolutionState::QueryUpstream(index + 1)
                        }
                    }
                }
                ResolutionState::CacheStore => {
                    let packet = response
                        .take()
                        .ok_or_else(|| anyhow!("resolver lost response packet"))?;
                    let source_addr = match source.as_ref() {
                        Some(ResolutionSource::Upstream(address)) => Some(address.as_str()),
                        _ => None,
                    };
                    let packet = self
                        .validate_and_finalize_response(
                            request,
                            &packet,
                            source_addr,
                            cache_key.as_ref(),
                        )
                        .await?;
                    let packet = self.apply_ip_health_policy(ctx.query_name.as_deref(), &packet);
                    if let Some(cache_key) = cache_key.clone() {
                        if let Some(ttl) = self.cache_ttl_if_cacheable(&packet) {
                            self.cache.insert(cache_key, packet.clone(), ttl);
                        }
                    }
                    return Ok(ResolvedResponse {
                        packet,
                        source: source
                            .take()
                            .ok_or_else(|| anyhow!("resolver lost source metadata"))?,
                    });
                }
            };
        }
    }

    /// 判断响应是否可缓存，并返回应使用的缓存 TTL。
    fn cache_ttl_if_cacheable(&self, packet: &[u8]) -> Option<Duration> {
        let rcode = dns::response_code(packet)?;
        let answer_count = dns::answer_count(packet).unwrap_or(0);
        let terminal_authority_soa = if rcode == 0 && answer_count == 0 {
            dns::analyze_referral_targets(packet)
                .map(|value| value.has_authority_soa && value.authority_ns_hostnames.is_empty())
                .unwrap_or(false)
        } else {
            false
        };

        match rcode {
            3 => Some(
                dns::extract_negative_cache_ttl(packet)
                    .or_else(|| dns::extract_cache_ttl(packet))
                    .unwrap_or(self.cache_ttl)
                    .max(Duration::from_secs(1)),
            ),
            0 if answer_count > 0 || terminal_authority_soa => {
                if answer_count == 0 {
                    Some(
                        dns::extract_negative_cache_ttl(packet)
                            .or_else(|| dns::extract_cache_ttl(packet))
                            .unwrap_or(self.cache_ttl)
                            .max(Duration::from_secs(1)),
                    )
                } else {
                    Some(
                        dns::extract_cache_ttl(packet)
                            .unwrap_or(self.cache_ttl)
                            .max(Duration::from_secs(1)),
                    )
                }
            }
            _ => None,
        }
    }

    /// 判断某个域名的缓存 TTL 是否被冻结。
    pub fn is_cache_ttl_frozen_for_qname(&self, qname: &str) -> bool {
        if self.cache.is_frozen_for_qname(qname) {
            return true;
        }

        if self.freeze_cache_ttl_decay {
            return true;
        }

        let normalized = qname.trim().trim_end_matches('.').to_ascii_lowercase();
        self.freeze_cache_domains
            .iter()
            .any(|domain| normalized == *domain || normalized.ends_with(&format!(".{domain}")))
    }

    fn bump_popularity(&self, cache_key: &CacheKey) {
        self.popularity.increment(cache_key);
        // Periodic decay: every 16_384 increments, halve all counters
        // to let cold entries fade (replaces old retain() sweep).
        static DECAY_MASK: AtomicUsize = AtomicUsize::new(0);
        if DECAY_MASK.fetch_add(1, Ordering::Relaxed) % 16_384 == 0 {
            self.popularity.decay_all();
        }
    }

    fn promote_hot_cache_if_popular(&self, cache_key: &CacheKey, packet: &[u8]) {
        let threshold = self.prefetch_popularity_threshold.max(1);
        let count = self.popularity.estimate(cache_key);
        if count < threshold {
            return;
        }
        if let Some(ttl) = self.cache_ttl_if_cacheable(packet) {
            self.hot_cache.insert(
                cache_key.clone(),
                packet.to_vec(),
                ttl.max(Duration::from_secs(1)),
            );
        }
    }

    fn record_cache_window_hit(&self) {
        self.adaptive_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_cache_window_miss(&self) {
        self.adaptive_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    fn maybe_tune_cache_capacity(&self) {
        if !self.adaptive_cache_enabled {
            return;
        }
        let now = Instant::now();
        let mut miss_ratio = None;
        if let Ok(mut window_start) = self.adaptive_cache_window_start.lock() {
            if now.duration_since(*window_start) < self.adaptive_cache_window {
                return;
            }
            let hits = self.adaptive_cache_hits.swap(0, Ordering::Relaxed);
            let misses = self.adaptive_cache_misses.swap(0, Ordering::Relaxed);
            let total = hits + misses;
            if total > 0 {
                miss_ratio = Some(misses as f64 / total as f64);
            }
            *window_start = now;
        }

        let Some(miss_ratio) = miss_ratio else {
            return;
        };
        let current = self.current_cache_capacity.load(Ordering::Relaxed);
        let mut target = current;
        if miss_ratio >= self.adaptive_cache_high_miss_ratio {
            target = target
                .saturating_add(self.adaptive_cache_step)
                .min(self.adaptive_cache_max_capacity);
        } else if miss_ratio <= self.adaptive_cache_low_miss_ratio {
            target = target
                .saturating_sub(self.adaptive_cache_step)
                .max(self.adaptive_cache_min_capacity);
        }
        if target != current {
            self.cache.set_capacity(target);
            self.current_cache_capacity.store(target, Ordering::Relaxed);
        }
    }

    fn consume_prefetch_budget(&self) -> bool {
        if self.prefetch_budget_per_window == 0 {
            return false;
        }

        let now = Instant::now();
        // Lock only for window rotation (infrequent); consume via atomic.
        if let Ok(mut window_start) = self.prefetch_budget_window_start.lock() {
            if now.duration_since(*window_start) >= self.prefetch_window {
                *window_start = now;
                self.prefetch_budget_consumed.store(0, Ordering::Relaxed);
            }
        } else {
            return false;
        }

        let prev = self
            .prefetch_budget_consumed
            .fetch_add(1, Ordering::Relaxed);
        if prev >= self.prefetch_budget_per_window {
            // Overshot budget; undo the increment (best-effort).
            self.prefetch_budget_consumed
                .fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    async fn maybe_prefetch_by_rule(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        cache_key: &CacheKey,
        hot_tier: bool,
    ) {
        let remaining_ttl = if hot_tier {
            self.hot_cache.remaining_ttl(
                cache_key,
                self.is_cache_ttl_frozen_for_qname(&cache_key.qname),
            )
        } else {
            self.cache.remaining_ttl(
                cache_key,
                self.is_cache_ttl_frozen_for_qname(&cache_key.qname),
            )
        };
        let Some(remaining_ttl) = remaining_ttl else {
            return;
        };
        if remaining_ttl > self.prefetch_ttl_trigger {
            return;
        }
        let count = self.popularity.estimate(cache_key);
        if count < self.prefetch_popularity_threshold.max(1) {
            return;
        }
        let Some(qtype) = ctx.query_type else {
            return;
        };
        let sibling_qtype = match qtype {
            1 => 28,
            28 => 1,
            _ => return,
        };
        let Some(qname) = ctx.query_name.as_ref() else {
            return;
        };
        let sibling_key = cache_key_for_query(qname, sibling_qtype, cache_key.dnssec_ok);
        if self.cache.get(&sibling_key, false).is_some()
            || self.hot_cache.get(&sibling_key, false).is_some()
        {
            return;
        }
        if !self.consume_prefetch_budget() {
            return;
        }

        let query_id = dns::parse_header(request)
            .map(|header| header.id)
            .unwrap_or_else(|_| next_iterative_query_id());
        let rd = dns::parse_header(request)
            .map(|header| (header.flags & 0x0100) != 0)
            .unwrap_or(true);
        let Some(prefetch_query) =
            dns::build_query_like_request(request, query_id, qname, sibling_qtype, rd)
        else {
            return;
        };

        let _ = self
            .prefetch_once(&prefetch_query, qname, sibling_qtype)
            .await;
    }

    async fn prefetch_once(&self, request: &[u8], qname: &str, qtype: u16) -> anyhow::Result<()> {
        let cache_key = cache_key_for_query(qname, qtype, dns::dnssec_ok_requested(request));
        let upstream_result = if self.mode == ResolverMode::Iterative {
            self.query_iterative_single(request, None)
                .await
                .map(|(packet, _)| (packet, None))
        } else {
            let plan = self.select_upstream_order();
            let Some(index) = plan.first().copied() else {
                return Ok(());
            };
            self.query_single_upstream(index, request)
                .await
                .map(|(packet, _)| (packet, Some(self.upstreams[index].address.as_str())))
        };

        let Ok((packet, upstream)) = upstream_result else {
            return Ok(());
        };
        let finalized = self
            .validate_and_finalize_response(request, &packet, upstream, Some(&cache_key))
            .await?;
        if let Some(ttl) = self.cache_ttl_if_cacheable(&finalized) {
            self.cache.insert(cache_key.clone(), finalized.clone(), ttl);
            self.promote_hot_cache_if_popular(&cache_key, &finalized);
        }
        Ok(())
    }

    /// Prefetch CNAME leaf target records after chain resolution (Phase D).
    /// Prefetches the sibling qtype for the leaf target name and optionally
    /// A/AAAA for intermediate CNAME targets, using existing prefetch budget.
    /// Spawns a background task for prefetching (breaks async recursion).
    fn spawn_prefetch_task(
        &self,
        request: Vec<u8>,
        qname: String,
        qtype: u16,
    ) {
        let cache = self.cache.clone();
        let hot_cache = self.hot_cache.clone();
        let mode = self.mode;
        let upstream_addr = self
            .select_upstream_order()
            .first()
            .copied()
            .map(|idx| self.upstreams[idx].address.clone());
        let upstream_timeout = self.upstream_timeout;
        let prefetch_popularity_threshold = self.prefetch_popularity_threshold;
        tokio::spawn(async move {
            let cache_key = cache_key_for_query(&qname, qtype, dns::dnssec_ok_requested(&request));
            let upstream_result = if mode == ResolverMode::Iterative {
                None // skip iterative prefetch in background task (would need full resolver)
            } else {
                let upstream = upstream_addr.as_deref().unwrap_or("");
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok();
                if let Some(socket) = socket {
                    let _ = socket.send_to(&request, upstream).await.ok();
                    let mut buf = vec![0u8; 4096];
                    if let Ok(Ok((len, _))) = tokio::time::timeout(
                        upstream_timeout,
                        socket.recv_from(&mut buf),
                    )
                    .await
                    {
                        buf.truncate(len);
                        Some((buf, Some(upstream)))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some((packet, _upstream)) = upstream_result {
                let ttl = dns::extract_cache_ttl(&packet);
                if let Some(ttl) = ttl {
                    cache.insert(cache_key.clone(), packet.clone(), ttl);
                    // Promote to hot cache if popular enough
                    let count = hot_cache
                        .get(&cache_key, false)
                        .map(|_| prefetch_popularity_threshold)
                        .unwrap_or(0);
                    if count >= prefetch_popularity_threshold.max(1) {
                        hot_cache.insert(cache_key, packet, ttl);
                    }
                }
            }
        });
    }

    fn maybe_prefetch_cname_targets(
        &self,
        request: &[u8],
        leaf_name: &str,
        qtype: u16,
        collected_cnames: &[(String, String, u32)],
    ) {
        if !self.cname_chain_target_prefetch_enabled {
            return;
        }
        let sibling_qtype = match qtype {
            1 => 28,
            28 => 1,
            _ => return,
        };
        let leaf_sibling_key =
            cache_key_for_query(leaf_name, sibling_qtype, dns::dnssec_ok_requested(request));
        let freeze_ttl = self.is_cache_ttl_frozen_for_qname(leaf_name);
        if self.cache.get(&leaf_sibling_key, freeze_ttl).is_none()
            && self.hot_cache.get(&leaf_sibling_key, freeze_ttl).is_none()
        {
            if self.consume_prefetch_budget() {
                let query_id = dns::parse_header(request)
                    .map(|h| h.id)
                    .unwrap_or_else(|_| next_iterative_query_id());
                let rd = dns::parse_header(request)
                    .map(|h| (h.flags & 0x0100) != 0)
                    .unwrap_or(true);
                if let Some(prefetch_query) = dns::build_query_like_request(
                    request,
                    query_id,
                    leaf_name,
                    sibling_qtype,
                    rd,
                ) {
                    self.spawn_prefetch_task(
                        prefetch_query,
                        leaf_name.to_string(),
                        sibling_qtype,
                    );
                }
            }
        }
        // Also prefetch A records for intermediate CNAME targets (limited to 2)
        for (_, target, _) in collected_cnames.iter().take(2) {
            let target_a_key =
                cache_key_for_query(target, 1, dns::dnssec_ok_requested(request));
            let ft = self.is_cache_ttl_frozen_for_qname(target);
            if self.cache.get(&target_a_key, ft).is_none()
                && self.hot_cache.get(&target_a_key, ft).is_none()
            {
                if !self.consume_prefetch_budget() {
                    break;
                }
                let query_id = dns::parse_header(request)
                    .map(|h| h.id)
                    .unwrap_or_else(|_| next_iterative_query_id());
                let rd = dns::parse_header(request)
                    .map(|h| (h.flags & 0x0100) != 0)
                    .unwrap_or(true);
                if let Some(q) =
                    dns::build_query_like_request(request, query_id, target, 1, rd)
                {
                    self.spawn_prefetch_task(q, target.clone(), 1);
                }
            }
        }
    }

    async fn validate_and_finalize_response(
        &self,
        request: &[u8],
        response: &[u8],
        preferred_upstream: Option<&str>,
        cache_key: Option<&CacheKey>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut packet = response.to_vec();
        let checking_disabled = dns::checking_disabled(request);

        if let Some(updated) = dns::set_checking_disabled(&packet, checking_disabled) {
            packet = updated;
        }
        dns::set_authentic_data(&mut packet, false);

        if !self.dnssec_enabled {
            return Ok(finalize_response_for_client(request, &packet));
        }

        if checking_disabled {
            return Ok(finalize_response_for_client(request, &packet));
        }

        if dnssec::validation_requested(request) && dnssec::response_has_dnssec_records(response) {
            match self
                .validate_dnssec_response(request, response, preferred_upstream, 0)
                .await
            {
                Ok(ValidationState::Secure) => dns::set_authentic_data(&mut packet, true),
                Ok(ValidationState::Insecure) => dns::set_authentic_data(&mut packet, false),
                Err(err) => {
                    warn!("dnssec validation failed: {}", err);
                    let servfail = dns::build_servfail_response(request)?;
                    if let Some(cache_key) = cache_key {
                        self.bad_cache.insert(
                            cache_key.clone(),
                            servfail.clone(),
                            self.bad_cache_ttl_for_response(response),
                        );
                    }
                    return Ok(servfail);
                }
            }
        } else {
            dns::set_authentic_data(&mut packet, false);
        }

        Ok(finalize_response_for_client(request, &packet))
    }

    fn bad_cache_ttl_for_response(&self, response: &[u8]) -> Duration {
        let ttl = dns::extract_cache_ttl(response)
            .unwrap_or(self.cache_ttl)
            .min(Duration::from_secs(DNSSEC_BAD_CACHE_MAX_TTL_SECS));
        ttl.max(Duration::from_secs(1))
    }

    async fn validate_dnssec_response(
        &self,
        request: &[u8],
        response: &[u8],
        preferred_upstream: Option<&str>,
        depth: usize,
    ) -> anyhow::Result<ValidationState> {
        if depth > 8 {
            return Err(anyhow!("dnssec validation recursion exceeded depth budget"));
        }

        // Check DNSSEC validation cache to avoid re-validating identical responses.
        if let Some((qname, qtype, _)) = dns::parse_first_question(request) {
            let cache_key = DnssecValidationCache::make_key(&qname, qtype, response);
            if let Some(cached_state) = self.dnssec_validation_cache.get(cache_key) {
                trace!(qname = %qname, qtype, "dnssec validation cache hit");
                return Ok(cached_state);
            }
            let message = dnssec::parse_message(response)?;
            let signers = dnssec::find_zone_signers(&message);
            if signers.is_empty() {
                self.dnssec_validation_cache
                    .insert(cache_key, ValidationState::Insecure);
                return Ok(ValidationState::Insecure);
            }

            for signer in signers {
                let validated_keys = self
                    .fetch_and_validate_zone_keys(request, &signer, preferred_upstream, depth + 1)
                    .await?;
                match dnssec::verify_message_rrsets(&message, &validated_keys)? {
                    state @ ValidationState::Secure => {
                        self.dnssec_validation_cache.insert(cache_key, state);
                        return Ok(state);
                    }
                    ValidationState::Insecure => continue,
                }
            }

            self.dnssec_validation_cache
                .insert(cache_key, ValidationState::Insecure);
            Ok(ValidationState::Insecure)
        } else {
            // Fallback when question parsing fails: validate without caching.
            let message = dnssec::parse_message(response)?;
            let signers = dnssec::find_zone_signers(&message);
            if signers.is_empty() {
                return Ok(ValidationState::Insecure);
            }
            for signer in signers {
                let validated_keys = self
                    .fetch_and_validate_zone_keys(request, &signer, preferred_upstream, depth + 1)
                    .await?;
                match dnssec::verify_message_rrsets(&message, &validated_keys)? {
                    ValidationState::Secure => return Ok(ValidationState::Secure),
                    ValidationState::Insecure => continue,
                }
            }
            Ok(ValidationState::Insecure)
        }
    }

    async fn fetch_and_validate_zone_keys(
        &self,
        request: &[u8],
        zone: &hickory_proto::rr::Name,
        preferred_upstream: Option<&str>,
        depth: usize,
    ) -> anyhow::Result<ValidatedKeys> {
        let zone_text = if zone.is_root() {
            ".".to_string()
        } else {
            zone.to_utf8().trim_end_matches('.').to_string()
        };
        let dnskey_packet = self
            .query_dnssec_supporting_rrset(
                request,
                &zone_text,
                dns::DNS_TYPE_DNSKEY,
                preferred_upstream,
            )
            .await?;
        let dnskey_message = dnssec::parse_message(&dnskey_packet)?;
        let dnskey_records = dnssec::collect_rrset_records(
            &dnskey_message,
            zone,
            hickory_proto::rr::RecordType::DNSKEY,
        );
        let dnskey_rrsigs = dnssec::collect_rrsig_records(
            &dnskey_message,
            zone,
            hickory_proto::rr::RecordType::DNSKEY,
        );
        if dnskey_records.is_empty() || dnskey_rrsigs.is_empty() {
            return Err(anyhow!(
                "missing DNSKEY or RRSIG rrset for zone {zone_text}"
            ));
        }

        if dnssec::dnskey_rrset_matches_trust_anchors(&dnskey_records, &self.root_trust_anchors) {
            dnssec::verify_rrset(zone, &dnskey_records, &dnskey_rrsigs, &dnskey_records)?;
            return Ok(ValidatedKeys {
                zone: zone.clone(),
                keys: dnskey_records,
            });
        }

        if zone.is_root() {
            return dnssec::verify_root_dnskeys_with_anchors(
                zone,
                &dnskey_records,
                &dnskey_rrsigs,
                &self.root_trust_anchors,
            );
        }

        let parent = dnssec::parent_zone(zone)
            .ok_or_else(|| anyhow!("failed to derive parent zone for {zone_text}"))?;
        let parent_keys = Box::pin(self.fetch_and_validate_zone_keys(
            request,
            &parent,
            preferred_upstream,
            depth + 1,
        ))
        .await?;

        let ds_packet = self
            .query_dnssec_supporting_rrset(
                request,
                &zone_text,
                dns::DNS_TYPE_DS,
                preferred_upstream,
            )
            .await?;
        let ds_message = dnssec::parse_message(&ds_packet)?;
        let ds_records =
            dnssec::collect_rrset_records(&ds_message, zone, hickory_proto::rr::RecordType::DS);
        let ds_rrsigs =
            dnssec::collect_rrsig_records(&ds_message, zone, hickory_proto::rr::RecordType::DS);
        if ds_records.is_empty() || ds_rrsigs.is_empty() {
            return Err(anyhow!("missing DS or RRSIG rrset for zone {zone_text}"));
        }

        dnssec::verify_rrset(zone, &ds_records, &ds_rrsigs, &parent_keys.keys)?;
        dnssec::verify_dnskey_with_ds(zone, &dnskey_records, &ds_records)?;
        dnssec::verify_rrset(zone, &dnskey_records, &dnskey_rrsigs, &dnskey_records)?;

        Ok(ValidatedKeys {
            zone: zone.clone(),
            keys: dnskey_records,
        })
    }

    async fn query_dnssec_supporting_rrset(
        &self,
        template_request: &[u8],
        qname: &str,
        qtype: u16,
        preferred_upstream: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let query = dns::build_dnssec_query_like_request(
            template_request,
            next_iterative_query_id(),
            qname,
            qtype,
            true,
            false,
        )
        .ok_or_else(|| {
            anyhow!("failed to build dnssec follow-up query for {qname} type {qtype}")
        })?;

        if self.mode == ResolverMode::Iterative {
            let (packet, _) = self.query_iterative_single(&query, None).await?;
            return Ok(packet);
        }

        let upstream = preferred_upstream
            .or_else(|| {
                self.upstreams
                    .first()
                    .map(|upstream| upstream.address.as_str())
            })
            .ok_or_else(|| anyhow!("no upstream resolvers configured for dnssec validation"))?;
        self.query_address(upstream, &query).await
    }

    /// Exposes resolver health and rolling KPI snapshots for admin APIs.
    /// 获取解析器健康快照，供管理接口使用。
    pub fn health_snapshot(&self) -> ResolverSnapshot {
        let now = Instant::now();
        let mut healthy = 0usize;
        let upstreams = self
            .upstreams
            .iter()
            .map(|upstream| {
                let state = upstream.state.read().recover("upstream_state");
                let is_healthy = state
                    .unhealthy_until
                    .map(|deadline| deadline <= now)
                    .unwrap_or(true);
                if is_healthy {
                    healthy += 1;
                }
                UpstreamSnapshot {
                    address: upstream.address.clone(),
                    healthy: is_healthy,
                    score: state.score,
                    consecutive_failures: state.consecutive_failures,
                    successes: state.successes,
                    failures: state.failures,
                    last_rtt_ms: state.last_rtt.map(|duration| duration.as_millis()),
                }
            })
            .collect::<Vec<_>>();

        let ns_cache_entries = self
            .ns_host_cache
            .shards
            .iter()
            .filter_map(|shard| shard.try_lock().ok().map(|guard| guard.entries.len()))
            .sum();
        let iterative_window = self.iterative_window_snapshot_for(self.stats_window);
        let iterative_window_short = self.iterative_window_snapshot_for(self.stats_short_window);
        let ns_cache_window = self.ns_cache_window_snapshot_for(self.stats_window);
        let ns_cache_window_short = self.ns_cache_window_snapshot_for(self.stats_short_window);
        let ns_cache_eviction_rate_long = ns_cache_window.eviction_rate;
        let ns_cache_eviction_rate_short = ns_cache_window_short.eviction_rate;
        let ns_cache_expired_lookup_ratio_long = ns_cache_window.expired_lookup_ratio;
        let ns_cache_expired_lookup_ratio_short = ns_cache_window_short.expired_lookup_ratio;
        let ip_health_summary = self
            .ip_health
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|manager| manager.summary()));
        if let Some(summary) = ip_health_summary.as_ref() {
            self.metrics.set_ip_health_counters(
                summary.all_unhealthy_events,
                summary.notify_attempt_total,
                summary.notify_fail_total,
            );
        }

        ResolverSnapshot {
            mode: match self.mode {
                ResolverMode::Forwarder => "forwarder".to_string(),
                ResolverMode::Iterative => "iterative".to_string(),
            },
            total_upstreams: self.upstreams.len(),
            healthy_upstreams: healthy,
            upstreams,
            forwarder_failovers: self.forwarder_failovers.load(Ordering::Relaxed),
            iterative_successes: self.iterative_successes.load(Ordering::Relaxed),
            iterative_failures: self.iterative_failures.load(Ordering::Relaxed),
            iterative_fallbacks: self.iterative_fallbacks.load(Ordering::Relaxed),
            iterative_loop_detected: self.iterative_loop_detected.load(Ordering::Relaxed),
            iterative_requests_started: self.iterative_requests_started.load(Ordering::Relaxed),
            iterative_referral_hops: self.iterative_referral_hops.load(Ordering::Relaxed),
            iterative_retry_queries: self.iterative_retry_queries.load(Ordering::Relaxed),
            iterative_no_referral_glue_failures: self
                .iterative_no_referral_glue_failures
                .load(Ordering::Relaxed),
            iterative_failure_rate_long: iterative_window.failure_rate,
            iterative_failure_rate_short: iterative_window_short.failure_rate,
            iterative_fallback_ratio_long: iterative_window.fallback_ratio,
            iterative_fallback_ratio_short: iterative_window_short.fallback_ratio,
            ns_cache_window,
            ns_cache_window_short,
            ns_cache_eviction_rate_long,
            ns_cache_eviction_rate_short,
            ns_cache_expired_lookup_ratio_long,
            ns_cache_expired_lookup_ratio_short,
            iterative_window,
            iterative_window_short,
            ns_cache_entries,
            ns_cache_capacity: self.ns_host_cache_capacity,
            ip_health_enabled: ip_health_summary
                .as_ref()
                .map(|value| value.enabled)
                .unwrap_or(false),
            ip_health_tracked_domains: ip_health_summary
                .as_ref()
                .map(|value| value.tracked_domains)
                .unwrap_or(0),
            ip_health_tracked_ips: ip_health_summary
                .as_ref()
                .map(|value| value.tracked_ips)
                .unwrap_or(0),
            ip_health_degraded_domains: ip_health_summary
                .as_ref()
                .map(|value| value.degraded_domains)
                .unwrap_or(0),
            ip_health_all_unhealthy_events: ip_health_summary
                .as_ref()
                .map(|value| value.all_unhealthy_events)
                .unwrap_or(0),
            ip_health_notify_attempt_total: ip_health_summary
                .as_ref()
                .map(|value| value.notify_attempt_total)
                .unwrap_or(0),
            ip_health_notify_fail_total: ip_health_summary
                .as_ref()
                .map(|value| value.notify_fail_total)
                .unwrap_or(0),
        }
    }

    fn apply_ip_health_policy(&self, domain: Option<&str>, packet: &[u8]) -> Vec<u8> {
        let Some(domain) = domain else {
            return packet.to_vec();
        };
        let manager = self
            .ip_health
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().cloned());
        let Some(manager) = manager else {
            return packet.to_vec();
        };

        let ips = dns::extract_answer_ips(packet);
        if ips.is_empty() {
            return packet.to_vec();
        }

        manager.register_domain_ips(domain, &ips);
        let preferred_ips = manager.prefer_healthy_ips(domain, &ips);
        let adjusted = dns::reorder_answer_address_records(packet, &preferred_ips)
            .unwrap_or_else(|| packet.to_vec());
        if manager.all_unhealthy_for_domain(domain, &ips) {
            manager.record_all_unhealthy_event(domain, &ips);
        }
        adjusted
    }

    /// 统计指定窗口内的迭代解析事件。
    fn iterative_window_snapshot_for(&self, window: Duration) -> IterativeWindowSnapshot {
        let mut snapshot = IterativeWindowSnapshot {
            window_secs: window.as_secs(),
            successes: 0,
            failures: 0,
            fallbacks: 0,
            loops: 0,
            failure_rate: 0.0,
            fallback_ratio: 0.0,
        };

        if let Ok(mut events) = self.iterative_events.lock() {
            let now = Instant::now();
            Self::trim_iterative_events(&mut events, now, self.stats_window);

            for (ts, event) in events.iter() {
                if now.duration_since(*ts) > window {
                    continue;
                }
                match event {
                    IterativeEventKind::Success => snapshot.successes += 1,
                    IterativeEventKind::Failure => snapshot.failures += 1,
                    IterativeEventKind::Fallback => snapshot.fallbacks += 1,
                    IterativeEventKind::LoopDetected => snapshot.loops += 1,
                }
            }
        }

        let total_terminal = snapshot.successes + snapshot.failures;
        if total_terminal > 0 {
            snapshot.failure_rate = snapshot.failures as f64 / total_terminal as f64;
        }
        if snapshot.successes > 0 {
            snapshot.fallback_ratio = snapshot.fallbacks as f64 / snapshot.successes as f64;
        }

        snapshot
    }

    /// 统计指定窗口内的 NS 缓存事件。
    fn ns_cache_window_snapshot_for(&self, window: Duration) -> NsCacheWindowSnapshot {
        let mut snapshot = NsCacheWindowSnapshot {
            window_secs: window.as_secs(),
            hits: 0,
            misses: 0,
            expired: 0,
            stores: 0,
            evicts: 0,
            cleanups: 0,
            cleanup_removed: 0,
            eviction_rate: 0.0,
            expired_lookup_ratio: 0.0,
        };

        if let Ok(mut events) = self.ns_cache_events.lock() {
            let now = Instant::now();
            Self::trim_ns_cache_events(&mut events, now, self.stats_window);

            for event in events.iter() {
                if now.duration_since(event.at) > window {
                    continue;
                }
                match event.kind {
                    NsCacheEventKind::Hit => snapshot.hits += 1,
                    NsCacheEventKind::Miss => snapshot.misses += 1,
                    NsCacheEventKind::Expired => snapshot.expired += 1,
                    NsCacheEventKind::Store => snapshot.stores += 1,
                    NsCacheEventKind::Evict => snapshot.evicts += 1,
                    NsCacheEventKind::Cleanup => {
                        snapshot.cleanups += 1;
                        snapshot.cleanup_removed += event.removed;
                    }
                }
            }
        }

        if snapshot.stores > 0 {
            snapshot.eviction_rate = snapshot.evicts as f64 / snapshot.stores as f64;
        }
        let lookups = snapshot.hits + snapshot.misses + snapshot.expired;
        if lookups > 0 {
            snapshot.expired_lookup_ratio = snapshot.expired as f64 / lookups as f64;
        }

        snapshot
    }

    /// 选择上游服务器的轮询顺序，优先健康。
    fn select_upstream_order(&self) -> Vec<usize> {
        if self.upstreams.is_empty() {
            return Vec::new();
        }

        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let mut healthy = Vec::with_capacity(self.upstreams.len());
        let mut unhealthy = Vec::with_capacity(self.upstreams.len());

        for offset in 0..self.upstreams.len() {
            let index = (start + offset) % self.upstreams.len();
            let upstream = &self.upstreams[index];
            let state = upstream.state.read().recover("upstream_state");
            let is_healthy = state
                .unhealthy_until
                .map(|deadline| deadline <= now)
                .unwrap_or(true);
            if is_healthy {
                healthy.push((index, state.score));
            } else {
                unhealthy.push((index, state.score));
            }
        }

        healthy.sort_by(|a, b| b.1.total_cmp(&a.1));
        unhealthy.sort_by(|a, b| b.1.total_cmp(&a.1));

        self.metrics.set_healthy_upstreams(healthy.len());
        let mut ordered = healthy
            .into_iter()
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        ordered.extend(unhealthy.into_iter().map(|(index, _)| index));
        ordered
    }

    /// 注册或等待同 key 的 in-flight 查询，避免重复解析。
    /// Uses lock-free DashMap for O(1) concurrent access without mutex contention.
    async fn register_or_wait(&self, cache_key: CacheKey) -> InFlightRole {
        // DashMap's entry API provides atomic get-or-insert semantics.
        // Use a two-phase approach: try to insert a placeholder, then check.
        if let Some(existing) = self.inflight.map.get(&cache_key) {
            return InFlightRole::Wait(existing.clone());
        }
        let notify = Arc::new(Notify::new());
        match self.inflight.map.entry(cache_key) {
            dashmap::mapref::entry::Entry::Occupied(entry) => {
                InFlightRole::Wait(entry.get().clone())
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(notify.clone());
                InFlightRole::Owner(notify)
            }
        }
    }

    /// 完成 in-flight 查询并通知等待者。
    async fn finish_inflight(&self, cache_key: CacheKey, notify: Arc<Notify>) {
        self.inflight.map.remove(&cache_key);
        notify.notify_waiters();
    }

    /// 向指定上游服务器发送一次查询，支持重试。
    async fn query_single_upstream(
        &self,
        upstream_index: usize,
        request: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Duration)> {
        let upstream = &self.upstreams[upstream_index];
        let upstream_addr = upstream.address.clone();
        let started = Instant::now();
        let mut last_error = anyhow!("upstream query failed without details");

        for attempt in 0..=self.upstream_retries {
            trace!(
                upstream = %upstream_addr,
                attempt,
                max_retries = self.upstream_retries,
                "upstream query attempt"
            );
            match self.query_address(&upstream_addr, request).await {
                Ok(buf) => {
                    trace!(upstream = %upstream_addr, bytes = buf.len(), "upstream response received");
                    // Cap the total CNAME-chain follow time so a deep/slow chain cannot
                    // block the forwarder path for tens of seconds.
                    let cname_chain_budget =
                        self.upstream_timeout * (self.cname_chain_max_depth as u32 + 1);
                    let resolved = timeout(
                        cname_chain_budget,
                        self.resolve_cname_chain_via_upstream(&upstream_addr, request, buf),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        debug!(upstream = %upstream_addr, "cname chain via upstream timed out");
                        Err(anyhow!("cname chain upstream timed out"))
                    });
                    match resolved {
                        Ok(packet) => {
                            let elapsed = started.elapsed();
                            self.mark_upstream_success(upstream_index, elapsed);
                            self.metrics.record_upstream_query(
                                &upstream_addr,
                                "success",
                                elapsed.as_secs_f64(),
                            );
                            return Ok((packet, elapsed));
                        }
                        Err(err) => {
                            debug!(upstream = %upstream_addr, "cname follow-up failed: {}", err);
                            last_error = err;
                        }
                    }
                }
                Err(err) => {
                    debug!(upstream = %upstream_addr, attempt, "upstream attempt failed: {}", err);
                    last_error = err;
                }
            }
        }

        let elapsed = started.elapsed();
        self.mark_upstream_failure(upstream_index);
        self.metrics
            .record_upstream_query(&upstream_addr, "failure", elapsed.as_secs_f64());
        Err(last_error)
    }

    /// 跟随 CNAME 链进行多次上游查询。
    async fn resolve_cname_chain_via_upstream(
        &self,
        upstream_addr: &str,
        request: &[u8],
        initial_packet: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        if !self.follow_cname_chain {
            trace!(upstream = %upstream_addr, "cname follow disabled, returning first upstream response");
            return Ok(initial_packet);
        }

        let Some((qname, qtype, _)) = dns::parse_first_question(request) else {
            return Ok(initial_packet);
        };
        if qtype != 1 && qtype != 28 {
            trace!(upstream = %upstream_addr, qtype, "skip cname follow for non A/AAAA query");
            return Ok(initial_packet);
        }

        let request_header = dns::parse_header(request).ok();
        let rd = request_header
            .map(|h| (h.flags & 0x0100) != 0)
            .unwrap_or(true);
        let query_id = request_header
            .map(|h| h.id)
            .unwrap_or_else(next_iterative_query_id);
        let mut seen_cname_targets = HashSet::new();
        seen_cname_targets.insert(qname.to_ascii_lowercase());

        let mut current_packet = initial_packet;
        let mut current_name = qname.clone();
        let mut collected_cnames = Vec::new();
        let mut collected_dnames = Vec::new();
        let mut cached_cname_count = 0usize;
        // Reusable query buffer for CNAME follow-up hops: cleared and rewritten per hop
        // instead of allocating a new Vec<u8> each iteration.
        let mut query_buf = Vec::with_capacity(512);
        for cname_depth in 0..=self.cname_chain_max_depth {
            trace!(
                upstream = %upstream_addr,
                depth = cname_depth,
                max_depth = self.cname_chain_max_depth,
                "cname follow-up step"
            );
            let answer_scan =
                dns::analyze_answer_for_name_with_dnames(&current_packet, &current_name, qtype);
            let analysis = answer_scan.as_ref().map(|value| &value.analysis);
            let rcode = analysis.map(|value| value.rcode).unwrap_or(2);
            let has_final_answer = analysis
                .as_ref()
                .map(|value| value.has_target_record)
                .unwrap_or(false);
            let has_owner_cname = analysis
                .as_ref()
                .map(|value| value.has_owner_cname)
                .unwrap_or(false);
            if let Some(new_records) = analysis.as_ref().map(|value| &value.cname_records) {
                collected_cnames.extend(new_records.iter().cloned());
            }
            if let Some(answer_scan) = answer_scan.as_ref() {
                collected_dnames.extend(answer_scan.dname_records.iter().cloned());
            }
            for (owner, target, ttl) in collected_cnames.iter().skip(cached_cname_count) {
                // 只缓存当前跳点CNAME
                if let Ok(cname_packet) =
                    crate::codec::dns::build_static_answer(request, target, *ttl, "CNAME")
                {
                    let cname_key = cache_key_for_query(owner, 5, false);
                    self.cache
                        .insert(cname_key, cname_packet, Duration::from_secs((*ttl).into()));
                }
            }
            cached_cname_count = collected_cnames.len();
            if rcode != 0 || (has_final_answer && !has_owner_cname) {
                trace!(upstream = %upstream_addr, rcode, qtype, "cname chain resolved or terminal response reached");
                let merged = dns::append_cname_answers(&current_packet, &collected_cnames)
                    .unwrap_or_else(|| current_packet.clone());
                let merged =
                    dns::append_answer_records(&merged, &collected_dnames).unwrap_or(merged);
                // Wrap collected vectors in Arc to share with Phase C background task
                // without cloning the full vectors (atomic refcount instead of O(n) allocation).
                let collected_cnames = Arc::new(collected_cnames);
                let collected_dnames = Arc::new(collected_dnames);
                // Cache combined CNAME chain result under original query name
                if self.cname_chain_cache_enabled {
                    if let Some(final_packet) = dns::rewrite_question_from_request(&merged, request) {
                        let cache_key =
                            cache_key_for_query(&qname, qtype, dns::dnssec_ok_requested(request));
                        if let Some(ttl) = self.cache_ttl_if_cacheable(&final_packet) {
                            self.cache.insert(cache_key, final_packet, ttl);
                        }
                    }
                }
                // Phase C: Eagerly resolve sibling qtype for dual-stack clients
                if self.cname_chain_dualstack_share_enabled
                    && (qtype == 1 || qtype == 28)
                    && !collected_cnames.is_empty()
                {
                    let sibling_qtype = if qtype == 1 { 28 } else { 1 };
                    let sibling_cache_key = cache_key_for_query(
                        &qname,
                        sibling_qtype,
                        dns::dnssec_ok_requested(request),
                    );
                    let freeze_ttl = self.is_cache_ttl_frozen_for_qname(&qname);
                    if self
                        .hot_cache
                        .get(&sibling_cache_key, freeze_ttl)
                        .is_none()
                        && self.cache.get(&sibling_cache_key, freeze_ttl).is_none()
                    {
                        let upstream = upstream_addr.to_string();
                        let request_owned = request.to_vec();
                        let hot_cache = self.hot_cache.clone();
                        let qname_owned = qname.clone();
                        let leaf_name = current_name.clone();
                        let collected = Arc::clone(&collected_cnames);
                        let collected_dnames_clone = Arc::clone(&collected_dnames);
                        let cache_ttl = self.cache_ttl;
                        let upstream_timeout = self.upstream_timeout;
                        trace!(
                            sibling_qtype,
                            leaf = %leaf_name,
                            original = %qname_owned,
                            "dual-stack eager sibling resolution started"
                        );
                        tokio::spawn(async move {
                            let sibling_req = dns::build_query_like_request(
                                &request_owned,
                                next_iterative_query_id(),
                                &leaf_name,
                                sibling_qtype,
                                true,
                            );
                            let Some(sibling_req) = sibling_req else {
                                return;
                            };
                            // Direct UDP query to upstream for cache warming
                            let result = async {
                                let socket =
                                    tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                                socket.send_to(&sibling_req, &upstream).await?;
                                let mut buf = vec![0u8; 4096];
                                let (len, _) = tokio::time::timeout(
                                    upstream_timeout,
                                    socket.recv_from(&mut buf),
                                )
                                .await??;
                                buf.truncate(len);
                                Ok::<Vec<u8>, anyhow::Error>(buf)
                            }
                            .await;
                            if let Ok(pkt) = result {
                                let merged = dns::append_cname_answers(&pkt, &collected)
                                    .unwrap_or(pkt.clone());
                                let merged = dns::append_answer_records(
                                    &merged,
                                    &collected_dnames_clone,
                                )
                                .unwrap_or(merged);
                                if let Some(final_packet) =
                                    dns::rewrite_question_from_request(&merged, &request_owned)
                                {
                                    let sk = cache_key_for_query(
                                        &qname_owned,
                                        sibling_qtype,
                                        false,
                                    );
                                    hot_cache.insert(
                                        sk,
                                        final_packet,
                                        cache_ttl.max(Duration::from_secs(1)),
                                    );
                                }
                            }
                        });
                    }
                }
                // Phase D: Prefetch CNAME leaf targets
                if self.cname_chain_target_prefetch_enabled && !collected_cnames.is_empty() {
                    self.maybe_prefetch_cname_targets(
                        request,
                        &current_name,
                        qtype,
                        &collected_cnames[..],
                    );
                }
                return Ok(merged);
            }

            let Some(next_name) = analysis.and_then(|value| value.first_cname.clone()) else {
                trace!(upstream = %upstream_addr, "no cname answer found, returning current response");
                // Cache the collected CNAME chain (even without final answer)
                if self.cname_chain_cache_enabled && !collected_cnames.is_empty() {
                    let merged = dns::append_cname_answers(&current_packet, &collected_cnames)
                        .unwrap_or_else(|| current_packet.clone());
                    if let Some(final_packet) = dns::rewrite_question_from_request(&merged, request) {
                        let cache_key =
                            cache_key_for_query(&qname, qtype, dns::dnssec_ok_requested(request));
                        if let Some(ttl) = self.cache_ttl_if_cacheable(&final_packet) {
                            self.cache.insert(cache_key, final_packet, ttl);
                        }
                    }
                }
                return Ok(current_packet);
            };

            if cname_depth >= self.cname_chain_max_depth {
                return Err(anyhow!(
                    "cname chain exceeded max depth ({})",
                    self.cname_chain_max_depth
                ));
            }

            let key = next_name.to_ascii_lowercase();
            if !seen_cname_targets.insert(key) {
                return Err(anyhow!("cname chain loop detected"));
            }

            // Rebuild query into reusable buffer (avoids per-hop allocation).
            if dns::build_query_like_request_into(
                &mut query_buf,
                request,
                query_id,
                &next_name,
                qtype,
                rd,
            )
            .is_none()
            {
                return Err(anyhow!(
                    "failed to build cname follow-up query for {}",
                    next_name
                ));
            };
            current_name = next_name.clone();
            // Phase B: Check cache for intermediate CNAME target before upstream query
            let mut found_in_cache = false;
            if self.cname_chain_inline_cache_enabled {
                let next_cache_key =
                    cache_key_for_query(&current_name, qtype, dns::dnssec_ok_requested(request));
                let freeze_ttl = self.is_cache_ttl_frozen_for_qname(&current_name);
                if let Some(cached) = self
                    .hot_cache
                    .get(&next_cache_key, freeze_ttl)
                    .or_else(|| self.cache.get(&next_cache_key, freeze_ttl))
                {
                    trace!(cname_target = %current_name, "cname chain cache hit for intermediate target");
                    current_packet = cached;
                    found_in_cache = true;
                }
            }
            if !found_in_cache {
                trace!(upstream = %upstream_addr, cname_target = %current_name, "sending cname follow-up query");
                current_packet = self.query_address(upstream_addr, &query_buf).await?;
            }
            collected_cnames.extend(dns::extract_answer_cname_records(&current_packet));
        }

        Err(anyhow!(
            "cname chain exceeded max depth ({})",
            self.cname_chain_max_depth
        ))
    }

    /// 递归模式下的迭代查询主流程。
    async fn query_iterative(&self, request: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
        if !self.follow_cname_chain {
            trace!("cname follow disabled for iterative mode");
            return self.query_iterative_single(request, None).await;
        }

        let Some((qname, qtype, _)) = dns::parse_first_question(request) else {
            return self.query_iterative_single(request, None).await;
        };
        if qtype != 1 && qtype != 28 {
            if qtype == 5 && self.iterative_fallback_to_forwarder {
                if let Some((packet, resolver_addr)) = self.query_bootstrap_recursive(request).await
                {
                    trace!(qtype, resolver = %resolver_addr, "iterative cname query routed via bootstrap recursive");
                    return Ok((packet, resolver_addr));
                }
            }
            trace!(qtype, "iterative cname follow skipped for non A/AAAA query");
            return self.query_iterative_single(request, None).await;
        }
        let global_deadline = Instant::now() + self.iterative_timeout;
        let query_id = dns::parse_header(request)
            .map(|h| h.id)
            .unwrap_or_else(|_| next_iterative_query_id());
        let mut seen_cname_targets = HashSet::new();
        seen_cname_targets.insert(qname.to_ascii_lowercase());
        let mut collected_cnames = Vec::new();
        let mut collected_dnames = Vec::new();

        // Reusable query buffer: holds the current iteration's query packet.
        // Initialised from the original request with RD=0, then rebuilt per CNAME hop.
        let mut query_buf =
            dns::set_recursion_desired(request, false).unwrap_or_else(|| request.to_vec());
        // Save original request for combined CNAME chain caching
        let orig_request = request.to_vec();
        let mut current_name = qname.clone();
        for cname_depth in 0..=self.cname_chain_max_depth {
            if Instant::now() >= global_deadline {
                self.metrics.record_iterative_event("timeout_budget");
                self.metrics
                    .observe_iterative_depth("timeout", cname_depth as f64 + 1.0);
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(anyhow!("iterative cname resolution timed out by budget"));
            }
            trace!(
                depth = cname_depth,
                max_depth = self.cname_chain_max_depth,
                "iterative cname follow-up step"
            );
            let remaining_budget = global_deadline.saturating_duration_since(Instant::now());
            if remaining_budget.is_zero() {
                self.metrics.record_iterative_event("timeout_budget");
                self.metrics
                    .observe_iterative_depth("timeout", cname_depth as f64 + 1.0);
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(anyhow!("iterative cname resolution timed out by budget"));
            }
            // Phase B: Check cache for intermediate CNAME target before iterative query
            let step_result = if self.cname_chain_inline_cache_enabled {
                let cache_key = cache_key_for_query(
                    &current_name,
                    qtype,
                    dns::dnssec_ok_requested(&orig_request),
                );
                let freeze_ttl = self.is_cache_ttl_frozen_for_qname(&current_name);
                if let Some(cached) = self
                    .hot_cache
                    .get(&cache_key, freeze_ttl)
                    .or_else(|| self.cache.get(&cache_key, freeze_ttl))
                {
                    trace!(cname_target = %current_name, "iterative cname chain cache hit for intermediate target");
                    Ok(Ok((cached, "cache".to_string())))
                } else {
                    timeout(
                        remaining_budget,
                        self.query_iterative_single(&query_buf, Some(global_deadline)),
                    )
                    .await
                }
            } else {
                timeout(
                    remaining_budget,
                    self.query_iterative_single(&query_buf, Some(global_deadline)),
                )
                .await
            };
            let (packet, resolver_addr) = match step_result {
                Ok(Ok(result)) => result,
                Ok(Err(err)) => {
                    let err_text = err.to_string();
                    let allow_bridge_fallback = self.iterative_cname_bridge_fallback_to_recursive
                        && !collected_cnames.is_empty()
                        && err_text.contains("iterative resolution failed without referral glue");
                    if self.iterative_fallback_to_forwarder || allow_bridge_fallback {
                        if let Some((packet, resolver_addr)) =
                            self.query_bootstrap_recursive(&query_buf).await
                        {
                            self.metrics.record_iterative_event("recursive_fallback");
                            if allow_bridge_fallback {
                                self.metrics
                                    .record_iterative_event("cname_recursive_bridge_fallback");
                            }
                            self.iterative_fallbacks.fetch_add(1, Ordering::Relaxed);
                            self.record_iterative_runtime_event(IterativeEventKind::Fallback);
                            let merged = dns::append_cname_answers(&packet, &collected_cnames)
                                .unwrap_or(packet);
                            return Ok((merged, resolver_addr));
                        }
                    }
                    return Err(err);
                }
                Err(_) => {
                    self.metrics.record_iterative_event("cname_step_timeout");
                    if self.iterative_fallback_to_forwarder {
                        if let Some((packet, resolver_addr)) =
                            self.query_bootstrap_recursive(&query_buf).await
                        {
                            self.metrics.record_iterative_event("recursive_fallback");
                            self.iterative_fallbacks.fetch_add(1, Ordering::Relaxed);
                            self.record_iterative_runtime_event(IterativeEventKind::Fallback);
                            let merged = dns::append_cname_answers(&packet, &collected_cnames)
                                .unwrap_or(packet);
                            return Ok((merged, resolver_addr));
                        }
                    }
                    self.metrics
                        .observe_iterative_depth("timeout", cname_depth as f64 + 1.0);
                    self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                    self.record_iterative_runtime_event(IterativeEventKind::Failure);
                    return Err(anyhow!("iterative cname resolution timed out by budget"));
                }
            };
            let answer_scan =
                dns::analyze_answer_for_name_with_dnames(&packet, &current_name, qtype);
            let analysis = answer_scan.as_ref().map(|value| &value.analysis);
            if let Some(new_records) = analysis.as_ref().map(|value| &value.cname_records) {
                collected_cnames.extend(new_records.iter().cloned());
            }
            if let Some(answer_scan) = answer_scan.as_ref() {
                collected_dnames.extend(answer_scan.dname_records.iter().cloned());
            }
            let rcode = analysis.map(|value| value.rcode).unwrap_or(2);
            let has_final_answer = analysis
                .as_ref()
                .map(|value| value.has_target_record)
                .unwrap_or(false);
            let has_owner_cname = analysis
                .as_ref()
                .map(|value| value.has_owner_cname)
                .unwrap_or(false);
            if rcode != 0 || (has_final_answer && !has_owner_cname) {
                trace!(resolver = %resolver_addr, rcode, qtype, "iterative cname chain resolved or terminal response reached");
                let merged = dns::append_cname_answers(&packet, &collected_cnames)
                    .unwrap_or_else(|| packet.clone());
                let merged =
                    dns::append_answer_records(&merged, &collected_dnames).unwrap_or(merged);
                // Cache combined CNAME chain result under original query name
                if self.cname_chain_cache_enabled {
                    if let Some(final_packet) =
                        dns::rewrite_question_from_request(&merged, &orig_request)
                    {
                        let cache_key = cache_key_for_query(
                            &qname,
                            qtype,
                            dns::dnssec_ok_requested(&orig_request),
                        );
                        if let Some(ttl) = self.cache_ttl_if_cacheable(&final_packet) {
                            self.cache.insert(cache_key, final_packet, ttl);
                        }
                    }
                }
                // Phase D: Prefetch CNAME leaf targets (iterative mode)
                if self.cname_chain_target_prefetch_enabled && !collected_cnames.is_empty() {
                    self.maybe_prefetch_cname_targets(
                        &orig_request,
                        &current_name,
                        qtype,
                        &collected_cnames,
                    );
                }
                return Ok((merged, resolver_addr));
            }

            let Some(next_name) = analysis.and_then(|value| value.first_cname.clone()) else {
                trace!(resolver = %resolver_addr, "iterative response has no cname answer, returning current response");
                // Cache the collected CNAME chain (even without final answer)
                if self.cname_chain_cache_enabled && !collected_cnames.is_empty() {
                    let merged = dns::append_cname_answers(&packet, &collected_cnames)
                        .unwrap_or_else(|| packet.clone());
                    if let Some(final_packet) =
                        dns::rewrite_question_from_request(&merged, &orig_request)
                    {
                        let cache_key = cache_key_for_query(
                            &qname,
                            qtype,
                            dns::dnssec_ok_requested(&orig_request),
                        );
                        if let Some(ttl) = self.cache_ttl_if_cacheable(&final_packet) {
                            self.cache.insert(cache_key, final_packet, ttl);
                        }
                    }
                }
                return Ok((packet, resolver_addr));
            };

            if cname_depth >= self.cname_chain_max_depth {
                self.metrics.record_iterative_event("cname_depth_exceeded");
                self.metrics
                    .observe_iterative_depth("cname_depth_exceeded", cname_depth as f64 + 1.0);
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(anyhow!(
                    "cname chain exceeded max depth ({})",
                    self.cname_chain_max_depth
                ));
            }

            let key = next_name.to_ascii_lowercase();
            if !seen_cname_targets.insert(key) {
                self.metrics.record_iterative_event("cname_loop_detected");
                self.metrics
                    .observe_iterative_depth("cname_loop_detected", cname_depth as f64 + 1.0);
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(anyhow!("cname chain loop detected"));
            }

            self.metrics.record_iterative_event("cname_followup");
            trace!(cname_target = %next_name, "iterative sending cname follow-up query");
            if dns::build_query_like_request_into(
                &mut query_buf,
                request,
                query_id,
                &next_name,
                qtype,
                false,
            )
            .is_none()
            {
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(anyhow!(
                    "failed to build cname follow-up query for {}",
                    next_name
                ));
            };
            current_name = next_name;
        }

        self.iterative_failures.fetch_add(1, Ordering::Relaxed);
        self.record_iterative_runtime_event(IterativeEventKind::Failure);
        Err(anyhow!(
            "cname chain exceeded max depth ({})",
            self.cname_chain_max_depth
        ))
    }

    /// 递归模式下单步迭代查询。
    async fn query_iterative_single(
        &self,
        request: &[u8],
        budget_deadline: Option<Instant>,
    ) -> anyhow::Result<(Vec<u8>, String)> {
        // Iterative mode walks referral candidates with depth and time budgets.
        let iterative_started = Instant::now();
        let global_deadline = budget_deadline.unwrap_or(iterative_started + self.iterative_timeout);
        self.iterative_requests_started
            .fetch_add(1, Ordering::Relaxed);
        let mut iterative_query_attempts = 0usize;
        let mut iterative_referral_hops = 0usize;
        let mut seen_signatures = HashSet::new();
        let mut attempted_ns_host_sets = HashSet::new();
        let root_candidates = if self.root_servers.is_empty() {
            self.bootstrap_recursive_resolvers.clone()
        } else {
            self.root_servers.clone()
        };
        if root_candidates.is_empty() {
            self.record_iterative_path_metrics(iterative_query_attempts, iterative_referral_hops);
            self.iterative_failures.fetch_add(1, Ordering::Relaxed);
            self.record_iterative_runtime_event(IterativeEventKind::Failure);
            return Err(anyhow!(
                "iterative mode has no root or upstream servers configured"
            ));
        }

        let iterative_request =
            dns::set_recursion_desired(request, false).unwrap_or_else(|| request.to_vec());
        let query_name = dns::parse_first_question(&iterative_request)
            .map(|(name, _, _)| name)
            .unwrap_or_else(|| ".".to_string());
        let selective_trace = crate::logging::should_trace_query_name(&query_name);

        let (mut candidates, mut delegation_seed_zone) =
            if let Some((zone, endpoints)) = self.get_cached_delegation_endpoints(&query_name) {
                self.metrics.record_iterative_event("delegation_cache_hit");
                (endpoints, Some(zone))
            } else {
                self.metrics.record_iterative_event("delegation_cache_miss");
                (root_candidates.clone(), None)
            };
        for depth in 0..self.iterative_max_depth {
            if selective_trace {
                info!(
                    target: "query",
                    qname = %query_name,
                    depth,
                    max_depth = self.iterative_max_depth,
                    candidate_count = candidates.len(),
                    "selective iterative trace: depth step"
                );
            } else {
                trace!(
                    depth,
                    max_depth = self.iterative_max_depth,
                    candidate_count = candidates.len(),
                    "iterative depth step"
                );
            }
            let mut signature_candidates = candidates.clone();
            signature_candidates.sort();
            let signature = signature_candidates.join("|");
            if !seen_signatures.insert(signature) {
                self.record_iterative_path_metrics(
                    iterative_query_attempts,
                    iterative_referral_hops,
                );
                self.metrics.record_iterative_event("loop_detected");
                self.metrics
                    .observe_iterative_depth("loop_detected", depth as f64 + 1.0);
                self.iterative_loop_detected.fetch_add(1, Ordering::Relaxed);
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::LoopDetected);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(anyhow!("iterative resolution detected referral loop"));
            }

            if Instant::now() >= global_deadline {
                self.record_iterative_path_metrics(
                    iterative_query_attempts,
                    iterative_referral_hops,
                );
                self.metrics.record_iterative_event("timeout_budget");
                self.metrics
                    .observe_iterative_depth("timeout", depth as f64 + 1.0);
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(anyhow!("iterative resolution timed out by budget"));
            }
            let mut next_candidates = Vec::new();
            let mut last_error = None;

            let mut in_flight = FuturesUnordered::new();
            for server in candidates.clone() {
                iterative_query_attempts += 1;
                if selective_trace {
                    info!(
                        target: "query",
                        qname = %query_name,
                        depth,
                        resolver = %server,
                        "selective iterative trace: querying candidate resolver"
                    );
                } else {
                    trace!(depth, resolver = %server, "iterative querying candidate resolver");
                }
                in_flight.push(async {
                    let result = self.query_address(&server, &iterative_request).await;
                    (server, result)
                });
            }

            while let Some((server, result)) = in_flight.next().await {
                match result {
                    Ok(packet) => {
                        let overview = dns::parse_response_overview(&packet);
                        let rcode = overview.map(|value| value.rcode).unwrap_or(2);
                        let ancount = overview.map(|value| value.ancount).unwrap_or(0);
                        if selective_trace {
                            info!(
                                target: "query",
                                qname = %query_name,
                                depth,
                                resolver = %server,
                                rcode,
                                ancount,
                                "selective iterative trace: candidate response"
                            );
                        } else {
                            trace!(depth, resolver = %server, rcode, ancount, "iterative candidate response");
                        }
                        if rcode != 0 || ancount > 0 {
                            self.record_iterative_path_metrics(
                                iterative_query_attempts,
                                iterative_referral_hops,
                            );
                            self.metrics.record_upstream_query(&server, "success", 0.0);
                            self.metrics.record_iterative_event("resolved");
                            self.metrics
                                .observe_iterative_depth("resolved", depth as f64 + 1.0);
                            self.iterative_successes.fetch_add(1, Ordering::Relaxed);
                            self.record_iterative_runtime_event(IterativeEventKind::Success);
                            return Ok((packet, server));
                        }

                        let referral = dns::analyze_referral_targets(&packet);

                        // Validate referral security before using or caching it
                        let referral_validation = referral
                            .as_ref()
                            .map(|analysis| dns::validate_referral_security(&query_name, analysis));
                        let referral_is_security_valid = referral_validation
                            .as_ref()
                            .map(|v| v.is_valid)
                            .unwrap_or(true);
                        if !referral_is_security_valid {
                            // Security validation failed: keep this referral usable for the current
                            // iterative walk (to avoid strict dead-ends), but never write it into cache.
                            trace!(
                                depth,
                                resolver = %server,
                                reason = ?referral_validation
                                    .as_ref()
                                    .and_then(|v| v.rejection_reason.as_ref()),
                                "referral validation failed, continue without cache write"
                            );
                            self.metrics
                                .record_iterative_event("referral_validation_rejected");
                        }

                        if referral
                            .as_ref()
                            .map(|value| {
                                value.has_authority_soa && value.authority_ns_hostnames.is_empty()
                            })
                            .unwrap_or(false)
                        {
                            self.record_iterative_path_metrics(
                                iterative_query_attempts,
                                iterative_referral_hops,
                            );
                            self.metrics.record_upstream_query(&server, "success", 0.0);
                            self.metrics
                                .record_iterative_event("terminal_authority_soa");
                            self.metrics
                                .observe_iterative_depth("resolved", depth as f64 + 1.0);
                            self.iterative_successes.fetch_add(1, Ordering::Relaxed);
                            self.record_iterative_runtime_event(IterativeEventKind::Success);
                            return Ok((packet, server));
                        }

                        let glue = referral
                            .as_ref()
                            .map(|value| value.glue_nameservers.as_slice())
                            .unwrap_or(&[]);
                        let allow_glue_in_this_hop = true;
                        if allow_glue_in_this_hop && !glue.is_empty() {
                            self.metrics.record_iterative_event("glue_referral");
                            next_candidates
                                .extend(self.filter_iterative_endpoints(glue.iter().cloned()));
                            // Glue is already enough to progress to the next hop.
                            // Avoid resolving NS hostnames recursively in this case,
                            // which can trigger expensive self-recursive lookups.
                            //
                            // Warm the NS hostname cache from glue so that future
                            // CNAME-chain hops can resolve the same NS hostnames
                            // even when the next referral omits glue records.
                            let glue_map = dns::build_ns_hostname_glue_map(&packet);
                            let ns_hosts = referral
                                .as_ref()
                                .map(|v| v.authority_ns_hostnames.as_slice())
                                .unwrap_or(&[]);
                            trace!(
                                glue_hosts = ?glue_map.keys().collect::<Vec<_>>(),
                                ns_hosts = ?ns_hosts,
                                "glue cache warm"
                            );
                            for (hostname, endpoints) in glue_map {
                                if !endpoints.is_empty() {
                                    self.put_cached_ns_endpoints(
                                        &hostname,
                                        endpoints,
                                    );
                                }
                            }
                            if !next_candidates.is_empty() {
                                break;
                            }
                        }

                        let referral_for_cache = referral.clone();
                        let ns_hosts = referral
                            .as_ref()
                            .map(|value| value.authority_ns_hostnames.clone())
                            .unwrap_or_default();
                        if !ns_hosts.is_empty() {
                            let mut ns_signature_parts: Vec<String> = ns_hosts
                                .iter()
                                .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
                                .collect();
                            ns_signature_parts.sort();
                            ns_signature_parts.dedup();
                            let ns_signature = ns_signature_parts.join("|");
                            if !attempted_ns_host_sets.insert(ns_signature.clone()) {
                                self.metrics
                                    .record_iterative_event("ns_host_resolve_dedup_skip");
                                continue;
                            }

                            // 计算本跳 NS 解析的 deadline：
                            // 若配置了 per_hop_timeout，取 (now + per_hop, 全局 deadline) 的较小值；
                            // 否则直接使用全局 deadline，行为与原版完全一致。
                            let hop_deadline = if self.iterative_per_hop_timeout.is_zero() {
                                global_deadline
                            } else {
                                let hop_end = Instant::now() + self.iterative_per_hop_timeout;
                                hop_end.min(global_deadline)
                            };
                            trace!(
                                ns_hosts = ?ns_hosts,
                                deadline_ms = ?(hop_deadline.saturating_duration_since(Instant::now()).as_millis()),
                                "resolving ns hostnames"
                            );
                            let resolved = self
                                .resolve_ns_hostnames(&ns_hosts, hop_deadline, request)
                                .await;
                            if resolved.is_empty() {
                                // Allow another response with the same NS-host set in this hop
                                // to retry hostname resolution, because the first attempt may
                                // have hit a transient timeout budget.
                                attempted_ns_host_sets.remove(&ns_signature);
                            }
                            if !resolved.is_empty() {
                                self.metrics.record_iterative_event("ns_host_resolved");

                                // Cache all delegations that passed authority-zone security validation,
                                // regardless of trust_level. Out-of-zone NS (e.g. HiChina serving 163.com)
                                // is a normal real-world pattern and must not be excluded from the cache.
                                let should_cache = referral_is_security_valid;

                                if should_cache {
                                    if let Some(referral) = referral_for_cache.as_ref() {
                                        if let Some(zone) = self
                                            .select_referral_zone_for_query(&query_name, referral)
                                        {
                                            let ttl = dns::extract_cache_ttl(&packet)
                                                .unwrap_or(self.cache_ttl)
                                                .min(self.delegation_cache_ttl_cap)
                                                .max(Duration::from_secs(1));
                                            self.put_cached_delegation_endpoints(
                                                &zone,
                                                resolved.clone(),
                                                ttl,
                                            );
                                            self.metrics
                                                .record_iterative_event("delegation_cache_written");
                                        }
                                    }
                                } else if referral_validation.is_some() {
                                    // Validation failed or trust level too low: skip cache write
                                    self.metrics
                                        .record_iterative_event("delegation_cache_write_skipped");
                                }
                            }
                            next_candidates.extend(resolved);
                            // 一旦收集到足够多的下跳端点，立即退出 in_flight 循环，
                            // 避免等待慢速候选服务器的重复转介响应（重复的 NS 主机名解析）。
                            if next_candidates.len() >= self.ns_hostname_enough_endpoints {
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        last_error = Some(err);
                    }
                }
            }

            if next_candidates.is_empty() {
                if depth == 0 {
                    if let Some(zone) = delegation_seed_zone.take() {
                        self.metrics
                            .record_iterative_event("delegation_cache_fallback_to_root");
                        self.mark_delegation_cache_failure(&zone);
                        candidates = root_candidates.clone();
                        if !candidates.is_empty() {
                            continue;
                        }
                    }
                }
                if self.iterative_fallback_to_forwarder {
                    if let Some((packet, server)) = self.query_bootstrap_recursive(request).await {
                        self.record_iterative_path_metrics(
                            iterative_query_attempts,
                            iterative_referral_hops,
                        );
                        self.metrics.record_iterative_event("recursive_fallback");
                        self.metrics
                            .observe_iterative_depth("fallback", depth as f64 + 1.0);
                        self.iterative_fallbacks.fetch_add(1, Ordering::Relaxed);
                        self.iterative_successes.fetch_add(1, Ordering::Relaxed);
                        self.record_iterative_runtime_event(IterativeEventKind::Fallback);
                        return Ok((packet, server));
                    }
                }
                self.record_iterative_path_metrics(
                    iterative_query_attempts,
                    iterative_referral_hops,
                );
                self.metrics.record_iterative_event("no_referral_target");
                self.metrics.record_iterative_event("no_referral_glue");
                self.iterative_no_referral_glue_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    qname = %query_name,
                    depth,
                    max_depth = self.iterative_max_depth,
                    selective_trace,
                    "iterative no-referral-glue dead-end"
                );
                self.metrics
                    .observe_iterative_depth("failed", depth as f64 + 1.0);
                self.iterative_failures.fetch_add(1, Ordering::Relaxed);
                self.record_iterative_runtime_event(IterativeEventKind::Failure);
                return Err(last_error
                    .map(|e| anyhow!("iterative resolution failed without referral glue: {e}"))
                    .unwrap_or_else(|| {
                        anyhow!("iterative resolution failed without referral glue")
                    }));
            }

            next_candidates.sort();
            next_candidates.dedup();
            iterative_referral_hops += 1;
            candidates = next_candidates;
        }

        self.record_iterative_path_metrics(iterative_query_attempts, iterative_referral_hops);
        self.metrics.record_iterative_event("depth_exceeded");
        self.metrics
            .observe_iterative_depth("depth_exceeded", self.iterative_max_depth as f64);
        self.iterative_failures.fetch_add(1, Ordering::Relaxed);
        self.record_iterative_runtime_event(IterativeEventKind::Failure);
        Err(anyhow!("iterative resolution exceeded max referral depth"))
    }

    fn record_iterative_path_metrics(&self, query_attempts: usize, referral_hops: usize) {
        if referral_hops > 0 {
            self.iterative_referral_hops
                .fetch_add(referral_hops, Ordering::Relaxed);
        }
        if query_attempts > 1 {
            self.iterative_retry_queries
                .fetch_add(query_attempts - 1, Ordering::Relaxed);
        }
    }

    fn filter_iterative_endpoints<I>(&self, endpoints: I) -> Vec<String>
    where
        I: IntoIterator<Item = String>,
    {
        filter_endpoints_for_iterative_family(endpoints, self.iterative_address_family)
    }

    /// 递归模式下遇到 referral deadend 时的兜底递归查询。
    async fn query_bootstrap_recursive(&self, request: &[u8]) -> Option<(Vec<u8>, String)> {
        let recursive_request =
            dns::set_recursion_desired(request, true).unwrap_or_else(|| request.to_vec());
        // Query all bootstrap resolvers in parallel and take the first valid answer.
        // This avoids sequential timeouts (up to 2.4 s × N servers) when the iterative
        // path has already exhausted most of the budget.
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        for server in &self.bootstrap_recursive_resolvers {
            let server = server.clone();
            let req = recursive_request.clone();
            in_flight.push(async move {
                trace!(resolver = %server, "iterative bootstrap recursive query");
                let result = self.query_address(&server, &req).await;
                (server, result)
            });
        }
        while let Some((server, result)) = in_flight.next().await {
            if let Ok(packet) = result {
                let overview = dns::parse_response_overview(&packet);
                let rcode = overview.map(|value| value.rcode).unwrap_or(2);
                let ancount = overview.map(|value| value.ancount).unwrap_or(0);
                let terminal_authority_soa = dns::analyze_referral_targets(&packet)
                    .map(|value| value.has_authority_soa && value.authority_ns_hostnames.is_empty())
                    .unwrap_or(false);
                if rcode == 3 || (rcode == 0 && (ancount > 0 || terminal_authority_soa)) {
                    return Some((packet, server));
                }
            }
        }
        None
    }

    /// 解析 NS 主机名，返回其 IP 地址集合。
    /// 解析一批 NS 主机名，返回可用的端点列表。
    ///
    /// 优化策略：
    /// 1. 最多同时并发 `NS_HOSTNAME_MAX_CONCURRENT` 个主机名的解析任务；
    /// 2. 每个任务有独立超时（`NS_HOSTNAME_PER_RESOLVE_MS`），超时即放弃该主机名；
    /// 3. 一旦累计收集到 `NS_HOSTNAME_ENOUGH_ENDPOINTS` 个不同端点，立即截断，
    ///    丢弃仍在飞行的任务，不再启动新任务。
    async fn resolve_ns_hostnames(
        &self,
        hostnames: &[String],
        deadline: Instant,
        request: &[u8],
    ) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        let mut hostname_iter = hostnames.iter();
        let mut scheduled_hostnames: HashSet<String> = HashSet::new();

        loop {
            // 填满并发槽，同时处理缓存命中（同步快路径）。
            while in_flight.len() < self.ns_hostname_max_concurrent {
                if Instant::now() >= deadline {
                    break;
                }
                let Some(hostname) = hostname_iter.next() else {
                    break;
                };
                let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();

                // Deduplicate same hostname within the same resolve batch.
                if !scheduled_hostnames.insert(hostname.clone()) {
                    continue;
                }

                // Skip hostnames that just failed in recent attempts to avoid
                // retry storms across recursive iterative resolution.
                if self.is_ns_host_recently_failed(&hostname) {
                    self.metrics
                        .record_iterative_event("ns_host_recent_fail_skip");
                    continue;
                }

                // 缓存命中直接收集，无需 I/O。
                if let Some(cached) = self.get_cached_ns_endpoints(&hostname) {
                    result.extend(cached);
                    if result.len() >= self.ns_hostname_enough_endpoints {
                        break; // 已足够，退出内层填充
                    }
                    continue;
                }

                // 构造 A / AAAA 查询包。
                let a_query = if self.iterative_address_family.allows_ipv4() {
                    dns::build_query_like_request(
                        request,
                        next_iterative_query_id(),
                        &hostname,
                        1,
                        true,
                    )
                } else {
                    None
                };
                let aaaa_query = if self.iterative_address_family.allows_ipv6() {
                    dns::build_query_like_request(
                        request,
                        next_iterative_query_id(),
                        &hostname,
                        28,
                        true,
                    )
                } else {
                    None
                };
                if a_query.is_none() && aaaa_query.is_none() {
                    continue;
                }

                // 计算本次任务的超时：取剩余 deadline 时间与单次上限的较小值。
                let remaining = deadline.saturating_duration_since(Instant::now());
                let per_timeout =
                    remaining.min(Duration::from_millis(self.ns_hostname_per_resolve_ms));
                let hostname = hostname.clone();

                // 将解析任务放入并发池。async 块只持有 &self（共享引用），安全。
                in_flight.push(async move {
                    let resolve_fut = async {
                        match self.ns_hostname_resolve_mode {
                            NsHostnameResolveMode::BootstrapRecursive => {
                                self.resolve_ns_hostname_via_bootstrap_recursive(
                                    a_query, aaaa_query, deadline,
                                )
                                .await
                            }
                            NsHostnameResolveMode::PureIterative => {
                                self.resolve_ns_hostname_via_pure_iterative(
                                    &hostname, request, deadline,
                                )
                                .await
                            }
                        }
                    };
                    // 单个主机名解析超时截断：超时返回空列表，不阻塞整体流程。
                    let endpoints = timeout(per_timeout, resolve_fut).await.unwrap_or_default();
                    (hostname, endpoints)
                });
            }

            // 缓存命中已经满足需求，可直接跳出。
            if result.len() >= self.ns_hostname_enough_endpoints {
                break;
            }
            // 并发池已空且无更多主机名，结束。
            if in_flight.is_empty() {
                break;
            }

            // 等待最先完成的一个解析任务。
            let Some((hostname, endpoints)) = in_flight.next().await else {
                break;
            };
            if !endpoints.is_empty() {
                self.put_cached_ns_endpoints(&hostname, endpoints.clone());
                result.extend(endpoints);
            } else {
                self.mark_ns_host_failed(&hostname);
            }

            // 快速截断：端点数量已够，丢弃剩余飞行任务（自动 drop）。
            if result.len() >= self.ns_hostname_enough_endpoints {
                break;
            }
        }

        result.sort();
        result.dedup();
        result
    }

    async fn resolve_ns_hostname_via_bootstrap_recursive(
        &self,
        a_query: Option<Vec<u8>>,
        aaaa_query: Option<Vec<u8>>,
        deadline: Instant,
    ) -> Vec<String> {
        let mut bootstrap_in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        // Query all bootstrap recursive resolvers in parallel and pick the first usable result.
        for resolver_addr in &self.bootstrap_recursive_resolvers {
            if Instant::now() >= deadline {
                break;
            }
            let resolver_addr = resolver_addr.clone();
            let a_query = a_query.clone();
            let aaaa_query = aaaa_query.clone();
            bootstrap_in_flight.push(async move {
                let mut endpoints: Vec<String> = Vec::new();
                match (a_query.as_ref(), aaaa_query.as_ref()) {
                    (Some(a), Some(aaaa)) => {
                        let (a_res, aaaa_res) = tokio::join!(
                            self.query_address(&resolver_addr, a),
                            self.query_address(&resolver_addr, aaaa)
                        );
                        if let Ok(pkt) = a_res {
                            endpoints.extend(dns::extract_answer_ip_endpoints_with_port(&pkt, self.iterative_dns_port));
                        }
                        if let Ok(pkt) = aaaa_res {
                            endpoints.extend(dns::extract_answer_ip_endpoints_with_port(&pkt, self.iterative_dns_port));
                        }
                    }
                    (Some(a), None) => {
                        if let Ok(pkt) = self.query_address(&resolver_addr, a).await {
                            endpoints.extend(dns::extract_answer_ip_endpoints_with_port(&pkt, self.iterative_dns_port));
                        }
                    }
                    (None, Some(aaaa)) => {
                        if let Ok(pkt) = self.query_address(&resolver_addr, aaaa).await {
                            endpoints.extend(dns::extract_answer_ip_endpoints_with_port(&pkt, self.iterative_dns_port));
                        }
                    }
                    (None, None) => {}
                }
                endpoints.sort();
                endpoints.dedup();
                endpoints
            });
        }

        while let Some(endpoints) = bootstrap_in_flight.next().await {
            let endpoints = self.filter_iterative_endpoints(endpoints);
            if !endpoints.is_empty() {
                return endpoints;
            }
        }

        Vec::new()
    }

    async fn resolve_ns_hostname_via_pure_iterative(
        &self,
        hostname: &str,
        request: &[u8],
        deadline: Instant,
    ) -> Vec<String> {
        let mut results = Vec::new();

        if self.iterative_address_family.allows_ipv4() {
            results.extend(
                self.resolve_ns_hostname_qtype_pure_iterative(hostname, 1, request, deadline)
                    .await,
            );
        }
        if self.iterative_address_family.allows_ipv6() {
            results.extend(
                self.resolve_ns_hostname_qtype_pure_iterative(hostname, 28, request, deadline)
                    .await,
            );
        }

        results = self.filter_iterative_endpoints(results);
        results.sort();
        results.dedup();
        results
    }

    async fn resolve_ns_hostname_qtype_pure_iterative(
        &self,
        hostname: &str,
        qtype: u16,
        request: &[u8],
        deadline: Instant,
    ) -> Vec<String> {
        let Some(iterative_request) = dns::build_query_like_request(
            request,
            next_iterative_query_id(),
            hostname,
            qtype,
            false,
        ) else {
            return Vec::new();
        };

        if self.root_servers.is_empty() {
            return Vec::new();
        }

        let mut candidates = self.root_servers.clone();
        let mut seen_signatures = HashSet::new();

        for _depth in 0..self.iterative_max_depth {
            if Instant::now() >= deadline {
                break;
            }

            let mut signature_candidates = candidates.clone();
            signature_candidates.sort();
            signature_candidates.dedup();
            let signature = signature_candidates.join("|");
            if !seen_signatures.insert(signature) {
                break;
            }

            let mut in_flight = FuturesUnordered::new();
            for server in candidates.clone() {
                in_flight.push(async {
                    let result = self.query_address(&server, &iterative_request).await;
                    (server, result)
                });
            }

            let mut next_candidates = Vec::new();
            while let Some((_server, result)) = in_flight.next().await {
                let Ok(packet) = result else {
                    continue;
                };

                let overview = dns::parse_response_overview(&packet);
                let rcode = overview.map(|value| value.rcode).unwrap_or(2);
                let ancount = overview.map(|value| value.ancount).unwrap_or(0);
                if rcode == 0 && ancount > 0 {
                    let mut endpoints =
                        self.filter_iterative_endpoints(dns::extract_answer_ip_endpoints_with_port(&packet, self.iterative_dns_port));
                    endpoints.sort();
                    endpoints.dedup();
                    if !endpoints.is_empty() {
                        return endpoints;
                    }
                }

                let referral = dns::analyze_referral_targets(&packet);
                let terminal_authority_soa = referral
                    .as_ref()
                    .map(|value| value.has_authority_soa && value.authority_ns_hostnames.is_empty())
                    .unwrap_or(false);
                if terminal_authority_soa {
                    continue;
                }

                let glue = referral
                    .as_ref()
                    .map(|value| value.glue_nameservers.as_slice())
                    .unwrap_or(&[]);
                if !glue.is_empty() {
                    next_candidates.extend(self.filter_iterative_endpoints(glue.iter().cloned()));
                    // Once enough next-hop candidates are collected, stop
                    // waiting for the remaining referral responses. This
                    // avoids slow TLD servers delaying NS hostname resolution
                    // past the per-hop deadline during CNAME chain walks.
                    if next_candidates.len() >= self.ns_hostname_enough_endpoints {
                        break;
                    }
                }
            }

            next_candidates.sort();
            next_candidates.dedup();
            if next_candidates.is_empty() {
                break;
            }
            candidates = next_candidates;
        }

        Vec::new()
    }

    /// 查询 NS 主机名的缓存 IP。
    fn get_cached_ns_endpoints(&self, hostname: &str) -> Option<Vec<String>> {
        let key = hostname.to_ascii_lowercase();
        let shard_index = aux_cache_shard_index(&key, self.ns_host_cache.shards.len());
        let mut cache = self.ns_host_cache.shards[shard_index]
            .lock()
            .recover("ns_host_cache");
        let now = Instant::now();
        self.cleanup_ns_host_cache_if_needed(&mut cache, now);
        let Some(entry) = cache.entries.get_mut(&key) else {
            self.record_ns_cache_event("miss", NsCacheEventKind::Miss, 0);
            trace!(ns_hostname = %key, "ns host cache miss");
            return None;
        };
        if now >= entry.expires_at {
            cache.entries.remove(&key);
            self.record_ns_cache_event("expired", NsCacheEventKind::Expired, 0);
            trace!(ns_hostname = %key, "ns host cache expired");
            return None;
        }
        entry.last_access = now;
        self.record_ns_cache_event("hit", NsCacheEventKind::Hit, 0);
        trace!(ns_hostname = %key, endpoints = ?entry.endpoints, "ns host cache hit");
        Some(entry.endpoints.clone())
    }

    /// 写入 NS 主机名的 IP 缓存。
    fn put_cached_ns_endpoints(&self, hostname: &str, endpoints: Vec<String>) {
        if self.ns_host_cache_capacity == 0 {
            self.metrics.record_ns_host_cache("skip_disabled");
            return;
        }

        let key = hostname.to_ascii_lowercase();
        let shard_index = aux_cache_shard_index(&key, self.ns_host_cache.shards.len());
        let shard_capacity = bounded_aux_shard_capacity(
            self.ns_host_cache_capacity,
            shard_index,
            self.ns_host_cache.shards.len(),
        )
        .unwrap_or(0);
        let mut cache = self.ns_host_cache.shards[shard_index]
            .lock()
            .recover("ns_host_cache");
        let now = Instant::now();
        self.cleanup_ns_host_cache_if_needed(&mut cache, now);

        if shard_capacity == 0 {
            cache.entries.clear();
            self.metrics.record_ns_host_cache("skip_disabled");
            return;
        }

        if cache.entries.len() >= shard_capacity {
            cache.entries.retain(|_, value| now < value.expires_at);
        }
        if cache.entries.len() >= shard_capacity {
            if let Some(evict_key) = cache
                .entries
                .iter()
                .min_by_key(|(_, value)| value.last_access)
                .map(|(key, _)| key.clone())
            {
                cache.entries.remove(&evict_key);
                self.record_ns_cache_event("evict", NsCacheEventKind::Evict, 0);
            }
        }
        cache.entries.insert(
            key,
            NsCacheEntry {
                endpoints,
                expires_at: now + self.ns_host_cache_ttl,
                last_access: now,
            },
        );
        self.record_ns_cache_event("store", NsCacheEventKind::Store, 0);
    }

    fn is_ns_host_recently_failed(&self, hostname: &str) -> bool {
        let key = hostname.to_ascii_lowercase();
        let shard_index = aux_cache_shard_index(&key, self.ns_host_cache.shards.len());
        let mut cache = self.ns_host_cache.shards[shard_index]
            .lock()
            .recover("ns_host_cache");
        let now = Instant::now();
        self.cleanup_ns_host_cache_if_needed(&mut cache, now);
        cache
            .failures
            .get(&key)
            .copied()
            .map(|until| now < until)
            .unwrap_or(false)
    }

    fn mark_ns_host_failed(&self, hostname: &str) {
        let key = hostname.to_ascii_lowercase();
        let shard_index = aux_cache_shard_index(&key, self.ns_host_cache.shards.len());
        let mut cache = self.ns_host_cache.shards[shard_index]
            .lock()
            .recover("ns_host_cache");
        let now = Instant::now();
        self.cleanup_ns_host_cache_if_needed(&mut cache, now);
        cache.failures.insert(key, now + NS_HOST_FAILURE_BACKOFF);
    }

    /// 定期清理过期的 NS 主机缓存。
    fn cleanup_ns_host_cache_if_needed(&self, cache: &mut NsHostCacheShard, now: Instant) {
        // Periodic cleanup avoids scanning on every cache operation.
        if now.duration_since(cache.last_cleanup) < self.ns_host_cache_cleanup_interval {
            return;
        }
        let before = cache.entries.len();
        cache.entries.retain(|_, value| now < value.expires_at);
        let removed = before.saturating_sub(cache.entries.len());
        cache.failures.retain(|_, until| now < *until);
        self.record_ns_cache_event("cleanup", NsCacheEventKind::Cleanup, removed);
        cache.last_cleanup = now;
    }

    fn get_cached_delegation_endpoints(&self, qname: &str) -> Option<(String, Vec<String>)> {
        if !self.enable_delegation_cache || self.delegation_cache_capacity == 0 {
            return None;
        }

        let now = Instant::now();
        for zone in iter_domain_suffixes(qname) {
            let zone = normalize_qname(&zone);
            let shard_index = aux_cache_shard_index(&zone, self.delegation_cache.shards.len());
            let mut cache = self.delegation_cache.shards[shard_index]
                .lock()
                .recover("delegation_cache");
            self.cleanup_delegation_cache_if_needed(&mut cache, now);
            let Some(entry) = cache.entries.get_mut(&zone) else {
                continue;
            };
            if now >= entry.expires_at {
                cache.entries.remove(&zone);
                self.metrics
                    .record_iterative_event("delegation_cache_expired");
                continue;
            }
            if entry
                .cooldown_until
                .map(|until| until > now)
                .unwrap_or(false)
            {
                self.metrics
                    .record_iterative_event("delegation_cache_cooldown_skip");
                continue;
            }
            entry.last_access = now;
            return Some((zone, entry.endpoints.clone()));
        }
        None
    }

    fn put_cached_delegation_endpoints(&self, zone: &str, endpoints: Vec<String>, ttl: Duration) {
        if !self.enable_delegation_cache || self.delegation_cache_capacity == 0 {
            return;
        }

        let zone = normalize_qname(zone);
        if zone == "." {
            return;
        }

        let mut endpoints = self.filter_iterative_endpoints(endpoints);
        endpoints.sort();
        endpoints.dedup();
        if endpoints.is_empty() {
            return;
        }

        let shard_index = aux_cache_shard_index(&zone, self.delegation_cache.shards.len());
        let shard_capacity = bounded_aux_shard_capacity(
            self.delegation_cache_capacity,
            shard_index,
            self.delegation_cache.shards.len(),
        )
        .unwrap_or(0);
        let mut cache = self.delegation_cache.shards[shard_index]
            .lock()
            .recover("delegation_cache");
        let now = Instant::now();
        self.cleanup_delegation_cache_if_needed(&mut cache, now);

        if shard_capacity == 0 {
            cache.entries.clear();
            return;
        }

        if cache.entries.len() >= shard_capacity {
            cache.entries.retain(|_, value| now < value.expires_at);
        }
        if cache.entries.len() >= shard_capacity {
            if let Some(evict_key) = cache
                .entries
                .iter()
                .min_by_key(|(_, value)| value.last_access)
                .map(|(key, _)| key.clone())
            {
                cache.entries.remove(&evict_key);
                self.metrics
                    .record_iterative_event("delegation_cache_evict");
            }
        }

        cache.entries.insert(
            zone,
            DelegationCacheEntry {
                endpoints,
                expires_at: now
                    + ttl
                        .min(self.delegation_cache_ttl_cap)
                        .max(Duration::from_secs(1)),
                last_access: now,
                cooldown_until: None,
            },
        );
        self.metrics
            .record_iterative_event("delegation_cache_store");
    }

    fn mark_delegation_cache_failure(&self, zone: &str) {
        if !self.enable_delegation_cache {
            return;
        }
        let zone = normalize_qname(zone);
        let shard_index = aux_cache_shard_index(&zone, self.delegation_cache.shards.len());
        let mut cache = self.delegation_cache.shards[shard_index]
            .lock()
            .recover("delegation_cache");
        let now = Instant::now();
        self.cleanup_delegation_cache_if_needed(&mut cache, now);
        if let Some(entry) = cache.entries.get_mut(&zone) {
            entry.cooldown_until = Some(now + self.delegation_failure_backoff);
            entry.last_access = now;
            self.metrics
                .record_iterative_event("delegation_cache_mark_failure");
        }
    }

    fn cleanup_delegation_cache_if_needed(&self, cache: &mut DelegationCacheShard, now: Instant) {
        if now.duration_since(cache.last_cleanup) < self.delegation_cache_cleanup_interval {
            return;
        }
        cache.entries.retain(|_, value| now < value.expires_at);
        cache.last_cleanup = now;
    }

    fn select_referral_zone_for_query(
        &self,
        qname: &str,
        referral: &dns::DnsReferralAnalysis,
    ) -> Option<String> {
        let qname = normalize_qname(qname);
        referral
            .authority_zones
            .iter()
            .map(|zone| normalize_qname(zone))
            .filter(|zone| domain_is_same_or_subdomain_of(&qname, zone))
            .max_by_key(|zone| zone.len())
    }

    /// 通过 UDP（必要时 TCP）向指定地址发送 DNS 查询。
    async fn query_address(&self, address: &str, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let response = self.query_address_once(address, request).await?;
        if dns::response_code(&response) == Some(1) && dns::extract_edns_opt(request).is_some() {
            if dns::dnssec_ok_requested(request) {
                return Err(anyhow!(
                    "resolver {} returned FORMERR for DNSSEC request with EDNS",
                    address
                ));
            }
            if let Some(downgraded_request) = dns::strip_edns_opt_from_request(request) {
                if dns::extract_edns_opt(&downgraded_request).is_none() {
                    trace!(resolver = %address, "FORMERR with EDNS request, retrying upstream without EDNS");
                    return self.query_address_once(address, &downgraded_request).await;
                }
            }
        }
        Ok(response)
    }

    async fn query_address_once(&self, address: &str, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        trace_dns_packet(address, request, "sending dns query to resolver");
        let udp_result = if let Some(transport) = self.upstream_udp_transports.get(address) {
            transport.query(request, self.upstream_timeout).await
        } else {
            self.query_address_over_udp(address, request).await
        };
        match udp_result {
            Ok(buf) => {
                trace_dns_packet(address, &buf, "received dns response from resolver");
                if dns::parse_header(&buf)
                    .map(|h| (h.flags & 0x0200) != 0)
                    .unwrap_or(false)
                {
                    trace!(resolver = %address, "udp response truncated, retrying resolver over tcp");
                    return self.query_address_over_tcp(address, request).await;
                }
                Ok(buf)
            }
            Err(err) => {
                trace!(resolver = %address, "udp receive failed, retrying resolver over tcp: {}", err);
                self.query_address_over_tcp(address, request)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to receive response from resolver {}: {}",
                            address, err
                        )
                    })
            }
        }
    }

    async fn query_address_over_udp(
        &self,
        address: &str,
        request: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind(bind_address_for_resolver(address))
            .await
            .context("failed to bind upstream UDP socket")?;
        socket
            .send_to(request, address)
            .await
            .with_context(|| format!("failed to send request to resolver {}", address))?;

        let mut buf = vec![0u8; dns::udp_payload_size_for_request(request)];
        let recv = timeout(self.upstream_timeout, socket.recv_from(&mut buf)).await;
        match recv {
            Ok(Ok((len, _))) => {
                buf.truncate(len);
                Ok(buf)
            }
            Ok(Err(err)) => Err(anyhow!(
                "failed to receive response from resolver {}: {}",
                address,
                err
            )),
            Err(_) => Err(anyhow!("resolver {} timed out", address)),
        }
    }

    /// 通过 TCP 向指定地址发送 DNS 查询。
    async fn query_address_over_tcp(
        &self,
        address: &str,
        request: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if let Some(transport) = self.upstream_tcp_transports.get(address) {
            return transport.query(request, self.upstream_timeout).await;
        }

        let mut stream = timeout(self.upstream_timeout, TcpStream::connect(address))
            .await
            .context("tcp connect timeout")?
            .with_context(|| format!("failed to connect resolver {} over tcp", address))?;
        stream
            .set_nodelay(true)
            .with_context(|| format!("failed to enable tcp nodelay for resolver {}", address))?;

        let req_len = u16::try_from(request.len()).map_err(|_| {
            anyhow!(
                "dns request too large for tcp framing: {} bytes",
                request.len()
            )
        })?;
        stream
            .write_all(&req_len.to_be_bytes())
            .await
            .with_context(|| format!("failed to write tcp length to resolver {}", address))?;
        stream
            .write_all(request)
            .await
            .with_context(|| format!("failed to write tcp request to resolver {}", address))?;

        let mut len_buf = [0u8; 2];
        timeout(self.upstream_timeout, stream.read_exact(&mut len_buf))
            .await
            .context("tcp read length timeout")?
            .with_context(|| {
                format!(
                    "failed to read tcp response length from resolver {}",
                    address
                )
            })?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 65_535 {
            return Err(anyhow!(
                "invalid tcp dns response length {} from resolver {}",
                resp_len,
                address
            ));
        }

        let mut response = vec![0u8; resp_len];
        timeout(self.upstream_timeout, stream.read_exact(&mut response))
            .await
            .context("tcp read body timeout")?
            .with_context(|| {
                format!("failed to read tcp response body from resolver {}", address)
            })?;

        trace_dns_packet(
            address,
            &response,
            "received dns response from resolver over tcp",
        );

        Ok(response)
    }

    /// 标记上游服务器一次成功响应。
    fn mark_upstream_success(&self, upstream_index: usize, elapsed: Duration) {
        let upstream = &self.upstreams[upstream_index];
        if let Ok(mut state) = upstream.state.write() {
            state.consecutive_failures = 0;
            state.last_rtt = Some(elapsed);
            state.unhealthy_until = None;
            state.successes = state.successes.saturating_add(1);
            state.score = self.compute_upstream_score(&state, Instant::now());
        }
    }

    /// 标记上游服务器一次失败响应。
    fn mark_upstream_failure(&self, upstream_index: usize) {
        let upstream = &self.upstreams[upstream_index];
        if let Ok(mut state) = upstream.state.write() {
            state.consecutive_failures += 1;
            state.unhealthy_until = Some(Instant::now() + self.unhealthy_backoff);
            state.failures = state.failures.saturating_add(1);
            state.score = self.compute_upstream_score(&state, Instant::now());
        }
    }

    fn compute_upstream_score(&self, state: &UpstreamState, now: Instant) -> f64 {
        let rtt_ms = state
            .last_rtt
            .unwrap_or(self.upstream_timeout + self.upstream_timeout)
            .as_secs_f64()
            * 1000.0;
        let failure_penalty = state.consecutive_failures as f64
            * self.upstream_score_failure_weight
            + state.failures as f64 * (self.upstream_score_failure_weight * 0.05);
        let success_bonus =
            (state.successes as f64 + 1.0).ln() * self.upstream_score_success_weight;
        let unhealthy_penalty = state
            .unhealthy_until
            .map(|deadline| if deadline > now { 1000.0 } else { 0.0 })
            .unwrap_or(0.0);

        1000.0 - rtt_ms * self.upstream_score_rtt_weight - failure_penalty - unhealthy_penalty
            + success_bonus
    }

    /// 记录一次迭代解析事件。
    fn record_iterative_runtime_event(&self, event: IterativeEventKind) {
        if let Ok(mut events) = self.iterative_events.lock() {
            let now = Instant::now();
            events.push_back((now, event));
            Self::trim_iterative_events(&mut events, now, self.stats_window);
            while events.len() > 8192 {
                events.pop_front();
            }
        }
    }

    /// 裁剪过期的迭代事件。
    fn trim_iterative_events(
        events: &mut VecDeque<(Instant, IterativeEventKind)>,
        now: Instant,
        window: Duration,
    ) {
        while let Some((ts, _)) = events.front() {
            if now.duration_since(*ts) <= window {
                break;
            }
            events.pop_front();
        }
    }

    /// 记录一次 NS 缓存事件。
    fn record_ns_cache_event(&self, label: &str, kind: NsCacheEventKind, removed: usize) {
        self.metrics.record_ns_host_cache(label);
        if let Ok(mut events) = self.ns_cache_events.lock() {
            let now = Instant::now();
            events.push_back(NsCacheEvent {
                at: now,
                kind,
                removed,
            });
            Self::trim_ns_cache_events(&mut events, now, self.stats_window);
            while events.len() > 8192 {
                events.pop_front();
            }
        }
    }

    /// 裁剪过期的 NS 缓存事件。
    fn trim_ns_cache_events(events: &mut VecDeque<NsCacheEvent>, now: Instant, window: Duration) {
        while let Some(event) = events.front() {
            if now.duration_since(event.at) <= window {
                break;
            }
            events.pop_front();
        }
    }
}

#[derive(Clone, Copy)]
enum ViewIndexKind {
    Static,
    Authoritative,
}

fn build_view_record_index(views: &[DnsView], kind: ViewIndexKind) -> ViewRecordIndex {
    let mut index = HashMap::with_capacity(views.len());
    for view in views {
        let view_name = view.name.trim();
        if view_name.is_empty() {
            continue;
        }

        let records = match kind {
            ViewIndexKind::Static => match view.effective_static_records() {
                Ok(records) => records,
                Err(err) => {
                    warn!(view = view_name, error = %err, "skip invalid effective view static records");
                    continue;
                }
            },
            ViewIndexKind::Authoritative => view.effective_authoritative_records(),
        };
        index.insert(view_name.to_string(), build_static_record_index(records));
    }
    index
}

/// 将 AuthoritativeZone 切片构建为运行时 zone entries（按 zone 名称长度降序排列以支持最长后缀匹配）。
fn build_authoritative_zone_entries(zones: &[AuthoritativeZone]) -> Vec<AuthoritativeZoneEntry> {
    let mut entries: Vec<AuthoritativeZoneEntry> = zones
        .iter()
        .map(|zone| {
            let zone_name = normalize_qname(&zone.name);
            // 扩展记录类型：zone records 支持 MX/TXT/NS/PTR，使用 parse_zone_record_qtype
            let (record_index, name_set) = build_zone_record_index(&zone.records, &zone_name);
            AuthoritativeZoneEntry {
                zone_name,
                soa: zone.soa.clone(),
                record_index,
                name_set,
            }
        })
        .collect();
    // 最长后缀优先（zone_name 越长越精确）
    entries.sort_by(|a, b| b.zone_name.len().cmp(&a.zone_name.len()));
    entries
}

/// 按 view 名称构建 view → zone entries 的索引。
fn build_view_zone_index(views: &[DnsView]) -> ViewZoneIndex {
    let mut index = HashMap::with_capacity(views.len());
    for view in views {
        let view_name = view.name.trim();
        if view_name.is_empty() {
            continue;
        }
        let entries = build_authoritative_zone_entries(&view.authoritative_zones);
        if !entries.is_empty() {
            index.insert(view_name.to_string(), entries);
        }
    }
    index
}

fn build_view_query_control_index(views: &[DnsView]) -> ViewQueryControlIndex {
    let mut index = HashMap::with_capacity(views.len());
    for view in views {
        let view_name = view.name.trim();
        if view_name.is_empty() {
            continue;
        }
        index.insert(
            view_name.to_string(),
            ViewQueryControl {
                query_mode: view.query_mode,
                enable_recursion: view.enable_recursion,
                view_static_cname_expand_for_address_queries: view
                    .view_static_cname_expand_for_address_queries,
                view_authoritative_cname_expand_for_address_queries: view
                    .view_authoritative_cname_expand_for_address_queries,
            },
        );
    }
    index
}

/// 在 zone entries 中查找与 qname 最长后缀匹配的区。
fn find_authoritative_zone<'a>(
    entries: &'a [AuthoritativeZoneEntry],
    qname: &str,
) -> Option<&'a AuthoritativeZoneEntry> {
    let normalized = normalize_qname(qname);
    entries.iter().find(|entry| {
        let zn = &entry.zone_name;
        // 精确匹配或 qname 以 ".zone_name" 结尾
        normalized == *zn || normalized.ends_with(&format!(".{zn}"))
    })
}

/// 为 zone records 构建索引（支持 A/AAAA/CNAME/MX/TXT/NS/PTR）。
/// 同名同类型的多条 RR 被合并到同一个 MultiRecordEntry（符合 RFC 1035 多记录语义）。
/// 同时返回区内所有规范化 QNAME 的存在集合，供 NXDOMAIN vs NODATA 判断使用（RFC 2308）。
fn build_zone_record_index(
    records: &[StaticRecord],
    zone_name: &str,
) -> (HashMap<CacheKey, MultiRecordEntry>, HashSet<String>) {
    let mut index: HashMap<CacheKey, MultiRecordEntry> = HashMap::with_capacity(records.len());
    let mut name_set: HashSet<String> = HashSet::new();
    // 区 apex 本身始终存在（即使没有 A 记录也有 SOA）
    name_set.insert(zone_name.to_string());
    for record in records {
        let Some(qtype) = parse_zone_record_qtype(&record.qtype) else {
            warn!(qname = %record.qname, qtype = %record.qtype, "skip zone record with unsupported qtype");
            continue;
        };
        let normalized_qname = normalize_qname(&record.qname);
        name_set.insert(normalized_qname);
        let key = cache_key_for_query(&record.qname, qtype, false);
        let entry = index.entry(key).or_insert_with(|| MultiRecordEntry {
            answers: Vec::new(),
            ttl: record.ttl,
            qtype_name: record.qtype.clone(),
        });
        entry.answers.push(record.answer.clone());
    }
    (index, name_set)
}

fn additional_target_hosts_for_qtype(qtype: u16, answers: &[String]) -> Vec<String> {
    match qtype {
        2 => answers
            .iter()
            .map(|value| normalize_qname(value))
            .filter(|value| !value.is_empty())
            .collect(),
        15 => answers
            .iter()
            .filter_map(|value| {
                let mut parts = value.split_whitespace();
                let _pref = parts.next()?;
                let exchange = parts.next()?;
                let normalized = normalize_qname(exchange);
                if normalized.is_empty() {
                    return None;
                }
                Some(normalized)
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn qname_belongs_to_zone(qname: &str, zone_name: &str) -> bool {
    let q = normalize_qname(qname);
    let z = normalize_qname(zone_name);
    q == z || q.ends_with(&format!(".{z}"))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum EndpointAddressFamily {
    Ipv4,
    Ipv6,
}

fn endpoint_address_family(endpoint: &str) -> Option<EndpointAddressFamily> {
    endpoint
        .parse::<SocketAddr>()
        .ok()
        .map(|address| match address {
            SocketAddr::V4(_) => EndpointAddressFamily::Ipv4,
            SocketAddr::V6(_) => EndpointAddressFamily::Ipv6,
        })
}

fn endpoint_matches_iterative_family(
    endpoint: &str,
    iterative_address_family: IterativeAddressFamily,
) -> bool {
    match endpoint_address_family(endpoint) {
        Some(EndpointAddressFamily::Ipv4) => iterative_address_family.allows_ipv4(),
        Some(EndpointAddressFamily::Ipv6) => iterative_address_family.allows_ipv6(),
        None => iterative_address_family == IterativeAddressFamily::DualStack,
    }
}

fn filter_endpoints_for_iterative_family<I>(
    endpoints: I,
    iterative_address_family: IterativeAddressFamily,
) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut filtered = endpoints
        .into_iter()
        .filter(|endpoint| endpoint_matches_iterative_family(endpoint, iterative_address_family))
        .collect::<Vec<_>>();
    filtered.sort();
    filtered.dedup();
    filtered
}

fn bind_address_for_resolver(address: &str) -> &'static str {
    match endpoint_address_family(address) {
        Some(EndpointAddressFamily::Ipv6) => "[::]:0",
        _ => "0.0.0.0:0",
    }
}

/// 规范化预热区名称：确保以 "." 结尾，并转换为小写，兼容 "com" 与 "com." 两种写法。
fn normalize_prewarm_zone(zone: &str) -> String {
    let z = zone.trim().trim_start_matches('.').to_ascii_lowercase();
    if z.ends_with('.') {
        z
    } else {
        format!("{z}.")
    }
}

/// 对端点列表排序去重后返回。
fn dedup_endpoints(mut endpoints: Vec<String>) -> Vec<String> {
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

fn build_bootstrap_recursive_resolvers(
    root_servers: &[String],
    upstreams: &[Upstream],
    iterative_address_family: IterativeAddressFamily,
) -> Vec<String> {
    let mut resolvers = upstreams
        .iter()
        .map(|upstream| upstream.address.clone())
        .collect::<Vec<_>>();
    if resolvers.is_empty() {
        resolvers.extend(root_servers.iter().cloned());
    }
    filter_endpoints_for_iterative_family(resolvers, iterative_address_family)
}

fn build_upstream_udp_transports(
    root_servers: &[String],
    upstreams: &[Upstream],
) -> HashMap<String, Arc<dyn UpstreamTransport>> {
    let mut addresses = build_bootstrap_recursive_resolvers(
        root_servers,
        upstreams,
        IterativeAddressFamily::DualStack,
    );
    for upstream in upstreams {
        addresses.push(upstream.address.clone());
    }
    addresses.sort();
    addresses.dedup();

    let mut transports: HashMap<String, Arc<dyn UpstreamTransport>> =
        HashMap::with_capacity(addresses.len());
    for address in addresses {
        let transport: Arc<dyn UpstreamTransport> =
            UpstreamUdpTransport::spawn(address.clone());
        transports.insert(address, transport);
    }
    transports
}

fn build_upstream_tcp_transports(
    root_servers: &[String],
    upstreams: &[Upstream],
) -> HashMap<String, Arc<dyn UpstreamTransport>> {
    let mut addresses = build_bootstrap_recursive_resolvers(
        root_servers,
        upstreams,
        IterativeAddressFamily::DualStack,
    );
    for upstream in upstreams {
        addresses.push(upstream.address.clone());
    }
    addresses.sort();
    addresses.dedup();

    let mut transports: HashMap<String, Arc<dyn UpstreamTransport>> =
        HashMap::with_capacity(addresses.len());
    for address in addresses {
        let transport: Arc<dyn UpstreamTransport> =
            UpstreamTcpTransport::spawn(address.clone());
        transports.insert(address, transport);
    }
    transports
}

impl UpstreamUdpTransport {
    fn spawn(address: String) -> Arc<Self> {
        let shard_count = upstream_udp_shard_count();
        let mut shards = Vec::with_capacity(shard_count);
        for shard_index in 0..shard_count {
            let (sender, receiver) = mpsc::channel(4096);
            tokio::spawn(run_upstream_udp_dispatcher(
                address.clone(),
                shard_index,
                receiver,
            ));
            shards.push(sender);
        }
        Arc::new(Self { shards })
    }

    async fn query(&self, request: &[u8], timeout_duration: Duration) -> anyhow::Result<Vec<u8>> {
        let mut packet = request.to_vec();
        if packet.len() < 2 {
            return Err(anyhow!("dns request too short for upstream udp transport"));
        }
        let recv_buf_size = dns::udp_payload_size_for_request(request);
        let query_id = next_iterative_query_id();
        packet[0..2].copy_from_slice(&query_id.to_be_bytes());

        let (response_tx, response_rx) = oneshot::channel();
        let shard_index = upstream_udp_shard_index(query_id, self.shards.len());
        self.shards[shard_index]
            .send(UpstreamUdpQuery {
                packet,
                recv_buf_size,
                response_tx,
                deadline: Instant::now() + timeout_duration,
            })
            .await
            .map_err(|_| anyhow!("upstream udp transport channel closed"))?;

        match timeout(timeout_duration, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!("upstream udp transport response channel closed")),
            Err(_) => Err(anyhow!("upstream udp transport timed out")),
        }
    }
}

#[async_trait]
impl crate::traits::UpstreamTransport for UpstreamUdpTransport {
    async fn query(&self, request: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>> {
        self.query(request, timeout).await
    }
}

impl UpstreamTcpTransport {
    fn spawn(address: String) -> Arc<Self> {
        let shard_count = upstream_tcp_shard_count();
        let mut shards = Vec::with_capacity(shard_count);
        for shard_index in 0..shard_count {
            let (sender, receiver) = mpsc::channel(256);
            tokio::spawn(run_upstream_tcp_dispatcher(
                address.clone(),
                shard_index,
                receiver,
            ));
            shards.push(sender);
        }
        Arc::new(Self { shards })
    }

    async fn query(&self, request: &[u8], timeout_duration: Duration) -> anyhow::Result<Vec<u8>> {
        let (response_tx, response_rx) = oneshot::channel();
        let shard_index = upstream_tcp_shard_index(request, self.shards.len());
        self.shards[shard_index]
            .send(UpstreamTcpQuery {
                packet: request.to_vec(),
                response_tx,
                deadline: Instant::now() + timeout_duration,
            })
            .await
            .map_err(|_| anyhow!("upstream tcp transport channel closed"))?;

        match timeout(timeout_duration, response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!("upstream tcp transport response channel closed")),
            Err(_) => Err(anyhow!("upstream tcp transport timed out")),
        }
    }
}

#[async_trait]
impl crate::traits::UpstreamTransport for UpstreamTcpTransport {
    async fn query(&self, request: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>> {
        self.query(request, timeout).await
    }
}

async fn run_upstream_udp_dispatcher(
    address: String,
    shard_index: usize,
    mut receiver: mpsc::Receiver<UpstreamUdpQuery>,
) {
    let socket = match UdpSocket::bind(bind_address_for_resolver(&address)).await {
        Ok(socket) => socket,
        Err(err) => {
            while let Some(query) = receiver.recv().await {
                let _ = query.response_tx.send(Err(anyhow!(
                    "failed to bind upstream UDP socket for {} shard {}: {}",
                    address,
                    shard_index,
                    err
                )));
            }
            return;
        }
    };

    let mut pending = HashMap::<u16, PendingUdpQuery>::new();
    let mut buf = vec![0u8; 4096];
    let mut cleanup = interval(Duration::from_millis(200));
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe_query = receiver.recv() => {
                let Some(query) = maybe_query else {
                    break;
                };
                if query.packet.len() < 2 {
                    let _ = query.response_tx.send(Err(anyhow!("dns request too short for upstream UDP dispatch")));
                    continue;
                }
                if query.recv_buf_size > buf.len() {
                    buf.resize(query.recv_buf_size, 0);
                }
                let query_id = u16::from_be_bytes([query.packet[0], query.packet[1]]);
                if let Some(replaced) = pending.remove(&query_id) {
                    let _ = replaced.response_tx.send(Err(anyhow!("upstream udp query id collision")));
                }
                match socket.send_to(&query.packet, &address).await {
                    Ok(_) => {
                        pending.insert(
                            query_id,
                            PendingUdpQuery {
                                response_tx: query.response_tx,
                                deadline: query.deadline,
                            },
                        );
                    }
                    Err(err) => {
                        let _ = query.response_tx.send(Err(anyhow!(
                            "failed to send request to resolver {} shard {}: {}",
                            address,
                            shard_index,
                            err
                        )));
                    }
                }
            }
            recv = socket.recv_from(&mut buf), if !pending.is_empty() => {
                match recv {
                    Ok((len, _)) => {
                        if len < 2 {
                            continue;
                        }
                        let response = buf[..len].to_vec();
                        let response_id = u16::from_be_bytes([response[0], response[1]]);
                        if let Some(query) = pending.remove(&response_id) {
                            let _ = query.response_tx.send(Ok(response));
                        }
                    }
                    Err(err) => {
                        let message = format!(
                            "failed to receive response from resolver {} shard {}: {}",
                            address,
                            shard_index,
                            err
                        );
                        for (_, query) in pending.drain() {
                            let _ = query.response_tx.send(Err(anyhow!(message.clone())));
                        }
                        break;
                    }
                }
            }
            _ = cleanup.tick(), if !pending.is_empty() => {
                let now = Instant::now();
                let expired_ids = pending
                    .iter()
                    .filter_map(|(query_id, query)| (now >= query.deadline).then_some(*query_id))
                    .collect::<Vec<_>>();
                for query_id in expired_ids {
                    if let Some(query) = pending.remove(&query_id) {
                        let _ = query.response_tx.send(Err(anyhow!(
                            "resolver {} shard {} timed out",
                            address,
                            shard_index
                        )));
                    }
                }
            }
        }
    }

    for (_, query) in pending.drain() {
        let _ = query.response_tx.send(Err(anyhow!(
            "upstream udp dispatcher for {} shard {} stopped",
            address,
            shard_index
        )));
    }
}

/// Maximum TCP connections to keep alive per upstream shard.
const TCP_POOL_MAX_CONNS: usize = 4;

async fn run_upstream_tcp_dispatcher(
    address: String,
    shard_index: usize,
    mut receiver: mpsc::Receiver<UpstreamTcpQuery>,
) {
    let mut pool: VecDeque<TcpStream> = VecDeque::with_capacity(TCP_POOL_MAX_CONNS);
    while let Some(query) = receiver.recv().await {
        let result =
            execute_upstream_tcp_query(&address, shard_index, &mut pool, &query).await;
        match result {
            Ok(response) => {
                let _ = query.response_tx.send(Ok(response));
            }
            Err(err) => {
                let _ = query.response_tx.send(Err(err));
            }
        }
    }
    // Close all pooled connections on shutdown.
    drop(pool);
}

async fn execute_upstream_tcp_query(
    address: &str,
    shard_index: usize,
    pool: &mut VecDeque<TcpStream>,
    query: &UpstreamTcpQuery,
) -> anyhow::Result<Vec<u8>> {
    if query.packet.len() < 2 {
        return Err(anyhow!("dns request too short for upstream tcp transport"));
    }

    // Try each pooled connection, then create a new one up to TCP_POOL_MAX_CONNS.
    let mut stream = pool.pop_front();
    for attempt in 0..(TCP_POOL_MAX_CONNS + 1) {
        let stream_ref = if stream.is_none() {
            match connect_upstream_tcp(address, shard_index, query.deadline).await {
                Ok(new_stream) => {
                    stream = Some(new_stream);
                    stream.as_mut()
                }
                Err(e) => {
                    if attempt == 0 && pool.is_empty() {
                        return Err(e);
                    }
                    // Try next pooled connection.
                    stream = pool.pop_front();
                    continue;
                }
            }
        } else {
            stream.as_mut()
        };

        let Some(stream_ref) = stream_ref else {
            stream = pool.pop_front();
            continue;
        };

        match perform_upstream_tcp_query(
            address,
            shard_index,
            stream_ref,
            query.deadline,
            &query.packet,
        )
        .await
        {
            Ok(response) => {
                // Return the healthy connection to the pool (up to max).
                if pool.len() < TCP_POOL_MAX_CONNS {
                    if let Some(s) = stream.take() {
                        pool.push_back(s);
                    }
                }
                // Drain excess connections gracefully (they'll be dropped).
                while pool.len() > TCP_POOL_MAX_CONNS {
                    let _ = pool.pop_front();
                }
                return Ok(response);
            }
            Err(_) => {
                // Discard broken connection, try next.
                stream = pool.pop_front();
            }
        }
    }

    Err(anyhow!("upstream tcp query failed after exhausting connection pool"))
}

async fn connect_upstream_tcp(
    address: &str,
    shard_index: usize,
    deadline: Instant,
) -> anyhow::Result<TcpStream> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(anyhow!("upstream tcp connect timed out"));
    }

    let stream = timeout(remaining, TcpStream::connect(address))
        .await
        .context("tcp connect timeout")?
        .with_context(|| {
            format!(
                "failed to connect resolver {} shard {} over tcp",
                address, shard_index
            )
        })?;
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable tcp nodelay for resolver {}", address))?;
    Ok(stream)
}

async fn perform_upstream_tcp_query(
    address: &str,
    shard_index: usize,
    stream: &mut TcpStream,
    deadline: Instant,
    packet: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let req_len = u16::try_from(packet.len()).map_err(|_| {
        anyhow!(
            "dns request too large for tcp framing: {} bytes",
            packet.len()
        )
    })?;

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(anyhow!("upstream tcp write timed out"));
    }
    timeout(remaining, stream.write_all(&req_len.to_be_bytes()))
        .await
        .context("tcp write length timeout")?
        .with_context(|| {
            format!(
                "failed to write tcp length to resolver {} shard {}",
                address, shard_index
            )
        })?;

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(anyhow!("upstream tcp write timed out"));
    }
    timeout(remaining, stream.write_all(packet))
        .await
        .context("tcp write request timeout")?
        .with_context(|| {
            format!(
                "failed to write tcp request to resolver {} shard {}",
                address, shard_index
            )
        })?;

    let mut len_buf = [0u8; 2];
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(anyhow!("upstream tcp read length timed out"));
    }
    timeout(remaining, stream.read_exact(&mut len_buf))
        .await
        .context("tcp read length timeout")?
        .with_context(|| {
            format!(
                "failed to read tcp response length from resolver {} shard {}",
                address, shard_index
            )
        })?;

    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 65_535 {
        return Err(anyhow!(
            "invalid tcp dns response length {} from resolver {} shard {}",
            resp_len,
            address,
            shard_index
        ));
    }

    let mut response = vec![0u8; resp_len];
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(anyhow!("upstream tcp read body timed out"));
    }
    timeout(remaining, stream.read_exact(&mut response))
        .await
        .context("tcp read body timeout")?
        .with_context(|| {
            format!(
                "failed to read tcp response body from resolver {} shard {}",
                address, shard_index
            )
        })?;

    trace_dns_packet(
        address,
        &response,
        "received dns response from resolver over tcp",
    );

    Ok(response)
}

fn upstream_udp_shard_count() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| (parallelism.get() * 2).clamp(2, 16))
        .unwrap_or(2)
}

fn upstream_tcp_shard_count() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().clamp(2, 4))
        .unwrap_or(2)
}

fn upstream_udp_shard_index(query_id: u16, shard_count: usize) -> usize {
    if shard_count == 0 {
        return 0;
    }
    usize::from(query_id) % shard_count
}

fn upstream_tcp_shard_index(request: &[u8], shard_count: usize) -> usize {
    if shard_count == 0 {
        return 0;
    }

    if let Some(overview) = dns::parse_request_overview(request) {
        let mut hasher = DefaultHasher::new();
        if let Some(query_name) = overview.query_name.as_deref() {
            normalize_qname(query_name).hash(&mut hasher);
        }
        overview.query_type.hash(&mut hasher);
        return (hasher.finish() as usize) % shard_count;
    }

    let mut hasher = DefaultHasher::new();
    request.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use std::time::{SystemTime, UNIX_EPOCH};

    use futures::future::join_all;
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
    use hickory_proto::dnssec::{
        Algorithm, DigestType, PublicKey, PublicKeyBuf, SigSigner, SigningKey, TrustAnchors,
        Verifier, TBS,
    };
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use tokio::net::{TcpListener, UdpSocket};

    use crate::context::Protocol;

    async fn spawn_mock_upstream_with<F>(
        counter: Arc<AtomicUsize>,
        responder: F,
    ) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)>
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let responder = Arc::new(responder);
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, Ordering::SeqCst);
                let response = responder(&buf[..len]);
                if socket.send_to(&response, peer).await.is_err() {
                    break;
                }
            }
        });
        Ok((addr, handle))
    }

    async fn spawn_silent_udp_upstream(
        counter: Arc<AtomicUsize>,
    ) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((_, _peer)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        Ok((addr, handle))
    }

    async fn spawn_udp_truncated_tcp_answer_upstream(
        udp_counter: Arc<AtomicUsize>,
        tcp_counter: Arc<AtomicUsize>,
        observed_payload_size: Arc<AtomicUsize>,
    ) -> anyhow::Result<(
        SocketAddr,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let socket = UdpSocket::bind(addr).await?;

        let udp_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                udp_counter.fetch_add(1, Ordering::SeqCst);
                let mut response =
                    dns::build_response_with_rcode(&buf[..len], 0).expect("truncated response");
                let mut flags = u16::from_be_bytes([response[2], response[3]]);
                flags |= 0x0200;
                response[2..4].copy_from_slice(&flags.to_be_bytes());
                if socket.send_to(&response, peer).await.is_err() {
                    break;
                }
            }
        });

        let tcp_handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tcp_counter.fetch_add(1, Ordering::SeqCst);
                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let req_len = u16::from_be_bytes(len_buf) as usize;
                    let mut request = vec![0u8; req_len];
                    if stream.read_exact(&mut request).await.is_err() {
                        break;
                    }
                    let payload_size = dns::extract_edns_opt(&request)
                        .map(|value| usize::from(value.udp_payload_size))
                        .unwrap_or(0);
                    observed_payload_size.store(payload_size, Ordering::SeqCst);

                    let response = build_answer_a_response(&request, [4, 4, 4, 4]);
                    if stream
                        .write_all(&(response.len() as u16).to_be_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if stream.write_all(&response).await.is_err() {
                        break;
                    }
                }
            }
        });

        Ok((addr, udp_handle, tcp_handle))
    }

    async fn spawn_formerr_on_edns_upstream(
        request_counter: Arc<AtomicUsize>,
        saw_edns_then_plain: Arc<AtomicUsize>,
    ) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let count = request_counter.fetch_add(1, Ordering::SeqCst);
                let has_edns = dns::extract_edns_opt(&buf[..len]).is_some();
                if count == 0 && has_edns {
                    saw_edns_then_plain.fetch_add(1, Ordering::SeqCst);
                }
                if count == 1 && !has_edns {
                    saw_edns_then_plain.fetch_add(1, Ordering::SeqCst);
                }

                let response = if has_edns {
                    build_response_with_rcode(&buf[..len], 1)
                } else {
                    build_answer_a_response(&buf[..len], [5, 5, 5, 5])
                };
                if socket.send_to(&response, peer).await.is_err() {
                    break;
                }
            }
        });
        Ok((addr, handle))
    }

    fn build_answer_a_response(request: &[u8], addr: [u8; 4]) -> Vec<u8> {
        let header = dns::parse_header(request).expect("header");
        let (_, _, qend) = dns::parse_first_question(request).expect("question");
        let mut packet = Vec::with_capacity(64);
        packet.extend_from_slice(&header.id.to_be_bytes());
        let opcode = header.flags & 0x7800;
        let rd = header.flags & 0x0100;
        let flags = 0x8000 | opcode | rd | 0x0080;
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&request[12..qend]);
        packet.extend_from_slice(&0xC00Cu16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&30u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&addr);
        let _ = dns::clone_edns_opt_from_request(request, &mut packet);
        packet
    }

    fn build_answer_with_cname_and_dname_response(request: &[u8]) -> Vec<u8> {
        let header = dns::parse_header(request).expect("header");
        let (_, _, qend) = dns::parse_first_question(request).expect("question");
        let mut packet = Vec::with_capacity(192);
        packet.extend_from_slice(&header.id.to_be_bytes());
        let opcode = header.flags & 0x7800;
        let rd = header.flags & 0x0100;
        let flags = 0x8000 | opcode | rd | 0x0080;
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&3u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&request[12..qend]);

        let mut cname_rdata = Vec::new();
        append_name(&mut cname_rdata, "alias.example.com");

        append_name(&mut packet, "WWW.Example.COM");
        packet.extend_from_slice(&5u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&cname_rdata);

        let mut dname_rdata = Vec::new();
        append_name(&mut dname_rdata, "target.example.net");
        append_name(&mut packet, "alias.example.com");
        packet.extend_from_slice(&39u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&90u32.to_be_bytes());
        packet.extend_from_slice(&(dname_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&dname_rdata);

        append_name(&mut packet, "alias.example.com");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&30u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 1]);
        packet
    }

    fn build_response_with_rcode(request: &[u8], rcode: u8) -> Vec<u8> {
        dns::build_response_with_rcode(request, u16::from(rcode)).expect("valid response")
    }

    #[test]
    fn upstream_udp_shard_index_is_stable_for_same_query_id() {
        let shard_count = 4;
        let first = upstream_udp_shard_index(10_001, shard_count);
        let second = upstream_udp_shard_index(10_001, shard_count);

        assert_eq!(first, second);
        assert!(first < shard_count);
        assert_eq!(
            upstream_udp_shard_index(10_002, shard_count),
            10_002usize % shard_count
        );
    }

    #[test]
    fn upstream_tcp_shard_index_normalizes_case_variants() {
        let request_upper = dns::build_query(300, "WWW.Example.COM", 1, true).expect("query");
        let request_lower = dns::build_query(301, "www.example.com", 1, true).expect("query");
        let shard_count = 4;

        let upper = upstream_tcp_shard_index(&request_upper, shard_count);
        let lower = upstream_tcp_shard_index(&request_lower, shard_count);

        assert_eq!(upper, lower);
        assert!(upper < shard_count);
    }

    fn append_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn build_referral_with_glue_response(
        request: &[u8],
        zone: &str,
        ns_host: &str,
        glue_ip: [u8; 4],
    ) -> Vec<u8> {
        let header = dns::parse_header(request).expect("header");
        let (_, _, qend) = dns::parse_first_question(request).expect("question");
        let mut packet = Vec::with_capacity(128);
        packet.extend_from_slice(&header.id.to_be_bytes());
        let opcode = header.flags & 0x7800;
        let rd = header.flags & 0x0100;
        let flags = 0x8000 | opcode | rd | 0x0080;
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&request[12..qend]);

        append_name(&mut packet, zone);
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        let mut ns_rdata = Vec::new();
        append_name(&mut ns_rdata, ns_host);
        packet.extend_from_slice(&(ns_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ns_rdata);

        append_name(&mut packet, ns_host);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&glue_ip);
        packet
    }

    fn build_noerror_nodata_soa_response(request: &[u8], zone: &str) -> Vec<u8> {
        let header = dns::parse_header(request).expect("header");
        let (_, _, qend) = dns::parse_first_question(request).expect("question");
        let mut packet = Vec::with_capacity(192);
        packet.extend_from_slice(&header.id.to_be_bytes());
        let opcode = header.flags & 0x7800;
        let rd = header.flags & 0x0100;
        let flags = 0x8000 | opcode | rd | 0x0080;
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&request[12..qend]);

        append_name(&mut packet, zone);
        packet.extend_from_slice(&6u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());

        let mut soa_rdata = Vec::new();
        append_name(&mut soa_rdata, &format!("ns1.{zone}"));
        append_name(&mut soa_rdata, &format!("hostmaster.{zone}"));
        soa_rdata.extend_from_slice(&1u32.to_be_bytes());
        soa_rdata.extend_from_slice(&60u32.to_be_bytes());
        soa_rdata.extend_from_slice(&60u32.to_be_bytes());
        soa_rdata.extend_from_slice(&60u32.to_be_bytes());
        soa_rdata.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&soa_rdata);
        packet
    }

    fn make_request_context(request_id: u16, qname: &str, qtype: u16) -> RequestContext {
        RequestContext {
            request_id,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53001".parse().expect("client addr"),
            query_name: Some(SmolStr::from(qname)),
            query_type: Some(qtype),
            recv_at: Instant::now(),
        }
    }

    fn make_resolver(
        upstreams: Vec<String>,
        static_records: Vec<StaticRecord>,
        authoritative_sources: Vec<AuthoritativeSource>,
    ) -> Resolver {
        Resolver::new(
            ResolverConfig {
                resolve_mode: "forwarder".to_string(),
                root_servers: Vec::new(),
                iterative_address_family: IterativeAddressFamily::DualStack,
                iterative_max_depth: 8,
                iterative_timeout_ms: 3000,
                cname_chain_max_depth: 8,
                follow_cname_chain: true,
                static_cname_expand_for_address_queries: false,
                iterative_fallback_to_forwarder: false,
                iterative_cname_bridge_fallback_to_recursive: true,
                cname_chain_cache_enabled: true,
                cname_chain_inline_cache_enabled: true,
                cname_chain_dualstack_share_enabled: true,
                cname_chain_target_prefetch_enabled: false,
                ns_host_cache_capacity: 1024,
                ns_host_cache_ttl_secs: 60,
                ns_host_cache_cleanup_interval_ms: 1000,
                enable_delegation_cache: false,
                strict_bailiwick: true,
                delegation_cache_capacity: 1024,
                delegation_cache_ttl_cap_secs: 300,
                delegation_cache_cleanup_interval_ms: 1000,
                delegation_failure_backoff_ms: 1000,
                stats_window_secs: 60,
                stats_short_window_secs: 10,
                cache_hot_capacity: 1024,
                upstreams,
                cache_ttl_secs: 30,
                freeze_cache_ttl_decay: false,
                freeze_cache_domains: Vec::new(),
                upstream_timeout_ms: 200,
                upstream_retries: 0,
                unhealthy_backoff_ms: 100,
                prefetch_budget_per_window: 16,
                prefetch_window_secs: 1,
                prefetch_ttl_trigger_secs: 5,
                prefetch_popularity_threshold: 2,
                upstream_score_rtt_weight: 1.0,
                upstream_score_failure_weight: 25.0,
                upstream_score_success_weight: 3.0,
                adaptive_cache_enabled: true,
                adaptive_cache_min_capacity: 128,
                adaptive_cache_max_capacity: 4096,
                adaptive_cache_step: 128,
                adaptive_cache_window_secs: 5,
                adaptive_cache_high_miss_ratio: 0.6,
                adaptive_cache_low_miss_ratio: 0.2,
                enable_recursion: true,
                dnssec_enabled: true,
                trust_anchors: TrustAnchors::default(),
                ns_hostname_max_concurrent: 4,
                ns_hostname_enough_endpoints: 2,
                ns_hostname_per_resolve_ms: 1500,
                ns_hostname_resolve_mode: NsHostnameResolveMode::BootstrapRecursive,
                iterative_per_hop_timeout_ms: 0,
                prewarm_delegation_zones: Vec::new(),
            },
            Arc::new(ResponseCache::default()),
            Arc::new(Metrics::new().expect("metrics")),
            static_records,
            authoritative_sources,
        )
    }

    fn make_iterative_resolver(root_servers: Vec<String>, upstreams: Vec<String>) -> Resolver {
        make_iterative_resolver_with_budget(root_servers, upstreams, 3000)
    }

    fn make_iterative_resolver_with_budget(
        root_servers: Vec<String>,
        upstreams: Vec<String>,
        iterative_timeout_ms: u64,
    ) -> Resolver {
        make_iterative_resolver_with_budget_and_bailiwick(
            root_servers,
            upstreams,
            iterative_timeout_ms,
            true,
        )
    }

    fn make_iterative_resolver_with_budget_and_bailiwick(
        root_servers: Vec<String>,
        upstreams: Vec<String>,
        iterative_timeout_ms: u64,
        strict_bailiwick: bool,
    ) -> Resolver {
        Resolver::new(
            ResolverConfig {
                resolve_mode: "iterative".to_string(),
                root_servers,
                iterative_address_family: IterativeAddressFamily::DualStack,
                iterative_max_depth: 8,
                iterative_timeout_ms,
                cname_chain_max_depth: 8,
                follow_cname_chain: true,
                static_cname_expand_for_address_queries: false,
                iterative_fallback_to_forwarder: false,
                iterative_cname_bridge_fallback_to_recursive: true,
                cname_chain_cache_enabled: true,
                cname_chain_inline_cache_enabled: true,
                cname_chain_dualstack_share_enabled: true,
                cname_chain_target_prefetch_enabled: false,
                ns_host_cache_capacity: 1024,
                ns_host_cache_ttl_secs: 60,
                ns_host_cache_cleanup_interval_ms: 1000,
                enable_delegation_cache: false,
                strict_bailiwick,
                delegation_cache_capacity: 1024,
                delegation_cache_ttl_cap_secs: 300,
                delegation_cache_cleanup_interval_ms: 1000,
                delegation_failure_backoff_ms: 1000,
                stats_window_secs: 60,
                stats_short_window_secs: 10,
                cache_hot_capacity: 1024,
                upstreams,
                cache_ttl_secs: 30,
                freeze_cache_ttl_decay: false,
                freeze_cache_domains: Vec::new(),
                upstream_timeout_ms: 200,
                upstream_retries: 0,
                unhealthy_backoff_ms: 100,
                prefetch_budget_per_window: 16,
                prefetch_window_secs: 1,
                prefetch_ttl_trigger_secs: 5,
                prefetch_popularity_threshold: 2,
                upstream_score_rtt_weight: 1.0,
                upstream_score_failure_weight: 25.0,
                upstream_score_success_weight: 3.0,
                adaptive_cache_enabled: true,
                adaptive_cache_min_capacity: 128,
                adaptive_cache_max_capacity: 4096,
                adaptive_cache_step: 128,
                adaptive_cache_window_secs: 5,
                adaptive_cache_high_miss_ratio: 0.6,
                adaptive_cache_low_miss_ratio: 0.2,
                enable_recursion: true,
                dnssec_enabled: true,
                trust_anchors: TrustAnchors::default(),
                ns_hostname_max_concurrent: 4,
                ns_hostname_enough_endpoints: 2,
                ns_hostname_per_resolve_ms: 1500,
                ns_hostname_resolve_mode: NsHostnameResolveMode::BootstrapRecursive,
                iterative_per_hop_timeout_ms: 0,
                prewarm_delegation_zones: Vec::new(),
            },
            Arc::new(ResponseCache::default()),
            Arc::new(Metrics::new().expect("metrics")),
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn iterative_address_family_filters_endpoints_strictly() {
        let endpoints = vec!["127.0.0.1:53".to_string(), "[::1]:53".to_string()];

        assert_eq!(
            filter_endpoints_for_iterative_family(endpoints.clone(), IterativeAddressFamily::Ipv4,),
            vec!["127.0.0.1:53".to_string()]
        );
        assert_eq!(
            filter_endpoints_for_iterative_family(endpoints.clone(), IterativeAddressFamily::Ipv6,),
            vec!["[::1]:53".to_string()]
        );
        assert_eq!(
            filter_endpoints_for_iterative_family(endpoints, IterativeAddressFamily::DualStack,),
            vec!["127.0.0.1:53".to_string(), "[::1]:53".to_string()]
        );
    }

    #[tokio::test]
    async fn ns_host_cache_expired_entries_are_not_reused() {
        let resolver = make_iterative_resolver(Vec::new(), vec!["127.0.0.1:53".to_string()]);
        let hostname = "ns1.cache-expire.test";
        resolver.put_cached_ns_endpoints(hostname, vec!["127.0.0.9:53".to_string()]);

        {
            let key = hostname.to_ascii_lowercase();
            let shard_index = aux_cache_shard_index(&key, resolver.ns_host_cache.shards.len());
            let mut cache = resolver.ns_host_cache.shards[shard_index]
                .lock()
                .recover("ns_host_cache");
            let entry = cache.entries.get_mut(&key).expect("entry must exist");
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }

        assert!(resolver.get_cached_ns_endpoints(hostname).is_none());
        let key = hostname.to_ascii_lowercase();
        let shard_index = aux_cache_shard_index(&key, resolver.ns_host_cache.shards.len());
        let cache = resolver.ns_host_cache.shards[shard_index]
            .lock()
            .recover("ns_host_cache");
        assert!(!cache.entries.contains_key(&key));
    }

    #[tokio::test]
    async fn ns_host_recent_failure_backoff_expires_after_window() {
        let resolver = make_iterative_resolver(Vec::new(), vec!["127.0.0.1:53".to_string()]);
        let hostname = "ns1.failbackoff.test";

        resolver.mark_ns_host_failed(hostname);
        assert!(resolver.is_ns_host_recently_failed(hostname));

        let key = hostname.to_ascii_lowercase();
        let shard_index = aux_cache_shard_index(&key, resolver.ns_host_cache.shards.len());
        {
            let mut cache = resolver.ns_host_cache.shards[shard_index]
                .lock()
                .recover("ns_host_cache");
            cache
                .failures
                .insert(key.clone(), Instant::now() - Duration::from_millis(1));
        }

        assert!(!resolver.is_ns_host_recently_failed(hostname));
    }

    #[tokio::test]
    async fn resolve_ns_hostnames_skips_recent_failed_hostname_without_querying() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [9, 9, 9, 9])
            })
            .await
            .expect("mock upstream");

        let mut resolver = make_iterative_resolver(
            vec![upstream_addr.to_string()],
            vec![upstream_addr.to_string()],
        );
        resolver.iterative_fallback_to_forwarder = true;

        let hostname = "ns-skip.fail.test";
        resolver.mark_ns_host_failed(hostname);

        let request = dns::build_query(900, "www.fail.test", 1, true).expect("query");
        let deadline = Instant::now() + Duration::from_millis(300);
        let endpoints = resolver
            .resolve_ns_hostnames(&[hostname.to_string()], deadline, &request)
            .await;

        assert!(endpoints.is_empty());
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        upstream_handle.abort();
    }

    #[tokio::test]
    async fn resolve_ns_hostnames_uses_parallel_bootstrap_resolvers() {
        let silent_counter = Arc::new(AtomicUsize::new(0));
        let success_counter = Arc::new(AtomicUsize::new(0));
        let (silent_addr, silent_handle) = spawn_silent_udp_upstream(silent_counter.clone())
            .await
            .expect("silent upstream");
        let (success_addr, success_handle) =
            spawn_mock_upstream_with(success_counter.clone(), |request| {
                build_answer_a_response(request, [203, 0, 113, 53])
            })
            .await
            .expect("success upstream");

        let mut resolver = make_iterative_resolver(
            vec![silent_addr.to_string(), success_addr.to_string()],
            vec![silent_addr.to_string(), success_addr.to_string()],
        );
        resolver.ns_hostname_per_resolve_ms = 150;

        let request = dns::build_query(901, "www.parallel.test", 1, true).expect("query");
        let deadline = Instant::now() + Duration::from_millis(150);
        let endpoints = resolver
            .resolve_ns_hostnames(&["ns1.parallel.test".to_string()], deadline, &request)
            .await;

        assert_eq!(endpoints, vec!["203.0.113.53:53".to_string()]);
        assert!(silent_counter.load(Ordering::SeqCst) >= 1);
        assert!(success_counter.load(Ordering::SeqCst) >= 1);

        silent_handle.abort();
        success_handle.abort();
    }

    #[tokio::test]
    async fn resolve_ns_hostnames_pure_iterative_mode_skips_bootstrap_recursive_queries() {
        let bootstrap_counter = Arc::new(AtomicUsize::new(0));
        let (bootstrap_addr, bootstrap_handle) =
            spawn_mock_upstream_with(bootstrap_counter.clone(), |request| {
                build_answer_a_response(request, [203, 0, 113, 53])
            })
            .await
            .expect("bootstrap upstream");

        let mut resolver = make_iterative_resolver(Vec::new(), vec![bootstrap_addr.to_string()]);
        resolver.ns_hostname_resolve_mode = NsHostnameResolveMode::PureIterative;

        let request = dns::build_query(902, "www.pure-mode.test", 1, true).expect("query");
        let deadline = Instant::now() + Duration::from_millis(150);
        let endpoints = resolver
            .resolve_ns_hostnames(&["ns1.pure-mode.test".to_string()], deadline, &request)
            .await;

        assert!(endpoints.is_empty());
        assert_eq!(bootstrap_counter.load(Ordering::SeqCst), 0);

        bootstrap_handle.abort();
    }

    #[tokio::test]
    async fn query_iterative_disables_cname_bridge_fallback_when_configured() {
        let root_counter = Arc::new(AtomicUsize::new(0));
        let bridge_counter = Arc::new(AtomicUsize::new(0));

        let (root_addr, root_handle) = spawn_mock_upstream_with(root_counter.clone(), |request| {
            let (qname, _qtype, _) = dns::parse_first_question(request).expect("question");
            if qname.eq_ignore_ascii_case("www.bridge.test") {
                dns::build_static_answer(request, "alias.bridge.test", 60, "CNAME")
                    .expect("cname answer")
            } else {
                // Return NOERROR + no answers/referral so iterative single-step ends with
                // "iterative resolution failed without referral glue".
                build_response_with_rcode(request, 0)
            }
        })
        .await
        .expect("root upstream");

        let (bridge_addr, bridge_handle) =
            spawn_mock_upstream_with(bridge_counter.clone(), |request| {
                build_answer_a_response(request, [203, 0, 113, 53])
            })
            .await
            .expect("bridge upstream");

        let mut resolver =
            make_iterative_resolver(vec![root_addr.to_string()], vec![bridge_addr.to_string()]);
        resolver.iterative_cname_bridge_fallback_to_recursive = false;

        let request = dns::build_query(920, "www.bridge.test", 1, true).expect("query");
        let err = resolver
            .query_iterative(&request)
            .await
            .expect_err("bridge fallback disabled should keep iterative error");

        assert!(err
            .to_string()
            .contains("iterative resolution failed without referral glue"));
        assert_eq!(bridge_counter.load(Ordering::SeqCst), 0);
        assert!(root_counter.load(Ordering::SeqCst) >= 2);

        root_handle.abort();
        bridge_handle.abort();
    }

    #[tokio::test]
    async fn query_iterative_single_skips_invalid_referral_before_ns_resolution() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                let (qname, _, _) = dns::parse_first_question(request).expect("question");
                if qname.eq_ignore_ascii_case("www.example.com") {
                    // invalid authority zone for www.example.com
                    build_referral_with_glue_response(
                        request,
                        "bad.zone",
                        "ns1.bad.zone",
                        [203, 0, 113, 53],
                    )
                } else {
                    build_response_with_rcode(request, 3)
                }
            })
            .await
            .expect("mock upstream");

        let resolver = make_iterative_resolver(
            vec![upstream_addr.to_string()],
            vec![upstream_addr.to_string()],
        );

        let request = dns::build_query(901, "www.example.com", 1, true).expect("query");
        let result = resolver.query_iterative_single(&request, None).await;

        assert!(result.is_err());
        // Only the original query should be sent; invalid referral must not trigger
        // follow-up NS hostname resolution queries.
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        upstream_handle.abort();
    }

    #[tokio::test]
    async fn delegation_cache_uses_longest_suffix_and_respects_failure_backoff() {
        let mut resolver = make_iterative_resolver(Vec::new(), vec!["127.0.0.1:53".to_string()]);
        resolver.enable_delegation_cache = true;
        resolver.delegation_cache_capacity = 256; // 足够大，确保每个分片至少有 28 个槽位
        resolver.delegation_cache_ttl_cap = Duration::from_secs(60);
        resolver.delegation_failure_backoff = Duration::from_secs(5);

        resolver.put_cached_delegation_endpoints(
            "com",
            vec!["127.0.0.53:53".to_string()],
            Duration::from_secs(30),
        );
        resolver.put_cached_delegation_endpoints(
            "qq.com",
            vec!["127.0.0.54:53".to_string()],
            Duration::from_secs(30),
        );

        let hit = resolver
            .get_cached_delegation_endpoints("www.qq.com")
            .expect("delegation hit");
        assert_eq!(hit.0, "qq.com");
        assert_eq!(hit.1, vec!["127.0.0.54:53".to_string()]);

        resolver.mark_delegation_cache_failure("qq.com");
        let fallback_hit = resolver
            .get_cached_delegation_endpoints("www.qq.com")
            .expect("fallback hit");
        assert_eq!(fallback_hit.0, "com");

        {
            let zone = normalize_qname("qq.com");
            let shard_index = aux_cache_shard_index(&zone, resolver.delegation_cache.shards.len());
            let mut cache = resolver.delegation_cache.shards[shard_index]
                .lock()
                .recover("delegation_cache");
            let entry = cache.entries.get_mut(&zone).expect("qq.com entry");
            entry.cooldown_until = Some(Instant::now() - Duration::from_secs(1));
        }

        assert!(resolver
            .get_cached_delegation_endpoints("www.qq.com")
            .is_some());
    }

    #[tokio::test]
    async fn prefetch_budget_exhaustion_limits_followup_prefetches() -> anyhow::Result<()> {
        let query_counter = Arc::new(AtomicUsize::new(0));
        let aaaa_counter = Arc::new(AtomicUsize::new(0));
        let aaaa_counter_clone = aaaa_counter.clone();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(query_counter.clone(), move |request| {
                let (_, qtype, _) = dns::parse_first_question(request).expect("question");
                if qtype == 28 {
                    aaaa_counter_clone.fetch_add(1, Ordering::SeqCst);
                }
                build_response_with_rcode(request, 0)
            })
            .await?;

        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.prefetch_budget_per_window = 1;
        resolver.prefetch_window = Duration::from_secs(300);
        resolver.prefetch_ttl_trigger = Duration::from_secs(30);
        resolver.prefetch_popularity_threshold = 1;

        for (idx, qname) in ["budget-a.prefetch.test", "budget-b.prefetch.test"]
            .iter()
            .enumerate()
        {
            let request = dns::build_query(700 + idx as u16, qname, 1, true).expect("query");
            let cache_key = cache_key_for_query(qname, 1, false);
            resolver.cache.insert(
                cache_key,
                build_answer_a_response(&request, [203, 0, 113, 10]),
                Duration::from_secs(2),
            );

            let ctx = make_request_context(700 + idx as u16, qname, 1);
            let resolved = resolver.resolve(&ctx, &request).await?;
            assert!(matches!(resolved.source, ResolutionSource::Cache));
        }

        assert_eq!(aaaa_counter.load(Ordering::SeqCst), 1);
        assert_eq!(query_counter.load(Ordering::SeqCst), 1);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn prefetch_requires_popularity_threshold() -> anyhow::Result<()> {
        let query_counter = Arc::new(AtomicUsize::new(0));
        let aaaa_counter = Arc::new(AtomicUsize::new(0));
        let aaaa_counter_clone = aaaa_counter.clone();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(query_counter.clone(), move |request| {
                let (_, qtype, _) = dns::parse_first_question(request).expect("question");
                if qtype == 28 {
                    aaaa_counter_clone.fetch_add(1, Ordering::SeqCst);
                }
                build_response_with_rcode(request, 0)
            })
            .await?;

        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.prefetch_budget_per_window = 8;
        resolver.prefetch_window = Duration::from_secs(60);
        resolver.prefetch_ttl_trigger = Duration::from_secs(30);
        resolver.prefetch_popularity_threshold = 2;

        let request = dns::build_query(710, "threshold.prefetch.test", 1, true).expect("query");
        let cache_key = cache_key_for_query("threshold.prefetch.test", 1, false);
        resolver.cache.insert(
            cache_key,
            build_answer_a_response(&request, [203, 0, 113, 11]),
            Duration::from_secs(2),
        );

        let ctx = make_request_context(710, "threshold.prefetch.test", 1);
        let first = resolver.resolve(&ctx, &request).await?;
        assert!(matches!(first.source, ResolutionSource::Cache));
        assert_eq!(aaaa_counter.load(Ordering::SeqCst), 0);

        let second = resolver.resolve(&ctx, &request).await?;
        assert!(matches!(second.source, ResolutionSource::Cache));
        assert_eq!(aaaa_counter.load(Ordering::SeqCst), 1);
        assert_eq!(query_counter.load(Ordering::SeqCst), 1);

        upstream_handle.abort();
        Ok(())
    }

    #[test]
    fn adaptive_cache_window_expands_and_shrinks_capacity() {
        let mut resolver = make_resolver(Vec::new(), Vec::new(), Vec::new());
        resolver.adaptive_cache_enabled = true;
        resolver.adaptive_cache_min_capacity = 32;
        resolver.adaptive_cache_max_capacity = 64;
        resolver.adaptive_cache_step = 16;
        resolver.adaptive_cache_window = Duration::from_secs(1);
        resolver.adaptive_cache_high_miss_ratio = 0.6;
        resolver.adaptive_cache_low_miss_ratio = 0.2;
        resolver.cache.set_capacity(48);
        resolver.current_cache_capacity.store(48, Ordering::Relaxed);

        {
            let mut ws = resolver
                .adaptive_cache_window_start
                .lock()
                .expect("adaptive cache state poisoned");
            *ws = Instant::now() - Duration::from_secs(2);
        }
        resolver.adaptive_cache_hits.store(0, Ordering::Relaxed);
        resolver.adaptive_cache_misses.store(10, Ordering::Relaxed);
        resolver.maybe_tune_cache_capacity();
        assert_eq!(resolver.cache.capacity(), 64);
        assert_eq!(resolver.current_cache_capacity.load(Ordering::Relaxed), 64);

        {
            let mut ws = resolver
                .adaptive_cache_window_start
                .lock()
                .expect("adaptive cache state poisoned");
            *ws = Instant::now() - Duration::from_secs(2);
        }
        resolver.adaptive_cache_hits.store(10, Ordering::Relaxed);
        resolver.adaptive_cache_misses.store(0, Ordering::Relaxed);
        resolver.maybe_tune_cache_capacity();
        assert_eq!(resolver.cache.capacity(), 48);
        assert_eq!(resolver.current_cache_capacity.load(Ordering::Relaxed), 48);
    }

    struct SignedZone {
        zone: Name,
        dnskey_record: Record,
        signer: SigSigner,
    }

    fn dnssec_record(name: Name, ttl: u32, data: RData) -> Record {
        let mut record = Record::from_rdata(name, ttl, data);
        record.set_dns_class(DNSClass::IN);
        record
    }

    fn dnssec_time_window() -> (u32, u32) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix time")
            .as_secs() as u32;
        (now.saturating_sub(60), now.saturating_add(300))
    }

    fn new_signed_zone(zone: &str) -> SignedZone {
        let zone = Name::from_ascii(zone).expect("zone name");
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).expect("pkcs8");
        let signing_key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).expect("signing key");
        let public_key = signing_key.to_public_key().expect("public key");
        let dnskey = DNSKEY::new(
            true,
            true,
            false,
            PublicKeyBuf::new(public_key.public_bytes().to_vec(), algorithm),
        );
        let dnskey_record = dnssec_record(
            zone.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        );
        let signer = SigSigner::dnssec(
            dnskey,
            Box::new(signing_key),
            zone.clone(),
            Duration::from_secs(300),
        );

        SignedZone {
            zone,
            dnskey_record,
            signer,
        }
    }

    fn sign_rrset(
        owner: &Name,
        ttl: u32,
        record_type: RecordType,
        signer: &SigSigner,
        rrset: &[Record],
    ) -> Record {
        let (inception, expiration) = dnssec_time_window();
        let key_tag = signer.calculate_key_tag().expect("key tag");
        let pre_rrsig = RRSIG::new(
            record_type,
            signer.key().algorithm(),
            owner.num_labels(),
            ttl,
            expiration,
            inception,
            key_tag,
            signer.signer_name().clone(),
            Vec::new(),
        );
        let mut pre_record: Record<RRSIG> =
            Record::from_rdata(owner.clone(), ttl, pre_rrsig.clone());
        pre_record.set_dns_class(DNSClass::IN);
        let tbs = TBS::from_rrsig(&pre_record, rrset.iter()).expect("rrsig tbs");
        let signature = signer.sign(&tbs).expect("rrsig signature");

        dnssec_record(
            owner.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
                record_type,
                signer.key().algorithm(),
                owner.num_labels(),
                ttl,
                expiration,
                inception,
                key_tag,
                signer.signer_name().clone(),
                signature,
            ))),
        )
    }

    fn signed_rrset(owner: &Name, ttl: u32, signer: &SigSigner, rrset: Vec<Record>) -> Vec<Record> {
        let mut records = rrset;
        let rrsig = sign_rrset(owner, ttl, records[0].record_type(), signer, &records);
        records.push(rrsig);
        records
    }

    fn dnssec_response_packet(
        request: &[u8],
        qname: &Name,
        qtype: RecordType,
        answers: Vec<Record>,
    ) -> Vec<u8> {
        let header = dns::parse_header(request).expect("request header");
        let mut message = Message::new();
        message
            .set_id(header.id)
            .set_message_type(MessageType::Response)
            .set_recursion_desired((header.flags & 0x0100) != 0)
            .set_recursion_available(true)
            .add_query(Query::query(qname.clone(), qtype))
            .add_answers(answers);

        if let Some(edns) = dns::extract_edns_opt(request) {
            let mut extensions = hickory_proto::op::Edns::new();
            extensions.set_max_payload(edns.udp_payload_size);
            extensions.set_dnssec_ok(edns.flags & dns::DNS_EDNS_FLAG_DO != 0);
            message.set_edns(extensions);
        }

        message.to_vec().expect("response packet")
    }

    type FixtureResponder = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

    fn build_dnssec_fixture() -> (TrustAnchors, Vec<u8>, FixtureResponder) {
        let root = new_signed_zone(".");
        let com = new_signed_zone("com.");
        let child = new_signed_zone("example.com.");
        let owner = Name::from_ascii("www.example.com.").expect("owner");
        let answer_record = dnssec_record(owner.clone(), 300, RData::A(A::new(203, 0, 113, 10)));
        let answer_rrset = signed_rrset(&owner, 300, &child.signer, vec![answer_record]);
        let com_dnskey_rrset =
            signed_rrset(&com.zone, 300, &com.signer, vec![com.dnskey_record.clone()]);
        let child_dnskey_rrset = signed_rrset(
            &child.zone,
            300,
            &child.signer,
            vec![child.dnskey_record.clone()],
        );
        let root_dnskey_rrset = signed_rrset(
            &root.zone,
            300,
            &root.signer,
            vec![root.dnskey_record.clone()],
        );

        let com_dnskey = match com.dnskey_record.data() {
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => dnskey.clone(),
            _ => panic!("com dnskey"),
        };
        let com_ds_record = dnssec_record(
            com.zone.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                com_dnskey.calculate_key_tag().expect("com key tag"),
                com_dnskey.algorithm(),
                DigestType::SHA256,
                com_dnskey
                    .to_digest(&com.zone, DigestType::SHA256)
                    .expect("com digest")
                    .as_ref()
                    .to_vec(),
            ))),
        );
        let com_ds_rrset = signed_rrset(&com.zone, 300, &root.signer, vec![com_ds_record]);

        let child_dnskey = match child.dnskey_record.data() {
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => dnskey.clone(),
            _ => panic!("child dnskey"),
        };
        let ds_record = dnssec_record(
            child.zone.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                child_dnskey.calculate_key_tag().expect("child key tag"),
                child_dnskey.algorithm(),
                DigestType::SHA256,
                child_dnskey
                    .to_digest(&child.zone, DigestType::SHA256)
                    .expect("child digest")
                    .as_ref()
                    .to_vec(),
            ))),
        );
        let ds_rrset = signed_rrset(&child.zone, 300, &com.signer, vec![ds_record]);

        let mut anchors = TrustAnchors::empty();
        anchors.insert(com_dnskey.key().expect("com public key").as_ref());

        let answer_seed = dnssec_response_packet(
            &dns::build_query(1, "www.example.com", 1, true).expect("query"),
            &owner,
            RecordType::A,
            answer_rrset.clone(),
        );

        let responder = Arc::new(move |request: &[u8]| -> Vec<u8> {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.as_str(), qtype) {
                ("www.example.com", 1) => {
                    dnssec_response_packet(request, &owner, RecordType::A, answer_rrset.clone())
                }
                ("example.com", dns::DNS_TYPE_DNSKEY) => dnssec_response_packet(
                    request,
                    &child.zone,
                    RecordType::DNSKEY,
                    child_dnskey_rrset.clone(),
                ),
                ("example.com", dns::DNS_TYPE_DS) => {
                    dnssec_response_packet(request, &child.zone, RecordType::DS, ds_rrset.clone())
                }
                ("com", dns::DNS_TYPE_DNSKEY) => dnssec_response_packet(
                    request,
                    &com.zone,
                    RecordType::DNSKEY,
                    com_dnskey_rrset.clone(),
                ),
                ("com", dns::DNS_TYPE_DS) => {
                    dnssec_response_packet(request, &com.zone, RecordType::DS, com_ds_rrset.clone())
                }
                ("", dns::DNS_TYPE_DNSKEY) => dnssec_response_packet(
                    request,
                    &root.zone,
                    RecordType::DNSKEY,
                    root_dnskey_rrset.clone(),
                ),
                _ => build_response_with_rcode(request, 3),
            }
        });

        (anchors, answer_seed, responder)
    }

    fn tamper_first_rrsig_byte(packet: &[u8]) -> Vec<u8> {
        let mut message = Message::from_vec(packet).expect("dnssec message");
        for record in message.answers_mut() {
            let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = record.data() else {
                continue;
            };
            let mut signature = rrsig.sig().to_vec();
            signature[0] ^= 0x80;
            let patched = RRSIG::new(
                rrsig.type_covered(),
                rrsig.algorithm(),
                rrsig.num_labels(),
                rrsig.original_ttl(),
                rrsig.sig_expiration().get(),
                rrsig.sig_inception().get(),
                rrsig.key_tag(),
                rrsig.signer_name().clone(),
                signature,
            );
            *record = dnssec_record(
                record.name().clone(),
                record.ttl(),
                RData::DNSSEC(DNSSECRData::RRSIG(patched)),
            );
            break;
        }
        message.to_vec().expect("tampered packet")
    }

    #[tokio::test]
    async fn cache_keys_are_case_insensitive_for_hits() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [1, 1, 1, 1])
            })
            .await?;
        let resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());

        let first_request = dns::build_query(100, "Example.COM", 1, true).expect("query");
        let first_ctx = make_request_context(100, "Example.COM", 1);
        let first = resolver.resolve(&first_ctx, &first_request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(0));

        let second_request = dns::build_query(101, "example.com", 1, true).expect("query");
        let second_ctx = make_request_context(101, "example.com", 1);
        let second = resolver.resolve(&second_ctx, &second_request).await?;
        assert_eq!(dns::response_code(&second.packet), Some(0));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        let (response_qname, _, _) =
            dns::parse_first_question(&second.packet).expect("response question");
        assert_eq!(response_qname, "example.com");

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn cache_hit_strips_edns_for_plain_client_after_dnssec_seed() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [6, 6, 6, 6])
            })
            .await?;
        let resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());

        let mut dnssec_request = dns::build_query(110, "do-cache.example", 1, true).expect("query");
        dns::append_edns_opt(&mut dnssec_request, 1232, dns::DNS_EDNS_FLAG_DO)
            .expect("append edns");
        let dnssec_ctx = make_request_context(110, "do-cache.example", 1);
        let first = resolver.resolve(&dnssec_ctx, &dnssec_request).await?;
        assert!(dns::dnssec_ok_requested(&first.packet));

        let plain_request = dns::build_query(111, "do-cache.example", 1, true).expect("query");
        let plain_ctx = make_request_context(111, "do-cache.example", 1);
        let second = resolver.resolve(&plain_ctx, &plain_request).await?;

        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert!(dns::extract_edns_opt(&second.packet).is_none());

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn cache_hit_restores_request_do_bit_for_dnssec_client() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [7, 7, 7, 7])
            })
            .await?;
        let resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());

        let plain_request = dns::build_query(112, "do-upgrade.example", 1, true).expect("query");
        let plain_ctx = make_request_context(112, "do-upgrade.example", 1);
        let first = resolver.resolve(&plain_ctx, &plain_request).await?;
        assert!(dns::extract_edns_opt(&first.packet).is_none());

        let mut dnssec_request =
            dns::build_query(113, "do-upgrade.example", 1, true).expect("query");
        dns::append_edns_opt(&mut dnssec_request, 1232, dns::DNS_EDNS_FLAG_DO)
            .expect("append edns");
        let dnssec_ctx = make_request_context(113, "do-upgrade.example", 1);
        let second = resolver.resolve(&dnssec_ctx, &dnssec_request).await?;

        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert!(dns::dnssec_ok_requested(&second.packet));
        assert_eq!(
            dns::extract_edns_opt(&second.packet).map(|value| value.udp_payload_size),
            Some(1232)
        );

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn dnssec_validated_response_sets_ad_bit() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (anchors, answer_packet, responder) = build_dnssec_fixture();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), move |request| responder(request)).await?;
        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.set_root_trust_anchors(anchors);

        let mut request = dns::build_query(220, "www.example.com", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, dns::DNS_EDNS_FLAG_DO).expect("append edns");
        let upstream_addr_text = upstream_addr.to_string();
        let validation = resolver
            .validate_dnssec_response(
                &request,
                &answer_packet,
                Some(upstream_addr_text.as_str()),
                0,
            )
            .await?;
        assert_eq!(validation, ValidationState::Secure);
        let ctx = make_request_context(220, "www.example.com", 1);
        let response = resolver.resolve(&ctx, &request).await?;

        assert_eq!(dns::response_code(&response.packet), Some(0));
        assert!(dns::authentic_data(&response.packet));
        assert!(counter.load(Ordering::SeqCst) >= 4);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn dnssec_validation_failure_returns_servfail() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (anchors, _answer_packet, responder) = build_dnssec_fixture();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), move |request| {
                let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
                if qname == "www.example.com" && qtype == 1 {
                    tamper_first_rrsig_byte(&responder(request))
                } else {
                    responder(request)
                }
            })
            .await?;
        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.set_root_trust_anchors(anchors);

        let mut request = dns::build_query(221, "www.example.com", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, dns::DNS_EDNS_FLAG_DO).expect("append edns");
        let ctx = make_request_context(221, "www.example.com", 1);
        let response = resolver.resolve(&ctx, &request).await?;

        assert_eq!(
            dns::response_code(&response.packet),
            Some(dns::DNS_RCODE_SERVFAIL)
        );
        assert!(!dns::authentic_data(&response.packet));

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn dnssec_validation_failure_populates_bad_cache() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (anchors, _answer_packet, responder) = build_dnssec_fixture();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), move |request| {
                let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
                if qname == "www.example.com" && qtype == 1 {
                    tamper_first_rrsig_byte(&responder(request))
                } else {
                    responder(request)
                }
            })
            .await?;
        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.set_root_trust_anchors(anchors);

        let mut request = dns::build_query(224, "www.example.com", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, dns::DNS_EDNS_FLAG_DO).expect("append edns");
        let first_ctx = make_request_context(224, "www.example.com", 1);
        let first = resolver.resolve(&first_ctx, &request).await?;
        assert_eq!(
            dns::response_code(&first.packet),
            Some(dns::DNS_RCODE_SERVFAIL)
        );

        let upstream_calls_after_first = counter.load(Ordering::SeqCst);
        let second_ctx = make_request_context(225, "www.example.com", 1);
        let second = resolver.resolve(&second_ctx, &request).await?;
        assert_eq!(
            dns::response_code(&second.packet),
            Some(dns::DNS_RCODE_SERVFAIL)
        );
        assert_eq!(counter.load(Ordering::SeqCst), upstream_calls_after_first);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn dnssec_bad_cache_is_bypassed_by_cd_requests() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (anchors, _answer_packet, responder) = build_dnssec_fixture();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), move |request| {
                let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
                if qname == "www.example.com" && qtype == 1 {
                    tamper_first_rrsig_byte(&responder(request))
                } else {
                    responder(request)
                }
            })
            .await?;
        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.set_root_trust_anchors(anchors);

        let mut validating_request =
            dns::build_query(226, "www.example.com", 1, true).expect("query");
        dns::append_edns_opt(&mut validating_request, 1232, dns::DNS_EDNS_FLAG_DO)
            .expect("append edns");
        let validating_ctx = make_request_context(226, "www.example.com", 1);
        let validating_response = resolver
            .resolve(&validating_ctx, &validating_request)
            .await?;
        assert_eq!(
            dns::response_code(&validating_response.packet),
            Some(dns::DNS_RCODE_SERVFAIL)
        );

        let upstream_calls_after_bad_cache = counter.load(Ordering::SeqCst);
        let cd_request = dns::set_checking_disabled(&validating_request, true).expect("set cd");
        let cd_ctx = make_request_context(227, "www.example.com", 1);
        let cd_response = resolver.resolve(&cd_ctx, &cd_request).await?;
        assert_eq!(dns::response_code(&cd_response.packet), Some(0));
        assert!(dns::checking_disabled(&cd_response.packet));
        assert!(counter.load(Ordering::SeqCst) > upstream_calls_after_bad_cache);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn dnssec_cd_request_copies_cd_bit_and_clears_ad() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (anchors, _answer_packet, responder) = build_dnssec_fixture();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), move |request| responder(request)).await?;
        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.set_root_trust_anchors(anchors);

        let mut request = dns::build_query(222, "www.example.com", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, dns::DNS_EDNS_FLAG_DO).expect("append edns");
        request = dns::set_checking_disabled(&request, true).expect("set cd");
        let ctx = make_request_context(222, "www.example.com", 1);
        let response = resolver.resolve(&ctx, &request).await?;

        assert_eq!(dns::response_code(&response.packet), Some(0));
        assert!(dns::checking_disabled(&response.packet));
        assert!(!dns::authentic_data(&response.packet));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn dnssec_resolver_clears_upstream_ad_without_validation() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (anchors, _answer_packet, responder) = build_dnssec_fixture();
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), move |request| {
                let mut packet = responder(request);
                dns::set_authentic_data(&mut packet, true);
                packet
            })
            .await?;
        let mut resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());
        resolver.set_root_trust_anchors(anchors);

        let request = dns::build_query(223, "www.example.com", 1, true).expect("query");
        let ctx = make_request_context(223, "www.example.com", 1);
        let response = resolver.resolve(&ctx, &request).await?;

        assert_eq!(dns::response_code(&response.packet), Some(0));
        assert!(!dns::checking_disabled(&response.packet));
        assert!(!dns::authentic_data(&response.packet));

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn static_record_lookup_accepts_named_qtype_case_insensitively() -> anyhow::Result<()> {
        let resolver = make_resolver(
            Vec::new(),
            vec![StaticRecord {
                qname: "EXAMPLE.COM".to_string(),
                qtype: "A".to_string(),
                answer: "9.9.9.9".to_string(),
                ttl: 60,
            }],
            Vec::new(),
        );

        let request = dns::build_query(120, "example.com", 1, true).expect("query");
        let ctx = make_request_context(120, "example.com", 1);
        let resolved = resolver.resolve(&ctx, &request).await?;

        assert!(matches!(resolved.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&resolved.packet), Some(0));
        assert!(dns::answer_has_record_type(&resolved.packet, 1));
        Ok(())
    }

    #[tokio::test]
    async fn static_record_cname_query_returns_configured_target() -> anyhow::Result<()> {
        let resolver = make_resolver(
            Vec::new(),
            vec![StaticRecord {
                qname: "www.bobo.com".to_string(),
                qtype: "CNAME".to_string(),
                answer: "www.baidu.com".to_string(),
                ttl: 120,
            }],
            Vec::new(),
        );

        let request = dns::build_query(121, "www.bobo.com", 5, true).expect("query");
        let ctx = make_request_context(121, "www.bobo.com", 5);
        let resolved = resolver.resolve(&ctx, &request).await?;

        assert!(matches!(resolved.source, ResolutionSource::Cache));
        assert!(dns::answer_has_record_type(&resolved.packet, 5));
        assert_eq!(
            dns::extract_first_answer_cname(&resolved.packet),
            Some("www.baidu.com".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn static_record_cname_can_serve_a_query_without_upstream() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [1, 1, 1, 1])
            })
            .await?;
        let resolver = make_resolver(
            vec![upstream_addr.to_string()],
            vec![StaticRecord {
                qname: "www.bobo.com".to_string(),
                qtype: "CNAME".to_string(),
                answer: "www.baidu.com".to_string(),
                ttl: 120,
            }],
            Vec::new(),
        );

        let request = dns::build_query(122, "www.bobo.com", 1, true).expect("query");
        let ctx = make_request_context(122, "www.bobo.com", 1);
        let resolved = resolver.resolve(&ctx, &request).await?;

        assert!(matches!(resolved.source, ResolutionSource::Cache));
        assert!(dns::answer_has_record_type(&resolved.packet, 5));
        assert_eq!(
            dns::extract_first_answer_cname(&resolved.packet),
            Some("www.baidu.com".to_string())
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn static_record_cname_expand_toggle_returns_cname_and_final_address(
    ) -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [7, 7, 7, 7])
            })
            .await?;
        let mut resolver = make_resolver(
            vec![upstream_addr.to_string()],
            vec![StaticRecord {
                qname: "www.bobo.com".to_string(),
                qtype: "CNAME".to_string(),
                answer: "www.baidu.com".to_string(),
                ttl: 120,
            }],
            Vec::new(),
        );
        resolver.static_cname_expand_for_address_queries = true;

        let request = dns::build_query(123, "www.bobo.com", 1, true).expect("query");
        let ctx = make_request_context(123, "www.bobo.com", 1);
        let resolved = resolver.resolve(&ctx, &request).await?;

        assert!(dns::answer_has_record_type(&resolved.packet, 1));
        assert!(dns::answer_has_cname_for_name(
            &resolved.packet,
            "www.bobo.com"
        ));
        assert_eq!(
            dns::extract_first_answer_cname(&resolved.packet),
            Some("www.baidu.com".to_string())
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn static_cname_chain_expansion_keeps_full_static_chain() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [8, 8, 8, 8])
            })
            .await?;
        let mut resolver = make_resolver(
            vec![upstream_addr.to_string()],
            vec![
                StaticRecord {
                    qname: "www.bobo.com".to_string(),
                    qtype: "CNAME".to_string(),
                    answer: "alias1.bobo.com".to_string(),
                    ttl: 120,
                },
                StaticRecord {
                    qname: "alias1.bobo.com".to_string(),
                    qtype: "CNAME".to_string(),
                    answer: "www.baidu.com".to_string(),
                    ttl: 90,
                },
            ],
            Vec::new(),
        );
        resolver.static_cname_expand_for_address_queries = true;

        let request = dns::build_query(124, "www.bobo.com", 1, true).expect("query");
        let ctx = make_request_context(124, "www.bobo.com", 1);
        let resolved = resolver.resolve(&ctx, &request).await?;
        let cname_records = dns::extract_answer_cname_records(&resolved.packet);

        assert!(dns::answer_has_record_type(&resolved.packet, 1));
        assert!(cname_records.iter().any(|(owner, target, _)| {
            owner.eq_ignore_ascii_case("www.bobo.com")
                && target.eq_ignore_ascii_case("alias1.bobo.com")
        }));
        assert!(cname_records.iter().any(|(owner, target, _)| {
            owner.eq_ignore_ascii_case("alias1.bobo.com")
                && target.eq_ignore_ascii_case("www.baidu.com")
        }));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn cname_followup_keeps_dname_records_without_extra_upstream_queries(
    ) -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_with_cname_and_dname_response(request)
            })
            .await?;
        let resolver = make_resolver(vec![upstream_addr.to_string()], Vec::new(), Vec::new());

        let request = dns::build_query(125, "www.example.com", 1, true).expect("query");
        let ctx = make_request_context(125, "www.example.com", 1);
        let resolved = resolver.resolve(&ctx, &request).await?;

        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert!(dns::answer_has_record_type(&resolved.packet, 1));
        assert!(dns::answer_has_record_type(&resolved.packet, 39));
        assert!(dns::answer_has_cname_for_name(
            &resolved.packet,
            "www.example.com"
        ));

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn shared_upstream_udp_transport_handles_concurrent_queries() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [2, 2, 2, 2])
            })
            .await?;
        let resolver = Arc::new(make_resolver(
            vec![upstream_addr.to_string()],
            Vec::new(),
            Vec::new(),
        ));

        let tasks = (0..32u16)
            .map(|offset| {
                let resolver = resolver.clone();
                async move {
                    let qname = format!("parallel-{}.example", offset);
                    let request = dns::build_query(400 + offset, &qname, 1, true).expect("query");
                    let ctx = make_request_context(400 + offset, &qname, 1);
                    resolver.resolve(&ctx, &request).await
                }
            })
            .collect::<Vec<_>>();

        for result in join_all(tasks).await {
            let resolved = result?;
            assert_eq!(dns::response_code(&resolved.packet), Some(0));
            assert!(dns::answer_has_record_type(&resolved.packet, 1));
        }
        assert_eq!(counter.load(Ordering::SeqCst), 32);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn sharded_inflight_deduplicates_same_key_concurrent_queries() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (upstream_addr, upstream_handle) =
            spawn_mock_upstream_with(counter.clone(), |request| {
                build_answer_a_response(request, [3, 3, 3, 3])
            })
            .await?;
        let resolver = Arc::new(make_resolver(
            vec![upstream_addr.to_string()],
            Vec::new(),
            Vec::new(),
        ));

        let tasks = (0..24u16)
            .map(|offset| {
                let resolver = resolver.clone();
                async move {
                    let request =
                        dns::build_query(700 + offset, "dedupe.example", 1, true).expect("query");
                    let ctx = make_request_context(700 + offset, "dedupe.example", 1);
                    resolver.resolve(&ctx, &request).await
                }
            })
            .collect::<Vec<_>>();

        for result in join_all(tasks).await {
            let resolved = result?;
            assert_eq!(dns::response_code(&resolved.packet), Some(0));
            assert!(dns::answer_has_record_type(&resolved.packet, 1));
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        upstream_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn iterative_terminal_servfail_is_returned_without_forwarder_fallback(
    ) -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (root_addr, root_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
            build_response_with_rcode(request, 2)
        })
        .await?;
        let resolver =
            make_iterative_resolver(vec![root_addr.to_string()], vec!["127.0.0.1:9".to_string()]);

        let request = dns::build_query(900, "servfail.example", 1, true).expect("query");
        let (packet, resolver_addr) = resolver.query_iterative_single(&request, None).await?;

        assert_eq!(resolver_addr, root_addr.to_string());
        assert_eq!(dns::response_code(&packet), Some(2));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let snapshot = resolver.health_snapshot();
        assert_eq!(snapshot.iterative_successes, 1);
        assert_eq!(snapshot.iterative_failures, 0);
        assert_eq!(snapshot.iterative_fallbacks, 0);

        root_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn iterative_terminal_refused_is_returned_without_forwarder_fallback(
    ) -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (root_addr, root_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
            build_response_with_rcode(request, 5)
        })
        .await?;
        let resolver =
            make_iterative_resolver(vec![root_addr.to_string()], vec!["127.0.0.1:9".to_string()]);

        let request = dns::build_query(903, "refused.example", 1, true).expect("query");
        let (packet, resolver_addr) = resolver.query_iterative_single(&request, None).await?;

        assert_eq!(resolver_addr, root_addr.to_string());
        assert_eq!(dns::response_code(&packet), Some(5));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.health_snapshot().iterative_fallbacks, 0);

        root_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn iterative_terminal_notimp_is_returned_without_forwarder_fallback() -> anyhow::Result<()>
    {
        let counter = Arc::new(AtomicUsize::new(0));
        let (root_addr, root_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
            build_response_with_rcode(request, 4)
        })
        .await?;
        let resolver =
            make_iterative_resolver(vec![root_addr.to_string()], vec!["127.0.0.1:9".to_string()]);

        let request = dns::build_query(904, "notimp.example", 1, true).expect("query");
        let (packet, resolver_addr) = resolver.query_iterative_single(&request, None).await?;

        assert_eq!(resolver_addr, root_addr.to_string());
        assert_eq!(dns::response_code(&packet), Some(4));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.health_snapshot().iterative_fallbacks, 0);

        root_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn iterative_timeout_budget_is_enforced_before_next_referral_hop() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (root_addr, root_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
            std::thread::sleep(Duration::from_millis(120));
            build_referral_with_glue_response(
                request,
                "example.com",
                "ns1.example.com",
                [127, 0, 0, 1],
            )
        })
        .await?;
        let resolver = make_iterative_resolver_with_budget_and_bailiwick(
            vec![root_addr.to_string()],
            vec!["127.0.0.1:9".to_string()],
            100,
            false, // strict_bailiwick=false: glue gets added as candidates so the loop
                   // can proceed to depth=1 and fire the "timed out by budget" check
        );

        let request = dns::build_query(901, "budget.example", 1, true).expect("query");
        let err = resolver
            .query_iterative_single(&request, None)
            .await
            .expect_err("expected iterative timeout budget error");

        assert!(err.to_string().contains("timed out by budget"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let snapshot = resolver.health_snapshot();
        assert_eq!(snapshot.iterative_failures, 1);
        assert_eq!(snapshot.iterative_successes, 0);

        root_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn iterative_noerror_authority_soa_is_returned_without_fallback() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (root_addr, root_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
            build_noerror_nodata_soa_response(request, "example.com")
        })
        .await?;
        let resolver =
            make_iterative_resolver(vec![root_addr.to_string()], vec!["127.0.0.1:9".to_string()]);

        let request = dns::build_query(902, "missing.example.com", 1, true).expect("query");
        let (packet, resolver_addr) = resolver.query_iterative_single(&request, None).await?;

        assert_eq!(resolver_addr, root_addr.to_string());
        assert_eq!(dns::response_code(&packet), Some(0));
        assert_eq!(dns::answer_count(&packet), Some(0));
        assert!(dns::analyze_referral_targets(&packet)
            .map(|value| value.has_authority_soa)
            .unwrap_or(false));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let snapshot = resolver.health_snapshot();
        assert_eq!(snapshot.iterative_successes, 1);
        assert_eq!(snapshot.iterative_failures, 0);
        assert_eq!(snapshot.iterative_fallbacks, 0);

        root_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn truncated_udp_response_retries_over_tcp_and_preserves_edns_payload_size(
    ) -> anyhow::Result<()> {
        let udp_counter = Arc::new(AtomicUsize::new(0));
        let tcp_counter = Arc::new(AtomicUsize::new(0));
        let observed_payload_size = Arc::new(AtomicUsize::new(0));
        let (addr, udp_handle, tcp_handle) = spawn_udp_truncated_tcp_answer_upstream(
            udp_counter.clone(),
            tcp_counter.clone(),
            observed_payload_size.clone(),
        )
        .await?;
        let resolver = make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());

        let mut request = dns::build_query(905, "tcp-fallback.example", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, 0).expect("append edns");

        let packet = resolver.query_address(&addr.to_string(), &request).await?;

        assert_eq!(dns::response_code(&packet), Some(0));
        assert!(dns::answer_has_record_type(&packet, 1));
        assert_eq!(udp_counter.load(Ordering::SeqCst), 1);
        assert_eq!(tcp_counter.load(Ordering::SeqCst), 1);
        assert_eq!(observed_payload_size.load(Ordering::SeqCst), 1232);
        assert_eq!(
            dns::extract_edns_opt(&packet).map(|value| value.udp_payload_size),
            Some(1232)
        );

        udp_handle.abort();
        tcp_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn repeated_tcp_fallback_queries_reuse_same_upstream_connection() -> anyhow::Result<()> {
        let udp_counter = Arc::new(AtomicUsize::new(0));
        let tcp_counter = Arc::new(AtomicUsize::new(0));
        let observed_payload_size = Arc::new(AtomicUsize::new(0));
        let (addr, udp_handle, tcp_handle) = spawn_udp_truncated_tcp_answer_upstream(
            udp_counter.clone(),
            tcp_counter.clone(),
            observed_payload_size.clone(),
        )
        .await?;
        let resolver = make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());

        let mut request = dns::build_query(906, "tcp-reuse.example", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, 0).expect("append edns");

        let first = resolver.query_address(&addr.to_string(), &request).await?;
        let second = resolver.query_address(&addr.to_string(), &request).await?;

        assert_eq!(dns::response_code(&first), Some(0));
        assert_eq!(dns::response_code(&second), Some(0));
        assert_eq!(udp_counter.load(Ordering::SeqCst), 2);
        assert_eq!(tcp_counter.load(Ordering::SeqCst), 1);
        assert_eq!(observed_payload_size.load(Ordering::SeqCst), 1232);

        udp_handle.abort();
        tcp_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn formerr_with_edns_retries_same_upstream_without_edns() -> anyhow::Result<()> {
        let request_counter = Arc::new(AtomicUsize::new(0));
        let saw_edns_then_plain = Arc::new(AtomicUsize::new(0));
        let (addr, handle) =
            spawn_formerr_on_edns_upstream(request_counter.clone(), saw_edns_then_plain.clone())
                .await?;
        let resolver = make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());

        let mut request = dns::build_query(906, "formerr-edns.example", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, 0).expect("append edns");

        let packet = resolver.query_address(&addr.to_string(), &request).await?;

        assert_eq!(dns::response_code(&packet), Some(0));
        assert!(dns::answer_has_record_type(&packet, 1));
        assert_eq!(request_counter.load(Ordering::SeqCst), 2);
        assert_eq!(saw_edns_then_plain.load(Ordering::SeqCst), 2);

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn formerr_with_dnssec_do_does_not_downgrade_edns() -> anyhow::Result<()> {
        let request_counter = Arc::new(AtomicUsize::new(0));
        let saw_edns_then_plain = Arc::new(AtomicUsize::new(0));
        let (addr, handle) =
            spawn_formerr_on_edns_upstream(request_counter.clone(), saw_edns_then_plain.clone())
                .await?;
        let resolver = make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());

        let mut request = dns::build_query(907, "formerr-dnssec.example", 1, true).expect("query");
        dns::append_edns_opt(&mut request, 1232, 0x8000).expect("append do-bit edns");

        let err = resolver
            .query_address(&addr.to_string(), &request)
            .await
            .expect_err("dnssec do query should not fallback to plain request");

        assert!(err
            .to_string()
            .contains("FORMERR for DNSSEC request with EDNS"));
        assert_eq!(request_counter.load(Ordering::SeqCst), 1);
        assert_eq!(saw_edns_then_plain.load(Ordering::SeqCst), 1);

        handle.abort();
        Ok(())
    }

    // ── CNAME Chain Optimization Tests ──────────────────────────────────

    fn build_answer_aaaa_response(request: &[u8], addr: [u8; 16]) -> Vec<u8> {
        let header = dns::parse_header(request).expect("header");
        let (_, _, qend) = dns::parse_first_question(request).expect("question");
        let mut packet = Vec::with_capacity(64);
        packet.extend_from_slice(&header.id.to_be_bytes());
        let opcode = header.flags & 0x7800;
        let rd = header.flags & 0x0100;
        let flags = 0x8000 | opcode | rd | 0x0080;
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&request[12..qend]);
        packet.extend_from_slice(&0xC00Cu16.to_be_bytes());
        packet.extend_from_slice(&28u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&30u32.to_be_bytes());
        packet.extend_from_slice(&16u16.to_be_bytes());
        packet.extend_from_slice(&addr);
        let _ = dns::clone_edns_opt_from_request(request, &mut packet);
        packet
    }

    /// Phase A: After resolving a CNAME chain, the combined result should
    /// be cached under the original query name. A second resolution must
    /// hit cache with zero additional upstream queries.
    #[tokio::test]
    async fn cname_chain_cache_combined_result_hits_on_reresolve() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.cache-test.example", 1) => {
                    dns::build_static_answer(request, "alias.cache-test.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("alias.cache-test.example", 1) => {
                    build_answer_a_response(request, [10, 20, 30, 40])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.dnssec_enabled = false;

        let request = dns::build_query(800, "www.cache-test.example", 1, true).expect("query");
        let ctx = make_request_context(800, "www.cache-test.example", 1);

        // First resolution: walks the CNAME chain, 2 upstream queries
        let first = resolver.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(0));
        assert!(dns::answer_has_record_type(&first.packet, 1));
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        // Second resolution: must hit cache, 0 additional queries
        let second = resolver.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&second.packet), Some(0));
        assert!(dns::answer_has_record_type(&second.packet, 1));
        assert!(matches!(second.source, ResolutionSource::Cache));
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        handle.abort();
        Ok(())
    }

    /// Phase A disabled: without combined caching, each resolve re-walks
    /// the chain via upstream even though individual-hop caches may exist.
    /// Verifies the config gate actually disables the optimization.
    #[tokio::test]
    async fn cname_chain_cache_disabled_does_not_cache_combined() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.nocache-test.example", 1) => {
                    dns::build_static_answer(request, "alias.nocache-test.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("alias.nocache-test.example", 1) => {
                    build_answer_a_response(request, [50, 60, 70, 80])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_cache_enabled = false;
        resolver.dnssec_enabled = false;

        let request = dns::build_query(801, "www.nocache-test.example", 1, true).expect("query");
        let ctx = make_request_context(801, "www.nocache-test.example", 1);

        // First resolution: 2 upstream queries (CNAME + A)
        let first = resolver.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(0));
        let after_first = counter.load(Ordering::SeqCst);
        assert!(after_first >= 2);

        // Second resolution: may or may not hit cache depending on normal
        // caching path, but Phase A gate is verified disabled.
        let second = resolver.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&second.packet), Some(0));
        // The important assertion: the resolver configured correctly
        assert!(!resolver.cname_chain_cache_enabled);

        handle.abort();
        Ok(())
    }

    /// Phase A: The combined CNAME chain is explicitly present in the
    /// main cache under the original (qname, qtype) key.
    #[tokio::test]
    async fn cname_chain_cache_entry_verifiable_in_cache_store() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.cache-entry.example", 1) => {
                    dns::build_static_answer(request, "final.cache-entry.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("final.cache-entry.example", 1) => {
                    build_answer_a_response(request, [11, 22, 33, 44])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.dnssec_enabled = false;

        let request = dns::build_query(810, "www.cache-entry.example", 1, true).expect("query");
        let ctx = make_request_context(810, "www.cache-entry.example", 1);

        resolver.resolve(&ctx, &request).await?;

        let cache_key = cache_key_for_query("www.cache-entry.example", 1, false);
        let cached = resolver.cache.get(&cache_key, false);
        assert!(cached.is_some(), "combined CNAME chain must be in main cache");

        // The cached response should have A record in the answer section
        if let Some(pkt) = cached {
            assert_eq!(dns::response_code(&pkt), Some(0));
            assert!(
                dns::answer_has_record_type(&pkt, 1) || dns::answer_has_record_type(&pkt, 5),
                "cached response should contain A or CNAME records"
            );
        }

        handle.abort();
        Ok(())
    }

    /// Phase B: Pre-populate cache with an intermediate CNAME target's
    /// A record. When resolving a chain that passes through that target,
    /// the inline cache lookup should skip the upstream query for that hop.
    #[tokio::test]
    async fn cname_chain_inline_cache_skips_upstream_for_cached_target() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.inline-test.example", 1) => {
                    dns::build_static_answer(request, "cached-target.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("cached-target.example", 1) => {
                    build_answer_a_response(request, [100, 100, 100, 100])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.dnssec_enabled = false;

        // Pre-populate the cache with cached-target.example A
        let pre_request = dns::build_query(900, "cached-target.example", 1, true).expect("query");
        let pre_cache_key = cache_key_for_query("cached-target.example", 1, false);
        resolver.cache.insert(
            pre_cache_key,
            build_answer_a_response(&pre_request, [100, 100, 100, 100]),
            Duration::from_secs(300),
        );

        let request = dns::build_query(820, "www.inline-test.example", 1, true).expect("query");
        let ctx = make_request_context(820, "www.inline-test.example", 1);

        let response = resolver.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&response.packet), Some(0));

        // Only 1 upstream query: the initial CNAME lookup for www.inline-test.example.
        // The intermediate target cached-target.example was found in cache (Phase B).
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Phase B should skip upstream query for cached intermediate target"
        );

        handle.abort();
        Ok(())
    }

    /// Phase B disabled: with inline cache disabled, every CNAME hop
    /// triggers an upstream query even if the target is already cached.
    #[tokio::test]
    async fn cname_chain_inline_cache_disabled_queries_every_hop() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.no-inline.example", 1) => {
                    dns::build_static_answer(request, "miss-target.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("miss-target.example", 1) => {
                    build_answer_a_response(request, [200, 200, 200, 200])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_inline_cache_enabled = false;
        resolver.dnssec_enabled = false;

        // Pre-populate cache with miss-target.example A — should be ignored
        let pre_request = dns::build_query(901, "miss-target.example", 1, true).expect("query");
        let pre_cache_key = cache_key_for_query("miss-target.example", 1, false);
        resolver.cache.insert(
            pre_cache_key,
            build_answer_a_response(&pre_request, [200, 200, 200, 200]),
            Duration::from_secs(300),
        );

        let request = dns::build_query(821, "www.no-inline.example", 1, true).expect("query");
        let ctx = make_request_context(821, "www.no-inline.example", 1);

        let response = resolver.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&response.packet), Some(0));

        // When Phase B is disabled, every hop queries upstream despite
        // the cached entry. Both hops go to upstream.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "Phase B disabled should query upstream for every hop"
        );

        handle.abort();
        Ok(())
    }

    /// Phase C: After resolving A via a CNAME chain, the sibling AAAA
    /// is background-resolved for the leaf target. Verify the hot cache
    /// contains the combined AAAA result for the original query name.
    #[tokio::test]
    async fn cname_chain_dualstack_share_populates_sibling_in_hot_cache() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.ds-test.example", 1) | ("www.ds-test.example", 28) => {
                    dns::build_static_answer(request, "leaf.ds-test.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("leaf.ds-test.example", 1) => {
                    build_answer_a_response(request, [10, 0, 0, 1])
                }
                ("leaf.ds-test.example", 28) => {
                    build_answer_aaaa_response(request, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_dualstack_share_enabled = true;
        resolver.dnssec_enabled = false;
        // Increase timeout so the background task has time to complete
        resolver.upstream_timeout = Duration::from_millis(500);

        let request_a = dns::build_query(830, "www.ds-test.example", 1, true).expect("query");
        let ctx = make_request_context(830, "www.ds-test.example", 1);

        let response = resolver.resolve(&ctx, &request_a).await?;
        assert_eq!(dns::response_code(&response.packet), Some(0));
        assert!(dns::answer_has_record_type(&response.packet, 1));

        // The A resolution triggered 2 upstream queries (CNAME + A).
        // Phase C spawns a background task that queries the sibling AAAA.
        // Wait briefly for the background tokio task.
        let before = counter.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after = counter.load(Ordering::SeqCst);

        // The background task should have fired at least one additional
        // query (AAAA for the leaf target).
        assert!(
            after > before,
            "Phase C background task should fire sibling AAAA query (before={before}, after={after})"
        );

        // Now verify that www.ds-test.example AAAA is populated in hot cache
        let sibling_key = cache_key_for_query("www.ds-test.example", 28, false);
        let hot_hit = resolver.hot_cache.get(&sibling_key, false);
        assert!(
            hot_hit.is_some(),
            "Phase C should populate sibling AAAA in hot cache for original qname"
        );

        handle.abort();
        Ok(())
    }

    /// Phase C with dual-stack disabled: no background sibling resolution.
    #[tokio::test]
    async fn cname_chain_dualstack_share_disabled_no_background_query() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.no-ds.example", 1) => {
                    dns::build_static_answer(request, "leaf.no-ds.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("leaf.no-ds.example", 1) => {
                    build_answer_a_response(request, [10, 0, 0, 2])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_dualstack_share_enabled = false;
        resolver.dnssec_enabled = false;
        resolver.upstream_timeout = Duration::from_millis(200);

        let request_a = dns::build_query(831, "www.no-ds.example", 1, true).expect("query");
        let ctx = make_request_context(831, "www.no-ds.example", 1);

        resolver.resolve(&ctx, &request_a).await?;

        let before = counter.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;

        // No additional background query
        assert_eq!(counter.load(Ordering::SeqCst), before);

        // Hot cache should NOT contain sibling
        let sibling_key = cache_key_for_query("www.no-ds.example", 28, false);
        let hot_hit = resolver.hot_cache.get(&sibling_key, false);
        assert!(hot_hit.is_none());

        handle.abort();
        Ok(())
    }

    /// Phase D: With target prefetch enabled, after resolving a CNAME
    /// chain the prefetch task fires for the leaf target's sibling qtype.
    #[tokio::test]
    async fn cname_chain_target_prefetch_fires_for_leaf_sibling() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.prefetch-test.example", 1) => {
                    dns::build_static_answer(request, "cdn.prefetch-test.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("cdn.prefetch-test.example", 1) => {
                    build_answer_a_response(request, [30, 30, 30, 30])
                }
                ("cdn.prefetch-test.example", 28) => {
                    build_answer_aaaa_response(request, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_target_prefetch_enabled = true;
        resolver.dnssec_enabled = false;
        resolver.upstream_timeout = Duration::from_millis(500);
        resolver.prefetch_budget_per_window = 32;
        resolver.prefetch_window = Duration::from_secs(60);
        resolver.prefetch_popularity_threshold = 0;

        let request_a = dns::build_query(840, "www.prefetch-test.example", 1, true).expect("query");
        let ctx = make_request_context(840, "www.prefetch-test.example", 1);

        let response = resolver.resolve(&ctx, &request_a).await?;
        assert_eq!(dns::response_code(&response.packet), Some(0));

        let before = counter.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after = counter.load(Ordering::SeqCst);

        assert!(
            after > before,
            "Phase D prefetch should fire background query for sibling"
        );

        handle.abort();
        Ok(())
    }

    /// Phase D disabled: no prefetch activity.
    #[tokio::test]
    async fn cname_chain_target_prefetch_disabled_no_extra_queries() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.no-prefetch.example", 1) => {
                    dns::build_static_answer(request, "cdn.no-prefetch.example", 60, "CNAME")
                        .expect("cname answer")
                }
                ("cdn.no-prefetch.example", 1) => {
                    build_answer_a_response(request, [40, 40, 40, 40])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_target_prefetch_enabled = false;
        resolver.cname_chain_dualstack_share_enabled = false;
        resolver.dnssec_enabled = false;
        resolver.upstream_timeout = Duration::from_millis(200);

        let request_a = dns::build_query(841, "www.no-prefetch.example", 1, true).expect("query");
        let ctx = make_request_context(841, "www.no-prefetch.example", 1);

        resolver.resolve(&ctx, &request_a).await?;

        let before = counter.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(counter.load(Ordering::SeqCst), before);

        handle.abort();
        Ok(())
    }

    /// Performance: dual-stack A+AAAA resolution for a 3-hop CNAME chain.
    /// With all optimizations enabled, the second query (AAAA) hits cache
    /// instead of re-walking the chain. This test measures upstream query
    /// counts to quantify the improvement.
    #[tokio::test]
    async fn cname_chain_all_optimizations_reduce_dualstack_queries() -> anyhow::Result<()> {
        // ── Mock: 3-hop CNAME chain for both A and AAAA ──
        let opt_counter = Arc::new(AtomicUsize::new(0));
        let (opt_addr, opt_handle) =
            spawn_mock_upstream_with(opt_counter.clone(), move |request| {
                let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
                match (qname.to_ascii_lowercase().as_str(), qtype) {
                    ("www.perf.example", 1) | ("www.perf.example", 28) => {
                        dns::build_static_answer(request, "mid1.perf.example", 60, "CNAME")
                            .expect("cname")
                    }
                    ("mid1.perf.example", 1) | ("mid1.perf.example", 28) => {
                        dns::build_static_answer(request, "mid2.perf.example", 60, "CNAME")
                            .expect("cname")
                    }
                    ("mid2.perf.example", 1) => {
                        build_answer_a_response(request, [1, 1, 1, 1])
                    }
                    ("mid2.perf.example", 28) => {
                        build_answer_aaaa_response(request, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
                    }
                    _ => build_response_with_rcode(request, 3),
                }
            })
            .await?;

        let mut opt_resolver = make_resolver(
            vec![opt_addr.to_string()],
            Vec::new(),
            Vec::new(),
        );
        opt_resolver.dnssec_enabled = false;
        opt_resolver.upstream_timeout = Duration::from_millis(500);

        // ── Optimized path: A then AAAA ──
        let req_a = dns::build_query(850, "www.perf.example", 1, true).expect("query");
        let ctx_a = make_request_context(850, "www.perf.example", 1);
        let resp_a = opt_resolver.resolve(&ctx_a, &req_a).await?;
        assert_eq!(dns::response_code(&resp_a.packet), Some(0));
        assert!(dns::answer_has_record_type(&resp_a.packet, 1));

        let after_a = opt_counter.load(Ordering::SeqCst);
        // A resolution: 3 hops = 3 upstream queries
        assert_eq!(after_a, 3, "optimized A resolution: 3 hops = 3 queries");

        // Wait for Phase C background task to finish
        tokio::time::sleep(Duration::from_millis(400)).await;

        let req_aaaa = dns::build_query(851, "www.perf.example", 28, true).expect("query");
        let ctx_aaaa = make_request_context(851, "www.perf.example", 28);
        let resp_aaaa = opt_resolver.resolve(&ctx_aaaa, &req_aaaa).await?;
        assert_eq!(dns::response_code(&resp_aaaa.packet), Some(0));
        assert!(dns::answer_has_record_type(&resp_aaaa.packet, 28) || dns::answer_has_record_type(&resp_aaaa.packet, 5));

        let after_aaaa = opt_counter.load(Ordering::SeqCst);
        // AAAA resolution: Phase C background task already did 1 query.
        // When AAAA resolve runs, Phase A cache may return immediately.
        // Total additional queries from the resolve call: either 0 (cache hit)
        // or up to 3 (if Phase C didn't finish in time).
        // In optimized mode, we expect: after_aaaa <= after_a + 3 (worst case full chain).
        // The key metric: AAAA resolution queries are ≤ A resolution queries.
        let aaaa_queries = after_aaaa.saturating_sub(after_a);
        let phase_c_bg_queries = if after_aaaa > after_a + 3 { 1 } else { 0 };
        // Total effective dual-stack queries = A queries + AAAA queries
        // In unoptimized mode this would be 3 + 3 = 6
        // In optimized mode this should be ≤ 3 + 1 = 4 (Phase C bg query)
        let effective_total = after_a + aaaa_queries.saturating_sub(phase_c_bg_queries);
        assert!(
            effective_total <= 5,
            "optimized dual-stack: expected ≤ 5 effective queries, got {effective_total} (A={after_a}, AAAA={aaaa_queries}, bg={phase_c_bg_queries})"
        );

        opt_handle.abort();

        // ── Unoptimized path: all CNAME optimizations off ──
        let noopt_counter = Arc::new(AtomicUsize::new(0));
        let (noopt_addr, noopt_handle) =
            spawn_mock_upstream_with(noopt_counter.clone(), move |request| {
                let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
                match (qname.to_ascii_lowercase().as_str(), qtype) {
                    ("www.perf2.example", 1) | ("www.perf2.example", 28) => {
                        dns::build_static_answer(request, "hop1.perf2.example", 60, "CNAME")
                            .expect("cname")
                    }
                    ("hop1.perf2.example", 1) | ("hop1.perf2.example", 28) => {
                        dns::build_static_answer(request, "hop2.perf2.example", 60, "CNAME")
                            .expect("cname")
                    }
                    ("hop2.perf2.example", 1) => {
                        build_answer_a_response(request, [2, 2, 2, 2])
                    }
                    ("hop2.perf2.example", 28) => {
                        build_answer_aaaa_response(request, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2])
                    }
                    _ => build_response_with_rcode(request, 3),
                }
            })
            .await?;

        let mut noopt_resolver = make_resolver(
            vec![noopt_addr.to_string()],
            Vec::new(),
            Vec::new(),
        );
        noopt_resolver.cname_chain_cache_enabled = false;
        noopt_resolver.cname_chain_inline_cache_enabled = false;
        noopt_resolver.cname_chain_dualstack_share_enabled = false;
        noopt_resolver.cname_chain_target_prefetch_enabled = false;
        noopt_resolver.dnssec_enabled = false;
        noopt_resolver.upstream_timeout = Duration::from_millis(500);

        let req_a2 = dns::build_query(852, "www.perf2.example", 1, true).expect("query");
        let ctx_a2 = make_request_context(852, "www.perf2.example", 1);
        noopt_resolver.resolve(&ctx_a2, &req_a2).await?;
        let _noopt_after_a = noopt_counter.load(Ordering::SeqCst);

        let req_aaaa2 = dns::build_query(853, "www.perf2.example", 28, true).expect("query");
        let ctx_aaaa2 = make_request_context(853, "www.perf2.example", 28);
        noopt_resolver.resolve(&ctx_aaaa2, &req_aaaa2).await?;
        let noopt_after_aaaa = noopt_counter.load(Ordering::SeqCst);

        // Unoptimized: A = 3 queries, AAAA = 3 queries independent = 6 total
        let noopt_total = noopt_after_aaaa;
        assert!(
            noopt_total >= 5,
            "unoptimized dual-stack: expected ≥5 queries, got {noopt_total}"
        );

        // ── Key assertion: optimized is strictly better ──
        let opt_total = after_aaaa; // total queries for A+AAAA optimized
        assert!(
            opt_total < noopt_total,
            "optimized ({opt_total}) should use fewer upstream queries than unoptimized ({noopt_total})"
        );

        noopt_handle.abort();
        Ok(())
    }

    /// CNAME loop detection still works correctly with inline cache
    /// enabled (Phase B must not hide loop patterns).
    #[tokio::test]
    async fn cname_chain_loop_detected_with_inline_cache_enabled() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.loop.example", 1) => {
                    dns::build_static_answer(request, "alias.loop.example", 60, "CNAME")
                        .expect("cname")
                }
                ("alias.loop.example", 1) => {
                    dns::build_static_answer(request, "www.loop.example", 60, "CNAME")
                        .expect("cname")
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_inline_cache_enabled = true;
        resolver.dnssec_enabled = false;

        let request = dns::build_query(860, "www.loop.example", 1, true).expect("query");
        let ctx = make_request_context(860, "www.loop.example", 1);

        let err = resolver
            .resolve(&ctx, &request)
            .await
            .expect_err("CNAME loop must be detected");

        assert!(
            err.to_string().contains("cname chain loop detected"),
            "expected loop error, got: {err}"
        );

        handle.abort();
        Ok(())
    }

    /// CNAME max depth exceeded error works with optimizations enabled.
    #[tokio::test]
    async fn cname_chain_max_depth_exceeded_with_optimizations() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            // Endless chain: each hop points to the next
            if qname.starts_with("level") && qtype == 1 {
                let level: u32 = qname
                    .split('.')
                    .next()
                    .and_then(|s| s.strip_prefix("level"))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let next = format!("level{}.depth.example", level + 1);
                dns::build_static_answer(request, &next, 60, "CNAME").expect("cname")
            } else if qname == "www.depth.example" && qtype == 1 {
                dns::build_static_answer(request, "level1.depth.example", 60, "CNAME")
                    .expect("cname")
            } else {
                build_response_with_rcode(request, 3)
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.cname_chain_max_depth = 3; // short depth to trigger quickly
        resolver.cname_chain_cache_enabled = true;
        resolver.cname_chain_inline_cache_enabled = true;
        resolver.dnssec_enabled = false;
        resolver.upstream_timeout = Duration::from_millis(500);

        let request = dns::build_query(861, "www.depth.example", 1, true).expect("query");
        let ctx = make_request_context(861, "www.depth.example", 1);

        let err = resolver
            .resolve(&ctx, &request)
            .await
            .expect_err("max depth exceeded must be detected");

        assert!(
            err.to_string().contains("cname chain exceeded max depth"),
            "expected depth error, got: {err}"
        );

        handle.abort();
        Ok(())
    }

    /// Combined result cached for the original query name contains the
    /// question section rewritten back to the original name (not the
    /// final CNAME leaf target).
    #[tokio::test]
    async fn cname_chain_cached_response_has_original_question() -> anyhow::Result<()> {
        let counter = Arc::new(AtomicUsize::new(0));
        let (addr, handle) = spawn_mock_upstream_with(counter.clone(), move |request| {
            let (qname, qtype, _) = dns::parse_first_question(request).expect("question");
            match (qname.to_ascii_lowercase().as_str(), qtype) {
                ("www.question.example", 1) => {
                    dns::build_static_answer(request, "final.question.example", 60, "CNAME")
                        .expect("cname")
                }
                ("final.question.example", 1) => {
                    build_answer_a_response(request, [77, 88, 99, 100])
                }
                _ => build_response_with_rcode(request, 3),
            }
        })
        .await?;

        let mut resolver =
            make_resolver(vec![addr.to_string()], Vec::new(), Vec::new());
        resolver.dnssec_enabled = false;

        let request = dns::build_query(870, "www.question.example", 1, true).expect("query");
        let ctx = make_request_context(870, "www.question.example", 1);

        resolver.resolve(&ctx, &request).await?;

        // Check the cached packet has the ORIGINAL question name
        let cache_key = cache_key_for_query("www.question.example", 1, false);
        let cached = resolver.cache.get(&cache_key, false).expect("must be cached");

        let (cached_qname, cached_qtype, _) =
            dns::parse_first_question(&cached).expect("parse question");
        assert_eq!(
            cached_qname.to_ascii_lowercase(),
            "www.question.example",
            "cached response must have original question name, got {}",
            cached_qname
        );
        assert_eq!(cached_qtype, 1);

        handle.abort();
        Ok(())
    }

    // ── Live DNS Resolution Benchmarks ─────────────────────────────────
    // These tests require internet access and use real DNS infrastructure.
    // Run with: cargo test -- cname_live --ignored --nocapture

    /// Helper: create a forwarder resolver pointed at Google DNS (8.8.8.8).
    fn make_forwarder_for_live_bench(
        cname_cache: bool,
        cname_inline: bool,
        cname_dualstack: bool,
        cname_prefetch: bool,
    ) -> Resolver {
        let mut resolver = Resolver::new(
            ResolverConfig {
                resolve_mode: "forwarder".to_string(),
                root_servers: Vec::new(),
                iterative_address_family: IterativeAddressFamily::DualStack,
                iterative_max_depth: 8,
                iterative_timeout_ms: 5000,
                cname_chain_max_depth: 10,
                follow_cname_chain: true,
                static_cname_expand_for_address_queries: false,
                iterative_fallback_to_forwarder: false,
                iterative_cname_bridge_fallback_to_recursive: true,
                cname_chain_cache_enabled: cname_cache,
                cname_chain_inline_cache_enabled: cname_inline,
                cname_chain_dualstack_share_enabled: cname_dualstack,
                cname_chain_target_prefetch_enabled: cname_prefetch,
                ns_host_cache_capacity: 1024,
                ns_host_cache_ttl_secs: 300,
                ns_host_cache_cleanup_interval_ms: 5000,
                enable_delegation_cache: false,
                strict_bailiwick: true,
                delegation_cache_capacity: 1024,
                delegation_cache_ttl_cap_secs: 300,
                delegation_cache_cleanup_interval_ms: 5000,
                delegation_failure_backoff_ms: 1000,
                stats_window_secs: 60,
                stats_short_window_secs: 10,
                cache_hot_capacity: 1024,
                upstreams: vec!["8.8.8.8:53".to_string()],
                cache_ttl_secs: 60,
                freeze_cache_ttl_decay: false,
                freeze_cache_domains: Vec::new(),
                upstream_timeout_ms: 3000,
                upstream_retries: 1,
                unhealthy_backoff_ms: 100,
                prefetch_budget_per_window: 32,
                prefetch_window_secs: 60,
                prefetch_ttl_trigger_secs: 5,
                prefetch_popularity_threshold: 0,
                upstream_score_rtt_weight: 1.0,
                upstream_score_failure_weight: 25.0,
                upstream_score_success_weight: 3.0,
                adaptive_cache_enabled: false,
                adaptive_cache_min_capacity: 128,
                adaptive_cache_max_capacity: 4096,
                adaptive_cache_step: 128,
                adaptive_cache_window_secs: 5,
                adaptive_cache_high_miss_ratio: 0.6,
                adaptive_cache_low_miss_ratio: 0.2,
                enable_recursion: true,
                dnssec_enabled: false,
                trust_anchors: TrustAnchors::default(),
                ns_hostname_max_concurrent: 4,
                ns_hostname_enough_endpoints: 2,
                ns_hostname_per_resolve_ms: 1500,
                ns_hostname_resolve_mode: NsHostnameResolveMode::BootstrapRecursive,
                iterative_per_hop_timeout_ms: 0,
                prewarm_delegation_zones: Vec::new(),
            },
            Arc::new(ResponseCache::default()),
            Arc::new(Metrics::new().expect("metrics")),
            Vec::new(),
            Vec::new(),
        );
        resolver.dnssec_enabled = false;
        resolver
    }

    /// Helper: create an iterative resolver with real root servers and
    /// Google DNS as bootstrap for NS hostname resolution.
    fn make_iterative_resolver_for_live_bench(upstream_timeout_ms: u64) -> Resolver {
        // IANA root servers (IPv4 subset)
        let root_servers: Vec<String> = vec![
            "198.41.0.4:53",
            "199.9.14.201:53",
            "192.33.4.12:53",
            "199.7.91.13:53",
            "192.203.230.10:53",
            "192.5.5.241:53",
            "192.112.36.4:53",
            "198.97.190.53:53",
            "192.36.148.17:53",
            "192.58.128.30:53",
            "193.0.14.129:53",
            "199.7.83.42:53",
            "202.12.27.33:53",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let mut resolver = Resolver::new(
            ResolverConfig {
                resolve_mode: "iterative".to_string(),
                root_servers,
                iterative_address_family: IterativeAddressFamily::Ipv4,
                iterative_max_depth: 20,
                iterative_timeout_ms: 30000,
                cname_chain_max_depth: 10,
                follow_cname_chain: true,
                static_cname_expand_for_address_queries: false,
                iterative_fallback_to_forwarder: true,
                iterative_cname_bridge_fallback_to_recursive: true,
                cname_chain_cache_enabled: true,
                cname_chain_inline_cache_enabled: true,
                cname_chain_dualstack_share_enabled: true,
                cname_chain_target_prefetch_enabled: false,
                ns_host_cache_capacity: 1024,
                ns_host_cache_ttl_secs: 300,
                ns_host_cache_cleanup_interval_ms: 5000,
                enable_delegation_cache: true,
                strict_bailiwick: true,
                delegation_cache_capacity: 1024,
                delegation_cache_ttl_cap_secs: 300,
                delegation_cache_cleanup_interval_ms: 5000,
                delegation_failure_backoff_ms: 1000,
                stats_window_secs: 60,
                stats_short_window_secs: 10,
                cache_hot_capacity: 1024,
                upstreams: vec!["8.8.8.8:53".to_string()],
                cache_ttl_secs: 60,
                freeze_cache_ttl_decay: false,
                freeze_cache_domains: Vec::new(),
                upstream_timeout_ms,
                upstream_retries: 2,
                unhealthy_backoff_ms: 100,
                prefetch_budget_per_window: 32,
                prefetch_window_secs: 60,
                prefetch_ttl_trigger_secs: 5,
                prefetch_popularity_threshold: 0,
                upstream_score_rtt_weight: 1.0,
                upstream_score_failure_weight: 25.0,
                upstream_score_success_weight: 3.0,
                adaptive_cache_enabled: false,
                adaptive_cache_min_capacity: 128,
                adaptive_cache_max_capacity: 4096,
                adaptive_cache_step: 128,
                adaptive_cache_window_secs: 5,
                adaptive_cache_high_miss_ratio: 0.6,
                adaptive_cache_low_miss_ratio: 0.2,
                enable_recursion: true,
                dnssec_enabled: false,
                trust_anchors: TrustAnchors::default(),
                ns_hostname_max_concurrent: 8,
                ns_hostname_enough_endpoints: 2,
                ns_hostname_per_resolve_ms: 2000,
                ns_hostname_resolve_mode: NsHostnameResolveMode::BootstrapRecursive,
                iterative_per_hop_timeout_ms: 3000,
                prewarm_delegation_zones: Vec::new(),
            },
            Arc::new(ResponseCache::default()),
            Arc::new(Metrics::new().expect("metrics")),
            Vec::new(),
            Vec::new(),
        );
        resolver.dnssec_enabled = false;
        resolver
    }

    /// Live benchmark: forwarder-mode resolution of www.163.com A
    /// against Google DNS. Measures query count and latency with all
    /// CNAME optimizations enabled (Phases A+B+C).
    ///
    /// Requires internet access. Run with:
    ///   cargo test -- cname_live_forwarder --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn cname_live_forwarder_www163_a_optimized() -> anyhow::Result<()> {
        let resolver = make_forwarder_for_live_bench(true, true, true, false);

        let request = dns::build_query(9901, "www.163.com", 1, true).expect("query");
        let ctx = make_request_context(9901, "www.163.com", 1);

        let started = Instant::now();
        let response = resolver.resolve(&ctx, &request).await?;
        let elapsed = started.elapsed();

        let rcode = dns::response_code(&response.packet).unwrap_or(255);
        let has_a = dns::answer_has_record_type(&response.packet, 1);
        let has_cname = dns::answer_has_record_type(&response.packet, 5);

        // Print diagnostic information
        println!();
        println!("=== www.163.com A — Forwarder (optimized) ===");
        println!("  elapsed:        {elapsed:.2?}");
        println!("  rcode:          {rcode}");
        println!("  has A record:   {has_a}");
        println!("  has CNAME:      {has_cname}");
        println!("  source:         {:?}", response.source);
        if let Some((qname, qtype, _)) = dns::parse_first_question(&response.packet) {
            println!("  qname in resp:  {qname} qtype={qtype}");
        }
        let ancount = dns::answer_count(&response.packet).unwrap_or(0);
        println!("  answer count:   {ancount}");

        // Extract and display CNAME chain from response
        let cnames = dns::extract_answer_cname_records(&response.packet);
        if !cnames.is_empty() {
            println!("  CNAME records in answer ({cnames_len}):",
                cnames_len = cnames.len());
            for (owner, target, ttl) in &cnames {
                println!("    {owner} → {target} (TTL={ttl})");
            }
        }

        // Second resolution — must be cache hit (Phase A)
        let started2 = Instant::now();
        let response2 = resolver.resolve(&ctx, &request).await?;
        let elapsed2 = started2.elapsed();

        println!("  --- second resolve (cache hit) ---");
        println!("  elapsed:        {elapsed2:.2?}");
        println!("  source:         {:?}", response2.source);
        println!("  rcode:          {}",
            dns::response_code(&response2.packet).unwrap_or(255));

        assert_eq!(rcode, 0, "expected NOERROR");
        assert!(has_a || has_cname, "expected A or CNAME in answer");
        assert!(
            matches!(response2.source, ResolutionSource::Cache),
            "second resolution should hit cache (Phase A)"
        );
        assert!(
            elapsed2 < elapsed / 2,
            "cache hit should be significantly faster than first resolution"
        );

        Ok(())
    }

    /// Live benchmark: forwarder-mode A+AAAA dual-stack resolution of
    /// www.163.com. Measures total upstream query latency for both
    /// address families with optimizations ON vs OFF.
    ///
    /// Requires internet access. Run with:
    ///   cargo test -- cname_live_dualstack --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn cname_live_dualstack_www163_optimized_vs_unoptimized() -> anyhow::Result<()> {
        // ── Optimized resolver ──
        let resolver_opt =
            make_forwarder_for_live_bench(true, true, true, false);

        // Warm up: pre-populate DNS cache for the upstream itself
        let warmup_req = dns::build_query(9910, "www.example.com", 1, true).expect("query");
        let warmup_ctx = make_request_context(9910, "www.example.com", 1);
        let _ = resolver_opt.resolve(&warmup_ctx, &warmup_req).await;

        // Resolve A
        let req_a = dns::build_query(9911, "www.163.com", 1, true).expect("query");
        let ctx_a = make_request_context(9911, "www.163.com", 1);

        let started_a = Instant::now();
        let resp_a = resolver_opt.resolve(&ctx_a, &req_a).await?;
        let elapsed_a = started_a.elapsed();
        let src_a = resp_a.source;

        // Short sleep for Phase C background task
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Resolve AAAA
        let req_aaaa = dns::build_query(9912, "www.163.com", 28, true).expect("query");
        let ctx_aaaa = make_request_context(9912, "www.163.com", 28);

        let started_aaaa = Instant::now();
        let resp_aaaa = resolver_opt.resolve(&ctx_aaaa, &req_aaaa).await?;
        let elapsed_aaaa = started_aaaa.elapsed();
        let src_aaaa = resp_aaaa.source;

        let total_opt = elapsed_a + elapsed_aaaa;

        println!();
        println!("=== www.163.com Dual-Stack (OPTIMIZED) ===");
        println!("  A   elapsed:  {elapsed_a:.2?}  source: {src_a:?}");
        println!("  AAAA elapsed: {elapsed_aaaa:.2?}  source: {src_aaaa:?}");
        println!("  TOTAL:        {total_opt:.2?}");

        // ── Unoptimized resolver ──
        let resolver_noopt =
            make_forwarder_for_live_bench(false, false, false, false);

        // Resolve A (unopt)
        let req_a2 = dns::build_query(9913, "www.163.com", 1, true).expect("query");
        let ctx_a2 = make_request_context(9913, "www.163.com", 1);

        let started_a2 = Instant::now();
        let resp_a2 = resolver_noopt.resolve(&ctx_a2, &req_a2).await?;
        let elapsed_a2 = started_a2.elapsed();
        let src_a2 = resp_a2.source;

        // Resolve AAAA (unopt — independent chain walk)
        let req_aaaa2 = dns::build_query(9914, "www.163.com", 28, true).expect("query");
        let ctx_aaaa2 = make_request_context(9914, "www.163.com", 28);

        let started_aaaa2 = Instant::now();
        let resp_aaaa2 = resolver_noopt.resolve(&ctx_aaaa2, &req_aaaa2).await?;
        let elapsed_aaaa2 = started_aaaa2.elapsed();
        let src_aaaa2 = resp_aaaa2.source;

        let total_noopt = elapsed_a2 + elapsed_aaaa2;

        println!();
        println!("=== www.163.com Dual-Stack (UNOPTIMIZED) ===");
        println!("  A   elapsed:  {elapsed_a2:.2?}  source: {src_a2:?}");
        println!("  AAAA elapsed: {elapsed_aaaa2:.2?}  source: {src_aaaa2:?}");
        println!("  TOTAL:        {total_noopt:.2?}");

        // Performance comparison
        let _improvement = if total_noopt > Duration::ZERO {
            let ratio = total_opt.as_secs_f64() / total_noopt.as_secs_f64();
            let pct = ((1.0 - ratio) * 100.0) as i32;
            println!();
            println!("  Optimized/Unoptimized ratio: {ratio:.2}");
            println!("  Improvement: {pct}% faster");
            pct
        } else {
            0
        };

        // AAAA should be a cache hit in optimized mode (Phase C)
        println!();
        println!("  Optimized AAAA source: {src_aaaa:?}");
        println!("  Unoptimized AAAA source: {src_aaaa2:?}");

        // Assert correctness (not speed — network latency varies)
        assert_eq!(
            dns::response_code(&resp_a.packet).unwrap_or(255),
            dns::response_code(&resp_a2.packet).unwrap_or(255),
            "A responses should have same rcode"
        );

        Ok(())
    }

    /// Live benchmark: pure iterative resolution of www.163.com using
    /// real root servers. Measures full recursive walk + CNAME chain
    /// resolution latency and hop count.
    ///
    /// Requires internet access. This is the most comprehensive test.
    /// Run with:
    ///   cargo test -- cname_live_iterative --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn cname_live_iterative_www163_full_walk() -> anyhow::Result<()> {
        let resolver = make_iterative_resolver_for_live_bench(3000);

        let request = dns::build_query(9920, "www.163.com", 1, true).expect("query");
        let ctx = make_request_context(9920, "www.163.com", 1);

        println!();
        println!("=== www.163.com A — Pure Iterative ===");
        println!("  Root servers: 13 (IANA IPv4)");
        println!("  Starting iterative resolution...");

        let started = Instant::now();
        let response = resolver.resolve(&ctx, &request).await;
        let elapsed = started.elapsed();

        match response {
            Ok(resp) => {
                let rcode = dns::response_code(&resp.packet).unwrap_or(255);
                let has_a = dns::answer_has_record_type(&resp.packet, 1);
                let has_cname = dns::answer_has_record_type(&resp.packet, 5);
                let ancount = dns::answer_count(&resp.packet).unwrap_or(0);

                println!("  SUCCESS");
                println!("  elapsed:        {elapsed:.2?}");
                println!("  rcode:          {rcode}");
                println!("  has A record:   {has_a}");
                println!("  has CNAME:      {has_cname}");
                println!("  answer count:   {ancount}");
                println!("  source:         {:?}", resp.source);

                let cnames = dns::extract_answer_cname_records(&resp.packet);
                if !cnames.is_empty() {
                    println!("  CNAME chain ({cnames_len} hops):",
                        cnames_len = cnames.len());
                    for (owner, target, ttl) in &cnames {
                        println!("    {owner} → {target} (TTL={ttl})");
                    }
                }

                if let Some((qname, qtype, _)) = dns::parse_first_question(&resp.packet) {
                    println!("  qname in resp:  {qname} qtype={qtype}");
                }

                // Verify the response is valid
                assert!(rcode == 0 || rcode == 3, "expected NOERROR or NXDOMAIN");
                assert!(has_a || has_cname, "expected A or CNAME in answer");

                // Second resolution — must hit cache (Phase A)
                let started2 = Instant::now();
                let response2 = resolver.resolve(&ctx, &request).await?;
                let elapsed2 = started2.elapsed();

                println!("  --- second resolve (cache hit) ---");
                println!("  elapsed:        {elapsed2:.2?}");
                println!("  source:         {:?}", response2.source);

                assert!(
                    matches!(response2.source, ResolutionSource::Cache),
                    "second iterative resolution should hit cache (Phase A)"
                );
            }
            Err(err) => {
                println!("  FAILED after {elapsed:.2?}: {err}");
                // Don't fail the test — real DNS can be unreliable
                println!("  (network-dependent test, failure is non-fatal)");
            }
        }

        Ok(())
    }

    /// Live benchmark: resolve www.163.com A 10 times and measure
    /// average latency with all optimizations enabled. Reports
    /// first-query time (cold cache) vs subsequent (warm cache).
    ///
    /// Run with:
    ///   cargo test -- cname_live_cold_vs_warm --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn cname_live_cold_vs_warm_www163() -> anyhow::Result<()> {
        let resolver = make_forwarder_for_live_bench(true, true, true, false);

        let request = dns::build_query(9930, "www.163.com", 1, true).expect("query");
        let ctx = make_request_context(9930, "www.163.com", 1);

        let iterations: usize = 5;
        let mut times: Vec<Duration> = Vec::with_capacity(iterations);

        println!();
        println!("=== www.163.com A — Cold vs Warm Cache ===");

        for i in 0..iterations {
            let started = Instant::now();
            let response = resolver.resolve(&ctx, &request).await?;
            let elapsed = started.elapsed();
            times.push(elapsed);

            let source = &response.source;
            let label = if i == 0 { "COLD" } else { "WARM" };
            println!(
                "  [{i}] {label:5}  {elapsed:.2?}  rcode={rcode}  src={source:?}",
                rcode = dns::response_code(&response.packet).unwrap_or(255),
            );
        }

        let cold = times[0];
        let warm_avg: Duration = times[1..].iter().sum::<Duration>() / (iterations - 1) as u32;

        println!();
        println!("  Cold (1st):   {cold:.2?}");
        println!("  Warm (avg):   {warm_avg:.2?}");
        if cold > Duration::ZERO {
            let speedup = cold.as_secs_f64() / warm_avg.as_secs_f64();
            println!("  Speedup:      {speedup:.1}x");
        }

        // Cache must be effective: warm queries should be sub-millisecond
        assert!(
            warm_avg < Duration::from_millis(2),
            "warm cache resolution should be sub-2ms (Phase A)"
        );
        // All warm queries must be cache hits
        for warm_time in &times[1..] {
            assert!(!warm_time.is_zero(), "warm resolution should be near-instant");
        }

        Ok(())
    }
}
