//! Shared application state injected into ingress and admin handlers.
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context;
use serde::Serialize;
use tokio::sync::Notify;
use tracing::info;

use crate::cache::ResponseCache;
use crate::cache::{CacheDump, CacheImportResult};
use crate::traits::DnsCache;
use crate::config::AppConfig;
use crate::context::RequestContext;
use crate::dnssec;
use crate::error::MutexRecover;
use crate::metrics::Metrics;
use crate::policy::{PolicyConfig, PolicyDecision, PolicyEngine, PolicySnapshot};
use crate::resolver::{ResolvedResponse, Resolver, ResolverConfig, ResolverSnapshot};
use crate::topn::{TopDomainStats, TopNStats};

#[derive(Debug, Clone, Serialize)]
pub struct ReloadAuditSnapshot {
    pub attempt_count: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub last_success: bool,
    pub last_duration_ms: u128,
    pub last_message: String,
    pub last_reload_uptime_secs: u64,
    pub last_resolve_mode: String,
    pub last_upstreams_count: usize,
}

#[derive(Debug, Clone)]
struct ReloadAuditState {
    attempt_count: usize,
    success_count: usize,
    failure_count: usize,
    last_success: bool,
    last_duration_ms: u128,
    last_message: String,
    last_reload_uptime_secs: u64,
    last_resolve_mode: String,
    last_upstreams_count: usize,
}

impl Default for ReloadAuditState {
    /// ReloadAuditState 的默认实现，初始化所有统计字段。
    fn default() -> Self {
        Self {
            attempt_count: 0,
            success_count: 0,
            failure_count: 0,
            last_success: true,
            last_duration_ms: 0,
            last_message: "not reloaded yet".to_string(),
            last_reload_uptime_secs: 0,
            last_resolve_mode: "unknown".to_string(),
            last_upstreams_count: 0,
        }
    }
}

impl ReloadAuditState {
    /// 获取当前 ReloadAuditState 的快照。
    fn snapshot(&self) -> ReloadAuditSnapshot {
        ReloadAuditSnapshot {
            attempt_count: self.attempt_count,
            success_count: self.success_count,
            failure_count: self.failure_count,
            last_success: self.last_success,
            last_duration_ms: self.last_duration_ms,
            last_message: self.last_message.clone(),
            last_reload_uptime_secs: self.last_reload_uptime_secs,
            last_resolve_mode: self.last_resolve_mode.clone(),
            last_upstreams_count: self.last_upstreams_count,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    policy: Arc<ArcSwap<PolicyEngine>>,
    resolver: Arc<ArcSwap<Resolver>>,
    config_path: Arc<String>,
    reload_audit: Arc<Mutex<ReloadAuditState>>,
    shutdown_notify: Arc<Notify>,
    pub metrics: Arc<Metrics>,
    pub started_at: Instant,
    top_n: Option<Arc<TopNStats>>,
    top_n_enabled: bool,
    response_cache: Arc<dyn DnsCache>,
}

impl AppState {
    /// Creates runtime state with reloadable policy/resolver pointers.
    /// 创建 AppState，包含独立的响应缓存。
    pub fn new(
        policy: PolicyEngine,
        resolver: Resolver,
        metrics: Arc<Metrics>,
        config_path: String,
    ) -> Self {
        Self::new_with_cache_and_topn(
            policy,
            resolver,
            Arc::new(ResponseCache::default()),
            metrics,
            config_path,
            false,
        )
    }

    /// Creates runtime state with a shared response cache that survives reload.
    /// 创建 AppState，允许传入共享的响应缓存（reload 时缓存不丢失）。
    pub fn new_with_cache(
        policy: PolicyEngine,
        resolver: Resolver,
        response_cache: Arc<dyn DnsCache>,
        metrics: Arc<Metrics>,
        config_path: String,
    ) -> Self {
        Self::new_with_cache_and_topn(
            policy,
            resolver,
            response_cache,
            metrics,
            config_path,
            false,
        )
    }

    /// Creates runtime state with optional TOP N stats tracking.
    pub fn new_with_cache_and_topn(
        policy: PolicyEngine,
        resolver: Resolver,
        response_cache: Arc<dyn DnsCache>,
        metrics: Arc<Metrics>,
        config_path: String,
        top_n_enabled: bool,
    ) -> Self {
        let top_n = if top_n_enabled {
            let (top_n, bg) = TopNStats::new();
            tokio::spawn(bg);
            Some(Arc::new(top_n))
        } else {
            None
        };
        Self {
            policy: Arc::new(ArcSwap::new(Arc::new(policy))),
            resolver: Arc::new(ArcSwap::new(Arc::new(resolver))),
            response_cache,
            config_path: Arc::new(config_path),
            reload_audit: Arc::new(Mutex::new(ReloadAuditState::default())),
            shutdown_notify: Arc::new(Notify::new()),
            metrics,
            started_at: Instant::now(),
            top_n,
            top_n_enabled,
        }
    }

    /// 通知所有等待 shutdown 的任务进行关闭。
    pub fn request_shutdown(&self) {
        self.shutdown_notify.notify_waiters();
    }

    /// 记录 TOP N 查询统计（域名 + 客户端 IP）。热路径，无锁。
    pub fn record_top_query(&self, ctx: &RequestContext, success: bool) {
        if !self.top_n_enabled {
            return;
        }
        if let (Some(top_n), Some(domain)) = (self.top_n.as_ref(), ctx.query_name.as_ref()) {
            top_n.record_query(domain, ctx.client_addr.ip(), success);
        }
    }

    /// 返回 TOP N 功能是否启用。
    pub fn top_n_enabled(&self) -> bool {
        self.top_n_enabled
    }

    /// 查询窗口内 TOP N 域名。
    pub fn top_domains(&self, n: usize, window_secs: u64) -> Vec<(String, u64)> {
        self.top_n
            .as_ref()
            .map(|top_n| top_n.top_domains(n, window_secs))
            .unwrap_or_default()
    }

    /// 查询窗口内 TOP N 域名（包含成功率）。
    pub fn top_domains_with_success(&self, n: usize, window_secs: u64) -> Vec<TopDomainStats> {
        self.top_n
            .as_ref()
            .map(|top_n| top_n.top_domains_with_success(n, window_secs))
            .unwrap_or_default()
    }

    /// 查询窗口内 TOP N 客户端 IP。
    pub fn top_clients(&self, n: usize, window_secs: u64) -> Vec<(std::net::IpAddr, u64)> {
        self.top_n
            .as_ref()
            .map(|top_n| top_n.top_clients(n, window_secs))
            .unwrap_or_default()
    }

    /// 异步等待 shutdown 通知。
    pub async fn wait_shutdown(&self) {
        self.shutdown_notify.notified().await;
    }

    /// 调用当前策略引擎对请求上下文进行策略评估。
    pub fn policy_evaluate(&self, ctx: &RequestContext) -> PolicyDecision {
        let policy = self.policy.load_full();
        policy.evaluate(ctx)
    }

    /// 获取当前策略引擎的快照。
    pub fn policy_snapshot(&self) -> PolicySnapshot {
        let policy = self.policy.load_full();
        policy.snapshot()
    }

    /// 调用当前解析器进行 DNS 查询。
    pub async fn resolve(
        &self,
        ctx: &RequestContext,
        request: &[u8],
    ) -> anyhow::Result<ResolvedResponse> {
        self.resolve_with_view(ctx, request, None).await
    }

    /// 调用当前解析器进行 DNS 查询，可指定已匹配的 split-horizon 视图名。
    pub async fn resolve_with_view(
        &self,
        ctx: &RequestContext,
        request: &[u8],
        matched_view: Option<&str>,
    ) -> anyhow::Result<ResolvedResponse> {
        let resolver = self.resolver.load_full();
        resolver.resolve_with_view(ctx, request, matched_view).await
    }

    /// 获取当前解析器的健康快照。
    pub fn resolver_snapshot(&self) -> ResolverSnapshot {
        let resolver = self.resolver.load_full();
        resolver.health_snapshot()
    }

    /// 返回当前 `Arc<Resolver>` 的克隆，供调用方持有共享引用。
    pub fn get_resolver(&self) -> Arc<Resolver> {
        self.resolver.load_full()
    }

    /// 获取最近一次 reload 的审计快照。
    pub fn reload_audit_snapshot(&self) -> ReloadAuditSnapshot {
        self.reload_audit
            .lock()
            .recover("reload_audit")
            .snapshot()
    }

    /// 返回当前运行实例绑定的配置文件路径。
    pub fn config_path(&self) -> &str {
        self.config_path.as_str()
    }

    /// 设置是否全局冻结缓存 TTL。
    pub fn set_cache_freeze_all(&self, enabled: bool) {
        self.response_cache.set_freeze_all(enabled);
    }

    /// 设置某个域名是否冻结缓存 TTL。
    pub fn set_cache_freeze_domain(&self, domain: &str, enabled: bool) -> usize {
        self.response_cache.set_freeze_domain(domain, enabled)
    }

    /// 清空所有缓存条目。
    pub fn clear_cache_all(&self) -> usize {
        self.response_cache.clear_all()
    }

    /// 清空指定域名相关的缓存条目。
    pub fn clear_cache_domain(&self, domain: &str) -> usize {
        self.response_cache.clear_domain(domain)
    }

    /// 导出当前缓存快照。
    pub fn export_cache_dump(&self) -> CacheDump {
        self.response_cache
            .export_dump(&|qname| self.response_cache.is_frozen_for_qname(qname))
    }

    /// 导入缓存快照。
    pub fn import_cache_dump(&self, dump: CacheDump) -> CacheImportResult {
        self.response_cache.import_dump(dump)
    }

    /// Reloads config from disk and atomically swaps policy/resolver runtime pointers.
    /// 从磁盘重新加载配置，并原子性替换策略和解析器。
    pub fn reload_from_disk(&self) -> anyhow::Result<()> {
        let started = Instant::now();
        let cfg = AppConfig::load_or_default(&self.config_path)
            .with_context(|| format!("failed to load config from {}", self.config_path))?;
        cfg.validate()
            .with_context(|| format!("invalid config in {}", self.config_path))?;

        // reload 完成配置加载后立即检查日志文件，确保被删除的日志文件就绪。
        crate::logging::check_and_recreate_log_files(&cfg);
        crate::logging::refresh_trace_query_domains(&cfg);

        let policy = PolicyEngine::new_with_views(
            PolicyConfig {
                allow_clients: cfg.allow_clients.clone(),
                blocked_domains: cfg.blocked_domains.clone(),
                rate_limit_per_second: cfg.rate_limit_per_second,
                deny_any_queries: cfg.deny_any_queries,
            },
            cfg.views.clone(),
        )?;

        let resolver = {
            info!(
                prewarm_source = "reload",
                "building new resolver (hot-reload)"
            );
            let mut resolver = Resolver::new(
                ResolverConfig {
                    resolve_mode: cfg.resolve_mode.clone(),
                    root_servers: cfg.root_servers.clone(),
                    iterative_address_family: cfg.iterative_address_family,
                    iterative_max_depth: cfg.iterative_max_depth,
                    iterative_timeout_ms: cfg.iterative_timeout_ms,
                    cname_chain_max_depth: cfg.cname_chain_max_depth,
                    follow_cname_chain: cfg.follow_cname_chain,
                    static_cname_expand_for_address_queries: cfg
                        .static_cname_expand_for_address_queries,
                    iterative_fallback_to_forwarder: cfg.iterative_fallback_to_forwarder,
                    iterative_cname_bridge_fallback_to_recursive: cfg
                        .iterative_cname_bridge_fallback_to_recursive,
                    cname_chain_cache_enabled: cfg.cname_chain_cache_enabled,
                    cname_chain_inline_cache_enabled: cfg.cname_chain_inline_cache_enabled,
                    cname_chain_dualstack_share_enabled: cfg.cname_chain_dualstack_share_enabled,
                    cname_chain_target_prefetch_enabled: cfg.cname_chain_target_prefetch_enabled,
                    ns_host_cache_capacity: cfg.ns_host_cache_capacity,
                    ns_host_cache_ttl_secs: cfg.ns_host_cache_ttl_secs,
                    ns_host_cache_cleanup_interval_ms: cfg.ns_host_cache_cleanup_interval_ms,
                    enable_delegation_cache: cfg.enable_delegation_cache,
                    strict_bailiwick: cfg.strict_bailiwick,
                    delegation_cache_capacity: cfg.delegation_cache_capacity,
                    delegation_cache_ttl_cap_secs: cfg.delegation_cache_ttl_cap_secs,
                    delegation_cache_cleanup_interval_ms: cfg.delegation_cache_cleanup_interval_ms,
                    delegation_failure_backoff_ms: cfg.delegation_failure_backoff_ms,
                    stats_window_secs: cfg.stats_window_secs,
                    stats_short_window_secs: cfg.stats_short_window_secs,
                    cache_hot_capacity: cfg.cache_hot_capacity,
                    upstreams: cfg.upstreams.clone(),
                    cache_ttl_secs: cfg.cache_ttl_secs,
                    freeze_cache_ttl_decay: cfg.freeze_cache_ttl_decay,
                    freeze_cache_domains: cfg.freeze_cache_domains.clone(),
                    upstream_timeout_ms: cfg.upstream_timeout_ms,
                    upstream_retries: cfg.upstream_retries,
                    unhealthy_backoff_ms: cfg.unhealthy_backoff_ms,
                    prefetch_budget_per_window: cfg.prefetch_budget_per_window,
                    prefetch_window_secs: cfg.prefetch_window_secs,
                    prefetch_ttl_trigger_secs: cfg.prefetch_ttl_trigger_secs,
                    prefetch_popularity_threshold: cfg.prefetch_popularity_threshold,
                    upstream_score_rtt_weight: cfg.upstream_score_rtt_weight,
                    upstream_score_failure_weight: cfg.upstream_score_failure_weight,
                    upstream_score_success_weight: cfg.upstream_score_success_weight,
                    adaptive_cache_enabled: cfg.adaptive_cache_enabled,
                    adaptive_cache_min_capacity: cfg.adaptive_cache_min_capacity,
                    adaptive_cache_max_capacity: cfg.adaptive_cache_max_capacity,
                    adaptive_cache_step: cfg.adaptive_cache_step,
                    adaptive_cache_window_secs: cfg.adaptive_cache_window_secs,
                    adaptive_cache_high_miss_ratio: cfg.adaptive_cache_high_miss_ratio,
                    adaptive_cache_low_miss_ratio: cfg.adaptive_cache_low_miss_ratio,
                    enable_recursion: cfg.enable_recursion,
                    dnssec_enabled: cfg.dnssec.enabled,
                    trust_anchors: dnssec::load_trust_anchors(
                        &self.config_path,
                        cfg.dnssec.use_builtin_trust_anchors,
                        &cfg.dnssec.trust_anchor_files,
                    )?,
                    ns_hostname_max_concurrent: cfg.ns_hostname_max_concurrent,
                    ns_hostname_enough_endpoints: cfg.ns_hostname_enough_endpoints,
                    ns_hostname_per_resolve_ms: cfg.ns_hostname_per_resolve_ms,
                    ns_hostname_resolve_mode: cfg.ns_hostname_resolve_mode,
                    iterative_per_hop_timeout_ms: cfg.iterative_per_hop_timeout_ms,
                    prewarm_delegation_zones: cfg.prewarm_delegation_zones.clone(),
                },
                {
                    self.response_cache
                        .set_capacity(cfg.response_cache_capacity);
                    self.response_cache.clone()
                },
                self.metrics.clone(),
                cfg.static_records.clone(),
                cfg.authoritative_sources.clone(),
            );
            resolver.configure_ip_health(cfg.health_check.clone());
            resolver.configure_minimal_response(cfg.minimal_response);
            resolver.configure_views(&cfg.views);
            resolver.configure_authoritative_zones(&cfg.authoritative_zones);
            resolver
        };

        {
            self.policy.store(Arc::new(policy));
        }
        let new_resolver = {
            let arc = Arc::new(resolver);
            self.resolver.store(Arc::clone(&arc));
            arc
        };
        // 热重载后启动 ns_hostnames 异步预热后台任务（不阻塞重载路径）
        new_resolver.start_hostname_prewarm();

        self.record_reload_audit(
            true,
            "runtime config reloaded".to_string(),
            started.elapsed(),
            &cfg,
        );

        Ok(())
    }

    /// 记录 reload 失败的审计信息。
    pub fn record_reload_failure(&self, message: String, duration: Duration) {
        let fallback_cfg = AppConfig::default();
        self.record_reload_audit(false, message, duration, &fallback_cfg);
    }

    /// 记录 reload 的详细审计信息。
    fn record_reload_audit(
        &self,
        success: bool,
        message: String,
        duration: Duration,
        cfg: &AppConfig,
    ) {
        let mut audit = self
            .reload_audit
            .lock()
            .recover("reload_audit");
        audit.attempt_count += 1;
        if success {
            audit.success_count += 1;
        } else {
            audit.failure_count += 1;
        }
        audit.last_success = success;
        audit.last_duration_ms = duration.as_millis();
        audit.last_message = message;
        audit.last_reload_uptime_secs = self.started_at.elapsed().as_secs();
        audit.last_resolve_mode = cfg.resolve_mode.clone();
        audit.last_upstreams_count = cfg.upstreams.len();
    }
}
