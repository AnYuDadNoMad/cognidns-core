//! Admin HTTP API exposing health, readiness and runtime stats.
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::time::UNIX_EPOCH;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;
use toml::value::Table;

use crate::cache::{CacheDump, CacheImportResult};
use crate::config::{
    AppConfig, AuthoritativeSource, AuthoritativeZone, DnsView, StaticRecord, ViewQueryMode,
    ZoneSoa,
};
use crate::metrics::MetricsSnapshot;
use crate::policy::PolicySnapshot;
use crate::resolver::ResolverSnapshot;
use crate::service::{AppState, ReloadAuditSnapshot};

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
    total_upstreams: usize,
    healthy_upstreams: usize,
    ip_health_enabled: bool,
    ip_health_tracked_domains: usize,
    ip_health_tracked_ips: usize,
    ip_health_degraded_domains: usize,
    ip_health_all_unhealthy_events: usize,
    ip_health_notify_attempt_total: usize,
    ip_health_notify_fail_total: usize,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    status: &'static str,
    version: &'static str,
    uptime_secs: u64,
    resolver: ResolverSnapshot,
    policy: PolicySnapshot,
    health_check: HealthCheckStatsResponse,
    metrics: MetricsSnapshot,
    reload_audit: ReloadAuditSnapshot,
}

#[derive(Debug, Serialize)]
struct HealthCheckStatsResponse {
    enabled: bool,
    tracked_domains: usize,
    tracked_ips: usize,
    degraded_domains: usize,
    all_unhealthy_events: usize,
    notify_attempt_total: usize,
    notify_fail_total: usize,
}

#[derive(Debug, Serialize)]
struct ReloadResponse {
    status: &'static str,
    reloaded: bool,
    message: String,
    audit: ReloadAuditSnapshot,
}

#[derive(Debug, Serialize)]
struct ShutdownResponse {
    status: &'static str,
    stopping: bool,
}

#[derive(Debug, Deserialize)]
struct CacheFreezeAllRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct CacheFreezeDomainRequest {
    domain: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct CacheClearDomainRequest {
    domain: String,
}

#[derive(Debug, Serialize)]
struct CacheActionResponse {
    status: &'static str,
    message: String,
    affected: usize,
}

#[derive(Debug, Serialize)]
struct CacheImportResponse {
    status: &'static str,
    result: CacheImportResult,
}

#[derive(Debug, Clone)]
struct AdminAuthConfig {
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TopNQueryParams {
    n: Option<usize>,
    window: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TopDomainEntry {
    domain: String,
    count: u64,
    success_count: u64,
    success_rate: f64,
}

#[derive(Debug, Serialize)]
struct TopClientEntry {
    client: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct TopQueriesResponse {
    status: &'static str,
    enabled: bool,
    window_secs: u64,
    entries: Vec<TopDomainEntry>,
}

#[derive(Debug, Serialize)]
struct TopClientsResponse {
    status: &'static str,
    enabled: bool,
    window_secs: u64,
    entries: Vec<TopClientEntry>,
}

#[derive(Debug, Serialize)]
struct AdminAuthErrorResponse {
    status: &'static str,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct ConfigRawResponse {
    status: &'static str,
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ConfigRawUpsertRequest {
    content: String,
}

#[derive(Debug, Serialize)]
struct ConfigApplyResponse {
    status: &'static str,
    reloaded: bool,
    message: String,
    audit: ReloadAuditSnapshot,
}

#[derive(Debug, Serialize)]
struct AuthoritativeZonesResponse {
    status: &'static str,
    zones: Vec<AuthoritativeZone>,
}

#[derive(Debug, Deserialize)]
struct AuthoritativeZoneUpsertRequest {
    zone: AuthoritativeZone,
}

#[derive(Debug, Serialize)]
struct AuthoritativeZoneMutationResponse {
    status: &'static str,
    message: String,
    audit: ReloadAuditSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthoritativeZoneFilePayload {
    #[serde(default)]
    zones: Vec<AuthoritativeZone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BasicListenControlSection {
    udp_listen: String,
    tcp_listen: String,
    admin_listen: String,
    control_listen: String,
    control_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolveUpstreamSection {
    resolve_mode: String,
    upstreams: Vec<String>,
    root_servers: Vec<String>,
    iterative_max_depth: u8,
    iterative_timeout_ms: u64,
    iterative_fallback_to_forwarder: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheSection {
    response_cache_capacity: usize,
    cache_ttl_secs: u64,
    freeze_cache_ttl_decay: bool,
    prefetch_budget_per_window: u32,
    prefetch_window_secs: u64,
    prefetch_ttl_trigger_secs: u64,
    prefetch_popularity_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransportSection {
    dot_enabled: bool,
    dot_listen: String,
    dot_cert_file: String,
    dot_key_file: String,
    doh_enabled: bool,
    doh_listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoggingSection {
    enabled: bool,
    console: bool,
    directory: String,
    rotation: String,
    format: String,
    query_level: String,
    response_level: String,
    general_level: String,
    trace_query_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StaticDataSection {
    static_records: Vec<StaticRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecuritySection {
    allow_clients: Vec<String>,
    blocked_domains: Vec<String>,
    rate_limit_per_second: u32,
    deny_any_queries: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdvancedSection {
    enable_recursion: bool,
    minimal_response: bool,
    iterative_address_family: String,
    cname_chain_max_depth: u8,
    follow_cname_chain: bool,
    static_cname_expand_for_address_queries: bool,
    iterative_cname_bridge_fallback_to_recursive: bool,
    iterative_per_hop_timeout_ms: u64,
    ns_host_cache_capacity: usize,
    ns_host_cache_ttl_secs: u64,
    ns_host_cache_cleanup_interval_ms: u64,
    enable_delegation_cache: bool,
    strict_bailiwick: bool,
    delegation_cache_capacity: usize,
    delegation_cache_ttl_cap_secs: u64,
    delegation_cache_cleanup_interval_ms: u64,
    delegation_failure_backoff_ms: u64,
    ns_hostname_max_concurrent: usize,
    ns_hostname_enough_endpoints: usize,
    ns_hostname_per_resolve_ms: u64,
    ns_hostname_resolve_mode: String,
    cache_hot_capacity: usize,
    freeze_cache_domains: Vec<String>,
    adaptive_cache_enabled: bool,
    adaptive_cache_min_capacity: usize,
    adaptive_cache_max_capacity: usize,
    adaptive_cache_step: usize,
    adaptive_cache_window_secs: u64,
    adaptive_cache_high_miss_ratio: f64,
    adaptive_cache_low_miss_ratio: f64,
    stats_window_secs: u64,
    stats_short_window_secs: u64,
    topn_stats_enabled: bool,
    upstream_timeout_ms: u64,
    upstream_retries: u8,
    unhealthy_backoff_ms: u64,
    upstream_score_rtt_weight: f64,
    upstream_score_failure_weight: f64,
    upstream_score_success_weight: f64,
    dnssec_enabled: bool,
    dnssec_use_builtin_trust_anchors: bool,
    dnssec_trust_anchor_files: Vec<String>,
    health_check_enabled: bool,
    health_check_mode: String,
    health_check_port: u16,
    health_check_http_path: String,
    health_check_http_host_header: Option<String>,
    health_check_interval_secs: u64,
    health_check_timeout_ms: u64,
    health_check_max_parallel: usize,
    health_check_failure_threshold: u32,
    health_check_success_threshold: u32,
    health_check_all_unhealthy_log_file: String,
    health_check_notify_webhook: Option<String>,
    health_check_probe_tls_insecure_skip_verify: bool,
    health_check_webhook_tls_insecure_skip_verify: bool,
    health_check_notify_webhook_retries: u32,
    health_check_notify_webhook_backoff_ms: u64,
    authoritative_sources: Vec<AuthoritativeSource>,
    prewarm_delegation_zones: Vec<PrewarmDelegationZoneSectionItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrewarmDelegationZoneSectionItem {
    zone: String,
    ns_endpoints: Vec<String>,
    ns_hostnames: Vec<String>,
    ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigSectionsPayload {
    basic: BasicListenControlSection,
    resolver: ResolveUpstreamSection,
    cache: CacheSection,
    transport: TransportSection,
    logging: LoggingSection,
    static_data: StaticDataSection,
    security: SecuritySection,
    advanced: AdvancedSection,
}

#[derive(Debug, Serialize)]
struct ConfigSectionsResponse {
    status: &'static str,
    path: String,
    sections: ConfigSectionsPayload,
}

#[derive(Debug, Deserialize)]
struct ConfigSectionsUpsertRequest {
    sections: ConfigSectionsPayload,
}

#[derive(Debug, Serialize)]
struct ConfigSectionsApplyResponse {
    status: &'static str,
    message: String,
    reloaded: bool,
    audit: ReloadAuditSnapshot,
}

#[derive(Debug, Deserialize)]
struct LogsDownloadQuery {
    file: String,
}

#[derive(Debug, Serialize)]
struct LogFileEntry {
    name: String,
    size_bytes: u64,
    modified_unix_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LogsFilesResponse {
    status: &'static str,
    directory: String,
    files: Vec<LogFileEntry>,
}

#[derive(Debug, Serialize)]
struct ViewsResponse {
    status: &'static str,
    views: Vec<DnsView>,
}

#[derive(Debug, Deserialize)]
struct ViewAuthoritativeRecordsUpsertRequest {
    records: Vec<StaticRecord>,
}

#[derive(Debug, Deserialize)]
struct ViewStaticRecordsUpsertRequest {
    records: Vec<StaticRecord>,
}

#[derive(Debug, Deserialize)]
struct ViewBlockedDomainsUpsertRequest {
    blocked_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct ViewDataUpsertRequest {
    authoritative_records: Option<Vec<StaticRecord>>,
    static_records: Option<Vec<StaticRecord>>,
    blocked_domains: Option<Vec<String>>,
    authoritative_zone_name: Option<String>,
}

impl Default for ViewDataUpsertRequest {
    fn default() -> Self {
        Self {
            authoritative_records: None,
            static_records: None,
            blocked_domains: None,
            authoritative_zone_name: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ViewUpsertRequest {
    name: String,
    #[serde(default)]
    previous_name: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    query_mode: String,
    #[serde(default)]
    client_cidrs: Vec<String>,
    #[serde(default)]
    static_records: Vec<StaticRecord>,
    #[serde(default)]
    blocked_domains: Vec<String>,
    #[serde(default = "default_true")]
    enable_recursion: bool,
    #[serde(default)]
    view_static_cname_expand_for_address_queries: Option<bool>,
    #[serde(default)]
    view_authoritative_cname_expand_for_address_queries: Option<bool>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct ViewAuthoritativeRecordsMutationResponse {
    status: &'static str,
    message: String,
    audit: ReloadAuditSnapshot,
}

#[derive(Debug, Serialize)]
struct StaticRecordsFileWritePayload {
    static_records: Vec<StaticRecord>,
}

#[derive(Debug, Serialize)]
struct BlockedDomainsFileWritePayload {
    blocked_domains: Vec<String>,
}

/// 启动 Admin HTTP 服务监听。
pub async fn run_admin_server(listen_addr: &str, state: AppState) -> anyhow::Result<()> {
    run_admin_server_with_token(listen_addr, state, None).await
}

/// 启动带 token 保护的 Admin HTTP 服务监听。
pub async fn run_admin_server_with_token(
    listen_addr: &str,
    state: AppState,
    token: Option<String>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    serve_admin_with_token(listener, state, token).await
}

/// 启动 axum 路由并服务于 Admin HTTP API。
pub async fn serve_admin(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    serve_admin_with_token(listener, state, None).await
}

/// 启动带 token 保护的 axum 路由并服务于 Admin HTTP API。
pub async fn serve_admin_with_token(
    listener: TcpListener,
    state: AppState,
    token: Option<String>,
) -> anyhow::Result<()> {
    let auth = AdminAuthConfig { token };
    let protected_routes = Router::new()
        .route("/stats", get(stats_handler))
        .route("/stats/top-queries", get(top_queries_handler))
        .route("/stats/top-clients", get(top_clients_handler))
        .route("/reload", post(reload_handler))
        .route("/shutdown", post(shutdown_handler))
        .route("/cache/freeze/all", post(cache_freeze_all_handler))
        .route("/cache/freeze/domain", post(cache_freeze_domain_handler))
        .route("/cache/clear/all", post(cache_clear_all_handler))
        .route("/cache/clear/domain", post(cache_clear_domain_handler))
        .route("/cache/export", get(cache_export_handler))
        .route("/cache/import", post(cache_import_handler))
        .route(
            "/config/sections",
            get(config_sections_handler).put(config_sections_upsert_handler),
        )
        .route(
            "/config/raw",
            get(config_raw_handler).put(config_raw_upsert_handler),
        )
        .route("/logs/files", get(logs_files_handler))
        .route("/logs/download", get(logs_download_handler))
        .route("/views", get(views_handler).post(views_upsert_handler))
        .route("/views/:view", delete(view_delete_handler))
        .route(
            "/views/:view/authoritative-records",
            put(view_authoritative_records_upsert_handler),
        )
        .route(
            "/views/:view/static-records",
            put(view_static_records_upsert_handler),
        )
        .route(
            "/views/:view/blocked-domains",
            put(view_blocked_domains_upsert_handler),
        )
        .route("/views/:view/data", put(view_data_upsert_handler))
        .route(
            "/views/:view/authoritative-zones/:zone",
            delete(view_authoritative_zone_delete_handler),
        )
        .route(
            "/views/:view/authoritative-zones",
            post(view_authoritative_zone_upsert_handler),
        )
        .route(
            "/views/:view/authoritative-zones/:zone/soa",
            patch(view_authoritative_zone_soa_patch_handler),
        )
        .route(
            "/authoritative/zones",
            get(authoritative_zones_handler).post(authoritative_zone_upsert_handler),
        )
        .route(
            "/authoritative/zones/:zone",
            delete(authoritative_zone_delete_handler),
        )
        .route(
            "/authoritative/zones/:zone/soa",
            patch(authoritative_zone_soa_patch_handler),
        )
        .route_layer(from_fn_with_state(auth, require_admin_token));

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .merge(protected_routes)
        .with_state(state);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn require_admin_token(
    State(auth): State<AdminAuthConfig>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if is_admin_request_authorized(request.headers(), auth.token.as_deref()) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "unauthorized",
            }),
        )
            .into_response()
    }
}

fn is_admin_request_authorized(headers: &HeaderMap, expected_token: Option<&str>) -> bool {
    let Some(expected) = expected_token.filter(|value| !value.is_empty()) else {
        return true;
    };

    if headers
        .get("x-cognidns-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| value == expected)
        .unwrap_or(false)
    {
        return true;
    }

    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value == expected)
        .unwrap_or(false)
}

/// 处理 /stats 路由，返回运行时统计信息。
async fn stats_handler(State(state): State<AppState>) -> Json<StatsResponse> {
    let resolver = state.resolver_snapshot();
    Json(StatsResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        health_check: HealthCheckStatsResponse {
            enabled: resolver.ip_health_enabled,
            tracked_domains: resolver.ip_health_tracked_domains,
            tracked_ips: resolver.ip_health_tracked_ips,
            degraded_domains: resolver.ip_health_degraded_domains,
            all_unhealthy_events: resolver.ip_health_all_unhealthy_events,
            notify_attempt_total: resolver.ip_health_notify_attempt_total,
            notify_fail_total: resolver.ip_health_notify_fail_total,
        },
        resolver,
        policy: state.policy_snapshot(),
        metrics: state.metrics.snapshot(),
        reload_audit: state.reload_audit_snapshot(),
    })
}

/// 处理 /stats/top-queries 路由，返回 TOP N 查询域名统计。
/// 查询参数：n（默认 10，上限 100），window（秒，默认 300，上限 3600）。
async fn top_queries_handler(
    State(state): State<AppState>,
    Query(params): Query<TopNQueryParams>,
) -> Json<TopQueriesResponse> {
    let n = params.n.unwrap_or(10).clamp(1, 100);
    let window = params.window.unwrap_or(300).clamp(1, 3600);
    let entries = state
        .top_domains_with_success(n, window)
        .into_iter()
        .map(|entry| TopDomainEntry {
            domain: entry.domain,
            count: entry.total_count,
            success_count: entry.success_count,
            success_rate: entry.success_rate,
        })
        .collect();
    Json(TopQueriesResponse {
        status: "ok",
        enabled: state.top_n_enabled(),
        window_secs: window,
        entries,
    })
}

/// 处理 /stats/top-clients 路由，返回 TOP N 查询客户端 IP 统计。
/// 查询参数：n（默认 10，上限 100），window（秒，默认 300，上限 3600）。
async fn top_clients_handler(
    State(state): State<AppState>,
    Query(params): Query<TopNQueryParams>,
) -> Json<TopClientsResponse> {
    let n = params.n.unwrap_or(10).clamp(1, 100);
    let window = params.window.unwrap_or(300).clamp(1, 3600);
    let entries = state
        .top_clients(n, window)
        .into_iter()
        .map(|(ip, count)| TopClientEntry {
            client: ip.to_string(),
            count,
        })
        .collect();
    Json(TopClientsResponse {
        status: "ok",
        enabled: state.top_n_enabled(),
        window_secs: window,
        entries,
    })
}

/// 处理 /health 路由，返回健康状态。
async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let snapshot = state.resolver_snapshot();
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        total_upstreams: snapshot.total_upstreams,
        healthy_upstreams: snapshot.healthy_upstreams,
        ip_health_enabled: snapshot.ip_health_enabled,
        ip_health_tracked_domains: snapshot.ip_health_tracked_domains,
        ip_health_tracked_ips: snapshot.ip_health_tracked_ips,
        ip_health_degraded_domains: snapshot.ip_health_degraded_domains,
        ip_health_all_unhealthy_events: snapshot.ip_health_all_unhealthy_events,
        ip_health_notify_attempt_total: snapshot.ip_health_notify_attempt_total,
        ip_health_notify_fail_total: snapshot.ip_health_notify_fail_total,
    })
}

/// 处理 /ready 路由，返回就绪状态。
async fn ready_handler(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let snapshot = state.resolver_snapshot();
    let status = if snapshot.healthy_upstreams > 0 {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            status: if status == StatusCode::OK {
                "ready"
            } else {
                "degraded"
            },
            version: env!("CARGO_PKG_VERSION"),
            uptime_secs: state.started_at.elapsed().as_secs(),
            total_upstreams: snapshot.total_upstreams,
            healthy_upstreams: snapshot.healthy_upstreams,
            ip_health_enabled: snapshot.ip_health_enabled,
            ip_health_tracked_domains: snapshot.ip_health_tracked_domains,
            ip_health_tracked_ips: snapshot.ip_health_tracked_ips,
            ip_health_degraded_domains: snapshot.ip_health_degraded_domains,
            ip_health_all_unhealthy_events: snapshot.ip_health_all_unhealthy_events,
            ip_health_notify_attempt_total: snapshot.ip_health_notify_attempt_total,
            ip_health_notify_fail_total: snapshot.ip_health_notify_fail_total,
        }),
    )
}

/// 处理 /reload 路由，触发配置热重载。
async fn reload_handler(State(state): State<AppState>) -> (StatusCode, Json<ReloadResponse>) {
    let started = Instant::now();
    match state.reload_from_disk() {
        Ok(()) => {
            state
                .metrics
                .record_reload(true, "ok", started.elapsed().as_secs_f64());
            (
                StatusCode::OK,
                Json(ReloadResponse {
                    status: "ok",
                    reloaded: true,
                    message: "runtime config reloaded".to_string(),
                    audit: state.reload_audit_snapshot(),
                }),
            )
        }
        Err(err) => {
            let message = err.to_string();
            let elapsed = started.elapsed();
            let reason = classify_reload_error(&message);
            state.record_reload_failure(message.clone(), elapsed);
            state
                .metrics
                .record_reload(false, reason, elapsed.as_secs_f64());
            (
                StatusCode::BAD_REQUEST,
                Json(ReloadResponse {
                    status: "error",
                    reloaded: false,
                    message,
                    audit: state.reload_audit_snapshot(),
                }),
            )
        }
    }
}

/// 处理 /shutdown 路由，触发服务优雅关闭。
async fn shutdown_handler(State(state): State<AppState>) -> (StatusCode, Json<ShutdownResponse>) {
    state.request_shutdown();
    (
        StatusCode::OK,
        Json(ShutdownResponse {
            status: "ok",
            stopping: true,
        }),
    )
}

/// 处理 /cache/freeze/all 路由，设置全局缓存冻结。
async fn cache_freeze_all_handler(
    State(state): State<AppState>,
    Json(req): Json<CacheFreezeAllRequest>,
) -> (StatusCode, Json<CacheActionResponse>) {
    state.set_cache_freeze_all(req.enabled);
    (
        StatusCode::OK,
        Json(CacheActionResponse {
            status: "ok",
            message: if req.enabled {
                "cache freeze-all enabled".to_string()
            } else {
                "cache freeze-all disabled".to_string()
            },
            affected: 0,
        }),
    )
}

/// 处理 /cache/freeze/domain 路由，设置指定域名缓存冻结。
async fn cache_freeze_domain_handler(
    State(state): State<AppState>,
    Json(req): Json<CacheFreezeDomainRequest>,
) -> (StatusCode, Json<CacheActionResponse>) {
    let count = state.set_cache_freeze_domain(&req.domain, req.enabled);
    (
        StatusCode::OK,
        Json(CacheActionResponse {
            status: "ok",
            message: if req.enabled {
                format!("cache freeze-domain added: {}", req.domain)
            } else {
                format!("cache freeze-domain removed: {}", req.domain)
            },
            affected: count,
        }),
    )
}

/// 处理 /cache/clear/all 路由，清空所有缓存。
async fn cache_clear_all_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<CacheActionResponse>) {
    let removed = state.clear_cache_all();
    (
        StatusCode::OK,
        Json(CacheActionResponse {
            status: "ok",
            message: "cache cleared (all)".to_string(),
            affected: removed,
        }),
    )
}

/// 处理 /cache/clear/domain 路由，清空指定域名缓存。
async fn cache_clear_domain_handler(
    State(state): State<AppState>,
    Json(req): Json<CacheClearDomainRequest>,
) -> (StatusCode, Json<CacheActionResponse>) {
    let removed = state.clear_cache_domain(&req.domain);
    (
        StatusCode::OK,
        Json(CacheActionResponse {
            status: "ok",
            message: format!("cache cleared for domain: {}", req.domain),
            affected: removed,
        }),
    )
}

/// 处理 /cache/export 路由，导出缓存快照。
async fn cache_export_handler(State(state): State<AppState>) -> Json<CacheDump> {
    Json(state.export_cache_dump())
}

/// 处理 /cache/import 路由，导入缓存快照。
async fn cache_import_handler(
    State(state): State<AppState>,
    Json(dump): Json<CacheDump>,
) -> (StatusCode, Json<CacheImportResponse>) {
    let result = state.import_cache_dump(dump);
    (
        StatusCode::OK,
        Json(CacheImportResponse {
            status: "ok",
            result,
        }),
    )
}

/// 分类 reload 错误类型，便于统计和上报。
fn classify_reload_error(message: &str) -> &'static str {
    let msg = message.to_ascii_lowercase();
    if msg.contains("failed to read config file") {
        "read_error"
    } else if msg.contains("failed to parse config file") {
        "parse_error"
    } else if msg.contains("invalid config in") || msg.contains("invalid config") {
        "invalid_config"
    } else if msg.contains("policy") || msg.contains("resolver") {
        "build_error"
    } else {
        "other"
    }
}

fn build_config_sections(cfg: &AppConfig) -> ConfigSectionsPayload {
    let default_view_static_records = build_effective_views(cfg)
        .into_iter()
        .find(|view| view.name.eq_ignore_ascii_case("default"))
        .map(|view| view.static_records)
        .unwrap_or_else(|| cfg.static_records.clone());

    ConfigSectionsPayload {
        basic: BasicListenControlSection {
            udp_listen: cfg.udp_listen.clone(),
            tcp_listen: cfg.tcp_listen.clone(),
            admin_listen: cfg.admin_listen.clone(),
            control_listen: cfg.control_listen.clone(),
            control_token: cfg.control_token.clone(),
        },
        resolver: ResolveUpstreamSection {
            resolve_mode: cfg.resolve_mode.clone(),
            upstreams: cfg.upstreams.clone(),
            root_servers: cfg.root_servers.clone(),
            iterative_max_depth: cfg.iterative_max_depth,
            iterative_timeout_ms: cfg.iterative_timeout_ms,
            iterative_fallback_to_forwarder: cfg.iterative_fallback_to_forwarder,
        },
        cache: CacheSection {
            response_cache_capacity: cfg.response_cache_capacity,
            cache_ttl_secs: cfg.cache_ttl_secs,
            freeze_cache_ttl_decay: cfg.freeze_cache_ttl_decay,
            prefetch_budget_per_window: cfg.prefetch_budget_per_window,
            prefetch_window_secs: cfg.prefetch_window_secs,
            prefetch_ttl_trigger_secs: cfg.prefetch_ttl_trigger_secs,
            prefetch_popularity_threshold: cfg.prefetch_popularity_threshold,
        },
        transport: TransportSection {
            dot_enabled: cfg.dot.enabled,
            dot_listen: cfg.dot.listen.clone(),
            dot_cert_file: cfg.dot.cert_file.clone(),
            dot_key_file: cfg.dot.key_file.clone(),
            doh_enabled: cfg.doh.enabled,
            doh_listen: cfg.doh.listen.clone(),
        },
        logging: LoggingSection {
            enabled: cfg.logging.enabled,
            console: cfg.logging.console,
            directory: cfg.logging.directory.clone(),
            rotation: cfg.logging.rotation.clone(),
            format: cfg.logging.format.clone(),
            query_level: cfg.logging.query_level.clone(),
            response_level: cfg.logging.response_level.clone(),
            general_level: cfg.logging.general_level.clone(),
            trace_query_domains: cfg.logging.trace_query_domains.clone(),
        },
        static_data: StaticDataSection {
            static_records: default_view_static_records,
        },
        security: SecuritySection {
            allow_clients: cfg.allow_clients.clone(),
            blocked_domains: cfg.blocked_domains.clone(),
            rate_limit_per_second: cfg.rate_limit_per_second,
            deny_any_queries: cfg.deny_any_queries,
        },
        advanced: AdvancedSection {
            enable_recursion: cfg.enable_recursion,
            minimal_response: cfg.minimal_response,
            iterative_address_family: match cfg.iterative_address_family {
                crate::config::IterativeAddressFamily::DualStack => "dual_stack".to_string(),
                crate::config::IterativeAddressFamily::Ipv4 => "ipv4".to_string(),
                crate::config::IterativeAddressFamily::Ipv6 => "ipv6".to_string(),
            },
            cname_chain_max_depth: cfg.cname_chain_max_depth,
            follow_cname_chain: cfg.follow_cname_chain,
            static_cname_expand_for_address_queries: cfg.static_cname_expand_for_address_queries,
            iterative_cname_bridge_fallback_to_recursive: cfg
                .iterative_cname_bridge_fallback_to_recursive,
            iterative_per_hop_timeout_ms: cfg.iterative_per_hop_timeout_ms,
            ns_host_cache_capacity: cfg.ns_host_cache_capacity,
            ns_host_cache_ttl_secs: cfg.ns_host_cache_ttl_secs,
            ns_host_cache_cleanup_interval_ms: cfg.ns_host_cache_cleanup_interval_ms,
            enable_delegation_cache: cfg.enable_delegation_cache,
            strict_bailiwick: cfg.strict_bailiwick,
            delegation_cache_capacity: cfg.delegation_cache_capacity,
            delegation_cache_ttl_cap_secs: cfg.delegation_cache_ttl_cap_secs,
            delegation_cache_cleanup_interval_ms: cfg.delegation_cache_cleanup_interval_ms,
            delegation_failure_backoff_ms: cfg.delegation_failure_backoff_ms,
            ns_hostname_max_concurrent: cfg.ns_hostname_max_concurrent,
            ns_hostname_enough_endpoints: cfg.ns_hostname_enough_endpoints,
            ns_hostname_per_resolve_ms: cfg.ns_hostname_per_resolve_ms,
            ns_hostname_resolve_mode: match cfg.ns_hostname_resolve_mode {
                crate::config::NsHostnameResolveMode::BootstrapRecursive => {
                    "bootstrap_recursive".to_string()
                }
                crate::config::NsHostnameResolveMode::PureIterative => "pure_iterative".to_string(),
            },
            cache_hot_capacity: cfg.cache_hot_capacity,
            freeze_cache_domains: cfg.freeze_cache_domains.clone(),
            adaptive_cache_enabled: cfg.adaptive_cache_enabled,
            adaptive_cache_min_capacity: cfg.adaptive_cache_min_capacity,
            adaptive_cache_max_capacity: cfg.adaptive_cache_max_capacity,
            adaptive_cache_step: cfg.adaptive_cache_step,
            adaptive_cache_window_secs: cfg.adaptive_cache_window_secs,
            adaptive_cache_high_miss_ratio: cfg.adaptive_cache_high_miss_ratio,
            adaptive_cache_low_miss_ratio: cfg.adaptive_cache_low_miss_ratio,
            stats_window_secs: cfg.stats_window_secs,
            stats_short_window_secs: cfg.stats_short_window_secs,
            topn_stats_enabled: cfg.topn_stats_enabled,
            upstream_timeout_ms: cfg.upstream_timeout_ms,
            upstream_retries: cfg.upstream_retries,
            unhealthy_backoff_ms: cfg.unhealthy_backoff_ms,
            upstream_score_rtt_weight: cfg.upstream_score_rtt_weight,
            upstream_score_failure_weight: cfg.upstream_score_failure_weight,
            upstream_score_success_weight: cfg.upstream_score_success_weight,
            dnssec_enabled: cfg.dnssec.enabled,
            dnssec_use_builtin_trust_anchors: cfg.dnssec.use_builtin_trust_anchors,
            dnssec_trust_anchor_files: cfg.dnssec.trust_anchor_files.clone(),
            health_check_enabled: cfg.health_check.enabled,
            health_check_mode: cfg.health_check.mode.clone(),
            health_check_port: cfg.health_check.port,
            health_check_http_path: cfg.health_check.http_path.clone(),
            health_check_http_host_header: cfg.health_check.http_host_header.clone(),
            health_check_interval_secs: cfg.health_check.interval_secs,
            health_check_timeout_ms: cfg.health_check.timeout_ms,
            health_check_max_parallel: cfg.health_check.max_parallel,
            health_check_failure_threshold: cfg.health_check.failure_threshold,
            health_check_success_threshold: cfg.health_check.success_threshold,
            health_check_all_unhealthy_log_file: cfg.health_check.all_unhealthy_log_file.clone(),
            health_check_notify_webhook: cfg.health_check.notify_webhook.clone(),
            health_check_probe_tls_insecure_skip_verify: cfg
                .health_check
                .probe_tls_insecure_skip_verify,
            health_check_webhook_tls_insecure_skip_verify: cfg
                .health_check
                .webhook_tls_insecure_skip_verify,
            health_check_notify_webhook_retries: cfg.health_check.notify_webhook_retries,
            health_check_notify_webhook_backoff_ms: cfg.health_check.notify_webhook_backoff_ms,
            authoritative_sources: cfg.authoritative_sources.clone(),
            prewarm_delegation_zones: cfg
                .prewarm_delegation_zones
                .iter()
                .map(|item| PrewarmDelegationZoneSectionItem {
                    zone: item.zone.clone(),
                    ns_endpoints: item.ns_endpoints.clone(),
                    ns_hostnames: item.ns_hostnames.clone(),
                    ttl_secs: item.ttl_secs,
                })
                .collect(),
        },
    }
}

fn string_array(values: &[String]) -> toml::Value {
    toml::Value::Array(
        values
            .iter()
            .map(|v| toml::Value::String(v.clone()))
            .collect(),
    )
}

fn default_view_data_dir_relative() -> String {
    "config/default".to_string()
}

fn default_view_static_records_file_relative() -> String {
    format!("{}/static_records.toml", default_view_data_dir_relative())
}

fn default_view_blocked_domains_file_relative() -> String {
    format!("{}/blocked_domains.toml", default_view_data_dir_relative())
}

fn update_config_sections_in_raw(
    raw: &str,
    sections: &ConfigSectionsPayload,
) -> anyhow::Result<String> {
    let mut table = load_toml_root_table(raw)?;

    table.insert(
        "udp_listen".to_string(),
        toml::Value::String(sections.basic.udp_listen.clone()),
    );
    table.insert(
        "tcp_listen".to_string(),
        toml::Value::String(sections.basic.tcp_listen.clone()),
    );
    table.insert(
        "admin_listen".to_string(),
        toml::Value::String(sections.basic.admin_listen.clone()),
    );
    table.insert(
        "control_listen".to_string(),
        toml::Value::String(sections.basic.control_listen.clone()),
    );
    table.insert(
        "control_token".to_string(),
        sections
            .basic
            .control_token
            .as_ref()
            .map(|v| toml::Value::String(v.clone()))
            .unwrap_or(toml::Value::String(String::new())),
    );

    table.insert(
        "resolve_mode".to_string(),
        toml::Value::String(sections.resolver.resolve_mode.clone()),
    );
    table.insert(
        "upstreams".to_string(),
        string_array(&sections.resolver.upstreams),
    );
    table.insert(
        "root_servers".to_string(),
        string_array(&sections.resolver.root_servers),
    );
    table.insert(
        "iterative_max_depth".to_string(),
        toml::Value::Integer(i64::from(sections.resolver.iterative_max_depth)),
    );
    table.insert(
        "iterative_timeout_ms".to_string(),
        toml::Value::Integer(sections.resolver.iterative_timeout_ms as i64),
    );
    table.insert(
        "iterative_fallback_to_forwarder".to_string(),
        toml::Value::Boolean(sections.resolver.iterative_fallback_to_forwarder),
    );

    table.insert(
        "response_cache_capacity".to_string(),
        toml::Value::Integer(sections.cache.response_cache_capacity as i64),
    );
    table.insert(
        "cache_ttl_secs".to_string(),
        toml::Value::Integer(sections.cache.cache_ttl_secs as i64),
    );
    table.insert(
        "freeze_cache_ttl_decay".to_string(),
        toml::Value::Boolean(sections.cache.freeze_cache_ttl_decay),
    );
    table.insert(
        "prefetch_budget_per_window".to_string(),
        toml::Value::Integer(sections.cache.prefetch_budget_per_window as i64),
    );
    table.insert(
        "prefetch_window_secs".to_string(),
        toml::Value::Integer(sections.cache.prefetch_window_secs as i64),
    );
    table.insert(
        "prefetch_ttl_trigger_secs".to_string(),
        toml::Value::Integer(sections.cache.prefetch_ttl_trigger_secs as i64),
    );
    table.insert(
        "prefetch_popularity_threshold".to_string(),
        toml::Value::Integer(sections.cache.prefetch_popularity_threshold as i64),
    );

    let mut dot_table = Table::new();
    dot_table.insert(
        "enabled".to_string(),
        toml::Value::Boolean(sections.transport.dot_enabled),
    );
    dot_table.insert(
        "listen".to_string(),
        toml::Value::String(sections.transport.dot_listen.clone()),
    );
    dot_table.insert(
        "cert_file".to_string(),
        toml::Value::String(sections.transport.dot_cert_file.clone()),
    );
    dot_table.insert(
        "key_file".to_string(),
        toml::Value::String(sections.transport.dot_key_file.clone()),
    );
    table.insert("dot".to_string(), toml::Value::Table(dot_table));

    let mut doh_table = Table::new();
    doh_table.insert(
        "enabled".to_string(),
        toml::Value::Boolean(sections.transport.doh_enabled),
    );
    doh_table.insert(
        "listen".to_string(),
        toml::Value::String(sections.transport.doh_listen.clone()),
    );
    table.insert("doh".to_string(), toml::Value::Table(doh_table));

    let mut logging_table = Table::new();
    logging_table.insert(
        "enabled".to_string(),
        toml::Value::Boolean(sections.logging.enabled),
    );
    logging_table.insert(
        "console".to_string(),
        toml::Value::Boolean(sections.logging.console),
    );
    logging_table.insert(
        "directory".to_string(),
        toml::Value::String(sections.logging.directory.clone()),
    );
    logging_table.insert(
        "rotation".to_string(),
        toml::Value::String(sections.logging.rotation.clone()),
    );
    logging_table.insert(
        "format".to_string(),
        toml::Value::String(sections.logging.format.clone()),
    );
    logging_table.insert(
        "query_level".to_string(),
        toml::Value::String(sections.logging.query_level.clone()),
    );
    logging_table.insert(
        "response_level".to_string(),
        toml::Value::String(sections.logging.response_level.clone()),
    );
    logging_table.insert(
        "general_level".to_string(),
        toml::Value::String(sections.logging.general_level.clone()),
    );
    logging_table.insert(
        "trace_query_domains".to_string(),
        string_array(&sections.logging.trace_query_domains),
    );
    table.insert("logging".to_string(), toml::Value::Table(logging_table));

    table.insert(
        "static_records_file".to_string(),
        toml::Value::String(default_view_static_records_file_relative()),
    );
    table.insert("static_records".to_string(), toml::Value::Array(Vec::new()));

    table.insert(
        "allow_clients".to_string(),
        string_array(&sections.security.allow_clients),
    );
    table.insert(
        "blocked_domains_file".to_string(),
        toml::Value::String(default_view_blocked_domains_file_relative()),
    );
    table.insert(
        "blocked_domains".to_string(),
        toml::Value::Array(Vec::new()),
    );
    table.insert(
        "rate_limit_per_second".to_string(),
        toml::Value::Integer(sections.security.rate_limit_per_second as i64),
    );
    table.insert(
        "deny_any_queries".to_string(),
        toml::Value::Boolean(sections.security.deny_any_queries),
    );

    table.insert(
        "enable_recursion".to_string(),
        toml::Value::Boolean(sections.advanced.enable_recursion),
    );
    table.insert(
        "minimal_response".to_string(),
        toml::Value::Boolean(sections.advanced.minimal_response),
    );
    table.insert(
        "iterative_address_family".to_string(),
        toml::Value::String(sections.advanced.iterative_address_family.clone()),
    );
    table.insert(
        "cname_chain_max_depth".to_string(),
        toml::Value::Integer(i64::from(sections.advanced.cname_chain_max_depth)),
    );
    table.insert(
        "follow_cname_chain".to_string(),
        toml::Value::Boolean(sections.advanced.follow_cname_chain),
    );
    table.insert(
        "static_cname_expand_for_address_queries".to_string(),
        toml::Value::Boolean(sections.advanced.static_cname_expand_for_address_queries),
    );
    table.insert(
        "iterative_cname_bridge_fallback_to_recursive".to_string(),
        toml::Value::Boolean(
            sections
                .advanced
                .iterative_cname_bridge_fallback_to_recursive,
        ),
    );
    table.insert(
        "iterative_per_hop_timeout_ms".to_string(),
        toml::Value::Integer(sections.advanced.iterative_per_hop_timeout_ms as i64),
    );
    table.insert(
        "ns_host_cache_capacity".to_string(),
        toml::Value::Integer(sections.advanced.ns_host_cache_capacity as i64),
    );
    table.insert(
        "ns_host_cache_ttl_secs".to_string(),
        toml::Value::Integer(sections.advanced.ns_host_cache_ttl_secs as i64),
    );
    table.insert(
        "ns_host_cache_cleanup_interval_ms".to_string(),
        toml::Value::Integer(sections.advanced.ns_host_cache_cleanup_interval_ms as i64),
    );
    table.insert(
        "enable_delegation_cache".to_string(),
        toml::Value::Boolean(sections.advanced.enable_delegation_cache),
    );
    table.insert(
        "strict_bailiwick".to_string(),
        toml::Value::Boolean(sections.advanced.strict_bailiwick),
    );
    table.insert(
        "delegation_cache_capacity".to_string(),
        toml::Value::Integer(sections.advanced.delegation_cache_capacity as i64),
    );
    table.insert(
        "delegation_cache_ttl_cap_secs".to_string(),
        toml::Value::Integer(sections.advanced.delegation_cache_ttl_cap_secs as i64),
    );
    table.insert(
        "delegation_cache_cleanup_interval_ms".to_string(),
        toml::Value::Integer(sections.advanced.delegation_cache_cleanup_interval_ms as i64),
    );
    table.insert(
        "delegation_failure_backoff_ms".to_string(),
        toml::Value::Integer(sections.advanced.delegation_failure_backoff_ms as i64),
    );
    table.insert(
        "ns_hostname_max_concurrent".to_string(),
        toml::Value::Integer(sections.advanced.ns_hostname_max_concurrent as i64),
    );
    table.insert(
        "ns_hostname_enough_endpoints".to_string(),
        toml::Value::Integer(sections.advanced.ns_hostname_enough_endpoints as i64),
    );
    table.insert(
        "ns_hostname_per_resolve_ms".to_string(),
        toml::Value::Integer(sections.advanced.ns_hostname_per_resolve_ms as i64),
    );
    table.insert(
        "ns_hostname_resolve_mode".to_string(),
        toml::Value::String(sections.advanced.ns_hostname_resolve_mode.clone()),
    );
    table.insert(
        "cache_hot_capacity".to_string(),
        toml::Value::Integer(sections.advanced.cache_hot_capacity as i64),
    );
    table.insert(
        "freeze_cache_domains".to_string(),
        string_array(&sections.advanced.freeze_cache_domains),
    );
    table.insert(
        "adaptive_cache_enabled".to_string(),
        toml::Value::Boolean(sections.advanced.adaptive_cache_enabled),
    );
    table.insert(
        "adaptive_cache_min_capacity".to_string(),
        toml::Value::Integer(sections.advanced.adaptive_cache_min_capacity as i64),
    );
    table.insert(
        "adaptive_cache_max_capacity".to_string(),
        toml::Value::Integer(sections.advanced.adaptive_cache_max_capacity as i64),
    );
    table.insert(
        "adaptive_cache_step".to_string(),
        toml::Value::Integer(sections.advanced.adaptive_cache_step as i64),
    );
    table.insert(
        "adaptive_cache_window_secs".to_string(),
        toml::Value::Integer(sections.advanced.adaptive_cache_window_secs as i64),
    );
    table.insert(
        "adaptive_cache_high_miss_ratio".to_string(),
        toml::Value::Float(sections.advanced.adaptive_cache_high_miss_ratio),
    );
    table.insert(
        "adaptive_cache_low_miss_ratio".to_string(),
        toml::Value::Float(sections.advanced.adaptive_cache_low_miss_ratio),
    );
    table.insert(
        "stats_window_secs".to_string(),
        toml::Value::Integer(sections.advanced.stats_window_secs as i64),
    );
    table.insert(
        "stats_short_window_secs".to_string(),
        toml::Value::Integer(sections.advanced.stats_short_window_secs as i64),
    );
    table.insert(
        "topn_stats_enabled".to_string(),
        toml::Value::Boolean(sections.advanced.topn_stats_enabled),
    );
    table.insert(
        "upstream_timeout_ms".to_string(),
        toml::Value::Integer(sections.advanced.upstream_timeout_ms as i64),
    );
    table.insert(
        "upstream_retries".to_string(),
        toml::Value::Integer(i64::from(sections.advanced.upstream_retries)),
    );
    table.insert(
        "unhealthy_backoff_ms".to_string(),
        toml::Value::Integer(sections.advanced.unhealthy_backoff_ms as i64),
    );
    table.insert(
        "upstream_score_rtt_weight".to_string(),
        toml::Value::Float(sections.advanced.upstream_score_rtt_weight),
    );
    table.insert(
        "upstream_score_failure_weight".to_string(),
        toml::Value::Float(sections.advanced.upstream_score_failure_weight),
    );
    table.insert(
        "upstream_score_success_weight".to_string(),
        toml::Value::Float(sections.advanced.upstream_score_success_weight),
    );

    let mut dnssec_table = Table::new();
    dnssec_table.insert(
        "enabled".to_string(),
        toml::Value::Boolean(sections.advanced.dnssec_enabled),
    );
    dnssec_table.insert(
        "use_builtin_trust_anchors".to_string(),
        toml::Value::Boolean(sections.advanced.dnssec_use_builtin_trust_anchors),
    );
    dnssec_table.insert(
        "trust_anchor_files".to_string(),
        string_array(&sections.advanced.dnssec_trust_anchor_files),
    );
    table.insert("dnssec".to_string(), toml::Value::Table(dnssec_table));

    let mut health_check_table = Table::new();
    health_check_table.insert(
        "enabled".to_string(),
        toml::Value::Boolean(sections.advanced.health_check_enabled),
    );
    health_check_table.insert(
        "mode".to_string(),
        toml::Value::String(sections.advanced.health_check_mode.clone()),
    );
    health_check_table.insert(
        "port".to_string(),
        toml::Value::Integer(i64::from(sections.advanced.health_check_port)),
    );
    health_check_table.insert(
        "http_path".to_string(),
        toml::Value::String(sections.advanced.health_check_http_path.clone()),
    );
    if let Some(http_host_header) = sections
        .advanced
        .health_check_http_host_header
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    {
        health_check_table.insert(
            "http_host_header".to_string(),
            toml::Value::String(http_host_header.to_string()),
        );
    } else {
        health_check_table.remove("http_host_header");
    }
    health_check_table.insert(
        "interval_secs".to_string(),
        toml::Value::Integer(sections.advanced.health_check_interval_secs as i64),
    );
    health_check_table.insert(
        "timeout_ms".to_string(),
        toml::Value::Integer(sections.advanced.health_check_timeout_ms as i64),
    );
    health_check_table.insert(
        "max_parallel".to_string(),
        toml::Value::Integer(sections.advanced.health_check_max_parallel as i64),
    );
    health_check_table.insert(
        "failure_threshold".to_string(),
        toml::Value::Integer(sections.advanced.health_check_failure_threshold as i64),
    );
    health_check_table.insert(
        "success_threshold".to_string(),
        toml::Value::Integer(sections.advanced.health_check_success_threshold as i64),
    );
    health_check_table.insert(
        "all_unhealthy_log_file".to_string(),
        toml::Value::String(
            sections
                .advanced
                .health_check_all_unhealthy_log_file
                .clone(),
        ),
    );
    if let Some(notify_webhook) = sections
        .advanced
        .health_check_notify_webhook
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    {
        health_check_table.insert(
            "notify_webhook".to_string(),
            toml::Value::String(notify_webhook.to_string()),
        );
    } else {
        health_check_table.remove("notify_webhook");
    }
    health_check_table.insert(
        "probe_tls_insecure_skip_verify".to_string(),
        toml::Value::Boolean(
            sections
                .advanced
                .health_check_probe_tls_insecure_skip_verify,
        ),
    );
    health_check_table.insert(
        "webhook_tls_insecure_skip_verify".to_string(),
        toml::Value::Boolean(
            sections
                .advanced
                .health_check_webhook_tls_insecure_skip_verify,
        ),
    );
    health_check_table.insert(
        "notify_webhook_retries".to_string(),
        toml::Value::Integer(sections.advanced.health_check_notify_webhook_retries as i64),
    );
    health_check_table.insert(
        "notify_webhook_backoff_ms".to_string(),
        toml::Value::Integer(sections.advanced.health_check_notify_webhook_backoff_ms as i64),
    );
    table.insert(
        "health_check".to_string(),
        toml::Value::Table(health_check_table),
    );

    table.insert(
        "authoritative_sources".to_string(),
        toml::Value::try_from(sections.advanced.authoritative_sources.clone())?,
    );
    table.insert(
        "prewarm_delegation_zones".to_string(),
        toml::Value::try_from(sections.advanced.prewarm_delegation_zones.clone())?,
    );

    toml::to_string_pretty(&toml::Value::Table(table)).map_err(Into::into)
}

fn build_effective_views(cfg: &AppConfig) -> Vec<DnsView> {
    let global_static_records = cfg.static_records.clone();

    let default_view_template = DnsView {
        name: "default".to_string(),
        summary: None,
        client_cidrs: Vec::new(),
        static_records_file: None,
        static_records: global_static_records.clone(),
        authoritative_records: Vec::new(),
        records: Vec::new(),
        blocked_domains_file: None,
        blocked_domains: Vec::new(),
        authoritative_zones_file: None,
        authoritative_zones_dir: None,
        authoritative_zones: Vec::new(),
        query_mode: ViewQueryMode::GlobalFallback,
        enable_recursion: true,
        view_static_cname_expand_for_address_queries: None,
        view_authoritative_cname_expand_for_address_queries: None,
    };

    let mut views = cfg.views.clone();
    if views.is_empty() {
        return vec![default_view_template];
    }

    if let Some(default_view) = views
        .iter_mut()
        .find(|view| view.name.eq_ignore_ascii_case("default"))
    {
        if default_view.static_records.is_empty() {
            default_view.static_records = global_static_records;
        }
    } else {
        views.insert(0, default_view_template);
    }

    views
}

fn resolve_relative_config_path(config_path: &str, target: &str) -> PathBuf {
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        return target_path.to_path_buf();
    }

    // Keep project-relative paths like "config/examples/..." unchanged when
    // they already resolve from current working directory.
    if target_path.exists() {
        return target_path.to_path_buf();
    }

    let base_dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let candidate = base_dir.join(target_path);
    if candidate.exists() {
        return candidate;
    }

    candidate
}

fn parse_zone_soa_payload(soa_payload: &serde_json::Value) -> anyhow::Result<ZoneSoa> {
    let soa_obj = soa_payload
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("soa payload must be a JSON object"))?;

    let read_string = |key: &str| -> anyhow::Result<String> {
        soa_obj
            .get(key)
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .ok_or_else(|| anyhow::anyhow!("soa payload missing field: {}", key))
    };
    let read_u32 = |key: &str| -> anyhow::Result<u32> {
        let value = soa_obj
            .get(key)
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
            })
            .ok_or_else(|| anyhow::anyhow!("soa payload missing field: {}", key))?;
        u32::try_from(value).map_err(|_| anyhow::anyhow!("soa payload field out of range: {}", key))
    };

    Ok(ZoneSoa {
        mname: read_string("mname")?,
        rname: read_string("rname")?,
        serial: read_u32("serial")?,
        refresh: read_u32("refresh")?,
        retry: read_u32("retry")?,
        expire: read_u32("expire")?,
        minimum_ttl: read_u32("minimum_ttl")?,
    })
}

fn delete_zone_from_list(zones: &mut Vec<AuthoritativeZone>, zone_name: &str) -> bool {
    let before = zones.len();
    zones.retain(|zone| !zone.name.eq_ignore_ascii_case(zone_name));
    zones.len() != before
}

fn update_zone_soa_in_list(
    zones: &mut [AuthoritativeZone],
    zone_name: &str,
    soa_payload: &serde_json::Value,
) -> anyhow::Result<bool> {
    let soa = parse_zone_soa_payload(soa_payload)?;

    for zone in zones.iter_mut() {
        if zone.name.eq_ignore_ascii_case(zone_name) {
            zone.soa = Some(soa.clone());
            return Ok(true);
        }
    }

    Ok(false)
}

fn delete_authoritative_zone_file_in_raw(
    raw: &str,
    zone_name: &str,
) -> anyhow::Result<(String, bool)> {
    let mut payload: AuthoritativeZoneFilePayload = toml::from_str(raw)?;
    let removed = delete_zone_from_list(&mut payload.zones, zone_name);
    Ok((toml::to_string_pretty(&payload)?, removed))
}

fn update_authoritative_zone_file_soa_in_raw(
    raw: &str,
    zone_name: &str,
    soa_payload: &serde_json::Value,
) -> anyhow::Result<(String, bool)> {
    let mut payload: AuthoritativeZoneFilePayload = toml::from_str(raw)?;
    let updated = update_zone_soa_in_list(&mut payload.zones, zone_name, soa_payload)?;
    Ok((toml::to_string_pretty(&payload)?, updated))
}

fn delete_view_authoritative_zone_in_raw(
    raw: &str,
    view_name: &str,
    zone_name: &str,
) -> anyhow::Result<(String, bool)> {
    let mut table = load_toml_root_table(raw)?;

    if let Some(value) = table.get_mut("views") {
        let views = value
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("views must be an array"))?;

        for view in views.iter_mut() {
            let Some(view_table) = view.as_table_mut() else {
                continue;
            };
            let Some(name) = view_table.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if !name.eq_ignore_ascii_case(view_name) {
                continue;
            }

            let Some(value) = view_table.get_mut("authoritative_zones") else {
                return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false));
            };
            let mut zones: Vec<AuthoritativeZone> = value.clone().try_into().map_err(|_| {
                anyhow::anyhow!("views.{view_name}.authoritative_zones must be an array of zones")
            })?;
            let removed = delete_zone_from_list(&mut zones, zone_name);
            *value = toml::Value::try_from(zones)?;
            return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, removed));
        }
    }

    Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false))
}

fn update_view_authoritative_zone_soa_in_raw(
    raw: &str,
    view_name: &str,
    zone_name: &str,
    soa_payload: &serde_json::Value,
) -> anyhow::Result<(String, bool)> {
    let mut table = load_toml_root_table(raw)?;

    if let Some(value) = table.get_mut("views") {
        let views = value
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("views must be an array"))?;

        for view in views.iter_mut() {
            let Some(view_table) = view.as_table_mut() else {
                continue;
            };
            let Some(name) = view_table.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if !name.eq_ignore_ascii_case(view_name) {
                continue;
            }

            let Some(value) = view_table.get_mut("authoritative_zones") else {
                return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false));
            };
            let mut zones: Vec<AuthoritativeZone> = value.clone().try_into().map_err(|_| {
                anyhow::anyhow!("views.{view_name}.authoritative_zones must be an array of zones")
            })?;
            let updated = update_zone_soa_in_list(&mut zones, zone_name, soa_payload)?;
            if !updated {
                return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false));
            }

            *value = toml::Value::try_from(zones)?;
            return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, true));
        }
    }

    Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false))
}

enum AuthoritativeZoneMutationTarget {
    ViewInline,
    ViewFile(PathBuf),
    ViewDir(PathBuf),
}

fn resolve_authoritative_zone_mutation_target(
    cfg: &AppConfig,
    config_path: &str,
    view_name: &str,
) -> Option<AuthoritativeZoneMutationTarget> {
    if let Some(view) = cfg
        .views
        .iter()
        .find(|view| view.name.eq_ignore_ascii_case(view_name))
    {
        if let Some(zones_dir) = view
            .authoritative_zones_dir
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(AuthoritativeZoneMutationTarget::ViewDir(
                resolve_relative_config_path(config_path, zones_dir),
            ));
        }
        if let Some(zones_file) = view
            .authoritative_zones_file
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(AuthoritativeZoneMutationTarget::ViewFile(
                resolve_relative_config_path(config_path, zones_file),
            ));
        }
        return Some(AuthoritativeZoneMutationTarget::ViewInline);
    }

    None
}

fn upsert_view_in_raw(raw: &str, req: &ViewUpsertRequest) -> anyhow::Result<(String, bool)> {
    let view_name = req.name.trim();
    if view_name.is_empty() {
        return Err(anyhow::anyhow!("view name is required"));
    }
    let lookup_name = req
        .previous_name
        .as_deref()
        .map(str::trim)
        .unwrap_or(view_name);
    if lookup_name.is_empty() {
        return Err(anyhow::anyhow!("previous view name is invalid"));
    }
    let is_target_default = view_name.eq_ignore_ascii_case("default");
    let is_lookup_default = lookup_name.eq_ignore_ascii_case("default");
    if is_target_default != is_lookup_default {
        return Err(anyhow::anyhow!("default view name is immutable"));
    }
    let query_mode = if req.query_mode.trim().is_empty() {
        "global_fallback".to_string()
    } else {
        req.query_mode.trim().to_string()
    };
    let summary = req.summary.as_deref().map(str::trim).unwrap_or("");

    let mut table = load_toml_root_table(raw)?;
    let views_value = table
        .entry("views".to_string())
        .or_insert(toml::Value::Array(toml::value::Array::new()));

    let views = views_value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("views must be an array"))?;

    let mut found = false;
    let mut target_name_taken = false;
    for view in views.iter_mut() {
        let Some(view_table) = view.as_table_mut() else {
            continue;
        };
        let Some(name) = view_table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let normalized_name = name.trim();

        if normalized_name.eq_ignore_ascii_case(view_name)
            && !normalized_name.eq_ignore_ascii_case(lookup_name)
        {
            target_name_taken = true;
        }

        if !normalized_name.eq_ignore_ascii_case(lookup_name) {
            continue;
        }
        found = true;
        view_table.insert(
            "name".to_string(),
            toml::Value::String(view_name.to_string()),
        );
        if summary.is_empty() {
            view_table.remove("summary");
        } else {
            view_table.insert(
                "summary".to_string(),
                toml::Value::String(summary.to_string()),
            );
        }
        view_table.insert(
            "query_mode".to_string(),
            toml::Value::String(query_mode.clone()),
        );
        view_table.insert("client_cidrs".to_string(), string_array(&req.client_cidrs));
        let has_static_records_file = view_table
            .get("static_records_file")
            .and_then(|v| v.as_str())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if has_static_records_file {
            view_table.remove("static_records");
        } else {
            view_table.insert(
                "static_records".to_string(),
                toml::Value::try_from(req.static_records.clone())?,
            );
        }

        let has_blocked_domains_file = view_table
            .get("blocked_domains_file")
            .and_then(|v| v.as_str())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if has_blocked_domains_file {
            view_table.remove("blocked_domains");
        } else {
            view_table.insert(
                "blocked_domains".to_string(),
                string_array(&req.blocked_domains),
            );
        }
        view_table.insert(
            "enable_recursion".to_string(),
            toml::Value::Boolean(req.enable_recursion),
        );
        match req.view_static_cname_expand_for_address_queries {
            Some(value) => {
                view_table.insert(
                    "view_static_cname_expand_for_address_queries".to_string(),
                    toml::Value::Boolean(value),
                );
            }
            None => {}
        }
        match req.view_authoritative_cname_expand_for_address_queries {
            Some(value) => {
                view_table.insert(
                    "view_authoritative_cname_expand_for_address_queries".to_string(),
                    toml::Value::Boolean(value),
                );
            }
            None => {}
        }
        break;
    }

    if target_name_taken {
        return Err(anyhow::anyhow!("view name already exists"));
    }

    if !found {
        if req.previous_name.is_some() {
            return Err(anyhow::anyhow!("previous view name not found"));
        }
        let mut new_view = toml::map::Map::new();
        new_view.insert(
            "name".to_string(),
            toml::Value::String(view_name.to_string()),
        );
        if !summary.is_empty() {
            new_view.insert(
                "summary".to_string(),
                toml::Value::String(summary.to_string()),
            );
        }
        new_view.insert("query_mode".to_string(), toml::Value::String(query_mode));
        new_view.insert("client_cidrs".to_string(), string_array(&req.client_cidrs));
        new_view.insert(
            "static_records".to_string(),
            toml::Value::try_from(req.static_records.clone())?,
        );
        new_view.insert(
            "blocked_domains".to_string(),
            string_array(&req.blocked_domains),
        );
        new_view.insert(
            "enable_recursion".to_string(),
            toml::Value::Boolean(req.enable_recursion),
        );
        if let Some(value) = req.view_static_cname_expand_for_address_queries {
            new_view.insert(
                "view_static_cname_expand_for_address_queries".to_string(),
                toml::Value::Boolean(value),
            );
        }
        if let Some(value) = req.view_authoritative_cname_expand_for_address_queries {
            new_view.insert(
                "view_authoritative_cname_expand_for_address_queries".to_string(),
                toml::Value::Boolean(value),
            );
        }
        views.push(toml::Value::Table(new_view));
    }

    Ok((toml::to_string_pretty(&toml::Value::Table(table))?, true))
}

fn delete_view_in_raw(raw: &str, view_name: &str) -> anyhow::Result<(String, bool)> {
    let view_name = view_name.trim();
    if view_name.is_empty() {
        return Err(anyhow::anyhow!("view name is required"));
    }
    if view_name.eq_ignore_ascii_case("default") {
        return Err(anyhow::anyhow!("default view cannot be deleted"));
    }

    let mut table = load_toml_root_table(raw)?;
    let Some(value) = table.get_mut("views") else {
        return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false));
    };

    let views = value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("views must be an array"))?;

    let initial_len = views.len();
    views.retain(|view| {
        if let Some(view_table) = view.as_table() {
            if let Some(name) = view_table.get("name").and_then(|v| v.as_str()) {
                return !name.trim().eq_ignore_ascii_case(view_name);
            }
        }
        true
    });

    let found = views.len() < initial_len;
    Ok((toml::to_string_pretty(&toml::Value::Table(table))?, found))
}

async fn config_sections_handler(
    State(state): State<AppState>,
) -> Result<Json<ConfigSectionsResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    Ok(Json(ConfigSectionsResponse {
        status: "ok",
        path: state.config_path().to_string(),
        sections: build_config_sections(&cfg),
    }))
}

async fn config_sections_upsert_handler(
    State(state): State<AppState>,
    Json(req): Json<ConfigSectionsUpsertRequest>,
) -> Result<Json<ConfigSectionsApplyResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let new_raw = update_config_sections_in_raw(&old_raw, &req.sections).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_update_config_sections",
            }),
        )
    })?;

    let default_dir = resolve_path_relative_to_config_for_creation(
        state.config_path(),
        &default_view_data_dir_relative(),
    );
    fs::create_dir_all(&default_dir).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_write_default_view_data_files",
            }),
        )
    })?;

    let mut backups: Vec<(PathBuf, Option<String>)> = Vec::new();

    let static_raw = serialize_static_records_file(req.sections.static_data.static_records.clone())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_write_default_static_records_file",
                }),
            )
        })?;
    write_file_with_backup(
        &default_dir.join("static_records.toml"),
        static_raw,
        &mut backups,
    )
    .map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_write_default_static_records_file",
            }),
        )
    })?;

    let blocked_domains = normalize_blocked_domains(&req.sections.security.blocked_domains);
    let blocked_raw = serialize_blocked_domains_file(blocked_domains).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_write_default_blocked_domains_file",
            }),
        )
    })?;
    write_file_with_backup(
        &default_dir.join("blocked_domains.toml"),
        blocked_raw,
        &mut backups,
    )
    .map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_write_default_blocked_domains_file",
            }),
        )
    })?;

    if let Err(_err) = apply_config_raw_and_reload(&state, new_raw) {
        rollback_view_data_files(backups);
        let _ = state.reload_from_disk();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        ));
    }

    Ok(Json(ConfigSectionsApplyResponse {
        status: "ok",
        message: "config sections updated and reloaded".to_string(),
        reloaded: true,
        audit: state.reload_audit_snapshot(),
    }))
}

async fn views_handler(
    State(state): State<AppState>,
) -> Result<Json<ViewsResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    Ok(Json(ViewsResponse {
        status: "ok",
        views: build_effective_views(&cfg),
    }))
}

async fn views_upsert_handler(
    State(state): State<AppState>,
    Json(req): Json<ViewUpsertRequest>,
) -> Result<
    Json<ViewAuthoritativeRecordsMutationResponse>,
    (StatusCode, Json<AdminAuthErrorResponse>),
> {
    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let (new_raw, _) = upsert_view_in_raw(&old_raw, &req).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_upsert_view",
            }),
        )
    })?;

    apply_config_raw_and_reload(&state, new_raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        )
    })?;

    Ok(Json(ViewAuthoritativeRecordsMutationResponse {
        status: "ok",
        message: format!("view upserted: {}", req.name),
        audit: state.reload_audit_snapshot(),
    }))
}

async fn view_delete_handler(
    AxumPath(view_name): AxumPath<String>,
    State(state): State<AppState>,
) -> Result<
    Json<ViewAuthoritativeRecordsMutationResponse>,
    (StatusCode, Json<AdminAuthErrorResponse>),
> {
    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let (new_raw, found) = delete_view_in_raw(&old_raw, &view_name).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_delete_view",
            }),
        )
    })?;

    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "view_not_found",
            }),
        ));
    }

    apply_config_raw_and_reload(&state, new_raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        )
    })?;

    Ok(Json(ViewAuthoritativeRecordsMutationResponse {
        status: "ok",
        message: format!("view deleted: {}", view_name),
        audit: state.reload_audit_snapshot(),
    }))
}

async fn view_authoritative_records_upsert_handler(
    AxumPath(view): AxumPath<String>,
    State(state): State<AppState>,
    Json(req): Json<ViewAuthoritativeRecordsUpsertRequest>,
) -> Result<
    Json<ViewAuthoritativeRecordsMutationResponse>,
    (StatusCode, Json<AdminAuthErrorResponse>),
> {
    view_data_upsert_handler(
        AxumPath(view),
        State(state),
        Json(ViewDataUpsertRequest {
            authoritative_records: Some(req.records),
            static_records: None,
            blocked_domains: None,
            authoritative_zone_name: None,
        }),
    )
    .await
}

fn normalize_blocked_domains(input: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    input
        .iter()
        .map(|v| v.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .filter(|v| seen.insert(v.clone()))
        .collect::<Vec<_>>()
}

fn infer_authoritative_zone_name(records: &[StaticRecord]) -> Option<String> {
    let names = records
        .iter()
        .map(|record| {
            record
                .qname
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if names.is_empty() {
        return None;
    }

    let first = names[0]
        .split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if first.is_empty() {
        return None;
    }

    let mut suffix = first;
    for name in names.iter().skip(1) {
        let labels = name
            .split('.')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if labels.is_empty() {
            return None;
        }

        let mut common = Vec::new();
        let mut i = 0usize;
        while i < suffix.len() && i < labels.len() {
            let lhs = &suffix[suffix.len() - 1 - i];
            let rhs = &labels[labels.len() - 1 - i];
            if lhs != rhs {
                break;
            }
            common.push(lhs.clone());
            i += 1;
        }
        common.reverse();
        suffix = common;
        if suffix.is_empty() {
            return None;
        }
    }

    Some(suffix.join("."))
}

fn build_default_zone_soa(zone_name: &str, ttl: u32) -> ZoneSoa {
    let normalized = zone_name.trim().trim_end_matches('.').to_ascii_lowercase();
    let base = if normalized.is_empty() {
        "local".to_string()
    } else {
        normalized
    };
    ZoneSoa {
        mname: format!("ns1.{base}."),
        rname: format!("hostmaster.{base}."),
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum_ttl: ttl,
    }
}

fn serialize_static_records_file(records: Vec<StaticRecord>) -> anyhow::Result<String> {
    toml::to_string_pretty(&StaticRecordsFileWritePayload {
        static_records: records,
    })
    .map_err(Into::into)
}

fn serialize_blocked_domains_file(blocked_domains: Vec<String>) -> anyhow::Result<String> {
    toml::to_string_pretty(&BlockedDomainsFileWritePayload { blocked_domains }).map_err(Into::into)
}

fn write_file_with_backup(
    path: &Path,
    content: String,
    backups: &mut Vec<(PathBuf, Option<String>)>,
) -> anyhow::Result<()> {
    if !backups.iter().any(|(p, _)| p == path) {
        backups.push((path.to_path_buf(), fs::read_to_string(path).ok()));
    }
    fs::write(path, content)?;
    Ok(())
}

fn ensure_view_support_files(
    view_dir: &Path,
    backups: &mut Vec<(PathBuf, Option<String>)>,
) -> anyhow::Result<()> {
    let static_file = view_dir.join("static_records.toml");
    if !static_file.exists() {
        let raw = serialize_static_records_file(Vec::new())?;
        write_file_with_backup(&static_file, raw, backups)?;
    }

    let blocked_file = view_dir.join("blocked_domains.toml");
    if !blocked_file.exists() {
        let raw = serialize_blocked_domains_file(Vec::new())?;
        write_file_with_backup(&blocked_file, raw, backups)?;
    }

    Ok(())
}

fn rollback_view_data_files(backups: Vec<(PathBuf, Option<String>)>) {
    for (path, old_content) in backups.into_iter().rev() {
        match old_content {
            Some(content) => {
                let _ = fs::write(&path, content);
            }
            None => {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

async fn view_data_upsert_handler(
    AxumPath(view): AxumPath<String>,
    State(state): State<AppState>,
    Json(req): Json<ViewDataUpsertRequest>,
) -> Result<
    Json<ViewAuthoritativeRecordsMutationResponse>,
    (StatusCode, Json<AdminAuthErrorResponse>),
> {
    if req.authoritative_records.is_none()
        && req.static_records.is_none()
        && req.blocked_domains.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "no_view_data_provided",
            }),
        ));
    }

    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let (new_config_raw, found_view) =
        ensure_view_data_paths_in_raw(&old_raw, &view).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_update_view_data_paths",
                }),
            )
        })?;

    if !found_view {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "view_not_found",
            }),
        ));
    }

    let view_dir_relative = view_data_dir_relative(&view);
    let view_dir =
        resolve_path_relative_to_config_for_creation(state.config_path(), &view_dir_relative);
    fs::create_dir_all(&view_dir).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_write_view_data_files",
            }),
        )
    })?;

    let mut backups: Vec<(PathBuf, Option<String>)> = Vec::new();

    ensure_view_support_files(&view_dir, &mut backups).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_write_view_data_files",
            }),
        )
    })?;

    if let Some(static_records) = req.static_records {
        let static_file = view_dir.join("static_records.toml");
        let static_raw = serialize_static_records_file(static_records).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_write_view_static_records_file",
                }),
            )
        })?;
        write_file_with_backup(&static_file, static_raw, &mut backups).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_write_view_static_records_file",
                }),
            )
        })?;
    }

    if let Some(blocked_domains) = req.blocked_domains {
        let blocked_file = view_dir.join("blocked_domains.toml");
        let blocked_domains = normalize_blocked_domains(&blocked_domains);
        let blocked_raw = serialize_blocked_domains_file(blocked_domains).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_write_view_blocked_domains_file",
                }),
            )
        })?;
        write_file_with_backup(&blocked_file, blocked_raw, &mut backups).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_write_view_blocked_domains_file",
                }),
            )
        })?;
    }

    if let Some(authoritative_records) = req.authoritative_records {
        let zone_name = req
            .authoritative_zone_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| infer_authoritative_zone_name(&authoritative_records))
            .unwrap_or_else(|| view.clone());

        let zone_file = zone_file_path_for_upsert(&view_dir, &zone_name);
        let existing_zone = cfg
            .views
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case(&view))
            .and_then(|item| {
                item.authoritative_zones
                    .iter()
                    .find(|zone| is_same_zone_name(&zone.name, &zone_name))
            })
            .cloned();
        let ttl = authoritative_records
            .iter()
            .map(|record| record.ttl)
            .min()
            .unwrap_or_else(|| {
                existing_zone
                    .as_ref()
                    .map(|zone| zone.default_ttl)
                    .unwrap_or(300)
            });
        let soa = existing_zone
            .as_ref()
            .and_then(|zone| zone.soa.clone())
            .or_else(|| Some(build_default_zone_soa(&zone_name, ttl)));

        let zone = AuthoritativeZone {
            name: zone_name,
            default_ttl: ttl,
            soa,
            records: authoritative_records,
        };
        let zone_raw = toml::to_string_pretty(&zone).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_write_view_authoritative_zone_file",
                }),
            )
        })?;
        write_file_with_backup(&zone_file, zone_raw, &mut backups).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_write_view_authoritative_zone_file",
                }),
            )
        })?;
    }

    if let Err(_err) = apply_config_raw_and_reload(&state, new_config_raw) {
        rollback_view_data_files(backups);
        let _ = state.reload_from_disk();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        ));
    }

    Ok(Json(ViewAuthoritativeRecordsMutationResponse {
        status: "ok",
        message: format!("view data updated: {}", view),
        audit: state.reload_audit_snapshot(),
    }))
}

async fn view_static_records_upsert_handler(
    AxumPath(view): AxumPath<String>,
    State(state): State<AppState>,
    Json(req): Json<ViewStaticRecordsUpsertRequest>,
) -> Result<
    Json<ViewAuthoritativeRecordsMutationResponse>,
    (StatusCode, Json<AdminAuthErrorResponse>),
> {
    view_data_upsert_handler(
        AxumPath(view),
        State(state),
        Json(ViewDataUpsertRequest {
            authoritative_records: None,
            static_records: Some(req.records),
            blocked_domains: None,
            authoritative_zone_name: None,
        }),
    )
    .await
}

async fn view_blocked_domains_upsert_handler(
    AxumPath(view): AxumPath<String>,
    State(state): State<AppState>,
    Json(req): Json<ViewBlockedDomainsUpsertRequest>,
) -> Result<
    Json<ViewAuthoritativeRecordsMutationResponse>,
    (StatusCode, Json<AdminAuthErrorResponse>),
> {
    view_data_upsert_handler(
        AxumPath(view),
        State(state),
        Json(ViewDataUpsertRequest {
            authoritative_records: None,
            static_records: None,
            blocked_domains: Some(req.blocked_domains),
            authoritative_zone_name: None,
        }),
    )
    .await
}

async fn view_authoritative_zone_delete_handler(
    AxumPath((view, zone)): AxumPath<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<AuthoritativeZoneMutationResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    let Some(target) = resolve_authoritative_zone_mutation_target(&cfg, state.config_path(), &view)
    else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "view_not_found",
            }),
        ));
    };

    match target {
        AuthoritativeZoneMutationTarget::ViewInline => {
            let old_raw = read_config_raw(&state).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_read_config",
                    }),
                )
            })?;

            let (new_raw, removed) = delete_view_authoritative_zone_in_raw(&old_raw, &view, &zone)
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(AdminAuthErrorResponse {
                            status: "error",
                            message: "failed_to_update_view_authoritative_zones",
                        }),
                    )
                })?;

            if !removed {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "zone_not_found",
                    }),
                ));
            }

            apply_config_raw_and_reload(&state, new_raw).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "invalid_or_unreloadable_config",
                    }),
                )
            })?;
        }
        AuthoritativeZoneMutationTarget::ViewFile(path) => {
            let old_raw = fs::read_to_string(&path).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_read_authoritative_zones_file",
                    }),
                )
            })?;

            let (new_raw, removed) = delete_authoritative_zone_file_in_raw(&old_raw, &zone)
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(AdminAuthErrorResponse {
                            status: "error",
                            message: "failed_to_update_authoritative_zones_file",
                        }),
                    )
                })?;

            if !removed {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "zone_not_found",
                    }),
                ));
            }

            apply_external_raw_and_reload(&state, &path, new_raw).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "invalid_or_unreloadable_config",
                    }),
                )
            })?;
        }
        AuthoritativeZoneMutationTarget::ViewDir(path) => {
            let file_path = find_zone_file_in_dir(&path, &zone)
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(AdminAuthErrorResponse {
                            status: "error",
                            message: "failed_to_update_authoritative_zones_dir",
                        }),
                    )
                })?
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        Json(AdminAuthErrorResponse {
                            status: "error",
                            message: "zone_not_found",
                        }),
                    )
                })?;

            apply_external_delete_and_reload(&state, &file_path).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "invalid_or_unreloadable_config",
                    }),
                )
            })?;
        }
    }

    Ok(Json(AuthoritativeZoneMutationResponse {
        status: "ok",
        message: format!("view authoritative zone deleted: {}/{}", view, zone),
        audit: state.reload_audit_snapshot(),
    }))
}

fn zone_file_path_for_upsert(dir_path: &Path, zone_name: &str) -> PathBuf {
    let stem = zone_name.trim().trim_end_matches('.').to_ascii_lowercase();
    let file_name = if stem.is_empty() {
        "zone.toml".to_string()
    } else {
        format!("{}.toml", stem)
    };
    dir_path.join(file_name)
}

fn sanitize_view_name_for_dir(view_name: &str) -> String {
    let sanitized = view_name
        .trim()
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect::<String>();

    if sanitized.is_empty() {
        "default".to_string()
    } else {
        sanitized
    }
}

fn view_data_dir_relative(view_name: &str) -> String {
    format!("config/{}", sanitize_view_name_for_dir(view_name))
}

fn view_static_records_file_relative(view_name: &str) -> String {
    format!("{}/static_records.toml", view_data_dir_relative(view_name))
}

fn view_blocked_domains_file_relative(view_name: &str) -> String {
    format!("{}/blocked_domains.toml", view_data_dir_relative(view_name))
}

fn resolve_path_relative_to_config_for_creation(config_path: &str, target: &str) -> PathBuf {
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        return target_path.to_path_buf();
    }

    let config_dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));

    if let Some(config_dir_name) = config_dir.file_name() {
        if let Ok(stripped) = target_path.strip_prefix(config_dir_name) {
            if !stripped.as_os_str().is_empty() {
                return config_dir.join(stripped);
            }
        }
    }

    config_dir.join(target_path)
}

fn ensure_view_data_paths_in_raw(raw: &str, view_name: &str) -> anyhow::Result<(String, bool)> {
    let mut table = load_toml_root_table(raw)?;
    let zones_dir = view_data_dir_relative(view_name);
    let static_records_file = view_static_records_file_relative(view_name);
    let blocked_domains_file = view_blocked_domains_file_relative(view_name);

    if let Some(value) = table.get_mut("views") {
        let views = value
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("views must be an array"))?;

        // Try to find existing view with matching name
        for view in views.iter_mut() {
            let Some(view_table) = view.as_table_mut() else {
                continue;
            };
            let Some(name) = view_table.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if !name.eq_ignore_ascii_case(view_name) {
                continue;
            }

            // Only set data path fields; never clear existing inline data arrays.
            // Inline data migration should be explicit, not automatic.
            view_table.insert(
                "authoritative_zones_dir".to_string(),
                toml::Value::String(zones_dir.to_string()),
            );
            view_table.insert(
                "static_records_file".to_string(),
                toml::Value::String(static_records_file),
            );
            view_table.insert(
                "blocked_domains_file".to_string(),
                toml::Value::String(blocked_domains_file),
            );
            return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, true));
        }
    } else {
        // Create views array if it doesn't exist
        table.insert("views".to_string(), toml::Value::Array(Vec::new()));
    }

    // View not found, create a new default view with data paths configured
    let mut new_view_table = toml::Table::new();
    new_view_table.insert(
        "name".to_string(),
        toml::Value::String(view_name.to_string()),
    );
    new_view_table.insert(
        "authoritative_zones_dir".to_string(),
        toml::Value::String(zones_dir),
    );
    new_view_table.insert(
        "static_records_file".to_string(),
        toml::Value::String(static_records_file),
    );
    new_view_table.insert(
        "blocked_domains_file".to_string(),
        toml::Value::String(blocked_domains_file),
    );
    new_view_table.insert("client_cidrs".to_string(), toml::Value::Array(Vec::new()));
    new_view_table.insert(
        "query_mode".to_string(),
        toml::Value::String("global_fallback".to_string()),
    );
    new_view_table.insert("enable_recursion".to_string(), toml::Value::Boolean(true));

    if let Some(value) = table.get_mut("views") {
        if let Some(views) = value.as_array_mut() {
            views.push(toml::Value::Table(new_view_table));
        }
    }

    Ok((toml::to_string_pretty(&toml::Value::Table(table))?, true))
}

async fn view_authoritative_zone_upsert_handler(
    AxumPath(view): AxumPath<String>,
    State(state): State<AppState>,
    Json(req): Json<AuthoritativeZoneUpsertRequest>,
) -> Result<Json<AuthoritativeZoneMutationResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    if req.zone.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "zone_name_required",
            }),
        ));
    }

    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let desired_view_dir = view_data_dir_relative(&view);
    let (new_config_raw, found_view) =
        ensure_view_data_paths_in_raw(&old_raw, &view).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_update_view_authoritative_zones",
                }),
            )
        })?;

    if !found_view {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "view_not_found",
            }),
        ));
    }

    let dir_path =
        resolve_path_relative_to_config_for_creation(state.config_path(), &desired_view_dir);
    fs::create_dir_all(&dir_path).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_update_authoritative_zones_dir",
            }),
        )
    })?;

    let file_path = find_zone_file_in_dir(&dir_path, &req.zone.name)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_update_authoritative_zones_dir",
                }),
            )
        })?
        .unwrap_or_else(|| zone_file_path_for_upsert(&dir_path, &req.zone.name));

    let mut support_backups: Vec<(PathBuf, Option<String>)> = Vec::new();
    ensure_view_support_files(&dir_path, &mut support_backups).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_update_authoritative_zones_dir",
            }),
        )
    })?;

    let old_zone_raw = fs::read_to_string(&file_path).ok();
    let new_zone_raw = toml::to_string_pretty(&req.zone).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_update_authoritative_zones_dir",
            }),
        )
    })?;

    fs::write(&file_path, &new_zone_raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_update_authoritative_zones_dir",
            }),
        )
    })?;

    if let Err(_err) = apply_config_raw_and_reload(&state, new_config_raw) {
        rollback_view_data_files(support_backups);
        if let Some(raw) = old_zone_raw {
            let _ = fs::write(&file_path, raw);
        } else {
            let _ = fs::remove_file(&file_path);
        }
        let _ = state.reload_from_disk();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        ));
    }

    Ok(Json(AuthoritativeZoneMutationResponse {
        status: "ok",
        message: format!(
            "view authoritative zone upserted: {}/{}",
            view, req.zone.name
        ),
        audit: state.reload_audit_snapshot(),
    }))
}

async fn view_authoritative_zone_soa_patch_handler(
    AxumPath((view, zone)): AxumPath<(String, String)>,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthoritativeZoneMutationResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let soa_payload = serde_json::from_str(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_json_payload",
            }),
        )
    })?;

    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    let Some(target) = resolve_authoritative_zone_mutation_target(&cfg, state.config_path(), &view)
    else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "view_not_found",
            }),
        ));
    };

    match target {
        AuthoritativeZoneMutationTarget::ViewInline => {
            let old_raw = read_config_raw(&state).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_read_config",
                    }),
                )
            })?;

            let (new_raw, updated) =
                update_view_authoritative_zone_soa_in_raw(&old_raw, &view, &zone, &soa_payload)
                    .map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(AdminAuthErrorResponse {
                                status: "error",
                                message: "failed_to_update_view_authoritative_zones",
                            }),
                        )
                    })?;

            if !updated {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "zone_not_found",
                    }),
                ));
            }

            apply_config_raw_and_reload(&state, new_raw).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "invalid_or_unreloadable_config",
                    }),
                )
            })?;
        }
        AuthoritativeZoneMutationTarget::ViewFile(path) => {
            let old_raw = fs::read_to_string(&path).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_read_authoritative_zones_file",
                    }),
                )
            })?;

            let (new_raw, updated) =
                update_authoritative_zone_file_soa_in_raw(&old_raw, &zone, &soa_payload).map_err(
                    |_| {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(AdminAuthErrorResponse {
                                status: "error",
                                message: "failed_to_update_authoritative_zones_file",
                            }),
                        )
                    },
                )?;

            if !updated {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "zone_not_found",
                    }),
                ));
            }

            apply_external_raw_and_reload(&state, &path, new_raw).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "invalid_or_unreloadable_config",
                    }),
                )
            })?;
        }
        AuthoritativeZoneMutationTarget::ViewDir(path) => {
            let updated = update_authoritative_zone_soa_in_dir(&path, &zone, &soa_payload)
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(AdminAuthErrorResponse {
                            status: "error",
                            message: "failed_to_update_authoritative_zones_dir",
                        }),
                    )
                })?;

            if !updated {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "zone_not_found",
                    }),
                ));
            }

            state.reload_from_disk().map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "invalid_or_unreloadable_config",
                    }),
                )
            })?;
        }
    }

    Ok(Json(AuthoritativeZoneMutationResponse {
        status: "ok",
        message: format!("view authoritative zone SOA updated: {}/{}", view, zone),
        audit: state.reload_audit_snapshot(),
    }))
}

fn parse_and_validate_config(raw: &str) -> anyhow::Result<()> {
    let cfg: AppConfig = toml::from_str(raw)?;
    cfg.validate()?;
    Ok(())
}

fn read_config_raw(state: &AppState) -> anyhow::Result<String> {
    fs::read_to_string(state.config_path()).map_err(Into::into)
}

fn apply_config_raw_and_reload(state: &AppState, raw: String) -> anyhow::Result<()> {
    parse_and_validate_config(&raw)?;

    let config_path = state.config_path();
    let old_raw = fs::read_to_string(config_path)?;
    fs::write(config_path, &raw)?;

    if let Err(err) = state.reload_from_disk() {
        let _ = fs::write(config_path, old_raw);
        let _ = state.reload_from_disk();
        return Err(err);
    }

    Ok(())
}

fn apply_external_raw_and_reload(state: &AppState, path: &Path, raw: String) -> anyhow::Result<()> {
    let old_raw = fs::read_to_string(path)?;
    fs::write(path, &raw)?;

    if let Err(err) = state.reload_from_disk() {
        let _ = fs::write(path, old_raw);
        let _ = state.reload_from_disk();
        return Err(err);
    }

    Ok(())
}

fn apply_external_delete_and_reload(state: &AppState, path: &Path) -> anyhow::Result<()> {
    let old_raw = fs::read_to_string(path)?;
    fs::remove_file(path)?;

    if let Err(err) = state.reload_from_disk() {
        let _ = fs::write(path, old_raw);
        let _ = state.reload_from_disk();
        return Err(err);
    }

    Ok(())
}

fn is_same_zone_name(lhs: &str, rhs: &str) -> bool {
    lhs.trim_end_matches('.')
        .eq_ignore_ascii_case(rhs.trim_end_matches('.'))
}

fn find_zone_file_in_dir(dir_path: &Path, zone_name: &str) -> anyhow::Result<Option<PathBuf>> {
    if !dir_path.exists() {
        return Ok(None);
    }
    if !dir_path.is_dir() {
        return Err(anyhow::anyhow!(
            "authoritative_zones_dir is not a directory: {}",
            dir_path.display()
        ));
    }

    let entries = fs::read_dir(dir_path)?;
    for entry in entries {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }

        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if is_same_zone_name(stem, zone_name) {
            return Ok(Some(path));
        }
    }

    Ok(None)
}

fn update_authoritative_zone_soa_in_dir(
    dir_path: &Path,
    zone_name: &str,
    soa_payload: &serde_json::Value,
) -> anyhow::Result<bool> {
    let Some(path) = find_zone_file_in_dir(dir_path, zone_name)? else {
        return Ok(false);
    };

    let old_raw = fs::read_to_string(&path)?;
    let mut zone: AuthoritativeZone = toml::from_str(&old_raw)?;
    zone.soa = Some(parse_zone_soa_payload(soa_payload)?);
    let new_raw = toml::to_string_pretty(&zone)?;
    fs::write(path, new_raw)?;
    Ok(true)
}

fn load_toml_root_table(raw: &str) -> anyhow::Result<Table> {
    let value: toml::Value = toml::from_str(raw)?;
    let table = value
        .as_table()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    Ok(table)
}

fn upsert_authoritative_zone_in_raw(raw: &str, zone: &AuthoritativeZone) -> anyhow::Result<String> {
    let mut table = load_toml_root_table(raw)?;

    let zones_entry = table
        .entry("authoritative_zones".to_string())
        .or_insert_with(|| toml::Value::Array(Vec::new()));

    let zones_array = zones_entry
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("authoritative_zones must be an array"))?;

    let zone_value = toml::Value::try_from(zone.clone())?;
    let mut replaced = false;

    for item in zones_array.iter_mut() {
        let same = item
            .as_table()
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .map(|name| name.eq_ignore_ascii_case(&zone.name))
            .unwrap_or(false);
        if same {
            *item = zone_value.clone();
            replaced = true;
            break;
        }
    }

    if !replaced {
        zones_array.push(zone_value);
    }

    toml::to_string_pretty(&toml::Value::Table(table)).map_err(Into::into)
}

fn delete_authoritative_zone_in_raw(raw: &str, zone_name: &str) -> anyhow::Result<(String, bool)> {
    let mut table = load_toml_root_table(raw)?;

    let Some(value) = table.get_mut("authoritative_zones") else {
        return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false));
    };

    let zones_array = value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("authoritative_zones must be an array"))?;

    let before = zones_array.len();
    zones_array.retain(|item| {
        !item
            .as_table()
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .map(|name| name.eq_ignore_ascii_case(zone_name))
            .unwrap_or(false)
    });
    let removed = zones_array.len() != before;

    Ok((toml::to_string_pretty(&toml::Value::Table(table))?, removed))
}

fn update_authoritative_zone_soa_in_raw(
    raw: &str,
    zone_name: &str,
    soa_payload: &serde_json::Value,
) -> anyhow::Result<(String, bool)> {
    let mut table = load_toml_root_table(raw)?;

    let Some(value) = table.get_mut("authoritative_zones") else {
        return Ok((toml::to_string_pretty(&toml::Value::Table(table))?, false));
    };

    let zones_array = value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("authoritative_zones must be an array"))?;

    let mut updated = false;
    for item in zones_array.iter_mut() {
        if let Some(zone_table) = item.as_table_mut() {
            if zone_table
                .get("name")
                .and_then(|v| v.as_str())
                .map(|name| name.eq_ignore_ascii_case(zone_name))
                .unwrap_or(false)
            {
                // 找到了目标Zone，更新SOA
                if let Some(soa_obj) = soa_payload.as_object() {
                    let mut soa_table = toml::Table::new();

                    // 提取SOA字段
                    if let Some(mname) = soa_obj.get("mname").and_then(|v| v.as_str()) {
                        soa_table
                            .insert("mname".to_string(), toml::Value::String(mname.to_string()));
                    }
                    if let Some(rname) = soa_obj.get("rname").and_then(|v| v.as_str()) {
                        soa_table
                            .insert("rname".to_string(), toml::Value::String(rname.to_string()));
                    }
                    if let Some(serial) = soa_obj.get("serial").and_then(|v| v.as_i64()) {
                        soa_table.insert("serial".to_string(), toml::Value::Integer(serial));
                    }
                    if let Some(refresh) = soa_obj.get("refresh").and_then(|v| v.as_i64()) {
                        soa_table.insert("refresh".to_string(), toml::Value::Integer(refresh));
                    }
                    if let Some(retry) = soa_obj.get("retry").and_then(|v| v.as_i64()) {
                        soa_table.insert("retry".to_string(), toml::Value::Integer(retry));
                    }
                    if let Some(expire) = soa_obj.get("expire").and_then(|v| v.as_i64()) {
                        soa_table.insert("expire".to_string(), toml::Value::Integer(expire));
                    }
                    if let Some(minimum_ttl) = soa_obj.get("minimum_ttl").and_then(|v| v.as_i64()) {
                        soa_table
                            .insert("minimum_ttl".to_string(), toml::Value::Integer(minimum_ttl));
                    }

                    zone_table.insert("soa".to_string(), toml::Value::Table(soa_table));
                    updated = true;
                    break;
                }
            }
        }
    }

    Ok((toml::to_string_pretty(&toml::Value::Table(table))?, updated))
}

async fn config_raw_handler(
    State(state): State<AppState>,
) -> Result<Json<ConfigRawResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let path = state.config_path().to_string();
    let content = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    Ok(Json(ConfigRawResponse {
        status: "ok",
        path,
        content,
    }))
}

async fn config_raw_upsert_handler(
    State(state): State<AppState>,
    Json(req): Json<ConfigRawUpsertRequest>,
) -> Result<Json<ConfigApplyResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    apply_config_raw_and_reload(&state, req.content).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        )
    })?;

    Ok(Json(ConfigApplyResponse {
        status: "ok",
        reloaded: true,
        message: "config replaced and reloaded".to_string(),
        audit: state.reload_audit_snapshot(),
    }))
}

fn load_log_directory(
    state: &AppState,
) -> Result<PathBuf, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    let path = resolve_relative_config_path(state.config_path(), &cfg.logging.directory);
    Ok(path)
}

fn validate_log_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && !file_name.contains('/')
        && !file_name.contains('\\')
        && !file_name.contains("..")
}

async fn logs_files_handler(
    State(state): State<AppState>,
) -> Result<Json<LogsFilesResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let directory = load_log_directory(&state)?;
    let dir_string = directory.to_string_lossy().to_string();

    let mut files = Vec::new();
    if directory.exists() {
        for entry in fs::read_dir(&directory).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_read_logs_directory",
                }),
            )
        })? {
            let entry = entry.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_read_logs_directory",
                    }),
                )
            })?;
            let metadata = entry.metadata().map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_read_logs_metadata",
                    }),
                )
            })?;
            if !metadata.is_file() {
                continue;
            }
            let Some(file_name) = entry.file_name().to_str().map(|v| v.to_string()) else {
                continue;
            };
            if !validate_log_file_name(&file_name) {
                continue;
            }
            let modified_unix_secs = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_secs());
            files.push(LogFileEntry {
                name: file_name,
                size_bytes: metadata.len(),
                modified_unix_secs,
            });
        }
    }

    files.sort_by(|a, b| {
        b.modified_unix_secs
            .cmp(&a.modified_unix_secs)
            .then(a.name.cmp(&b.name))
    });

    Ok(Json(LogsFilesResponse {
        status: "ok",
        directory: dir_string,
        files,
    }))
}

async fn logs_download_handler(
    State(state): State<AppState>,
    Query(query): Query<LogsDownloadQuery>,
) -> Result<Response, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let file_name = query.file.trim();
    if !validate_log_file_name(file_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_log_file",
            }),
        ));
    }

    let directory = load_log_directory(&state)?;
    if !directory.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "logs_directory_not_found",
            }),
        ));
    }

    let canonical_dir = fs::canonicalize(&directory).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_resolve_logs_directory",
            }),
        )
    })?;
    let candidate = canonical_dir.join(file_name);
    let canonical_file = fs::canonicalize(&candidate).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "log_file_not_found",
            }),
        )
    })?;
    if !canonical_file.starts_with(&canonical_dir) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_log_file",
            }),
        ));
    }

    let file = tokio::fs::File::open(&canonical_file).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "log_file_not_found",
            }),
        )
    })?;
    let size = file.metadata().await.ok().map(|value| value.len());
    let stream = ReaderStream::with_capacity(file, 1024 * 1024);
    let mut response = Response::new(axum::body::Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(disposition) =
        header::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file_name))
    {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, disposition);
    }
    if let Some(content_len) = size {
        if let Ok(value) = header::HeaderValue::from_str(&content_len.to_string()) {
            response.headers_mut().insert(header::CONTENT_LENGTH, value);
        }
    }
    Ok(response)
}

async fn authoritative_zones_handler(
    State(state): State<AppState>,
) -> Result<Json<AuthoritativeZonesResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    Ok(Json(AuthoritativeZonesResponse {
        status: "ok",
        zones: cfg.authoritative_zones,
    }))
}

async fn authoritative_zone_upsert_handler(
    State(state): State<AppState>,
    Json(req): Json<AuthoritativeZoneUpsertRequest>,
) -> Result<Json<AuthoritativeZoneMutationResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    if req.zone.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "zone_name_required",
            }),
        ));
    }

    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let new_raw = upsert_authoritative_zone_in_raw(&old_raw, &req.zone).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_update_authoritative_zones",
            }),
        )
    })?;

    apply_config_raw_and_reload(&state, new_raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        )
    })?;

    Ok(Json(AuthoritativeZoneMutationResponse {
        status: "ok",
        message: format!("authoritative zone upserted: {}", req.zone.name),
        audit: state.reload_audit_snapshot(),
    }))
}

async fn authoritative_zone_delete_handler(
    AxumPath(zone): AxumPath<String>,
    State(state): State<AppState>,
) -> Result<Json<AuthoritativeZoneMutationResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    if let Some(zones_dir) = cfg
        .authoritative_zones_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let dir_path = resolve_relative_config_path(state.config_path(), zones_dir);
        let file_path = find_zone_file_in_dir(&dir_path, &zone)
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_update_authoritative_zones_dir",
                    }),
                )
            })?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "zone_not_found",
                    }),
                )
            })?;

        apply_external_delete_and_reload(&state, &file_path).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "invalid_or_unreloadable_config",
                }),
            )
        })?;

        return Ok(Json(AuthoritativeZoneMutationResponse {
            status: "ok",
            message: format!("authoritative zone deleted: {}", zone),
            audit: state.reload_audit_snapshot(),
        }));
    }

    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let (new_raw, removed) = delete_authoritative_zone_in_raw(&old_raw, &zone).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_update_authoritative_zones",
            }),
        )
    })?;

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "zone_not_found",
            }),
        ));
    }

    apply_config_raw_and_reload(&state, new_raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        )
    })?;

    Ok(Json(AuthoritativeZoneMutationResponse {
        status: "ok",
        message: format!("authoritative zone deleted: {}", zone),
        audit: state.reload_audit_snapshot(),
    }))
}

async fn authoritative_zone_soa_patch_handler(
    AxumPath(zone): AxumPath<String>,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthoritativeZoneMutationResponse>, (StatusCode, Json<AdminAuthErrorResponse>)> {
    let soa_payload = serde_json::from_str(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_json_payload",
            }),
        )
    })?;

    let cfg = AppConfig::load_or_default(state.config_path()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_load_config",
            }),
        )
    })?;

    if let Some(zones_dir) = cfg
        .authoritative_zones_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let dir_path = resolve_relative_config_path(state.config_path(), zones_dir);
        let updated = update_authoritative_zone_soa_in_dir(&dir_path, &zone, &soa_payload)
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(AdminAuthErrorResponse {
                        status: "error",
                        message: "failed_to_update_authoritative_zones_dir",
                    }),
                )
            })?;

        if !updated {
            return Err((
                StatusCode::NOT_FOUND,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "zone_not_found",
                }),
            ));
        }

        state.reload_from_disk().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "invalid_or_unreloadable_config",
                }),
            )
        })?;

        return Ok(Json(AuthoritativeZoneMutationResponse {
            status: "ok",
            message: format!("authoritative zone SOA updated: {}", zone),
            audit: state.reload_audit_snapshot(),
        }));
    }

    let old_raw = read_config_raw(&state).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "failed_to_read_config",
            }),
        )
    })?;

    let (new_raw, updated) = update_authoritative_zone_soa_in_raw(&old_raw, &zone, &soa_payload)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AdminAuthErrorResponse {
                    status: "error",
                    message: "failed_to_update_zone_soa",
                }),
            )
        })?;

    if !updated {
        return Err((
            StatusCode::NOT_FOUND,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "zone_not_found",
            }),
        ));
    }

    apply_config_raw_and_reload(&state, new_raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(AdminAuthErrorResponse {
                status: "error",
                message: "invalid_or_unreloadable_config",
            }),
        )
    })?;

    Ok(Json(AuthoritativeZoneMutationResponse {
        status: "ok",
        message: format!("authoritative zone SOA updated: {}", zone),
        audit: state.reload_audit_snapshot(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        build_config_sections, classify_reload_error, delete_view_in_raw,
        ensure_view_data_paths_in_raw, ensure_view_support_files, is_admin_request_authorized,
        resolve_path_relative_to_config_for_creation, resolve_relative_config_path,
        update_config_sections_in_raw, upsert_view_in_raw, ViewUpsertRequest,
    };
    use crate::config::{AppConfig, DnsView, StaticRecord};
    use axum::http::{header, HeaderMap, HeaderValue};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn classify_reload_errors() {
        assert_eq!(
            classify_reload_error("failed to read config file: x"),
            "read_error"
        );
        assert_eq!(
            classify_reload_error("failed to parse config file: x"),
            "parse_error"
        );
        assert_eq!(
            classify_reload_error("invalid config in x"),
            "invalid_config"
        );
        assert_eq!(classify_reload_error("resolver init failed"), "build_error");
        assert_eq!(classify_reload_error("something else"), "other");
    }

    #[test]
    fn admin_auth_accepts_bearer_and_custom_header() {
        let mut bearer_headers = HeaderMap::new();
        bearer_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        assert!(is_admin_request_authorized(&bearer_headers, Some("secret")));

        let mut custom_headers = HeaderMap::new();
        custom_headers.insert("x-cognidns-token", HeaderValue::from_static("secret"));
        assert!(is_admin_request_authorized(&custom_headers, Some("secret")));
        assert!(!is_admin_request_authorized(&custom_headers, Some("other")));
    }

    #[test]
    fn config_sections_static_data_uses_default_view_records() {
        let mut cfg = AppConfig::default();
        cfg.static_records = vec![StaticRecord {
            qname: "global.example.com".to_string(),
            qtype: "A".to_string(),
            answer: "1.1.1.1".to_string(),
            ttl: 60,
        }];

        let mut default_view = DnsView::default();
        default_view.name = "default".to_string();
        default_view.static_records = vec![StaticRecord {
            qname: "default.example.com".to_string(),
            qtype: "A".to_string(),
            answer: "2.2.2.2".to_string(),
            ttl: 120,
        }];
        cfg.views = vec![default_view];

        let sections = build_config_sections(&cfg);
        assert_eq!(sections.static_data.static_records.len(), 1);
        assert_eq!(
            sections.static_data.static_records[0].qname,
            "default.example.com"
        );
        assert_eq!(sections.static_data.static_records[0].answer, "2.2.2.2");
    }

    #[test]
    fn update_config_sections_sets_default_view_data_file_paths() {
        let mut sections = build_config_sections(&AppConfig::default());
        sections.static_data.static_records = vec![StaticRecord {
            qname: "cfg.example.com".to_string(),
            qtype: "A".to_string(),
            answer: "3.3.3.3".to_string(),
            ttl: 300,
        }];
        sections.security.blocked_domains = vec!["ads.example.com".to_string()];

        let updated_raw = update_config_sections_in_raw("", &sections).expect("update config");
        let updated_cfg: AppConfig = toml::from_str(&updated_raw).expect("parse updated config");
        assert_eq!(
            updated_cfg.static_records_file.as_deref(),
            Some("config/default/static_records.toml")
        );
        assert!(updated_cfg.static_records.is_empty());
        assert_eq!(
            updated_cfg.blocked_domains_file.as_deref(),
            Some("config/default/blocked_domains.toml")
        );
        assert!(updated_cfg.blocked_domains.is_empty());
    }

    #[test]
    fn config_sections_round_trip_advanced_fields() {
        let mut cfg = AppConfig::default();
        cfg.minimal_response = false;
        cfg.follow_cname_chain = false;
        cfg.iterative_address_family = crate::config::IterativeAddressFamily::Ipv6;
        cfg.cname_chain_max_depth = 16;
        cfg.freeze_cache_domains = vec!["critical.example.com".to_string()];
        cfg.dnssec.trust_anchor_files = vec!["config/root.key".to_string()];
        cfg.authoritative_sources = vec![crate::config::AuthoritativeSource {
            qname: "dynamic.example.com".to_string(),
            qtype: "TXT".to_string(),
            source: "https://example.com/dns/txt".to_string(),
            ttl: 60,
        }];
        cfg.prewarm_delegation_zones = vec![crate::config::PreWarmZone {
            zone: "com.".to_string(),
            ns_endpoints: vec!["192.5.6.30:53".to_string()],
            ns_hostnames: vec![],
            ttl_secs: 900,
        }];

        let sections = build_config_sections(&cfg);
        assert!(!sections.advanced.minimal_response);
        assert!(!sections.advanced.follow_cname_chain);
        assert_eq!(sections.advanced.iterative_address_family, "ipv6");
        assert_eq!(sections.advanced.cname_chain_max_depth, 16);
        assert_eq!(
            sections.advanced.freeze_cache_domains,
            vec!["critical.example.com".to_string()]
        );
        assert_eq!(
            sections.advanced.dnssec_trust_anchor_files,
            vec!["config/root.key".to_string()]
        );
        assert_eq!(sections.advanced.authoritative_sources.len(), 1);
        assert_eq!(sections.advanced.prewarm_delegation_zones.len(), 1);

        let updated_raw = update_config_sections_in_raw("", &sections).expect("update config");
        let updated_cfg: AppConfig = toml::from_str(&updated_raw).expect("parse updated config");
        assert!(!updated_cfg.minimal_response);
        assert!(!updated_cfg.follow_cname_chain);
        assert_eq!(
            updated_cfg.iterative_address_family,
            crate::config::IterativeAddressFamily::Ipv6
        );
        assert_eq!(updated_cfg.cname_chain_max_depth, 16);
        assert_eq!(
            updated_cfg.freeze_cache_domains,
            vec!["critical.example.com".to_string()]
        );
        assert_eq!(
            updated_cfg.dnssec.trust_anchor_files,
            vec!["config/root.key".to_string()]
        );
        assert_eq!(updated_cfg.authoritative_sources.len(), 1);
        assert_eq!(updated_cfg.prewarm_delegation_zones.len(), 1);
    }

    #[test]
    fn resolve_relative_config_path_prefers_existing_project_relative_path() {
        let resolved = resolve_relative_config_path(
            "config/cognidns.toml",
            "config/examples/authoritative_zones.example.toml",
        );
        assert_eq!(
            resolved,
            PathBuf::from("config/examples/authoritative_zones.example.toml")
        );
    }

    #[test]
    fn resolve_relative_config_path_falls_back_to_config_dir_relative_path() {
        let resolved = resolve_relative_config_path(
            "config/cognidns.toml",
            "authoritative_zones.example.toml",
        );
        assert_eq!(
            resolved,
            PathBuf::from("config").join("authoritative_zones.example.toml")
        );
    }

    #[test]
    fn resolve_path_relative_to_config_for_creation_normalizes_config_prefix() {
        let resolved =
            resolve_path_relative_to_config_for_creation("config/cognidns.toml", "config/default");
        assert_eq!(resolved, PathBuf::from("config/default"));
    }

    #[test]
    fn ensure_view_data_paths_in_raw_sets_target_view() {
        let raw = r#"
[[views]]
name = "default"

[[views]]
name = "test-view"
"#;

        let (updated, found) =
            ensure_view_data_paths_in_raw(raw, "test-view").expect("update should succeed");

        assert!(found);
        let cfg: AppConfig = toml::from_str(&updated).expect("updated config should parse");
        let view = cfg
            .views
            .iter()
            .find(|v| v.name == "test-view")
            .expect("target view should exist");
        assert_eq!(
            view.authoritative_zones_dir.as_deref(),
            Some("config/test-view")
        );
        assert_eq!(
            view.static_records_file.as_deref(),
            Some("config/test-view/static_records.toml")
        );
        assert_eq!(
            view.blocked_domains_file.as_deref(),
            Some("config/test-view/blocked_domains.toml")
        );
    }

    #[test]
    fn ensure_view_support_files_creates_missing_data_files() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX_EPOCH")
            .as_nanos();
        let view_dir = std::env::temp_dir().join(format!("cognidns-admin-view-support-{ts}"));
        fs::create_dir_all(&view_dir).expect("create view dir");

        let mut backups: Vec<(PathBuf, Option<String>)> = Vec::new();
        ensure_view_support_files(&view_dir, &mut backups).expect("ensure support files");

        let static_raw = fs::read_to_string(view_dir.join("static_records.toml"))
            .expect("read static_records.toml");
        let blocked_raw = fs::read_to_string(view_dir.join("blocked_domains.toml"))
            .expect("read blocked_domains.toml");
        assert!(static_raw.contains("static_records"));
        assert!(blocked_raw.contains("blocked_domains"));

        fs::remove_dir_all(&view_dir).expect("cleanup temp view dir");
    }

    #[test]
    fn upsert_view_in_raw_can_rename_and_update_metadata() {
        let raw = r#"
[[views]]
name = "default"
summary = "old summary"
query_mode = "global_fallback"
client_cidrs = ["10.0.0.0/8"]
enable_recursion = true
static_records = []
blocked_domains = []

[[views]]
name = "office"
summary = "office old"
query_mode = "global_fallback"
client_cidrs = ["172.16.0.0/16"]
enable_recursion = true
static_records = []
blocked_domains = []
"#;

        let (updated, found) = upsert_view_in_raw(
            raw,
            &ViewUpsertRequest {
                name: "corp".to_string(),
                previous_name: Some("office".to_string()),
                summary: Some("office clients".to_string()),
                query_mode: "view_only".to_string(),
                client_cidrs: vec!["192.168.10.0/24".to_string()],
                static_records: Vec::new(),
                blocked_domains: Vec::new(),
                enable_recursion: false,
                view_static_cname_expand_for_address_queries: None,
                view_authoritative_cname_expand_for_address_queries: None,
            },
        )
        .expect("rename should succeed");

        assert!(found);
        let cfg: AppConfig = toml::from_str(&updated).expect("updated config should parse");
        assert_eq!(cfg.views.len(), 2);
        let view = cfg
            .views
            .iter()
            .find(|view| view.name == "corp")
            .expect("renamed view should exist");
        assert_eq!(view.summary.as_deref(), Some("office clients"));
        assert_eq!(view.query_mode, crate::config::ViewQueryMode::ViewOnly);
        assert_eq!(view.client_cidrs, vec!["192.168.10.0/24".to_string()]);
        assert!(!view.enable_recursion);
        assert!(cfg
            .views
            .iter()
            .any(|view| view.name.eq_ignore_ascii_case("default")));
    }

    #[test]
    fn upsert_view_in_raw_keeps_file_backed_view_data_out_of_inline_arrays() {
        let raw = r#"
[[views]]
name = "default"
query_mode = "global_fallback"
client_cidrs = []
enable_recursion = true
static_records_file = "config/default/static_records.toml"
blocked_domains_file = "config/default/blocked_domains.toml"
static_records = [{ qname = "a.example.com", qtype = "A", answer = "1.1.1.1", ttl = 60 }]
blocked_domains = ["legacy.example.com"]
"#;

        let (updated, found) = upsert_view_in_raw(
            raw,
            &ViewUpsertRequest {
                name: "default".to_string(),
                previous_name: None,
                summary: Some("updated".to_string()),
                query_mode: "global_fallback".to_string(),
                client_cidrs: Vec::new(),
                static_records: vec![StaticRecord {
                    qname: "b.example.com".to_string(),
                    qtype: "A".to_string(),
                    answer: "2.2.2.2".to_string(),
                    ttl: 60,
                }],
                blocked_domains: vec!["new-inline.example.com".to_string()],
                enable_recursion: true,
                view_static_cname_expand_for_address_queries: None,
                view_authoritative_cname_expand_for_address_queries: None,
            },
        )
        .expect("update should succeed");

        assert!(found);
        assert!(!updated.contains("legacy.example.com"));
        assert!(!updated.contains("new-inline.example.com"));

        let cfg: AppConfig = toml::from_str(&updated).expect("updated config should parse");
        let view = cfg
            .views
            .iter()
            .find(|view| view.name.eq_ignore_ascii_case("default"))
            .expect("default view should exist");
        assert_eq!(
            view.static_records_file.as_deref(),
            Some("config/default/static_records.toml")
        );
        assert_eq!(
            view.blocked_domains_file.as_deref(),
            Some("config/default/blocked_domains.toml")
        );
        assert!(view.static_records.is_empty());
        assert!(view.blocked_domains.is_empty());
    }

    #[test]
    fn upsert_view_in_raw_rejects_renaming_default_view() {
        let raw = r#"
[[views]]
name = "default"
query_mode = "global_fallback"
client_cidrs = []
enable_recursion = true
static_records = []
blocked_domains = []
"#;

        let result = upsert_view_in_raw(
            raw,
            &ViewUpsertRequest {
                name: "renamed-default".to_string(),
                previous_name: Some("default".to_string()),
                summary: None,
                query_mode: "global_fallback".to_string(),
                client_cidrs: Vec::new(),
                static_records: Vec::new(),
                blocked_domains: Vec::new(),
                enable_recursion: true,
                view_static_cname_expand_for_address_queries: None,
                view_authoritative_cname_expand_for_address_queries: None,
            },
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("immutable"));
    }

    #[test]
    fn upsert_view_in_raw_rejects_rename_when_previous_not_found() {
        let raw = r#"
[[views]]
name = "default"
query_mode = "global_fallback"
client_cidrs = []
enable_recursion = true
static_records = []
blocked_domains = []

[[views]]
name = "test-view"
query_mode = "global_fallback"
client_cidrs = []
enable_recursion = true
static_records = []
blocked_domains = []
"#;

        let result = upsert_view_in_raw(
            raw,
            &ViewUpsertRequest {
                name: "test1".to_string(),
                previous_name: Some("missing-view".to_string()),
                summary: None,
                query_mode: "global_fallback".to_string(),
                client_cidrs: Vec::new(),
                static_records: Vec::new(),
                blocked_domains: Vec::new(),
                enable_recursion: true,
                view_static_cname_expand_for_address_queries: None,
                view_authoritative_cname_expand_for_address_queries: None,
            },
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("previous view name not found"));
    }

    #[test]
    fn delete_view_in_raw_rejects_deleting_default_view() {
        let raw = r#"
[[views]]
name = "default"
query_mode = "global_fallback"
client_cidrs = []
enable_recursion = true
static_records = []
blocked_domains = []
"#;

        let result = delete_view_in_raw(raw, "default");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot be deleted"));
    }
}
