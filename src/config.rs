//! Application configuration model and loader.
use std::fs;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use ipnet::IpNet;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use tracing::warn;

use crate::health::HealthCheckConfig;

/// 委托区预热条目：启动时直接注入已知的 NS 端点，跳过 root→TLD 遍历。
///
/// 支持两种输入：
/// - `ns_endpoints`：直接可用的 IP:port 端点，同步注入委托缓存。
/// - `ns_hostnames`：NS 主机名（如 "a.dns.cn."），服务启动后在后台异步解析并注入。
///
/// 两者可同时配置，最终注入端点集合为并集去重。两者不能同时为空。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct PreWarmZone {
    /// 区名，如 "cnnic.cn." 或 "com"（两种写法均可，内部会规范化）。
    pub zone: String,
    /// NS 服务器端点列表，格式为 "IP:port"，如 "203.119.25.1:53"。
    /// 启动时同步注入，立即生效。
    pub ns_endpoints: Vec<String>,
    /// NS 主机名列表，如 "a.dns.cn."。
    /// 服务启动后在后台异步解析为 IP:53 端点，解析完成后增量注入委托缓存。
    /// 解析失败不阻断服务，查询会回退至常规迭代路径。
    pub ns_hostnames: Vec<String>,
    /// 预热缓存 TTL（秒），到期后下一次查询重新走迭代流程。默认 3600。
    #[serde(default = "default_prewarm_ttl_secs")]
    pub ttl_secs: u64,
}

fn default_prewarm_ttl_secs() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DotConfig {
    pub enabled: bool,
    pub listen: String,
    pub cert_file: String,
    pub key_file: String,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:853".to_string(),
            cert_file: "config/dot.crt".to_string(),
            key_file: "config/dot.key".to_string(),
        }
    }
}

/// DNS-over-HTTPS (DoH, RFC 8484) 服务配置。
///
/// 支持 GET（`?dns=<base64url>`）和 POST（`application/dns-message`）两种接入方式。
/// 若需 HTTPS，建议在前面部署 TLS 反向代理（如 nginx/caddy）。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DohConfig {
    pub enabled: bool,
    pub listen: String,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:8053".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnssecConfig {
    pub enabled: bool,
    pub use_builtin_trust_anchors: bool,
    pub trust_anchor_files: Vec<String>,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_builtin_trust_anchors: true,
            trust_anchor_files: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRecord {
    #[serde(alias = "name")]
    pub qname: String,
    #[serde(alias = "rtype", alias = "type")]
    pub qtype: String,
    #[serde(alias = "value")]
    pub answer: String,
    #[serde(default = "default_static_record_ttl")]
    pub ttl: u32,
}

fn default_static_record_ttl() -> u32 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewRecord {
    #[serde(alias = "name")]
    pub domain_name: String,
    pub ip: String,
}

/// SOA (Start of Authority) 记录，标识权威区的主权威服务器信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneSoa {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}

/// 权威 DNS 区域定义，包含 SOA 和区内资源记录。
/// 区内查询命中时响应 AA=1；在区内但无记录时返回 NXDOMAIN + SOA（AA=1）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthoritativeZone {
    pub name: String,
    #[serde(default = "default_static_record_ttl")]
    pub default_ttl: u32,
    pub soa: Option<ZoneSoa>,
    pub records: Vec<StaticRecord>,
}

#[derive(Debug, Deserialize)]
struct AuthoritativeZoneFilePayload {
    #[serde(default)]
    zones: Vec<AuthoritativeZone>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ViewQueryMode {
    #[serde(rename = "view_only", alias = "view-only")]
    ViewOnly,
    #[serde(rename = "global_fallback", alias = "global-fallback")]
    #[default]
    GlobalFallback,
}

fn default_view_enable_recursion() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsView {
    pub name: String,
    pub summary: Option<String>,
    pub client_cidrs: Vec<String>,
    pub static_records_file: Option<String>,
    pub static_records: Vec<StaticRecord>,
    pub authoritative_records: Vec<StaticRecord>,
    pub records: Vec<ViewRecord>,
    pub blocked_domains_file: Option<String>,
    pub blocked_domains: Vec<String>,
    pub authoritative_zones_file: Option<String>,
    /// 权威区目录：目录内每个 `<zone_name>.toml` 文件对应一个权威区，
    /// 文件名（不含扩展名）为区名，每个文件的格式与 authoritative_zones_file 中单个 zone 一致。
    /// 加载优先级：authoritative_zones_dir 中的文件追加到 authoritative_zones_file 和内联 authoritative_zones 之后。
    pub authoritative_zones_dir: Option<String>,
    pub authoritative_zones: Vec<AuthoritativeZone>,
    pub query_mode: ViewQueryMode,
    #[serde(default = "default_view_enable_recursion")]
    pub enable_recursion: bool,
    /// 视图级静态记录 CNAME 地址查询展开开关。
    /// None 表示沿用全局 static_cname_expand_for_address_queries。
    pub view_static_cname_expand_for_address_queries: Option<bool>,
    /// 视图级权威记录/Zone CNAME 地址查询展开开关。
    /// None 表示沿用全局 static_cname_expand_for_address_queries。
    pub view_authoritative_cname_expand_for_address_queries: Option<bool>,
}

impl DnsView {
    pub fn effective_static_records(&self) -> anyhow::Result<Vec<StaticRecord>> {
        let mut records = self.static_records.clone();
        for legacy in &self.records {
            records.push(self.convert_legacy_record(legacy)?);
        }
        Ok(records)
    }

    pub fn effective_authoritative_records(&self) -> Vec<StaticRecord> {
        self.authoritative_records.clone()
    }

    fn convert_legacy_record(&self, record: &ViewRecord) -> anyhow::Result<StaticRecord> {
        let parsed_ip = record.ip.parse::<IpAddr>().with_context(|| {
            format!(
                "invalid IP in legacy views.{}.records for domain {}: {}",
                self.name, record.domain_name, record.ip
            )
        })?;
        let qtype = match parsed_ip {
            IpAddr::V4(_) => "A",
            IpAddr::V6(_) => "AAAA",
        };

        Ok(StaticRecord {
            qname: record.domain_name.clone(),
            qtype: qtype.to_string(),
            answer: parsed_ip.to_string(),
            ttl: default_static_record_ttl(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthoritativeSource {
    #[serde(alias = "name")]
    pub qname: String,
    #[serde(alias = "rtype", alias = "type")]
    pub qtype: String,
    pub source: String, // URL or command
    pub ttl: u32,
}

#[derive(Debug, Deserialize)]
struct StaticRecordFilePayload {
    #[serde(default)]
    static_records: Vec<StaticRecord>,
}

#[derive(Debug, Deserialize)]
struct BlockedDomainsFilePayload {
    #[serde(default)]
    blocked_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StaticRecordJsonPayload {
    Wrapped {
        #[serde(default)]
        static_records: Vec<StaticRecord>,
    },
    Flat(Vec<StaticRecord>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub console: bool,
    pub directory: String,
    pub rotation: String,
    pub format: String,
    pub query_level: String,
    pub response_level: String,
    pub general_level: String,
    /// 低损耗递归追踪：仅对这些后缀域名输出详细链路日志。
    /// 示例： ["cnnic.cn", "qq.com"]
    pub trace_query_domains: Vec<String>,
}

impl Default for LoggingConfig {
    /// LoggingConfig 的默认实现，初始化日志相关字段。
    fn default() -> Self {
        Self {
            enabled: true,
            console: true,
            directory: "logs".to_string(),
            rotation: "day".to_string(),
            format: "compact".to_string(),
            query_level: "info".to_string(),
            response_level: "info".to_string(),
            general_level: "info".to_string(),
            trace_query_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IterativeAddressFamily {
    #[default]
    DualStack,
    Ipv4,
    Ipv6,
}

impl IterativeAddressFamily {
    pub fn allows_ipv4(self) -> bool {
        matches!(self, Self::DualStack | Self::Ipv4)
    }

    pub fn allows_ipv6(self) -> bool {
        matches!(self, Self::DualStack | Self::Ipv6)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NsHostnameResolveMode {
    #[default]
    BootstrapRecursive,
    PureIterative,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub udp_listen: String,
    pub tcp_listen: String,
    pub admin_listen: String,
    pub control_listen: String,
    pub control_token: Option<String>,
    pub resolve_mode: String,
    pub root_servers: Vec<String>,
    pub iterative_address_family: IterativeAddressFamily,
    pub iterative_max_depth: u8,
    pub iterative_timeout_ms: u64,
    pub cname_chain_max_depth: u8,
    pub follow_cname_chain: bool,
    /// A/AAAA 查询命中静态 CNAME 时是否展开并返回终点地址记录。
    /// false: 直接返回配置的 CNAME；true: 返回静态 CNAME 链并继续解析到最终 A/AAAA。
    pub static_cname_expand_for_address_queries: bool,
    /// iterative 解析失败后是否回退到 forwarder upstreams。
    pub iterative_fallback_to_forwarder: bool,
    /// iterative CNAME 跟随中遇到 "no referral glue" 时，是否允许临时桥接到
    /// bootstrap recursive resolvers 做一次递归补全。
    pub iterative_cname_bridge_fallback_to_recursive: bool,
    /// 是否将完整的 CNAME 链合并结果缓存到原始查询名。
    pub cname_chain_cache_enabled: bool,
    /// 是否在 CNAME 链追踪过程中查询缓存，避免不必要的上游请求。
    pub cname_chain_inline_cache_enabled: bool,
    /// 是否在解析一种 qtype 后立即预解析兄弟 qtype（A↔AAAA），为双栈客户端预热缓存。
    pub cname_chain_dualstack_share_enabled: bool,
    /// 是否在 CNAME 链解析完成后预取叶子目标的记录到缓存。
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
    /// 是否启用 TOP N 查询域名/客户端统计。
    /// 默认关闭以确保解析热路径不受额外开销影响。
    pub topn_stats_enabled: bool,
    pub cache_hot_capacity: usize,
    pub response_cache_capacity: usize,
    pub prefetch_budget_per_window: u32,
    pub prefetch_window_secs: u64,
    pub prefetch_ttl_trigger_secs: u64,
    pub prefetch_popularity_threshold: u32,
    pub upstreams: Vec<String>,
    pub cache_ttl_secs: u64,
    pub freeze_cache_ttl_decay: bool,
    pub freeze_cache_domains: Vec<String>,
    pub upstream_timeout_ms: u64,
    pub upstream_retries: u8,
    pub unhealthy_backoff_ms: u64,
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
    pub allow_clients: Vec<String>,
    pub blocked_domains_file: Option<String>,
    pub blocked_domains: Vec<String>,
    /// 全局递归开关：false 时仅响应本地权威/静态数据，不向上游递归查询。
    pub enable_recursion: bool,
    /// 是否启用最小应答（minimal response）。
    /// true: 仅返回最小必要区段；false: 可附加 MX/NS 目标主机 A/AAAA。
    pub minimal_response: bool,
    pub views: Vec<DnsView>,
    pub rate_limit_per_second: u32,
    pub deny_any_queries: bool,
    pub dot: DotConfig,
    pub doh: DohConfig,
    pub dnssec: DnssecConfig,
    pub logging: LoggingConfig,
    pub health_check: HealthCheckConfig,
    pub static_records_file: Option<String>,
    pub static_records: Vec<StaticRecord>,
    pub authoritative_sources: Vec<AuthoritativeSource>,
    pub authoritative_zones_file: Option<String>,
    /// 全局权威区目录：目录内每个 `<zone_name>.toml` 文件对应一个权威区。
    pub authoritative_zones_dir: Option<String>,
    pub authoritative_zones: Vec<AuthoritativeZone>,
    /// NS 主机名并发解析上限（每跳最多同时飞行几个主机名任务）。
    pub ns_hostname_max_concurrent: usize,
    /// 累计收集到该端点数即提前截断，减少不必要 I/O。
    pub ns_hostname_enough_endpoints: usize,
    /// 单个主机名解析超时（ms）。
    pub ns_hostname_per_resolve_ms: u64,
    /// NS 主机名解析模式。
    pub ns_hostname_resolve_mode: NsHostnameResolveMode,
    /// 单跳 NS 解析最大时间（ms），0 = 不限制，使用全局预算。
    /// 推荐值：iterative_timeout_ms / iterative_max_depth。
    pub iterative_per_hop_timeout_ms: u64,
    /// 委托区预热列表：启动时直接注入已知的 NS 端点，跳过冷启动 root→TLD 遍历。
    pub prewarm_delegation_zones: Vec<PreWarmZone>,
}

impl Default for AppConfig {
    /// AppConfig 的默认实现，提供一套合理的默认配置。
    fn default() -> Self {
        Self {
            udp_listen: "0.0.0.0:5300".to_string(),
            tcp_listen: "0.0.0.0:5300".to_string(),
            admin_listen: "0.0.0.0:8080".to_string(),
            control_listen: "127.0.0.1:19090".to_string(),
            control_token: None,
            resolve_mode: "forwarder".to_string(),
            root_servers: vec![
                "198.41.0.4:53".to_string(),
                "199.9.14.201:53".to_string(),
                "192.33.4.12:53".to_string(),
                "199.7.91.13:53".to_string(),
            ],
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
            delegation_cache_capacity: 2048,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            topn_stats_enabled: false,
            cache_hot_capacity: 50_000,
            response_cache_capacity: 200_000,
            prefetch_budget_per_window: 64,
            prefetch_window_secs: 1,
            prefetch_ttl_trigger_secs: 5,
            prefetch_popularity_threshold: 3,
            upstreams: vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 1500,
            upstream_retries: 1,
            unhealthy_backoff_ms: 3000,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 100_000,
            adaptive_cache_max_capacity: 400_000,
            adaptive_cache_step: 10_000,
            adaptive_cache_window_secs: 10,
            adaptive_cache_high_miss_ratio: 0.55,
            adaptive_cache_low_miss_ratio: 0.15,
            allow_clients: Vec::new(),
            blocked_domains_file: None,
            blocked_domains: Vec::new(),
            enable_recursion: true,
            minimal_response: true,
            views: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
            dot: DotConfig::default(),
            doh: DohConfig::default(),
            dnssec: DnssecConfig::default(),
            logging: LoggingConfig::default(),
            health_check: HealthCheckConfig::default(),
            static_records_file: None,
            static_records: Vec::new(),
            authoritative_sources: Vec::new(),
            authoritative_zones_file: None,
            authoritative_zones_dir: None,
            authoritative_zones: Vec::new(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            ns_hostname_resolve_mode: NsHostnameResolveMode::BootstrapRecursive,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Loads TOML config from disk or returns defaults when file does not exist.
    /// 从磁盘加载 TOML 配置文件，不存在则返回默认配置。
    pub fn load_or_default(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {path}"))?;
        let mut cfg: Self =
            toml::from_str(&raw).with_context(|| format!("failed to parse config file: {path}"))?;
        cfg.load_misplaced_top_level_fields(&raw, path)?;
        cfg.load_static_records_from_file(path)?;
        cfg.load_blocked_domains_from_file(path)?;
        cfg.load_authoritative_zones_from_file(path)?;
        cfg.load_authoritative_zones_from_dir(path)?;
        cfg.load_view_static_and_blocked_data(path)?;
        cfg.load_view_authoritative_zones(path)?;
        Ok(cfg)
    }

    fn load_misplaced_top_level_fields(
        &mut self,
        raw: &str,
        config_path: &str,
    ) -> anyhow::Result<()> {
        let document: toml::Value = toml::from_str(raw)
            .with_context(|| format!("failed to parse config file: {config_path}"))?;
        let Some(root) = document.as_table() else {
            return Ok(());
        };

        load_misplaced_field_if_absent(&document, root, &mut self.udp_listen, "udp_listen")?;
        load_misplaced_field_if_absent(&document, root, &mut self.tcp_listen, "tcp_listen")?;
        load_misplaced_field_if_absent(&document, root, &mut self.admin_listen, "admin_listen")?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.control_listen,
            "control_listen",
        )?;
        load_misplaced_field_if_absent(&document, root, &mut self.control_token, "control_token")?;
        load_misplaced_field_if_absent(&document, root, &mut self.resolve_mode, "resolve_mode")?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.iterative_address_family,
            "iterative_address_family",
        )?;
        load_misplaced_field_if_absent(&document, root, &mut self.root_servers, "root_servers")?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.iterative_max_depth,
            "iterative_max_depth",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.iterative_timeout_ms,
            "iterative_timeout_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.cname_chain_max_depth,
            "cname_chain_max_depth",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.follow_cname_chain,
            "follow_cname_chain",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.static_cname_expand_for_address_queries,
            "static_cname_expand_for_address_queries",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.iterative_fallback_to_forwarder,
            "iterative_fallback_to_forwarder",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.iterative_cname_bridge_fallback_to_recursive,
            "iterative_cname_bridge_fallback_to_recursive",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.cache_hot_capacity,
            "cache_hot_capacity",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.response_cache_capacity,
            "response_cache_capacity",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.prefetch_budget_per_window,
            "prefetch_budget_per_window",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.prefetch_window_secs,
            "prefetch_window_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.prefetch_ttl_trigger_secs,
            "prefetch_ttl_trigger_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.prefetch_popularity_threshold,
            "prefetch_popularity_threshold",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.cache_ttl_secs,
            "cache_ttl_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.freeze_cache_ttl_decay,
            "freeze_cache_ttl_decay",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.freeze_cache_domains,
            "freeze_cache_domains",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.ns_host_cache_capacity,
            "ns_host_cache_capacity",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.ns_host_cache_ttl_secs,
            "ns_host_cache_ttl_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.ns_host_cache_cleanup_interval_ms,
            "ns_host_cache_cleanup_interval_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.enable_delegation_cache,
            "enable_delegation_cache",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.strict_bailiwick,
            "strict_bailiwick",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.delegation_cache_capacity,
            "delegation_cache_capacity",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.delegation_cache_ttl_cap_secs,
            "delegation_cache_ttl_cap_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.delegation_cache_cleanup_interval_ms,
            "delegation_cache_cleanup_interval_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.delegation_failure_backoff_ms,
            "delegation_failure_backoff_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.stats_window_secs,
            "stats_window_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.stats_short_window_secs,
            "stats_short_window_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.topn_stats_enabled,
            "topn_stats_enabled",
        )?;
        load_misplaced_field_if_absent(&document, root, &mut self.upstreams, "upstreams")?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.upstream_timeout_ms,
            "upstream_timeout_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.upstream_retries,
            "upstream_retries",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.unhealthy_backoff_ms,
            "unhealthy_backoff_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.upstream_score_rtt_weight,
            "upstream_score_rtt_weight",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.upstream_score_failure_weight,
            "upstream_score_failure_weight",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.upstream_score_success_weight,
            "upstream_score_success_weight",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.adaptive_cache_enabled,
            "adaptive_cache_enabled",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.adaptive_cache_min_capacity,
            "adaptive_cache_min_capacity",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.adaptive_cache_max_capacity,
            "adaptive_cache_max_capacity",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.adaptive_cache_step,
            "adaptive_cache_step",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.adaptive_cache_window_secs,
            "adaptive_cache_window_secs",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.adaptive_cache_high_miss_ratio,
            "adaptive_cache_high_miss_ratio",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.adaptive_cache_low_miss_ratio,
            "adaptive_cache_low_miss_ratio",
        )?;
        load_misplaced_field_if_absent(&document, root, &mut self.allow_clients, "allow_clients")?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.blocked_domains,
            "blocked_domains",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.blocked_domains_file,
            "blocked_domains_file",
        )?;
        load_misplaced_field_if_absent(&document, root, &mut self.views, "views")?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.rate_limit_per_second,
            "rate_limit_per_second",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.deny_any_queries,
            "deny_any_queries",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.static_records_file,
            "static_records_file",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.static_records,
            "static_records",
        )?;
        load_misplaced_field_if_absent(&document, root, &mut self.health_check, "health_check")?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.authoritative_sources,
            "authoritative_sources",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.ns_hostname_max_concurrent,
            "ns_hostname_max_concurrent",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.ns_hostname_enough_endpoints,
            "ns_hostname_enough_endpoints",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.ns_hostname_per_resolve_ms,
            "ns_hostname_per_resolve_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.ns_hostname_resolve_mode,
            "ns_hostname_resolve_mode",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.iterative_per_hop_timeout_ms,
            "iterative_per_hop_timeout_ms",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.prewarm_delegation_zones,
            "prewarm_delegation_zones",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.authoritative_zones_file,
            "authoritative_zones_file",
        )?;
        load_misplaced_field_if_absent(
            &document,
            root,
            &mut self.authoritative_zones,
            "authoritative_zones",
        )?;
        Ok(())
    }

    fn load_static_records_from_file(&mut self, config_path: &str) -> anyhow::Result<()> {
        let Some(resolved_path) =
            resolve_optional_config_path(config_path, self.static_records_file.as_deref())
        else {
            return Ok(());
        };

        let raw = read_config_file(&resolved_path, "static_records_file")?;
        let loaded = parse_static_records(&raw, &resolved_path)?;
        self.static_records = loaded;
        Ok(())
    }

    fn load_blocked_domains_from_file(&mut self, config_path: &str) -> anyhow::Result<()> {
        let Some(resolved_path) =
            resolve_optional_config_path(config_path, self.blocked_domains_file.as_deref())
        else {
            return Ok(());
        };

        let raw = read_config_file(&resolved_path, "blocked_domains_file")?;
        self.blocked_domains = parse_blocked_domains(&raw, &resolved_path)?;
        Ok(())
    }

    fn load_authoritative_zones_from_file(&mut self, config_path: &str) -> anyhow::Result<()> {
        let Some(resolved_path) =
            resolve_optional_config_path(config_path, self.authoritative_zones_file.as_deref())
        else {
            return Ok(());
        };

        let raw = read_config_file(&resolved_path, "authoritative_zones_file")?;
        let loaded = parse_authoritative_zones(&raw, &resolved_path)?;
        self.authoritative_zones = loaded;
        Ok(())
    }

    /// 从 authoritative_zones_dir 目录加载各区数据文件（每区一个文件，文件名=区名）。
    /// 追加到已有的 authoritative_zones 之后（不覆盖）。
    fn load_authoritative_zones_from_dir(&mut self, config_path: &str) -> anyhow::Result<()> {
        let Some(dir_path) =
            resolve_optional_config_path(config_path, self.authoritative_zones_dir.as_deref())
        else {
            return Ok(());
        };

        let extra = load_zones_from_dir(&dir_path)?;
        self.authoritative_zones.extend(extra);
        Ok(())
    }

    fn load_view_authoritative_zones(&mut self, config_path: &str) -> anyhow::Result<()> {
        for view in &mut self.views {
            load_view_authoritative_zones(view, config_path)?;
        }
        Ok(())
    }

    fn load_view_static_and_blocked_data(&mut self, config_path: &str) -> anyhow::Result<()> {
        for view in &mut self.views {
            load_view_static_records(view, config_path)?;
            load_view_blocked_domains(view, config_path)?;
        }
        Ok(())
    }

    /// Validates config semantics before services are started.
    /// 校验配置项的语义合法性，服务启动前调用。
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_endpoint(&self.udp_listen, "udp_listen")?;
        validate_endpoint(&self.tcp_listen, "tcp_listen")?;
        validate_endpoint(&self.admin_listen, "admin_listen")?;
        validate_endpoint(&self.control_listen, "control_listen")?;

        if !self.resolve_mode.eq_ignore_ascii_case("forwarder")
            && !self.resolve_mode.eq_ignore_ascii_case("iterative")
        {
            return Err(anyhow!(
                "resolve_mode must be either 'forwarder' or 'iterative'"
            ));
        }

        let requires_forwarder_upstreams = self.resolve_mode.eq_ignore_ascii_case("forwarder")
            || self.iterative_fallback_to_forwarder;
        if requires_forwarder_upstreams && self.upstreams.is_empty() {
            return Err(anyhow!(
                "upstreams must not be empty when resolve_mode=forwarder or iterative_fallback_to_forwarder=true"
            ));
        }
        for item in &self.upstreams {
            validate_endpoint(item, "upstreams")?;
        }
        for item in &self.root_servers {
            validate_endpoint(item, "root_servers")?;
        }
        if self.ns_hostname_resolve_mode == NsHostnameResolveMode::PureIterative
            && self.root_servers.is_empty()
        {
            return Err(anyhow!(
                "ns_hostname_resolve_mode=pure_iterative requires non-empty root_servers"
            ));
        }

        if self.iterative_max_depth == 0 {
            return Err(anyhow!("iterative_max_depth must be greater than 0"));
        }
        if self.iterative_timeout_ms == 0 {
            return Err(anyhow!("iterative_timeout_ms must be greater than 0"));
        }
        if self.cname_chain_max_depth == 0 {
            return Err(anyhow!("cname_chain_max_depth must be greater than 0"));
        }
        if self.upstream_timeout_ms == 0 {
            return Err(anyhow!("upstream_timeout_ms must be greater than 0"));
        }
        self.health_check.validate()?;
        if self.cache_ttl_secs == 0 {
            return Err(anyhow!("cache_ttl_secs must be greater than 0"));
        }
        if self.ns_host_cache_ttl_secs == 0 {
            return Err(anyhow!("ns_host_cache_ttl_secs must be greater than 0"));
        }
        if self.ns_host_cache_cleanup_interval_ms == 0 {
            return Err(anyhow!(
                "ns_host_cache_cleanup_interval_ms must be greater than 0"
            ));
        }
        if self.enable_delegation_cache {
            if self.delegation_cache_capacity == 0 {
                return Err(anyhow!("delegation_cache_capacity must be greater than 0"));
            }
            if self.delegation_cache_ttl_cap_secs == 0 {
                return Err(anyhow!(
                    "delegation_cache_ttl_cap_secs must be greater than 0"
                ));
            }
            if self.delegation_cache_cleanup_interval_ms == 0 {
                return Err(anyhow!(
                    "delegation_cache_cleanup_interval_ms must be greater than 0"
                ));
            }
            if self.delegation_failure_backoff_ms == 0 {
                return Err(anyhow!(
                    "delegation_failure_backoff_ms must be greater than 0"
                ));
            }
        }
        if self.stats_window_secs == 0 || self.stats_short_window_secs == 0 {
            return Err(anyhow!(
                "stats_window_secs and stats_short_window_secs must be greater than 0"
            ));
        }
        if self.cache_hot_capacity == 0 {
            return Err(anyhow!("cache_hot_capacity must be greater than 0"));
        }
        if self.response_cache_capacity == 0 {
            return Err(anyhow!("response_cache_capacity must be greater than 0"));
        }
        if self.prefetch_window_secs == 0 {
            return Err(anyhow!("prefetch_window_secs must be greater than 0"));
        }
        if self.prefetch_ttl_trigger_secs == 0 {
            return Err(anyhow!("prefetch_ttl_trigger_secs must be greater than 0"));
        }
        if self.adaptive_cache_enabled {
            if self.adaptive_cache_min_capacity == 0 {
                return Err(anyhow!(
                    "adaptive_cache_min_capacity must be greater than 0"
                ));
            }
            if self.adaptive_cache_max_capacity == 0 {
                return Err(anyhow!(
                    "adaptive_cache_max_capacity must be greater than 0"
                ));
            }
            if self.adaptive_cache_step == 0 {
                return Err(anyhow!("adaptive_cache_step must be greater than 0"));
            }
            if self.adaptive_cache_window_secs == 0 {
                return Err(anyhow!("adaptive_cache_window_secs must be greater than 0"));
            }
            if self.adaptive_cache_min_capacity > self.adaptive_cache_max_capacity {
                return Err(anyhow!(
                    "adaptive_cache_min_capacity must be <= adaptive_cache_max_capacity"
                ));
            }
            if !(0.0..=1.0).contains(&self.adaptive_cache_high_miss_ratio)
                || !(0.0..=1.0).contains(&self.adaptive_cache_low_miss_ratio)
            {
                return Err(anyhow!(
                    "adaptive_cache_high_miss_ratio and adaptive_cache_low_miss_ratio must be in [0,1]"
                ));
            }
            if self.adaptive_cache_low_miss_ratio >= self.adaptive_cache_high_miss_ratio {
                return Err(anyhow!(
                    "adaptive_cache_low_miss_ratio must be less than adaptive_cache_high_miss_ratio"
                ));
            }
        }
        if self.upstream_score_rtt_weight < 0.0
            || self.upstream_score_failure_weight < 0.0
            || self.upstream_score_success_weight < 0.0
        {
            return Err(anyhow!("upstream_score_* weights must be non-negative"));
        }

        if self
            .authoritative_zones_file
            .as_deref()
            .is_some_and(|path| path.trim().is_empty())
        {
            return Err(anyhow!(
                "authoritative_zones_file must not be empty when provided"
            ));
        }

        if self
            .authoritative_zones_file
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty())
        {
            return Err(anyhow!(
                "top-level authoritative_zones_file is not supported; configure authoritative zones under views[*].authoritative_zones_file or views[*].authoritative_zones_dir"
            ));
        }

        if self
            .authoritative_zones_dir
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty())
        {
            return Err(anyhow!(
                "top-level authoritative_zones_dir is not supported; configure authoritative zones under views[*].authoritative_zones_dir"
            ));
        }

        if !self.authoritative_zones.is_empty() {
            return Err(anyhow!(
                "top-level authoritative_zones is not supported; configure authoritative zones under views[*].authoritative_zones"
            ));
        }

        if self.logging.enabled {
            if self.logging.directory.trim().is_empty() {
                return Err(anyhow!(
                    "logging.directory must not be empty when logging is enabled"
                ));
            }
            if !self.logging.rotation.eq_ignore_ascii_case("day") {
                return Err(anyhow!("logging.rotation must be 'day' in current version"));
            }
            if !self.logging.format.eq_ignore_ascii_case("compact")
                && !self.logging.format.eq_ignore_ascii_case("json")
            {
                return Err(anyhow!("logging.format must be either 'compact' or 'json'"));
            }
            validate_level(&self.logging.query_level, "logging.query_level")?;
            validate_level(&self.logging.response_level, "logging.response_level")?;
            validate_level(&self.logging.general_level, "logging.general_level")?;
            for domain in &self.logging.trace_query_domains {
                if domain.trim().is_empty() {
                    return Err(anyhow!(
                        "logging.trace_query_domains contains an empty domain"
                    ));
                }
            }
        }

        for cidr in &self.allow_clients {
            cidr.parse::<IpNet>()
                .with_context(|| format!("invalid CIDR in allow_clients: {cidr}"))?;
        }

        for domain in &self.blocked_domains {
            if domain.trim().is_empty() {
                return Err(anyhow!("blocked_domains contains an empty domain"));
            }
        }

        for (index, record) in self.static_records.iter().enumerate() {
            validate_static_like_record(record, &format!("static_records[{index}]"))?;
        }

        for (index, source) in self.authoritative_sources.iter().enumerate() {
            validate_authoritative_source(source, &format!("authoritative_sources[{index}]"))?;
        }

        for view in &self.views {
            if view.name.trim().is_empty() {
                return Err(anyhow!("views contains an item with empty name"));
            }
            for cidr in &view.client_cidrs {
                cidr.parse::<IpNet>().with_context(|| {
                    format!("invalid CIDR in views.{}.client_cidrs: {cidr}", view.name)
                })?;
            }
            for domain in &view.blocked_domains {
                if domain.trim().is_empty() {
                    return Err(anyhow!(
                        "views.{}.blocked_domains contains an empty domain",
                        view.name
                    ));
                }
            }
            for (index, record) in view.static_records.iter().enumerate() {
                validate_static_like_record(
                    record,
                    &format!("views.{}.static_records[{index}]", view.name),
                )?;
            }
            if !view.authoritative_records.is_empty() {
                return Err(anyhow!(
                    "views.{}.authoritative_records is not supported; use views[].authoritative_zones (with SOA) or views[].authoritative_zones_dir instead",
                    view.name
                ));
            }
            for (index, record) in view.records.iter().enumerate() {
                validate_legacy_view_record(
                    record,
                    &format!("views.{}.records[{index}]", view.name),
                )?;
            }
            for (i, zone) in view.authoritative_zones.iter().enumerate() {
                validate_authoritative_zone(
                    zone,
                    &format!("views.{}.authoritative_zones[{i}]", view.name),
                )?;
            }
        }

        for domain in &self.freeze_cache_domains {
            if domain.trim().is_empty() {
                return Err(anyhow!("freeze_cache_domains contains an empty domain"));
            }
        }

        for path in &self.dnssec.trust_anchor_files {
            if path.trim().is_empty() {
                return Err(anyhow!("dnssec.trust_anchor_files contains an empty path"));
            }
        }

        if self.dnssec.enabled
            && !self.dnssec.use_builtin_trust_anchors
            && self.dnssec.trust_anchor_files.is_empty()
        {
            return Err(anyhow!(
                "dnssec requires either use_builtin_trust_anchors=true or at least one trust_anchor_files entry"
            ));
        }

        if self.dot.enabled {
            validate_endpoint(&self.dot.listen, "dot.listen")?;
            if self.dot.cert_file.trim().is_empty() {
                return Err(anyhow!(
                    "dot.cert_file must not be empty when DoT is enabled"
                ));
            }
            if self.dot.key_file.trim().is_empty() {
                return Err(anyhow!(
                    "dot.key_file must not be empty when DoT is enabled"
                ));
            }
        }

        if self.doh.enabled {
            validate_endpoint(&self.doh.listen, "doh.listen")?;
        }

        if self.ns_hostname_max_concurrent == 0 {
            return Err(anyhow!("ns_hostname_max_concurrent must be >= 1"));
        }
        if self.ns_hostname_enough_endpoints == 0 {
            return Err(anyhow!("ns_hostname_enough_endpoints must be >= 1"));
        }
        if self.ns_hostname_per_resolve_ms < 100 {
            return Err(anyhow!("ns_hostname_per_resolve_ms must be >= 100"));
        }
        if self.iterative_per_hop_timeout_ms > 0
            && self.iterative_per_hop_timeout_ms >= self.iterative_timeout_ms
        {
            return Err(anyhow!(
                "iterative_per_hop_timeout_ms must be less than iterative_timeout_ms when non-zero"
            ));
        }
        if self.iterative_per_hop_timeout_ms > 0
            && self.ns_hostname_per_resolve_ms > self.iterative_per_hop_timeout_ms
        {
            return Err(anyhow!(
                "ns_hostname_per_resolve_ms ({}) should not exceed iterative_per_hop_timeout_ms ({})",
                self.ns_hostname_per_resolve_ms,
                self.iterative_per_hop_timeout_ms
            ));
        }
        if !self.prewarm_delegation_zones.is_empty() && !self.enable_delegation_cache {
            return Err(anyhow!(
                "prewarm_delegation_zones is configured but enable_delegation_cache = false; \
                 set enable_delegation_cache = true to activate prewarm"
            ));
        }
        for (i, zone) in self.prewarm_delegation_zones.iter().enumerate() {
            if zone.zone.trim().is_empty() {
                return Err(anyhow!(
                    "prewarm_delegation_zones[{i}].zone must not be empty"
                ));
            }
            if zone.ns_endpoints.is_empty() && zone.ns_hostnames.is_empty() {
                return Err(anyhow!(
                    "prewarm_delegation_zones[{i}]: ns_endpoints and ns_hostnames \
                     cannot both be empty; provide at least one"
                ));
            }
            if zone.ttl_secs == 0 {
                return Err(anyhow!(
                    "prewarm_delegation_zones[{i}].ttl_secs must be > 0"
                ));
            }
            if zone.ttl_secs > self.delegation_cache_ttl_cap_secs {
                warn!(
                    zone = %zone.zone,
                    configured_ttl = zone.ttl_secs,
                    cap = self.delegation_cache_ttl_cap_secs,
                    "prewarm_delegation_zones[{i}].ttl_secs exceeds delegation_cache_ttl_cap_secs; \
                     effective TTL will be capped at {}",
                    self.delegation_cache_ttl_cap_secs
                );
            }
            for ep in &zone.ns_endpoints {
                validate_endpoint(ep, &format!("prewarm_delegation_zones[{i}].ns_endpoints"))?;
            }
            for hn in &zone.ns_hostnames {
                if hn.trim().is_empty() {
                    return Err(anyhow!(
                        "prewarm_delegation_zones[{i}].ns_hostnames contains an empty entry"
                    ));
                }
                if !is_valid_dns_name(hn) {
                    return Err(anyhow!(
                        "prewarm_delegation_zones[{i}].ns_hostnames[{hn:?}] \
                         is not a valid DNS hostname"
                    ));
                }
            }
        }

        Ok(())
    }
}

fn resolve_path_relative_to_config(config_path: &str, target: &str) -> PathBuf {
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        return target_path.to_path_buf();
    }

    let config_dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let direct = config_dir.join(target_path);
    if direct.exists() {
        return direct;
    }

    // When config lives under ./config and target is written as "config/...",
    // avoid resolving to "config/config/...".
    if let Some(config_dir_name) = config_dir.file_name() {
        if let Ok(stripped) = target_path.strip_prefix(config_dir_name) {
            if !stripped.as_os_str().is_empty() {
                let normalized = config_dir.join(stripped);
                if normalized.exists() {
                    return normalized;
                }
            }
        }
    }

    direct
}

fn resolve_optional_config_path(config_path: &str, target: Option<&str>) -> Option<PathBuf> {
    target
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| resolve_path_relative_to_config(config_path, value))
}

fn read_config_file(path: &Path, field_name: &str) -> anyhow::Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read {field_name}: {}", path.display()))
}

fn load_view_static_records(view: &mut DnsView, config_path: &str) -> anyhow::Result<()> {
    let Some(resolved_path) =
        resolve_optional_config_path(config_path, view.static_records_file.as_deref())
    else {
        return Ok(());
    };

    let label = format!("views.{}.static_records_file", view.name);
    let raw = read_config_file(&resolved_path, &label)?;
    view.static_records = parse_static_records(&raw, &resolved_path)?;
    Ok(())
}

fn load_view_blocked_domains(view: &mut DnsView, config_path: &str) -> anyhow::Result<()> {
    let Some(resolved_path) =
        resolve_optional_config_path(config_path, view.blocked_domains_file.as_deref())
    else {
        return Ok(());
    };

    let label = format!("views.{}.blocked_domains_file", view.name);
    let raw = read_config_file(&resolved_path, &label)?;
    view.blocked_domains = parse_blocked_domains(&raw, &resolved_path)?;
    Ok(())
}

fn load_view_authoritative_zones(view: &mut DnsView, config_path: &str) -> anyhow::Result<()> {
    if let Some(resolved_path) =
        resolve_optional_config_path(config_path, view.authoritative_zones_file.as_deref())
    {
        let label = format!("views.{}.authoritative_zones_file", view.name);
        let raw = read_config_file(&resolved_path, &label)?;
        let mut loaded = parse_authoritative_zones(&raw, &resolved_path)?;
        view.authoritative_zones.append(&mut loaded);
    }

    if let Some(dir_path) =
        resolve_optional_config_path(config_path, view.authoritative_zones_dir.as_deref())
    {
        let extra = load_zones_from_dir(&dir_path).with_context(|| {
            format!(
                "failed to load authoritative_zones_dir for view '{}': {}",
                view.name,
                dir_path.display()
            )
        })?;
        view.authoritative_zones.extend(extra);
    }

    Ok(())
}

fn load_misplaced_field_if_absent<T>(
    document: &toml::Value,
    root: &toml::map::Map<String, toml::Value>,
    target: &mut T,
    key: &str,
) -> anyhow::Result<()>
where
    T: DeserializeOwned,
{
    if root.contains_key(key) {
        return Ok(());
    }

    let Some(value) = find_nested_key(document, key) else {
        return Ok(());
    };

    *target = value
        .clone()
        .try_into()
        .with_context(|| format!("failed to parse misplaced config key: {key}"))?;
    Ok(())
}

fn find_nested_key<'a>(value: &'a toml::Value, key: &str) -> Option<&'a toml::Value> {
    match value {
        toml::Value::Table(table) => table
            .get(key)
            .or_else(|| table.values().find_map(|child| find_nested_key(child, key))),
        toml::Value::Array(items) => items.iter().find_map(|item| find_nested_key(item, key)),
        _ => None,
    }
}

fn parse_static_records(raw: &str, source_path: &Path) -> anyhow::Result<Vec<StaticRecord>> {
    let extension = source_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    if extension.as_deref() == Some("json") {
        let payload: StaticRecordJsonPayload = serde_json::from_str(raw).with_context(|| {
            format!(
                "failed to parse static records json: {}",
                source_path.display()
            )
        })?;
        return Ok(match payload {
            StaticRecordJsonPayload::Wrapped { static_records } => static_records,
            StaticRecordJsonPayload::Flat(records) => records,
        });
    }

    let payload: StaticRecordFilePayload = toml::from_str(raw).with_context(|| {
        format!(
            "failed to parse static records toml: {}",
            source_path.display()
        )
    })?;
    Ok(payload.static_records)
}

fn parse_blocked_domains(raw: &str, source_path: &Path) -> anyhow::Result<Vec<String>> {
    let payload: BlockedDomainsFilePayload = toml::from_str(raw).with_context(|| {
        format!(
            "failed to parse blocked domains toml: {}",
            source_path.display()
        )
    })?;
    Ok(payload.blocked_domains)
}

fn parse_authoritative_zones(
    raw: &str,
    source_path: &Path,
) -> anyhow::Result<Vec<AuthoritativeZone>> {
    let payload: AuthoritativeZoneFilePayload = toml::from_str(raw).with_context(|| {
        format!(
            "failed to parse authoritative zones toml: {}",
            source_path.display()
        )
    })?;
    Ok(payload.zones)
}

/// 从目录中加载权威区文件（每文件一个区，文件名即区名）。
///
/// 目录中每个 `.toml` 文件被解析为一个 `AuthoritativeZone`。
/// 文件名（去掉 `.toml` 扩展名）作为区名，可被文件内的 `name` 字段覆盖。
/// 解析失败的文件会记录警告并跳过，不中断整体加载。
fn load_zones_from_dir(dir_path: &Path) -> anyhow::Result<Vec<AuthoritativeZone>> {
    if !dir_path.exists() {
        return Ok(Vec::new());
    }
    if !dir_path.is_dir() {
        return Err(anyhow!(
            "authoritative_zones_dir is not a directory: {}",
            dir_path.display()
        ));
    }

    let mut zones = Vec::new();
    let entries = fs::read_dir(dir_path).with_context(|| {
        format!(
            "failed to read authoritative_zones_dir: {}",
            dir_path.display()
        )
    })?;

    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect();
    // 按文件名排序，保证加载顺序确定性
    paths.sort();

    for file_path in paths {
        let zone_name_from_file = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        // Keep view data files in the same directory without treating them as zones.
        if zone_name_from_file.eq_ignore_ascii_case("static_records")
            || zone_name_from_file.eq_ignore_ascii_case("blocked_domains")
        {
            continue;
        }

        let raw = match fs::read_to_string(&file_path) {
            Ok(r) => r,
            Err(err) => {
                warn!(
                    path = %file_path.display(),
                    error = %err,
                    "skip zone file: failed to read"
                );
                continue;
            }
        };

        let mut zone: AuthoritativeZone = match toml::from_str(&raw) {
            Ok(z) => z,
            Err(err) => {
                warn!(
                    path = %file_path.display(),
                    error = %err,
                    "skip zone file: failed to parse TOML"
                );
                continue;
            }
        };

        // 若文件中未显式设置 name，则使用文件名作为区名
        if zone.name.trim().is_empty() {
            zone.name = zone_name_from_file;
        }

        if zone.name.trim().is_empty() {
            warn!(path = %file_path.display(), "skip zone file: zone name is empty");
            continue;
        }

        zones.push(zone);
    }

    Ok(zones)
}

/// 校验 static_records / view.static_records 记录，
/// 与运行时 static-like 应答能力保持一致：A/AAAA/CNAME/MX/TXT/NS/PTR。
fn validate_static_like_record(record: &StaticRecord, path: &str) -> anyhow::Result<()> {
    if record.qname.trim().is_empty() {
        return Err(anyhow!("{path}.qname must not be empty"));
    }
    if record.qtype.trim().is_empty() {
        return Err(anyhow!("{path}.qtype must not be empty"));
    }
    if record.answer.trim().is_empty() {
        return Err(anyhow!("{path}.answer must not be empty"));
    }
    if record.ttl == 0 {
        return Err(anyhow!("{path}.ttl must be greater than 0"));
    }

    match record.qtype.trim().to_ascii_uppercase().as_str() {
        "A" => {
            record.answer.parse::<Ipv4Addr>().with_context(|| {
                format!("invalid IPv4 address in {path}.answer: {}", record.answer)
            })?;
        }
        "AAAA" => {
            record.answer.parse::<Ipv6Addr>().with_context(|| {
                format!("invalid IPv6 address in {path}.answer: {}", record.answer)
            })?;
        }
        "CNAME" | "NS" | "PTR" => {}
        "MX" => {
            let answer = record.answer.trim();
            let mut parts = answer.splitn(2, ' ');
            let priority = parts.next().unwrap_or("");
            let exchange = parts.next().unwrap_or("");
            priority.parse::<u16>().with_context(|| {
                format!(
                    "invalid MX priority in {path}.answer (expected 'priority exchange'): {answer}"
                )
            })?;
            if exchange.trim().is_empty() {
                return Err(anyhow!("missing MX exchange in {path}.answer: {answer}"));
            }
        }
        "TXT" => {}
        _ => {
            return Err(anyhow!(
                "{path}.qtype must be one of A|AAAA|CNAME|MX|TXT|NS|PTR in current version"
            ));
        }
    }

    Ok(())
}

/// 校验权威区记录，支持 A/AAAA/CNAME/MX/TXT/NS/PTR。
fn validate_zone_record(record: &StaticRecord, path: &str) -> anyhow::Result<()> {
    if record.qname.trim().is_empty() {
        return Err(anyhow!("{path}.qname must not be empty"));
    }
    if record.qtype.trim().is_empty() {
        return Err(anyhow!("{path}.qtype must not be empty"));
    }
    if record.answer.trim().is_empty() {
        return Err(anyhow!("{path}.answer must not be empty"));
    }
    if record.ttl == 0 {
        return Err(anyhow!("{path}.ttl must be greater than 0"));
    }

    match record.qtype.trim().to_ascii_uppercase().as_str() {
        "A" => {
            record.answer.parse::<Ipv4Addr>().with_context(|| {
                format!("invalid IPv4 address in {path}.answer: {}", record.answer)
            })?;
        }
        "AAAA" => {
            record.answer.parse::<Ipv6Addr>().with_context(|| {
                format!("invalid IPv6 address in {path}.answer: {}", record.answer)
            })?;
        }
        "CNAME" | "NS" | "PTR" => {}
        "MX" => {
            let answer = record.answer.trim();
            let mut parts = answer.splitn(2, ' ');
            let priority = parts.next().unwrap_or("");
            let exchange = parts.next().unwrap_or("");
            priority.parse::<u16>().with_context(|| {
                format!(
                    "invalid MX priority in {path}.answer (expected 'priority exchange'): {answer}"
                )
            })?;
            if exchange.trim().is_empty() {
                return Err(anyhow!("missing MX exchange in {path}.answer: {answer}"));
            }
        }
        "TXT" => {}
        _ => {
            return Err(anyhow!(
                "{path}.qtype must be one of A|AAAA|CNAME|MX|TXT|NS|PTR"
            ));
        }
    }

    Ok(())
}

fn validate_authoritative_zone(zone: &AuthoritativeZone, path: &str) -> anyhow::Result<()> {
    if zone.name.trim().is_empty() {
        return Err(anyhow!("{path}.name must not be empty"));
    }
    if zone.default_ttl == 0 {
        return Err(anyhow!("{path}.default_ttl must be greater than 0"));
    }
    if let Some(soa) = &zone.soa {
        if soa.mname.trim().is_empty() {
            return Err(anyhow!("{path}.soa.mname must not be empty"));
        }
        if soa.rname.trim().is_empty() {
            return Err(anyhow!("{path}.soa.rname must not be empty"));
        }
    }
    for (i, record) in zone.records.iter().enumerate() {
        validate_zone_record(record, &format!("{path}.records[{i}]"))?;
    }
    Ok(())
}

fn validate_legacy_view_record(record: &ViewRecord, path: &str) -> anyhow::Result<()> {
    if record.domain_name.trim().is_empty() {
        return Err(anyhow!("{path}.domain_name must not be empty"));
    }
    record
        .ip
        .parse::<IpAddr>()
        .with_context(|| format!("invalid IP in legacy {path}: {}", record.ip))?;
    Ok(())
}

fn validate_authoritative_source(source: &AuthoritativeSource, path: &str) -> anyhow::Result<()> {
    if source.qname.trim().is_empty() {
        return Err(anyhow!("{path}.qname must not be empty"));
    }
    if source.qtype.trim().is_empty() {
        return Err(anyhow!("{path}.qtype must not be empty"));
    }
    if source.source.trim().is_empty() {
        return Err(anyhow!("{path}.source must not be empty"));
    }
    if source.ttl == 0 {
        return Err(anyhow!("{path}.ttl must be greater than 0"));
    }
    Ok(())
}

/// 校验日志等级字符串是否合法。
fn validate_level(value: &str, field: &str) -> anyhow::Result<()> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" | "off" => Ok(()),
        _ => Err(anyhow!(
            "{field} must be one of trace|debug|info|warn|error|off"
        )),
    }
}

/// 校验 host:port 格式的网络端点是否合法。
fn validate_endpoint(value: &str, field: &str) -> anyhow::Result<()> {
    let addr = value.trim();
    if addr.is_empty() {
        return Err(anyhow!("{field} must not be empty"));
    }

    let parsed = addr.parse::<SocketAddr>().with_context(|| {
        format!("{field} endpoint must be a valid ip:port socket address: {addr}")
    })?;

    if parsed.port() == 0 {
        return Err(anyhow!(
            "{field} has invalid port 0 (expected 1..65535): {addr}"
        ));
    }

    Ok(())
}

/// 检查字符串是否符合基本 DNS 主机名语法（标签以 '.' 分隔，每个标签由字母、数字、'-'
/// 组成，不以 '-' 开头或结尾，总长度不超过 253 个字符）。
/// 允许末尾带点（FQDN 形式）。不检查网络可达性。
fn is_valid_dns_name(name: &str) -> bool {
    let stripped = name.strip_suffix('.').unwrap_or(name);
    if stripped.is_empty() || stripped.len() > 253 {
        return false;
    }
    for label in stripped.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        AppConfig, DnsView, DnssecConfig, IterativeAddressFamily, NsHostnameResolveMode,
        StaticRecord, ViewQueryMode, ViewRecord,
    };

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = AppConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn iterative_fallback_to_forwarder_defaults_to_disabled() {
        let cfg = AppConfig::default();
        assert!(!cfg.iterative_fallback_to_forwarder);
    }

    #[test]
    fn iterative_cname_bridge_fallback_defaults_to_enabled() {
        let cfg = AppConfig::default();
        assert!(cfg.iterative_cname_bridge_fallback_to_recursive);
    }

    #[test]
    fn ns_hostname_resolve_mode_defaults_to_bootstrap_recursive() {
        let cfg = AppConfig::default();
        assert_eq!(
            cfg.ns_hostname_resolve_mode,
            NsHostnameResolveMode::BootstrapRecursive
        );
    }

    #[test]
    fn topn_stats_defaults_to_disabled() {
        let cfg = AppConfig::default();
        assert!(!cfg.topn_stats_enabled);
    }

    #[test]
    fn invalid_resolve_mode_is_rejected() {
        let cfg = AppConfig {
            resolve_mode: "bad-mode".to_string(),
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_upstream_endpoint_is_rejected() {
        let cfg = AppConfig {
            upstreams: vec!["8.8.8.8".to_string()],
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_upstream_ip_is_rejected() {
        let cfg = AppConfig {
            upstreams: vec!["999.1.1.1:53".to_string()],
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn empty_upstreams_allowed_for_iterative_without_forwarder_fallback() {
        let cfg = AppConfig {
            resolve_mode: "iterative".to_string(),
            iterative_fallback_to_forwarder: false,
            upstreams: Vec::new(),
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn empty_upstreams_rejected_for_forwarder_mode() {
        let cfg = AppConfig {
            resolve_mode: "forwarder".to_string(),
            upstreams: Vec::new(),
            ..AppConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("forwarder mode should require non-empty upstreams");
        assert!(err
            .to_string()
            .contains("upstreams must not be empty when resolve_mode=forwarder"));
    }

    #[test]
    fn empty_upstreams_rejected_when_iterative_fallback_enabled() {
        let cfg = AppConfig {
            resolve_mode: "iterative".to_string(),
            iterative_fallback_to_forwarder: true,
            upstreams: Vec::new(),
            ..AppConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("iterative fallback requires upstreams");
        assert!(err
            .to_string()
            .contains("iterative_fallback_to_forwarder=true"));
    }

    #[test]
    fn view_authoritative_records_is_rejected() {
        let cfg = AppConfig {
            views: vec![DnsView {
                name: "internal".to_string(),
                authoritative_records: vec![StaticRecord {
                    qname: "api.example.com".to_string(),
                    qtype: "A".to_string(),
                    answer: "10.0.0.10".to_string(),
                    ttl: 60,
                }],
                ..DnsView::default()
            }],
            ..AppConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("authoritative_records should be rejected");
        assert!(err
            .to_string()
            .contains("authoritative_records is not supported"));
    }

    #[test]
    fn pure_iterative_ns_hostname_mode_requires_root_servers() {
        let cfg = AppConfig {
            ns_hostname_resolve_mode: NsHostnameResolveMode::PureIterative,
            root_servers: Vec::new(),
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_port_is_rejected() {
        let cfg = AppConfig {
            udp_listen: "0.0.0.0:0".to_string(),
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dnssec_requires_some_trust_anchor_source_when_enabled() {
        let cfg = AppConfig {
            dnssec: DnssecConfig {
                enabled: true,
                use_builtin_trust_anchors: false,
                trust_anchor_files: Vec::new(),
            },
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dnssec_can_be_disabled_without_trust_anchors() {
        let cfg = AppConfig {
            dnssec: DnssecConfig {
                enabled: false,
                use_builtin_trust_anchors: false,
                trust_anchor_files: Vec::new(),
            },
            ..AppConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn load_or_default_parses_dnssec_block() {
        let temp_path =
            std::env::temp_dir().join(format!("cognidns-config-{}.toml", std::process::id()));
        fs::write(
            &temp_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"

[dnssec]
enabled = false
use_builtin_trust_anchors = false
trust_anchor_files = ["config/root.key"]
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(temp_path.to_str().expect("temp path"))
            .expect("load config");
        assert!(!cfg.dnssec.enabled);
        assert!(!cfg.dnssec.use_builtin_trust_anchors);
        assert_eq!(
            cfg.dnssec.trust_anchor_files,
            vec!["config/root.key".to_string()]
        );

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn load_or_default_parses_iterative_address_family() {
        let temp_path = std::env::temp_dir().join(format!(
            "cognidns-config-family-{}.toml",
            std::process::id()
        ));
        fs::write(
            &temp_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
iterative_address_family = "ipv6"
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(temp_path.to_str().expect("temp path"))
            .expect("load config");
        assert_eq!(cfg.iterative_address_family, IterativeAddressFamily::Ipv6);

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn load_or_default_parses_iterative_fallback_toggle() {
        let temp_path = std::env::temp_dir().join(format!(
            "cognidns-config-fallback-{}.toml",
            std::process::id()
        ));
        fs::write(
            &temp_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
iterative_fallback_to_forwarder = true
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(temp_path.to_str().expect("temp path"))
            .expect("load config");
        assert!(cfg.iterative_fallback_to_forwarder);

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn load_or_default_parses_iterative_cname_bridge_toggle() {
        let temp_path = std::env::temp_dir().join(format!(
            "cognidns-config-cname-bridge-fallback-{}.toml",
            std::process::id()
        ));
        fs::write(
            &temp_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
iterative_cname_bridge_fallback_to_recursive = false
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(temp_path.to_str().expect("temp path"))
            .expect("load config");
        assert!(!cfg.iterative_cname_bridge_fallback_to_recursive);

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn load_or_default_parses_ns_hostname_resolve_mode() {
        let temp_path = std::env::temp_dir().join(format!(
            "cognidns-config-ns-hostname-mode-{}.toml",
            std::process::id()
        ));
        fs::write(
            &temp_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
ns_hostname_resolve_mode = "pure_iterative"
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(temp_path.to_str().expect("temp path"))
            .expect("load config");
        assert_eq!(
            cfg.ns_hostname_resolve_mode,
            NsHostnameResolveMode::PureIterative
        );

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn load_or_default_parses_topn_stats_toggle() {
        let temp_path =
            std::env::temp_dir().join(format!("cognidns-config-topn-{}.toml", std::process::id()));
        fs::write(
            &temp_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
topn_stats_enabled = true
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(temp_path.to_str().expect("temp path"))
            .expect("load config");
        assert!(cfg.topn_stats_enabled);

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn load_or_default_loads_static_records_from_external_toml() {
        let temp_dir = unique_temp_dir("cognidns-static-records");
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let config_path = temp_dir.join("cognidns.toml");
        let records_path = temp_dir.join("static_records.toml");

        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
static_records_file = "static_records.toml"
"#,
        )
        .expect("write temp config");

        fs::write(
            &records_path,
            r#"
[[static_records]]
name = "www.example.com"
rtype = "A"
value = "5.5.5.5"

[[static_records]]
name = "ipv6.example.com"
rtype = "AAAA"
value = "2001:db8::1"
ttl = 120
"#,
        )
        .expect("write static records");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with external static records");
        assert_eq!(cfg.static_records.len(), 2);
        assert_eq!(cfg.static_records[0].qname, "www.example.com");
        assert_eq!(cfg.static_records[0].qtype, "A");
        assert_eq!(cfg.static_records[0].answer, "5.5.5.5");
        assert_eq!(cfg.static_records[0].ttl, 300);
        assert_eq!(cfg.static_records[1].ttl, 120);

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(records_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn load_or_default_ignores_whitespace_external_file_paths() {
        let temp_dir = unique_temp_dir("cognidns-whitespace-file-paths");
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let config_path = temp_dir.join("cognidns.toml");

        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
static_records_file = "   "
blocked_domains_file = "   "

[[views]]
name = "internal"
client_cidrs = []
static_records_file = "   "
blocked_domains_file = "   "
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with whitespace file paths");

        assert!(cfg.static_records.is_empty());
        assert!(cfg.blocked_domains.is_empty());
        assert_eq!(cfg.views.len(), 1);
        assert!(cfg.views[0].static_records.is_empty());
        assert!(cfg.views[0].blocked_domains.is_empty());

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn load_or_default_rejects_directory_used_as_static_records_file() {
        let temp_dir = unique_temp_dir("cognidns-static-records-dir-error");
        let config_dir = temp_dir.join("config");
        let records_dir = config_dir.join("static-records");
        fs::create_dir_all(&records_dir).expect("create records dir");

        let config_path = config_dir.join("cognidns.toml");
        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
static_records_file = "static-records"
"#,
        )
        .expect("write temp config");

        let err = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect_err("directory path should be rejected as static_records_file");
        let message = format!("{err:#}");
        assert!(message.contains("failed to read static_records_file"));

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn load_or_default_loads_blocked_domains_from_external_toml() {
        let temp_dir = unique_temp_dir("cognidns-blocked-domains");
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let config_path = temp_dir.join("cognidns.toml");
        let blocked_path = temp_dir.join("blocked_domains.toml");

        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
blocked_domains_file = "blocked_domains.toml"
"#,
        )
        .expect("write temp config");

        fs::write(
            &blocked_path,
            r#"
blocked_domains = ["ads.example.com", "*.tracker.example.com"]
"#,
        )
        .expect("write blocked domains");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with external blocked domains");
        assert_eq!(cfg.blocked_domains.len(), 2);
        assert_eq!(cfg.blocked_domains[0], "ads.example.com");
        assert_eq!(cfg.blocked_domains[1], "*.tracker.example.com");

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(blocked_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn empty_file_path_is_allowed_for_static_and_blocked_domains() {
        let cfg = AppConfig {
            static_records_file: Some(String::new()),
            blocked_domains_file: Some(String::new()),
            views: vec![DnsView {
                name: "empty-file-path-view".to_string(),
                static_records_file: Some(String::new()),
                blocked_domains_file: Some(String::new()),
                ..DnsView::default()
            }],
            ..AppConfig::default()
        };

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn load_or_default_rejects_view_blocked_domains_file_pointing_to_directory() {
        let temp_dir = unique_temp_dir("cognidns-view-blocked-domains-dir-error");
        let config_dir = temp_dir.join("config");
        let blocked_dir = config_dir.join("blocked-domains");
        fs::create_dir_all(&blocked_dir).expect("create blocked domains dir");

        let config_path = config_dir.join("cognidns.toml");
        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"

[[views]]
name = "internal"
client_cidrs = []
blocked_domains_file = "blocked-domains"
"#,
        )
        .expect("write temp config");

        let err = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect_err("directory path should be rejected as view blocked_domains_file");
        let message = format!("{err:#}");
        assert!(message.contains("blocked_domains_file"));
        assert!(message.contains("blocked-domains"));

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn load_or_default_loads_authoritative_zones_with_config_prefix_path() {
        let temp_dir = unique_temp_dir("cognidns-authoritative-zones");
        let config_dir = temp_dir.join("config");
        let examples_dir = config_dir.join("examples");
        fs::create_dir_all(&examples_dir).expect("create examples dir");

        let config_path = config_dir.join("cognidns.toml");
        let zones_path = examples_dir.join("authoritative_zones.example.toml");

        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
authoritative_zones_file = "config/examples/authoritative_zones.example.toml"
"#,
        )
        .expect("write temp config");

        fs::write(
            &zones_path,
            r#"
[[zones]]
name = "example.com"
default_ttl = 300

[zones.soa]
mname = "ns1.example.com"
rname = "hostmaster.example.com"
serial = 2026042801
refresh = 3600
retry = 900
expire = 604800
minimum_ttl = 300

[[zones.records]]
qname = "example.com"
qtype = "A"
answer = "192.0.2.1"
ttl = 300
"#,
        )
        .expect("write zone file");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with authoritative zones");
        assert_eq!(cfg.authoritative_zones.len(), 1);
        assert_eq!(cfg.authoritative_zones[0].name, "example.com");
        assert_eq!(cfg.authoritative_zones[0].records.len(), 1);

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(zones_path);
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn load_or_default_loads_authoritative_zones_from_dir_and_view_dir() {
        let temp_dir = unique_temp_dir("cognidns-authoritative-zones-dir");
        let config_dir = temp_dir.join("config");
        let global_dir = config_dir.join("zones-global");
        let view_dir = config_dir.join("zones-view-internal");
        fs::create_dir_all(&global_dir).expect("create global zones dir");
        fs::create_dir_all(&view_dir).expect("create view zones dir");

        let config_path = config_dir.join("cognidns.toml");

        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
authoritative_zones_dir = "zones-global"

[[views]]
name = "internal"
client_cidrs = ["10.0.0.0/8"]
authoritative_zones_dir = "zones-view-internal"
"#,
        )
        .expect("write temp config");

        fs::write(
            global_dir.join("example.com.toml"),
            r#"
default_ttl = 300

[soa]
mname = "ns1.example.com"
rname = "hostmaster.example.com"
serial = 2026051301
refresh = 3600
retry = 900
expire = 604800
minimum_ttl = 300

[[records]]
qname = "example.com"
qtype = "A"
answer = "192.0.2.1"
ttl = 300
"#,
        )
        .expect("write global zone");

        fs::write(
            view_dir.join("corp.local.toml"),
            r#"
default_ttl = 60

[soa]
mname = "ns1.corp.local"
rname = "hostmaster.corp.local"
serial = 2026051301
refresh = 3600
retry = 900
expire = 604800
minimum_ttl = 60

[[records]]
qname = "api.corp.local"
qtype = "A"
answer = "10.0.0.10"
ttl = 60
"#,
        )
        .expect("write view zone");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with authoritative_zones_dir");

        assert_eq!(cfg.authoritative_zones.len(), 1);
        assert_eq!(cfg.authoritative_zones[0].name, "example.com");
        assert_eq!(cfg.authoritative_zones[0].records.len(), 1);

        assert_eq!(cfg.views.len(), 1);
        assert_eq!(cfg.views[0].authoritative_zones.len(), 1);
        assert_eq!(cfg.views[0].authoritative_zones[0].name, "corp.local");

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn load_or_default_recovers_misplaced_top_level_fields_from_section_scope() {
        let temp_dir = unique_temp_dir("cognidns-misplaced-top-level");
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let config_path = temp_dir.join("cognidns.toml");
        let records_path = temp_dir.join("static_records.toml");

        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"

[logging]
enabled = true
console = true
directory = "logs"
rotation = "day"
format = "compact"
query_level = "info"
response_level = "info"
general_level = "info"
static_records_file = "static_records.toml"
cache_ttl_secs = 123

[[authoritative_sources]]
name = "api.example.com"
rtype = "A"
source = "http://127.0.0.1:9000/dns?name={qname}&type={qtype}"
ttl = 60
"#,
        )
        .expect("write temp config");

        fs::write(
            &records_path,
            r#"
[[static_records]]
name = "www.example.com"
rtype = "A"
value = "5.5.5.5"
ttl = 600
"#,
        )
        .expect("write static records");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with misplaced top-level fields");
        assert_eq!(cfg.cache_ttl_secs, 123);
        assert_eq!(
            cfg.static_records_file.as_deref(),
            Some("static_records.toml")
        );
        assert_eq!(cfg.static_records.len(), 1);
        assert_eq!(cfg.static_records[0].qname, "www.example.com");
        assert_eq!(cfg.authoritative_sources.len(), 1);
        assert_eq!(cfg.authoritative_sources[0].qname, "api.example.com");

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(records_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn load_or_default_recovers_misplaced_top_level_fields_from_view_scope() {
        let temp_dir = unique_temp_dir("cognidns-misplaced-view-scope");
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let config_path = temp_dir.join("cognidns.toml");
        let records_path = temp_dir.join("static_records.toml");

        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"

[[views]]
name = "internal"
client_cidrs = ["0.0.0.0/0"]
query_mode = "global_fallback"
enable_recursion = true
static_records_file = "static_records.toml"
cache_ttl_secs = 123
"#,
        )
        .expect("write temp config");

        fs::write(
            &records_path,
            r#"
[[static_records]]
name = "www.example.com"
rtype = "A"
value = "5.5.5.5"
ttl = 600
"#,
        )
        .expect("write static records");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with misplaced view-scoped top-level fields");
        assert_eq!(cfg.cache_ttl_secs, 123);
        assert_eq!(
            cfg.static_records_file.as_deref(),
            Some("static_records.toml")
        );
        assert_eq!(cfg.static_records.len(), 1);
        assert_eq!(cfg.static_records[0].qname, "www.example.com");

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(records_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn load_or_default_parses_dotted_logging_levels() {
        let temp_dir = unique_temp_dir("cognidns-dotted-logging");
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let config_path = temp_dir.join("cognidns.toml");
        fs::write(
            &config_path,
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
control_token = "changeme"
resolve_mode = "iterative"

logging.enabled = true
logging.console = false
logging.directory = "logs"
logging.rotation = "day"
logging.format = "compact"
logging.query_level = "trace"
logging.response_level = "trace"
logging.general_level = "trace"
"#,
        )
        .expect("write temp config");

        let cfg = AppConfig::load_or_default(config_path.to_str().expect("config path"))
            .expect("load config with dotted logging levels");

        assert_eq!(cfg.logging.query_level, "trace");
        assert_eq!(cfg.logging.response_level, "trace");
        assert_eq!(cfg.logging.general_level, "trace");

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn dns_view_effective_static_records_merges_new_and_legacy_records() {
        let view = DnsView {
            name: "guest".to_string(),
            client_cidrs: vec!["192.168.2.0/24".to_string()],
            static_records: vec![StaticRecord {
                qname: "new.example.com".to_string(),
                qtype: "CNAME".to_string(),
                answer: "target.example.com".to_string(),
                ttl: 90,
            }],
            authoritative_records: vec![StaticRecord {
                qname: "auth.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "10.10.10.10".to_string(),
                ttl: 120,
            }],
            records: vec![ViewRecord {
                domain_name: "legacy.example.com".to_string(),
                ip: "10.1.2.3".to_string(),
            }],
            blocked_domains: Vec::new(),
            ..Default::default()
        };

        let records = view
            .effective_static_records()
            .expect("effective static records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].qname, "new.example.com");
        assert_eq!(records[0].qtype, "CNAME");
        assert_eq!(records[1].qname, "legacy.example.com");
        assert_eq!(records[1].qtype, "A");
        assert_eq!(records[1].answer, "10.1.2.3");
        assert_eq!(records[1].ttl, 300);

        let auth_records = view.effective_authoritative_records();
        assert_eq!(auth_records.len(), 1);
        assert_eq!(auth_records[0].qname, "auth.example.com");
    }

    #[test]
    fn dns_view_validate_rejects_invalid_new_static_record() {
        let cfg = AppConfig {
            views: vec![DnsView {
                name: "guest".to_string(),
                client_cidrs: vec!["192.168.2.0/24".to_string()],
                static_records: vec![StaticRecord {
                    qname: "broken.example.com".to_string(),
                    qtype: "A".to_string(),
                    answer: "not-an-ip".to_string(),
                    ttl: 120,
                }],
                authoritative_records: Vec::new(),
                records: Vec::new(),
                blocked_domains: Vec::new(),
                ..Default::default()
            }],
            ..AppConfig::default()
        };

        let error = cfg.validate().expect_err("invalid view static record");
        assert!(error
            .to_string()
            .contains("views.guest.static_records[0].answer"));
    }

    #[test]
    fn dns_view_validate_accepts_new_and_legacy_records_together() {
        let cfg = AppConfig {
            views: vec![DnsView {
                name: "guest".to_string(),
                client_cidrs: vec!["192.168.2.0/24".to_string()],
                static_records: vec![StaticRecord {
                    qname: "new.example.com".to_string(),
                    qtype: "A".to_string(),
                    answer: "10.10.10.20".to_string(),
                    ttl: 120,
                }],
                authoritative_records: Vec::new(),
                records: vec![ViewRecord {
                    domain_name: "legacy.example.com".to_string(),
                    ip: "2001:db8::20".to_string(),
                }],
                blocked_domains: Vec::new(),
                ..Default::default()
            }],
            ..AppConfig::default()
        };

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn dns_view_validate_accepts_extended_static_like_record_types() {
        let cfg = AppConfig {
            views: vec![DnsView {
                name: "extended".to_string(),
                client_cidrs: vec!["10.0.0.0/8".to_string()],
                static_records: vec![
                    StaticRecord {
                        qname: "ns1.example.com".to_string(),
                        qtype: "NS".to_string(),
                        answer: "ns1.example.net".to_string(),
                        ttl: 300,
                    },
                    StaticRecord {
                        qname: "example.com".to_string(),
                        qtype: "MX".to_string(),
                        answer: "10 mail.example.com".to_string(),
                        ttl: 300,
                    },
                    StaticRecord {
                        qname: "example.com".to_string(),
                        qtype: "TXT".to_string(),
                        answer: "v=spf1 -all".to_string(),
                        ttl: 300,
                    },
                    StaticRecord {
                        qname: "1.0.0.127.in-addr.arpa".to_string(),
                        qtype: "PTR".to_string(),
                        answer: "localhost".to_string(),
                        ttl: 300,
                    },
                ],
                authoritative_records: Vec::new(),
                records: Vec::new(),
                blocked_domains: Vec::new(),
                ..Default::default()
            }],
            ..AppConfig::default()
        };

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_top_level_authoritative_zone_configuration() {
        let cfg = AppConfig {
            authoritative_zones_file: Some(
                "config/examples/authoritative_zones.example.toml".to_string(),
            ),
            ..AppConfig::default()
        };

        let error = cfg
            .validate()
            .expect_err("top-level authoritative zone config should be rejected");
        assert!(error
            .to_string()
            .contains("top-level authoritative_zones_file is not supported"));
    }

    #[test]
    fn dns_view_query_control_defaults_keep_compatible_behavior() {
        let cfg: AppConfig = toml::from_str(
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"

[[views]]
name = "guest"
client_cidrs = ["192.168.2.0/24"]
"#,
        )
        .expect("load config");

        assert_eq!(cfg.views.len(), 1);
        assert_eq!(cfg.views[0].query_mode, ViewQueryMode::GlobalFallback);
        assert!(cfg.views[0].enable_recursion);
    }

    #[test]
    fn dns_view_query_mode_accepts_hyphen_alias() {
        let cfg: AppConfig = toml::from_str(
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"

[[views]]
name = "guest"
client_cidrs = ["192.168.2.0/24"]
query_mode = "view-only"
enable_recursion = false
"#,
        )
        .expect("load config");

        assert_eq!(cfg.views.len(), 1);
        assert_eq!(cfg.views[0].query_mode, ViewQueryMode::ViewOnly);
        assert!(!cfg.views[0].enable_recursion);
    }

    #[test]
    fn global_enable_recursion_defaults_to_true_and_can_be_disabled() {
        let default_cfg = AppConfig::default();
        assert!(default_cfg.enable_recursion);

        let cfg: AppConfig = toml::from_str(
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
enable_recursion = false
"#,
        )
        .expect("load config");

        assert!(!cfg.enable_recursion);
    }

    #[test]
    fn minimal_response_defaults_to_true_and_can_be_disabled() {
        let default_cfg = AppConfig::default();
        assert!(default_cfg.minimal_response);

        let cfg: AppConfig = toml::from_str(
            r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
minimal_response = false
"#,
        )
        .expect("load config");

        assert!(!cfg.minimal_response);
    }
}
