//! CogniDNS binary bootstrap.
//! Wires config, policy, resolver, ingress, and admin services.
use anyhow::Context;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use cognidns::admin;
use cognidns::cache::ResponseCache;
use cognidns::config::AppConfig;
use cognidns::control::{
    read_request, send_request, write_response, ControlCommand, ControlRequest, ControlResponse,
    CODE_ADMIN_PROXY_FAILED, CODE_INVALID_REQUEST, CODE_START_FAILED, CODE_STOP_FAILED,
    CODE_UNAUTHORIZED, CODE_UNSUPPORTED_VERSION, CONTROL_PROTOCOL_VERSION,
};
use cognidns::ctl_cli;
use cognidns::ctl_config::CtlConfig;
use cognidns::dnssec;
use cognidns::ingress;
use cognidns::metrics::Metrics;
use cognidns::policy::{PolicyConfig, PolicyEngine};
use cognidns::resolver::{Resolver, ResolverConfig};
use cognidns::service::AppState;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Stdio;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream as TokioTcpStream};
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::{watch, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

/// CogniDNS — high-performance DNS resolver
#[derive(Parser, Debug)]
#[command(
    name = "cognidns",
    version,
    about = "CogniDNS — high-performance DNS resolver",
    after_help = "Subcommand options (such as --config) are shown in command help:\n  cognidns worker --help\n  cognidns agent --help\n  cognidns ctl --help\n\nCommon examples:\n  cognidns agent --config config/cognidns.toml\n      Start agent in foreground\n\n  cognidns agent start --config config/cognidns.toml\n      Start agent in background\n\n  cognidns ctl stop --all --config config/cognidns.toml\n      Stop worker and agent together"
)]
struct Cli {
    /// Foreground/debug mode (suppress background spawn, inherit stdout/stderr)
    #[arg(short = 'd', long, global = true)]
    debug: bool,

    /// Increase log verbosity (repeatable: -v info, -vv debug, -vvv trace)
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<TopCommand>,
}

#[derive(Subcommand, Debug)]
enum TopCommand {
    /// Run the DNS worker process directly
    #[command(
        after_help = "Examples:\n  cognidns worker --config config/cognidns.toml\n      Start worker with explicit config path\n\n  cognidns worker config/cognidns.toml\n      Start worker using positional config path (compatibility form)\n\n  cognidns -vv worker --config config/cognidns.toml\n      Start worker with elevated log verbosity"
    )]
    Worker(WorkerArgs),
    /// Run the control agent (manages worker lifecycle)
    #[command(
        after_help = "Examples:\n  cognidns agent --config config/cognidns.toml\n      Start agent in foreground and auto-start worker\n\n  cognidns agent start --config config/cognidns.toml\n      Start agent in background (compatibility form)\n\n  cognidns -d agent start --config config/cognidns.toml\n      Start agent in foreground debug mode\n\n  cognidns agent stop --config config/cognidns.toml\n      Stop agent and worker together"
    )]
    Agent {
        /// Subcommand: 'start' accepted for backward compatibility
        #[command(subcommand)]
        subcmd: Option<AgentSubcmd>,
        #[command(flatten)]
        opts: AgentOpts,
    },
    /// Send control commands to the running agent
    #[command(
        after_help = "Examples:\n  cognidns ctl health --config config/cognidns.toml\n      Check agent and worker health\n\n  cognidns ctl stop --config config/cognidns.toml\n      Stop only the worker and keep agent alive\n\n  cognidns ctl stop --all --config config/cognidns.toml\n      Stop worker and agent together\n\n  cognidns ctl start --config config/cognidns.toml\n      Start worker again when agent is still running"
    )]
    Ctl(CtlArgs),
    /// Fallback: bare config path or unknown first arg → worker mode (backward compat)
    #[command(external_subcommand)]
    Other(Vec<String>),
}

/// Arguments for the worker subcommand
#[derive(Args, Debug)]
struct WorkerArgs {
    /// Path to config file
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
    /// Config file path (positional, for backward compatibility)
    #[arg(value_name = "CONFIG_PATH", hide = true)]
    config_path: Option<String>,
}

/// Shared options for 'agent' and 'agent start'
#[derive(Args, Clone, Debug)]
struct AgentOpts {
    /// Path to config file
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
    /// Control listen address (overrides config)
    #[arg(long, value_name = "HOST:PORT")]
    listen: Option<String>,
    /// Control token (overrides config)
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
}

#[derive(Args, Debug)]
struct CtlArgs {
    /// Path to control config file
    #[arg(long, value_name = "PATH", global = true)]
    config: Option<String>,
    /// Control server address
    #[arg(long, value_name = "HOST:PORT", global = true)]
    server: Option<String>,
    /// Control token override
    #[arg(long, value_name = "TOKEN", global = true)]
    token: Option<String>,
    #[command(subcommand)]
    command: CtlCommand,
}

#[derive(Subcommand, Debug)]
enum CtlCommand {
    /// Start worker under the running agent
    Start,
    /// Stop worker, or use --all to stop worker and agent together
    Stop(CtlStopArgs),
    /// Reload runtime config via the running agent
    Reload,
    /// Fetch runtime stats snapshot
    Stats,
    /// Check basic health
    Health,
    /// Check readiness
    Ready,
    /// Show version info
    Version,
    /// Cache management commands
    Cache(CacheArgs),
    /// TOP N statistics commands
    Top(TopArgs),
}

#[derive(Args, Debug)]
struct CtlStopArgs {
    /// Stop worker and agent together
    #[arg(long)]
    all: bool,
}

#[derive(Args, Debug)]
struct TopArgs {
    #[command(subcommand)]
    command: TopCtlCommand,
}

#[derive(Subcommand, Debug)]
enum TopCtlCommand {
    /// Show top queried domains
    Queries(TopWindowArgs),
    /// Show top client IPs
    Clients(TopWindowArgs),
}

#[derive(Args, Debug)]
struct TopWindowArgs {
    /// Number of rows to show
    #[arg(long = "top", default_value_t = 10)]
    n: usize,
    /// Time window in seconds
    #[arg(long = "window", default_value_t = 300)]
    window_secs: u64,
}

#[derive(Args, Debug)]
struct CacheArgs {
    #[command(subcommand)]
    command: CacheCommand,
}

#[derive(Subcommand, Debug)]
enum CacheCommand {
    /// Freeze or unfreeze cache TTL behavior
    Freeze(CacheFreezeArgs),
    /// Clear all cache or a specific domain
    Clear(CacheClearArgs),
    /// Export cache dump to a file
    Export(CacheExportArgs),
    /// Import cache dump from a file
    Import(CacheImportArgs),
}

#[derive(Args, Debug)]
struct CacheFreezeArgs {
    #[command(subcommand)]
    target: CacheFreezeTarget,
}

#[derive(Subcommand, Debug)]
enum CacheFreezeTarget {
    /// Freeze or unfreeze all cached entries
    All(CacheToggleArgs),
    /// Freeze or unfreeze one domain
    Domain(CacheDomainToggleArgs),
}

#[derive(Args, Debug)]
struct CacheToggleArgs {
    #[arg(value_enum)]
    state: ToggleState,
}

#[derive(Args, Debug)]
struct CacheDomainToggleArgs {
    /// Domain name
    domain: String,
    #[arg(value_enum)]
    state: ToggleState,
}

#[derive(Args, Debug)]
struct CacheClearArgs {
    #[command(subcommand)]
    target: Option<CacheClearTarget>,
    /// Domain name shorthand, compatible with `cache clear <domain>`
    #[arg(value_name = "DOMAIN")]
    domain: Option<String>,
}

#[derive(Subcommand, Debug)]
enum CacheClearTarget {
    /// Clear all cache entries
    All,
    /// Clear one domain from cache
    Domain(CacheDomainArg),
}

#[derive(Args, Debug)]
struct CacheDomainArg {
    /// Domain name
    domain: String,
}

#[derive(Args, Debug)]
struct CacheExportArgs {
    /// Output file path
    #[arg(long = "out", default_value = "cache_dump.json")]
    out: String,
}

#[derive(Args, Debug)]
struct CacheImportArgs {
    /// Input file path
    #[arg(long = "in", default_value = "cache_dump.json")]
    input: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ToggleState {
    On,
    Off,
}

impl ToggleState {
    fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Subcommand, Debug)]
enum AgentSubcmd {
    /// Start the agent (backward-compat alias for 'agent' directly)
    #[command(hide = true)]
    Start(AgentOpts),
    /// Stop the running agent and its worker
    Stop(AgentOpts),
}

#[derive(Clone, Copy, Debug, Default)]
struct LaunchOptions {
    debug: bool,
    verbose: u8,
}

/// Compute Levenshtein edit distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j - 1].min(dp[i - 1][j]).min(dp[i][j - 1])
            };
        }
    }
    dp[m][n]
}

/// Return the closest candidate to `input` (case-insensitive) within edit-distance threshold,
/// or `None` if no candidate is close enough.
fn suggest_close_match<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let threshold = (input.len() / 3 + 1).min(3);
    let input_lower = input.to_ascii_lowercase();
    candidates
        .iter()
        .copied()
        .filter_map(|c| {
            let d = edit_distance(&input_lower, &c.to_ascii_lowercase());
            if d <= threshold {
                Some((c, d))
            } else {
                None
            }
        })
        .min_by_key(|(_, d)| *d)
        .map(|(c, _)| c)
}

fn has_global_version_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "-V" || arg == "--version")
}

fn level_rank(level: &str) -> Option<u8> {
    match level.trim().to_ascii_lowercase().as_str() {
        "off" => Some(0),
        "error" => Some(1),
        "warn" => Some(2),
        "info" => Some(3),
        "debug" => Some(4),
        "trace" => Some(5),
        _ => None,
    }
}

fn rank_to_level(rank: u8) -> &'static str {
    match rank {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    }
}

fn apply_launch_overrides(cfg: &mut AppConfig, options: LaunchOptions) {
    if options.debug {
        cfg.logging.console = true;
    }

    let floor = match options.verbose {
        0 => return,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    };

    if let Some(floor) = floor {
        let floor_rank = level_rank(floor).unwrap_or(3);
        let general_rank = level_rank(&cfg.logging.general_level).unwrap_or(floor_rank);
        let query_rank = level_rank(&cfg.logging.query_level).unwrap_or(floor_rank);
        let response_rank = level_rank(&cfg.logging.response_level).unwrap_or(floor_rank);

        cfg.logging.general_level = rank_to_level(general_rank.max(floor_rank)).to_string();
        cfg.logging.query_level = rank_to_level(query_rank.max(floor_rank)).to_string();
        cfg.logging.response_level = rank_to_level(response_rank.max(floor_rank)).to_string();
    }
}

#[cfg(windows)]
fn apply_background_spawn(command: &mut Command) {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn apply_background_spawn(_command: &mut Command) {}

async fn run_agent_detached(opts: AgentOpts, launch_options: LaunchOptions) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("failed to locate executable")?;
    let mut command = Command::new(exe);
    command.arg("agent");
    if let Some(config) = opts.config {
        command.arg("--config").arg(config);
    }
    if let Some(listen) = opts.listen {
        command.arg("--listen").arg(listen);
    }
    if let Some(token) = opts.token {
        command.arg("--token").arg(token);
    }
    for _ in 0..launch_options.verbose {
        command.arg("-v");
    }

    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_background_spawn(&mut command);
    command
        .spawn()
        .context("failed to spawn detached control agent")?;
    println!("control agent started in background");
    Ok(())
}

async fn run_agent_stop(opts: AgentOpts) -> anyhow::Result<()> {
    let config_path = opts
        .config
        .unwrap_or_else(|| "config/cognidns.toml".to_string());
    let cfg = AppConfig::load_or_default(&config_path)
        .with_context(|| format!("failed to load config from {}", config_path))?;
    let server = opts.listen.unwrap_or(cfg.control_listen.clone());
    let token = opts.token.or_else(|| cfg.control_token.clone());

    let request = ControlRequest {
        version: CONTROL_PROTOCOL_VERSION,
        token,
        command: ControlCommand::StopAll,
    };
    let response = send_request(&server, &request)
        .await
        .with_context(|| format!("failed to contact control agent at {}", server))?;
    if response.status.eq_ignore_ascii_case("error") {
        anyhow::bail!(
            "agent stop failed: server={} code={} message={}",
            server,
            response.code,
            response.message
        );
    }

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// 程序主入口，解析命令行参数并根据参数启动不同模式（worker、agent、ctl），默认启动 worker。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    if has_global_version_flag(&raw_args) {
        println!("cognidns {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let cli = Cli::parse();
    let launch_options = LaunchOptions {
        debug: cli.debug,
        verbose: cli.verbose,
    };

    match cli.command {
        None => run_worker("config/cognidns.toml", launch_options).await,
        Some(TopCommand::Worker(args)) => {
            let config_path = args
                .config
                .or(args.config_path)
                .unwrap_or_else(|| "config/cognidns.toml".to_string());
            run_worker(&config_path, launch_options).await
        }
        Some(TopCommand::Agent { subcmd, opts }) => {
            let start_mode = matches!(subcmd, Some(AgentSubcmd::Start(_)));
            let stop_mode = matches!(subcmd, Some(AgentSubcmd::Stop(_)));
            let effective_opts = match subcmd {
                Some(AgentSubcmd::Start(start_opts)) => AgentOpts {
                    config: start_opts.config.or(opts.config),
                    listen: start_opts.listen.or(opts.listen),
                    token: start_opts.token.or(opts.token),
                },
                Some(AgentSubcmd::Stop(stop_opts)) => AgentOpts {
                    config: stop_opts.config.or(opts.config),
                    listen: stop_opts.listen.or(opts.listen),
                    token: stop_opts.token.or(opts.token),
                },
                None => opts,
            };
            if stop_mode {
                run_agent_stop(effective_opts).await
            } else if start_mode && !launch_options.debug {
                run_agent_detached(effective_opts, launch_options).await
            } else {
                run_agent(effective_opts, launch_options).await
            }
        }
        Some(TopCommand::Ctl(args)) => run_control_cli(args).await,
        Some(TopCommand::Other(args)) => {
            // If the first arg looks like a mistyped subcommand, give a suggestion.
            if let Some(first) = args.first() {
                if !first.contains('/') && !first.contains('\\') && !first.ends_with(".toml") {
                    let known = &["worker", "agent", "ctl"];
                    if let Some(hint) = suggest_close_match(first, known) {
                        anyhow::bail!(
                            "unrecognized subcommand '{}'\n\n  Did you mean '{}'?\n\nRun 'cognidns --help' for usage.",
                            first,
                            hint
                        );
                    }
                }
            }
            // Backward compat: bare config path → run as worker.
            let config_path = args
                .first()
                .map(|s| s.as_str())
                .unwrap_or("config/cognidns.toml");
            run_worker(config_path, launch_options).await
        }
    }
}

/// 启动 worker 服务，加载配置，初始化各模块并启动 UDP/TCP/Admin 服务。
async fn run_worker(config_path: &str, launch_options: LaunchOptions) -> anyhow::Result<()> {
    let mut cfg = AppConfig::load_or_default(config_path)
        .with_context(|| format!("failed to load config from {}", config_path))?;
    cfg.validate()
        .with_context(|| format!("invalid config in {}", config_path))?;
    apply_launch_overrides(&mut cfg, launch_options);
    let _logging = cognidns::logging::init_logging(&cfg)?;

    info!(
        udp = %cfg.udp_listen,
        tcp = %cfg.tcp_listen,
        admin = %cfg.admin_listen,
        mode = %cfg.resolve_mode,
        "starting CogniDNS MVP service"
    );

    let metrics = Arc::new(Metrics::new()?);
    let policy = PolicyEngine::new_with_views(
        PolicyConfig {
            allow_clients: cfg.allow_clients.clone(),
            blocked_domains: cfg.blocked_domains.clone(),
            rate_limit_per_second: cfg.rate_limit_per_second,
            deny_any_queries: cfg.deny_any_queries,
        },
        cfg.views.clone(),
    )?;
    // Build resolver from runtime config and shared cache/runtime collector.
    let response_cache = Arc::new(ResponseCache::new(cfg.response_cache_capacity));
    let trust_anchors = dnssec::load_trust_anchors(
        config_path,
        cfg.dnssec.use_builtin_trust_anchors,
        &cfg.dnssec.trust_anchor_files,
    )?;
    info!(prewarm_source = "startup", "building resolver");
    let mut resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: cfg.resolve_mode.clone(),
            root_servers: cfg.root_servers.clone(),
            iterative_address_family: cfg.iterative_address_family,
            iterative_max_depth: cfg.iterative_max_depth,
            iterative_timeout_ms: cfg.iterative_timeout_ms,
            cname_chain_max_depth: cfg.cname_chain_max_depth,
            follow_cname_chain: cfg.follow_cname_chain,
            static_cname_expand_for_address_queries: cfg.static_cname_expand_for_address_queries,
            iterative_fallback_to_forwarder: cfg.iterative_fallback_to_forwarder,
            iterative_cname_bridge_fallback_to_recursive: cfg
                .iterative_cname_bridge_fallback_to_recursive,
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
            trust_anchors,
            ns_hostname_max_concurrent: cfg.ns_hostname_max_concurrent,
            ns_hostname_enough_endpoints: cfg.ns_hostname_enough_endpoints,
            ns_hostname_per_resolve_ms: cfg.ns_hostname_per_resolve_ms,
            ns_hostname_resolve_mode: cfg.ns_hostname_resolve_mode,
            iterative_per_hop_timeout_ms: cfg.iterative_per_hop_timeout_ms,
            prewarm_delegation_zones: cfg.prewarm_delegation_zones.clone(),
        },
        response_cache.clone(),
        metrics.clone(),
        cfg.static_records.clone(),
        cfg.authoritative_sources.clone(),
    );
    resolver.configure_ip_health(cfg.health_check.clone());
    resolver.configure_minimal_response(cfg.minimal_response);
    resolver.configure_views(&cfg.views);
    resolver.configure_authoritative_zones(&cfg.authoritative_zones);
    let state = AppState::new_with_cache_and_topn(
        policy,
        resolver,
        response_cache,
        metrics,
        config_path.to_string(),
        cfg.topn_stats_enabled,
    );

    // 启动 ns_hostnames 异步预热后台任务（不阻塞启动路径）
    {
        let resolver = state.get_resolver();
        resolver.start_hostname_prewarm();
    }

    let udp_addr = cfg.udp_listen.clone();
    let tcp_addr = cfg.tcp_listen.clone();
    let admin_addr = cfg.admin_listen.clone();
    let dot_listen = cfg.dot.listen.clone();
    let dot_cert = cfg.dot.cert_file.clone();
    let dot_key = cfg.dot.key_file.clone();
    let dot_enabled = cfg.dot.enabled;
    let doh_listen = cfg.doh.listen.clone();
    let doh_enabled = cfg.doh.enabled;

    tokio::select! {
        res = ingress::udp::run_udp_server(&udp_addr, state.clone()) => {
            res?;
        }
        res = ingress::tcp::run_tcp_server(&tcp_addr, state.clone()) => {
            res?;
        }
        res = admin::run_admin_server_with_token(&admin_addr, state.clone(), cfg.control_token.clone()) => {
            res?;
        }
        res = async {
            if dot_enabled {
                ingress::dot::run_dot_server(&dot_listen, &dot_cert, &dot_key, state.clone()).await
            } else {
                std::future::pending::<anyhow::Result<()>>().await
            }
        } => {
            res?;
        }
        res = async {
            if doh_enabled {
                ingress::doh::run_doh_server(&doh_listen, state.clone()).await
            } else {
                std::future::pending::<anyhow::Result<()>>().await
            }
        } => {
            res?;
        }
        _ = state.wait_shutdown() => {
            info!("received shutdown request from control plane");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received Ctrl+C, shutting down");
        }
    }

    Ok(())
}

#[derive(Debug)]
/// Agent 运行时结构体，保存 worker 子进程、配置路径、admin 地址和 token。
struct AgentRuntime {
    worker: Option<Child>,
    config_path: String,
    admin_addr: String,
    token: Option<String>,
    worker_debug: bool,
    worker_verbose: u8,
    shutdown_tx: watch::Sender<bool>,
}

/// 启动 control agent，监听控制端口，处理控制连接。
async fn run_agent(opts: AgentOpts, launch_options: LaunchOptions) -> anyhow::Result<()> {
    let config_path = opts
        .config
        .unwrap_or_else(|| "config/cognidns.toml".to_string());
    let mut cfg = AppConfig::load_or_default(&config_path)
        .with_context(|| format!("failed to load config from {}", config_path))?;
    cfg.validate()
        .with_context(|| format!("invalid config in {}", config_path))?;
    apply_launch_overrides(&mut cfg, launch_options);
    let _logging = cognidns::logging::init_logging(&cfg)?;
    let listen_addr = opts.listen.unwrap_or(cfg.control_listen.clone());
    let token = opts.token.or_else(|| cfg.control_token.clone());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let runtime = Arc::new(Mutex::new(AgentRuntime {
        worker: None,
        config_path,
        admin_addr: normalize_connect_addr(&cfg.admin_listen),
        token,
        worker_debug: launch_options.debug,
        worker_verbose: launch_options.verbose,
        shutdown_tx,
    }));

    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            warn!(
                listen = %listen_addr,
                "control agent already running on the target listen address"
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    // Auto-start worker so launching `agent` is immediately query-ready.
    // Run this only after control port bind succeeds, to avoid duplicate spawn attempts
    // when another agent instance is already running.
    let _ = ensure_worker_started(runtime.clone()).await?;

    info!(listen = %listen_addr, "control agent listening");
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("control agent received shutdown signal");
                    break;
                }
            }
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => info!("control agent received Ctrl+C"),
                    Err(err) => warn!(error = %err, "failed to listen for Ctrl+C; shutting down agent"),
                }
                break;
            }
            accept_result = listener.accept() => {
                let (socket, peer) = match accept_result {
                    Ok(value) => value,
                    Err(err) => {
                        warn!(error = %err, "control agent accept failed; keep listening");
                        continue;
                    }
                };
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_control_connection(socket, runtime).await {
                        info!(peer = %peer, error = %err, "control request handling failed");
                    }
                });
            }
        }
    }

    shutdown_runtime_worker(&runtime).await;
    info!("control agent stopped");
    Ok(())
}

/// 处理单个控制连接，读取请求、鉴权、执行命令并返回响应。
async fn handle_control_connection(
    mut socket: TokioTcpStream,
    runtime: Arc<Mutex<AgentRuntime>>,
) -> anyhow::Result<()> {
    let request = match read_request(&mut socket).await {
        Ok(v) => v,
        Err(err) => {
            let _ = write_response(
                &mut socket,
                &ControlResponse::error(CODE_INVALID_REQUEST, format!("invalid request: {err}")),
            )
            .await;
            return Ok(());
        }
    };

    if request.version != CONTROL_PROTOCOL_VERSION {
        write_response(
            &mut socket,
            &ControlResponse::error(
                CODE_UNSUPPORTED_VERSION,
                format!(
                    "unsupported protocol version {}, expected {}",
                    request.version, CONTROL_PROTOCOL_VERSION
                ),
            ),
        )
        .await?;
        return Ok(());
    }

    if !is_authorized(&runtime, request.token.as_deref()).await {
        write_response(
            &mut socket,
            &ControlResponse::error(CODE_UNAUTHORIZED, "unauthorized"),
        )
        .await?;
        return Ok(());
    }

    let response = execute_control_command(runtime, request.command).await;
    write_response(&mut socket, &response).await?;
    Ok(())
}

/// 校验控制请求的 token 是否有效。
async fn is_authorized(runtime: &Arc<Mutex<AgentRuntime>>, request_token: Option<&str>) -> bool {
    let expected = runtime.lock().await.token.clone();
    match expected {
        Some(v) => request_token.map(|t| t == v).unwrap_or(false),
        None => true,
    }
}

/// 执行控制命令，根据命令类型启动/停止 worker 或代理到 admin。
async fn execute_control_command(
    runtime: Arc<Mutex<AgentRuntime>>,
    command: ControlCommand,
) -> ControlResponse {
    match command {
        ControlCommand::Start => match ensure_worker_started(runtime).await {
            Ok(true) => ControlResponse::ok("worker started", None),
            Ok(false) => ControlResponse::ok("worker already running", None),
            Err(err) => ControlResponse::error(CODE_START_FAILED, format!("{err}")),
        },
        ControlCommand::Stop => {
            let (child_opt, admin_addr, token) = {
                let mut guard = runtime.lock().await;
                (
                    guard.worker.take(),
                    guard.admin_addr.clone(),
                    guard.token.clone(),
                )
            };

            let Some(child) = child_opt else {
                return ControlResponse::ok("worker not running", None);
            };
            stop_worker(child, &admin_addr, token.as_deref()).await
        }
        ControlCommand::StopAll => {
            let (child_opt, admin_addr, token, shutdown_tx) = {
                let mut guard = runtime.lock().await;
                (
                    guard.worker.take(),
                    guard.admin_addr.clone(),
                    guard.token.clone(),
                    guard.shutdown_tx.clone(),
                )
            };

            let response = match child_opt {
                Some(child) => stop_worker(child, &admin_addr, token.as_deref()).await,
                None => ControlResponse::ok("worker not running", None),
            };
            let _ = shutdown_tx.send(true);

            if response.status.eq_ignore_ascii_case("error") {
                response
            } else if response.message == "worker not running" {
                ControlResponse::ok("agent shutting down", None)
            } else {
                ControlResponse::ok(format!("{}; agent shutting down", response.message), None)
            }
        }
        ControlCommand::Reload => proxy_admin(runtime, "POST", "/reload", None).await,
        ControlCommand::Stats => proxy_admin(runtime, "GET", "/stats", None).await,
        ControlCommand::Health => proxy_admin(runtime, "GET", "/health", None).await,
        ControlCommand::Ready => proxy_admin(runtime, "GET", "/ready", None).await,
        ControlCommand::CacheFreezeAll { enabled } => {
            proxy_admin_dynamic(
                runtime,
                "POST",
                "/cache/freeze/all",
                Some(serde_json::json!({ "enabled": enabled }).to_string()),
            )
            .await
        }
        ControlCommand::CacheFreezeDomain { domain, enabled } => {
            proxy_admin_dynamic(
                runtime,
                "POST",
                "/cache/freeze/domain",
                Some(serde_json::json!({ "domain": domain, "enabled": enabled }).to_string()),
            )
            .await
        }
        ControlCommand::CacheClearAll => {
            proxy_admin_dynamic(runtime, "POST", "/cache/clear/all", None).await
        }
        ControlCommand::CacheClearDomain { domain } => {
            proxy_admin_dynamic(
                runtime,
                "POST",
                "/cache/clear/domain",
                Some(serde_json::json!({ "domain": domain }).to_string()),
            )
            .await
        }
        ControlCommand::CacheExport => {
            proxy_admin_dynamic(runtime, "GET", "/cache/export", None).await
        }
        ControlCommand::CacheImport { dump } => {
            proxy_admin_dynamic(
                runtime,
                "POST",
                "/cache/import",
                Some(serde_json::to_string(&dump).unwrap_or_else(|_| "{}".to_string())),
            )
            .await
        }
        ControlCommand::TopQueries { n, window_secs } => {
            proxy_admin_dynamic(
                runtime,
                "GET",
                &format!("/stats/top-queries?n={n}&window={window_secs}"),
                None,
            )
            .await
        }
        ControlCommand::TopClients { n, window_secs } => {
            proxy_admin_dynamic(
                runtime,
                "GET",
                &format!("/stats/top-clients?n={n}&window={window_secs}"),
                None,
            )
            .await
        }
        ControlCommand::Version => ControlResponse::ok(
            "version info",
            Some(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": "control-v1-json-len32"
            })),
        ),
    }
}

async fn shutdown_runtime_worker(runtime: &Arc<Mutex<AgentRuntime>>) {
    let (child_opt, admin_addr, token) = {
        let mut guard = runtime.lock().await;
        (
            guard.worker.take(),
            guard.admin_addr.clone(),
            guard.token.clone(),
        )
    };

    let Some(child) = child_opt else {
        return;
    };

    let response = stop_worker(child, &admin_addr, token.as_deref()).await;
    if response.status.eq_ignore_ascii_case("error") {
        warn!(message = %response.message, code = %response.code, "failed to stop worker during agent shutdown");
    }
}

async fn ensure_worker_started(runtime: Arc<Mutex<AgentRuntime>>) -> anyhow::Result<bool> {
    let (config_path, worker_debug, worker_verbose) = {
        let mut guard = runtime.lock().await;
        if worker_running(&mut guard.worker) {
            return Ok(false);
        }
        (
            guard.config_path.clone(),
            guard.worker_debug,
            guard.worker_verbose,
        )
    };

    let exe = std::env::current_exe().context("failed to locate executable")?;
    let mut command = Command::new(exe);
    command.arg("worker");
    if worker_debug {
        command.arg("--debug");
    }
    for _ in 0..worker_verbose {
        command.arg("-v");
    }
    command.arg("--config").arg(config_path);

    if worker_debug {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    } else {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        apply_background_spawn(&mut command);
    }

    let child = command.spawn().context("failed to spawn worker process")?;
    let mut guard = runtime.lock().await;
    guard.worker = Some(child);
    Ok(true)
}

/// 代理请求到 admin 服务（静态 path 版本）。
async fn proxy_admin(
    runtime: Arc<Mutex<AgentRuntime>>,
    method: &'static str,
    path: &'static str,
    body: Option<String>,
) -> ControlResponse {
    proxy_admin_dynamic(runtime, method, path, body).await
}

/// 代理请求到 admin 服务（动态 path 版本），支持自定义 body。
async fn proxy_admin_dynamic(
    runtime: Arc<Mutex<AgentRuntime>>,
    method: &'static str,
    path: &str,
    body: Option<String>,
) -> ControlResponse {
    let (admin_addr, token) = {
        let guard = runtime.lock().await;
        (guard.admin_addr.clone(), guard.token.clone())
    };
    let path = path.to_string();
    let body_clone = body.clone();
    let result = tokio::task::spawn_blocking(move || {
        http_json_request(
            &admin_addr,
            method,
            &path,
            body_clone.as_deref(),
            token.as_deref(),
        )
    })
    .await;

    match result {
        Ok(Ok(raw)) => {
            let data = serde_json::from_str::<Value>(&raw).unwrap_or(Value::String(raw));
            ControlResponse::ok("admin request success", Some(data))
        }
        Ok(Err(err)) => ControlResponse::error(
            CODE_ADMIN_PROXY_FAILED,
            format!("admin request failed: {err}"),
        ),
        Err(err) => ControlResponse::error(
            CODE_ADMIN_PROXY_FAILED,
            format!("admin worker join error: {err}"),
        ),
    }
}

/// 停止 worker 子进程，优雅关闭，超时则强制杀死。
async fn stop_worker(mut child: Child, admin_addr: &str, token: Option<&str>) -> ControlResponse {
    let admin_addr_owned = admin_addr.to_string();
    let token_owned = token.map(|value| value.to_string());
    let _ = tokio::task::spawn_blocking(move || {
        http_json_request(
            &admin_addr_owned,
            "POST",
            "/shutdown",
            None,
            token_owned.as_deref(),
        )
    })
    .await;

    match child.try_wait() {
        Ok(Some(_)) => return ControlResponse::ok("worker already exited", None),
        Ok(None) => {}
        Err(err) => {
            return ControlResponse::error(
                CODE_STOP_FAILED,
                format!("failed to inspect worker state: {err}"),
            );
        }
    }

    match timeout(Duration::from_secs(3), child.wait()).await {
        Ok(Ok(_)) => ControlResponse::ok("worker stopped gracefully", None),
        Ok(Err(err)) => {
            ControlResponse::error(CODE_STOP_FAILED, format!("worker wait failed: {err}"))
        }
        Err(_) => {
            if let Err(err) = child.kill().await {
                return ControlResponse::error(
                    CODE_STOP_FAILED,
                    format!("graceful stop timeout and kill failed: {err}"),
                );
            }
            if let Err(err) = child.wait().await {
                return ControlResponse::error(
                    CODE_STOP_FAILED,
                    format!("worker wait after kill failed: {err}"),
                );
            }
            ControlResponse::ok("worker stopped by force after timeout", None)
        }
    }
}

/// 判断 worker 子进程是否正在运行。
fn worker_running(worker: &mut Option<Child>) -> bool {
    let Some(child) = worker.as_mut() else {
        return false;
    };
    match child.try_wait() {
        Ok(None) => true,
        Ok(Some(_)) => {
            *worker = None;
            false
        }
        Err(_) => false,
    }
}

/// 将监听地址中的 0.0.0.0 或 [::] 转换为本地回环地址。
fn normalize_connect_addr(listen_addr: &str) -> String {
    if let Some(port) = listen_addr.strip_prefix("0.0.0.0:") {
        return format!("127.0.0.1:{port}");
    }
    if let Some(port) = listen_addr.strip_prefix("[::]:") {
        return format!("[::1]:{port}");
    }
    listen_addr.to_string()
}

/// 控制命令行入口，解析参数并向 control agent 发送请求。
async fn run_control_cli(args: CtlArgs) -> anyhow::Result<()> {
    let config_path = args
        .config
        .unwrap_or_else(|| "config/cognidns.toml".to_string());
    let cfg = CtlConfig::load_or_default(&config_path)
        .with_context(|| format!("failed to load control config from {}", config_path))?;

    let server = args.server.unwrap_or(cfg.server.clone());
    let token = args.token.or_else(|| cfg.token.clone());
    let (command, cache_export_out, is_top_queries, is_top_clients) = match args.command {
        CtlCommand::Start => (ControlCommand::Start, None, false, false),
        CtlCommand::Stop(stop_args) => (
            if stop_args.all {
                ControlCommand::StopAll
            } else {
                ControlCommand::Stop
            },
            None,
            false,
            false,
        ),
        CtlCommand::Reload => (ControlCommand::Reload, None, false, false),
        CtlCommand::Stats => (ControlCommand::Stats, None, false, false),
        CtlCommand::Health => (ControlCommand::Health, None, false, false),
        CtlCommand::Ready => (ControlCommand::Ready, None, false, false),
        CtlCommand::Version => (ControlCommand::Version, None, false, false),
        CtlCommand::Top(top_args) => match top_args.command {
            TopCtlCommand::Queries(query_args) => (
                ControlCommand::TopQueries {
                    n: query_args.n,
                    window_secs: query_args.window_secs,
                },
                None,
                true,
                false,
            ),
            TopCtlCommand::Clients(client_args) => (
                ControlCommand::TopClients {
                    n: client_args.n,
                    window_secs: client_args.window_secs,
                },
                None,
                false,
                true,
            ),
        },
        CtlCommand::Cache(cache_args) => {
            match cache_args.command {
                CacheCommand::Freeze(freeze_args) => match freeze_args.target {
                    CacheFreezeTarget::All(toggle_args) => (
                        ControlCommand::CacheFreezeAll {
                            enabled: toggle_args.state.enabled(),
                        },
                        None,
                        false,
                        false,
                    ),
                    CacheFreezeTarget::Domain(domain_args) => (
                        ControlCommand::CacheFreezeDomain {
                            domain: domain_args.domain,
                            enabled: domain_args.state.enabled(),
                        },
                        None,
                        false,
                        false,
                    ),
                },
                CacheCommand::Clear(clear_args) => {
                    let command = match (clear_args.target, clear_args.domain) {
                        (Some(CacheClearTarget::All), None) | (None, None) => {
                            ControlCommand::CacheClearAll
                        }
                        (Some(CacheClearTarget::Domain(domain_args)), None) => {
                            ControlCommand::CacheClearDomain {
                                domain: domain_args.domain,
                            }
                        }
                        (None, Some(domain)) => ControlCommand::CacheClearDomain { domain },
                        (Some(CacheClearTarget::All), Some(_))
                        | (Some(CacheClearTarget::Domain(_)), Some(_)) => {
                            anyhow::bail!("cache clear accepts either a target or a domain shorthand, not both")
                        }
                    };
                    (command, None, false, false)
                }
                CacheCommand::Export(export_args) => (
                    ControlCommand::CacheExport,
                    Some(export_args.out),
                    false,
                    false,
                ),
                CacheCommand::Import(import_args) => {
                    let raw = std::fs::read_to_string(&import_args.input).with_context(|| {
                        format!("failed to read cache dump from {}", import_args.input)
                    })?;
                    let dump = serde_json::from_str(&raw).with_context(|| {
                        format!("failed to parse cache dump json from {}", import_args.input)
                    })?;
                    (ControlCommand::CacheImport { dump }, None, false, false)
                }
            }
        }
    };

    let request = ControlRequest {
        version: CONTROL_PROTOCOL_VERSION,
        token,
        command,
    };
    let response = timeout(
        Duration::from_millis(cfg.timeout_ms),
        send_request(&server, &request),
    )
    .await
    .with_context(|| {
        format!(
            "control request timed out after {} ms when connecting to {}",
            cfg.timeout_ms, server
        )
    })??;

    if response.status.eq_ignore_ascii_case("error") {
        if response.code == CODE_UNAUTHORIZED {
            anyhow::bail!(
                "control command unauthorized: server={} config={} message={}. \
                 The running agent and ctl must use the same control_token. \
                 If the agent was started with another config file, rerun ctl with --config <same-config> \
                 or pass --token <same-token> explicitly.",
                server,
                config_path,
                response.message
            );
        }

        anyhow::bail!(
            "control command failed: server={} code={} message={}",
            server,
            response.code,
            response.message
        );
    }

    if let Some(output) = cache_export_out {
        let Some(data) = response.data.as_ref() else {
            anyhow::bail!("cache export missing response data");
        };
        let payload = serde_json::to_vec_pretty(data)
            .with_context(|| "failed to serialize cache export payload")?;
        std::fs::write(&output, payload)
            .with_context(|| format!("failed to write cache dump to {}", output))?;
    }

    if is_top_queries || is_top_clients {
        ctl_cli::print_top_response(&response, is_top_queries);
        return Ok(());
    }

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// 发送 HTTP JSON 请求到 admin 服务，返回响应体。
fn http_json_request(
    admin: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(admin)?;
    let payload = body.unwrap_or("");
    let auth_header = token
        .filter(|value| !value.is_empty())
        .map(|value| format!("Authorization: Bearer {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
        method,
        path,
        admin,
        auth_header,
        payload.len(),
        payload
    );
    stream.write_all(request.as_bytes())?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let mut parts = text.splitn(2, "\r\n\r\n");
    let headers = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();
    if !headers.contains(" 200 ") {
        anyhow::bail!(
            "request failed: {}",
            headers.lines().next().unwrap_or("unknown error")
        );
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{
        edit_distance, handle_control_connection, normalize_connect_addr, suggest_close_match,
        AgentOpts, AgentRuntime, AgentSubcmd, CacheArgs, CacheClearArgs, CacheCommand, Cli,
        CtlArgs, CtlCommand, CtlStopArgs, TopArgs, TopCommand, TopCtlCommand, TopWindowArgs,
        WorkerArgs,
    };
    use clap::Parser;
    use cognidns::control::{
        ControlCommand, ControlRequest, ControlResponse, CODE_INVALID_REQUEST, CODE_UNAUTHORIZED,
        CODE_UNSUPPORTED_VERSION, CONTROL_PROTOCOL_VERSION,
    };
    use cognidns::ctl_cli;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream as TokioTcpStream};
    use tokio::process::Child;
    use tokio::sync::Mutex;

    #[test]
    fn normalize_wildcard_ipv4_to_loopback() {
        assert_eq!(normalize_connect_addr("0.0.0.0:8080"), "127.0.0.1:8080");
    }

    #[test]
    fn normalize_wildcard_ipv6_to_loopback() {
        assert_eq!(normalize_connect_addr("[::]:8080"), "[::1]:8080");
    }

    #[test]
    fn cli_parses_global_debug_and_verbose() {
        let cli = Cli::try_parse_from(["cognidns", "-d", "-vv"]).unwrap();
        assert!(cli.debug);
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn cli_parses_long_verbose_repeatable() {
        let cli = Cli::try_parse_from(["cognidns", "--verbose", "--verbose", "--verbose"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn cli_parses_worker_with_config_flag() {
        let cli =
            Cli::try_parse_from(["cognidns", "worker", "--config", "config/test.toml"]).unwrap();
        let Some(TopCommand::Worker(WorkerArgs { config, .. })) = cli.command else {
            panic!("expected Worker")
        };
        assert_eq!(config, Some("config/test.toml".to_string()));
    }

    #[test]
    fn cli_parses_worker_with_positional_config() {
        let cli = Cli::try_parse_from(["cognidns", "worker", "config/test.toml"]).unwrap();
        let Some(TopCommand::Worker(WorkerArgs { config_path, .. })) = cli.command else {
            panic!("expected Worker")
        };
        assert_eq!(config_path, Some("config/test.toml".to_string()));
    }

    #[test]
    fn cli_parses_agent_start_backward_compat() {
        let cli = Cli::try_parse_from([
            "cognidns",
            "agent",
            "start",
            "--config",
            "config/cognidns.toml",
        ])
        .unwrap();
        let Some(TopCommand::Agent { subcmd, .. }) = cli.command else {
            panic!("expected Agent")
        };
        let Some(AgentSubcmd::Start(AgentOpts { config, .. })) = subcmd else {
            panic!("expected Start subcmd")
        };
        assert_eq!(config, Some("config/cognidns.toml".to_string()));
    }

    #[test]
    fn cli_parses_agent_direct_config() {
        let cli =
            Cli::try_parse_from(["cognidns", "agent", "--config", "config/cognidns.toml"]).unwrap();
        let Some(TopCommand::Agent { subcmd: None, opts }) = cli.command else {
            panic!("expected Agent without subcmd")
        };
        assert_eq!(opts.config, Some("config/cognidns.toml".to_string()));
    }

    #[test]
    fn cli_parses_global_verbose_after_subcommand() {
        let cli = Cli::try_parse_from([
            "cognidns",
            "agent",
            "--config",
            "config/cognidns.toml",
            "-v",
        ])
        .unwrap();
        assert_eq!(cli.verbose, 1);
    }

    #[test]
    fn cli_parses_agent_stop() {
        let cli = Cli::try_parse_from([
            "cognidns",
            "agent",
            "stop",
            "--config",
            "config/cognidns.toml",
        ])
        .unwrap();
        let Some(TopCommand::Agent { subcmd, .. }) = cli.command else {
            panic!("expected Agent")
        };
        let Some(AgentSubcmd::Stop(AgentOpts { config, .. })) = subcmd else {
            panic!("expected Stop subcmd")
        };
        assert_eq!(config, Some("config/cognidns.toml".to_string()));
    }

    #[test]
    fn cli_parses_ctl_stop_all() {
        let cli = Cli::try_parse_from([
            "cognidns",
            "ctl",
            "stop",
            "--all",
            "--config",
            "config/cognidns.toml",
        ])
        .unwrap();
        let Some(TopCommand::Ctl(CtlArgs {
            config, command, ..
        })) = cli.command
        else {
            panic!("expected Ctl")
        };
        assert_eq!(config, Some("config/cognidns.toml".to_string()));
        let CtlCommand::Stop(CtlStopArgs { all }) = command else {
            panic!("expected Stop")
        };
        assert!(all);
    }

    #[test]
    fn cli_parses_ctl_top_queries() {
        let cli = Cli::try_parse_from([
            "cognidns", "ctl", "top", "queries", "--top", "25", "--window", "120",
        ])
        .unwrap();
        let Some(TopCommand::Ctl(CtlArgs { command, .. })) = cli.command else {
            panic!("expected Ctl")
        };
        let CtlCommand::Top(TopArgs { command }) = command else {
            panic!("expected Top")
        };
        let TopCtlCommand::Queries(TopWindowArgs { n, window_secs }) = command else {
            panic!("expected top queries")
        };
        assert_eq!(n, 25);
        assert_eq!(window_secs, 120);
    }

    #[test]
    fn cli_parses_ctl_cache_clear_shorthand() {
        let cli = Cli::try_parse_from(["cognidns", "ctl", "cache", "clear", "www.qq.com"]).unwrap();
        let Some(TopCommand::Ctl(CtlArgs { command, .. })) = cli.command else {
            panic!("expected Ctl")
        };
        let CtlCommand::Cache(CacheArgs { command }) = command else {
            panic!("expected Cache")
        };
        let CacheCommand::Clear(CacheClearArgs {
            target: None,
            domain,
        }) = command
        else {
            panic!("expected clear shorthand")
        };
        assert_eq!(domain, Some("www.qq.com".to_string()));
    }

    #[test]
    fn cli_rejects_unknown_global_flag() {
        let err = Cli::try_parse_from(["cognidns", "--unknown-flag"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unexpected argument") || msg.contains("--unknown-flag"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn cli_suggests_fix_for_unknown_worker_flag() {
        // clap should catch unknown flags in the worker subcommand
        let err = Cli::try_parse_from(["cognidns", "worker", "--conifg", "foo"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--conifg") || msg.contains("unexpected"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn edit_distance_exact_match_is_zero() {
        assert_eq!(edit_distance("worker", "worker"), 0);
    }

    #[test]
    fn edit_distance_one_substitution() {
        assert_eq!(edit_distance("agant", "agent"), 1);
    }

    #[test]
    fn edit_distance_transposition() {
        // "worekr" vs "worker": swap e and k = 2 operations
        assert!(edit_distance("worekr", "worker") <= 2);
    }

    #[test]
    fn suggest_close_match_finds_typo() {
        let known = &["worker", "agent", "ctl"];
        assert_eq!(suggest_close_match("workre", known), Some("worker"));
        assert_eq!(suggest_close_match("agant", known), Some("agent"));
    }

    #[test]
    fn suggest_close_match_returns_none_for_garbage() {
        let known = &["worker", "agent", "ctl"];
        assert_eq!(suggest_close_match("xyzqwerty", known), None);
    }

    #[test]
    fn parse_cache_clear_domain_shorthand() {
        let args = vec![
            "cache".to_string(),
            "clear".to_string(),
            "www.qq.com".to_string(),
        ];
        let cmd = ctl_cli::parse_cache_command(&args, "cargo run -- ctl")
            .expect("should parse clear shorthand");
        assert!(matches!(
            cmd,
            ControlCommand::CacheClearDomain { domain } if domain == "www.qq.com"
        ));
    }

    #[test]
    fn parse_cache_clear_without_target_defaults_to_all() {
        let args = vec!["cache".to_string(), "clear".to_string()];
        let cmd = ctl_cli::parse_cache_command(&args, "cargo run -- ctl")
            .expect("should parse clear all by default");
        assert!(matches!(cmd, ControlCommand::CacheClearAll));
    }

    #[test]
    fn parse_top_queries_defaults() {
        let args = vec!["top".to_string(), "queries".to_string()];
        let cmd = ctl_cli::parse_top_command(&args, "cargo run -- ctl")
            .expect("should parse top queries defaults");
        assert!(matches!(
            cmd,
            ControlCommand::TopQueries { n, window_secs } if n == 10 && window_secs == 300
        ));
    }

    #[test]
    fn parse_top_clients_with_overrides() {
        let args = vec![
            "top".to_string(),
            "clients".to_string(),
            "--top".to_string(),
            "25".to_string(),
            "--window".to_string(),
            "120".to_string(),
        ];
        let cmd = ctl_cli::parse_top_command(&args, "cargo run -- ctl")
            .expect("should parse top clients overrides");
        assert!(matches!(
            cmd,
            ControlCommand::TopClients { n, window_secs } if n == 25 && window_secs == 120
        ));
    }

    fn make_agent_runtime(token: Option<&str>) -> Arc<Mutex<AgentRuntime>> {
        make_agent_runtime_with_admin(token, "127.0.0.1:65535")
    }

    fn make_agent_runtime_with_admin(
        token: Option<&str>,
        admin_addr: &str,
    ) -> Arc<Mutex<AgentRuntime>> {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        Arc::new(Mutex::new(AgentRuntime {
            worker: Option::<Child>::None,
            config_path: "config/cognidns.toml".to_string(),
            admin_addr: admin_addr.to_string(),
            token: token.map(|value| value.to_string()),
            worker_debug: false,
            worker_verbose: 0,
            shutdown_tx,
        }))
    }

    async fn spawn_mock_admin_server(
        expected_auth: Option<&str>,
        response_body: &'static str,
        request_count: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind admin listener");
        let addr = listener.local_addr().expect("admin local addr");
        let expected_auth = expected_auth.map(|value| value.to_string());
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept admin connection");
            let mut buf = [0u8; 4096];
            let mut raw = Vec::new();
            loop {
                let len = socket.read(&mut buf).await.expect("read admin request");
                if len == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..len]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            request_count.fetch_add(1, Ordering::SeqCst);
            let request_text = String::from_utf8(raw).expect("utf8 admin request");
            if let Some(expected) = expected_auth.as_deref() {
                assert!(
                    request_text.contains(&format!("Authorization: Bearer {expected}\r\n")),
                    "expected bearer token in admin proxy request"
                );
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write admin response");
        });
        (addr.to_string(), handle)
    }

    async fn spawn_mock_admin_server_with_expectation(
        expected_auth: Option<&str>,
        expected_request_line_fragment: &'static str,
        response_body: &'static str,
        request_count: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind admin listener");
        let addr = listener.local_addr().expect("admin local addr");
        let expected_auth = expected_auth.map(|value| value.to_string());
        let expected_request_line_fragment = expected_request_line_fragment.to_string();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept admin connection");
            let mut buf = [0u8; 4096];
            let mut raw = Vec::new();
            loop {
                let len = socket.read(&mut buf).await.expect("read admin request");
                if len == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..len]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            request_count.fetch_add(1, Ordering::SeqCst);
            let request_text = String::from_utf8(raw).expect("utf8 admin request");
            assert!(
                request_text.contains(&expected_request_line_fragment),
                "unexpected admin request path/method: {}",
                request_text
            );
            if let Some(expected) = expected_auth.as_deref() {
                assert!(
                    request_text.contains(&format!("Authorization: Bearer {expected}\r\n")),
                    "expected bearer token in admin proxy request"
                );
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write admin response");
        });
        (addr.to_string(), handle)
    }

    async fn send_raw_control_payload(
        payload: &[u8],
        runtime: Arc<Mutex<AgentRuntime>>,
    ) -> ControlResponse {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept connection");
            handle_control_connection(socket, runtime)
                .await
                .expect("handle control connection");
        });

        let mut client = TokioTcpStream::connect(addr).await.expect("connect client");
        client
            .write_u32(payload.len() as u32)
            .await
            .expect("write len");
        client.write_all(payload).await.expect("write payload");

        let len = client.read_u32().await.expect("read response len") as usize;
        let mut body = vec![0u8; len];
        client
            .read_exact(&mut body)
            .await
            .expect("read response body");
        server.await.expect("join server");
        serde_json::from_slice(&body).expect("decode control response")
    }

    #[tokio::test]
    async fn control_connection_rejects_unauthorized_request() {
        let payload = serde_json::to_vec(&ControlRequest {
            version: CONTROL_PROTOCOL_VERSION,
            token: Some("wrong".to_string()),
            command: ControlCommand::Health,
        })
        .expect("serialize request");

        let response =
            send_raw_control_payload(&payload, make_agent_runtime(Some("expected"))).await;
        assert_eq!(response.status, "error");
        assert_eq!(response.code, CODE_UNAUTHORIZED);
    }

    #[tokio::test]
    async fn control_connection_rejects_unsupported_version() {
        let payload = serde_json::to_vec(&ControlRequest {
            version: CONTROL_PROTOCOL_VERSION + 1,
            token: Some("expected".to_string()),
            command: ControlCommand::Health,
        })
        .expect("serialize request");

        let response =
            send_raw_control_payload(&payload, make_agent_runtime(Some("expected"))).await;
        assert_eq!(response.status, "error");
        assert_eq!(response.code, CODE_UNSUPPORTED_VERSION);
    }

    #[tokio::test]
    async fn control_connection_rejects_malformed_frame_payload() {
        let response = send_raw_control_payload(br#"{not-json}"#, make_agent_runtime(None)).await;
        assert_eq!(response.status, "error");
        assert_eq!(response.code, CODE_INVALID_REQUEST);
    }

    #[tokio::test]
    async fn control_connection_rejects_unauthorized_request_before_admin_proxy() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let (admin_addr, admin_handle) = spawn_mock_admin_server(
            Some("expected"),
            r#"{"status":"ok"}"#,
            request_count.clone(),
        )
        .await;

        let payload = serde_json::to_vec(&ControlRequest {
            version: CONTROL_PROTOCOL_VERSION,
            token: Some("wrong".to_string()),
            command: ControlCommand::Stats,
        })
        .expect("serialize request");

        let response = send_raw_control_payload(
            &payload,
            make_agent_runtime_with_admin(Some("expected"), &admin_addr),
        )
        .await;
        assert_eq!(response.status, "error");
        assert_eq!(response.code, CODE_UNAUTHORIZED);
        assert_eq!(request_count.load(Ordering::SeqCst), 0);

        admin_handle.abort();
    }

    #[tokio::test]
    async fn control_connection_authorized_request_proxies_admin_with_token() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let (admin_addr, admin_handle) = spawn_mock_admin_server(
            Some("expected"),
            r#"{"status":"ok","resolver":{"healthy_upstreams":1}}"#,
            request_count.clone(),
        )
        .await;

        let payload = serde_json::to_vec(&ControlRequest {
            version: CONTROL_PROTOCOL_VERSION,
            token: Some("expected".to_string()),
            command: ControlCommand::Stats,
        })
        .expect("serialize request");

        let response = send_raw_control_payload(
            &payload,
            make_agent_runtime_with_admin(Some("expected"), &admin_addr),
        )
        .await;
        assert_eq!(response.status, "ok");
        assert_eq!(response.code, "ok");
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
        let data = response.data.expect("expected proxied admin data");
        assert_eq!(data["resolver"]["healthy_upstreams"], 1);

        admin_handle.await.expect("join admin server");
    }

    #[tokio::test]
    async fn control_connection_proxies_top_queries_with_expected_path_and_token() {
        let request_count = Arc::new(AtomicUsize::new(0));
        let (admin_addr, admin_handle) = spawn_mock_admin_server_with_expectation(
            Some("expected"),
            "GET /stats/top-queries?n=7&window=120 HTTP/1.1",
            r#"{"status":"ok","enabled":true,"entries":[]}"#,
            request_count.clone(),
        )
        .await;

        let payload = serde_json::to_vec(&ControlRequest {
            version: CONTROL_PROTOCOL_VERSION,
            token: Some("expected".to_string()),
            command: ControlCommand::TopQueries {
                n: 7,
                window_secs: 120,
            },
        })
        .expect("serialize request");

        let response = send_raw_control_payload(
            &payload,
            make_agent_runtime_with_admin(Some("expected"), &admin_addr),
        )
        .await;
        assert_eq!(response.status, "ok");
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        admin_handle.await.expect("join admin server");
    }
}
