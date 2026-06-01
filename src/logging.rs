//! Logging bootstrap with category-specific files and levels.
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use anyhow::Context;
use chrono::Local;
use tracing::Level;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use crate::config::AppConfig;

static TRACE_QUERY_DOMAINS: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

fn trace_query_domains_store() -> &'static RwLock<Vec<String>> {
    TRACE_QUERY_DOMAINS.get_or_init(|| RwLock::new(Vec::new()))
}

fn normalize_trace_domain(domain: &str) -> Option<String> {
    let normalized = domain
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// 根据配置刷新“低损耗定向追踪”的域名后缀列表。
pub fn refresh_trace_query_domains(config: &AppConfig) {
    let store = trace_query_domains_store();
    let mut domains = config
        .logging
        .trace_query_domains
        .iter()
        .filter_map(|d| normalize_trace_domain(d))
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    if !config.logging.enabled {
        domains.clear();
    }
    if let Ok(mut guard) = store.write() {
        *guard = domains;
    }
}

/// 是否应对该查询名输出低损耗定向追踪日志。
pub fn should_trace_query_name(qname: &str) -> bool {
    let normalized_qname = qname.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized_qname.is_empty() {
        return false;
    }
    let Ok(guard) = trace_query_domains_store().read() else {
        return false;
    };
    if guard.is_empty() {
        return false;
    }
    guard.iter().any(|suffix| {
        normalized_qname == *suffix
            || normalized_qname
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

pub struct LoggingGuards {
    _guards: Vec<()>,
}

#[derive(Clone)]
struct ResilientDailyMakeWriter {
    directory: PathBuf,
    base_name: String,
}

impl ResilientDailyMakeWriter {
    fn new(directory: impl Into<PathBuf>, base_name: &str) -> Self {
        Self {
            directory: directory.into(),
            base_name: base_name.to_string(),
        }
    }

    fn current_log_path(&self) -> PathBuf {
        let date = Local::now().format("%Y-%m-%d").to_string();
        self.directory.join(format!("{}.{}", self.base_name, date))
    }
}

struct ResilientDailyWriter {
    path: PathBuf,
}

impl Write for ResilientDailyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for ResilientDailyMakeWriter {
    type Writer = ResilientDailyWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ResilientDailyWriter {
            path: self.current_log_path(),
        }
    }
}

#[derive(Copy, Clone)]
enum ConfigLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// 初始化日志系统，根据配置输出到不同文件和格式。
pub fn init_logging(config: &AppConfig) -> anyhow::Result<LoggingGuards> {
    refresh_trace_query_domains(config);

    if !config.logging.enabled {
        let subscriber = tracing_subscriber::registry();
        subscriber
            .try_init()
            .context("failed to initialize disabled logging subscriber")?;
        return Ok(LoggingGuards {
            _guards: Vec::new(),
        });
    }

    let query_level = parse_level(&config.logging.query_level, "logging.query_level")?;
    let response_level = parse_level(&config.logging.response_level, "logging.response_level")?;
    let general_level = parse_level(&config.logging.general_level, "logging.general_level")?;
    let json_format = config.logging.format.eq_ignore_ascii_case("json");

    fs::create_dir_all(&config.logging.directory).with_context(|| {
        format!(
            "failed to create logging directory: {}",
            config.logging.directory
        )
    })?;

    let query_writer = ResilientDailyMakeWriter::new(&config.logging.directory, "query.log");
    let response_writer = ResilientDailyMakeWriter::new(&config.logging.directory, "response.log");
    let general_writer = ResilientDailyMakeWriter::new(&config.logging.directory, "general.log");

    if json_format {
        let query_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(query_writer)
            .json()
            .flatten_event(true)
            .with_filter(filter_fn(move |meta| {
                meta.target() == "query" && level_enabled(query_level, meta.level())
            }));

        let response_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(response_writer)
            .json()
            .flatten_event(true)
            .with_filter(filter_fn(move |meta| {
                meta.target() == "response" && level_enabled(response_level, meta.level())
            }));

        let general_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(general_writer)
            .json()
            .flatten_event(true)
            .with_filter(filter_fn(move |meta| {
                meta.target() != "query"
                    && meta.target() != "response"
                    && level_enabled(general_level, meta.level())
            }));

        let subscriber = tracing_subscriber::registry()
            .with(query_layer)
            .with(response_layer)
            .with(general_layer);

        if config.logging.console {
            let console_min_level = most_permissive(query_level, response_level, general_level);
            let console_layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(std::io::stdout)
                .json()
                .flatten_event(true)
                .with_filter(filter_fn(move |meta| {
                    level_enabled(console_min_level, meta.level())
                }));
            subscriber
                .with(console_layer)
                .try_init()
                .context("failed to initialize logging subscriber")?;
        } else {
            subscriber
                .try_init()
                .context("failed to initialize logging subscriber")?;
        }
    } else {
        let query_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(query_writer)
            .compact()
            .with_filter(filter_fn(move |meta| {
                meta.target() == "query" && level_enabled(query_level, meta.level())
            }));

        let response_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(response_writer)
            .compact()
            .with_filter(filter_fn(move |meta| {
                meta.target() == "response" && level_enabled(response_level, meta.level())
            }));

        let general_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(general_writer)
            .compact()
            .with_filter(filter_fn(move |meta| {
                meta.target() != "query"
                    && meta.target() != "response"
                    && level_enabled(general_level, meta.level())
            }));

        let subscriber = tracing_subscriber::registry()
            .with(query_layer)
            .with(response_layer)
            .with(general_layer);

        if config.logging.console {
            let console_min_level = most_permissive(query_level, response_level, general_level);
            let console_layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(std::io::stdout)
                .compact()
                .with_filter(filter_fn(move |meta| {
                    level_enabled(console_min_level, meta.level())
                }));
            subscriber
                .with(console_layer)
                .try_init()
                .context("failed to initialize logging subscriber")?;
        } else {
            subscriber
                .try_init()
                .context("failed to initialize logging subscriber")?;
        }
    }

    tracing::info!(
        logging_query_level = %config.logging.query_level,
        logging_response_level = %config.logging.response_level,
        logging_general_level = %config.logging.general_level,
        logging_format = %config.logging.format,
        logging_directory = %config.logging.directory,
        "logging initialized"
    );

    Ok(LoggingGuards {
        _guards: Vec::new(),
    })
}

/// 解析日志等级字符串为枚举。
fn parse_level(value: &str, field: &str) -> anyhow::Result<ConfigLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "trace" => Ok(ConfigLevel::Trace),
        "debug" => Ok(ConfigLevel::Debug),
        "info" => Ok(ConfigLevel::Info),
        "warn" => Ok(ConfigLevel::Warn),
        "error" => Ok(ConfigLevel::Error),
        "off" => Ok(ConfigLevel::Off),
        _ => anyhow::bail!("{field} must be one of trace|debug|info|warn|error|off"),
    }
}

/// 返回三个 ConfigLevel 中最宽松（输出最多）的一个，用于 console layer 过滤。
fn most_permissive(a: ConfigLevel, b: ConfigLevel, c: ConfigLevel) -> ConfigLevel {
    fn rank(l: ConfigLevel) -> u8 {
        match l {
            ConfigLevel::Trace => 5,
            ConfigLevel::Debug => 4,
            ConfigLevel::Info => 3,
            ConfigLevel::Warn => 2,
            ConfigLevel::Error => 1,
            ConfigLevel::Off => 0,
        }
    }
    fn by_rank(r: u8) -> ConfigLevel {
        match r {
            5 => ConfigLevel::Trace,
            4 => ConfigLevel::Debug,
            3 => ConfigLevel::Info,
            2 => ConfigLevel::Warn,
            1 => ConfigLevel::Error,
            _ => ConfigLevel::Off,
        }
    }
    by_rank(rank(a).max(rank(b)).max(rank(c)))
}

/// 判断某日志等级是否被当前配置允许输出。
fn level_enabled(configured: ConfigLevel, incoming: &Level) -> bool {
    match configured {
        ConfigLevel::Off => false,
        ConfigLevel::Trace => true,
        ConfigLevel::Debug => {
            matches!(
                incoming,
                &Level::DEBUG | &Level::INFO | &Level::WARN | &Level::ERROR
            )
        }
        ConfigLevel::Info => matches!(incoming, &Level::INFO | &Level::WARN | &Level::ERROR),
        ConfigLevel::Warn => matches!(incoming, &Level::WARN | &Level::ERROR),
        ConfigLevel::Error => matches!(incoming, &Level::ERROR),
    }
}

/// reload 时检查日志目录与当天三个日志文件是否存在，不存在则主动创建。
///
/// 这是对 `ResilientDailyWriter` 按写自动创建语义的补充——它确保在 reload 完成后、
/// 下一条日志被写入之前，日志文件即已就绪（例如被外部工具删除的场景）。
pub fn check_and_recreate_log_files(config: &crate::config::AppConfig) {
    if !config.logging.enabled {
        return;
    }
    let dir = std::path::Path::new(&config.logging.directory);
    if let Err(e) = fs::create_dir_all(dir) {
        tracing::warn!(error = %e, directory = %dir.display(), "log check: failed to recreate log directory");
        return;
    }
    let date = Local::now().format("%Y-%m-%d").to_string();
    for base in &["query.log", "response.log", "general.log"] {
        let path = dir.join(format!("{}.{}", base, date));
        if !path.exists() {
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(_) => {
                    tracing::info!(path = %path.display(), "log check: recreated missing log file")
                }
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "log check: failed to recreate log file")
                }
            }
        }
    }
}
