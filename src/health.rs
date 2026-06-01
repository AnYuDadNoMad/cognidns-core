//! Domain->IP health checker runtime.
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::anyhow;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub mode: String,
    pub port: u16,
    pub http_path: String,
    pub http_host_header: Option<String>,
    pub interval_secs: u64,
    pub timeout_ms: u64,
    pub max_parallel: usize,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub all_unhealthy_log_file: String,
    pub notify_webhook: Option<String>,
    pub probe_tls_insecure_skip_verify: bool,
    pub webhook_tls_insecure_skip_verify: bool,
    pub notify_webhook_retries: u32,
    pub notify_webhook_backoff_ms: u64,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "tcp".to_string(),
            port: 80,
            http_path: "/".to_string(),
            http_host_header: None,
            interval_secs: 30,
            timeout_ms: 1000,
            max_parallel: 64,
            failure_threshold: 2,
            success_threshold: 1,
            all_unhealthy_log_file: "logs/health-all-unhealthy.log".to_string(),
            notify_webhook: None,
            probe_tls_insecure_skip_verify: false,
            webhook_tls_insecure_skip_verify: false,
            notify_webhook_retries: 2,
            notify_webhook_backoff_ms: 500,
        }
    }
}

impl HealthCheckConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !self.mode.eq_ignore_ascii_case("tcp")
            && !self.mode.eq_ignore_ascii_case("http")
            && !self.mode.eq_ignore_ascii_case("https")
        {
            return Err(anyhow!(
                "health_check.mode must be either 'tcp', 'http' or 'https'"
            ));
        }
        if self.port == 0 {
            return Err(anyhow!("health_check.port must be greater than 0"));
        }
        if self.interval_secs == 0 {
            return Err(anyhow!("health_check.interval_secs must be greater than 0"));
        }
        if self.timeout_ms == 0 {
            return Err(anyhow!("health_check.timeout_ms must be greater than 0"));
        }
        if self.max_parallel == 0 {
            return Err(anyhow!("health_check.max_parallel must be greater than 0"));
        }
        if self.failure_threshold == 0 {
            return Err(anyhow!(
                "health_check.failure_threshold must be greater than 0"
            ));
        }
        if self.success_threshold == 0 {
            return Err(anyhow!(
                "health_check.success_threshold must be greater than 0"
            ));
        }
        if self.http_path.trim().is_empty() {
            return Err(anyhow!("health_check.http_path must not be empty"));
        }
        if self.notify_webhook_retries > 10 {
            return Err(anyhow!("health_check.notify_webhook_retries must be <= 10"));
        }
        if self.notify_webhook_backoff_ms == 0 {
            return Err(anyhow!(
                "health_check.notify_webhook_backoff_ms must be greater than 0"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthCheckSummary {
    pub enabled: bool,
    pub tracked_domains: usize,
    pub tracked_ips: usize,
    pub degraded_domains: usize,
    pub all_unhealthy_events: usize,
    pub notify_attempt_total: usize,
    pub notify_fail_total: usize,
}

#[derive(Debug, Clone, Default)]
struct IpProbeState {
    healthy: Option<bool>,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_error: Option<String>,
    last_checked: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
struct DomainProbeState {
    ips: HashMap<String, IpProbeState>,
    last_all_unhealthy_logged: Option<Instant>,
}

#[derive(Debug)]
pub struct IpHealthManager {
    cfg: HealthCheckConfig,
    state: RwLock<HashMap<String, DomainProbeState>>,
    all_unhealthy_events: Arc<AtomicUsize>,
    notify_attempt_total: Arc<AtomicUsize>,
    notify_fail_total: Arc<AtomicUsize>,
}

impl IpHealthManager {
    pub fn new(cfg: HealthCheckConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            state: RwLock::new(HashMap::new()),
            all_unhealthy_events: Arc::new(AtomicUsize::new(0)),
            notify_attempt_total: Arc::new(AtomicUsize::new(0)),
            notify_fail_total: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn start_background(self: Arc<Self>) {
        if !self.cfg.enabled {
            return;
        }
        tokio::spawn(async move {
            self.run_loop().await;
        });
    }

    pub fn register_domain_ips(&self, domain: &str, ips: &[String]) {
        if !self.cfg.enabled || ips.is_empty() {
            return;
        }
        let normalized_domain = normalize_domain(domain);
        if normalized_domain.is_empty() {
            return;
        }

        if let Ok(mut all) = self.state.write() {
            let entry = all.entry(normalized_domain).or_default();
            let mut keep = HashMap::with_capacity(ips.len());
            for ip in ips {
                let key = ip.trim().to_string();
                if key.is_empty() {
                    continue;
                }
                let existing = entry.ips.remove(&key).unwrap_or_default();
                keep.insert(key, existing);
            }
            entry.ips = keep;
        }
    }

    pub fn prefer_healthy_ips(&self, domain: &str, ips: &[String]) -> Vec<String> {
        if !self.cfg.enabled || ips.len() <= 1 {
            return ips.to_vec();
        }
        let normalized_domain = normalize_domain(domain);
        let mut ranked = ips
            .iter()
            .enumerate()
            .map(|(index, ip)| {
                let score = self
                    .state
                    .read()
                    .ok()
                    .and_then(|all| all.get(&normalized_domain).cloned())
                    .and_then(|domain_state| domain_state.ips.get(ip).cloned())
                    .and_then(|ip_state| ip_state.healthy)
                    .map(|healthy| if healthy { 2usize } else { 0usize })
                    .unwrap_or(1usize);
                (score, index, ip.clone())
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        ranked.into_iter().map(|(_, _, ip)| ip).collect()
    }

    pub fn all_unhealthy_for_domain(&self, domain: &str, ips: &[String]) -> bool {
        if !self.cfg.enabled || ips.is_empty() {
            return false;
        }
        let normalized_domain = normalize_domain(domain);
        let Ok(all) = self.state.read() else {
            return false;
        };
        let Some(domain_state) = all.get(&normalized_domain) else {
            return false;
        };
        let mut checked = 0usize;
        for ip in ips {
            let Some(state) = domain_state.ips.get(ip) else {
                return false;
            };
            let Some(healthy) = state.healthy else {
                return false;
            };
            if healthy {
                return false;
            }
            checked += 1;
        }
        checked == ips.len()
    }

    pub fn record_all_unhealthy_event(&self, domain: &str, ips: &[String]) {
        if !self.cfg.enabled || ips.is_empty() {
            return;
        }
        let normalized_domain = normalize_domain(domain);
        let now = Instant::now();
        let mut should_log = true;
        if let Ok(mut all) = self.state.write() {
            let entry = all.entry(normalized_domain.clone()).or_default();
            if let Some(last) = entry.last_all_unhealthy_logged {
                if now.duration_since(last) < Duration::from_secs(60) {
                    should_log = false;
                }
            }
            if should_log {
                entry.last_all_unhealthy_logged = Some(now);
            }
        }
        if !should_log {
            return;
        }

        self.all_unhealthy_events.fetch_add(1, Ordering::Relaxed);
        if let Err(err) =
            append_all_unhealthy_log(&self.cfg.all_unhealthy_log_file, &normalized_domain, ips)
        {
            warn!(error = %err, "failed to write all-unhealthy event log");
        }

        if let Some(url) = self
            .cfg
            .notify_webhook
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let domain_owned = normalized_domain.clone();
            let ips_owned = ips.to_vec();
            let cfg = self.cfg.clone();
            let notify_attempt_total = Arc::clone(&self.notify_attempt_total);
            let notify_fail_total = Arc::clone(&self.notify_fail_total);
            let url_owned = url.to_string();
            tokio::spawn(async move {
                post_all_unhealthy_webhook(
                    &cfg,
                    &notify_attempt_total,
                    &notify_fail_total,
                    &url_owned,
                    &domain_owned,
                    &ips_owned,
                )
                .await;
            });
        }
    }

    pub fn summary(&self) -> HealthCheckSummary {
        let mut tracked_domains = 0usize;
        let mut tracked_ips = 0usize;
        let mut degraded_domains = 0usize;

        if let Ok(all) = self.state.read() {
            tracked_domains = all.len();
            for domain_state in all.values() {
                tracked_ips += domain_state.ips.len();
                if !domain_state.ips.is_empty()
                    && domain_state
                        .ips
                        .values()
                        .all(|state| state.healthy == Some(false))
                {
                    degraded_domains += 1;
                }
            }
        }

        HealthCheckSummary {
            enabled: self.cfg.enabled,
            tracked_domains,
            tracked_ips,
            degraded_domains,
            all_unhealthy_events: self.all_unhealthy_events.load(Ordering::Relaxed),
            notify_attempt_total: self.notify_attempt_total.load(Ordering::Relaxed),
            notify_fail_total: self.notify_fail_total.load(Ordering::Relaxed),
        }
    }

    async fn run_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_secs(self.cfg.interval_secs.max(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            let workload = self.collect_workload();
            if workload.is_empty() {
                continue;
            }

            let sem = Arc::new(Semaphore::new(self.cfg.max_parallel.max(1)));
            let mut in_flight = FuturesUnordered::new();

            for (domain, ip) in workload {
                let sem = Arc::clone(&sem);
                let manager = Arc::clone(&self);
                in_flight.push(tokio::spawn(async move {
                    let permit = sem.acquire_owned().await;
                    if permit.is_err() {
                        return None;
                    }
                    let result = manager.probe_ip(&ip).await;
                    Some((domain, ip, result))
                }));
            }

            while let Some(joined) = in_flight.next().await {
                let Some((domain, ip, result)) = joined.ok().flatten() else {
                    continue;
                };
                self.update_probe_result(&domain, &ip, result);
            }
        }
    }

    fn collect_workload(&self) -> Vec<(String, String)> {
        let Ok(all) = self.state.read() else {
            return Vec::new();
        };
        let mut result = Vec::new();
        for (domain, domain_state) in all.iter() {
            for ip in domain_state.ips.keys() {
                result.push((domain.clone(), ip.clone()));
            }
        }
        result
    }

    fn update_probe_result(&self, domain: &str, ip: &str, result: anyhow::Result<()>) {
        let Ok(mut all) = self.state.write() else {
            return;
        };
        let Some(domain_state) = all.get_mut(domain) else {
            return;
        };
        let Some(ip_state) = domain_state.ips.get_mut(ip) else {
            return;
        };

        ip_state.last_checked = Some(Instant::now());
        match result {
            Ok(()) => {
                ip_state.consecutive_failures = 0;
                ip_state.consecutive_successes = ip_state.consecutive_successes.saturating_add(1);
                ip_state.last_error = None;
                if ip_state.consecutive_successes >= self.cfg.success_threshold {
                    ip_state.healthy = Some(true);
                }
            }
            Err(err) => {
                ip_state.consecutive_successes = 0;
                ip_state.consecutive_failures = ip_state.consecutive_failures.saturating_add(1);
                ip_state.last_error = Some(err.to_string());
                if ip_state.consecutive_failures >= self.cfg.failure_threshold {
                    ip_state.healthy = Some(false);
                }
            }
        }
    }

    async fn probe_ip(&self, ip: &str) -> anyhow::Result<()> {
        if self.cfg.mode.eq_ignore_ascii_case("https") {
            self.probe_https(ip).await
        } else if self.cfg.mode.eq_ignore_ascii_case("http") {
            self.probe_http(ip).await
        } else {
            self.probe_tcp(ip).await
        }
    }

    async fn probe_tcp(&self, ip: &str) -> anyhow::Result<()> {
        let addr = format!("{}:{}", ip, self.cfg.port);
        let connect = timeout(
            Duration::from_millis(self.cfg.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| anyhow!("tcp probe timeout"))?;
        connect.map(|_| ()).map_err(|err| err.into())
    }

    async fn probe_http(&self, ip: &str) -> anyhow::Result<()> {
        let addr = format!("{}:{}", ip, self.cfg.port);
        let mut stream = timeout(
            Duration::from_millis(self.cfg.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| anyhow!("http probe connect timeout"))??;

        let host = self
            .cfg
            .http_host_header
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(ip);
        let path = if self.cfg.http_path.starts_with('/') {
            self.cfg.http_path.as_str()
        } else {
            "/"
        };
        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: CogniDNS-Health/0.1\r\n\r\n",
            path, host
        );
        timeout(
            Duration::from_millis(self.cfg.timeout_ms),
            stream.write_all(request.as_bytes()),
        )
        .await
        .map_err(|_| anyhow!("http probe write timeout"))??;

        let mut buf = [0u8; 256];
        let n = timeout(
            Duration::from_millis(self.cfg.timeout_ms),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| anyhow!("http probe read timeout"))??;
        if n == 0 {
            return Err(anyhow!("http probe empty response"));
        }

        let text = String::from_utf8_lossy(&buf[..n]);
        if text.starts_with("HTTP/1.1 2")
            || text.starts_with("HTTP/1.1 3")
            || text.starts_with("HTTP/1.0 2")
            || text.starts_with("HTTP/1.0 3")
        {
            Ok(())
        } else {
            debug!(response = %text, "http probe non-success status");
            Err(anyhow!("http probe non-success status"))
        }
    }

    async fn probe_https(&self, ip: &str) -> anyhow::Result<()> {
        let host = self
            .cfg
            .http_host_header
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(ip);
        let path = if self.cfg.http_path.starts_with('/') {
            self.cfg.http_path.as_str()
        } else {
            "/"
        };
        let url = format!("https://{}:{}{}", host, self.cfg.port, path);
        let mut builder =
            reqwest::Client::builder().timeout(Duration::from_millis(self.cfg.timeout_ms));
        if self.cfg.probe_tls_insecure_skip_verify {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        if host != ip {
            if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                builder =
                    builder.resolve(host, std::net::SocketAddr::new(parsed_ip, self.cfg.port));
            }
        }
        let client = builder.build()?;
        let resp = client.head(url).send().await?;
        if resp.status().is_success() || resp.status().is_redirection() {
            Ok(())
        } else {
            Err(anyhow!("https probe non-success status: {}", resp.status()))
        }
    }
}

async fn post_all_unhealthy_webhook(
    cfg: &HealthCheckConfig,
    notify_attempt_total: &Arc<AtomicUsize>,
    notify_fail_total: &Arc<AtomicUsize>,
    url: &str,
    domain: &str,
    ips: &[String],
) {
    let started = Instant::now();
    let parsed = match parse_http_like_url(url) {
        Some(value) => value,
        None => {
            notify_fail_total.fetch_add(1, Ordering::Relaxed);
            warn!(url = %url, "webhook notify url is invalid");
            return;
        }
    };

    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms.max(500)))
        .build();
    if cfg.webhook_tls_insecure_skip_verify {
        client_builder = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(500)))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build();
    }
    let client = match client_builder {
        Ok(c) => c,
        Err(err) => {
            notify_fail_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %err, "failed to build webhook client");
            return;
        }
    };

    let payload = json!({
        "request_id": format!(
            "health-{}",
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        ),
        "event": "all_unhealthy",
        "probe_mode": cfg.mode,
        "domain": domain,
        "ips": ips,
        "time": format!("{:?}", SystemTime::now()),
    });

    let retries = cfg.notify_webhook_retries;
    for attempt in 0..=retries {
        notify_attempt_total.fetch_add(1, Ordering::Relaxed);
        let request = client
            .post(&parsed)
            .header("content-type", "application/json")
            .json(&payload);
        match request.send().await {
            Ok(resp) if resp.status().is_success() => {
                warn!(
                    url = %parsed,
                    domain = %domain,
                    attempt,
                    max_attempt = retries,
                    elapsed_ms = started.elapsed().as_millis(),
                    "webhook notify succeeded"
                );
                return;
            }
            Ok(resp) => {
                notify_fail_total.fetch_add(1, Ordering::Relaxed);
                warn!(
                    url = %parsed,
                    domain = %domain,
                    attempt,
                    max_attempt = retries,
                    status = %resp.status(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "webhook notify returned non-success status"
                );
            }
            Err(err) => {
                notify_fail_total.fetch_add(1, Ordering::Relaxed);
                warn!(
                    url = %parsed,
                    domain = %domain,
                    attempt,
                    max_attempt = retries,
                    error = %err,
                    elapsed_ms = started.elapsed().as_millis(),
                    "webhook notify request failed"
                );
            }
        }
        if attempt < retries {
            let backoff_ms = cfg
                .notify_webhook_backoff_ms
                .saturating_mul(1u64 << attempt.min(16));
            warn!(
                url = %parsed,
                domain = %domain,
                attempt,
                next_attempt = attempt + 1,
                backoff_ms,
                elapsed_ms = started.elapsed().as_millis(),
                "webhook notify scheduling retry"
            );
            sleep(Duration::from_millis(backoff_ms)).await;
        }
    }
}

fn parse_http_like_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }
    reqwest::Url::parse(trimmed)
        .ok()
        .map(|value| value.to_string())
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn append_all_unhealthy_log(path: &str, domain: &str, ips: &[String]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let timestamp = format!("{:?}", SystemTime::now());
    let line = format!(
        "time={} event=all_unhealthy domain={} ips={}\n",
        timestamp,
        domain,
        ips.join(",")
    );
    file.write_all(line.as_bytes())?;
    Ok(())
}
