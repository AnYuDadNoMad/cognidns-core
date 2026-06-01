use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, Serialize)]
enum TransportProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, Serialize)]
enum QNameMode {
    Fixed,
    Unique,
}

#[derive(Debug, Clone)]
struct BenchConfig {
    server: String,
    qname: String,
    qtype: u16,
    protocol: TransportProtocol,
    qname_mode: QNameMode,
    concurrency: usize,
    duration_sec: u64,
    warmup_sec: u64,
    timeout_ms: u64,
    admin_addr: Option<String>,
    out_json: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatsDelta {
    forwarder_failovers: i64,
    iterative_requests_started: i64,
    iterative_referral_hops: i64,
    iterative_retry_queries: i64,
    iterative_successes: i64,
    iterative_failures: i64,
    iterative_fallbacks: i64,
    iterative_loop_detected: i64,
    delegation_cache_hit: i64,
    delegation_cache_miss: i64,
    delegation_cache_written: i64,
    delegation_cache_write_skipped: i64,
    referral_validation_rejected: i64,
    delegation_cache_fallback_to_root: i64,
    iterative_fallback_ratio: f64,
    iterative_referral_ratio: f64,
    iterative_retry_ratio: f64,
    delegation_cache_hit_ratio: f64,
    delegation_cache_write_skipped_ratio: f64,
    referral_validation_reject_ratio: f64,
}

#[derive(Debug, Serialize)]
struct BenchResult {
    timestamp: String,
    server: String,
    protocol: TransportProtocol,
    qname: String,
    qtype: String,
    qname_mode: QNameMode,
    concurrency: usize,
    warmup_sec: u64,
    duration_sec: u64,
    timeout_ms: u64,
    total_requests: u64,
    successes: u64,
    timeouts: u64,
    errors: u64,
    success_rate_pct: f64,
    qps: f64,
    avg_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_delta: Option<StatsDelta>,
}

#[derive(Clone)]
struct BenchShared {
    total_requests: Arc<AtomicU64>,
    successes: Arc<AtomicU64>,
    timeouts: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    latencies: Arc<Mutex<Vec<f64>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = parse_args(env::args().skip(1).collect())?;
    let server_addr = resolve_server(&config.server).await?;
    let stats_before = config
        .admin_addr
        .as_deref()
        .map(fetch_stats_snapshot)
        .transpose()?;

    let shared = BenchShared {
        total_requests: Arc::new(AtomicU64::new(0)),
        successes: Arc::new(AtomicU64::new(0)),
        timeouts: Arc::new(AtomicU64::new(0)),
        errors: Arc::new(AtomicU64::new(0)),
        latencies: Arc::new(Mutex::new(Vec::new())),
    };

    let warmup_deadline = Instant::now() + Duration::from_secs(config.warmup_sec);
    let measure_deadline = warmup_deadline + Duration::from_secs(config.duration_sec);

    let mut tasks = Vec::with_capacity(config.concurrency);
    for worker_index in 0..config.concurrency {
        let shared = shared.clone();
        let qname = config.qname.clone();
        let qtype = config.qtype;
        let protocol = config.protocol;
        let timeout_ms = config.timeout_ms;

        tasks.push(tokio::spawn(async move {
            let mut sequence: u64 = 0;
            match protocol {
                TransportProtocol::Udp => {
                    let socket = UdpSocket::bind("0.0.0.0:0")
                        .await
                        .context("failed to bind benchmark udp socket")?;
                    socket.connect(server_addr).await.with_context(|| {
                        format!("failed to connect benchmark socket to {server_addr}")
                    })?;

                    let mut recv_buf = [0u8; 4096];
                    while Instant::now() < measure_deadline {
                        sequence = sequence.wrapping_add(1);
                        let query_id = (((worker_index as u64) << 16) ^ sequence) as u16;
                        let effective_qname = match config.qname_mode {
                            QNameMode::Fixed => qname.clone(),
                            QNameMode::Unique => {
                                format!("w{}-s{}.{}", worker_index, sequence, qname)
                            }
                        };
                        let packet = build_query(query_id, &effective_qname, qtype)?;
                        let started = Instant::now();
                        let measured = Instant::now() >= warmup_deadline;

                        let send_recv = async {
                            socket.send(&packet).await?;
                            let len = socket.recv(&mut recv_buf).await?;
                            Ok::<usize, std::io::Error>(len)
                        };

                        record_benchmark_outcome(
                            timeout(Duration::from_millis(timeout_ms), send_recv).await,
                            measured,
                            started,
                            &shared,
                        );
                    }
                }
                TransportProtocol::Tcp => {
                    let mut stream = TcpStream::connect(server_addr).await.with_context(|| {
                        format!("failed to connect benchmark tcp stream to {server_addr}")
                    })?;
                    stream.set_nodelay(true).with_context(|| {
                        format!("failed to enable tcp nodelay for {server_addr}")
                    })?;
                    while Instant::now() < measure_deadline {
                        sequence = sequence.wrapping_add(1);
                        let query_id = (((worker_index as u64) << 16) ^ sequence) as u16;
                        let effective_qname = match config.qname_mode {
                            QNameMode::Fixed => qname.clone(),
                            QNameMode::Unique => {
                                format!("w{}-s{}.{}", worker_index, sequence, qname)
                            }
                        };
                        let packet = build_query(query_id, &effective_qname, qtype)?;
                        let started = Instant::now();
                        let measured = Instant::now() >= warmup_deadline;

                        let send_recv = async {
                            let frame_len = u16::try_from(packet.len()).map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "packet too large",
                                )
                            })?;
                            stream.write_all(&frame_len.to_be_bytes()).await?;
                            stream.write_all(&packet).await?;
                            let mut len_buf = [0u8; 2];
                            stream.read_exact(&mut len_buf).await?;
                            let response_len = u16::from_be_bytes(len_buf) as usize;
                            let mut response = vec![0u8; response_len];
                            stream.read_exact(&mut response).await?;
                            Ok::<usize, std::io::Error>(response_len)
                        };

                        record_benchmark_outcome(
                            timeout(Duration::from_millis(timeout_ms), send_recv).await,
                            measured,
                            started,
                            &shared,
                        );
                    }
                }
            }

            Ok::<(), anyhow::Error>(())
        }));
    }

    for task in tasks {
        task.await.context("benchmark task join failed")??;
    }

    let mut latency_values = shared.latencies.lock().expect("latencies poisoned").clone();
    latency_values
        .sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));

    let request_count = shared.total_requests.load(Ordering::Relaxed);
    let success_count = shared.successes.load(Ordering::Relaxed);
    let timeout_count = shared.timeouts.load(Ordering::Relaxed);
    let error_count = shared.errors.load(Ordering::Relaxed);
    let success_rate_pct = if request_count > 0 {
        (success_count as f64 / request_count as f64) * 100.0
    } else {
        0.0
    };
    let qps = if config.duration_sec > 0 {
        success_count as f64 / config.duration_sec as f64
    } else {
        0.0
    };
    let avg_ms = if latency_values.is_empty() {
        0.0
    } else {
        latency_values.iter().sum::<f64>() / latency_values.len() as f64
    };
    let stats_after = config
        .admin_addr
        .as_deref()
        .map(fetch_stats_snapshot)
        .transpose()?;
    let stats_delta = stats_before
        .zip(stats_after)
        .map(|(before, after)| after.delta(&before));

    let result = BenchResult {
        timestamp: format!("{:?}", SystemTime::now()),
        server: config.server.clone(),
        protocol: config.protocol,
        qname: config.qname.clone(),
        qtype: if config.qtype == 28 {
            "AAAA".to_string()
        } else {
            "A".to_string()
        },
        qname_mode: config.qname_mode,
        concurrency: config.concurrency,
        warmup_sec: config.warmup_sec,
        duration_sec: config.duration_sec,
        timeout_ms: config.timeout_ms,
        total_requests: request_count,
        successes: success_count,
        timeouts: timeout_count,
        errors: error_count,
        success_rate_pct: round3(success_rate_pct),
        qps: round3(qps),
        avg_ms: round3(avg_ms),
        p50_ms: round3(percentile(&latency_values, 0.50)),
        p95_ms: round3(percentile(&latency_values, 0.95)),
        p99_ms: round3(percentile(&latency_values, 0.99)),
        max_ms: round3(latency_values.last().copied().unwrap_or(0.0)),
        stats_delta,
    };

    println!("{}", serde_json::to_string_pretty(&result)?);

    if let Some(path) = &config.out_json {
        fs::write(path, serde_json::to_vec_pretty(&result)?)
            .with_context(|| format!("failed to write benchmark json to {path}"))?;
    }

    Ok(())
}

fn parse_args(args: Vec<String>) -> anyhow::Result<BenchConfig> {
    let mut config = BenchConfig {
        server: "127.0.0.1:5301".to_string(),
        qname: "bench.example".to_string(),
        qtype: 1,
        protocol: TransportProtocol::Udp,
        qname_mode: QNameMode::Fixed,
        concurrency: 32,
        duration_sec: 15,
        warmup_sec: 3,
        timeout_ms: 1000,
        admin_addr: None,
        out_json: None,
    };

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--server" => {
                index += 1;
                config.server = args
                    .get(index)
                    .cloned()
                    .ok_or_else(|| anyhow!("missing value for --server"))?;
            }
            "--qname" => {
                index += 1;
                config.qname = args
                    .get(index)
                    .cloned()
                    .ok_or_else(|| anyhow!("missing value for --qname"))?;
            }
            "--qtype" => {
                index += 1;
                let value = args
                    .get(index)
                    .cloned()
                    .ok_or_else(|| anyhow!("missing value for --qtype"))?;
                config.qtype = if value.eq_ignore_ascii_case("AAAA") {
                    28
                } else {
                    1
                };
            }
            "--protocol" => {
                index += 1;
                let value = args
                    .get(index)
                    .cloned()
                    .ok_or_else(|| anyhow!("missing value for --protocol"))?;
                config.protocol = match value.as_str() {
                    "udp" => TransportProtocol::Udp,
                    "tcp" => TransportProtocol::Tcp,
                    _ => return Err(anyhow!("unsupported --protocol: {value}")),
                };
            }
            "--qname-mode" => {
                index += 1;
                let value = args
                    .get(index)
                    .cloned()
                    .ok_or_else(|| anyhow!("missing value for --qname-mode"))?;
                config.qname_mode = match value.as_str() {
                    "fixed" => QNameMode::Fixed,
                    "unique" => QNameMode::Unique,
                    _ => return Err(anyhow!("unsupported --qname-mode: {value}")),
                };
            }
            "--concurrency" => {
                index += 1;
                config.concurrency = args
                    .get(index)
                    .ok_or_else(|| anyhow!("missing value for --concurrency"))?
                    .parse()
                    .context("invalid --concurrency")?;
            }
            "--duration-sec" => {
                index += 1;
                config.duration_sec = args
                    .get(index)
                    .ok_or_else(|| anyhow!("missing value for --duration-sec"))?
                    .parse()
                    .context("invalid --duration-sec")?;
            }
            "--warmup-sec" => {
                index += 1;
                config.warmup_sec = args
                    .get(index)
                    .ok_or_else(|| anyhow!("missing value for --warmup-sec"))?
                    .parse()
                    .context("invalid --warmup-sec")?;
            }
            "--timeout-ms" => {
                index += 1;
                config.timeout_ms = args
                    .get(index)
                    .ok_or_else(|| anyhow!("missing value for --timeout-ms"))?
                    .parse()
                    .context("invalid --timeout-ms")?;
            }
            "--admin-addr" => {
                index += 1;
                config.admin_addr = Some(
                    args.get(index)
                        .cloned()
                        .ok_or_else(|| anyhow!("missing value for --admin-addr"))?,
                );
            }
            "--out-json" => {
                index += 1;
                config.out_json = Some(
                    args.get(index)
                        .cloned()
                        .ok_or_else(|| anyhow!("missing value for --out-json"))?,
                );
            }
            other => return Err(anyhow!("unsupported argument: {other}")),
        }
        index += 1;
    }

    Ok(config)
}

async fn resolve_server(server: &str) -> anyhow::Result<SocketAddr> {
    lookup_host(server)
        .await
        .with_context(|| format!("failed to resolve benchmark server {server}"))?
        .next()
        .ok_or_else(|| anyhow!("benchmark server {server} resolved to no addresses"))
}

fn build_query(id: u16, name: &str, qtype: u16) -> anyhow::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(anyhow!("invalid qname label too long: {label}"));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

fn percentile(values: &[f64], ratio: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let index = ((values.len() as f64 * ratio).ceil() as usize).saturating_sub(1);
    values[index.min(values.len() - 1)]
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn record_benchmark_outcome(
    outcome: Result<Result<usize, std::io::Error>, tokio::time::error::Elapsed>,
    measured: bool,
    started: Instant,
    shared: &BenchShared,
) {
    match outcome {
        Ok(Ok(_)) => {
            if measured {
                shared.total_requests.fetch_add(1, Ordering::Relaxed);
                shared.successes.fetch_add(1, Ordering::Relaxed);
                let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                shared
                    .latencies
                    .lock()
                    .expect("latencies poisoned")
                    .push(elapsed_ms);
            }
        }
        Err(_) => {
            if measured {
                shared.total_requests.fetch_add(1, Ordering::Relaxed);
                shared.timeouts.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(Err(_)) => {
            if measured {
                shared.total_requests.fetch_add(1, Ordering::Relaxed);
                shared.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct StatsSnapshot {
    forwarder_failovers: i64,
    iterative_requests_started: i64,
    iterative_referral_hops: i64,
    iterative_retry_queries: i64,
    iterative_successes: i64,
    iterative_failures: i64,
    iterative_fallbacks: i64,
    iterative_loop_detected: i64,
    delegation_cache_hit: i64,
    delegation_cache_miss: i64,
    delegation_cache_written: i64,
    delegation_cache_write_skipped: i64,
    referral_validation_rejected: i64,
    delegation_cache_fallback_to_root: i64,
}

impl StatsSnapshot {
    fn delta(&self, before: &StatsSnapshot) -> StatsDelta {
        let iterative_requests_started =
            self.iterative_requests_started - before.iterative_requests_started;
        let iterative_referral_hops = self.iterative_referral_hops - before.iterative_referral_hops;
        let iterative_retry_queries = self.iterative_retry_queries - before.iterative_retry_queries;
        let iterative_fallbacks = self.iterative_fallbacks - before.iterative_fallbacks;
        let delegation_cache_hit = self.delegation_cache_hit - before.delegation_cache_hit;
        let delegation_cache_miss = self.delegation_cache_miss - before.delegation_cache_miss;
        let delegation_cache_written =
            self.delegation_cache_written - before.delegation_cache_written;
        let delegation_cache_write_skipped =
            self.delegation_cache_write_skipped - before.delegation_cache_write_skipped;
        let referral_validation_rejected =
            self.referral_validation_rejected - before.referral_validation_rejected;
        let delegation_cache_fallback_to_root =
            self.delegation_cache_fallback_to_root - before.delegation_cache_fallback_to_root;
        StatsDelta {
            forwarder_failovers: self.forwarder_failovers - before.forwarder_failovers,
            iterative_requests_started,
            iterative_referral_hops,
            iterative_retry_queries,
            iterative_successes: self.iterative_successes - before.iterative_successes,
            iterative_failures: self.iterative_failures - before.iterative_failures,
            iterative_fallbacks,
            iterative_loop_detected: self.iterative_loop_detected - before.iterative_loop_detected,
            delegation_cache_hit,
            delegation_cache_miss,
            delegation_cache_written,
            delegation_cache_write_skipped,
            referral_validation_rejected,
            delegation_cache_fallback_to_root,
            iterative_fallback_ratio: ratio(iterative_fallbacks, iterative_requests_started),
            iterative_referral_ratio: ratio(iterative_referral_hops, iterative_requests_started),
            iterative_retry_ratio: ratio(iterative_retry_queries, iterative_requests_started),
            delegation_cache_hit_ratio: ratio(delegation_cache_hit, iterative_requests_started),
            delegation_cache_write_skipped_ratio: ratio(
                delegation_cache_write_skipped,
                iterative_requests_started,
            ),
            referral_validation_reject_ratio: ratio(
                referral_validation_rejected,
                iterative_requests_started,
            ),
        }
    }
}

fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator <= 0 {
        0.0
    } else {
        round3(numerator as f64 / denominator as f64)
    }
}

fn fetch_stats_snapshot(admin_addr: &str) -> anyhow::Result<StatsSnapshot> {
    let mut stream = std::net::TcpStream::connect(admin_addr)
        .with_context(|| format!("failed to connect admin addr {admin_addr}"))?;
    let request = format!(
        "GET /stats HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        admin_addr
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8(raw).context("stats response is not utf8")?;
    let (_, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("invalid admin response"))?;
    let value: Value = serde_json::from_str(body).context("failed to decode /stats json")?;
    let resolver = value
        .get("resolver")
        .ok_or_else(|| anyhow!("stats missing resolver object"))?;
    let iterative_events = value
        .get("metrics")
        .and_then(|metrics| metrics.get("iterative_events"));

    Ok(StatsSnapshot {
        forwarder_failovers: stat_i64(resolver, "forwarder_failovers"),
        iterative_requests_started: stat_i64(resolver, "iterative_requests_started"),
        iterative_referral_hops: stat_i64(resolver, "iterative_referral_hops"),
        iterative_retry_queries: stat_i64(resolver, "iterative_retry_queries"),
        iterative_successes: stat_i64(resolver, "iterative_successes"),
        iterative_failures: stat_i64(resolver, "iterative_failures"),
        iterative_fallbacks: stat_i64(resolver, "iterative_fallbacks"),
        iterative_loop_detected: stat_i64(resolver, "iterative_loop_detected"),
        delegation_cache_hit: stat_iterative_event_i64(iterative_events, "delegation_cache_hit"),
        delegation_cache_miss: stat_iterative_event_i64(iterative_events, "delegation_cache_miss"),
        delegation_cache_written: stat_iterative_event_i64(
            iterative_events,
            "delegation_cache_written",
        ),
        delegation_cache_write_skipped: stat_iterative_event_i64(
            iterative_events,
            "delegation_cache_write_skipped",
        ),
        referral_validation_rejected: stat_iterative_event_i64(
            iterative_events,
            "referral_validation_rejected",
        ),
        delegation_cache_fallback_to_root: stat_iterative_event_i64(
            iterative_events,
            "delegation_cache_fallback_to_root",
        ),
    })
}

fn stat_i64(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn stat_iterative_event_i64(events: Option<&Value>, key: &str) -> i64 {
    events
        .and_then(|value| value.get(key))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}
