//! TOP N query domain and client IP statistics.
//!
//! Hot path: `record_query` only does an unbounded channel send (no locking).
//! A background task drains the channel every second and maintains 60-second
//! time buckets.  Lookups (`top_domains` / `top_clients`) hold the lock only
//! for a brief merge + sort over the relevant buckets.
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

/// Width of each time bucket in seconds.
const BUCKET_SECS: u64 = 60;
/// Maximum number of historical buckets to keep (= 1 hour lookback).
const MAX_HISTORY_BUCKETS: usize = 60;

// ── internal event ────────────────────────────────────────────────────────────

enum TopNEvent {
    Query {
        domain: String,
        ip: IpAddr,
        success: bool,
    },
}

// ── internal state (owned by background task) ─────────────────────────────────

struct BucketSnapshot {
    start_unix_secs: u64,
    domains: HashMap<String, DomainCounter>,
    ips: HashMap<IpAddr, u64>,
}

#[derive(Default, Clone)]
struct DomainCounter {
    total: u64,
    success: u64,
}

struct TopNState {
    current_domains: HashMap<String, DomainCounter>,
    current_ips: HashMap<IpAddr, u64>,
    current_start: Instant,
    current_start_unix_secs: u64,
    history: VecDeque<BucketSnapshot>,
    max_history: usize,
}

// ── public API ────────────────────────────────────────────────────────────────

/// TOP N statistics tracker.
///
/// Create with [`TopNStats::new`], then call [`TopNStats::record_query`] from
/// every request hot path.  The returned background future **must** be spawned
/// with `tokio::spawn`; it runs until the associated `TopNStats` is dropped.
pub struct TopNStats {
    tx: mpsc::UnboundedSender<TopNEvent>,
    state: Arc<Mutex<TopNState>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TopDomainStats {
    pub domain: String,
    pub total_count: u64,
    pub success_count: u64,
    pub success_rate: f64,
}

impl TopNStats {
    /// Construct a new `TopNStats` and its companion background future.
    ///
    /// The caller is responsible for spawning the returned future:
    /// ```ignore
    /// let (top_n, bg) = TopNStats::new();
    /// tokio::spawn(bg);
    /// ```
    pub fn new() -> (Self, impl std::future::Future<Output = ()> + Send + 'static) {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(Mutex::new(TopNState {
            current_domains: HashMap::new(),
            current_ips: HashMap::new(),
            current_start: Instant::now(),
            current_start_unix_secs: unix_now(),
            history: VecDeque::with_capacity(MAX_HISTORY_BUCKETS + 1),
            max_history: MAX_HISTORY_BUCKETS,
        }));

        let bg_state = Arc::clone(&state);
        let bg = background_task(rx, bg_state);

        (Self { tx, state }, bg)
    }

    /// Record one DNS query.  Lock-free; returns immediately.
    /// Silently drops the event if the background task has exited.
    pub fn record_query(&self, domain: &str, ip: IpAddr, success: bool) {
        let _ = self.tx.send(TopNEvent::Query {
            domain: domain.to_string(),
            ip,
            success,
        });
    }

    /// Return the top `n` domains (by query count) within the last
    /// `window_secs` seconds.  Results are sorted descending by count.
    ///
    /// `n` is capped at 100.  `window_secs` is capped at 3600.
    pub fn top_domains(&self, n: usize, window_secs: u64) -> Vec<(String, u64)> {
        let n = n.clamp(1, 100);
        let window_secs = window_secs.clamp(1, 3600);

        let state = self.state.lock().expect("topn state poisoned");
        let cutoff = unix_now().saturating_sub(window_secs);

        let mut merged: HashMap<String, u64> = HashMap::new();

        // Always include the current (in-progress) bucket.
        for (k, v) in &state.current_domains {
            *merged.entry(k.clone()).or_insert(0) += v.total;
        }

        // Include historical buckets that overlap with the requested window.
        for bucket in &state.history {
            if bucket.start_unix_secs + BUCKET_SECS > cutoff {
                for (k, v) in &bucket.domains {
                    *merged.entry(k.clone()).or_insert(0) += v.total;
                }
            }
        }

        let mut entries: Vec<(String, u64)> = merged.into_iter().collect();
        entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }

    /// Return top `n` domains with success counters and success rate.
    ///
    /// Success is defined as a response with DNS RCODE == 0.
    pub fn top_domains_with_success(&self, n: usize, window_secs: u64) -> Vec<TopDomainStats> {
        let n = n.clamp(1, 100);
        let window_secs = window_secs.clamp(1, 3600);

        let state = self.state.lock().expect("topn state poisoned");
        let cutoff = unix_now().saturating_sub(window_secs);

        let mut merged: HashMap<String, DomainCounter> = HashMap::new();

        for (k, v) in &state.current_domains {
            let entry = merged.entry(k.clone()).or_default();
            entry.total += v.total;
            entry.success += v.success;
        }

        for bucket in &state.history {
            if bucket.start_unix_secs + BUCKET_SECS > cutoff {
                for (k, v) in &bucket.domains {
                    let entry = merged.entry(k.clone()).or_default();
                    entry.total += v.total;
                    entry.success += v.success;
                }
            }
        }

        let mut entries: Vec<TopDomainStats> = merged
            .into_iter()
            .map(|(domain, counter)| {
                let success_rate = if counter.total == 0 {
                    0.0
                } else {
                    counter.success as f64 / counter.total as f64
                };
                TopDomainStats {
                    domain,
                    total_count: counter.total,
                    success_count: counter.success,
                    success_rate,
                }
            })
            .collect();
        entries.sort_unstable_by(|a, b| b.total_count.cmp(&a.total_count));
        entries.truncate(n);
        entries
    }

    /// Return the top `n` client IPs (by query count) within the last
    /// `window_secs` seconds.  Results are sorted descending by count.
    ///
    /// `n` is capped at 100.  `window_secs` is capped at 3600.
    pub fn top_clients(&self, n: usize, window_secs: u64) -> Vec<(IpAddr, u64)> {
        let n = n.clamp(1, 100);
        let window_secs = window_secs.clamp(1, 3600);

        let state = self.state.lock().expect("topn state poisoned");
        let cutoff = unix_now().saturating_sub(window_secs);

        let mut merged: HashMap<IpAddr, u64> = HashMap::new();

        for (k, v) in &state.current_ips {
            *merged.entry(*k).or_insert(0) += v;
        }

        for bucket in &state.history {
            if bucket.start_unix_secs + BUCKET_SECS > cutoff {
                for (k, v) in &bucket.ips {
                    *merged.entry(*k).or_insert(0) += v;
                }
            }
        }

        let mut entries: Vec<(IpAddr, u64)> = merged.into_iter().collect();
        entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }
}

// ── background task ───────────────────────────────────────────────────────────

async fn background_task(mut rx: mpsc::UnboundedReceiver<TopNEvent>, state: Arc<Mutex<TopNState>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        // Drain all pending events into a local batch (no lock held during recv).
        let mut batch: Vec<TopNEvent> = Vec::new();
        while let Ok(event) = rx.try_recv() {
            batch.push(event);
        }

        let mut st = state.lock().expect("topn state poisoned");

        // Rotate bucket if the current one has aged past BUCKET_SECS.
        if st.current_start.elapsed() >= Duration::from_secs(BUCKET_SECS) {
            let snapshot = BucketSnapshot {
                start_unix_secs: st.current_start_unix_secs,
                domains: std::mem::take(&mut st.current_domains),
                ips: std::mem::take(&mut st.current_ips),
            };
            st.history.push_front(snapshot);
            while st.history.len() > st.max_history {
                st.history.pop_back();
            }
            st.current_start = Instant::now();
            st.current_start_unix_secs = unix_now();
        }

        // Flush batch into current bucket.
        for event in batch {
            match event {
                TopNEvent::Query {
                    domain,
                    ip,
                    success,
                } => {
                    let counter = st.current_domains.entry(domain).or_default();
                    counter.total += 1;
                    if success {
                        counter.success += 1;
                    }
                    *st.current_ips.entry(ip).or_insert(0) += 1;
                }
            }
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn top_domains_returns_sorted_results() {
        let (stats, bg) = TopNStats::new();
        tokio::spawn(bg);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        stats.record_query("example.com.", ip, true);
        stats.record_query("example.com.", ip, true);
        stats.record_query("example.com.", ip, true);
        stats.record_query("other.com.", ip, true);
        stats.record_query("other.com.", ip, true);

        // Drain channel via one tick sleep.
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let top = stats.top_domains(10, 300);
        assert_eq!(top[0].0, "example.com.");
        assert_eq!(top[0].1, 3);
        assert_eq!(top[1].0, "other.com.");
        assert_eq!(top[1].1, 2);
    }

    #[tokio::test]
    async fn top_clients_returns_sorted_results() {
        let (stats, bg) = TopNStats::new();
        tokio::spawn(bg);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..5 {
            stats.record_query("a.com.", ip1, true);
        }
        stats.record_query("a.com.", ip2, true);

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let top = stats.top_clients(10, 300);
        assert_eq!(top[0].0, ip1);
        assert_eq!(top[0].1, 5);
        assert_eq!(top[1].0, ip2);
        assert_eq!(top[1].1, 1);
    }

    #[tokio::test]
    async fn top_n_cap_respected() {
        let (stats, bg) = TopNStats::new();
        tokio::spawn(bg);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for i in 0..20u32 {
            let domain = format!("domain{}.com.", i);
            for _ in 0..=i {
                stats.record_query(&domain, ip, true);
            }
        }

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let top = stats.top_domains(5, 300);
        assert_eq!(top.len(), 5);
        // All entries should be in descending order.
        for w in top.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[tokio::test]
    async fn top_domains_with_success_reports_rate() {
        let (stats, bg) = TopNStats::new();
        tokio::spawn(bg);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        stats.record_query("alpha.test.", ip, true);
        stats.record_query("alpha.test.", ip, false);
        stats.record_query("alpha.test.", ip, true);
        stats.record_query("beta.test.", ip, false);

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let top = stats.top_domains_with_success(10, 300);
        assert_eq!(top[0].domain, "alpha.test.");
        assert_eq!(top[0].total_count, 3);
        assert_eq!(top[0].success_count, 2);
        assert!((top[0].success_rate - (2.0 / 3.0)).abs() < 1e-9);

        assert_eq!(top[1].domain, "beta.test.");
        assert_eq!(top[1].total_count, 1);
        assert_eq!(top[1].success_count, 0);
        assert_eq!(top[1].success_rate, 0.0);
    }
}
