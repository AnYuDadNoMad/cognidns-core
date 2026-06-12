//! Internal runtime collector used by resolver and control paths.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use dashmap::DashMap;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DepthSnapshot {
    pub count: u64,
    pub avg: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowKpiSnapshot {
    pub failure_rate: f64,
    pub fallback_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NsWindowKpiSnapshot {
    pub eviction_rate: f64,
    pub expired_lookup_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub request_total: u64,
    pub cache_hit_total: u64,
    pub policy_allowed_total: u64,
    pub policy_denied_total: u64,
    pub upstream_query_total: u64,
    pub healthy_upstreams: usize,
    pub reload_success_total: u64,
    pub reload_failure_total: u64,
    pub iterative_events: HashMap<String, u64>,
    pub ns_host_cache_events: HashMap<String, u64>,
    pub iterative_depth: HashMap<String, DepthSnapshot>,
    pub iterative_window_kpis: HashMap<String, WindowKpiSnapshot>,
    pub ns_cache_window_kpis: HashMap<String, NsWindowKpiSnapshot>,
    pub ip_health_all_unhealthy_events: u64,
    pub ip_health_notify_attempt_total: u64,
    pub ip_health_notify_fail_total: u64,
}

// DepthAccumulator replaced by lock-free AtomicDepthAccumulator (see Metrics impl below).

/// Lock-free depth accumulator for per-outcome depth tracking.
/// Uses AtomicU64 for count, AtomicU64 for sum (f64 bits), AtomicU64 for max (f64 bits).
#[derive(Debug, Default)]
struct AtomicDepthAccumulator {
    count: AtomicU64,
    /// f64 bits stored as u64. Updated via CAS loop.
    sum_bits: AtomicU64,
    /// f64 bits stored as u64. Updated via CAS loop.
    max_bits: AtomicU64,
}

impl AtomicDepthAccumulator {
    fn observe(&self, depth: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        // Update sum via CAS loop on f64-bits.
        loop {
            let old_bits = self.sum_bits.load(Ordering::Relaxed);
            let old_val = f64::from_bits(old_bits);
            let new_val = old_val + depth;
            match self.sum_bits.compare_exchange_weak(
                old_bits,
                new_val.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        // Update max via CAS loop.
        loop {
            let old_bits = self.max_bits.load(Ordering::Relaxed);
            let old_val = f64::from_bits(old_bits);
            if depth <= old_val {
                break;
            }
            match self.max_bits.compare_exchange_weak(
                old_bits,
                depth.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    fn snapshot(&self) -> DepthSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let sum = f64::from_bits(self.sum_bits.load(Ordering::Relaxed));
        let max = f64::from_bits(self.max_bits.load(Ordering::Relaxed));
        let avg = if count > 0 { sum / count as f64 } else { 0.0 };
        DepthSnapshot { count, avg, max }
    }
}

/// Increment a counter in a DashMap keyed by String, inserting AtomicU64(0) if absent.
fn dashmap_counter_inc(map: &DashMap<String, AtomicU64>, key: &str) {
    map.entry(key.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug)]
pub struct Metrics {
    request_total: AtomicU64,
    cache_hit_total: AtomicU64,
    policy_allowed_total: AtomicU64,
    policy_denied_total: AtomicU64,
    upstream_query_total: AtomicU64,
    healthy_upstreams: AtomicUsize,
    reload_success_total: AtomicU64,
    reload_failure_total: AtomicU64,
    /// Lock-free: per-event atomic counters, no Mutex on hot path.
    iterative_events: DashMap<String, AtomicU64>,
    /// Lock-free: per-action atomic counters, no Mutex on hot path.
    ns_host_cache_events: DashMap<String, AtomicU64>,
    /// Lock-free: per-outcome atomic depth accumulators, no Mutex on hot path.
    iterative_depth: DashMap<String, AtomicDepthAccumulator>,
    /// Low-frequency (background task only), Mutex is acceptable.
    iterative_window_kpis: Mutex<HashMap<String, WindowKpiSnapshot>>,
    /// Low-frequency (background task only), Mutex is acceptable.
    ns_cache_window_kpis: Mutex<HashMap<String, NsWindowKpiSnapshot>>,
    ip_health_all_unhealthy_events: AtomicU64,
    ip_health_notify_attempt_total: AtomicU64,
    ip_health_notify_fail_total: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            request_total: AtomicU64::new(0),
            cache_hit_total: AtomicU64::new(0),
            policy_allowed_total: AtomicU64::new(0),
            policy_denied_total: AtomicU64::new(0),
            upstream_query_total: AtomicU64::new(0),
            healthy_upstreams: AtomicUsize::new(0),
            reload_success_total: AtomicU64::new(0),
            reload_failure_total: AtomicU64::new(0),
            iterative_events: DashMap::new(),
            ns_host_cache_events: DashMap::new(),
            iterative_depth: DashMap::new(),
            iterative_window_kpis: Mutex::new(HashMap::new()),
            ns_cache_window_kpis: Mutex::new(HashMap::new()),
            ip_health_all_unhealthy_events: AtomicU64::new(0),
            ip_health_notify_attempt_total: AtomicU64::new(0),
            ip_health_notify_fail_total: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    /// 创建 Metrics 实例。
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    /// 导出当前指标快照。
    pub fn snapshot(&self) -> MetricsSnapshot {
        let iterative_events: HashMap<String, u64> = self
            .iterative_events
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
            .collect();
        let ns_host_cache_events: HashMap<String, u64> = self
            .ns_host_cache_events
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
            .collect();
        let iterative_depth: HashMap<String, DepthSnapshot> = self
            .iterative_depth
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().snapshot()))
            .collect();
        let iterative_window_kpis = self
            .iterative_window_kpis
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();
        let ns_cache_window_kpis = self
            .ns_cache_window_kpis
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();

        MetricsSnapshot {
            request_total: self.request_total.load(Ordering::Relaxed),
            cache_hit_total: self.cache_hit_total.load(Ordering::Relaxed),
            policy_allowed_total: self.policy_allowed_total.load(Ordering::Relaxed),
            policy_denied_total: self.policy_denied_total.load(Ordering::Relaxed),
            upstream_query_total: self.upstream_query_total.load(Ordering::Relaxed),
            healthy_upstreams: self.healthy_upstreams.load(Ordering::Relaxed),
            reload_success_total: self.reload_success_total.load(Ordering::Relaxed),
            reload_failure_total: self.reload_failure_total.load(Ordering::Relaxed),
            iterative_events,
            ns_host_cache_events,
            iterative_depth,
            iterative_window_kpis,
            ns_cache_window_kpis,
            ip_health_all_unhealthy_events: self
                .ip_health_all_unhealthy_events
                .load(Ordering::Relaxed),
            ip_health_notify_attempt_total: self
                .ip_health_notify_attempt_total
                .load(Ordering::Relaxed),
            ip_health_notify_fail_total: self.ip_health_notify_fail_total.load(Ordering::Relaxed),
        }
    }

    /// 记录一次请求的协议、结果、响应码和耗时。
    pub fn record_request(
        &self,
        _protocol: &str,
        _outcome: &str,
        _rcode: u16,
        _duration_seconds: f64,
    ) {
        self.request_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录一次缓存命中。
    pub fn record_cache_hit(&self, _rcode: u16) {
        self.cache_hit_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录一次策略判决。
    pub fn record_policy_decision(&self, _reason: &str, allowed: bool) {
        if allowed {
            self.policy_allowed_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.policy_denied_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 记录一次上游查询。
    pub fn record_upstream_query(&self, _upstream: &str, _outcome: &str, _duration_seconds: f64) {
        self.upstream_query_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 设置健康上游服务器数量。
    pub fn set_healthy_upstreams(&self, count: usize) {
        self.healthy_upstreams.store(count, Ordering::Relaxed);
    }

    /// 记录一次递归解析事件。Lock-free: O(1) atomic increment, no Mutex.
    pub fn record_iterative_event(&self, event: &str) {
        dashmap_counter_inc(&self.iterative_events, event);
    }

    /// 记录递归解析深度。Lock-free: CAS-loop on atomic f64, no Mutex.
    pub fn observe_iterative_depth(&self, outcome: &str, depth: f64) {
        self.iterative_depth
            .entry(outcome.to_string())
            .or_insert_with(AtomicDepthAccumulator::default)
            .observe(depth);
    }

    /// 记录 NS 主机缓存相关事件。Lock-free: O(1) atomic increment, no Mutex.
    pub fn record_ns_host_cache(&self, action: &str) {
        dashmap_counter_inc(&self.ns_host_cache_events, action);
    }

    /// 设置递归窗口 KPI。
    pub fn set_iterative_window_kpis(&self, window: &str, failure_rate: f64, fallback_ratio: f64) {
        if let Ok(mut values) = self.iterative_window_kpis.lock() {
            values.insert(
                window.to_string(),
                WindowKpiSnapshot {
                    failure_rate,
                    fallback_ratio,
                },
            );
        }
    }

    /// 设置 NS 缓存窗口 KPI。
    pub fn set_ns_cache_window_kpis(
        &self,
        window: &str,
        eviction_rate: f64,
        expired_lookup_ratio: f64,
    ) {
        if let Ok(mut values) = self.ns_cache_window_kpis.lock() {
            values.insert(
                window.to_string(),
                NsWindowKpiSnapshot {
                    eviction_rate,
                    expired_lookup_ratio,
                },
            );
        }
    }

    /// 记录一次配置热重载事件。
    pub fn record_reload(&self, success: bool, _reason: &str, _duration_seconds: f64) {
        if success {
            self.reload_success_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.reload_failure_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 设置 IP 健康检查计数快照。
    pub fn set_ip_health_counters(
        &self,
        all_unhealthy_events: usize,
        notify_attempt_total: usize,
        notify_fail_total: usize,
    ) {
        self.ip_health_all_unhealthy_events
            .store(all_unhealthy_events as u64, Ordering::Relaxed);
        self.ip_health_notify_attempt_total
            .store(notify_attempt_total as u64, Ordering::Relaxed);
        self.ip_health_notify_fail_total
            .store(notify_fail_total as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn metrics_snapshot_accumulates_core_counters() {
        let metrics = Metrics::new().expect("metrics");

        metrics.record_request("udp", "upstream", 0, 0.01);
        metrics.record_request("udp", "cache", 0, 0.001);
        metrics.record_cache_hit(0);
        metrics.record_policy_decision("allow", true);
        metrics.record_policy_decision("blocked_domain", false);
        metrics.record_upstream_query("8.8.8.8:53", "success", 0.005);
        metrics.set_healthy_upstreams(2);
        metrics.record_reload(true, "ok", 0.1);
        metrics.record_reload(false, "invalid_config", 0.2);
        metrics.set_ip_health_counters(3, 4, 1);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.request_total, 2);
        assert_eq!(snapshot.cache_hit_total, 1);
        assert_eq!(snapshot.policy_allowed_total, 1);
        assert_eq!(snapshot.policy_denied_total, 1);
        assert_eq!(snapshot.upstream_query_total, 1);
        assert_eq!(snapshot.healthy_upstreams, 2);
        assert_eq!(snapshot.reload_success_total, 1);
        assert_eq!(snapshot.reload_failure_total, 1);
        assert_eq!(snapshot.ip_health_all_unhealthy_events, 3);
        assert_eq!(snapshot.ip_health_notify_attempt_total, 4);
        assert_eq!(snapshot.ip_health_notify_fail_total, 1);
    }

    #[test]
    fn metrics_snapshot_tracks_iterative_and_window_values() {
        let metrics = Metrics::new().expect("metrics");

        metrics.record_iterative_event("delegation_cache_hit");
        metrics.record_iterative_event("delegation_cache_hit");
        metrics.record_ns_host_cache("store");
        metrics.observe_iterative_depth("resolved", 2.0);
        metrics.observe_iterative_depth("resolved", 4.0);
        metrics.set_iterative_window_kpis("short", 0.1, 0.2);
        metrics.set_ns_cache_window_kpis("short", 0.3, 0.4);

        let snapshot = metrics.snapshot();
        assert_eq!(
            snapshot.iterative_events.get("delegation_cache_hit"),
            Some(&2)
        );
        assert_eq!(snapshot.ns_host_cache_events.get("store"), Some(&1));

        let resolved_depth = snapshot
            .iterative_depth
            .get("resolved")
            .expect("resolved depth present");
        assert_eq!(resolved_depth.count, 2);
        assert!((resolved_depth.avg - 3.0).abs() < f64::EPSILON);
        assert!((resolved_depth.max - 4.0).abs() < f64::EPSILON);

        let iterative_kpi = snapshot
            .iterative_window_kpis
            .get("short")
            .expect("iterative kpi present");
        assert!((iterative_kpi.failure_rate - 0.1).abs() < f64::EPSILON);
        assert!((iterative_kpi.fallback_ratio - 0.2).abs() < f64::EPSILON);

        let ns_kpi = snapshot
            .ns_cache_window_kpis
            .get("short")
            .expect("ns cache kpi present");
        assert!((ns_kpi.eviction_rate - 0.3).abs() < f64::EPSILON);
        assert!((ns_kpi.expired_lookup_ratio - 0.4).abs() < f64::EPSILON);
    }
}
