//! Internal runtime collector used by resolver and control paths.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

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

#[derive(Debug, Default)]
struct DepthAccumulator {
    count: u64,
    sum: f64,
    max: f64,
}

#[derive(Debug, Default)]
pub struct Metrics {
    request_total: AtomicU64,
    cache_hit_total: AtomicU64,
    policy_allowed_total: AtomicU64,
    policy_denied_total: AtomicU64,
    upstream_query_total: AtomicU64,
    healthy_upstreams: AtomicUsize,
    reload_success_total: AtomicU64,
    reload_failure_total: AtomicU64,
    iterative_events: Mutex<HashMap<String, u64>>,
    ns_host_cache_events: Mutex<HashMap<String, u64>>,
    iterative_depth: Mutex<HashMap<String, DepthAccumulator>>,
    iterative_window_kpis: Mutex<HashMap<String, WindowKpiSnapshot>>,
    ns_cache_window_kpis: Mutex<HashMap<String, NsWindowKpiSnapshot>>,
    ip_health_all_unhealthy_events: AtomicU64,
    ip_health_notify_attempt_total: AtomicU64,
    ip_health_notify_fail_total: AtomicU64,
}

impl Metrics {
    /// 创建 Metrics 实例。
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    /// 导出当前指标快照。
    pub fn snapshot(&self) -> MetricsSnapshot {
        let iterative_events = self
            .iterative_events
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();
        let ns_host_cache_events = self
            .ns_host_cache_events
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();
        let iterative_depth = self
            .iterative_depth
            .lock()
            .map(|depth_map| {
                depth_map
                    .iter()
                    .map(|(key, value)| {
                        let avg = if value.count > 0 {
                            value.sum / value.count as f64
                        } else {
                            0.0
                        };
                        (
                            key.clone(),
                            DepthSnapshot {
                                count: value.count,
                                avg,
                                max: value.max,
                            },
                        )
                    })
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
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

    /// 记录一次递归解析事件。
    pub fn record_iterative_event(&self, event: &str) {
        if let Ok(mut values) = self.iterative_events.lock() {
            *values.entry(event.to_string()).or_insert(0) += 1;
        }
    }

    /// 记录递归解析深度。
    pub fn observe_iterative_depth(&self, outcome: &str, depth: f64) {
        if let Ok(mut values) = self.iterative_depth.lock() {
            let entry = values.entry(outcome.to_string()).or_default();
            entry.count = entry.count.saturating_add(1);
            entry.sum += depth;
            if depth > entry.max {
                entry.max = depth;
            }
        }
    }

    /// 记录 NS 主机缓存相关事件。
    pub fn record_ns_host_cache(&self, action: &str) {
        if let Ok(mut values) = self.ns_host_cache_events.lock() {
            *values.entry(action.to_string()).or_insert(0) += 1;
        }
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
