//! Policy engine for ACL, RPZ-lite block list, ANY denial and rate limit.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use serde::Serialize;
use tracing::debug;

use crate::config::DnsView;
use crate::context::RequestContext;

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub allow_clients: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub rate_limit_per_second: u32,
    pub deny_any_queries: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub rcode: u16,
    pub reason: &'static str,
    pub matched_view: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicySnapshot {
    pub allowed_clients_count: usize,
    pub blocked_domains_count: usize,
    pub rate_limit_per_second: u32,
    pub deny_any_queries: bool,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            rcode: 0,
            reason: "allow",
            matched_view: None,
        }
    }

    pub fn refuse(reason: &'static str) -> Self {
        Self {
            allowed: false,
            rcode: 5,
            reason,
            matched_view: None,
        }
    }

    pub fn refuse_in_view(reason: &'static str, view_name: String) -> Self {
        Self {
            allowed: false,
            rcode: 5,
            reason,
            matched_view: Some(view_name),
        }
    }
}

#[derive(Debug)]
struct RateWindow {
    started_at: Instant,
    count: u32,
}

#[derive(Debug)]
struct PolicyView {
    name: String,
    blocked_domains: Vec<String>,
}

#[derive(Debug, Default)]
struct CidrTrieNode {
    zero: Option<Box<CidrTrieNode>>,
    one: Option<Box<CidrTrieNode>>,
    terminal_min_index: Option<usize>,
}

#[derive(Debug, Default)]
struct CidrTrie {
    ipv4_root: CidrTrieNode,
    ipv6_root: CidrTrieNode,
}

impl CidrTrie {
    fn insert(&mut self, net: &IpNet, index: usize) {
        match net {
            IpNet::V4(item) => {
                let octets = item.addr().octets();
                insert_prefix_bits(
                    &mut self.ipv4_root,
                    octets.as_slice(),
                    item.prefix_len() as usize,
                    index,
                );
            }
            IpNet::V6(item) => {
                let octets = item.addr().octets();
                insert_prefix_bits(
                    &mut self.ipv6_root,
                    octets.as_slice(),
                    item.prefix_len() as usize,
                    index,
                );
            }
        }
    }

    fn lookup(&self, ip: IpAddr) -> Option<usize> {
        match ip {
            IpAddr::V4(item) => lookup_bits(&self.ipv4_root, item.octets().as_slice()),
            IpAddr::V6(item) => lookup_bits(&self.ipv6_root, item.octets().as_slice()),
        }
    }
}

fn insert_prefix_bits(root: &mut CidrTrieNode, bytes: &[u8], prefix_len: usize, index: usize) {
    let mut node = root;
    if prefix_len == 0 {
        update_min_index(&mut node.terminal_min_index, index);
        return;
    }

    for bit in 0..prefix_len {
        let child_slot = if bit_at(bytes, bit) {
            &mut node.one
        } else {
            &mut node.zero
        };
        node = child_slot
            .get_or_insert_with(|| Box::new(CidrTrieNode::default()))
            .as_mut();
    }

    update_min_index(&mut node.terminal_min_index, index);
}

fn lookup_bits(root: &CidrTrieNode, bytes: &[u8]) -> Option<usize> {
    let mut best = root.terminal_min_index;
    let mut node = root;

    for bit in 0..(bytes.len() * 8) {
        let next = if bit_at(bytes, bit) {
            node.one.as_deref()
        } else {
            node.zero.as_deref()
        };
        let Some(next_node) = next else {
            break;
        };
        node = next_node;
        if let Some(candidate) = node.terminal_min_index {
            best = Some(best.map_or(candidate, |current| current.min(candidate)));
        }
    }

    best
}

fn bit_at(bytes: &[u8], bit: usize) -> bool {
    let byte = bytes[bit / 8];
    let offset = 7 - (bit % 8);
    ((byte >> offset) & 0x01) == 1
}

fn update_min_index(slot: &mut Option<usize>, candidate: usize) {
    match slot {
        Some(current) if *current <= candidate => {}
        _ => *slot = Some(candidate),
    }
}

#[derive(Debug)]
pub struct PolicyEngine {
    allowed_clients_count: usize,
    allowed_clients_matcher: CidrTrie,
    blocked_domains: Vec<String>,
    views: Vec<PolicyView>,
    view_matcher: CidrTrie,
    default_view_index: Option<usize>,
    rate_limit_per_second: u32,
    deny_any_queries: bool,
    client_windows: Mutex<HashMap<IpAddr, RateWindow>>,
}

impl PolicyEngine {
    /// Builds policy runtime state from static config.
    pub fn new(config: PolicyConfig) -> anyhow::Result<Self> {
        Self::new_with_views(config, Vec::new())
    }

    /// Builds policy runtime state with split-horizon views.
    pub fn new_with_views(config: PolicyConfig, views: Vec<DnsView>) -> anyhow::Result<Self> {
        let allowed_clients = config
            .allow_clients
            .iter()
            .map(|item| item.parse::<IpNet>())
            .collect::<Result<Vec<_>, _>>()?;

        let mut allowed_clients_matcher = CidrTrie::default();
        for (index, cidr) in allowed_clients.iter().enumerate() {
            allowed_clients_matcher.insert(cidr, index);
        }

        let mut view_matcher = CidrTrie::default();
        let views = views
            .into_iter()
            .enumerate()
            .map(|(view_index, view)| -> anyhow::Result<PolicyView> {
                let client_cidrs = view
                    .client_cidrs
                    .iter()
                    .map(|item| item.parse::<IpNet>())
                    .collect::<Result<Vec<_>, _>>()?;
                for cidr in &client_cidrs {
                    view_matcher.insert(cidr, view_index);
                }
                Ok(PolicyView {
                    name: view.name,
                    blocked_domains: view
                        .blocked_domains
                        .into_iter()
                        .map(|item| normalize_domain_pattern(&item))
                        .filter(|item| !item.is_empty())
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let default_view_index = views
            .iter()
            .position(|view| view.name.trim().eq_ignore_ascii_case("default"));

        Ok(Self {
            allowed_clients_count: allowed_clients.len(),
            allowed_clients_matcher,
            blocked_domains: config
                .blocked_domains
                .into_iter()
                .map(|item| normalize_domain_pattern(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            views,
            view_matcher,
            default_view_index,
            rate_limit_per_second: config.rate_limit_per_second,
            deny_any_queries: config.deny_any_queries,
            client_windows: Mutex::new(HashMap::new()),
        })
    }

    /// Evaluates a single DNS request against all enabled policy checks.
    pub fn evaluate(&self, ctx: &RequestContext) -> PolicyDecision {
        if self.allowed_clients_count > 0
            && self
                .allowed_clients_matcher
                .lookup(ctx.client_addr.ip())
                .is_none()
        {
            return PolicyDecision::refuse("acl_denied");
        }

        if self.deny_any_queries && ctx.query_type == Some(255) {
            return PolicyDecision::refuse("any_denied");
        }

        let matched_view = self
            .view_matcher
            .lookup(ctx.client_addr.ip())
            .and_then(|index| self.views.get(index))
            .or_else(|| {
                self.default_view_index
                    .and_then(|index| self.views.get(index))
            });

        if let Some(view) = matched_view {
            debug!(
                request_id = ctx.request_id,
                client = %ctx.client_addr,
                view = %view.name,
                "policy matched view"
            );
        }

        if let Some(query_name) = &ctx.query_name {
            let query_name = normalize_query_name(query_name);
            if let Some(view) = matched_view {
                if view
                    .blocked_domains
                    .iter()
                    .any(|blocked| domain_matches_normalized(&query_name, blocked))
                {
                    debug!(
                        request_id = ctx.request_id,
                        qname = %query_name,
                        client = %ctx.client_addr,
                        view = %view.name,
                        "policy blocked by view blacklist"
                    );
                    return PolicyDecision::refuse_in_view("view_blocked", view.name.clone());
                }
            }
            if self
                .blocked_domains
                .iter()
                .any(|blocked| domain_matches_normalized(&query_name, blocked))
            {
                return PolicyDecision {
                    allowed: false,
                    rcode: 3,
                    reason: "rpz_blocked",
                    matched_view: matched_view.map(|view| view.name.clone()),
                };
            }
        }

        if self.rate_limit_per_second > 0 && !self.consume_token(ctx.client_addr.ip()) {
            return PolicyDecision::refuse("rate_limited");
        }

        let mut decision = PolicyDecision::allow();
        decision.matched_view = matched_view.map(|view| view.name.clone());
        decision
    }

    /// Exposes policy runtime settings for admin /stats.
    pub fn snapshot(&self) -> PolicySnapshot {
        PolicySnapshot {
            allowed_clients_count: self.allowed_clients_count,
            blocked_domains_count: self.blocked_domains.len(),
            rate_limit_per_second: self.rate_limit_per_second,
            deny_any_queries: self.deny_any_queries,
        }
    }

    fn consume_token(&self, client_ip: IpAddr) -> bool {
        let Ok(mut windows) = self.client_windows.lock() else {
            return true;
        };

        let now = Instant::now();
        let window = windows.entry(client_ip).or_insert(RateWindow {
            started_at: now,
            count: 0,
        });

        if now.duration_since(window.started_at) >= Duration::from_secs(1) {
            window.started_at = now;
            window.count = 0;
        }

        if window.count >= self.rate_limit_per_second {
            return false;
        }

        window.count += 1;
        true
    }
}

#[cfg(test)]
fn domain_matches(query_name: &str, blocked: &str) -> bool {
    let pattern = normalize_domain_pattern(blocked);
    let query = normalize_query_name(query_name);
    if query.is_empty() || pattern.is_empty() {
        return false;
    }

    domain_matches_normalized(&query, &pattern)
}

fn domain_matches_normalized(query: &str, pattern: &str) -> bool {
    if query.is_empty() || pattern.is_empty() {
        return false;
    }

    // Wildcard pattern (`*.example.com`) matches any query ending with `example.com`.
    // This includes exact suffix match and deeper subdomains.
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() {
            return false;
        }
        return query == suffix || query.ends_with(&format!(".{suffix}"));
    }

    // Plain pattern matches exact domain only.
    query == pattern
}

fn normalize_query_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_domain_pattern(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    use super::{domain_matches, PolicyConfig, PolicyEngine};
    use crate::config::{DnsView, ViewRecord};
    use crate::context::{Protocol, RequestContext};

    #[test]
    fn domain_matches_plain_suffix_rule() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("www.example.com", "example.com"));
        assert!(!domain_matches("api.example.com", "example.com"));
        assert!(!domain_matches("badexample.com", "example.com"));
    }

    #[test]
    fn domain_matches_wildcard_rule() {
        assert!(domain_matches("www.example.com", "*.example.com"));
        assert!(domain_matches("a.b.example.com", "*.example.com"));
        assert!(domain_matches("example.com", "*.example.com"));
        assert!(!domain_matches("example.net", "*.example.com"));
    }

    #[test]
    fn domain_matches_is_case_insensitive_and_trailing_dot_safe() {
        assert!(domain_matches("WWW.Example.COM.", "*.example.com."));
    }

    #[test]
    fn domain_matches_required_www_abc_com_semantics() {
        // Plain rule matches exact only.
        assert!(domain_matches("www.abc.com", "www.abc.com"));
        assert!(!domain_matches("a.www.abc.com", "www.abc.com"));

        // Wildcard rule matches all domains ending with suffix.
        assert!(domain_matches("www.abc.com", "*.www.abc.com"));
        assert!(domain_matches("a.www.abc.com", "*.www.abc.com"));
        assert!(domain_matches("b.a.www.abc.com", "*.www.abc.com"));
        assert!(!domain_matches("www2.abc.com", "*.www.abc.com"));
    }

    #[test]
    fn split_horizon_uses_first_matching_view_and_refuses_blocked_domain() {
        let policy = PolicyEngine::new_with_views(
            PolicyConfig {
                allow_clients: Vec::new(),
                blocked_domains: Vec::new(),
                rate_limit_per_second: 0,
                deny_any_queries: false,
            },
            vec![
                DnsView {
                    name: "guest".to_string(),
                    client_cidrs: vec!["10.0.0.0/8".to_string()],
                    static_records: Vec::new(),
                    authoritative_records: Vec::new(),
                    records: vec![ViewRecord {
                        domain_name: "only.example.com".to_string(),
                        ip: "10.1.1.1".to_string(),
                    }],
                    blocked_domains: vec!["blocked.example.com".to_string()],
                    ..Default::default()
                },
                DnsView {
                    name: "later".to_string(),
                    client_cidrs: vec!["10.0.0.0/8".to_string()],
                    static_records: Vec::new(),
                    authoritative_records: Vec::new(),
                    records: Vec::new(),
                    blocked_domains: Vec::new(),
                    ..Default::default()
                },
            ],
        )
        .expect("policy");

        let ctx = RequestContext {
            request_id: 1,
            protocol: Protocol::Udp,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 53000),
            query_name: Some("blocked.example.com".to_string()),
            query_type: Some(1),
            recv_at: Instant::now(),
        };

        let decision = policy.evaluate(&ctx);
        assert!(!decision.allowed);
        assert_eq!(decision.rcode, 5);
        assert_eq!(decision.reason, "view_blocked");
        assert_eq!(decision.matched_view.as_deref(), Some("guest"));
    }

    #[test]
    fn split_horizon_keeps_config_order_even_with_more_specific_later_cidr() {
        let policy = PolicyEngine::new_with_views(
            PolicyConfig {
                allow_clients: Vec::new(),
                blocked_domains: Vec::new(),
                rate_limit_per_second: 0,
                deny_any_queries: false,
            },
            vec![
                DnsView {
                    name: "first".to_string(),
                    client_cidrs: vec!["10.0.0.0/8".to_string()],
                    static_records: Vec::new(),
                    authoritative_records: Vec::new(),
                    records: Vec::new(),
                    blocked_domains: Vec::new(),
                    ..Default::default()
                },
                DnsView {
                    name: "second".to_string(),
                    client_cidrs: vec!["10.1.0.0/16".to_string()],
                    static_records: Vec::new(),
                    authoritative_records: Vec::new(),
                    records: Vec::new(),
                    blocked_domains: Vec::new(),
                    ..Default::default()
                },
            ],
        )
        .expect("policy");

        let ctx = RequestContext {
            request_id: 1,
            protocol: Protocol::Udp,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 53000),
            query_name: Some("www.example.com".to_string()),
            query_type: Some(1),
            recv_at: Instant::now(),
        };

        let decision = policy.evaluate(&ctx);
        assert!(decision.allowed);
        assert_eq!(decision.matched_view.as_deref(), Some("first"));
    }

    #[test]
    fn acl_matcher_supports_ipv6_prefix_lookup() {
        let policy = PolicyEngine::new(PolicyConfig {
            allow_clients: vec!["2001:db8::/32".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        })
        .expect("policy");

        let allowed_ctx = RequestContext {
            request_id: 1,
            protocol: Protocol::Udp,
            client_addr: "[2001:db8::100]:53000"
                .parse::<SocketAddr>()
                .expect("socket"),
            query_name: Some("www.example.com".to_string()),
            query_type: Some(1),
            recv_at: Instant::now(),
        };

        let denied_ctx = RequestContext {
            request_id: 2,
            protocol: Protocol::Udp,
            client_addr: "[2001:dead::1]:53000"
                .parse::<SocketAddr>()
                .expect("socket"),
            query_name: Some("www.example.com".to_string()),
            query_type: Some(1),
            recv_at: Instant::now(),
        };

        let allowed = policy.evaluate(&allowed_ctx);
        assert!(allowed.allowed);

        let denied = policy.evaluate(&denied_ctx);
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "acl_denied");
    }

    #[test]
    fn split_horizon_falls_back_to_default_view_without_cidr_match() {
        let policy = PolicyEngine::new_with_views(
            PolicyConfig {
                allow_clients: Vec::new(),
                blocked_domains: Vec::new(),
                rate_limit_per_second: 0,
                deny_any_queries: false,
            },
            vec![DnsView {
                name: "default".to_string(),
                client_cidrs: Vec::new(),
                blocked_domains: vec!["www.abc.com".to_string()],
                ..Default::default()
            }],
        )
        .expect("policy");

        let ctx = RequestContext {
            request_id: 1,
            protocol: Protocol::Udp,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 53000),
            query_name: Some("www.abc.com".to_string()),
            query_type: Some(1),
            recv_at: Instant::now(),
        };

        let decision = policy.evaluate(&ctx);
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "view_blocked");
        assert_eq!(decision.matched_view.as_deref(), Some("default"));
    }

    #[test]
    fn split_horizon_without_default_view_keeps_global_behavior() {
        let policy = PolicyEngine::new_with_views(
            PolicyConfig {
                allow_clients: Vec::new(),
                blocked_domains: Vec::new(),
                rate_limit_per_second: 0,
                deny_any_queries: false,
            },
            vec![DnsView {
                name: "corp".to_string(),
                client_cidrs: vec!["10.0.0.0/8".to_string()],
                blocked_domains: vec!["www.abc.com".to_string()],
                ..Default::default()
            }],
        )
        .expect("policy");

        let ctx = RequestContext {
            request_id: 1,
            protocol: Protocol::Udp,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 53000),
            query_name: Some("www.abc.com".to_string()),
            query_type: Some(1),
            recv_at: Instant::now(),
        };

        let decision = policy.evaluate(&ctx);
        assert!(decision.allowed);
        assert!(decision.matched_view.is_none());
    }
}
