//! Request context shared across ingress, policy and resolver.
use std::net::SocketAddr;
use std::time::Instant;

use smol_str::SmolStr;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: u16,
    pub protocol: Protocol,
    pub client_addr: SocketAddr,
    /// DNS query name. SmolStr avoids heap allocation for names ≤22 bytes
    /// (covers the vast majority of real-world domains).
    pub query_name: Option<SmolStr>,
    pub query_type: Option<u16>,
    pub recv_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Udp,
    Tcp,
    Dot,
    Doh,
}

impl Protocol {
    /// 获取协议类型的字符串标签（用于日志和指标）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Dot => "dot",
            Self::Doh => "doh",
        }
    }
}
