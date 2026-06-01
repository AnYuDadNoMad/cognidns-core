//! UDP ingress server for DNS queries.
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::codec::dns;
use crate::context::{Protocol, RequestContext};
use crate::service::AppState;

/// 启动 UDP DNS 服务监听，绑定端口并进入主循环。
pub async fn run_udp_server(listen_addr: &str, state: AppState) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket on {listen_addr}"))?;

    serve_udp(socket, state).await
}

/// UDP 主循环，接收 DNS 查询并返回响应。
pub async fn serve_udp(socket: UdpSocket, state: AppState) -> anyhow::Result<()> {
    let listen_addr = socket.local_addr()?;
    let socket = Arc::new(socket);

    info!("UDP listener ready on {}", listen_addr);

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(err) => {
                // Windows UDP sockets can surface ICMP port-unreachable as WSAECONNRESET (10054).
                // Treat receive errors as transient and keep serving subsequent packets.
                if err.raw_os_error() == Some(10054) {
                    debug!("udp recv_from transient WSAECONNRESET(10054), continuing");
                } else {
                    warn!("udp recv_from failed, continuing: {}", err);
                }
                continue;
            }
        };
        let request = &buf[..len];

        let overview = if let Some(overview) = dns::parse_request_overview(request) {
            overview
        } else {
            debug!("received malformed dns packet from {}", peer);
            continue;
        };

        let ctx = RequestContext {
            request_id: overview.id,
            protocol: Protocol::Udp,
            client_addr: peer,
            query_name: overview.query_name,
            query_type: overview.query_type,
            recv_at: std::time::Instant::now(),
        };
        let qtype_text = dns::qtype_label_opt(ctx.query_type);

        if !dns::edns_version_supported(request) {
            let response = match dns::build_badvers_response(request) {
                Ok(packet) => packet,
                Err(err) => {
                    error!(client = %peer, "failed to build badvers response: {}", err);
                    continue;
                }
            };
            state.metrics.record_request(
                ctx.protocol.as_str(),
                "protocol",
                dns::DNS_RCODE_BADVERS,
                ctx.recv_at.elapsed().as_secs_f64(),
            );
            info!(target: "query",
                request_id = ctx.request_id,
                protocol = ctx.protocol.as_str(),
                client = %ctx.client_addr,
                qname = ?ctx.query_name,
                qtype = %qtype_text,
                source = "protocol",
                rcode = dns::DNS_RCODE_BADVERS,
                elapsed_ms = ctx.recv_at.elapsed().as_millis(),
                "dns query rejected due to unsupported edns version"
            );
            if let Err(err) = socket.send_to(&response, peer).await {
                error!(client = %peer, "failed to send badvers response: {}", err);
            }
            state.record_top_query(&ctx, false);
            continue;
        }

        let policy = state.policy_evaluate(&ctx);
        state
            .metrics
            .record_policy_decision(policy.reason, policy.allowed);
        if !policy.allowed {
            let response = match dns::build_response_with_rcode(request, policy.rcode) {
                Ok(packet) => packet,
                Err(err) => {
                    error!(client = %peer, "failed to build policy response: {}", err);
                    continue;
                }
            };
            state.metrics.record_request(
                ctx.protocol.as_str(),
                policy.reason,
                policy.rcode,
                ctx.recv_at.elapsed().as_secs_f64(),
            );
            if let Err(err) = socket.send_to(&response, peer).await {
                error!(client = %peer, "failed to send policy response: {}", err);
            }
            info!(target: "query",
                request_id = ctx.request_id,
                protocol = ctx.protocol.as_str(),
                client = %ctx.client_addr,
                qname = ?ctx.query_name,
                qtype = %qtype_text,
                source = policy.reason,
                rcode = policy.rcode,
                elapsed_ms = ctx.recv_at.elapsed().as_millis(),
                "dns query denied by policy"
            );
            state.record_top_query(&ctx, false);
            continue;
        }

        // Resolve after policy decision and track source labels in metrics.
        let response = match state
            .resolve_with_view(&ctx, request, policy.matched_view.as_deref())
            .await
        {
            Ok(result) => {
                let rcode = dns::response_code(&result.packet).unwrap_or(2);
                state.record_top_query(&ctx, rcode == 0);
                state.metrics.record_request(
                    ctx.protocol.as_str(),
                    result.source.label(),
                    rcode,
                    ctx.recv_at.elapsed().as_secs_f64(),
                );
                info!(target: "query",
                    request_id = ctx.request_id,
                    protocol = ctx.protocol.as_str(),
                    client = %ctx.client_addr,
                    qname = ?ctx.query_name,
                    qtype = %qtype_text,
                    source = result.source.label(),
                    rcode,
                    elapsed_ms = ctx.recv_at.elapsed().as_millis(),
                    "dns query resolved"
                );
                result.packet
            }
            Err(err) => {
                state.record_top_query(&ctx, false);
                error!(client = %peer, "failed to resolve dns request: {}", err);
                info!(target: "query",
                    request_id = ctx.request_id,
                    protocol = ctx.protocol.as_str(),
                    client = %ctx.client_addr,
                    qname = ?ctx.query_name,
                    qtype = %qtype_text,
                    source = "error",
                    rcode = 2u8,
                    elapsed_ms = ctx.recv_at.elapsed().as_millis(),
                    "dns query error"
                );
                match dns::build_servfail_response(request) {
                    Ok(data) => data,
                    Err(build_err) => {
                        error!(client = %peer, "failed to build fallback dns response: {}", build_err);
                        continue;
                    }
                }
            }
        };

        if let Err(err) = socket.send_to(&response, peer).await {
            error!(client = %peer, "failed to send dns response: {}", err);
        } else {
            info!(target: "response",
                request_id = ctx.request_id,
                protocol = ctx.protocol.as_str(),
                client = %ctx.client_addr,
                qname = ?ctx.query_name,
                rcode = dns::response_code(&response).unwrap_or(2),
                bytes = response.len(),
                elapsed_ms = ctx.recv_at.elapsed().as_millis(),
                "dns response sent"
            );
        }
    }
}

/// 辅助函数：将 SocketAddr 转为字符串。
#[allow(dead_code)]
fn _peer_to_string(peer: SocketAddr) -> String {
    peer.to_string()
}
