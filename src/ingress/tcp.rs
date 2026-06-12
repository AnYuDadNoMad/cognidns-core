//! TCP ingress server for DNS-over-TCP queries.
use std::net::SocketAddr;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use crate::codec::dns;
use crate::context::{Protocol, RequestContext};
use crate::service::AppState;

/// 启动 TCP DNS 服务监听，绑定端口并进入主循环。
pub async fn run_tcp_server(listen_addr: &str, state: AppState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind TCP listener on {listen_addr}"))?;

    serve_tcp(listener, state).await
}

/// TCP 主循环，接受连接并为每个连接启动异步处理。
pub async fn serve_tcp(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    let listen_addr = listener.local_addr()?;

    info!("TCP listener ready on {}", listen_addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state).await {
                error!(client = %peer, "tcp connection error: {}", err);
            }
        });
    }
}

/// 处理单个 TCP 连接，循环读取 DNS 查询并返回响应。
async fn handle_connection(mut stream: TcpStream, state: AppState) -> anyhow::Result<()> {
    let peer = stream.peer_addr()?;
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable tcp nodelay for client {peer}"))?;
    serve_dns_stream(&mut stream, peer, Protocol::Tcp, &state).await
}

/// 通用 DNS-over-Stream 处理函数，供 TCP 和 DoT 共用。
/// 循环读取 2 字节长度前缀 + DNS 消息体，处理后写回响应。
pub(crate) async fn serve_dns_stream<S>(
    stream: &mut S,
    peer: SocketAddr,
    protocol: Protocol,
    state: &AppState,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut msg_buf = Vec::with_capacity(4096);

    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 4096 {
            debug!(client = %peer, message_length = msg_len, "invalid dns tcp message length");
            return Ok(());
        }

        msg_buf.clear();
        msg_buf.resize(msg_len, 0);
        stream.read_exact(&mut msg_buf).await?;

        let overview = if let Some(overview) = dns::parse_request_overview(&msg_buf) {
            overview
        } else {
            debug!(client = %peer, "received malformed dns packet on tcp");
            continue;
        };

        let ctx = RequestContext {
            request_id: overview.id,
            protocol,
            client_addr: peer,
            query_name: overview.query_name,
            query_type: overview.query_type,
            recv_at: std::time::Instant::now(),
        };
        let qtype_text = dns::qtype_label_opt(ctx.query_type);

        if !dns::edns_version_supported(&msg_buf) {
            let response = dns::build_badvers_response(&msg_buf)?;
            state.metrics.record_request(
                ctx.protocol.as_str(),
                "protocol",
                dns::DNS_RCODE_BADVERS,
                ctx.recv_at.elapsed().as_secs_f64(),
            );
            let resp_len = (response.len() as u16).to_be_bytes();
            stream.write_all(&resp_len).await?;
            stream.write_all(&response).await?;
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
            state.record_top_query(&ctx, false);
            continue;
        }

        let policy = state.policy_evaluate(&ctx);
        state
            .metrics
            .record_policy_decision(policy.reason, policy.allowed);
        if !policy.allowed {
            let response = dns::build_response_with_rcode(&msg_buf, policy.rcode)?;
            state.metrics.record_request(
                ctx.protocol.as_str(),
                policy.reason,
                policy.rcode,
                ctx.recv_at.elapsed().as_secs_f64(),
            );
            let resp_len = (response.len() as u16).to_be_bytes();
            stream.write_all(&resp_len).await?;
            stream.write_all(&response).await?;
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

        // Resolver output is returned with source metadata for request metrics.
        let response = match state
            .resolve_with_view(&ctx, &msg_buf, policy.matched_view.as_deref())
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
                match dns::build_servfail_response(&msg_buf) {
                    Ok(data) => data,
                    Err(build_err) => {
                        error!(client = %peer, "failed to build fallback dns response: {}", build_err);
                        continue;
                    }
                }
            }
        };

        let rcode = dns::response_code(&response).unwrap_or(2);
        let bytes = response.len();
        let resp_len = (bytes as u16).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;
        info!(target: "response",
            request_id = ctx.request_id,
            protocol = ctx.protocol.as_str(),
            client = %ctx.client_addr,
            qname = ?ctx.query_name,
            rcode,
            bytes,
            elapsed_ms = ctx.recv_at.elapsed().as_millis(),
            "dns response sent"
        );
    }
}
