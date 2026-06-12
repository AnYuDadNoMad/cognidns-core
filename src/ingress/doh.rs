//! DNS-over-HTTPS (DoH) ingress server (RFC 8484).
//!
//! 暴露两个端点：
//!   GET  /dns-query?dns=<base64url>        (Content-Type: application/dns-message)
//!   POST /dns-query                        (body: DNS wire-format，Content-Type: application/dns-message)
//!
//! 返回二进制 DNS 响应（Content-Type: application/dns-message）。
//! 若需 HTTPS，建议使用 TLS 反向代理（nginx/caddy）在前面终止 TLS；
//! 或直接使用 DoT 端口（src/ingress/dot.rs）。
use std::net::SocketAddr;

use anyhow::Context;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::codec::dns;
use crate::context::{Protocol, RequestContext};
use crate::service::AppState;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(Debug, Deserialize)]
struct DnsQueryParams {
    dns: Option<String>,
}

/// 启动 DoH HTTP 服务，绑定端口并进入主循环。
pub async fn run_doh_server(listen_addr: &str, state: AppState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind DoH listener on {listen_addr}"))?;
    serve_doh(listener, state).await
}

/// 在已绑定的 TcpListener 上启动 DoH 服务（供集成测试复用）。
pub async fn serve_doh(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/dns-query", get(handle_get).post(handle_post))
        .with_state(state);
    let listen_addr = listener.local_addr()?;
    info!("DoH listener ready on {}", listen_addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("DoH server error: {}", e))
}

/// GET /dns-query?dns=<base64url>
async fn handle_get(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(params): Query<DnsQueryParams>,
) -> Response {
    let dns_param = match params.dns {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing 'dns' query parameter").into_response(),
    };
    // RFC 8484 §6: base64url without padding
    let wire = match BASE64URL_NOPAD.decode(dns_param.as_bytes()) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid base64url in 'dns' parameter",
            )
                .into_response()
        }
    };
    serve_dns_over_http(&state, peer, wire).await
}

/// POST /dns-query (body: raw DNS wire-format)
async fn handle_post(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with(DNS_MESSAGE_CONTENT_TYPE) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/dns-message",
        )
            .into_response();
    }
    serve_dns_over_http(&state, peer, body.to_vec()).await
}

/// 通用 DoH 请求处理：解析 DNS 报文 → 策略 → 解析 → 返回二进制响应。
async fn serve_dns_over_http(state: &AppState, peer: SocketAddr, wire: Vec<u8>) -> Response {
    let overview = match dns::parse_request_overview(&wire) {
        Some(o) => o,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let ctx = RequestContext {
        request_id: overview.id,
        protocol: Protocol::Doh,
        client_addr: peer,
        query_name: overview.query_name,
        query_type: overview.query_type,
        recv_at: std::time::Instant::now(),
    };
    let qtype_text = dns::qtype_label_opt(ctx.query_type);

    // EDNS version check
    if !dns::edns_version_supported(&wire) {
        let response = match dns::build_badvers_response(&wire) {
            Ok(r) => r,
            Err(e) => {
                error!(client = %peer, "doh: failed to build badvers response: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
        state.record_top_query(&ctx, false);
        return dns_wire_response(response);
    }

    // Policy check
    let policy = state.policy_evaluate(&ctx);
    state
        .metrics
        .record_policy_decision(policy.reason, policy.allowed);
    if !policy.allowed {
        let response = match dns::build_response_with_rcode(&wire, policy.rcode) {
            Ok(r) => r,
            Err(e) => {
                error!(client = %peer, "doh: failed to build policy deny response: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        state.metrics.record_request(
            ctx.protocol.as_str(),
            policy.reason,
            policy.rcode,
            ctx.recv_at.elapsed().as_secs_f64(),
        );
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
        return dns_wire_response(response);
    }

    // Resolve
    let response_bytes = match state
        .resolve_with_view(&ctx, &wire, policy.matched_view.as_deref())
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
            let rcode = dns::response_code(&result.packet).unwrap_or(2);
            let bytes = result.packet.len();
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
            result.packet
        }
        Err(err) => {
            state.record_top_query(&ctx, false);
            error!(client = %peer, "doh: failed to resolve dns request: {}", err);
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
            state.metrics.record_request(
                ctx.protocol.as_str(),
                "error",
                2u16,
                ctx.recv_at.elapsed().as_secs_f64(),
            );
            match dns::build_servfail_response(&wire) {
                Ok(data) => data,
                Err(build_err) => {
                    error!(client = %peer, "doh: failed to build servfail response: {}", build_err);
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
    };

    dns_wire_response(response_bytes)
}

/// 将 DNS wire 格式字节包装为 HTTP 200 响应（Content-Type: application/dns-message）。
fn dns_wire_response(wire: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)],
        wire,
    )
        .into_response()
}
