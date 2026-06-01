//! DNS-over-TLS (DoT) ingress server (RFC 7858).
//!
//! Listens on a configurable port (default 853), performs a TLS handshake using
//! the configured certificate/key pair, then reuses the same DNS-over-TCP framing
//! logic as the plain TCP ingress.
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::context::Protocol;
use crate::service::AppState;

use super::tcp::serve_dns_stream;

/// 启动 DoT 服务监听，加载 TLS 配置后进入主循环。
pub async fn run_dot_server(
    listen_addr: &str,
    cert_file: &str,
    key_file: &str,
    state: AppState,
) -> anyhow::Result<()> {
    let tls_config = build_tls_config(cert_file, key_file)
        .with_context(|| format!("failed to build TLS config (cert={cert_file} key={key_file})"))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind DoT listener on {listen_addr}"))?;

    info!("DoT listener ready on {}", listen_addr);

    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_dot_connection(tcp_stream, peer, acceptor, state).await {
                error!(client = %peer, "dot connection error: {}", err);
            }
        });
    }
}

/// 处理单个 DoT 连接：TLS 握手 → 复用 DNS-over-TCP 帧处理逻辑。
async fn handle_dot_connection(
    tcp_stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    state: AppState,
) -> anyhow::Result<()> {
    let mut tls_stream = acceptor
        .accept(tcp_stream)
        .await
        .with_context(|| format!("TLS handshake failed for {peer}"))?;
    serve_dns_stream(&mut tls_stream, peer, Protocol::Dot, &state).await
}

/// 从 PEM 文件加载证书链和私钥，构建 rustls ServerConfig。
fn build_tls_config(cert_file: &str, key_file: &str) -> anyhow::Result<rustls::ServerConfig> {
    // Load certificate chain.
    let cert_bytes = std::fs::read(cert_file)
        .with_context(|| format!("failed to read TLS cert file: {cert_file}"))?;
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_bytes.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse TLS cert file: {cert_file}"))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in {cert_file}"));
    }

    // Load private key.
    let key_bytes = std::fs::read(key_file)
        .with_context(|| format!("failed to read TLS key file: {key_file}"))?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_ref())
        .with_context(|| format!("failed to parse TLS key file: {key_file}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {key_file}"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS certificate and key do not match")?;

    Ok(config)
}
