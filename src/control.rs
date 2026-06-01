//! Private TCP control protocol used by agent and CLI.
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cache::CacheDump;

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

pub const CODE_OK: &str = "ok";
pub const CODE_UNAUTHORIZED: &str = "unauthorized";
pub const CODE_INVALID_REQUEST: &str = "invalid_request";
pub const CODE_UNSUPPORTED_VERSION: &str = "unsupported_version";
pub const CODE_START_FAILED: &str = "start_failed";
pub const CODE_STOP_FAILED: &str = "stop_failed";
pub const CODE_ADMIN_PROXY_FAILED: &str = "admin_proxy_failed";
pub const CODE_IO_FAILED: &str = "io_failed";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlCommand {
    Start,
    Stop,
    StopAll,
    Reload,
    Stats,
    Health,
    Ready,
    Version,
    CacheFreezeAll { enabled: bool },
    CacheFreezeDomain { domain: String, enabled: bool },
    CacheClearAll,
    CacheClearDomain { domain: String },
    CacheExport,
    CacheImport { dump: CacheDump },
    TopQueries { n: usize, window_secs: u64 },
    TopClients { n: usize, window_secs: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRequest {
    #[serde(default = "default_protocol_version")]
    pub version: u16,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(flatten)]
    pub command: ControlCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub version: u16,
    pub status: String,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ControlResponse {
    pub fn ok(message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            version: CONTROL_PROTOCOL_VERSION,
            status: "ok".to_string(),
            code: CODE_OK.to_string(),
            message: message.into(),
            data,
        }
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            version: CONTROL_PROTOCOL_VERSION,
            status: "error".to_string(),
            code: code.into(),
            message: message.into(),
            data: None,
        }
    }
}

fn default_protocol_version() -> u16 {
    CONTROL_PROTOCOL_VERSION
}

pub async fn read_request(stream: &mut TcpStream) -> anyhow::Result<ControlRequest> {
    let payload = read_frame(stream).await?;
    let req = serde_json::from_slice::<ControlRequest>(&payload)?;
    Ok(req)
}

pub async fn write_response(
    stream: &mut TcpStream,
    response: &ControlResponse,
) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(response)?;
    write_frame(stream, &payload).await
}

pub async fn send_request(
    server: &str,
    request: &ControlRequest,
) -> anyhow::Result<ControlResponse> {
    let mut stream = TcpStream::connect(server).await?;
    let payload = serde_json::to_vec(request)?;
    write_frame(&mut stream, &payload).await?;
    let raw = read_frame(&mut stream).await?;
    let response = serde_json::from_slice::<ControlResponse>(&raw)?;
    Ok(response)
}

async fn read_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    if len == 0 {
        return Err(anyhow!("empty frame"));
    }
    if len > MAX_FRAME_BYTES {
        return Err(anyhow!("frame too large: {len}"));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> anyhow::Result<()> {
    if payload.is_empty() {
        return Err(anyhow!("empty payload"));
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(anyhow!("payload too large: {}", payload.len()));
    }
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        read_request, write_response, ControlCommand, ControlRequest, ControlResponse,
        CONTROL_PROTOCOL_VERSION,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn read_request_accepts_valid_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let req = read_request(&mut socket).await.expect("read request");
            assert_eq!(req.version, CONTROL_PROTOCOL_VERSION);
            assert!(matches!(req.command, ControlCommand::Health));
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let payload = serde_json::to_vec(&ControlRequest {
            version: CONTROL_PROTOCOL_VERSION,
            token: None,
            command: ControlCommand::Health,
        })
        .expect("serialize");
        client
            .write_u32(payload.len() as u32)
            .await
            .expect("write len");
        client.write_all(&payload).await.expect("write payload");

        server.await.expect("join");
    }

    #[tokio::test]
    async fn read_request_rejects_invalid_json_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let result = read_request(&mut socket).await;
            assert!(result.is_err());
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let payload = b"{ not-json }";
        client
            .write_u32(payload.len() as u32)
            .await
            .expect("write len");
        client.write_all(payload).await.expect("write payload");

        server.await.expect("join");
    }

    #[tokio::test]
    async fn write_response_includes_version_and_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            write_response(
                &mut socket,
                &ControlResponse::ok("ok", Some(serde_json::json!({"k": 1}))),
            )
            .await
            .expect("write response");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let len = client.read_u32().await.expect("read len") as usize;
        let mut payload = vec![0u8; len];
        client.read_exact(&mut payload).await.expect("read payload");
        let resp: ControlResponse = serde_json::from_slice(&payload).expect("decode response");
        assert_eq!(resp.version, CONTROL_PROTOCOL_VERSION);
        assert_eq!(resp.code, "ok");

        server.await.expect("join");
    }

    #[tokio::test]
    async fn read_request_rejects_empty_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let err = read_request(&mut socket)
                .await
                .expect_err("empty frame should be rejected");
            assert!(format!("{err:#}").contains("empty frame"));
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client.write_u32(0).await.expect("write zero length");

        server.await.expect("join");
    }

    #[tokio::test]
    async fn read_request_rejects_truncated_frame_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let err = read_request(&mut socket)
                .await
                .expect_err("truncated frame should be rejected");
            let message = format!("{err:#}").to_ascii_lowercase();
            assert!(message.contains("early eof") || message.contains("unexpected end"));
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client.write_u32(8).await.expect("write declared length");
        client
            .write_all(b"{}{}")
            .await
            .expect("write partial payload");
        client.shutdown().await.expect("shutdown write half");

        server.await.expect("join");
    }

    #[tokio::test]
    async fn read_request_rejects_frame_larger_than_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let err = read_request(&mut socket)
                .await
                .expect_err("oversized frame should be rejected");
            assert!(format!("{err:#}").contains("frame too large"));
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client
            .write_u32((8 * 1024 * 1024 + 1) as u32)
            .await
            .expect("write oversized length");

        server.await.expect("join");
    }
}
