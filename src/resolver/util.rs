//! Resolver utility functions: name normalization, cache key construction,
//! response normalization, packet tracing, and sharding helpers.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

use smol_str::SmolStr;
use tracing::trace;

use crate::cache::CacheKey;
use crate::codec::dns;

use super::types::{AuthoritativeSourceEntry, StaticRecordEntry};

// ── Constants ────────────────────────────────────────────────────────────────

pub(super) const DNSSEC_BAD_CACHE_CAPACITY: usize = 256;
pub(super) const DNSSEC_BAD_CACHE_MAX_TTL_SECS: u64 = 30;
pub(super) const NS_HOST_FAILURE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

// ── Query ID generation ──────────────────────────────────────────────────────

pub(super) static ITERATIVE_QUERY_ID: AtomicUsize = AtomicUsize::new(10_000);

pub(super) fn next_iterative_query_id() -> u16 {
    (ITERATIVE_QUERY_ID.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16
}

// ── Name normalization & cache keys ──────────────────────────────────────────

pub(super) fn normalize_qname(qname: &str) -> String {
    let normalized = qname.trim().trim_end_matches('.');
    if normalized.is_empty() || normalized == "." {
        return ".".to_string();
    }
    normalized.to_ascii_lowercase()
}

pub(super) fn cache_key_for_query(qname: &str, qtype: u16, dnssec_ok: bool) -> CacheKey {
    CacheKey {
        qname: SmolStr::from(normalize_qname(qname)),
        qtype,
        dnssec_ok,
    }
}

pub(super) fn iter_domain_suffixes(qname: &str) -> Vec<String> {
    let normalized = normalize_qname(qname);
    if normalized == "." {
        return Vec::new();
    }
    let labels = normalized.split('.').collect::<Vec<_>>();
    let mut suffixes = Vec::with_capacity(labels.len());
    for index in 0..labels.len() {
        suffixes.push(labels[index..].join("."));
    }
    suffixes
}

pub(super) fn iterative_minimized_qname(qname: &str, depth: usize) -> String {
    let normalized = normalize_qname(qname);
    if normalized == "." {
        return ".".to_string();
    }
    let suffixes = iter_domain_suffixes(&normalized);
    suffixes
        .into_iter()
        .rev()
        .nth(depth)
        .unwrap_or(normalized)
}

pub(super) fn domain_is_same_or_subdomain_of(qname: &str, zone: &str) -> bool {
    let qname = normalize_qname(qname);
    let zone = normalize_qname(zone);
    if zone == "." {
        return true;
    }
    qname == zone || qname.ends_with(&format!(".{zone}"))
}

// ── Record qtype parsing ─────────────────────────────────────────────────────

pub(super) fn parse_record_qtype(qtype: &str) -> Option<u16> {
    let normalized = qtype.trim().trim_end_matches('.').to_ascii_uppercase();
    match normalized.as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "SVCB" => Some(64),
        "HTTPS" => Some(65),
        "CAA" => Some(257),
        "ANY" => Some(255),
        _ => normalized.parse::<u16>().ok(),
    }
}

/// 解析权威区记录类型（扩展版，支持 A/AAAA/CNAME/MX/TXT/NS/PTR）。
pub(super) fn parse_zone_record_qtype(qtype: &str) -> Option<u16> {
    match qtype.trim().to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "PTR" => Some(12),
        _ => None,
    }
}

// ── Packet tracing ───────────────────────────────────────────────────────────

/// 简要描述 DNS 包内容。
fn packet_summary(packet: &[u8]) -> String {
    let header = dns::parse_header(packet).ok();
    let question = dns::parse_first_question(packet);
    let id = header.map(|h| h.id).unwrap_or(0);
    let response = dns::parse_response_overview(packet);
    let rcode = response.map(|value| value.rcode).unwrap_or(0xFFFF);
    let ancount = response.map(|value| value.ancount).unwrap_or(0);
    let qname = question.as_ref().map(|q| q.0.as_str()).unwrap_or("-");
    let qtype = question.as_ref().map(|q| q.1).unwrap_or(0);
    let qtype_text = dns::qtype_label(qtype);
    format!(
        "id={} qname={} qtype={} rcode={} ancount={}",
        id, qname, qtype_text, rcode, ancount
    )
}

/// 生成 DNS 包的十六进制预览字符串。
fn packet_hex_preview(packet: &[u8], max_len: usize) -> String {
    let take_len = packet.len().min(max_len);
    let mut out = String::with_capacity(take_len * 3 + 16);
    for (idx, b) in packet.iter().take(take_len).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:02x}", b));
    }
    if packet.len() > take_len {
        out.push_str(" ...");
    }
    out
}

// Disabled by default to avoid high-volume binary payload logging in trace mode.
const TRACE_DNS_HEX_PREVIEW_ENABLED: bool = false;

pub(super) fn trace_dns_packet(address: &str, packet: &[u8], message: &str) {
    if !tracing::enabled!(tracing::Level::TRACE) {
        return;
    }
    if TRACE_DNS_HEX_PREVIEW_ENABLED {
        trace!(
            resolver = %address,
            bytes = packet.len(),
            packet = %packet_summary(packet),
            hex_preview = %packet_hex_preview(packet, 96),
            "{}",
            message
        );
    } else {
        trace!(
            resolver = %address,
            bytes = packet.len(),
            packet = %packet_summary(packet),
            "{}",
            message
        );
    }
}

// ── Response normalization ───────────────────────────────────────────────────

/// 对响应包进行规范化，修正 CNAME 链和问题部分。
pub(super) fn finalize_response_for_client(request: &[u8], response: &[u8]) -> Vec<u8> {
    let mut packet = None::<Vec<u8>>;
    let mut can_safe_rewrite_question = false;

    if let Some((_, qtype, _)) = dns::parse_first_question(request) {
        let current = packet.as_deref().unwrap_or(response);
        if (qtype == 1 || qtype == 28) && dns::extract_first_answer_cname(current).is_some() {
            if let Some(normalized) =
                crate::codec::dns_rfc_patch::normalize_cname_chain_answers(current, qtype)
            {
                packet = Some(normalized);
            }
            can_safe_rewrite_question =
                dns::extract_first_answer_cname(packet.as_deref().unwrap_or(response)).is_some();
        }
    }

    if can_safe_rewrite_question {
        let current = packet.as_deref().unwrap_or(response);
        if let Some(rewritten) = dns::rewrite_question_and_reencode_answers(current, request) {
            packet = Some(rewritten);
        }
    } else if !question_sections_match(packet.as_deref().unwrap_or(response), request)
        .unwrap_or(false)
    {
        let current = packet.as_deref().unwrap_or(response);
        if let Some(rewritten) = dns::rewrite_question_from_request(current, request) {
            packet = Some(rewritten);
        }
    }

    let current = packet.as_deref().unwrap_or(response);
    if let Some(aligned) = dns::align_response_edns_to_request(current, request) {
        packet = Some(aligned);
    }

    if let Some(mut packet) = packet {
        normalize_response_for_client_in_place(request, &mut packet);
        packet
    } else {
        normalize_response_for_client(request, response)
    }
}

/// 规范化响应包头部，保证与请求一致。
pub(super) fn normalize_response_for_client(request: &[u8], response: &[u8]) -> Vec<u8> {
    if request.len() < 12 || response.len() < 12 {
        return response.to_vec();
    }

    let mut packet = response.to_vec();
    normalize_response_for_client_in_place(request, &mut packet);
    packet
}

fn normalize_response_for_client_in_place(request: &[u8], packet: &mut [u8]) {
    if request.len() < 12 || packet.len() < 12 {
        return;
    }

    packet[0..2].copy_from_slice(&request[0..2]);

    let req_flags = u16::from_be_bytes([request[2], request[3]]);
    let mut resp_flags = u16::from_be_bytes([packet[2], packet[3]]);
    resp_flags = (resp_flags & !0x0100) | (req_flags & 0x0100);
    resp_flags |= 0x8000;
    resp_flags &= !0x0400;
    resp_flags |= 0x0080;
    packet[2..4].copy_from_slice(&resp_flags.to_be_bytes());
}

pub(super) fn build_refused_response_without_ra(request: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut packet = dns::build_response_with_rcode(request, 5)?;
    if packet.len() >= 4 {
        let mut flags = u16::from_be_bytes([packet[2], packet[3]]);
        flags &= !0x0080;
        packet[2..4].copy_from_slice(&flags.to_be_bytes());
    }
    Ok(packet)
}

fn question_sections_match(packet: &[u8], request: &[u8]) -> Option<bool> {
    if packet.len() < 12 || request.len() < 12 {
        return Some(false);
    }

    let pkt_header = dns::parse_header(packet).ok()?;
    let req_header = dns::parse_header(request).ok()?;

    let mut pkt_q_end = 12usize;
    for _ in 0..pkt_header.qdcount {
        pkt_q_end = dns::skip_name(packet, pkt_q_end)?;
        if pkt_q_end + 4 > packet.len() {
            return None;
        }
        pkt_q_end += 4;
    }

    let mut req_q_end = 12usize;
    for _ in 0..req_header.qdcount {
        req_q_end = dns::skip_name(request, req_q_end)?;
        if req_q_end + 4 > request.len() {
            return None;
        }
        req_q_end += 4;
    }

    Some(packet[12..pkt_q_end] == request[12..req_q_end])
}

// ── Sharding helpers ─────────────────────────────────────────────────────────

pub(super) fn aux_cache_shard_count(capacity: usize) -> usize {
    let preferred = std::thread::available_parallelism()
        .map(|parallelism| (parallelism.get() * 2).clamp(8, 64))
        .unwrap_or(16);
    if capacity == 0 {
        preferred
    } else {
        preferred.min(capacity.max(1))
    }
}

pub(super) fn aux_cache_shard_index(key: &str, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}

pub(super) fn bounded_aux_shard_capacity(
    total_capacity: usize,
    shard_index: usize,
    shard_count: usize,
) -> Option<usize> {
    if total_capacity == 0 {
        return None;
    }
    let base = total_capacity / shard_count;
    let remainder = total_capacity % shard_count;
    Some(base + usize::from(shard_index < remainder))
}

// ── Index construction ───────────────────────────────────────────────────────

pub(super) fn build_static_record_index(
    records: Vec<crate::config::StaticRecord>,
) -> std::collections::HashMap<CacheKey, StaticRecordEntry> {
    let mut index = std::collections::HashMap::with_capacity(records.len());
    for record in records {
        let Some(qtype) = parse_record_qtype(&record.qtype) else {
            tracing::warn!(qname = %record.qname, qtype = %record.qtype, "skip static record with unsupported qtype");
            continue;
        };
        index
            .entry(cache_key_for_query(&record.qname, qtype, false))
            .or_insert_with(|| StaticRecordEntry {
                answer: record.answer,
                ttl: record.ttl,
                qtype_name: record.qtype,
            });
    }
    index
}

pub(super) fn build_authoritative_source_index(
    sources: Vec<crate::config::AuthoritativeSource>,
) -> std::collections::HashMap<CacheKey, AuthoritativeSourceEntry> {
    let mut index = std::collections::HashMap::with_capacity(sources.len());
    for source in sources {
        let Some(qtype) = parse_record_qtype(&source.qtype) else {
            tracing::warn!(qname = %source.qname, qtype = %source.qtype, "skip authoritative source with unsupported qtype");
            continue;
        };
        index
            .entry(cache_key_for_query(&source.qname, qtype, false))
            .or_insert_with(|| AuthoritativeSourceEntry {
                source: source.source,
                ttl: source.ttl,
                qtype_name: source.qtype,
            });
    }
    index
}

// ── InFlightRole ─────────────────────────────────────────────────────────────

pub(super) enum InFlightRole {
    Owner(std::sync::Arc<tokio::sync::Notify>),
    Wait(std::sync::Arc<tokio::sync::Notify>),
}
