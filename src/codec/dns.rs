/// 构造静态记录响应，支持 A/AAAA/CNAME/MX/TXT/NS/PTR。
pub fn build_static_answer(request: &[u8], answer: &str, ttl: u32, qtype: &str) -> Result<Vec<u8>> {
    let (qname, qtype_num, qend) =
        parse_first_question(request).ok_or_else(|| anyhow!("invalid dns question"))?;
    let mut response = Vec::with_capacity(512);
    let header = parse_header(request)?;
    response.extend_from_slice(&header.id.to_be_bytes());
    // QR=1, OPCODE copied, RD copied, RA=1, RCODE=0
    let opcode = header.flags & 0x7800;
    let rd = header.flags & 0x0100;
    let flags = 0x8000 | opcode | rd | 0x0080;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    response.extend_from_slice(&request[12..qend]);
    // Answer section
    encode_name(&qname, &mut response);
    let typenum = match qtype.to_ascii_uppercase().as_str() {
        "A" => 1u16,
        "AAAA" => 28u16,
        "CNAME" => 5u16,
        "NS" => 2u16,
        "MX" => 15u16,
        "TXT" => 16u16,
        "PTR" => 12u16,
        _ => qtype_num,
    };
    response.extend_from_slice(&typenum.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // IN
    response.extend_from_slice(&ttl.to_be_bytes());
    let rdata = encode_record_rdata(typenum, answer)
        .map_err(|_| anyhow!("unsupported static record type"))?;
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);
    let _ = maybe_append_request_edns_opt(request, &mut response);
    Ok(response)
}

/// 伪实现：模拟权威源数据获取，实际应为 HTTP 请求或外部命令。
pub async fn fetch_authoritative_answer(
    _source: &str,
    _qname: &str,
    _qtype: &str,
) -> Result<String> {
    // 实际实现应根据 source 类型发起 HTTP 请求或本地查询
    // 这里只返回固定值用于演示
    Ok("6.6.6.6".to_string())
}

/// 构造权威 DNS 响应（AA=1），支持 A/AAAA/CNAME/MX/TXT/NS/PTR 类型。
/// 与 `build_static_answer` 相同，但在 flags 中设置 AA bit（0x0400）。
pub fn build_authoritative_answer(
    request: &[u8],
    answer: &str,
    ttl: u32,
    qtype: &str,
) -> Result<Vec<u8>> {
    let owned = answer.to_owned();
    build_authoritative_answer_multi(request, std::slice::from_ref(&owned), ttl, qtype)
}

/// 构造权威 DNS 响应（AA=1），支持多条 RR（ANCOUNT ≥ 1，符合 RFC 1035）。
/// 对同名同类型的多条资源记录（如多个 A、多个 MX、多个 NS）编码到应答区。
pub fn build_authoritative_answer_multi(
    request: &[u8],
    answers: &[String],
    ttl: u32,
    qtype: &str,
) -> Result<Vec<u8>> {
    if answers.is_empty() {
        return Err(anyhow!("answers must not be empty"));
    }
    let (qname, qtype_num, qend) =
        parse_first_question(request).ok_or_else(|| anyhow!("invalid dns question"))?;
    let typenum = match qtype.to_ascii_uppercase().as_str() {
        "A" => 1u16,
        "AAAA" => 28u16,
        "CNAME" => 5u16,
        "NS" => 2u16,
        "MX" => 15u16,
        "TXT" => 16u16,
        "PTR" => 12u16,
        _ => qtype_num,
    };
    let mut response = Vec::with_capacity(512);
    let header = parse_header(request)?;
    response.extend_from_slice(&header.id.to_be_bytes());
    // QR=1, AA=1, OPCODE copied, RD copied, RA=1, RCODE=0
    let opcode = header.flags & 0x7800;
    let rd = header.flags & 0x0100;
    let flags = 0x8000 | 0x0400 | opcode | rd | 0x0080;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                                                     // 先写占位 ANCOUNT，稍后回填
    let ancount_offset = response.len();
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT placeholder
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                     // Question section（原样复制）
    response.extend_from_slice(&request[12..qend]);
    // Answer section：每条 answer 一条 RR
    let mut ancount: u16 = 0;
    for ans in answers {
        let rdata = match encode_record_rdata(typenum, ans) {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(answer = %ans, qtype, error = %err, "skip malformed zone record rdata");
                continue;
            }
        };
        encode_name(&qname, &mut response);
        response.extend_from_slice(&typenum.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
        ancount = ancount.saturating_add(1);
    }
    if ancount == 0 {
        return Err(anyhow!(
            "all zone record rdata encoding failed for qtype={qtype}"
        ));
    }
    // 回填 ANCOUNT
    let ancount_bytes = ancount.to_be_bytes();
    response[ancount_offset] = ancount_bytes[0];
    response[ancount_offset + 1] = ancount_bytes[1];
    let _ = maybe_append_request_edns_opt(request, &mut response);
    Ok(response)
}

/// 构造权威 NODATA 响应（NOERROR + AA=1 + 空答案区 + SOA authority section）。
///
/// 当查询名在权威区内**存在**但**无该类型记录**时返回，符合 RFC 2308 §2.2 NXRRSET 语义。
/// 不同于 NXDOMAIN：此处 QNAME 本身是有效的节点名，只是没有被查询类型的记录。
#[allow(clippy::too_many_arguments)]
pub fn build_authoritative_nodata(
    request: &[u8],
    zone_name: &str,
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32,
) -> Result<Vec<u8>> {
    let (_qname, _qtype_num, qend) =
        parse_first_question(request).ok_or_else(|| anyhow!("invalid dns question"))?;
    let mut response = Vec::with_capacity(512);
    let header = parse_header(request)?;
    response.extend_from_slice(&header.id.to_be_bytes());
    // QR=1, AA=1, OPCODE copied, RD copied, RA=1, RCODE=0 (NOERROR)
    let opcode = header.flags & 0x7800;
    let rd = header.flags & 0x0100;
    let flags = 0x8000 | 0x0400 | opcode | rd | 0x0080;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    response.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT = 1 (SOA)
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                     // Question section
    response.extend_from_slice(&request[12..qend]);
    // Authority section: SOA RR（TTL = SOA minimum，RFC 2308 §3）
    encode_name(zone_name, &mut response);
    response.extend_from_slice(&6u16.to_be_bytes()); // TYPE SOA
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    response.extend_from_slice(&minimum_ttl.to_be_bytes());
    let soa_rdata = encode_soa_rdata(mname, rname, serial, refresh, retry, expire, minimum_ttl);
    response.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&soa_rdata);
    let _ = maybe_append_request_edns_opt(request, &mut response);
    Ok(response)
}

/// 编码 SOA RDATA（RFC 1035）。
pub fn encode_soa_rdata(
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    encode_name(mname, &mut buf);
    encode_name(rname, &mut buf);
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.extend_from_slice(&refresh.to_be_bytes());
    buf.extend_from_slice(&retry.to_be_bytes());
    buf.extend_from_slice(&expire.to_be_bytes());
    buf.extend_from_slice(&minimum.to_be_bytes());
    buf
}

/// 构造权威 NXDOMAIN 响应（AA=1, RCODE=3），Authority section 含 SOA RR。
/// 当查询名在权威区内但无匹配记录时调用。
#[allow(clippy::too_many_arguments)]
pub fn build_authoritative_nxdomain(
    request: &[u8],
    zone_name: &str,
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32,
) -> Result<Vec<u8>> {
    let (_qname, _qtype_num, qend) =
        parse_first_question(request).ok_or_else(|| anyhow!("invalid dns question"))?;
    let mut response = Vec::with_capacity(512);
    let header = parse_header(request)?;
    response.extend_from_slice(&header.id.to_be_bytes());
    // QR=1, AA=1, OPCODE copied, RD copied, RA=1, RCODE=3 (NXDOMAIN)
    let opcode = header.flags & 0x7800;
    let rd = header.flags & 0x0100;
    let flags = 0x8000 | 0x0400 | opcode | rd | 0x0080 | 0x0003;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT (SOA)
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                     // Question section
    response.extend_from_slice(&request[12..qend]);
    // Authority section: SOA RR
    encode_name(zone_name, &mut response);
    response.extend_from_slice(&6u16.to_be_bytes()); // TYPE SOA
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    response.extend_from_slice(&minimum_ttl.to_be_bytes()); // TTL = SOA minimum
    let soa_rdata = encode_soa_rdata(mname, rname, serial, refresh, retry, expire, minimum_ttl);
    response.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&soa_rdata);
    let _ = maybe_append_request_edns_opt(request, &mut response);
    Ok(response)
}

/// 构造权威 SOA 响应（AA=1），用于区内 SOA 查询。
#[allow(clippy::too_many_arguments)]
pub fn build_authoritative_soa_answer(
    request: &[u8],
    zone_name: &str,
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32,
) -> Result<Vec<u8>> {
    let (_qname, _qtype_num, qend) =
        parse_first_question(request).ok_or_else(|| anyhow!("invalid dns question"))?;
    let mut response = Vec::with_capacity(512);
    let header = parse_header(request)?;
    response.extend_from_slice(&header.id.to_be_bytes());
    let opcode = header.flags & 0x7800;
    let rd = header.flags & 0x0100;
    let flags = 0x8000 | 0x0400 | opcode | rd | 0x0080;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    response.extend_from_slice(&request[12..qend]);

    encode_name(zone_name, &mut response);
    response.extend_from_slice(&6u16.to_be_bytes()); // TYPE SOA
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    response.extend_from_slice(&minimum_ttl.to_be_bytes());
    let soa_rdata = encode_soa_rdata(mname, rname, serial, refresh, retry, expire, minimum_ttl);
    response.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&soa_rdata);
    let _ = maybe_append_request_edns_opt(request, &mut response);
    Ok(response)
}

/// 在现有 DNS 响应报文末尾追加 Additional 资源记录，并更新 ARCOUNT。
pub fn append_additional_records(
    response: &[u8],
    records: &[DnsAdditionalRecord],
) -> Result<Vec<u8>> {
    if records.is_empty() {
        return Ok(response.to_vec());
    }

    let header = parse_header(response)?;
    let mut offset = skip_question_section(response, header)
        .ok_or_else(|| anyhow!("invalid question section"))?;

    for _ in 0..header.ancount {
        offset =
            skip_rr(response, offset).ok_or_else(|| anyhow!("invalid answer section record"))?;
    }
    for _ in 0..header.nscount {
        offset =
            skip_rr(response, offset).ok_or_else(|| anyhow!("invalid authority section record"))?;
    }
    for _ in 0..header.arcount {
        offset = skip_rr(response, offset)
            .ok_or_else(|| anyhow!("invalid additional section record"))?;
    }

    let mut out = response[..offset].to_vec();
    let mut appended: u16 = 0;

    for record in records {
        for answer in &record.answers {
            let rdata = match encode_record_rdata(record.rr_type, answer) {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!(
                        owner = %record.owner_name,
                        rr_type = record.rr_type,
                        answer = %answer,
                        error = %err,
                        "skip malformed additional record rdata"
                    );
                    continue;
                }
            };

            encode_name(&record.owner_name, &mut out)
                .ok_or_else(|| anyhow!("invalid additional owner name"))?;
            out.extend_from_slice(&record.rr_type.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&record.ttl.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&rdata);

            appended = appended
                .checked_add(1)
                .ok_or_else(|| anyhow!("additional records overflow"))?;
        }
    }

    out.extend_from_slice(&response[offset..]);
    if appended == 0 {
        return Ok(out);
    }

    let new_arcount = header
        .arcount
        .checked_add(appended)
        .ok_or_else(|| anyhow!("arcount overflow"))?;
    out[10..12].copy_from_slice(&new_arcount.to_be_bytes());
    Ok(out)
}

/// 将记录的文本 answer 编码为对应类型的 RDATA 字节序列。
fn encode_record_rdata(typenum: u16, answer: &str) -> Result<Vec<u8>> {
    match typenum {
        1 => {
            // A 记录
            answer
                .parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.octets().to_vec())
                .map_err(|_| anyhow!("invalid A record ip: {answer}"))
        }
        28 => {
            // AAAA 记录
            answer
                .parse::<std::net::Ipv6Addr>()
                .map(|ip| ip.octets().to_vec())
                .map_err(|_| anyhow!("invalid AAAA record ip: {answer}"))
        }
        5 | 2 | 12 => {
            // CNAME / NS / PTR — domain-name encoded
            let mut buf = Vec::with_capacity(answer.len() + 2);
            encode_name(answer, &mut buf)
                .ok_or_else(|| anyhow!("invalid domain name: {answer}"))?;
            Ok(buf)
        }
        15 => {
            // MX: "priority exchange"
            let trimmed = answer.trim();
            let mut parts = trimmed.splitn(2, ' ');
            let priority_str = parts.next().unwrap_or("");
            let exchange = parts.next().unwrap_or("").trim();
            let priority: u16 = priority_str
                .parse()
                .map_err(|_| anyhow!("invalid MX priority: {answer}"))?;
            if exchange.is_empty() {
                return Err(anyhow!("missing MX exchange in: {answer}"));
            }
            let mut buf = Vec::with_capacity(exchange.len() + 4);
            buf.extend_from_slice(&priority.to_be_bytes());
            encode_name(exchange, &mut buf)
                .ok_or_else(|| anyhow!("invalid MX exchange domain: {exchange}"))?;
            Ok(buf)
        }
        16 => {
            // TXT: length-prefixed character-strings (single string, max 255 bytes per segment)
            let bytes = answer.as_bytes();
            let mut buf = Vec::with_capacity(bytes.len() + 1);
            for chunk in bytes.chunks(255) {
                buf.push(chunk.len() as u8);
                buf.extend_from_slice(chunk);
            }
            Ok(buf)
        }
        _ => Err(anyhow!("unsupported record type: {typenum}")),
    }
}
use std::ops::ControlFlow;
/// Minimal DNS codec utilities used by ingress and resolver.
use std::time::Duration;

use anyhow::{anyhow, Result};
use smol_str::SmolStr;

#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, Clone)]
pub struct DnsRequestOverview {
    pub id: u16,
    pub query_name: Option<SmolStr>,
    pub query_type: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct DnsResponseOverview {
    pub id: u16,
    pub rcode: u16,
    pub ancount: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsEdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsEdnsClientSubnet {
    pub family: u16,
    pub source_prefix: u8,
    pub scope_prefix: u8,
    pub address: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DnsEdnsOpt {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub options: Vec<DnsEdnsOption>,
}

pub const DNS_RCODE_FORMERR: u16 = 1;
pub const DNS_RCODE_SERVFAIL: u16 = 2;
pub const DNS_RCODE_NOTIMP: u16 = 4;
pub const DNS_RCODE_REFUSED: u16 = 5;
pub const DNS_RCODE_BADVERS: u16 = 16;
pub const DNS_FLAG_AD: u16 = 0x0020;
pub const DNS_FLAG_CD: u16 = 0x0010;
pub const DNS_EDNS_FLAG_DO: u16 = 0x8000;
pub const DNS_TYPE_DS: u16 = 43;
pub const DNS_TYPE_RRSIG: u16 = 46;
pub const DNS_TYPE_DNSKEY: u16 = 48;
pub const DNS_EDNS_OPTION_NSID: u16 = 3;
pub const DNS_EDNS_OPTION_CLIENT_SUBNET: u16 = 8;
pub const DNS_EDNS_OPTION_COOKIE: u16 = 10;
pub const DNS_EDNS_OPTION_PADDING: u16 = 12;

pub fn qtype_label(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        43 => "DS".to_string(),
        46 => "RRSIG".to_string(),
        47 => "NSEC".to_string(),
        48 => "DNSKEY".to_string(),
        50 => "NSEC3".to_string(),
        65 => "HTTPS".to_string(),
        _ => format!("TYPE{}", qtype),
    }
}

pub fn qtype_label_opt(qtype: Option<u16>) -> String {
    qtype
        .map(qtype_label)
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

#[derive(Debug, Clone)]
pub struct DnsAnswerAnalysis {
    pub rcode: u16,
    pub has_target_record: bool,
    pub has_owner_cname: bool,
    pub first_cname: Option<String>,
    pub cname_records: Vec<(String, String, u32)>,
}

#[derive(Debug, Clone)]
pub struct DnsAnswerFollowupAnalysis {
    pub analysis: DnsAnswerAnalysis,
    pub dname_records: Vec<(String, u16, u16, u32, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct DnsReferralAnalysis {
    pub glue_nameservers: Vec<String>,
    pub authority_ns_hostnames: Vec<String>,
    pub authority_zones: Vec<String>,
    pub has_authority_soa: bool,
}

#[derive(Debug, Clone)]
pub struct DnsAdditionalRecord {
    pub owner_name: String,
    pub rr_type: u16,
    pub ttl: u32,
    pub answers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReferralSecurityValidation {
    pub is_valid: bool,
    pub rejection_reason: Option<String>,
    pub trust_level: u8,
    pub authority_zones_valid: bool,
    pub bailiwick_valid: bool,
    pub glue_coverage: f64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsSection {
    Answer,
    Authority,
    Additional,
}

struct DnsRecordView<'a> {
    owner: String,
    rr_type: u16,
    rr_class: u16,
    ttl: u32,
    rdata_offset: usize,
    rdata: &'a [u8],
}

pub(crate) fn parse_header(packet: &[u8]) -> Result<DnsHeader> {
    if packet.len() < 12 {
        return Err(anyhow!("dns packet too short"));
    }

    Ok(DnsHeader {
        id: u16::from_be_bytes([packet[0], packet[1]]),
        flags: u16::from_be_bytes([packet[2], packet[3]]),
        qdcount: u16::from_be_bytes([packet[4], packet[5]]),
        ancount: u16::from_be_bytes([packet[6], packet[7]]),
        nscount: u16::from_be_bytes([packet[8], packet[9]]),
        arcount: u16::from_be_bytes([packet[10], packet[11]]),
    })
}

pub(crate) fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    // Supports both labels and compression pointers.
    loop {
        if offset >= packet.len() {
            return None;
        }

        let len = packet[offset];
        if len & 0b1100_0000 == 0b1100_0000 {
            if offset + 1 >= packet.len() {
                return None;
            }
            return Some(offset + 2);
        }

        offset += 1;
        if len == 0 {
            return Some(offset);
        }

        offset += len as usize;
        if offset > packet.len() {
            return None;
        }
    }
}

pub(crate) fn parse_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    parse_name_with_depth(packet, offset, 0)
}

fn parse_name_with_depth(
    packet: &[u8],
    mut offset: usize,
    depth: usize,
) -> Option<(String, usize)> {
    // Depth guard prevents malicious pointer recursion loops.
    if depth > 16 || offset >= packet.len() {
        return None;
    }

    let mut labels = Vec::new();
    let mut consumed = 0usize;

    loop {
        if offset >= packet.len() {
            return None;
        }

        let len = packet[offset];
        if len & 0b1100_0000 == 0b1100_0000 {
            if offset + 1 >= packet.len() {
                return None;
            }
            let ptr = (((len as u16 & 0x3F) << 8) | packet[offset + 1] as u16) as usize;
            let (suffix, _) = parse_name_with_depth(packet, ptr, depth + 1)?;
            if !suffix.is_empty() {
                labels.push(suffix);
            }
            consumed += 2;
            break;
        }

        offset += 1;
        consumed += 1;
        if len == 0 {
            break;
        }

        if offset + len as usize > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[offset..offset + len as usize]).ok()?;
        labels.push(label.to_string());
        offset += len as usize;
        consumed += len as usize;
    }

    Some((labels.join("."), consumed))
}

pub(crate) fn encode_name(name: &str, out: &mut Vec<u8>) -> Option<()> {
    let normalized = name.trim();
    if normalized.is_empty() || normalized == "." {
        out.push(0);
        return Some(());
    }

    // Accept absolute FQDN form with trailing dot (e.g. "ns1.example.com.").
    let normalized = normalized.strip_suffix('.').unwrap_or(normalized);
    if normalized.is_empty() {
        out.push(0);
        return Some(());
    }

    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(())
}

pub(crate) fn skip_rr(packet: &[u8], offset: usize) -> Option<usize> {
    let name_end = skip_name(packet, offset)?;
    if name_end + 10 > packet.len() {
        return None;
    }
    let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
    let next = name_end + 10 + rdlen;
    if next > packet.len() {
        return None;
    }
    Some(next)
}

pub fn extract_cache_ttl(packet: &[u8]) -> Option<Duration> {
    // Cache ttl follows the minimum ttl found across parsed records.
    let header = parse_header(packet).ok()?;
    let mut offset = 12usize;

    for _ in 0..header.qdcount {
        offset = skip_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }

    let mut min_ttl: Option<u32> = None;
    let total_records = header.ancount as usize + header.nscount as usize + header.arcount as usize;
    for _ in 0..total_records {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);

        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        // OPT (EDNS, TYPE 41) uses this field for extended metadata, not DNS RR TTL.
        if rr_type != 41 {
            min_ttl = Some(match min_ttl {
                Some(current) => current.min(ttl),
                None => ttl,
            });
        }

        if offset + rdlen > packet.len() {
            return None;
        }
        offset += rdlen;
    }

    min_ttl.map(|ttl| Duration::from_secs(ttl as u64))
}

pub fn extract_negative_cache_ttl(packet: &[u8]) -> Option<Duration> {
    let header = parse_header(packet).ok()?;
    let mut result = None;

    let _ = scan_resource_records(packet, header, |section, record| {
        if section != DnsSection::Authority || record.rr_class != 1 || record.rr_type != 6 {
            return ControlFlow::<(), ()>::Continue(());
        }

        let Some((_, mname_len)) = parse_name(packet, record.rdata_offset) else {
            return ControlFlow::<(), ()>::Continue(());
        };
        let rname_offset = record.rdata_offset + mname_len;
        let Some((_, rname_len)) = parse_name(packet, rname_offset) else {
            return ControlFlow::<(), ()>::Continue(());
        };
        let fields_offset = rname_offset + rname_len;
        if fields_offset + 20 > packet.len() {
            return ControlFlow::<(), ()>::Continue(());
        }

        let minimum = u32::from_be_bytes([
            packet[fields_offset + 16],
            packet[fields_offset + 17],
            packet[fields_offset + 18],
            packet[fields_offset + 19],
        ]);
        let ttl = record.ttl.min(minimum);
        result = Some(Duration::from_secs(ttl as u64));
        ControlFlow::Break(())
    })?;

    result
}

pub fn answer_count(packet: &[u8]) -> Option<u16> {
    Some(parse_response_overview(packet)?.ancount)
}

pub fn parse_request_overview(packet: &[u8]) -> Option<DnsRequestOverview> {
    let header = parse_header(packet).ok()?;
    let question = parse_first_question_from_header(packet, header);
    Some(DnsRequestOverview {
        id: header.id,
        query_name: question.as_ref().map(|value| SmolStr::from(value.0.as_str())),
        query_type: question.as_ref().map(|value| value.1),
    })
}

pub fn parse_response_overview(packet: &[u8]) -> Option<DnsResponseOverview> {
    let header = parse_header(packet).ok()?;
    let header_rcode = header.flags & 0x000F;
    let extended_rcode = extract_edns_opt(packet)
        .map(|opt| u16::from(opt.extended_rcode))
        .unwrap_or(0);
    Some(DnsResponseOverview {
        id: header.id,
        rcode: (extended_rcode << 4) | header_rcode,
        ancount: header.ancount,
    })
}

pub fn extract_answer_ips(packet: &[u8]) -> Vec<String> {
    let Some(header) = parse_header(packet).ok() else {
        return Vec::new();
    };
    let Some(mut offset) = skip_question_section(packet, header) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for _ in 0..header.ancount {
        let Some(name_end) = skip_name(packet, offset) else {
            return Vec::new();
        };
        if name_end + 10 > packet.len() {
            return Vec::new();
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rr_class = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let rdata_offset = name_end + 10;
        let rr_end = rdata_offset + rdlen;
        if rr_end > packet.len() {
            return Vec::new();
        }

        if rr_class == 1 {
            match rr_type {
                1 if rdlen == 4 => {
                    let ip = std::net::Ipv4Addr::new(
                        packet[rdata_offset],
                        packet[rdata_offset + 1],
                        packet[rdata_offset + 2],
                        packet[rdata_offset + 3],
                    );
                    result.push(ip.to_string());
                }
                28 if rdlen == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[rdata_offset..rr_end]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    result.push(ip.to_string());
                }
                _ => {}
            }
        }

        offset = rr_end;
    }

    result
}

pub fn reorder_answer_address_records(packet: &[u8], preferred_ips: &[String]) -> Option<Vec<u8>> {
    let header = parse_header(packet).ok()?;
    if header.ancount <= 1 {
        return Some(packet.to_vec());
    }
    let answer_start = skip_question_section(packet, header)?;
    let mut answer_end = answer_start;

    struct AnswerSlot {
        is_address: bool,
        rr_bytes: Vec<u8>,
        address: Option<String>,
    }

    let mut slots = Vec::with_capacity(header.ancount as usize);
    for _ in 0..header.ancount {
        let rr_start = answer_end;
        let name_end = skip_name(packet, rr_start)?;
        if name_end + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rr_class = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let rdata_offset = name_end + 10;
        let rr_end = rdata_offset + rdlen;
        if rr_end > packet.len() {
            return None;
        }

        let (is_address, address) = if rr_class == 1 && rr_type == 1 && rdlen == 4 {
            let ip = std::net::Ipv4Addr::new(
                packet[rdata_offset],
                packet[rdata_offset + 1],
                packet[rdata_offset + 2],
                packet[rdata_offset + 3],
            );
            (true, Some(ip.to_string()))
        } else if rr_class == 1 && rr_type == 28 && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[rdata_offset..rr_end]);
            (true, Some(std::net::Ipv6Addr::from(octets).to_string()))
        } else {
            (false, None)
        };

        slots.push(AnswerSlot {
            is_address,
            rr_bytes: packet[rr_start..rr_end].to_vec(),
            address,
        });
        answer_end = rr_end;
    }

    let mut address_records = slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.is_address)
        .map(|(index, slot)| {
            (
                index,
                slot.address.clone().unwrap_or_default(),
                slot.rr_bytes.clone(),
            )
        })
        .collect::<Vec<_>>();
    if address_records.len() <= 1 {
        return Some(packet.to_vec());
    }

    let mut rank = std::collections::HashMap::<String, usize>::new();
    for (idx, ip) in preferred_ips.iter().enumerate() {
        rank.entry(ip.clone()).or_insert(idx);
    }
    let fallback_rank = preferred_ips.len().saturating_add(1024);
    address_records.sort_by(|a, b| {
        let ar = rank.get(&a.1).copied().unwrap_or(fallback_rank + a.0);
        let br = rank.get(&b.1).copied().unwrap_or(fallback_rank + b.0);
        ar.cmp(&br).then_with(|| a.0.cmp(&b.0))
    });

    let mut addr_iter = address_records.into_iter().map(|(_, _, bytes)| bytes);
    let mut rebuilt_answers = Vec::new();
    for slot in slots {
        if slot.is_address {
            rebuilt_answers.extend_from_slice(&addr_iter.next()?);
        } else {
            rebuilt_answers.extend_from_slice(&slot.rr_bytes);
        }
    }

    let mut out = Vec::with_capacity(packet.len());
    out.extend_from_slice(&packet[..answer_start]);
    out.extend_from_slice(&rebuilt_answers);
    out.extend_from_slice(&packet[answer_end..]);
    Some(out)
}

pub fn extract_edns_opt(packet: &[u8]) -> Option<DnsEdnsOpt> {
    let header = parse_header(packet).ok()?;
    let mut offset = skip_question_section(packet, header)?;

    for _ in 0..header.ancount {
        offset = skip_rr(packet, offset)?;
    }
    for _ in 0..header.nscount {
        offset = skip_rr(packet, offset)?;
    }

    for _ in 0..header.arcount {
        let name_end = skip_name(packet, offset)?;
        if name_end + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rr_class = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
        let ttl = u32::from_be_bytes([
            packet[name_end + 4],
            packet[name_end + 5],
            packet[name_end + 6],
            packet[name_end + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let next = name_end + 10 + rdlen;
        if next > packet.len() {
            return None;
        }

        if rr_type == 41 {
            let rdata = &packet[name_end + 10..next];
            return Some(DnsEdnsOpt {
                udp_payload_size: rr_class,
                extended_rcode: ((ttl >> 24) & 0xFF) as u8,
                version: ((ttl >> 16) & 0xFF) as u8,
                flags: (ttl & 0xFFFF) as u16,
                options: parse_edns_options(rdata)?,
            });
        }

        offset = next;
    }

    None
}

pub fn analyze_answer_for_name(
    packet: &[u8],
    qname: &str,
    target_type: u16,
) -> Option<DnsAnswerAnalysis> {
    analyze_answer_for_name_with_dnames(packet, qname, target_type).map(|value| value.analysis)
}

pub fn analyze_answer_for_name_with_dnames(
    packet: &[u8],
    qname: &str,
    target_type: u16,
) -> Option<DnsAnswerFollowupAnalysis> {
    let header = parse_header(packet).ok()?;
    let mut offset = skip_question_section(packet, header)?;
    let target = qname.trim_end_matches('.').to_ascii_lowercase();
    let mut has_target_record = false;
    let mut has_owner_cname = false;
    let mut first_cname = None;
    let mut cname_records = Vec::new();
    let mut dname_records = Vec::new();

    for _ in 0..header.ancount {
        let (owner, consumed) = parse_name(packet, offset)?;
        offset += consumed;
        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return None;
        }

        if rr_class == 1 {
            if rr_type == target_type && owner.trim_end_matches('.').eq_ignore_ascii_case(&target) {
                has_target_record = true;
            }

            if rr_type == 5 {
                if let Some((cname_target, _)) = parse_name(packet, offset) {
                    if owner.trim_end_matches('.').eq_ignore_ascii_case(&target) {
                        has_owner_cname = true;
                    }
                    if !cname_target.is_empty() {
                        if first_cname.is_none() {
                            first_cname = Some(cname_target.clone());
                        }
                        if !owner.is_empty() {
                            cname_records.push((owner, cname_target, ttl));
                        }
                    }
                }
            } else if rr_type == 39 {
                dname_records.push((
                    owner,
                    rr_type,
                    rr_class,
                    ttl,
                    packet[offset..offset + rdlen].to_vec(),
                ));
            }
        }

        offset += rdlen;
    }

    Some(DnsAnswerFollowupAnalysis {
        analysis: DnsAnswerAnalysis {
            rcode: header.flags & 0x000F,
            has_target_record,
            has_owner_cname,
            first_cname,
            cname_records,
        },
        dname_records,
    })
}

pub fn build_query(id: u16, name: &str, qtype: u16, rd: bool) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    let flags = if rd { 0x0100u16 } else { 0u16 };
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    encode_name(name, &mut packet)?;
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Some(packet)
}

pub fn build_query_like_request(
    template_request: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    rd: bool,
) -> Option<Vec<u8>> {
    let mut packet = build_query(id, name, qtype, rd)?;
    let _ = clone_edns_opt_from_request(template_request, &mut packet);
    Some(packet)
}

/// Buffer-reusing variant of `build_query`. Clears the buffer and writes the query into it,
/// avoiding a fresh allocation when queries are built repeatedly (e.g., CNAME chain hops).
pub fn build_query_into(
    buffer: &mut Vec<u8>,
    id: u16,
    name: &str,
    qtype: u16,
    rd: bool,
) -> Option<()> {
    buffer.clear();
    buffer.extend_from_slice(&id.to_be_bytes());
    let flags = if rd { 0x0100u16 } else { 0u16 };
    buffer.extend_from_slice(&flags.to_be_bytes());
    buffer.extend_from_slice(&1u16.to_be_bytes());
    buffer.extend_from_slice(&0u16.to_be_bytes());
    buffer.extend_from_slice(&0u16.to_be_bytes());
    buffer.extend_from_slice(&0u16.to_be_bytes());
    encode_name(name, buffer)?;
    buffer.extend_from_slice(&qtype.to_be_bytes());
    buffer.extend_from_slice(&1u16.to_be_bytes());
    Some(())
}

/// Buffer-reusing variant of `build_query_like_request`.
/// Clears the buffer and writes the query + cloned EDNS opt into it.
pub fn build_query_like_request_into(
    buffer: &mut Vec<u8>,
    template_request: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    rd: bool,
) -> Option<()> {
    build_query_into(buffer, id, name, qtype, rd)?;
    let _ = clone_edns_opt_from_request(template_request, buffer);
    Some(())
}

pub fn append_edns_opt(packet: &mut Vec<u8>, udp_payload_size: u16, flags: u16) -> Option<()> {
    append_edns_opt_with_rcode(packet, udp_payload_size, 0, 0, flags)
}

pub fn append_edns_opt_with_rcode(
    packet: &mut Vec<u8>,
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
) -> Option<()> {
    append_edns_opt_with_options(
        packet,
        udp_payload_size,
        extended_rcode,
        version,
        flags,
        &[],
    )
}

pub fn append_edns_opt_with_options(
    packet: &mut Vec<u8>,
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
    options: &[DnsEdnsOption],
) -> Option<()> {
    if packet.len() < 12 {
        return None;
    }

    let header = parse_header(packet).ok()?;
    let arcount = header.arcount.checked_add(1)?;
    packet.extend_from_slice(&build_edns_opt_record(
        udp_payload_size,
        extended_rcode,
        version,
        flags,
        options,
    )?);
    packet[10..12].copy_from_slice(&arcount.to_be_bytes());
    Some(())
}

pub fn edns_version_supported(packet: &[u8]) -> bool {
    extract_edns_opt(packet)
        .map(|opt| opt.version == 0)
        .unwrap_or(true)
}

pub fn dnssec_ok_requested(packet: &[u8]) -> bool {
    extract_edns_opt(packet)
        .map(|opt| (opt.flags & DNS_EDNS_FLAG_DO) != 0)
        .unwrap_or(false)
}

pub fn checking_disabled(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    (flags & DNS_FLAG_CD) != 0
}

pub fn authentic_data(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    (flags & DNS_FLAG_AD) != 0
}

pub fn set_authentic_data(packet: &mut [u8], enabled: bool) {
    if packet.len() < 4 {
        return;
    }
    let mut flags = u16::from_be_bytes([packet[2], packet[3]]);
    if enabled {
        flags |= DNS_FLAG_AD;
    } else {
        flags &= !DNS_FLAG_AD;
    }
    packet[2..4].copy_from_slice(&flags.to_be_bytes());
}

pub fn set_checking_disabled(packet: &[u8], enabled: bool) -> Option<Vec<u8>> {
    if packet.len() < 4 {
        return None;
    }
    let mut modified = packet.to_vec();
    let mut flags = u16::from_be_bytes([modified[2], modified[3]]);
    if enabled {
        flags |= DNS_FLAG_CD;
    } else {
        flags &= !DNS_FLAG_CD;
    }
    modified[2..4].copy_from_slice(&flags.to_be_bytes());
    Some(modified)
}

pub fn extract_edns_option(packet: &[u8], code: u16) -> Option<Vec<u8>> {
    extract_edns_opt(packet)?
        .options
        .into_iter()
        .find_map(|option| {
            if option.code == code {
                Some(option.data)
            } else {
                None
            }
        })
}

pub fn extract_edns_nsid(packet: &[u8]) -> Option<Vec<u8>> {
    extract_edns_option(packet, DNS_EDNS_OPTION_NSID)
}

pub fn extract_edns_cookie(packet: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let data = extract_edns_option(packet, DNS_EDNS_OPTION_COOKIE)?;
    if data.len() < 8 {
        return None;
    }
    let client_cookie = data[..8].to_vec();
    let server_cookie = if data.len() > 8 {
        Some(data[8..].to_vec())
    } else {
        None
    };
    Some((client_cookie, server_cookie))
}

pub fn extract_edns_client_subnet(packet: &[u8]) -> Option<DnsEdnsClientSubnet> {
    let data = extract_edns_option(packet, DNS_EDNS_OPTION_CLIENT_SUBNET)?;
    if data.len() < 4 {
        return None;
    }
    Some(DnsEdnsClientSubnet {
        family: u16::from_be_bytes([data[0], data[1]]),
        source_prefix: data[2],
        scope_prefix: data[3],
        address: data[4..].to_vec(),
    })
}

pub fn align_response_edns_to_request(response: &[u8], request: &[u8]) -> Option<Vec<u8>> {
    let request_edns = extract_edns_opt(request);
    let response_edns = extract_edns_opt(response);

    if request_edns.is_none() && response_edns.is_none() {
        return Some(response.to_vec());
    }

    let header = parse_header(response).ok()?;
    let mut offset = skip_question_section(response, header)?;
    for _ in 0..header.ancount {
        offset = skip_rr(response, offset)?;
    }
    for _ in 0..header.nscount {
        offset = skip_rr(response, offset)?;
    }

    let additional_start = offset;
    let mut out = Vec::with_capacity(response.len() + 32);
    out.extend_from_slice(&response[..additional_start]);
    let mut arcount = 0u16;

    for _ in 0..header.arcount {
        let rr_start = offset;
        let name_end = skip_name(response, offset)?;
        if name_end + 10 > response.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([response[name_end], response[name_end + 1]]);
        let rdlen = u16::from_be_bytes([response[name_end + 8], response[name_end + 9]]) as usize;
        let next = name_end + 10 + rdlen;
        if next > response.len() {
            return None;
        }

        if rr_type != 41 {
            out.extend_from_slice(&response[rr_start..next]);
            arcount = arcount.checked_add(1)?;
        }
        offset = next;
    }

    if let Some(request_opt) = request_edns {
        let response_opt = response_edns.unwrap_or_else(|| DnsEdnsOpt {
            udp_payload_size: request_opt.udp_payload_size,
            extended_rcode: 0,
            version: 0,
            flags: 0,
            options: Vec::new(),
        });
        out.extend_from_slice(&build_edns_opt_record(
            request_opt.udp_payload_size,
            response_opt.extended_rcode,
            0,
            request_opt.flags,
            &response_opt.options,
        )?);
        arcount = arcount.checked_add(1)?;
    }

    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    Some(out)
}

pub fn build_dnssec_query_like_request(
    template_request: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    rd: bool,
    checking_disabled: bool,
) -> Option<Vec<u8>> {
    let mut packet = build_query_like_request(template_request, id, name, qtype, rd)?;
    packet = set_checking_disabled(&packet, checking_disabled)?;

    if let Some(edns) = extract_edns_opt(&packet) {
        let stripped = strip_edns_opt_from_request(&packet)?;
        packet = stripped;
        append_edns_opt_with_options(
            &mut packet,
            edns.udp_payload_size,
            0,
            0,
            edns.flags | DNS_EDNS_FLAG_DO,
            &edns.options,
        )?;
    } else {
        append_edns_opt(&mut packet, 1232, DNS_EDNS_FLAG_DO)?;
    }

    Some(packet)
}

pub fn set_recursion_desired(packet: &[u8], rd: bool) -> Option<Vec<u8>> {
    if packet.len() < 4 {
        return None;
    }
    let mut modified = packet.to_vec();
    let mut flags = u16::from_be_bytes([modified[2], modified[3]]);
    if rd {
        flags |= 0x0100;
    } else {
        flags &= !0x0100;
    }
    modified[2..4].copy_from_slice(&flags.to_be_bytes());
    Some(modified)
}

pub fn clone_edns_opt_from_request(request: &[u8], packet: &mut Vec<u8>) -> Option<()> {
    maybe_append_request_edns_opt(request, packet)
}

pub fn strip_edns_opt_from_request(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(packet).ok()?;
    let mut offset = skip_question_section(packet, header)?;

    for _ in 0..header.ancount {
        offset = skip_rr(packet, offset)?;
    }
    for _ in 0..header.nscount {
        offset = skip_rr(packet, offset)?;
    }

    let additional_start = offset;
    let mut out = Vec::with_capacity(packet.len());
    out.extend_from_slice(&packet[..additional_start]);
    let mut new_arcount = 0u16;
    let mut removed = false;

    for _ in 0..header.arcount {
        let rr_start = offset;
        let name_end = skip_name(packet, offset)?;
        if name_end + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let next = name_end + 10 + rdlen;
        if next > packet.len() {
            return None;
        }

        if rr_type == 41 {
            removed = true;
        } else {
            out.extend_from_slice(&packet[rr_start..next]);
            new_arcount = new_arcount.checked_add(1)?;
        }
        offset = next;
    }

    if removed {
        out[10..12].copy_from_slice(&new_arcount.to_be_bytes());
        Some(out)
    } else {
        Some(packet.to_vec())
    }
}

pub fn udp_payload_size_for_request(packet: &[u8]) -> usize {
    extract_edns_opt(packet)
        .map(|opt| usize::from(opt.udp_payload_size.max(512)))
        .unwrap_or(4096)
}

pub fn truncate_response_for_udp(request: &[u8], response: &[u8]) -> Option<Vec<u8>> {
    let limit = udp_payload_size_for_request(request).max(512).min(u16::MAX as usize);
    if response.len() <= limit {
        return Some(response.to_vec());
    }

    let header = parse_header(response).ok()?;
    let (_, _, qend) = parse_first_question(response)?;

    let mut truncated = Vec::with_capacity(qend + 16);
    truncated.extend_from_slice(&response[..qend]);

    let mut flags = u16::from_be_bytes([truncated[2], truncated[3]]);
    flags |= 0x0200; // TC
    truncated[2..4].copy_from_slice(&flags.to_be_bytes());

    if header.qdcount > 0 {
        truncated[4..6].copy_from_slice(&header.qdcount.to_be_bytes());
    } else {
        truncated[4..6].copy_from_slice(&1u16.to_be_bytes());
    }
    truncated[6..8].copy_from_slice(&0u16.to_be_bytes());
    truncated[8..10].copy_from_slice(&0u16.to_be_bytes());
    truncated[10..12].copy_from_slice(&0u16.to_be_bytes());

    if let Some(opt) = extract_opt_record_bytes(request) {
        let projected = truncated.len().saturating_add(opt.len());
        if projected <= limit {
            truncated.extend_from_slice(&opt);
            truncated[10..12].copy_from_slice(&1u16.to_be_bytes());
        }
    }

    Some(truncated)
}

fn maybe_append_request_edns_opt(request: &[u8], response: &mut Vec<u8>) -> Option<()> {
    maybe_append_request_edns_opt_with_rcode(request, response, 0)
}

fn maybe_append_request_edns_opt_with_rcode(
    request: &[u8],
    response: &mut Vec<u8>,
    response_rcode: u16,
) -> Option<()> {
    let mut opt = extract_opt_record_bytes(request)?;
    if response.len() < 12 {
        return None;
    }
    if opt.len() >= 9 {
        opt[5] = ((response_rcode >> 4) & 0x00FF) as u8;
        opt[6] = 0;
    }
    let header = parse_header(response).ok()?;
    let arcount = header.arcount.checked_add(1)?;
    response.extend_from_slice(&opt);
    response[10..12].copy_from_slice(&arcount.to_be_bytes());
    Some(())
}

fn build_edns_opt_record(
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
    options: &[DnsEdnsOption],
) -> Option<Vec<u8>> {
    let mut record =
        Vec::with_capacity(11 + options.iter().map(|opt| opt.data.len() + 4).sum::<usize>());
    record.extend_from_slice(&[0]);
    record.extend_from_slice(&41u16.to_be_bytes());
    record.extend_from_slice(&udp_payload_size.to_be_bytes());
    let ttl = (u32::from(extended_rcode) << 24) | (u32::from(version) << 16) | u32::from(flags);
    record.extend_from_slice(&ttl.to_be_bytes());

    let mut rdata = Vec::new();
    for option in options {
        rdata.extend_from_slice(&option.code.to_be_bytes());
        rdata.extend_from_slice(&(option.data.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&option.data);
    }
    record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    record.extend_from_slice(&rdata);
    Some(record)
}

fn parse_edns_options(rdata: &[u8]) -> Option<Vec<DnsEdnsOption>> {
    let mut offset = 0usize;
    let mut options = Vec::new();
    while offset < rdata.len() {
        if offset + 4 > rdata.len() {
            return None;
        }
        let code = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let len = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        if offset + len > rdata.len() {
            return None;
        }
        options.push(DnsEdnsOption {
            code,
            data: rdata[offset..offset + len].to_vec(),
        });
        offset += len;
    }
    Some(options)
}

fn extract_opt_record_bytes(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(packet).ok()?;
    let mut offset = skip_question_section(packet, header)?;

    for _ in 0..header.ancount {
        offset = skip_rr(packet, offset)?;
    }
    for _ in 0..header.nscount {
        offset = skip_rr(packet, offset)?;
    }

    for _ in 0..header.arcount {
        let rr_start = offset;
        let name_end = skip_name(packet, offset)?;
        if name_end + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let next = name_end + 10 + rdlen;
        if next > packet.len() {
            return None;
        }

        if rr_type == 41 {
            return Some(packet[rr_start..next].to_vec());
        }

        offset = next;
    }

    None
}

pub fn analyze_referral_targets(packet: &[u8]) -> Option<DnsReferralAnalysis> {
    let header = parse_header(packet).ok()?;
    let mut glue_nameservers = Vec::new();
    let mut authority_ns_hostnames = Vec::new();
    let mut authority_zones = Vec::new();
    let mut has_authority_soa = false;

    let _ = scan_resource_records(packet, header, |section, record| {
        if record.rr_class != 1 {
            return ControlFlow::<(), ()>::Continue(());
        }

        match section {
            DnsSection::Authority if record.rr_type == 2 => {
                if !record.owner.is_empty() {
                    authority_zones.push(record.owner.trim_end_matches('.').to_ascii_lowercase());
                }
                if let Some((hostname, _)) = parse_name(packet, record.rdata_offset) {
                    if !hostname.is_empty() {
                        authority_ns_hostnames
                            .push(hostname.trim_end_matches('.').to_ascii_lowercase());
                    }
                }
            }
            DnsSection::Authority if record.rr_type == 6 => {
                has_authority_soa = true;
            }
            DnsSection::Additional => {
                if let Some(endpoint) = endpoint_from_rdata(record.rr_type, record.rdata) {
                    glue_nameservers.push(endpoint);
                }
            }
            _ => {}
        }

        ControlFlow::<(), ()>::Continue(())
    })?;

    glue_nameservers.sort();
    glue_nameservers.dedup();
    authority_ns_hostnames.sort();
    authority_ns_hostnames.dedup();
    authority_zones.sort();
    authority_zones.dedup();

    Some(DnsReferralAnalysis {
        glue_nameservers,
        authority_ns_hostnames,
        authority_zones,
        has_authority_soa,
    })
}

/// Build a map from NS hostname (lowercased, no trailing dot) to glue
/// endpoint strings by scanning the additional section of a referral packet.
///
/// This lets the resolver warm its NS hostname cache from glue records even
/// when the glue fast-path skips the normal `resolve_ns_hostnames` call.
pub fn build_ns_hostname_glue_map(
    packet: &[u8],
) -> std::collections::HashMap<String, Vec<String>> {
    let header = match parse_header(packet) {
        Ok(h) => h,
        Err(_) => return std::collections::HashMap::new(),
    };
    let mut map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let _ = scan_resource_records(packet, header, |section, record| {
        if section == DnsSection::Additional && record.rr_class == 1 {
            if record.rr_type == 1 || record.rr_type == 28 {
                let owner = record
                    .owner
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if let Some(endpoint) = endpoint_from_rdata(record.rr_type, record.rdata) {
                    map.entry(owner).or_default().push(endpoint);
                }
            }
        }
        ControlFlow::<(), ()>::Continue(())
    });
    map
}

fn domain_is_same_or_subdomain_of(name: &str, zone: &str) -> bool {
    let raw_zone = zone.trim();
    if raw_zone == "." {
        return true;
    }

    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.trim_end_matches('.').to_ascii_lowercase();
    if zone.is_empty() {
        return false;
    }
    name == zone || name.ends_with(&format!(".{}", zone))
}

pub fn validate_referral_security(
    qname: &str,
    analysis: &DnsReferralAnalysis,
) -> ReferralSecurityValidation {
    let authority_zones_valid = !analysis.authority_zones.is_empty()
        && analysis
            .authority_zones
            .iter()
            .all(|zone| domain_is_same_or_subdomain_of(qname, zone));

    if !authority_zones_valid {
        return ReferralSecurityValidation {
            is_valid: false,
            rejection_reason: Some("invalid_authority_zone".to_string()),
            trust_level: 0,
            authority_zones_valid: false,
            bailiwick_valid: false,
            glue_coverage: 0.0,
        };
    }

    let ns_hostnames_in_zone = analysis.authority_ns_hostnames.iter().all(|hostname| {
        analysis
            .authority_zones
            .iter()
            .any(|zone| domain_is_same_or_subdomain_of(hostname, zone))
    });

    let glue_coverage = if analysis.authority_ns_hostnames.is_empty() {
        1.0
    } else if analysis.glue_nameservers.is_empty() {
        0.0
    } else {
        let ratio =
            analysis.glue_nameservers.len() as f64 / analysis.authority_ns_hostnames.len() as f64;
        ratio.min(1.0)
    };

    let mut trust_level = 80u8;
    if glue_coverage >= 1.0 {
        trust_level = trust_level.saturating_add(20);
    } else if glue_coverage < 0.5 {
        trust_level = trust_level.saturating_sub(20);
    }
    if analysis.has_authority_soa {
        trust_level = trust_level.saturating_sub(20);
    }
    if !ns_hostnames_in_zone {
        // Out-of-zone NS hostnames are common in real-world delegations (e.g. gtld servers).
        // Keep referral usable but lower trust to avoid overconfident caching decisions.
        trust_level = trust_level.saturating_sub(20);
    }

    ReferralSecurityValidation {
        is_valid: true,
        rejection_reason: None,
        trust_level,
        authority_zones_valid: true,
        bailiwick_valid: ns_hostnames_in_zone,
        glue_coverage,
    }
}

pub fn extract_glue_nameservers(packet: &[u8]) -> Vec<String> {
    analyze_referral_targets(packet)
        .map(|analysis| analysis.glue_nameservers)
        .unwrap_or_default()
}

pub fn extract_authority_ns_hostnames(packet: &[u8]) -> Vec<String> {
    analyze_referral_targets(packet)
        .map(|analysis| analysis.authority_ns_hostnames)
        .unwrap_or_default()
}

pub fn extract_answer_ip_endpoints(packet: &[u8]) -> Vec<String> {
    extract_answer_ip_endpoints_with_port(packet, 53)
}

/// Same as `extract_answer_ip_endpoints` but allows overriding the DNS port.
/// Used by the iterative resolver when a non-standard port is configured (tests).
pub fn extract_answer_ip_endpoints_with_port(packet: &[u8], port: u16) -> Vec<String> {
    let mut result = Vec::new();
    let Ok(header) = parse_header(packet) else {
        return result;
    };

    if scan_resource_records(packet, header, |section, record| {
        if section == DnsSection::Answer && record.rr_class == 1 {
            if let Some(endpoint) =
                endpoint_from_rdata_with_port(record.rr_type, record.rdata, port)
            {
                result.push(endpoint);
            }
        }
        ControlFlow::<(), ()>::Continue(())
    })
    .is_none()
    {
        return Vec::new();
    }

    result.sort();
    result.dedup();
    result
}

pub fn answer_has_record_type(packet: &[u8], target_type: u16) -> bool {
    let Ok(header) = parse_header(packet) else {
        return false;
    };

    matches!(
        scan_answer_records(packet, header, |record| {
            if record.rr_type == target_type {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }),
        Some(ControlFlow::Break(()))
    )
}

pub fn answer_has_record_type_for_name(packet: &[u8], qname: &str, target_type: u16) -> bool {
    let Ok(header) = parse_header(packet) else {
        return false;
    };

    let target = qname.trim_end_matches('.').to_ascii_lowercase();

    matches!(
        scan_answer_records(packet, header, |record| {
            if record.rr_class == 1
                && record.rr_type == target_type
                && record
                    .owner
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(&target)
            {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }),
        Some(ControlFlow::Break(()))
    )
}

pub fn answer_has_cname_for_name(packet: &[u8], qname: &str) -> bool {
    let Ok(header) = parse_header(packet) else {
        return false;
    };

    let target = qname.trim_end_matches('.').to_ascii_lowercase();

    matches!(
        scan_answer_records(packet, header, |record| {
            if record.rr_class == 1
                && record.rr_type == 5
                && record
                    .owner
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(&target)
            {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }),
        Some(ControlFlow::Break(()))
    )
}

pub fn extract_first_answer_cname(packet: &[u8]) -> Option<String> {
    let header = parse_header(packet).ok()?;

    match scan_answer_records(packet, header, |record| {
        if record.rr_type == 5 && record.rr_class == 1 {
            if let Some((target, _)) = parse_name(packet, record.rdata_offset) {
                if !target.is_empty() {
                    return ControlFlow::Break(target);
                }
            }
        }
        ControlFlow::<String, ()>::Continue(())
    }) {
        Some(ControlFlow::Break(target)) => Some(target),
        _ => None,
    }
}

pub fn extract_answer_cname_records(packet: &[u8]) -> Vec<(String, String, u32)> {
    let mut result = Vec::new();
    let Ok(header) = parse_header(packet) else {
        return result;
    };

    if scan_answer_records(packet, header, |record| {
        if record.rr_type == 5 && record.rr_class == 1 {
            if let Some((target, _)) = parse_name(packet, record.rdata_offset) {
                if !record.owner.is_empty() && !target.is_empty() {
                    result.push((record.owner, target, record.ttl));
                }
            }
        }
        ControlFlow::<(), ()>::Continue(())
    })
    .is_none()
    {
        return Vec::new();
    }

    result
}

pub fn extract_answer_records_by_type(
    packet: &[u8],
    wanted_rr_type: u16,
) -> Vec<(String, u16, u16, u32, Vec<u8>)> {
    let mut result = Vec::new();
    let Ok(header) = parse_header(packet) else {
        return result;
    };

    if scan_answer_records(packet, header, |record| {
        if record.rr_type == wanted_rr_type {
            result.push((
                record.owner,
                record.rr_type,
                record.rr_class,
                record.ttl,
                record.rdata.to_vec(),
            ));
        }
        ControlFlow::<(), ()>::Continue(())
    })
    .is_none()
    {
        return Vec::new();
    }

    result
}

/// Rewrite the question section of `packet` to match the one from `request`.
/// Used after CNAME chain following: the final merged packet carries the CNAME
/// target's question, but the client asked for the original name.
pub fn rewrite_question_from_request(packet: &[u8], request: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 || request.len() < 12 {
        return None;
    }
    let pkt_header = parse_header(packet).ok()?;
    let req_header = parse_header(request).ok()?;

    // Compute where the question section ends in packet
    let mut pkt_q_end = 12usize;
    for _ in 0..pkt_header.qdcount {
        pkt_q_end = skip_name(packet, pkt_q_end)?;
        if pkt_q_end + 4 > packet.len() {
            return None;
        }
        pkt_q_end += 4;
    }

    // Compute where the question section ends in request
    let mut req_q_end = 12usize;
    for _ in 0..req_header.qdcount {
        req_q_end = skip_name(request, req_q_end)?;
        if req_q_end + 4 > request.len() {
            return None;
        }
        req_q_end += 4;
    }

    // Skip if both question sections are identical (avoids a copy on the fast path)
    if packet[12..pkt_q_end] == request[12..req_q_end] {
        return Some(packet.to_vec());
    }

    let req_q_len = req_q_end - 12;
    let mut out = Vec::with_capacity(12 + req_q_len + (packet.len() - pkt_q_end));
    out.extend_from_slice(&packet[..12]);
    out.extend_from_slice(&request[12..req_q_end]);
    out.extend_from_slice(&packet[pkt_q_end..]);
    // Fix qdcount to match original request
    out[4..6].copy_from_slice(&req_header.qdcount.to_be_bytes());
    Some(out)
}

/// Safely rewrites response question to match request by re-encoding all answer RRs
/// without name compression and dropping authority/additional sections.
///
/// This avoids pointer-offset corruption when the response question differs from request.
pub fn rewrite_question_and_reencode_answers(packet: &[u8], request: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 || request.len() < 12 {
        return None;
    }

    let pkt_header = parse_header(packet).ok()?;
    let req_header = parse_header(request).ok()?;

    let mut pkt_q_end = 12usize;
    for _ in 0..pkt_header.qdcount {
        pkt_q_end = skip_name(packet, pkt_q_end)?;
        if pkt_q_end + 4 > packet.len() {
            return None;
        }
        pkt_q_end += 4;
    }

    let mut req_q_end = 12usize;
    for _ in 0..req_header.qdcount {
        req_q_end = skip_name(request, req_q_end)?;
        if req_q_end + 4 > request.len() {
            return None;
        }
        req_q_end += 4;
    }

    let mut answer_offset = pkt_q_end;
    let mut answers = Vec::new();
    for _ in 0..pkt_header.ancount {
        let (owner, consumed) = parse_name(packet, answer_offset)?;
        answer_offset += consumed;
        if answer_offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[answer_offset], packet[answer_offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[answer_offset + 2], packet[answer_offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[answer_offset + 4],
            packet[answer_offset + 5],
            packet[answer_offset + 6],
            packet[answer_offset + 7],
        ]);
        let rdlen =
            u16::from_be_bytes([packet[answer_offset + 8], packet[answer_offset + 9]]) as usize;
        let rdata_offset = answer_offset + 10;
        let rdata_end = rdata_offset + rdlen;
        if rdata_end > packet.len() {
            return None;
        }

        let mut rr = Vec::new();
        encode_name(&owner, &mut rr)?;
        rr.extend_from_slice(&rr_type.to_be_bytes());
        rr.extend_from_slice(&rr_class.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());

        if rr_type == 5 && rr_class == 1 {
            let (target, _) = parse_name(packet, rdata_offset)?;
            let mut rdata = Vec::new();
            encode_name(&target, &mut rdata)?;
            rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            rr.extend_from_slice(&rdata);
        } else {
            rr.extend_from_slice(&(rdlen as u16).to_be_bytes());
            rr.extend_from_slice(&packet[rdata_offset..rdata_end]);
        }

        answers.extend_from_slice(&rr);
        answer_offset = rdata_end;
    }

    let req_q_len = req_q_end - 12;
    let mut out = Vec::with_capacity(12 + req_q_len + answers.len());
    out.extend_from_slice(&packet[..12]);
    out.extend_from_slice(&request[12..req_q_end]);
    out.extend_from_slice(&answers);

    out[4..6].copy_from_slice(&req_header.qdcount.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    Some(out)
}

pub fn append_cname_answers(packet: &[u8], records: &[(String, String, u32)]) -> Option<Vec<u8>> {
    if records.is_empty() {
        return Some(packet.to_vec());
    }

    let header = parse_header(packet).ok()?;

    let mut answer_start = 12usize;
    for _ in 0..header.qdcount {
        answer_start = skip_name(packet, answer_start)?;
        if answer_start + 4 > packet.len() {
            return None;
        }
        answer_start += 4;
    }

    let mut answer_end = answer_start;
    for _ in 0..header.ancount {
        answer_end = skip_rr(packet, answer_end)?;
    }

    let existing = extract_answer_cname_records(packet)
        .into_iter()
        .map(|(owner, target, _)| {
            (
                owner.trim_end_matches('.').to_ascii_lowercase(),
                target.trim_end_matches('.').to_ascii_lowercase(),
            )
        })
        .collect::<std::collections::HashSet<_>>();

    let mut to_append = Vec::new();
    let mut appended = 0u16;
    let mut seen_local = std::collections::HashSet::new();
    for (owner, target, ttl) in records {
        let owner_norm = owner.trim_end_matches('.').to_ascii_lowercase();
        let target_norm = target.trim_end_matches('.').to_ascii_lowercase();
        let pair = (owner_norm.clone(), target_norm.clone());
        if existing.contains(&pair) || !seen_local.insert(pair) {
            continue;
        }

        let mut rr = Vec::new();
        encode_name(&owner_norm, &mut rr)?;
        rr.extend_from_slice(&5u16.to_be_bytes());
        rr.extend_from_slice(&1u16.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name(&target_norm, &mut rdata)?;
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(&rdata);
        to_append.extend_from_slice(&rr);
        appended = appended.saturating_add(1);
    }

    if appended == 0 {
        return Some(packet.to_vec());
    }

    let new_ancount = header.ancount.checked_add(appended)?;
    let mut out = Vec::with_capacity(packet.len() + to_append.len());
    out.extend_from_slice(&packet[..answer_end]);
    out.extend_from_slice(&to_append);
    out.extend_from_slice(&packet[answer_end..]);
    out[6..8].copy_from_slice(&new_ancount.to_be_bytes());
    Some(out)
}

pub fn append_answer_records(
    packet: &[u8],
    records: &[(String, u16, u16, u32, Vec<u8>)],
) -> Option<Vec<u8>> {
    if records.is_empty() {
        return Some(packet.to_vec());
    }

    let header = parse_header(packet).ok()?;

    let mut answer_start = 12usize;
    for _ in 0..header.qdcount {
        answer_start = skip_name(packet, answer_start)?;
        if answer_start + 4 > packet.len() {
            return None;
        }
        answer_start += 4;
    }

    let mut answer_end = answer_start;
    for _ in 0..header.ancount {
        answer_end = skip_rr(packet, answer_end)?;
    }

    let mut existing = std::collections::HashSet::new();
    let _ = scan_answer_records(packet, header, |record| {
        existing.insert((
            record.owner.trim_end_matches('.').to_ascii_lowercase(),
            record.rr_type,
            record.rr_class,
            record.rdata.to_vec(),
        ));
        ControlFlow::<(), ()>::Continue(())
    })?;

    let mut to_append = Vec::new();
    let mut appended = 0u16;
    let mut seen_local = std::collections::HashSet::new();
    for (owner, rr_type, rr_class, ttl, rdata) in records {
        let key = (
            owner.trim_end_matches('.').to_ascii_lowercase(),
            *rr_type,
            *rr_class,
            rdata.clone(),
        );
        if existing.contains(&key) || !seen_local.insert(key) {
            continue;
        }

        let mut rr = Vec::new();
        encode_name(owner, &mut rr)?;
        rr.extend_from_slice(&rr_type.to_be_bytes());
        rr.extend_from_slice(&rr_class.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(rdata);
        to_append.extend_from_slice(&rr);
        appended = appended.saturating_add(1);
    }

    if appended == 0 {
        return Some(packet.to_vec());
    }

    let new_ancount = header.ancount.checked_add(appended)?;
    let mut out = Vec::with_capacity(packet.len() + to_append.len());
    out.extend_from_slice(&packet[..answer_end]);
    out.extend_from_slice(&to_append);
    out.extend_from_slice(&packet[answer_end..]);
    out[6..8].copy_from_slice(&new_ancount.to_be_bytes());
    Some(out)
}

pub fn parse_first_question(packet: &[u8]) -> Option<(String, u16, usize)> {
    let header = parse_header(packet).ok()?;
    parse_first_question_from_header(packet, header)
}

fn parse_first_question_from_header(
    packet: &[u8],
    header: DnsHeader,
) -> Option<(String, u16, usize)> {
    if header.qdcount == 0 {
        return None;
    }

    let mut offset = 12usize;
    let mut labels = Vec::new();

    loop {
        if offset >= packet.len() {
            return None;
        }

        let len = packet[offset] as usize;
        offset += 1;

        if len == 0 {
            break;
        }

        if len & 0b1100_0000 != 0 {
            return None;
        }

        if offset + len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }

    if offset + 4 > packet.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    offset += 4;

    let qname = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Some((qname, qtype, offset))
}

fn skip_question_section(packet: &[u8], header: DnsHeader) -> Option<usize> {
    let mut offset = 12usize;
    for _ in 0..header.qdcount {
        offset = skip_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }
    Some(offset)
}

fn scan_resource_records<F, B>(
    packet: &[u8],
    header: DnsHeader,
    mut visitor: F,
) -> Option<ControlFlow<B>>
where
    F: FnMut(DnsSection, DnsRecordView<'_>) -> ControlFlow<B>,
{
    let mut offset = skip_question_section(packet, header)?;

    for _ in 0..header.ancount {
        match scan_single_resource_record(packet, offset, DnsSection::Answer, &mut visitor)? {
            ControlFlow::Continue(next_offset) => offset = next_offset,
            ControlFlow::Break(value) => return Some(ControlFlow::Break(value)),
        }
    }
    for _ in 0..header.nscount {
        match scan_single_resource_record(packet, offset, DnsSection::Authority, &mut visitor)? {
            ControlFlow::Continue(next_offset) => offset = next_offset,
            ControlFlow::Break(value) => return Some(ControlFlow::Break(value)),
        }
    }
    for _ in 0..header.arcount {
        match scan_single_resource_record(packet, offset, DnsSection::Additional, &mut visitor)? {
            ControlFlow::Continue(next_offset) => offset = next_offset,
            ControlFlow::Break(value) => return Some(ControlFlow::Break(value)),
        }
    }

    Some(ControlFlow::Continue(()))
}

fn scan_single_resource_record<F, B>(
    packet: &[u8],
    offset: usize,
    section: DnsSection,
    visitor: &mut F,
) -> Option<ControlFlow<B, usize>>
where
    F: FnMut(DnsSection, DnsRecordView<'_>) -> ControlFlow<B>,
{
    let (owner, consumed) = parse_name(packet, offset)?;
    let mut cursor = offset + consumed;
    if cursor + 10 > packet.len() {
        return None;
    }

    let rr_type = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    let rr_class = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
    let ttl = u32::from_be_bytes([
        packet[cursor + 4],
        packet[cursor + 5],
        packet[cursor + 6],
        packet[cursor + 7],
    ]);
    let rdlen = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]) as usize;
    cursor += 10;
    let rdata_offset = cursor;
    let rdata_end = rdata_offset + rdlen;
    if rdata_end > packet.len() {
        return None;
    }

    let flow = visitor(
        section,
        DnsRecordView {
            owner,
            rr_type,
            rr_class,
            rdata_offset,
            rdata: &packet[rdata_offset..rdata_end],
            ttl,
        },
    );
    match flow {
        ControlFlow::Continue(()) => Some(ControlFlow::Continue(rdata_end)),
        ControlFlow::Break(value) => Some(ControlFlow::Break(value)),
    }
}

fn scan_answer_records<F, B>(
    packet: &[u8],
    header: DnsHeader,
    mut visitor: F,
) -> Option<ControlFlow<B>>
where
    F: FnMut(DnsRecordView<'_>) -> ControlFlow<B>,
{
    scan_resource_records(packet, header, |section, record| {
        if section == DnsSection::Answer {
            visitor(record)
        } else {
            ControlFlow::Continue(())
        }
    })
}

fn endpoint_from_rdata(rr_type: u16, rdata: &[u8]) -> Option<String> {
    endpoint_from_rdata_with_port(rr_type, rdata, 53)
}

fn endpoint_from_rdata_with_port(rr_type: u16, rdata: &[u8], port: u16) -> Option<String> {
    match rr_type {
        1 if rdata.len() == 4 => Some(format!(
            "{}:{}",
            std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
            port
        )),
        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Some(format!("[{}]:{}", std::net::Ipv6Addr::from(octets), port))
        }
        _ => None,
    }
}

pub fn build_servfail_response(request: &[u8]) -> Result<Vec<u8>> {
    build_response_with_rcode(request, DNS_RCODE_SERVFAIL)
}

pub fn build_badvers_response(request: &[u8]) -> Result<Vec<u8>> {
    build_response_with_rcode(request, DNS_RCODE_BADVERS)
}

pub fn build_response_with_rcode(request: &[u8], rcode: u16) -> Result<Vec<u8>> {
    let header = parse_header(request)?;

    let mut response = Vec::with_capacity(512);
    response.extend_from_slice(&header.id.to_be_bytes());

    // QR=1, OPCODE copied, RD copied, RA=1, caller-provided RCODE
    let opcode = header.flags & 0x7800;
    let rd = header.flags & 0x0100;
    let mut flags = 0x8000 | opcode | rd | 0x0080;
    flags |= rcode & 0x000F;
    response.extend_from_slice(&flags.to_be_bytes());

    let qdcount = if header.qdcount > 0 { 1u16 } else { 0u16 };
    response.extend_from_slice(&qdcount.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    if qdcount == 1 {
        let (_, _, qend) =
            parse_first_question(request).ok_or_else(|| anyhow!("invalid first dns question"))?;
        response.extend_from_slice(&request[12..qend]);
    }

    let _ = maybe_append_request_edns_opt_with_rcode(request, &mut response, rcode);

    Ok(response)
}

pub fn response_code(packet: &[u8]) -> Option<u16> {
    Some(parse_response_overview(packet)?.rcode)
}

/// Clears the RCODE field in the DNS header (low nibble of byte 3) to NOERROR(0).
/// Used when a CNAME chain has collected valid CNAME records but the final
/// target returned an error (e.g. NXDOMAIN) — the original query name DOES have
/// a CNAME, so the rcode should reflect that.
pub fn clear_header_rcode(packet: &mut [u8]) {
    if packet.len() >= 4 {
        packet[3] &= 0xF0;
    }
}

pub fn decay_response_ttl_in_place(packet: &mut [u8], elapsed: Duration) {
    let Ok(header) = parse_header(packet) else {
        return;
    };

    let elapsed_secs = elapsed.as_secs().min(u32::MAX as u64) as u32;
    let mut offset = 12usize;

    for _ in 0..header.qdcount {
        let Some(next) = skip_name(packet, offset) else {
            return;
        };
        offset = next;
        if offset + 4 > packet.len() {
            return;
        }
        offset += 4;
    }

    let total_records = header.ancount as usize + header.nscount as usize + header.arcount as usize;
    for _ in 0..total_records {
        let Some(next) = skip_name(packet, offset) else {
            return;
        };
        offset = next;
        if offset + 10 > packet.len() {
            return;
        }

        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let decayed = ttl.saturating_sub(elapsed_secs);
        packet[offset + 4..offset + 8].copy_from_slice(&decayed.to_be_bytes());

        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return;
        }
        offset += rdlen;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_query() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(3);
        packet.extend_from_slice(b"www");
        packet.push(7);
        packet.extend_from_slice(b"example");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    fn edns_query() -> Vec<u8> {
        let mut packet = basic_query();
        append_edns_opt(&mut packet, 1232, 0).expect("append edns");
        packet
    }

    fn edns_query_with_version(version: u8) -> Vec<u8> {
        let mut packet = basic_query();
        append_edns_opt_with_rcode(&mut packet, 1232, 0, version, 0).expect("append edns");
        packet
    }

    fn edns_query_with_options(flags: u16) -> Vec<u8> {
        let mut packet = basic_query();
        append_edns_opt_with_options(
            &mut packet,
            1232,
            0,
            0,
            flags,
            &[
                DnsEdnsOption {
                    code: DNS_EDNS_OPTION_NSID,
                    data: vec![0xAA, 0xBB],
                },
                DnsEdnsOption {
                    code: DNS_EDNS_OPTION_COOKIE,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                },
                DnsEdnsOption {
                    code: DNS_EDNS_OPTION_CLIENT_SUBNET,
                    data: vec![0, 1, 24, 0, 192, 0, 2],
                },
            ],
        )
        .expect("append edns options");
        packet
    }

    fn edns_query_with_cookie(cookie: &[u8]) -> Vec<u8> {
        let mut packet = basic_query();
        append_edns_opt_with_options(
            &mut packet,
            1232,
            0,
            0,
            DNS_EDNS_FLAG_DO,
            &[DnsEdnsOption {
                code: DNS_EDNS_OPTION_COOKIE,
                data: cookie.to_vec(),
            }],
        )
        .expect("append cookie edns");
        packet
    }

    #[test]
    fn toggles_rd_bit() {
        let packet = basic_query();
        let modified = set_recursion_desired(&packet, false).expect("modify packet");
        let flags = u16::from_be_bytes([modified[2], modified[3]]);
        assert_eq!(flags & 0x0100, 0);
    }

    #[test]
    fn extracts_glue_ipv4_address() {
        let mut packet = basic_query();

        // ancount=0, nscount=1, arcount=1
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8..10].copy_from_slice(&1u16.to_be_bytes());
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());

        // Authority NS record: example.com NS ns1.example.com
        packet.extend_from_slice(&[0xC0, 0x10]); // name ptr to example.com
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        let ns_rdata = vec![
            3, b'n', b's', b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        packet.extend_from_slice(&(ns_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ns_rdata);

        // Additional A record for ns1.example.com = 192.0.2.53
        packet.extend_from_slice(&[
            3, b'n', b's', b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 53]);

        let glues = extract_glue_nameservers(&packet);
        assert!(glues.contains(&"192.0.2.53:53".to_string()));
    }

    #[test]
    fn extracts_authority_ns_hostnames() {
        let mut packet = basic_query();
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8..10].copy_from_slice(&1u16.to_be_bytes());
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());

        packet.extend_from_slice(&[0xC0, 0x10]);
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        let ns_rdata = vec![
            2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        packet.extend_from_slice(&(ns_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ns_rdata);

        let hosts = extract_authority_ns_hostnames(&packet);
        assert_eq!(hosts, vec!["ns.example.com".to_string()]);
    }

    #[test]
    fn referral_analysis_normalizes_case_and_deduplicates_hosts_zones() {
        let mut packet = basic_query();
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8..10].copy_from_slice(&2u16.to_be_bytes());
        packet[10..12].copy_from_slice(&2u16.to_be_bytes());

        // Authority NS #1: EXAMPLE.COM NS Ns1.Example.COM
        packet.extend_from_slice(&[
            7, b'E', b'X', b'A', b'M', b'P', b'L', b'E', 3, b'C', b'O', b'M', 0,
        ]);
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        let ns1 = vec![
            3, b'N', b's', b'1', 7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'C', b'O', b'M',
            0,
        ];
        packet.extend_from_slice(&(ns1.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ns1);

        // Authority NS #2: example.com NS ns1.example.com (duplicate after normalization)
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        let ns2 = vec![
            3, b'n', b's', b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        packet.extend_from_slice(&(ns2.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ns2);

        // Additional A glue duplicated by two records.
        packet.extend_from_slice(&[
            3, b'n', b's', b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 53]);

        packet.extend_from_slice(&[
            3, b'N', b'S', b'1', 7, b'E', b'X', b'A', b'M', b'P', b'L', b'E', 3, b'C', b'O', b'M',
            0,
        ]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 53]);

        let analysis = analyze_referral_targets(&packet).expect("analysis");
        assert_eq!(analysis.authority_zones, vec!["example.com".to_string()]);
        assert_eq!(
            analysis.authority_ns_hostnames,
            vec!["ns1.example.com".to_string()]
        );
        assert_eq!(analysis.glue_nameservers, vec!["192.0.2.53:53".to_string()]);
    }

    #[test]
    fn detects_authority_soa_without_referral_ns() {
        let mut packet = basic_query();
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8..10].copy_from_slice(&1u16.to_be_bytes());
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());

        packet.extend_from_slice(&[0xC0, 0x10]);
        packet.extend_from_slice(&6u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());

        let mut soa_rdata = Vec::new();
        soa_rdata.extend_from_slice(&[
            2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        soa_rdata.extend_from_slice(&[
            10, b'h', b'o', b's', b't', b'm', b'a', b's', b't', b'e', b'r', 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        soa_rdata.extend_from_slice(&1u32.to_be_bytes());
        soa_rdata.extend_from_slice(&2u32.to_be_bytes());
        soa_rdata.extend_from_slice(&3u32.to_be_bytes());
        soa_rdata.extend_from_slice(&4u32.to_be_bytes());
        soa_rdata.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&soa_rdata);

        let analysis = analyze_referral_targets(&packet).expect("analysis");
        assert!(analysis.has_authority_soa);
        assert!(analysis.authority_ns_hostnames.is_empty());
        assert!(analysis.authority_zones.is_empty());
        assert!(analysis.glue_nameservers.is_empty());
    }

    #[test]
    fn referral_validation_rejects_invalid_authority_zone() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["bad.zone".to_string()],
            has_authority_soa: false,
        };

        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(!validation.is_valid);
        assert!(!validation.authority_zones_valid);
        assert_eq!(
            validation.rejection_reason.as_deref(),
            Some("invalid_authority_zone")
        );
    }

    #[test]
    fn referral_validation_degrades_trust_for_out_of_zone_ns() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.other.com".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };

        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(!validation.bailiwick_valid);
        assert!(validation.trust_level <= 80);
        assert!(validation.trust_level < 100);
        assert!(validation.rejection_reason.is_none());
    }

    #[test]
    fn referral_validation_accepts_well_formed_referral() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string(), "192.0.2.54:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };

        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(validation.authority_zones_valid);
        assert!(validation.bailiwick_valid);
        assert!(validation.trust_level >= 80);
        assert!(validation.glue_coverage > 0.0);
    }

    #[test]
    fn referral_validation_tolerates_case_and_trailing_dot() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["Ns1.Example.Com.".to_string()],
            authority_zones: vec!["Example.COM.".to_string()],
            has_authority_soa: false,
        };

        let validation = validate_referral_security("WWW.Example.COM.", &analysis);
        assert!(validation.is_valid);
        assert!(validation.authority_zones_valid);
    }

    #[test]
    fn referral_validation_accepts_root_authority_zone() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.5.6.30:53".to_string()],
            authority_ns_hostnames: vec!["a.root-servers.net".to_string()],
            authority_zones: vec![".".to_string()],
            has_authority_soa: false,
        };

        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(validation.authority_zones_valid);
    }

    // ── 回归测试：out-of-zone NS 场景不能被硬拒绝 ──────────────────────────────
    //
    // 互联网 DNS 中，NS 主机名不在授权区内是完全正常的（如 a.gtld-servers.net
    // 服务于 com 区但其主机名不是 com 的子域名）。这组测试防止未来回退到
    // 将此类情况硬拒绝的逻辑。

    /// Root → TLD 场景：根服务器将 com 委托给 gtld-servers.net 系列主机。
    /// NS 主机名（a.gtld-servers.net）完全不在授权区（com）内，属于标准做法。
    #[test]
    fn referral_root_to_tld_out_of_zone_ns_is_valid() {
        let analysis = DnsReferralAnalysis {
            // 实际 root hints 不带 glue，这里给一个以便 trust_level 可计算
            glue_nameservers: vec!["192.5.6.30:53".to_string(), "192.5.6.31:53".to_string()],
            authority_ns_hostnames: vec![
                "a.gtld-servers.net".to_string(),
                "b.gtld-servers.net".to_string(),
            ],
            // 委托区是 com，NS 主机名在 gtld-servers.net，完全 out-of-zone
            authority_zones: vec!["com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);

        // 必须接受，不能硬拒绝
        assert!(
            validation.is_valid,
            "root→TLD out-of-zone referral must NOT be hard-rejected (is_valid=false)"
        );
        assert!(
            validation.rejection_reason.is_none(),
            "rejection_reason must be None for out-of-zone NS: {:?}",
            validation.rejection_reason
        );
        // bailiwick 标志应如实报告为 false
        assert!(
            !validation.bailiwick_valid,
            "bailiwick_valid should be false when NS hostnames are not subdomains of authority zone"
        );
        // trust_level 应被降低，但仍 > 0，使转介可被缓存（threshold = 60）
        assert!(
            validation.trust_level >= 60,
            "trust_level must still be >= 60 to allow caching, got {}",
            validation.trust_level
        );
    }

    /// TLD → 权威场景：163.com 被委托给 nease.net 系列 NS，同样 out-of-zone。
    /// 这正是历史上导致 www.163.com 解析失败的场景。
    #[test]
    fn referral_tld_to_authoritative_out_of_zone_ns_is_valid() {
        let analysis = DnsReferralAnalysis {
            // 2 glue records for 3 NS hostnames → coverage ≈ 66% ≥ 50%, no glue penalty
            // trust_level = 80 - 20 (out-of-zone) = 60 ≥ 60 (caching threshold)
            glue_nameservers: vec!["202.108.2.1:53".to_string(), "202.108.2.2:53".to_string()],
            authority_ns_hostnames: vec![
                "ns1.nease.net".to_string(),
                "ns2.nease.net".to_string(),
                "ns3.nease.net".to_string(),
            ],
            // 委托区是 163.com，NS 主机名在 nease.net，out-of-zone
            authority_zones: vec!["163.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.163.com", &analysis);

        assert!(
            validation.is_valid,
            "TLD→authoritative out-of-zone referral must NOT be hard-rejected (www.163.com scenario)"
        );
        assert!(
            validation.rejection_reason.is_none(),
            "rejection_reason must be None: {:?}",
            validation.rejection_reason
        );
        assert!(
            !validation.bailiwick_valid,
            "bailiwick_valid should be false for nease.net NS under 163.com"
        );
        assert!(
            validation.trust_level >= 60,
            "trust_level must be >= 60 for caching to work, got {}",
            validation.trust_level
        );
    }

    /// 无 glue 的 out-of-zone NS：常见于真实根 referral（cold start）。
    /// 此时 trust_level 较低，但 is_valid 仍须为 true。
    #[test]
    fn referral_no_glue_out_of_zone_ns_remains_valid() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec![], // 无 glue
            authority_ns_hostnames: vec!["ns1.example.net".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("sub.example.com", &analysis);

        assert!(
            validation.is_valid,
            "no-glue out-of-zone referral must remain valid (is_valid=false is regression)"
        );
        assert!(validation.rejection_reason.is_none());
        assert!(!validation.bailiwick_valid);
        // 无 glue（-20）+ out-of-zone（-20）= 80 - 20 - 20 = 40，低于缓存门槛
        // 这是预期行为：可接受转介但不缓存，防止过度信任无 glue 且 out-of-zone 的转介
        assert!(
            validation.trust_level < 60,
            "no-glue+out-of-zone trust_level should be < 60 (got {}), so delegation won't be cached blindly",
            validation.trust_level
        );
    }

    #[test]
    fn qtype_label_helpers_return_readable_values() {
        assert_eq!(qtype_label(1), "A");
        assert_eq!(qtype_label(28), "AAAA");
        assert_eq!(qtype_label(65280), "TYPE65280");
        assert_eq!(qtype_label_opt(Some(5)), "CNAME");
        assert_eq!(qtype_label_opt(None), "UNKNOWN");
    }

    #[test]
    fn build_static_answer_accepts_compressed_ipv6() {
        let request = build_query(321, "www.wan.cn", 28, true).expect("query");
        let packet = build_static_answer(&request, "1::1", 600, "AAAA").expect("static aaaa");

        assert_eq!(response_code(&packet), Some(0));
        assert!(answer_has_record_type_for_name(&packet, "www.wan.cn", 28));
    }

    #[test]
    fn build_static_answer_supports_extended_record_types() {
        let ns_query = build_query(11, "example.com", 2, true).expect("ns query");
        let ns_packet =
            build_static_answer(&ns_query, "ns1.example.com", 300, "NS").expect("ns answer");
        assert!(answer_has_record_type_for_name(
            &ns_packet,
            "example.com",
            2
        ));

        let mx_query = build_query(12, "example.com", 15, true).expect("mx query");
        let mx_packet =
            build_static_answer(&mx_query, "10 mail.example.com", 300, "MX").expect("mx answer");
        assert!(answer_has_record_type_for_name(
            &mx_packet,
            "example.com",
            15
        ));

        let txt_query = build_query(13, "example.com", 16, true).expect("txt query");
        let txt_packet =
            build_static_answer(&txt_query, "v=spf1 -all", 300, "TXT").expect("txt answer");
        assert!(answer_has_record_type_for_name(
            &txt_packet,
            "example.com",
            16
        ));

        let ptr_query = build_query(14, "1.0.0.127.in-addr.arpa", 12, true).expect("ptr query");
        let ptr_packet =
            build_static_answer(&ptr_query, "localhost", 300, "PTR").expect("ptr answer");
        assert!(answer_has_record_type_for_name(
            &ptr_packet,
            "1.0.0.127.in-addr.arpa",
            12
        ));
    }

    #[test]
    fn extracts_edns_opt_from_request() {
        let packet = edns_query();
        let edns = extract_edns_opt(&packet).expect("edns opt");
        assert_eq!(edns.udp_payload_size, 1232);
        assert_eq!(edns.extended_rcode, 0);
        assert_eq!(edns.version, 0);
        assert_eq!(edns.flags, 0);
        assert!(edns.options.is_empty());
    }

    #[test]
    fn build_response_with_rcode_echoes_request_edns_opt() {
        let request = edns_query();
        let response = build_response_with_rcode(&request, 2).expect("response");
        let header = parse_header(&response).expect("response header");
        assert_eq!(header.arcount, 1);

        let edns = extract_edns_opt(&response).expect("response edns opt");
        assert_eq!(edns.udp_payload_size, 1232);
        assert_eq!(edns.extended_rcode, 0);
        assert_eq!(edns.version, 0);
        assert_eq!(edns.flags, 0);
        assert!(edns.options.is_empty());
    }

    #[test]
    fn build_query_like_request_preserves_edns_opt() {
        let request = edns_query();
        let query =
            build_query_like_request(&request, 55, "next.example", 1, false).expect("query");
        let edns = extract_edns_opt(&query).expect("edns opt");
        let header = parse_header(&query).expect("header");

        assert_eq!(header.id, 55);
        assert_eq!(edns.udp_payload_size, 1232);
        assert_eq!(edns.extended_rcode, 0);
        assert_eq!(edns.version, 0);
        assert_eq!(edns.flags, 0);
        assert!(edns.options.is_empty());
    }

    #[test]
    fn truncate_response_for_udp_sets_tc_and_respects_payload_size() {
        let request = edns_query();
        let mut response = build_response_with_rcode(&request, 0).expect("response");
        response.extend_from_slice(&vec![0u8; 2048]);

        let truncated = truncate_response_for_udp(&request, &response).expect("truncated");
        let header = parse_header(&truncated).expect("header");

        assert!(truncated.len() <= udp_payload_size_for_request(&request));
        assert!(header.flags & 0x0200 != 0);
        assert_eq!(header.qdcount, 1);
    }

    fn push_name_rr(
        packet: &mut Vec<u8>,
        owner: &str,
        rr_type: u16,
        rr_class: u16,
        ttl: u32,
        rdata: &[u8],
    ) {
        encode_name(owner, packet).expect("owner name");
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&rr_class.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
    }

    fn build_answer_with_cname_and_dname_response(request: &[u8]) -> Vec<u8> {
        let header = parse_header(request).expect("header");
        let (_, _, qend) = parse_first_question(request).expect("question");
        let mut packet = Vec::with_capacity(192);
        packet.extend_from_slice(&header.id.to_be_bytes());
        let opcode = header.flags & 0x7800;
        let rd = header.flags & 0x0100;
        let flags = 0x8000 | opcode | rd | 0x0080;
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&3u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&request[12..qend]);

        let mut cname_rdata = Vec::new();
        encode_name("alias.example.com", &mut cname_rdata).expect("cname target");
        push_name_rr(&mut packet, "WWW.Example.COM", 5, 1, 120, &cname_rdata);

        push_name_rr(
            &mut packet,
            "alias.example.com",
            39,
            1,
            90,
            b"\x05target\x07example\x03net\x00",
        );

        push_name_rr(&mut packet, "alias.example.com", 1, 1, 30, &[192, 0, 2, 1]);
        packet
    }

    #[test]
    fn analyze_answer_for_name_with_dnames_collects_all_followup_records_in_one_pass() {
        let request = build_query(200, "www.example.com", 1, true).expect("query");
        let packet = build_answer_with_cname_and_dname_response(&request);

        let combined =
            analyze_answer_for_name_with_dnames(&packet, "WWW.Example.COM", 1).expect("analysis");

        assert_eq!(combined.analysis.rcode, 0);
        assert!(!combined.analysis.has_target_record);
        assert!(combined.analysis.has_owner_cname);
        assert_eq!(
            combined.analysis.first_cname.as_deref(),
            Some("alias.example.com")
        );
        assert_eq!(combined.analysis.cname_records.len(), 1);
        assert_eq!(combined.dname_records.len(), 1);
        assert_eq!(combined.dname_records[0].0, "alias.example.com");
        assert_eq!(combined.dname_records[0].1, 39);
        assert_eq!(combined.dname_records[0].2, 1);
    }

    #[test]
    fn extracts_edns_options_and_common_option_entrypoints() {
        let packet = edns_query_with_options(DNS_EDNS_FLAG_DO);
        let edns = extract_edns_opt(&packet).expect("edns opt");

        assert_eq!(edns.options.len(), 3);
        assert!(dnssec_ok_requested(&packet));
        assert_eq!(extract_edns_nsid(&packet), Some(vec![0xAA, 0xBB]));
        assert_eq!(
            extract_edns_cookie(&packet),
            Some((vec![1, 2, 3, 4, 5, 6, 7, 8], Some(vec![9, 10, 11, 12])))
        );

        let ecs = extract_edns_client_subnet(&packet).expect("ecs");
        assert_eq!(ecs.family, 1);
        assert_eq!(ecs.source_prefix, 24);
        assert_eq!(ecs.scope_prefix, 0);
        assert_eq!(ecs.address, vec![192, 0, 2]);
    }

    #[test]
    fn extracts_cookie_option_and_rejects_short_cookie() {
        let packet = edns_query_with_cookie(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(
            extract_edns_cookie(&packet),
            Some((vec![1, 2, 3, 4, 5, 6, 7, 8], Some(vec![9, 10, 11, 12])))
        );

        let short_cookie = edns_query_with_cookie(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(extract_edns_cookie(&short_cookie), None);
    }

    #[test]
    fn align_response_edns_to_request_strips_unsolicited_opt() {
        let request = basic_query();
        let response = build_response_with_rcode(&edns_query_with_options(DNS_EDNS_FLAG_DO), 0)
            .expect("response");
        let aligned = align_response_edns_to_request(&response, &request).expect("aligned");

        assert!(extract_edns_opt(&aligned).is_none());
    }

    #[test]
    fn align_response_edns_to_request_restores_request_do_bit() {
        let request = edns_query_with_options(DNS_EDNS_FLAG_DO);
        let response = build_response_with_rcode(&basic_query(), 0).expect("response");
        let aligned = align_response_edns_to_request(&response, &request).expect("aligned");
        let edns = extract_edns_opt(&aligned).expect("edns");

        assert_eq!(edns.udp_payload_size, 1232);
        assert_eq!(edns.flags & DNS_EDNS_FLAG_DO, DNS_EDNS_FLAG_DO);
        assert_eq!(edns.options.len(), 0);
    }

    #[test]
    fn build_query_like_request_preserves_cookie_option() {
        let request = edns_query_with_cookie(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let query = build_query_like_request(&request, 77, "alias.example.com", 1, true)
            .expect("query");

        assert_eq!(extract_edns_cookie(&query), Some((
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            Some(vec![9, 10, 11, 12])
        )));
        assert!(dnssec_ok_requested(&query));
    }

    #[test]
    fn build_badvers_response_sets_extended_rcode_and_resets_version() {
        let request = edns_query_with_version(1);
        let response = build_badvers_response(&request).expect("response");
        let header = parse_header(&response).expect("response header");
        let edns = extract_edns_opt(&response).expect("response edns");

        assert_eq!(header.flags & 0x000F, 0);
        assert_eq!(response_code(&response), Some(DNS_RCODE_BADVERS));
        assert_eq!(edns.extended_rcode, 1);
        assert_eq!(edns.version, 0);
        assert_eq!(edns.udp_payload_size, 1232);
    }

    #[test]
    fn rejects_unsupported_edns_version() {
        let request = edns_query_with_version(1);
        assert!(!edns_version_supported(&request));
        assert!(edns_version_supported(&basic_query()));
    }

    #[test]
    fn toggles_cd_bit() {
        let packet = basic_query();
        let modified = set_checking_disabled(&packet, true).expect("modify packet");
        assert!(checking_disabled(&modified));
        let restored = set_checking_disabled(&modified, false).expect("restore packet");
        assert!(!checking_disabled(&restored));
    }

    #[test]
    fn build_dnssec_query_like_request_sets_do_and_cd() {
        let request = basic_query();
        let query = build_dnssec_query_like_request(
            &request,
            77,
            "dnssec.example",
            DNS_TYPE_DNSKEY,
            true,
            true,
        )
        .expect("query");

        assert!(dnssec_ok_requested(&query));
        assert!(checking_disabled(&query));
        assert_eq!(
            extract_edns_opt(&query).map(|value| value.udp_payload_size),
            Some(1232)
        );
    }

    #[test]
    fn strip_edns_opt_from_request_removes_opt_record() {
        let request = edns_query();
        let stripped = strip_edns_opt_from_request(&request).expect("stripped request");
        let header = parse_header(&stripped).expect("header");

        assert_eq!(header.arcount, 0);
        assert!(extract_edns_opt(&stripped).is_none());
        assert_eq!(
            parse_first_question(&stripped).map(|value| value.0),
            Some("www.example.com".to_string())
        );
    }

    #[test]
    fn extracts_negative_cache_ttl_from_authority_soa() {
        let mut packet = basic_query();
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8..10].copy_from_slice(&1u16.to_be_bytes());
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());

        packet.extend_from_slice(&[0xC0, 0x10]);
        packet.extend_from_slice(&6u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());

        let mut soa_rdata = Vec::new();
        soa_rdata.extend_from_slice(&[
            2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        soa_rdata.extend_from_slice(&[
            10, b'h', b'o', b's', b't', b'm', b'a', b's', b't', b'e', b'r', 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        soa_rdata.extend_from_slice(&1u32.to_be_bytes());
        soa_rdata.extend_from_slice(&2u32.to_be_bytes());
        soa_rdata.extend_from_slice(&3u32.to_be_bytes());
        soa_rdata.extend_from_slice(&4u32.to_be_bytes());
        soa_rdata.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&soa_rdata);

        assert_eq!(
            extract_negative_cache_ttl(&packet),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn build_authoritative_answer_multi_sets_ancount_for_multiple_rrs() {
        let request = basic_query();
        let answers = vec!["192.0.2.10".to_string(), "192.0.2.11".to_string()];
        let response = build_authoritative_answer_multi(&request, &answers, 300, "A")
            .expect("multi answer response");
        let header = parse_header(&response).expect("header");

        assert_eq!(header.ancount, 2);
        assert_eq!(header.flags & 0x0400, 0x0400); // AA=1
        assert_eq!(response_code(&response), Some(0)); // NOERROR
    }

    #[test]
    fn build_authoritative_nodata_returns_noerror_with_soa_authority() {
        let request = basic_query();
        let response = build_authoritative_nodata(
            &request,
            "example.com",
            "ns1.example.com",
            "hostmaster.example.com",
            2026051301,
            3600,
            900,
            604800,
            300,
        )
        .expect("nodata response");
        let header = parse_header(&response).expect("header");

        assert_eq!(response_code(&response), Some(0)); // NOERROR
        assert_eq!(header.flags & 0x0400, 0x0400); // AA=1
        assert_eq!(header.ancount, 0);
        assert_eq!(header.nscount, 1);
    }

    #[test]
    fn build_authoritative_soa_answer_uses_soa_type() {
        let mut request = Vec::new();
        request.extend_from_slice(&2u16.to_be_bytes());
        request.extend_from_slice(&0x0100u16.to_be_bytes());
        request.extend_from_slice(&1u16.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.push(3);
        request.extend_from_slice(b"soa");
        request.push(7);
        request.extend_from_slice(b"example");
        request.push(3);
        request.extend_from_slice(b"com");
        request.push(0);
        request.extend_from_slice(&6u16.to_be_bytes());
        request.extend_from_slice(&1u16.to_be_bytes());

        let response = build_authoritative_soa_answer(
            &request,
            "example.com",
            "ns1.example.com",
            "hostmaster.example.com",
            2024051201,
            3600,
            600,
            86400,
            300,
        )
        .expect("soa answer response");

        let header = parse_header(&response).expect("response header");
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 1);
        assert_eq!(header.flags & 0x0400, 0x0400);

        let (_qname, _qtype, qend) = parse_first_question(&response).expect("question section");
        let answer_type = u16::from_be_bytes([response[qend + 13], response[qend + 14]]);
        assert_eq!(answer_type, 6);
    }

    #[test]
    fn build_authoritative_soa_answer_accepts_trailing_dot_names() {
        let mut request = Vec::new();
        request.extend_from_slice(&3u16.to_be_bytes());
        request.extend_from_slice(&0x0100u16.to_be_bytes());
        request.extend_from_slice(&1u16.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.extend_from_slice(&0u16.to_be_bytes());
        request.push(7);
        request.extend_from_slice(b"example");
        request.push(3);
        request.extend_from_slice(b"com");
        request.push(0);
        request.extend_from_slice(&6u16.to_be_bytes());
        request.extend_from_slice(&1u16.to_be_bytes());

        let response = build_authoritative_soa_answer(
            &request,
            "example.com.",
            "ns1.example.com.",
            "hostmaster.example.com.",
            2026051402,
            3600,
            600,
            86400,
            300,
        )
        .expect("soa answer response");

        let (_qname, _qtype, qend) = parse_first_question(&response).expect("question section");
        let answer_offset = qend;
        let name_end = skip_name(&response, answer_offset).expect("answer name");
        let rdlen = u16::from_be_bytes([response[name_end + 8], response[name_end + 9]]) as usize;
        let rdata_offset = name_end + 10;
        assert!(rdata_offset + rdlen <= response.len());

        let (mname, mname_len) = parse_name(&response, rdata_offset).expect("soa mname");
        let (rname, _) = parse_name(&response, rdata_offset + mname_len).expect("soa rname");
        assert_eq!(mname, "ns1.example.com");
        assert_eq!(rname, "hostmaster.example.com");
    }

    #[test]
    fn extract_cache_ttl_ignores_opt_record_ttl_field() {
        let mut packet = basic_query();
        // QR=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=1
        packet[2..4].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet[8..10].copy_from_slice(&0u16.to_be_bytes());
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());

        // Answer: NAME ptr, TYPE A, CLASS IN, TTL=300, RDATA=1.2.3.4
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[1, 2, 3, 4]);

        // Additional OPT: TTL field is EDNS flags/extended rcode, should not affect cache ttl.
        packet.extend_from_slice(&0u8.to_be_bytes()); // root name
        packet.extend_from_slice(&41u16.to_be_bytes()); // OPT
        packet.extend_from_slice(&1232u16.to_be_bytes()); // UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // extended rcode/version/flags
        packet.extend_from_slice(&0u16.to_be_bytes()); // RDLEN

        assert_eq!(extract_cache_ttl(&packet), Some(Duration::from_secs(300)));
    }

    #[test]
    fn decays_answer_ttl_in_place() {
        let mut packet = basic_query();
        // QR=1, ancount=1
        packet[2..4].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());

        // Answer: pointer to question name, TYPE A, CLASS IN, TTL=60, RDATA=1.2.3.4
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[1, 2, 3, 4]);

        decay_response_ttl_in_place(&mut packet, Duration::from_secs(7));

        let ttl_offset = packet.len() - 10;
        let ttl = u32::from_be_bytes([
            packet[ttl_offset],
            packet[ttl_offset + 1],
            packet[ttl_offset + 2],
            packet[ttl_offset + 3],
        ]);
        assert_eq!(ttl, 53);
    }

    // ────────────────────────────────────────────────────────────────────────
    // RFC 角落回归测试：21 个新测试，覆盖 case 规范化、trailing-dot、glue、
    // authority zone 验证、信任等级边界及环境特定场景
    // ────────────────────────────────────────────────────────────────────────

    /// RFC 1034 section 3.1: 域名是 case-insensitive 的。
    /// 测试 authority zone 全大写时的规范化。
    #[test]
    fn referral_authority_zone_all_uppercase_normalized() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["EXAMPLE.COM".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(
            validation.is_valid,
            "all-uppercase authority zone should normalize"
        );
        assert!(validation.authority_zones_valid);
        assert!(validation.bailiwick_valid);
    }

    /// NS 主机名全大写的规范化测试。
    #[test]
    fn referral_ns_hostname_all_uppercase_normalized() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["NS1.EXAMPLE.COM".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(validation.bailiwick_valid);
    }

    /// Query name 全大写时的规范化测试。
    #[test]
    fn referral_query_name_all_uppercase_normalized() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("WWW.EXAMPLE.COM", &analysis);
        assert!(validation.is_valid);
        assert!(validation.authority_zones_valid);
    }

    /// 混合大小写：query、zone、NS 主机名各不相同。
    #[test]
    fn referral_mixed_case_across_all_fields() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["Ns1.Example.COM".to_string()],
            authority_zones: vec!["ExAmPlE.CoM".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("WwW.eXaMpLe.cOm", &analysis);
        assert!(validation.is_valid);
        assert!(validation.bailiwick_valid);
    }

    /// 多重重复 NS 主机名（大小写变体）。
    /// 注：由于直接构造 DnsReferralAnalysis（未经 analyze_referral_targets 的去重），
    /// 这里的 3 个 NS 字段仍然是 3 条。glue_coverage 会计算为 1 glue / 3 NS ≈ 33%。
    /// 此测试验证验证函数不会因此崩溃，且仍返回有效的转介。
    #[test]
    fn referral_multiple_ns_hostnames_with_case_variants_deduplicated() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            // 3 个逻辑重复的 NS（case 变体），但此结构体未自动去重
            authority_ns_hostnames: vec![
                "ns1.example.com".to_string(),
                "NS1.EXAMPLE.COM".to_string(),
                "Ns1.Example.Com".to_string(),
            ],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        // Glue coverage = 1 glue / 3 NS ≈ 0.33，低于 50% 阈值
        assert!(validation.glue_coverage > 0.3 && validation.glue_coverage < 0.4);
        // Trust level 应因 glue 不足而被降低
        assert!(validation.trust_level < 100);
    }

    /// Authority zone 带尾部 dot 的规范化。
    #[test]
    fn referral_authority_zone_with_trailing_dot() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["example.com.".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(validation.authority_zones_valid);
    }

    /// NS 主机名带尾部 dot。
    #[test]
    fn referral_ns_hostname_with_trailing_dot() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com.".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(validation.bailiwick_valid);
    }

    /// Query name 带尾部 dot（root 查询场景）。
    #[test]
    fn referral_query_name_with_trailing_dot() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com.", &analysis);
        assert!(validation.is_valid);
        assert!(validation.authority_zones_valid);
    }

    /// 混合 trailing dots：某些字段带，某些不带。
    #[test]
    fn referral_mixed_trailing_dots_across_fields() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com.".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com.", &analysis);
        assert!(validation.is_valid);
        assert!(validation.bailiwick_valid);
    }

    /// 完整 glue 覆盖（所有 NS 都有对应的 glue IP）。
    #[test]
    fn referral_full_glue_coverage() {
        let analysis = DnsReferralAnalysis {
            // 3 NS，3 glue IP → 100% 覆盖
            glue_nameservers: vec![
                "192.0.2.53:53".to_string(),
                "192.0.2.54:53".to_string(),
                "192.0.2.55:53".to_string(),
            ],
            authority_ns_hostnames: vec![
                "ns1.example.com".to_string(),
                "ns2.example.com".to_string(),
                "ns3.example.com".to_string(),
            ],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(
            validation.glue_coverage > 0.99,
            "should have >= 100% coverage"
        );
        assert!(
            validation.trust_level >= 80,
            "full glue should boost trust_level"
        );
    }

    /// 部分 glue 覆盖（50% NS 有 glue）。
    #[test]
    fn referral_partial_glue_coverage_fifty_percent() {
        let analysis = DnsReferralAnalysis {
            // 2 NS，1 glue → 50% 覆盖
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec![
                "ns1.example.com".to_string(),
                "ns2.example.com".to_string(),
            ],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(validation.glue_coverage >= 0.4 && validation.glue_coverage <= 0.6);
        // 部分 glue 应施加信任惩罚
        assert!(
            validation.trust_level < 100,
            "partial glue should reduce trust_level"
        );
    }

    /// 无 glue（常见于根转介的冷启动场景）。
    #[test]
    fn referral_no_glue_at_all() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec![],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid, "no-glue referral must remain valid");
        assert_eq!(validation.glue_coverage, 0.0);
        // 无 glue 导致信任等级显著下降
        assert!(
            validation.trust_level < 70,
            "no glue should significantly reduce trust_level, got {}",
            validation.trust_level
        );
    }

    /// Glue 数量多于 NS 主机名（某些 glue 未被利用）。
    /// 覆盖率计算为：min(glue_count / ns_count, 1.0) = min(5 / 2, 1.0) = 1.0（上限）。
    #[test]
    fn referral_more_glue_than_ns_hostnames() {
        let analysis = DnsReferralAnalysis {
            // 5 glue 但只有 2 NS
            glue_nameservers: vec![
                "192.0.2.53:53".to_string(),
                "192.0.2.54:53".to_string(),
                "192.0.2.55:53".to_string(),
                "192.0.2.56:53".to_string(),
                "192.0.2.57:53".to_string(),
            ],
            authority_ns_hostnames: vec![
                "ns1.example.com".to_string(),
                "ns2.example.com".to_string(),
            ],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        // Glue 覆盖 = 5 glue / 2 NS = 2.5，被上限为 1.0（100%）
        assert!(
            (validation.glue_coverage - 1.0).abs() < 0.001,
            "coverage should be capped at 1.0, got {}",
            validation.glue_coverage
        );
    }

    /// Authority zone 为空列表（无效场景）。
    #[test]
    fn referral_empty_authority_zones_rejected() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec![],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(
            !validation.is_valid,
            "empty authority_zones must be rejected"
        );
        assert!(!validation.authority_zones_valid);
    }

    /// 多个 authority zone（无效场景）。
    #[test]
    fn referral_multiple_authority_zones_rejected() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.example.com".to_string()],
            authority_zones: vec!["example.com".to_string(), "other.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(
            !validation.is_valid,
            "multiple authority zones must be rejected"
        );
        assert!(!validation.authority_zones_valid);
    }

    /// Out-of-zone NS 且有充足 glue（HiChina 场景）。
    #[test]
    fn referral_out_of_zone_ns_with_good_glue_coverage() {
        let analysis = DnsReferralAnalysis {
            // 充足 glue（3 IP for 2 NS）
            glue_nameservers: vec![
                "202.108.2.1:53".to_string(),
                "202.108.2.2:53".to_string(),
                "202.108.2.3:53".to_string(),
            ],
            authority_ns_hostnames: vec!["ns1.nease.net".to_string(), "ns2.nease.net".to_string()],
            // 委托区是 163.com，NS 在 nease.net → out-of-zone
            authority_zones: vec!["163.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.163.com", &analysis);
        assert!(validation.is_valid, "out-of-zone with glue must be valid");
        assert!(!validation.bailiwick_valid, "bailiwick should be false");
        // Out-of-zone 有 glue，trust_level 应在可接受范围
        assert!(
            validation.trust_level >= 60,
            "out-of-zone + good glue should yield trust_level >= 60, got {}",
            validation.trust_level
        );
    }

    /// Out-of-zone NS 且无 glue（无法继续转介）。
    #[test]
    fn referral_out_of_zone_ns_without_glue_low_trust() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec![],
            authority_ns_hostnames: vec!["ns1.external.net".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(
            validation.is_valid,
            "out-of-zone + no-glue must remain valid"
        );
        assert!(!validation.bailiwick_valid);
        // 双重惩罚（no-glue + out-of-zone）导致信任等级 < 60
        assert!(
            validation.trust_level < 60,
            "out-of-zone + no-glue should yield trust_level < 60 for safety, got {}",
            validation.trust_level
        );
    }

    /// Authority zone 匹配但 SOA 存在的特殊情形（NXDOMAIN 应答）。
    #[test]
    fn referral_out_of_zone_with_authority_soa_present() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.external.net".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: true, // SOA 标记
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        assert!(!validation.bailiwick_valid);
        // SOA 存在时应施加额外惩罚（这是 NXDOMAIN 类应答，转介后不再需要）
        assert!(
            validation.trust_level <= 80,
            "presence of SOA should reduce trust further"
        );
    }

    /// 混合 case + 混合 trailing dots + 无 glue + out-of-zone（复杂环境场景）。
    #[test]
    fn referral_complex_mixed_case_dots_no_glue_out_of_zone() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec![],
            authority_ns_hostnames: vec!["Ns1.External.NET.".to_string()],
            authority_zones: vec!["ExAmPlE.CoM.".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("WwW.eXaMpLe.cOm.", &analysis);
        assert!(
            validation.is_valid,
            "complex mixed case/dots/no-glue/out-of-zone must remain valid"
        );
        assert!(!validation.bailiwick_valid);
        assert_eq!(validation.glue_coverage, 0.0);
        assert!(
            validation.trust_level < 60,
            "complex scenario should yield low trust"
        );
    }

    /// 多个 NS 主机名，部分重复（case 变体），混合 glue 与 no-glue。
    /// 此测试验证结构体中有 4 个 NS 条目且 3 个 glue，计算为 3/4 = 0.75。
    /// 因为直接构造的 DnsReferralAnalysis 不会自动去重重复的 NS。
    #[test]
    fn referral_multiple_ns_mixed_duplicates_and_glue() {
        let analysis = DnsReferralAnalysis {
            // 3 glue for 4 NS 条目（未去重）
            glue_nameservers: vec![
                "192.0.2.53:53".to_string(),
                "192.0.2.54:53".to_string(),
                "192.0.2.55:53".to_string(),
            ],
            authority_ns_hostnames: vec![
                "ns1.example.com".to_string(),
                "NS1.EXAMPLE.COM".to_string(), // 重复（case 变体），但此结构体中仍为 2 条
                "ns2.example.com".to_string(),
                "ns3.example.com".to_string(),
            ],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        assert!(validation.is_valid);
        // Glue coverage = 3 glue / 4 NS = 0.75
        assert!(
            (validation.glue_coverage - 0.75).abs() < 0.01,
            "glue coverage should be ~0.75, got {}",
            validation.glue_coverage
        );
    }

    /// Root zone 作为 authority zone，query 为根查询。
    #[test]
    fn referral_root_zone_query_root() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.5.6.30:53".to_string()],
            authority_ns_hostnames: vec!["a.root-servers.net".to_string()],
            authority_zones: vec![".".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security(".", &analysis);
        assert!(validation.is_valid);
        assert!(validation.authority_zones_valid);
    }

    /// Authority zone 为子域但 query 是更高级别的域（mismatch）。
    #[test]
    fn referral_authority_zone_subdomain_query_parent_mismatch() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.0.2.53:53".to_string()],
            authority_ns_hostnames: vec!["ns1.sub.example.com".to_string()],
            authority_zones: vec!["sub.example.com".to_string()],
            has_authority_soa: false,
        };
        // Query 是 example.com，但转介是 sub.example.com
        let validation = validate_referral_security("example.com", &analysis);
        // Query 应该匹配或大于等于 authority zone，这里 example.com > sub.example.com，应被拒绝
        assert!(
            !validation.is_valid,
            "query superior to authority zone should be rejected"
        );
    }

    /// NS 主机名为根（特殊情形）。
    /// 根 (\".\") 不在 example.com 域内（bailiwick violation），
    /// 但验证函数允许此转介（is_valid=true），只是标记 bailiwick 无效。
    /// Trust level = 80 (base) + 20 (full glue) - 20 (out-of-zone) = 80
    #[test]
    fn referral_ns_hostname_is_root_remains_valid() {
        let analysis = DnsReferralAnalysis {
            glue_nameservers: vec!["192.5.6.30:53".to_string()],
            authority_ns_hostnames: vec![".".to_string()],
            authority_zones: vec!["example.com".to_string()],
            has_authority_soa: false,
        };
        let validation = validate_referral_security("www.example.com", &analysis);
        // 验证函数接受此转介但标记 bailiwick 违反
        assert!(
            validation.is_valid,
            "root as NS hostname should not hard-reject (out-of-zone is soft penalty)"
        );
        assert!(
            !validation.bailiwick_valid,
            "root is not in example.com zone"
        );
        // Full glue offsets out-of-zone penalty: 80 + 20 - 20 = 80
        assert_eq!(
            validation.trust_level, 80,
            "full glue + out-of-zone should yield 80"
        );
    }
}
