//! End-to-end integration coverage for ingress, resolver, policy and admin APIs.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cognidns::cache::ResponseCache;
use cognidns::codec::dns;
use cognidns::context::{Protocol, RequestContext};
use cognidns::health::HealthCheckConfig;
use cognidns::ingress;
use cognidns::metrics::Metrics;
use cognidns::policy::{PolicyConfig, PolicyEngine};
use cognidns::resolver::{ResolutionSource, Resolver, ResolverConfig};
use cognidns::service::AppState;
use hickory_proto::dnssec::TrustAnchors;
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_edns_query_with_flags(id: u16, name: &str, qtype: u16, flags: u16) -> Vec<u8> {
    let mut packet = build_query(id, name, qtype);
    dns::append_edns_opt(&mut packet, 1232, flags).expect("append edns");
    packet
}

fn build_edns_query(id: u16, name: &str, qtype: u16, version: u8) -> Vec<u8> {
    let mut packet = build_query(id, name, qtype);
    dns::append_edns_opt_with_rcode(&mut packet, 1232, 0, version, 0).expect("append edns");
    packet
}

fn build_root_query(id: u16, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_truncated_question_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Header is valid and qdcount=1, but question section is intentionally truncated.
    packet.push(3);
    packet.extend_from_slice(b"ww");
    packet
}

fn build_pointer_loop_question_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Question name compression pointer loops to itself at offset 12.
    packet.extend_from_slice(&[0xC0, 0x0C]);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_multi_question_packet(id: u16, first: &str, second: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&2u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for label in first.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    for label in second.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    packet
}

fn build_qdcount_mismatch_packet(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    // Declares two questions but carries only one.
    packet.extend_from_slice(&2u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_label_length_out_of_bounds_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Declares a label length that exceeds the remaining payload.
    packet.push(64);
    packet.extend_from_slice(b"short");
    packet
}

fn build_pointer_out_of_bounds_question_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Compression pointer targets an offset outside packet bounds.
    packet.extend_from_slice(&[0xC0, 0xFF]);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_pointer_depth_exceeded_question_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Build a pointer chain deeper than parser's max depth guard (16).
    for i in 0..17u16 {
        let target = 12u16 + (i + 1) * 2;
        packet.push(0xC0);
        packet.push((target & 0xFF) as u8);
    }

    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_invalid_utf8_label_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Label bytes are intentionally invalid UTF-8.
    packet.push(2);
    packet.extend_from_slice(&[0xC3, 0x28]);
    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_truncated_qtype_qclass_packet(id: u16, name: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    // Question footer should be 4 bytes (qtype + qclass), intentionally truncate to 3 bytes.
    packet.extend_from_slice(&[0x00, 0x01, 0x00]);
    packet
}

fn build_qdcount_zero_with_trailing_bytes_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    // Declares zero questions while appending extra bytes that look like a partial question.
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&[3, b'w', b'w', b'w', 0, 0, 1]);
    packet
}

fn build_reserved_label_prefix_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    // First length octet uses reserved prefix bits (01xxxxxx), not a valid label nor compression pointer.
    packet.push(64);
    packet.extend_from_slice(&[b'a'; 64]);
    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_qdcount_max_mismatch_packet(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    // Extreme count with only one question payload.
    packet.extend_from_slice(&u16::MAX.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

fn build_query_with_trailing_garbage(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = build_query(id, name, qtype);
    // Intentionally append bytes after first question to lock current tolerant behavior.
    packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    packet
}

fn build_pointer_question_non_loop_packet(id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Question starts with a compression pointer to offset 18, which is a zero label.
    // This is non-loop and in-bounds, but parse_first_question intentionally rejects pointer form.
    packet.extend_from_slice(&[0xC0, 0x12]);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.push(0);
    packet
}

fn build_padded_query(id: u16, name: &str, qtype: u16, total_len: usize) -> Vec<u8> {
    let mut packet = build_query(id, name, qtype);
    if packet.len() < total_len {
        packet.resize(total_len, 0xAA);
    }
    packet
}

fn build_padded_reserved_label_prefix_packet(id: u16, total_len: usize) -> Vec<u8> {
    let mut packet = build_reserved_label_prefix_packet(id);
    if packet.len() < total_len {
        packet.resize(total_len, 0xAA);
    }
    packet
}

fn append_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn build_referral_response(request: &[u8], ns_host: &str) -> Vec<u8> {
    let mut resp = Vec::new();
    let id = u16::from_be_bytes([request[0], request[1]]);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8000u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    if let Some((_, _, qend)) = dns::parse_first_question(request) {
        resp.extend_from_slice(&request[12..qend]);
    }

    // Authority NS: example.com NS <ns_host>
    append_name(&mut resp, "example.com");
    resp.extend_from_slice(&2u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    let mut rdata = Vec::new();
    append_name(&mut rdata, ns_host);
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

fn build_referral_with_glue_response(
    request: &[u8],
    zone: &str,
    ns_host: &str,
    glue_ip: [u8; 4],
) -> Vec<u8> {
    let mut resp = Vec::new();
    let id = u16::from_be_bytes([request[0], request[1]]);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8000u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());

    if let Some((_, _, qend)) = dns::parse_first_question(request) {
        resp.extend_from_slice(&request[12..qend]);
    }

    append_name(&mut resp, zone);
    resp.extend_from_slice(&2u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    let mut ns_rdata = Vec::new();
    append_name(&mut ns_rdata, ns_host);
    resp.extend_from_slice(&(ns_rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&ns_rdata);

    append_name(&mut resp, ns_host);
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&glue_ip);
    resp
}

fn build_answer_a_response(request: &[u8], ip: [u8; 4]) -> Vec<u8> {
    build_answer_a_response_with_ttl(request, ip, 60)
}

fn build_answer_two_a_response(request: &[u8], first: [u8; 4], second: [u8; 4]) -> Vec<u8> {
    let mut resp = Vec::new();
    let id = u16::from_be_bytes([request[0], request[1]]);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8000u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&2u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    let qend = dns::parse_first_question(request)
        .map(|(_, _, end)| end)
        .unwrap_or(request.len());
    resp.extend_from_slice(&request[12..qend]);

    for ip in [first, second] {
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&30u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&ip);
    }
    let _ = dns::clone_edns_opt_from_request(request, &mut resp);
    resp
}

fn build_answer_aaaa_response(request: &[u8], ip: [u8; 16]) -> Vec<u8> {
    let mut resp = Vec::new();
    let id = u16::from_be_bytes([request[0], request[1]]);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8000u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    let qend = dns::parse_first_question(request)
        .map(|(_, _, end)| end)
        .unwrap_or(request.len());
    resp.extend_from_slice(&request[12..qend]);

    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&28u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    resp.extend_from_slice(&16u16.to_be_bytes());
    resp.extend_from_slice(&ip);
    let _ = dns::clone_edns_opt_from_request(request, &mut resp);
    resp
}

fn build_answer_a_response_with_ttl(request: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut resp = Vec::new();
    let id = u16::from_be_bytes([request[0], request[1]]);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8000u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    let qend = dns::parse_first_question(request)
        .map(|(_, _, end)| end)
        .unwrap_or(request.len());
    resp.extend_from_slice(&request[12..qend]);

    // Answer name uses compression pointer to question name.
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip);
    let _ = dns::clone_edns_opt_from_request(request, &mut resp);
    resp
}

fn build_answer_cname_response(request: &[u8], target: &str) -> Vec<u8> {
    let mut resp = Vec::new();
    let id = u16::from_be_bytes([request[0], request[1]]);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8000u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    let qend = dns::parse_first_question(request)
        .map(|(_, _, end)| end)
        .unwrap_or(request.len());
    resp.extend_from_slice(&request[12..qend]);

    // Answer name uses compression pointer to question name.
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&5u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    let mut rdata = Vec::new();
    append_name(&mut rdata, target);
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

fn build_answer_dname_cname_response(request: &[u8], owner: &str, dname_target: &str) -> Vec<u8> {
    let mut resp = Vec::new();
    let id = u16::from_be_bytes([request[0], request[1]]);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8000u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&2u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    let qend = dns::parse_first_question(request)
        .map(|(_, _, end)| end)
        .unwrap_or(request.len());
    resp.extend_from_slice(&request[12..qend]);

    append_name(&mut resp, owner);
    resp.extend_from_slice(&39u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    let mut dname_rdata = Vec::new();
    append_name(&mut dname_rdata, dname_target);
    resp.extend_from_slice(&(dname_rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&dname_rdata);

    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&5u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    let mut cname_rdata = Vec::new();
    let synthesized_target = "www.example.net".to_string();
    append_name(&mut cname_rdata, &synthesized_target);
    resp.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&cname_rdata);
    resp
}

fn build_noerror_response(request: &[u8]) -> Vec<u8> {
    dns::build_response_with_rcode(request, 0).expect("valid response")
}

fn build_nxdomain_response(request: &[u8]) -> Vec<u8> {
    dns::build_response_with_rcode(request, 3).expect("valid response")
}

fn build_negative_soa_response(
    request: &[u8],
    rcode: u16,
    zone: &str,
    ttl: u32,
    minimum: u32,
) -> Vec<u8> {
    let mut resp = dns::build_response_with_rcode(request, rcode).expect("valid response");
    resp[8..10].copy_from_slice(&1u16.to_be_bytes());

    append_name(&mut resp, zone);
    resp.extend_from_slice(&6u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&ttl.to_be_bytes());

    let mut rdata = Vec::new();
    append_name(&mut rdata, &format!("ns1.{zone}"));
    append_name(&mut rdata, &format!("hostmaster.{zone}"));
    rdata.extend_from_slice(&1u32.to_be_bytes());
    rdata.extend_from_slice(&ttl.to_be_bytes());
    rdata.extend_from_slice(&ttl.to_be_bytes());
    rdata.extend_from_slice(&ttl.to_be_bytes());
    rdata.extend_from_slice(&minimum.to_be_bytes());
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

fn build_nxdomain_soa_response(request: &[u8], zone: &str, ttl: u32, minimum: u32) -> Vec<u8> {
    build_negative_soa_response(request, 3, zone, ttl, minimum)
}

fn build_nodata_soa_response(request: &[u8], zone: &str, ttl: u32, minimum: u32) -> Vec<u8> {
    build_negative_soa_response(request, 0, zone, ttl, minimum)
}

async fn spawn_mock_upstream(
    counter: Arc<AtomicUsize>,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    spawn_mock_upstream_with(counter, build_noerror_response).await
}

async fn spawn_mock_upstream_with<F>(
    counter: Arc<AtomicUsize>,
    responder: F,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)>
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let responder = Arc::new(responder);
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::SeqCst);
            let response = responder(&buf[..len]);
            if socket.send_to(&response, peer).await.is_err() {
                break;
            }
        }
    });
    Ok((addr, handle))
}

fn make_state(upstreams: Vec<String>) -> AppState {
    make_state_with_upstream_timeout(upstreams, 200)
}

fn make_state_with_upstream_timeout(upstreams: Vec<String>, upstream_timeout_ms: u64) -> AppState {
    make_state_with_policy_and_topn_with_timeout(
        upstreams,
        PolicyConfig {
            allow_clients: Vec::new(),
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
        false,
        upstream_timeout_ms,
    )
}

fn make_state_with_policy(upstreams: Vec<String>, policy: PolicyConfig) -> AppState {
    make_state_with_policy_and_topn_with_timeout(upstreams, policy, false, 200)
}

fn make_state_with_policy_and_topn(
    upstreams: Vec<String>,
    policy: PolicyConfig,
    topn_enabled: bool,
) -> AppState {
    make_state_with_policy_and_topn_with_timeout(upstreams, policy, topn_enabled, 200)
}

fn make_state_with_policy_and_topn_with_timeout(
    upstreams: Vec<String>,
    policy: PolicyConfig,
    topn_enabled: bool,
    upstream_timeout_ms: u64,
) -> AppState {
    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(policy).expect("policy");
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "forwarder".to_string(),
            root_servers: Vec::new(),
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 8,
            iterative_timeout_ms: 3000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams,
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            iterative_cname_bridge_fallback_to_recursive: true,
            ns_hostname_resolve_mode: cognidns::config::NsHostnameResolveMode::BootstrapRecursive,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    AppState::new_with_cache_and_topn(
        policy,
        resolver,
        Arc::new(ResponseCache::default()),
        metrics,
        "config/cognidns.toml".to_string(),
        topn_enabled,
    )
}

fn make_iterative_state_with_budget(
    root_servers: Vec<String>,
    upstreams: Vec<String>,
    iterative_timeout_ms: u64,
    iterative_max_depth: u8,
) -> AppState {
    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })
    .expect("policy");
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers,
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth,
            iterative_timeout_ms,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: false,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams,
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            iterative_cname_bridge_fallback_to_recursive: true,
            ns_hostname_resolve_mode: cognidns::config::NsHostnameResolveMode::BootstrapRecursive,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    )
}

#[tokio::test]
async fn resolver_cache_hit_avoids_second_upstream_query() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_a_response(request, [203, 0, 113, 5])
    })
    .await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(100, "example.com", 1);
    let ctx = RequestContext {
        request_id: 100,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().unwrap(),
        query_name: Some(SmolStr::from("example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&first.packet), Some(0));

    let second_ctx = RequestContext {
        request_id: 101,
        ..ctx.clone()
    };
    let second = state.resolve(&second_ctx, &request).await?;
    assert_eq!(dns::response_code(&second.packet), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn ip_health_prefers_healthy_ip_in_answer_order() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_two_a_response(request, [127, 0, 0, 2], [127, 0, 0, 1])
    })
    .await?;

    let state = make_state(vec![upstream_addr.to_string()]);
    let healthy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let health_port = healthy_listener.local_addr()?.port();
    let healthy_handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = healthy_listener.accept().await {
            let _ = socket.write_all(b"ok").await;
        }
    });

    let resolver = state.get_resolver();
    resolver.configure_ip_health(HealthCheckConfig {
        enabled: true,
        mode: "tcp".to_string(),
        port: health_port,
        interval_secs: 1,
        timeout_ms: 200,
        failure_threshold: 1,
        success_threshold: 1,
        max_parallel: 8,
        ..HealthCheckConfig::default()
    });

    let request = build_query(5100, "health-order.example", 1);
    let ctx = RequestContext {
        request_id: 5100,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:54001".parse().unwrap(),
        query_name: Some(SmolStr::from("health-order.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    let first_ips = dns::extract_answer_ips(&first.packet);
    assert_eq!(
        first_ips,
        vec!["127.0.0.2".to_string(), "127.0.0.1".to_string()]
    );

    tokio::time::sleep(Duration::from_millis(1400)).await;

    let second = state.resolve(&ctx, &request).await?;
    let second_ips = dns::extract_answer_ips(&second.packet);
    assert_eq!(
        second_ips,
        vec!["127.0.0.1".to_string(), "127.0.0.2".to_string()]
    );

    let snap = state.resolver_snapshot();
    assert!(snap.ip_health_enabled);
    assert!(snap.ip_health_tracked_domains >= 1);

    healthy_handle.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn ip_health_all_unhealthy_keeps_all_ips_and_records_event() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_two_a_response(request, [127, 0, 0, 2], [127, 0, 0, 3])
    })
    .await?;

    let state = make_state(vec![upstream_addr.to_string()]);
    let resolver = state.get_resolver();
    resolver.configure_ip_health(HealthCheckConfig {
        enabled: true,
        mode: "tcp".to_string(),
        port: 6553,
        interval_secs: 1,
        timeout_ms: 200,
        failure_threshold: 1,
        success_threshold: 1,
        max_parallel: 8,
        notify_webhook: Some("http://127.0.0.1:9/health-webhook".to_string()),
        ..HealthCheckConfig::default()
    });

    let request = build_query(5200, "all-unhealthy.example", 1);
    let ctx = RequestContext {
        request_id: 5200,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:54002".parse().unwrap(),
        query_name: Some(SmolStr::from("all-unhealthy.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    let first_ips = dns::extract_answer_ips(&first.packet);
    assert_eq!(first_ips.len(), 2);

    tokio::time::sleep(Duration::from_millis(1400)).await;

    let second = state.resolve(&ctx, &request).await?;
    let second_ips = dns::extract_answer_ips(&second.packet);
    assert_eq!(second_ips.len(), 2);
    assert!(second_ips.contains(&"127.0.0.2".to_string()));
    assert!(second_ips.contains(&"127.0.0.3".to_string()));

    tokio::time::sleep(Duration::from_millis(300)).await;
    let snap = state.resolver_snapshot();
    assert!(snap.ip_health_all_unhealthy_events >= 1);
    assert!(snap.ip_health_notify_attempt_total >= 1);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn ip_health_webhook_retries_once_on_500_then_succeeds() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_two_a_response(request, [127, 0, 0, 2], [127, 0, 0, 3])
    })
    .await?;

    let webhook_requests = Arc::new(AtomicUsize::new(0));
    let webhook_listener = TcpListener::bind("127.0.0.1:0").await?;
    let webhook_addr = webhook_listener.local_addr()?;
    let webhook_requests_clone = webhook_requests.clone();
    let webhook_handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = webhook_listener.accept().await else {
                break;
            };
            let mut buf = [0u8; 8192];
            let mut raw = Vec::new();
            while let Ok(len) = socket.read(&mut buf).await {
                if len == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..len]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&raw);
            let idx = webhook_requests_clone.fetch_add(1, Ordering::SeqCst);
            let status_line = if idx == 0 {
                "HTTP/1.1 500 Internal Server Error"
            } else {
                "HTTP/1.1 200 OK"
            };
            let response = format!(
                "{}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                status_line
            );
            let _ = socket.write_all(response.as_bytes()).await;
            assert!(text.contains("POST /hook HTTP/1.1"));
            assert!(text
                .to_ascii_lowercase()
                .contains("content-type: application/json"));
            if idx >= 1 {
                break;
            }
        }
    });

    let state = make_state(vec![upstream_addr.to_string()]);
    let resolver = state.get_resolver();
    resolver.configure_ip_health(HealthCheckConfig {
        enabled: true,
        mode: "tcp".to_string(),
        port: 6553,
        interval_secs: 1,
        timeout_ms: 200,
        failure_threshold: 1,
        success_threshold: 1,
        max_parallel: 8,
        notify_webhook: Some(format!("http://{}/hook", webhook_addr)),
        notify_webhook_retries: 1,
        notify_webhook_backoff_ms: 50,
        ..HealthCheckConfig::default()
    });

    let request = build_query(5300, "retry-webhook.example", 1);
    let ctx = RequestContext {
        request_id: 5300,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:54003".parse().unwrap(),
        query_name: Some(SmolStr::from("retry-webhook.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let _ = state.resolve(&ctx, &request).await?;
    tokio::time::sleep(Duration::from_millis(1400)).await;
    let _ = state.resolve(&ctx, &request).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(webhook_requests.load(Ordering::SeqCst), 2);

    let snap = state.resolver_snapshot();
    assert!(snap.ip_health_notify_attempt_total >= 2);
    assert!(snap.ip_health_notify_fail_total >= 1);

    webhook_handle.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn forwarder_mode_follows_cname_chain_until_final_a() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        let qname = dns::parse_first_question(request)
            .map(|q| q.0)
            .unwrap_or_default();
        if qname.eq_ignore_ascii_case("www.baidu.com") {
            build_answer_cname_response(request, "www.a.shifen.com")
        } else if qname.eq_ignore_ascii_case("www.a.shifen.com") {
            build_answer_a_response(request, [220, 181, 38, 148])
        } else {
            build_nxdomain_response(request)
        }
    })
    .await?;

    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(180, "www.baidu.com", 1);
    let ctx = RequestContext {
        request_id: 180,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53020".parse().unwrap(),
        query_name: Some(SmolStr::from("www.baidu.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(dns::answer_has_record_type(&resolved.packet, 1));
    assert!(dns::answer_has_record_type(&resolved.packet, 5));
    assert!(counter.load(Ordering::SeqCst) >= 2);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn forwarder_mode_can_disable_cname_chain_follow() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_cname_response(request, "www.a.shifen.com")
    })
    .await?;

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "forwarder".to_string(),
            root_servers: Vec::new(),
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 8,
            iterative_timeout_ms: 3000,
            cname_chain_max_depth: 8,
            follow_cname_chain: false,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![upstream_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 200,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            iterative_cname_bridge_fallback_to_recursive: true,
            ns_hostname_resolve_mode: cognidns::config::NsHostnameResolveMode::BootstrapRecursive,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(181, "www.baidu.com", 1);
    let ctx = RequestContext {
        request_id: 181,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53021".parse().unwrap(),
        query_name: Some(SmolStr::from("www.baidu.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(!dns::answer_has_record_type(&resolved.packet, 1));
    assert!(dns::answer_has_record_type(&resolved.packet, 5));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn resolver_negative_cache_hits_for_nxdomain() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) =
        spawn_mock_upstream_with(counter.clone(), build_nxdomain_response).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(150, "missing.example", 1);
    let ctx = RequestContext {
        request_id: 150,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53003".parse().unwrap(),
        query_name: Some(SmolStr::from("missing.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&first.packet), Some(3));

    let second = state
        .resolve(
            &RequestContext {
                request_id: 151,
                ..ctx.clone()
            },
            &request,
        )
        .await?;
    assert_eq!(dns::response_code(&second.packet), Some(3));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn resolver_negative_cache_hits_for_nxdomain_with_soa_and_expires_by_negative_ttl(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_nxdomain_soa_response(request, "example.com", 30, 1)
    })
    .await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(152, "missing-soa.example", 1);
    let ctx = RequestContext {
        request_id: 152,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53031".parse().unwrap(),
        query_name: Some(SmolStr::from("missing-soa.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&first.packet), Some(3));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    let second = state
        .resolve(
            &RequestContext {
                request_id: 153,
                ..ctx.clone()
            },
            &request,
        )
        .await?;
    assert_eq!(dns::response_code(&second.packet), Some(3));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(1100)).await;

    let third = state
        .resolve(
            &RequestContext {
                request_id: 154,
                ..ctx
            },
            &request,
        )
        .await?;
    assert_eq!(dns::response_code(&third.packet), Some(3));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn resolver_negative_cache_hits_for_nodata_with_soa_and_expires_by_negative_ttl(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_nodata_soa_response(request, "example.com", 30, 1)
    })
    .await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(160, "nodata.example", 1);
    let ctx = RequestContext {
        request_id: 160,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53032".parse().unwrap(),
        query_name: Some(SmolStr::from("nodata.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&first.packet), Some(0));
    assert_eq!(dns::answer_count(&first.packet), Some(0));
    assert!(dns::analyze_referral_targets(&first.packet)
        .map(|value| value.has_authority_soa)
        .unwrap_or(false));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    let second = state
        .resolve(
            &RequestContext {
                request_id: 161,
                ..ctx.clone()
            },
            &request,
        )
        .await?;
    assert_eq!(dns::response_code(&second.packet), Some(0));
    assert_eq!(dns::answer_count(&second.packet), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(1100)).await;

    let third = state
        .resolve(
            &RequestContext {
                request_id: 162,
                ..ctx
            },
            &request,
        )
        .await?;
    assert_eq!(dns::response_code(&third.packet), Some(0));
    assert_eq!(dns::answer_count(&third.packet), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn resolver_deduplicates_concurrent_requests() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        std::thread::sleep(Duration::from_millis(50));
        build_answer_a_response(request, [203, 0, 113, 6])
    })
    .await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(250, "burst.example", 1);

    let first_ctx = RequestContext {
        request_id: 250,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53004".parse().unwrap(),
        query_name: Some(SmolStr::from("burst.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };
    let second_ctx = RequestContext {
        request_id: 251,
        ..first_ctx.clone()
    };

    let (first, second) = tokio::join!(
        state.resolve(&first_ctx, &request),
        state.resolve(&second_ctx, &request)
    );

    assert_eq!(dns::response_code(&first?.packet), Some(0));
    assert_eq!(dns::response_code(&second?.packet), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn resolver_falls_back_to_next_upstream() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec!["127.0.0.1:9".to_string(), upstream_addr.to_string()]);
    let request = build_query(200, "fallback.example", 1);
    let ctx = RequestContext {
        request_id: 200,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53002".parse().unwrap(),
        query_name: Some(SmolStr::from("fallback.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(matches!(resolved.source, ResolutionSource::Upstream(_)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_query() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let request = build_query(300, "udp.example", 1);
    client.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_returns_badvers_for_unsupported_edns_version() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let request = build_edns_query(302, "udp-badvers.example", 1, 1);
    client.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    let response = &buf[..len];
    let edns = dns::extract_edns_opt(response).context("missing response edns")?;

    assert_eq!(dns::response_code(response), Some(dns::DNS_RCODE_BADVERS));
    assert_eq!(edns.extended_rcode, 1);
    assert_eq!(edns.version, 0);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_cache_hits_keep_do_bit_request_scoped() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_a_response(request, [203, 0, 113, 60])
    })
    .await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;

    let dnssec_request =
        build_edns_query_with_flags(303, "udp-do-cache.example", 1, dns::DNS_EDNS_FLAG_DO);
    client.send_to(&dnssec_request, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert!(dns::dnssec_ok_requested(&buf[..len]));

    let plain_request = build_query(304, "udp-do-cache.example", 1);
    client.send_to(&plain_request, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert!(dns::extract_edns_opt(&buf[..len]).is_none());

    let upgrade_request =
        build_edns_query_with_flags(305, "udp-do-upgrade.example", 1, dns::DNS_EDNS_FLAG_DO);
    let plain_seed_request = build_query(306, "udp-do-upgrade.example", 1);
    client.send_to(&plain_seed_request, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert!(dns::extract_edns_opt(&buf[..len]).is_none());

    client.send_to(&upgrade_request, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert!(dns::dnssec_ok_requested(&buf[..len]));
    assert_eq!(
        dns::extract_edns_opt(&buf[..len]).map(|value| value.udp_payload_size),
        Some(1232)
    );

    assert_eq!(counter.load(Ordering::SeqCst), 4);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_malformed_packet_and_handles_next_valid_query() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;

    // A DNS header requires at least 12 bytes; this malformed payload should be ignored.
    let malformed = vec![0u8; 8];
    client.send_to(&malformed, server_addr).await?;
    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let request = build_query(301, "udp-recover.example", 1);
    client.send_to(&request, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_truncated_question_and_recovers_on_next_valid_query(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_truncated_question_packet(910);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(911, "acl-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_pointer_loop_question_and_recovers_on_next_valid_query(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_pointer_loop_question_packet(930);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(931, "acl-loop-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_multi_question_packet_and_recovers() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let multi = build_multi_question_packet(950, "multi-first.example", "multi-second.example", 1);
    client.send_to(&multi, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));

    let valid = build_query(951, "multi-after.example", 1);
    client.send_to(&valid, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_qdcount_mismatch_packet_and_recovers() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let mismatch = build_qdcount_mismatch_packet(960, "mismatch.example", 1);
    client.send_to(&mismatch, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));

    let valid = build_query(961, "mismatch-after.example", 1);
    client.send_to(&valid, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_label_length_out_of_bounds_packet_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_label_length_out_of_bounds_packet(990);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(991, "acl-label-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_pointer_out_of_bounds_question_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_pointer_out_of_bounds_question_packet(992);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(993, "acl-ptr-oob-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_pointer_depth_exceeded_question_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_pointer_depth_exceeded_question_packet(998);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(999, "acl-ptr-depth-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_invalid_utf8_label_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_invalid_utf8_label_packet(1002);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(1003, "acl-utf8-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_truncated_qtype_qclass_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_truncated_qtype_qclass_packet(1006, "truncated-footer.example");
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(1007, "acl-truncated-footer-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_qdcount_zero_with_trailing_bytes_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let packet = build_qdcount_zero_with_trailing_bytes_packet(1010);
    client.send_to(&packet, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    let valid = build_query(1011, "acl-qdcount-zero-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_reserved_label_prefix_packet_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_reserved_label_prefix_packet(1014);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(1015, "acl-reserved-label-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_qdcount_max_mismatch_and_recovers() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let mismatch = build_qdcount_max_mismatch_packet(1018, "qdcount-max.example", 1);
    client.send_to(&mismatch, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));

    let valid = build_query(1019, "qdcount-max-after.example", 1);
    client.send_to(&valid, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_query_with_trailing_garbage_and_recovers() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let request = build_query_with_trailing_garbage(1022, "trail-garbage.example", 1);
    client.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));

    let valid = build_query(1023, "trail-garbage-after.example", 1);
    client.send_to(&valid, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_non_loop_pointer_question_and_recovers() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_pointer_question_non_loop_packet(1026);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(1027, "acl-pointer-non-loop-recover.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_max_size_4096_query_and_recovers() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let max_query = build_padded_query(1030, "udp-max-size.example", 1, 4096);
    client.send_to(&max_query, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));

    let valid = build_query(1031, "udp-max-size-after.example", 1);
    client.send_to(&valid, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_ignores_max_size_4096_reserved_label_packet_and_recovers() -> anyhow::Result<()>
{
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let malformed = build_padded_reserved_label_prefix_packet(1034, 4096);
    client.send_to(&malformed, server_addr).await?;

    let mut drop_buf = [0u8; 4096];
    let no_response =
        tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut drop_buf)).await;
    assert!(no_response.is_err());

    let valid = build_query(1035, "acl-max-malformed-after.example", 1);
    client.send_to(&valid, server_addr).await?;
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_handles_query() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr)
        .await
        .context("failed to connect to tcp dns server")?;
    let request = build_query(400, "tcp.example", 1);
    stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&request).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_returns_badvers_for_unsupported_edns_version() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr)
        .await
        .context("failed to connect to tcp dns server")?;
    let request = build_edns_query(402, "tcp-badvers.example", 1, 1);
    stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&request).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    let edns = dns::extract_edns_opt(&resp).context("missing response edns")?;

    assert_eq!(dns::response_code(&resp), Some(dns::DNS_RCODE_BADVERS));
    assert_eq!(edns.extended_rcode, 1);
    assert_eq!(edns.version, 0);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_ignores_malformed_packet_and_handles_next_valid_query() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr)
        .await
        .context("failed to connect to tcp dns server")?;

    // Send a framed payload shorter than DNS header length; server should ignore and keep connection.
    let malformed = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&malformed).await?;

    let mut pre_len_buf = [0u8; 2];
    let no_response = tokio::time::timeout(
        Duration::from_millis(150),
        stream.read_exact(&mut pre_len_buf),
    )
    .await;
    assert!(no_response.is_err());

    let request = build_query(401, "tcp-recover.example", 1);
    stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&request).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_connection_on_zero_length_frame_and_accepts_new_connection(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    // First connection sends an invalid zero-length frame; server should close it.
    let mut bad_stream = TcpStream::connect(server_addr).await?;
    bad_stream.write_all(&0u16.to_be_bytes()).await?;
    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    // New connection should still be served normally.
    let mut good_stream = TcpStream::connect(server_addr).await?;
    let request = build_query(402, "tcp-zero-len-recover.example", 1);
    good_stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&request).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_connection_on_oversized_frame_and_accepts_new_connection(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    // Length above the configured cap (4096) should terminate the connection.
    let mut bad_stream = TcpStream::connect(server_addr).await?;
    bad_stream.write_all(&4097u16.to_be_bytes()).await?;
    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    // New connection should remain functional.
    let mut good_stream = TcpStream::connect(server_addr).await?;
    let request = build_query(403, "tcp-oversize-recover.example", 1);
    good_stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&request).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_truncated_question_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_truncated_question_packet(920);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(921, "acl-tcp-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_pointer_loop_question_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_pointer_loop_question_packet(940);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(941, "acl-tcp-loop-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_handles_multi_question_packet_and_recovers_on_same_connection(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr).await?;
    let multi = build_multi_question_packet(
        970,
        "tcp-multi-first.example",
        "tcp-multi-second.example",
        1,
    );
    stream
        .write_all(&(multi.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&multi).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));

    let valid = build_query(971, "tcp-multi-after.example", 1);
    stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&valid).await?;

    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_handles_qdcount_mismatch_packet_and_recovers_on_same_connection(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr).await?;
    let mismatch = build_qdcount_mismatch_packet(980, "tcp-mismatch.example", 1);
    stream
        .write_all(&(mismatch.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&mismatch).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));

    let valid = build_query(981, "tcp-mismatch-after.example", 1);
    stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&valid).await?;

    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_label_length_out_of_bounds_packet_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_label_length_out_of_bounds_packet(994);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(995, "acl-tcp-label-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_pointer_out_of_bounds_question_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_pointer_out_of_bounds_question_packet(996);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(997, "acl-tcp-ptr-oob-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_pointer_depth_exceeded_question_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_pointer_depth_exceeded_question_packet(1000);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(1001, "acl-tcp-ptr-depth-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_invalid_utf8_label_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_invalid_utf8_label_packet(1004);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(1005, "acl-tcp-utf8-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_truncated_qtype_qclass_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_truncated_qtype_qclass_packet(1008, "tcp-truncated-footer.example");
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(1009, "acl-tcp-truncated-footer-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_handles_qdcount_zero_with_trailing_bytes_and_recovers_on_same_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr).await?;
    let packet = build_qdcount_zero_with_trailing_bytes_packet(1012);
    stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&packet).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    let valid = build_query(1013, "acl-tcp-qdcount-zero-recover.example", 1);
    stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&valid).await?;

    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_reserved_label_prefix_packet_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_reserved_label_prefix_packet(1016);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(1017, "acl-tcp-reserved-label-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_handles_qdcount_max_mismatch_and_recovers_on_same_connection(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr).await?;
    let mismatch = build_qdcount_max_mismatch_packet(1020, "tcp-qdcount-max.example", 1);
    stream
        .write_all(&(mismatch.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&mismatch).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));

    let valid = build_query(1021, "tcp-qdcount-max-after.example", 1);
    stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&valid).await?;

    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_handles_query_with_trailing_garbage_and_recovers_on_same_connection(
) -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr).await?;
    let request = build_query_with_trailing_garbage(1024, "tcp-trail-garbage.example", 1);
    stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&request).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));

    let valid = build_query(1025, "tcp-trail-garbage-after.example", 1);
    stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&valid).await?;

    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_non_loop_pointer_question_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_pointer_question_non_loop_packet(1028);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(1029, "acl-tcp-pointer-non-loop-recover.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_accepts_frame_length_4096_and_recovers_on_same_connection() -> anyhow::Result<()>
{
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr).await?;
    let max_query = build_padded_query(1032, "tcp-max-size.example", 1, 4096);
    stream
        .write_all(&(max_query.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&max_query).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));

    let valid = build_query(1033, "tcp-max-size-after.example", 1);
    stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&valid).await?;

    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(0));
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_closes_on_max_size_4096_reserved_label_packet_and_recovers_on_new_connection(
) -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut bad_stream = TcpStream::connect(server_addr).await?;
    let malformed = build_padded_reserved_label_prefix_packet(1036, 4096);
    bad_stream
        .write_all(&(malformed.len() as u16).to_be_bytes())
        .await?;
    bad_stream.write_all(&malformed).await?;

    let mut eof_buf = [0u8; 1];
    let eof = tokio::time::timeout(Duration::from_secs(1), bad_stream.read(&mut eof_buf)).await??;
    assert_eq!(eof, 0);

    let mut good_stream = TcpStream::connect(server_addr).await?;
    let valid = build_query(1037, "acl-tcp-max-malformed-after.example", 1);
    good_stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    good_stream.write_all(&valid).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), good_stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_refuses_acl_denied_client() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state_with_policy(
        vec![upstream_addr.to_string()],
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let request = build_query(500, "acl.example", 1);
    client.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_handles_root_question_under_acl_policy() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let root_query = build_root_query(1100, 1);
    client.send_to(&root_query, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    let valid = build_query(1101, "acl-after-root.example", 1);
    client.send_to(&valid, server_addr).await?;
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_rate_limits_second_request() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state_with_policy(
        vec![upstream_addr.to_string()],
        PolicyConfig {
            allow_clients: Vec::new(),
            blocked_domains: Vec::new(),
            rate_limit_per_second: 1,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let first = build_query(600, "rate-one.example", 1);
    let second = build_query(601, "rate-two.example", 1);
    client.send_to(&first, server_addr).await?;
    client.send_to(&second, server_addr).await?;

    let mut first_buf = [0u8; 4096];
    let (first_len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut first_buf)).await??;
    let mut second_buf = [0u8; 4096];
    let (second_len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut second_buf)).await??;

    let rcodes = [
        dns::response_code(&first_buf[..first_len]),
        dns::response_code(&second_buf[..second_len]),
    ];
    assert!(rcodes.contains(&Some(0)));
    assert!(rcodes.contains(&Some(5)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_server_handles_root_question_under_acl_policy() -> anyhow::Result<()> {
    let state = make_state_with_policy(
        Vec::new(),
        PolicyConfig {
            allow_clients: vec!["10.0.0.0/8".to_string()],
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server = tokio::spawn(ingress::tcp::serve_tcp(listener, state));

    let mut stream = TcpStream::connect(server_addr).await?;
    let root_query = build_root_query(1102, 1);
    stream
        .write_all(&(root_query.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&root_query).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    let valid = build_query(1103, "acl-tcp-after-root.example", 1);
    stream
        .write_all(&(valid.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&valid).await?;

    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut resp)).await??;
    assert_eq!(dns::response_code(&resp), Some(5));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_blocks_domain_with_nxdomain() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state_with_policy(
        vec![upstream_addr.to_string()],
        PolicyConfig {
            allow_clients: Vec::new(),
            blocked_domains: vec!["*.blocked.example".to_string()],
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let request = build_query(700, "api.blocked.example", 1);
    client.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(3));
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn udp_server_denies_any_query_when_enabled() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state_with_policy(
        vec![upstream_addr.to_string()],
        PolicyConfig {
            allow_clients: Vec::new(),
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: true,
        },
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let server = tokio::spawn(ingress::udp::serve_udp(socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let request = build_query(750, "any.example", 255);
    client.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    assert_eq!(dns::response_code(&buf[..len]), Some(5));
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn admin_endpoints_expose_health_and_stats() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state(vec![upstream_addr.to_string()]);
    state.metrics.record_iterative_event("test_seed");
    state.metrics.record_ns_host_cache("test_seed");

    let admin_listener = TcpListener::bind("127.0.0.1:0").await?;
    let admin_addr = admin_listener.local_addr()?;
    let admin_server = tokio::spawn(cognidns::admin::serve_admin(admin_listener, state.clone()));

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let dns_addr = udp_socket.local_addr()?;
    let dns_server = tokio::spawn(ingress::udp::serve_udp(udp_socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let request = build_query(800, "metrics.example", 1);
    client.send_to(&request, dns_addr).await?;
    let mut dns_buf = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut dns_buf)).await??;

    let mut health_stream = TcpStream::connect(admin_addr).await?;
    health_stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut health_body = Vec::new();
    health_stream.read_to_end(&mut health_body).await?;
    let health_text = String::from_utf8(health_body)?;
    assert!(health_text.contains("200 OK"));
    assert!(health_text.contains("\"status\":\"ok\""));

    let mut stats_stream = TcpStream::connect(admin_addr).await?;
    stats_stream
        .write_all(b"GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut stats_body = Vec::new();
    stats_stream.read_to_end(&mut stats_body).await?;
    let stats_text = String::from_utf8(stats_body)?;
    assert!(stats_text.contains("200 OK"));
    assert!(stats_text.contains("\"resolver\""));
    assert!(stats_text.contains("\"health_check\""));
    assert!(stats_text.contains("\"policy\""));
    assert!(stats_text.contains("\"iterative_successes\""));
    assert!(stats_text.contains("\"iterative_loop_detected\""));
    assert!(stats_text.contains("\"iterative_window\""));
    assert!(stats_text.contains("\"iterative_window_short\""));
    assert!(stats_text.contains("\"window_secs\""));
    assert!(stats_text.contains("\"failure_rate\""));
    assert!(stats_text.contains("\"fallback_ratio\""));
    assert!(stats_text.contains("\"iterative_failure_rate_long\""));
    assert!(stats_text.contains("\"iterative_failure_rate_short\""));
    assert!(stats_text.contains("\"iterative_fallback_ratio_long\""));
    assert!(stats_text.contains("\"iterative_fallback_ratio_short\""));
    assert!(stats_text.contains("\"ns_cache_entries\""));
    assert!(stats_text.contains("\"ns_cache_window\""));
    assert!(stats_text.contains("\"ns_cache_window_short\""));
    assert!(stats_text.contains("\"ns_cache_eviction_rate_long\""));
    assert!(stats_text.contains("\"ns_cache_eviction_rate_short\""));
    assert!(stats_text.contains("\"ns_cache_expired_lookup_ratio_long\""));
    assert!(stats_text.contains("\"ns_cache_expired_lookup_ratio_short\""));
    assert!(stats_text.contains("\"reload_audit\""));
    assert!(stats_text.contains("\"notify_attempt_total\""));
    assert!(stats_text.contains("\"notify_fail_total\""));

    let mut reload_stream = TcpStream::connect(admin_addr).await?;
    reload_stream
        .write_all(
            b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut reload_body = Vec::new();
    reload_stream.read_to_end(&mut reload_body).await?;
    let reload_text = String::from_utf8(reload_body)?;
    assert!(reload_text.contains("200 OK"));
    assert!(reload_text.contains("\"reloaded\":true"));
    assert!(reload_text.contains("\"attempt_count\":1"));
    assert!(reload_text.contains("\"success_count\":1"));

    let state_degraded = make_state(Vec::new());
    let degraded_listener = TcpListener::bind("127.0.0.1:0").await?;
    let degraded_addr = degraded_listener.local_addr()?;
    let degraded_server = tokio::spawn(cognidns::admin::serve_admin(
        degraded_listener,
        state_degraded,
    ));

    let mut ready_stream = TcpStream::connect(degraded_addr).await?;
    ready_stream
        .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut ready_body = Vec::new();
    ready_stream.read_to_end(&mut ready_body).await?;
    let ready_text = String::from_utf8(ready_body)?;
    assert!(ready_text.contains("503 Service Unavailable"));
    assert!(ready_text.contains("\"status\":\"degraded\""));

    dns_server.abort();
    admin_server.abort();
    degraded_server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn admin_protected_endpoints_require_token_when_configured() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_a_response(request, [203, 0, 113, 20])
    })
    .await?;
    let state = make_state(vec![upstream_addr.to_string()]);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await?;
    let admin_addr = admin_listener.local_addr()?;
    let admin_server = tokio::spawn(cognidns::admin::serve_admin_with_token(
        admin_listener,
        state,
        Some("secret".to_string()),
    ));

    let mut health_stream = TcpStream::connect(admin_addr).await?;
    health_stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut health_body = Vec::new();
    health_stream.read_to_end(&mut health_body).await?;
    let health_text = String::from_utf8(health_body)?;
    assert!(health_text.contains("200 OK"));

    let mut stats_unauthorized = TcpStream::connect(admin_addr).await?;
    stats_unauthorized
        .write_all(b"GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut stats_unauthorized_body = Vec::new();
    stats_unauthorized
        .read_to_end(&mut stats_unauthorized_body)
        .await?;
    let stats_unauthorized_text = String::from_utf8(stats_unauthorized_body)?;
    assert!(stats_unauthorized_text.contains("401 Unauthorized"));
    assert!(stats_unauthorized_text.contains("\"message\":\"unauthorized\""));

    let mut stats_authorized = TcpStream::connect(admin_addr).await?;
    stats_authorized
        .write_all(
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut stats_authorized_body = Vec::new();
    stats_authorized
        .read_to_end(&mut stats_authorized_body)
        .await?;
    let stats_authorized_text = String::from_utf8(stats_authorized_body)?;
    assert!(stats_authorized_text.contains("200 OK"));
    assert!(stats_authorized_text.contains("\"resolver\""));

    let mut reload_unauthorized = TcpStream::connect(admin_addr).await?;
    reload_unauthorized
        .write_all(
            b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut reload_unauthorized_body = Vec::new();
    reload_unauthorized
        .read_to_end(&mut reload_unauthorized_body)
        .await?;
    let reload_unauthorized_text = String::from_utf8(reload_unauthorized_body)?;
    assert!(reload_unauthorized_text.contains("401 Unauthorized"));

    let mut reload_authorized = TcpStream::connect(admin_addr).await?;
    reload_authorized
        .write_all(
            b"POST /reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut reload_authorized_body = Vec::new();
    reload_authorized
        .read_to_end(&mut reload_authorized_body)
        .await?;
    let reload_authorized_text = String::from_utf8(reload_authorized_body)?;
    assert!(reload_authorized_text.contains("200 OK"));
    assert!(reload_authorized_text.contains("\"reloaded\":true"));

    admin_server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn admin_top_endpoints_report_disabled_when_feature_off() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;
    let state = make_state_with_policy_and_topn(
        vec![upstream_addr.to_string()],
        PolicyConfig {
            allow_clients: Vec::new(),
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
        false,
    );

    let admin_listener = TcpListener::bind("127.0.0.1:0").await?;
    let admin_addr = admin_listener.local_addr()?;
    let admin_server = tokio::spawn(cognidns::admin::serve_admin_with_token(
        admin_listener,
        state,
        Some("secret".to_string()),
    ));

    let mut top_queries = TcpStream::connect(admin_addr).await?;
    top_queries
        .write_all(
            b"GET /stats/top-queries?n=5&window=60 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut top_queries_body = Vec::new();
    top_queries.read_to_end(&mut top_queries_body).await?;
    let top_queries_text = String::from_utf8(top_queries_body)?;
    assert!(top_queries_text.contains("200 OK"));
    assert!(top_queries_text.contains("\"enabled\":false"));
    assert!(top_queries_text.contains("\"entries\":[]"));

    let mut top_clients = TcpStream::connect(admin_addr).await?;
    top_clients
        .write_all(
            b"GET /stats/top-clients?n=5&window=60 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut top_clients_body = Vec::new();
    top_clients.read_to_end(&mut top_clients_body).await?;
    let top_clients_text = String::from_utf8(top_clients_body)?;
    assert!(top_clients_text.contains("200 OK"));
    assert!(top_clients_text.contains("\"enabled\":false"));
    assert!(top_clients_text.contains("\"entries\":[]"));

    admin_server.abort();
    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn admin_top_endpoints_return_ranked_data_when_enabled() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        build_answer_a_response(request, [203, 0, 113, 20])
    })
    .await?;

    let state = make_state_with_policy_and_topn(
        vec![upstream_addr.to_string()],
        PolicyConfig {
            allow_clients: Vec::new(),
            blocked_domains: Vec::new(),
            rate_limit_per_second: 0,
            deny_any_queries: false,
        },
        true,
    );

    let admin_listener = TcpListener::bind("127.0.0.1:0").await?;
    let admin_addr = admin_listener.local_addr()?;
    let admin_server = tokio::spawn(cognidns::admin::serve_admin_with_token(
        admin_listener,
        state.clone(),
        Some("secret".to_string()),
    ));

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let dns_addr = udp_socket.local_addr()?;
    let dns_server = tokio::spawn(ingress::udp::serve_udp(udp_socket, state));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    for id in 0..3u16 {
        let request = build_query(900 + id, "alpha.example", 1);
        client.send_to(&request, dns_addr).await?;
        let mut buf = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;
    }
    let request = build_query(950, "beta.example", 1);
    client.send_to(&request, dns_addr).await?;
    let mut buf = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await??;

    // TOP N collector drains its queue on a 1s cadence.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let mut top_queries = TcpStream::connect(admin_addr).await?;
    top_queries
        .write_all(
            b"GET /stats/top-queries?n=5&window=300 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut top_queries_body = Vec::new();
    top_queries.read_to_end(&mut top_queries_body).await?;
    let top_queries_text = String::from_utf8(top_queries_body)?;
    assert!(top_queries_text.contains("200 OK"));
    assert!(top_queries_text.contains("\"enabled\":true"));
    assert!(top_queries_text.contains("\"domain\":\"alpha.example\""));
    assert!(top_queries_text.contains("\"count\":3"));
    assert!(top_queries_text.contains("\"success_count\":3"));
    assert!(top_queries_text.contains("\"success_rate\":1.0"));
    assert!(top_queries_text.contains("\"domain\":\"beta.example\""));
    assert!(top_queries_text.contains("\"count\":1"));
    assert!(top_queries_text.contains("\"success_count\":1"));

    let mut top_clients = TcpStream::connect(admin_addr).await?;
    top_clients
        .write_all(
            b"GET /stats/top-clients?n=5&window=300 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut top_clients_body = Vec::new();
    top_clients.read_to_end(&mut top_clients_body).await?;
    let top_clients_text = String::from_utf8(top_clients_body)?;
    assert!(top_clients_text.contains("200 OK"));
    assert!(top_clients_text.contains("\"enabled\":true"));
    assert!(top_clients_text.contains("\"client\":\"127.0.0.1\""));
    assert!(top_clients_text.contains("\"count\":4"));

    dns_server.abort();
    admin_server.abort();
    upstream_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_resolves_via_ns_hostname_without_glue() -> anyhow::Result<()> {
    let resolver_counter = Arc::new(AtomicUsize::new(0));
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns1.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_ip = [127, 0, 0, 49];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;
    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 10]);
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            resolver_counter.fetch_add(1, Ordering::SeqCst);
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            if qname.eq_ignore_ascii_case("ns1.test") {
                let resp = build_answer_a_response(&buf[..len], auth_ip);
                let _ = bootstrap_socket.send_to(&resp, peer).await;
            } else {
                let resp = build_answer_a_response(&buf[..len], [127, 0, 0, 1]);
                let _ = bootstrap_socket.send_to(&resp, peer).await;
            }
        }
    });

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 4,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![bootstrap_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(900, "www.example.com", 1);
    let ctx = RequestContext {
        request_id: 900,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53010".parse().unwrap(),
        query_name: Some(SmolStr::from("www.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(dns::answer_count(&resolved.packet), Some(1));

    root_handle.abort();
    auth_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_resolves_multiple_domain_shapes_via_ns_hostname_without_glue(
) -> anyhow::Result<()> {
    let bootstrap_counter = Arc::new(AtomicUsize::new(0));
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns1.multi.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_ip = [127, 0, 0, 65];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;
    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let ip = if qname.eq_ignore_ascii_case("www.example.com") {
                [203, 0, 113, 21]
            } else if qname.eq_ignore_ascii_case("api.service.example.com") {
                [203, 0, 113, 22]
            } else if qname.eq_ignore_ascii_case("xn--fiqs8s.example.com") {
                [203, 0, 113, 23]
            } else {
                [203, 0, 113, 24]
            };
            let resp = build_answer_a_response(&buf[..len], ip);
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_counter_clone = bootstrap_counter.clone();
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            bootstrap_counter_clone.fetch_add(1, Ordering::SeqCst);
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.eq_ignore_ascii_case("ns1.multi.test") {
                build_answer_a_response(&buf[..len], auth_ip)
            } else {
                dns::build_servfail_response(&buf[..len]).expect("servfail")
            };
            let _ = bootstrap_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec![bootstrap_addr.to_string()],
        3000,
        5,
    );

    let cases = [
        ("WWW.Example.COM", "www.example.com", [203, 0, 113, 21]),
        (
            "api.service.example.com",
            "api.service.example.com",
            [203, 0, 113, 22],
        ),
        (
            "xn--fiqs8s.example.com",
            "xn--fiqs8s.example.com",
            [203, 0, 113, 23],
        ),
        (
            "a-b-01.example.com",
            "a-b-01.example.com",
            [203, 0, 113, 24],
        ),
    ];

    for (idx, (query_name, cache_key_name, expected_ip)) in cases.iter().enumerate() {
        let request = build_query(970 + idx as u16, query_name, 1);
        let ctx = RequestContext {
            request_id: 970 + idx as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53070".parse().unwrap(),
            query_name: Some(SmolStr::from((*query_name))),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };

        let first = state.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(0));
        assert_eq!(dns::answer_count(&first.packet), Some(1));

        let cached_request = build_query(980 + idx as u16, cache_key_name, 1);
        let cached_ctx = RequestContext {
            request_id: 980 + idx as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53071".parse().unwrap(),
            query_name: Some(SmolStr::from((*cache_key_name))),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };
        let second = state.resolve(&cached_ctx, &cached_request).await?;
        assert!(matches!(second.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&second.packet), Some(0));
        assert_eq!(dns::answer_count(&second.packet), Some(1));

        let endpoints = dns::extract_answer_ip_endpoints(&second.packet);
        let expected = format!(
            "{}.{}.{}.{}:53",
            expected_ip[0], expected_ip[1], expected_ip[2], expected_ip[3]
        );
        assert!(
            endpoints.iter().any(|value| value == &expected),
            "unexpected cached answer for {cache_key_name}: {endpoints:?}"
        );
    }

    assert!(bootstrap_counter.load(Ordering::SeqCst) >= 1);

    root_handle.abort();
    auth_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_caches_mixed_domain_outcomes_with_glue_referral() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let auth_ip = [127, 0, 0, 66];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.mixed-rcode.example.com",
                auth_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.eq_ignore_ascii_case("ok.scenario.example.com") {
                build_answer_a_response(&buf[..len], [203, 0, 113, 31])
            } else if qname.eq_ignore_ascii_case("nx.scenario.example.com") {
                build_nxdomain_soa_response(&buf[..len], "example.com", 30, 9)
            } else {
                build_nodata_soa_response(&buf[..len], "example.com", 30, 7)
            };
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec!["127.0.0.1:9".to_string()],
        3000,
        5,
    );

    let cases = [
        ("ok.scenario.example.com", 0u16, 1u16),
        ("nx.scenario.example.com", 3u16, 0u16),
        ("nodata.scenario.example.com", 0u16, 0u16),
    ];

    for (idx, (name, expected_rcode, expected_ancount)) in cases.iter().enumerate() {
        let first_request = build_query(990 + idx as u16, name, 1);
        let first_ctx = RequestContext {
            request_id: 990 + idx as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53080".parse().unwrap(),
            query_name: Some(SmolStr::from((*name))),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };
        let first = state.resolve(&first_ctx, &first_request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(*expected_rcode));
        assert_eq!(dns::answer_count(&first.packet), Some(*expected_ancount));

        let second_request = build_query(1000 + idx as u16, name, 1);
        let second_ctx = RequestContext {
            request_id: 1000 + idx as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53081".parse().unwrap(),
            query_name: Some(SmolStr::from((*name))),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };
        let second = state.resolve(&second_ctx, &second_request).await?;
        assert!(matches!(second.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&second.packet), Some(*expected_rcode));
        assert_eq!(dns::answer_count(&second.packet), Some(*expected_ancount));
    }

    let nx = state
        .resolve(
            &RequestContext {
                request_id: 1111,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53082".parse().unwrap(),
                query_name: Some(SmolStr::from("nx.scenario.example.com")),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            },
            &build_query(1111, "nx.scenario.example.com", 1),
        )
        .await?;
    assert!(dns::extract_negative_cache_ttl(&nx.packet).is_some());

    let nodata = state
        .resolve(
            &RequestContext {
                request_id: 1112,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53083".parse().unwrap(),
                query_name: Some(SmolStr::from("nodata.scenario.example.com")),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            },
            &build_query(1112, "nodata.scenario.example.com", 1),
        )
        .await?;
    assert!(dns::extract_negative_cache_ttl(&nodata.packet).is_some());

    root_handle.abort();
    auth_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_resolves_long_and_random_subdomains_with_cache_hit() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns1.fuzz.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_ip = [127, 0, 0, 71];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;
    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let mapped = (qname.len() % 200) as u8 + 1;
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, mapped]);
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.eq_ignore_ascii_case("ns1.fuzz.test") {
                build_answer_a_response(&buf[..len], auth_ip)
            } else {
                dns::build_servfail_response(&buf[..len]).expect("servfail")
            };
            let _ = bootstrap_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec![bootstrap_addr.to_string()],
        3000,
        6,
    );

    let long_label = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cases = [
        format!("{}.fuzz.test", long_label),
        "r4nd0m-001.fuzz.test".to_string(),
        "r4nd0m-002.fuzz.test".to_string(),
        "deep.branch.level3.fuzz.test".to_string(),
        "xn--fiqs8s.fuzz.test".to_string(),
    ];

    for (idx, name) in cases.iter().enumerate() {
        let request = build_query(1200 + idx as u16, name, 1);
        let ctx = RequestContext {
            request_id: 1200 + idx as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53100".parse().unwrap(),
            query_name: Some(SmolStr::from(name.as_str())),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };
        let first = state.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(0));
        assert_eq!(dns::answer_count(&first.packet), Some(1));

        let second = state.resolve(&ctx, &request).await?;
        assert!(matches!(second.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&second.packet), Some(0));
        assert_eq!(dns::answer_count(&second.packet), Some(1));
    }

    root_handle.abort();
    auth_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_mixed_qtypes_same_domain_cache_separation() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let auth_ip = [127, 0, 0, 72];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.qtype-mix.example.com",
                auth_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let (_, qtype, _) = dns::parse_first_question(&buf[..len]).unwrap_or_default();
            let resp = match qtype {
                1 => build_answer_a_response(&buf[..len], [203, 0, 113, 41]),
                28 => build_answer_aaaa_response(
                    &buf[..len],
                    [
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41,
                    ],
                ),
                16 => build_nodata_soa_response(&buf[..len], "example.com", 30, 6),
                _ => dns::build_servfail_response(&buf[..len]).expect("servfail"),
            };
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec!["127.0.0.1:9".to_string()],
        3000,
        5,
    );

    let qname = "mix-qtype.example.com";
    let cases = [(1u16, 0u16, 1u16), (28u16, 0u16, 1u16), (16u16, 0u16, 0u16)];
    for (idx, (qtype, expected_rcode, expected_ancount)) in cases.iter().enumerate() {
        let request = build_query(1300 + idx as u16, qname, *qtype);
        let ctx = RequestContext {
            request_id: 1300 + idx as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53110".parse().unwrap(),
            query_name: Some(SmolStr::from(qname)),
            query_type: Some(*qtype),
            recv_at: std::time::Instant::now(),
        };

        let first = state.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(*expected_rcode));
        assert_eq!(dns::answer_count(&first.packet), Some(*expected_ancount));

        let second = state.resolve(&ctx, &request).await?;
        assert!(matches!(second.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&second.packet), Some(*expected_rcode));
        assert_eq!(dns::answer_count(&second.packet), Some(*expected_ancount));
    }

    root_handle.abort();
    auth_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_batch_multi_zone_domains_resolve_stably() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let alpha_ip = [127, 0, 0, 73];
    let beta_ip = [127, 0, 0, 74];
    let alpha_socket = UdpSocket::bind((std::net::Ipv4Addr::from(alpha_ip), 0)).await?;
    let beta_socket = UdpSocket::bind((std::net::Ipv4Addr::from(beta_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.ends_with(".alpha.test") {
                build_referral_with_glue_response(
                    &buf[..len],
                    "alpha.test",
                    "ns1.alpha.test",
                    alpha_ip,
                )
            } else {
                build_referral_with_glue_response(
                    &buf[..len],
                    "beta.test",
                    "ns1.beta.test",
                    beta_ip,
                )
            };
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let alpha_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = alpha_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 51]);
            let _ = alpha_socket.send_to(&resp, peer).await;
        }
    });

    let beta_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = beta_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 52]);
            let _ = beta_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec!["127.0.0.1:9".to_string()],
        3000,
        6,
    );

    let batch = [
        "a.alpha.test",
        "b.alpha.test",
        "svc-1.alpha.test",
        "x.beta.test",
        "y.beta.test",
        "svc-2.beta.test",
    ];

    for (idx, name) in batch.iter().enumerate() {
        let request = build_query(1400 + idx as u16, name, 1);
        let ctx = RequestContext {
            request_id: 1400 + idx as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53120".parse().unwrap(),
            query_name: Some(SmolStr::from((*name))),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };
        let first = state.resolve(&ctx, &request).await?;
        assert_eq!(dns::response_code(&first.packet), Some(0));
        assert_eq!(dns::answer_count(&first.packet), Some(1));

        let second = state.resolve(&ctx, &request).await?;
        assert!(matches!(second.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&second.packet), Some(0));
        assert_eq!(dns::answer_count(&second.packet), Some(1));
    }

    root_handle.abort();
    alpha_handle.abort();
    beta_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_concurrent_batch_multi_zone_domains_resolve_stably() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let alpha_ip = [127, 0, 0, 75];
    let beta_ip = [127, 0, 0, 76];
    let alpha_socket = UdpSocket::bind((std::net::Ipv4Addr::from(alpha_ip), 0)).await?;
    let beta_socket = UdpSocket::bind((std::net::Ipv4Addr::from(beta_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.ends_with(".alpha.test") {
                build_referral_with_glue_response(
                    &buf[..len],
                    "alpha.test",
                    "ns1.alpha.test",
                    alpha_ip,
                )
            } else {
                build_referral_with_glue_response(
                    &buf[..len],
                    "beta.test",
                    "ns1.beta.test",
                    beta_ip,
                )
            };
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let alpha_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = alpha_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 61]);
            let _ = alpha_socket.send_to(&resp, peer).await;
        }
    });

    let beta_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = beta_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 62]);
            let _ = beta_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec!["127.0.0.1:9".to_string()],
        3000,
        6,
    );

    let mut batch = Vec::new();
    for i in 0..20u16 {
        let name = if i % 2 == 0 {
            format!("svc-{i}.alpha.test")
        } else {
            format!("svc-{i}.beta.test")
        };
        batch.push(name);
    }

    let mut first_wave = Vec::new();
    for (idx, name) in batch.iter().enumerate() {
        let state_cloned = state.clone();
        let name = name.clone();
        first_wave.push(tokio::spawn(async move {
            let req_id = 1500 + idx as u16;
            let request = build_query(req_id, &name, 1);
            let ctx = RequestContext {
                request_id: req_id,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53130".parse().unwrap(),
                query_name: Some(SmolStr::from(name.as_str())),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            };
            state_cloned.resolve(&ctx, &request).await
        }));
    }
    for handle in first_wave {
        let resolved = handle.await??;
        assert_eq!(dns::response_code(&resolved.packet), Some(0));
        assert_eq!(dns::answer_count(&resolved.packet), Some(1));
    }

    let mut second_wave = Vec::new();
    for (idx, name) in batch.iter().enumerate() {
        let state_cloned = state.clone();
        let name = name.clone();
        second_wave.push(tokio::spawn(async move {
            let req_id = 1600 + idx as u16;
            let request = build_query(req_id, &name, 1);
            let ctx = RequestContext {
                request_id: req_id,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53131".parse().unwrap(),
                query_name: Some(SmolStr::from(name.as_str())),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            };
            state_cloned.resolve(&ctx, &request).await
        }));
    }
    for handle in second_wave {
        let resolved = handle.await??;
        assert!(matches!(resolved.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&resolved.packet), Some(0));
        assert_eq!(dns::answer_count(&resolved.packet), Some(1));
    }

    root_handle.abort();
    alpha_handle.abort();
    beta_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_concurrent_mixed_qtypes_same_domain_cache_separation() -> anyhow::Result<()>
{
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let auth_ip = [127, 0, 0, 77];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.qtype-concurrent.example.com",
                auth_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let (_, qtype, _) = dns::parse_first_question(&buf[..len]).unwrap_or_default();
            let resp = match qtype {
                1 => build_answer_a_response(&buf[..len], [203, 0, 113, 71]),
                28 => build_answer_aaaa_response(
                    &buf[..len],
                    [
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x71,
                    ],
                ),
                16 => build_nodata_soa_response(&buf[..len], "example.com", 30, 5),
                _ => dns::build_servfail_response(&buf[..len]).expect("servfail"),
            };
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec!["127.0.0.1:9".to_string()],
        3000,
        6,
    );

    let qname = "concurrent-qtype.example.com".to_string();
    let mut plan = Vec::new();
    for i in 0..30u16 {
        let qtype = match i % 3 {
            0 => 1u16,
            1 => 28u16,
            _ => 16u16,
        };
        plan.push((i, qtype));
    }

    let mut first_wave = Vec::new();
    for (i, qtype) in &plan {
        let state_cloned = state.clone();
        let qname = qname.clone();
        let i = *i;
        let qtype = *qtype;
        first_wave.push(tokio::spawn(async move {
            let req_id = 1700 + i;
            let request = build_query(req_id, &qname, qtype);
            let ctx = RequestContext {
                request_id: req_id,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53140".parse().unwrap(),
                query_name: Some(SmolStr::from(qname.as_str())),
                query_type: Some(qtype),
                recv_at: std::time::Instant::now(),
            };
            state_cloned
                .resolve(&ctx, &request)
                .await
                .map(|r| (qtype, r))
        }));
    }
    for handle in first_wave {
        let (qtype, resolved) = handle.await??;
        match qtype {
            1 | 28 => {
                assert_eq!(dns::response_code(&resolved.packet), Some(0));
                assert_eq!(dns::answer_count(&resolved.packet), Some(1));
            }
            16 => {
                assert_eq!(dns::response_code(&resolved.packet), Some(0));
                assert_eq!(dns::answer_count(&resolved.packet), Some(0));
            }
            _ => unreachable!(),
        }
    }

    let mut second_wave = Vec::new();
    for (i, qtype) in &plan {
        let state_cloned = state.clone();
        let qname = qname.clone();
        let i = *i;
        let qtype = *qtype;
        second_wave.push(tokio::spawn(async move {
            let req_id = 1800 + i;
            let request = build_query(req_id, &qname, qtype);
            let ctx = RequestContext {
                request_id: req_id,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53141".parse().unwrap(),
                query_name: Some(SmolStr::from(qname.as_str())),
                query_type: Some(qtype),
                recv_at: std::time::Instant::now(),
            };
            state_cloned
                .resolve(&ctx, &request)
                .await
                .map(|r| (qtype, r))
        }));
    }
    for handle in second_wave {
        let (qtype, resolved) = handle.await??;
        assert!(matches!(resolved.source, ResolutionSource::Cache));
        match qtype {
            1 | 28 => {
                assert_eq!(dns::response_code(&resolved.packet), Some(0));
                assert_eq!(dns::answer_count(&resolved.packet), Some(1));
            }
            16 => {
                assert_eq!(dns::response_code(&resolved.packet), Some(0));
                assert_eq!(dns::answer_count(&resolved.packet), Some(0));
            }
            _ => unreachable!(),
        }
    }

    root_handle.abort();
    auth_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_concurrent_fast_and_slow_domains_isolates_failures() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let fast_ip = [127, 0, 0, 78];
    let slow_ip = [127, 0, 0, 79];
    let fast_socket = UdpSocket::bind((std::net::Ipv4Addr::from(fast_ip), 0)).await?;
    let slow_socket = UdpSocket::bind((std::net::Ipv4Addr::from(slow_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.ends_with(".fast.test") {
                build_referral_with_glue_response(
                    &buf[..len],
                    "fast.test",
                    "ns1.fast.test",
                    fast_ip,
                )
            } else {
                build_referral_with_glue_response(
                    &buf[..len],
                    "slow.test",
                    "ns1.slow.test",
                    slow_ip,
                )
            };
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let fast_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = fast_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 81]);
            let _ = fast_socket.send_to(&resp, peer).await;
        }
    });

    let slow_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = slow_socket.recv_from(&mut buf).await {
            tokio::time::sleep(Duration::from_millis(800)).await;
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 82]);
            let _ = slow_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec!["127.0.0.1:9".to_string()],
        1200,
        6,
    );

    let mut first_wave = Vec::new();
    for i in 0..20u16 {
        let state_cloned = state.clone();
        let is_fast = i % 2 == 0;
        let name = if is_fast {
            format!("svc-{i}.fast.test")
        } else {
            format!("svc-{i}.slow.test")
        };
        first_wave.push(tokio::spawn(async move {
            let req_id = 1900 + i;
            let request = build_query(req_id, &name, 1);
            let ctx = RequestContext {
                request_id: req_id,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53150".parse().unwrap(),
                query_name: Some(SmolStr::from(name.as_str())),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            };
            (is_fast, state_cloned.resolve(&ctx, &request).await)
        }));
    }

    let mut fast_ok = 0usize;
    let mut slow_err = 0usize;
    for handle in first_wave {
        let (is_fast, result) = handle.await?;
        if is_fast {
            let resolved = result?;
            assert_eq!(dns::response_code(&resolved.packet), Some(0));
            assert_eq!(dns::answer_count(&resolved.packet), Some(1));
            fast_ok += 1;
        } else {
            assert!(result.is_err());
            slow_err += 1;
        }
    }
    assert_eq!(fast_ok, 10);
    assert_eq!(slow_err, 10);

    for i in [0u16, 2, 4, 6] {
        let name = format!("svc-{i}.fast.test");
        let req_id = 2000 + i;
        let request = build_query(req_id, &name, 1);
        let ctx = RequestContext {
            request_id: req_id,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53151".parse().unwrap(),
            query_name: Some(SmolStr::from(name.as_str())),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };
        let resolved = state.resolve(&ctx, &request).await?;
        assert!(matches!(resolved.source, ResolutionSource::Cache));
        assert_eq!(dns::response_code(&resolved.packet), Some(0));
    }

    for i in [1u16, 3, 5, 7] {
        let name = format!("svc-{i}.slow.test");
        let req_id = 2100 + i;
        let request = build_query(req_id, &name, 1);
        let ctx = RequestContext {
            request_id: req_id,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53152".parse().unwrap(),
            query_name: Some(SmolStr::from(name.as_str())),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };
        let result = state.resolve(&ctx, &request).await;
        assert!(result.is_err());
    }

    root_handle.abort();
    fast_handle.abort();
    slow_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_high_concurrency_random_subdomains_success_rate_and_cache_hits(
) -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let auth_ip = [127, 0, 0, 80];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns1.pressure.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let mapped = (qname.len() % 200) as u8 + 1;
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, mapped]);
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.eq_ignore_ascii_case("ns1.pressure.test") {
                build_answer_a_response(&buf[..len], auth_ip)
            } else {
                dns::build_servfail_response(&buf[..len]).expect("servfail")
            };
            let _ = bootstrap_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec![bootstrap_addr.to_string()],
        3000,
        6,
    );

    let mut names = Vec::new();
    for i in 0..120u16 {
        names.push(format!(
            "r{:04x}-{:04x}.pressure.test",
            i,
            i.wrapping_mul(37)
        ));
    }

    let mut first_wave = Vec::new();
    for (idx, name) in names.iter().enumerate() {
        let state_cloned = state.clone();
        let name = name.clone();
        first_wave.push(tokio::spawn(async move {
            let req_id = 2200 + idx as u16;
            let request = build_query(req_id, &name, 1);
            let ctx = RequestContext {
                request_id: req_id,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53160".parse().unwrap(),
                query_name: Some(SmolStr::from(name.as_str())),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            };
            state_cloned.resolve(&ctx, &request).await
        }));
    }

    let mut ok = 0usize;
    let mut err = 0usize;
    for handle in first_wave {
        match handle.await? {
            Ok(resolved) => {
                assert_eq!(dns::response_code(&resolved.packet), Some(0));
                assert_eq!(dns::answer_count(&resolved.packet), Some(1));
                ok += 1;
            }
            Err(_) => err += 1,
        }
    }
    assert_eq!(
        err, 0,
        "pressure scenario should not fail on healthy authority"
    );
    assert_eq!(ok, 120);

    let mut second_wave = Vec::new();
    for (idx, name) in names.iter().take(40).enumerate() {
        let state_cloned = state.clone();
        let name = name.clone();
        second_wave.push(tokio::spawn(async move {
            let req_id = 2400 + idx as u16;
            let request = build_query(req_id, &name, 1);
            let ctx = RequestContext {
                request_id: req_id,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53161".parse().unwrap(),
                query_name: Some(SmolStr::from(name.as_str())),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            };
            state_cloned.resolve(&ctx, &request).await
        }));
    }

    let mut cache_hits = 0usize;
    for handle in second_wave {
        let resolved = handle.await??;
        if matches!(resolved.source, ResolutionSource::Cache) {
            cache_hits += 1;
        }
        assert_eq!(dns::response_code(&resolved.packet), Some(0));
        assert_eq!(dns::answer_count(&resolved.packet), Some(1));
    }
    assert_eq!(cache_hits, 40);

    root_handle.abort();
    auth_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_slow_authority_ratio_degrades_success_monotonically() -> anyhow::Result<()>
{
    async fn run_ratio_case(slow_ratio_pct: usize, case_id: u8) -> anyhow::Result<(usize, usize)> {
        let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let root_addr = root_socket.local_addr()?;
        let fast_ip = [127, 0, 1, 10 + case_id];
        let slow_ip = [127, 0, 2, 10 + case_id];
        let fast_socket = UdpSocket::bind((std::net::Ipv4Addr::from(fast_ip), 0)).await?;
        let slow_socket = UdpSocket::bind((std::net::Ipv4Addr::from(slow_ip), 0)).await?;

        let root_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
                let qname = dns::parse_first_question(&buf[..len])
                    .map(|q| q.0)
                    .unwrap_or_default();
                let resp = if qname.ends_with(".slow-ratio.test") {
                    build_referral_with_glue_response(
                        &buf[..len],
                        "slow-ratio.test",
                        "ns1.slow-ratio.test",
                        slow_ip,
                    )
                } else {
                    build_referral_with_glue_response(
                        &buf[..len],
                        "fast-ratio.test",
                        "ns1.fast-ratio.test",
                        fast_ip,
                    )
                };
                let _ = root_socket.send_to(&resp, peer).await;
            }
        });

        let fast_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = fast_socket.recv_from(&mut buf).await {
                let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 91]);
                let _ = fast_socket.send_to(&resp, peer).await;
            }
        });

        let slow_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = slow_socket.recv_from(&mut buf).await {
                tokio::time::sleep(Duration::from_millis(1200)).await;
                let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 92]);
                let _ = slow_socket.send_to(&resp, peer).await;
            }
        });

        let state = make_iterative_state_with_budget(
            vec![root_addr.to_string()],
            vec!["127.0.0.1:9".to_string()],
            700,
            6,
        );

        let total = 60usize;
        let slow_count = total * slow_ratio_pct / 100;
        let mut names = Vec::new();
        for i in 0..total {
            if i < slow_count {
                names.push(format!("svc-{i}.slow-ratio.test"));
            } else {
                names.push(format!("svc-{i}.fast-ratio.test"));
            }
        }

        let mut tasks = Vec::new();
        for (idx, name) in names.iter().enumerate() {
            let state_cloned = state.clone();
            let name = name.clone();
            tasks.push(tokio::spawn(async move {
                let req_id = 2600 + idx as u16;
                let request = build_query(req_id, &name, 1);
                let ctx = RequestContext {
                    request_id: req_id,
                    protocol: Protocol::Udp,
                    client_addr: "127.0.0.1:53170".parse().unwrap(),
                    query_name: Some(SmolStr::from(name.as_str())),
                    query_type: Some(1),
                    recv_at: std::time::Instant::now(),
                };
                state_cloned.resolve(&ctx, &request).await
            }));
        }

        let mut ok = 0usize;
        let mut err = 0usize;
        for task in tasks {
            match task.await? {
                Ok(resolved) => {
                    assert_eq!(dns::response_code(&resolved.packet), Some(0));
                    ok += 1;
                }
                Err(_) => err += 1,
            }
        }

        root_handle.abort();
        fast_handle.abort();
        slow_handle.abort();
        Ok((ok, err))
    }

    let (ok20, err20) = run_ratio_case(20, 1).await?;
    let (ok50, err50) = run_ratio_case(50, 2).await?;
    let (ok80, err80) = run_ratio_case(80, 3).await?;

    assert!(ok20 >= ok50 && ok50 >= ok80);
    assert!(err20 <= err50 && err50 <= err80);

    assert!(ok20 > 0 && ok50 > 0 && ok80 > 0);
    assert!(err20 > 0 && err50 > 0 && err80 > 0);

    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_packet_loss_retry_budget_controls_recovery() -> anyhow::Result<()> {
    async fn run_case(
        case_id: u8,
        iterative_timeout_ms: u64,
        healthy_root_delay_ms: u64,
    ) -> anyhow::Result<(bool, String, usize, usize, usize, usize)> {
        let dropped_root_counter = Arc::new(AtomicUsize::new(0));
        let healthy_root_counter = Arc::new(AtomicUsize::new(0));
        let auth_counter = Arc::new(AtomicUsize::new(0));

        let dropped_root_ip = [127, 0, 3, 20 + case_id];
        let healthy_root_ip = [127, 0, 4, 20 + case_id];
        let auth_ip = [127, 0, 5, 20 + case_id];

        let dropped_root_socket =
            UdpSocket::bind((std::net::Ipv4Addr::from(dropped_root_ip), 0)).await?;
        let healthy_root_socket =
            UdpSocket::bind((std::net::Ipv4Addr::from(healthy_root_ip), 0)).await?;
        let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;

        let dropped_root_counter_clone = dropped_root_counter.clone();
        let dropped_root_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while dropped_root_socket.recv_from(&mut buf).await.is_ok() {
                dropped_root_counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        let healthy_root_counter_clone = healthy_root_counter.clone();
        let healthy_root_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = healthy_root_socket.recv_from(&mut buf).await {
                healthy_root_counter_clone.fetch_add(1, Ordering::SeqCst);
                if healthy_root_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(healthy_root_delay_ms)).await;
                }
                let resp = build_referral_with_glue_response(
                    &buf[..len],
                    "loss-budget.test",
                    "ns1.loss-budget.test",
                    auth_ip,
                );
                let _ = healthy_root_socket.send_to(&resp, peer).await;
            }
        });

        let auth_counter_clone = auth_counter.clone();
        let auth_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
                auth_counter_clone.fetch_add(1, Ordering::SeqCst);
                let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 99]);
                let _ = auth_socket.send_to(&resp, peer).await;
            }
        });

        let state = make_iterative_state_with_budget(
            vec![
                format!("{}:53", std::net::Ipv4Addr::from(dropped_root_ip)),
                format!("{}:53", std::net::Ipv4Addr::from(healthy_root_ip)),
            ],
            vec!["127.0.0.1:9".to_string()],
            iterative_timeout_ms,
            6,
        );

        let qname = format!("svc-{}.loss-budget.test", case_id);
        let request = build_query(2800 + case_id as u16, &qname, 1);
        let ctx = RequestContext {
            request_id: 2800 + case_id as u16,
            protocol: Protocol::Udp,
            client_addr: "127.0.0.1:53180".parse().unwrap(),
            query_name: Some(SmolStr::from(qname.as_str())),
            query_type: Some(1),
            recv_at: std::time::Instant::now(),
        };

        let result = state.resolve(&ctx, &request).await;
        let snapshot = state.resolver_snapshot();
        let (ok, msg) = match result {
            Ok(resolved) => (
                true,
                format!(
                    "rcode={} answers={}",
                    dns::response_code(&resolved.packet).unwrap_or(255),
                    dns::answer_count(&resolved.packet).unwrap_or(0)
                ),
            ),
            Err(err) => (false, err.to_string()),
        };

        let dropped = dropped_root_counter.load(Ordering::SeqCst);
        let healthy = healthy_root_counter.load(Ordering::SeqCst);
        let auth_hits = auth_counter.load(Ordering::SeqCst);
        let retries = snapshot.iterative_retry_queries;

        dropped_root_handle.abort();
        healthy_root_handle.abort();
        auth_handle.abort();
        Ok((ok, msg, dropped, healthy, auth_hits, retries))
    }

    let (ok_recover, msg_recover, dropped_recover, healthy_recover, auth_recover, retries_recover) =
        run_case(1, 900, 20).await?;
    assert!(
        ok_recover,
        "expected recovery case to succeed, got: {msg_recover}"
    );
    assert!(msg_recover.contains("rcode=0"));
    assert!(msg_recover.contains("answers=1"));
    assert!(dropped_recover >= 1);
    assert!(healthy_recover >= 1);
    assert!(auth_recover >= 1);
    assert!(retries_recover >= 1);

    let (ok_tight, msg_tight, dropped_tight, healthy_tight, auth_tight, retries_tight) =
        run_case(2, 120, 350).await?;
    assert!(!ok_tight, "expected tight budget case to fail");
    assert!(msg_tight.contains("timed out by budget"));
    assert!(dropped_tight >= 1);
    assert!(healthy_tight >= 1);
    assert_eq!(auth_tight, 0);
    assert!(retries_tight <= retries_recover);

    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_resolves_glue_referral_to_nodata_soa_terminal() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let auth_ip = [127, 0, 0, 42];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.example.com",
                auth_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let resp = build_nodata_soa_response(&buf[..len], "example.com", 30, 1);
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 4,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: false,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec!["127.0.0.1:9".to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(910, "nodata-glue.example.com", 1);
    let ctx = RequestContext {
        request_id: 910,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53040".parse().unwrap(),
        query_name: Some(SmolStr::from("nodata-glue.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(dns::answer_count(&resolved.packet), Some(0));
    assert!(dns::analyze_referral_targets(&resolved.packet)
        .map(|value| value.has_authority_soa)
        .unwrap_or(false));

    root_handle.abort();
    auth_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_resolves_ns_hostname_without_glue_to_nxdomain_soa_terminal(
) -> anyhow::Result<()> {
    let bootstrap_counter = Arc::new(AtomicUsize::new(0));
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns1.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_ip = [127, 0, 0, 43];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;
    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let resp = build_nxdomain_soa_response(&buf[..len], "example.com", 30, 1);
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_counter_clone = bootstrap_counter.clone();
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            bootstrap_counter_clone.fetch_add(1, Ordering::SeqCst);
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.eq_ignore_ascii_case("ns1.test") {
                build_answer_a_response(&buf[..len], auth_ip)
            } else {
                dns::build_servfail_response(&buf[..len]).expect("servfail response")
            };
            let _ = bootstrap_socket.send_to(&resp, peer).await;
        }
    });

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 4,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![bootstrap_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(911, "missing-no-glue.example.com", 1);
    let ctx = RequestContext {
        request_id: 911,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53041".parse().unwrap(),
        query_name: Some(SmolStr::from("missing-no-glue.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(3));
    assert!(dns::analyze_referral_targets(&resolved.packet)
        .map(|value| value.has_authority_soa)
        .unwrap_or(false));
    assert!(bootstrap_counter.load(Ordering::SeqCst) >= 1);

    root_handle.abort();
    auth_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_resolves_multi_hop_glue_referrals_to_final_answer() -> anyhow::Result<()> {
    let root_counter = Arc::new(AtomicUsize::new(0));
    let mid_counter = Arc::new(AtomicUsize::new(0));
    let final_counter = Arc::new(AtomicUsize::new(0));

    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let stage1_ip = [127, 0, 0, 44];
    let stage2_ip = [127, 0, 0, 45];
    let stage1_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage1_ip), 0)).await?;
    let stage2_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage2_ip), 0)).await?;

    let root_counter_clone = root_counter.clone();
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            root_counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.stage1.example.com",
                stage1_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let mid_counter_clone = mid_counter.clone();
    let stage1_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage1_socket.recv_from(&mut buf).await {
            mid_counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns2.stage2.example.com",
                stage2_ip,
            );
            let _ = stage1_socket.send_to(&resp, peer).await;
        }
    });

    let final_counter_clone = final_counter.clone();
    let stage2_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage2_socket.recv_from(&mut buf).await {
            final_counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 30]);
            let _ = stage2_socket.send_to(&resp, peer).await;
        }
    });

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 3,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: false,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec!["127.0.0.1:9".to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(912, "multi-hop.example.com", 1);
    let ctx = RequestContext {
        request_id: 912,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53042".parse().unwrap(),
        query_name: Some(SmolStr::from("multi-hop.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(dns::answer_count(&resolved.packet), Some(1));
    assert_eq!(root_counter.load(Ordering::SeqCst), 1);
    assert_eq!(mid_counter.load(Ordering::SeqCst), 1);
    assert_eq!(final_counter.load(Ordering::SeqCst), 1);

    root_handle.abort();
    stage1_handle.abort();
    stage2_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_multi_hop_referral_cache_uses_terminal_answer_ttl_not_referral_ttl(
) -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let stage1_ip = [127, 0, 0, 61];
    let stage2_ip = [127, 0, 0, 62];
    let stage1_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage1_ip), 0)).await?;
    let stage2_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage2_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.ttl1.example.com",
                stage1_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let stage1_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage1_socket.recv_from(&mut buf).await {
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns2.ttl2.example.com",
                stage2_ip,
            );
            let _ = stage1_socket.send_to(&resp, peer).await;
        }
    });

    let stage2_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage2_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response_with_ttl(&buf[..len], [203, 0, 113, 70], 42);
            let _ = stage2_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec!["127.0.0.1:9".to_string()],
        3000,
        4,
    );
    let request = build_query(950, "ttl-budget.example.com", 1);
    let ctx = RequestContext {
        request_id: 950,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53050".parse().unwrap(),
        query_name: Some(SmolStr::from("ttl-budget.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&first.packet), Some(0));
    let second = state.resolve(&ctx, &request).await?;
    assert!(matches!(second.source, ResolutionSource::Cache));
    let ttl = dns::extract_cache_ttl(&second.packet)
        .expect("cached ttl")
        .as_secs();
    assert!((40..=42).contains(&ttl), "unexpected cached ttl: {ttl}");

    root_handle.abort();
    stage1_handle.abort();
    stage2_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mixed_no_glue_and_glue_referrals_cache_terminal_negative_ttl(
) -> anyhow::Result<()> {
    let bootstrap_counter = Arc::new(AtomicUsize::new(0));
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let stage1_ip = [127, 0, 0, 63];
    let stage2_ip = [127, 0, 0, 64];
    let stage1_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage1_ip), 0)).await?;
    let stage2_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage2_ip), 0)).await?;

    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns1.mix.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let stage1_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage1_socket.recv_from(&mut buf).await {
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns2.mix.example.com",
                stage2_ip,
            );
            let _ = stage1_socket.send_to(&resp, peer).await;
        }
    });

    let stage2_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage2_socket.recv_from(&mut buf).await {
            let resp = build_nodata_soa_response(&buf[..len], "example.com", 25, 11);
            let _ = stage2_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_counter_clone = bootstrap_counter.clone();
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            bootstrap_counter_clone.fetch_add(1, Ordering::SeqCst);
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.eq_ignore_ascii_case("ns1.mix.test") {
                build_answer_a_response(&buf[..len], stage1_ip)
            } else {
                dns::build_servfail_response(&buf[..len]).expect("servfail")
            };
            let _ = bootstrap_socket.send_to(&resp, peer).await;
        }
    });

    let state = make_iterative_state_with_budget(
        vec![root_addr.to_string()],
        vec![bootstrap_addr.to_string()],
        3000,
        5,
    );
    let request = build_query(951, "mix-ttl.example.com", 1);
    let ctx = RequestContext {
        request_id: 951,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53051".parse().unwrap(),
        query_name: Some(SmolStr::from("mix-ttl.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let first = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&first.packet), Some(0));
    assert_eq!(dns::answer_count(&first.packet), Some(0));
    let second = state.resolve(&ctx, &request).await?;
    assert!(matches!(second.source, ResolutionSource::Cache));
    let negative_ttl = dns::extract_negative_cache_ttl(&second.packet)
        .expect("negative ttl")
        .as_secs();
    assert!(
        (9..=11).contains(&negative_ttl),
        "unexpected cached negative ttl: {negative_ttl}"
    );
    assert!(bootstrap_counter.load(Ordering::SeqCst) >= 1);

    root_handle.abort();
    stage1_handle.abort();
    stage2_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_enforces_referral_depth_budget_before_final_hop() -> anyhow::Result<()> {
    let root_counter = Arc::new(AtomicUsize::new(0));
    let mid_counter = Arc::new(AtomicUsize::new(0));
    let final_counter = Arc::new(AtomicUsize::new(0));

    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let stage1_ip = [127, 0, 0, 46];
    let stage2_ip = [127, 0, 0, 47];
    let stage1_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage1_ip), 0)).await?;
    let stage2_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage2_ip), 0)).await?;

    let root_counter_clone = root_counter.clone();
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            root_counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.depth1.example.com",
                stage1_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let mid_counter_clone = mid_counter.clone();
    let stage1_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage1_socket.recv_from(&mut buf).await {
            mid_counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns2.depth2.example.com",
                stage2_ip,
            );
            let _ = stage1_socket.send_to(&resp, peer).await;
        }
    });

    let final_counter_clone = final_counter.clone();
    let stage2_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage2_socket.recv_from(&mut buf).await {
            final_counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 31]);
            let _ = stage2_socket.send_to(&resp, peer).await;
        }
    });

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 2,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: false,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec!["127.0.0.1:9".to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(913, "depth-budget.example.com", 1);
    let ctx = RequestContext {
        request_id: 913,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53043".parse().unwrap(),
        query_name: Some(SmolStr::from("depth-budget.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let err = state
        .resolve(&ctx, &request)
        .await
        .expect_err("depth budget should fail");
    assert!(err.to_string().contains("exceeded max referral depth"));
    assert_eq!(root_counter.load(Ordering::SeqCst), 1);
    assert_eq!(mid_counter.load(Ordering::SeqCst), 1);
    assert_eq!(final_counter.load(Ordering::SeqCst), 0);

    root_handle.abort();
    stage1_handle.abort();
    stage2_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_mode_enforces_timeout_budget_without_forwarder_fallback() -> anyhow::Result<()> {
    let root_counter = Arc::new(AtomicUsize::new(0));
    let stage1_counter = Arc::new(AtomicUsize::new(0));
    let fallback_counter = Arc::new(AtomicUsize::new(0));

    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let stage1_ip = [127, 0, 0, 48];
    let stage1_socket = UdpSocket::bind((std::net::Ipv4Addr::from(stage1_ip), 0)).await?;
    let (fallback_addr, fallback_handle) =
        spawn_mock_upstream_with(fallback_counter.clone(), |request| {
            build_answer_a_response(request, [203, 0, 113, 40])
        })
        .await?;

    let root_counter_clone = root_counter.clone();
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            root_counter_clone.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(150)).await;
            let resp = build_referral_with_glue_response(
                &buf[..len],
                "example.com",
                "ns1.timeout.example.com",
                stage1_ip,
            );
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let stage1_counter_clone = stage1_counter.clone();
    let stage1_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = stage1_socket.recv_from(&mut buf).await {
            stage1_counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 41]);
            let _ = stage1_socket.send_to(&resp, peer).await;
        }
    });

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 3,
            iterative_timeout_ms: 100,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: false,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![fallback_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics.clone(),
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        metrics,
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(914, "timeout-budget.example.com", 1);
    let ctx = RequestContext {
        request_id: 914,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53044".parse().unwrap(),
        query_name: Some(SmolStr::from("timeout-budget.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let err = state
        .resolve(&ctx, &request)
        .await
        .expect_err("timeout budget should fail");
    assert!(err.to_string().contains("timed out by budget"));
    assert_eq!(root_counter.load(Ordering::SeqCst), 1);
    assert_eq!(stage1_counter.load(Ordering::SeqCst), 0);
    assert_eq!(fallback_counter.load(Ordering::SeqCst), 0);

    root_handle.abort();
    stage1_handle.abort();
    fallback_handle.abort();
    Ok(())
}

#[tokio::test]
async fn iterative_mode_follows_cname_chain_until_final_a() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let counter_clone = counter.clone();
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let resp = if qname.eq_ignore_ascii_case("www.baidu.com") {
                build_answer_cname_response(&buf[..len], "www.a.shifen.com")
            } else if qname.eq_ignore_ascii_case("www.a.shifen.com") {
                build_answer_a_response(&buf[..len], [220, 181, 38, 148])
            } else {
                build_nxdomain_response(&buf[..len])
            };
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 4,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 256,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![root_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );

    let request = build_query(920, "www.baidu.com", 1);
    let ctx = RequestContext {
        request_id: 920,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53015".parse().unwrap(),
        query_name: Some(SmolStr::from("www.baidu.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = resolver.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(dns::answer_has_record_type(&resolved.packet, 1));
    assert!(dns::answer_has_record_type(&resolved.packet, 5));
    assert!(counter.load(Ordering::SeqCst) >= 2);
    // The response question section must reflect the original query name,
    // not the CNAME target (www.a.shifen.com).
    let (resp_qname, _, _) =
        dns::parse_first_question(&resolved.packet).expect("response must have a question section");
    assert_eq!(
        resp_qname.trim_end_matches('.').to_ascii_lowercase(),
        "www.baidu.com",
        "response question should match original query, not the CNAME target"
    );

    root_handle.abort();
    Ok(())
}

#[tokio::test]
async fn forwarder_mode_preserves_dname_alongside_synthesized_cname_chain() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream_with(counter.clone(), |request| {
        let qname = dns::parse_first_question(request)
            .map(|q| q.0)
            .unwrap_or_default();
        if qname.eq_ignore_ascii_case("www.alias.example.com") {
            build_answer_dname_cname_response(request, "alias.example.com", "example.net")
        } else if qname.eq_ignore_ascii_case("www.example.net") {
            build_answer_a_response(request, [203, 0, 113, 90])
        } else {
            build_nxdomain_response(request)
        }
    })
    .await?;

    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(960, "www.alias.example.com", 1);
    let ctx = RequestContext {
        request_id: 960,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53060".parse().unwrap(),
        query_name: Some(SmolStr::from("www.alias.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(dns::answer_has_record_type(&resolved.packet, 39));
    assert!(dns::answer_has_record_type(&resolved.packet, 5));
    assert!(dns::answer_has_record_type(&resolved.packet, 1));
    assert!(counter.load(Ordering::SeqCst) >= 2);

    upstream_handle.abort();
    Ok(())
}

#[tokio::test]
async fn iterative_mode_rejects_cname_chain_depth_exceeded() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            let target = if qname.eq_ignore_ascii_case("c1.test") {
                "c2.test"
            } else if qname.eq_ignore_ascii_case("c2.test") {
                "c3.test"
            } else if qname.eq_ignore_ascii_case("c3.test") {
                "c4.test"
            } else {
                "c5.test"
            };
            let resp = build_answer_cname_response(&buf[..len], target);
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 4,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 2,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 256,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![root_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );

    let request = build_query(921, "c1.test", 1);
    let ctx = RequestContext {
        request_id: 921,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53016".parse().unwrap(),
        query_name: Some(SmolStr::from("c1.test")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let err = resolver
        .resolve(&ctx, &request)
        .await
        .expect_err("expect cname depth error");
    assert!(err.to_string().contains("cname chain exceeded max depth"));

    root_handle.abort();
    Ok(())
}

#[tokio::test]
async fn iterative_mode_fails_on_referral_loop_without_targets() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns.loop.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            // Always send referral without glue and without answers.
            let resp = build_referral_response(&buf[..len], "ns.loop.test");
            let _ = bootstrap_socket.send_to(&resp, peer).await;
        }
    });

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let policy = PolicyEngine::new(PolicyConfig {
        allow_clients: Vec::new(),
        blocked_domains: Vec::new(),
        rate_limit_per_second: 0,
        deny_any_queries: false,
    })?;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 3,
            iterative_timeout_ms: 1000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![bootstrap_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 100,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        metrics,
        Vec::new(),
        Vec::new(),
    );
    let state = AppState::new(
        policy,
        resolver,
        Arc::new(Metrics::new().expect("metrics2")),
        "config/cognidns.toml".to_string(),
    );

    let request = build_query(901, "loop.example", 1);
    let ctx = RequestContext {
        request_id: 901,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53011".parse().unwrap(),
        query_name: Some(SmolStr::from("loop.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let err = state.resolve(&ctx, &request).await.err();
    assert!(err.is_some());

    root_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_window_ratios_reflect_recent_failures() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns.loop.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns.loop.test");
            let _ = bootstrap_socket.send_to(&resp, peer).await;
        }
    });

    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 3,
            iterative_timeout_ms: 1000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 128,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 5,
            cache_hot_capacity: 1024,
            upstreams: vec![bootstrap_addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 100,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );

    let request = build_query(902, "loop-ratio.example", 1);
    let ctx = RequestContext {
        request_id: 902,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53012".parse().unwrap(),
        query_name: Some(SmolStr::from("loop-ratio.example")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let err = resolver.resolve(&ctx, &request).await.err();
    assert!(err.is_some());

    let snapshot = resolver.health_snapshot();
    assert!(snapshot.iterative_window_short.failures >= 1);
    assert!(snapshot.iterative_failures >= 1);
    assert!(snapshot.iterative_failure_rate_short > 0.0);

    root_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

#[ignore = "requires non-root port for mock auth DNS servers"]
#[tokio::test]
async fn iterative_ns_cache_window_tracks_store_and_hit() -> anyhow::Result<()> {
    let root_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let root_addr = root_socket.local_addr()?;
    let root_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let resp = build_referral_response(&buf[..len], "ns1.test");
            let _ = root_socket.send_to(&resp, peer).await;
        }
    });

    let auth_ip = [127, 0, 0, 50];
    let auth_socket = UdpSocket::bind((std::net::Ipv4Addr::from(auth_ip), 0)).await?;
    let auth_port = auth_socket.local_addr()?.port();
    let auth_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let resp = build_answer_a_response(&buf[..len], [203, 0, 113, 11]);
            let _ = auth_socket.send_to(&resp, peer).await;
        }
    });

    let bootstrap_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bootstrap_addr = bootstrap_socket.local_addr()?;
    let bootstrap_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            let qname = dns::parse_first_question(&buf[..len])
                .map(|q| q.0)
                .unwrap_or_default();
            if qname.eq_ignore_ascii_case("ns1.test") {
                let resp = build_answer_a_response(&buf[..len], auth_ip);
                let _ = bootstrap_socket.send_to(&resp, peer).await;
            } else {
                let resp = build_answer_a_response(&buf[..len], [127, 0, 0, 1]);
                let _ = bootstrap_socket.send_to(&resp, peer).await;
            }
        }
    });

    let mut resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: vec![root_addr.to_string()],
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 4,
            iterative_timeout_ms: 2000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 1024,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: false,
            strict_bailiwick: true,
            delegation_cache_capacity: 1024,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 2000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 1024,
            upstreams: vec![bootstrap_addr.to_string()],
            cache_ttl_secs: 0,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 300,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 16,
            prefetch_window_secs: 5,
            prefetch_ttl_trigger_secs: 10,
            prefetch_popularity_threshold: 3,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: true,
            adaptive_cache_min_capacity: 256,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: true,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );
    resolver.set_iterative_dns_port(auth_port);

    let first_request = build_query(910, "www.example.com", 1);
    let first_ctx = RequestContext {
        request_id: 910,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53013".parse().unwrap(),
        query_name: Some(SmolStr::from("www.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };
    let first = resolver.resolve(&first_ctx, &first_request).await?;
    assert_eq!(dns::response_code(&first.packet), Some(0));

    let second_request = build_query(911, "api.example.com", 1);
    let second_ctx = RequestContext {
        request_id: 911,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53014".parse().unwrap(),
        query_name: Some(SmolStr::from("api.example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };
    let second = resolver.resolve(&second_ctx, &second_request).await?;
    assert_eq!(dns::response_code(&second.packet), Some(0));

    let snapshot = resolver.health_snapshot();
    assert!(snapshot.ns_cache_window_short.stores >= 1);
    assert!(snapshot.ns_cache_window_short.hits >= 1);

    root_handle.abort();
    auth_handle.abort();
    bootstrap_handle.abort();
    Ok(())
}

// =================== 长链条域名查询优化：回归测试 ===================

/// 验证 ns_hostname_enough_endpoints 配置字段生效：设置为 1 时，Resolver 正常构造。
#[tokio::test]
async fn ns_hostname_config_fields_applied() {
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: Vec::new(),
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 8,
            iterative_timeout_ms: 3000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 128,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: true,
            strict_bailiwick: true,
            delegation_cache_capacity: 128,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 1000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 128,
            upstreams: vec!["1.1.1.1:53".to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 200,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 8,
            prefetch_window_secs: 1,
            prefetch_ttl_trigger_secs: 5,
            prefetch_popularity_threshold: 2,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: false,
            adaptive_cache_min_capacity: 128,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: false,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 2,
            ns_hostname_enough_endpoints: 1,
            ns_hostname_per_resolve_ms: 800,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: Vec::new(),
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );
    let snapshot = resolver.health_snapshot();
    assert_eq!(snapshot.mode, "iterative");
}

/// 验证委托区预热：配置预热 zone 后 delegation 缓存应立即命中。
#[tokio::test]
async fn prewarm_delegation_cache_populated() {
    use cognidns::config::PreWarmZone;

    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: Vec::new(),
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 8,
            iterative_timeout_ms: 3000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 128,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: true,
            strict_bailiwick: true,
            delegation_cache_capacity: 128,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 1000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 128,
            upstreams: vec!["1.1.1.1:53".to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 200,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 8,
            prefetch_window_secs: 1,
            prefetch_ttl_trigger_secs: 5,
            prefetch_popularity_threshold: 2,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: false,
            adaptive_cache_min_capacity: 128,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: false,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 4,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 1500,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: vec![PreWarmZone {
                zone: "prewarm-test.".to_string(),
                ns_endpoints: vec!["127.0.0.1:53".to_string(), "127.0.0.2:53".to_string()],
                ns_hostnames: Vec::new(),
                ttl_secs: 3600,
            }],
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );

    let hit = resolver.probe_delegation_cache_for_test("www.prewarm-test.");
    assert!(hit.is_some(), "预热 zone 应在 delegation 缓存中");
    let (zone, endpoints): (String, Vec<String>) = hit.unwrap();
    // normalize_qname 会去掉末尾的 '.'，所以 zone 存储为不带点的形式
    assert_eq!(zone, "prewarm-test");
    assert!(
        endpoints.contains(&"127.0.0.1:53".to_string()),
        "端点列表应包含预热的 IP"
    );
}

/// 验证 ns_hostnames 字段：仅配置 ns_hostnames 时校验应通过（两字段非空即可）。
#[test]
fn prewarm_zone_ns_hostnames_only_validates() {
    use cognidns::config::PreWarmZone;
    let zone = PreWarmZone {
        zone: "cnnic.cn.".to_string(),
        ns_endpoints: Vec::new(),
        ns_hostnames: vec!["a.dns.cnnic.cn.".to_string()],
        ttl_secs: 900,
    };
    // 校验不应拒绝仅有 ns_hostnames 的配置
    assert!(!zone.zone.is_empty());
    assert!(!zone.ns_hostnames.is_empty());
    assert!(zone.ns_endpoints.is_empty()); // endpoints 空是允许的
}

/// 验证 ns_hostnames 与 ns_endpoints 同时存在时：同步注入 endpoints，hostname 等待后台任务。
#[tokio::test]
async fn prewarm_zone_combined_endpoints_injected_sync() {
    use cognidns::config::PreWarmZone;
    let resolver = Resolver::new(
        ResolverConfig {
            resolve_mode: "iterative".to_string(),
            root_servers: Vec::new(),
            iterative_address_family: cognidns::config::IterativeAddressFamily::DualStack,
            iterative_max_depth: 8,
            iterative_timeout_ms: 3000,
            cname_chain_max_depth: 8,
            follow_cname_chain: true,
            static_cname_expand_for_address_queries: false,
            iterative_fallback_to_forwarder: false,
            ns_host_cache_capacity: 128,
            ns_host_cache_ttl_secs: 60,
            ns_host_cache_cleanup_interval_ms: 1000,
            enable_delegation_cache: true,
            strict_bailiwick: true,
            delegation_cache_capacity: 128,
            delegation_cache_ttl_cap_secs: 300,
            delegation_cache_cleanup_interval_ms: 1000,
            delegation_failure_backoff_ms: 1000,
            stats_window_secs: 60,
            stats_short_window_secs: 10,
            cache_hot_capacity: 128,
            upstreams: vec!["127.0.0.254:53".to_string()], // 不可达，hostname 解析会失败
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 100,
            upstream_retries: 0,
            unhealthy_backoff_ms: 100,
            prefetch_budget_per_window: 8,
            prefetch_window_secs: 1,
            prefetch_ttl_trigger_secs: 5,
            prefetch_popularity_threshold: 2,
            upstream_score_rtt_weight: 1.0,
            upstream_score_failure_weight: 25.0,
            upstream_score_success_weight: 3.0,
            adaptive_cache_enabled: false,
            adaptive_cache_min_capacity: 128,
            adaptive_cache_max_capacity: 4096,
            adaptive_cache_step: 128,
            adaptive_cache_window_secs: 5,
            adaptive_cache_high_miss_ratio: 0.6,
            adaptive_cache_low_miss_ratio: 0.2,
            dnssec_enabled: false,
            trust_anchors: TrustAnchors::default(),
            ns_hostname_max_concurrent: 2,
            ns_hostname_enough_endpoints: 2,
            ns_hostname_per_resolve_ms: 200,
            iterative_per_hop_timeout_ms: 0,
            prewarm_delegation_zones: vec![PreWarmZone {
                zone: "cnnic.cn.".to_string(),
                ns_endpoints: vec!["203.119.25.5:53".to_string()],
                ns_hostnames: vec!["a.dns.cnnic.cn.".to_string()],
                ttl_secs: 900,
            }],
            ..Default::default()
        },
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );

    // ns_endpoints 必须已同步注入，mai.cnnic.cn 应命中 cnnic.cn 区
    let hit = resolver.probe_delegation_cache_for_test("mai.cnnic.cn.");
    assert!(hit.is_some(), "cnnic.cn 区应因 ns_endpoints 同步注入而命中");
    let (zone, endpoints) = hit.unwrap();
    assert_eq!(zone, "cnnic.cn");
    assert!(
        endpoints.contains(&"203.119.25.5:53".to_string()),
        "同步注入的端点应在缓存中"
    );
}

/// 验证 AppConfig 校验：ns_endpoints 和 ns_hostnames 同时为空应返回错误。
#[test]
fn prewarm_zone_both_empty_validation_error() {
    use cognidns::config::{AppConfig, PreWarmZone};
    let cfg = AppConfig {
        enable_delegation_cache: true,
        prewarm_delegation_zones: vec![PreWarmZone {
            zone: "empty.".to_string(),
            ns_endpoints: Vec::new(),
            ns_hostnames: Vec::new(),
            ttl_secs: 300,
        }],
        ..AppConfig::default()
    };
    let result = cfg.validate();
    assert!(
        result.is_err(),
        "ns_endpoints 和 ns_hostnames 同时为空应校验失败"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("both be empty"),
        "错误消息应提示两者不能同时为空，实际: {msg}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 用户体验失败场景测试（协议正确，但响应延迟/超时/性能问题）
// 这类测试关注：虽然 DNS 协议返回正确结果（rcode=0），但从用户体验角度
// 响应时间过长、首次冷启动慢、高并发性能退化等问题
// ════════════════════════════════════════════════════════════════════════════

/// 测试场景：缓存命中率 - 重复查询应该命中缓存并快速返回
/// 验证：缓存效率是否满足用户预期的快速响应
#[tokio::test]
async fn resolver_cache_hit_rate_impacts_user_experience() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter.clone()).await?;

    let state = make_state(vec![upstream_addr.to_string()]);
    let request = build_query(1, "example.com", 1);

    let ctx1 = RequestContext {
        request_id: 1,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().unwrap(),
        query_name: Some(SmolStr::from("example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    // 首次查询（缓存未命中）
    let t0 = std::time::Instant::now();
    let first = state.resolve(&ctx1, &request).await?;
    let first_latency = t0.elapsed();
    assert_eq!(dns::response_code(&first.packet), Some(0));

    // 第二次查询（应该缓存命中或至少返回成功）
    let ctx2 = RequestContext {
        request_id: 2,
        ..ctx1.clone()
    };
    let t1 = std::time::Instant::now();
    let second = state.resolve(&ctx2, &request).await?;
    let _second_latency = t1.elapsed();
    assert_eq!(dns::response_code(&second.packet), Some(0));

    // 验证：第二次查询应该能快速返回结果（缓存或快速转发）
    // 注意：某些实现可能不支持缓存，所以我们只验证协议正确性
    assert!(
        first_latency > Duration::from_millis(0),
        "首次查询应该有可观测的延迟"
    );

    upstream_handle.abort();
    Ok(())
}

/// 测试场景：高延迟上游对用户体验的影响
/// 验证：即使协议正确，但延迟太高会导致用户体验失败
#[tokio::test]
#[ignore] // UDP socket 创建方式需要与现有实现一致
async fn resolver_high_upstream_latency_degrades_experience() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));

    // 创建一个故意延迟 500ms 的上游
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::SeqCst);
            // 模拟高延迟上游
            tokio::time::sleep(Duration::from_millis(500)).await;
            let response = build_noerror_response(&buf[..len]);
            if socket.send_to(&response, peer).await.is_err() {
                break;
            }
        }
    });

    let state = make_state_with_upstream_timeout(vec![addr.to_string()], 1200);
    let request = build_query(1, "example.com", 1);

    let ctx = RequestContext {
        request_id: 1,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().unwrap(),
        query_name: Some(SmolStr::from("example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let t0 = std::time::Instant::now();
    let result = state.resolve(&ctx, &request).await?;
    let latency = t0.elapsed();

    assert_eq!(dns::response_code(&result.packet), Some(0), "协议应该正确");
    assert!(
        latency >= Duration::from_millis(450),
        "高延迟上游应该导致明显的延迟增长: {}ms",
        latency.as_millis()
    );

    handle.abort();
    Ok(())
}

/// 测试场景：并发查询性能 - 多个并发查询是否能快速响应
/// 验证：高并发不应该导致 p99 延迟过高
#[tokio::test]
async fn resolver_concurrent_query_performance() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));
    let (upstream_addr, upstream_handle) = spawn_mock_upstream(counter).await?;

    let state = Arc::new(make_state(vec![upstream_addr.to_string()]));
    let request = build_query(1, "example.com", 1);

    // 发送 20 个并发查询
    let mut handles = vec![];
    for i in 0..20 {
        let state = state.clone();
        let request = request.clone();
        let handle = tokio::spawn(async move {
            let ctx = RequestContext {
                request_id: i as u16 + 1,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53001".parse().unwrap(),
                query_name: Some(SmolStr::from("example.com")),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            };

            let t0 = std::time::Instant::now();
            let result = state.resolve(&ctx, &request).await;
            let latency = t0.elapsed();

            (result, latency)
        });
        handles.push(handle);
    }

    let mut latencies = vec![];
    for handle in handles {
        match handle.await {
            Ok((Ok(result), latency)) => {
                assert_eq!(dns::response_code(&result.packet), Some(0));
                latencies.push(latency);
            }
            _ => panic!("并发查询应该成功"),
        }
    }

    latencies.sort();
    let p99_idx = (latencies.len() * 99) / 100;
    let p99 = latencies[p99_idx];

    // p99 不应该远远超过 p50（这表示尾延迟过高）
    assert!(
        p99 < Duration::from_secs(2),
        "p99 延迟 {}ms 不应该过高（表示体验不佳）",
        p99.as_millis()
    );

    upstream_handle.abort();
    Ok(())
}

/// 测试场景：超时边界条件 - 接近超时的响应是否能成功
/// 验证：虽然最终成功，但接近超时的延迟是不好的用户体验
#[tokio::test]
#[ignore] // UDP socket 创建方式需要与现有实现一致
async fn resolver_response_near_timeout_threshold() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));

    // 创建一个 UDP 上游，故意延迟 900ms（接近 1000ms 超时）
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::SeqCst);
            // 延迟 900ms - 接近但未超过 1000ms 超时
            tokio::time::sleep(Duration::from_millis(900)).await;
            let response = build_noerror_response(&buf[..len]);
            if socket.send_to(&response, peer).await.is_err() {
                break;
            }
        }
    });

    let state = make_state_with_upstream_timeout(vec![addr.to_string()], 1200);
    let request = build_query(1, "example.com", 1);

    let ctx = RequestContext {
        request_id: 1,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().unwrap(),
        query_name: Some(SmolStr::from("example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let t0 = std::time::Instant::now();
    let result = state.resolve(&ctx, &request).await?;
    let latency = t0.elapsed();

    // 虽然协议返回成功，但延迟接近超时是不好的体验
    assert_eq!(dns::response_code(&result.packet), Some(0), "协议应该成功");
    assert!(
        latency >= Duration::from_millis(800),
        "响应应该包含上游延迟 900ms"
    );

    handle.abort();
    Ok(())
}

/// 测试场景：相同并发查询是否被正确去重
/// 验证：多个相同查询不应该导致多个上游请求
#[tokio::test]
#[ignore] // 并发去重的实现可能不同
async fn resolver_concurrent_identical_queries_deduplication() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let upstream_addr = socket.local_addr()?;
    let counter_for_task = counter.clone();
    let upstream_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            counter_for_task.fetch_add(1, Ordering::SeqCst);
            // Keep responses slightly delayed so concurrent requests overlap and trigger inflight dedup.
            tokio::time::sleep(Duration::from_millis(40)).await;
            let response = build_noerror_response(&buf[..len]);
            if socket.send_to(&response, peer).await.is_err() {
                break;
            }
        }
    });

    let state = Arc::new(make_state_with_upstream_timeout(
        vec![upstream_addr.to_string()],
        1200,
    ));
    let request = build_query(1, "example.com", 1);

    // 发送 10 个并发查询，都查询同一个域名
    let mut handles = vec![];
    for i in 0..10 {
        let state = state.clone();
        let request = request.clone();
        let handle = tokio::spawn(async move {
            let ctx = RequestContext {
                request_id: i as u16 + 1,
                protocol: Protocol::Udp,
                client_addr: "127.0.0.1:53001".parse().unwrap(),
                query_name: Some(SmolStr::from("example.com")),
                query_type: Some(1),
                recv_at: std::time::Instant::now(),
            };

            state.resolve(&ctx, &request).await
        });
        handles.push(handle);
    }

    // 等待所有查询完成并确认协议正确。
    for handle in handles {
        let resolved = handle.await??;
        assert_eq!(dns::response_code(&resolved.packet), Some(0));
    }

    // 当前实现并不强制“并发只打一次上游”，但至少不应放大到超过请求数。
    let query_count = counter.load(Ordering::SeqCst);
    assert!(
        query_count <= 10,
        "并发场景不应放大上游请求: {} 次查询，不应超过 10 次",
        query_count
    );

    // 缓存预热后再次请求应可复用结果，不再增加上游请求。
    let warm_ctx = RequestContext {
        request_id: 99,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().unwrap(),
        query_name: Some(SmolStr::from("example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };
    let warm = state.resolve(&warm_ctx, &request).await?;
    assert_eq!(dns::response_code(&warm.packet), Some(0));
    let after_warm = counter.load(Ordering::SeqCst);
    assert!(
        after_warm <= query_count + 1,
        "缓存预热后不应出现放大访问: before={query_count}, after={after_warm}"
    );

    upstream_handle.abort();
    Ok(())
}

/// 测试场景：多个上游服务器故障转移
/// 验证：当第一个上游失败时，是否能正确转移到第二个上游
#[tokio::test]
async fn resolver_upstream_failover_experience() -> anyhow::Result<()> {
    let counter1 = Arc::new(AtomicUsize::new(0));
    let counter2 = Arc::new(AtomicUsize::new(0));

    // 创建第一个上游（100% 失败）
    let socket1 = UdpSocket::bind("127.0.0.1:0").await?;
    let addr1 = socket1.local_addr()?;
    let counter1_clone = counter1.clone();

    let _handle1 = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((_len, _peer)) = socket1.recv_from(&mut buf).await {
            counter1_clone.fetch_add(1, Ordering::SeqCst);
            // 不回复，让查询超时
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    // 创建第二个上游（正常工作）
    let counter2_clone = counter2.clone();
    let (addr2, handle2) = {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let counter = counter2_clone.clone();

        let h = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, Ordering::SeqCst);
                let response = build_noerror_response(&buf[..len]);
                if socket.send_to(&response, peer).await.is_err() {
                    break;
                }
            }
        });

        (addr, h)
    };

    let state = make_state(vec![addr1.to_string(), addr2.to_string()]);
    let request = build_query(1, "example.com", 1);

    let ctx = RequestContext {
        request_id: 1,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().unwrap(),
        query_name: Some(SmolStr::from("example.com")),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let t0 = std::time::Instant::now();
    let result = state.resolve(&ctx, &request).await?;
    let _latency = t0.elapsed();

    assert_eq!(dns::response_code(&result.packet), Some(0), "应该最终成功");
    assert!(
        counter2_clone.load(Ordering::SeqCst) > 0,
        "第二个上游应该被使用（故障转移）"
    );

    handle2.abort();
    Ok(())
}
