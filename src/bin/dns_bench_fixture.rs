use std::env;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use data_encoding::BASE64;
use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::dnssec::{
    Algorithm, DigestType, PublicKey, PublicKeyBuf, SigSigner, SigningKey, TBS,
};
use hickory_proto::op::{Edns, Message, MessageType, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let scenario = args.first().map(String::as_str).unwrap_or("forwarder-cold");
    match scenario {
        "forwarder-cold" => run_forwarder_cold().await,
        "forwarder-dnssec" => run_forwarder_dnssec().await,
        "forwarder-fallback" => run_forwarder_fallback().await,
        "iterative" => run_iterative().await,
        other => Err(anyhow!("unsupported fixture scenario: {other}")),
    }
}

async fn run_forwarder_cold() -> anyhow::Result<()> {
    run_responder("127.0.0.1:5531", [203, 0, 113, 10]).await
}

async fn run_forwarder_dnssec() -> anyhow::Result<()> {
    let fixture = build_dnssec_fixture()?;
    write_dnssec_trust_anchor(&fixture.root)?;

    let socket = UdpSocket::bind("127.0.0.1:5534").await?;
    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let response = fixture.respond(&buf[..len])?;
        socket.send_to(&response, peer).await?;
    }
}

async fn run_forwarder_fallback() -> anyhow::Result<()> {
    let drop_socket = UdpSocket::bind("127.0.0.1:5532").await?;
    let _responder = tokio::spawn(run_responder("127.0.0.1:5533", [203, 0, 113, 20]));
    let mut buf = [0u8; 4096];
    loop {
        let _ = drop_socket.recv_from(&mut buf).await?;
    }
}

async fn run_iterative() -> anyhow::Result<()> {
    let fallback_counter = Arc::new(AtomicUsize::new(0));
    let root_socket = UdpSocket::bind("127.0.0.1:5541").await?;
    let bootstrap_socket = UdpSocket::bind("127.0.0.1:5542").await?;
    let auth_socket = UdpSocket::bind("127.0.0.1:53")
        .await
        .context("failed to bind iterative auth fixture on 127.0.0.1:53")?;

    let fallback_root_counter = fallback_counter.clone();
    let root = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = root_socket.recv_from(&mut buf).await {
            let request = &buf[..len];
            let current = fallback_root_counter.fetch_add(1, Ordering::Relaxed) + 1;
            let response = if current.is_multiple_of(5) {
                build_empty_noerror_response(request)
            } else {
                build_referral_response(request, "bench.test", "ns1.bench.test")
            };
            let _ = root_socket.send_to(&response, peer).await;
        }
    });

    let bootstrap = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = bootstrap_socket.recv_from(&mut buf).await {
            let request = &buf[..len];
            let qname = parse_first_question_name(request).unwrap_or_default();
            let response = if qname.eq_ignore_ascii_case("ns1.bench.test") {
                build_answer_a_response(request, [127, 0, 0, 1])
            } else {
                build_answer_a_response(request, [203, 0, 113, 30])
            };
            let _ = bootstrap_socket.send_to(&response, peer).await;
        }
    });

    let auth = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = auth_socket.recv_from(&mut buf).await {
            let request = &buf[..len];
            let response = build_answer_a_response(request, [203, 0, 113, 31]);
            let _ = auth_socket.send_to(&response, peer).await;
        }
    });

    let _ = tokio::join!(root, bootstrap, auth);
    Ok(())
}

async fn run_responder(bind_addr: &str, ip: [u8; 4]) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let response = build_answer_a_response(&buf[..len], ip);
        socket.send_to(&response, peer).await?;
    }
}

fn parse_first_question_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
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
        if offset + len > packet.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&packet[offset..offset + len])
                .ok()?
                .to_string(),
        );
        offset += len;
    }
    Some(labels.join("."))
}

fn question_end(packet: &[u8]) -> Option<usize> {
    let mut offset = 12usize;
    loop {
        if offset >= packet.len() {
            return None;
        }
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if offset + len > packet.len() {
            return None;
        }
        offset += len;
    }
    if offset + 4 > packet.len() {
        return None;
    }
    Some(offset + 4)
}

fn append_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn build_answer_a_response(request: &[u8], ip: [u8; 4]) -> Vec<u8> {
    let id = u16::from_be_bytes([request[0], request[1]]);
    let qend = question_end(request).unwrap_or(request.len());
    let mut response = Vec::with_capacity(request.len() + 32);
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&request[12..qend]);
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&30u32.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&ip);
    response
}

fn build_empty_noerror_response(request: &[u8]) -> Vec<u8> {
    let id = u16::from_be_bytes([request[0], request[1]]);
    let qend = question_end(request).unwrap_or(request.len());
    let mut response = Vec::with_capacity(request.len());
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&request[12..qend]);
    response
}

fn build_referral_response(request: &[u8], zone: &str, ns_host: &str) -> Vec<u8> {
    let id = u16::from_be_bytes([request[0], request[1]]);
    let qend = question_end(request).unwrap_or(request.len());
    let mut response = Vec::with_capacity(request.len() + 64);
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&request[12..qend]);
    append_name(&mut response, zone);
    response.extend_from_slice(&2u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&30u32.to_be_bytes());
    let mut rdata = Vec::new();
    append_name(&mut rdata, ns_host);
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);
    response
}

struct SignedZone {
    zone: Name,
    dnskey_record: Record,
    signer: SigSigner,
}

struct DnssecFixture {
    root: SignedZone,
    com: SignedZone,
    child: SignedZone,
    root_dnskey_rrset: Vec<Record>,
    com_dnskey_rrset: Vec<Record>,
    child_dnskey_rrset: Vec<Record>,
    com_ds_rrset: Vec<Record>,
    child_ds_rrset: Vec<Record>,
}

impl DnssecFixture {
    fn respond(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let message = Message::from_vec(request)?;
        let Some(query) = message.query() else {
            return Err(anyhow!("missing benchmark query section"));
        };

        let qname = query.name().to_ascii();
        let qtype = query.query_type();
        let response = match (qname.as_str(), qtype) {
            _ if qtype == RecordType::A && qname.ends_with(".example.com.") => {
                let owner = query.name().clone();
                let answer_record =
                    dnssec_record(owner.clone(), 300, RData::A(A::new(203, 0, 113, 40)));
                let answer_rrset =
                    signed_rrset(&owner, 300, &self.child.signer, vec![answer_record])?;
                dnssec_response_packet(request, &owner, RecordType::A, answer_rrset)
            }
            ("example.com.", RecordType::DNSKEY) => dnssec_response_packet(
                request,
                &self.child.zone,
                RecordType::DNSKEY,
                self.child_dnskey_rrset.clone(),
            ),
            ("example.com.", RecordType::DS) => dnssec_response_packet(
                request,
                &self.child.zone,
                RecordType::DS,
                self.child_ds_rrset.clone(),
            ),
            ("com.", RecordType::DNSKEY) => dnssec_response_packet(
                request,
                &self.com.zone,
                RecordType::DNSKEY,
                self.com_dnskey_rrset.clone(),
            ),
            ("com.", RecordType::DS) => dnssec_response_packet(
                request,
                &self.com.zone,
                RecordType::DS,
                self.com_ds_rrset.clone(),
            ),
            (".", RecordType::DNSKEY) => dnssec_response_packet(
                request,
                &self.root.zone,
                RecordType::DNSKEY,
                self.root_dnskey_rrset.clone(),
            ),
            _ => build_empty_noerror_response(request),
        };

        Ok(response)
    }
}

fn build_dnssec_fixture() -> anyhow::Result<DnssecFixture> {
    let root = new_signed_zone(".")?;
    let com = new_signed_zone("com.")?;
    let child = new_signed_zone("example.com.")?;
    let root_dnskey_rrset = signed_rrset(
        &root.zone,
        300,
        &root.signer,
        vec![root.dnskey_record.clone()],
    )?;
    let com_dnskey_rrset =
        signed_rrset(&com.zone, 300, &com.signer, vec![com.dnskey_record.clone()])?;
    let child_dnskey_rrset = signed_rrset(
        &child.zone,
        300,
        &child.signer,
        vec![child.dnskey_record.clone()],
    )?;

    let com_dnskey = as_dnskey(&com.dnskey_record).ok_or_else(|| anyhow!("missing com dnskey"))?;
    let com_ds_record = dnssec_record(
        com.zone.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DS(DS::new(
            com_dnskey.calculate_key_tag()?,
            com_dnskey.public_key().algorithm(),
            DigestType::SHA256,
            com_dnskey
                .to_digest(&com.zone, DigestType::SHA256)?
                .as_ref()
                .to_vec(),
        ))),
    );
    let com_ds_rrset = signed_rrset(&com.zone, 300, &root.signer, vec![com_ds_record])?;

    let child_dnskey =
        as_dnskey(&child.dnskey_record).ok_or_else(|| anyhow!("missing child dnskey"))?;
    let child_ds_record = dnssec_record(
        child.zone.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DS(DS::new(
            child_dnskey.calculate_key_tag()?,
            child_dnskey.public_key().algorithm(),
            DigestType::SHA256,
            child_dnskey
                .to_digest(&child.zone, DigestType::SHA256)?
                .as_ref()
                .to_vec(),
        ))),
    );
    let child_ds_rrset = signed_rrset(&child.zone, 300, &com.signer, vec![child_ds_record])?;

    Ok(DnssecFixture {
        root,
        com,
        child,
        root_dnskey_rrset,
        com_dnskey_rrset,
        child_dnskey_rrset,
        com_ds_rrset,
        child_ds_rrset,
    })
}

fn write_dnssec_trust_anchor(root: &SignedZone) -> anyhow::Result<()> {
    fs::create_dir_all("logs")?;
    let dnskey = as_dnskey(&root.dnskey_record).ok_or_else(|| anyhow!("missing root dnskey"))?;
    let public_key = BASE64.encode(dnskey.public_key().public_bytes());
    let line = format!(
        ". IN DNSKEY {} 3 {} {}\n",
        dnskey.flags(),
        u8::from(dnskey.public_key().algorithm()),
        public_key
    );
    fs::write("logs/bench-dnssec-root.anchor", line)
        .context("failed to write DNSSEC benchmark trust anchor")
}

fn new_signed_zone(zone: &str) -> anyhow::Result<SignedZone> {
    let zone = Name::from_ascii(zone)?;
    let algorithm = Algorithm::ECDSAP256SHA256;
    let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm)?;
    let signing_key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm)?;
    let public_key = signing_key.to_public_key()?;
    let dnskey = DNSKEY::new(
        true,
        true,
        false,
        PublicKeyBuf::new(public_key.public_bytes().to_vec(), algorithm),
    );
    let dnskey_record = dnssec_record(
        zone.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    );
    let signer = SigSigner::dnssec(
        dnskey,
        Box::new(signing_key),
        zone.clone(),
        Duration::from_secs(300),
    );

    Ok(SignedZone {
        zone,
        dnskey_record,
        signer,
    })
}

fn dnssec_record(name: Name, ttl: u32, data: RData) -> Record {
    let mut record = Record::from_rdata(name, ttl, data);
    record.set_dns_class(DNSClass::IN);
    record
}

fn dnssec_time_window() -> (u32, u32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs() as u32;
    (now.saturating_sub(60), now.saturating_add(300))
}

fn sign_rrset(
    owner: &Name,
    ttl: u32,
    record_type: RecordType,
    signer: &SigSigner,
    rrset: &[Record],
) -> anyhow::Result<Record> {
    let (inception, expiration) = dnssec_time_window();
    let key_tag = signer.calculate_key_tag()?;
    let pre_rrsig = RRSIG::new(
        record_type,
        signer.key().algorithm(),
        owner.num_labels(),
        ttl,
        expiration,
        inception,
        key_tag,
        signer.signer_name().clone(),
        Vec::new(),
    );
    let mut pre_record: Record<RRSIG> = Record::from_rdata(owner.clone(), ttl, pre_rrsig.clone());
    pre_record.set_dns_class(DNSClass::IN);
    let tbs = TBS::from_rrsig(&pre_record, rrset.iter())?;
    let signature = signer.sign(&tbs)?;

    Ok(dnssec_record(
        owner.clone(),
        ttl,
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
            record_type,
            signer.key().algorithm(),
            owner.num_labels(),
            ttl,
            expiration,
            inception,
            key_tag,
            signer.signer_name().clone(),
            signature,
        ))),
    ))
}

fn signed_rrset(
    owner: &Name,
    ttl: u32,
    signer: &SigSigner,
    rrset: Vec<Record>,
) -> anyhow::Result<Vec<Record>> {
    let mut records = rrset;
    let record_type = records[0].record_type();
    let rrsig = sign_rrset(owner, ttl, record_type, signer, &records)?;
    records.push(rrsig);
    Ok(records)
}

fn dnssec_response_packet(
    request: &[u8],
    qname: &Name,
    qtype: RecordType,
    answers: Vec<Record>,
) -> Vec<u8> {
    let header = hickory_proto::serialize::binary::BinDecoder::new(request);
    let _ = header;
    let request_message = Message::from_vec(request).expect("request packet");
    let mut message = Message::new();
    message
        .set_id(request_message.id())
        .set_message_type(MessageType::Response)
        .set_recursion_desired(request_message.recursion_desired())
        .set_recursion_available(true)
        .add_query(Query::query(qname.clone(), qtype))
        .add_answers(answers);

    if let Some(request_edns) = request_message.extensions() {
        let mut edns = Edns::new();
        edns.set_max_payload(request_edns.max_payload());
        edns.set_dnssec_ok(request_edns.flags().dnssec_ok);
        message.set_edns(edns);
    }

    message.to_vec().expect("dnssec response packet")
}

fn as_dnskey(record: &Record) -> Option<&DNSKEY> {
    match record.data() {
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => Some(dnskey),
        _ => None,
    }
}
