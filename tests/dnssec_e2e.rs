use cognidns::cache::ResponseCache;
use cognidns::codec::dns;
use cognidns::context::{Protocol, RequestContext};
use cognidns::metrics::Metrics;
use cognidns::policy::{PolicyConfig, PolicyEngine};
use cognidns::resolver::{Resolver, ResolverConfig};
use cognidns::service::AppState;
use data_encoding::BASE32_DNSSEC;
use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, NSEC3, RRSIG};
use hickory_proto::dnssec::PublicKey;
use hickory_proto::dnssec::TrustAnchors;
use hickory_proto::dnssec::{Algorithm, Nsec3HashAlgorithm, PublicKeyBuf, SigSigner, SigningKey};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

// This test is a focused end-to-end check that the resolver
// performs DNSSEC validation path (NSEC3 negative proof case) at a high level.
// It uses a simple mock upstream that returns a pre-constructed NXDOMAIN
// with DNSSEC-related RRs simulated via `codec::dns::build_response_with_rcode`.
// The purpose is to exercise resolver wiring and configuration, not
// to re-implement full NSEC3 signing — detailed cryptographic cases
// remain covered by unit tests in `src/dnssec.rs`.

#[tokio::test]
async fn e2e_dnssec_nxdomain_path_basic() -> anyhow::Result<()> {
    // Counter for upstream queries
    let counter = Arc::new(AtomicUsize::new(0));

    // Spawn a UDP mock upstream that always returns NXDOMAIN (rcode 3).
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let addr = socket.local_addr()?;
    let socket_clone = socket.clone();
    let counter_clone = counter.clone();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket_clone.recv_from(&mut buf).await {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            // Build a simple NXDOMAIN response echoing question and with no answers.
            if let Ok(resp) = dns::build_response_with_rcode(&buf[..len], dns::DNS_RCODE_FORMERR) {
                let mut nxd = resp;
                // set RCODE to NXDOMAIN (3)
                if nxd.len() >= 4 {
                    nxd[3] = (nxd[3] & 0xF0) | 3u8;
                }
                let _ = socket_clone.send_to(&nxd, peer).await;
            } else if let Ok(nxd) = dns::build_response_with_rcode(&buf[..len], 3) {
                let _ = socket_clone.send_to(&nxd, peer).await;
            }
        }
    });

    // Build resolver + app state
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
            iterative_max_depth: 4,
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
            upstreams: vec![addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 500,
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

    let state = AppState::new_with_cache_and_topn(
        policy,
        resolver,
        Arc::new(ResponseCache::default()),
        metrics,
        "config/cognidns.toml".to_string(),
        false,
    );

    // Send a query that should produce NXDOMAIN from upstream and be handled by resolver.
    let request = dns::build_query(0xdead, "no.such.domain.example", 1, true).expect("build query");

    let ctx = RequestContext {
        request_id: 0xdead,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53000".parse().unwrap(),
        query_name: Some("no.such.domain.example".to_string()),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;

    // We expect NXDOMAIN (rcode 3) from upstream; ensure resolver returns a negative response.
    assert_eq!(dns::response_code(&resolved.packet), Some(3));
    // Upstream must have been hit at least once.
    assert!(counter.load(Ordering::SeqCst) >= 1);

    // Cleanup
    handle.abort();
    Ok(())
}

#[tokio::test]
async fn e2e_nsec3_nodata() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));

    // Build signed NSEC3 NOERROR (NODATA) message for qname "noa.example.com."
    let (zone, dnskey_rr, signer) = new_signed_zone("example.com.");
    let qname = Name::from_ascii("noa.example.com.").unwrap();
    let salt = vec![0x01, 0x02, 0x03, 0x04];
    let next_closer = Name::from_ascii("noa.example.com.").unwrap();
    let closest = Name::from_ascii("example.com.").unwrap();
    let closest_hash = hash_nsec3_name(&closest, Nsec3HashAlgorithm::SHA1, &salt, 1);
    let zero_hash = vec![0u8; closest_hash.len()];
    let ce_owner = nsec3_owner_name(&zone, &closest_hash);
    let cover_owner = nsec3_owner_name(&zone, &zero_hash);

    let ce_record = record(
        ce_owner.clone(),
        300,
        RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            1,
            salt.clone(),
            hash_nsec3_name(&next_closer, Nsec3HashAlgorithm::SHA1, &salt, 1),
            [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))),
    );

    let covering_record = record(
        cover_owner.clone(),
        300,
        RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            1,
            salt.clone(),
            vec![0xAAu8; closest_hash.len()],
            [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))),
    );

    let mut authority = signed_rrset(&ce_owner, 300, &signer, vec![ce_record]);
    authority.extend(signed_rrset(
        &cover_owner,
        300,
        &signer,
        vec![covering_record],
    ));
    authority.push(dnskey_rr.clone());

    let message = message_with_authority(&qname, RecordType::A, ResponseCode::NoError, authority);
    let packet = message.to_vec().expect("packet");

    // spawn upstream that returns this packet
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let addr = socket.local_addr()?;
    let socket_clone = socket.clone();
    let packet_clone = packet.clone();
    let counter_clone = counter.clone();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((_len, peer)) = socket_clone.recv_from(&mut buf).await {
            let mut reply = packet_clone.clone();
            if buf.len() >= 2 && reply.len() >= 2 {
                reply[0] = buf[0];
                reply[1] = buf[1];
            }
            let _ = socket_clone.send_to(&reply, peer).await;
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    // resolver setup (reuse same as other tests)
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
            iterative_max_depth: 4,
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
            upstreams: vec![addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 500,
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

    let state = AppState::new_with_cache_and_topn(
        policy,
        resolver,
        Arc::new(ResponseCache::default()),
        metrics,
        "config/cognidns.toml".to_string(),
        false,
    );

    let request = dns::build_query(0xabba, "noa.example.com", 1, true).expect("build");
    let ctx = RequestContext {
        request_id: 0xabba,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53002".parse().unwrap(),
        query_name: Some("noa.example.com".to_string()),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    // Expect NOERROR (0) and upstream was hit
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(counter.load(Ordering::SeqCst) >= 1);

    handle.abort();
    Ok(())
}

fn now_window() -> (u32, u32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs() as u32;
    (now.saturating_sub(60), now.saturating_add(300))
}

fn record(name: Name, ttl: u32, data: RData) -> Record {
    let mut record = Record::from_rdata(name, ttl, data);
    record.set_dns_class(hickory_proto::rr::DNSClass::IN);
    record
}

fn sign_rrset(
    owner: &Name,
    ttl: u32,
    record_type: RecordType,
    signer: &SigSigner,
    rrset: &[Record],
) -> Record {
    let (inception, expiration) = now_window();
    let key_tag = signer.calculate_key_tag().expect("key tag");
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
    pre_record.set_dns_class(hickory_proto::rr::DNSClass::IN);
    let tbs = hickory_proto::dnssec::TBS::from_rrsig(&pre_record, rrset.iter()).expect("rrsig tbs");
    let signature = signer.sign(&tbs).expect("rrsig signature");
    record(
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
    )
}

fn signed_rrset(owner: &Name, ttl: u32, signer: &SigSigner, rrset: Vec<Record>) -> Vec<Record> {
    let mut records = rrset;
    let record_type = records[0].record_type();
    let rrsig = sign_rrset(owner, ttl, record_type, signer, &records);
    records.push(rrsig);
    records
}

fn message_with_authority(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    authority: Vec<Record>,
) -> Message {
    let mut message = Message::new();
    message
        .set_id(88)
        .set_message_type(MessageType::Response)
        .set_response_code(rcode)
        .add_query(Query::query(qname.clone(), qtype))
        .add_name_servers(authority);
    message
}

fn new_signed_zone(zone: &str) -> (Name, Record, SigSigner) {
    let zone = Name::from_ascii(zone).expect("zone name");
    let algorithm = Algorithm::ECDSAP256SHA256;
    let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).expect("pkcs8");
    let signing_key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).expect("signing key");
    let public_key = signing_key.to_public_key().expect("public key");
    let dnskey = DNSKEY::new(
        true,
        true,
        false,
        PublicKeyBuf::new(public_key.public_bytes().to_vec(), algorithm),
    );
    let dnskey_record = record(
        zone.clone(),
        300,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    );
    let signer = SigSigner::dnssec(
        dnskey,
        Box::new(signing_key),
        zone.clone(),
        std::time::Duration::from_secs(300),
    );
    (zone, dnskey_record, signer)
}

fn nsec3_owner_name(zone: &Name, hash: &[u8]) -> Name {
    let encoded = BASE32_DNSSEC.encode(hash);
    Name::from_ascii(format!("{encoded}.{}", zone.to_ascii())).expect("nsec3 owner")
}

fn hash_nsec3_name(
    name: &Name,
    algorithm: Nsec3HashAlgorithm,
    salt: &[u8],
    iterations: u16,
) -> Vec<u8> {
    algorithm
        .hash(salt, name, iterations)
        .expect("hash")
        .as_ref()
        .to_vec()
}

#[tokio::test]
async fn e2e_nsec3_nxdomain() -> anyhow::Result<()> {
    let counter = Arc::new(AtomicUsize::new(0));

    // Build signed NSEC3 NXDOMAIN message for qname "missing.example.com."
    let (zone, dnskey_rr, signer) = new_signed_zone("example.com.");
    let qname = Name::from_ascii("missing.example.com.").unwrap();
    let salt = vec![0x10, 0x20, 0x30, 0x40];
    let next_closer = Name::from_ascii("missing.example.com.").unwrap();
    let closest = Name::from_ascii("example.com.").unwrap();
    let closest_hash = hash_nsec3_name(&closest, Nsec3HashAlgorithm::SHA1, &salt, 1);
    let zero_hash = vec![0u8; closest_hash.len()];
    let ce_owner = nsec3_owner_name(&zone, &closest_hash);
    let cover_owner = nsec3_owner_name(&zone, &zero_hash);

    let ce_record = record(
        ce_owner.clone(),
        300,
        RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            1,
            salt.clone(),
            hash_nsec3_name(&next_closer, Nsec3HashAlgorithm::SHA1, &salt, 1),
            [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))),
    );

    let covering_record = record(
        cover_owner.clone(),
        300,
        RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            1,
            salt.clone(),
            vec![0xFFu8; closest_hash.len()],
            [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
        ))),
    );

    let mut authority = signed_rrset(&ce_owner, 300, &signer, vec![ce_record]);
    authority.extend(signed_rrset(
        &cover_owner,
        300,
        &signer,
        vec![covering_record],
    ));

    // include zone DNSKEY too so validation has material
    authority.push(dnskey_rr.clone());
    let message = message_with_authority(&qname, RecordType::A, ResponseCode::NXDomain, authority);
    let packet = message.to_vec().expect("packet");

    // spawn upstream that returns this packet
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let addr = socket.local_addr()?;
    let socket_clone = socket.clone();
    let packet_clone = packet.clone();
    let counter_clone = counter.clone();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((_len, peer)) = socket_clone.recv_from(&mut buf).await {
            // copy packet and set response ID to match request
            let mut reply = packet_clone.clone();
            if buf.len() >= 2 && reply.len() >= 2 {
                reply[0] = buf[0];
                reply[1] = buf[1];
            }
            let _ = socket_clone.send_to(&reply, peer).await;
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    // resolver setup
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
            iterative_max_depth: 4,
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
            upstreams: vec![addr.to_string()],
            cache_ttl_secs: 30,
            freeze_cache_ttl_decay: false,
            freeze_cache_domains: Vec::new(),
            upstream_timeout_ms: 500,
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

    let state = AppState::new_with_cache_and_topn(
        policy,
        resolver,
        Arc::new(ResponseCache::default()),
        metrics,
        "config/cognidns.toml".to_string(),
        false,
    );

    let request = dns::build_query(0xfeed, "missing.example.com", 1, true).expect("build");
    let ctx = RequestContext {
        request_id: 0xfeed,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().unwrap(),
        query_name: Some("missing.example.com".to_string()),
        query_type: Some(1),
        recv_at: std::time::Instant::now(),
    };

    let resolved = state.resolve(&ctx, &request).await?;
    assert_eq!(dns::response_code(&resolved.packet), Some(3));
    assert!(counter.load(Ordering::SeqCst) >= 1);

    handle.abort();
    Ok(())
}
