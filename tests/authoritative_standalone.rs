use smol_str::SmolStr;
use std::sync::Arc;
use std::time::Instant;

use cognidns::cache::ResponseCache;
use cognidns::codec::dns;
use cognidns::config::{AuthoritativeZone, DnsView, StaticRecord, ViewQueryMode, ZoneSoa};
use cognidns::context::{Protocol, RequestContext};
use cognidns::metrics::Metrics;
use cognidns::resolver::{ResolutionSource, Resolver, ResolverConfig};

fn build_zone_example_com() -> AuthoritativeZone {
    AuthoritativeZone {
        name: "example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 2026051301,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 300,
        }),
        records: vec![
            StaticRecord {
                qname: "www.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "192.0.2.10".to_string(),
                ttl: 120,
            },
            StaticRecord {
                qname: "www.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "192.0.2.11".to_string(),
                ttl: 120,
            },
            StaticRecord {
                qname: "mail.example.com".to_string(),
                qtype: "TXT".to_string(),
                answer: "v=spf1 -all".to_string(),
                ttl: 120,
            },
        ],
    }
}

fn build_parent_zone_example_com() -> AuthoritativeZone {
    AuthoritativeZone {
        name: "example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 2026051401,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 111,
        }),
        records: vec![
            StaticRecord {
                qname: "child.example.com".to_string(),
                qtype: "NS".to_string(),
                answer: "ns1.child.example.com".to_string(),
                ttl: 300,
            },
            StaticRecord {
                qname: "ns1.child.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "192.0.2.53".to_string(),
                ttl: 300,
            },
        ],
    }
}

fn build_child_zone_child_example_com() -> AuthoritativeZone {
    AuthoritativeZone {
        name: "child.example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.child.example.com".to_string(),
            rname: "hostmaster.child.example.com".to_string(),
            serial: 2026051401,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 777,
        }),
        records: vec![StaticRecord {
            qname: "www.child.example.com".to_string(),
            qtype: "A".to_string(),
            answer: "198.51.100.77".to_string(),
            ttl: 180,
        }],
    }
}

fn make_request(id: u16, qname: &str, qtype: u16) -> (RequestContext, Vec<u8>) {
    let ctx = RequestContext {
        request_id: id,
        protocol: Protocol::Udp,
        client_addr: "127.0.0.1:53001".parse().expect("client addr"),
        query_name: Some(SmolStr::from(qname)),
        query_type: Some(qtype),
        recv_at: Instant::now(),
    };
    let packet = dns::build_query(id, qname, qtype, true).expect("build query");
    (ctx, packet)
}

fn make_authoritative_resolver(enable_recursion: bool) -> Resolver {
    let cfg = ResolverConfig {
        resolve_mode: "forwarder".to_string(),
        upstreams: vec!["203.0.113.53:53".to_string()],
        enable_recursion,
        ..ResolverConfig::default()
    };

    let mut resolver = Resolver::new(
        cfg,
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );
    resolver.configure_authoritative_zones(&[build_zone_example_com()]);
    resolver
}

fn has_aa(packet: &[u8]) -> bool {
    packet.len() >= 4 && (u16::from_be_bytes([packet[2], packet[3]]) & 0x0400) != 0
}

fn has_ra(packet: &[u8]) -> bool {
    packet.len() >= 4 && (u16::from_be_bytes([packet[2], packet[3]]) & 0x0080) != 0
}

fn answer_count(packet: &[u8]) -> u16 {
    if packet.len() < 8 {
        return 0;
    }
    u16::from_be_bytes([packet[6], packet[7]])
}

fn authority_count(packet: &[u8]) -> u16 {
    if packet.len() < 10 {
        return 0;
    }
    u16::from_be_bytes([packet[8], packet[9]])
}

fn additional_count(packet: &[u8]) -> u16 {
    if packet.len() < 12 {
        return 0;
    }
    u16::from_be_bytes([packet[10], packet[11]])
}

fn negative_ttl_secs(packet: &[u8]) -> Option<u64> {
    dns::extract_negative_cache_ttl(packet).map(|value| value.as_secs())
}

fn make_static_resolver(enable_recursion: bool, minimal_response: bool) -> Resolver {
    let cfg = ResolverConfig {
        resolve_mode: "forwarder".to_string(),
        upstreams: vec!["203.0.113.53:53".to_string()],
        enable_recursion,
        ..ResolverConfig::default()
    };

    let mut resolver = Resolver::new(
        cfg,
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        vec![
            StaticRecord {
                qname: "example.com".to_string(),
                qtype: "MX".to_string(),
                answer: "10 mail1.example.com".to_string(),
                ttl: 300,
            },
            StaticRecord {
                qname: "mail1.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "192.0.2.25".to_string(),
                ttl: 180,
            },
        ],
        Vec::new(),
    );
    resolver.configure_minimal_response(minimal_response);
    resolver
}

fn make_authoritative_mx_resolver(minimal_response: bool) -> Resolver {
    let mut resolver = make_authoritative_resolver(false);
    resolver.configure_authoritative_zones(&[AuthoritativeZone {
        name: "example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 2026051402,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 300,
        }),
        records: vec![
            StaticRecord {
                qname: "example.com".to_string(),
                qtype: "MX".to_string(),
                answer: "10 mail1.example.com".to_string(),
                ttl: 300,
            },
            StaticRecord {
                qname: "mail1.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "192.0.2.25".to_string(),
                ttl: 180,
            },
        ],
    }]);
    resolver.configure_minimal_response(minimal_response);
    resolver
}

fn make_authoritative_mx_out_of_zone_resolver(minimal_response: bool) -> Resolver {
    let mut resolver = make_authoritative_resolver(false);
    resolver.configure_authoritative_zones(&[AuthoritativeZone {
        name: "example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 2026052001,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 300,
        }),
        records: vec![StaticRecord {
            qname: "example.com".to_string(),
            qtype: "MX".to_string(),
            answer: "20 mail1.abc.com".to_string(),
            ttl: 300,
        }],
    }]);
    resolver.configure_minimal_response(minimal_response);
    resolver
}

fn make_static_ns_resolver(minimal_response: bool) -> Resolver {
    let cfg = ResolverConfig {
        resolve_mode: "forwarder".to_string(),
        upstreams: vec!["203.0.113.53:53".to_string()],
        enable_recursion: false,
        ..ResolverConfig::default()
    };

    let mut resolver = Resolver::new(
        cfg,
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        vec![
            StaticRecord {
                qname: "example.com".to_string(),
                qtype: "NS".to_string(),
                answer: "ns1.example.com".to_string(),
                ttl: 300,
            },
            StaticRecord {
                qname: "ns1.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "192.0.2.53".to_string(),
                ttl: 180,
            },
        ],
        Vec::new(),
    );
    resolver.configure_minimal_response(minimal_response);
    resolver
}

fn make_authoritative_ns_resolver(minimal_response: bool) -> Resolver {
    let mut resolver = make_authoritative_resolver(false);
    resolver.configure_authoritative_zones(&[AuthoritativeZone {
        name: "example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 2026051403,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 300,
        }),
        records: vec![
            StaticRecord {
                qname: "example.com".to_string(),
                qtype: "NS".to_string(),
                answer: "ns1.example.com".to_string(),
                ttl: 300,
            },
            StaticRecord {
                qname: "ns1.example.com".to_string(),
                qtype: "A".to_string(),
                answer: "192.0.2.53".to_string(),
                ttl: 180,
            },
        ],
    }]);
    resolver.configure_minimal_response(minimal_response);
    resolver
}

#[tokio::test]
async fn authoritative_only_returns_multi_rr_answer_with_aa() {
    let resolver = make_authoritative_resolver(false);
    let (ctx, request) = make_request(1001, "www.example.com", 1);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert!(matches!(resolved.source, ResolutionSource::Cache));
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(has_aa(&resolved.packet));
    assert!(!has_ra(&resolved.packet));

    assert_eq!(answer_count(&resolved.packet), 2);
}

#[tokio::test]
async fn authoritative_only_returns_nodata_for_existing_name_without_qtype() {
    let resolver = make_authoritative_resolver(false);
    let (ctx, request) = make_request(1002, "mail.example.com", 1);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(has_aa(&resolved.packet));

    assert_eq!(answer_count(&resolved.packet), 0);
    assert!(authority_count(&resolved.packet) >= 1);
}

#[tokio::test]
async fn authoritative_only_returns_nxdomain_for_nonexistent_name_in_zone() {
    let resolver = make_authoritative_resolver(false);
    let (ctx, request) = make_request(1003, "nosuch.example.com", 1);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(3));
    assert!(has_aa(&resolved.packet));

    assert_eq!(answer_count(&resolved.packet), 0);
    assert!(authority_count(&resolved.packet) >= 1);
}

#[tokio::test]
async fn authoritative_only_refuses_out_of_zone_queries_and_clears_ra() {
    let resolver = make_authoritative_resolver(false);
    let (ctx, request) = make_request(1004, "www.outside.net", 1);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(5));
    assert!(!has_aa(&resolved.packet));
    assert!(!has_ra(&resolved.packet));
}

#[tokio::test]
async fn global_disable_recursion_overrides_view_enable_recursion() {
    let mut resolver = make_authoritative_resolver(false);
    resolver.configure_views(&[DnsView {
        name: "auth".to_string(),
        query_mode: ViewQueryMode::GlobalFallback,
        enable_recursion: true,
        authoritative_zones: vec![build_zone_example_com()],
        ..DnsView::default()
    }]);

    let (ctx, request) = make_request(1005, "www.outside.net", 1);
    let resolved = resolver
        .resolve_with_view(&ctx, &request, Some("auth"))
        .await
        .expect("resolve");

    assert_eq!(dns::response_code(&resolved.packet), Some(5));
    assert!(!has_ra(&resolved.packet));
}

#[tokio::test]
async fn view_authoritative_hit_still_works_when_recursion_disabled_globally() {
    let mut resolver = make_authoritative_resolver(false);
    resolver.configure_views(&[DnsView {
        name: "auth".to_string(),
        query_mode: ViewQueryMode::GlobalFallback,
        enable_recursion: true,
        authoritative_zones: vec![build_zone_example_com()],
        ..DnsView::default()
    }]);

    let (ctx, request) = make_request(1006, "www.example.com", 1);
    let resolved = resolver
        .resolve_with_view(&ctx, &request, Some("auth"))
        .await
        .expect("resolve");

    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(has_aa(&resolved.packet));

    assert_eq!(answer_count(&resolved.packet), 2);
}

#[tokio::test]
async fn authoritative_zone_supports_literal_wildcard_owner_name() {
    let mut resolver = make_authoritative_resolver(false);
    resolver.configure_authoritative_zones(&[AuthoritativeZone {
        name: "example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 2026051401,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 300,
        }),
        records: vec![StaticRecord {
            qname: "*.example.com".to_string(),
            qtype: "A".to_string(),
            answer: "192.0.2.99".to_string(),
            ttl: 90,
        }],
    }]);

    let (ctx, request) = make_request(1007, "*.example.com", 1);
    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");

    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert!(has_aa(&resolved.packet));
    assert_eq!(answer_count(&resolved.packet), 1);
}

#[tokio::test]
async fn authoritative_zone_does_not_expand_wildcard_implicitly_for_random_label() {
    let mut resolver = make_authoritative_resolver(false);
    resolver.configure_authoritative_zones(&[AuthoritativeZone {
        name: "example.com".to_string(),
        default_ttl: 300,
        soa: Some(ZoneSoa {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 2026051401,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum_ttl: 300,
        }),
        records: vec![StaticRecord {
            qname: "*.example.com".to_string(),
            qtype: "A".to_string(),
            answer: "192.0.2.99".to_string(),
            ttl: 90,
        }],
    }]);

    let (ctx, request) = make_request(1008, "foo.example.com", 1);
    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");

    assert_eq!(dns::response_code(&resolved.packet), Some(3));
    assert!(has_aa(&resolved.packet));
    assert_eq!(negative_ttl_secs(&resolved.packet), Some(300));
}

#[tokio::test]
async fn authoritative_zone_prefers_longest_suffix_match_for_parent_child_zones() {
    let cfg = ResolverConfig {
        resolve_mode: "forwarder".to_string(),
        upstreams: vec!["203.0.113.53:53".to_string()],
        enable_recursion: false,
        ..ResolverConfig::default()
    };

    let mut resolver = Resolver::new(
        cfg,
        Arc::new(ResponseCache::default()),
        Arc::new(Metrics::new().expect("metrics")),
        Vec::new(),
        Vec::new(),
    );
    resolver.configure_authoritative_zones(&[
        build_child_zone_child_example_com(),
        build_parent_zone_example_com(),
    ]);

    let (hit_ctx, hit_request) = make_request(1009, "www.child.example.com", 1);
    let hit = resolver
        .resolve(&hit_ctx, &hit_request)
        .await
        .expect("resolve hit");
    assert_eq!(dns::response_code(&hit.packet), Some(0));
    assert!(has_aa(&hit.packet));
    assert_eq!(answer_count(&hit.packet), 1);

    let (miss_ctx, miss_request) = make_request(1010, "nosuch.child.example.com", 1);
    let miss = resolver
        .resolve(&miss_ctx, &miss_request)
        .await
        .expect("resolve miss");
    assert_eq!(dns::response_code(&miss.packet), Some(3));
    assert!(has_aa(&miss.packet));
    assert_eq!(negative_ttl_secs(&miss.packet), Some(777));
}

#[tokio::test]
async fn authoritative_negative_cache_is_partitioned_between_nodata_and_nxdomain() {
    let resolver = make_authoritative_resolver(false);

    let (nodata_ctx, nodata_request) = make_request(1011, "mail.example.com", 1);
    let nodata = resolver
        .resolve(&nodata_ctx, &nodata_request)
        .await
        .expect("resolve nodata");
    assert_eq!(dns::response_code(&nodata.packet), Some(0));
    assert_eq!(answer_count(&nodata.packet), 0);
    assert_eq!(negative_ttl_secs(&nodata.packet), Some(300));

    let (positive_ctx, positive_request) = make_request(1012, "mail.example.com", 16);
    let positive = resolver
        .resolve(&positive_ctx, &positive_request)
        .await
        .expect("resolve positive");
    assert_eq!(dns::response_code(&positive.packet), Some(0));
    assert_eq!(answer_count(&positive.packet), 1);

    let (nxdomain_ctx, nxdomain_request) = make_request(1013, "nosuch.example.com", 1);
    let nxdomain = resolver
        .resolve(&nxdomain_ctx, &nxdomain_request)
        .await
        .expect("resolve nxdomain");
    assert_eq!(dns::response_code(&nxdomain.packet), Some(3));
    assert_eq!(answer_count(&nxdomain.packet), 0);
    assert_eq!(negative_ttl_secs(&nxdomain.packet), Some(300));
}

#[tokio::test]
async fn minimal_response_enabled_keeps_static_mx_reply_without_address_additional() {
    let resolver = make_static_resolver(false, true);
    let (ctx, request) = make_request(1014, "example.com", 15);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert_eq!(additional_count(&resolved.packet), 0);
}

#[tokio::test]
async fn minimal_response_disabled_adds_address_records_for_mx_targets() {
    let resolver = make_static_resolver(false, false);
    let (ctx, request) = make_request(1015, "example.com", 15);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert!(additional_count(&resolved.packet) >= 1);
}

#[tokio::test]
async fn minimal_response_disabled_adds_address_records_for_authoritative_mx_targets() {
    let resolver = make_authoritative_mx_resolver(false);
    let (ctx, request) = make_request(1016, "example.com", 15);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert!(additional_count(&resolved.packet) >= 1);
}

#[tokio::test]
async fn authoritative_mx_out_of_zone_target_does_not_add_additional_addresses() {
    let resolver = make_authoritative_mx_out_of_zone_resolver(false);
    let (ctx, request) = make_request(10161, "example.com", 15);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert_eq!(additional_count(&resolved.packet), 0);
}

#[tokio::test]
async fn minimal_response_enabled_keeps_static_ns_reply_without_address_additional() {
    let resolver = make_static_ns_resolver(true);
    let (ctx, request) = make_request(1017, "example.com", 2);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert_eq!(additional_count(&resolved.packet), 0);
}

#[tokio::test]
async fn minimal_response_disabled_adds_address_records_for_static_ns_targets() {
    let resolver = make_static_ns_resolver(false);
    let (ctx, request) = make_request(1018, "example.com", 2);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert!(additional_count(&resolved.packet) >= 1);
}

#[tokio::test]
async fn minimal_response_enabled_keeps_authoritative_ns_reply_without_address_additional() {
    let resolver = make_authoritative_ns_resolver(true);
    let (ctx, request) = make_request(1019, "example.com", 2);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert_eq!(additional_count(&resolved.packet), 0);
}

#[tokio::test]
async fn minimal_response_disabled_adds_address_records_for_authoritative_ns_targets() {
    let resolver = make_authoritative_ns_resolver(false);
    let (ctx, request) = make_request(1020, "example.com", 2);

    let resolved = resolver.resolve(&ctx, &request).await.expect("resolve");
    assert_eq!(dns::response_code(&resolved.packet), Some(0));
    assert_eq!(answer_count(&resolved.packet), 1);
    assert!(additional_count(&resolved.packet) >= 1);
}
