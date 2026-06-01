use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cognidns::config::AppConfig;

fn temp_test_root() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("cognidns-view-data-files-{ts}"))
}

#[test]
fn loads_view_data_files_from_single_view_directory() {
    let root = temp_test_root();
    let config_dir = root.join("config");
    let view_dir = config_dir.join("test-view");
    fs::create_dir_all(&view_dir).expect("create test directories");

    let static_records = (1..=220)
        .map(|i| {
            format!(
                "{{ qname = \"s{i}.example.com\", qtype = \"A\", answer = \"10.0.0.{}\", ttl = 300 }}",
                (i % 250) + 1
            )
        })
        .collect::<Vec<_>>()
        .join(",\n  ");
    let static_raw = format!("static_records = [\n  {}\n]\n", static_records);
    fs::write(view_dir.join("static_records.toml"), static_raw).expect("write static_records.toml");

    let blocked_domains = (1..=180)
        .map(|i| format!("\"blocked-{i}.example.com\""))
        .collect::<Vec<_>>()
        .join(", ");
    let blocked_raw = format!("blocked_domains = [{}]\n", blocked_domains);
    fs::write(view_dir.join("blocked_domains.toml"), blocked_raw)
        .expect("write blocked_domains.toml");

    let zone_raw = r#"
name = "example.com"
default_ttl = 300

[soa]
mname = "ns1.example.com."
rname = "hostmaster.example.com."
serial = 2026051401
refresh = 3600
retry = 600
expire = 86400
minimum_ttl = 300

records = [
  { qname = "www.example.com", qtype = "A", answer = "1.1.1.1", ttl = 300 },
  { qname = "api.example.com", qtype = "A", answer = "1.1.1.2", ttl = 300 }
]
"#;
    fs::write(view_dir.join("example.com.toml"), zone_raw).expect("write zone file");

    let config_raw = r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
resolve_mode = "forwarder"
upstreams = ["1.1.1.1:53"]

[[views]]
name = "test-view"
query_mode = "global_fallback"
client_cidrs = []
enable_recursion = true
static_records_file = "config/test-view/static_records.toml"
blocked_domains_file = "config/test-view/blocked_domains.toml"
authoritative_zones_dir = "config/test-view"
"#;
    let config_path = config_dir.join("cognidns.toml");
    fs::write(&config_path, config_raw).expect("write config file");

    let cfg = AppConfig::load_or_default(
        config_path
            .to_str()
            .expect("config path should be valid UTF-8"),
    )
    .expect("load config with view data files");

    let view = cfg
        .views
        .iter()
        .find(|v| v.name == "test-view")
        .expect("test-view should exist");

    assert_eq!(view.static_records.len(), 220);
    assert_eq!(view.blocked_domains.len(), 180);
    assert!(view
        .authoritative_zones
        .iter()
        .any(|zone| zone.name.eq_ignore_ascii_case("example.com")));

    fs::remove_dir_all(&root).expect("cleanup temp test directory");
}

#[test]
fn loads_view_directory_while_skipping_helper_and_invalid_zone_files() {
    let root = temp_test_root();
    let config_dir = root.join("config");
    let view_dir = config_dir.join("edge-view");
    fs::create_dir_all(&view_dir).expect("create test directories");

    fs::write(
        view_dir.join("static_records.toml"),
        "static_records = [{ qname = \"edge.example.com\", qtype = \"A\", answer = \"10.0.0.8\", ttl = 60 }]\n",
    )
    .expect("write static_records.toml");
    fs::write(
        view_dir.join("blocked_domains.toml"),
        "blocked_domains = [\"blocked.edge.example.com\"]\n",
    )
    .expect("write blocked_domains.toml");
    fs::write(view_dir.join("broken-zone.toml"), "not valid toml = [")
        .expect("write broken zone file");

    let zone_raw = r#"
default_ttl = 120

[soa]
mname = "ns1.edge.example.com."
rname = "hostmaster.edge.example.com."
serial = 2026052501
refresh = 3600
retry = 600
expire = 86400
minimum_ttl = 120

[[records]]
qname = "www.edge.example.com"
qtype = "A"
answer = "192.0.2.55"
ttl = 120
"#;
    fs::write(view_dir.join("edge.example.com.toml"), zone_raw).expect("write valid zone file");

    let config_raw = r#"
udp_listen = "127.0.0.1:5300"
tcp_listen = "127.0.0.1:5300"
admin_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:19090"
resolve_mode = "forwarder"
upstreams = ["1.1.1.1:53"]

[[views]]
name = "edge-view"
query_mode = "global_fallback"
client_cidrs = []
enable_recursion = true
static_records_file = "config/edge-view/static_records.toml"
blocked_domains_file = "config/edge-view/blocked_domains.toml"
authoritative_zones_dir = "config/edge-view"
"#;
    let config_path = config_dir.join("cognidns.toml");
    fs::write(&config_path, config_raw).expect("write config file");

    let cfg = AppConfig::load_or_default(
        config_path
            .to_str()
            .expect("config path should be valid UTF-8"),
    )
    .expect("load config with mixed view directory files");

    let view = cfg
        .views
        .iter()
        .find(|v| v.name == "edge-view")
        .expect("edge-view should exist");

    assert_eq!(view.static_records.len(), 1);
    assert_eq!(view.blocked_domains, vec!["blocked.edge.example.com"]);
    assert_eq!(view.authoritative_zones.len(), 1);
    assert_eq!(view.authoritative_zones[0].name, "edge.example.com");
    assert_eq!(view.authoritative_zones[0].records.len(), 1);

    fs::remove_dir_all(&root).expect("cleanup temp test directory");
}
