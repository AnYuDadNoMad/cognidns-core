//! Shared control CLI parsing and rendering helpers.
use anyhow::Context;

use crate::control::{ControlCommand, ControlResponse};

pub fn parse_top_command(args: &[String], command_prefix: &str) -> anyhow::Result<ControlCommand> {
    if args.len() < 2 {
        anyhow::bail!("usage: {command_prefix} top <queries|clients> [--top N] [--window SECS]");
    }
    let n = option_value(args, "--top")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10);
    let window_secs = option_value(args, "--window")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);
    match args[1].as_str() {
        "queries" => Ok(ControlCommand::TopQueries { n, window_secs }),
        "clients" => Ok(ControlCommand::TopClients { n, window_secs }),
        other => anyhow::bail!("unknown top subcommand: {}", other),
    }
}

pub fn parse_cache_command(
    args: &[String],
    command_prefix: &str,
) -> anyhow::Result<ControlCommand> {
    if args.len() < 2 {
        anyhow::bail!("usage: {command_prefix} cache <freeze|clear|export|import> ...");
    }

    match args[1].as_str() {
        "freeze" => {
            if args.len() < 4 {
                anyhow::bail!(
                    "usage: {command_prefix} cache freeze all <on|off> | domain <name> <on|off>"
                );
            }
            match args[2].as_str() {
                "all" => {
                    let enabled = parse_on_off(&args[3])?;
                    Ok(ControlCommand::CacheFreezeAll { enabled })
                }
                "domain" => {
                    if args.len() < 5 {
                        anyhow::bail!(
                            "usage: {command_prefix} cache freeze domain <name> <on|off>"
                        );
                    }
                    let enabled = parse_on_off(&args[4])?;
                    Ok(ControlCommand::CacheFreezeDomain {
                        domain: args[3].clone(),
                        enabled,
                    })
                }
                other => anyhow::bail!("unknown cache freeze target: {}", other),
            }
        }
        "clear" => {
            if args.len() < 3 {
                return Ok(ControlCommand::CacheClearAll);
            }
            match args[2].as_str() {
                "all" => Ok(ControlCommand::CacheClearAll),
                "domain" => {
                    if args.len() < 4 {
                        anyhow::bail!("usage: {command_prefix} cache clear domain <name>");
                    }
                    Ok(ControlCommand::CacheClearDomain {
                        domain: args[3].clone(),
                    })
                }
                other => Ok(ControlCommand::CacheClearDomain {
                    domain: other.to_string(),
                }),
            }
        }
        "export" => Ok(ControlCommand::CacheExport),
        "import" => {
            let input = option_value(args, "--in").unwrap_or_else(|| "cache_dump.json".to_string());
            let raw = std::fs::read_to_string(&input)
                .with_context(|| format!("failed to read cache dump from {}", input))?;
            let dump = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse cache dump json from {}", input))?;
            Ok(ControlCommand::CacheImport { dump })
        }
        other => anyhow::bail!("unknown cache subcommand: {}", other),
    }
}

pub fn print_top_response(response: &ControlResponse, is_queries: bool) {
    let data = match response.data.as_ref() {
        Some(d) => d,
        None => {
            println!("(no data)");
            return;
        }
    };
    let enabled = data
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let window = data
        .get("window_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let entries = match data.get("entries").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            println!("(empty)");
            return;
        }
    };

    if !enabled {
        println!("TOP N stats feature is disabled (topn_stats_enabled=false).");
        return;
    }

    if is_queries {
        println!("TOP {} QUERIES (last {}s)", entries.len(), window);
        println!("{:-<86}", "");
        println!(
            "{:<4} {:<38} {:>7} {:>9} {:>11}",
            "#", "Domain", "Count", "Success", "Success%"
        );
        println!("{:-<86}", "");
        for (i, entry) in entries.iter().enumerate() {
            let domain = entry.get("domain").and_then(|v| v.as_str()).unwrap_or("-");
            let count = entry.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let success_count = entry
                .get("success_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let success_rate = entry
                .get("success_rate")
                .and_then(|v| v.as_f64())
                .unwrap_or_else(|| {
                    if count == 0 {
                        0.0
                    } else {
                        success_count as f64 / count as f64
                    }
                });
            println!(
                "{:<4} {:<38} {:>7} {:>9} {:>10.2}%",
                i + 1,
                domain,
                count,
                success_count,
                success_rate * 100.0
            );
        }
    } else {
        println!("TOP {} CLIENTS (last {}s)", entries.len(), window);
        println!("{:-<52}", "");
        println!("{:<4} {:<40} {:>6}", "#", "Client IP", "Count");
        println!("{:-<52}", "");
        for (i, entry) in entries.iter().enumerate() {
            let client = entry.get("client").and_then(|v| v.as_str()).unwrap_or("-");
            let count = entry.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("{:<4} {:<40} {:>6}", i + 1, client, count);
        }
    }
    if is_queries {
        println!("{:-<86}", "");
    } else {
        println!("{:-<52}", "");
    }
}

pub fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn parse_on_off(value: &str) -> anyhow::Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        other => anyhow::bail!("expected on/off, got: {}", other),
    }
}
