use anyhow::Context;
use cognidns::control::{
    send_request, ControlCommand, ControlRequest, CODE_UNAUTHORIZED, CONTROL_PROTOCOL_VERSION,
};
use cognidns::ctl_cli;
use cognidns::ctl_config::CtlConfig;

use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    run_control_cli(&args).await
}

async fn run_control_cli(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("usage: cargo run --bin cognidns_ctl -- <start|stop|reload|stats|health|ready|version|top ...|cache ...> [--config path] [--server host:port] [--token value]");
    }
    let config_path = ctl_cli::option_value(args, "--config")
        .unwrap_or_else(|| "config/cognidns-ctl.toml".to_string());
    let cfg = CtlConfig::load_or_default(&config_path)
        .with_context(|| format!("failed to load control config from {}", config_path))?;

    let server = ctl_cli::option_value(args, "--server").unwrap_or(cfg.server.clone());
    let token = ctl_cli::option_value(args, "--token").or_else(|| cfg.token.clone());
    let command = match args[0].as_str() {
        "start" => ControlCommand::Start,
        "stop" => ControlCommand::Stop,
        "reload" => ControlCommand::Reload,
        "stats" => ControlCommand::Stats,
        "health" => ControlCommand::Health,
        "ready" => ControlCommand::Ready,
        "version" => ControlCommand::Version,
        "cache" => ctl_cli::parse_cache_command(args, "cargo run --bin cognidns_ctl --")?,
        "top" => ctl_cli::parse_top_command(args, "cargo run --bin cognidns_ctl --")?,
        other => anyhow::bail!("unknown ctl subcommand: {}", other),
    };

    let is_cache_export = matches!(command, ControlCommand::CacheExport);
    let is_top_queries = matches!(command, ControlCommand::TopQueries { .. });
    let is_top_clients = matches!(command, ControlCommand::TopClients { .. });

    let request = ControlRequest {
        version: CONTROL_PROTOCOL_VERSION,
        token,
        command,
    };
    let response = timeout(
        Duration::from_millis(cfg.timeout_ms),
        send_request(&server, &request),
    )
    .await
    .with_context(|| {
        format!(
            "control request timed out after {} ms when connecting to {}",
            cfg.timeout_ms, server
        )
    })??;

    if response.status.eq_ignore_ascii_case("error") {
        if response.code == CODE_UNAUTHORIZED {
            anyhow::bail!(
                "control command unauthorized: server={} config={} message={}. \
                 The running agent and ctl must use the same control_token. \
                 If the agent was started with another config file, rerun ctl with --config <same-config> \
                 or pass --token <same-token> explicitly.",
                server,
                config_path,
                response.message
            );
        }

        anyhow::bail!(
            "control command failed: server={} code={} message={}",
            server,
            response.code,
            response.message
        );
    }

    if is_cache_export {
        let output =
            ctl_cli::option_value(args, "--out").unwrap_or_else(|| "cache_dump.json".to_string());
        let Some(data) = response.data.as_ref() else {
            anyhow::bail!("cache export missing response data");
        };
        let payload = serde_json::to_vec_pretty(data)
            .with_context(|| "failed to serialize cache export payload")?;
        std::fs::write(&output, payload)
            .with_context(|| format!("failed to write cache dump to {}", output))?;
    }

    if is_top_queries || is_top_clients {
        ctl_cli::print_top_response(&response, is_top_queries);
        return Ok(());
    }

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
