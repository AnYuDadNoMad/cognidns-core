//! Control CLI configuration model and loader.
use std::fs;
use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct CtlConfig {
    pub server: String,
    pub token: Option<String>,
    pub timeout_ms: u64,
    pub output: String,
}

impl Default for CtlConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:19090".to_string(),
            token: None,
            timeout_ms: 5_000,
            output: "json".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RawCtlConfig {
    server: Option<String>,
    token: Option<String>,
    timeout_ms: Option<u64>,
    output: Option<String>,
    control_listen: Option<String>,
    control_token: Option<String>,
}

impl CtlConfig {
    pub fn load_or_default(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read control config file: {path}"))?;
        let parsed: RawCtlConfig = toml::from_str(&raw)
            .with_context(|| format!("failed to parse control config file: {path}"))?;

        let mut cfg = Self::default();
        if let Some(server) = parsed.server.or(parsed.control_listen) {
            cfg.server = server;
        }
        cfg.token = parsed.token.or(parsed.control_token);
        if let Some(timeout_ms) = parsed.timeout_ms {
            cfg.timeout_ms = timeout_ms;
        }
        if let Some(output) = parsed.output {
            cfg.output = output;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.trim().is_empty() {
            anyhow::bail!("control server must not be empty");
        }
        if self.timeout_ms == 0 {
            anyhow::bail!("timeout_ms must be > 0");
        }
        match self.output.as_str() {
            "json" | "table" => Ok(()),
            other => anyhow::bail!("invalid output: {other} (expected: json|table)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CtlConfig;

    #[test]
    fn default_values_are_stable() {
        let cfg = CtlConfig::default();
        assert_eq!(cfg.server, "127.0.0.1:19090");
        assert_eq!(cfg.timeout_ms, 5000);
        assert_eq!(cfg.output, "json");
        assert!(cfg.token.is_none());
    }

    #[test]
    fn load_or_default_recovers_legacy_control_fields() {
        let path = std::env::temp_dir().join("cognidns_ctl_legacy.toml");
        std::fs::write(
            &path,
            "control_listen = \"127.0.0.1:20001\"\ncontrol_token = \"abc\"\n",
        )
        .expect("write");

        let cfg = CtlConfig::load_or_default(path.to_str().expect("path")).expect("load");
        assert_eq!(cfg.server, "127.0.0.1:20001");
        assert_eq!(cfg.token.as_deref(), Some("abc"));

        let _ = std::fs::remove_file(path);
    }
}
