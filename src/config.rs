//! `~/.config/lagblame/config.toml` (every key optional).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Apps to watch: process name (comm), executable name or argv[0], case-insensitive.
    pub apps: Vec<String>,
    /// Watched only while one of `apps` runs (voice chat, launchers): no session of their own.
    pub companions: Vec<String>,
    /// Userspace VPN/tunnel processes, watched too so their stalls can be blamed.
    pub tunnel_procs: Vec<String>,
    pub thresholds: Thresholds,
    pub probe: Probe,
    pub record: Record,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Runqueue wait that becomes an event (ms).
    pub runqueue_ms: f64,
    /// Gap on a busy flow that becomes an event (ms).
    pub gap_ms: f64,
    /// Socket -> app pickup delay that becomes an event (ms).
    pub pickup_ms: f64,
    /// NIC -> socket delay that becomes an event (ms).
    pub stack_ms: f64,
    /// NET_RX/NET_TX softirq latency that becomes an event (ms).
    pub softirq_ms: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Probe {
    /// "builtin" (ICMP ping sockets), "file" (read `file`), or "off".
    pub mode: String,
    /// Host for the internet probe. The gateway comes from the routing table.
    pub wan_target: String,
    /// JSON written by another prober, with `gw` and `wan` (ms) and optional `loss`.
    pub file: Option<String>,
    pub interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Record {
    pub dir: Option<String>,
    pub retention_days: u64,
    pub max_mb: u64,
    /// Close a session this long after the last watched app exits.
    pub linger_s: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            apps: vec![],
            companions: vec![],
            tunnel_procs: [
                "mullvad-daemon",
                "wireguard-go",
                "gotatun",
                "boringtun",
                "boringtun-cli",
                "openvpn",
                "tailscaled",
                "nebula",
                "zerotier-one",
            ]
            .map(String::from)
            .to_vec(),
            thresholds: Thresholds::default(),
            probe: Probe::default(),
            record: Record::default(),
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            runqueue_ms: 4.0,
            gap_ms: 50.0,
            pickup_ms: 4.0,
            stack_ms: 2.0,
            softirq_ms: 2.0,
        }
    }
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            mode: "builtin".into(),
            wan_target: "1.1.1.1".into(),
            file: None,
            interval_ms: 1000,
        }
    }
}

impl Default for Record {
    fn default() -> Self {
        Self {
            dir: None,
            retention_days: 7,
            max_mb: 2048,
            linger_s: 30,
        }
    }
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(p),
    }
}

pub fn config_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("lagblame/config.toml")
}

pub fn state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"))
        .join("lagblame")
}

impl Config {
    pub fn load(path: Option<&str>) -> Result<Self> {
        let p = path.map(expand).unwrap_or_else(config_path);
        match std::fs::read_to_string(&p) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && path.is_none() => {
                Ok(Self::default())
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    pub fn session_dir(&self) -> PathBuf {
        self.record
            .dir
            .as_deref()
            .map(expand)
            .unwrap_or_else(|| state_dir().join("sessions"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_config_keeps_defaults() {
        let c: Config = toml::from_str("apps = [\"cs2\"]\n[thresholds]\ngap_ms = 30\n").unwrap();
        assert_eq!(c.apps, vec!["cs2"]);
        assert_eq!(c.thresholds.gap_ms, 30.0);
        assert_eq!(c.thresholds.runqueue_ms, 4.0);
        assert!(c.tunnel_procs.iter().any(|p| p == "wireguard-go"));
        assert_eq!(c.probe.mode, "builtin");
    }
}
