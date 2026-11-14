//! What one tick / one spike looks like, live and on disk (JSON Lines).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

fn is_zero(v: &f64) -> bool {
    *v == 0.0
}
fn is_zero_u(v: &u64) -> bool {
    *v == 0
}

/// Round to 2 decimals so the JSON stays small.
pub fn r2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AppTick {
    pub name: String,
    /// "app" or "tunnel"
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub pids: u32,
    /// runqueue: wakeups measured, avg / p99 / max wait (ms)
    #[serde(default, skip_serializing_if = "is_zero_u")]
    pub rq_n: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rq_avg: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rq_p99: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rq_max: f64,
    /// UDP packets/s and kbit/s
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tx_pps: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tx_kbps: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rx_pps: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rx_kbps: f64,
    /// longest gap between packets on a busy flow (ms)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tx_gap: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rx_gap: f64,
    /// NIC -> socket (ms)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub stack_avg: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub stack_max: f64,
    /// in-kernel tunnel decap (ms)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tun_max: f64,
    /// share of received packets that came through a tunnel interface (0..1)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub via_tun: f64,
    /// socket -> app (ms)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pick_avg: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pick_max: f64,
    #[serde(default, skip_serializing_if = "is_zero_u")]
    pub rcvbuf_drops: u64,
    #[serde(default, skip_serializing_if = "is_zero_u")]
    pub drops: u64,
    #[serde(default, skip_serializing_if = "is_zero_u")]
    pub retrans: u64,
    /// TCP smoothed RTT (ms)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rtt_avg: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rtt_max: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetTick {
    /// RTT to the default gateway (ms): LAN / Wi-Fi
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gw: Option<f64>,
    /// RTT to the internet target (ms)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan: Option<f64>,
    /// probe loss in the last second (0..1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss: Option<f64>,
    /// NET_RX softirq: raise -> run latency, max / avg, and longest run (ms)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rx_sirq_max: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rx_sirq_avg: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rx_sirq_run: f64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tx_sirq_max: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Tick {
    /// unix time (s)
    pub t: f64,
    pub dt: f64,
    #[serde(default)]
    pub apps: Vec<AppTick>,
    #[serde(default)]
    pub net: NetTick,
    /// kernel skb drops by reason (system-wide, noise reasons included)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub drops: BTreeMap<String, u64>,
}

impl Tick {
    pub fn app(&self, name: &str) -> Option<&AppTick> {
        self.apps.iter().find(|a| a.name == name)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Ev {
    pub t: f64,
    /// rq, tx_gap, rx_gap, pickup, stack, tunnel, softirq, rcvbuf_drop, drop, retrans
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default)]
    pub ms: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<u32>,
    /// rq: what ran on the CPU just before ("comm[pid]")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// remote "addr:port"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Meta {
    pub version: String,
    pub host: String,
    pub kernel: String,
    pub started: f64,
    pub apps: Vec<String>,
    pub tunnel_procs: Vec<String>,
    #[serde(default)]
    pub ifaces: BTreeMap<String, String>,
    #[serde(default)]
    pub missing_probes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Mark {
    pub t: f64,
    #[serde(default)]
    pub note: String,
}

/// One line of a session file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "k", rename_all = "lowercase")]
pub enum Line {
    Meta(Meta),
    Tick(Tick),
    Ev(Ev),
    Mark(Mark),
}
