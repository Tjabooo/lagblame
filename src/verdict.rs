//! "What happened at 21:43:10": ranks the layers that could explain a spike.

use std::fmt::Write as _;

use serde::Serialize;

use crate::model::{AppTick, Ev, Tick};
use crate::session::fmt_time;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Cpu,
    App,
    Kernel,
    Tunnel,
    Lan,
    Internet,
    Server,
}

impl Layer {
    pub fn title(self) -> &'static str {
        match self {
            Layer::Cpu => "CPU scheduler",
            Layer::App => "the app itself",
            Layer::Kernel => "kernel network stack",
            Layer::Tunnel => "VPN tunnel",
            Layer::Lan => "LAN / Wi-Fi",
            Layer::Internet => "internet / ISP",
            Layer::Server => "server (or the route to it)",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Cause {
    pub layer: Layer,
    pub score: f64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub at: f64,
    pub app: Option<String>,
    pub causes: Vec<Cause>,
    /// numbers that were looked at, for the "everything else was fine" line
    pub clean: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub before: f64,
    pub after: f64,
    pub gap_ms: f64,
    pub rq_ms: f64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            before: 3.0,
            after: 1.0,
            gap_ms: 50.0,
            rq_ms: 4.0,
        }
    }
}

fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some(v[v.len() / 2])
}

/// "0.42" / "<0.01" for the "checked" lines
fn small(v: f64) -> String {
    if v < 0.01 {
        "<0.01".into()
    } else {
        format!("{v:.2}")
    }
}

fn maxf(it: impl Iterator<Item = f64>) -> f64 {
    it.fold(0.0, f64::max)
}

/// Drop reasons that happen all day and say nothing about lag.
pub fn noise_reason(r: &str) -> bool {
    matches!(
        r,
        "NOT_SPECIFIED"
            | "NO_SOCKET"
            | "SOCKET_FILTER"
            | "UNHANDLED_PROTO"
            | "OTHERHOST"
            | "PKT_TOO_SMALL"
            | "IP_NOPROTO"
    ) || r.starts_with("reason_")
}

struct Sig<'a> {
    w: Vec<&'a Tick>,
    base: Vec<&'a Tick>,
}

impl<'a> Sig<'a> {
    fn app_ticks(&self, name: &str) -> Vec<&'a AppTick> {
        self.w.iter().filter_map(|t| t.app(name)).collect()
    }
    fn base_app(&self, name: &str) -> Vec<&'a AppTick> {
        self.base.iter().filter_map(|t| t.app(name)).collect()
    }
}

/// Pick the app to explain: the busiest watched app in the window.
fn pick_app(w: &[&Tick]) -> Option<String> {
    let mut best: Option<(f64, String)> = None;
    for t in w {
        for a in t.apps.iter().filter(|a| a.role != "tunnel") {
            let score = a.rx_gap + a.tx_gap + a.rq_max + (a.rx_pps + a.tx_pps) * 0.01;
            if best.as_ref().is_none_or(|b| score > b.0) {
                best = Some((score, a.name.clone()));
            }
        }
    }
    best.map(|b| b.1)
}

pub fn explain(ticks: &[Tick], evs: &[Ev], at: f64, app: Option<&str>, o: &Opts) -> Verdict {
    let (a0, a1) = (at - o.before, at + o.after);
    let sig = Sig {
        w: ticks
            .iter()
            .filter(|t| t.t >= a0 && t.t - t.dt <= a1)
            .collect(),
        base: ticks
            .iter()
            .filter(|t| t.t < a0 && t.t >= a0 - 60.0)
            .collect(),
    };
    let wev: Vec<&Ev> = evs.iter().filter(|e| e.t >= a0 && e.t <= a1).collect();
    let app = app.map(String::from).or_else(|| pick_app(&sig.w));
    let mut causes: Vec<Cause> = vec![];
    let mut clean: Vec<String> = vec![];
    let mut add = |layer: Layer, score: f64, line: String| {
        if let Some(c) = causes.iter_mut().find(|c| c.layer == layer) {
            c.score += score;
            c.evidence.push(line);
        } else {
            causes.push(Cause {
                layer,
                score,
                evidence: vec![line],
            });
        }
    };

    if sig.w.is_empty() {
        return Verdict {
            at,
            app,
            causes: vec![],
            clean: vec![],
            summary: format!("No data recorded around {}.", fmt_time(at)),
        };
    }

    // ---------------------------------------------------------- the app's own numbers
    if let Some(name) = app.as_deref() {
        let at_ = sig.app_ticks(name);
        let ev_of = |k: &'static str| {
            wev.iter()
                .filter(move |e| e.kind == k && e.app.as_deref() == Some(name))
        };
        let rx_gap = maxf(
            at_.iter()
                .map(|a| a.rx_gap)
                .chain(ev_of("rx_gap").map(|e| e.ms)),
        );
        let tx_gap = maxf(
            at_.iter()
                .map(|a| a.tx_gap)
                .chain(ev_of("tx_gap").map(|e| e.ms)),
        );
        let rq_max = maxf(
            at_.iter()
                .map(|a| a.rq_max)
                .chain(ev_of("rq").map(|e| e.ms)),
        );
        let via_tun = maxf(at_.iter().map(|a| a.via_tun));
        let base_pps = median(
            sig.base_app(name)
                .iter()
                .map(|a| a.rx_pps)
                .filter(|p| *p > 0.0)
                .collect(),
        )
        .or_else(|| median(at_.iter().map(|a| a.rx_pps).filter(|p| *p > 0.0).collect()));
        let expected_gap = base_pps.map(|p| 1000.0 / p).unwrap_or(0.0);
        let gap_floor = o.gap_ms.max(expected_gap * 3.0);
        let rx_bad = rx_gap >= gap_floor;
        let tx_bad = tx_gap >= gap_floor;
        let peer = ev_of("rx_gap")
            .chain(ev_of("tx_gap"))
            .find_map(|e| e.peer.clone());

        // CPU: the app's threads waited for a CPU
        let mut rq_evs: Vec<&&Ev> = ev_of("rq").collect();
        rq_evs.sort_by(|a, b| b.ms.total_cmp(&a.ms));
        if rq_max >= o.rq_ms {
            let mut score = (rq_max * 4.0).min(100.0);
            if tx_bad && rq_max >= tx_gap * 0.5 {
                score += 30.0;
            }
            let mut line = format!("{name}: a thread waited {rq_max:.1} ms for a CPU");
            if let Some(e) = rq_evs.first() {
                line = format!(
                    "{name}: thread `{}`{} waited {:.1} ms for a CPU{}{}",
                    e.thread.as_deref().unwrap_or("?"),
                    e.tid.map(|t| format!(" [{t}]")).unwrap_or_default(),
                    e.ms,
                    e.cpu.map(|c| format!(" (cpu {c}")).unwrap_or_default(),
                    e.by.as_deref()
                        .map(|b| format!(", after {b})"))
                        .unwrap_or_else(|| ")".into()),
                );
            }
            add(Layer::Cpu, score, line);
            let others: Vec<String> = rq_evs
                .iter()
                .skip(1)
                .take(3)
                .map(|e| format!("`{}` {:.1} ms", e.thread.as_deref().unwrap_or("?"), e.ms))
                .collect();
            if !others.is_empty() {
                add(
                    Layer::Cpu,
                    0.0,
                    format!("also waiting: {}", others.join(", ")),
                );
            }
        } else {
            clean.push(format!("CPU wait ≤ {rq_max:.1} ms"));
        }

        // the app stopped sending without being starved
        if tx_bad && rq_max < tx_gap * 0.25 {
            add(
                Layer::App,
                (tx_gap / 2.0).min(100.0),
                format!(
                    "{name} sent nothing for {tx_gap:.0} ms while its threads got a CPU quickly (max wait {rq_max:.1} ms): \
                     the app itself stalled (frame hitch, shader compile, disk, GC)"
                ),
            );
        }
        let pick = maxf(
            at_.iter()
                .map(|a| a.pick_max)
                .chain(ev_of("pickup").map(|e| e.ms)),
        );
        if pick >= 8.0 {
            if rq_max >= pick * 0.5 {
                add(
                    Layer::Cpu,
                    10.0,
                    format!(
                        "{name} left packets unread for {pick:.1} ms (its threads were waiting for a CPU)"
                    ),
                );
            } else {
                add(
                    Layer::App,
                    (pick / 2.0).min(60.0),
                    format!("{name} left received packets unread for {pick:.1} ms"),
                );
            }
        }
        let rcvbuf: u64 = at_.iter().map(|a| a.rcvbuf_drops).sum();
        if rcvbuf > 0 {
            let layer = if rq_max >= o.rq_ms {
                Layer::Cpu
            } else {
                Layer::App
            };
            add(
                layer,
                40.0,
                format!(
                    "{name}'s socket buffer overflowed: {rcvbuf} packet(s) dropped (read too slowly)"
                ),
            );
        }

        // kernel
        let stack = maxf(
            at_.iter()
                .map(|a| a.stack_max)
                .chain(ev_of("stack").map(|e| e.ms)),
        );
        if stack >= 2.0 {
            add(
                Layer::Kernel,
                (stack * 8.0).min(100.0),
                format!("packets took {stack:.1} ms from the NIC to {name}'s socket"),
            );
        } else if stack > 0.0 {
            clean.push(format!("NIC→socket ≤ {} ms", small(stack)));
        }
        let mut reasons: Vec<String> = ev_of("drop")
            .filter_map(|e| e.reason.clone())
            .filter(|r| !noise_reason(r))
            .collect();
        reasons.sort();
        reasons.dedup();
        let drops: u64 = at_.iter().map(|a| a.drops).sum();
        if drops > 0 && !reasons.is_empty() {
            add(
                Layer::Kernel,
                (20.0 * drops as f64).min(60.0),
                format!(
                    "kernel dropped {drops} of {name}'s packets ({})",
                    reasons.join(", ")
                ),
            );
        }

        // tunnel
        let tun = maxf(
            at_.iter()
                .map(|a| a.tun_max)
                .chain(ev_of("tunnel").map(|e| e.ms)),
        );
        if tun >= 2.0 {
            add(
                Layer::Tunnel,
                (tun * 8.0).min(100.0),
                format!("in-kernel tunnel decryption took {tun:.1} ms"),
            );
        }
        if via_tun >= 0.2 {
            let tnames: Vec<String> = {
                let mut v: Vec<String> = sig
                    .w
                    .iter()
                    .flat_map(|t| t.apps.iter())
                    .filter(|a| a.role == "tunnel")
                    .map(|a| a.name.clone())
                    .collect();
                v.sort();
                v.dedup();
                v
            };
            for tn in tnames {
                let tt = sig.app_ticks(&tn);
                let trq = maxf(
                    tt.iter().map(|a| a.rq_max).chain(
                        wev.iter()
                            .filter(|e| e.kind == "rq" && e.app.as_deref() == Some(&tn))
                            .map(|e| e.ms),
                    ),
                );
                let tpick = maxf(tt.iter().map(|a| a.pick_max));
                let tgap = maxf(tt.iter().map(|a| a.rx_gap));
                let trx = maxf(tt.iter().map(|a| a.rx_pps));
                if trq >= o.rq_ms {
                    add(
                        Layer::Tunnel,
                        (trq * 4.0).min(100.0),
                        format!("tunnel process `{tn}` waited {trq:.1} ms for a CPU"),
                    );
                }
                if tpick >= 4.0 {
                    add(
                        Layer::Tunnel,
                        (tpick * 3.0).min(80.0),
                        format!("`{tn}` left tunnel packets unread for {tpick:.1} ms"),
                    );
                }
                if rx_bad && trx > 0.0 && tgap < rx_gap * 0.5 {
                    add(
                        Layer::Tunnel,
                        50.0,
                        format!(
                            "packets kept reaching `{tn}` (largest gap {tgap:.0} ms) while {name} got nothing for {rx_gap:.0} ms"
                        ),
                    );
                }
            }
        }

        // TCP
        let retrans: u64 = at_.iter().map(|a| a.retrans).sum();
        if retrans > 0 {
            let rtt = maxf(at_.iter().map(|a| a.rtt_max));
            add(
                Layer::Internet,
                (10.0 * retrans as f64).min(50.0),
                format!("{retrans} TCP retransmit(s), RTT up to {rtt:.0} ms"),
            );
        }

        // server: data stopped while the local side looked fine
        if rx_bad {
            let from = peer.map(|p| format!(" from {p}")).unwrap_or_default();
            add(
                Layer::Server,
                (rx_gap / 2.0).min(100.0),
                format!(
                    "nothing arrived{from} for {rx_gap:.0} ms (normally every {expected_gap:.0} ms)"
                ),
            );
        } else if rx_gap > 0.0 {
            clean.push(format!("receive gap ≤ {rx_gap:.0} ms"));
        }
    }

    // ---------------------------------------------------------- softirq (system-wide)
    let sirq = maxf(
        sig.w
            .iter()
            .map(|t| t.net.rx_sirq_max)
            .chain(wev.iter().filter(|e| e.kind == "softirq").map(|e| e.ms)),
    );
    if sirq >= 2.0 {
        let who = wev
            .iter()
            .filter(|e| e.kind == "softirq")
            .max_by(|a, b| a.ms.total_cmp(&b.ms))
            .and_then(|e| e.thread.clone())
            .map(|t| format!(" (CPU was busy with `{t}`)"))
            .unwrap_or_default();
        add(
            Layer::Kernel,
            (sirq * 8.0).min(100.0),
            format!("network softirq ran {sirq:.1} ms late{who}"),
        );
    } else {
        clean.push(format!("softirq ≤ {} ms", small(sirq)));
    }

    // ---------------------------------------------------------- LAN and internet probes
    let base_gw = median(sig.base.iter().filter_map(|t| t.net.gw).collect());
    let base_wan = median(sig.base.iter().filter_map(|t| t.net.wan).collect());
    let gw = sig
        .w
        .iter()
        .filter_map(|t| t.net.gw)
        .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
    let wan = sig
        .w
        .iter()
        .filter_map(|t| t.net.wan)
        .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
    let loss = sig.w.iter().filter_map(|t| t.net.loss).fold(0.0, f64::max);
    let mut lan_bad = false;
    match (gw, base_gw) {
        (Some(g), Some(b)) if g - b >= 5.0 && g >= b * 3.0 => {
            lan_bad = true;
            add(
                Layer::Lan,
                ((g - b) * 2.0).min(100.0),
                format!("gateway ping rose to {g:.1} ms (normally {b:.1} ms)"),
            );
        }
        (None, Some(b)) => {
            lan_bad = true;
            add(
                Layer::Lan,
                60.0,
                format!("gateway stopped answering pings (normally {b:.1} ms)"),
            );
        }
        (Some(g), _) => clean.push(format!("LAN {g:.1} ms")),
        _ => {}
    }
    match (wan, base_wan) {
        (Some(w), Some(b)) if !lan_bad && w - b >= 15.0 && w >= b * 1.5 => {
            add(
                Layer::Internet,
                (w - b).min(100.0),
                format!("internet ping rose to {w:.0} ms (normally {b:.0} ms)"),
            );
        }
        (None, Some(b)) if !lan_bad => {
            add(
                Layer::Internet,
                60.0,
                format!("internet probe stopped answering (normally {b:.0} ms)"),
            );
        }
        (Some(w), _) => clean.push(format!("internet {w:.0} ms")),
        _ => {}
    }
    if loss >= 0.2 && !lan_bad {
        add(
            Layer::Internet,
            20.0,
            format!("probe loss {:.0} %", loss * 100.0),
        );
    }

    // a quiet server only counts if nothing local explains the gap
    let local = causes
        .iter()
        .filter(|c| c.layer != Layer::Server)
        .map(|c| c.score)
        .fold(0.0, f64::max);
    if let Some(s) = causes.iter_mut().find(|c| c.layer == Layer::Server) {
        if local >= 40.0 {
            s.score *= 0.3;
        } else if !clean.is_empty() {
            s.evidence
                .push(format!("your side looked clean: {}", clean.join(", ")));
        }
    }

    causes.retain(|c| c.score >= 10.0);
    causes.sort_by(|a, b| b.score.total_cmp(&a.score));
    for c in &mut causes {
        c.score = c.score.min(100.0).round();
    }
    let summary = match causes.first() {
        Some(c) => format!("Most likely: {} — {}", c.layer.title(), c.evidence[0]),
        None => format!(
            "Nothing stood out around {}{}. If it felt laggy, look at frame pacing / GPU, or the server's own simulation.",
            fmt_time(at),
            if clean.is_empty() {
                String::new()
            } else {
                format!(" ({})", clean.join(", "))
            }
        ),
    };
    Verdict {
        at,
        app,
        causes,
        clean,
        summary,
    }
}

pub fn render(v: &Verdict) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{}{}",
        fmt_time(v.at),
        v.app
            .as_deref()
            .map(|a| format!("  ·  {a}"))
            .unwrap_or_default()
    );
    let _ = writeln!(s, "{}", v.summary);
    for c in &v.causes {
        let _ = writeln!(s, "\n{} ({:.0})", c.layer.title(), c.score);
        for e in &c.evidence {
            let _ = writeln!(s, "  · {e}");
        }
    }
    s
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Spike {
    pub t: f64,
    pub app: String,
    pub what: String,
    pub ms: f64,
}

/// Moments worth a look: long receive/send gaps on busy flows and long CPU waits.
pub fn spikes(ticks: &[Tick], evs: &[Ev], o: &Opts) -> Vec<Spike> {
    let mut out: Vec<Spike> = vec![];
    let mut pps: std::collections::HashMap<&str, f64> = Default::default();
    for t in ticks {
        for a in t.apps.iter().filter(|a| a.role != "tunnel") {
            let p = pps.entry(a.name.as_str()).or_insert(a.rx_pps);
            let floor = o.gap_ms.max(if *p > 0.0 { 3000.0 / *p } else { 0.0 });
            *p = *p * 0.9 + a.rx_pps * 0.1;
            let mut push = |what: &str, ms: f64, kind: &str| {
                // exact time from the matching event when there is one
                let te = evs
                    .iter()
                    .filter(|e| {
                        e.kind == kind
                            && e.app.as_deref() == Some(&a.name)
                            && e.t <= t.t
                            && e.t >= t.t - t.dt - 0.05
                    })
                    .max_by(|x, y| x.ms.total_cmp(&y.ms))
                    .map(|e| e.t)
                    .unwrap_or(t.t);
                out.push(Spike {
                    t: te,
                    app: a.name.clone(),
                    what: what.into(),
                    ms,
                });
            };
            if a.rx_gap >= floor {
                push("recv gap", a.rx_gap, "rx_gap");
            }
            if a.tx_gap >= floor {
                push("send gap", a.tx_gap, "tx_gap");
            }
            if a.rq_max >= (o.rq_ms * 4.0).max(16.0) {
                push("CPU wait", a.rq_max, "rq");
            }
        }
    }
    out.sort_by(|a, b| a.t.total_cmp(&b.t));
    // one spike per app per second (keep the biggest)
    let mut merged: Vec<Spike> = vec![];
    for s in out {
        if let Some(last) = merged.iter_mut().rev().find(|m| m.app == s.app)
            && s.t - last.t < 1.0
        {
            // keep the biggest, but remember every kind of gap in the label
            let mut whats: Vec<String> = last.what.split(" + ").map(String::from).collect();
            if !whats.contains(&s.what) {
                whats.push(s.what.clone());
            }
            whats.sort();
            if s.ms > last.ms {
                last.t = s.t;
                last.ms = s.ms;
            }
            last.what = whats.join(" + ");
            continue;
        }
        merged.push(s);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str) -> AppTick {
        AppTick {
            name: name.into(),
            role: "app".into(),
            pids: 1,
            rx_pps: 64.0,
            tx_pps: 64.0,
            rx_gap: 17.0,
            tx_gap: 16.0,
            rq_max: 0.3,
            ..Default::default()
        }
    }

    /// 60 s of a healthy 64 Hz game, then whatever `spike` does to the tick at t=1060.
    fn session(spike: impl Fn(&mut Tick)) -> Vec<Tick> {
        let mut v = vec![];
        for i in 0..320 {
            let t = 1000.0 + i as f64 * 0.25;
            let mut tick = Tick {
                t,
                dt: 0.25,
                apps: vec![app("cs2")],
                ..Default::default()
            };
            tick.net.gw = Some(0.7);
            tick.net.wan = Some(12.0);
            tick.net.rx_sirq_max = 0.05;
            if (t - 1060.0).abs() < 0.01 {
                spike(&mut tick);
            }
            v.push(tick);
        }
        v
    }

    #[test]
    fn quiet_server() {
        let ticks = session(|t| t.apps[0].rx_gap = 180.0);
        let v = explain(&ticks, &[], 1060.0, None, &Opts::default());
        assert_eq!(v.app.as_deref(), Some("cs2"));
        assert_eq!(v.causes[0].layer, Layer::Server, "{v:#?}");
        assert!(v.causes[0].evidence.iter().any(|e| e.contains("clean")));
    }

    #[test]
    fn cpu_starved() {
        let ticks = session(|t| {
            t.apps[0].rq_max = 25.0;
            t.apps[0].tx_gap = 40.0;
        });
        let evs = vec![Ev {
            t: 1059.9,
            kind: "rq".into(),
            app: Some("cs2".into()),
            ms: 25.0,
            thread: Some("cs2".into()),
            tid: Some(4242),
            cpu: Some(5),
            by: Some("cargo[999]".into()),
            ..Default::default()
        }];
        let v = explain(&ticks, &evs, 1060.0, Some("cs2"), &Opts::default());
        assert_eq!(v.causes[0].layer, Layer::Cpu, "{v:#?}");
        assert!(v.summary.contains("cargo[999]"), "{}", v.summary);
    }

    #[test]
    fn app_hitch() {
        let ticks = session(|t| t.apps[0].tx_gap = 200.0);
        let v = explain(&ticks, &[], 1060.0, Some("cs2"), &Opts::default());
        assert_eq!(v.causes[0].layer, Layer::App, "{v:#?}");
    }

    #[test]
    fn wifi_spike_beats_server() {
        let ticks = session(|t| {
            t.apps[0].rx_gap = 150.0;
            t.net.gw = Some(85.0);
            t.net.wan = Some(95.0);
        });
        let v = explain(&ticks, &[], 1060.0, Some("cs2"), &Opts::default());
        assert_eq!(v.causes[0].layer, Layer::Lan, "{v:#?}");
        // internet not blamed separately when the LAN already explains it
        assert!(!v.causes.iter().any(|c| c.layer == Layer::Internet));
        let server = v.causes.iter().find(|c| c.layer == Layer::Server).unwrap();
        assert!(server.score < v.causes[0].score);
    }

    #[test]
    fn internet_spike() {
        let ticks = session(|t| {
            t.apps[0].rx_gap = 120.0;
            t.net.wan = Some(140.0);
        });
        let v = explain(&ticks, &[], 1060.0, Some("cs2"), &Opts::default());
        assert_eq!(v.causes[0].layer, Layer::Internet, "{v:#?}");
    }

    #[test]
    fn softirq_late() {
        let ticks = session(|t| {
            t.apps[0].rx_gap = 70.0;
            t.net.rx_sirq_max = 30.0;
        });
        let v = explain(&ticks, &[], 1060.0, Some("cs2"), &Opts::default());
        assert_eq!(v.causes[0].layer, Layer::Kernel, "{v:#?}");
    }

    #[test]
    fn tunnel_daemon_starved() {
        let mut ticks = session(|t| t.apps[0].rx_gap = 120.0);
        for t in &mut ticks {
            t.apps[0].via_tun = 1.0;
            let mut tun = AppTick {
                name: "mullvad-daemon".into(),
                role: "tunnel".into(),
                rx_pps: 70.0,
                rx_gap: 16.0,
                ..Default::default()
            };
            if (t.t - 1060.0).abs() < 0.01 {
                tun.rq_max = 90.0;
            }
            t.apps.push(tun);
        }
        let v = explain(&ticks, &[], 1060.0, Some("cs2"), &Opts::default());
        assert_eq!(v.causes[0].layer, Layer::Tunnel, "{v:#?}");
    }

    #[test]
    fn nothing_found() {
        let ticks = session(|_| {});
        let v = explain(&ticks, &[], 1060.0, None, &Opts::default());
        assert!(v.causes.is_empty(), "{v:#?}");
        assert!(v.summary.starts_with("Nothing stood out"));
    }

    #[test]
    fn spike_detection_merges() {
        let mut ticks = session(|t| t.apps[0].rx_gap = 180.0);
        ticks[241].apps[0].rx_gap = 90.0; // 0.25 s later, same spike
        let s = spikes(&ticks, &[], &Opts::default());
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].ms, 180.0);
        assert_eq!(s[0].what, "recv gap");
    }

    #[test]
    fn merged_spike_keeps_both_labels() {
        let ticks = session(|t| {
            t.apps[0].tx_gap = 150.0;
            t.apps[0].rx_gap = 160.0;
        });
        let s = spikes(&ticks, &[], &Opts::default());
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].what, "recv gap + send gap");
        assert_eq!(s[0].ms, 160.0);
    }
}
