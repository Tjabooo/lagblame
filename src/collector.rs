//! Turns raw BPF stats and events into ticks/events, manages targets and sessions.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::bpf::{self, GlobRaw, RawEvent, SlotRaw, Thresholds, Tracer, cstr};
use crate::config::Config;
use crate::model::{AppTick, Ev, Line, Meta, NetTick, Tick, r2};
use crate::net::{self, Iface, ProbeHandle};
use crate::procs::{self, Role, Want};
use crate::session::Writer;

/// Kept per tick and kind/app; the rest are counted, not stored.
const EVENTS_PER_KIND: usize = 6;

pub struct Collector {
    tracer: Tracer,
    wants: Vec<Want>,
    pids: BTreeMap<String, Vec<u32>>,
    ifaces: BTreeMap<u32, Iface>,
    probe: ProbeHandle,
    pub probe_note: Option<String>,
    last_scan: Option<Instant>,
    last_drain: Instant,
    wall_offset: f64,
    pub cfg: Config,
    writer: Option<Writer>,
    record: bool,
    idle_since: Option<Instant>,
    /// set when a session file was opened or closed (for status lines)
    pub session_note: Option<String>,
}

pub struct Step {
    pub tick: Option<Tick>,
    pub evs: Vec<Ev>,
}

fn now_wall() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn now_mono() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

impl Collector {
    pub fn new(cfg: Config, record: bool) -> Result<Self> {
        let th = &cfg.thresholds;
        let ms = |v: f64| (v * 1e6) as u64;
        let tracer = Tracer::new(&Thresholds {
            rq_ns: ms(th.runqueue_ms),
            gap_ns: ms(th.gap_ms),
            pickup_ns: ms(th.pickup_ms),
            stack_ns: ms(th.stack_ms),
            sirq_ns: ms(th.softirq_ms),
        })?;
        let mut wants: Vec<Want> = vec![];
        for a in &cfg.apps {
            wants.push(Want {
                name: a.clone(),
                role: Role::App,
            });
        }
        for a in &cfg.companions {
            if !wants.iter().any(|w| w.name.eq_ignore_ascii_case(a)) {
                wants.push(Want {
                    name: a.clone(),
                    role: Role::Companion,
                });
            }
        }
        for t in &cfg.tunnel_procs {
            if !wants.iter().any(|w| w.name.eq_ignore_ascii_case(t)) {
                wants.push(Want {
                    name: t.clone(),
                    role: Role::Tunnel,
                });
            }
        }
        wants.truncate(bpf::MAX_SLOTS as usize);
        let (probe, probe_note) = net::start_probe(&cfg.probe);
        let mut c = Self {
            tracer,
            wants,
            pids: BTreeMap::new(),
            ifaces: BTreeMap::new(),
            probe,
            probe_note,
            last_scan: None,
            last_drain: Instant::now(),
            wall_offset: now_wall() - now_mono(),
            cfg,
            writer: None,
            record,
            idle_since: None,
            session_note: None,
        };
        c.refresh_ifaces()?;
        Ok(c)
    }

    pub fn missing(&self) -> &[String] {
        &self.tracer.missing
    }

    /// Attach every hook once (no targets needed) and detach again.
    pub fn tracer_attach_test(&mut self) -> Result<usize> {
        self.tracer.attach()?;
        let n = self.tracer.link_count();
        self.tracer.detach();
        Ok(n)
    }

    pub fn tracer(&self) -> &Tracer {
        &self.tracer
    }

    fn refresh_ifaces(&mut self) -> Result<()> {
        let list = net::ifaces();
        let tun: Vec<u32> = list
            .iter()
            .filter(|i| i.is_tunnel())
            .map(|i| i.index)
            .collect();
        let new = net::iface_map(&list);
        if new.keys().ne(self.ifaces.keys()) {
            self.tracer.set_tunnel_ifaces(&tun)?;
        }
        self.ifaces = new;
        Ok(())
    }

    fn any_app_running(&self) -> bool {
        self.wants
            .iter()
            .any(|w| w.role == Role::App && self.pids.contains_key(&w.name))
    }

    fn rescan(&mut self) -> Result<()> {
        self.pids = procs::scan(&self.wants);
        let mut targets = BTreeMap::new();
        for (slot, w) in self.wants.iter().enumerate() {
            for pid in self.pids.get(&w.name).into_iter().flatten() {
                targets.insert(*pid, slot as u32);
            }
        }
        self.tracer.set_targets(&targets)?;
        self.refresh_ifaces()?;
        // stay detached (zero overhead) until a watched app runs; tunnels alone don't count
        if self.any_app_running() {
            self.idle_since = None;
            if !self.tracer.attached() {
                self.tracer.attach()?;
                self.last_drain = Instant::now();
                let _ = self.tracer.drain(&self.slots());
            }
            if self.record && self.writer.is_none() {
                let meta = self.meta();
                let w = Writer::create(&self.cfg.session_dir(), &meta)?;
                self.session_note = Some(format!("recording {}", w.path.display()));
                self.writer = Some(w);
            }
        } else {
            let since = *self.idle_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(self.cfg.record.linger_s)
                || self.writer.is_none()
            {
                if self.tracer.attached() {
                    self.tracer.detach();
                }
                if let Some(w) = self.writer.take() {
                    self.session_note = Some(format!("closed {}", w.path.display()));
                }
            }
        }
        Ok(())
    }

    pub fn meta(&self) -> Meta {
        Meta {
            version: env!("CARGO_PKG_VERSION").into(),
            host: hostname(),
            kernel: kernel_release(),
            started: now_wall(),
            apps: self
                .wants
                .iter()
                .filter(|w| w.role != Role::Tunnel)
                .map(|w| w.name.clone())
                .collect(),
            tunnel_procs: self
                .wants
                .iter()
                .filter(|w| w.role == Role::Tunnel)
                .map(|w| w.name.clone())
                .collect(),
            ifaces: self
                .ifaces
                .values()
                .map(|i| (i.name.clone(), i.kind.clone()))
                .collect(),
            missing_probes: self.tracer.missing.clone(),
        }
    }

    fn slots(&self) -> Vec<u32> {
        (0..self.wants.len() as u32).collect()
    }

    pub fn active(&self) -> bool {
        self.tracer.attached()
    }

    /// Poll events until the next tick is due; returns the tick when it is.
    pub fn step(&mut self, tick: Duration) -> Result<Step> {
        if self
            .last_scan
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
        {
            self.last_scan = Some(Instant::now());
            self.rescan()?;
            self.wall_offset = now_wall() - now_mono();
        }
        let left = tick.saturating_sub(self.last_drain.elapsed());
        if !self.active() {
            std::thread::sleep(left.min(Duration::from_millis(200)));
            if self.last_drain.elapsed() >= tick {
                self.last_drain = Instant::now();
            }
            return Ok(Step {
                tick: None,
                evs: vec![],
            });
        }
        let raw = self.tracer.poll(left.min(Duration::from_millis(100)));
        let evs = self.convert_events(raw);
        let mut out = Step { tick: None, evs };
        if self.last_drain.elapsed() >= tick {
            let dt = self.last_drain.elapsed().as_secs_f64();
            self.last_drain = Instant::now();
            let (slots, glob) = self.tracer.drain(&self.slots())?;
            out.tick = Some(self.build_tick(dt, &slots, &glob));
        }
        if let Some(w) = self.writer.as_mut() {
            for e in &out.evs {
                w.write(&Line::Ev(e.clone()))?;
            }
            if let Some(t) = &out.tick {
                w.write(&Line::Tick(t.clone()))?;
            }
        }
        Ok(out)
    }

    pub fn write_mark(&mut self, m: crate::model::Mark) -> Result<()> {
        if let Some(w) = self.writer.as_mut() {
            w.write(&Line::Mark(m))?;
            w.flush()?;
        }
        Ok(())
    }

    fn build_tick(&self, dt: f64, slots: &BTreeMap<u32, SlotRaw>, g: &GlobRaw) -> Tick {
        let ms = |ns: u64| r2(ns as f64 / 1e6);
        let avg = |sum: u64, n: u64| {
            if n == 0 {
                0.0
            } else {
                r2(sum as f64 / n as f64 / 1e6)
            }
        };
        let mut apps = vec![];
        for (slot, w) in self.wants.iter().enumerate() {
            let Some(pids) = self.pids.get(&w.name) else {
                continue;
            };
            let s = slots.get(&(slot as u32)).cloned().unwrap_or_default();
            apps.push(AppTick {
                name: w.name.clone(),
                role: w.role.as_str().into(),
                pids: pids.len() as u32,
                rq_n: s.rq_cnt,
                rq_avg: avg(s.rq_sum, s.rq_cnt),
                rq_p99: ms(s.rq_percentile(0.99)),
                rq_max: ms(s.rq_max),
                tx_pps: r2(s.tx_pkts as f64 / dt),
                tx_kbps: r2(s.tx_bytes as f64 * 8.0 / 1000.0 / dt),
                rx_pps: r2(s.rx_pkts as f64 / dt),
                rx_kbps: r2(s.rx_bytes as f64 * 8.0 / 1000.0 / dt),
                tx_gap: ms(s.tx_gap_max),
                rx_gap: ms(s.rx_gap_max),
                stack_avg: avg(s.stack_sum, s.stack_cnt),
                stack_max: ms(s.stack_max),
                tun_max: ms(s.tun_max),
                via_tun: if s.rx_pkts == 0 {
                    0.0
                } else {
                    r2(s.rx_tun_pkts as f64 / s.rx_pkts as f64)
                },
                pick_avg: avg(s.pick_sum, s.pick_cnt),
                pick_max: ms(s.pick_max),
                rcvbuf_drops: s.rcvbuf_drops,
                drops: s.skb_drops,
                retrans: s.tcp_retrans,
                rtt_avg: if s.srtt_cnt == 0 {
                    0.0
                } else {
                    r2(s.srtt_sum as f64 / s.srtt_cnt as f64 / 1000.0)
                },
                rtt_max: r2(s.srtt_max as f64 / 1000.0),
            });
        }
        let p = self.probe.get();
        let net = NetTick {
            gw: p.gw.map(r2),
            wan: p.wan.map(r2),
            loss: p.loss.map(r2),
            rx_sirq_max: ms(g.sirq_lat_max[1]),
            rx_sirq_avg: avg(g.sirq_lat_sum[1], g.sirq_cnt[1]),
            rx_sirq_run: ms(g.sirq_dur_max[1]),
            tx_sirq_max: ms(g.sirq_lat_max[0]),
        };
        let mut drops = BTreeMap::new();
        for (i, n) in g.drops.iter().enumerate() {
            if *n > 0 {
                drops.insert(
                    self.tracer
                        .drop_names
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| format!("reason_{i}")),
                    *n,
                );
            }
        }
        Tick {
            t: now_wall(),
            dt: r2(dt * 100.0) / 100.0,
            apps,
            net,
            drops,
        }
    }

    fn convert_events(&self, mut raw: Vec<RawEvent>) -> Vec<Ev> {
        // keep the biggest few per (kind, slot)
        raw.sort_by_key(|a| (a.kind, a.slot, std::cmp::Reverse(a.value)));
        let mut out = vec![];
        let mut last = (0, u32::MAX);
        let mut n = 0;
        for e in raw {
            if (e.kind, e.slot) != last {
                last = (e.kind, e.slot);
                n = 0;
            }
            n += 1;
            if n > EVENTS_PER_KIND {
                continue;
            }
            out.push(self.convert(&e));
        }
        out.sort_by(|a, b| a.t.total_cmp(&b.t));
        out
    }

    fn iface_name(&self, idx: u32) -> Option<String> {
        self.ifaces.get(&idx).map(|i| i.name.clone())
    }

    fn convert(&self, e: &RawEvent) -> Ev {
        let kind = match e.kind {
            bpf::EV_RQ => "rq",
            bpf::EV_TX_GAP => "tx_gap",
            bpf::EV_RX_GAP => "rx_gap",
            bpf::EV_PICKUP => "pickup",
            bpf::EV_STACK => "stack",
            bpf::EV_TUNNEL => "tunnel",
            bpf::EV_SOFTIRQ => "softirq",
            bpf::EV_RCVBUF_DROP => "rcvbuf_drop",
            bpf::EV_SKB_DROP => "drop",
            bpf::EV_TCP_RETRANS => "retrans",
            _ => "unknown",
        };
        let app = self.wants.get(e.slot as usize).map(|w| w.name.clone());
        let ms = if e.kind == bpf::EV_TCP_RETRANS {
            e.value as f64 / 1000.0
        } else {
            e.value as f64 / 1e6
        };
        let comm = cstr(&e.comm);
        let mut ev = Ev {
            t: e.ts as f64 / 1e9 + self.wall_offset,
            kind: kind.into(),
            app,
            ms: r2(ms),
            thread: (!comm.is_empty()).then_some(comm),
            tid: (e.tid != 0).then_some(e.tid),
            cpu: Some(e.cpu),
            ..Default::default()
        };
        ev.t = (ev.t * 1e6).round() / 1e6;
        if e.rport != 0 {
            ev.peer = Some(peer(e.family, &e.raddr, e.rport));
        }
        match e.kind {
            bpf::EV_RQ => {
                let other = cstr(&e.other_comm);
                ev.by = Some(if e.other_pid == 0 {
                    "idle".into()
                } else {
                    format!("{other}[{}]", e.other_pid)
                });
            }
            bpf::EV_STACK | bpf::EV_TUNNEL => ev.iface = self.iface_name(e.aux),
            bpf::EV_SOFTIRQ => {
                ev.reason = Some(if e.aux == 3 {
                    "NET_RX".into()
                } else {
                    "NET_TX".into()
                });
            }
            bpf::EV_SKB_DROP => ev.reason = self.tracer.drop_names.get(e.aux as usize).cloned(),
            bpf::EV_RCVBUF_DROP => ev.reason = Some("socket receive buffer full".into()),
            _ => {}
        }
        ev
    }
}

pub fn peer(family: u16, addr: &[u8; 16], port: u16) -> String {
    if family == 10 {
        let a = Ipv6Addr::from(*addr);
        match a.to_ipv4_mapped() {
            Some(v4) => format!("{v4}:{port}"),
            None => format!("[{a}]:{port}"),
        }
    } else {
        format!(
            "{}:{port}",
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers() {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[155, 133, 1, 2]);
        assert_eq!(peer(2, &a, 27015), "155.133.1.2:27015");
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(peer(10, &v6.octets(), 443), "[2001:db8::1]:443");
        let mapped: Ipv6Addr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(peer(10, &mapped.octets(), 9), "1.2.3.4:9");
    }
}
