//! Interfaces and the LAN / internet latency probe.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::config::{Probe, expand};

#[derive(Debug, Clone)]
pub struct Iface {
    pub index: u32,
    pub name: String,
    /// loopback, ethernet, wifi, tun, wireguard, bridge, veth, other
    pub kind: String,
}

impl Iface {
    pub fn is_tunnel(&self) -> bool {
        matches!(self.kind.as_str(), "tun" | "wireguard")
    }
}

pub fn ifaces() -> Vec<Iface> {
    let mut out = vec![];
    let Ok(rd) = fs::read_dir("/sys/class/net") else {
        return out;
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let p = ent.path();
        let Some(index) = fs::read_to_string(p.join("ifindex"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
        else {
            continue;
        };
        let uevent = fs::read_to_string(p.join("uevent")).unwrap_or_default();
        let devtype = uevent
            .lines()
            .find_map(|l| l.strip_prefix("DEVTYPE="))
            .unwrap_or("");
        let ty: u32 = fs::read_to_string(p.join("type"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let kind = if name == "lo" || ty == 772 {
            "loopback"
        } else if p.join("wireless").exists() || p.join("phy80211").exists() || devtype == "wlan" {
            "wifi"
        } else if p.join("tun_flags").exists() {
            "tun"
        } else if devtype == "wireguard" {
            "wireguard"
        } else if devtype == "bridge" || devtype == "veth" || devtype == "vlan" {
            devtype
        } else if ty == 1 {
            "ethernet"
        } else {
            "other"
        };
        out.push(Iface {
            index,
            name,
            kind: kind.into(),
        });
    }
    out.sort_by_key(|i| i.index);
    out
}

/// Default IPv4 gateway and its interface from /proc/net/route (main table).
pub fn default_gateway() -> Option<(Ipv4Addr, String)> {
    let s = fs::read_to_string("/proc/net/route").ok()?;
    let mut best: Option<(u32, Ipv4Addr, String)> = None;
    for l in s.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 7 || f[1] != "00000000" {
            continue;
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        if gw == 0 {
            continue;
        }
        let metric: u32 = f[6].parse().unwrap_or(0);
        let ip = Ipv4Addr::from(u32::from_be(gw));
        if best.as_ref().is_none_or(|b| metric < b.0) {
            best = Some((metric, ip, f[0].to_string()));
        }
    }
    best.map(|(_, ip, dev)| (ip, dev))
}

#[derive(Debug, Clone, Default)]
pub struct ProbeSample {
    pub gw: Option<f64>,
    pub wan: Option<f64>,
    pub loss: Option<f64>,
}

/// Latest probe results, shared with the prober thread.
#[derive(Clone, Default)]
pub struct ProbeHandle(Arc<Mutex<ProbeSample>>);

impl ProbeHandle {
    pub fn get(&self) -> ProbeSample {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

pub fn start_probe(cfg: &Probe) -> (ProbeHandle, Option<String>) {
    let h = ProbeHandle::default();
    match cfg.mode.as_str() {
        "off" => (h, None),
        "file" => {
            let Some(path) = cfg.file.clone() else {
                return (h, Some("probe.mode = \"file\" needs probe.file".into()));
            };
            let h2 = h.clone();
            std::thread::spawn(move || file_loop(&expand(&path), h2));
            (h, None)
        }
        _ => {
            let target = cfg.wan_target.clone();
            let interval = Duration::from_millis(cfg.interval_ms.max(200));
            // check that ping sockets work before starting the thread
            if let Err(e) = Pinger::new(Ipv4Addr::LOCALHOST) {
                return (
                    h,
                    Some(format!(
                        "ICMP ping sockets unavailable ({e}); see net.ipv4.ping_group_range"
                    )),
                );
            }
            let h2 = h.clone();
            std::thread::spawn(move || ping_loop(&target, interval, h2));
            (h, None)
        }
    }
}

fn file_loop(path: &std::path::Path, h: ProbeHandle) {
    let mut last = None;
    loop {
        if let Ok(md) = fs::metadata(path) {
            let fresh = md
                .modified()
                .ok()
                .and_then(|m| SystemTime::now().duration_since(m).ok());
            let m = md.modified().ok();
            if m != last {
                last = m;
                if let Some(s) = fs::read_to_string(path)
                    .ok()
                    .and_then(|s| parse_probe_json(&s))
                    && let Ok(mut g) = h.0.lock()
                {
                    *g = s;
                }
            } else if fresh.is_some_and(|d| d > Duration::from_secs(5))
                && let Ok(mut g) = h.0.lock()
            {
                *g = ProbeSample::default();
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `{"gw": ms, "wan": ms, "loss": 0..1 or percent}`
pub fn parse_probe_json(s: &str) -> Option<ProbeSample> {
    let v: serde_json::Value = serde_json::from_str(s).ok()?;
    let num = |k: &str| v.get(k).and_then(|x| x.as_f64());
    let loss = num("loss").map(|l| if l > 1.0 { l / 100.0 } else { l });
    Some(ProbeSample {
        gw: num("gw"),
        wan: num("wan"),
        loss,
    })
}

struct Pinger {
    fd: i32,
    seq: u16,
}

impl Pinger {
    fn new(dst: Ipv4Addr) -> std::io::Result<Self> {
        // SAFETY: plain socket syscalls on a fd we own.
        unsafe {
            let fd = libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            );
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(dst).to_be(),
                },
                sin_zero: [0; 8],
            };
            if libc::connect(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as u32,
            ) < 0
            {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            Ok(Self { fd, seq: 0 })
        }
    }

    /// RTT in ms, or None on timeout.
    fn ping(&mut self, timeout: Duration) -> Option<f64> {
        self.seq = self.seq.wrapping_add(1);
        let mut pkt = [0u8; 16];
        pkt[0] = 8; // echo request; kernel fills id + checksum
        pkt[6..8].copy_from_slice(&self.seq.to_be_bytes());
        let start = Instant::now();
        // SAFETY: buffers are valid for the given lengths.
        unsafe {
            if libc::send(self.fd, pkt.as_ptr().cast(), pkt.len(), 0) < 0 {
                return None;
            }
            loop {
                let left = timeout.checked_sub(start.elapsed())?;
                let mut pfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, left.as_millis().max(1) as i32) <= 0 {
                    return None;
                }
                let mut buf = [0u8; 64];
                let n = libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0);
                if n >= 8 && buf[0] == 0 && u16::from_be_bytes([buf[6], buf[7]]) == self.seq {
                    return Some(start.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
    }
}

impl Drop for Pinger {
    fn drop(&mut self) {
        // SAFETY: we own the fd.
        unsafe { libc::close(self.fd) };
    }
}

fn resolve(host: &str) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse() {
        return Some(ip);
    }
    (host, 0).to_socket_addrs().ok()?.find_map(|a| match a {
        std::net::SocketAddr::V4(v4) => Some(*SocketAddrV4::ip(&v4)),
        _ => None,
    })
}

fn ping_loop(target: &str, interval: Duration, h: ProbeHandle) {
    let mut gw: Option<(Ipv4Addr, Pinger)> = None;
    let mut wan: Option<(Ipv4Addr, Pinger)> = None;
    let mut hist: std::collections::VecDeque<bool> = Default::default();
    let timeout = interval.min(Duration::from_millis(900));
    loop {
        let t0 = Instant::now();
        let want_gw = default_gateway().map(|g| g.0);
        if gw.as_ref().map(|g| g.0) != want_gw {
            gw = want_gw.and_then(|ip| Pinger::new(ip).ok().map(|p| (ip, p)));
        }
        if wan.is_none() {
            wan = resolve(target).and_then(|ip| Pinger::new(ip).ok().map(|p| (ip, p)));
        }
        let g = gw.as_mut().and_then(|(_, p)| p.ping(timeout));
        let w = wan.as_mut().and_then(|(_, p)| p.ping(timeout));
        if gw.is_some() {
            hist.push_back(g.is_some());
        }
        if wan.is_some() {
            hist.push_back(w.is_some());
        }
        while hist.len() > 10 {
            hist.pop_front();
        }
        let loss = (!hist.is_empty())
            .then(|| hist.iter().filter(|ok| !**ok).count() as f64 / hist.len() as f64);
        if let Ok(mut s) = h.0.lock() {
            *s = ProbeSample {
                gw: g,
                wan: w,
                loss,
            };
        }
        if let Some(rest) = interval.checked_sub(t0.elapsed()) {
            std::thread::sleep(rest);
        }
    }
}

pub fn iface_map(list: &[Iface]) -> BTreeMap<u32, Iface> {
    list.iter().map(|i| (i.index, i.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_json() {
        let s = parse_probe_json(r#"{"gw":0.71,"wan":2.07,"loss":0.0,"iface":"eno1"}"#).unwrap();
        assert_eq!(s.gw, Some(0.71));
        assert_eq!(s.wan, Some(2.07));
        assert_eq!(s.loss, Some(0.0));
        let s = parse_probe_json(r#"{"gw":1,"loss":20}"#).unwrap();
        assert_eq!(s.loss, Some(0.2));
        assert_eq!(s.wan, None);
    }

    #[test]
    fn finds_loopback() {
        assert!(ifaces().iter().any(|i| i.kind == "loopback"));
    }
}
