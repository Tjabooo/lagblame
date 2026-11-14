//! Loads the BPF program, keeps the target map in sync and drains stats/events.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::types::{Enum, Func};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Btf, Link, MapCore, MapFlags, OpenObject, RingBuffer, RingBufferBuilder};

#[allow(clippy::all, dead_code, unused_imports)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/lagblame.skel.rs"));
}
use skel::types::{drop_counts, glob_stats, slot_stats};
use skel::{LagblameSkel, LagblameSkelBuilder};

pub const MAX_SLOTS: u32 = 32;
pub const RQ_BUCKETS: usize = 24;
pub const MAX_REASONS: usize = 256;

pub const EV_RQ: u32 = 1;
pub const EV_TX_GAP: u32 = 2;
pub const EV_RX_GAP: u32 = 3;
pub const EV_PICKUP: u32 = 4;
pub const EV_STACK: u32 = 5;
pub const EV_TUNNEL: u32 = 6;
pub const EV_SOFTIRQ: u32 = 7;
pub const EV_RCVBUF_DROP: u32 = 8;
pub const EV_SKB_DROP: u32 = 9;
pub const EV_TCP_RETRANS: u32 = 10;

/// Mirror of `struct event` in lagblame.h.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RawEvent {
    pub ts: u64,
    pub value: u64,
    pub kind: u32,
    pub slot: u32,
    pub tgid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub other_pid: u32,
    pub aux: u32,
    pub rport: u16,
    pub family: u16,
    pub raddr: [u8; 16],
    pub comm: [u8; 16],
    pub other_comm: [u8; 16],
}

pub fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

#[derive(Debug, Clone, Default)]
pub struct SlotRaw {
    pub rq_cnt: u64,
    pub rq_sum: u64,
    pub rq_max: u64,
    pub rq_hist: [u64; RQ_BUCKETS],
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub tx_gap_max: u64,
    pub rx_gap_max: u64,
    pub stack_cnt: u64,
    pub stack_sum: u64,
    pub stack_max: u64,
    pub tun_cnt: u64,
    pub tun_sum: u64,
    pub tun_max: u64,
    pub pick_cnt: u64,
    pub pick_sum: u64,
    pub pick_max: u64,
    pub rcvbuf_drops: u64,
    pub skb_drops: u64,
    pub tcp_retrans: u64,
    pub rx_tun_pkts: u64,
    pub srtt_cnt: u64,
    pub srtt_sum: u64,
    pub srtt_max: u64,
}

impl SlotRaw {
    fn add(&mut self, s: &slot_stats) {
        self.rq_cnt += s.rq_cnt;
        self.rq_sum += s.rq_sum;
        self.rq_max = self.rq_max.max(s.rq_max);
        for (a, b) in self.rq_hist.iter_mut().zip(s.rq_hist.iter()) {
            *a += b;
        }
        self.tx_pkts += s.tx_pkts;
        self.tx_bytes += s.tx_bytes;
        self.rx_pkts += s.rx_pkts;
        self.rx_bytes += s.rx_bytes;
        self.tx_gap_max = self.tx_gap_max.max(s.tx_gap_max);
        self.rx_gap_max = self.rx_gap_max.max(s.rx_gap_max);
        self.stack_cnt += s.stack_cnt;
        self.stack_sum += s.stack_sum;
        self.stack_max = self.stack_max.max(s.stack_max);
        self.tun_cnt += s.tun_cnt;
        self.tun_sum += s.tun_sum;
        self.tun_max = self.tun_max.max(s.tun_max);
        self.pick_cnt += s.pick_cnt;
        self.pick_sum += s.pick_sum;
        self.pick_max = self.pick_max.max(s.pick_max);
        self.rcvbuf_drops += s.rcvbuf_drops;
        self.skb_drops += s.skb_drops;
        self.tcp_retrans += s.tcp_retrans;
        self.rx_tun_pkts += s.rx_tun_pkts;
        self.srtt_cnt += s.srtt_cnt;
        self.srtt_sum += s.srtt_sum;
        self.srtt_max = self.srtt_max.max(s.srtt_max);
    }

    /// Upper bound of the bucket holding the p-th percentile, in ns.
    pub fn rq_percentile(&self, p: f64) -> u64 {
        let total: u64 = self.rq_hist.iter().sum();
        if total == 0 {
            return 0;
        }
        let want = ((total as f64) * p).ceil() as u64;
        let mut acc = 0;
        for (i, n) in self.rq_hist.iter().enumerate() {
            acc += n;
            if acc >= want {
                return ((2u64 << i) * 1000).min(self.rq_max.max(1));
            }
        }
        self.rq_max
    }
}

#[derive(Debug, Clone, Default)]
pub struct GlobRaw {
    /// [0] = NET_TX, [1] = NET_RX
    pub sirq_cnt: [u64; 2],
    pub sirq_lat_sum: [u64; 2],
    pub sirq_lat_max: [u64; 2],
    pub sirq_dur_sum: [u64; 2],
    pub sirq_dur_max: [u64; 2],
    pub drops: Vec<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Thresholds {
    pub rq_ns: u64,
    pub gap_ns: u64,
    pub pickup_ns: u64,
    pub stack_ns: u64,
    pub sirq_ns: u64,
}

pub struct Tracer {
    skel: LagblameSkel<'static>,
    links: Vec<Link>,
    rb: RingBuffer<'static>,
    queue: Rc<RefCell<Vec<RawEvent>>>,
    /// programs left out (kernel lacks the hook) or that failed to attach
    pub missing: Vec<String>,
    targets: BTreeMap<u32, u32>,
    pub drop_names: Vec<String>,
}

fn kernel_has(btf: &Btf, section: &str) -> bool {
    if let Some(f) = section
        .strip_prefix("fentry/")
        .or_else(|| section.strip_prefix("fexit/"))
    {
        return btf.type_by_name::<Func>(f).is_some();
    }
    if let Some(tp) = section.strip_prefix("tp_btf/") {
        let name = format!("btf_trace_{tp}");
        return btf.type_by_name::<BtfType>(&name).is_some();
    }
    true
}

pub fn drop_reason_names(btf: &Btf) -> Vec<String> {
    let mut names: Vec<String> = (0..MAX_REASONS).map(|i| format!("reason_{i}")).collect();
    if let Some(e) = btf.type_by_name::<Enum>("skb_drop_reason") {
        for m in e.iter() {
            let v = m.value;
            if let (Some(n), true) = (m.name, (0..MAX_REASONS as i64).contains(&v)) {
                let n = n.to_string_lossy();
                names[v as usize] = n.strip_prefix("SKB_DROP_REASON_").unwrap_or(&n).to_string();
            }
        }
    }
    names
}

/// The vmlinux types we need, or an error that explains it.
pub fn vmlinux_btf() -> Result<Btf<'static>> {
    Btf::from_vmlinux()
        .context("reading /sys/kernel/btf/vmlinux (kernel needs CONFIG_DEBUG_INFO_BTF)")
}

impl Tracer {
    pub fn new(th: &Thresholds) -> Result<Self> {
        let btf = vmlinux_btf()?;
        let open_obj: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));
        let builder = LagblameSkelBuilder::default();
        let mut open = builder.open(open_obj).context("opening the BPF object")?;
        {
            let ro = open
                .maps
                .rodata_data
                .as_deref_mut()
                .ok_or_else(|| anyhow!("no rodata"))?;
            ro.rq_thresh_ns = th.rq_ns;
            ro.gap_thresh_ns = th.gap_ns;
            ro.pickup_thresh_ns = th.pickup_ns;
            ro.stack_thresh_ns = th.stack_ns;
            ro.sirq_thresh_ns = th.sirq_ns;
        }
        let mut missing = vec![];
        for mut p in open.open_object_mut().progs_mut() {
            let sec = p.section().to_string_lossy().into_owned();
            if !kernel_has(&btf, &sec) {
                missing.push(sec);
                p.set_autoload(false);
            }
        }
        let skel = open.load().map_err(|e| {
            if has_bpf_caps() {
                anyhow!("the kernel rejected a BPF program: {e} (verifier log above; please report it with `uname -r`)")
            } else {
                anyhow!(
                    "loading BPF programs failed: {e}\n\
                     (needs CAP_BPF + CAP_PERFMON: run as root or `sudo setcap cap_bpf,cap_perfmon+ep <binary>`)"
                )
            }
        })?;
        let queue: Rc<RefCell<Vec<RawEvent>>> = Rc::default();
        let q2 = queue.clone();
        let mut rbb = RingBufferBuilder::new();
        rbb.add(&skel.maps.events, move |data: &[u8]| {
            if data.len() >= size_of::<RawEvent>() {
                // SAFETY: the kernel wrote a full struct event; read_unaligned copes with alignment.
                let ev = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawEvent) };
                q2.borrow_mut().push(ev);
            }
            0
        })?;
        let rb = rbb.build()?;
        let drop_names = drop_reason_names(&btf);
        Ok(Self {
            skel,
            links: vec![],
            rb,
            queue,
            missing,
            targets: BTreeMap::new(),
            drop_names,
        })
    }

    pub fn attached(&self) -> bool {
        !self.links.is_empty()
    }

    pub fn attach(&mut self) -> Result<()> {
        if self.attached() {
            return Ok(());
        }
        let mut fails = vec![];
        for p in self.skel.object().progs_mut() {
            if !p.autoload() {
                continue;
            }
            match p.attach() {
                Ok(l) => self.links.push(l),
                Err(e) => fails.push(format!("{} ({e})", p.section().to_string_lossy())),
            }
        }
        if self.links.is_empty() {
            return Err(anyhow!("no BPF program attached: {}", fails.join(", ")));
        }
        for f in fails {
            if !self.missing.contains(&f) {
                self.missing.push(f);
            }
        }
        Ok(())
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    pub fn detach(&mut self) {
        self.links.clear();
    }

    /// Make the kernel-side target map equal to `want` (tgid -> slot).
    pub fn set_targets(&mut self, want: &BTreeMap<u32, u32>) -> Result<()> {
        let m = &self.skel.maps.targets;
        for tgid in self.targets.keys() {
            if !want.contains_key(tgid) {
                let _ = m.delete(&tgid.to_ne_bytes());
            }
        }
        for (tgid, slot) in want {
            if self.targets.get(tgid) != Some(slot) {
                m.update(&tgid.to_ne_bytes(), &slot.to_ne_bytes(), MapFlags::ANY)?;
            }
        }
        self.targets = want.clone();
        Ok(())
    }

    pub fn set_tunnel_ifaces(&mut self, ifindexes: &[u32]) -> Result<()> {
        let m = &self.skel.maps.tunifs;
        let old: Vec<Vec<u8>> = m.keys().collect();
        for k in old {
            let _ = m.delete(&k);
        }
        for i in ifindexes {
            m.update(&i.to_ne_bytes(), &[1u8], MapFlags::ANY)?;
        }
        Ok(())
    }

    /// Flip the parity and collect everything written since the last drain.
    pub fn drain(&mut self, slots: &[u32]) -> Result<(BTreeMap<u32, SlotRaw>, GlobRaw)> {
        let bss = self
            .skel
            .maps
            .bss_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("no bss"))?;
        let old = bss.parity & 1;
        // SAFETY: bss is a live mmap of the BPF .bss section.
        unsafe { std::ptr::write_volatile(&mut bss.parity, old ^ 1) };
        // let programs that already read the old parity finish
        std::thread::sleep(Duration::from_micros(200));

        let mut out = BTreeMap::new();
        let stats = &self.skel.maps.stats;
        for &slot in slots {
            if slot >= MAX_SLOTS {
                continue;
            }
            let key = (slot * 2 + old).to_ne_bytes();
            let Some(per_cpu) = stats.lookup_percpu(&key, MapFlags::ANY)? else {
                continue;
            };
            let mut agg = SlotRaw::default();
            for v in &per_cpu {
                agg.add(&read_struct::<slot_stats>(v));
            }
            let zero = vec![vec![0u8; per_cpu.first().map_or(0, |v| v.len())]; per_cpu.len()];
            stats.update_percpu(&key, &zero, MapFlags::ANY)?;
            out.insert(slot, agg);
        }

        let mut g = GlobRaw {
            drops: vec![0; MAX_REASONS],
            ..Default::default()
        };
        let key = old.to_ne_bytes();
        if let Some(per_cpu) = self.skel.maps.gstats.lookup_percpu(&key, MapFlags::ANY)? {
            for v in &per_cpu {
                let s = read_struct::<glob_stats>(v);
                for i in 0..2 {
                    g.sirq_cnt[i] += s.sirq_cnt[i];
                    g.sirq_lat_sum[i] += s.sirq_lat_sum[i];
                    g.sirq_lat_max[i] = g.sirq_lat_max[i].max(s.sirq_lat_max[i]);
                    g.sirq_dur_sum[i] += s.sirq_dur_sum[i];
                    g.sirq_dur_max[i] = g.sirq_dur_max[i].max(s.sirq_dur_max[i]);
                }
            }
            let zero = vec![vec![0u8; per_cpu[0].len()]; per_cpu.len()];
            self.skel
                .maps
                .gstats
                .update_percpu(&key, &zero, MapFlags::ANY)?;
        }
        if let Some(per_cpu) = self.skel.maps.drops.lookup_percpu(&key, MapFlags::ANY)? {
            for v in &per_cpu {
                let d = read_struct::<drop_counts>(v);
                for (a, b) in g.drops.iter_mut().zip(d.n.iter()) {
                    *a += b;
                }
            }
            let zero = vec![vec![0u8; per_cpu[0].len()]; per_cpu.len()];
            self.skel
                .maps
                .drops
                .update_percpu(&key, &zero, MapFlags::ANY)?;
        }
        Ok((out, g))
    }

    /// Wait up to `timeout` for spike events.
    pub fn poll(&mut self, timeout: Duration) -> Vec<RawEvent> {
        let _ = self.rb.poll(timeout);
        std::mem::take(&mut *self.queue.borrow_mut())
    }

    /// (program section, run count, run time ns) — run time needs kernel.bpf_stats_enabled=1.
    pub fn prog_stats(&self) -> Vec<(String, u64, u64)> {
        let mut out = vec![];
        for p in self.skel.object().progs() {
            if !p.autoload() {
                continue;
            }
            let mut info = libbpf_rs::libbpf_sys::bpf_prog_info::default();
            let mut len = size_of::<libbpf_rs::libbpf_sys::bpf_prog_info>() as u32;
            let fd = p.as_fd();
            // SAFETY: info/len describe a valid buffer.
            let rc = unsafe {
                libbpf_rs::libbpf_sys::bpf_prog_get_info_by_fd(
                    std::os::fd::AsRawFd::as_raw_fd(&fd),
                    &mut info,
                    &mut len,
                )
            };
            if rc == 0 {
                out.push((
                    p.section().to_string_lossy().into_owned(),
                    info.run_cnt,
                    info.run_time_ns,
                ));
            }
        }
        out
    }
}

/// CAP_BPF and CAP_PERFMON (or CAP_SYS_ADMIN) in the effective set.
pub fn has_bpf_caps() -> bool {
    let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let eff = st
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let v = u64::from_str_radix(&eff, 16).unwrap_or(0);
    let has = |bit: u32| v & (1 << bit) != 0;
    has(21) || (has(38) && has(39))
}

fn read_struct<T: Copy + Default>(b: &[u8]) -> T {
    if b.len() < size_of::<T>() {
        return T::default();
    }
    // SAFETY: T is a plain repr(C) struct of integers and b is long enough.
    unsafe { std::ptr::read_unaligned(b.as_ptr() as *const T) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_event_layout_matches_c() {
        assert_eq!(size_of::<RawEvent>(), 96);
        assert_eq!(std::mem::offset_of!(RawEvent, rport), 44);
        assert_eq!(std::mem::offset_of!(RawEvent, raddr), 48);
        assert_eq!(std::mem::offset_of!(RawEvent, comm), 64);
    }

    #[test]
    fn percentile_from_hist() {
        let mut s = SlotRaw::default();
        s.rq_hist[3] = 99; // 8..16 us
        s.rq_hist[12] = 1; // 4..8 ms
        s.rq_max = 5_000_000;
        assert_eq!(s.rq_percentile(0.5), 16_000);
        assert_eq!(s.rq_percentile(1.0), 5_000_000);
    }

    #[test]
    fn cstr_stops_at_nul() {
        assert_eq!(cstr(b"cs2\0\0junk"), "cs2");
    }
}
