//! lagblame: when a game or call lags, say which layer it came from.

mod bpf;
mod collector;
mod config;
mod model;
mod net;
mod procs;
mod session;
mod tui;
mod verdict;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::collector::Collector;
use crate::config::Config;
use crate::model::Mark;
use crate::verdict::Opts;

#[derive(Parser)]
#[command(
    version,
    about = "Explains lag spikes per app with eBPF: CPU, network stack, tunnel, LAN, internet or server"
)]
struct Cli {
    /// Config file (default ~/.config/lagblame/config.toml)
    #[arg(long, global = true)]
    config: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Watch {
    /// App to watch (process name, executable or argv[0]); repeat for more. Overrides `apps` in the config.
    #[arg(short, long = "app")]
    apps: Vec<String>,
    /// Also watch this one, but only while an app runs (e.g. --with Discord); repeatable
    #[arg(short, long = "with")]
    with: Vec<String>,
    /// Tick length in ms
    #[arg(long, default_value_t = 250)]
    tick_ms: u64,
}

#[derive(Subcommand)]
enum Cmd {
    /// Live view (records a session too, so you can rewind)
    Live {
        #[command(flatten)]
        watch: Watch,
        /// Don't write a session file
        #[arg(long)]
        no_record: bool,
    },
    /// Record sessions in the background (for a systemd user service)
    Record {
        #[command(flatten)]
        watch: Watch,
    },
    /// Open a recorded session in the viewer
    Replay {
        /// Session file or name prefix (default: latest)
        session: Option<String>,
        /// Start at this time (21:43:10, "2026-11-14 21:43:10", -30s)
        #[arg(long)]
        at: Option<String>,
    },
    /// Explain what happened at a moment
    Explain {
        /// Session file or name prefix (default: the one covering --at, else latest)
        session: Option<String>,
        /// When (21:43:10, "2026-11-14 21:43:10", -30s); default: last mark, else biggest spike
        #[arg(long)]
        at: Option<String>,
        /// App to explain (default: the busiest one)
        #[arg(long)]
        app: Option<String>,
        /// Seconds before the moment to look at
        #[arg(long, default_value_t = 3.0)]
        window: f64,
        #[arg(long)]
        json: bool,
    },
    /// List the spikes in a session
    Spikes {
        session: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Mark "it lagged just now" (bind it to a key); add --explain for an instant answer
    Mark {
        note: Vec<String>,
        /// Wait a moment, then print the verdict for the mark
        #[arg(long)]
        explain: bool,
        /// Also show the verdict as a desktop notification (notify-send)
        #[arg(long)]
        notify: bool,
    },
    /// List recorded sessions
    Sessions,
    /// Check kernel, permissions and hooks
    Doctor,
    /// Exit 0 if this binary may load BPF programs (for ExecCondition=), else print the setcap command
    Caps,
    /// Measure lagblame's own CPU cost while the apps run
    Overhead {
        #[command(flatten)]
        watch: Watch,
        #[arg(long, default_value_t = 20)]
        seconds: u64,
    },
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_signals() {
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

fn load_cfg(path: Option<&str>, w: Option<&Watch>) -> Result<Config> {
    let mut cfg = Config::load(path)?;
    if let Some(w) = w {
        if !w.apps.is_empty() {
            cfg.apps = w.apps.clone();
        }
        if !w.with.is_empty() {
            cfg.companions = w.with.clone();
        }
    }
    Ok(cfg)
}

fn need_apps(cfg: &Config) -> Result<()> {
    if cfg.apps.is_empty() {
        bail!(
            "no apps to watch: pass --app NAME (e.g. --app cs2 --app Discord) or set `apps` in {}",
            config::config_path().display()
        );
    }
    Ok(())
}

fn opts(cfg: &Config) -> Opts {
    Opts {
        gap_ms: cfg.thresholds.gap_ms,
        rq_ms: cfg.thresholds.runqueue_ms,
        ..Default::default()
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("lagblame: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let cfgp = cli.config.as_deref();
    match cli.cmd {
        Cmd::Live { watch, no_record } => {
            let cfg = load_cfg(cfgp, Some(&watch))?;
            need_apps(&cfg)?;
            // the background recorder already writes the session
            let record = !no_record && !procs::recorder_running();
            tui::live(cfg, Duration::from_millis(watch.tick_ms), record)
        }
        Cmd::Record { watch } => {
            let cfg = load_cfg(cfgp, Some(&watch))?;
            need_apps(&cfg)?;
            record(cfg, Duration::from_millis(watch.tick_ms))
        }
        Cmd::Replay { session, at } => {
            let cfg = load_cfg(cfgp, None)?;
            let path = session::resolve(&cfg.session_dir(), session.as_deref())?;
            let s = session::read(&path)?;
            let at = at
                .map(|a| session::parse_time(&a, s.start(), s.end()))
                .transpose()?;
            tui::replay(s, at, opts(&cfg))
        }
        Cmd::Explain {
            session,
            at,
            app,
            window,
            json,
        } => {
            let cfg = load_cfg(cfgp, None)?;
            explain_cmd(
                &cfg,
                session.as_deref(),
                at.as_deref(),
                app.as_deref(),
                window,
                json,
            )
        }
        Cmd::Spikes { session, json } => {
            let cfg = load_cfg(cfgp, None)?;
            let path = session::resolve(&cfg.session_dir(), session.as_deref())?;
            let s = session::read(&path)?;
            let sp = verdict::spikes(&s.ticks, &s.evs, &opts(&cfg));
            if json {
                println!("{}", serde_json::to_string_pretty(&sp)?);
            } else if sp.is_empty() {
                println!("no spikes in {}", path.display());
            } else {
                for x in sp {
                    println!(
                        "{}  {:<14} {:<20} {:>7.0} ms",
                        session::fmt_time(x.t),
                        x.app,
                        x.what,
                        x.ms
                    );
                }
            }
            Ok(())
        }
        Cmd::Mark {
            note,
            explain,
            notify,
        } => {
            let m = Mark {
                t: now(),
                note: note.join(" "),
            };
            session::add_mark(&m)?;
            println!("marked {}", session::fmt_time(m.t));
            if explain || notify {
                // let the recorder flush the seconds after the mark
                std::thread::sleep(Duration::from_millis(1500));
                let cfg = load_cfg(cfgp, None)?;
                let dir = cfg.session_dir();
                let path = session::covering(&dir, m.t).context("no session is being recorded")?;
                let s = session::read(&path)?;
                let v = verdict::explain(&s.ticks, &s.evs, m.t, None, &opts(&cfg));
                print!("{}", verdict::render(&v));
                if notify {
                    let body: String = v
                        .causes
                        .iter()
                        .take(3)
                        .map(|c| format!("{}: {}\n", c.layer.title(), c.evidence[0]))
                        .collect();
                    let _ = std::process::Command::new("notify-send")
                        .args([
                            "-a",
                            "lagblame",
                            &v.summary.chars().take(120).collect::<String>(),
                            &body,
                        ])
                        .status();
                }
            }
            Ok(())
        }
        Cmd::Sessions => {
            let cfg = load_cfg(cfgp, None)?;
            let dir = cfg.session_dir();
            let all = session::list(&dir);
            if all.is_empty() {
                println!("no sessions in {}", dir.display());
            }
            for p in all {
                let s = session::read(&p)?;
                let sp = verdict::spikes(&s.ticks, &s.evs, &opts(&cfg));
                let mut apps: Vec<String> = s
                    .ticks
                    .iter()
                    .flat_map(|t| {
                        t.apps
                            .iter()
                            .filter(|a| a.role != "tunnel")
                            .map(|a| a.name.clone())
                    })
                    .collect();
                apps.sort();
                apps.dedup();
                println!(
                    "{}  {}–{}  {:>5.0} min  {:>3} spikes  {}",
                    p.file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    session::fmt_datetime(s.start()),
                    session::fmt_time(s.end()).get(..8).unwrap_or(""),
                    (s.end() - s.start()) / 60.0,
                    sp.len(),
                    apps.join(", ")
                );
            }
            Ok(())
        }
        Cmd::Doctor => doctor(cfgp),
        Cmd::Caps => {
            if bpf::has_bpf_caps() {
                println!("ok: {}", caps_line());
                Ok(())
            } else {
                let exe = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "lagblame".into());
                eprintln!(
                    "missing capabilities ({})\n  sudo setcap cap_bpf,cap_perfmon+ep {exe}",
                    caps_line()
                );
                std::process::exit(1);
            }
        }
        Cmd::Overhead { watch, seconds } => {
            let cfg = load_cfg(cfgp, Some(&watch))?;
            need_apps(&cfg)?;
            overhead(cfg, Duration::from_millis(watch.tick_ms), seconds)
        }
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn record(cfg: Config, tick: Duration) -> Result<()> {
    install_signals();
    let removed = session::prune(
        &cfg.session_dir(),
        cfg.record.retention_days,
        cfg.record.max_mb,
    );
    if removed > 0 {
        eprintln!("pruned {removed} old session(s)");
    }
    let o = opts(&cfg);
    let mut c = Collector::new(cfg.clone(), true)?;
    for m in c.missing() {
        eprintln!("note: hook unavailable on this kernel: {m}");
    }
    if let Some(n) = &c.probe_note {
        eprintln!("note: {n}");
    }
    eprintln!(
        "watching {} (tunnels: {})",
        cfg.apps.join(", "),
        cfg.tunnel_procs.join(", ")
    );
    let mut recent: std::collections::VecDeque<model::Tick> = Default::default();
    let mut recent_ev: Vec<model::Ev> = vec![];
    let mut reported = 0.0;
    let mut last_prune = Instant::now();
    while !STOP.load(Ordering::SeqCst) {
        let step = c.step(tick)?;
        if let Some(n) = c.session_note.take() {
            eprintln!("{n}");
        }
        recent_ev.extend(step.evs);
        if let Some(t) = step.tick {
            recent.push_back(t);
            while recent.len() > 400 {
                recent.pop_front();
            }
            let tt: Vec<model::Tick> = recent.iter().cloned().collect();
            recent_ev.retain(|e| e.t >= tt[0].t - 1.0);
            // report each spike once its "after" window has passed
            for s in verdict::spikes(&tt, &recent_ev, &o) {
                if s.t > reported && s.t <= tt[tt.len() - 1].t - o.after {
                    reported = s.t;
                    let v = verdict::explain(&tt, &recent_ev, s.t, Some(&s.app), &o);
                    println!(
                        "{} {} {} {:.0} ms → {}",
                        session::fmt_time(s.t),
                        s.app,
                        s.what,
                        s.ms,
                        v.summary
                    );
                }
            }
        }
        if last_prune.elapsed() > Duration::from_secs(3600) {
            last_prune = Instant::now();
            session::prune(
                &cfg.session_dir(),
                cfg.record.retention_days,
                cfg.record.max_mb,
            );
        }
    }
    Ok(())
}

fn explain_cmd(
    cfg: &Config,
    sess: Option<&str>,
    at: Option<&str>,
    app: Option<&str>,
    window: f64,
    json: bool,
) -> Result<()> {
    let dir = cfg.session_dir();
    // an absolute time can pick its own session
    let path = match (sess, at) {
        (Some(s), _) => session::resolve(&dir, Some(s))?,
        (None, Some(a)) => {
            let latest = session::resolve(&dir, None)?;
            let s = session::read(&latest)?;
            let t = session::parse_time(a, s.start(), s.end())?;
            if t < s.start() {
                session::covering(&dir, t).unwrap_or(latest)
            } else {
                latest
            }
        }
        (None, None) => session::resolve(&dir, None)?,
    };
    let s = session::read(&path)?;
    let mut o = opts(cfg);
    o.before = window;
    let t = match at {
        Some(a) => session::parse_time(a, s.start(), s.end())?,
        None => {
            if let Some(m) = s.marks.last() {
                eprintln!(
                    "explaining the last mark ({}{})",
                    session::fmt_time(m.t),
                    if m.note.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", m.note)
                    }
                );
                m.t
            } else {
                let sp = verdict::spikes(&s.ticks, &s.evs, &o);
                let big = sp
                    .iter()
                    .max_by(|a, b| a.ms.total_cmp(&b.ms))
                    .context("no marks or spikes in this session: pass --at")?;
                eprintln!(
                    "explaining the biggest spike ({} {} {:.0} ms)",
                    big.app, big.what, big.ms
                );
                big.t
            }
        }
    };
    let v = verdict::explain(&s.ticks, &s.evs, t, app, &o);
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print!("{}", verdict::render(&v));
    }
    Ok(())
}

fn caps_line() -> String {
    let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    // same bits bpf::has_bpf_caps() checks
    let eff = st
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let v = u64::from_str_radix(&eff, 16).unwrap_or(0);
    let has = |bit: u32| v & (1 << bit) != 0;
    // CAP_SYS_ADMIN 21, CAP_PERFMON 38, CAP_BPF 39
    format!(
        "CAP_BPF {} · CAP_PERFMON {} · CAP_SYS_ADMIN {}",
        if has(39) { "yes" } else { "no" },
        if has(38) { "yes" } else { "no" },
        if has(21) { "yes" } else { "no" }
    )
}

fn doctor(cfgp: Option<&str>) -> Result<()> {
    let ok = |b: bool| if b { "ok  " } else { "FAIL" };
    println!("lagblame {}", env!("CARGO_PKG_VERSION"));
    println!("kernel     {}", collector::kernel_release());
    let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
    println!("[{}] BTF      /sys/kernel/btf/vmlinux", ok(btf));
    println!("     caps     {}", caps_line());
    let cfg = load_cfg(cfgp, None)?;
    println!(
        "     config   {} ({})",
        config::config_path().display(),
        if config::config_path().exists() {
            "found"
        } else {
            "defaults"
        }
    );
    println!(
        "     apps     {}",
        if cfg.apps.is_empty() {
            "(none: pass --app)".into()
        } else {
            cfg.apps.join(", ")
        }
    );
    println!("     sessions {}", cfg.session_dir().display());
    let stats = std::fs::read_to_string("/proc/sys/kernel/bpf_stats_enabled")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    println!(
        "     bpf_stats {}",
        if stats {
            "on (overhead numbers available)"
        } else {
            "off (`sudo sysctl kernel.bpf_stats_enabled=1` for `lagblame overhead`)"
        }
    );
    let list = net::ifaces();
    let names: Vec<String> = list
        .iter()
        .filter(|i| i.kind != "loopback")
        .map(|i| format!("{} ({})", i.name, i.kind))
        .collect();
    println!("     ifaces   {}", names.join(", "));
    if let Some((gw, dev)) = net::default_gateway() {
        println!("     gateway  {gw} via {dev}");
    }
    let mut c = cfg.clone();
    c.probe.mode = "off".into();
    match Collector::new(c, false) {
        Ok(mut col) => {
            println!("[ok  ] load     BPF programs loaded");
            for m in col.missing() {
                println!("[warn] hook     {m} not in this kernel (that signal is skipped)");
            }
            // attach briefly without targets to prove the hooks work
            match col.tracer_attach_test() {
                Ok(n) => println!("[ok  ] attach   {n} hooks attached"),
                Err(e) => println!("[FAIL] attach   {e:#}"),
            }
        }
        Err(e) => {
            println!("[FAIL] load     {e:#}");
            if bpf::has_bpf_caps() {
                return Ok(());
            }
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "lagblame".into());
            println!(
                "\nGive the binary the two capabilities it needs (once per install):\n  sudo setcap cap_bpf,cap_perfmon+ep {exe}"
            );
        }
    }
    match cfg.probe.mode.as_str() {
        "off" => println!("     probe    off"),
        "file" => println!(
            "     probe    file {}",
            cfg.probe.file.as_deref().unwrap_or("(unset)")
        ),
        _ => {
            let (_h, note) = net::start_probe(&config::Probe {
                mode: "builtin".into(),
                ..cfg.probe.clone()
            });
            println!(
                "[{}] probe    ICMP ping sockets{}",
                ok(note.is_none()),
                note.map(|n| format!(": {n}")).unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn overhead(cfg: Config, tick: Duration, seconds: u64) -> Result<()> {
    install_signals();
    let stats_on = std::fs::read_to_string("/proc/sys/kernel/bpf_stats_enabled")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    if !stats_on {
        eprintln!(
            "kernel.bpf_stats_enabled is 0: BPF run time will read 0. Turn it on for the test:\n  sudo sysctl kernel.bpf_stats_enabled=1\n(and off again afterwards: sudo sysctl kernel.bpf_stats_enabled=0)"
        );
    }
    let mut c = Collector::new(cfg, false)?;
    let wait = Instant::now();
    while !c.active() && !STOP.load(Ordering::SeqCst) {
        c.step(tick)?;
        if wait.elapsed() > Duration::from_secs(2) && wait.elapsed().as_secs().is_multiple_of(10) {
            eprint!("\rwaiting for a watched app to start…");
        }
    }
    let before = c.tracer().prog_stats();
    let cpu0 = self_cpu();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(seconds) && !STOP.load(Ordering::SeqCst) {
        c.step(tick)?;
    }
    let secs = t0.elapsed().as_secs_f64();
    let after = c.tracer().prog_stats();
    let user = (self_cpu() - cpu0) / secs;
    let mut total_ns = 0u64;
    println!(
        "{:<36} {:>12} {:>10} {:>9}",
        "hook", "runs/s", "ns/run", "µs/s"
    );
    for (name, cnt, ns) in &after {
        let (c0, n0) = before
            .iter()
            .find(|b| &b.0 == name)
            .map(|b| (b.1, b.2))
            .unwrap_or((0, 0));
        let (dc, dn) = (cnt - c0, ns - n0);
        total_ns += dn;
        println!(
            "{:<36} {:>12.0} {:>10.0} {:>9.1}",
            name,
            dc as f64 / secs,
            if dc > 0 { dn as f64 / dc as f64 } else { 0.0 },
            dn as f64 / secs / 1000.0
        );
    }
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as f64;
    let kern = total_ns as f64 / secs / 1e9;
    println!(
        "\nkernel side: {:.3} % of one core ({:.4} % of the machine) · user side: {:.3} % of one core",
        kern * 100.0,
        kern * 100.0 / ncpu,
        user * 100.0
    );
    Ok(())
}

/// CPU seconds this process used so far.
fn self_cpu() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = s.rsplit_once(')').map(|x| x.1).unwrap_or("");
    let f: Vec<&str> = rest.split_whitespace().collect();
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let ut: f64 = f.get(11).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let st: f64 = f.get(12).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (ut + st) / tck.max(1.0)
}
