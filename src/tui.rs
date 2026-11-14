//! Live view and replay: per-app table, rewindable timelines, spikes, verdict.

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::Duration;

use anyhow::Result;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Cell, List, ListItem, ListState, Paragraph, Row, Sparkline, Table, Wrap,
};

use crate::collector::Collector;
use crate::config::Config;
use crate::model::{Ev, Mark, Tick};
use crate::session::{Session, fmt_time};
use crate::verdict::{self, Opts, Spike};

const ACCENT: Color = Color::Rgb(255, 140, 26);
const HOT: Color = Color::Rgb(229, 72, 77);
const DIM: Color = Color::Rgb(122, 103, 90);
const FG: Color = Color::Rgb(216, 203, 191);
const OK: Color = Color::Rgb(120, 170, 110);
const MAX_LIVE_TICKS: usize = 4 * 3600;

enum Msg {
    Tick(Tick),
    Evs(Vec<Ev>),
    Status(String),
    Fatal(String),
}

struct View {
    ticks: Vec<Tick>,
    evs: Vec<Ev>,
    marks: Vec<Mark>,
    spikes: Vec<Spike>,
    /// index into ticks; None = follow the newest
    cursor: Option<usize>,
    sel_app: usize,
    sel_spike: Option<usize>,
    live: bool,
    status: String,
    title: String,
    opts: Opts,
    fatal: Option<String>,
}

impl View {
    fn cur(&self) -> usize {
        self.cursor.unwrap_or(self.ticks.len().saturating_sub(1))
    }

    fn app_names(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = vec![];
        let from = self.cur().saturating_sub(40);
        for t in self.ticks.iter().skip(from).take(41) {
            for a in &t.apps {
                if !v.iter().any(|x| x.0 == a.name) {
                    v.push((a.name.clone(), a.role.clone()));
                }
            }
        }
        // apps before tunnels
        v.sort_by_key(|x| match x.1.as_str() {
            "app" => 0,
            "companion" => 1,
            _ => 2,
        });
        v
    }

    fn sel_name(&self) -> Option<String> {
        let names = self.app_names();
        names
            .get(self.sel_app.min(names.len().saturating_sub(1)))
            .map(|x| x.0.clone())
    }

    fn move_cursor(&mut self, delta: isize) {
        if self.ticks.is_empty() {
            return;
        }
        let last = self.ticks.len() - 1;
        let c = self.cur() as isize + delta;
        if c >= last as isize && self.live {
            self.cursor = None;
        } else {
            self.cursor = Some(c.clamp(0, last as isize) as usize);
        }
        self.sel_spike = None;
    }

    fn index_at(&self, t: f64) -> usize {
        self.ticks
            .partition_point(|x| x.t < t)
            .min(self.ticks.len().saturating_sub(1))
    }

    fn jump_spike(&mut self, dir: isize) {
        if self.spikes.is_empty() {
            return;
        }
        let i = match self.sel_spike {
            Some(i) => (i as isize + dir).clamp(0, self.spikes.len() as isize - 1) as usize,
            None => {
                let t = self.ticks.get(self.cur()).map(|t| t.t).unwrap_or(0.0);
                if dir < 0 {
                    self.spikes
                        .iter()
                        .rposition(|s| s.t < t - 0.01)
                        .unwrap_or(0)
                } else {
                    self.spikes
                        .iter()
                        .position(|s| s.t > t + 0.01)
                        .unwrap_or(self.spikes.len() - 1)
                }
            }
        };
        self.sel_spike = Some(i);
        let s = &self.spikes[i];
        self.cursor = Some(self.index_at(s.t));
        if let Some(pos) = self.app_names().iter().position(|a| a.0 == s.app) {
            self.sel_app = pos;
        }
    }

    fn refresh_spikes_tail(&mut self) {
        let from = self.ticks.len().saturating_sub(48);
        let tail = &self.ticks[from..];
        let t0 = tail.first().map(|t| t.t - 1.0).unwrap_or(0.0);
        let evs: Vec<Ev> = self.evs.iter().filter(|e| e.t >= t0).cloned().collect();
        let last_t = self.spikes.last().map(|s| s.t).unwrap_or(0.0);
        let done = tail.last().map(|t| t.t - self.opts.after).unwrap_or(0.0);
        for s in verdict::spikes(tail, &evs, &self.opts) {
            if s.t > last_t + 0.001
                && s.t <= done
                && !self
                    .spikes
                    .iter()
                    .rev()
                    .take(8)
                    .any(|x| x.app == s.app && (x.t - s.t).abs() < 1.0)
            {
                self.spikes.push(s);
            }
        }
    }

    fn push_tick(&mut self, t: Tick) {
        self.ticks.push(t);
        if self.ticks.len() > MAX_LIVE_TICKS {
            let cut = MAX_LIVE_TICKS / 10;
            self.ticks.drain(..cut);
            let t0 = self.ticks[0].t;
            self.evs.retain(|e| e.t >= t0);
            if let Some(c) = self.cursor.as_mut() {
                *c = c.saturating_sub(cut);
            }
        }
        self.refresh_spikes_tail();
    }
}

pub fn live(cfg: Config, tick: Duration, record: bool) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Msg>();
    let (mark_tx, mark_rx) = mpsc::channel::<Mark>();
    let opts = Opts {
        gap_ms: cfg.thresholds.gap_ms,
        rq_ms: cfg.thresholds.runqueue_ms,
        ..Default::default()
    };
    // the collector (and its BPF objects) live on their own thread
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let cfg2 = cfg.clone();
    std::thread::spawn(move || worker(cfg2, tick, record, tx, mark_rx, ready_tx));
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => anyhow::bail!("{e}"),
        Err(_) => anyhow::bail!("collector thread died"),
    }
    let view = View {
        ticks: vec![],
        evs: vec![],
        marks: vec![],
        spikes: vec![],
        cursor: None,
        sel_app: 0,
        sel_spike: None,
        live: true,
        status: format!("waiting for {}…", cfg.apps.join(", ")),
        title: "LIVE".into(),
        opts,
        fatal: None,
    };
    run_ui(view, Some(rx), Some(mark_tx))
}

fn worker(
    cfg: Config,
    tick: Duration,
    record: bool,
    tx: Sender<Msg>,
    marks: Receiver<Mark>,
    ready: Sender<Result<(), String>>,
) {
    let mut c = match Collector::new(cfg, record) {
        Ok(c) => {
            let _ = ready.send(Ok(()));
            c
        }
        Err(e) => {
            let _ = ready.send(Err(format!("{e:#}")));
            return;
        }
    };
    let mut notes: Vec<String> = c
        .missing()
        .iter()
        .map(|m| format!("hook unavailable: {m}"))
        .collect();
    if let Some(n) = c.probe_note.clone() {
        notes.push(n);
    }
    if !notes.is_empty() {
        let _ = tx.send(Msg::Status(notes.join(" · ")));
    }
    loop {
        while let Ok(m) = marks.try_recv() {
            let _ = c.write_mark(m);
        }
        match c.step(tick) {
            Ok(step) => {
                if let Some(n) = c.session_note.take() {
                    let _ = tx.send(Msg::Status(n));
                }
                if !step.evs.is_empty() && tx.send(Msg::Evs(step.evs)).is_err() {
                    return;
                }
                if let Some(t) = step.tick
                    && tx.send(Msg::Tick(t)).is_err()
                {
                    return;
                }
                if !c.active() {
                    let waiting: Vec<String> = c.cfg.apps.clone();
                    let _ = tx.send(Msg::Status(format!(
                        "waiting for {}… (detached: no overhead)",
                        waiting.join(", ")
                    )));
                }
            }
            Err(e) => {
                let _ = tx.send(Msg::Fatal(format!("{e:#}")));
                return;
            }
        }
    }
}

pub fn replay(s: Session, at: Option<f64>, opts: Opts) -> Result<()> {
    if s.ticks.is_empty() {
        anyhow::bail!("{} has no data", s.path.display());
    }
    let spikes = verdict::spikes(&s.ticks, &s.evs, &opts);
    let mut v = View {
        cursor: Some(s.ticks.len() - 1),
        ticks: s.ticks,
        evs: s.evs,
        marks: s.marks,
        spikes,
        sel_app: 0,
        sel_spike: None,
        live: false,
        status: format!(
            "{} · {} {}",
            s.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            s.meta.host,
            s.meta.kernel
        ),
        title: "REPLAY".into(),
        opts,
        fatal: None,
    };
    if let Some(t) = at {
        v.cursor = Some(v.index_at(t));
    } else if let Some(m) = v.marks.last() {
        v.cursor = Some(v.index_at(m.t));
    } else if let Some((i, _)) = v
        .spikes
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.ms.total_cmp(&b.1.ms))
    {
        v.jump_spike(0);
        v.sel_spike = Some(i);
        v.cursor = Some(v.index_at(v.spikes[i].t));
    }
    run_ui(v, None, None)
}

fn run_ui(mut v: View, rx: Option<Receiver<Msg>>, marks: Option<Sender<Mark>>) -> Result<()> {
    let mut term = ratatui::init();
    let res = (|| -> Result<()> {
        loop {
            if let Some(rx) = &rx {
                loop {
                    match rx.try_recv() {
                        Ok(Msg::Tick(t)) => v.push_tick(t),
                        Ok(Msg::Evs(e)) => v.evs.extend(e),
                        Ok(Msg::Status(s)) => v.status = s,
                        Ok(Msg::Fatal(s)) => v.fatal = Some(s),
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            if v.fatal.is_none() {
                                v.fatal = Some("collector stopped".into());
                            }
                            break;
                        }
                    }
                }
            }
            term.draw(|f| draw(f, &v))?;
            if !event::poll(Duration::from_millis(100))? {
                continue;
            }
            let Event::Key(k) = event::read()? else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            let big = k.modifiers.contains(KeyModifiers::SHIFT);
            match k.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
                KeyCode::Esc => {
                    if v.sel_spike.is_some() {
                        v.sel_spike = None;
                    } else {
                        return Ok(());
                    }
                }
                KeyCode::Left | KeyCode::Char('h') => v.move_cursor(if big { -40 } else { -1 }),
                KeyCode::Right | KeyCode::Char('l') => v.move_cursor(if big { 40 } else { 1 }),
                KeyCode::PageUp => v.move_cursor(-240),
                KeyCode::PageDown => v.move_cursor(240),
                KeyCode::Home => v.cursor = Some(0),
                KeyCode::End => {
                    v.cursor = if v.live {
                        None
                    } else {
                        Some(v.ticks.len().saturating_sub(1))
                    };
                    v.sel_spike = None;
                }
                KeyCode::Up | KeyCode::Char('k') => v.sel_app = v.sel_app.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => {
                    v.sel_app = (v.sel_app + 1).min(v.app_names().len().saturating_sub(1))
                }
                KeyCode::Char('[') | KeyCode::Char('p') => v.jump_spike(-1),
                KeyCode::Char(']') | KeyCode::Char('n') => v.jump_spike(1),
                KeyCode::Char(' ') if v.live => {
                    v.cursor = match v.cursor {
                        None => Some(v.cur()),
                        Some(_) => None,
                    }
                }
                KeyCode::Char('m') => {
                    let t = v.ticks.get(v.cur()).map(|t| t.t);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0);
                    let m = Mark {
                        t: if v.cursor.is_some() {
                            t.unwrap_or(now)
                        } else {
                            now
                        },
                        note: "marked in viewer".into(),
                    };
                    let _ = crate::session::add_mark(&m);
                    if let Some(tx) = &marks {
                        let _ = tx.send(m.clone());
                    }
                    v.status = format!("marked {}", fmt_time(m.t));
                    v.marks.push(m);
                }
                _ => {}
            }
        }
    })();
    ratatui::restore();
    res
}

fn ms(v: f64) -> String {
    if v == 0.0 {
        "·".into()
    } else if v < 1.0 {
        format!("{:.0}µ", v * 1000.0)
    } else if v < 100.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

fn draw(f: &mut Frame, v: &View) {
    let area = f.area();
    let napps = v.app_names().len().max(1) as u16;
    let [head, table, graphs, bottom, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(napps + 3),
        Constraint::Length(9),
        Constraint::Min(6),
        Constraint::Length(1),
    ])
    .areas(area);

    // ------------------------------------------------ header
    let cur = v.ticks.get(v.cur());
    let when = cur
        .map(|t| fmt_time(t.t))
        .unwrap_or_else(|| "--:--:--".into());
    let following = v.live && v.cursor.is_none();
    let mode = if following {
        Span::styled(" ● LIVE ", Style::new().fg(Color::Black).bg(ACCENT))
    } else {
        Span::styled(
            format!(" ◀ {} ", v.title),
            Style::new().fg(Color::Black).bg(DIM),
        )
    };
    let mut spans = vec![
        Span::styled(
            " lagblame ",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        mode,
        Span::raw(format!("  {when}  ")),
    ];
    if let Some(e) = &v.fatal {
        spans.push(Span::styled(format!("error: {e}"), Style::new().fg(HOT)));
    } else {
        spans.push(Span::styled(v.status.clone(), Style::new().fg(DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), head);

    // ------------------------------------------------ table
    let names = v.app_names();
    let sel = v.sel_app.min(names.len().saturating_sub(1));
    // max over the last second up to the cursor
    let idx = v.cur();
    let win: Vec<&Tick> = v
        .ticks
        .iter()
        .skip(idx.saturating_sub(3))
        .take(idx.min(3) + 1)
        .collect();
    let rows: Vec<Row> = names
        .iter()
        .enumerate()
        .map(|(i, (name, role))| {
            let a: Vec<_> = win.iter().filter_map(|t| t.app(name)).collect();
            let mx =
                |f: fn(&crate::model::AppTick) -> f64| a.iter().map(|x| f(x)).fold(0.0, f64::max);
            let sum = |f: fn(&crate::model::AppTick) -> u64| a.iter().map(|x| f(x)).sum::<u64>();
            let last = a.last();
            let hot = |val: f64, th: f64| {
                if val >= th {
                    Style::new().fg(HOT)
                } else {
                    Style::new().fg(FG)
                }
            };
            let rq = mx(|x| x.rq_max);
            let txg = mx(|x| x.tx_gap);
            let rxg = mx(|x| x.rx_gap);
            let pick = mx(|x| x.pick_max);
            let stack = mx(|x| x.stack_max);
            let drops = sum(|x| x.drops + x.rcvbuf_drops);
            let retx = sum(|x| x.retrans);
            let rtt = mx(|x| x.rtt_max);
            let label = if role == "tunnel" {
                format!("{name} (vpn)")
            } else {
                name.clone()
            };
            let style = if i == sel {
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(FG)
            };
            Row::new(vec![
                Cell::from(label).style(style),
                Cell::from(last.map(|x| x.pids.to_string()).unwrap_or_default()),
                Cell::from(format!(
                    "{} / {}",
                    ms(rq),
                    ms(last.map(|x| x.rq_p99).unwrap_or(0.0))
                ))
                .style(hot(rq, v.opts.rq_ms * 2.0)),
                Cell::from(ms(txg)).style(hot(txg, v.opts.gap_ms)),
                Cell::from(ms(rxg)).style(hot(rxg, v.opts.gap_ms)),
                Cell::from(format!(
                    "{:.0}/{:.0}",
                    last.map(|x| x.rx_pps).unwrap_or(0.0),
                    last.map(|x| x.tx_pps).unwrap_or(0.0)
                )),
                Cell::from(ms(stack)).style(hot(stack, 2.0)),
                Cell::from(ms(pick)).style(hot(pick, 8.0)),
                Cell::from(if drops > 0 {
                    drops.to_string()
                } else {
                    "·".into()
                })
                .style(hot(drops as f64, 1.0)),
                Cell::from(if rtt > 0.0 || retx > 0 {
                    format!("{} / {retx}", ms(rtt))
                } else {
                    "·".into()
                })
                .style(hot(retx as f64, 1.0)),
            ])
        })
        .collect();
    let header = Row::new([
        "app",
        "pids",
        "CPU wait max/p99",
        "send gap",
        "recv gap",
        "pkt/s in/out",
        "NIC→sock",
        "unread",
        "drops",
        "TCP rtt/retx",
    ])
    .style(Style::new().fg(DIM));
    let widths = [
        Constraint::Length(18),
        Constraint::Length(5),
        Constraint::Length(17),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(13),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(12),
    ];
    let t = Table::new(rows, widths).header(header).block(
        Block::bordered()
            .title(" apps · ms, max of the last second ")
            .border_style(Style::new().fg(DIM)),
    );
    f.render_widget(t, table);

    // ------------------------------------------------ timelines
    let gblock = Block::bordered()
        .title(format!(" timeline · {} ", v.sel_name().unwrap_or_default()))
        .border_style(Style::new().fg(DIM));
    let inner = gblock.inner(graphs);
    f.render_widget(gblock, graphs);
    let sel_name = v.sel_name().unwrap_or_default();
    type Get = Box<dyn Fn(&Tick) -> f64>;
    let n1 = sel_name.clone();
    let n2 = sel_name.clone();
    let n3 = sel_name.clone();
    let n4 = sel_name.clone();
    let metrics: Vec<(&str, Get, f64, f64)> = vec![
        (
            "recv gap",
            Box::new(move |t: &Tick| t.app(&n1).map(|a| a.rx_gap).unwrap_or(0.0)),
            100.0,
            v.opts.gap_ms,
        ),
        (
            "send gap",
            Box::new(move |t: &Tick| t.app(&n2).map(|a| a.tx_gap).unwrap_or(0.0)),
            100.0,
            v.opts.gap_ms,
        ),
        (
            "CPU wait",
            Box::new(move |t: &Tick| t.app(&n3).map(|a| a.rq_max).unwrap_or(0.0)),
            10.0,
            v.opts.rq_ms * 2.0,
        ),
        (
            "unread",
            Box::new(move |t: &Tick| t.app(&n4).map(|a| a.pick_max).unwrap_or(0.0)),
            10.0,
            8.0,
        ),
        ("softirq", Box::new(|t: &Tick| t.net.rx_sirq_max), 5.0, 2.0),
        (
            "LAN ping",
            Box::new(|t: &Tick| t.net.gw.unwrap_or(0.0)),
            10.0,
            20.0,
        ),
        (
            "net ping",
            Box::new(|t: &Tick| t.net.wan.unwrap_or(0.0)),
            50.0,
            150.0,
        ),
    ];
    let lines = Layout::vertical(vec![Constraint::Length(1); metrics.len()]).split(inner);
    for (i, (label, get, floor, th)) in metrics.iter().enumerate() {
        let Some(row) = lines.get(i) else { break };
        let [l, g, r] = Layout::horizontal([
            Constraint::Length(10),
            Constraint::Min(10),
            Constraint::Length(8),
        ])
        .areas(*row);
        let width = g.width as usize;
        let end = v.cur() + 1;
        let start = end.saturating_sub(width);
        let vals: Vec<f64> = v.ticks[start.min(v.ticks.len())..end.min(v.ticks.len())]
            .iter()
            .map(get)
            .collect();
        let peak = vals.iter().cloned().fold(0.0, f64::max);
        let maxv = peak.max(*floor);
        let data: Vec<u64> = vals.iter().map(|x| (x * 100.0) as u64).collect();
        let now = vals.last().cloned().unwrap_or(0.0);
        let color = if peak >= *th { HOT } else { ACCENT };
        f.render_widget(
            Paragraph::new(Span::styled(*label, Style::new().fg(DIM))),
            l,
        );
        f.render_widget(
            Sparkline::default()
                .data(data)
                .max((maxv * 100.0) as u64)
                .style(Style::new().fg(color)),
            g,
        );
        f.render_widget(
            Paragraph::new(Span::styled(
                format!("{:>7}", ms(now)),
                Style::new().fg(if now >= *th { HOT } else { FG }),
            )),
            r,
        );
    }

    // ------------------------------------------------ spikes + verdict
    let [left, right] =
        Layout::horizontal([Constraint::Length(54), Constraint::Min(30)]).areas(bottom);
    draw_spikes(f, v, left);
    draw_verdict(f, v, right);

    let keys = if v.live {
        " ←/→ rewind (shift ×10s) · space pause · end live · [ ] spikes · ↑/↓ app · m mark · q quit"
    } else {
        " ←/→ move (shift ×10s) · pgup/pgdn 1 min · [ ] spikes · ↑/↓ app · m mark · q quit"
    };
    f.render_widget(
        Paragraph::new(Span::styled(keys, Style::new().fg(DIM))),
        foot,
    );
}

fn draw_spikes(f: &mut Frame, v: &View, area: Rect) {
    let items: Vec<ListItem> = v
        .spikes
        .iter()
        .map(|s| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    fmt_time(s.t).get(..8).unwrap_or("").to_string(),
                    Style::new().fg(DIM),
                ),
                Span::raw(format!(" {:<10.10} ", s.app)),
                Span::styled(format!("{:<19.19}", s.what), Style::new().fg(FG)),
                Span::styled(format!("{:>6.0} ms", s.ms), Style::new().fg(HOT)),
            ]))
        })
        .collect();
    let mut st = ListState::default();
    st.select(
        v.sel_spike
            .or_else(|| (!v.spikes.is_empty()).then(|| v.spikes.len() - 1)),
    );
    let title = format!(
        " spikes ({}){} ",
        v.spikes.len(),
        if v.marks.is_empty() {
            String::new()
        } else {
            format!(" · {} marks", v.marks.len())
        }
    );
    let list = List::new(items)
        .block(
            Block::bordered()
                .title(title)
                .border_style(Style::new().fg(DIM)),
        )
        .highlight_style(Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
        .highlight_symbol("▸");
    f.render_stateful_widget(list, area, &mut st);
}

fn draw_verdict(f: &mut Frame, v: &View, area: Rect) {
    let (at, app, title) = if let Some(s) = v.sel_spike.and_then(|i| v.spikes.get(i)) {
        (
            Some(s.t),
            Some(s.app.clone()),
            format!(" why: {} {} at {} ", s.app, s.what, fmt_time(s.t)),
        )
    } else if v.cursor.is_some() {
        let t = v.ticks.get(v.cur()).map(|t| t.t);
        (
            t,
            v.sel_name(),
            format!(" at cursor {} ", t.map(fmt_time).unwrap_or_default()),
        )
    } else if let Some(s) = v.spikes.last() {
        (
            Some(s.t),
            Some(s.app.clone()),
            format!(" latest spike: {} {} at {} ", s.app, s.what, fmt_time(s.t)),
        )
    } else {
        (None, None, " verdict ".into())
    };
    let block = Block::bordered()
        .title(title)
        .border_style(Style::new().fg(DIM));
    let Some(at) = at else {
        let msg = if v.ticks.is_empty() {
            "No data yet."
        } else {
            "No spikes yet. Rewind with ← to look at any moment."
        };
        f.render_widget(
            Paragraph::new(Span::styled(msg, Style::new().fg(DIM))).block(block),
            area,
        );
        return;
    };
    let verdict = verdict::explain(&v.ticks, &v.evs, at, app.as_deref(), &v.opts);
    let mut lines = vec![Line::from(Span::styled(
        verdict.summary.clone(),
        Style::new().fg(FG).add_modifier(Modifier::BOLD),
    ))];
    for c in &verdict.causes {
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", c.layer.title()), Style::new().fg(ACCENT)),
            Span::styled(format!("{:.0}", c.score), Style::new().fg(DIM)),
        ]));
        for e in &c.evidence {
            lines.push(Line::from(Span::styled(
                format!("  · {e}"),
                Style::new().fg(FG),
            )));
        }
    }
    if verdict.causes.is_empty() && !verdict.clean.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("checked: {}", verdict.clean.join(", ")),
            Style::new().fg(OK),
        )));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppTick;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn hex(c: Color, dflt: &str) -> String {
        match c {
            Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
            Color::Black => "#120d0a".into(),
            _ => dflt.into(),
        }
    }

    /// The rendered buffer as an SVG "screenshot" for the README.
    fn to_svg(buf: &ratatui::buffer::Buffer) -> String {
        let (cw, ch) = (8.4, 18.0);
        let (w, h) = (
            buf.area.width as f64 * cw + 24.0,
            buf.area.height as f64 * ch + 24.0,
        );
        let mut s = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{h}\" viewBox=\"0 0 {w} {h}\">\n\
             <rect width=\"100%\" height=\"100%\" rx=\"8\" fill=\"#120d0a\"/>\n\
             <g font-family=\"JetBrains Mono, DejaVu Sans Mono, Menlo, Consolas, monospace\" font-size=\"14\" xml:space=\"preserve\">\n"
        );
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let c = &buf[(x, y)];
                let (px, py) = (12.0 + x as f64 * cw, 12.0 + y as f64 * ch);
                if c.bg != Color::Reset {
                    s += &format!(
                        "<rect x=\"{px:.1}\" y=\"{py:.1}\" width=\"{cw}\" height=\"{ch}\" fill=\"{}\"/>\n",
                        hex(c.bg, "#1b1410")
                    );
                }
                let sym = c.symbol();
                if sym.trim().is_empty() {
                    continue;
                }
                let esc = sym
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;");
                let bold = if c.modifier.contains(Modifier::BOLD) {
                    " font-weight=\"bold\""
                } else {
                    ""
                };
                s += &format!(
                    "<text x=\"{px:.1}\" y=\"{:.1}\" fill=\"{}\"{bold}>{esc}</text>\n",
                    py + 14.0,
                    hex(c.fg, "#d8cbbf")
                );
            }
        }
        s + "</g>\n</svg>\n"
    }

    fn fixture() -> View {
        let mut ticks = vec![];
        for i in 0..400 {
            let t = 1_794_696_000.0 + i as f64 * 0.25;
            let mut cs2 = AppTick {
                name: "cs2".into(),
                role: "app".into(),
                pids: 1,
                rx_pps: 64.0,
                tx_pps: 128.0,
                rx_gap: 17.0,
                tx_gap: 9.0,
                rq_max: 0.4,
                rq_p99: 0.1,
                stack_max: 0.02,
                pick_max: 0.3,
                ..Default::default()
            };
            let disc = AppTick {
                name: "Discord".into(),
                role: "companion".into(),
                pids: 6,
                rx_pps: 50.0,
                tx_pps: 50.0,
                rx_gap: 22.0,
                rtt_max: 14.0,
                ..Default::default()
            };
            let tun = AppTick {
                name: "mullvad-daemon".into(),
                role: "tunnel".into(),
                pids: 1,
                rx_pps: 3.0,
                ..Default::default()
            };
            if i == 300 {
                cs2.rx_gap = 182.0;
            }
            if i == 360 {
                cs2.rq_max = 23.0;
                cs2.tx_gap = 41.0;
                cs2.rx_gap = 44.0;
            }
            let mut tick = Tick {
                t,
                dt: 0.25,
                apps: vec![cs2, disc, tun],
                ..Default::default()
            };
            tick.net.gw = Some(0.7 + (i % 7) as f64 * 0.05);
            tick.net.wan = Some(12.0);
            ticks.push(tick);
        }
        let evs = vec![Ev {
            t: ticks[360].t - 0.1,
            kind: "rq".into(),
            app: Some("cs2".into()),
            ms: 23.0,
            thread: Some("cs2".into()),
            tid: Some(48211),
            cpu: Some(5),
            by: Some("cargo[90311]".into()),
            ..Default::default()
        }];
        let opts = Opts::default();
        let spikes = verdict::spikes(&ticks, &evs, &opts);
        View {
            ticks,
            evs,
            marks: vec![],
            spikes,
            cursor: None,
            sel_app: 0,
            sel_spike: None,
            live: true,
            status: "recording 2026-11-14_21-40-00.jsonl".into(),
            title: "LIVE".into(),
            opts,
            fatal: None,
        }
    }

    #[test]
    fn renders() {
        let v = fixture();
        let mut term = Terminal::new(TestBackend::new(120, 36)).unwrap();
        term.draw(|f| draw(f, &v)).unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    + "\n"
            })
            .collect();
        if std::env::var_os("SHOW_TUI").is_some() {
            println!("{text}");
        }
        if let Some(path) = std::env::var_os("TUI_SVG") {
            std::fs::write(path, to_svg(&buf)).unwrap();
        }
        assert!(text.contains("lagblame"));
        assert!(text.contains("Most likely: CPU scheduler"));
        assert!(text.contains("recv gap"));
        assert!(text.contains("mullvad-daemon"));
    }
}
