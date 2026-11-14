//! Session files: one JSON Lines file per stretch of time a watched app ran.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};

use crate::config::state_dir;
use crate::model::{Ev, Line, Mark, Meta, Tick};

pub struct Writer {
    out: BufWriter<File>,
    pub path: PathBuf,
    last_flush: Instant,
}

impl Writer {
    pub fn create(dir: &Path, meta: &Meta) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let name = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let mut path = dir.join(format!("{name}.jsonl"));
        let mut n = 2;
        while path.exists() {
            path = dir.join(format!("{name}-{n}.jsonl"));
            n += 1;
        }
        let f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        let mut w = Self {
            out: BufWriter::new(f),
            path,
            last_flush: Instant::now(),
        };
        w.write(&Line::Meta(meta.clone()))?;
        w.flush()?;
        Ok(w)
    }

    pub fn write(&mut self, l: &Line) -> Result<()> {
        serde_json::to_writer(&mut self.out, l)?;
        self.out.write_all(b"\n")?;
        if self.last_flush.elapsed() >= Duration::from_secs(1) {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.out.flush()?;
        self.last_flush = Instant::now();
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.out.flush();
    }
}

#[derive(Debug, Default, Clone)]
pub struct Session {
    pub path: PathBuf,
    pub meta: Meta,
    pub ticks: Vec<Tick>,
    pub evs: Vec<Ev>,
    pub marks: Vec<Mark>,
}

impl Session {
    pub fn start(&self) -> f64 {
        self.ticks
            .first()
            .map(|t| t.t - t.dt)
            .unwrap_or(self.meta.started)
    }
    pub fn end(&self) -> f64 {
        self.ticks.last().map(|t| t.t).unwrap_or(self.meta.started)
    }
}

pub fn read(path: &Path) -> Result<Session> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut s = Session {
        path: path.to_path_buf(),
        ..Default::default()
    };
    for line in BufReader::new(f).lines() {
        let Ok(line) = line else { break };
        // a crash can leave a half-written last line
        let Ok(l) = serde_json::from_str::<Line>(&line) else {
            continue;
        };
        match l {
            Line::Meta(m) => s.meta = m,
            Line::Tick(t) => s.ticks.push(t),
            Line::Ev(e) => s.evs.push(e),
            Line::Mark(m) => s.marks.push(m),
        }
    }
    let (a, b) = (s.start() - 1.0, s.end() + 5.0);
    s.marks
        .extend(read_marks().into_iter().filter(|m| m.t >= a && m.t <= b));
    s.marks.sort_by(|x, y| x.t.total_cmp(&y.t));
    s.marks.dedup_by(|x, y| (x.t - y.t).abs() < 0.001);
    Ok(s)
}

pub fn list(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// `None`/"latest" = newest session; otherwise a path or a (prefix of a) file name in `dir`.
pub fn resolve(dir: &Path, arg: Option<&str>) -> Result<PathBuf> {
    let all = list(dir);
    match arg {
        None | Some("latest") | Some("last") => all
            .last()
            .cloned()
            .ok_or_else(|| anyhow!("no sessions in {} yet", dir.display())),
        Some(a) => {
            let p = PathBuf::from(a);
            if p.exists() {
                return Ok(p);
            }
            let hits: Vec<&PathBuf> = all
                .iter()
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with(a))
                })
                .collect();
            match hits.as_slice() {
                [one] => Ok((*one).clone()),
                [] => bail!("no session matching {a:?} in {}", dir.display()),
                many => Ok(many.last().map(|p| (*p).clone()).unwrap_or_default()),
            }
        }
    }
}

/// Session that covers unix time `t` (or the newest one before it).
pub fn covering(dir: &Path, t: f64) -> Option<PathBuf> {
    let mut best = None;
    for p in list(dir) {
        let started = p
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| NaiveDateTime::parse_from_str(s.get(..19)?, "%Y-%m-%d_%H-%M-%S").ok())
            .and_then(|n| Local.from_local_datetime(&n).earliest())
            .map(|d| d.timestamp() as f64);
        if started.is_some_and(|s| s <= t + 1.0) {
            best = Some(p);
        }
    }
    best
}

/// Delete sessions older than `days` and the oldest ones beyond `max_mb`.
pub fn prune(dir: &Path, days: u64, max_mb: u64) -> usize {
    let mut files: Vec<(PathBuf, SystemTime, u64)> = list(dir)
        .into_iter()
        .filter_map(|p| {
            let m = fs::metadata(&p).ok()?;
            Some((p, m.modified().ok()?, m.len()))
        })
        .collect();
    files.sort_by_key(|f| f.1);
    let mut removed = 0;
    let cutoff = SystemTime::now() - Duration::from_secs(days * 86400);
    let mut total: u64 = files.iter().map(|f| f.2).sum();
    // never touch the newest file (it may be the one being written)
    let keep_last = files.pop();
    for (p, mtime, len) in files {
        if (mtime < cutoff || total > max_mb * 1024 * 1024) && fs::remove_file(&p).is_ok() {
            removed += 1;
            total = total.saturating_sub(len);
        }
    }
    drop(keep_last);
    removed
}

pub fn marks_path() -> PathBuf {
    state_dir().join("marks.jsonl")
}

pub fn add_mark(m: &Mark) -> Result<()> {
    let p = marks_path();
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(&p)?;
    writeln!(f, "{}", serde_json::to_string(m)?)?;
    Ok(())
}

pub fn read_marks() -> Vec<Mark> {
    let Ok(f) = File::open(marks_path()) else {
        return vec![];
    };
    BufReader::new(f)
        .lines()
        .map_while(|l| l.ok())
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

/// "21:43:10", "21:43:10.5", "2026-11-14 21:43:10", unix seconds, or "-30s" (before `end`).
pub fn parse_time(s: &str, start: f64, end: f64) -> Result<f64> {
    let s = s.trim();
    if let Some(rel) = s.strip_prefix('-') {
        let secs = parse_duration(rel)?;
        return Ok(end - secs);
    }
    if let Ok(v) = s.parse::<f64>()
        && v > 1e9
    {
        return Ok(v);
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return local_ts(n);
        }
    }
    let time = NaiveTime::parse_from_str(s, "%H:%M:%S%.f")
        .or_else(|_| NaiveTime::parse_from_str(s, "%H:%M:%S"))
        .or_else(|_| NaiveTime::parse_from_str(s, "%H:%M"))
        .map_err(|_| {
            anyhow!("can't read time {s:?} (try 21:43:10, \"2026-11-14 21:43:10\" or -30s)")
        })?;
    let day: NaiveDate = Local
        .timestamp_opt(start as i64, 0)
        .single()
        .map(|d| d.date_naive())
        .ok_or_else(|| anyhow!("bad session start"))?;
    let mut t = local_ts(day.and_time(time))?;
    // session crossed midnight
    if t < start - 3600.0 {
        t += 86400.0;
    }
    Ok(t)
}

fn local_ts(n: NaiveDateTime) -> Result<f64> {
    let d = Local
        .from_local_datetime(&n)
        .earliest()
        .ok_or_else(|| anyhow!("time does not exist locally"))?;
    Ok(d.timestamp() as f64 + d.timestamp_subsec_micros() as f64 / 1e6)
}

pub fn parse_duration(s: &str) -> Result<f64> {
    let s = s.trim();
    let (num, mul) = if let Some(n) = s.strip_suffix("ms") {
        (n, 0.001)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1.0)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60.0)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600.0)
    } else {
        (s, 1.0)
    };
    Ok(num
        .trim()
        .parse::<f64>()
        .map_err(|_| anyhow!("bad duration {s:?}"))?
        * mul)
}

pub fn fmt_time(t: f64) -> String {
    Local
        .timestamp_opt(t.floor() as i64, ((t.fract()) * 1e9) as u32)
        .single()
        .map(|d| d.format("%H:%M:%S%.3f").to_string())
        .unwrap_or_else(|| format!("{t:.3}"))
}

pub fn fmt_datetime(t: f64) -> String {
    Local
        .timestamp_opt(t as i64, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| format!("{t:.0}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppTick;

    #[test]
    fn roundtrip_and_truncated_tail() {
        let dir = tempfile::tempdir().unwrap();
        let meta = Meta {
            version: "t".into(),
            started: 100.0,
            apps: vec!["cs2".into()],
            ..Default::default()
        };
        let path = {
            let mut w = Writer::create(dir.path(), &meta).unwrap();
            let tick = Tick {
                t: 101.0,
                dt: 0.25,
                apps: vec![AppTick {
                    name: "cs2".into(),
                    rx_gap: 12.5,
                    ..Default::default()
                }],
                ..Default::default()
            };
            w.write(&Line::Tick(tick)).unwrap();
            w.write(&Line::Ev(Ev {
                t: 101.1,
                kind: "rq".into(),
                ms: 9.0,
                ..Default::default()
            }))
            .unwrap();
            w.path.clone()
        };
        // simulate a crash mid-line
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        write!(f, "{{\"k\":\"tick\",\"t\":10").unwrap();
        let s = read(&path).unwrap();
        assert_eq!(s.meta.apps, vec!["cs2"]);
        assert_eq!(s.ticks.len(), 1);
        assert_eq!(s.ticks[0].apps[0].rx_gap, 12.5);
        assert_eq!(s.evs.len(), 1);
        assert_eq!(resolve(dir.path(), None).unwrap(), path);
    }

    #[test]
    fn times() {
        let start = local_ts(
            NaiveDateTime::parse_from_str("2026-11-14 21:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
        )
        .unwrap();
        let t = parse_time("21:43:10", start, start + 7200.0).unwrap();
        assert_eq!(t - start, 43.0 * 60.0 + 10.0);
        let t = parse_time("00:10:00", start, start + 7200.0).unwrap();
        assert_eq!(t - start, 3.0 * 3600.0 + 10.0 * 60.0);
        assert_eq!(
            parse_time("-30s", start, start + 100.0).unwrap(),
            start + 70.0
        );
        assert_eq!(parse_duration("250ms").unwrap(), 0.25);
        assert!(parse_time("nonsense", start, start).is_err());
    }
}
