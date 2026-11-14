//! Finds the watched apps in /proc.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub name: String,
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// starts a session when it runs
    App,
    /// watched only while an app runs (e.g. voice chat during a game)
    Companion,
    /// userspace VPN, watched so its stalls can be blamed
    Tunnel,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::App => "app",
            Role::Companion => "companion",
            Role::Tunnel => "tunnel",
        }
    }
}

fn base(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

/// Does a process with this comm / exe / argv[0] count as `want`?
pub fn matches(want: &str, comm: &str, exe: Option<&str>, argv0: Option<&str>) -> bool {
    let w = want.to_ascii_lowercase();
    let eq = |s: &str| {
        let s = base(s).to_ascii_lowercase();
        // comm is cut at 15 bytes
        s == w || (s.len() == 15 && w.starts_with(&s)) || s == format!("{w}.exe")
    };
    eq(comm) || exe.is_some_and(eq) || argv0.is_some_and(eq)
}

fn proc_info(dir: &Path) -> Option<(String, Option<String>, Option<String>)> {
    let comm = fs::read_to_string(dir.join("comm"))
        .ok()?
        .trim_end()
        .to_string();
    let exe = fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let argv0 = fs::read(dir.join("cmdline")).ok().and_then(|b| {
        let first = b.split(|c| *c == 0).next()?;
        (!first.is_empty()).then(|| String::from_utf8_lossy(first).into_owned())
    });
    Some((comm, exe, argv0))
}

/// tgids per wanted name (only names that are running).
pub fn scan(wants: &[Want]) -> BTreeMap<String, Vec<u32>> {
    let mut out: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return out;
    };
    for ent in rd.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Some((comm, exe, argv0)) = proc_info(&ent.path()) else {
            continue;
        };
        for w in wants {
            if matches(&w.name, &comm, exe.as_deref(), argv0.as_deref()) {
                out.entry(w.name.clone()).or_default().push(pid);
                break;
            }
        }
    }
    out
}

/// Another `lagblame record` already running (the background service)?
pub fn recorder_running() -> bool {
    let me = std::process::id();
    let Ok(rd) = fs::read_dir("/proc") else {
        return false;
    };
    rd.flatten().any(|e| {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            return false;
        };
        if pid == me {
            return false;
        }
        let Ok(cmd) = fs::read(e.path().join("cmdline")) else {
            return false;
        };
        let args: Vec<&[u8]> = cmd.split(|c| *c == 0).collect();
        args.first()
            .is_some_and(|a0| base(&String::from_utf8_lossy(a0)) == "lagblame")
            && args.iter().any(|a| *a == b"record")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_rules() {
        assert!(matches("cs2", "cs2", None, None));
        assert!(matches("discord", "Discord", None, None));
        assert!(matches(
            "Discord",
            "electron",
            Some("/opt/discord/Discord"),
            None
        ));
        assert!(matches("mullvad-daemon", "mullvad-daemon", None, None));
        // comm truncated to 15 chars
        assert!(matches("steamwebhelper-x", "steamwebhelper-", None, None));
        assert!(matches(
            "game",
            "wine64-preload",
            None,
            Some("Z:\\games\\game.exe")
        ));
        assert!(!matches(
            "cs2",
            "cs2-presence",
            None,
            Some("/home/u/.local/bin/cs2-presence")
        ));
        assert!(!matches("cs", "cs2", None, None));
    }
}
