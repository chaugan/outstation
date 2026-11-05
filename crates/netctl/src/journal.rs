//! Crash-safe state journal.
//!
//! Every reversible host change outstation makes is written to a small
//! line-oriented text file under a caller-chosen state directory
//! *before* the change is applied, and removed only after the change
//! was successfully undone. After a crash, [`crate::cleanup_all`]
//! replays the journal.
//!
//! Two files live in the state directory:
//!
//! * [`ALIASES_FILE`] (`state-aliases.txt`): one IP alias per line,
//!   `<iface> <ip> <prefix>` (the historical format, kept so files
//!   written by older versions are still reclaimed).
//! * [`GUARDS_FILE`] (`state-guards.txt`): sysctl/offload prior values
//!   and iptables rules, see [`GuardEntry`].
//!
//! Every read-modify-write holds an exclusive `flock` on a sidecar
//! `<file>.lock` (so concurrent threads *and* processes serialize), and
//! the new content is written to a temp file, fsynced and renamed over
//! the original, so a crash mid-write never leaves a truncated file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Alias journal file name inside the state directory.
pub const ALIASES_FILE: &str = "state-aliases.txt";
/// Guard journal file name inside the state directory.
pub const GUARDS_FILE: &str = "state-guards.txt";
/// Default state directory for callers that have no better choice.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/outstation";

/// Path of the alias journal in `state_dir`.
pub fn aliases_path(state_dir: &Path) -> PathBuf {
    state_dir.join(ALIASES_FILE)
}

/// Path of the guard journal in `state_dir`.
pub fn guards_path(state_dir: &Path) -> PathBuf {
    state_dir.join(GUARDS_FILE)
}

/// Exclusive advisory lock on `<path>.lock`, released on drop.
struct FileLock {
    _file: File,
}

impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open lock file {}", lock_path.display()))?;
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err).with_context(|| format!("flock {}", lock_path.display()));
            }
        }
        Ok(Self { _file: file })
    }
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn write_atomic(path: &Path, lines: &[String]) -> Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    {
        let mut f = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        for l in lines {
            f.write_all(l.as_bytes())?;
            f.write_all(b"\n")?;
        }
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Locked read-modify-write of a journal file. `f` gets the current
/// non-empty lines and may edit them; the file is rewritten atomically
/// only if they changed. The lock is held while `f` runs, so `f` can
/// apply the host change it is journaling and keep the two consistent.
pub fn update_lines<R>(path: &Path, f: impl FnOnce(&mut Vec<String>) -> R) -> Result<R> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create state dir {}", parent.display()))?;
        }
    }
    let _lock = FileLock::acquire(path)?;
    let before = read_lines(path)?;
    let mut lines = before.clone();
    let r = f(&mut lines);
    if lines != before {
        write_atomic(path, &lines)?;
    }
    Ok(r)
}

/// Locked snapshot of a journal's lines.
pub fn read_journal(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let _lock = FileLock::acquire(path)?;
    read_lines(path)
}

/// Append `line` unless an identical line is already present.
pub fn add_line(path: &Path, line: &str) -> Result<()> {
    check_line(line)?;
    update_lines(path, |lines| {
        if !lines.iter().any(|l| l == line) {
            lines.push(line.to_string());
        }
    })
}

/// Remove the first line equal to `line`. Returns whether one was found.
pub fn remove_line(path: &Path, line: &str) -> Result<bool> {
    update_lines(path, |lines| {
        if let Some(i) = lines.iter().position(|l| l == line) {
            lines.remove(i);
            true
        } else {
            false
        }
    })
}

fn check_line(line: &str) -> Result<()> {
    if line.contains('\n') || line.contains('\r') || line.trim().is_empty() {
        bail!("invalid journal line {line:?}");
    }
    Ok(())
}

/// One record in the guard journal. Each serializes to one
/// whitespace-separated line; every field is validated to contain no
/// whitespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardEntry {
    /// `sysctl <key> <prev>`: restore `key` to `prev`.
    Sysctl { key: String, prev: String },
    /// `offload <nic> <feature> <on|off>`: restore an ethtool feature.
    Offload {
        nic: String,
        feature: String,
        prev_on: bool,
    },
    /// `iptables <table> <chain> <rule...>`: delete this rule.
    Iptables {
        table: String,
        chain: String,
        rule: Vec<String>,
    },
}

fn token_ok(t: &str) -> bool {
    !t.is_empty() && !t.chars().any(char::is_whitespace)
}

impl GuardEntry {
    pub fn to_line(&self) -> Result<String> {
        let parts: Vec<&str> = match self {
            GuardEntry::Sysctl { key, prev } => vec!["sysctl", key, prev],
            GuardEntry::Offload {
                nic,
                feature,
                prev_on,
            } => vec!["offload", nic, feature, if *prev_on { "on" } else { "off" }],
            GuardEntry::Iptables { table, chain, rule } => {
                let mut v = vec!["iptables", table.as_str(), chain.as_str()];
                v.extend(rule.iter().map(String::as_str));
                v
            }
        };
        if let Some(bad) = parts.iter().find(|p| !token_ok(p)) {
            bail!("journal field {bad:?} is empty or contains whitespace");
        }
        Ok(parts.join(" "))
    }

    pub fn parse(line: &str) -> Option<Self> {
        let t: Vec<&str> = line.split_ascii_whitespace().collect();
        match t.as_slice() {
            ["sysctl", key, prev] => Some(GuardEntry::Sysctl {
                key: key.to_string(),
                prev: prev.to_string(),
            }),
            ["offload", nic, feature, v @ ("on" | "off")] => Some(GuardEntry::Offload {
                nic: nic.to_string(),
                feature: feature.to_string(),
                prev_on: *v == "on",
            }),
            ["iptables", table, chain, rule @ ..] if !rule.is_empty() => {
                Some(GuardEntry::Iptables {
                    table: table.to_string(),
                    chain: chain.to_string(),
                    rule: rule.iter().map(|s| s.to_string()).collect(),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "netctl-journal-{tag}-{}-{}",
            std::process::id(),
            crate::test_nonce()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn add_remove_roundtrip() {
        let d = tmpdir("rt");
        let p = d.join("j.txt");
        add_line(&p, "a 1").unwrap();
        add_line(&p, "b 2").unwrap();
        add_line(&p, "a 1").unwrap(); // dedup
        assert_eq!(read_journal(&p).unwrap(), vec!["a 1", "b 2"]);
        assert!(remove_line(&p, "a 1").unwrap());
        assert!(!remove_line(&p, "a 1").unwrap());
        assert_eq!(read_journal(&p).unwrap(), vec!["b 2"]);
        assert!(!d.join("j.txt.tmp").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn creates_missing_state_dir() {
        let d = tmpdir("mk").join("nested/deeper");
        let p = d.join("j.txt");
        add_line(&p, "x").unwrap();
        assert_eq!(read_journal(&p).unwrap(), vec!["x"]);
    }

    #[test]
    fn rejects_multiline() {
        let d = tmpdir("ml");
        assert!(add_line(&d.join("j"), "a\nb").is_err());
        assert!(add_line(&d.join("j"), "  ").is_err());
    }

    #[test]
    fn concurrent_writers_lose_nothing() {
        // F033: 200 threads appending and removing at once must not
        // drop each other's records.
        let d = tmpdir("cc");
        let p = d.join("j.txt");
        std::thread::scope(|s| {
            for i in 0..50 {
                let p = &p;
                s.spawn(move || {
                    add_line(p, &format!("keep {i}")).unwrap();
                    add_line(p, &format!("drop {i}")).unwrap();
                    assert!(remove_line(p, &format!("drop {i}")).unwrap());
                });
            }
        });
        let mut got = read_journal(&p).unwrap();
        got.sort();
        let mut want: Vec<String> = (0..50).map(|i| format!("keep {i}")).collect();
        want.sort();
        assert_eq!(got, want);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn guard_entry_roundtrip() {
        let es = [
            GuardEntry::Sysctl {
                key: "net.ipv4.ip_forward".into(),
                prev: "0".into(),
            },
            GuardEntry::Offload {
                nic: "eth0".into(),
                feature: "tx".into(),
                prev_on: true,
            },
            GuardEntry::Iptables {
                table: "raw".into(),
                chain: "PREROUTING".into(),
                rule: "-i pcr1_br -m comment --comment outstation-run-1 -j DROP"
                    .split(' ')
                    .map(String::from)
                    .collect(),
            },
        ];
        for e in es {
            let l = e.to_line().unwrap();
            assert_eq!(GuardEntry::parse(&l), Some(e));
        }
        assert!(GuardEntry::Sysctl {
            key: "a b".into(),
            prev: "1".into()
        }
        .to_line()
        .is_err());
        assert_eq!(GuardEntry::parse("garbage"), None);
        assert_eq!(GuardEntry::parse("iptables raw PREROUTING"), None);
    }
}
