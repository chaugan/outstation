//! One process per state directory (N7).
//!
//! `outstation serve` runs a host cleanup at startup that removes every
//! outstation-marked interface and tagged rule, and `outstation cleanup`
//! does the same by hand. Either one, started while a server is running
//! a replay, would tear down the live run. The server and `outstation
//! bench` therefore hold an exclusive `flock` on `<state>/outstation.lock`
//! for as long as they run; a second server or bench with the same
//! state directory refuses to start, and `outstation cleanup` refuses
//! unless `--force`. The kernel drops the lock when the holder exits,
//! however it exits, so a crash never leaves a stale lock behind. The
//! file holds the holder's pid and role, for the error message only.

use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Name of the lock file inside the state directory.
pub const LOCK_FILE: &str = "outstation.lock";

/// The lock is held by another live process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockHeld {
    pub path: PathBuf,
    /// `pid=<n> role=<serve|bench|cleanup>` as the holder wrote it, if
    /// it could be read.
    pub holder: Option<String>,
}

impl std::fmt::Display for LockHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the state directory is in use by another outstation process ({}; lock {})",
            self.holder.as_deref().unwrap_or("holder unknown"),
            self.path.display()
        )
    }
}

impl std::error::Error for LockHeld {}

/// An exclusive lock on a state directory, released on drop or exit.
#[derive(Debug)]
pub struct StateLock {
    // Keeps the descriptor (and so the flock) alive.
    _file: File,
    path: PathBuf,
}

impl StateLock {
    /// Take the lock for `role` (e.g. `serve`). Fails with [`LockHeld`]
    /// (downcastable from the error) when another process holds it.
    pub fn acquire(state_dir: &Path, role: &str) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("create {}", state_dir.display()))?;
        let path = state_dir.join(LOCK_FILE);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        // SAFETY: flock on a descriptor we own.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                let mut s = String::new();
                let holder = file
                    .read_to_string(&mut s)
                    .ok()
                    .map(|_| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                return Err(LockHeld { path, holder }.into());
            }
            return Err(err).with_context(|| format!("lock {}", path.display()));
        }
        file.set_len(0)?;
        file.rewind()?;
        writeln!(file, "pid={} role={role}", std::process::id())?;
        file.flush()?;
        Ok(Self { _file: file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Is the lock of `state_dir` held by a live process? `Some(holder)`
/// when it is; `None` when it is free (or the directory has no lock).
pub fn held_by(state_dir: &Path) -> Option<LockHeld> {
    if !state_dir.join(LOCK_FILE).exists() {
        return None;
    }
    match StateLock::acquire(state_dir, "probe") {
        Ok(_) => None,
        Err(e) => e.downcast::<LockHeld>().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_holder_is_refused_until_the_first_drops() {
        let d = tempfile::tempdir().unwrap();
        let a = StateLock::acquire(d.path(), "serve").unwrap();
        let e = StateLock::acquire(d.path(), "serve").unwrap_err();
        let held = e.downcast::<LockHeld>().expect("LockHeld");
        let holder = held.holder.clone().unwrap();
        assert!(
            holder.contains(&format!("pid={}", std::process::id())),
            "{holder}"
        );
        assert!(holder.contains("role=serve"));
        assert!(held.to_string().contains("in use"));
        assert!(held_by(d.path()).is_some());
        drop(a);
        assert!(held_by(d.path()).is_none());
        let _b = StateLock::acquire(d.path(), "bench").unwrap();
        let held = held_by(d.path()).unwrap();
        assert!(held.holder.unwrap().contains("role=bench"));
    }

    #[test]
    fn missing_lock_file_means_free() {
        let d = tempfile::tempdir().unwrap();
        assert!(held_by(&d.path().join("nope")).is_none());
    }
}
