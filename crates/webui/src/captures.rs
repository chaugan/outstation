//! Replay capture files under `<state dir>/captures` (F055, F072, F133,
//! F149).
//!
//! Captures used to be written to `/tmp/outstation-captures`, which the
//! systemd unit's `PrivateTmp=yes` wiped on every restart. They now live
//! next to the run database, are found again after a restart, and are
//! bounded by a total-size and count cap (oldest evicted first).

use std::path::{Path, PathBuf};

use tracing::{info, warn};

/// Pre-T04 capture location.
pub(crate) const LEGACY_CAPTURE_DIR: &str = "/tmp/outstation-captures";

pub(crate) fn capture_path(captures_dir: &Path, id: u64) -> PathBuf {
    captures_dir.join(format!("run_{id}.pcap"))
}

/// Find the capture of run `id`: the current location first, then the
/// path recorded in its report, then the legacy /tmp location.
pub(crate) fn locate_capture(
    captures_dir: &Path,
    id: u64,
    recorded: Option<&str>,
) -> Option<PathBuf> {
    let current = capture_path(captures_dir, id);
    if current.is_file() {
        return Some(current);
    }
    if let Some(r) = recorded {
        let p = PathBuf::from(r);
        if p.is_file() {
            return Some(p);
        }
    }
    let legacy = capture_path(Path::new(LEGACY_CAPTURE_DIR), id);
    if legacy.is_file() {
        return Some(legacy);
    }
    // Nothing on disk; keep the canonical location so a later check
    // reports it as missing rather than pointing at /tmp.
    Some(current)
}

/// Move `run_<id>.pcap` files for known runs from the legacy /tmp dir
/// into `captures_dir`. Best effort: failures are logged.
pub(crate) fn migrate_legacy(captures_dir: &Path, known_ids: &[u64], legacy_dir: &Path) -> usize {
    let mut moved = 0;
    for &id in known_ids {
        let from = capture_path(legacy_dir, id);
        let to = capture_path(captures_dir, id);
        if !from.is_file() || to.exists() {
            continue;
        }
        let res = std::fs::rename(&from, &to)
            .or_else(|_| std::fs::copy(&from, &to).and_then(|_| std::fs::remove_file(&from)));
        match res {
            Ok(()) => moved += 1,
            Err(e) => {
                warn!(id, from = %from.display(), error = %e, "could not migrate legacy capture")
            }
        }
    }
    if moved > 0 {
        info!(moved, dir = %captures_dir.display(), "migrated captures out of /tmp");
    }
    moved
}

/// Evict the oldest `run_*.pcap` files until the directory holds at
/// most `max_count` files and `max_bytes` bytes. `keep` (the active
/// run's capture) is never evicted. Returns the evicted paths.
pub(crate) fn enforce_retention(
    captures_dir: &Path,
    max_bytes: u64,
    max_count: usize,
    keep: Option<&Path>,
) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(captures_dir) else {
        return Vec::new();
    };
    let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_str()?;
            if !(name.starts_with("run_") && name.ends_with(".pcap")) {
                return None;
            }
            let md = e.metadata().ok()?;
            md.is_file()
                .then(|| (md.modified().unwrap_or(std::time::UNIX_EPOCH), md.len(), p))
        })
        .collect();
    files.sort_by_key(|f| f.0);
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    let mut count = files.len();
    let mut evicted = Vec::new();
    for (_, len, p) in files {
        if total <= max_bytes && count <= max_count {
            break;
        }
        if keep == Some(p.as_path()) {
            continue;
        }
        match std::fs::remove_file(&p) {
            Ok(()) => {
                total = total.saturating_sub(len);
                count -= 1;
                info!(path = %p.display(), bytes = len, "evicted capture (retention cap)");
                evicted.push(p);
            }
            Err(e) => warn!(path = %p.display(), error = %e, "capture eviction failed"),
        }
    }
    evicted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &Path, n: usize) {
        std::fs::write(p, vec![0u8; n]).unwrap();
    }

    #[test]
    fn retention_evicts_oldest_and_keeps_active() {
        let d = tempfile::tempdir().unwrap();
        for id in 1..=4 {
            write(&capture_path(d.path(), id), 100);
            // Distinct mtimes.
            let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(id * 10);
            let f = std::fs::File::options()
                .write(true)
                .open(capture_path(d.path(), id))
                .unwrap();
            f.set_modified(t).unwrap();
        }
        let keep = capture_path(d.path(), 1);
        let ev = enforce_retention(d.path(), 250, 100, Some(&keep));
        assert_eq!(
            ev,
            vec![capture_path(d.path(), 2), capture_path(d.path(), 3)]
        );
        assert!(keep.exists());
        assert!(capture_path(d.path(), 4).exists());
    }

    #[test]
    fn legacy_captures_are_migrated() {
        let legacy = tempfile::tempdir().unwrap();
        let cur = tempfile::tempdir().unwrap();
        write(&capture_path(legacy.path(), 5), 10);
        write(&capture_path(legacy.path(), 6), 10);
        assert_eq!(migrate_legacy(cur.path(), &[5], legacy.path()), 1);
        assert!(capture_path(cur.path(), 5).is_file());
        assert!(capture_path(legacy.path(), 6).is_file());
        assert_eq!(
            locate_capture(cur.path(), 5, None),
            Some(capture_path(cur.path(), 5))
        );
    }
}
