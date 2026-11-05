//! Replay capture files under `<state dir>/captures` (F055, F072, F133,
//! F149).
//!
//! Captures used to be written to `/tmp/outstation-captures`, which the
//! systemd unit's `PrivateTmp=yes` wiped on every restart. They now live
//! next to the run database, are found again after a restart, and are
//! bounded by a total-size and count cap (oldest evicted first).

use std::path::{Path, PathBuf};

use tracing::{info, warn};

pub(crate) fn capture_path(captures_dir: &Path, id: u64) -> PathBuf {
    captures_dir.join(format!("run_{id}.pcap"))
}

/// Find the capture of run `id`. Only files *inside* `captures_dir` are
/// ever returned: the canonical `run_<id>.pcap`, or a recorded path
/// that canonicalises to a regular, non-symlink file under
/// `captures_dir`. Captures from before the move out of `/tmp` are not
/// read: that directory is world-writable (symlink/planted-file risk)
/// and `PrivateTmp=yes` wiped it on every restart anyway.
pub(crate) fn locate_capture(
    captures_dir: &Path,
    id: u64,
    recorded: Option<&str>,
) -> Option<PathBuf> {
    let current = capture_path(captures_dir, id);
    if is_regular_file_inside(&current, captures_dir) {
        return Some(current);
    }
    if let Some(r) = recorded {
        let p = PathBuf::from(r);
        if is_regular_file_inside(&p, captures_dir) {
            return Some(p);
        }
    }
    // Nothing on disk; keep the canonical location so a later check
    // reports it as missing.
    Some(current)
}

/// True when `p` is a regular file (not a symlink) whose canonical path
/// lies inside the canonical `dir`.
pub(crate) fn is_regular_file_inside(p: &Path, dir: &Path) -> bool {
    let Ok(md) = std::fs::symlink_metadata(p) else {
        return false;
    };
    if !md.file_type().is_file() {
        return false;
    }
    match (p.canonicalize(), dir.canonicalize()) {
        (Ok(cp), Ok(cd)) => cp.starts_with(&cd),
        _ => false,
    }
}

/// Evict the oldest `run_*.pcap` files until the directory holds at
/// most `max_count` files and `max_bytes` bytes. Files in `keep` (the
/// active run's capture, the run that just finished and runs whose
/// analysis is still pending) are never evicted. Returns the evicted
/// paths.
pub(crate) fn enforce_retention(
    captures_dir: &Path,
    max_bytes: u64,
    max_count: usize,
    keep: &[PathBuf],
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
        if keep.iter().any(|k| k == &p) {
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
        let ev = enforce_retention(d.path(), 250, 100, std::slice::from_ref(&keep));
        assert_eq!(
            ev,
            vec![capture_path(d.path(), 2), capture_path(d.path(), 3)]
        );
        assert!(keep.exists());
        assert!(capture_path(d.path(), 4).exists());
    }

    #[test]
    fn locate_only_returns_regular_files_inside_captures_dir() {
        let cur = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(&capture_path(cur.path(), 5), 10);
        assert_eq!(
            locate_capture(cur.path(), 5, None),
            Some(capture_path(cur.path(), 5))
        );
        // A recorded path outside the captures dir is never returned.
        let foreign = outside.path().join("secret.pcap");
        write(&foreign, 10);
        let got = locate_capture(cur.path(), 6, Some(foreign.to_str().unwrap()));
        assert_eq!(got, Some(capture_path(cur.path(), 6)));
        // A symlink inside the captures dir pointing outside is refused.
        let link = capture_path(cur.path(), 7);
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        assert!(!is_regular_file_inside(&link, cur.path()));
    }
}
