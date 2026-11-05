//! Shared application state.

use std::collections::HashMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use tracing::warn;

use crate::db::Db;
use crate::dto::*;

#[derive(Clone)]
pub struct AppState {
    pub(crate) runs: Arc<Mutex<HashMap<u64, RunState>>>,
    pub(crate) next_id: Arc<AtomicU64>,
    pub(crate) library_dir: Arc<PathBuf>,
    pub(crate) db: Db,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let library_dir = std::env::var("OUTSTATION_LIBRARY_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/outstation/library"));
        if let Err(e) = std::fs::create_dir_all(&library_dir) {
            warn!(dir = %library_dir.display(), error = %e, "library dir create failed");
        }
        let db_path = library_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/var/lib/outstation"))
            .join("runs.sqlite");
        let db = Db::open(&db_path).unwrap_or_else(|e| {
            warn!(error = %e, path = %db_path.display(), "failed to open runs db — falling back to in-memory");
            Db::open(StdPath::new(":memory:")).expect("open in-memory sqlite")
        });
        Self {
            runs: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            library_dir: Arc::new(library_dir),
            db,
        }
    }
}

/// Where the IP-alias state file lives. Defaults to a sibling of the
/// library dir under /var/lib/outstation; honors OUTSTATION_LIBRARY_DIR
/// for parity with the library layout.
pub(crate) fn alias_state_path() -> std::path::PathBuf {
    let library_dir = std::env::var("OUTSTATION_LIBRARY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/outstation/library"));
    let parent = library_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/outstation"));
    parent.join("state-aliases.txt")
}
