//! Server configuration and shared application state.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::sync::{broadcast, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::db::Db;
use crate::dto::*;
use crate::error::LockExt;
use crate::events::RunEvent;
use crate::runs::{RunExecutor, SchedExecutor};

/// Default library directory when `OUTSTATION_LIBRARY_DIR` is unset.
pub const DEFAULT_LIBRARY_DIR: &str = "/var/lib/outstation/library";

/// Library directory from `OUTSTATION_LIBRARY_DIR`, else the default.
pub fn default_library_dir() -> PathBuf {
    std::env::var_os("OUTSTATION_LIBRARY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LIBRARY_DIR))
}

/// State directory: the parent of the library dir (`/var/lib/outstation`
/// by default). The DB, alias state file, captures and temp files live
/// here.
pub fn state_dir_for(library_dir: &Path) -> PathBuf {
    library_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/var/lib/outstation"))
}

/// The state directory implied by the environment.
pub fn default_state_dir() -> PathBuf {
    state_dir_for(&default_library_dir())
}

/// Where the IP-alias state file lives inside `state_dir`.
pub fn alias_state_path_in(state_dir: &Path) -> PathBuf {
    state_dir.join("state-aliases.txt")
}

/// Default for [`ServeConfig::runs_in_memory`].
pub const DEFAULT_RUNS_IN_MEMORY: usize = 500;

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// Everything `serve` needs to know. Built by the CLI; tests build one
/// around a temp dir.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    pub bind: SocketAddr,
    pub library_dir: PathBuf,
    pub state_dir: PathBuf,
    /// Keep run history in memory only. Without it, failing to open the
    /// DB is a startup error (F076).
    pub ephemeral: bool,
    /// Extra Host names accepted by the same-origin guard, on top of IP
    /// literals, `localhost` and this machine's host names.
    pub allow_hosts: Vec<String>,
    /// Extra trusted `Origin`s (`scheme://host[:port]`, normalized) for
    /// state-changing requests and WebSockets, for a reverse proxy that
    /// rewrites `Host`. Empty by default.
    pub allow_origins: Vec<String>,
    /// Largest accepted upload (library and analysis), in bytes.
    pub max_upload_bytes: u64,
    /// Uploads and new captures are refused when free space in the state
    /// dir would drop below this many bytes.
    pub min_free_bytes: u64,
    /// Free-space source of the disk checks (uploads, health, the run
    /// guard); statvfs by default.
    pub free_space: crate::sysinfo::FreeSpace,
    /// Total size cap for `<state>/captures`; oldest captures are evicted
    /// first.
    pub capture_max_total_bytes: u64,
    /// Maximum number of capture files kept.
    pub capture_max_count: usize,
    /// Per-run capture size cap in bytes; a capture that reaches it
    /// stops recording and the run says `capture_truncated` (F055,
    /// F072). 0 = no cap. `--capture-run-max-mb` or
    /// `OUTSTATION_CAPTURE_RUN_MAX_MB`; default 4096 MiB.
    pub capture_run_max_bytes: u64,
    /// Finished runs kept in memory; older ones are served from the
    /// database on demand (F054). `--runs-in-memory` or
    /// `OUTSTATION_RUNS_IN_MEMORY`; default 500.
    pub runs_in_memory: usize,
    /// Total size quota of the pcap library in bytes; 0 = no quota
    /// (F051). `--library-max-mb` or `OUTSTATION_LIBRARY_MAX_MB`.
    pub library_max_bytes: u64,
    /// Concurrent heavy requests (analysis, uploads, gap histograms).
    pub heavy_concurrency: usize,
    /// CP56Time2a drift tolerance (ms) for automatic and on-demand
    /// analyses (F066). `--cp56-tolerance-ms` or
    /// `OUTSTATION_CP56_TOLERANCE_MS`; default 50.
    pub cp56_tolerance_ms: f64,
    /// Analyse every finished benchmark run's own capture automatically
    /// and store the result (T08). `serve --no-auto-analyze` or
    /// `OUTSTATION_AUTO_ANALYZE=0` turns it off.
    pub auto_analyze: bool,
}

/// Parse a boolean environment switch: `0`, `false`, `no` and `off`
/// (any case) are false, anything else non-empty is true.
pub fn env_flag(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "0" | "false" | "no" | "off" => Some(false),
        _ => Some(true),
    }
}

impl ServeConfig {
    /// Defaults derived from the environment. `OUTSTATION_ALLOW_HOSTS`
    /// and `OUTSTATION_ALLOW_ORIGINS` are comma-separated lists.
    pub fn from_env(bind: SocketAddr) -> Self {
        let library_dir = default_library_dir();
        let state_dir = state_dir_for(&library_dir);
        let env_u64 = |k: &str| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        Self {
            bind,
            library_dir,
            state_dir,
            ephemeral: false,
            allow_hosts: std::env::var("OUTSTATION_ALLOW_HOSTS")
                .map(|v| split_hosts(&v))
                .unwrap_or_default(),
            allow_origins: std::env::var("OUTSTATION_ALLOW_ORIGINS")
                .map(|v| split_origins(&v))
                .unwrap_or_default(),
            max_upload_bytes: env_u64("OUTSTATION_MAX_UPLOAD_MB")
                .map(|v| v * MIB)
                .unwrap_or(GIB),
            min_free_bytes: env_u64("OUTSTATION_MIN_FREE_MB")
                .map(|v| v * MIB)
                .unwrap_or(512 * MIB),
            free_space: Default::default(),
            capture_max_total_bytes: env_u64("OUTSTATION_CAPTURE_MAX_MB")
                .map(|v| v * MIB)
                .unwrap_or(10 * GIB),
            capture_max_count: env_u64("OUTSTATION_CAPTURE_MAX_COUNT")
                .map(|v| v as usize)
                .unwrap_or(200),
            runs_in_memory: env_u64("OUTSTATION_RUNS_IN_MEMORY")
                .map(|v| (v as usize).max(1))
                .unwrap_or(DEFAULT_RUNS_IN_MEMORY),
            capture_run_max_bytes: env_u64("OUTSTATION_CAPTURE_RUN_MAX_MB")
                .map(|v| v * MIB)
                .unwrap_or(4 * GIB),
            library_max_bytes: env_u64("OUTSTATION_LIBRARY_MAX_MB")
                .map(|v| v * MIB)
                .unwrap_or(0),
            heavy_concurrency: 2,
            cp56_tolerance_ms: std::env::var("OUTSTATION_CP56_TOLERANCE_MS")
                .ok()
                .and_then(|v| v.trim().parse::<f64>().ok())
                .and_then(|v| crate::analysis::check_cp56_tolerance(v).ok())
                .unwrap_or(crate::analysis::DEFAULT_CP56_TOLERANCE_MS),
            auto_analyze: std::env::var("OUTSTATION_AUTO_ANALYZE")
                .ok()
                .and_then(|v| env_flag(&v))
                .unwrap_or(true),
        }
    }

    pub fn captures_dir(&self) -> PathBuf {
        self.state_dir.join("captures")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.state_dir.join("tmp")
    }

    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("runs.sqlite")
    }

    pub fn alias_state_path(&self) -> PathBuf {
        alias_state_path_in(&self.state_dir)
    }
}

/// Split a comma/whitespace separated host list.
/// Comma/space-separated `scheme://host[:port]` list, normalized the way
/// the origin guard compares them (lower case, no trailing slash).
pub fn split_origins(v: &str) -> Vec<String> {
    split_hosts(v)
        .iter()
        .map(|o| crate::security::normalize_origin(o))
        .collect()
}

pub fn split_hosts(v: &str) -> Vec<String> {
    v.split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The run that currently owns the host topology. At most one exists.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ActiveRun {
    pub run_id: u64,
    pub client_ip: String,
    pub started_at: u64,
}

/// One run's state behind its own lock, so the run list never holds the
/// global map lock while copying run data (F029).
pub(crate) type RunEntry = Arc<Mutex<RunState>>;

#[derive(Clone)]
pub struct AppState {
    pub(crate) runs: Arc<Mutex<HashMap<u64, RunEntry>>>,
    pub(crate) next_id: Arc<AtomicU64>,
    pub(crate) library_dir: Arc<PathBuf>,
    pub(crate) db: Db,
    pub(crate) cfg: Arc<ServeConfig>,
    /// Single-active-run slot (F037/F048/F070).
    pub(crate) active: Arc<Mutex<Option<ActiveRun>>>,
    /// Worker threads of runs started by this process, for stop/delete
    /// liveness checks and graceful shutdown joins.
    pub(crate) workers: Arc<Mutex<HashMap<u64, std::thread::JoinHandle<()>>>>,
    pub(crate) events: broadcast::Sender<RunEvent>,
    pub(crate) shutdown: CancellationToken,
    pub(crate) heavy: Arc<Semaphore>,
    pub(crate) executor: Arc<dyn RunExecutor>,
    pub(crate) host_names: Arc<Vec<String>>,
    pub(crate) gap_cache: Arc<Mutex<HashMap<u64, Arc<serde_json::Value>>>>,
    pub(crate) started: std::time::Instant,
    /// Runtime that background work (auto-analysis) is spawned on;
    /// captured when the state is opened inside one.
    pub(crate) rt: Option<tokio::runtime::Handle>,
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    /// Library quota reservations of uploads in progress (F051).
    pub(crate) library_quota: Arc<Mutex<crate::routes::library::QuotaBook>>,
}

impl AppState {
    /// Build the state for `cfg`: create directories and open the DB.
    /// A DB that cannot be opened is an error unless `cfg.ephemeral`.
    pub fn open(cfg: ServeConfig) -> Result<Self> {
        Self::open_with_executor(cfg, Arc::new(SchedExecutor))
    }

    pub(crate) fn open_with_executor(
        cfg: ServeConfig,
        executor: Arc<dyn RunExecutor>,
    ) -> Result<Self> {
        for d in [&cfg.library_dir, &cfg.captures_dir()] {
            std::fs::create_dir_all(d).with_context(|| format!("create {}", d.display()))?;
        }
        crate::library::prepare_private_dir(&cfg.tmp_dir())?;
        let db = if cfg.ephemeral {
            Db::open_in_memory()?
        } else {
            Db::open(&cfg.db_path()).with_context(|| {
                format!(
                    "open run database {} (pass --ephemeral to run without persistence)",
                    cfg.db_path().display()
                )
            })?
        };
        let (events, _) = broadcast::channel(64);
        Ok(Self {
            runs: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            library_dir: Arc::new(cfg.library_dir.clone()),
            db,
            active: Arc::new(Mutex::new(None)),
            workers: Arc::new(Mutex::new(HashMap::new())),
            events,
            shutdown: CancellationToken::new(),
            heavy: Arc::new(Semaphore::new(cfg.heavy_concurrency.max(1))),
            executor,
            host_names: Arc::new(crate::security::local_host_names()),
            gap_cache: Arc::new(Mutex::new(HashMap::new())),
            started: std::time::Instant::now(),
            rt: tokio::runtime::Handle::try_current().ok(),
            metrics: Arc::new(crate::metrics::Metrics::default()),
            library_quota: Arc::new(Mutex::new(Default::default())),
            cfg: Arc::new(cfg),
        })
    }

    pub(crate) fn get_run(&self, id: u64) -> Option<RunEntry> {
        self.runs.lock_safe().get(&id).cloned()
    }

    /// A run from memory, or else from the database (F054). The second
    /// value is false for a database copy: changes to it are not kept.
    pub(crate) fn get_run_any(&self, id: u64) -> Option<(RunEntry, bool)> {
        if let Some(e) = self.get_run(id) {
            return Some((e, true));
        }
        let rs = self.load_stored_run(id)?;
        Some((Arc::new(Mutex::new(rs)), false))
    }

    /// Decode a run that is not in memory from the database, with its
    /// newest analysis.
    pub(crate) fn load_stored_run(&self, id: u64) -> Option<RunState> {
        let stored = match self.db.load_one(id) {
            Ok(s) => s?,
            Err(e) => {
                tracing::warn!(id, error = %e, "could not read run from the database");
                return None;
            }
        };
        self.load_stored_run_from(&stored)
    }

    /// [`Self::load_stored_run`] for a row already read.
    pub(crate) fn load_stored_run_from(&self, stored: &crate::db::StoredRun) -> Option<RunState> {
        let id = stored.id;
        let mut rs = crate::persist::stored_to_runstate(
            stored,
            &self.cfg.library_dir,
            &self.cfg.captures_dir(),
        )
        .map_err(|e| tracing::warn!(id, error = %e, "skipping unreadable run"))
        .ok()?;
        if let Ok(list) = self.db.analyses_for_run(id) {
            rs.latest_analysis = list.first().map(Into::into);
        }
        Some(rs)
    }

    pub(crate) fn all_runs(&self) -> Vec<RunEntry> {
        self.runs.lock_safe().values().cloned().collect()
    }

    pub(crate) fn active_run(&self) -> Option<ActiveRun> {
        self.active.lock_safe().clone()
    }

    /// Is a worker thread for `id` still alive?
    pub(crate) fn worker_alive(&self, id: u64) -> bool {
        self.workers
            .lock_safe()
            .get(&id)
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }
}
