//! Host and service health shared by `GET /api/status` and
//! `GET /metrics` (T13): DB writability, free disk, capabilities and
//! host-state journal entries still waiting for cleanup.

use serde::Serialize;

use crate::state::AppState;
use crate::sysinfo::{capabilities, free_bytes, Capabilities};

/// One reason the service is degraded. `code` is stable for the UI;
/// `message` is for humans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Degraded {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

/// Entries in netctl's crash-safe journals under the state dir.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct JournalPending {
    /// sysctl / NIC offload / iptables entries (`state-guards.txt`).
    pub(crate) guards: usize,
    /// IP aliases (`state-aliases.txt`).
    pub(crate) aliases: usize,
    /// Why a journal could not be read, if it could not.
    pub(crate) error: Option<String>,
}

impl JournalPending {
    pub(crate) fn total(&self) -> usize {
        self.guards + self.aliases
    }
}

pub(crate) struct Health {
    pub(crate) db: Result<(), String>,
    pub(crate) free: Option<u64>,
    pub(crate) caps: Option<Capabilities>,
    pub(crate) journal: JournalPending,
    pub(crate) degraded: Vec<Degraded>,
}

/// Count the entries of both journals in `state_dir`.
pub(crate) fn journal_pending(state_dir: &std::path::Path) -> JournalPending {
    let mut out = JournalPending::default();
    let mut errs = Vec::new();
    match netctl::journal::read_journal(&netctl::guards_path(state_dir)) {
        Ok(l) => out.guards = l.len(),
        Err(e) => errs.push(format!("{e:#}")),
    }
    match netctl::journal::read_journal(&netctl::aliases_path(state_dir)) {
        Ok(l) => out.aliases = l.len(),
        Err(e) => errs.push(format!("{e:#}")),
    }
    if !errs.is_empty() {
        out.error = Some(errs.join("; "));
    }
    out
}

/// Derive the degraded reasons from the raw facts. Pure, for tests.
pub(crate) fn degraded_reasons(
    state: &AppState,
    db: &Result<(), String>,
    free: Option<u64>,
    caps: Option<&Capabilities>,
    journal: &JournalPending,
    run_active: bool,
) -> Vec<Degraded> {
    let mut d = Vec::new();
    let mut push = |code: &'static str, message: String| d.push(Degraded { code, message });
    if let Err(e) = db {
        push(
            "db_not_writable",
            format!("run database is not writable: {e}"),
        );
    }
    if state.cfg.ephemeral {
        push(
            "ephemeral",
            "ephemeral mode: run history is not persisted".into(),
        );
    }
    match free {
        Some(f) if f < state.cfg.min_free_bytes => push(
            "low_disk",
            format!(
                "low disk: {f} bytes free in {} (minimum {})",
                state.cfg.state_dir.display(),
                state.cfg.min_free_bytes
            ),
        ),
        None => push("disk_unknown", "free disk space unknown".into()),
        _ => {}
    }
    match caps {
        Some(c) if !(c.net_admin && c.net_raw) => push(
            "missing_capabilities",
            "missing CAP_NET_ADMIN/CAP_NET_RAW: runs will fail".into(),
        ),
        None => push(
            "capabilities_unknown",
            "effective capabilities could not be read".into(),
        ),
        _ => {}
    }
    if let Some(e) = &journal.error {
        push(
            "journal_unreadable",
            format!("host-state journal could not be read: {e}"),
        );
    }
    // While a run is active its own entries are expected.
    if !run_active && journal.total() > 0 {
        push(
            "cleanup_pending",
            format!(
                "{} host-state journal entr{} ({} guard, {} alias) left by an earlier run; \
                 run `outstation cleanup` or restart the service",
                journal.total(),
                if journal.total() == 1 { "y" } else { "ies" },
                journal.guards,
                journal.aliases
            ),
        );
    }
    if state.shutdown.is_cancelled() {
        push("shutting_down", "server is shutting down".into());
    }
    d
}

/// Gather every health fact on the blocking pool.
pub(crate) async fn gather(state: &AppState) -> Health {
    let st = state.clone();
    let (db, free, caps, journal) = tokio::task::spawn_blocking(move || {
        (
            st.db.check_writable().map_err(|e| format!("{e:#}")),
            free_bytes(&st.cfg.state_dir),
            capabilities(),
            journal_pending(&st.cfg.state_dir),
        )
    })
    .await
    .unwrap_or_else(|e| {
        (
            Err(format!("status task: {e}")),
            None,
            None,
            JournalPending::default(),
        )
    });
    let degraded = degraded_reasons(
        state,
        &db,
        free,
        caps.as_ref(),
        &journal,
        state.active_run().is_some(),
    );
    Health {
        db,
        free,
        caps,
        journal,
        degraded,
    }
}
