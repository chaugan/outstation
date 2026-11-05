//! Run lifecycle: launch, progress snapshots, finalisation, stop and
//! shutdown.
//!
//! Invariants:
//! * A run is registered (id allocated, DB row written) only after its
//!   request validated and its pcap loaded (F049, F092, F146).
//! * At most one run is active; the slot is released by [`finalize`]
//!   (F037, F048, F070).
//! * Every worker body runs under `catch_unwind`, and [`finalize`]
//!   always persists a terminal status, so no run stays "running"
//!   without a worker (F074, F086).
//! * The final status comes from per-session results (F094).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use pcapload::LoadedPcap;
use sched::{BenchmarkConfig, BenchmarkReport, RunConfig, RunContext, RunReport};
use tracing::{info, info_span, warn};

use crate::captures;
use crate::dto::*;
use crate::error::{panic_message, AppError, LockExt};
use crate::events::now_secs;
use crate::persist::runstate_to_stored;
use crate::state::{ActiveRun, AppState};

pub(crate) fn get_proto(name: &str) -> Option<Arc<dyn protoplay::ProtoReplayer>> {
    proto_registry::lookup(name)
}

/// What actually executes a run. Production uses [`SchedExecutor`];
/// tests inject fakes so the lifecycle can be exercised without
/// CAP_NET_ADMIN.
pub(crate) trait RunExecutor: Send + Sync + 'static {
    fn run_raw(&self, pcap: Arc<LoadedPcap>, cfg: RunConfig, ctx: RunContext) -> Result<RunReport>;
    fn run_benchmark(
        &self,
        pcap: Arc<LoadedPcap>,
        cfg: BenchmarkConfig,
        replayer: Arc<dyn protoplay::ProtoReplayer>,
        ctx: RunContext,
    ) -> Result<BenchmarkReport>;
}

pub(crate) struct SchedExecutor;

impl RunExecutor for SchedExecutor {
    fn run_raw(&self, pcap: Arc<LoadedPcap>, cfg: RunConfig, ctx: RunContext) -> Result<RunReport> {
        sched::run(pcap, cfg, ctx)
    }

    fn run_benchmark(
        &self,
        pcap: Arc<LoadedPcap>,
        cfg: BenchmarkConfig,
        replayer: Arc<dyn protoplay::ProtoReplayer>,
        ctx: RunContext,
    ) -> Result<BenchmarkReport> {
        sched::run_benchmark(pcap, cfg, replayer, ctx)
    }
}

/// A validated run, ready to register and spawn.
pub(crate) enum RunJob {
    Raw(RunConfig),
    Benchmark(BenchmarkConfig, Arc<dyn protoplay::ProtoReplayer>),
}

pub(crate) enum RunOutcome {
    Raw(Result<RunReport>),
    Benchmark(Result<BenchmarkReport>),
    Panicked(String),
    /// Finalised without a worker result (stop/delete of a run whose
    /// worker is gone).
    Abandoned(String),
}

/// Snapshot the live atomics in a run's context into its serializable
/// progress fields. No-op for terminal runs, whose snapshot is final.
pub(crate) fn refresh_progress(rs: &mut RunState) {
    if !matches!(rs.status, RunStatus::Running) {
        return;
    }
    let sp = rs.ctx.per_source.lock_safe();
    // Per-source counters are the live truth. `ctx.sent` is only fanned
    // in when a raw worker exits, and in benchmark mode it counts
    // finished sessions, not messages, so it is used only before any
    // per-source entry exists (F030, F094).
    let live_sent: u64 = sp.iter().map(|p| p.snapshot_sent()).sum();
    let live_bytes: u64 = sp.iter().map(|p| p.snapshot_bytes()).sum();
    let live_planned: u64 = sp.iter().map(|p| p.snapshot_planned()).sum();
    if sp.is_empty() {
        rs.planned = rs.ctx.planned.load(Ordering::Relaxed);
        rs.sent = if rs.mode == "raw" {
            rs.ctx.sent.load(Ordering::Relaxed)
        } else {
            0
        };
        rs.bytes_progress = rs.ctx.bytes.load(Ordering::Relaxed);
    } else {
        rs.planned = if live_planned > 0 {
            live_planned
        } else {
            rs.ctx.planned.load(Ordering::Relaxed)
        };
        rs.sent = live_sent;
        rs.bytes_progress = live_bytes;
    }
    rs.per_source_progress = sp
        .iter()
        .map(|p| {
            let m = p.src_mac;
            SourceProgressJson {
                src_ip: p.src_ip.map(|i| i.to_string()),
                src_mac: format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                ),
                tap: p.tap.clone(),
                planned: p.snapshot_planned(),
                sent: p.snapshot_sent(),
                bytes: p.snapshot_bytes(),
                received: p.snapshot_received(),
                unacked: p.snapshot_unacked(),
                listen_port: p.listen_port,
                listen_ip: (*p.listen_ip.lock_safe()).to_string(),
                state: state_to_str(p.snapshot_state()).to_string(),
                ready: p.is_ready(),
                cancelled: p.is_cancelled(),
                iter_current: p.iter_current.load(Ordering::Relaxed),
                iter_total: p.iter_total.load(Ordering::Relaxed),
            }
        })
        .collect();
}

/// Total frames/messages sent so far, summed over per-source counters.
fn live_sent_total(ctx: &RunContext) -> u64 {
    ctx.per_source
        .lock_safe()
        .iter()
        .map(|p| p.snapshot_sent())
        .sum()
}

/// Derive the terminal status and error from an outcome (F094).
pub(crate) fn derive_status(cancelled: bool, outcome: &RunOutcome) -> (RunStatus, Option<String>) {
    match outcome {
        RunOutcome::Panicked(msg) => (
            RunStatus::Failed,
            Some(format!("run worker panicked: {msg}")),
        ),
        RunOutcome::Abandoned(msg) => (
            if cancelled {
                RunStatus::Stopped
            } else {
                RunStatus::Failed
            },
            Some(msg.clone()),
        ),
        RunOutcome::Raw(Err(e)) | RunOutcome::Benchmark(Err(e)) => {
            (RunStatus::Failed, Some(format!("{e:#}")))
        }
        _ if cancelled => (RunStatus::Stopped, None),
        RunOutcome::Raw(Ok(r)) => {
            if r.total_packets == 0 && r.total_errors > 0 {
                (
                    RunStatus::Failed,
                    Some(format!("no packets sent ({} send errors)", r.total_errors)),
                )
            } else if r.total_errors > 0 {
                (
                    RunStatus::Partial,
                    Some(format!("{} send errors", r.total_errors)),
                )
            } else {
                (RunStatus::Completed, None)
            }
        }
        RunOutcome::Benchmark(Ok(r)) => {
            let n = r.per_session.len();
            let errs: Vec<&str> = r
                .per_session
                .iter()
                .filter_map(|s| s.proto_report.error.as_deref())
                .collect();
            if n == 0 {
                (
                    RunStatus::Failed,
                    Some("no sessions ran (no matching flows or RTUs selected)".into()),
                )
            } else if errs.len() == n {
                (
                    RunStatus::Failed,
                    Some(format!("all {n} sessions failed; first error: {}", errs[0])),
                )
            } else if !errs.is_empty() {
                (
                    RunStatus::Partial,
                    Some(format!(
                        "{} of {n} sessions failed; first error: {}",
                        errs.len(),
                        errs[0]
                    )),
                )
            } else {
                (RunStatus::Completed, None)
            }
        }
    }
}

/// Request metadata recorded with a run.
pub(crate) struct Launch {
    pub(crate) pcap: Arc<LoadedPcap>,
    pub(crate) pcap_path: PathBuf,
    pub(crate) pcap_id: String,
    pub(crate) client_ip: String,
    pub(crate) client_id: Option<String>,
    pub(crate) job: RunJob,
    /// Fills in the run-specific RunState fields.
    pub(crate) template: RunState,
}

/// Error for a busy active-run slot.
pub(crate) fn run_active_error(a: &ActiveRun) -> AppError {
    AppError::Conflict(
        "run_active",
        format!(
            "run #{} is active (started by {} at {}); stop it before starting another",
            a.run_id, a.client_ip, a.started_at
        ),
    )
    .with("active_run_id", a.run_id.into())
    .with("client_ip", a.client_ip.clone().into())
    .with("started_at", a.started_at.into())
}

/// Register and spawn a validated run. Holds the active slot from
/// reservation until [`finalize`].
pub(crate) fn launch(state: &AppState, l: Launch) -> Result<u64, AppError> {
    if state.shutdown.is_cancelled() {
        return Err(AppError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
        ));
    }
    let mut active = state.active.lock_safe();
    if let Some(a) = active.as_ref() {
        return Err(run_active_error(a));
    }
    let id = state.next_id.fetch_add(1, Ordering::SeqCst);
    let started_at = now_secs();
    let capture = captures::capture_path(&state.cfg.captures_dir(), id);
    let ctx = RunContext::new();
    let mut rs = l.template;
    rs.id = id;
    rs.status = RunStatus::Running;
    rs.started_at = started_at;
    rs.started_by = Some(l.client_ip.clone());
    rs.pcap = l.pcap_path.clone();
    rs.pcap_id = Some(l.pcap_id.clone());
    rs.capture_file = Some(capture.clone());
    rs.ctx = ctx.clone();
    if let Err(e) = state.db.insert_run_start(&runstate_to_stored(&rs)) {
        warn!(id, error = %e, "db insert_run_start failed");
        return Err(AppError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "db_unavailable",
            format!("could not record run in the database: {e:#}"),
        ));
    }
    *active = Some(ActiveRun {
        run_id: id,
        client_ip: l.client_ip.clone(),
        started_at,
    });
    state
        .runs
        .lock_safe()
        .insert(id, Arc::new(std::sync::Mutex::new(rs)));
    drop(active);

    let job = match l.job {
        RunJob::Raw(mut cfg) => {
            cfg.capture_path = Some(capture.clone());
            RunJob::Raw(cfg)
        }
        RunJob::Benchmark(mut cfg, rep) => {
            cfg.capture_path = Some(capture.clone());
            RunJob::Benchmark(cfg, rep)
        }
    };
    let st = state.clone();
    let pcap = l.pcap;
    let worker_ctx = ctx.clone();
    let spawned = std::thread::Builder::new()
        .name(format!("webui-run-{id}"))
        .spawn(move || {
            let span = info_span!("run", id);
            let _enter = span.enter();
            info!("run worker started");
            let exec = st.executor.clone();
            let outcome = catch_unwind(AssertUnwindSafe(|| match job {
                RunJob::Raw(cfg) => RunOutcome::Raw(exec.run_raw(pcap, cfg, worker_ctx)),
                RunJob::Benchmark(cfg, rep) => {
                    RunOutcome::Benchmark(exec.run_benchmark(pcap, cfg, rep, worker_ctx))
                }
            }))
            .unwrap_or_else(|p| RunOutcome::Panicked(panic_message(&*p)));
            finalize(&st, id, outcome);
        });
    match spawned {
        Ok(h) => {
            state.workers.lock_safe().insert(id, h);
        }
        Err(e) => {
            finalize(
                state,
                id,
                RunOutcome::Panicked(format!("could not spawn run thread: {e}")),
            );
            return Err(AppError::Internal(format!("spawn run thread: {e}")));
        }
    }
    spawn_sampler(state.clone(), id, ctx);
    state.emit("run_started", id, &l.client_ip, l.client_id, "running");
    info!(id, client = %l.client_ip, "run started");
    Ok(id)
}

/// Move a run to its terminal status, persist it, release the active
/// slot and announce it. Idempotent: a run already terminal is left
/// alone.
pub(crate) fn finalize(state: &AppState, id: u64, outcome: RunOutcome) {
    let Some(entry) = state.get_run(id) else {
        release_active(state, id);
        return;
    };
    let (status, started_by) = {
        let mut rs = entry.lock_safe();
        if rs.status.is_terminal() {
            drop(rs);
            release_active(state, id);
            return;
        }
        // Snapshot progress while still Running so the guard in
        // refresh_progress lets the final values through.
        refresh_progress(&mut rs);
        let (status, err) = derive_status(rs.ctx.is_cancelled(), &outcome);
        match outcome {
            RunOutcome::Raw(Ok(r)) => rs.report = Some((&r).into()),
            RunOutcome::Benchmark(Ok(r)) => rs.benchmark = Some((&r).into()),
            _ => {}
        }
        if let Some(e) = &err {
            if status == RunStatus::Failed {
                warn!(id, error = %e, "run failed");
            }
        }
        rs.status = status;
        rs.error = err.or_else(|| rs.error.take());
        rs.finished_at = Some(now_secs());
        if let Err(e) = state.db.update_finished(&runstate_to_stored(&rs)) {
            warn!(id, error = %e, "db update_finished failed");
        }
        (status, rs.started_by.clone().unwrap_or_default())
    };
    release_active(state, id);
    let keep = state
        .active_run()
        .map(|a| captures::capture_path(&state.cfg.captures_dir(), a.run_id));
    captures::enforce_retention(
        &state.cfg.captures_dir(),
        state.cfg.capture_max_total_bytes,
        state.cfg.capture_max_count,
        keep.as_deref(),
    );
    state.emit("run_finished", id, &started_by, None, status.as_str());
    info!(id, status = status.as_str(), "run finished");
}

fn release_active(state: &AppState, id: u64) {
    let mut a = state.active.lock_safe();
    if a.as_ref().is_some_and(|a| a.run_id == id) {
        *a = None;
    }
}

/// Flip every cancel flag of a run.
pub(crate) fn cancel_run(rs: &RunState) {
    rs.ctx.cancel.store(true, Ordering::Relaxed);
    let sp = rs.ctx.per_source.lock_safe();
    for entry in sp.iter() {
        entry.cancel.store(true, Ordering::Relaxed);
        // Wake pending slaves so they see the cancel and exit.
        entry.ready.store(true, Ordering::Relaxed);
    }
}

/// Once per second, while the run is running, push the number of
/// frames/messages sent in the last second (summed per-source
/// counters, tolerant of per-iteration resets) into the throughput
/// history. Also stops the run if free disk in the state dir drops
/// below the configured floor.
fn spawn_sampler(state: AppState, id: u64, ctx: RunContext) {
    let _ = std::thread::Builder::new()
        .name(format!("webui-tps-{id}"))
        .spawn(move || {
            let mut last = 0u64;
            let mut tick = 0u64;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                tick += 1;
                let Some(entry) = state.get_run(id) else {
                    return;
                };
                let now = live_sent_total(&ctx);
                let delta = throughput_delta(last, now);
                last = now;
                {
                    let mut rs = entry.lock_safe();
                    if rs.status.is_terminal() {
                        return;
                    }
                    rs.throughput_history.push(delta);
                    if rs.throughput_history.len() > 120 {
                        rs.throughput_history.remove(0);
                    }
                    if tick % 5 == 0 && !ctx.is_cancelled() {
                        if let Some(free) = crate::sysinfo::free_bytes(&state.cfg.state_dir) {
                            if free < state.cfg.min_free_bytes / 2 {
                                warn!(id, free, "free disk critically low; stopping run");
                                rs.error = Some(format!(
                                    "stopped: free disk in {} fell to {free} bytes",
                                    state.cfg.state_dir.display()
                                ));
                                cancel_run(&rs);
                            }
                        }
                    }
                }
            }
        });
}

/// Frames sent since the previous sample. Per-source counters may reset
/// at an iteration boundary; a drop counts as a fresh start.
pub(crate) fn throughput_delta(last: u64, now: u64) -> u64 {
    if now >= last {
        now - last
    } else {
        now
    }
}

/// Request cancellation of every running run (graceful shutdown).
pub(crate) fn cancel_all(state: &AppState) {
    for entry in state.all_runs() {
        let rs = entry.lock_safe();
        if !rs.status.is_terminal() {
            cancel_run(&rs);
        }
    }
}

/// Join worker threads until `timeout`. Returns the ids still running.
pub(crate) fn join_workers(state: &AppState, timeout: Duration) -> Vec<u64> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let pending: Vec<u64> = {
            let mut w = state.workers.lock_safe();
            let done: Vec<u64> = w
                .iter()
                .filter(|(_, h)| h.is_finished())
                .map(|(id, _)| *id)
                .collect();
            for id in done {
                if let Some(h) = w.remove(&id) {
                    let _ = h.join();
                }
            }
            w.keys().copied().collect()
        };
        if pending.is_empty() || std::time::Instant::now() >= deadline {
            return pending;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8};
    use std::sync::Mutex;

    fn source(sent: u64, planned: u64) -> sched::SourceProgress {
        sched::SourceProgress {
            src_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            src_mac: [0; 6],
            tap: String::new(),
            planned: Arc::new(AtomicU64::new(planned)),
            sent: Arc::new(AtomicU64::new(sent)),
            bytes: Arc::new(AtomicU64::new(sent * 10)),
            received: Arc::new(AtomicU64::new(0)),
            unacked: Arc::new(AtomicU64::new(0)),
            ready: Arc::new(AtomicBool::new(true)),
            state: Arc::new(AtomicU8::new(0)),
            cancel: Arc::new(AtomicBool::new(false)),
            listen_port: 0,
            listen_ip: Arc::new(Mutex::new(Ipv4Addr::UNSPECIFIED)),
            iter_current: Arc::new(AtomicU64::new(0)),
            iter_total: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn progress_counts_messages_not_sessions() {
        // Benchmark: sched bumps ctx.sent once per finished session.
        let ctx = RunContext::new();
        ctx.sent.store(1, Ordering::Relaxed);
        ctx.per_source.lock_safe().push(source(0, 144));
        let mut rs = crate::persist::stored_to_runstate(
            &crate::db::StoredRun {
                id: 1,
                status: "running".into(),
                target_ip: "10.0.0.1".into(),
                mode: "benchmark".into(),
                ..Default::default()
            },
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/nonexistent"),
        )
        .unwrap();
        rs.ctx = ctx;
        refresh_progress(&mut rs);
        assert_eq!(
            (rs.sent, rs.planned),
            (0, 144),
            "a failed session is not a sent frame"
        );
    }

    #[test]
    fn throughput_tolerates_counter_reset() {
        assert_eq!(throughput_delta(100, 150), 50);
        assert_eq!(throughput_delta(150, 20), 20);
    }

    #[test]
    fn cancelled_run_is_stopped_even_with_session_errors() {
        let r = BenchmarkReport {
            per_session: vec![],
            ..Default::default()
        };
        let (st, _) = derive_status(true, &RunOutcome::Benchmark(Ok(r)));
        assert_eq!(st, RunStatus::Stopped);
        let (st, e) = derive_status(false, &RunOutcome::Panicked("x".into()));
        assert_eq!(st, RunStatus::Failed);
        assert!(e.unwrap().contains("panicked"));
    }
}
