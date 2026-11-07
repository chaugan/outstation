//! Web UI: axum backend + embedded static HTML page.
//!
//! Endpoints (all errors are `{"error": .., "code": ..}`):
//!
//! | method | path | notes |
//! |---|---|---|
//! | GET | `/` | SPA |
//! | GET | `/api/status` | health: DB, disk, capabilities, active run |
//! | GET | `/api/events` | SSE: `hello`, `run_started`, `run_finished`, `run_stopped` |
//! | GET | `/api/protocols` | registered replayers |
//! | POST | `/api/inspect` | `{pcap_id}` |
//! | POST | `/api/run` | start a run (409 `run_active` if one is active) |
//! | GET | `/api/runs[?status=running]` | slim summaries |
//! | GET/DELETE | `/api/runs/:id` | full detail / delete |
//! | POST | `/api/runs/:id/stop` | stop |
//! | POST | `/api/runs/:id/rerun[?force=true]` | new run with the stored request |
//! | GET | `/api/runs/:a/compare/:b` | run-to-run deltas and regression flags (read-only) |
//! | GET/POST | `/api/profiles` | named run requests |
//! | GET/PUT/DELETE | `/api/profiles/:id` | one profile |
//! | GET | `/metrics` | Prometheus text exposition |
//! | GET | `/api/runs/:id/live` | WebSocket progress |
//! | GET | `/api/runs/:id/download`, `/gaps` | capture, gap histogram |
//! | POST | `/api/analyze[?run_id=N]` | fidelity analysis upload |
//! | GET | `/api/runs/:id/analyses` | stored analyses of a run |
//! | POST | `/api/runs/:id/analyze` | analyse the run's own capture now |
//! | GET | `/api/analyses/:id` | stored analysis summary |
//! | GET | `/api/analyses/:id/endpoints/:endpoint` | one endpoint's stored detail |
//! | GET | `/api/analyses/:id/report.html` | self-contained, printable HTML report |
//! | * | `/api/pcaps...` | library |
//!
//! Only one run may be active at a time. Every request passes the
//! same-origin/Host guard in [`security`].

mod analysis;
mod analysis_run;
pub mod bench;
mod captures;
mod cleanup;
mod compare;
mod db;
mod dto;
mod error;
mod events;
mod health;
mod library;
mod metrics;
mod netprobe;
mod persist;
mod report_html;
mod routes;
pub mod runbuild;
mod runs;
mod security;
mod state;
pub mod statelock;
mod sysinfo;

#[cfg(test)]
mod helper_tests;
#[cfg(test)]
mod tests;

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post};
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tracing::{error, info, warn};

pub use analysis::{check_cp56_tolerance, DEFAULT_CP56_TOLERANCE_MS};
pub use cleanup::host_cleanup;
pub use dto::{
    BenchmarkReportJson, LatencyHistogramJson, RunReportJson, RunState, RunStatus, RunSummary,
    SessionReportJson, SourceProgressJson, SourceReportJson,
};
pub use events::RunEvent;
pub use state::{
    default_library_dir, default_state_dir, env_flag, split_hosts, split_origins, ActiveRun,
    AppState, ServeConfig,
};
pub use sysinfo::FreeSpace;

use error::LockExt;
use routes::analyze::*;
use routes::compare::*;
use routes::library::*;
use routes::live::*;
use routes::misc::*;
use routes::net::*;
use routes::profiles::*;
use routes::runs::*;
use routes::slaves::*;

pub fn router(state: AppState) -> Router {
    // Multipart bodies are bounded by the configured upload cap (plus
    // room for the multipart framing); handlers enforce the exact cap.
    let body_limit = usize::try_from(state.cfg.max_upload_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(1024 * 1024);
    Router::new()
        .route("/", get(serve_index))
        .route("/echarts.min.js", get(serve_echarts))
        .route("/api/status", get(api_status))
        .route("/api/events", get(events::api_events))
        .route("/api/protocols", get(api_protocols))
        .route("/api/inspect", post(api_inspect))
        .route("/api/run", post(api_run))
        .route("/api/runs", get(api_runs))
        .route("/api/runs/:id", get(api_run_by_id).delete(api_run_delete))
        .route("/api/runs/:id/stop", post(api_run_stop))
        .route("/api/runs/:id/rerun", post(api_run_rerun))
        .route("/api/runs/:a/compare/:b", get(api_run_compare))
        .route(
            "/api/profiles",
            get(api_profiles_list).post(api_profile_create),
        )
        .route(
            "/api/profiles/:id",
            get(api_profile_get)
                .put(api_profile_update)
                .delete(api_profile_delete),
        )
        .route("/metrics", get(api_metrics))
        .route("/api/runs/:id/live", get(api_run_live_ws))
        .route("/api/runs/:id/slaves/:idx/start", post(api_run_start_slave))
        .route("/api/runs/:id/slaves/:idx/stop", post(api_run_stop_slave))
        .route("/api/runs/:id/slaves/:idx", patch(api_run_patch_slave))
        .route(
            "/api/runs/:id/slaves/start_all",
            post(api_run_start_all_slaves),
        )
        .route("/api/verify-ip", post(api_verify_ip))
        .route("/api/nics", get(api_nics))
        .route("/api/arp", post(api_arp))
        .route(
            "/api/analyze",
            post(api_analyze).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route("/api/runs/:id/analyses", get(api_run_analyses))
        .route("/api/runs/:id/analyze", post(api_run_analyze))
        .route("/api/analyses/:id", get(api_analysis_summary))
        .route(
            "/api/analyses/:id/report.html",
            get(api_analysis_report_html),
        )
        .route(
            "/api/analyses/:id/endpoints/:endpoint",
            get(api_analysis_detail),
        )
        .route("/api/runs/:id/download", get(api_run_download))
        .route("/api/runs/:id/gaps", get(api_run_gaps))
        .route("/api/pcaps", get(api_library_list))
        .route(
            "/api/pcaps",
            post(api_library_upload).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route("/api/pcaps/:id", delete(api_library_delete))
        .route("/api/pcaps/:id", patch(api_library_rename))
        .route("/api/pcaps/:id/download", get(api_library_download))
        .fallback(error::not_found_fallback)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security::origin_guard,
        ))
        .layer(CatchPanicLayer::custom(error::panic_response))
        .with_state(state)
}

/// Startup work on a freshly opened state: mark orphans, restore runs,
/// seed the id counter, migrate legacy captures, sweep temp files and
/// enforce capture retention.
pub(crate) fn restore(state: &AppState) -> Result<()> {
    match state
        .db
        .mark_orphans_failed("interrupted by server restart")
    {
        Ok(n) if n > 0 => warn!(count = n, "marked {n} orphaned run(s) as failed at startup"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "mark_orphans_failed failed"),
    }
    // Seed ids from the DB independently of how many rows decode, so a
    // bad row can never cause an id to be reused (F073).
    let max_id = state.db.max_id().context("read max run id")?;
    state.next_id.store(max_id + 1, Ordering::SeqCst);

    let captures_dir = state.cfg.captures_dir();
    let stored = state.db.load_all().context("load run history")?;
    let mut restored = 0usize;
    let mut db_only = 0usize;
    // Only the newest `runs_in_memory` runs are kept in memory; older
    // ones are served from the database on demand and only folded into
    // the metrics here (F054). `load_all` is ordered by id.
    let keep_from = stored.len().saturating_sub(state.cfg.runs_in_memory.max(1));
    {
        let mut folded = state.metrics.folded.lock_safe();
        let mut map = state.runs.lock_safe();
        for (i, s) in stored.iter().enumerate() {
            match persist::stored_to_runstate(s, &state.cfg.library_dir, &captures_dir) {
                Ok(rs) if i < keep_from => {
                    metrics::fold_evicted(&mut folded, &rs);
                    db_only += 1;
                }
                Ok(rs) => {
                    map.insert(rs.id, std::sync::Arc::new(std::sync::Mutex::new(rs)));
                    restored += 1;
                }
                Err(e) => warn!(id = s.id, error = %e, "skipping unreadable run"),
            }
        }
    }
    drop(stored);
    info!(
        restored,
        db_only,
        next_id = max_id + 1,
        "restored runs from sqlite"
    );
    match state.db.latest_analyses() {
        Ok(list) => {
            for a in &list {
                analysis_run::note_analysis(state, a);
            }
        }
        Err(e) => warn!(error = %e, "could not read stored analyses"),
    }

    let parts = library::sweep_part_files(&state.cfg.library_dir);
    let tmps = library::sweep_tmp_dir(&state.cfg.tmp_dir());
    if parts + tmps > 0 {
        info!(
            parts,
            tmps, "removed leftover partial uploads and temp files"
        );
    }
    captures::enforce_retention(
        &captures_dir,
        state.cfg.capture_max_total_bytes,
        state.cfg.capture_max_count,
        &[],
    );
    Ok(())
}

/// How long shutdown waits for run workers to unwind their guards.
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(20);
/// How long shutdown waits for open HTTP connections to finish.
const HTTP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(error = %e, "install SIGINT handler failed");
            std::future::pending::<()>().await;
        }
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                error!(error = %e, "install SIGTERM handler failed");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = ctrl_c => info!("SIGINT received"),
        _ = term => info!("SIGTERM received"),
    }
}

/// Stop everything in order: refuse new runs and close event streams,
/// cancel running runs, then join their workers so the RAII guards in
/// sched/netctl drop before the process exits (F036, F071).
pub(crate) async fn shutdown(state: &AppState, join_timeout: Duration) -> Vec<u64> {
    state.shutdown.cancel();
    runs::cancel_all(state);
    let st = state.clone();
    let left = tokio::task::spawn_blocking(move || runs::join_workers(&st, join_timeout))
        .await
        .unwrap_or_default();
    if left.is_empty() {
        info!("all run workers finished");
    } else {
        warn!(?left, "run workers still busy after the shutdown timeout");
    }
    left
}

/// Run the web UI until SIGTERM/SIGINT, then shut down gracefully.
pub async fn serve(cfg: ServeConfig) -> Result<()> {
    let bind = cfg.bind;
    // One server per state directory: a second one would run the
    // startup cleanup below and tear down this one's live run (N7).
    let _lock = statelock::StateLock::acquire(&cfg.state_dir, "serve")
        .context("refusing to start a second server on this state directory")?;
    // Reclaim host state left by a previous process before anything new
    // is created.
    let state_dir = cfg.state_dir.clone();
    tokio::task::spawn_blocking(move || host_cleanup(&state_dir)).await??;

    let state = AppState::open(cfg)?;
    restore(&state)?;
    // Runs that finished during the last shutdown (or crash) were never
    // analysed (O3).
    analysis_run::queue_startup_backlog(&state, analysis_run::STARTUP_BACKLOG_LIMIT);
    if !state.cfg.allow_hosts.is_empty() {
        info!(hosts = ?state.cfg.allow_hosts, "extra allowed Host names");
    }
    if !state.cfg.allow_origins.is_empty() {
        info!(origins = ?state.cfg.allow_origins, "extra trusted Origins (reverse proxy)");
    }

    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    info!(addr = %bind, "outstation webui listening");
    let token = state.shutdown.clone();
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<security::ConnAddrs>(),
    )
    .with_graceful_shutdown(async move { token.cancelled().await });
    let mut server = tokio::spawn(async move { server.await });

    tokio::select! {
        r = &mut server => {
            // Server ended on its own (error); still clean up.
            let res = r.context("server task")?;
            shutdown(&state, WORKER_JOIN_TIMEOUT).await;
            let sd = state.cfg.state_dir.clone();
            tokio::task::spawn_blocking(move || host_cleanup(&sd)).await??;
            return res.context("http server");
        }
        _ = shutdown_signal() => {}
    }
    info!("shutting down: cancelling runs and draining connections");
    shutdown(&state, WORKER_JOIN_TIMEOUT).await;
    if tokio::time::timeout(HTTP_DRAIN_TIMEOUT, &mut server)
        .await
        .is_err()
    {
        warn!("HTTP connections still open after the drain timeout; closing");
        server.abort();
    }
    let sd = state.cfg.state_dir.clone();
    tokio::task::spawn_blocking(move || host_cleanup(&sd)).await??;
    info!("shutdown complete");
    Ok(())
}
