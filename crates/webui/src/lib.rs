//! Web UI: axum backend + embedded static HTML page.
//!
//! Endpoints:
//!   GET  /                → static HTML SPA
//!   GET  /api/status      → health/version
//!   GET  /api/protocols   → list registered protocol-aware replayers
//!   POST /api/inspect     → inspect a pcap file at a given path
//!   POST /api/run         → start a replay run, returns a run id
//!   GET  /api/runs        → list active/recent runs
//!   GET  /api/runs/:id    → full state + stats of one run
//!
//! Run state lives in a shared `RunRegistry`. `POST /api/run` spawns a
//! std thread that invokes `sched::run` blockingly and updates the run
//! state on completion. The API stays non-blocking for clients.

mod analysis;
mod db;
mod dto;
mod error;
mod library;
mod netprobe;
mod persist;
mod routes;
mod runs;
mod state;

use std::sync::atomic::Ordering;

use anyhow::Result;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post};
use axum::Router;
use tracing::{info, warn};

pub use dto::{
    BenchmarkReportJson, RunReportJson, RunState, RunStatus, SessionReportJson, SourceProgressJson,
    SourceReportJson,
};
pub use state::AppState;

use persist::stored_to_runstate;
use routes::analyze::*;
use routes::library::*;
use routes::live::*;
use routes::misc::*;
use routes::net::*;
use routes::runs::*;
use routes::slaves::*;
use state::alias_state_path;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/echarts.min.js", get(serve_echarts))
        .route("/api/status", get(api_status))
        .route("/api/protocols", get(api_protocols))
        .route("/api/inspect", post(api_inspect))
        .route("/api/run", post(api_run))
        .route("/api/runs", get(api_runs))
        .route("/api/runs/:id", get(api_run_by_id).delete(api_run_delete))
        .route("/api/runs/:id/stop", post(api_run_stop))
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
            post(api_analyze).layer(DefaultBodyLimit::max(1024 * 1024 * 1024)),
        )
        .route("/api/runs/:id/download", get(api_run_download))
        .route("/api/runs/:id/gaps", get(api_run_gaps))
        .route("/api/pcaps", get(api_library_list))
        .route(
            "/api/pcaps",
            post(api_library_upload).layer(DefaultBodyLimit::max(1024 * 1024 * 1024)),
        )
        .route("/api/pcaps/:id", delete(api_library_delete))
        .route("/api/pcaps/:id", patch(api_library_rename))
        .route("/api/pcaps/:id/download", get(api_library_download))
        .with_state(state)
}

pub async fn serve(bind: std::net::SocketAddr) -> Result<()> {
    // Startup-time reclamation: anything we created and didn't clean
    // up in a prior run is orphaned now. Walk the state file for
    // tracked IP aliases, delete them, and also wipe stale pcr_*
    // veth/bridge interfaces left over from a killed run.
    let state_path = alias_state_path();
    match netctl::reclaim_recorded_aliases(&state_path) {
        Ok(n) if n > 0 => {
            warn!(count = n, path = %state_path.display(),
                "reclaimed {n} orphaned ip alias(es) from a previous run — \
                 the prior run did not clean up properly");
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "reclaim_recorded_aliases failed"),
    }
    match netctl::reclaim_stale("pcr_br0", "pcr_") {
        Ok(n) if n > 0 => warn!(
            count = n,
            "reclaimed {n} stale pcr_* interface(s) at startup"
        ),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "reclaim_stale failed"),
    }

    let state = AppState::new();

    // Any rows left in status=running are from a process that died
    // without updating them. Mark them failed so the UI doesn't think
    // they're still in flight, then reload everything.
    match state
        .db
        .mark_orphans_failed("interrupted by server restart")
    {
        Ok(n) if n > 0 => warn!(count = n, "marked {n} orphaned run(s) as failed at startup"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "mark_orphans_failed failed"),
    }
    match state.db.load_all() {
        Ok(stored) => {
            let mut map = state.runs.lock().unwrap();
            let mut max_id = 0u64;
            for s in &stored {
                if let Some(rs) = stored_to_runstate(s) {
                    if rs.id > max_id {
                        max_id = rs.id;
                    }
                    map.insert(rs.id, rs);
                }
            }
            drop(map);
            state.next_id.store(max_id + 1, Ordering::SeqCst);
            info!(count = stored.len(), "restored runs from sqlite");
        }
        Err(e) => warn!(error = %e, "load_all failed"),
    }

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(addr = %bind, "outstation webui listening");
    axum::serve(listener, app).await?;
    Ok(())
}
