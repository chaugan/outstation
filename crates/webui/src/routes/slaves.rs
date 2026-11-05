//! Per-slave controls for slave-mode benchmark runs.

use crate::error::LockExt;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tracing::info;

use crate::error::{ApiJson, ApiPath, AppError};
use crate::state::*;

pub(crate) async fn api_run_start_slave(
    State(state): State<AppState>,
    ApiPath((id, idx)): ApiPath<(u64, usize)>,
) -> Result<StatusCode, AppError> {
    let entry = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let rs = entry.lock_safe();
    if rs.status.is_terminal() {
        return Err(AppError::Conflict(
            "run_finished",
            format!("run {id} has already finished"),
        ));
    }
    let sp = rs.ctx.per_source.lock_safe();
    let entry = sp
        .get(idx)
        .ok_or_else(|| AppError::NotFound(format!("slave idx {idx} not found in run {id}")))?;
    entry.ready.store(true, Ordering::Relaxed);
    info!(id, idx, "slave start requested");
    Ok(StatusCode::ACCEPTED)
}

/// Fan-out "start all slaves" for a running slave-mode benchmark. Flips
/// `ready=true` on every per-source entry that is still PENDING and
/// hasn't already been cancelled. Idempotent — re-posting after some
/// rows have already been started is a no-op for those rows.
pub(crate) async fn api_run_start_all_slaves(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Json<serde_json::Value>, AppError> {
    use protoplay::session_state as ss;
    let entry = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let rs = entry.lock_safe();
    if rs.status.is_terminal() {
        return Err(AppError::Conflict(
            "run_finished",
            format!("run {id} has already finished"),
        ));
    }
    let sp = rs.ctx.per_source.lock_safe();
    let mut started = 0u64;
    for entry in sp.iter() {
        if entry.is_cancelled() {
            continue;
        }
        let state_now = entry.snapshot_state();
        if state_now != ss::PENDING {
            continue;
        }
        entry.ready.store(true, Ordering::Relaxed);
        started += 1;
    }
    let total = sp.len() as u64;
    drop(sp);
    info!(id, started, total, "slave start-all requested");
    Ok(Json(
        serde_json::json!({ "started": started, "total": total }),
    ))
}

pub(crate) async fn api_run_stop_slave(
    State(state): State<AppState>,
    ApiPath((id, idx)): ApiPath<(u64, usize)>,
) -> Result<StatusCode, AppError> {
    let entry = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let rs = entry.lock_safe();
    if rs.status.is_terminal() {
        return Err(AppError::Conflict(
            "run_finished",
            format!("run {id} has already finished"),
        ));
    }
    let sp = rs.ctx.per_source.lock_safe();
    let entry = sp
        .get(idx)
        .ok_or_else(|| AppError::NotFound(format!("slave idx {idx} not found in run {id}")))?;
    entry.cancel.store(true, Ordering::Relaxed);
    // Also set ready so a pending slave that's still waiting for its
    // start signal wakes up, sees cancel=true, and exits cleanly.
    entry.ready.store(true, Ordering::Relaxed);
    info!(id, idx, "slave stop requested");
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
pub(crate) struct PatchSlaveReq {
    #[serde(default)]
    pub(crate) listen_ip: Option<String>,
}

pub(crate) async fn api_run_patch_slave(
    State(state): State<AppState>,
    ApiPath((id, idx)): ApiPath<(u64, usize)>,
    ApiJson(req): ApiJson<PatchSlaveReq>,
) -> Result<StatusCode, AppError> {
    let entry = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let rs = entry.lock_safe();
    if rs.status.is_terminal() {
        return Err(AppError::Conflict(
            "run_finished",
            format!("run {id} has already finished"),
        ));
    }
    let sp = rs.ctx.per_source.lock_safe();
    let entry = sp
        .get(idx)
        .ok_or_else(|| AppError::NotFound(format!("slave idx {idx} not found in run {id}")))?;
    if entry.snapshot_state() != protoplay::session_state::PENDING {
        return Err(AppError::BadRequest(
            "cannot patch a slave that has already started",
        ));
    }
    if let Some(ip_str) = req.listen_ip {
        let ip: Ipv4Addr = ip_str
            .parse()
            .map_err(|e| AppError::BadRequest(format!("bad listen_ip {ip_str:?}: {e}")))?;
        *entry.listen_ip.lock_safe() = ip;
        info!(id, idx, %ip, "slave listen_ip updated");
    }
    Ok(StatusCode::ACCEPTED)
}
