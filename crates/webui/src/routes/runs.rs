//! Run start, list, detail, stop, delete, gaps and capture download.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use pcapload::load;
use sched::RunContext;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::dto::*;
use crate::error::{ApiJson, ApiPath, ApiQuery, AppError, LockExt};
use crate::library::*;
use crate::runbuild::{self, RequestError, RoleReq, RunMode, RunRequest};
use crate::runs::*;
use crate::security::{client_id, ClientIp, LocalIp};
use crate::state::*;

/// Request body of `POST /api/run` (see [`crate::runbuild`]).
pub(crate) type RunReq = RunRequest;

/// Interface-name check with the API error shape (F042).
pub(crate) fn validate_ifname(field: &str, name: &str, max_len: usize) -> Result<(), AppError> {
    runbuild::validate_ifname(field, name, max_len).map_err(AppError::from)
}

impl From<RequestError> for AppError {
    fn from(e: RequestError) -> Self {
        AppError::BadRequest(e.message).code(e.code)
    }
}

/// Cheap field checks that need no I/O.
pub(crate) fn validate_fields(req: &RunReq) -> Result<(), AppError> {
    runbuild::validate_request(req).map_err(AppError::from)
}

/// Build the scheduler job and the RunState template for a validated
/// request.
pub(crate) fn build_job(
    req: &RunReq,
    state_dir: &std::path::Path,
    protected_addrs: Vec<std::net::IpAddr>,
) -> (RunJob, RunState) {
    let is_bench = req.mode == RunMode::Benchmark;
    let template = RunState {
        id: 0,
        status: RunStatus::Running,
        started_at: 0,
        finished_at: None,
        started_by: None,
        pcap: PathBuf::new(),
        pcap_id: None,
        target_ip: req.target_ip,
        target_mac: req.target_mac.clone(),
        speed: req.speed,
        top_speed: req.top_speed,
        realtime: req.realtime,
        error: None,
        report: None,
        benchmark: None,
        mode: if is_bench { "benchmark" } else { "raw" },
        role: match (is_bench, req.role) {
            (false, _) => "",
            (true, RoleReq::Slave) => "slave",
            (true, RoleReq::Master) => "master",
        },
        target_port: match (is_bench, req.role) {
            (false, _) => 0,
            (true, RoleReq::Slave) => req.listen_port_base,
            (true, RoleReq::Master) => req.target_port,
        },
        proto: if is_bench {
            req.proto_name.clone()
        } else {
            default_proto_name()
        },
        proto_config: req.proto_config.clone(),
        planned: 0,
        sent: 0,
        bytes_progress: 0,
        per_source_progress: Vec::new(),
        throughput_history: Vec::new(),
        capture_file: None,
        request: Some(runbuild::canonical_json(req)),
        rerun_of: None,
        latest_analysis: None,
        auto_analysis: None,
        ctx: RunContext::new(),
    };
    let job = if is_bench {
        let (cfg, replayer) = runbuild::benchmark_config(req, state_dir, protected_addrs);
        RunJob::Benchmark(cfg, replayer)
    } else {
        RunJob::Raw(runbuild::raw_config(req, state_dir, protected_addrs))
    };
    (job, template)
}

#[derive(Serialize)]
pub(crate) struct RunResp {
    id: u64,
}

/// How long a run start waits for a heavy-work permit before 429.
pub(crate) const RUN_LOAD_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
/// How long `/api/inspect` waits for a heavy-work permit before 429.
pub(crate) const INSPECT_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Load a pcap on the blocking pool under a heavy-work permit (F053,
/// F087): parsing a large pcap costs as much memory and CPU as an
/// analysis. `wait` is how long to wait for a permit; `None` gives 429
/// `busy` at once.
pub(crate) async fn load_heavy(
    state: &AppState,
    path: PathBuf,
    wait: Option<std::time::Duration>,
) -> Result<pcapload::LoadedPcap, AppError> {
    let sem = state.heavy.clone();
    let _permit = match wait {
        None => sem.try_acquire_owned().map_err(|_| busy())?,
        Some(d) => tokio::time::timeout(d, sem.acquire_owned())
            .await
            .map_err(|_| busy())?
            .map_err(|_| busy())?,
    };
    load_blocking(path).await
}

/// Load a pcap on the blocking pool. Callers hold a heavy permit.
async fn load_blocking(path: PathBuf) -> Result<pcapload::LoadedPcap, AppError> {
    tokio::task::spawn_blocking(move || load(&path))
        .await
        .map_err(|e| AppError::Internal(format!("pcap load task: {e}")))?
        .map_err(|e| AppError::BadRequest(format!("load pcap: {e:#}")).code("pcap_unreadable"))
}

pub(crate) async fn api_run(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    LocalIp(local_ip): LocalIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<RunReq>,
) -> Result<Json<RunResp>, AppError> {
    let id = start_run(&state, client_ip, local_ip, &headers, req, None).await?;
    Ok(Json(RunResp { id }))
}

/// Validate, load the pcap and launch: the one path behind
/// `POST /api/run` and `POST /api/runs/:id/rerun`, with the same
/// validation and single-run rule (409 `run_active`).
pub(crate) async fn start_run(
    state: &AppState,
    client_ip: String,
    local_ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    req: RunReq,
    rerun_of: Option<u64>,
) -> Result<u64, AppError> {
    validate_fields(&req)?;
    // Fail fast before the (possibly slow) pcap load; `launch`
    // re-checks atomically when it takes the slot.
    if let Some(a) = state.active_run() {
        return Err(run_active_error(&a));
    }
    let pcap_id = req.pcap_id.clone().unwrap_or_default();
    let pcap_path = library_pcap_path(&state.library_dir, &pcap_id)?;
    let pcap = Arc::new(load_heavy(state, pcap_path.clone(), Some(RUN_LOAD_PERMIT_WAIT)).await?);
    // The address the operator reached this UI on must never be taken
    // over by a run (security review of T03/T04).
    let protected: Vec<std::net::IpAddr> = local_ip.into_iter().collect();
    let (job, mut template) = build_job(&req, &state.cfg.state_dir, protected);
    template.rerun_of = rerun_of;
    launch(
        state,
        Launch {
            pcap,
            pcap_path,
            pcap_id,
            client_ip,
            client_id: client_id(headers),
            job,
            template,
        },
    )
}

#[derive(Deserialize, Default)]
pub(crate) struct RerunQuery {
    /// Re-confirm `force` for the new run. A stored `force: true` is
    /// never inherited silently: without this the re-run starts with
    /// `force: false`.
    #[serde(default)]
    force: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct RerunResp {
    id: u64,
    rerun_of: u64,
    /// The request the new run was started with.
    request: serde_json::Value,
}

/// `POST /api/runs/:id/rerun[?force=true]`: start a new run with the
/// stored request of run `id`. Same validation and 409 rules as
/// `POST /api/run`; the new run's `rerun_of` is `id`.
pub(crate) async fn api_run_rerun(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    LocalIp(local_ip): LocalIp,
    headers: HeaderMap,
    ApiPath(id): ApiPath<u64>,
    ApiQuery(q): ApiQuery<RerunQuery>,
) -> Result<Json<RerunResp>, AppError> {
    let stored = {
        let entry = state
            .get_run(id)
            .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
        let rs = entry.lock_safe();
        rs.request.clone()
    }
    .ok_or_else(|| {
        AppError::Conflict(
            "request_missing",
            format!("run {id} predates stored run requests and cannot be re-run"),
        )
    })?;
    let mut req = runbuild::from_json(stored).map_err(AppError::from)?;
    req.force = q.force.unwrap_or(false);
    let request = runbuild::canonical_json(&req);
    let new_id = start_run(&state, client_ip, local_ip, &headers, req, Some(id)).await?;
    Ok(Json(RerunResp {
        id: new_id,
        rerun_of: id,
        request,
    }))
}

#[derive(Deserialize, Default)]
pub(crate) struct RunsQuery {
    #[serde(default)]
    status: Option<String>,
}

/// Slim run list (F029, F054): no per-session rows, no latency
/// histograms, and live per-source progress only for running runs.
/// `?status=running` (or any status) filters.
pub(crate) async fn api_runs(
    State(state): State<AppState>,
    ApiQuery(q): ApiQuery<RunsQuery>,
) -> Result<Json<Vec<RunSummary>>, AppError> {
    let filter = match q.status.as_deref() {
        None | Some("") => None,
        Some(s) => {
            let st = RunStatus::from_str(s);
            if st.as_str() != s {
                return Err(AppError::BadRequest(format!("unknown status filter {s:?}"))
                    .code("invalid_request"));
            }
            Some(st)
        }
    };
    // Copy only the Arc handles under the global lock; each run is
    // then locked on its own while its summary is built.
    let mut out: Vec<RunSummary> = state
        .all_runs()
        .into_iter()
        .filter_map(|e| {
            let mut rs = e.lock_safe();
            if filter.is_some_and(|f| f != rs.status) {
                return None;
            }
            refresh_progress(&mut rs);
            Some(rs.summary())
        })
        .collect();
    out.sort_by_key(|r| std::cmp::Reverse(r.id));
    Ok(Json(out))
}

/// Full detail of one run, including per-session rows and histograms,
/// plus `has_capture`.
#[derive(Serialize)]
pub(crate) struct RunDetail {
    #[serde(flatten)]
    run: RunState,
    has_capture: bool,
}

pub(crate) async fn api_run_by_id(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Json<RunDetail>, AppError> {
    let entry = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let mut rs = entry.lock_safe().clone();
    refresh_progress(&mut rs);
    let has_capture = rs.capture_file.as_ref().is_some_and(|p| p.is_file());
    Ok(Json(RunDetail {
        run: rs,
        has_capture,
    }))
}

/// Delete a finished run. A run marked running whose worker is gone is
/// finalised first; a run with a live worker gives 409.
pub(crate) async fn api_run_delete(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<StatusCode, AppError> {
    let entry = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let (running, capture) = {
        let rs = entry.lock_safe();
        (!rs.status.is_terminal(), rs.capture_file.clone())
    };
    if running {
        if state.worker_alive(id) {
            return Err(AppError::Conflict(
                "run_running",
                format!("run {id} is still running; stop it before deleting"),
            ));
        }
        finalize(
            &state,
            id,
            RunOutcome::Abandoned("run had no live worker".into()),
        );
    }
    {
        // Fold the run's totals into the metrics before it disappears,
        // under the lock the scrape takes, so counters never go back.
        let mut folded = state.metrics.folded.lock_safe();
        crate::metrics::fold_deleted(&mut folded, &entry.lock_safe());
        state.runs.lock_safe().remove(&id);
    }
    state.workers.lock_safe().remove(&id);
    state.gap_cache.lock_safe().remove(&id);
    if let Err(e) = state.db.delete(id) {
        warn!(id, error = %e, "db delete failed");
    }
    // Only ever delete our own capture file.
    if let Some(p) = capture.filter(|p| p.starts_with(state.cfg.captures_dir())) {
        let _ = std::fs::remove_file(p);
    }
    info!(id, "run deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub(crate) struct StopResp {
    id: u64,
    status: RunStatus,
}

/// Request a stop. Running runs get their cancel flags set (202). A run
/// still marked running with no live worker is finalised as stopped
/// right away (200), so stop can always clear a zombie (F049, F074).
pub(crate) async fn api_run_stop(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    ApiPath(id): ApiPath<u64>,
) -> Result<(StatusCode, Json<StopResp>), AppError> {
    let entry = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let status = {
        let rs = entry.lock_safe();
        if rs.status.is_terminal() {
            return Ok((
                StatusCode::OK,
                Json(StopResp {
                    id,
                    status: rs.status,
                }),
            ));
        }
        cancel_run(&rs);
        rs.status
    };
    state.emit(
        "run_stopped",
        id,
        &client_ip,
        client_id(&headers),
        "stopping",
    );
    info!(id, client = %client_ip, "stop requested");
    if !state.worker_alive(id) {
        finalize(
            &state,
            id,
            RunOutcome::Abandoned("stopped; run had no live worker".into()),
        );
        let st = entry.lock_safe().status;
        return Ok((StatusCode::OK, Json(StopResp { id, status: st })));
    }
    Ok((StatusCode::ACCEPTED, Json(StopResp { id, status })))
}

#[derive(Serialize)]
pub(crate) struct GapHistResp {
    /// Log-spaced bucket boundaries in nanoseconds. 21 entries define 20 buckets.
    buckets_ns: Vec<u64>,
    /// Original pcap's inter-packet gaps, one count per bucket.
    original: Vec<u64>,
    /// Captured replay's inter-packet gaps, one count per bucket.
    captured: Vec<u64>,
    /// Library id of the source pcap (no server paths are echoed).
    pcap_id: Option<String>,
    run_id: u64,
}

/// Compute a 20-bucket log histogram of inter-packet gaps (ns).
/// Buckets span 1 µs → 10 s.
pub(crate) fn bucket_gaps(packets: &[pcapload::Packet]) -> Vec<u64> {
    let mut buckets = vec![0u64; 20];
    if packets.len() < 2 {
        return buckets;
    }
    let min_log = (1_000f64).log10();
    let max_log = (10_000_000_000f64).log10();
    for pair in packets.windows(2) {
        let gap = pair[1].ts_ns.saturating_sub(pair[0].ts_ns);
        if gap == 0 {
            continue;
        }
        let l = (gap as f64).log10();
        let idx = (((l - min_log) / (max_log - min_log)) * 20.0) as isize;
        buckets[idx.clamp(0, 19) as usize] += 1;
    }
    buckets
}

pub(crate) async fn api_run_gaps(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(v) = state.gap_cache.lock_safe().get(&id) {
        return Ok(Json((**v).clone()));
    }
    let (original_path, captured_path, pcap_id, terminal) = {
        let entry = state
            .get_run(id)
            .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
        let rs = entry.lock_safe();
        let cap = rs
            .capture_file
            .clone()
            .filter(|p| p.is_file())
            .ok_or_else(|| AppError::NotFound(format!("run {id} has no capture file")))?;
        (
            rs.pcap.clone(),
            cap,
            rs.pcap_id.clone(),
            rs.status.is_terminal(),
        )
    };
    if !original_path.is_file() {
        return Err(AppError::NotFound(format!(
            "source pcap of run {id} is no longer in the library"
        ))
        .code("source_pcap_missing"));
    }
    let _permit = state
        .heavy
        .clone()
        .try_acquire_owned()
        .map_err(|_| busy())?;
    let resp = tokio::task::spawn_blocking(move || -> Result<GapHistResp, AppError> {
        let orig = load(&original_path)
            .map_err(|e| AppError::BadRequest(format!("load original: {e:#}")))?;
        let cap = load(&captured_path)
            .map_err(|e| AppError::BadRequest(format!("load capture: {e:#}")))?;
        let edges = (0..=20)
            .map(|i| 10f64.powf(3.0 + (i as f64) * (7.0 / 20.0)) as u64)
            .collect();
        Ok(GapHistResp {
            buckets_ns: edges,
            original: bucket_gaps(&orig.packets),
            captured: bucket_gaps(&cap.packets),
            pcap_id,
            run_id: id,
        })
    })
    .await
    .map_err(|e| AppError::Internal(format!("gap task: {e}")))??;
    let v = serde_json::to_value(&resp).map_err(|e| AppError::Internal(e.to_string()))?;
    if terminal {
        state.gap_cache.lock_safe().insert(id, Arc::new(v.clone()));
    }
    Ok(Json(v))
}

pub(crate) fn busy() -> AppError {
    AppError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "busy",
        "too many heavy requests in progress; retry shortly",
    )
}

/// Stream a run's capture (raw or benchmark) to the client (F055).
pub(crate) async fn api_run_download(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Response, AppError> {
    let path = {
        let entry = state
            .get_run(id)
            .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
        let rs = entry.lock_safe();
        rs.capture_file.clone()
    }
    .filter(|p| crate::captures::is_regular_file_inside(p, &state.cfg.captures_dir()))
    .ok_or_else(|| {
        AppError::NotFound(format!(
            "no capture for run {id} (never written or evicted)"
        ))
        .code("capture_missing")
    })?;
    crate::routes::stream_file(&path, &format!("run_{id}.pcap")).await
}
