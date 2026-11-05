//! Run start, list, detail, stop, delete, gaps and capture download.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use netctl::parse_mac;
use pcapload::load;
use sched::{BenchmarkConfig, ConcurrencyModel, RunConfig, RunContext};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::dto::*;
use crate::error::{ApiJson, ApiPath, ApiQuery, AppError, LockExt};
use crate::library::*;
use crate::runs::*;
use crate::security::{client_id, ClientIp, LocalIp};
use crate::state::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunMode {
    Raw,
    Benchmark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RoleReq {
    Master,
    Slave,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PacingReq {
    Fast,
    Original,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConcurrencyReq {
    AllAtOnce,
    Staggered,
}

/// Body of `POST /api/run`. Unknown enum values are rejected with 422
/// (F056); the pcap is referenced by library id only (F052, F148).
#[derive(Deserialize)]
pub(crate) struct RunReq {
    /// Rejected when present: raw filesystem paths are not accepted.
    #[serde(default)]
    pub(crate) pcap: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) pcap_id: Option<String>,
    pub(crate) target_ip: Ipv4Addr,
    /// Required for raw replay; ignored in benchmark mode.
    #[serde(default)]
    pub(crate) target_mac: String,
    #[serde(default)]
    pub(crate) nic: Option<String>,
    #[serde(default = "default_bridge")]
    pub(crate) bridge: String,
    #[serde(default = "default_tap_prefix")]
    pub(crate) tap_prefix: String,
    #[serde(default = "default_speed")]
    pub(crate) speed: f64,
    #[serde(default)]
    pub(crate) top_speed: bool,
    #[serde(default)]
    pub(crate) realtime: bool,
    #[serde(default)]
    pub(crate) skip_non_ip: bool,
    #[serde(default)]
    pub(crate) only_src: Vec<Ipv4Addr>,
    /// Pre-run RTU subset (slave: server IPs; master: client IPs).
    #[serde(default)]
    pub(crate) selected_rtus: Vec<Ipv4Addr>,
    /// Slave-mode only: loop the script within one TCP session.
    #[serde(default)]
    pub(crate) loop_within_session: bool,
    #[serde(default = "default_warmup")]
    pub(crate) warmup_secs: u64,
    #[serde(default = "default_mode")]
    pub(crate) mode: RunMode,
    #[serde(default = "default_target_port")]
    pub(crate) target_port: u16,
    #[serde(default = "default_proto_name")]
    pub(crate) proto_name: String,
    #[serde(default = "default_concurrency")]
    pub(crate) concurrency: ConcurrencyReq,
    #[serde(default)]
    pub(crate) proto_config: Option<String>,
    #[serde(default = "default_role")]
    pub(crate) role: RoleReq,
    #[serde(default = "default_listen_port_base")]
    pub(crate) listen_port_base: u16,
    #[serde(default = "default_pacing")]
    pub(crate) pacing: PacingReq,
    /// Number of times to repeat the captured script. `0` = unlimited.
    #[serde(default = "default_iterations")]
    pub(crate) iterations: u64,
    #[serde(default)]
    pub(crate) scada_gateway_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub(crate) scada_gateway_iface: Option<String>,
    #[serde(default)]
    pub(crate) upstream_nat_iface: Option<String>,
    #[serde(default)]
    pub(crate) master_bind_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub(crate) tcp_nodelay: Option<bool>,
    /// Slave mode: interface that receives RTU listen-IP aliases when
    /// they are not already local. Defaults to the default-route NIC,
    /// which is protected (refused unless `force`).
    #[serde(default)]
    pub(crate) alias_iface: Option<String>,
    /// Operator override for netctl's NIC / address protection (default
    /// route NIC, the address this UI is reached on, bridge ports,
    /// addresses held by other interfaces). Absolute refusals
    /// (loopback, gateway, multicast, …) still apply.
    #[serde(default)]
    pub(crate) force: bool,
}

fn default_iterations() -> u64 {
    1
}
fn default_pacing() -> PacingReq {
    PacingReq::Fast
}
fn default_role() -> RoleReq {
    RoleReq::Master
}
fn default_listen_port_base() -> u16 {
    2404
}
fn default_mode() -> RunMode {
    RunMode::Raw
}
fn default_target_port() -> u16 {
    2404
}
fn default_concurrency() -> ConcurrencyReq {
    ConcurrencyReq::AllAtOnce
}
fn default_warmup() -> u64 {
    5
}
fn default_bridge() -> String {
    "pcr_br0".into()
}
fn default_tap_prefix() -> String {
    "pcr_t".into()
}
fn default_speed() -> f64 {
    1.0
}

/// Longest warmup accepted, in seconds.
const MAX_WARMUP_SECS: u64 = 3600;

/// Interface-name check: kernel IFNAMSIZ (15 usable chars), no
/// wildcard (`+`), no option-like leading `-` (F042).
pub(crate) fn validate_ifname(field: &str, name: &str, max_len: usize) -> Result<(), AppError> {
    let ok = !name.is_empty()
        && name.len() <= max_len
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "{field}: {name:?} is not a valid interface name (1..={max_len} chars of \
             [A-Za-z0-9._-], not starting with '-')"
        ))
        .code("invalid_request"))
    }
}

fn bad(msg: impl Into<String>) -> AppError {
    AppError::BadRequest(msg).code("invalid_request")
}

/// Cheap field checks that need no I/O.
pub(crate) fn validate_fields(req: &RunReq) -> Result<(), AppError> {
    if req.pcap.is_some() {
        return Err(AppError::BadRequest(
            "raw filesystem paths are not accepted; upload the pcap to the library and \
             pass its pcap_id",
        )
        .code("raw_path_rejected"));
    }
    if req.pcap_id.as_deref().unwrap_or("").is_empty() {
        return Err(bad("pcap_id is required"));
    }
    if !(req.speed.is_finite() && (0.001..=1000.0).contains(&req.speed)) {
        return Err(bad(format!(
            "speed must be a finite number in 0.001..=1000, got {}",
            req.speed
        )));
    }
    if req.warmup_secs > MAX_WARMUP_SECS {
        return Err(bad(format!("warmup_secs must be <= {MAX_WARMUP_SECS}")));
    }
    validate_ifname("bridge", &req.bridge, 15)?;
    validate_ifname("tap_prefix", &req.tap_prefix, 10)?;
    for (field, v) in [
        ("nic", &req.nic),
        ("scada_gateway_iface", &req.scada_gateway_iface),
        ("upstream_nat_iface", &req.upstream_nat_iface),
        ("alias_iface", &req.alias_iface),
    ] {
        if let Some(n) = v.as_deref().filter(|s| !s.is_empty()) {
            validate_ifname(field, n, 15)?;
        }
    }
    if req.scada_gateway_ip.is_some()
        != req
            .scada_gateway_iface
            .as_deref()
            .is_some_and(|s| !s.is_empty())
    {
        return Err(bad(
            "scada_gateway_ip and scada_gateway_iface must be given together",
        ));
    }
    if let Some(pc) = req.proto_config.as_deref().filter(|s| !s.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(pc)
            .map_err(|e| bad(format!("proto_config is not valid JSON: {e}")))?;
    }
    match req.mode {
        RunMode::Raw => {
            parse_mac(&req.target_mac).map_err(|e| bad(format!("target_mac: {e}")))?;
        }
        RunMode::Benchmark => {
            if req.target_port == 0 {
                return Err(bad("target_port must be 1..=65535"));
            }
            if req.role == RoleReq::Slave {
                if req.listen_port_base == 0 {
                    return Err(bad("listen_port_base must be 1..=65535"));
                }
                let n = req.selected_rtus.len().max(1) as u32;
                if u32::from(req.listen_port_base) + n - 1 > u32::from(u16::MAX) {
                    return Err(bad(
                        "listen_port_base + number of selected RTUs exceeds 65535",
                    ));
                }
            }
            let Some(rep) = get_proto(&req.proto_name) else {
                return Err(bad(format!("unknown proto_name: {}", req.proto_name)));
            };
            if rep.readiness() == protoplay::Readiness::Stub {
                return Err(AppError::BadRequest(format!(
                    "protocol {} is a stub and cannot run benchmarks yet",
                    req.proto_name
                ))
                .code("protocol_not_ready"));
            }
        }
    }
    Ok(())
}

/// Build the scheduler job and the RunState template for a validated
/// request.
fn build_job(
    req: &RunReq,
    cfg: &ServeConfig,
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
        ctx: RunContext::new(),
    };
    let job = if is_bench {
        let replayer = get_proto(&req.proto_name).expect("validated proto");
        RunJob::Benchmark(
            BenchmarkConfig {
                // run_id is set by `launch` once the id is allocated;
                // bridge/tap names are then derived from it (F035).
                run_id: 0,
                target_ip: req.target_ip,
                target_port: req.target_port,
                proto_name: req.proto_name.clone(),
                bridge_name: None,
                tap_prefix: None,
                egress_nic: req.nic.clone().filter(|s| !s.is_empty()),
                concurrency: match req.concurrency {
                    ConcurrencyReq::Staggered => ConcurrencyModel::StaggeredPcapTiming,
                    ConcurrencyReq::AllAtOnce => ConcurrencyModel::AllAtOnce,
                },
                connect_timeout_secs: 5,
                startup_delay_secs: req.warmup_secs,
                capture_path: None,
                proto_config: req.proto_config.clone(),
                role: match req.role {
                    RoleReq::Slave => protoplay::Role::Slave,
                    RoleReq::Master => protoplay::Role::Master,
                },
                listen_port_base: req.listen_port_base,
                pacing: match req.pacing {
                    PacingReq::Original => protoplay::Pacing::OriginalTiming { speed: req.speed },
                    PacingReq::Fast => protoplay::Pacing::AsFastAsPossible,
                },
                iterations: req.iterations,
                scada_gateway_ip: req.scada_gateway_ip,
                scada_gateway_iface: req.scada_gateway_iface.clone(),
                upstream_nat_iface: req.upstream_nat_iface.clone().filter(|s| !s.is_empty()),
                state_dir: Some(cfg.state_dir.clone()),
                protected_addrs: protected_addrs.clone(),
                force_protected_nic: req.force,
                alias_iface: req.alias_iface.clone().filter(|s| !s.is_empty()),
                master_bind_ip: req.master_bind_ip,
                tcp_nodelay: req.tcp_nodelay,
                selected_endpoints: if req.selected_rtus.is_empty() {
                    None
                } else {
                    Some(req.selected_rtus.iter().copied().collect())
                },
                loop_within_session: req.loop_within_session,
            },
            replayer,
        )
    } else {
        RunJob::Raw(RunConfig {
            run_id: 0,
            target_ip: req.target_ip,
            target_mac: parse_mac(&req.target_mac).expect("validated mac"),
            bridge_name: None,
            tap_prefix: None,
            egress_nic: req.nic.clone().filter(|s| !s.is_empty()),
            speed: req.speed,
            top_speed: req.top_speed,
            realtime: req.realtime,
            filter_sources: if req.only_src.is_empty() {
                None
            } else {
                Some(req.only_src.clone())
            },
            include_non_ip: !req.skip_non_ip,
            startup_delay_secs: req.warmup_secs,
            capture_path: None,
            iterations: req.iterations,
            state_dir: Some(cfg.state_dir.clone()),
            protected_addrs,
            force_protected_nic: req.force,
        })
    };
    (job, template)
}

#[derive(Serialize)]
pub(crate) struct RunResp {
    id: u64,
}

/// Load a pcap on the blocking pool (F053, F087).
pub(crate) async fn load_blocking(path: PathBuf) -> Result<pcapload::LoadedPcap, AppError> {
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
    validate_fields(&req)?;
    // Fail fast before the (possibly slow) pcap load; `launch`
    // re-checks atomically when it takes the slot.
    if let Some(a) = state.active_run() {
        return Err(run_active_error(&a));
    }
    let pcap_id = req.pcap_id.clone().unwrap_or_default();
    let pcap_path = library_pcap_path(&state.library_dir, &pcap_id)?;
    let pcap = Arc::new(load_blocking(pcap_path.clone()).await?);
    // The address the operator reached this UI on must never be taken
    // over by a run (security review of T03/T04).
    let protected: Vec<std::net::IpAddr> = local_ip.into_iter().collect();
    let (job, template) = build_job(&req, &state.cfg, protected);
    let id = launch(
        &state,
        Launch {
            pcap,
            pcap_path,
            pcap_id,
            client_ip,
            client_id: client_id(&headers),
            job,
            template,
        },
    )?;
    Ok(Json(RunResp { id }))
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
                return Err(bad(format!("unknown status filter {s:?}")));
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
    state.runs.lock_safe().remove(&id);
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
