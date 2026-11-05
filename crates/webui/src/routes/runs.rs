//! Run start, list, detail, stop, delete, gaps and capture download.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use netctl::parse_mac;
use pcapload::load;
use sched::{
    run as sched_run, run_benchmark as sched_run_benchmark, BenchmarkConfig, ConcurrencyModel,
    RunConfig, RunContext,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::dto::*;
use crate::error::AppError;
use crate::library::*;
use crate::persist::*;
use crate::runs::*;
use crate::state::*;

#[derive(Deserialize)]
pub(crate) struct RunReq {
    #[serde(default)]
    pub(crate) pcap: Option<PathBuf>,
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
    /// Pre-run RTU subset. In slave-mode this filters which captured
    /// server IPs get a listener; in master-mode it filters which
    /// client IPs spawn a session. Empty = all (run all).
    #[serde(default)]
    pub(crate) selected_rtus: Vec<Ipv4Addr>,
    /// Slave-mode only. When `true`, the slave replays the captured
    /// script `iterations` times *within one TCP session* (no STOPDT
    /// between loops). Default `false` keeps the legacy
    /// "fresh handshake per iteration" behaviour.
    #[serde(default)]
    pub(crate) loop_within_session: bool,
    #[serde(default = "default_warmup")]
    pub(crate) warmup_secs: u64,
    /// "raw" (default) or "benchmark".
    #[serde(default = "default_mode")]
    pub(crate) mode: String,
    /// Benchmark-only: destination port of the target protocol. 2404 for IEC 104.
    #[serde(default = "default_target_port")]
    pub(crate) target_port: u16,
    /// Benchmark-only: which ProtoReplayer module to use.
    #[serde(default = "default_proto_name")]
    pub(crate) proto_name: String,
    /// Benchmark-only: "all_at_once" | "staggered".
    #[serde(default = "default_concurrency")]
    pub(crate) concurrency: String,
    /// Benchmark-only: free-form JSON passed through to the protocol
    /// module. For IEC 104, this is the ASDU rewrite map
    /// (`{"common_address": {...}, "cot": {...}, "ioa": {...}}`).
    #[serde(default)]
    pub(crate) proto_config: Option<String>,
    /// Benchmark-only: "master" (default) = tool connects out to the
    /// target as a client; "slave" = tool listens and waits for the
    /// target master to connect in.
    #[serde(default = "default_role")]
    pub(crate) role: String,
    /// Benchmark-slave-only: first TCP listen port. Session i listens
    /// on `listen_port_base + i`.
    #[serde(default = "default_listen_port_base")]
    pub(crate) listen_port_base: u16,
    /// Benchmark-only: "fast" (default) = fire as fast as the
    /// protocol window allows; "original" = match the original
    /// pcap's inter-frame cadence, scaled by `speed`.
    #[serde(default = "default_pacing")]
    pub(crate) pacing: String,
    /// Number of times to repeat the captured script. `0` = unlimited
    /// (loop until cancel). Default `1`.
    #[serde(default = "default_iterations")]
    pub(crate) iterations: u64,
    /// SCADA-gateway mode (see doc/scada-lab.md): claim this IP as a
    /// /32 alias on `scada_gateway_iface` for the run, so a SCADA
    /// guest on an isolated vSwitch routes off-subnet traffic to us.
    #[serde(default)]
    pub(crate) scada_gateway_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub(crate) scada_gateway_iface: Option<String>,
    /// Optional upstream NIC for MASQUERADE. If set, IP forwarding is
    /// enabled and SCADA's non-capture egress is NAT'd out this NIC.
    #[serde(default)]
    pub(crate) upstream_nat_iface: Option<String>,
    /// Master-mode only: override the per-session bind IP. Default
    /// (None) keeps the captured client IPs as the source addresses
    /// of the replayed master sessions. Set to a local IP (or one we
    /// can alias onto the bridge) to make all master sessions
    /// originate from a specific local address regardless of what
    /// the pcap recorded. Useful when the captured master IP
    /// (e.g. 192.168.10.10) doesn't exist on the replay host.
    #[serde(default)]
    pub(crate) master_bind_ip: Option<Ipv4Addr>,
    /// Override TCP_NODELAY on the session sockets. Default (None)
    /// uses the role-based default: slave = true (matches real RTU
    /// event-driven behaviour), master = false. Set explicitly to
    /// override either way for debugging or A/B comparisons.
    #[serde(default)]
    pub(crate) tcp_nodelay: Option<bool>,
}

pub(crate) fn default_iterations() -> u64 {
    1
}

pub(crate) fn default_pacing() -> String {
    "fast".into()
}

pub(crate) fn default_role() -> String {
    "master".into()
}
pub(crate) fn default_listen_port_base() -> u16 {
    2404
}

pub(crate) fn default_mode() -> String {
    "raw".into()
}
pub(crate) fn default_target_port() -> u16 {
    2404
}
pub(crate) fn default_concurrency() -> String {
    "all_at_once".into()
}

pub(crate) fn default_warmup() -> u64 {
    5
}

pub(crate) fn default_bridge() -> String {
    "pcr_br0".into()
}
pub(crate) fn default_tap_prefix() -> String {
    "pcr_t".into()
}
pub(crate) fn default_speed() -> f64 {
    1.0
}

#[derive(Serialize)]
pub(crate) struct RunResp {
    pub(crate) id: u64,
}

pub(crate) async fn api_run(
    State(state): State<AppState>,
    Json(req): Json<RunReq>,
) -> Result<Json<RunResp>, AppError> {
    let pcap_path: PathBuf = if let Some(id) = req.pcap_id.as_deref() {
        library_pcap_path(&state.library_dir, id)?
    } else if let Some(p) = req.pcap.clone() {
        p
    } else {
        return Err(AppError::BadRequest(
            "run request needs either pcap_id or pcap path".into(),
        ));
    };
    let pcap = load(&pcap_path).map_err(|e| AppError::BadRequest(format!("load pcap: {e}")))?;
    let pcap = Arc::new(pcap);
    let is_benchmark = req.mode == "benchmark";
    let id = state.next_id.fetch_add(1, Ordering::SeqCst);
    let capture_pb = std::path::PathBuf::from(format!("{CAPTURE_DIR}/run_{id}.pcap"));

    let ctx = RunContext::new();
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mode_str: &'static str = if is_benchmark { "benchmark" } else { "raw" };
    let role_str: &'static str = if is_benchmark {
        if req.role == "slave" {
            "slave"
        } else {
            "master"
        }
    } else {
        ""
    };
    let target_port_for_state: u16 = if is_benchmark {
        if req.role == "slave" {
            req.listen_port_base
        } else {
            req.target_port
        }
    } else {
        0
    };
    let initial = RunState {
        id,
        status: RunStatus::Running,
        started_at,
        pcap: pcap_path.clone(),
        target_ip: req.target_ip,
        target_mac: req.target_mac.clone(),
        speed: req.speed,
        top_speed: req.top_speed,
        realtime: req.realtime,
        error: None,
        report: None,
        benchmark: None,
        mode: mode_str,
        role: role_str,
        target_port: target_port_for_state,
        proto: if is_benchmark {
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
        ctx: ctx.clone(),
    };
    if let Err(e) = state.db.insert_run_start(&runstate_to_stored(&initial)) {
        warn!(id, error = %e, "db insert_run_start failed");
    }
    state.runs.lock().unwrap().insert(id, initial);

    let runs = state.runs.clone();
    let ctx_for_thread = ctx.clone();

    if is_benchmark {
        // Look up the protocol module.
        let Some(replayer) = get_proto(&req.proto_name) else {
            let mut map = runs.lock().unwrap();
            if let Some(rs) = map.get_mut(&id) {
                rs.status = RunStatus::Failed;
                rs.error = Some(format!("unknown proto_name: {}", req.proto_name));
            }
            return Err(AppError::BadRequest(format!(
                "unknown proto_name: {}",
                req.proto_name
            )));
        };
        let concurrency = match req.concurrency.as_str() {
            "staggered" => ConcurrencyModel::StaggeredPcapTiming,
            _ => ConcurrencyModel::AllAtOnce,
        };
        let bcfg = BenchmarkConfig {
            target_ip: req.target_ip,
            target_port: req.target_port,
            proto_name: req.proto_name.clone(),
            bridge_name: req.bridge.clone(),
            tap_prefix: req.tap_prefix.clone(),
            egress_nic: req.nic.clone(),
            concurrency,
            connect_timeout_secs: 5,
            startup_delay_secs: req.warmup_secs,
            capture_path: Some(capture_pb.clone()),
            proto_config: req.proto_config.clone(),
            role: match req.role.as_str() {
                "slave" => protoplay::Role::Slave,
                _ => protoplay::Role::Master,
            },
            listen_port_base: req.listen_port_base,
            pacing: match req.pacing.as_str() {
                "original" => protoplay::Pacing::OriginalTiming { speed: req.speed },
                _ => protoplay::Pacing::AsFastAsPossible,
            },
            iterations: req.iterations,
            scada_gateway_ip: req.scada_gateway_ip,
            scada_gateway_iface: req.scada_gateway_iface.clone(),
            upstream_nat_iface: req.upstream_nat_iface.clone(),
            alias_state_path: Some(alias_state_path()),
            master_bind_ip: req.master_bind_ip,
            tcp_nodelay: req.tcp_nodelay,
            selected_endpoints: if req.selected_rtus.is_empty() {
                None
            } else {
                Some(req.selected_rtus.iter().copied().collect())
            },
            loop_within_session: req.loop_within_session,
        };
        let db_bench = state.db.clone();
        thread::Builder::new()
            .name(format!("webui-bench-{id}"))
            .spawn(move || {
                info!(id, "starting benchmark run");
                let result = sched_run_benchmark(pcap, bcfg, replayer, ctx_for_thread);
                let mut map = runs.lock().unwrap();
                if let Some(rs) = map.get_mut(&id) {
                    // Snapshot final progress BEFORE flipping status, so
                    // refresh_progress's "running-only" guard lets the
                    // last values through into the stored row.
                    refresh_progress(rs);
                    match result {
                        Ok(r) => {
                            rs.status = if rs.ctx.is_cancelled() {
                                RunStatus::Stopped
                            } else {
                                RunStatus::Completed
                            };
                            rs.benchmark = Some((&r).into());
                        }
                        Err(e) => {
                            warn!(id, error = %e, "benchmark failed");
                            rs.status = RunStatus::Failed;
                            rs.error = Some(format!("{e:#}"));
                        }
                    }
                    let stored = runstate_to_stored(rs);
                    if let Err(e) = db_bench.update_finished(
                        stored.id,
                        &stored.status,
                        stored.error.as_deref(),
                        stored.report_json.as_deref(),
                        stored.benchmark_json.as_deref(),
                        stored.per_source_json.as_deref(),
                        stored.throughput_json.as_deref(),
                        stored.planned,
                        stored.sent,
                        stored.bytes,
                    ) {
                        warn!(id, error = %e, "db update_finished (bench) failed");
                    }
                }
            })
            .map_err(|e| AppError::Internal(format!("spawn thread: {e}")))?;
    } else {
        // Raw replay path — needs a target MAC.
        let target_mac_bytes =
            parse_mac(&req.target_mac).map_err(|e| AppError::BadRequest(format!("{e}")))?;
        let cfg = RunConfig {
            target_ip: req.target_ip,
            target_mac: target_mac_bytes,
            bridge_name: req.bridge.clone(),
            tap_prefix: req.tap_prefix.clone(),
            egress_nic: req.nic.clone(),
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
            capture_path: Some(capture_pb.clone()),
            iterations: req.iterations,
        };
        let db_raw = state.db.clone();
        thread::Builder::new()
            .name(format!("webui-run-{id}"))
            .spawn(move || {
                info!(id, "starting run");
                let result = sched_run(pcap, cfg, ctx_for_thread);
                let mut map = runs.lock().unwrap();
                if let Some(rs) = map.get_mut(&id) {
                    // Snapshot final progress BEFORE flipping status, so
                    // refresh_progress's "running-only" guard lets the
                    // last values through into the stored row.
                    refresh_progress(rs);
                    match result {
                        Ok(r) => {
                            rs.status = if rs.ctx.is_cancelled() {
                                RunStatus::Stopped
                            } else {
                                RunStatus::Completed
                            };
                            rs.report = Some((&r).into());
                        }
                        Err(e) => {
                            warn!(id, error = %e, "run failed");
                            rs.status = RunStatus::Failed;
                            rs.error = Some(format!("{e:#}"));
                        }
                    }
                    let stored = runstate_to_stored(rs);
                    if let Err(e) = db_raw.update_finished(
                        stored.id,
                        &stored.status,
                        stored.error.as_deref(),
                        stored.report_json.as_deref(),
                        stored.benchmark_json.as_deref(),
                        stored.per_source_json.as_deref(),
                        stored.throughput_json.as_deref(),
                        stored.planned,
                        stored.sent,
                        stored.bytes,
                    ) {
                        warn!(id, error = %e, "db update_finished (raw) failed");
                    }
                }
            })
            .map_err(|e| AppError::Internal(format!("spawn thread: {e}")))?;
    }

    // Kick off a background throughput sampler for this run. Every 1 s,
    // while status is Running, snapshot `ctx.sent` and push
    // `(sent_this_tick - sent_last_tick)` into the history buffer.
    let runs_s = state.runs.clone();
    let ctx_s = ctx;
    thread::Builder::new()
        .name(format!("webui-tps-{id}"))
        .spawn(move || {
            let mut last = 0u64;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let mut map = runs_s.lock().unwrap();
                let Some(rs) = map.get_mut(&id) else {
                    return;
                };
                if !matches!(rs.status, RunStatus::Running) {
                    return;
                }
                let now = ctx_s.sent.load(Ordering::Relaxed);
                let delta = now.saturating_sub(last);
                last = now;
                rs.throughput_history.push(delta);
                if rs.throughput_history.len() > 120 {
                    rs.throughput_history.remove(0);
                }
            }
        })
        .ok();

    Ok(Json(RunResp { id }))
}

pub(crate) async fn api_runs(State(state): State<AppState>) -> Json<Vec<RunState>> {
    let map = state.runs.lock().unwrap();
    let mut v: Vec<RunState> = map.values().cloned().collect();
    drop(map);
    for r in &mut v {
        refresh_progress(r);
    }
    v.sort_by_key(|r| std::cmp::Reverse(r.id));
    Json(v)
}

pub(crate) async fn api_run_by_id(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<RunState>, AppError> {
    let map = state.runs.lock().unwrap();
    let mut rs = map
        .get(&id)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    drop(map);
    refresh_progress(&mut rs);
    Ok(Json(rs))
}

pub(crate) async fn api_run_delete(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<StatusCode, AppError> {
    {
        let map = state.runs.lock().unwrap();
        if let Some(rs) = map.get(&id) {
            if matches!(rs.status, RunStatus::Running) {
                return Err(AppError::BadRequest(format!(
                    "run {id} is still running — stop it before deleting"
                )));
            }
        } else {
            return Err(AppError::NotFound(format!("run {id} not found")));
        }
    }
    state.runs.lock().unwrap().remove(&id);
    if let Err(e) = state.db.delete(id) {
        warn!(id, error = %e, "db delete failed");
    }
    // Best-effort: also remove the capture file if it exists.
    let cap = std::path::PathBuf::from(format!("{CAPTURE_DIR}/run_{id}.pcap"));
    let _ = std::fs::remove_file(&cap);
    info!(id, "run deleted");
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn api_run_stop(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<StatusCode, AppError> {
    let map = state.runs.lock().unwrap();
    let rs = map
        .get(&id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    rs.ctx.cancel.store(true, Ordering::Relaxed);
    // Fan out: flip every per-session cancel so replayers unwind
    // promptly at their next check, not just when the top-level
    // ctx.cancel is read by sched's own loops.
    let sp = rs.ctx.per_source.lock().unwrap();
    for entry in sp.iter() {
        entry.cancel.store(true, Ordering::Relaxed);
        entry.ready.store(true, Ordering::Relaxed);
    }
    drop(sp);
    info!(id, "stop requested");
    Ok(StatusCode::ACCEPTED)
}

#[derive(Serialize)]
pub(crate) struct GapHistResp {
    /// Log-spaced bucket boundaries in nanoseconds. 21 entries define 20 buckets.
    pub(crate) buckets_ns: Vec<u64>,
    /// Original pcap's inter-packet gaps, one count per bucket.
    pub(crate) original: Vec<u64>,
    /// Captured replay's inter-packet gaps, one count per bucket.
    pub(crate) captured: Vec<u64>,
    /// Source pcap paths used.
    pub(crate) original_path: String,
    pub(crate) captured_path: String,
}

/// Compute a 20-bucket log histogram of inter-packet gaps (ns).
/// Buckets span 1 µs → 10 s.
pub(crate) fn bucket_gaps(packets: &[pcapload::Packet]) -> Vec<u64> {
    let mut buckets = vec![0u64; 20];
    if packets.len() < 2 {
        return buckets;
    }
    let min_log = (1_000f64).log10(); // 1 µs  = 10^3 ns
    let max_log = (10_000_000_000f64).log10(); // 10 s = 10^10 ns
    for pair in packets.windows(2) {
        let gap = pair[1].ts_ns.saturating_sub(pair[0].ts_ns);
        if gap == 0 {
            continue;
        }
        let l = (gap as f64).log10();
        let mut idx = (((l - min_log) / (max_log - min_log)) * 20.0) as isize;
        if idx < 0 {
            idx = 0;
        }
        if idx >= 20 {
            idx = 19;
        }
        buckets[idx as usize] += 1;
    }
    buckets
}

pub(crate) async fn api_run_gaps(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<GapHistResp>, AppError> {
    // Resolve the two pcap paths from the run's record.
    let (original_path, captured_path) = {
        let map = state.runs.lock().unwrap();
        let rs = map
            .get(&id)
            .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
        let orig = rs.pcap.display().to_string();
        let cap = rs
            .report
            .as_ref()
            .and_then(|r| r.capture_path.clone())
            .or_else(|| rs.benchmark.as_ref().and_then(|b| b.capture_path.clone()))
            .ok_or_else(|| AppError::NotFound(format!("run {id} has no capture file")))?;
        (orig, cap)
    };

    let orig_pcap =
        load(&original_path).map_err(|e| AppError::BadRequest(format!("load original: {e}")))?;
    let cap_pcap =
        load(&captured_path).map_err(|e| AppError::BadRequest(format!("load capture: {e}")))?;

    // Bucket boundaries for labeling (21 edges, 20 buckets, log-spaced 1 µs → 10 s).
    let mut edges = Vec::with_capacity(21);
    for i in 0..=20 {
        let l = 3.0 + (i as f64) * ((10.0 - 3.0) / 20.0);
        edges.push(10f64.powf(l) as u64);
    }

    Ok(Json(GapHistResp {
        buckets_ns: edges,
        original: bucket_gaps(&orig_pcap.packets),
        captured: bucket_gaps(&cap_pcap.packets),
        original_path,
        captured_path,
    }))
}

pub(crate) async fn api_run_download(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Response, AppError> {
    let path = {
        let map = state.runs.lock().unwrap();
        map.get(&id)
            .and_then(|r| r.report.as_ref().and_then(|rep| rep.capture_path.clone()))
            .ok_or_else(|| AppError::NotFound(format!("no capture for run {id}")))?
    };
    let bytes =
        std::fs::read(&path).map_err(|e| AppError::Internal(format!("read {path:?}: {e}")))?;
    let fname = std::path::Path::new(&path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("replay.pcap")
        .to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.tcpdump.pcap"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{fname}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    Ok((headers, bytes).into_response())
}
