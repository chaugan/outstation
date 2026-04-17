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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path as StdPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

mod analysis;
mod db;
use analysis::{analyze, AnalysisMode, RoleHint, DEFAULT_CP56_TOLERANCE_MS};
use proto_iec104::asdu::Cp56Zone;
use db::{Db, StoredRun};

use anyhow::Result;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use netctl::parse_mac;
use pcapload::load;
use sched::{
    run as sched_run, run_benchmark as sched_run_benchmark, BenchmarkConfig, BenchmarkReport,
    ConcurrencyModel, RunConfig, RunContext, RunReport, SessionReport, SourceKind, SourceReport,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const EMBEDDED_HTML: &str = include_str!("index.html");
const EMBEDDED_ECHARTS: &str = include_str!("echarts.min.js");

#[derive(Clone)]
pub struct AppState {
    runs: Arc<Mutex<HashMap<u64, RunState>>>,
    next_id: Arc<AtomicU64>,
    library_dir: Arc<PathBuf>,
    db: Db,
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

#[derive(Clone, Serialize)]
pub struct RunState {
    pub id: u64,
    pub status: RunStatus,
    pub started_at: u64,
    pub pcap: PathBuf,
    pub target_ip: Ipv4Addr,
    pub target_mac: String,
    pub speed: f64,
    pub top_speed: bool,
    pub realtime: bool,
    /// Whether CP56Time2a timestamps were rewritten to wall-clock on
    /// every outgoing IEC 104 ASDU for this run. Persisted so the
    /// post-run fidelity/analysis pass knows to expect fresh stamps.
    #[serde(default)]
    pub rewrite_cp56_to_now: bool,
    /// Timezone convention used for the CP56 rewrite, either
    /// `"local"` or `"utc"`. Required at analysis time so the drift
    /// check decodes stamps with the same zone convention.
    pub cp56_zone: String,
    pub error: Option<String>,
    pub report: Option<RunReportJson>,
    pub benchmark: Option<BenchmarkReportJson>,
    pub mode: &'static str,
    /// Benchmark role: "master" or "slave", "" for raw.
    #[serde(default)]
    pub role: &'static str,
    /// Benchmark target port, 0 for raw.
    #[serde(default)]
    pub target_port: u16,
    /// Total frames planned for this run (snapshot from ctx.planned).
    pub planned: u64,
    /// Frames sent so far (snapshot from ctx.sent).
    pub sent: u64,
    /// Wire bytes sent so far (snapshot from ctx.bytes).
    pub bytes_progress: u64,
    /// Per-source live progress snapshot.
    pub per_source_progress: Vec<SourceProgressJson>,
    /// Rolling throughput samples in packets per second — one entry
    /// per server-side poll tick while the run was running. Used by
    /// the UI to draw the throughput sparkline.
    pub throughput_history: Vec<u64>,
    /// Live shared counters from sched. Not serialized.
    #[serde(skip)]
    pub ctx: RunContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProgressJson {
    pub src_ip: Option<String>,
    pub src_mac: String,
    pub tap: String,
    pub planned: u64,
    pub sent: u64,
    pub bytes: u64,
    #[serde(default)]
    pub received: u64,
    #[serde(default)]
    pub unacked: u64,
    /// Slave-benchmark: the local port this session listens on, or 0.
    #[serde(default)]
    pub listen_port: u16,
    /// Slave-benchmark: the local address the session listens on.
    /// Defaults to `0.0.0.0` (any interface). User-editable per-slave.
    #[serde(default)]
    pub listen_ip: String,
    /// Lifecycle state: "pending", "listening", "connected", "active",
    /// "completed", "failed".
    pub state: String,
    /// True once the per-session start button has been clicked.
    #[serde(default)]
    pub ready: bool,
    /// True once this session has been individually cancelled.
    #[serde(default)]
    pub cancelled: bool,
}

fn runstate_to_stored(rs: &RunState) -> StoredRun {
    StoredRun {
        id: rs.id,
        started_at: rs.started_at,
        status: rs.status.as_str().to_string(),
        pcap: rs.pcap.display().to_string(),
        target_ip: rs.target_ip.to_string(),
        target_mac: rs.target_mac.clone(),
        mode: rs.mode.to_string(),
        role: rs.role.to_string(),
        target_port: rs.target_port,
        speed: rs.speed,
        top_speed: rs.top_speed,
        realtime: rs.realtime,
        rewrite_cp56_to_now: rs.rewrite_cp56_to_now,
        cp56_zone: rs.cp56_zone.clone(),
        planned: rs.planned,
        sent: rs.sent,
        bytes: rs.bytes_progress,
        error: rs.error.clone(),
        report_json: rs.report.as_ref().and_then(|r| serde_json::to_string(r).ok()),
        benchmark_json: rs
            .benchmark
            .as_ref()
            .and_then(|b| serde_json::to_string(b).ok()),
        per_source_json: serde_json::to_string(&rs.per_source_progress).ok(),
        throughput_json: serde_json::to_string(&rs.throughput_history).ok(),
    }
}

fn stored_to_runstate(s: &StoredRun) -> Option<RunState> {
    let target_ip: Ipv4Addr = s.target_ip.parse().ok()?;
    let mode: &'static str = match s.mode.as_str() {
        "benchmark" => "benchmark",
        _ => "raw",
    };
    let role: &'static str = match s.role.as_str() {
        "master" => "master",
        "slave" => "slave",
        _ => "",
    };
    let report: Option<RunReportJson> = s
        .report_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());
    let benchmark: Option<BenchmarkReportJson> = s
        .benchmark_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());
    let per_source_progress: Vec<SourceProgressJson> = s
        .per_source_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    let throughput_history: Vec<u64> = s
        .throughput_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    Some(RunState {
        id: s.id,
        status: RunStatus::from_str(&s.status),
        started_at: s.started_at,
        pcap: PathBuf::from(&s.pcap),
        target_ip,
        target_mac: s.target_mac.clone(),
        speed: s.speed,
        top_speed: s.top_speed,
        realtime: s.realtime,
        rewrite_cp56_to_now: s.rewrite_cp56_to_now,
        cp56_zone: s.cp56_zone.clone(),
        error: s.error.clone(),
        report,
        benchmark,
        mode,
        role,
        target_port: s.target_port,
        planned: s.planned,
        sent: s.sent,
        bytes_progress: s.bytes,
        per_source_progress,
        throughput_history,
        ctx: RunContext::new(),
    })
}

fn state_to_str(s: u8) -> &'static str {
    use protoplay::session_state as ss;
    match s {
        ss::PENDING => "pending",
        ss::LISTENING => "listening",
        ss::CONNECTED => "connected",
        ss::ACTIVE => "active",
        ss::COMPLETED => "completed",
        ss::FAILED => "failed",
        ss::CANCELLED => "cancelled",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Stopped,
    Failed,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Completed => "completed",
            RunStatus::Stopped => "stopped",
            RunStatus::Failed => "failed",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "running" => RunStatus::Running,
            "completed" => RunStatus::Completed,
            "stopped" => RunStatus::Stopped,
            _ => RunStatus::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReportJson {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
    pub per_source: Vec<SourceReportJson>,
    pub capture_path: Option<String>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceReportJson {
    pub src_ip: Option<String>,
    pub src_mac: String,
    pub tap: String,
    pub kind: String,
    pub sent: u64,
    pub bytes: u64,
    pub send_errors: u64,
    pub elapsed_ms: f64,
    pub mean_jitter_us: f64,
    pub p99_jitter_us: f64,
}

impl From<&SourceReport> for SourceReportJson {
    fn from(s: &SourceReport) -> Self {
        let m = s.src_mac;
        Self {
            src_ip: s.src_ip.map(|i| i.to_string()),
            src_mac: format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            tap: s.tap.clone(),
            kind: match s.kind {
                SourceKind::Ipv4 => "ipv4".to_string(),
                SourceKind::NonIp => "non_ip".to_string(),
            },
            sent: s.stats.sent,
            bytes: s.stats.bytes,
            send_errors: s.stats.send_errors,
            elapsed_ms: s.stats.elapsed_ns as f64 / 1e6,
            mean_jitter_us: s.stats.mean_abs_jitter_ns as f64 / 1e3,
            p99_jitter_us: s.stats.p99_abs_jitter_ns as f64 / 1e3,
        }
    }
}

impl From<&RunReport> for RunReportJson {
    fn from(r: &RunReport) -> Self {
        Self {
            total_packets: r.total_packets,
            total_bytes: r.total_bytes,
            total_errors: r.total_errors,
            per_source: r.per_source.iter().map(Into::into).collect(),
            capture_path: r.capture_path.as_ref().map(|p| p.display().to_string()),
            captured_packets: r.captured_packets,
            captured_bytes: r.captured_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReportJson {
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub aggregate_latency_min_us: u64,
    pub aggregate_latency_p50_us: u64,
    pub aggregate_latency_p90_us: u64,
    pub aggregate_latency_p99_us: u64,
    pub aggregate_latency_max_us: u64,
    pub aggregate_throughput_msgs_per_sec: f64,
    /// Up to 5000 latency samples in microseconds, flattened across
    /// every session. The UI uses this to draw the aggregate
    /// histogram; per-session histograms come from each session's
    /// `proto_report.latency_samples_us` field.
    pub aggregate_latency_samples_us: Vec<u64>,
    pub per_session: Vec<SessionReportJson>,
    pub capture_path: Option<String>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReportJson {
    pub src_ip: String,
    pub src_mac: String,
    pub tap: String,
    pub connected: bool,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub elapsed_ms: u64,
    pub latency_min_us: u64,
    pub latency_p50_us: u64,
    pub latency_p90_us: u64,
    pub latency_p99_us: u64,
    pub latency_max_us: u64,
    pub throughput_msgs_per_sec: f64,
    pub window_stalls: u64,
    pub unacked_at_end: u64,
    pub error: Option<String>,
    pub latency_samples_us: Vec<u64>,
}

impl From<&SessionReport> for SessionReportJson {
    fn from(s: &SessionReport) -> Self {
        let m = s.src_mac;
        let pr = &s.proto_report;
        Self {
            src_ip: s.src_ip.to_string(),
            src_mac: format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            tap: s.tap.clone(),
            connected: pr.connected,
            messages_sent: pr.messages_sent,
            messages_received: pr.messages_received,
            bytes_written: pr.bytes_written,
            bytes_read: pr.bytes_read,
            elapsed_ms: pr.elapsed_ms,
            latency_min_us: pr.latency_min_us,
            latency_p50_us: pr.latency_p50_us,
            latency_p90_us: pr.latency_p90_us,
            latency_p99_us: pr.latency_p99_us,
            latency_max_us: pr.latency_max_us,
            throughput_msgs_per_sec: pr.throughput_msgs_per_sec,
            window_stalls: pr.window_stalls,
            unacked_at_end: pr.unacked_at_end,
            error: pr.error.clone(),
            latency_samples_us: pr.latency_samples_us.clone(),
        }
    }
}

impl From<&BenchmarkReport> for BenchmarkReportJson {
    fn from(r: &BenchmarkReport) -> Self {
        // Cap aggregate samples so the JSON response doesn't balloon.
        let sample_cap = 5000usize;
        let samples = if r.aggregate_latency_samples_us.len() > sample_cap {
            r.aggregate_latency_samples_us[..sample_cap].to_vec()
        } else {
            r.aggregate_latency_samples_us.clone()
        };
        Self {
            total_messages_sent: r.total_messages_sent,
            total_messages_received: r.total_messages_received,
            aggregate_latency_min_us: r.aggregate_latency_min_us,
            aggregate_latency_p50_us: r.aggregate_latency_p50_us,
            aggregate_latency_p90_us: r.aggregate_latency_p90_us,
            aggregate_latency_p99_us: r.aggregate_latency_p99_us,
            aggregate_latency_max_us: r.aggregate_latency_max_us,
            aggregate_throughput_msgs_per_sec: r.aggregate_throughput_msgs_per_sec,
            aggregate_latency_samples_us: samples,
            per_session: r.per_session.iter().map(Into::into).collect(),
            capture_path: r.capture_path.as_ref().map(|p| p.display().to_string()),
            captured_packets: r.captured_packets,
            captured_bytes: r.captured_bytes,
        }
    }
}

fn get_proto(name: &str) -> Option<Arc<dyn protoplay::ProtoReplayer>> {
    match name {
        "iec104" => Some(Arc::new(proto_iec104::Iec104Replayer::new())),
        "modbus_tcp" => Some(Arc::new(proto_modbus_tcp::ModbusTcpReplayer)),
        "dnp3_tcp" => Some(Arc::new(proto_dnp3_tcp::Dnp3TcpReplayer)),
        "iec61850_mms" => Some(Arc::new(proto_iec61850_mms::Iec61850MmsReplayer)),
        "iec60870_6_iccp" => Some(Arc::new(proto_iec60870_6_iccp::IccpReplayer)),
        _ => None,
    }
}

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
        .route("/api/runs/:id/slaves/start_all", post(api_run_start_all_slaves))
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

/// Snapshot the live atomics in a run's context into its serializable
/// progress fields. Called on every read so the HTTP response reflects
/// the latest state.
fn refresh_progress(rs: &mut RunState) {
    // Terminal runs (restored from sqlite on startup or already finished
    // in this process) have authoritative snapshots already. Their ctx
    // is fresh/empty and would clobber the stored values — bail out.
    if !matches!(rs.status, RunStatus::Running) {
        return;
    }
    let sp = rs.ctx.per_source.lock().unwrap();
    // Sum live per-source counters. Workers increment these as they go,
    // while the global `ctx.sent` atomic is only fanned-in at worker
    // completion; the sum is the right source of truth for live progress.
    //
    // Also sum per-source `planned`. For raw replay this equals
    // `ctx.planned` by construction. For benchmark runs `ctx.planned`
    // holds the session count (e.g. 1) while per-source `planned`
    // holds the per-session I-frame count populated by the protocol
    // replayer — summing gives the real "expected messages" total.
    let live_sent: u64 = sp.iter().map(|p| p.snapshot_sent()).sum();
    let live_bytes: u64 = sp.iter().map(|p| p.snapshot_bytes()).sum();
    let live_planned: u64 = sp.iter().map(|p| p.snapshot_planned()).sum();
    let global_planned = rs.ctx.planned.load(Ordering::Relaxed);
    rs.planned = if live_planned > 0 {
        live_planned
    } else {
        global_planned
    };
    rs.sent = live_sent.max(rs.ctx.sent.load(Ordering::Relaxed));
    rs.bytes_progress = live_bytes.max(rs.ctx.bytes.load(Ordering::Relaxed));
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
                listen_ip: p.snapshot_listen_ip().to_string(),
                state: state_to_str(p.snapshot_state()).to_string(),
                ready: p.is_ready(),
                cancelled: p.is_cancelled(),
            }
        })
        .collect();
}

const CAPTURE_DIR: &str = "/tmp/outstation-captures";

async fn serve_index() -> Html<&'static str> {
    Html(EMBEDDED_HTML)
}

async fn serve_echarts() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    (headers, EMBEDDED_ECHARTS).into_response()
}

#[derive(Serialize)]
struct StatusJson {
    ok: bool,
    version: &'static str,
}

async fn api_status() -> Json<StatusJson> {
    Json(StatusJson {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct ProtoJson {
    name: &'static str,
    status: &'static str,
    ports: Vec<u16>,
}

async fn api_protocols() -> Json<Vec<ProtoJson>> {
    let registry: Vec<Box<dyn protoplay::ProtoReplayer>> = vec![
        Box::new(proto_iec104::Iec104Replayer::new()),
        Box::new(proto_modbus_tcp::ModbusTcpReplayer),
        Box::new(proto_dnp3_tcp::Dnp3TcpReplayer),
        Box::new(proto_iec61850_mms::Iec61850MmsReplayer),
        Box::new(proto_iec60870_6_iccp::IccpReplayer),
    ];
    let out = registry
        .iter()
        .map(|m| ProtoJson {
            name: m.name(),
            status: match m.readiness() {
                protoplay::Readiness::Ready => "ready",
                protoplay::Readiness::Stub => "stub",
            },
            ports: m.well_known_ports().to_vec(),
        })
        .collect();
    Json(out)
}

#[derive(Deserialize)]
struct InspectReq {
    path: PathBuf,
}

#[derive(Serialize)]
struct InspectResp {
    packets: usize,
    sources: Vec<InspectSource>,
    non_ip_sources: Vec<InspectNonIp>,
    tcp_flows: Vec<InspectFlow>,
    duration_ms: f64,
}

#[derive(Serialize)]
struct InspectSource {
    src_ip: String,
    src_mac: String,
    packet_count: u64,
    byte_count: u64,
    flow_count: usize,
    mac_collision: bool,
}

#[derive(Serialize)]
struct InspectNonIp {
    src_mac: String,
    packet_count: u64,
    byte_count: u64,
    ethertypes: Vec<String>,
}

#[derive(Serialize)]
struct InspectFlow {
    client: String,
    server: String,
    packets: usize,
    state: String,
}

async fn api_inspect(Json(req): Json<InspectReq>) -> Result<Json<InspectResp>, AppError> {
    let p = load(&req.path).map_err(|e| AppError::BadRequest(format!("load pcap: {e}")))?;
    let sources: Vec<InspectSource> = p
        .sources
        .iter()
        .map(|(ip, s)| {
            let m = s.src_mac;
            InspectSource {
                src_ip: ip.to_string(),
                src_mac: format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                ),
                packet_count: s.packet_count,
                byte_count: s.byte_count,
                flow_count: s.flow_indices.len(),
                mac_collision: s.mac_collision,
            }
        })
        .collect();
    let non_ip_sources: Vec<InspectNonIp> = p
        .non_ip_sources
        .iter()
        .map(|(mac, info)| {
            let m = *mac;
            InspectNonIp {
                src_mac: format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                ),
                packet_count: info.packet_count,
                byte_count: info.byte_count,
                ethertypes: info
                    .ethertypes
                    .iter()
                    .map(|e| format!("0x{e:04x}"))
                    .collect(),
            }
        })
        .collect();
    let tcp_flows: Vec<InspectFlow> = p
        .flows
        .iter()
        .map(|f| {
            let client = f
                .client
                .map(|(ip, port)| format!("{ip}:{port}"))
                .unwrap_or_else(|| "?".into());
            let server = f
                .server
                .map(|(ip, port)| format!("{ip}:{port}"))
                .unwrap_or_else(|| "?".into());
            let mut state = String::new();
            if f.saw_syn {
                state.push_str("SYN ");
            }
            if f.saw_syn_ack {
                state.push_str("SYN-ACK ");
            }
            if f.saw_fin {
                state.push_str("FIN ");
            }
            if f.saw_rst {
                state.push_str("RST ");
            }
            InspectFlow {
                client,
                server,
                packets: f.packet_indices.len(),
                state: state.trim().into(),
            }
        })
        .collect();
    Ok(Json(InspectResp {
        packets: p.packets.len(),
        sources,
        non_ip_sources,
        tcp_flows,
        duration_ms: (p.last_ts_ns.saturating_sub(p.first_ts_ns)) as f64 / 1e6,
    }))
}

#[derive(Deserialize)]
struct RunReq {
    #[serde(default)]
    pcap: Option<PathBuf>,
    #[serde(default)]
    pcap_id: Option<String>,
    target_ip: Ipv4Addr,
    /// Required for raw replay; ignored in benchmark mode.
    #[serde(default)]
    target_mac: String,
    #[serde(default)]
    nic: Option<String>,
    #[serde(default = "default_bridge")]
    bridge: String,
    #[serde(default = "default_tap_prefix")]
    tap_prefix: String,
    #[serde(default = "default_speed")]
    speed: f64,
    #[serde(default)]
    top_speed: bool,
    #[serde(default)]
    realtime: bool,
    #[serde(default)]
    skip_non_ip: bool,
    #[serde(default)]
    only_src: Vec<Ipv4Addr>,
    #[serde(default = "default_warmup")]
    warmup_secs: u64,
    /// "raw" (default) or "benchmark".
    #[serde(default = "default_mode")]
    mode: String,
    /// Benchmark-only: destination port of the target protocol. 2404 for IEC 104.
    #[serde(default = "default_target_port")]
    target_port: u16,
    /// Benchmark-only: which ProtoReplayer module to use.
    #[serde(default = "default_proto_name")]
    proto_name: String,
    /// Benchmark-only: "all_at_once" | "staggered".
    #[serde(default = "default_concurrency")]
    concurrency: String,
    /// Benchmark-only: free-form JSON passed through to the protocol
    /// module. For IEC 104, this is the ASDU rewrite map
    /// (`{"common_address": {...}, "cot": {...}, "ioa": {...}}`).
    #[serde(default)]
    proto_config: Option<String>,
    /// Benchmark-only: "master" (default) = tool connects out to the
    /// target as a client; "slave" = tool listens and waits for the
    /// target master to connect in.
    #[serde(default = "default_role")]
    role: String,
    /// Benchmark-slave-only: first TCP listen port. Session i listens
    /// on `listen_port_base + i`.
    #[serde(default = "default_listen_port_base")]
    listen_port_base: u16,
    /// Benchmark-only: "fast" (default) = fire as fast as the
    /// protocol window allows; "original" = match the original
    /// pcap's inter-frame cadence, scaled by `speed`.
    #[serde(default = "default_pacing")]
    pacing: String,
    /// Number of times to repeat the captured script. `0` = unlimited
    /// (loop until cancel). Default `1`.
    #[serde(default = "default_iterations")]
    iterations: u64,
    /// SCADA-gateway mode (see doc/scada-lab.md): claim this IP as a
    /// /32 alias on `scada_gateway_iface` for the run, so a SCADA
    /// guest on an isolated vSwitch routes off-subnet traffic to us.
    #[serde(default)]
    scada_gateway_ip: Option<Ipv4Addr>,
    #[serde(default)]
    scada_gateway_iface: Option<String>,
    /// Optional upstream NIC for MASQUERADE. If set, IP forwarding is
    /// enabled and SCADA's non-capture egress is NAT'd out this NIC.
    #[serde(default)]
    upstream_nat_iface: Option<String>,
    /// IEC 104 only: rewrite every CP56Time2a timestamp inside
    /// outgoing ASDUs to the actual wall-clock moment the frame is
    /// emitted. SCADA sees fresh event timestamps; intra-pcap
    /// spacing preserved; IV preserved from source.
    #[serde(default)]
    rewrite_cp56_to_now: bool,
    /// Timezone convention for the rewrite: `"local"` (default) or
    /// `"utc"`. Ignored unless `rewrite_cp56_to_now` is true.
    #[serde(default = "default_cp56_zone")]
    cp56_zone: String,
    /// Master-mode only: override the per-session bind IP. Default
    /// (None) keeps the captured client IPs as the source addresses
    /// of the replayed master sessions. Set to a local IP (or one we
    /// can alias onto the bridge) to make all master sessions
    /// originate from a specific local address regardless of what
    /// the pcap recorded. Useful when the captured master IP
    /// (e.g. 192.168.10.10) doesn't exist on the replay host.
    #[serde(default)]
    master_bind_ip: Option<Ipv4Addr>,
    /// Override TCP_NODELAY on the session sockets. Default (None)
    /// uses the role-based default: slave = true (matches real RTU
    /// event-driven behaviour), master = false. Set explicitly to
    /// override either way for debugging or A/B comparisons.
    #[serde(default)]
    tcp_nodelay: Option<bool>,
}

fn default_cp56_zone() -> String {
    "local".into()
}

fn default_iterations() -> u64 {
    1
}

fn default_pacing() -> String {
    "fast".into()
}

fn default_role() -> String {
    "master".into()
}
fn default_listen_port_base() -> u16 {
    2404
}

fn default_mode() -> String {
    "raw".into()
}
fn default_target_port() -> u16 {
    2404
}
fn default_proto_name() -> String {
    "iec104".into()
}
fn default_concurrency() -> String {
    "all_at_once".into()
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

#[derive(Serialize)]
struct RunResp {
    id: u64,
}

async fn api_run(
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
        rewrite_cp56_to_now: req.rewrite_cp56_to_now,
        cp56_zone: req.cp56_zone.clone(),
        error: None,
        report: None,
        benchmark: None,
        mode: mode_str,
        role: role_str,
        target_port: target_port_for_state,
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
            rewrite_cp56_to_now: req.rewrite_cp56_to_now,
            cp56_zone: req.cp56_zone.clone(),
            master_bind_ip: req.master_bind_ip,
            tcp_nodelay: req.tcp_nodelay,
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
            rewrite_cp56_to_now: req.rewrite_cp56_to_now,
            cp56_zone: req.cp56_zone.clone(),
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

async fn api_runs(State(state): State<AppState>) -> Json<Vec<RunState>> {
    let map = state.runs.lock().unwrap();
    let mut v: Vec<RunState> = map.values().cloned().collect();
    drop(map);
    for r in &mut v {
        refresh_progress(r);
    }
    v.sort_by_key(|r| std::cmp::Reverse(r.id));
    Json(v)
}

async fn api_run_by_id(
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

/// WebSocket endpoint that streams a compact run snapshot every 200 ms
/// while the connection is open. Used by the per-run live network
/// diagram + progress card so the UI doesn't need to poll. Closes
/// itself once the run reaches a terminal state.
async fn api_run_live_ws(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| run_live_loop(state, id, socket))
}

/// Sliding-window rate estimator. Pushes (timestamp, counter) samples
/// and reports pps = (newest_count - oldest_count) / elapsed_seconds
/// across the window. Used so slow-paced sessions (e.g., 1.3 msg/s in
/// original-pcap-timing mode) don't show pps=0 just because no
/// messages happened in the last 200 ms WS tick.
#[derive(Default)]
struct SessionRateWindow {
    samples: std::collections::VecDeque<(std::time::Instant, u64, u64)>,
}

impl SessionRateWindow {
    const WINDOW_SECS: f64 = 1.5;
    const CAP: usize = 12;

    fn push(&mut self, now: std::time::Instant, sent: u64, recv: u64) {
        self.samples.push_back((now, sent, recv));
        while let Some(front) = self.samples.front() {
            if now.duration_since(front.0).as_secs_f64() > Self::WINDOW_SECS
                || self.samples.len() > Self::CAP
            {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn pps(&self) -> (u64, u64) {
        if self.samples.len() < 2 {
            return (0, 0);
        }
        let (t0, s0, r0) = *self.samples.front().unwrap();
        let (t1, s1, r1) = *self.samples.back().unwrap();
        let dt = t1.duration_since(t0).as_secs_f64();
        if dt < 0.05 {
            return (0, 0);
        }
        // ceil so any non-zero count delta in the window reports at
        // least 1 pps (otherwise a 1.3 msg/s session would round to
        // 0 and the diagram animation would die).
        let pps_s = ((s1.saturating_sub(s0) as f64) / dt).ceil() as u64;
        let pps_r = ((r1.saturating_sub(r0) as f64) / dt).ceil() as u64;
        (pps_s, pps_r)
    }
}

async fn run_live_loop(state: AppState, id: u64, mut socket: WebSocket) {
    let interval = std::time::Duration::from_millis(200);
    // Sliding-window rate estimators for the global aggregate and for
    // each per-source session. Indexed by per_source position.
    let mut global_win = SessionRateWindow::default();
    let mut session_wins: Vec<SessionRateWindow> = Vec::new();
    loop {
        let frame = {
            let map = state.runs.lock().unwrap();
            let Some(rs) = map.get(&id).cloned() else {
                break;
            };
            drop(map);
            let mut rs = rs;
            refresh_progress(&mut rs);

            let now = std::time::Instant::now();

            // Resize the per-session window vec to match the current
            // session count (may grow as workers spawn).
            if session_wins.len() != rs.per_source_progress.len() {
                session_wins.resize_with(
                    rs.per_source_progress.len(),
                    SessionRateWindow::default,
                );
            }

            let total_recv: u64 = rs
                .per_source_progress
                .iter()
                .map(|p| p.received)
                .sum();
            global_win.push(now, rs.sent, total_recv);
            let (pps_sent, pps_recv) = global_win.pps();

            let per_session: Vec<_> = rs
                .per_source_progress
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    session_wins[i].push(now, p.sent, p.received);
                    let (pps_s, pps_r) = session_wins[i].pps();
                    LivePerSession {
                        src_ip: p.src_ip.clone(),
                        state: p.state.clone(),
                        planned: p.planned,
                        sent: p.sent,
                        received: p.received,
                        unacked: p.unacked,
                        listen_port: p.listen_port,
                        pps_sent: pps_s,
                        pps_recv: pps_r,
                    }
                })
                .collect();

            let terminal = !matches!(rs.status, RunStatus::Running);
            (
                LiveFrame {
                    run_id: rs.id,
                    status: format!("{:?}", rs.status).to_lowercase(),
                    mode: rs.mode,
                    role: rs.role,
                    planned: rs.planned,
                    sent: rs.sent,
                    bytes: rs.bytes_progress,
                    pps_sent,
                    pps_recv,
                    per_session,
                },
                terminal,
            )
        };
        let (msg, terminal) = frame;
        let payload = match serde_json::to_string(&msg) {
            Ok(s) => s,
            Err(_) => break,
        };
        if socket.send(Message::Text(payload)).await.is_err() {
            break;
        }
        if terminal {
            // Send one final tick so the client sees the terminal
            // state before we close.
            break;
        }
        tokio::time::sleep(interval).await;
    }
}

#[derive(Serialize)]
struct LiveFrame {
    run_id: u64,
    status: String,
    mode: &'static str,
    role: &'static str,
    planned: u64,
    sent: u64,
    bytes: u64,
    pps_sent: u64,
    pps_recv: u64,
    per_session: Vec<LivePerSession>,
}

#[derive(Serialize)]
struct LivePerSession {
    src_ip: Option<String>,
    state: String,
    planned: u64,
    sent: u64,
    received: u64,
    unacked: u64,
    listen_port: u16,
    /// Per-session uplink rate (messages/s sent by this session to
    /// the live target since the last WS tick). Drives the live
    /// network diagram's animation speed.
    pps_sent: u64,
    /// Per-session downlink rate (messages/s received from the live
    /// target since the last WS tick).
    pps_recv: u64,
}

async fn api_run_delete(
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

async fn api_run_stop(
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

async fn api_run_start_slave(
    State(state): State<AppState>,
    Path((id, idx)): Path<(u64, usize)>,
) -> Result<StatusCode, AppError> {
    let map = state.runs.lock().unwrap();
    let rs = map
        .get(&id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let sp = rs.ctx.per_source.lock().unwrap();
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
async fn api_run_start_all_slaves(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<serde_json::Value>, AppError> {
    use protoplay::session_state as ss;
    let map = state.runs.lock().unwrap();
    let rs = map
        .get(&id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let sp = rs.ctx.per_source.lock().unwrap();
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
    Ok(Json(serde_json::json!({ "started": started, "total": total })))
}

async fn api_run_stop_slave(
    State(state): State<AppState>,
    Path((id, idx)): Path<(u64, usize)>,
) -> Result<StatusCode, AppError> {
    let map = state.runs.lock().unwrap();
    let rs = map
        .get(&id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let sp = rs.ctx.per_source.lock().unwrap();
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
struct PatchSlaveReq {
    #[serde(default)]
    listen_ip: Option<String>,
}

async fn api_run_patch_slave(
    State(state): State<AppState>,
    Path((id, idx)): Path<(u64, usize)>,
    Json(req): Json<PatchSlaveReq>,
) -> Result<StatusCode, AppError> {
    let map = state.runs.lock().unwrap();
    let rs = map
        .get(&id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
    let sp = rs.ctx.per_source.lock().unwrap();
    let entry = sp
        .get(idx)
        .ok_or_else(|| AppError::NotFound(format!("slave idx {idx} not found in run {id}")))?;
    if entry.snapshot_state() != protoplay::session_state::PENDING {
        return Err(AppError::BadRequest(
            "cannot patch a slave that has already started".into(),
        ));
    }
    if let Some(ip_str) = req.listen_ip {
        let ip: Ipv4Addr = ip_str
            .parse()
            .map_err(|e| AppError::BadRequest(format!("bad listen_ip {ip_str:?}: {e}")))?;
        *entry.listen_ip.lock().unwrap() = ip;
        info!(id, idx, %ip, "slave listen_ip updated");
    }
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct VerifyIpReq {
    ip: String,
    #[serde(default)]
    iface: Option<String>,
}

#[derive(Serialize)]
struct VerifyIpResp {
    ip: String,
    iface: String,
    in_use: bool,
    /// True if the IP is already assigned to one of this host's
    /// interfaces. When false + in_use=false, the webui tells the
    /// user the IP will be auto-aliased onto the egress interface
    /// when the slave is started.
    locally_assigned: bool,
    mac: Option<String>,
    error: Option<String>,
}

/// Probe an IP to see if it's already taken. Two sources of truth:
///   1. `ip -4 -o addr show` — if the host already owns the IP on any
///      interface, we report "local host" immediately (arping would
///      otherwise come back as "no reply" because the host kernel
///      doesn't ARP-reply to its own addresses).
///   2. `arping -D` — duplicate-address detection probe on the
///      relevant interface. Responds? Someone else owns it.
async fn api_verify_ip(Json(req): Json<VerifyIpReq>) -> Result<Json<VerifyIpResp>, AppError> {
    // 0.0.0.0 is the "any" sentinel — always valid, skip probing.
    if req.ip.trim() == "0.0.0.0" {
        return Ok(Json(VerifyIpResp {
            ip: "0.0.0.0".into(),
            iface: "any".into(),
            in_use: false,
            locally_assigned: true,
            mac: None,
            error: None,
        }));
    }
    let ip: Ipv4Addr = req
        .ip
        .parse()
        .map_err(|e| AppError::BadRequest(format!("bad ip {:?}: {e}", req.ip)))?;
    let iface = match req.iface {
        Some(i) => i,
        None => default_route_iface()
            .map_err(|e| AppError::Internal(format!("detect default iface: {e}")))?,
    };

    // Check host's own addresses first.
    if let Some(local_iface) = find_local_ip_iface(&ip) {
        return Ok(Json(VerifyIpResp {
            ip: ip.to_string(),
            iface: local_iface,
            in_use: true,
            locally_assigned: true,
            mac: Some("local host".into()),
            error: None,
        }));
    }

    // arping -D -c 2 -w 2 -I <iface> <ip>
    let out = std::process::Command::new("arping")
        .args([
            "-D", "-c", "2", "-w", "2", "-I", &iface, &ip.to_string(),
        ])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return Ok(Json(VerifyIpResp {
                ip: ip.to_string(),
                iface,
                in_use: false,
                locally_assigned: false,
                mac: None,
                error: Some(format!("arping not available: {e}. apt install iputils-arping")),
            }));
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // arping -D with iputils semantics: exit 1 means "someone replied
    // (conflict)", exit 0 means "no reply". Also parse the stdout —
    // presence of "Unicast reply" or "reply from" is a strong signal.
    let in_use = !out.status.success()
        || stdout.contains("reply from")
        || stdout.contains("Unicast reply");
    let mac = extract_mac(&stdout).or_else(|| extract_mac(&stderr));
    Ok(Json(VerifyIpResp {
        ip: ip.to_string(),
        iface,
        in_use,
        locally_assigned: false,
        mac,
        error: None,
    }))
}

/// Look up `ip` in the host's address table. Returns the owning
/// interface name if found.
async fn api_analyze(
    State(state): State<AppState>,
    mut mp: Multipart,
) -> Result<Json<analysis::AnalysisReport>, AppError> {
    let mut captured_bytes: Option<Vec<u8>> = None;
    let mut mode: AnalysisMode = AnalysisMode::Generic;
    let mut run_id_opt: Option<u64> = None;
    let mut cp56_tolerance_ms: f64 = DEFAULT_CP56_TOLERANCE_MS;
    while let Some(mut field) = mp
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        match name.as_str() {
            "file" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read chunk: {e}")))?
                {
                    buf.extend_from_slice(&chunk);
                }
                captured_bytes = Some(buf);
            }
            "mode" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read mode: {e}")))?;
                mode = if s.trim().eq_ignore_ascii_case("correct") {
                    AnalysisMode::Correct
                } else {
                    AnalysisMode::Generic
                };
            }
            "run_id" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read run_id: {e}")))?;
                run_id_opt = s.trim().parse().ok();
            }
            "cp56_tolerance_ms" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read cp56 tol: {e}")))?;
                if let Ok(v) = s.trim().parse::<f64>() {
                    if v >= 0.0 {
                        cp56_tolerance_ms = v;
                    }
                }
            }
            _ => {}
        }
    }

    let bytes = captured_bytes
        .ok_or_else(|| AppError::BadRequest("missing 'file' part in multipart body".into()))?;
    if bytes.is_empty() {
        return Err(AppError::BadRequest("captured pcap is empty".into()));
    }

    // Pick the target run: explicit id, else most recent completed/stopped/failed run.
    let picked = {
        let map = state.runs.lock().unwrap();
        if let Some(id) = run_id_opt {
            map.get(&id).cloned()
        } else {
            let mut vs: Vec<RunState> = map
                .values()
                .filter(|r| !matches!(r.status, RunStatus::Running))
                .cloned()
                .collect();
            vs.sort_by_key(|r| std::cmp::Reverse(r.id));
            vs.into_iter().next()
        }
    };
    let rs = picked.ok_or_else(|| AppError::NotFound("no completed run to analyze against".into()))?;

    if rs.mode != "benchmark" {
        return Err(AppError::BadRequest(
            "analysis currently targets benchmark runs only".into(),
        ));
    }

    let role_hint = match rs.role {
        "slave" => RoleHint::Slave,
        _ => RoleHint::Master,
    };
    let target_port = rs.target_port;

    // Persist the captured pcap to a temp file so pcapload can mmap
    // it the way it wants. Dropped at end of scope.
    let tmp_dir = std::env::temp_dir().join("outstation-analysis");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| AppError::Internal(format!("create tmp: {e}")))?;
    let tmp_path = tmp_dir.join(format!("capt_{}.pcap", rs.id));
    std::fs::write(&tmp_path, &bytes)
        .map_err(|e| AppError::Internal(format!("write tmp: {e}")))?;

    let rewrite_cp56_was_on = rs.rewrite_cp56_to_now;
    let cp56_zone = Cp56Zone::parse(&rs.cp56_zone).unwrap_or(Cp56Zone::Local);
    let report = tokio::task::spawn_blocking({
        let original_pcap = rs.pcap.clone();
        let tmp_path = tmp_path.clone();
        let run_id = rs.id;
        move || {
            analyze(
                &original_pcap,
                &tmp_path,
                run_id,
                target_port,
                role_hint,
                mode,
                rewrite_cp56_was_on,
                cp56_zone,
                cp56_tolerance_ms,
            )
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("analyze task: {e}")))?
    .map_err(|e| AppError::BadRequest(format!("analyze: {e}")))?;

    // Leave the file behind for now; /tmp gets swept by the OS.
    Ok(Json(report))
}

#[derive(Serialize)]
struct NicJson {
    name: String,
    mac: Option<String>,
    ipv4: Vec<String>,
    up: bool,
    loopback: bool,
    bridge: bool,
}

async fn api_nics() -> Result<Json<Vec<NicJson>>, AppError> {
    let nics =
        netctl::list_nics().map_err(|e| AppError::Internal(format!("list nics: {e}")))?;
    let out = nics
        .into_iter()
        .map(|n| NicJson {
            name: n.name,
            mac: n.mac.map(|m| netctl::format_mac(m)),
            ipv4: n.ipv4.into_iter().map(|ip| ip.to_string()).collect(),
            up: n.up,
            loopback: n.loopback,
            bridge: n.bridge,
        })
        .collect();
    Ok(Json(out))
}

#[derive(Deserialize)]
struct ArpReq {
    ip: String,
    #[serde(default)]
    iface: Option<String>,
}

#[derive(Serialize)]
struct ArpResp {
    ip: String,
    iface: String,
    mac: Option<String>,
    error: Option<String>,
}

/// Send an ARP request via `arping` and return the responding MAC.
/// Used by the UI's "ARP" button next to the target_mac field so the
/// user doesn't have to type it.
async fn api_arp(Json(req): Json<ArpReq>) -> Result<Json<ArpResp>, AppError> {
    let ip: Ipv4Addr = req
        .ip
        .parse()
        .map_err(|e| AppError::BadRequest(format!("bad ip {:?}: {e}", req.ip)))?;
    let iface = match req.iface {
        Some(i) if !i.is_empty() => i,
        _ => default_route_iface()
            .map_err(|e| AppError::Internal(format!("detect default iface: {e}")))?,
    };

    // If the IP is one of our own local addresses, return the local MAC immediately.
    if let Some(local_iface) = find_local_ip_iface(&ip) {
        let mac = netctl::list_nics()
            .ok()
            .and_then(|nics| {
                nics.into_iter()
                    .find(|n| n.name == local_iface)
                    .and_then(|n| n.mac.map(netctl::format_mac))
            });
        return Ok(Json(ArpResp {
            ip: ip.to_string(),
            iface: local_iface,
            mac,
            error: None,
        }));
    }

    let out = std::process::Command::new("arping")
        .args(["-c", "2", "-w", "2", "-I", &iface, &ip.to_string()])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return Ok(Json(ArpResp {
                ip: ip.to_string(),
                iface,
                mac: None,
                error: Some(format!("arping not available: {e}. apt install iputils-arping")),
            }));
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mac = extract_mac(&stdout).or_else(|| extract_mac(&stderr));
    if mac.is_none() {
        let msg = format!(
            "no ARP reply within 2 s (is the host live and on the same L2 segment as {iface}?)"
        );
        return Ok(Json(ArpResp {
            ip: ip.to_string(),
            iface,
            mac: None,
            error: Some(msg),
        }));
    }
    Ok(Json(ArpResp {
        ip: ip.to_string(),
        iface,
        mac,
        error: None,
    }))
}

fn find_local_ip_iface(ip: &Ipv4Addr) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let target = ip.to_string();
    for line in s.lines() {
        // format: "N: <iface> inet X.X.X.X/NN ..."
        let mut it = line.split_ascii_whitespace();
        let _idx = it.next()?;
        let iface = it.next()?;
        let _inet = it.next()?;
        let Some(addr_cidr) = it.next() else {
            continue;
        };
        let addr = addr_cidr.split_once('/').map(|(a, _)| a).unwrap_or(addr_cidr);
        if addr == target {
            return Some(iface.trim_end_matches(':').to_string());
        }
    }
    None
}

fn extract_mac(s: &str) -> Option<String> {
    // find any AA:BB:CC:DD:EE:FF pattern
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(16) {
        let slice = &s[i..i + 17];
        if slice
            .chars()
            .enumerate()
            .all(|(j, c)| match j % 3 {
                0 | 1 => c.is_ascii_hexdigit(),
                2 => c == ':',
                _ => false,
            })
        {
            return Some(slice.to_lowercase());
        }
    }
    None
}

fn default_route_iface() -> std::io::Result<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "route", "get", "1.1.1.1"])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("ip route get failed"));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // format: "1.1.1.1 via X.X.X.X dev <iface> src ..."
    let mut it = s.split_ascii_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            if let Some(dev) = it.next() {
                return Ok(dev.to_string());
            }
        }
    }
    Err(std::io::Error::other("no dev in `ip route get` output"))
}

#[derive(Serialize)]
struct GapHistResp {
    /// Log-spaced bucket boundaries in nanoseconds. 21 entries define 20 buckets.
    buckets_ns: Vec<u64>,
    /// Original pcap's inter-packet gaps, one count per bucket.
    original: Vec<u64>,
    /// Captured replay's inter-packet gaps, one count per bucket.
    captured: Vec<u64>,
    /// Source pcap paths used.
    original_path: String,
    captured_path: String,
}

/// Compute a 20-bucket log histogram of inter-packet gaps (ns).
/// Buckets span 1 µs → 10 s.
fn bucket_gaps(packets: &[pcapload::Packet]) -> Vec<u64> {
    let mut buckets = vec![0u64; 20];
    if packets.len() < 2 {
        return buckets;
    }
    let min_log = (1_000f64).log10();        // 1 µs  = 10^3 ns
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

async fn api_run_gaps(
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

async fn api_run_download(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Response, AppError> {
    let path = {
        let map = state.runs.lock().unwrap();
        map.get(&id)
            .and_then(|r| r.report.as_ref().and_then(|rep| rep.capture_path.clone()))
            .ok_or_else(|| AppError::NotFound(format!("no capture for run {id}")))?
    };
    let bytes = std::fs::read(&path)
        .map_err(|e| AppError::Internal(format!("read {path:?}: {e}")))?;
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

#[derive(Debug)]
enum AppError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
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
        Ok(n) if n > 0 => warn!(count = n, "reclaimed {n} stale pcr_* interface(s) at startup"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "reclaim_stale failed"),
    }

    let state = AppState::new();

    // Any rows left in status=running are from a process that died
    // without updating them. Mark them failed so the UI doesn't think
    // they're still in flight, then reload everything.
    match state.db.mark_orphans_failed("interrupted by server restart") {
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
            state
                .next_id
                .store(max_id + 1, Ordering::SeqCst);
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

/// Where the IP-alias state file lives. Defaults to a sibling of the
/// library dir under /var/lib/outstation; honors OUTSTATION_LIBRARY_DIR
/// for parity with the library layout.
fn alias_state_path() -> std::path::PathBuf {
    let library_dir = std::env::var("OUTSTATION_LIBRARY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/outstation/library"));
    let parent = library_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/outstation"));
    parent.join("state-aliases.txt")
}

// ---------------------------------------------------------------------------
// Pcap library: upload, list, rename, delete.
//
// Files live in `<library_dir>/pcr_<nanos>.pcap` with a sibling
// `pcr_<nanos>.json` sidecar holding the display name + quick-inspect
// metadata. The id is the filename stem (no extension).

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibraryEntry {
    id: String,
    name: String,
    uploaded_at_ms: u64,
    size_bytes: u64,
    packets: u64,
    ip_sources: u64,
    non_ip_sources: u64,
    tcp_flows: u64,
    duration_ms: f64,
    /// Absolute UTC start / end of the pcap (unix epoch ms), so the
    /// UI can show "captured 2026-02-14 — 2026-02-14" alongside the
    /// duration. Makes it easy to spot when the pcap is old enough
    /// that SCADA will treat its CP56Time2a stamps as stale.
    #[serde(default)]
    pcap_start_unix_ms: Option<u64>,
    #[serde(default)]
    pcap_end_unix_ms: Option<u64>,
    /// Number of source IPs whose MAC was ambiguous in the pcap
    /// (multiple MACs observed for the same IP). Surfaced in the UI
    /// so the user knows the replay-side MAC is a "most-common" pick.
    #[serde(default)]
    mac_collisions: u64,
    /// Optional viability advisory computed at upload time.
    /// Older library entries written before this field existed
    /// deserialize with `viability: None` thanks to serde(default).
    #[serde(default)]
    viability: Option<Viability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Viability {
    /// Sum of TCP payload bytes from the client side of all
    /// server_port=2404 flows. Approximates the master-mode wire load.
    client_payload_bytes: u64,
    /// Sum of TCP payload bytes from the server side of all
    /// server_port=2404 flows. Approximates the slave-mode wire load.
    server_payload_bytes: u64,
    /// Distinct client IPs observed talking to port 2404. This is
    /// the number of sessions a master-mode benchmark would spawn.
    sessions_master_mode: u64,
    /// Distinct server IPs observed listening on port 2404. This is
    /// the number of listeners a slave-mode benchmark would spawn.
    sessions_slave_mode: u64,
    /// Rough peak working-set estimate in MB for replaying this
    /// pcap, accounting for the parsed packet store, per-session
    /// payloads (post move-out), reservoir sample buffers and a
    /// per-thread stack budget. Worst-case of master vs slave.
    estimated_peak_mb: u64,
    /// One of: "ok", "caution", "heavy", "not_recommended".
    verdict: String,
    /// Human-readable reason for the verdict.
    verdict_reason: String,
    /// Extra observations the UI can render as bullet notes.
    notes: Vec<String>,
}

fn library_entry_id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn library_pcap_path(dir: &StdPath, id: &str) -> Result<PathBuf, AppError> {
    if !library_entry_id_valid(id) {
        return Err(AppError::BadRequest(format!("invalid pcap id: {id}")));
    }
    let p = dir.join(format!("{id}.pcap"));
    if !p.exists() {
        return Err(AppError::NotFound(format!("pcap id not found: {id}")));
    }
    Ok(p)
}

fn library_sidecar_path(dir: &StdPath, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn load_library_entry(dir: &StdPath, id: &str) -> Option<LibraryEntry> {
    let bytes = std::fs::read(library_sidecar_path(dir, id)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn save_library_entry(dir: &StdPath, entry: &LibraryEntry) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(entry).unwrap();
    std::fs::write(library_sidecar_path(dir, &entry.id), bytes)
}

struct QuickInspect {
    packets: u64,
    ip_sources: u64,
    non_ip_sources: u64,
    tcp_flows: u64,
    duration_ms: f64,
    pcap_start_unix_ms: Option<u64>,
    pcap_end_unix_ms: Option<u64>,
    mac_collisions: u64,
    viability: Option<Viability>,
}

fn quick_inspect(path: &StdPath) -> QuickInspect {
    match load(path) {
        Ok(p) => {
            let viability = compute_viability(&p, path);
            let mac_collisions = p.sources.values().filter(|s| s.mac_collision).count() as u64;
            QuickInspect {
                packets: p.packets.len() as u64,
                ip_sources: p.sources.len() as u64,
                non_ip_sources: p.non_ip_sources.len() as u64,
                tcp_flows: p.flows.len() as u64,
                duration_ms: (p.last_ts_ns.saturating_sub(p.first_ts_ns)) as f64 / 1e6,
                pcap_start_unix_ms: (p.first_ts_ns > 0).then(|| p.first_ts_ns / 1_000_000),
                pcap_end_unix_ms: (p.last_ts_ns > 0).then(|| p.last_ts_ns / 1_000_000),
                mac_collisions,
                viability: Some(viability),
            }
        }
        Err(_) => QuickInspect {
            packets: 0,
            ip_sources: 0,
            non_ip_sources: 0,
            tcp_flows: 0,
            duration_ms: 0.0,
            pcap_start_unix_ms: None,
            pcap_end_unix_ms: None,
            mac_collisions: 0,
            viability: None,
        },
    }
}

/// Walk the loaded pcap and compute a feasibility advisory aimed at
/// the IEC 104 benchmark workflow. Counts unique client/server IPs on
/// port 2404, sums TCP payload bytes per direction, and produces a
/// bucketed verdict. Cheap enough to run on every upload.
fn compute_viability(p: &pcapload::LoadedPcap, path: &StdPath) -> Viability {
    use std::collections::HashSet;
    const TARGET_PORT: u16 = 2404;
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let mut client_ips: HashSet<Ipv4Addr> = HashSet::new();
    let mut server_ips: HashSet<Ipv4Addr> = HashSet::new();
    let mut client_payload_bytes: u64 = 0;
    let mut server_payload_bytes: u64 = 0;
    let mut midflow_flows: u64 = 0;
    let mut clean_handshake_flows: u64 = 0;

    for (idx, flow) in p.flows.iter().enumerate() {
        let Some((server_ip, server_port)) = flow.server else {
            continue;
        };
        if server_port != TARGET_PORT {
            continue;
        }
        let Some((client_ip, _)) = flow.client else {
            continue;
        };
        client_ips.insert(client_ip);
        server_ips.insert(server_ip);
        if flow.saw_syn {
            clean_handshake_flows += 1;
        } else {
            midflow_flows += 1;
        }

        if let Ok(rf) = p.reassemble_client_payload(idx) {
            client_payload_bytes += rf.payload.len() as u64;
        }
        if let Ok(rf) = p.reassemble_server_payload(idx) {
            server_payload_bytes += rf.payload.len() as u64;
        }
    }

    let sessions_master_mode = client_ips.len() as u64;
    let sessions_slave_mode = server_ips.len() as u64;

    // Memory model. The "parsed packet store" is the dominant cost
    // (LoadedPcap holds Vec<Packet> where each Packet owns its bytes).
    // It is roughly the file size. Per-session payloads now move
    // straight into worker threads (no clones), so they're owned
    // exactly once. Latency reservoir is bounded at 80 KB/session.
    // Per-thread stack budget: ~2 MB on Linux default.
    let mb = |b: u64| (b + 1024 * 1024 - 1) / (1024 * 1024);
    let parsed_store_mb = mb(file_size);
    let max_session_count = sessions_master_mode.max(sessions_slave_mode);
    let session_payload_mb = mb(client_payload_bytes.max(server_payload_bytes));
    let reservoir_mb = mb(max_session_count * 80 * 1024);
    let stack_mb = max_session_count * 2;
    let estimated_peak_mb = parsed_store_mb + session_payload_mb + reservoir_mb + stack_mb + 32; // 32 MB headroom

    // Bucketing: pick the heavier of file-size or session-count.
    let (verdict, verdict_reason): (&str, String) = if file_size > 8 * 1024 * 1024 * 1024
        || max_session_count > 1500
    {
        (
            "not_recommended",
            format!(
                "{} sessions and a {} MB pcap exceed comfortable single-host limits",
                max_session_count,
                file_size / (1024 * 1024)
            ),
        )
    } else if file_size > 2 * 1024 * 1024 * 1024 || max_session_count > 500 {
        (
            "heavy",
            format!(
                "{} sessions / {} MB pcap — needs a roomy host (≥ {} MB free RAM)",
                max_session_count,
                file_size / (1024 * 1024),
                estimated_peak_mb
            ),
        )
    } else if file_size > 500 * 1024 * 1024 || max_session_count > 100 {
        (
            "caution",
            format!(
                "{} sessions / {} MB pcap — feasible but expect ~{} MB peak RAM",
                max_session_count,
                file_size / (1024 * 1024),
                estimated_peak_mb
            ),
        )
    } else if max_session_count == 0 {
        (
            "ok",
            format!(
                "no IEC 104 flows on port 2404 — fine for raw replay; benchmark mode has nothing to drive"
            ),
        )
    } else {
        (
            "ok",
            format!(
                "{} session(s) and {} MB pcap — easy to replay on this host",
                max_session_count,
                file_size / (1024 * 1024)
            ),
        )
    };

    let mut notes = Vec::new();
    if max_session_count == 0 {
        notes.push(
            "no TCP flow with server_port=2404 found — benchmark mode would have nothing to do"
                .into(),
        );
    } else {
        notes.push(format!(
            "{} unique client IPs talk to port 2404 (master-mode session count)",
            sessions_master_mode
        ));
        notes.push(format!(
            "{} unique server IPs listen on port 2404 (slave-mode session count)",
            sessions_slave_mode
        ));
        notes.push(format!(
            "{} MB of client TCP payload, {} MB of server TCP payload across all relevant flows",
            client_payload_bytes / (1024 * 1024),
            server_payload_bytes / (1024 * 1024),
        ));
        if midflow_flows > 0 {
            notes.push(format!(
                "{} of {} flows are mid-flow (no SYN observed) — the replayer will synthesize a fresh TCP+STARTDT prelude and resync to the first clean APCI boundary; {} flows had a clean handshake in the capture",
                midflow_flows,
                midflow_flows + clean_handshake_flows,
                clean_handshake_flows,
            ));
        }
    }
    if file_size > 1024 * 1024 * 1024 {
        notes.push(
            "pcap is larger than 1 GB; pcapload reads it fully into RAM (no mmap path yet)".into(),
        );
    }
    if max_session_count > 256 {
        notes.push(
            "session count exceeds 256 — ensure `ulimit -n` is large enough for one socket per session".into(),
        );
    }

    Viability {
        client_payload_bytes,
        server_payload_bytes,
        sessions_master_mode,
        sessions_slave_mode,
        estimated_peak_mb,
        verdict: verdict.into(),
        verdict_reason,
        notes,
    }
}

async fn api_library_list(State(state): State<AppState>) -> Json<Vec<LibraryEntry>> {
    let dir: &StdPath = state.library_dir.as_ref();
    let mut out: Vec<LibraryEntry> = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Json(out);
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("pcap") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(e) = load_library_entry(dir, stem) {
            out.push(e);
        }
    }
    out.sort_by(|a, b| b.uploaded_at_ms.cmp(&a.uploaded_at_ms));
    Json(out)
}

async fn api_library_upload(
    State(state): State<AppState>,
    mut mp: Multipart,
) -> Result<Json<LibraryEntry>, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let mut field = mp
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
        .ok_or_else(|| AppError::BadRequest("empty upload".into()))?;

    let original_name = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "upload.pcap".to_string());

    // Stream the field into a temp file within the library dir so it's on
    // the same filesystem for atomic rename.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let id = format!("pcr_{nanos}");
    let tmp_path = dir.join(format!(".{id}.part"));
    let final_path = dir.join(format!("{id}.pcap"));

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(|e| AppError::Internal(format!("open tmp: {e}")))?;
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| AppError::BadRequest(format!("read chunk: {e}")))?
        {
            f.write_all(&chunk)
                .map_err(|e| AppError::Internal(format!("write: {e}")))?;
        }
        f.sync_all().ok();
    }
    std::fs::rename(&tmp_path, &final_path)
        .map_err(|e| AppError::Internal(format!("rename: {e}")))?;

    // Fast validation: check the magic bytes only. Multi-GB pcaps
    // would otherwise block the HTTP handler for tens of seconds
    // while we walked every packet. Full parse runs in a background
    // thread below.
    if let Err(e) = pcapload::validate(&final_path) {
        let _ = std::fs::remove_file(&final_path);
        return Err(AppError::BadRequest(format!("not a pcap: {e}")));
    }

    let size_bytes = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
    let uploaded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Initial sidecar: viability=None means "still analyzing". The
    // background thread below will rewrite the sidecar with full
    // metadata once the parse completes. The library list endpoint
    // surfaces this transient state to the UI.
    let pending = LibraryEntry {
        id: id.clone(),
        name: original_name.clone(),
        uploaded_at_ms,
        size_bytes,
        packets: 0,
        ip_sources: 0,
        non_ip_sources: 0,
        tcp_flows: 0,
        duration_ms: 0.0,
        pcap_start_unix_ms: None,
        pcap_end_unix_ms: None,
        mac_collisions: 0,
        viability: None,
    };
    save_library_entry(dir, &pending)
        .map_err(|e| AppError::Internal(format!("sidecar: {e}")))?;
    info!(id = %pending.id, name = %pending.name, size_bytes, "pcap uploaded, analysis spawning");

    // Spawn the analyzer. Cheap pcaps finish before the user
    // notices; multi-GB pcaps take seconds-to-minutes and the UI's
    // library poll picks up the populated sidecar when it's done.
    let dir_owned = dir.to_path_buf();
    let final_path_owned = final_path.clone();
    let id_for_thread = id.clone();
    let original_name_for_thread = original_name.clone();
    std::thread::Builder::new()
        .name(format!("library-analyze-{id}"))
        .spawn(move || {
            let qi = quick_inspect(&final_path_owned);
            if qi.packets == 0 {
                // Parse failed after passing the magic check — rare
                // (truncated body, exotic linktype). Mark the sidecar
                // with a sentinel and leave it for the user to delete.
                warn!(id = %id_for_thread, "background parse failed; leaving stub sidecar");
                let stub = LibraryEntry {
                    id: id_for_thread.clone(),
                    name: format!("{original_name_for_thread} (parse failed)"),
                    uploaded_at_ms,
                    size_bytes,
                    packets: 0,
                    ip_sources: 0,
                    non_ip_sources: 0,
                    tcp_flows: 0,
                    duration_ms: 0.0,
                    pcap_start_unix_ms: None,
                    pcap_end_unix_ms: None,
                    mac_collisions: 0,
                    viability: Some(Viability {
                        client_payload_bytes: 0,
                        server_payload_bytes: 0,
                        sessions_master_mode: 0,
                        sessions_slave_mode: 0,
                        estimated_peak_mb: 0,
                        verdict: "not_recommended".into(),
                        verdict_reason: "background parse failed — file may be truncated or use an unsupported link type".into(),
                        notes: vec![],
                    }),
                };
                let _ = save_library_entry(&dir_owned, &stub);
                return;
            }
            let final_entry = LibraryEntry {
                id: id_for_thread.clone(),
                name: original_name_for_thread,
                uploaded_at_ms,
                size_bytes,
                packets: qi.packets,
                ip_sources: qi.ip_sources,
                non_ip_sources: qi.non_ip_sources,
                tcp_flows: qi.tcp_flows,
                duration_ms: qi.duration_ms,
                pcap_start_unix_ms: qi.pcap_start_unix_ms,
                pcap_end_unix_ms: qi.pcap_end_unix_ms,
                mac_collisions: qi.mac_collisions,
                viability: qi.viability,
            };
            if let Err(e) = save_library_entry(&dir_owned, &final_entry) {
                warn!(id = %id_for_thread, error = %e, "sidecar rewrite failed");
            } else {
                info!(id = %id_for_thread, packets = qi.packets, "background analysis complete");
            }
        })
        .map_err(|e| AppError::Internal(format!("spawn analyzer: {e}")))?;

    Ok(Json(pending))
}

async fn api_library_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if !library_entry_id_valid(&id) {
        return Err(AppError::BadRequest(format!("invalid id: {id}")));
    }
    let dir: &StdPath = state.library_dir.as_ref();
    let pcap_p = dir.join(format!("{id}.pcap"));
    let sidecar_p = library_sidecar_path(dir, &id);
    if !pcap_p.exists() && !sidecar_p.exists() {
        return Err(AppError::NotFound(format!("pcap id not found: {id}")));
    }
    let _ = std::fs::remove_file(&pcap_p);
    let _ = std::fs::remove_file(&sidecar_p);
    info!(%id, "pcap deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RenameReq {
    name: String,
}

async fn api_library_rename(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RenameReq>,
) -> Result<Json<LibraryEntry>, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let mut entry = load_library_entry(dir, &id)
        .ok_or_else(|| AppError::NotFound(format!("pcap id not found: {id}")))?;
    let trimmed = req.name.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(AppError::BadRequest("name must be 1..256 chars".into()));
    }
    entry.name = trimmed.to_string();
    save_library_entry(dir, &entry).map_err(|e| AppError::Internal(format!("sidecar: {e}")))?;
    Ok(Json(entry))
}

async fn api_library_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let path = library_pcap_path(dir, &id)?;
    let entry = load_library_entry(dir, &id);
    let bytes = std::fs::read(&path)
        .map_err(|e| AppError::Internal(format!("read {path:?}: {e}")))?;
    let fname = entry
        .map(|e| e.name)
        .unwrap_or_else(|| format!("{id}.pcap"));
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
