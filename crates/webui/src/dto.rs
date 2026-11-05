//! Serializable run state and report DTOs.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use sched::{BenchmarkReport, RunContext, RunReport, SessionReport, SourceKind, SourceReport};
use serde::{Deserialize, Serialize};

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
    /// Name of the protocol replayer used for this run (matches
    /// [`protoplay::ProtoReplayer::name`]). Surfaced so the analyser
    /// can look up the right replayer via [`proto_registry::lookup`].
    #[serde(default = "default_proto_name")]
    pub proto: String,
    /// Free-form per-protocol JSON config the run was started with.
    /// Persisted so the post-run analyser can read protocol-specific
    /// settings (e.g. IEC 104 CP56 rewrite + zone).
    #[serde(default)]
    pub proto_config: Option<String>,
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
    /// Current iteration number (1-based) the session is on. `0`
    /// before the first iteration starts; equal to `iter_total` once
    /// the run is complete.
    #[serde(default)]
    pub iter_current: u64,
    /// Total iterations planned. `0` = unbounded (loop until cancel).
    #[serde(default)]
    pub iter_total: u64,
}

pub(crate) fn state_to_str(s: u8) -> &'static str {
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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Completed => "completed",
            RunStatus::Stopped => "stopped",
            RunStatus::Failed => "failed",
        }
    }

    pub(crate) fn from_str(s: &str) -> Self {
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

pub(crate) fn default_proto_name() -> String {
    "iec104".into()
}
