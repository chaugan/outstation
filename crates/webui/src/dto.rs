//! Serializable run state and report DTOs.
//!
//! Persisted report structs (`RunReportJson`, `BenchmarkReportJson`,
//! `SessionReportJson`, `SourceProgressJson`) are `#[serde(default)]`
//! so adding a field never makes older history unreadable (F090).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use sched::{BenchmarkReport, RunContext, RunReport, SessionReport, SourceKind, SourceReport};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize)]
pub struct RunState {
    pub id: u64,
    pub status: RunStatus,
    pub started_at: u64,
    /// Unix seconds when the run reached a terminal status.
    pub finished_at: Option<u64>,
    /// Peer address of the client that started the run.
    pub started_by: Option<String>,
    /// Absolute path of the source pcap (server-side only; requests
    /// reference pcaps by library id).
    pub pcap: PathBuf,
    /// Library id of the source pcap.
    pub pcap_id: Option<String>,
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
    pub role: &'static str,
    /// Benchmark target port, 0 for raw.
    pub target_port: u16,
    /// Name of the protocol replayer used for this run (matches
    /// [`protoplay::ProtoReplayer::name`]).
    pub proto: String,
    /// Free-form per-protocol JSON config the run was started with.
    pub proto_config: Option<String>,
    /// Total frames planned for this run.
    pub planned: u64,
    /// Frames (raw) or messages (benchmark) sent so far.
    pub sent: u64,
    /// Wire bytes sent so far.
    pub bytes_progress: u64,
    /// Per-source live progress snapshot.
    pub per_source_progress: Vec<SourceProgressJson>,
    /// Rolling throughput samples in frames/messages per second, one
    /// per second while the run was running.
    pub throughput_history: Vec<u64>,
    /// Absolute path of this run's capture file.
    pub capture_file: Option<PathBuf>,
    /// Canonical JSON of the validated request the run was started
    /// with (T08); `None` for runs that predate it.
    pub request: Option<serde_json::Value>,
    /// The run this one re-ran (`POST /api/runs/:id/rerun`).
    pub rerun_of: Option<u64>,
    /// Newest stored analysis of this run.
    pub latest_analysis: Option<AnalysisRef>,
    /// Automatic post-run analysis progress (this process only).
    pub auto_analysis: Option<AutoAnalysis>,
    /// Live shared counters from sched. Not serialized.
    #[serde(skip)]
    pub ctx: RunContext,
}

/// Reference to a stored analysis, carried on run summaries.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AnalysisRef {
    pub id: u64,
    pub verdict: String,
    /// Fleet score in percent.
    pub score: f64,
    /// `manual`, `auto` or `on_demand`.
    pub source: String,
    pub created_at: u64,
}

impl From<&crate::db::StoredAnalysis> for AnalysisRef {
    fn from(a: &crate::db::StoredAnalysis) -> Self {
        Self {
            id: a.id,
            verdict: a.verdict.clone(),
            score: a.score_pct,
            source: a.source.clone(),
            created_at: a.created_at,
        }
    }
}

/// State of the automatic analysis of a finished benchmark run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AutoAnalysis {
    /// `queued`, `running`, `done`, `failed` or `skipped`.
    pub state: &'static str,
    /// Why it failed or was skipped.
    pub error: Option<String>,
    pub analysis_id: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceProgressJson {
    pub src_ip: Option<String>,
    pub src_mac: String,
    pub tap: String,
    pub planned: u64,
    pub sent: u64,
    pub bytes: u64,
    pub received: u64,
    pub unacked: u64,
    /// Slave-benchmark: the local port this session listens on, or 0.
    pub listen_port: u16,
    /// Slave-benchmark: the local address the session listens on.
    pub listen_ip: String,
    /// Lifecycle state: "pending", "listening", "connected", "active",
    /// "completed", "failed", "cancelled".
    pub state: String,
    /// True once the per-session start button has been clicked.
    pub ready: bool,
    /// True once this session has been individually cancelled.
    pub cancelled: bool,
    /// Current iteration number (1-based); 0 before the first.
    pub iter_current: u64,
    /// Total iterations planned. `0` = unbounded.
    pub iter_total: u64,
    /// Why the session failed, set when `state` is "failed" (T07b).
    /// `null` otherwise, and in rows stored before this field existed.
    pub error: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    /// Finished, but some (not all) sessions reported an error.
    Partial,
    Stopped,
    Failed,
}

impl RunStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Completed => "completed",
            RunStatus::Partial => "partial",
            RunStatus::Stopped => "stopped",
            RunStatus::Failed => "failed",
        }
    }

    pub(crate) fn from_str(s: &str) -> Self {
        match s {
            "running" => RunStatus::Running,
            "completed" => RunStatus::Completed,
            "partial" => RunStatus::Partial,
            "stopped" => RunStatus::Stopped,
            _ => RunStatus::Failed,
        }
    }

    pub(crate) fn is_terminal(self) -> bool {
        !matches!(self, RunStatus::Running)
    }
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RunReportJson {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
    pub per_source: Vec<SourceReportJson>,
    pub capture_path: Option<String>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
    /// Frames the capture lost to a full kernel queue (T18b); 0 in old
    /// rows.
    pub captured_dropped: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
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
        Self {
            src_ip: s.src_ip.map(|i| i.to_string()),
            src_mac: fmt_mac(s.src_mac),
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
            captured_dropped: r.captured_dropped,
        }
    }
}

/// Pre-binned latency histogram. Bins are log-spaced: bin `i` covers
/// `[10^(log10_min_us + i*w), 10^(log10_min_us + (i+1)*w))` µs with
/// `w = (log10_max_us - log10_min_us) / counts.len()`. Samples below
/// the first edge land in `underflow`, samples at or above the last
/// edge in `overflow` — nothing is clipped (F136).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LatencyHistogramJson {
    pub log10_min_us: f64,
    pub log10_max_us: f64,
    pub counts: Vec<u64>,
    pub underflow: u64,
    pub overflow: u64,
    /// Sum of all counts (weighted for the aggregate histogram).
    pub total: u64,
}

/// 10 µs .. 10 s, four bins per decade.
pub(crate) const HIST_LOG_MIN: f64 = 1.0;
pub(crate) const HIST_LOG_MAX: f64 = 7.0;
pub(crate) const HIST_BINS: usize = 24;

impl Default for LatencyHistogramJson {
    fn default() -> Self {
        Self {
            log10_min_us: HIST_LOG_MIN,
            log10_max_us: HIST_LOG_MAX,
            counts: vec![0; HIST_BINS],
            underflow: 0,
            overflow: 0,
            total: 0,
        }
    }
}

/// Floating-point accumulator behind [`LatencyHistogramJson`], so
/// weighted contributions are summed before rounding.
#[derive(Debug, Clone)]
pub(crate) struct HistAcc {
    counts: Vec<f64>,
    underflow: f64,
    overflow: f64,
}

impl HistAcc {
    pub(crate) fn new() -> Self {
        Self {
            counts: vec![0.0; HIST_BINS],
            underflow: 0.0,
            overflow: 0.0,
        }
    }

    pub(crate) fn add(&mut self, sample_us: u64, weight: f64) {
        let l = (sample_us.max(1) as f64).log10();
        if sample_us == 0 || l < HIST_LOG_MIN {
            self.underflow += weight;
        } else if l >= HIST_LOG_MAX {
            self.overflow += weight;
        } else {
            let w = (HIST_LOG_MAX - HIST_LOG_MIN) / HIST_BINS as f64;
            let idx = (((l - HIST_LOG_MIN) / w) as usize).min(HIST_BINS - 1);
            self.counts[idx] += weight;
        }
    }

    pub(crate) fn finish(self) -> LatencyHistogramJson {
        let counts: Vec<u64> = self.counts.iter().map(|c| c.round() as u64).collect();
        let underflow = self.underflow.round() as u64;
        let overflow = self.overflow.round() as u64;
        let total = counts.iter().sum::<u64>() + underflow + overflow;
        LatencyHistogramJson {
            log10_min_us: HIST_LOG_MIN,
            log10_max_us: HIST_LOG_MAX,
            counts,
            underflow,
            overflow,
            total,
        }
    }
}

pub(crate) fn histogram_of(samples: &[u64]) -> LatencyHistogramJson {
    let mut acc = HistAcc::new();
    for &s in samples {
        acc.add(s, 1.0);
    }
    acc.finish()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BenchmarkReportJson {
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub aggregate_latency_min_us: u64,
    pub aggregate_latency_p50_us: u64,
    pub aggregate_latency_p90_us: u64,
    pub aggregate_latency_p99_us: u64,
    pub aggregate_latency_max_us: u64,
    pub aggregate_throughput_msgs_per_sec: f64,
    /// Fleet latency histogram. Each session's reservoir is weighted by
    /// `acked messages / reservoir size`, so heavy sessions count in
    /// proportion to their traffic (F027).
    pub aggregate_latency_histogram: Option<LatencyHistogramJson>,
    /// Legacy (pre-T04) flattened sample prefix. Read from old rows and
    /// converted into `aggregate_latency_histogram`; never written.
    #[serde(skip_serializing)]
    pub aggregate_latency_samples_us: Vec<u64>,
    pub per_session: Vec<SessionReportJson>,
    pub capture_path: Option<String>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
    /// Frames the capture lost to a full kernel queue (T18b); 0 in old
    /// rows.
    pub captured_dropped: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
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
    /// Pre-binned per-session latency histogram (unweighted reservoir).
    pub latency_histogram: Option<LatencyHistogramJson>,
    /// Legacy raw samples; read from old rows, never written.
    #[serde(skip_serializing)]
    pub latency_samples_us: Vec<u64>,
    /// Protocol-level counters and violations (absent in old rows).
    pub protocol: Option<ProtocolStatsJson>,
    /// The session was stopped (run stop or per-session cancel), not
    /// failed; `error` then says where it was stopped (T07b).
    pub cancelled: bool,
}

/// One protocol violation, as recorded by the session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolErrorJson {
    pub at_ms: u64,
    pub kind: String,
    pub detail: String,
    pub fatal: bool,
}

/// [`protoplay::ProtocolStats`] for the UI. The capped per-message
/// vectors are summarised instead of shipped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolStatsJson {
    pub protocol_violations: u64,
    pub protocol_errors: Vec<ProtocolErrorJson>,
    pub synthesized_frames: u64,
    pub stripped_capture_frames: u64,
    pub command_response_count: u64,
    pub command_response_p50_us: u64,
    pub command_response_max_us: u64,
    pub capture_gaps: u64,
    pub script_skipped_bytes: u64,
    pub script_dropped_frames: u64,
    pub idle_serve_ms: u64,
    pub acks_sent: u64,
    pub keepalives_sent: u64,
    /// Per command type round-trip figures (T11), sorted by type ID.
    /// The sample arrays are capped by the session; the UI computes
    /// percentiles from them.
    pub commands: Vec<CommandTypeStatsJson>,
    /// Negative command confirmations, capped by the session.
    pub negative_confirmations: Vec<NegativeConfirmationJson>,
    /// Deliberately injected faults (T12), capped by the session.
    pub faults_injected: Vec<FaultRecordJson>,
    /// Peer reaction to the injected faults; `None` when none fired.
    pub fault_reaction: Option<FaultReactionJson>,
}

/// [`protoplay::CommandTypeStats`] for the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandTypeStatsJson {
    pub type_id: u8,
    pub commands: u64,
    pub act_con: u64,
    pub negative: u64,
    pub act_term: u64,
    pub deact_con: u64,
    pub unanswered: u64,
    pub actcon_us: Vec<u64>,
    pub actterm_us: Vec<u64>,
}

/// [`protoplay::NegativeConfirmation`] for the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NegativeConfirmationJson {
    pub at_ms: u64,
    pub type_id: u8,
    pub ca: u16,
    pub ioa: u32,
    pub cot: u8,
}

/// [`protoplay::FaultRecord`] for the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FaultRecordJson {
    pub at_ms: u64,
    pub kind: String,
    pub detail: String,
    pub frames_affected: u64,
}

/// [`protoplay::FaultReaction`] for the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FaultReactionJson {
    pub peer_closed: bool,
    pub peer_reset: bool,
    pub peer_stopdt: bool,
    pub protocol_errors: Vec<String>,
    pub first_reaction_ms: Option<u64>,
    pub summary: String,
}

impl From<&protoplay::ProtocolStats> for ProtocolStatsJson {
    fn from(p: &protoplay::ProtocolStats) -> Self {
        let mut cr = p.command_response_us.clone();
        cr.sort_unstable();
        Self {
            protocol_violations: p.protocol_violations,
            protocol_errors: p
                .protocol_errors
                .iter()
                .map(|e| ProtocolErrorJson {
                    at_ms: e.at_ms,
                    kind: e.kind.clone(),
                    detail: e.detail.clone(),
                    fatal: e.fatal,
                })
                .collect(),
            synthesized_frames: p.synthesized_frames,
            stripped_capture_frames: p.stripped_capture_frames,
            command_response_count: cr.len() as u64,
            command_response_p50_us: cr.get(cr.len() / 2).copied().unwrap_or(0),
            command_response_max_us: cr.last().copied().unwrap_or(0),
            capture_gaps: p.capture_gaps,
            script_skipped_bytes: p.script_skipped_bytes,
            script_dropped_frames: p.script_dropped_frames,
            idle_serve_ms: p.idle_serve_ms,
            acks_sent: p.acks_sent,
            keepalives_sent: p.keepalives_sent,
            commands: p
                .commands
                .iter()
                .map(|c| CommandTypeStatsJson {
                    type_id: c.type_id,
                    commands: c.commands,
                    act_con: c.act_con,
                    negative: c.negative,
                    act_term: c.act_term,
                    deact_con: c.deact_con,
                    unanswered: c.unanswered,
                    actcon_us: c.actcon_us.clone(),
                    actterm_us: c.actterm_us.clone(),
                })
                .collect(),
            negative_confirmations: p
                .negative_confirmations
                .iter()
                .map(|n| NegativeConfirmationJson {
                    at_ms: n.at_ms,
                    type_id: n.type_id,
                    ca: n.ca,
                    ioa: n.ioa,
                    cot: n.cot,
                })
                .collect(),
            faults_injected: p
                .faults_injected
                .iter()
                .map(|f| FaultRecordJson {
                    at_ms: f.at_ms,
                    kind: f.kind.clone(),
                    detail: f.detail.clone(),
                    frames_affected: f.frames_affected,
                })
                .collect(),
            fault_reaction: p.fault_reaction.as_ref().map(|r| FaultReactionJson {
                peer_closed: r.peer_closed,
                peer_reset: r.peer_reset,
                peer_stopdt: r.peer_stopdt,
                protocol_errors: r.protocol_errors.clone(),
                first_reaction_ms: r.first_reaction_ms,
                summary: r.summary.clone(),
            }),
        }
    }
}

impl BenchmarkReportJson {
    /// Convert legacy sample vectors (old DB rows) into histograms and
    /// drop the samples.
    pub(crate) fn upgrade_legacy(&mut self) {
        if self.aggregate_latency_histogram.is_none()
            && !self.aggregate_latency_samples_us.is_empty()
        {
            self.aggregate_latency_histogram =
                Some(histogram_of(&self.aggregate_latency_samples_us));
        }
        self.aggregate_latency_samples_us = Vec::new();
        for s in &mut self.per_session {
            if s.latency_histogram.is_none() && !s.latency_samples_us.is_empty() {
                s.latency_histogram = Some(histogram_of(&s.latency_samples_us));
            }
            s.latency_samples_us = Vec::new();
        }
    }

    /// Protocol violations summed over every session.
    pub(crate) fn protocol_violations(&self) -> u64 {
        self.per_session
            .iter()
            .filter_map(|s| s.protocol.as_ref())
            .map(|p| p.protocol_violations)
            .sum()
    }

    /// Sessions that ended with an error and were not stopped.
    pub(crate) fn sessions_failed(&self) -> usize {
        self.per_session
            .iter()
            .filter(|s| s.error.is_some() && !s.cancelled)
            .count()
    }

    /// Sessions stopped (run stop or per-session cancel) before they
    /// finished.
    pub(crate) fn sessions_cancelled(&self) -> usize {
        self.per_session.iter().filter(|s| s.cancelled).count()
    }
}

impl From<&SessionReport> for SessionReportJson {
    fn from(s: &SessionReport) -> Self {
        let pr = &s.proto_report;
        Self {
            src_ip: s.src_ip.to_string(),
            src_mac: fmt_mac(s.src_mac),
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
            latency_histogram: (!pr.latency_samples_us.is_empty())
                .then(|| histogram_of(&pr.latency_samples_us)),
            latency_samples_us: Vec::new(),
            protocol: Some(ProtocolStatsJson::from(&pr.protocol)),
            cancelled: s.cancelled,
        }
    }
}

/// Weight of one reservoir sample: how many acknowledged messages it
/// stands for. A session's reservoir holds at most a fixed number of
/// samples however many messages it acked.
fn session_weight(pr: &protoplay::ProtoReport) -> f64 {
    let n = pr.latency_samples_us.len();
    if n == 0 {
        return 0.0;
    }
    let acked = pr.messages_sent.saturating_sub(pr.unacked_at_end) as f64;
    (acked / n as f64).max(1.0)
}

/// Weighted percentile over `(value, weight)` pairs sorted by value.
fn weighted_percentile(sorted: &[(u64, f64)], total: f64, p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let target = total * p;
    let mut acc = 0.0;
    for &(v, w) in sorted {
        acc += w;
        if acc >= target {
            return v;
        }
    }
    sorted[sorted.len() - 1].0
}

impl From<&BenchmarkReport> for BenchmarkReportJson {
    fn from(r: &BenchmarkReport) -> Self {
        // Weighted fleet histogram and percentiles from every session's
        // full reservoir.
        let mut acc = HistAcc::new();
        let mut pairs: Vec<(u64, f64)> = Vec::new();
        for s in &r.per_session {
            let w = session_weight(&s.proto_report);
            for &v in &s.proto_report.latency_samples_us {
                acc.add(v, w);
                pairs.push((v, w));
            }
        }
        let (p50, p90, p99, hist) = if pairs.is_empty() {
            (
                r.aggregate_latency_p50_us,
                r.aggregate_latency_p90_us,
                r.aggregate_latency_p99_us,
                None,
            )
        } else {
            pairs.sort_unstable_by_key(|p| p.0);
            let total: f64 = pairs.iter().map(|p| p.1).sum();
            (
                weighted_percentile(&pairs, total, 0.50),
                weighted_percentile(&pairs, total, 0.90),
                weighted_percentile(&pairs, total, 0.99),
                Some(acc.finish()),
            )
        };
        Self {
            total_messages_sent: r.total_messages_sent,
            total_messages_received: r.total_messages_received,
            aggregate_latency_min_us: r.aggregate_latency_min_us,
            aggregate_latency_p50_us: p50,
            aggregate_latency_p90_us: p90,
            aggregate_latency_p99_us: p99,
            aggregate_latency_max_us: r.aggregate_latency_max_us,
            aggregate_throughput_msgs_per_sec: r.aggregate_throughput_msgs_per_sec,
            aggregate_latency_histogram: hist,
            aggregate_latency_samples_us: Vec::new(),
            per_session: r.per_session.iter().map(Into::into).collect(),
            capture_path: r.capture_path.as_ref().map(|p| p.display().to_string()),
            captured_packets: r.captured_packets,
            captured_bytes: r.captured_bytes,
            captured_dropped: r.captured_dropped,
        }
    }
}

pub(crate) fn default_proto_name() -> String {
    "iec104".into()
}

// ---------------------------------------------------------------------------
// Slim list view (F029/F054).

/// Raw report without the per-source table.
#[derive(Debug, Clone, Serialize)]
pub struct RunReportSummary {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
    pub capture_path: Option<String>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
    /// Frames the capture lost to a full kernel queue (T18b); 0 in old
    /// rows.
    pub captured_dropped: u64,
}

/// Benchmark report without per-session rows or histograms.
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkSummary {
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub aggregate_latency_min_us: u64,
    pub aggregate_latency_p50_us: u64,
    pub aggregate_latency_p90_us: u64,
    pub aggregate_latency_p99_us: u64,
    pub aggregate_latency_max_us: u64,
    pub aggregate_throughput_msgs_per_sec: f64,
    pub capture_path: Option<String>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
    /// Frames the capture lost to a full kernel queue (T18b).
    pub captured_dropped: u64,
    pub sessions: usize,
    /// Sessions that ended with an error (cancelled ones excluded).
    pub sessions_failed: usize,
    /// Sessions stopped before they finished (T07b).
    pub sessions_cancelled: usize,
    /// Protocol violations summed over every session.
    pub protocol_violations: u64,
}

/// One row of `GET /api/runs`.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub id: u64,
    pub status: RunStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub started_by: Option<String>,
    pub pcap: String,
    pub pcap_id: Option<String>,
    pub target_ip: Ipv4Addr,
    pub target_mac: String,
    pub speed: f64,
    pub top_speed: bool,
    pub realtime: bool,
    pub error: Option<String>,
    pub mode: &'static str,
    pub role: &'static str,
    pub target_port: u16,
    pub proto: String,
    pub planned: u64,
    pub sent: u64,
    pub bytes_progress: u64,
    pub throughput_history: Vec<u64>,
    /// Live per-source progress; only filled while the run is running.
    pub per_source_progress: Vec<SourceProgressJson>,
    /// Number of per-source progress rows (sessions/sources).
    pub sources: usize,
    /// Rows whose final state was "failed".
    pub sources_failed: usize,
    /// Rows whose final state was "cancelled" (stopped, never failed).
    pub sources_cancelled: usize,
    /// True when the capture file exists on disk and can be downloaded.
    pub has_capture: bool,
    pub report: Option<RunReportSummary>,
    pub benchmark: Option<BenchmarkSummary>,
    /// The run this one re-ran.
    pub rerun_of: Option<u64>,
    /// Newest stored analysis: `{id, verdict, score, source, created_at}`.
    pub latest_analysis: Option<AnalysisRef>,
    /// Automatic analysis progress: `{state, error, analysis_id}`.
    pub auto_analysis: Option<AutoAnalysis>,
}

impl RunState {
    pub(crate) fn summary(&self) -> RunSummary {
        let running = matches!(self.status, RunStatus::Running);
        RunSummary {
            id: self.id,
            status: self.status,
            started_at: self.started_at,
            finished_at: self.finished_at,
            started_by: self.started_by.clone(),
            pcap: self.pcap.display().to_string(),
            pcap_id: self.pcap_id.clone(),
            target_ip: self.target_ip,
            target_mac: self.target_mac.clone(),
            speed: self.speed,
            top_speed: self.top_speed,
            realtime: self.realtime,
            error: self.error.clone(),
            mode: self.mode,
            role: self.role,
            target_port: self.target_port,
            proto: self.proto.clone(),
            planned: self.planned,
            sent: self.sent,
            bytes_progress: self.bytes_progress,
            throughput_history: self.throughput_history.clone(),
            per_source_progress: if running {
                self.per_source_progress.clone()
            } else {
                Vec::new()
            },
            sources: self.per_source_progress.len(),
            sources_failed: self
                .per_source_progress
                .iter()
                .filter(|p| p.state == "failed")
                .count(),
            sources_cancelled: self
                .per_source_progress
                .iter()
                .filter(|p| p.state == "cancelled")
                .count(),
            has_capture: self.capture_file.as_ref().is_some_and(|p| p.is_file()),
            report: self.report.as_ref().map(|r| RunReportSummary {
                total_packets: r.total_packets,
                total_bytes: r.total_bytes,
                total_errors: r.total_errors,
                capture_path: r.capture_path.clone(),
                captured_packets: r.captured_packets,
                captured_bytes: r.captured_bytes,
                captured_dropped: r.captured_dropped,
            }),
            benchmark: self.benchmark.as_ref().map(|b| BenchmarkSummary {
                total_messages_sent: b.total_messages_sent,
                total_messages_received: b.total_messages_received,
                aggregate_latency_min_us: b.aggregate_latency_min_us,
                aggregate_latency_p50_us: b.aggregate_latency_p50_us,
                aggregate_latency_p90_us: b.aggregate_latency_p90_us,
                aggregate_latency_p99_us: b.aggregate_latency_p99_us,
                aggregate_latency_max_us: b.aggregate_latency_max_us,
                aggregate_throughput_msgs_per_sec: b.aggregate_throughput_msgs_per_sec,
                capture_path: b.capture_path.clone(),
                captured_packets: b.captured_packets,
                captured_bytes: b.captured_bytes,
                captured_dropped: b.captured_dropped,
                sessions: b.per_session.len(),
                sessions_failed: b.sessions_failed(),
                sessions_cancelled: b.sessions_cancelled(),
                protocol_violations: b.protocol_violations(),
            }),
            rerun_of: self.rerun_of,
            latest_analysis: self.latest_analysis.clone(),
            auto_analysis: self.auto_analysis.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protoplay::ProtoReport;

    fn session(samples: Vec<u64>, sent: u64) -> SessionReport {
        SessionReport {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_mac: [0; 6],
            tap: String::new(),
            flow_idx: 0,
            started_at_ns: 0,
            proto_report: ProtoReport {
                messages_sent: sent,
                latency_samples_us: samples,
                ..Default::default()
            },
            cancelled: false,
        }
    }

    #[test]
    fn aggregate_is_weighted_by_session_volume() {
        // Heavy session: 1M messages, reservoir of 1000 samples at 100 µs.
        // Light session: 1000 messages, all 1000 samples at 100 ms.
        let r = BenchmarkReport {
            per_session: vec![
                session(vec![1_000; 1000], 1_000),
                session(vec![100; 1000], 1_000_000),
            ],
            ..Default::default()
        };
        let j = BenchmarkReportJson::from(&r);
        // Without weighting p50 would be ambiguous (50/50); with it the
        // heavy session dominates the p90.
        assert_eq!(j.aggregate_latency_p90_us, 100);
        let h = j.aggregate_latency_histogram.unwrap();
        assert_eq!(h.total, 1_000_000 + 1_000);
    }

    #[test]
    fn histogram_keeps_tail_in_overflow() {
        let h = histogram_of(&[5, 50, 5_000_000, 20_000_000, 7_000_000_000]);
        assert_eq!(h.underflow, 1);
        assert_eq!(h.overflow, 2);
        assert_eq!(h.counts.iter().sum::<u64>(), 2);
        assert_eq!(h.total, 5);
    }

    #[test]
    fn legacy_samples_upgrade_to_histogram() {
        let json = r#"{"total_messages_sent":3,"aggregate_latency_samples_us":[10,20,30],
            "per_session":[{"src_ip":"10.0.0.1","latency_samples_us":[10]}]}"#;
        let mut b: BenchmarkReportJson = serde_json::from_str(json).unwrap();
        b.upgrade_legacy();
        assert_eq!(b.aggregate_latency_histogram.as_ref().unwrap().total, 3);
        assert!(b.aggregate_latency_samples_us.is_empty());
        let out = serde_json::to_value(&b).unwrap();
        assert!(out.get("aggregate_latency_samples_us").is_none());
        assert!(out["per_session"][0].get("latency_samples_us").is_none());
    }

    #[test]
    fn session_json_carries_protocol_stats() {
        let mut s = session(vec![10], 5);
        s.proto_report.protocol.protocol_violations = 3;
        s.proto_report.protocol.command_response_us = vec![30, 10, 20];
        s.proto_report.protocol.protocol_errors = vec![protoplay::ProtocolError {
            at_ms: 7,
            kind: "ns_mismatch".into(),
            detail: "expected 1, got 4".into(),
            fatal: true,
        }];
        let r = BenchmarkReport {
            per_session: vec![s],
            ..Default::default()
        };
        let j = BenchmarkReportJson::from(&r);
        let p = j.per_session[0].protocol.as_ref().unwrap();
        assert_eq!(p.protocol_violations, 3);
        assert_eq!(p.command_response_count, 3);
        assert_eq!(p.command_response_p50_us, 20);
        assert_eq!(p.command_response_max_us, 30);
        assert_eq!(p.protocol_errors[0].kind, "ns_mismatch");
        assert_eq!(j.protocol_violations(), 3);
        // Old rows without the field still load.
        let old: SessionReportJson = serde_json::from_str(r#"{"src_ip":"10.0.0.1"}"#).unwrap();
        assert!(old.protocol.is_none());
    }

    #[test]
    fn session_json_carries_commands_and_faults() {
        let mut s = session(vec![10], 5);
        let p = &mut s.proto_report.protocol;
        p.commands = vec![protoplay::CommandTypeStats {
            type_id: 45,
            commands: 2,
            act_con: 1,
            negative: 1,
            act_term: 1,
            actcon_us: vec![300, 100],
            actterm_us: vec![900],
            ..Default::default()
        }];
        p.negative_confirmations = vec![protoplay::NegativeConfirmation {
            at_ms: 12,
            type_id: 45,
            ca: 1,
            ioa: 4001,
            cot: 47,
        }];
        p.faults_injected = vec![protoplay::FaultRecord {
            at_ms: 500,
            kind: "rst".into(),
            detail: "connection reset".into(),
            frames_affected: 0,
        }];
        p.fault_reaction = Some(protoplay::FaultReaction {
            peer_reset: true,
            first_reaction_ms: Some(3),
            summary: "1 fault injected".into(),
            ..Default::default()
        });
        let r = BenchmarkReport {
            per_session: vec![s],
            ..Default::default()
        };
        let v = serde_json::to_value(BenchmarkReportJson::from(&r)).unwrap();
        let p = &v["per_session"][0]["protocol"];
        assert_eq!(p["commands"][0]["type_id"], 45);
        assert_eq!(p["commands"][0]["actcon_us"], serde_json::json!([300, 100]));
        assert_eq!(p["negative_confirmations"][0]["cot"], 47);
        assert_eq!(p["faults_injected"][0]["kind"], "rst");
        assert_eq!(p["fault_reaction"]["peer_reset"], true);
        assert_eq!(p["fault_reaction"]["first_reaction_ms"], 3);
        // A stored report round-trips, and rows written before these
        // fields existed still load with empty defaults.
        let back: BenchmarkReportJson = serde_json::from_value(v).unwrap();
        let bp = back.per_session[0].protocol.as_ref().unwrap();
        assert_eq!(bp.commands[0].actterm_us, vec![900]);
        let old: ProtocolStatsJson = serde_json::from_str(r#"{"protocol_violations":1}"#).unwrap();
        assert!(old.commands.is_empty() && old.fault_reaction.is_none());
    }

    #[test]
    fn report_structs_tolerate_missing_fields() {
        let _: RunReportJson = serde_json::from_str("{}").unwrap();
        let _: BenchmarkReportJson = serde_json::from_str("{}").unwrap();
        let _: SessionReportJson = serde_json::from_str("{}").unwrap();
    }
}
