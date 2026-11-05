//! Post-run analysis shell: compare a user-uploaded captured pcap
//! against the source pcap of a completed run.
//!
//! The shell is protocol-agnostic. It handles pcap loading, endpoint
//! enumeration and pairing, per-session flow picking, fleet rollup,
//! iteration-boundary detection, and the fleet pacing timeline. The
//! per-session protocol analysis (playback vs target diff, handshake,
//! drift, timing, verdict) is delegated to the selected
//! [`protoplay::ProtoReplayer`] via
//! [`analyze_flow`](protoplay::ProtoReplayer::analyze_flow), whose
//! [`VerdictOutcome`] drives the rollup so the shell never interprets
//! protocol verdict strings.
//!
//! # Which endpoints are judged
//!
//! The run's own selection ([`RunInfo::endpoints`], taken from its
//! per-source progress) is authoritative:
//!
//! * a selected endpoint with no captured session is `never_connected`
//!   (a failure);
//! * captured traffic on the run's port that pairs with no selected
//!   endpoint is listed as `unpaired` and is not scored;
//! * every captured TCP session of an endpoint is analysed (not just
//!   the busiest), and the endpoint's verdict is its worst session's,
//!   with reconnects counted.
//!
//! Without run facts (old runs) the shell falls back to the endpoints
//! present in both pcaps.
//!
//! # Report size and persistence
//!
//! [`AnalysisReport`] still carries `details_by_ip` for the current UI,
//! but every per-endpoint detail is bounded by the protocol's caps
//! (IEC 104: 200 mismatches, 2 000-entry sequences, strided samples).
//! [`AnalysisReport::split`] separates it into a small serializable
//! [`AnalysisSummary`] (verdicts, scores, fleet rollup, timelines) and
//! the per-endpoint [`SlaveDetail`] map, so the caller can persist the
//! summary with the run and store or serve each detail lazily.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::Path;

use pcapload::{LoadedPcap, ReassembledFlow};
use protoplay::{
    AnalyzeCtx, FleetDriftTimeline, FlowSnapshot, ProtoReplayer, ProtoSlaveAnalysis, Role,
    RunFacts, VerdictOutcome,
};
use serde::Serialize;

/// Default tolerance for the CP56Time2a drift analyzer: 50 ms is
/// generous for a LAN SCADA session but keeps noise out of the count.
pub const DEFAULT_CP56_TOLERANCE_MS: f64 = 50.0;
/// Largest accepted CP56Time2a drift tolerance (one hour).
pub const MAX_CP56_TOLERANCE_MS: f64 = 3_600_000.0;

/// Check a configured CP56Time2a drift tolerance (F066).
pub fn check_cp56_tolerance(v: f64) -> Result<f64, String> {
    if v.is_finite() && (0.0..=MAX_CP56_TOLERANCE_MS).contains(&v) {
        Ok(v)
    } else {
        Err(format!(
            "cp56_tolerance_ms must be a number in 0..={MAX_CP56_TOLERANCE_MS}, got {v}"
        ))
    }
}

/// Cap on points emitted in the fleet timelines. Aggregate stats stay
/// accurate beyond this; only the scatter is trimmed.
pub const MAX_FLEET_TIMELINE_POINTS: usize = 5_000;

/// Cap on the per-endpoint session list in a detail.
pub const MAX_SESSIONS_LISTED: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    /// Target is a different software than the one in the pcap.
    /// Only checks outstation's side delivered the expected frames and
    /// that the peer held up basic protocol flow control.
    Generic,
    /// Target is the same device(s) as the original pcap. Extra
    /// byte-level comparison of the target's replies vs the original.
    Correct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleHint {
    /// outstation acted as the client (master).
    Master,
    /// outstation acted as the server (slave).
    Slave,
}

impl RoleHint {
    fn as_role(self) -> Role {
        match self {
            RoleHint::Master => Role::Master,
            RoleHint::Slave => Role::Slave,
        }
    }
}

/// Final status of the run being judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatusHint {
    Completed,
    /// Finished, but some (not all) sessions reported an error.
    Partial,
    /// Stopped by the user: a truncated final iteration is expected.
    Stopped,
    Failed,
    /// Still running when analysed.
    Running,
    #[default]
    Unknown,
}

/// One endpoint the run was configured to replay, from the run's
/// per-source progress.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedEndpoint {
    /// The endpoint's IP in the source pcap: the RTU (server) IP in
    /// slave role, the master (client) IP in master role.
    pub source_ip: Ipv4Addr,
    /// Slave role: the address the session listened on, when it was
    /// not the source IP (user-edited listen IP). `None` or
    /// `0.0.0.0` = the source IP.
    pub listen_ip: Option<Ipv4Addr>,
    /// Slave role: the port the session listened on.
    pub listen_port: Option<u16>,
    /// Final lifecycle state ("completed", "failed", "cancelled", …).
    pub state: String,
    pub cancelled: bool,
    /// Messages the endpoint's session(s) sent.
    pub sent: u64,
}

/// Run facts the analysis needs from the caller (F060, F062, F093).
/// `RunInfo::default()` means "unknown" and reproduces the
/// capture-driven behaviour for runs that predate these facts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunInfo {
    pub status: RunStatusHint,
    pub error: Option<String>,
    /// Total messages the run reported sending; `Some(0)` triggers the
    /// "run sent nothing" warning.
    pub messages_sent: Option<u64>,
    /// Selected endpoints. Empty = unknown (fall back to the capture).
    pub endpoints: Vec<SelectedEndpoint>,
    /// Configured iterations; `0` = unbounded (loop until stopped).
    pub iterations: u64,
    /// Whether iterations ran inside one TCP session. `None` = unknown:
    /// iterations are then detected from the captured stream.
    pub loop_within_session: Option<bool>,
    /// Pacing speed when the run replayed original timing; `None` =
    /// as fast as possible or unknown (timing not judged).
    pub paced_speed: Option<f64>,
    /// Server port of the endpoint flows in the source pcap. `None` =
    /// the analysis target port, else detected.
    pub source_port: Option<u16>,
    /// Frames the run's own capture lost to a full kernel queue. Any
    /// loss makes "missing" frames in the verdict suspect.
    pub capture_dropped: u64,
}

/// Everything [`analyze`] needs.
#[derive(Debug, Clone)]
pub struct AnalyzeRequest<'a> {
    pub original_pcap_path: &'a Path,
    pub captured_pcap_path: &'a Path,
    pub run_id: u64,
    /// Captured-side port: the target port in master role, the listen
    /// port (base) in slave role.
    pub target_port: u16,
    pub role: RoleHint,
    pub mode: AnalysisMode,
    pub proto_config: Option<String>,
    pub cp56_tolerance_ms: f64,
    pub run: RunInfo,
}

#[derive(Serialize, Debug, Clone)]
pub struct AnalysisReport {
    pub run_id: u64,
    /// Status of the run this capture was judged against.
    pub run_status: RunStatusHint,
    /// Set when the run failed or sent nothing: the verdict can then
    /// never be `all_correct` (F093).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_warning: Option<String>,
    pub mode: &'static str,
    pub role: &'static str,
    /// Protocol name (e.g. `"iec104"`) — lets the UI pick the right
    /// slave-detail renderer from `PROTOCOL_RENDERERS`.
    pub protocol: &'static str,
    pub original_pcap: String,
    pub captured_size_bytes: u64,
    pub captured_total_packets: usize,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub score_pct: f64,
    pub notes: Vec<String>,
    pub fleet: FleetSummary,
    pub slaves: Vec<SlaveSummary>,
    pub details_by_ip: BTreeMap<String, SlaveDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_ip_mapping: Option<MasterIpMapping>,
    /// Fleet-wide drift timeline, aggregated by the protocol. `None`
    /// when the protocol doesn't produce drift samples for this run
    /// (e.g. IEC 104 without fresh-timestamps mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_drift_timeline: Option<FleetDriftTimeline>,
    /// Fleet-wide pacing drift — `None` when no endpoint delivered any
    /// messages in both pcaps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_pacing_timeline: Option<FleetPacingTimeline>,
}

/// [`AnalysisReport`] without the per-endpoint details: small enough
/// to persist with the run and to send on every poll. Serialize it as
/// JSON and store it as text; fetch details separately by endpoint
/// key (`SlaveSummary::slave_ip`).
#[derive(Serialize, Debug, Clone)]
pub struct AnalysisSummary {
    pub run_id: u64,
    pub run_status: RunStatusHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_warning: Option<String>,
    pub mode: &'static str,
    pub role: &'static str,
    pub protocol: &'static str,
    pub original_pcap: String,
    pub captured_size_bytes: u64,
    pub captured_total_packets: usize,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub score_pct: f64,
    pub notes: Vec<String>,
    pub fleet: FleetSummary,
    pub slaves: Vec<SlaveSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_ip_mapping: Option<MasterIpMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_drift_timeline: Option<FleetDriftTimeline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_pacing_timeline: Option<FleetPacingTimeline>,
}

impl AnalysisReport {
    /// Split into the persistable summary and the per-endpoint detail
    /// map (keyed like `SlaveSummary::slave_ip`).
    pub fn split(self) -> (AnalysisSummary, BTreeMap<String, SlaveDetail>) {
        (
            AnalysisSummary {
                run_id: self.run_id,
                run_status: self.run_status,
                run_warning: self.run_warning,
                mode: self.mode,
                role: self.role,
                protocol: self.protocol,
                original_pcap: self.original_pcap,
                captured_size_bytes: self.captured_size_bytes,
                captured_total_packets: self.captured_total_packets,
                verdict: self.verdict,
                verdict_reason: self.verdict_reason,
                score_pct: self.score_pct,
                notes: self.notes,
                fleet: self.fleet,
                slaves: self.slaves,
                master_ip_mapping: self.master_ip_mapping,
                fleet_drift_timeline: self.fleet_drift_timeline,
                fleet_pacing_timeline: self.fleet_pacing_timeline,
            },
            self.details_by_ip,
        )
    }
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct FleetSummary {
    /// Endpoints judged (selected endpoints; unpaired traffic excluded).
    pub slave_count: usize,
    /// Endpoints with at least one captured session.
    pub attempted: usize,
    /// Same as `never_connected`; kept for the current UI.
    pub not_attempted: usize,
    pub never_connected: usize,
    /// Captured endpoints that pair with no selected endpoint (not
    /// scored).
    pub unpaired: usize,
    /// Endpoints whose verdict is inconclusive (no reference…), not
    /// scored but blocking `all_correct`.
    pub inconclusive: usize,
    pub fully_correct: usize,
    pub partial: usize,
    pub failed: usize,
    /// Extra TCP sessions beyond the expected count, summed.
    pub reconnects: usize,
    /// Mean of per-endpoint scores (each clamped to 0..=100) over the
    /// scored endpoints; never-connected endpoints count as 0.
    pub aggregate_score_pct: f64,
    /// Same, weighted by each endpoint's expected message count.
    pub frame_weighted_score_pct: f64,
    pub best: Option<BestWorst>,
    pub worst: Option<BestWorst>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct BestWorst {
    pub slave_ip: String,
    pub score_pct: f64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct SlaveSummary {
    /// Endpoint key: the RTU IP in slave role, the replayed master IP
    /// in master role (name kept for the UI).
    pub slave_ip: String,
    pub score_pct: f64,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub outcome: VerdictOutcome,
    /// Expected protocol messages (IEC 104: I-frames; Modbus: PDUs).
    pub expected_iframes: usize,
    /// Delivered protocol messages on the wire.
    pub delivered_iframes: usize,
    pub packets: usize,
    /// Protocol-level handshake flag. For IEC 104 this is STARTDT.
    pub startdt_handshake_ok: bool,
    /// Captured TCP sessions analysed for this endpoint.
    pub sessions: usize,
    /// Sessions beyond the expected count.
    pub reconnects: usize,
}

/// One captured TCP session of an endpoint.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct SessionSummary {
    /// 1-based, in capture order.
    pub index: usize,
    pub flow: FlowInfo,
    pub first_ts_ms: f64,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub outcome: VerdictOutcome,
    pub score_pct: f64,
    pub expected: usize,
    pub delivered: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct SlaveDetail {
    /// The session whose drill-down is in `protocol_specific` (the
    /// worst one).
    pub tcp_flow: Option<FlowInfo>,
    /// Every captured session of this endpoint, capped at
    /// [`MAX_SESSIONS_LISTED`].
    pub sessions: Vec<SessionSummary>,
    pub sessions_total: usize,
    /// Protocol-specific drill-down produced by the replayer's
    /// [`analyze_flow`](protoplay::ProtoReplayer::analyze_flow) for the
    /// worst session. The matching UI renderer in
    /// `static/<proto>_ui.js` walks this blob.
    pub protocol_specific: serde_json::Value,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub score_pct: f64,
    pub notes: Vec<String>,
    /// Pacing samples of every session, used for the fleet timeline
    /// only (not serialized; the timeline is).
    #[serde(skip)]
    pub pacing_samples: Vec<[f64; 2]>,
    /// How many real samples each entry of `pacing_samples` stands for.
    #[serde(skip)]
    pub pacing_weight: f64,
}

#[derive(Serialize, Debug, Clone)]
pub struct MasterIpMapping {
    pub captured: Option<String>,
    pub live: Option<String>,
    pub renamed: bool,
}

/// Fleet-wide pacing-drift timeline. Protocol-agnostic XY series.
#[derive(Serialize, Debug, Clone)]
pub struct FleetPacingTimeline {
    pub samples: Vec<[f64; 2]>,
    pub total_samples: usize,
    pub decimated: bool,
    pub iteration_starts_ms: Vec<f64>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FlowInfo {
    pub client: String,
    pub server: String,
    pub packets: usize,
    pub state: String,
}

fn flow_state_label(flow: &pcapload::Flow) -> String {
    let mut s = String::new();
    if flow.saw_syn {
        s.push_str("SYN ");
    }
    if flow.saw_syn_ack {
        s.push_str("SYN-ACK ");
    }
    if flow.saw_fin {
        s.push_str("FIN ");
    }
    if flow.saw_rst {
        s.push_str("RST ");
    }
    s.trim().to_string()
}

fn flow_info(flow: &pcapload::Flow) -> FlowInfo {
    FlowInfo {
        client: flow
            .client
            .map(|(ip, p)| format!("{ip}:{p}"))
            .unwrap_or_else(|| "?".into()),
        server: flow
            .server
            .map(|(ip, p)| format!("{ip}:{p}"))
            .unwrap_or_else(|| "?".into()),
        packets: flow.packet_indices.len(),
        state: flow_state_label(flow),
    }
}

/// Auto-detect the master IP: the client IP with the most flows whose
/// server port matches `target_port`.
fn detect_master_ip(p: &LoadedPcap, target_port: u16) -> Option<Ipv4Addr> {
    let mut counts: HashMap<Ipv4Addr, usize> = HashMap::new();
    for flow in &p.flows {
        let Some((_, sp)) = flow.server else { continue };
        if sp != target_port {
            continue;
        }
        if let Some((cip, _)) = flow.client {
            *counts.entry(cip).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(ip, c)| (*c, std::cmp::Reverse(*ip)))
        .map(|(ip, _)| ip)
}

/// The endpoint key of a flow: RTU (server) IP in slave role, master
/// (client) IP in master role.
fn endpoint_of(flow: &pcapload::Flow, role: RoleHint) -> Option<Ipv4Addr> {
    match role {
        RoleHint::Slave => flow.server.map(|(ip, _)| ip),
        RoleHint::Master => flow.client.map(|(ip, _)| ip),
    }
}

fn server_port(flow: &pcapload::Flow) -> Option<u16> {
    flow.server.map(|(_, p)| p)
}

fn first_ts_ms(p: &LoadedPcap, flow: &pcapload::Flow) -> f64 {
    flow.packet_indices
        .first()
        .map(|&i| p.packets[i].rel_ts_ns as f64 / 1e6)
        .unwrap_or(0.0)
}

/// Server port of the endpoint flows in the source pcap.
fn detect_source_port(
    original: &LoadedPcap,
    target_port: u16,
    run: &RunInfo,
    role: RoleHint,
) -> u16 {
    if let Some(p) = run.source_port {
        return p;
    }
    if role == RoleHint::Master
        || original
            .flows
            .iter()
            .any(|f| server_port(f) == Some(target_port))
    {
        return target_port;
    }
    // Slave role with a custom listen port: the source port is not
    // recorded in the run, so take the most common server port among
    // the selected RTUs' source flows.
    let selected: BTreeSet<Ipv4Addr> = run.endpoints.iter().map(|e| e.source_ip).collect();
    let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
    for f in &original.flows {
        if let (Some((ip, port)), true) = (f.server, f.client.is_some()) {
            if selected.is_empty() || selected.contains(&ip) {
                *counts.entry(port).or_default() += 1;
            }
        }
    }
    counts
        .into_iter()
        .max_by_key(|(p, c)| (*c, std::cmp::Reverse(*p)))
        .map(|(p, _)| p)
        .unwrap_or(target_port)
}

/// How captured sessions are recognised for one endpoint.
#[derive(Debug, Clone)]
struct EndpointMatch {
    key: Ipv4Addr,
    /// Slave role: the (ip, port) the session listened on.
    listen: Option<(Ipv4Addr, u16)>,
}

impl EndpointMatch {
    fn matches(&self, flow: &pcapload::Flow, role: RoleHint, port: u16) -> bool {
        match role {
            RoleHint::Slave => {
                let (ip, p) = self.listen.unwrap_or((self.key, port));
                flow.server == Some((ip, p))
            }
            RoleHint::Master => {
                server_port(flow) == Some(port) && endpoint_of(flow, role) == Some(self.key)
            }
        }
    }
}

/// Core entry point. Loads both pcaps, pairs every selected endpoint
/// with its source flow and all of its captured sessions, runs the
/// protocol analysis per session, and rolls the results up.
pub fn analyze(
    replayer: &dyn ProtoReplayer,
    req: &AnalyzeRequest,
) -> anyhow::Result<AnalysisReport> {
    use anyhow::Context;

    let original = pcapload::load(req.original_pcap_path).context("load original pcap")?;
    let captured = pcapload::load(req.captured_pcap_path).context("load captured pcap")?;
    let captured_size_bytes = std::fs::metadata(req.captured_pcap_path)
        .map(|m| m.len())
        .unwrap_or(0);
    analyze_loaded(replayer, req, &original, &captured, captured_size_bytes)
}

fn analyze_loaded(
    replayer: &dyn ProtoReplayer,
    req: &AnalyzeRequest,
    original: &LoadedPcap,
    captured: &LoadedPcap,
    captured_size_bytes: u64,
) -> anyhow::Result<AnalysisReport> {
    let role = req.role;
    let run = &req.run;
    let mut fleet_notes: Vec<String> = Vec::new();
    let source_port = detect_source_port(original, req.target_port, run, role);

    let captured_master_ip = detect_master_ip(original, source_port);
    let live_master_ip = detect_master_ip(captured, req.target_port);
    let renamed = match (captured_master_ip, live_master_ip) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    };
    let master_ip_mapping = if captured_master_ip.is_some() || live_master_ip.is_some() {
        Some(MasterIpMapping {
            captured: captured_master_ip.map(|ip| ip.to_string()),
            live: live_master_ip.map(|ip| ip.to_string()),
            renamed,
        })
    } else {
        None
    };
    if let (true, Some(a), Some(b)) = (renamed, captured_master_ip, live_master_ip) {
        fleet_notes.push(format!("master IP renamed: captured={a} live={b}"));
    }

    // Source endpoints and the reference flow the replayer used for
    // each: the first flow in pcap order (sched picks the same one).
    let mut reference: BTreeMap<Ipv4Addr, usize> = BTreeMap::new();
    for (idx, f) in original.flows.iter().enumerate() {
        if server_port(f) != Some(source_port) {
            continue;
        }
        if let Some(ep) = endpoint_of(f, role) {
            reference.entry(ep).or_insert(idx);
        }
    }

    // Endpoints to judge.
    let run_known = !run.endpoints.is_empty();
    let matchers: Vec<(EndpointMatch, Option<&SelectedEndpoint>)> = if run_known {
        run.endpoints
            .iter()
            .map(|e| {
                let listen = match role {
                    RoleHint::Slave => {
                        let ip = e
                            .listen_ip
                            .filter(|ip| !ip.is_unspecified())
                            .unwrap_or(e.source_ip);
                        Some((ip, e.listen_port.unwrap_or(req.target_port)))
                    }
                    RoleHint::Master => None,
                };
                (
                    EndpointMatch {
                        key: e.source_ip,
                        listen,
                    },
                    Some(e),
                )
            })
            .collect()
    } else {
        let captured_eps: BTreeSet<Ipv4Addr> = captured
            .flows
            .iter()
            .filter(|f| server_port(f) == Some(req.target_port))
            .filter_map(|f| endpoint_of(f, role))
            .collect();
        let paired: Vec<Ipv4Addr> = if captured_eps.iter().any(|ip| reference.contains_key(ip)) {
            captured_eps
                .iter()
                .filter(|ip| reference.contains_key(ip))
                .copied()
                .collect()
        } else {
            reference.keys().copied().collect()
        };
        let not_in_capture = reference.keys().filter(|ip| !paired.contains(ip)).count();
        if not_in_capture > 0 {
            fleet_notes.push(format!(
                "run facts unavailable: judging the {} source endpoint(s) seen in the capture; {} source endpoint(s) have no captured traffic and were not judged",
                paired.len(),
                not_in_capture
            ));
        }
        paired
            .into_iter()
            .map(|ip| {
                (
                    EndpointMatch {
                        key: ip,
                        listen: None,
                    },
                    None,
                )
            })
            .collect()
    };
    if matchers.is_empty() {
        return Err(anyhow::anyhow!(
            "no flow in source pcap with server_port={source_port}; nothing to compare against"
        ));
    }

    // Captured sessions per endpoint, in capture order.
    let mut claimed = vec![false; captured.flows.len()];
    let mut sessions_by_ep: Vec<Vec<usize>> = Vec::with_capacity(matchers.len());
    for (m, _) in &matchers {
        let mut v: Vec<usize> = captured
            .flows
            .iter()
            .enumerate()
            .filter(|(_, f)| m.matches(f, role, req.target_port))
            .map(|(i, _)| i)
            .collect();
        v.sort_by(|&a, &b| {
            first_ts_ms(captured, &captured.flows[a])
                .partial_cmp(&first_ts_ms(captured, &captured.flows[b]))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.cmp(&b))
        });
        for &i in &v {
            claimed[i] = true;
        }
        sessions_by_ep.push(v);
    }

    let base_ctx = AnalyzeCtx {
        role: role.as_role(),
        mode_correct: matches!(req.mode, AnalysisMode::Correct),
        captured_first_ts_ns: captured.first_ts_ns,
        target_port: req.target_port,
        proto_config: req.proto_config.clone(),
        cp56_tolerance_ms: req.cp56_tolerance_ms,
        run: RunFacts::default(),
    };

    let mut summaries: Vec<SlaveSummary> = Vec::new();
    let mut details: BTreeMap<String, SlaveDetail> = BTreeMap::new();
    for ((m, sel), sessions) in matchers.iter().zip(&sessions_by_ep) {
        let key = m.key.to_string();
        let ref_idx = reference.get(&m.key).copied();
        let (summary, detail) = analyze_endpoint(
            replayer, original, captured, role, run, *sel, ref_idx, sessions, &base_ctx, &key,
        );
        summaries.push(summary);
        details.insert(key, detail);
    }

    // Captured traffic on the run's port that pairs with nothing.
    if run_known {
        let mut unpaired: BTreeMap<Ipv4Addr, Vec<usize>> = BTreeMap::new();
        for (i, f) in captured.flows.iter().enumerate() {
            if claimed[i] || server_port(f) != Some(req.target_port) {
                continue;
            }
            if let Some(ep) = endpoint_of(f, role) {
                unpaired.entry(ep).or_default().push(i);
            }
        }
        for (ip, flows) in unpaired {
            let key = ip.to_string();
            if details.contains_key(&key) {
                continue;
            }
            let packets = flows
                .iter()
                .map(|&i| captured.flows[i].packet_indices.len())
                .sum();
            let reason = format!(
                "{} captured session(s) on port {} pair with no endpoint selected in this run; not scored",
                flows.len(),
                req.target_port
            );
            summaries.push(SlaveSummary {
                slave_ip: key.clone(),
                score_pct: 0.0,
                verdict: "unpaired",
                verdict_reason: reason.clone(),
                outcome: VerdictOutcome::Inconclusive,
                expected_iframes: 0,
                delivered_iframes: 0,
                packets,
                startdt_handshake_ok: false,
                sessions: flows.len(),
                reconnects: 0,
            });
            details.insert(
                key,
                SlaveDetail {
                    tcp_flow: flows.first().map(|&i| flow_info(&captured.flows[i])),
                    sessions: Vec::new(),
                    sessions_total: flows.len(),
                    protocol_specific: serde_json::Value::Null,
                    verdict: "unpaired",
                    verdict_reason: reason,
                    score_pct: 0.0,
                    notes: Vec::new(),
                    pacing_samples: Vec::new(),
                    pacing_weight: 1.0,
                },
            );
        }
    }

    summaries.sort_by(|a, b| {
        a.score_pct
            .partial_cmp(&b.score_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.slave_ip.cmp(&b.slave_ip))
    });

    if run.capture_dropped > 0 {
        fleet_notes.insert(
            0,
            format!(
                "WARNING: the capture lost {} frames (kernel receive queue full); frames reported missing may have been delivered",
                run.capture_dropped
            ),
        );
    }
    let (fleet, verdict, verdict_reason, score_pct) = roll_up_fleet(&summaries);
    let RunJudgement {
        verdict,
        reason: verdict_reason,
        warning: run_warning,
        score_pct,
    } = apply_run_status(run, verdict, verdict_reason, score_pct, &mut fleet_notes);

    let iteration_starts_ms = detect_iteration_starts(captured, req.target_port, fleet.slave_count);

    // Fleet-wide drift timeline is protocol-driven: the replayer pulls
    // whatever drift series it cares about from each endpoint's
    // protocol_specific JSON.
    let per_slave_proto: BTreeMap<String, serde_json::Value> = details
        .iter()
        .filter(|(_, d)| !d.protocol_specific.is_null())
        .map(|(ip, d)| (ip.clone(), d.protocol_specific.clone()))
        .collect();
    let fleet_drift_timeline =
        replayer.aggregate_fleet_drift(&per_slave_proto, &iteration_starts_ms);
    let fleet_pacing_timeline = build_fleet_pacing_timeline(&details, &iteration_starts_ms);

    Ok(AnalysisReport {
        run_id: req.run_id,
        run_status: run.status,
        run_warning,
        mode: mode_str(req.mode),
        role: role_str(role),
        protocol: replayer.name(),
        original_pcap: req.original_pcap_path.display().to_string(),
        captured_size_bytes,
        captured_total_packets: captured.packets.len(),
        verdict,
        verdict_reason,
        score_pct,
        notes: fleet_notes,
        fleet,
        slaves: summaries,
        details_by_ip: details,
        master_ip_mapping,
        fleet_drift_timeline,
        fleet_pacing_timeline,
    })
}

/// The fleet verdict after the run's own status was applied.
#[derive(Debug, Clone, PartialEq)]
struct RunJudgement {
    verdict: &'static str,
    reason: String,
    warning: Option<String>,
    score_pct: f64,
}

/// True when the run delivered nothing at all: it reported 0 messages
/// sent, or every endpoint failed before sending one.
fn delivered_nothing(run: &RunInfo) -> bool {
    run.messages_sent == Some(0)
        || (!run.endpoints.is_empty()
            && run
                .endpoints
                .iter()
                .all(|e| e.sent == 0 && e.state == "failed"))
}

/// F093/T07b: a run that failed, is still running or delivered nothing
/// can never be certified, and never gets a `partial` (or any other
/// capture-derived) verdict: it is `run_failed`. A run that delivered
/// nothing also scores 0, whatever the capture holds.
fn apply_run_status(
    run: &RunInfo,
    verdict: &'static str,
    reason: String,
    score_pct: f64,
    notes: &mut Vec<String>,
) -> RunJudgement {
    let silent = delivered_nothing(run);
    // (warning, whether it blocks certification)
    let (warning, blocks) = match (run.status, run.messages_sent) {
        (RunStatusHint::Failed, _) => (
            Some(format!(
                "the run being analysed FAILED{}",
                run.error
                    .as_ref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            )),
            true,
        ),
        (_, Some(0)) => (
            Some("the run being analysed sent 0 messages".to_string()),
            true,
        ),
        _ if silent => (
            Some("every session of the run being analysed failed before sending".to_string()),
            true,
        ),
        (RunStatusHint::Running, _) => (
            Some("the run being analysed is still running".to_string()),
            true,
        ),
        // A stopped run is judged only up to the stop; it is never
        // certified as a complete replay (N11).
        (RunStatusHint::Stopped, _) => (
            Some(
                "the run being analysed was STOPPED before it finished; only what it sent \
                 before the stop is judged"
                    .to_string(),
            ),
            false,
        ),
        // Session errors are judged per endpoint from the capture.
        (RunStatusHint::Partial, _) => (
            Some("some sessions of the run being analysed reported errors".to_string()),
            false,
        ),
        _ => (None, false),
    };
    let Some(w) = warning else {
        return RunJudgement {
            verdict,
            reason,
            warning: None,
            score_pct,
        };
    };
    notes.insert(0, format!("WARNING: {w}"));
    if !blocks {
        // A clean but stopped run says so instead of `all_correct`.
        let (verdict, reason) = if run.status == RunStatusHint::Stopped && verdict == "all_correct"
        {
            (
                "stopped_clean",
                format!(
                    "stopped before the end; everything sent before the stop was clean ({reason})"
                ),
            )
        } else {
            (verdict, reason)
        };
        return RunJudgement {
            verdict,
            reason,
            warning: Some(w),
            score_pct,
        };
    }
    let reason = if silent {
        format!("{w}: the run delivered nothing, so there is nothing to score (capture: {verdict}, {reason})")
    } else if verdict == "all_correct" || verdict == "inconclusive" {
        format!("{w}; the capture matched ({reason}), but this run cannot be certified")
    } else {
        format!("{w}; capture verdict {verdict}: {reason}")
    };
    RunJudgement {
        verdict: "run_failed",
        reason,
        warning: Some(w),
        score_pct: if silent { 0.0 } else { score_pct },
    }
}

/// Analyse every captured session of one endpoint and fold them into
/// one summary/detail.
#[allow(clippy::too_many_arguments)]
fn analyze_endpoint(
    replayer: &dyn ProtoReplayer,
    original: &LoadedPcap,
    captured: &LoadedPcap,
    role: RoleHint,
    run: &RunInfo,
    sel: Option<&SelectedEndpoint>,
    ref_idx: Option<usize>,
    sessions: &[usize],
    base_ctx: &AnalyzeCtx,
    key: &str,
) -> (SlaveSummary, SlaveDetail) {
    let mut notes: Vec<String> = Vec::new();

    // Reference flow (the one the replayer replays).
    let (orig_client, orig_server) = match ref_idx {
        Some(i) => (
            original.reassemble_client_payload(i).ok(),
            original.reassemble_server_payload(i).ok(),
        ),
        None => {
            notes.push(format!(
                "endpoint {key} has no flow in the source pcap; nothing to compare against"
            ));
            (None, None)
        }
    };
    if let Some(i) = ref_idx {
        let n = original
            .flows
            .iter()
            .filter(|f| {
                endpoint_of(f, role) == endpoint_of(&original.flows[i], role)
                    && server_port(f) == server_port(&original.flows[i])
            })
            .count();
        if n > 1 {
            notes.push(format!(
                "source pcap has {n} sessions for this endpoint; the replayer replays the first, which is the reference"
            ));
        }
    }
    let (orig_pb, orig_tg) = pick_playback_target(role, orig_client.as_ref(), orig_server.as_ref());

    // A stop excuses a truncated tail, but never on an endpoint whose
    // own session failed: its missing frames are a failure, whatever
    // happened to the run afterwards (N11).
    let failed = sel.is_some_and(|s| s.state == "failed" && !s.cancelled);
    let stopped =
        !failed && (run.status == RunStatusHint::Stopped || sel.is_some_and(|s| s.cancelled));
    let (per_session_iters, expected_sessions) = match run.loop_within_session {
        Some(true) => (run.iterations, Some(1u64)),
        Some(false) => (1, (run.iterations > 0).then_some(run.iterations)),
        None => (0, None),
    };
    // An unbounded loop always ends on a stop.
    let stopped =
        !failed && (stopped || (run.loop_within_session.is_some() && run.iterations == 0));

    // Sessions that carried no payload at all (port probes, refused
    // connects) are listed but not judged.
    let mut analyses: Vec<(usize, ProtoSlaveAnalysis)> = Vec::new();
    let mut session_rows: Vec<SessionSummary> = Vec::new();
    let mut empty_sessions = 0usize;
    let payload_sessions: Vec<(usize, ReassembledFlow, ReassembledFlow)> = sessions
        .iter()
        .filter_map(|&i| {
            let c = captured.reassemble_client_payload(i).ok()?;
            let s = captured.reassemble_server_payload(i).ok()?;
            if c.payload.is_empty() && s.payload.is_empty() {
                None
            } else {
                Some((i, c, s))
            }
        })
        .collect();
    empty_sessions += sessions.len() - payload_sessions.len();
    let n_sessions = payload_sessions.len();
    for (k, (i, c, s)) in payload_sessions.iter().enumerate() {
        let is_last = k + 1 == n_sessions;
        let ctx = AnalyzeCtx {
            run: RunFacts {
                iterations_per_session: per_session_iters,
                // Only the final session can have been cut by a stop.
                stopped_early: stopped && is_last,
                paced_speed: run.paced_speed,
            },
            ..base_ctx.clone()
        };
        let (cap_pb, cap_tg) = pick_playback_target(role, Some(c), Some(s));
        let a = replayer.analyze_flow(
            orig_pb.map(snapshot),
            cap_pb.map(snapshot),
            orig_tg.map(snapshot),
            cap_tg.map(snapshot),
            &ctx,
        );
        let flow = &captured.flows[*i];
        session_rows.push(SessionSummary {
            index: k + 1,
            flow: flow_info(flow),
            first_ts_ms: first_ts_ms(captured, flow),
            verdict: a.verdict,
            verdict_reason: a.verdict_reason.clone(),
            outcome: a.outcome,
            score_pct: a.score_pct.clamp(0.0, 100.0),
            expected: a.expected_messages,
            delivered: a.delivered_messages,
        });
        analyses.push((*i, a));
    }
    if empty_sessions > 0 {
        notes.push(format!(
            "{empty_sessions} captured session(s) carried no payload (connect without data) and were not judged"
        ));
    }

    let packets: usize = sessions
        .iter()
        .map(|&i| captured.flows[i].packet_indices.len())
        .sum();
    let reconnects = match expected_sessions {
        Some(n) => n_sessions.saturating_sub(n as usize),
        None => n_sessions.saturating_sub(1),
    };
    if n_sessions > 1 {
        notes.push(format!(
            "{n_sessions} TCP sessions captured for this endpoint{}",
            if reconnects > 0 {
                format!(" ({reconnects} more than expected: reconnects)")
            } else {
                String::new()
            }
        ));
    }

    if analyses.is_empty() {
        // Selected but never reached the wire.
        let state = sel.map(|s| s.state.as_str()).unwrap_or("unknown");
        let reason =
            format!("no captured session with payload for this endpoint (run state: {state})");
        let summary = SlaveSummary {
            slave_ip: key.to_string(),
            score_pct: 0.0,
            verdict: "never_connected",
            verdict_reason: reason.clone(),
            outcome: VerdictOutcome::Fail,
            expected_iframes: 0,
            delivered_iframes: 0,
            packets,
            startdt_handshake_ok: false,
            sessions: 0,
            reconnects: 0,
        };
        let detail = SlaveDetail {
            tcp_flow: sessions.first().map(|&i| flow_info(&captured.flows[i])),
            sessions: Vec::new(),
            sessions_total: 0,
            protocol_specific: serde_json::Value::Null,
            verdict: "never_connected",
            verdict_reason: reason,
            score_pct: 0.0,
            notes,
            pacing_samples: Vec::new(),
            pacing_weight: 1.0,
        };
        return (summary, detail);
    }

    // Worst session: Fail < Inconclusive < Pass, then lowest score.
    let rank = |o: VerdictOutcome| match o {
        VerdictOutcome::Fail => 0,
        VerdictOutcome::Inconclusive => 1,
        VerdictOutcome::Pass => 2,
    };
    let worst = analyses
        .iter()
        .enumerate()
        .min_by(|(_, (_, a)), (_, (_, b))| {
            rank(a.outcome).cmp(&rank(b.outcome)).then(
                a.score_pct
                    .partial_cmp(&b.score_pct)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        })
        .map(|(k, _)| k)
        .unwrap_or(0);

    let weight = |a: &ProtoSlaveAnalysis| a.expected_messages.max(1) as f64;
    let mut wsum: f64 = analyses.iter().map(|(_, a)| weight(a)).sum();
    let score_sum: f64 = analyses
        .iter()
        .map(|(_, a)| a.score_pct.clamp(0.0, 100.0) * weight(a))
        .sum();
    let expected_total: usize = analyses.iter().map(|(_, a)| a.expected_messages).sum();
    let delivered_total: usize = analyses.iter().map(|(_, a)| a.delivered_messages).sum();
    let handshake_ok = analyses.iter().all(|(_, a)| a.handshake_ok);

    let (_, wa) = &analyses[worst];
    let mut outcome = wa.outcome;
    let mut verdict = wa.verdict;
    let mut reason = if n_sessions > 1 {
        format!(
            "session {}/{}: {}",
            worst + 1,
            n_sessions,
            wa.verdict_reason
        )
    } else {
        wa.verdict_reason.clone()
    };

    // Configured iterations that never got a session.
    if let Some(n) = expected_sessions {
        let missing = (n as usize).saturating_sub(n_sessions);
        if missing > 0 && !stopped {
            let per = wsum / n_sessions as f64;
            wsum += per * missing as f64;
            outcome = VerdictOutcome::Fail;
            verdict = "missing_sessions";
            reason = format!(
                "{n_sessions} of {n} configured iteration sessions captured; {missing} missing. Worst captured session: {}",
                wa.verdict_reason
            );
        }
    }
    let score = if wsum > 0.0 {
        (score_sum / wsum).clamp(0.0, 100.0)
    } else {
        0.0
    };

    let mut all_notes = notes;
    let mut pacing: Vec<[f64; 2]> = Vec::new();
    let mut pacing_total = 0usize;
    for (k, (_, a)) in analyses.iter().enumerate() {
        pacing.extend_from_slice(&a.pacing_samples);
        pacing_total += a.pacing_samples_total.max(a.pacing_samples.len());
        if k == worst {
            all_notes.extend(a.notes.iter().cloned());
        }
    }
    let pacing_weight = if pacing.is_empty() {
        1.0
    } else {
        pacing_total as f64 / pacing.len() as f64
    };

    let sessions_total = session_rows.len();
    session_rows.truncate(MAX_SESSIONS_LISTED);
    let (worst_flow_idx, worst_analysis) = analyses.swap_remove(worst);
    let summary = SlaveSummary {
        slave_ip: key.to_string(),
        score_pct: score,
        verdict,
        verdict_reason: reason.clone(),
        outcome,
        expected_iframes: expected_total,
        delivered_iframes: delivered_total,
        packets,
        startdt_handshake_ok: handshake_ok,
        sessions: n_sessions,
        reconnects,
    };
    let detail = SlaveDetail {
        tcp_flow: Some(flow_info(&captured.flows[worst_flow_idx])),
        sessions: session_rows,
        sessions_total,
        protocol_specific: worst_analysis.protocol_specific,
        verdict,
        verdict_reason: reason,
        score_pct: score,
        notes: all_notes,
        pacing_samples: pacing,
        pacing_weight,
    };
    (summary, detail)
}

/// Merge every endpoint's pacing samples into one time-sorted timeline
/// and decimate it, weighting each endpoint by how many real samples
/// its (already decimated) series stands for (F136). Protocol-agnostic.
fn build_fleet_pacing_timeline(
    details: &BTreeMap<String, SlaveDetail>,
    iteration_starts_ms: &[f64],
) -> Option<FleetPacingTimeline> {
    let mut all: Vec<(f64, f64, f64)> = Vec::new();
    let mut total = 0.0f64;
    for d in details.values() {
        let w = d.pacing_weight.max(1.0);
        for s in &d.pacing_samples {
            all.push((s[0], s[1], w));
        }
        total += w * d.pacing_samples.len() as f64;
    }
    if all.is_empty() {
        return None;
    }
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let total_samples = total.round() as usize;
    let (kept, decimated) = weighted_decimate(&all, MAX_FLEET_TIMELINE_POINTS);
    Some(FleetPacingTimeline {
        samples: kept,
        total_samples,
        decimated: decimated || total_samples > all.len(),
        iteration_starts_ms: iteration_starts_ms.to_vec(),
    })
}

/// Weighted random sampling without replacement (Efraimidis–Spirakis)
/// over time-sorted `(t, value, weight)`, deterministic (hash of the
/// index as the random source). Returns points in time order.
fn weighted_decimate(sorted: &[(f64, f64, f64)], cap: usize) -> (Vec<[f64; 2]>, bool) {
    if sorted.len() <= cap {
        return (sorted.iter().map(|&(t, d, _)| [t, d]).collect(), false);
    }
    let mut keyed: Vec<(f64, usize)> = sorted
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut z = (i as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let u = ((z >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
            (u.ln() / s.2.max(1e-12), i)
        })
        .collect();
    keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut idx: Vec<usize> = keyed.into_iter().take(cap).map(|(_, i)| i).collect();
    idx.sort_unstable();
    (
        idx.into_iter()
            .map(|i| [sorted[i].0, sorted[i].1])
            .collect(),
        true,
    )
}

/// Detect iteration boundaries by clustering TCP SYN packets to the
/// target port. Each benchmark iteration triggers a tight burst of
/// handshakes, so we bin SYNs by 1-second windows and flag bins that
/// contain at least 30 % of the expected endpoint count. Adjacent
/// flagged bins coalesce into a single iteration start.
fn detect_iteration_starts(
    captured: &LoadedPcap,
    target_port: u16,
    expected_slave_count: usize,
) -> Vec<f64> {
    if expected_slave_count == 0 {
        return Vec::new();
    }
    let threshold = ((expected_slave_count as f64) * 0.30).max(5.0) as usize;

    let mut syn_times_ms: Vec<f64> = Vec::new();
    for flow in captured.flows.iter() {
        let Some((_, sp)) = flow.server else { continue };
        if sp != target_port {
            continue;
        }
        if let Some(&first_pkt_idx) = flow.packet_indices.first() {
            let pkt = &captured.packets[first_pkt_idx];
            syn_times_ms.push(pkt.rel_ts_ns as f64 / 1e6);
        }
    }
    if syn_times_ms.is_empty() {
        return Vec::new();
    }
    syn_times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let max_ms = *syn_times_ms.last().unwrap();
    let bin_count = ((max_ms / 1000.0) as usize).saturating_add(2);
    let mut bins: Vec<usize> = vec![0; bin_count];
    for &t in &syn_times_ms {
        let b = (t / 1000.0) as usize;
        if b < bins.len() {
            bins[b] += 1;
        }
    }

    let mut starts: Vec<f64> = Vec::new();
    let mut last_start_ms: Option<f64> = None;
    for (b, &count) in bins.iter().enumerate() {
        if count < threshold {
            continue;
        }
        let bin_start_ms = b as f64 * 1000.0;
        if let Some(prev) = last_start_ms {
            if bin_start_ms - prev < 5_000.0 {
                continue;
            }
        }
        starts.push(bin_start_ms);
        last_start_ms = Some(bin_start_ms);
    }
    starts
}

fn snapshot(rf: &ReassembledFlow) -> FlowSnapshot<'_> {
    FlowSnapshot {
        payload: &rf.payload,
        packet_offsets: &rf.packet_offsets,
    }
}

/// Resolve (playback, target) flow references from (client, server)
/// based on which role outstation played in this run.
fn pick_playback_target<'a>(
    role: RoleHint,
    client: Option<&'a ReassembledFlow>,
    server: Option<&'a ReassembledFlow>,
) -> (Option<&'a ReassembledFlow>, Option<&'a ReassembledFlow>) {
    match role {
        RoleHint::Master => (client, server),
        RoleHint::Slave => (server, client),
    }
}

/// Fleet rollup. Classes come from each endpoint's [`VerdictOutcome`]
/// (never from its score), so an endpoint with an unknown or
/// inconclusive verdict can never count as fully correct.
///
/// | fleet verdict | when |
/// |---|---|
/// | `no_session` | no endpoint to judge |
/// | `no_delivery` | no judged endpoint has a captured session |
/// | `all_correct` | every judged endpoint passed |
/// | `failed` | every judged endpoint failed with score 0 |
/// | `inconclusive` | nothing failed, but some endpoints could not be verified |
/// | `partial` | anything else |
///
/// `run_failed` is applied on top by [`apply_run_status`].
fn roll_up_fleet(slaves: &[SlaveSummary]) -> (FleetSummary, &'static str, String, f64) {
    let judged: Vec<&SlaveSummary> = slaves.iter().filter(|s| s.verdict != "unpaired").collect();
    let unpaired = slaves.len() - judged.len();
    let slave_count = judged.len();
    let never_connected = judged
        .iter()
        .filter(|s| s.verdict == "never_connected")
        .count();
    let attempted = judged.iter().filter(|s| s.sessions > 0).count();
    let fully_correct = judged
        .iter()
        .filter(|s| s.outcome == VerdictOutcome::Pass)
        .count();
    let inconclusive = judged
        .iter()
        .filter(|s| s.outcome == VerdictOutcome::Inconclusive)
        .count();
    let failed = judged
        .iter()
        .filter(|s| s.outcome == VerdictOutcome::Fail && s.score_pct <= 0.0)
        .count();
    let partial = judged
        .iter()
        .filter(|s| s.outcome == VerdictOutcome::Fail && s.score_pct > 0.0)
        .count();
    let reconnects = judged.iter().map(|s| s.reconnects).sum();

    let scored: Vec<&SlaveSummary> = judged
        .iter()
        .copied()
        .filter(|s| s.outcome != VerdictOutcome::Inconclusive)
        .collect();
    let clamp = |s: &SlaveSummary| s.score_pct.clamp(0.0, 100.0);
    let aggregate_score_pct = if scored.is_empty() {
        0.0
    } else {
        scored.iter().map(|s| clamp(s)).sum::<f64>() / scored.len() as f64
    };
    let wsum: f64 = scored
        .iter()
        .map(|s| s.expected_iframes.max(1) as f64)
        .sum();
    let frame_weighted_score_pct = if wsum > 0.0 {
        scored
            .iter()
            .map(|s| clamp(s) * s.expected_iframes.max(1) as f64)
            .sum::<f64>()
            / wsum
    } else {
        0.0
    };
    let cmp = |a: &&SlaveSummary, b: &&SlaveSummary| {
        clamp(a)
            .partial_cmp(&clamp(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    };
    let to_bw = |s: &SlaveSummary| BestWorst {
        slave_ip: s.slave_ip.clone(),
        score_pct: clamp(s),
    };
    let best = scored.iter().copied().max_by(cmp).map(to_bw);
    let worst = scored.iter().copied().min_by(cmp).map(to_bw);

    let summary = FleetSummary {
        slave_count,
        attempted,
        not_attempted: never_connected,
        never_connected,
        unpaired,
        inconclusive,
        fully_correct,
        partial,
        failed,
        reconnects,
        aggregate_score_pct: aggregate_score_pct.clamp(0.0, 100.0),
        frame_weighted_score_pct: frame_weighted_score_pct.clamp(0.0, 100.0),
        best,
        worst,
    };

    let (verdict, reason): (&'static str, String) = if slave_count == 0 {
        (
            "no_session",
            if unpaired > 0 {
                format!(
                    "no selected endpoint to judge; {unpaired} unpaired endpoint(s) in the capture"
                )
            } else {
                "no endpoints to judge".into()
            },
        )
    } else if attempted == 0 {
        (
            "no_delivery",
            format!("none of {slave_count} endpoints reached the wire"),
        )
    } else if fully_correct == slave_count {
        (
            "all_correct",
            format!("all {slave_count} endpoints replayed correctly"),
        )
    } else if failed == slave_count {
        ("failed", format!("all {slave_count} endpoints failed"))
    } else if failed + partial == 0 {
        (
            "inconclusive",
            format!(
                "{fully_correct}/{slave_count} endpoints verified correct; {inconclusive} could not be verified"
            ),
        )
    } else {
        let mut tail = String::new();
        if never_connected > 0 {
            tail.push_str(&format!(" ({never_connected} never connected)"));
        }
        if inconclusive > 0 {
            tail.push_str(&format!(", {inconclusive} inconclusive"));
        }
        (
            "partial",
            format!(
                "{fully_correct}/{slave_count} endpoints replayed correctly; {partial} partial, {failed} failed{tail}"
            ),
        )
    };

    (
        summary,
        verdict,
        reason,
        aggregate_score_pct.clamp(0.0, 100.0),
    )
}

fn mode_str(m: AnalysisMode) -> &'static str {
    match m {
        AnalysisMode::Generic => "generic",
        AnalysisMode::Correct => "correct",
    }
}
fn role_str(r: RoleHint) -> &'static str {
    match r {
        RoleHint::Master => "master",
        RoleHint::Slave => "slave",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ---------------- pcap builder ----------------

    #[derive(Default)]
    struct Cap {
        pkts: Vec<(u64, Vec<u8>)>,
    }

    fn ip4_csum(h: &[u8]) -> u16 {
        let mut s: u32 = 0;
        for c in h.chunks(2) {
            s += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }

    fn packet(
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.push(0x50);
        tcp.push(flags);
        tcp.extend_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(data);
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&dst.octets());
        let c = ip4_csum(&ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        ip.extend_from_slice(&tcp);
        let mut eth = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
        eth[11] = src.octets()[3];
        eth.extend_from_slice(&ip);
        eth
    }

    enum Dir {
        C2S,
        S2C,
    }

    impl Cap {
        /// One TCP session: handshake, `msgs` in order (`dt_ns` after
        /// the previous packet), FIN.
        fn session(
            &mut self,
            c: (Ipv4Addr, u16),
            s: (Ipv4Addr, u16),
            t0: u64,
            msgs: &[(u64, Dir, Vec<u8>)],
        ) {
            const SYN: u8 = 0x02;
            const ACK: u8 = 0x10;
            const PSH: u8 = 0x08;
            const FIN: u8 = 0x01;
            let (mut cs, mut ss) = (1000u32, 5000u32);
            let mut t = t0;
            self.pkts
                .push((t, packet(c.0, c.1, s.0, s.1, cs, 0, SYN, &[])));
            cs += 1;
            t += 1000;
            self.pkts
                .push((t, packet(s.0, s.1, c.0, c.1, ss, cs, SYN | ACK, &[])));
            ss += 1;
            t += 1000;
            self.pkts
                .push((t, packet(c.0, c.1, s.0, s.1, cs, ss, ACK, &[])));
            for (dt, dir, data) in msgs {
                t += dt;
                match dir {
                    Dir::C2S => {
                        self.pkts
                            .push((t, packet(c.0, c.1, s.0, s.1, cs, ss, ACK | PSH, data)));
                        cs += data.len() as u32;
                    }
                    Dir::S2C => {
                        self.pkts
                            .push((t, packet(s.0, s.1, c.0, c.1, ss, cs, ACK | PSH, data)));
                        ss += data.len() as u32;
                    }
                }
            }
            t += 1000;
            self.pkts
                .push((t, packet(c.0, c.1, s.0, s.1, cs, ss, FIN | ACK, &[])));
        }

        fn load(mut self) -> LoadedPcap {
            self.pkts.sort_by_key(|p| p.0);
            let mut out = Vec::new();
            out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
            out.extend_from_slice(&2u16.to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&65535u32.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            let base = 1_700_000_000_000_000_000u64;
            for (t, d) in &self.pkts {
                let t = base + t;
                out.extend_from_slice(&((t / 1_000_000_000) as u32).to_le_bytes());
                out.extend_from_slice(&(((t % 1_000_000_000) / 1000) as u32).to_le_bytes());
                out.extend_from_slice(&(d.len() as u32).to_le_bytes());
                out.extend_from_slice(&(d.len() as u32).to_le_bytes());
                out.extend_from_slice(d);
            }
            pcapload::load_bytes(&out, PathBuf::from("test.pcap")).expect("load test pcap")
        }
    }

    fn iframe(asdu: &[u8]) -> Vec<u8> {
        let mut f = vec![0x68, (asdu.len() + 4) as u8, 0, 0, 0, 0];
        f.extend_from_slice(asdu);
        f
    }

    fn me(ioa: u8, val: u8) -> Vec<u8> {
        vec![13, 1, 3, 0, 1, 0, ioa, 0, 0, val, 0, 0, 0, 0]
    }

    const STARTDT_ACT: [u8; 6] = [0x68, 4, 0x07, 0, 0, 0];
    const STARTDT_CON: [u8; 6] = [0x68, 4, 0x0B, 0, 0, 0];

    fn script() -> Vec<Vec<u8>> {
        (0..8).map(|i| me(i, i)).collect()
    }

    /// Slave-role session: the master sends STARTDT, the RTU confirms
    /// and sends `asdus` 100 ms apart.
    fn rtu_session(
        cap: &mut Cap,
        rtu: Ipv4Addr,
        port: u16,
        cport: u16,
        t0: u64,
        asdus: &[Vec<u8>],
    ) {
        let master = Ipv4Addr::new(10, 0, 0, 1);
        let mut msgs = vec![
            (1_000_000, Dir::C2S, STARTDT_ACT.to_vec()),
            (1_000_000, Dir::S2C, STARTDT_CON.to_vec()),
        ];
        for a in asdus {
            msgs.push((100_000_000, Dir::S2C, iframe(a)));
        }
        cap.session((master, cport), (rtu, port), t0, &msgs);
    }

    fn rtu(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, n)
    }

    fn source_pcap(rtus: &[u8]) -> LoadedPcap {
        let mut cap = Cap::default();
        for (k, &n) in rtus.iter().enumerate() {
            rtu_session(
                &mut cap,
                rtu(n),
                2404,
                40000 + k as u16,
                k as u64 * 1_000,
                &script(),
            );
        }
        cap.load()
    }

    fn selected(n: u8) -> SelectedEndpoint {
        SelectedEndpoint {
            source_ip: rtu(n),
            listen_ip: Some(rtu(n)),
            listen_port: Some(2404),
            state: "completed".into(),
            cancelled: false,
            sent: 8,
        }
    }

    fn request(run: RunInfo) -> AnalyzeRequest<'static> {
        AnalyzeRequest {
            original_pcap_path: Path::new("source.pcap"),
            captured_pcap_path: Path::new("captured.pcap"),
            run_id: 7,
            target_port: 2404,
            role: RoleHint::Slave,
            mode: AnalysisMode::Generic,
            proto_config: None,
            cp56_tolerance_ms: DEFAULT_CP56_TOLERANCE_MS,
            run,
        }
    }

    fn completed_run(eps: &[u8]) -> RunInfo {
        RunInfo {
            status: RunStatusHint::Completed,
            messages_sent: Some(8 * eps.len() as u64),
            endpoints: eps.iter().map(|&n| selected(n)).collect(),
            iterations: 1,
            loop_within_session: Some(false),
            ..Default::default()
        }
    }

    fn run_analysis(source: &LoadedPcap, captured: &LoadedPcap, run: RunInfo) -> AnalysisReport {
        let replayer = proto_registry::lookup("iec104").expect("iec104 replayer");
        analyze_loaded(replayer.as_ref(), &request(run), source, captured, 0).expect("analyze")
    }

    fn slave(r: &AnalysisReport, n: u8) -> &SlaveSummary {
        let key = rtu(n).to_string();
        r.slaves
            .iter()
            .find(|s| s.slave_ip == key)
            .unwrap_or_else(|| panic!("{key} missing"))
    }

    // ---------------- end-to-end ----------------

    #[test]
    fn selected_rtus_are_authoritative() {
        // F062: RTU .4 was selected but never connected; .9 shows up
        // in the capture but was not selected.
        let source = source_pcap(&[2, 3, 4, 9]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        let mut dropped = script();
        dropped.remove(3);
        rtu_session(&mut cap, rtu(3), 2404, 50001, 0, &dropped);
        rtu_session(&mut cap, rtu(9), 2404, 50002, 0, &script());
        let r = run_analysis(&source, &cap.load(), completed_run(&[2, 3, 4]));

        assert_eq!(slave(&r, 2).verdict, "good_delivery");
        assert_eq!(slave(&r, 2).outcome, VerdictOutcome::Pass);
        assert_eq!(slave(&r, 3).verdict, "partial_delivery");
        assert!((slave(&r, 3).score_pct - 87.5).abs() < 1e-9);
        assert_eq!(slave(&r, 4).verdict, "never_connected");
        assert_eq!(slave(&r, 4).outcome, VerdictOutcome::Fail);
        assert_eq!(slave(&r, 9).verdict, "unpaired");
        assert_eq!(r.fleet.slave_count, 3);
        assert_eq!(r.fleet.never_connected, 1);
        assert_eq!(r.fleet.unpaired, 1);
        assert_eq!(r.fleet.fully_correct, 1);
        assert_eq!(r.verdict, "partial");
        assert!((r.score_pct - (100.0 + 87.5 + 0.0) / 3.0).abs() < 1e-9);
    }

    #[test]
    fn every_session_of_an_rtu_is_analysed() {
        // F063: two iterations in two sessions; the second died early.
        let source = source_pcap(&[2]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        rtu_session(&mut cap, rtu(2), 2404, 50001, 5_000_000_000, &script()[..4]);
        let run = RunInfo {
            iterations: 2,
            ..completed_run(&[2])
        };
        let r = run_analysis(&source, &cap.load(), run);
        let s = slave(&r, 2);
        assert_eq!(s.sessions, 2);
        assert_eq!(s.verdict, "partial_delivery");
        assert!(
            s.verdict_reason.starts_with("session 2/2"),
            "{}",
            s.verdict_reason
        );
        assert_eq!(s.reconnects, 0);
        assert!((s.score_pct - 75.0).abs() < 1e-9, "{}", s.score_pct);
        let d = &r.details_by_ip[&rtu(2).to_string()];
        assert_eq!(d.sessions.len(), 2);
        assert_eq!(d.sessions[0].verdict, "good_delivery");

        // The same capture as a single-iteration run: one reconnect.
        let r = run_analysis(&source, &source_like_two(), completed_run(&[2]));
        assert_eq!(slave(&r, 2).reconnects, 1);
        assert_eq!(r.fleet.reconnects, 1);
    }

    fn source_like_two() -> LoadedPcap {
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        rtu_session(&mut cap, rtu(2), 2404, 50001, 5_000_000_000, &script());
        cap.load()
    }

    #[test]
    fn missing_iteration_sessions_fail() {
        let source = source_pcap(&[2]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        let run = RunInfo {
            iterations: 3,
            ..completed_run(&[2])
        };
        let r = run_analysis(&source, &cap.load(), run);
        let s = slave(&r, 2);
        assert_eq!(s.verdict, "missing_sessions");
        assert_eq!(s.outcome, VerdictOutcome::Fail);
        assert!((s.score_pct - 100.0 / 3.0).abs() < 1e-9, "{}", s.score_pct);
        assert_ne!(r.verdict, "all_correct");
    }

    #[test]
    fn a_lossy_capture_is_flagged() {
        let source = source_pcap(&[2]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        let captured = cap.load();
        let r = run_analysis(&source, &captured, completed_run(&[2]));
        assert!(!r.notes.iter().any(|n| n.contains("capture lost")));
        let lossy = RunInfo {
            capture_dropped: 17,
            ..completed_run(&[2])
        };
        let r = run_analysis(&source, &captured, lossy);
        assert!(
            r.notes[0].starts_with("WARNING: the capture lost 17 frames"),
            "{:?}",
            r.notes
        );
    }

    #[test]
    fn failed_or_silent_run_is_never_all_correct() {
        // F093: a capture that matches perfectly, judged against a run
        // that failed (or sent nothing), must not be certified.
        let source = source_pcap(&[2]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        let captured = cap.load();

        let r = run_analysis(&source, &captured, completed_run(&[2]));
        assert_eq!(r.verdict, "all_correct");
        assert!(r.run_warning.is_none());

        let failed = RunInfo {
            status: RunStatusHint::Failed,
            error: Some("create bridge: Operation not permitted".into()),
            ..completed_run(&[2])
        };
        let r = run_analysis(&source, &captured, failed);
        assert_eq!(r.verdict, "run_failed");
        assert!(r.run_warning.as_deref().unwrap().contains("FAILED"));
        assert!(r.notes[0].starts_with("WARNING"));

        let silent = RunInfo {
            messages_sent: Some(0),
            ..completed_run(&[2])
        };
        let r = run_analysis(&source, &captured, silent);
        assert_eq!(r.verdict, "run_failed");
    }

    #[test]
    fn listen_ip_remap_pairs_with_the_source_rtu() {
        // The user moved RTU .3 to listen on .50: still paired with .3.
        let source = source_pcap(&[3]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(50), 2404, 50000, 0, &script());
        let mut run = completed_run(&[3]);
        run.endpoints[0].listen_ip = Some(rtu(50));
        let r = run_analysis(&source, &cap.load(), run);
        assert_eq!(slave(&r, 3).verdict, "good_delivery");
        assert_eq!(r.fleet.unpaired, 0);
        assert_eq!(r.verdict, "all_correct");
    }

    #[test]
    fn without_run_facts_the_capture_decides() {
        let source = source_pcap(&[2, 3]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        let r = run_analysis(&source, &cap.load(), RunInfo::default());
        assert_eq!(r.slaves.len(), 1);
        assert_eq!(r.verdict, "all_correct");
        assert!(r
            .notes
            .iter()
            .any(|n| n.contains("1 source endpoint(s) have no captured traffic")));
    }

    #[test]
    fn split_gives_a_detail_free_summary() {
        let source = source_pcap(&[2]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        let r = run_analysis(&source, &cap.load(), completed_run(&[2]));
        let (summary, details) = r.split();
        let json = serde_json::to_value(&summary).unwrap();
        assert!(json.get("details_by_ip").is_none());
        assert_eq!(json["verdict"], "all_correct");
        assert_eq!(json["slaves"][0]["slave_ip"], "10.0.0.2");
        assert!(details.contains_key("10.0.0.2"));
        let d = serde_json::to_value(&details["10.0.0.2"]).unwrap();
        assert!(d.get("pacing_samples").is_none());
        assert_eq!(
            d["protocol_specific"]["playback"]["byte_identical_count"],
            8
        );
    }

    // ---------------- roll-up table ----------------

    fn s(
        ip: &str,
        verdict: &'static str,
        outcome: VerdictOutcome,
        score: f64,
        sessions: usize,
    ) -> SlaveSummary {
        SlaveSummary {
            slave_ip: ip.into(),
            score_pct: score,
            verdict,
            verdict_reason: String::new(),
            outcome,
            expected_iframes: 10,
            delivered_iframes: 10,
            packets: sessions * 10,
            startdt_handshake_ok: true,
            sessions,
            reconnects: 0,
        }
    }

    #[test]
    fn roll_up_table() {
        use VerdictOutcome::*;
        let pass = |ip| s(ip, "good_delivery", Pass, 100.0, 1);
        let cases: Vec<(&str, Vec<SlaveSummary>, &str, f64)> = vec![
            ("empty", vec![], "no_session", 0.0),
            (
                "only unpaired",
                vec![s("a", "unpaired", Inconclusive, 0.0, 1)],
                "no_session",
                0.0,
            ),
            (
                "nobody reached the wire",
                vec![s("a", "never_connected", Fail, 0.0, 0)],
                "no_delivery",
                0.0,
            ),
            ("all pass", vec![pass("a"), pass("b")], "all_correct", 100.0),
            (
                "all pass plus unpaired",
                vec![pass("a"), s("z", "unpaired", Inconclusive, 0.0, 1)],
                "all_correct",
                100.0,
            ),
            (
                "pass plus never connected",
                vec![pass("a"), s("b", "never_connected", Fail, 0.0, 0)],
                "partial",
                50.0,
            ),
            (
                "all failed",
                vec![
                    s("a", "no_delivery", Fail, 0.0, 1),
                    s("b", "no_delivery", Fail, 0.0, 1),
                ],
                "failed",
                0.0,
            ),
            (
                "pass plus no_reference",
                vec![pass("a"), s("b", "no_reference", Inconclusive, 0.0, 1)],
                "inconclusive",
                100.0,
            ),
            (
                "unknown verdict at 100% is not correct",
                vec![pass("a"), s("b", "unknown", Inconclusive, 100.0, 1)],
                "inconclusive",
                100.0,
            ),
            (
                "degraded at 100% is not correct",
                vec![pass("a"), s("b", "degraded", Fail, 100.0, 1)],
                "partial",
                100.0,
            ),
            (
                "over-100 scores are clamped",
                vec![
                    s("a", "partial_delivery", Fail, 200.0, 1),
                    s("b", "partial_delivery", Fail, 50.0, 1),
                ],
                "partial",
                75.0,
            ),
        ];
        for (name, slaves, verdict, score) in cases {
            let (fleet, v, reason, sc) = roll_up_fleet(&slaves);
            assert_eq!(v, verdict, "{name}: {reason}");
            assert!((sc - score).abs() < 1e-9, "{name}: {sc}");
            assert!((0.0..=100.0).contains(&fleet.aggregate_score_pct), "{name}");
            assert!(
                (0.0..=100.0).contains(&fleet.frame_weighted_score_pct),
                "{name}"
            );
            if let Some(b) = &fleet.best {
                assert!(b.score_pct <= 100.0, "{name}");
            }
            assert_eq!(
                fleet.fully_correct,
                slaves.iter().filter(|x| x.outcome == Pass).count(),
                "{name}"
            );
        }
    }

    #[test]
    fn apply_run_status_table() {
        let ep = |state: &str, sent: u64| SelectedEndpoint {
            source_ip: rtu(2),
            listen_ip: None,
            listen_port: None,
            state: state.into(),
            cancelled: false,
            sent,
        };
        let info = |status, sent: Option<u64>, eps: Vec<SelectedEndpoint>| RunInfo {
            status,
            messages_sent: sent,
            endpoints: eps,
            ..Default::default()
        };
        use RunStatusHint as H;
        // (name, run, capture verdict, capture score, verdict, score, warned)
        let cases: Vec<(&str, RunInfo, &str, f64, &str, f64, bool)> = vec![
            (
                "clean run",
                info(H::Completed, Some(10), vec![]),
                "all_correct",
                100.0,
                "all_correct",
                100.0,
                false,
            ),
            (
                "clean partial",
                info(H::Completed, Some(10), vec![]),
                "partial",
                81.4,
                "partial",
                81.4,
                false,
            ),
            (
                "session errors",
                info(H::Partial, Some(10), vec![]),
                "all_correct",
                100.0,
                "all_correct",
                100.0,
                true,
            ),
            (
                "failed, matched",
                info(H::Failed, Some(10), vec![]),
                "all_correct",
                100.0,
                "run_failed",
                100.0,
                true,
            ),
            (
                "failed, partial",
                info(H::Failed, Some(10), vec![]),
                "partial",
                81.4,
                "run_failed",
                81.4,
                true,
            ),
            (
                "failed, failed",
                info(H::Failed, Some(10), vec![]),
                "failed",
                10.0,
                "run_failed",
                10.0,
                true,
            ),
            (
                "running",
                info(H::Running, Some(10), vec![]),
                "all_correct",
                100.0,
                "run_failed",
                100.0,
                true,
            ),
            // The T07b report: 0 messages sent, capture judged partial.
            (
                "sent 0, partial",
                info(H::Completed, Some(0), vec![]),
                "partial",
                81.4,
                "run_failed",
                0.0,
                true,
            ),
            (
                "stopped, sent 0",
                info(H::Stopped, Some(0), vec![]),
                "partial",
                81.4,
                "run_failed",
                0.0,
                true,
            ),
            (
                "failed, sent 0",
                info(H::Failed, Some(0), vec![]),
                "all_correct",
                100.0,
                "run_failed",
                0.0,
                true,
            ),
            (
                "every session failed before sending",
                info(H::Failed, None, vec![ep("failed", 0), ep("failed", 0)]),
                "partial",
                81.4,
                "run_failed",
                0.0,
                true,
            ),
            (
                "every session failed before sending, status unknown",
                info(H::Unknown, None, vec![ep("failed", 0), ep("failed", 0)]),
                "partial",
                81.4,
                "run_failed",
                0.0,
                true,
            ),
            (
                "one endpoint delivered",
                info(H::Unknown, None, vec![ep("failed", 0), ep("completed", 5)]),
                "partial",
                81.4,
                "partial",
                81.4,
                false,
            ),
        ];
        for (name, run, v0, s0, want_v, want_s, warned) in cases {
            let mut notes = Vec::new();
            let j = apply_run_status(&run, v0, "x".into(), s0, &mut notes);
            assert_eq!(j.verdict, want_v, "{name}");
            assert_eq!(j.score_pct, want_s, "{name}");
            assert_eq!(j.warning.is_some(), warned, "{name}");
            assert_eq!(notes.len(), usize::from(warned), "{name}");
            if want_s == 0.0 {
                assert!(
                    j.reason.contains("delivered nothing"),
                    "{name}: {}",
                    j.reason
                );
            }
        }
    }

    #[test]
    fn fleet_pacing_timeline_weights_decimated_endpoints() {
        // F136: endpoint A kept every sample, B was decimated 10:1.
        let mut details = BTreeMap::new();
        let mk = |samples: Vec<[f64; 2]>, w: f64| SlaveDetail {
            tcp_flow: None,
            sessions: Vec::new(),
            sessions_total: 0,
            protocol_specific: serde_json::Value::Null,
            verdict: "good_delivery",
            verdict_reason: String::new(),
            score_pct: 100.0,
            notes: Vec::new(),
            pacing_samples: samples,
            pacing_weight: w,
        };
        details.insert(
            "a".to_string(),
            mk((0..40_000).map(|i| [i as f64, 0.0]).collect(), 1.0),
        );
        details.insert(
            "b".to_string(),
            mk((0..4_000).map(|i| [i as f64 * 10.0, 1.0]).collect(), 10.0),
        );
        let t = build_fleet_pacing_timeline(&details, &[]).unwrap();
        assert_eq!(t.total_samples, 80_000);
        assert_eq!(t.samples.len(), MAX_FLEET_TIMELINE_POINTS);
        assert!(t.decimated);
        let b = t.samples.iter().filter(|p| p[1] == 1.0).count() as f64;
        let frac = b / t.samples.len() as f64;
        assert!((0.4..0.6).contains(&frac), "B share {frac}");
    }

    // ---------------- N11 regressions (re-audit reaudit_* probes) ----------------

    /// RTU .2 completed; RTU .3's session FAILED after 2 of 8 frames,
    /// then the operator stopped the run. The stop must not excuse the
    /// failed endpoint, and the fleet is never certified.
    #[test]
    fn reaudit_failed_session_in_stopped_run() {
        let source = source_pcap(&[2, 3]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        rtu_session(&mut cap, rtu(3), 2404, 50001, 0, &script()[..2]);
        let mut run = completed_run(&[2, 3]);
        run.status = RunStatusHint::Stopped;
        run.endpoints[1].state = "failed".into();
        run.endpoints[1].sent = 2;
        let r = run_analysis(&source, &cap.load(), run);
        let s = slave(&r, 3);
        assert_eq!(s.outcome, VerdictOutcome::Fail, "{s:?}");
        assert_ne!(s.verdict, "stopped_clean");
        assert!(s.score_pct < 100.0, "{s:?}");
        assert_eq!(slave(&r, 2).outcome, VerdictOutcome::Pass);
        assert_eq!(r.verdict, "partial", "{}", r.verdict_reason);
        assert_ne!(r.fleet.fully_correct, 2);
        assert!(r.run_warning.as_deref().unwrap().contains("STOPPED"));
        assert!(r.notes[0].starts_with("WARNING"), "{:?}", r.notes);
    }

    /// Same failure in an unbounded loop (which always ends on a stop).
    #[test]
    fn reaudit_failed_session_in_unbounded_loop() {
        let source = source_pcap(&[2, 3]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        rtu_session(&mut cap, rtu(3), 2404, 50001, 0, &script()[..2]);
        let mut run = completed_run(&[2, 3]);
        run.status = RunStatusHint::Partial;
        run.iterations = 0;
        run.loop_within_session = Some(true);
        run.endpoints[1].state = "failed".into();
        run.endpoints[1].sent = 2;
        let r = run_analysis(&source, &cap.load(), run);
        let s = slave(&r, 3);
        assert_eq!(s.outcome, VerdictOutcome::Fail, "{s:?}");
        assert!(s.score_pct < 100.0, "{s:?}");
        assert_ne!(r.verdict, "all_correct");
    }

    /// A finished run whose session failed midway.
    #[test]
    fn reaudit_completed_run_session_failed_midway() {
        let source = source_pcap(&[2, 3]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script());
        rtu_session(&mut cap, rtu(3), 2404, 50001, 0, &script()[..2]);
        let mut run = completed_run(&[2, 3]);
        run.status = RunStatusHint::Partial;
        run.endpoints[1].state = "failed".into();
        run.endpoints[1].sent = 2;
        let r = run_analysis(&source, &cap.load(), run);
        let s = slave(&r, 3);
        assert_eq!(s.outcome, VerdictOutcome::Fail, "{s:?}");
        assert!(s.score_pct < 100.0);
        assert_eq!(r.verdict, "partial");
    }

    /// A run stopped after one frame per RTU is clean up to the stop,
    /// but is reported as stopped with a warning, never `all_correct`.
    #[test]
    fn stopped_run_is_never_all_correct() {
        let source = source_pcap(&[2, 3]);
        let mut cap = Cap::default();
        rtu_session(&mut cap, rtu(2), 2404, 50000, 0, &script()[..1]);
        rtu_session(&mut cap, rtu(3), 2404, 50001, 0, &script()[..1]);
        let mut run = completed_run(&[2, 3]);
        run.status = RunStatusHint::Stopped;
        run.messages_sent = Some(2);
        for e in &mut run.endpoints {
            e.state = "cancelled".into();
            e.cancelled = true;
            e.sent = 1;
        }
        let r = run_analysis(&source, &cap.load(), run);
        assert_eq!(slave(&r, 2).verdict, "stopped_clean");
        assert_eq!(r.verdict, "stopped_clean", "{}", r.verdict_reason);
        assert!(r.verdict_reason.contains("stopped"));
        assert!(r.run_warning.as_deref().unwrap().contains("STOPPED"));
        assert!(r.notes[0].contains("STOPPED"), "{:?}", r.notes);
    }

    #[test]
    fn cp56_tolerance_is_bounded() {
        assert_eq!(check_cp56_tolerance(0.0), Ok(0.0));
        assert_eq!(check_cp56_tolerance(250.0), Ok(250.0));
        for bad in [-1.0, f64::NAN, f64::INFINITY, MAX_CP56_TOLERANCE_MS + 1.0] {
            assert!(check_cp56_tolerance(bad).is_err(), "{bad}");
        }
    }
}
