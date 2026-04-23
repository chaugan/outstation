//! Post-run analysis shell: compare a user-uploaded captured pcap
//! against the source pcap of a completed run.
//!
//! The shell is protocol-agnostic. It handles pcap loading, slave IP
//! enumeration, flow picking, fleet rollup, iteration-boundary
//! detection, and fleet-level pacing timeline construction — all
//! generic concepts — then delegates the per-slave protocol analysis
//! (playback vs target diff, handshake detection, drift measurement,
//! timing stats) to the selected [`protoplay::ProtoReplayer`] via its
//! [`analyze_flow`](protoplay::ProtoReplayer::analyze_flow) method.
//!
//! The protocol-specific detail lands inside
//! `SlaveDetail.protocol_specific` as a JSON value rendered by the
//! matching proto crate's UI fragment (see `static/*.js`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::Path;

use pcapload::{LoadedPcap, ReassembledFlow};
use protoplay::{AnalyzeCtx, FleetDriftTimeline, FlowSnapshot, ProtoReplayer, Role};
use serde::Serialize;

/// Default tolerance for the CP56Time2a drift analyzer: 50 ms is
/// generous for a LAN SCADA session but keeps noise out of the count.
pub const DEFAULT_CP56_TOLERANCE_MS: f64 = 50.0;

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

#[derive(Serialize, Debug, Clone)]
pub struct AnalysisReport {
    pub run_id: u64,
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
    /// Fleet-wide pacing drift — `None` when no slave delivered any
    /// messages in both pcaps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_pacing_timeline: Option<FleetPacingTimeline>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FleetSummary {
    pub slave_count: usize,
    pub attempted: usize,
    pub not_attempted: usize,
    pub fully_correct: usize,
    pub partial: usize,
    pub failed: usize,
    pub aggregate_score_pct: f64,
    pub best: Option<BestWorst>,
    pub worst: Option<BestWorst>,
}

#[derive(Serialize, Debug, Clone)]
pub struct BestWorst {
    pub slave_ip: String,
    pub score_pct: f64,
}

#[derive(Serialize, Debug, Clone)]
pub struct SlaveSummary {
    pub slave_ip: String,
    pub score_pct: f64,
    pub verdict: &'static str,
    pub verdict_reason: String,
    /// Expected protocol messages (IEC 104: I-frames; Modbus: PDUs).
    pub expected_iframes: usize,
    /// Delivered protocol messages on the wire.
    pub delivered_iframes: usize,
    pub packets: usize,
    /// Protocol-level handshake flag. For IEC 104 this is STARTDT.
    pub startdt_handshake_ok: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct SlaveDetail {
    pub tcp_flow: Option<FlowInfo>,
    /// Protocol-specific drill-down produced by the replayer's
    /// [`analyze_flow`](protoplay::ProtoReplayer::analyze_flow). The
    /// matching UI renderer in `static/<proto>_ui.js` walks this blob.
    pub protocol_specific: serde_json::Value,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub score_pct: f64,
    pub notes: Vec<String>,
    /// Per-message pacing-drift samples `[capture_wall_ms, drift_ms]`
    /// surfaced at the top level so the core can aggregate them into a
    /// protocol-agnostic fleet pacing timeline. The same series is also
    /// available inside `protocol_specific` for per-slave rendering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pacing_samples: Vec<[f64; 2]>,
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

/// Cap on points emitted in the fleet timelines. Aggregate stats stay
/// accurate beyond this; only the scatter is trimmed.
pub const MAX_FLEET_TIMELINE_POINTS: usize = 5_000;

#[derive(Serialize, Debug, Clone)]
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

/// Pick the **busiest** captured flow for a given (server_ip, port).
/// "Busiest" = most TCP packets. Ranking by packets fixes the case
/// where a stale 10-packet FIN-only flow shadows the real working
/// session that carries thousands of packets.
fn find_busiest_captured_flow(
    captured: &LoadedPcap,
    server_ip: Ipv4Addr,
    target_port: u16,
) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (idx, flow) in captured.flows.iter().enumerate() {
        let Some((ip, sp)) = flow.server else { continue };
        if sp != target_port || ip != server_ip {
            continue;
        }
        let pkts = flow.packet_indices.len();
        if best.map_or(true, |(_, p)| pkts > p) {
            best = Some((idx, pkts));
        }
    }
    best.map(|(idx, _)| idx)
}

/// Auto-detect the master IP: unique client IP across all flows whose
/// server port matches `target_port`. When multiple distinct clients
/// exist, returns the busiest one (most flows).
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
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(ip, _)| ip)
}

fn list_slave_ips(p: &LoadedPcap, target_port: u16) -> BTreeSet<Ipv4Addr> {
    let mut ips: BTreeSet<Ipv4Addr> = BTreeSet::new();
    for flow in &p.flows {
        if let Some((ip, sp)) = flow.server {
            if sp == target_port {
                ips.insert(ip);
            }
        }
    }
    ips
}

fn find_original_flow_for_slave(
    original: &LoadedPcap,
    slave_ip: Ipv4Addr,
    target_port: u16,
) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (idx, flow) in original.flows.iter().enumerate() {
        let Some((ip, sp)) = flow.server else { continue };
        if sp != target_port || ip != slave_ip {
            continue;
        }
        let pkts = flow.packet_indices.len();
        if best.map_or(true, |(_, p)| pkts > p) {
            best = Some((idx, pkts));
        }
    }
    best.map(|(idx, _)| idx)
}

/// Core entry point. Loads both pcaps, enumerates every slave
/// (server-port == target_port) in the original pcap, runs a per-slave
/// comparison via the replayer's `analyze_flow`, and rolls the per-
/// slave outcomes up into a fleet report.
pub fn analyze(
    replayer: &dyn ProtoReplayer,
    original_pcap_path: &Path,
    captured_pcap_path: &Path,
    run_id: u64,
    target_port: u16,
    role: RoleHint,
    mode: AnalysisMode,
    proto_config: Option<String>,
    cp56_tolerance_ms: f64,
) -> anyhow::Result<AnalysisReport> {
    use anyhow::Context;

    let original = pcapload::load(original_pcap_path).context("load original pcap")?;
    let captured = pcapload::load(captured_pcap_path).context("load captured pcap")?;
    let captured_size_bytes = std::fs::metadata(captured_pcap_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut fleet_notes: Vec<String> = Vec::new();

    let captured_master_ip = detect_master_ip(&original, target_port);
    let live_master_ip = detect_master_ip(&captured, target_port);
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
    if renamed {
        fleet_notes.push(format!(
            "master IP renamed: captured={} live={}",
            captured_master_ip.unwrap(),
            live_master_ip.unwrap()
        ));
    }

    // Slave list strategy: prefer the captured pcap's slave set
    // (those are the RTUs the run actually attempted — matches the
    // run-config "select RTUs" picker subset). Fall back to the
    // source-pcap set only when the captured pcap has no slave-side
    // traffic at all (e.g. capture started after the run finished or
    // every session bailed pre-handshake) — in that case we still
    // want to see what the source expected so the analysis isn't
    // empty.
    let source_slave_ips: BTreeSet<Ipv4Addr> = list_slave_ips(&original, target_port);
    let captured_slave_ips: BTreeSet<Ipv4Addr> = list_slave_ips(&captured, target_port);
    let slave_ips: BTreeSet<Ipv4Addr> = if !captured_slave_ips.is_empty() {
        captured_slave_ips.clone()
    } else {
        source_slave_ips.clone()
    };
    if slave_ips.is_empty() {
        return Err(anyhow::anyhow!(
            "no flow in source pcap with server_port={target_port}; nothing to compare against"
        ));
    }
    let dropped = source_slave_ips.len().saturating_sub(slave_ips.len());
    if dropped > 0 {
        fleet_notes.push(format!(
            "{} of {} captured-pcap RTUs not attempted in this run; only the {} replayed RTU(s) are listed below",
            dropped,
            source_slave_ips.len(),
            slave_ips.len()
        ));
    }

    let ctx = AnalyzeCtx {
        role: role.as_role(),
        mode_correct: matches!(mode, AnalysisMode::Correct),
        captured_first_ts_ns: captured.first_ts_ns,
        target_port,
        proto_config,
        cp56_tolerance_ms,
    };

    let mut summaries: Vec<SlaveSummary> = Vec::new();
    let mut details: BTreeMap<String, SlaveDetail> = BTreeMap::new();
    for ip in &slave_ips {
        match analyze_one_slave(replayer, &original, &captured, *ip, target_port, role, &ctx) {
            Ok((summary, detail)) => {
                summaries.push(summary);
                details.insert(ip.to_string(), detail);
            }
            Err(e) => {
                fleet_notes.push(format!("slave {ip}: skipped ({e})"));
            }
        }
    }

    summaries.sort_by(|a, b| {
        a.score_pct
            .partial_cmp(&b.score_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.slave_ip.cmp(&b.slave_ip))
    });

    let (fleet, verdict, verdict_reason, score_pct) = roll_up_fleet(&summaries);

    let iteration_starts_ms =
        detect_iteration_starts(&captured, target_port, fleet.slave_count);

    // Fleet-wide drift timeline is protocol-driven: the replayer pulls
    // whatever drift series it cares about from each slave's
    // protocol_specific JSON.
    let per_slave_proto: BTreeMap<String, serde_json::Value> = details
        .iter()
        .map(|(ip, d)| (ip.clone(), d.protocol_specific.clone()))
        .collect();
    let fleet_drift_timeline =
        replayer.aggregate_fleet_drift(&per_slave_proto, &iteration_starts_ms);

    let fleet_pacing_timeline =
        build_fleet_pacing_timeline(&details, &iteration_starts_ms);

    Ok(AnalysisReport {
        run_id,
        mode: mode_str(mode),
        role: role_str(role),
        protocol: replayer.name(),
        original_pcap: original_pcap_path.display().to_string(),
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

/// Walk each slave's pacing samples, merge into one time-sorted
/// timeline, and decimate. Protocol-agnostic — every protocol that
/// returns a `ProtoSlaveAnalysis::pacing_samples` participates.
fn build_fleet_pacing_timeline(
    details: &BTreeMap<String, SlaveDetail>,
    iteration_starts_ms: &[f64],
) -> Option<FleetPacingTimeline> {
    let mut all: Vec<(f64, f64)> = Vec::new();
    for d in details.values() {
        for s in &d.pacing_samples {
            all.push((s[0], s[1]));
        }
    }
    if all.is_empty() {
        return None;
    }
    let total_samples = all.len();
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    let decimated = total_samples > MAX_FLEET_TIMELINE_POINTS;
    let kept: Vec<[f64; 2]> = if decimated {
        let stride = (total_samples + MAX_FLEET_TIMELINE_POINTS - 1) / MAX_FLEET_TIMELINE_POINTS;
        all.iter().step_by(stride).map(|&(t, d)| [t, d]).collect()
    } else {
        all.iter().map(|&(t, d)| [t, d]).collect()
    };

    Some(FleetPacingTimeline {
        samples: kept,
        total_samples,
        decimated,
        iteration_starts_ms: iteration_starts_ms.to_vec(),
    })
}

/// Detect iteration boundaries by clustering TCP SYN packets to the
/// target port. Each benchmark iteration triggers a tight burst of
/// handshakes, so we bin SYNs by 1-second windows and flag bins that
/// contain at least 30 % of the expected slave count. Adjacent flagged
/// bins coalesce into a single iteration start.
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

/// Run the single-slave comparison shell: pick the original flow for
/// this slave IP, pick the busiest captured flow for the same IP,
/// delegate the actual protocol analysis to `replayer.analyze_flow`,
/// and stitch a SlaveSummary + SlaveDetail from the result.
fn analyze_one_slave(
    replayer: &dyn ProtoReplayer,
    original: &LoadedPcap,
    captured: &LoadedPcap,
    slave_ip: Ipv4Addr,
    target_port: u16,
    role: RoleHint,
    ctx: &AnalyzeCtx,
) -> anyhow::Result<(SlaveSummary, SlaveDetail)> {
    use anyhow::Context;

    let mut notes: Vec<String> = Vec::new();
    let slave_ip_str = slave_ip.to_string();

    // Original-side reassembly. Skip if the original pcap has no flow
    // for this slave (orphan: slave seen in captured but not original).
    let orig_flow_idx_opt = find_original_flow_for_slave(original, slave_ip, target_port);
    let (orig_client, orig_server) = if let Some(orig_idx) = orig_flow_idx_opt {
        let oc = original
            .reassemble_client_payload(orig_idx)
            .context("reassemble original client side")?;
        let os = original
            .reassemble_server_payload(orig_idx)
            .context("reassemble original server side")?;
        (Some(oc), Some(os))
    } else {
        notes.push(format!(
            "slave {slave_ip} appears in captured pcap but not in source — \
             nothing to compare against"
        ));
        (None, None)
    };

    // Captured-side flow (busiest match).
    let cap_flow_idx_opt = find_busiest_captured_flow(captured, slave_ip, target_port);
    let cap_flow_idx = match cap_flow_idx_opt {
        Some(i) => i,
        None => {
            notes.push(format!(
                "slave {slave_ip}: no TCP flow in captured pcap on port {target_port}"
            ));
            // Still call analyze_flow with no captured flows — the
            // protocol's impl will produce a "not_attempted"-shaped
            // report. Passing original lets it at least record the
            // expected message count.
            let (orig_pb, orig_tg) = pick_playback_target(role, orig_client.as_ref(), orig_server.as_ref());
            let analysis = replayer.analyze_flow(
                orig_pb.map(snapshot),
                None,
                orig_tg.map(snapshot),
                None,
                ctx,
            );
            let verdict_reason = format!(
                "no TCP flow on port {target_port} for slave {slave_ip} in captured pcap"
            );
            let detail = SlaveDetail {
                tcp_flow: None,
                protocol_specific: analysis.protocol_specific,
                verdict: "not_attempted",
                verdict_reason: verdict_reason.clone(),
                score_pct: 0.0,
                notes: {
                    let mut n = notes.clone();
                    n.extend(analysis.notes);
                    n
                },
                pacing_samples: analysis.pacing_samples,
            };
            let summary = SlaveSummary {
                slave_ip: slave_ip_str,
                score_pct: 0.0,
                verdict: "not_attempted",
                verdict_reason,
                expected_iframes: analysis.expected_messages,
                delivered_iframes: 0,
                packets: 0,
                startdt_handshake_ok: false,
            };
            return Ok((summary, detail));
        }
    };
    let cap_flow = &captured.flows[cap_flow_idx];
    let flow_info = FlowInfo {
        client: cap_flow
            .client
            .map(|(ip, p)| format!("{ip}:{p}"))
            .unwrap_or_else(|| "?".into()),
        server: cap_flow
            .server
            .map(|(ip, p)| format!("{ip}:{p}"))
            .unwrap_or_else(|| "?".into()),
        packets: cap_flow.packet_indices.len(),
        state: flow_state_label(cap_flow),
    };

    let cap_client_rf = captured.reassemble_client_payload(cap_flow_idx).ok();
    let cap_server_rf = captured.reassemble_server_payload(cap_flow_idx).ok();

    let (orig_pb, orig_tg) = pick_playback_target(role, orig_client.as_ref(), orig_server.as_ref());
    let (cap_pb, cap_tg) =
        pick_playback_target(role, cap_client_rf.as_ref(), cap_server_rf.as_ref());

    let analysis = replayer.analyze_flow(
        orig_pb.map(snapshot),
        cap_pb.map(snapshot),
        orig_tg.map(snapshot),
        cap_tg.map(snapshot),
        ctx,
    );

    let mut all_notes = notes;
    all_notes.extend(analysis.notes);

    let summary = SlaveSummary {
        slave_ip: slave_ip_str,
        score_pct: analysis.score_pct,
        verdict: analysis.verdict,
        verdict_reason: analysis.verdict_reason.clone(),
        expected_iframes: analysis.expected_messages,
        delivered_iframes: analysis.delivered_messages,
        packets: flow_info.packets,
        startdt_handshake_ok: analysis.handshake_ok,
    };
    let detail = SlaveDetail {
        tcp_flow: Some(flow_info),
        protocol_specific: analysis.protocol_specific,
        verdict: analysis.verdict,
        verdict_reason: analysis.verdict_reason,
        score_pct: analysis.score_pct,
        notes: all_notes,
        pacing_samples: analysis.pacing_samples,
    };
    Ok((summary, detail))
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

fn roll_up_fleet(
    slaves: &[SlaveSummary],
) -> (FleetSummary, &'static str, String, f64) {
    let slave_count = slaves.len();
    let attempted = slaves.iter().filter(|s| s.packets > 0).count();
    let not_attempted = slave_count.saturating_sub(attempted);
    let fully_correct = slaves
        .iter()
        .filter(|s| s.packets > 0 && s.score_pct >= 99.999)
        .count();
    let failed = slaves
        .iter()
        .filter(|s| s.packets > 0 && s.score_pct == 0.0)
        .count();
    let partial = attempted
        .saturating_sub(fully_correct)
        .saturating_sub(failed);

    let attempted_scores: Vec<f64> = slaves
        .iter()
        .filter(|s| s.packets > 0)
        .map(|s| s.score_pct)
        .collect();
    let aggregate_score_pct = if attempted_scores.is_empty() {
        0.0
    } else {
        attempted_scores.iter().sum::<f64>() / attempted_scores.len() as f64
    };

    let best = slaves
        .iter()
        .filter(|s| s.packets > 0)
        .max_by(|a, b| {
            a.score_pct
                .partial_cmp(&b.score_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|s| BestWorst {
            slave_ip: s.slave_ip.clone(),
            score_pct: s.score_pct,
        });
    let worst = slaves
        .iter()
        .filter(|s| s.packets > 0)
        .min_by(|a, b| {
            a.score_pct
                .partial_cmp(&b.score_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|s| BestWorst {
            slave_ip: s.slave_ip.clone(),
            score_pct: s.score_pct,
        });

    let summary = FleetSummary {
        slave_count,
        attempted,
        not_attempted,
        fully_correct,
        partial,
        failed,
        aggregate_score_pct,
        best,
        worst,
    };

    let (verdict, reason): (&'static str, String) = if slave_count == 0 {
        ("no_session", "no slaves in source pcap".into())
    } else if attempted == 0 {
        (
            "no_delivery",
            format!("none of {} slaves reached the wire", slave_count),
        )
    } else if failed == 0 && partial == 0 && fully_correct == attempted && not_attempted == 0 {
        (
            "all_correct",
            format!("all {} slaves replayed correctly", attempted),
        )
    } else if failed == attempted {
        (
            "failed",
            format!(
                "all {} attempted slaves produced 0 messages",
                attempted
            ),
        )
    } else {
        let na_tail = if not_attempted > 0 {
            format!(", {} not attempted", not_attempted)
        } else {
            String::new()
        };
        (
            "partial",
            format!(
                "{}/{} slaves replayed correctly; {} partial, {} failed{}",
                fully_correct, attempted, partial, failed, na_tail
            ),
        )
    };

    (summary, verdict, reason, aggregate_score_pct)
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
