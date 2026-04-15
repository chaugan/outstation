//! Post-run analysis: compare a user-uploaded captured pcap against
//! the source pcap of a completed run.
//!
//! Produces a structured [`AnalysisReport`] with three sections:
//!
//! 1. **Playback side** — what pcapreplay was supposed to deliver.
//!    In master runs, that's the original client-side I-frames;
//!    in slave runs, the original server-side I-frames. The analyzer
//!    checks how many of them arrived at the wire in the captured
//!    pcap and diffs their Type IDs and ASDU bytes.
//!
//! 2. **Target side** — what the live target sent back. The analyzer
//!    classifies those frames (U/S/I counts, STARTDT/STOPDT
//!    handshake detection) and, in **correct mode**, diffs the
//!    target's I-frames against the original pcap's opposite side
//!    to flag deviations from the captured conversation.
//!
//! 3. **Timing** — original vs captured durations and per-bucket
//!    inter-frame gap statistics on the playback side, so the user
//!    can see if pacing mode worked as expected.

use std::collections::HashMap;
use std::path::Path;

use pcapload::{LoadedPcap, ReassembledFlow};
use proto_iec104::apdu::{Apdu, ApduReader, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT, U_TESTFR_CON};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    /// Target is a different software than the one in the pcap.
    /// We only care that pcapreplay's side delivered the expected
    /// frames and the target held up basic IEC 104 flow control.
    Generic,
    /// Target is the same device(s) as the original pcap. Expect the
    /// target's I-frames to match the original's opposite side
    /// byte-for-byte in type ID sequence.
    Correct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleHint {
    /// pcapreplay acted as the client (master).
    Master,
    /// pcapreplay acted as the server (slave).
    Slave,
}

#[derive(Serialize, Debug, Clone)]
pub struct AnalysisReport {
    pub run_id: u64,
    pub mode: &'static str,
    pub role: &'static str,
    pub original_pcap: String,
    pub captured_size_bytes: u64,
    pub captured_total_packets: usize,
    pub tcp_flow: Option<FlowInfo>,
    pub playback: PlaybackReport,
    pub target: TargetReport,
    pub timing: TimingReport,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub score_pct: f64,
    pub notes: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FlowInfo {
    pub client: String,
    pub server: String,
    pub packets: usize,
    pub state: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct PlaybackReport {
    pub direction: &'static str,
    pub expected_iframes: usize,
    pub delivered_iframes: usize,
    pub matched_type_ids: usize,
    pub type_id_sequence_match: bool,
    pub byte_identical_count: usize,
    pub missing_indices: Vec<usize>,
    pub mismatches: Vec<IFrameDiff>,
    pub expected_type_ids: Vec<u8>,
    pub delivered_type_ids: Vec<u8>,
}

#[derive(Serialize, Debug, Clone)]
pub struct IFrameDiff {
    pub index: usize,
    pub expected_type_id: u8,
    pub actual_type_id: u8,
    pub expected_asdu_hex: String,
    pub actual_asdu_hex: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct TargetReport {
    pub direction: &'static str,
    pub u_frames: usize,
    pub s_frames: usize,
    pub i_frames: usize,
    pub u_codes_seen: Vec<String>,
    pub startdt_handshake_ok: bool,
    pub target_type_ids: Vec<u8>,
    /// Only populated when mode == Correct. None in Generic mode.
    pub correctness: Option<CorrectnessCheck>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CorrectnessCheck {
    pub expected_iframes: usize,
    pub actual_iframes: usize,
    pub matched_type_id_prefix: usize,
    pub missing_tail: Vec<u8>,
    pub extra_tail: Vec<u8>,
    pub byte_identical_count: usize,
    pub total_mismatches: usize,
    /// Length of the longest common subsequence of Type IDs between
    /// what the original target sent and what the live target sent.
    /// A high LCS on small overlap means "same script, wrong subset";
    /// a low LCS on large overlap means "the target is running its
    /// own script entirely" (divergent).
    pub lcs_type_ids: usize,
    /// Fraction of the original script's type IDs the target also
    /// produced, in order, somewhere in its stream. `lcs / expected`.
    pub lcs_similarity: f64,
    /// The type-id sequence the **original** target (from the pcap)
    /// produced. Kept here so the UI can render a side-by-side
    /// comparison against `TargetReport::target_type_ids`.
    pub original_type_ids: Vec<u8>,
    /// Classification of the target's behavior. Populated only in
    /// correct mode.
    ///   `"same_script"`     — target replayed the captured script
    ///                         essentially verbatim.
    ///   `"subset"`          — target sent a proper prefix / subset
    ///                         of what the original did.
    ///   `"divergent"`       — target is clearly running its own
    ///                         script (LCS similarity < ~40%).
    ///                         Not an error, just a different peer.
    ///   `"silent"`          — target sent zero I-frames.
    pub target_script_kind: &'static str,
}

#[derive(Serialize, Debug, Clone)]
pub struct TimingReport {
    pub original_iframes: usize,
    pub captured_iframes: usize,
    pub original_duration_ms: f64,
    pub captured_duration_ms: f64,
    pub speedup_factor: f64,
    pub original_mean_gap_ms: f64,
    pub captured_mean_gap_ms: f64,
    pub original_p50_gap_ms: f64,
    pub captured_p50_gap_ms: f64,
    pub original_p99_gap_ms: f64,
    pub captured_p99_gap_ms: f64,
    pub original_gaps_ms: Vec<f64>,
    pub captured_gaps_ms: Vec<f64>,
}

/// Walk an APDU byte stream and return the I-frame bodies in order.
fn extract_iframes(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = ApduReader::new(payload);
    let mut out = Vec::new();
    loop {
        match reader.next_apdu() {
            Ok(Some(Apdu::I { asdu, .. })) => out.push(asdu),
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    out
}

/// Walk an APDU stream and return every frame kind with its U-code
/// (for U frames). Used to count and classify the target's replies.
fn classify_apdus(payload: &[u8]) -> (Vec<Apdu>, Vec<String>) {
    let mut reader = ApduReader::new(payload);
    let mut frames = Vec::new();
    let mut u_codes = Vec::new();
    loop {
        match reader.next_apdu() {
            Ok(Some(a)) => {
                if let Apdu::U { code } = a {
                    let name = match code {
                        U_STARTDT_ACT => "STARTDT_ACT",
                        U_STARTDT_CON => "STARTDT_CON",
                        U_STOPDT_ACT => "STOPDT_ACT",
                        U_STOPDT_CON => "STOPDT_CON",
                        U_TESTFR_ACT => "TESTFR_ACT",
                        U_TESTFR_CON => "TESTFR_CON",
                        _ => "U_OTHER",
                    };
                    u_codes.push(name.to_string());
                }
                frames.push(a);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    (frames, u_codes)
}

/// Compute inter-frame gaps (ms) between I-frames found in `payload`
/// by mapping each I-frame's start byte to its source packet's
/// timestamp through `flow.packet_offsets`.
fn iframe_gap_timings(flow: &ReassembledFlow) -> Vec<f64> {
    let payload = &flow.payload;
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 6 <= payload.len() {
        if payload[i] != 0x68 {
            i += 1;
            continue;
        }
        let ln = payload[i + 1] as usize;
        if i + 2 + ln > payload.len() {
            break;
        }
        let cf1 = payload[i + 2];
        if cf1 & 0x01 == 0 {
            starts.push(i);
        }
        i += 2 + ln;
    }
    if starts.len() < 2 {
        return Vec::new();
    }
    let ts: Vec<u64> = starts.iter().map(|&b| flow.ts_for_byte(b)).collect();
    let mut out = Vec::with_capacity(ts.len() - 1);
    for w in ts.windows(2) {
        out.push((w[1].saturating_sub(w[0])) as f64 / 1e6);
    }
    out
}

fn total_span_ms(gaps: &[f64]) -> f64 {
    gaps.iter().sum()
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

fn percentile(v: &[f64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    let idx = ((n as f64 - 1.0) * p).round() as usize;
    s[idx.min(n - 1)]
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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

/// Locate the captured flow that corresponds to the run's expected
/// target port (raw path), or any TCP flow on 2404 / `target_port`
/// whose server address matches the run's target. Returns the flow
/// index in `captured.flows` plus a `role` hint.
fn find_captured_flow(
    captured: &LoadedPcap,
    target_port: u16,
    role: RoleHint,
) -> Option<usize> {
    // Prefer an exact match on server_port == target_port. Multiple
    // flows may match (e.g., one per simulated RTU in slave mode);
    // return the first so the caller can compare against the most
    // interesting one.
    for (idx, flow) in captured.flows.iter().enumerate() {
        let Some((_, sp)) = flow.server else { continue };
        if sp == target_port {
            // Slave: we're the server side, so the flow's server
            // should be our listen address. Master: we're the client.
            let _ = role; // not used to narrow further for now.
            return Some(idx);
        }
    }
    // Fallback: a flow where any side port matches.
    for (idx, flow) in captured.flows.iter().enumerate() {
        if let Some((_, cp)) = flow.client {
            if cp == target_port {
                return Some(idx);
            }
        }
        if let Some((_, sp)) = flow.server {
            if sp == target_port {
                return Some(idx);
            }
        }
    }
    None
}

/// Pick the flow in the **original** pcap that pcapreplay was
/// replaying. In both roles it's the one whose `server.port` matches
/// `target_port`. When the captured session lands on a specific RTU
/// (slave mode, many listeners) or from a specific master
/// (master mode, many initiators), the caller passes that endpoint IP
/// as `server_ip_hint` so we pin on the right flow instead of
/// returning "whichever happened to land first in the flow index".
fn find_original_flow(
    original: &LoadedPcap,
    target_port: u16,
    server_ip_hint: Option<std::net::Ipv4Addr>,
) -> Option<usize> {
    if let Some(want) = server_ip_hint {
        for (idx, flow) in original.flows.iter().enumerate() {
            let Some((ip, sp)) = flow.server else { continue };
            if sp == target_port && ip == want {
                return Some(idx);
            }
        }
    }
    for (idx, flow) in original.flows.iter().enumerate() {
        let Some((_, sp)) = flow.server else { continue };
        if sp == target_port {
            return Some(idx);
        }
    }
    None
}

/// Core entry point. Loads both pcaps, picks the relevant flow, and
/// runs the comparison.
pub fn analyze(
    original_pcap_path: &Path,
    captured_pcap_path: &Path,
    run_id: u64,
    target_port: u16,
    role: RoleHint,
    mode: AnalysisMode,
) -> anyhow::Result<AnalysisReport> {
    use anyhow::Context;

    let original = pcapload::load(original_pcap_path).context("load original pcap")?;
    let captured = pcapload::load(captured_pcap_path).context("load captured pcap")?;
    let captured_size_bytes = std::fs::metadata(captured_pcap_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut notes: Vec<String> = Vec::new();

    // --- Captured pcap's relevant flow (picked FIRST so we can use
    //     its server IP to pin the original flow when the source pcap
    //     holds more than one RTU). ---
    let cap_flow_idx_opt = find_captured_flow(&captured, target_port, role);
    let cap_server_ip_hint = cap_flow_idx_opt
        .and_then(|idx| captured.flows.get(idx))
        .and_then(|f| f.server)
        .map(|(ip, _)| ip);

    // --- Original pcap's relevant flow, pinned to the captured
    //     session's server IP when one was observed. ---
    let orig_flow_idx = find_original_flow(&original, target_port, cap_server_ip_hint)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no flow in source pcap with server_port={target_port}; nothing to compare against"
            )
        })?;
    let orig_client = original
        .reassemble_client_payload(orig_flow_idx)
        .context("reassemble original client side")?;
    let orig_server = original
        .reassemble_server_payload(orig_flow_idx)
        .context("reassemble original server side")?;
    let orig_client_iframes = extract_iframes(&orig_client.payload);
    let orig_server_iframes = extract_iframes(&orig_server.payload);
    if let Some(hint) = cap_server_ip_hint {
        let picked = original.flows[orig_flow_idx].server.map(|(ip, _)| ip);
        if picked != Some(hint) {
            notes.push(format!(
                "source pcap has no flow for captured server {hint}; compared against \
                 first available flow with port {target_port} instead"
            ));
        }
    }

    // --- Captured pcap flow ---
    let cap_flow_idx = match cap_flow_idx_opt {
        Some(i) => i,
        None => {
            notes.push(format!(
                "no TCP flow in captured pcap with a port {target_port} endpoint \
                 — the session never reached the wire"
            ));
            // Return an early verdict with what we can.
            return Ok(AnalysisReport {
                run_id,
                mode: mode_str(mode),
                role: role_str(role),
                original_pcap: original_pcap_path.display().to_string(),
                captured_size_bytes,
                captured_total_packets: captured.packets.len(),
                tcp_flow: None,
                playback: empty_playback(role, &orig_client_iframes, &orig_server_iframes),
                target: TargetReport {
                    direction: target_direction(role),
                    u_frames: 0,
                    s_frames: 0,
                    i_frames: 0,
                    u_codes_seen: Vec::new(),
                    startdt_handshake_ok: false,
                    target_type_ids: Vec::new(),
                    correctness: None,
                },
                timing: TimingReport::default(),
                verdict: "no_session",
                verdict_reason: format!(
                    "captured pcap has no TCP flow on port {target_port}"
                ),
                score_pct: 0.0,
                notes,
            });
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

    // Figure out which side in the captured flow is pcapreplay's
    // playback and which is the target.
    let (playback_rf, target_rf) = match role {
        RoleHint::Master => {
            // pcapreplay was the client side
            (cap_client_rf.as_ref(), cap_server_rf.as_ref())
        }
        RoleHint::Slave => {
            // pcapreplay was the server side
            (cap_server_rf.as_ref(), cap_client_rf.as_ref())
        }
    };

    let expected_iframes = match role {
        RoleHint::Master => &orig_client_iframes,
        RoleHint::Slave => &orig_server_iframes,
    };
    let target_expected_iframes = match role {
        RoleHint::Master => &orig_server_iframes,
        RoleHint::Slave => &orig_client_iframes,
    };

    // --- Playback-side analysis ---
    let delivered_iframes: Vec<Vec<u8>> = playback_rf
        .map(|rf| extract_iframes(&rf.payload))
        .unwrap_or_default();

    let expected_tids: Vec<u8> = expected_iframes
        .iter()
        .map(|a| a.first().copied().unwrap_or(0))
        .collect();
    let delivered_tids: Vec<u8> = delivered_iframes
        .iter()
        .map(|a| a.first().copied().unwrap_or(0))
        .collect();

    // Sequence comparison: walk both in parallel, count matched TIDs
    // in order. Anything after the first mismatch is flagged.
    let mut matched_type_ids = 0usize;
    let mut byte_identical = 0usize;
    let mut mismatches: Vec<IFrameDiff> = Vec::new();
    let cmp_len = expected_tids.len().min(delivered_tids.len());
    for i in 0..cmp_len {
        if expected_tids[i] == delivered_tids[i] {
            matched_type_ids += 1;
            if expected_iframes[i] == delivered_iframes[i] {
                byte_identical += 1;
            } else {
                mismatches.push(IFrameDiff {
                    index: i,
                    expected_type_id: expected_tids[i],
                    actual_type_id: delivered_tids[i],
                    expected_asdu_hex: to_hex(&expected_iframes[i]),
                    actual_asdu_hex: to_hex(&delivered_iframes[i]),
                });
            }
        } else {
            mismatches.push(IFrameDiff {
                index: i,
                expected_type_id: expected_tids[i],
                actual_type_id: delivered_tids[i],
                expected_asdu_hex: to_hex(&expected_iframes[i]),
                actual_asdu_hex: to_hex(&delivered_iframes[i]),
            });
        }
    }
    let missing_indices: Vec<usize> = if delivered_tids.len() < expected_tids.len() {
        (delivered_tids.len()..expected_tids.len()).collect()
    } else {
        Vec::new()
    };

    let playback = PlaybackReport {
        direction: match role {
            RoleHint::Master => "master → server",
            RoleHint::Slave => "slave → master",
        },
        expected_iframes: expected_iframes.len(),
        delivered_iframes: delivered_iframes.len(),
        matched_type_ids,
        type_id_sequence_match: matched_type_ids == expected_tids.len()
            && matched_type_ids == delivered_tids.len(),
        byte_identical_count: byte_identical,
        missing_indices,
        mismatches,
        expected_type_ids: expected_tids,
        delivered_type_ids: delivered_tids,
    };

    // --- Target-side analysis ---
    let (target_frames, target_u_codes) = target_rf
        .map(|rf| classify_apdus(&rf.payload))
        .unwrap_or_default();
    let mut u_frames = 0usize;
    let mut s_frames = 0usize;
    let mut i_frames = 0usize;
    let mut target_iframes_body: Vec<Vec<u8>> = Vec::new();
    for f in &target_frames {
        match f {
            Apdu::U { .. } => u_frames += 1,
            Apdu::S { .. } => s_frames += 1,
            Apdu::I { asdu, .. } => {
                i_frames += 1;
                target_iframes_body.push(asdu.clone());
            }
        }
    }
    let target_tids: Vec<u8> = target_iframes_body
        .iter()
        .map(|a| a.first().copied().unwrap_or(0))
        .collect();

    // In slave role the target is a master and "correctly" it should
    // send STARTDT_ACT; in master role the target is a server and
    // should send STARTDT_CON.
    let startdt_handshake_ok = match role {
        RoleHint::Master => target_u_codes.iter().any(|c| c == "STARTDT_CON"),
        RoleHint::Slave => target_u_codes.iter().any(|c| c == "STARTDT_ACT"),
    };

    let correctness = if matches!(mode, AnalysisMode::Correct) {
        let target_expected_tids: Vec<u8> = target_expected_iframes
            .iter()
            .map(|a| a.first().copied().unwrap_or(0))
            .collect();
        let cmp = target_expected_tids.len().min(target_tids.len());
        let mut matched = 0usize;
        let mut byte_id = 0usize;
        let mut total_mm = 0usize;
        for i in 0..cmp {
            if target_expected_tids[i] == target_tids[i] {
                matched += 1;
                if target_expected_iframes[i] == target_iframes_body[i] {
                    byte_id += 1;
                } else {
                    total_mm += 1;
                }
            } else {
                total_mm += 1;
            }
        }
        let missing_tail = if target_tids.len() < target_expected_tids.len() {
            target_expected_tids[target_tids.len()..].to_vec()
        } else {
            Vec::new()
        };
        let extra_tail = if target_tids.len() > target_expected_tids.len() {
            target_tids[target_expected_tids.len()..].to_vec()
        } else {
            Vec::new()
        };

        // Longest common subsequence of the two type-ID streams.
        // Gives a much more honest read of "same conversation vs
        // different script" than the index-by-index prefix match.
        let lcs = lcs_length(&target_expected_tids, &target_tids);
        let similarity = if target_expected_tids.is_empty() {
            1.0
        } else {
            lcs as f64 / target_expected_tids.len() as f64
        };
        let kind = classify_script(&target_expected_tids, &target_tids, lcs, byte_id);

        Some(CorrectnessCheck {
            expected_iframes: target_expected_tids.len(),
            actual_iframes: target_tids.len(),
            matched_type_id_prefix: matched,
            missing_tail,
            extra_tail,
            byte_identical_count: byte_id,
            total_mismatches: total_mm,
            lcs_type_ids: lcs,
            lcs_similarity: similarity,
            original_type_ids: target_expected_tids.clone(),
            target_script_kind: kind,
        })
    } else {
        None
    };

    let target = TargetReport {
        direction: target_direction(role),
        u_frames,
        s_frames,
        i_frames,
        u_codes_seen: target_u_codes,
        startdt_handshake_ok,
        target_type_ids: target_tids,
        correctness,
    };

    // --- Timing analysis ---
    let orig_playback_flow = match role {
        RoleHint::Master => &orig_client,
        RoleHint::Slave => &orig_server,
    };
    let orig_gaps = iframe_gap_timings(orig_playback_flow);
    let cap_gaps = playback_rf
        .map(|rf| iframe_gap_timings(rf))
        .unwrap_or_default();
    let orig_dur = total_span_ms(&orig_gaps);
    let cap_dur = total_span_ms(&cap_gaps);
    let timing = TimingReport {
        original_iframes: expected_iframes.len(),
        captured_iframes: delivered_iframes.len(),
        original_duration_ms: orig_dur,
        captured_duration_ms: cap_dur,
        speedup_factor: if cap_dur > 0.0 {
            orig_dur / cap_dur
        } else {
            0.0
        },
        original_mean_gap_ms: mean(&orig_gaps),
        captured_mean_gap_ms: mean(&cap_gaps),
        original_p50_gap_ms: percentile(&orig_gaps, 0.5),
        captured_p50_gap_ms: percentile(&cap_gaps, 0.5),
        original_p99_gap_ms: percentile(&orig_gaps, 0.99),
        captured_p99_gap_ms: percentile(&cap_gaps, 0.99),
        original_gaps_ms: orig_gaps,
        captured_gaps_ms: cap_gaps,
    };

    // --- Verdict ---
    let (verdict, reason, score) = decide_verdict(&playback, &target, mode, &notes);

    Ok(AnalysisReport {
        run_id,
        mode: mode_str(mode),
        role: role_str(role),
        original_pcap: original_pcap_path.display().to_string(),
        captured_size_bytes,
        captured_total_packets: captured.packets.len(),
        tcp_flow: Some(flow_info),
        playback,
        target,
        timing,
        verdict,
        verdict_reason: reason,
        score_pct: score,
        notes,
    })
}

fn target_direction(role: RoleHint) -> &'static str {
    match role {
        RoleHint::Master => "server → master (target replies)",
        RoleHint::Slave => "master → slave (target commands)",
    }
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

fn empty_playback(role: RoleHint, orig_client: &[Vec<u8>], orig_server: &[Vec<u8>]) -> PlaybackReport {
    let expected = match role {
        RoleHint::Master => orig_client,
        RoleHint::Slave => orig_server,
    };
    let expected_tids: Vec<u8> = expected
        .iter()
        .map(|a| a.first().copied().unwrap_or(0))
        .collect();
    PlaybackReport {
        direction: match role {
            RoleHint::Master => "master → server",
            RoleHint::Slave => "slave → master",
        },
        expected_iframes: expected.len(),
        delivered_iframes: 0,
        matched_type_ids: 0,
        type_id_sequence_match: false,
        byte_identical_count: 0,
        missing_indices: (0..expected.len()).collect(),
        mismatches: Vec::new(),
        expected_type_ids: expected_tids,
        delivered_type_ids: Vec::new(),
    }
}

fn decide_verdict(
    pb: &PlaybackReport,
    tg: &TargetReport,
    mode: AnalysisMode,
    _notes: &[String],
) -> (&'static str, String, f64) {
    if pb.delivered_iframes == 0 {
        return (
            "no_delivery",
            "pcapreplay's side produced zero I-frames in the captured pcap".into(),
            0.0,
        );
    }
    let delivery_pct = if pb.expected_iframes > 0 {
        (pb.matched_type_ids as f64 / pb.expected_iframes as f64) * 100.0
    } else {
        100.0
    };

    if let Some(c) = &tg.correctness {
        let target_pct = if c.expected_iframes > 0 {
            (c.matched_type_id_prefix as f64 / c.expected_iframes as f64) * 100.0
        } else {
            100.0
        };

        // Strongest positive verdict: target replayed the same script
        // byte-for-byte.
        if c.matched_type_id_prefix == c.expected_iframes
            && c.actual_iframes == c.expected_iframes
            && pb.matched_type_ids == pb.expected_iframes
            && c.total_mismatches == 0
        {
            return (
                "identical",
                format!(
                    "every playback I-frame matched and target's {} I-frames matched the original byte-for-byte",
                    c.expected_iframes
                ),
                100.0,
            );
        }
        if pb.matched_type_ids == pb.expected_iframes && c.total_mismatches == 0 {
            let combined = (delivery_pct + target_pct) / 2.0;
            return (
                "structurally_identical",
                "type IDs match on both sides; byte-level diffs exist".into(),
                combined,
            );
        }

        // Differentiate "target ran its own script" (divergent) from
        // "target ran a subset/truncation of the original" (subset)
        // from "target produced noise at wrong indices" (partial).
        match c.target_script_kind {
            "silent" => {
                return (
                    "target_silent",
                    "target sent zero I-frames — only handshake and ACKs".into(),
                    delivery_pct.min(50.0),
                );
            }
            "divergent" => {
                return (
                    "divergent_script",
                    format!(
                        "target ran its own command script (type-id overlap {:.0}%, {} target i-frames vs {} original)",
                        c.lcs_similarity * 100.0,
                        c.actual_iframes,
                        c.expected_iframes
                    ),
                    delivery_pct,
                );
            }
            "subset" => {
                return (
                    "subset_script",
                    format!(
                        "target replayed a subset of the original script ({}/{} i-frames in order)",
                        c.lcs_type_ids, c.expected_iframes
                    ),
                    delivery_pct,
                );
            }
            _ => {}
        }

        let combined = (delivery_pct + target_pct) / 2.0;
        return (
            "partial",
            format!(
                "delivery {:.0}%, target correctness {:.0}%",
                delivery_pct, target_pct
            ),
            combined,
        );
    }

    // Generic mode: only judge delivery + handshake.
    if pb.matched_type_ids == pb.expected_iframes && tg.startdt_handshake_ok {
        let _ = mode;
        return (
            "good_delivery",
            format!(
                "all {} expected I-frames delivered; target completed STARTDT and ACKed as expected",
                pb.expected_iframes
            ),
            100.0,
        );
    }
    if pb.matched_type_ids > 0 && pb.matched_type_ids < pb.expected_iframes {
        return (
            "partial_delivery",
            format!(
                "{}/{} I-frames delivered",
                pb.matched_type_ids, pb.expected_iframes
            ),
            delivery_pct,
        );
    }
    if !tg.startdt_handshake_ok {
        return (
            "handshake_incomplete",
            "STARTDT handshake did not complete with the target".into(),
            delivery_pct.min(50.0),
        );
    }
    ("unknown", "analysis inconclusive".into(), delivery_pct)
}

impl Default for TimingReport {
    fn default() -> Self {
        Self {
            original_iframes: 0,
            captured_iframes: 0,
            original_duration_ms: 0.0,
            captured_duration_ms: 0.0,
            speedup_factor: 0.0,
            original_mean_gap_ms: 0.0,
            captured_mean_gap_ms: 0.0,
            original_p50_gap_ms: 0.0,
            captured_p50_gap_ms: 0.0,
            original_p99_gap_ms: 0.0,
            captured_p99_gap_ms: 0.0,
            original_gaps_ms: Vec::new(),
            captured_gaps_ms: Vec::new(),
        }
    }
}

// Unused hashmap helper kept to silence import warnings in future work.
#[allow(dead_code)]
fn _unused(_: HashMap<u8, u8>) {}

/// Length of the longest common subsequence of two `u8` streams.
/// Classic O(n·m) DP. Capped: we skip the LCS if either side is
/// larger than 4096 frames to keep UI latency sane on huge pcaps.
pub fn lcs_length(a: &[u8], b: &[u8]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    if a.len() > 4096 || b.len() > 4096 {
        // Fall back to a linear heuristic: count how many of a's type
        // IDs also appear in b, in order. Looser but cheap.
        let mut j = 0usize;
        let mut matches = 0usize;
        for &x in a {
            while j < b.len() && b[j] != x {
                j += 1;
            }
            if j < b.len() {
                matches += 1;
                j += 1;
            }
        }
        return matches;
    }
    let m = a.len();
    let n = b.len();
    let mut prev = vec![0usize; n + 1];
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j].max(curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        for c in curr.iter_mut() {
            *c = 0;
        }
    }
    prev[n]
}

/// Classify the target's script against the original.
///
/// The key dimensions:
///   * `actual == 0`      → silent
///   * byte_identical_count == expected → same script
///   * lcs / expected >= 0.8            → same script
///   * lcs / expected >= 0.4 and actual < expected → subset
///   * otherwise → divergent (target is running its own show)
pub fn classify_script(
    expected: &[u8],
    actual: &[u8],
    lcs: usize,
    byte_identical: usize,
) -> &'static str {
    if actual.is_empty() {
        return "silent";
    }
    if expected.is_empty() {
        return "divergent";
    }
    if byte_identical == expected.len() && actual.len() == expected.len() {
        return "same_script";
    }
    let similarity = lcs as f64 / expected.len() as f64;
    if similarity >= 0.8 {
        return "same_script";
    }
    if similarity >= 0.4 && actual.len() <= expected.len() {
        return "subset";
    }
    "divergent"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcs_basic() {
        assert_eq!(lcs_length(&[1, 2, 3], &[1, 2, 3]), 3);
        assert_eq!(lcs_length(&[1, 2, 3], &[1, 3]), 2);
        assert_eq!(lcs_length(&[1, 2, 3], &[4, 5, 6]), 0);
        assert_eq!(lcs_length(&[], &[1, 2]), 0);
        assert_eq!(lcs_length(&[1, 100, 3, 100, 5], &[100, 100]), 2);
    }

    #[test]
    fn classify_same_script() {
        let orig = vec![70, 100, 1, 3, 5];
        let same = vec![70, 100, 1, 3, 5];
        let lcs = lcs_length(&orig, &same);
        assert_eq!(classify_script(&orig, &same, lcs, 5), "same_script");
    }

    #[test]
    fn classify_subset() {
        let orig = vec![70, 100, 1, 3, 5, 7, 9, 11, 13, 30];
        let subset = vec![70, 100, 1, 3, 5]; // strict prefix
        let lcs = lcs_length(&orig, &subset);
        assert_eq!(classify_script(&orig, &subset, lcs, 0), "subset");
    }

    #[test]
    fn classify_divergent() {
        // redisant client case: 16 expected commands, 2 actual.
        let orig = vec![45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46];
        let actual = vec![100, 101]; // C_IC_NA_1 + C_CI_NA_1
        let lcs = lcs_length(&orig, &actual);
        assert_eq!(classify_script(&orig, &actual, lcs, 0), "divergent");
    }

    #[test]
    fn classify_silent() {
        let orig = vec![1, 2, 3];
        let actual: Vec<u8> = vec![];
        assert_eq!(classify_script(&orig, &actual, 0, 0), "silent");
    }
}
