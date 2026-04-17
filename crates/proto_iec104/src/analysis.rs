//! IEC 60870-5-104 post-run analyzer.
//!
//! Compares an original (captured) pcap's client/server flows against a
//! replay's client/server flows for one RTU and produces:
//!
//! * **Playback side** — what outstation was expected to deliver:
//!   matched type IDs, ASDU-byte-level diff classified three ways
//!   (identical / cp56-only / real deviation), missing-tail indices.
//! * **Target side** — what the live peer sent back: U/S/I frame
//!   counts, STARTDT handshake detection, optional "correct mode"
//!   target-script comparison (LCS / subset / divergent).
//! * **Timing** — per-I-frame inter-frame gap stats and per-frame
//!   pacing-drift samples.
//! * **CP56Time2a drift** — when the run rewrote timestamps to the
//!   wire-send moment, compares each captured stamp to its actual
//!   wire-send time and produces per-sample + aggregate drift stats.
//!
//! This module is called by [`crate::Iec104Replayer::analyze_flow`]
//! via the generic [`protoplay::ProtoReplayer`] trait, so the webui
//! shell stays protocol-agnostic.

use std::collections::BTreeMap;

use protoplay::{
    AnalyzeCtx, FleetDriftTimeline, FlowSnapshot, ProtoSlaveAnalysis, Role,
};
use serde::Serialize;
use serde_json::json;

use crate::apdu::{
    Apdu, ApduReader, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT,
    U_TESTFR_CON,
};
use crate::asdu::{
    cp56_offset_in_element, decode_cp56time2a, decode_cp56time2a_local, element_len, vsq,
    Cp56Zone, Iec104ProtoConfig, DUI_LEN, IOA_LEN,
};

/// Cap on points emitted in the fleet drift timeline. Aggregates
/// (mean / p99) stay accurate beyond this; only the scatter is trimmed.
pub const MAX_FLEET_TIMELINE_POINTS: usize = 5_000;

/// Cap on the per-frame drift sample arrays. A 50k-frame run × 8 B per
/// f64 + 4 B index + 1 B type ≈ 650 KB raw, ~250 KB after JSON.
/// Aggregates stay accurate beyond this cap; we just stop emitting
/// individual samples.
pub const MAX_DRIFT_SAMPLES: usize = 50_000;

#[derive(Serialize, Debug, Clone)]
pub struct PlaybackReport {
    pub direction: &'static str,
    pub expected_iframes: usize,
    pub delivered_iframes: usize,
    pub matched_type_ids: usize,
    pub type_id_sequence_match: bool,
    pub byte_identical_count: usize,
    #[serde(default)]
    pub cp56_only_count: usize,
    #[serde(default)]
    pub real_mismatch_count: usize,
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
    #[serde(default)]
    pub cp56_only_count: usize,
    pub total_mismatches: usize,
    pub lcs_type_ids: usize,
    pub lcs_similarity: f64,
    pub original_type_ids: Vec<u8>,
    pub target_script_kind: &'static str,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct Cp56DriftReport {
    pub samples: usize,
    pub iframes_with_cp56: usize,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub out_of_tolerance: usize,
    pub tolerance_ms: f64,
    pub mean_signed_ms: f64,
    pub invalid_flag_count: usize,
    pub summer_flag_count: usize,
    #[serde(default)]
    pub drift_samples_ms: Vec<f64>,
    #[serde(default)]
    pub sample_frame_indices: Vec<u32>,
    #[serde(default)]
    pub sample_type_ids: Vec<u8>,
    #[serde(default)]
    pub sample_wall_ms: Vec<f64>,
    #[serde(default)]
    pub samples_truncated: bool,
}

#[derive(Serialize, Debug, Clone, Default)]
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
    #[serde(default)]
    pub pacing_samples: Vec<[f64; 2]>,
}

/// Entry point for [`crate::Iec104Replayer::analyze_flow`].
///
/// Returns a [`ProtoSlaveAnalysis`] with IEC 104-specific detail packed
/// inside `protocol_specific` and the common fields (score, verdict,
/// expected/delivered counts, handshake flag, pacing samples) surfaced
/// so the webui core can roll them into the fleet summary without
/// protocol knowledge.
pub fn analyze_iec104_flow(
    orig_playback: Option<FlowSnapshot>,
    cap_playback: Option<FlowSnapshot>,
    orig_target: Option<FlowSnapshot>,
    cap_target: Option<FlowSnapshot>,
    ctx: &AnalyzeCtx,
) -> ProtoSlaveAnalysis {
    let cp56_cfg = Iec104ProtoConfig::parse(ctx.proto_config.as_deref()).cp56;
    let rewrite_cp56_was_on = cp56_cfg.rewrite_to_now;
    let cp56_zone = Cp56Zone::parse(&cp56_cfg.zone).unwrap_or(Cp56Zone::Local);

    let mut notes: Vec<String> = Vec::new();

    // --- Playback-side analysis ---
    let expected_iframes: Vec<Vec<u8>> = orig_playback
        .as_ref()
        .map(|rf| extract_iframes(rf.payload))
        .unwrap_or_default();
    let delivered_iframes: Vec<Vec<u8>> = cap_playback
        .as_ref()
        .map(|rf| extract_iframes(rf.payload))
        .unwrap_or_default();

    let expected_tids: Vec<u8> = expected_iframes
        .iter()
        .map(|a| a.first().copied().unwrap_or(0))
        .collect();
    let delivered_tids: Vec<u8> = delivered_iframes
        .iter()
        .map(|a| a.first().copied().unwrap_or(0))
        .collect();

    let mut matched_type_ids = 0usize;
    let mut byte_identical = 0usize;
    let mut cp56_only = 0usize;
    let mut mismatches: Vec<IFrameDiff> = Vec::new();
    let cmp_len = expected_tids.len().min(delivered_tids.len());
    for i in 0..cmp_len {
        if expected_tids[i] == delivered_tids[i] {
            matched_type_ids += 1;
            match compare_asdu(&expected_iframes[i], &delivered_iframes[i]) {
                AsduCmp::Identical => byte_identical += 1,
                AsduCmp::Cp56Only => cp56_only += 1,
                AsduCmp::Different => mismatches.push(IFrameDiff {
                    index: i,
                    expected_type_id: expected_tids[i],
                    actual_type_id: delivered_tids[i],
                    expected_asdu_hex: to_hex(&expected_iframes[i]),
                    actual_asdu_hex: to_hex(&delivered_iframes[i]),
                }),
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
    let real_mismatch_count = mismatches.len();
    let missing_indices: Vec<usize> = if delivered_tids.len() < expected_tids.len() {
        (delivered_tids.len()..expected_tids.len()).collect()
    } else {
        Vec::new()
    };

    let playback = PlaybackReport {
        direction: match ctx.role {
            Role::Master => "master → server",
            Role::Slave => "slave → master",
        },
        expected_iframes: expected_iframes.len(),
        delivered_iframes: delivered_iframes.len(),
        matched_type_ids,
        type_id_sequence_match: matched_type_ids == expected_tids.len()
            && matched_type_ids == delivered_tids.len(),
        byte_identical_count: byte_identical,
        cp56_only_count: cp56_only,
        real_mismatch_count,
        missing_indices,
        mismatches,
        expected_type_ids: expected_tids.clone(),
        delivered_type_ids: delivered_tids.clone(),
    };

    // --- Target-side analysis ---
    let (target_frames, target_u_codes) = cap_target
        .as_ref()
        .map(|rf| classify_apdus(rf.payload))
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

    // In slave role the target is a master and should send STARTDT_ACT;
    // in master role the target is a server and should send STARTDT_CON.
    let startdt_handshake_ok = match ctx.role {
        Role::Master => target_u_codes.iter().any(|c| c == "STARTDT_CON"),
        Role::Slave => target_u_codes.iter().any(|c| c == "STARTDT_ACT"),
    };

    let target_expected_iframes: Vec<Vec<u8>> = orig_target
        .as_ref()
        .map(|rf| extract_iframes(rf.payload))
        .unwrap_or_default();

    let correctness = if ctx.mode_correct {
        let target_expected_tids: Vec<u8> = target_expected_iframes
            .iter()
            .map(|a| a.first().copied().unwrap_or(0))
            .collect();
        let cmp = target_expected_tids.len().min(target_tids.len());
        let mut matched = 0usize;
        let mut byte_id = 0usize;
        let mut cp56_only_t = 0usize;
        let mut total_mm = 0usize;
        for i in 0..cmp {
            if target_expected_tids[i] == target_tids[i] {
                matched += 1;
                match compare_asdu(&target_expected_iframes[i], &target_iframes_body[i]) {
                    AsduCmp::Identical => byte_id += 1,
                    AsduCmp::Cp56Only => cp56_only_t += 1,
                    AsduCmp::Different => total_mm += 1,
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
            cp56_only_count: cp56_only_t,
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
        direction: target_direction(ctx.role),
        u_frames,
        s_frames,
        i_frames,
        u_codes_seen: target_u_codes,
        startdt_handshake_ok,
        target_type_ids: target_tids,
        correctness,
    };

    // --- Timing analysis (per-I-frame gaps + pacing drift) ---
    let orig_gaps = orig_playback
        .as_ref()
        .map(iframe_gap_timings)
        .unwrap_or_default();
    let cap_gaps = cap_playback
        .as_ref()
        .map(iframe_gap_timings)
        .unwrap_or_default();
    let orig_dur = total_span_ms(&orig_gaps);
    let cap_dur = total_span_ms(&cap_gaps);

    let pacing_samples: Vec<[f64; 2]> = match (cap_playback.as_ref(), orig_playback.as_ref()) {
        (Some(cap_rf), Some(orig_rf)) => {
            let cap_walls = iframe_wall_times_ms(cap_rf);
            let orig_walls = iframe_wall_times_ms(orig_rf);
            if cap_walls.is_empty() || orig_walls.is_empty() {
                Vec::new()
            } else {
                let cap_zero = cap_walls[0];
                let orig_zero = orig_walls[0];
                let n = cap_walls.len().min(orig_walls.len());
                (0..n)
                    .map(|i| {
                        let drift = (cap_walls[i] - cap_zero) - (orig_walls[i] - orig_zero);
                        [cap_walls[i], drift]
                    })
                    .collect()
            }
        }
        _ => Vec::new(),
    };
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
        pacing_samples: pacing_samples.clone(),
    };

    // --- CP56Time2a drift (only meaningful when rewrite_to_now was on) ---
    let cp56_drift = if rewrite_cp56_was_on {
        cap_playback.as_ref().and_then(|rf| {
            compute_cp56_drift(rf, ctx.captured_first_ts_ns, cp56_zone, ctx.cp56_tolerance_ms)
        })
    } else {
        None
    };
    if rewrite_cp56_was_on && cp56_drift.is_none() {
        notes.push(
            "fresh-timestamps mode was enabled but captured flow contained no CP56Time2a \
             fields — either the ASDU types in this pcap carry no time tag or the playback \
             side had no I-frames to inspect"
                .into(),
        );
    }

    // --- Verdict ---
    let (verdict, reason, score) = decide_verdict(&playback, &target, ctx.mode_correct, &notes);

    let protocol_specific = json!({
        "playback": playback,
        "target": target,
        "timing": timing,
        "cp56_drift": cp56_drift,
    });

    ProtoSlaveAnalysis {
        score_pct: score,
        verdict,
        verdict_reason: reason,
        expected_messages: expected_iframes.len(),
        delivered_messages: delivered_iframes.len(),
        handshake_ok: startdt_handshake_ok,
        notes,
        protocol_specific,
        pacing_samples,
    }
}

/// Fleet-level CP56Time2a drift aggregator: walk each slave's
/// `protocol_specific` blob for its `cp56_drift.drift_samples_ms` +
/// `cp56_drift.sample_wall_ms` arrays, concatenate, sort by wall ms,
/// decimate to [`MAX_FLEET_TIMELINE_POINTS`], and return a generic
/// [`FleetDriftTimeline`].
pub fn aggregate_iec104_fleet_drift(
    per_slave: &BTreeMap<String, serde_json::Value>,
    iteration_starts_ms: &[f64],
) -> Option<FleetDriftTimeline> {
    let mut all: Vec<(f64, f64)> = Vec::new();
    for v in per_slave.values() {
        let Some(dr) = v.get("cp56_drift") else { continue };
        if dr.is_null() {
            continue;
        }
        let drift = dr.get("drift_samples_ms").and_then(|x| x.as_array());
        let walls = dr.get("sample_wall_ms").and_then(|x| x.as_array());
        let (Some(drift), Some(walls)) = (drift, walls) else {
            continue;
        };
        let n = drift.len().min(walls.len());
        for i in 0..n {
            if let (Some(d), Some(w)) = (drift[i].as_f64(), walls[i].as_f64()) {
                all.push((w, d));
            }
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

    Some(FleetDriftTimeline {
        samples: kept,
        total_samples,
        decimated,
        iteration_starts_ms: iteration_starts_ms.to_vec(),
    })
}

// ---------------------------------------------------------------------
// internal helpers — previously in webui/src/analysis.rs
// ---------------------------------------------------------------------

/// Outcome of comparing two ASDU buffers. Fresh-timestamps mode (or a
/// live target with its own clock) will produce different CP56Time2a
/// bytes for the same underlying event — those differences are not
/// protocol deviations and must not be counted as mismatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsduCmp {
    Identical,
    Cp56Only,
    Different,
}

/// Compare two ASDU buffers, distinguishing byte-identical vs
/// CP56-only-diff vs real protocol deviation.
pub fn compare_asdu(a: &[u8], b: &[u8]) -> AsduCmp {
    if a == b {
        return AsduCmp::Identical;
    }
    if a.len() != b.len() {
        return AsduCmp::Different;
    }
    let offs_a = cp56_field_offsets(a);
    let offs_b = cp56_field_offsets(b);
    if offs_a.is_empty() || offs_a != offs_b {
        return AsduCmp::Different;
    }
    let mut ma = a.to_vec();
    let mut mb = b.to_vec();
    for &off in &offs_a {
        if off + 7 <= ma.len() {
            for i in 0..7 {
                ma[off + i] = 0;
                mb[off + i] = 0;
            }
        }
    }
    if ma == mb {
        AsduCmp::Cp56Only
    } else {
        AsduCmp::Different
    }
}

/// Walk an ASDU and return the byte offset of every CP56Time2a field it contains.
fn cp56_field_offsets(asdu: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if asdu.len() < DUI_LEN {
        return out;
    }
    let type_id = asdu[0];
    let Some(cp56_off_in_elem) = cp56_offset_in_element(type_id) else {
        return out;
    };
    let Some(elem) = element_len(type_id) else {
        return out;
    };
    let (sq, n) = vsq(asdu);
    let n = n as usize;
    if n == 0 {
        return out;
    }

    if sq {
        let mut off = DUI_LEN + IOA_LEN;
        for _ in 0..n {
            let cp_start = off + cp56_off_in_elem;
            if cp_start + 7 > asdu.len() {
                break;
            }
            out.push(cp_start);
            off += elem;
        }
    } else {
        let stride = IOA_LEN + elem;
        let mut off = DUI_LEN;
        for _ in 0..n {
            let cp_start = off + IOA_LEN + cp56_off_in_elem;
            if cp_start + 7 > asdu.len() {
                break;
            }
            out.push(cp_start);
            off += stride;
        }
    }
    out
}

/// Convenience: walk an ASDU and return every CP56Time2a as
/// `(unix_ns, iv, su)`, decoded with the UTC decoder.
fn extract_cp56_from_asdu(asdu: &[u8]) -> Vec<(u64, bool, bool)> {
    let mut out = Vec::new();
    for off in cp56_field_offsets(asdu) {
        let arr: [u8; 7] = asdu[off..off + 7].try_into().unwrap();
        out.push(decode_cp56time2a(&arr));
    }
    out
}

/// Walk an APDU byte stream and return the I-frame ASDU bodies in order.
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

/// Walk an APDU stream and classify every frame, recording U-codes.
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

/// Inter-I-frame gaps (ms) derived from each frame's source-packet
/// timestamp via `FlowSnapshot::ts_for_byte`.
fn iframe_gap_timings(flow: &FlowSnapshot) -> Vec<f64> {
    let payload = flow.payload;
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

/// Per-I-frame wire-send wall-clock times (ms, relative to the flow's
/// pcap's first packet) in order.
fn iframe_wall_times_ms(flow: &FlowSnapshot) -> Vec<f64> {
    let payload = flow.payload;
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
    starts
        .into_iter()
        .map(|b| flow.ts_for_byte(b) as f64 / 1e6)
        .collect()
}

/// Walk every I-frame in `flow`, extract each CP56Time2a in the ASDU,
/// and compare its decoded wall time to the frame's wire-send time.
///
/// `capture_epoch_ns` is the absolute UTC ns of the captured pcap's
/// first packet — added to `flow.ts_for_byte(...)` (which is relative
/// to that first packet) to land on the same axis as CP56Time2a.
fn compute_cp56_drift(
    flow: &FlowSnapshot,
    capture_epoch_ns: u64,
    zone: Cp56Zone,
    tolerance_ms: f64,
) -> Option<Cp56DriftReport> {
    let payload = flow.payload;
    let mut abs_ms: Vec<f64> = Vec::new();
    let mut signed_ms_sum: f64 = 0.0;
    let mut iframes_with_cp56: usize = 0;
    let mut invalid_flag_count: usize = 0;
    let mut summer_flag_count: usize = 0;
    let mut drift_samples_ms: Vec<f64> = Vec::new();
    let mut sample_frame_indices: Vec<u32> = Vec::new();
    let mut sample_type_ids: Vec<u8> = Vec::new();
    let mut sample_wall_ms: Vec<f64> = Vec::new();
    let mut samples_truncated = false;
    let mut iframe_index: u32 = 0;

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
        let frame_start = i;
        let cf1 = payload[i + 2];
        let body_start = i + 2;
        if cf1 & 0x01 == 0 {
            let this_iframe_idx = iframe_index;
            iframe_index = iframe_index.saturating_add(1);
            let asdu_start = body_start + 4;
            let asdu_end = i + 2 + ln;
            if asdu_end > payload.len() {
                break;
            }
            let asdu = &payload[asdu_start..asdu_end];
            let type_id = asdu.first().copied().unwrap_or(0);
            let stamps = extract_cp56_from_asdu(asdu);
            let stamps = match zone {
                Cp56Zone::Utc => stamps,
                Cp56Zone::Local => {
                    let mut redone = Vec::with_capacity(stamps.len());
                    for off in cp56_field_offsets(asdu) {
                        if off + 7 <= asdu.len() {
                            let mut arr = [0u8; 7];
                            arr.copy_from_slice(&asdu[off..off + 7]);
                            let (ns, iv) = decode_cp56time2a_local(&arr);
                            let su = arr[3] & 0x80 != 0;
                            redone.push((ns, iv, su));
                        }
                    }
                    redone
                }
            };
            if !stamps.is_empty() {
                iframes_with_cp56 += 1;
                let send_ns = capture_epoch_ns.saturating_add(flow.ts_for_byte(frame_start));
                for (stamp_ns, iv, su) in stamps {
                    if iv {
                        invalid_flag_count += 1;
                    }
                    if su {
                        summer_flag_count += 1;
                    }
                    let diff_ns = send_ns as i128 - stamp_ns as i128;
                    let diff_ms = diff_ns as f64 / 1e6;
                    signed_ms_sum += diff_ms;
                    abs_ms.push(diff_ms.abs());
                    if drift_samples_ms.len() < MAX_DRIFT_SAMPLES {
                        drift_samples_ms.push(diff_ms);
                        sample_frame_indices.push(this_iframe_idx);
                        sample_type_ids.push(type_id);
                        sample_wall_ms.push(flow.ts_for_byte(frame_start) as f64 / 1e6);
                    } else {
                        samples_truncated = true;
                    }
                }
            }
        }
        i += 2 + ln;
    }

    if abs_ms.is_empty() {
        return None;
    }
    let samples = abs_ms.len();
    let mean = abs_ms.iter().sum::<f64>() / samples as f64;
    let mean_signed = signed_ms_sum / samples as f64;
    let mut sorted = abs_ms.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let max = *sorted.last().unwrap_or(&0.0);
    let p50 = percentile(&sorted, 0.5);
    let p99 = percentile(&sorted, 0.99);
    let out_of_tolerance = abs_ms.iter().filter(|&&d| d > tolerance_ms).count();

    Some(Cp56DriftReport {
        samples,
        iframes_with_cp56,
        mean_ms: mean,
        p50_ms: p50,
        p99_ms: p99,
        max_ms: max,
        out_of_tolerance,
        tolerance_ms,
        mean_signed_ms: mean_signed,
        invalid_flag_count,
        summer_flag_count,
        drift_samples_ms,
        sample_frame_indices,
        sample_type_ids,
        sample_wall_ms,
        samples_truncated,
    })
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

fn target_direction(role: Role) -> &'static str {
    match role {
        Role::Master => "server → master (target replies)",
        Role::Slave => "master → slave (target commands)",
    }
}

/// Verdict decision for a single slave. Identical to the prior
/// webui-side logic; only the signature changed (takes `mode_correct`
/// bool instead of an analyzer-local enum).
fn decide_verdict(
    pb: &PlaybackReport,
    tg: &TargetReport,
    mode_correct: bool,
    _notes: &[String],
) -> (&'static str, String, f64) {
    if pb.expected_iframes == 0 && pb.delivered_iframes == 0 {
        if tg.startdt_handshake_ok {
            return (
                "no_iframes_expected",
                "no I-frames in source pcap; target completed STARTDT handshake".into(),
                100.0,
            );
        }
        return (
            "no_iframes_expected",
            "no I-frames in source pcap; nothing to deliver".into(),
            100.0,
        );
    }
    if pb.delivered_iframes == 0 {
        return (
            "no_delivery",
            "outstation's side produced zero I-frames in the captured pcap".into(),
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

    let _ = mode_correct;

    // Generic mode: judge delivery + handshake.
    if pb.matched_type_ids == pb.expected_iframes && tg.startdt_handshake_ok {
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

/// Length of the longest common subsequence of two `u8` streams.
/// Classic O(n·m) DP; falls back to a cheap linear heuristic over 4096
/// entries so UI latency stays sane on huge pcaps.
pub fn lcs_length(a: &[u8], b: &[u8]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    if a.len() > 4096 || b.len() > 4096 {
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

/// Classify the target's script against the original:
///   * `actual == 0`      → silent
///   * byte_identical_count == expected → same script
///   * lcs / expected >= 0.8            → same script
///   * lcs / expected >= 0.4 and actual < expected → subset
///   * otherwise → divergent
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
    use crate::asdu::encode_cp56time2a;

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
        let subset = vec![70, 100, 1, 3, 5];
        let lcs = lcs_length(&orig, &subset);
        assert_eq!(classify_script(&orig, &subset, lcs, 0), "subset");
    }

    #[test]
    fn classify_divergent() {
        let orig = vec![45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46];
        let actual = vec![100, 101];
        let lcs = lcs_length(&orig, &actual);
        assert_eq!(classify_script(&orig, &actual, lcs, 0), "divergent");
    }

    #[test]
    fn classify_silent() {
        let orig = vec![1, 2, 3];
        let actual: Vec<u8> = vec![];
        assert_eq!(classify_script(&orig, &actual, 0, 0), "silent");
    }

    fn build_type36_iframe(stamp_ns: u64) -> Vec<u8> {
        let mut asdu = vec![
            36, 0x01, 0x03, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        asdu.extend_from_slice(&encode_cp56time2a(stamp_ns, false, false));
        let mut frame = vec![0x68, (asdu.len() + 4) as u8, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&asdu);
        frame
    }

    #[test]
    fn cp56_drift_zero_when_stamp_matches_send_time() {
        const CAP_EPOCH_NS: u64 = 1_710_428_966_000_000_000;
        const SEND_REL_NS: u64 = 12_345_678_900;
        let stamp_absolute = CAP_EPOCH_NS + SEND_REL_NS;

        let iframe = build_type36_iframe(stamp_absolute);
        let packet_offsets = vec![(SEND_REL_NS, 0)];
        let flow = FlowSnapshot {
            payload: &iframe,
            packet_offsets: &packet_offsets,
        };

        let drift = compute_cp56_drift(&flow, CAP_EPOCH_NS, Cp56Zone::Utc, 50.0)
            .expect("should yield drift");
        assert_eq!(drift.samples, 1);
        assert_eq!(drift.iframes_with_cp56, 1);
        assert!(drift.max_ms < 1.0);
        assert_eq!(drift.out_of_tolerance, 0);
        assert_eq!(drift.drift_samples_ms.len(), drift.samples);
        assert_eq!(drift.sample_frame_indices.len(), drift.samples);
        assert_eq!(drift.sample_type_ids.len(), drift.samples);
        assert!(!drift.samples_truncated);
        assert_eq!(drift.sample_frame_indices[0], 0);
        assert_eq!(drift.sample_type_ids[0], 36);
    }

    #[test]
    fn cp56_drift_flags_out_of_tolerance() {
        const CAP_EPOCH_NS: u64 = 1_710_428_966_000_000_000;
        const SEND_REL_NS: u64 = 5_000_000_000;
        let stale_stamp = CAP_EPOCH_NS + SEND_REL_NS - 100_000_000;

        let iframe = build_type36_iframe(stale_stamp);
        let packet_offsets = vec![(SEND_REL_NS, 0)];
        let flow = FlowSnapshot {
            payload: &iframe,
            packet_offsets: &packet_offsets,
        };

        let drift = compute_cp56_drift(&flow, CAP_EPOCH_NS, Cp56Zone::Utc, 50.0).unwrap();
        assert_eq!(drift.out_of_tolerance, 1);
        assert!((drift.mean_ms - 100.0).abs() < 2.0);
        assert!(drift.mean_signed_ms > 80.0);
        assert_eq!(drift.drift_samples_ms.len(), 1);
        assert!((drift.drift_samples_ms[0] - 100.0).abs() < 2.0);
    }

    #[test]
    fn compare_asdu_identical_returns_identical() {
        let a = vec![1, 0x01, 0x03, 0, 0x01, 0, 0x01, 0, 0, 0x42];
        assert_eq!(compare_asdu(&a, &a), AsduCmp::Identical);
    }

    #[test]
    fn compare_asdu_cp56_only_diff_classified() {
        let mut a = vec![
            36, 0x01, 0x03, 0, 0x01, 0,
            0x01, 0, 0,
            0xde, 0xad, 0xbe, 0xef, 0x00,
        ];
        let mut b = a.clone();
        a.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x04, 0x18]);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18]);
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Cp56Only);
    }

    #[test]
    fn compare_asdu_real_diff_in_payload_classified() {
        let mut a = vec![
            36, 0x01, 0x03, 0, 0x01, 0,
            0x01, 0, 0,
            0xde, 0xad, 0xbe, 0xef, 0x00,
        ];
        let mut b = a.clone();
        b[12] = 0xff;
        a.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x04, 0x18]);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18]);
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Different);
    }

    #[test]
    fn compare_asdu_no_cp56_field_is_real_diff() {
        let a = vec![
            13, 0x01, 0x03, 0, 0x01, 0,
            0x01, 0, 0,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut b = a.clone();
        b[12] = 0xff;
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Different);
    }

    #[test]
    fn compare_asdu_different_lengths_is_different() {
        let a = vec![36, 0x01, 0x03, 0, 0x01, 0];
        let b = vec![36, 0x01, 0x03, 0, 0x01, 0, 0xff];
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Different);
    }

    #[test]
    fn cp56_drift_none_when_no_cp56_types() {
        let asdu = vec![
            13, 0x01, 0x03, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut frame = vec![0x68, (asdu.len() + 4) as u8, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&asdu);
        let packet_offsets = vec![(0u64, 0usize)];
        let flow = FlowSnapshot {
            payload: &frame,
            packet_offsets: &packet_offsets,
        };
        assert!(compute_cp56_drift(&flow, 0, Cp56Zone::Utc, 50.0).is_none());
    }
}
