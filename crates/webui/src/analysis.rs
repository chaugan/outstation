//! Post-run analysis: compare a user-uploaded captured pcap against
//! the source pcap of a completed run.
//!
//! Produces a structured [`AnalysisReport`] with three sections:
//!
//! 1. **Playback side** — what outstation was supposed to deliver.
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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::Path;

use pcapload::{LoadedPcap, ReassembledFlow};
use proto_iec104::apdu::{Apdu, ApduReader, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT, U_TESTFR_CON};
use proto_iec104::asdu::{
    cp56_offset_in_element, decode_cp56time2a, decode_cp56time2a_local, element_len, vsq,
    Cp56Zone, DUI_LEN, IOA_LEN,
};
use serde::Serialize;

/// Default tolerance for the CP56Time2a drift analyzer: 50 ms is
/// generous for a LAN SCADA session but keeps noise out of the count.
pub const DEFAULT_CP56_TOLERANCE_MS: f64 = 50.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    /// Target is a different software than the one in the pcap.
    /// We only care that outstation's side delivered the expected
    /// frames and the target held up basic IEC 104 flow control.
    Generic,
    /// Target is the same device(s) as the original pcap. Expect the
    /// target's I-frames to match the original's opposite side
    /// byte-for-byte in type ID sequence.
    Correct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleHint {
    /// outstation acted as the client (master).
    Master,
    /// outstation acted as the server (slave).
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
    /// Top-level rollup across the whole fleet of replayed slaves.
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub score_pct: f64,
    /// Fleet-level notes only. Per-slave notes live inside
    /// `details_by_ip[ip].notes`.
    pub notes: Vec<String>,
    pub fleet: FleetSummary,
    /// One light-weight row per slave, intended for the table view.
    /// Sorted worst-score-first so the UI can render as-is.
    pub slaves: Vec<SlaveSummary>,
    /// Full drill-down detail per slave IP. UI renders only the entry
    /// for the row the user expanded.
    pub details_by_ip: BTreeMap<String, SlaveDetail>,
    /// Captured-master-IP → live-master-IP mapping. `captured` is
    /// auto-detected from the original pcap (the unique client across
    /// 2404 flows). `live` is auto-detected from the captured pcap
    /// the same way. Surfaced so the UI can show "rewrote .10.10 →
    /// .86.223 across N sessions".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_ip_mapping: Option<MasterIpMapping>,
    /// Fleet-wide aggregated CP56Time2a drift over time. Drives the
    /// top-of-card aggregated drift chart in the UI. `None` when
    /// fresh-timestamps mode wasn't used or no slave produced any
    /// CP56 samples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_drift_timeline: Option<FleetDriftTimeline>,
    /// Fleet-wide pacing drift over time — answers "is the replayer
    /// falling behind the original schedule?" Always populated when
    /// at least one slave delivered I-frames in both pcaps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_pacing_timeline: Option<FleetPacingTimeline>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FleetSummary {
    pub slave_count: usize,
    /// Slaves where the captured pcap saw at least one TCP packet.
    pub attempted: usize,
    /// Slaves expected from the original pcap that never showed up
    /// in the captured pcap.
    pub not_attempted: usize,
    /// score_pct >= 99.999.
    pub fully_correct: usize,
    /// 0 < score_pct < 99.999.
    pub partial: usize,
    /// score_pct == 0 among attempted slaves.
    pub failed: usize,
    /// Mean score_pct across attempted slaves only. Not_attempted
    /// slaves are excluded so the number reflects "how well did the
    /// stuff that ran do" rather than blending in zeros for IPs
    /// nobody ever connected to.
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
    pub expected_iframes: usize,
    pub delivered_iframes: usize,
    pub packets: usize,
    pub startdt_handshake_ok: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct SlaveDetail {
    pub tcp_flow: Option<FlowInfo>,
    pub playback: PlaybackReport,
    pub target: TargetReport,
    pub timing: TimingReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp56_drift: Option<Cp56DriftReport>,
    pub verdict: &'static str,
    pub verdict_reason: String,
    pub score_pct: f64,
    pub notes: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct MasterIpMapping {
    /// Master IP observed in the original pcap (None if the pcap had
    /// no IEC 104 client, or if multiple clients were ambiguous).
    pub captured: Option<String>,
    /// Master IP observed in the captured live pcap.
    pub live: Option<String>,
    /// True iff both sides resolved to a single, distinct address —
    /// i.e. there's a meaningful captured→live rename to surface.
    pub renamed: bool,
}

/// Fleet-wide CP56Time2a drift timeline. Aggregates per-frame drift
/// samples from every slave onto a single wall-clock axis so the UI
/// can render one chart that reflects the whole run. Decimated to
/// ~`MAX_FLEET_TIMELINE_POINTS` points to keep the response small.
///
/// Populated only when fresh-timestamps mode was on (else there are
/// no meaningful drift samples). When the run was a loop with
/// multiple iterations, `iteration_starts_ms` carries one entry per
/// iteration boundary so the UI can annotate the chart.
#[derive(Serialize, Debug, Clone)]
pub struct FleetDriftTimeline {
    /// One entry per kept sample after decimation. `[wall_ms, drift_ms]`.
    pub samples: Vec<[f64; 2]>,
    /// Total samples observed before decimation (samples.len() will
    /// be ≤ this).
    pub total_samples: usize,
    /// True when decimation discarded samples to keep the response
    /// size manageable. Aggregates (mean / p99) stay accurate.
    pub decimated: bool,
    /// Wall-clock ms (relative to capture start) of each detected
    /// iteration start. For a single-run benchmark this contains one
    /// entry near 0 (or is empty if detection found no clear burst);
    /// the UI suppresses single-iteration annotations.
    pub iteration_starts_ms: Vec<f64>,
}

/// Cap on points emitted in `FleetDriftTimeline.samples`. With ~165
/// slaves × ~3 894 CP56 fields each, raw counts can hit 600k+.
/// Decimating to ~5 000 keeps the JSON small and ECharts smooth.
pub const MAX_FLEET_TIMELINE_POINTS: usize = 5_000;

/// Fleet-wide pacing-drift timeline. Per-I-frame samples of how much
/// the live replay landed each frame later than the original
/// schedule, aggregated across all slaves on a single capture-side
/// wall-clock axis. Decimated to `MAX_FLEET_TIMELINE_POINTS`.
///
/// Shape mirrors `FleetDriftTimeline` so the UI can use the same
/// chart template. Iteration boundaries are reused from the same
/// detector — so loops show the per-iteration mean line clearly
/// snapping back to ~0 at each restart (or trending upward across
/// iterations if the replayer falls progressively behind).
#[derive(Serialize, Debug, Clone)]
pub struct FleetPacingTimeline {
    /// `[capture_wall_ms, pacing_drift_ms]` per kept sample.
    pub samples: Vec<[f64; 2]>,
    pub total_samples: usize,
    pub decimated: bool,
    pub iteration_starts_ms: Vec<f64>,
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
    /// Frames where every byte (including embedded CP56Time2a) matches
    /// the original.
    pub byte_identical_count: usize,
    /// Frames whose only difference from the original is inside the
    /// CP56Time2a field(s) — same DUI, same IOA, same payload, just
    /// a different timestamp. Expected when the run had
    /// fresh-timestamps mode on.
    #[serde(default)]
    pub cp56_only_count: usize,
    /// Frames whose bytes differ in fields *other* than CP56Time2a —
    /// the count of `mismatches`. Tracked separately so the score
    /// reflects real protocol-level deviations and not the timestamp
    /// rewriting we asked for.
    #[serde(default)]
    pub real_mismatch_count: usize,
    pub missing_indices: Vec<usize>,
    /// Only the *real* mismatches are listed here — frames whose only
    /// diff is the CP56Time2a stamp are tallied in `cp56_only_count`
    /// instead, to keep this list honest.
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
    /// Frames where the target's reply differs from the original only
    /// in the CP56Time2a stamp — common because live targets generate
    /// stamps from their own clock. Counted here so they don't inflate
    /// `total_mismatches` (which counts *real* protocol deviations).
    #[serde(default)]
    pub cp56_only_count: usize,
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

/// Per-run statistics on how closely each captured CP56Time2a stamp
/// matches the wall-clock moment at which its carrying frame actually
/// hit the wire. Only meaningful when the run enabled
/// `rewrite_cp56_to_now` — otherwise the stamps are the pcap's original
/// capture times and drift metrics describe "how stale was the pcap"
/// rather than "how accurate is our rewrite".
#[derive(Serialize, Debug, Clone, Default)]
pub struct Cp56DriftReport {
    /// Number of CP56Time2a fields compared.
    pub samples: usize,
    /// Number of captured I-frames containing at least one CP56 field.
    pub iframes_with_cp56: usize,
    /// Absolute difference (send_wall - decoded_stamp) stats, ms.
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    /// Samples whose drift exceeds `tolerance_ms`. Good runs have 0.
    pub out_of_tolerance: usize,
    pub tolerance_ms: f64,
    /// Signed mean drift (positive = stamp trailed wire time, i.e.
    /// stamp in the past relative to actual send). Included to make
    /// a systematic bias easy to spot.
    pub mean_signed_ms: f64,
    /// IV (invalid) flag counts seen on captured stamps.
    pub invalid_flag_count: usize,
    pub summer_flag_count: usize,
    /// Per-CP56-field signed drift in milliseconds (capture wire ts
    /// minus decoded stamp). One entry per `samples`. Lets the UI plot
    /// every needle directly without re-walking the pcap. Capped at
    /// `MAX_DRIFT_SAMPLES` to keep response sizes sane on huge runs;
    /// when capped, the array contains the first `MAX_DRIFT_SAMPLES`
    /// samples and `samples_truncated` is set true.
    #[serde(default)]
    pub drift_samples_ms: Vec<f64>,
    /// Index of the I-frame the corresponding sample came from
    /// (relative to delivered I-frames). Same length as
    /// `drift_samples_ms`.
    #[serde(default)]
    pub sample_frame_indices: Vec<u32>,
    /// ASDU type ID for the same frame. Same length again.
    #[serde(default)]
    pub sample_type_ids: Vec<u8>,
    /// Wall-clock timestamp (ms relative to the captured pcap's first
    /// packet) at which this sample's frame hit the wire. Same length
    /// as `drift_samples_ms`. Used by the fleet-level aggregated
    /// drift chart so per-slave samples can be unified onto a single
    /// time axis.
    #[serde(default)]
    pub sample_wall_ms: Vec<f64>,
    /// True when the per-sample arrays were capped because the run
    /// produced more CP56 fields than `MAX_DRIFT_SAMPLES`.
    #[serde(default)]
    pub samples_truncated: bool,
}

/// Cap on the per-frame drift sample arrays. A 50k-frame run × 8 B
/// per f64 + 4 B index + 1 B type ≈ 650 KB raw, ~250 KB after JSON.
/// That's the upper bound; aggregates stay accurate beyond this.
pub const MAX_DRIFT_SAMPLES: usize = 50_000;

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
    /// Per-I-frame pacing-drift samples for this slave:
    /// `[capture_wall_ms, pacing_drift_ms]` where pacing_drift_ms is
    /// `(cap_t_i - cap_t_0) - (orig_t_i - orig_t_0)`. Positive means
    /// the live replay landed the i-th frame later than the original
    /// schedule. capture_wall_ms is absolute (relative to the
    /// captured pcap's first packet) so cross-slave aggregation onto
    /// a single time axis works.
    #[serde(default)]
    pub pacing_samples: Vec<[f64; 2]>,
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

/// Walk a flow's payload and return the wire-send wall-clock time
/// (ms relative to the pcap's first packet) of every I-frame, in
/// order. Used by pacing-drift analysis: compare same-index frames
/// across original and captured to see how much later (or earlier)
/// the live replay sent each frame relative to the original schedule.
fn iframe_wall_times_ms(flow: &ReassembledFlow) -> Vec<f64> {
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
    starts
        .into_iter()
        .map(|b| flow.ts_for_byte(b) as f64 / 1e6)
        .collect()
}

/// Walk every I-frame in `flow`, extract each CP56Time2a field inside
/// the ASDU, and compare its decoded wall time to the wire send time
/// for the frame's starting byte.
///
/// `flow.ts_for_byte` returns the packet's timestamp **relative** to
/// the pcap's first packet, so `capture_epoch_ns` must be added to
/// land in absolute UTC — the same epoch that CP56Time2a encodes.
/// Returns `None` if no CP56 fields were seen.
fn compute_cp56_drift(
    flow: &ReassembledFlow,
    capture_epoch_ns: u64,
    zone: Cp56Zone,
    tolerance_ms: f64,
) -> Option<Cp56DriftReport> {
    let payload = &flow.payload;
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
    // Local I-frame index, incremented for every I-frame walked
    // regardless of CP56 presence — matches what the UI sees as "the
    // i'th frame in the captured playback".
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
        let body_start = i + 2; // APCI: 4 control bytes start at +2 of 0x68
        // I-frame test: LSB of CF1 is 0.
        if cf1 & 0x01 == 0 {
            let this_iframe_idx = iframe_index;
            iframe_index = iframe_index.saturating_add(1);
            // ASDU begins after 4-byte control field.
            let asdu_start = body_start + 4;
            let asdu_end = i + 2 + ln;
            if asdu_end > payload.len() {
                break;
            }
            let asdu = &payload[asdu_start..asdu_end];
            let type_id = asdu.first().copied().unwrap_or(0);
            // Extract every CP56Time2a in this ASDU (same SQ=0/SQ=1
            // walk as rewrite, reusing asdu.rs offset helpers).
            let stamps = extract_cp56_from_asdu(asdu);
            let stamps = match zone {
                Cp56Zone::Utc => stamps,
                Cp56Zone::Local => {
                    // Re-decode per element using the local-timezone
                    // decoder so drift math lands on the same epoch.
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
                        // Wall ms is the byte timestamp relative to
                        // the pcap's first packet — already what
                        // ts_for_byte returns. Convert ns → ms.
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
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
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

/// Outcome of comparing two ASDU buffers. The "is the data the same?"
/// question splits three ways once you account for the fact that
/// fresh-timestamps mode (and live targets that read their own clock)
/// will produce different CP56Time2a bytes for the same underlying
/// event — those differences are not protocol deviations and must not
/// be counted as mismatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsduCmp {
    /// Byte-for-byte identical, including embedded CP56Time2a.
    Identical,
    /// Same length and same bytes outside the CP56Time2a fields; only
    /// the timestamp(s) differ. Expected for runs with fresh
    /// timestamps on, or for live targets with independent clocks.
    Cp56Only,
    /// Bytes differ in fields outside CP56Time2a (or layouts disagree).
    /// A real protocol-level deviation.
    Different,
}

/// Compare two ASDU buffers. Distinguishes "byte-identical",
/// "differs only in CP56Time2a bytes", and "really different" so the
/// analyzer can keep the score honest when CP56 stamps are
/// deliberately rewritten by fresh-timestamps mode.
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
        // No CP56 fields, or layout differs — diff is genuine.
        return AsduCmp::Different;
    }
    // Mask every CP56 region (7 bytes each) and re-compare.
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

/// Walk an ASDU and return the byte offset of every CP56Time2a field
/// it contains. Caller supplies the zone-appropriate decoder.
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

/// Detect the master IP for an IEC 104 pcap: the unique client IP
/// across all flows whose server port matches `target_port`. When
/// multiple distinct clients exist, returns the busiest one (most
/// flows). Returns None if no client speaks 2404 at all.
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

/// Enumerate distinct slave IPs in a pcap (server_port == target_port).
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

/// Pick the flow in the **original** pcap whose server matches the
/// given slave IP and port. In a multi-RTU pcap there's typically one
/// flow per slave IP; if multiple flows match (the slave reconnected
/// during capture), pick the busiest.
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
/// comparison, and rolls the per-slave outcomes up into a fleet
/// report.
pub fn analyze(
    original_pcap_path: &Path,
    captured_pcap_path: &Path,
    run_id: u64,
    target_port: u16,
    role: RoleHint,
    mode: AnalysisMode,
    rewrite_cp56_was_on: bool,
    cp56_zone: Cp56Zone,
    cp56_tolerance_ms: f64,
) -> anyhow::Result<AnalysisReport> {
    use anyhow::Context;

    let original = pcapload::load(original_pcap_path).context("load original pcap")?;
    let captured = pcapload::load(captured_pcap_path).context("load captured pcap")?;
    let captured_size_bytes = std::fs::metadata(captured_pcap_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut fleet_notes: Vec<String> = Vec::new();

    // Auto-detect master IPs on each side and surface as a mapping
    // for the UI. A "rename" is meaningful only when both sides
    // resolved to a single, distinct address.
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

    // Slave universe: union of slaves seen in either pcap. We iterate
    // the union so the report covers BOTH slaves the replayer was
    // supposed to drive AND any unexpected slave traffic the live
    // capture contained.
    let mut slave_ips: BTreeSet<Ipv4Addr> = list_slave_ips(&original, target_port);
    let captured_slave_ips = list_slave_ips(&captured, target_port);
    for ip in &captured_slave_ips {
        slave_ips.insert(*ip);
    }
    if slave_ips.is_empty() {
        return Err(anyhow::anyhow!(
            "no flow in source pcap with server_port={target_port}; nothing to compare against"
        ));
    }

    // Per-slave analysis.
    let mut summaries: Vec<SlaveSummary> = Vec::new();
    let mut details: BTreeMap<String, SlaveDetail> = BTreeMap::new();
    for ip in &slave_ips {
        match analyze_one_slave(
            &original,
            &captured,
            *ip,
            target_port,
            role,
            mode,
            rewrite_cp56_was_on,
            cp56_zone,
            cp56_tolerance_ms,
        ) {
            Ok((summary, detail)) => {
                summaries.push(summary);
                details.insert(ip.to_string(), detail);
            }
            Err(e) => {
                fleet_notes.push(format!("slave {ip}: skipped ({e})"));
            }
        }
    }

    // Sort worst-first so the UI table is meaningful at a glance.
    summaries.sort_by(|a, b| {
        a.score_pct
            .partial_cmp(&b.score_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.slave_ip.cmp(&b.slave_ip))
    });

    let (fleet, verdict, verdict_reason, score_pct) = roll_up_fleet(&summaries);

    // Fleet-wide drift timeline: union of every slave's per-sample
    // (wall_ms, drift_ms), decimated, plus iteration boundary marks
    // detected from the captured pcap's STARTDT_act bursts.
    let fleet_drift_timeline =
        build_fleet_drift_timeline(&details, &captured, target_port, fleet.slave_count);
    let fleet_pacing_timeline =
        build_fleet_pacing_timeline(&details, &captured, target_port, fleet.slave_count);

    Ok(AnalysisReport {
        run_id,
        mode: mode_str(mode),
        role: role_str(role),
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

/// Walk every slave's per-frame pacing samples, merge into one
/// time-sorted timeline, and decimate. Same shape as the drift
/// timeline so the UI can render with the same chart template.
fn build_fleet_pacing_timeline(
    details: &BTreeMap<String, SlaveDetail>,
    captured: &LoadedPcap,
    target_port: u16,
    expected_slave_count: usize,
) -> Option<FleetPacingTimeline> {
    let mut all: Vec<(f64, f64)> = Vec::new();
    for d in details.values() {
        for s in &d.timing.pacing_samples {
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
    let iteration_starts_ms = detect_iteration_starts(captured, target_port, expected_slave_count);

    Some(FleetPacingTimeline {
        samples: kept,
        total_samples,
        decimated,
        iteration_starts_ms,
    })
}

/// Walk every slave's per-sample drift array, merge into one
/// time-sorted timeline, decimate to `MAX_FLEET_TIMELINE_POINTS` if
/// needed, and detect iteration boundaries from the captured pcap.
/// Returns None when no slave had any CP56 samples (e.g.
/// fresh-timestamps mode wasn't on for this run).
fn build_fleet_drift_timeline(
    details: &BTreeMap<String, SlaveDetail>,
    captured: &LoadedPcap,
    target_port: u16,
    expected_slave_count: usize,
) -> Option<FleetDriftTimeline> {
    let mut all: Vec<(f64, f64)> = Vec::new();
    for d in details.values() {
        let Some(dr) = d.cp56_drift.as_ref() else { continue };
        // Both arrays share length; tolerate any drift.
        let n = dr.drift_samples_ms.len().min(dr.sample_wall_ms.len());
        for i in 0..n {
            all.push((dr.sample_wall_ms[i], dr.drift_samples_ms[i]));
        }
    }
    if all.is_empty() {
        return None;
    }
    let total_samples = all.len();
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    // Decimate by stride if oversized. Aggregate stats stay accurate
    // because the per-slave Cp56DriftReport already carries them.
    let decimated = total_samples > MAX_FLEET_TIMELINE_POINTS;
    let kept: Vec<[f64; 2]> = if decimated {
        let stride = (total_samples + MAX_FLEET_TIMELINE_POINTS - 1) / MAX_FLEET_TIMELINE_POINTS;
        all.iter()
            .step_by(stride)
            .map(|&(t, d)| [t, d])
            .collect()
    } else {
        all.iter().map(|&(t, d)| [t, d]).collect()
    };

    let iteration_starts_ms = detect_iteration_starts(captured, target_port, expected_slave_count);

    Some(FleetDriftTimeline {
        samples: kept,
        total_samples,
        decimated,
        iteration_starts_ms,
    })
}

/// Detect iteration boundaries by clustering TCP SYN packets to
/// `target_port`. In a single benchmark iteration every slave handshake
/// happens in a tight burst near the run start. A loop iteration adds
/// another burst at each restart. We bin SYNs by 1-second windows and
/// flag bins that contain at least 30 % of the expected slave count.
/// Adjacent flagged bins coalesce into a single iteration start.
///
/// Returns wall-clock ms (relative to captured pcap's first packet)
/// for each detected iteration start. Empty when no clear bursts
/// are found.
fn detect_iteration_starts(
    captured: &LoadedPcap,
    target_port: u16,
    expected_slave_count: usize,
) -> Vec<f64> {
    if expected_slave_count == 0 {
        return Vec::new();
    }
    // Threshold: need at least this many SYNs in one second to count
    // as a burst. 30 % of expected slaves, floored at 5 so tiny runs
    // still register.
    let threshold = ((expected_slave_count as f64) * 0.30).max(5.0) as usize;

    // Collect (rel_ms, port_match) for every SYN packet (no ACK).
    let mut syn_times_ms: Vec<f64> = Vec::new();
    for (idx, flow) in captured.flows.iter().enumerate() {
        let Some((_, sp)) = flow.server else { continue };
        if sp != target_port {
            continue;
        }
        // First packet of this flow in time order is the SYN (or our
        // best mid-flow approximation). flow.packet_indices[0] is
        // the earliest captured packet for the flow.
        if let Some(&first_pkt_idx) = flow.packet_indices.first() {
            let pkt = &captured.packets[first_pkt_idx];
            syn_times_ms.push(pkt.rel_ts_ns as f64 / 1e6);
        }
        let _ = idx;
    }
    if syn_times_ms.is_empty() {
        return Vec::new();
    }
    syn_times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Bin by 1-second windows.
    let max_ms = *syn_times_ms.last().unwrap();
    let bin_count = ((max_ms / 1000.0) as usize).saturating_add(2);
    let mut bins: Vec<usize> = vec![0; bin_count];
    for &t in &syn_times_ms {
        let b = (t / 1000.0) as usize;
        if b < bins.len() {
            bins[b] += 1;
        }
    }

    // Find peaks: any bin >= threshold. Coalesce adjacent peaks
    // (within 5 s of each other) into a single iteration start.
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

/// Run the single-slave comparison: pick the original flow for this
/// slave IP, pick the busiest captured flow for the same IP, and
/// produce a SlaveSummary + SlaveDetail.
fn analyze_one_slave(
    original: &LoadedPcap,
    captured: &LoadedPcap,
    slave_ip: Ipv4Addr,
    target_port: u16,
    role: RoleHint,
    mode: AnalysisMode,
    rewrite_cp56_was_on: bool,
    cp56_zone: Cp56Zone,
    cp56_tolerance_ms: f64,
) -> anyhow::Result<(SlaveSummary, SlaveDetail)> {
    use anyhow::Context;

    let mut notes: Vec<String> = Vec::new();
    let slave_ip_str = slave_ip.to_string();

    // Original-side reassembly. Skip if the original pcap has no flow
    // for this slave (orphan: slave seen in captured but not original).
    let orig_flow_idx_opt = find_original_flow_for_slave(original, slave_ip, target_port);
    let (orig_client_iframes, orig_server_iframes, orig_client, orig_server) =
        if let Some(orig_idx) = orig_flow_idx_opt {
            let oc = original
                .reassemble_client_payload(orig_idx)
                .context("reassemble original client side")?;
            let os = original
                .reassemble_server_payload(orig_idx)
                .context("reassemble original server side")?;
            let oci = extract_iframes(&oc.payload);
            let osi = extract_iframes(&os.payload);
            (oci, osi, Some(oc), Some(os))
        } else {
            notes.push(format!(
                "slave {slave_ip} appears in captured pcap but not in source — \
                 nothing to compare against"
            ));
            (Vec::new(), Vec::new(), None, None)
        };

    // Captured-side flow (busiest match). Bug 1 fix lives here.
    let cap_flow_idx_opt = find_busiest_captured_flow(captured, slave_ip, target_port);
    let cap_flow_idx = match cap_flow_idx_opt {
        Some(i) => i,
        None => {
            // Slave was expected but never reached the wire.
            let expected = match role {
                RoleHint::Master => &orig_client_iframes,
                RoleHint::Slave => &orig_server_iframes,
            };
            notes.push(format!(
                "slave {slave_ip}: no TCP flow in captured pcap on port {target_port}"
            ));
            let pb = empty_playback(role, &orig_client_iframes, &orig_server_iframes);
            let detail = SlaveDetail {
                tcp_flow: None,
                playback: pb,
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
                cp56_drift: None,
                verdict: "not_attempted",
                verdict_reason: format!(
                    "no TCP flow on port {target_port} for slave {slave_ip} \
                     in captured pcap"
                ),
                score_pct: 0.0,
                notes,
            };
            let summary = SlaveSummary {
                slave_ip: slave_ip_str,
                score_pct: 0.0,
                verdict: "not_attempted",
                verdict_reason: detail.verdict_reason.clone(),
                expected_iframes: expected.len(),
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

    // Figure out which side in the captured flow is outstation's
    // playback and which is the target.
    let (playback_rf, target_rf) = match role {
        RoleHint::Master => {
            // outstation was the client side
            (cap_client_rf.as_ref(), cap_server_rf.as_ref())
        }
        RoleHint::Slave => {
            // outstation was the server side
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
    // in order. Frame-by-frame body diff is classified three ways
    // (identical / cp56-only / really-different) so the score reflects
    // protocol deviations, not the timestamp rewriting we asked for.
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
        cp56_only_count: cp56_only,
        real_mismatch_count,
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
    let orig_playback_flow_opt = match role {
        RoleHint::Master => orig_client.as_ref(),
        RoleHint::Slave => orig_server.as_ref(),
    };
    let orig_gaps = orig_playback_flow_opt
        .map(|f| iframe_gap_timings(f))
        .unwrap_or_default();
    let cap_gaps = playback_rf
        .map(|rf| iframe_gap_timings(rf))
        .unwrap_or_default();
    let orig_dur = total_span_ms(&orig_gaps);
    let cap_dur = total_span_ms(&cap_gaps);
    // Per-I-frame pacing drift: how much the live replay landed each
    // frame later than the original schedule. Both wall-time series
    // are normalised to their own first I-frame so cross-slave
    // session-start differences don't pollute the metric.
    let pacing_samples: Vec<[f64; 2]> = match (playback_rf, orig_playback_flow_opt) {
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
        pacing_samples,
    };

    // --- CP56Time2a drift (fresh-timestamps mode only) ---
    let cp56_drift = if rewrite_cp56_was_on {
        let cap_epoch_ns = captured.first_ts_ns;
        playback_rf
            .and_then(|rf| compute_cp56_drift(rf, cap_epoch_ns, cp56_zone, cp56_tolerance_ms))
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
    let (verdict, reason, score) = decide_verdict(&playback, &target, mode, &notes);

    let summary = SlaveSummary {
        slave_ip: slave_ip_str,
        score_pct: score,
        verdict,
        verdict_reason: reason.clone(),
        expected_iframes: playback.expected_iframes,
        delivered_iframes: playback.delivered_iframes,
        packets: flow_info.packets,
        startdt_handshake_ok: target.startdt_handshake_ok,
    };
    let detail = SlaveDetail {
        tcp_flow: Some(flow_info),
        playback,
        target,
        timing,
        cp56_drift,
        verdict,
        verdict_reason: reason,
        score_pct: score,
        notes,
    };
    Ok((summary, detail))
}

/// Fold the per-slave summaries into a fleet rollup. Returns the
/// FleetSummary plus the top-level (verdict, reason, score) tuple
/// suitable for the report header.
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
        ("no_session", "no IEC 104 slaves in source pcap".into())
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
                "all {} attempted slaves produced 0 I-frames",
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
        cp56_only_count: 0,
        real_mismatch_count: 0,
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
    if pb.expected_iframes == 0 && pb.delivered_iframes == 0 {
        // No I-frame traffic in either direction. If the target at
        // least completed the IEC 104 handshake, the session is
        // healthy — there was just nothing to replay.
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
            pacing_samples: Vec::new(),
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

    /// Build an IEC 104 APCI I-frame wrapping a type-36 (M_ME_TF_1)
    /// ASDU with a single CP56Time2a stamp set to `stamp_ns`.
    fn build_type36_iframe(stamp_ns: u64) -> Vec<u8> {
        use proto_iec104::asdu::encode_cp56time2a;
        let mut asdu = vec![
            36,           // type
            0x01,         // VSQ: SQ=0, N=1
            0x03, 0x00,   // COT
            0x01, 0x00,   // CA
            0x01, 0x00, 0x00, // IOA
            0x00, 0x00, 0x00, 0x00, // float payload
            0x00,         // QDS
        ];
        asdu.extend_from_slice(&encode_cp56time2a(stamp_ns, false, false));
        // APCI: start byte, length, 4 control bytes (I-frame, ns=0, nr=0).
        let mut frame = vec![0x68, (asdu.len() + 4) as u8, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&asdu);
        frame
    }

    fn fake_flow(payload: Vec<u8>, frame_positions: Vec<(u64, usize)>) -> ReassembledFlow {
        ReassembledFlow {
            flow_idx: 0,
            client: ("10.0.0.1".parse().unwrap(), 12345),
            server: ("10.0.0.2".parse().unwrap(), 2404),
            dup_bytes: 0,
            payload,
            packet_offsets: frame_positions,
        }
    }

    #[test]
    fn cp56_drift_zero_when_stamp_matches_send_time() {
        // stamp encodes the exact wire-send epoch → drift = 0.
        const CAP_EPOCH_NS: u64 = 1_710_428_966_000_000_000; // pcap's first-packet ts
        const SEND_REL_NS: u64 = 12_345_678_900; // 12.345 s after first packet
        let stamp_absolute = CAP_EPOCH_NS + SEND_REL_NS;

        let iframe = build_type36_iframe(stamp_absolute);
        let flow = fake_flow(iframe.clone(), vec![(SEND_REL_NS, 0)]);

        let drift = compute_cp56_drift(&flow, CAP_EPOCH_NS, Cp56Zone::Utc, 50.0)
            .expect("should yield drift");
        assert_eq!(drift.samples, 1);
        assert_eq!(drift.iframes_with_cp56, 1);
        assert!(drift.max_ms < 1.0, "drift.max_ms = {}", drift.max_ms);
        assert_eq!(drift.out_of_tolerance, 0);
        // Per-frame arrays must be populated and length-consistent.
        assert_eq!(drift.drift_samples_ms.len(), drift.samples);
        assert_eq!(drift.sample_frame_indices.len(), drift.samples);
        assert_eq!(drift.sample_type_ids.len(), drift.samples);
        assert!(!drift.samples_truncated);
        // Single sample at frame index 0, type 36.
        assert_eq!(drift.sample_frame_indices[0], 0);
        assert_eq!(drift.sample_type_ids[0], 36);
    }

    #[test]
    fn cp56_drift_flags_out_of_tolerance() {
        // Stamp 100 ms earlier than actual send time → 100 ms drift,
        // outside a 50 ms tolerance.
        const CAP_EPOCH_NS: u64 = 1_710_428_966_000_000_000;
        const SEND_REL_NS: u64 = 5_000_000_000;
        let stale_stamp = CAP_EPOCH_NS + SEND_REL_NS - 100_000_000; // 100 ms stale

        let iframe = build_type36_iframe(stale_stamp);
        let flow = fake_flow(iframe, vec![(SEND_REL_NS, 0)]);

        let drift = compute_cp56_drift(&flow, CAP_EPOCH_NS, Cp56Zone::Utc, 50.0).unwrap();
        assert_eq!(drift.out_of_tolerance, 1);
        // abs(100ms) and signed should be +100ms (stamp trailed wire by 100ms).
        assert!((drift.mean_ms - 100.0).abs() < 2.0, "{}", drift.mean_ms);
        assert!(drift.mean_signed_ms > 80.0);
        // The single per-frame sample must reflect the +100 ms drift
        // (signed positive: stamp landed in the past relative to wire).
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
        // Type 36 (M_ME_TF_1): float + QDS + CP56. SQ=0, N=1.
        // Same DUI, IOA, payload — only the trailing CP56 bytes differ.
        let mut a = vec![
            36, 0x01, 0x03, 0, 0x01, 0,    // DUI
            0x01, 0, 0,                    // IOA
            0xde, 0xad, 0xbe, 0xef, 0x00,  // float + QDS
        ];
        let mut b = a.clone();
        // Append two different CP56 stamps.
        a.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x04, 0x18]);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18]);
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Cp56Only);
    }

    #[test]
    fn compare_asdu_real_diff_in_payload_classified() {
        // Same as above but the float byte changes too.
        let mut a = vec![
            36, 0x01, 0x03, 0, 0x01, 0,
            0x01, 0, 0,
            0xde, 0xad, 0xbe, 0xef, 0x00,
        ];
        let mut b = a.clone();
        b[12] = 0xff;  // mutate the float payload
        a.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x04, 0x18]);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18]);
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Different);
    }

    #[test]
    fn compare_asdu_no_cp56_field_is_real_diff() {
        // Type 13 (M_ME_NC_1): no CP56 -> any byte diff is real.
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
        // Type 13 (M_ME_NC_1) has no CP56 field.
        let asdu = vec![
            13, 0x01, 0x03, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut frame = vec![0x68, (asdu.len() + 4) as u8, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&asdu);
        let flow = fake_flow(frame, vec![(0, 0)]);
        assert!(compute_cp56_drift(&flow, 0, Cp56Zone::Utc, 50.0).is_none());
    }
}
