//! IEC 60870-5-104 post-run analyzer.
//!
//! Compares one endpoint's source (original pcap) flow against one
//! captured TCP session of the replay and produces:
//!
//! * **Playback side**: what outstation was expected to deliver. The
//!   delivered I-frames are aligned against the source script with a
//!   Myers diff over content hashes (CP56Time2a bytes masked), so one
//!   dropped frame shows up as one gap instead of a cascade. Each
//!   aligned pair is classified as byte-identical, CP56-only (accepted
//!   only when CP56 rewriting was on and the stamp is within
//!   tolerance) or modified; unaligned frames are missing, extra or
//!   reordered. Loop-within-session runs are aligned against the
//!   script repeated N times and reported per iteration, with a
//!   stopped-tail partial iteration when the run was stopped.
//! * **Synthesized GI/CI responses**: frames the slave synthesized in
//!   answer to live master interrogations are identified by matching
//!   each live request to its ActCon..ActTerm response burst and are
//!   removed from the delivered side only. The source script's own
//!   captured interrogation bursts stay on both sides, because the
//!   replayer resends them verbatim.
//! * **Synthesized command responses**: with command echo on (slave
//!   role, `commands.enabled`, the default) the captured command
//!   confirmations are not expected ([`commands::is_captured_command_frame`]),
//!   and the confirmations, return information and ActTerms the slave
//!   sent in answer to the live master's commands are removed from the
//!   delivered side, like synthesized GI/CI responses. With return
//!   information on, the capture's own remote return information
//!   (COT 11) is not expected either; local (COT 12) is. The expected
//!   side is filtered by the replayer's own rule,
//!   [`interrogation::CaptureStrip`].
//! * **Command-driven state**: a command executed with return
//!   information changes the point's value in the slave's inventory,
//!   and later GI/CI answers carry the new value. The identification
//!   and audit of those answers replay the same changes in stream
//!   order (`InventoryTimeline`).
//! * **Injected faults** (`proto_config.faults`): frames the replayer
//!   deliberately dropped (an N(S) gap on the wire), duplicated (a
//!   repeated N(S) with identical content) or sent with a corrupted
//!   N(S) are not replay infidelity: duplicates leave the delivered
//!   side, dropped frames are excused from the missing count, a
//!   session the peer ended in reaction is judged like a stopped run,
//!   and timing is not judged. The `faults` verdict dimension
//!   summarises what the capture shows of the faults and the peer's
//!   reaction.
//! * **Target side**: what the live peer sent back: U/S/I frame
//!   counts, STARTDT detection, optional "correct mode" target-script
//!   comparison (aligned, not positional).
//! * **Timing**: per-iteration pacing from aligned frame pairs
//!   (synthesized frames excluded), gap deltas, drift and an honest
//!   speed label.
//! * **CP56Time2a drift**: when the run rewrote timestamps to the
//!   wire-send moment, each stamp is compared to its actual send time.
//! * **Verdict**: content score plus pass/fail dimensions for time
//!   tags, the GI/CI audit, timing and the STARTDT handshake. See
//!   [`decide_verdict`].
//!
//! All byte-stream walkers in this module go through the crate's one
//! framer ([`crate::apci::frames`]), which resynchronises on junk
//! instead of stopping, so frame indices agree between the comparison,
//! timing, drift and audit passes and with the replayer itself.
//!
//! This module is called by [`crate::Iec104Replayer::analyze_flow`]
//! via the generic [`protoplay::ProtoReplayer`] trait, so the webui
//! shell stays protocol-agnostic.

use std::collections::{BTreeMap, HashMap};

use protoplay::{
    AnalyzeCtx, FleetDriftTimeline, FlowSnapshot, ProtoSlaveAnalysis, Role, VerdictOutcome,
};
use serde::Serialize;
use serde_json::json;

use crate::apci;
use crate::apdu::{
    U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT, U_TESTFR_CON,
};
use crate::asdu::{
    common_address, cot_value, cp56_field_offsets, decode_cp56time2a, decode_cp56time2a_local,
    load_rewrite_map, rewrite_asdu, vsq, Cp56Zone, Iec104ProtoConfig, DUI_LEN, IOA_LEN,
};
use crate::commands;
use crate::faults::FaultPlan;
use crate::interrogation;
use crate::inventory::{Inventory, CA_BROADCAST};
use crate::responder::{
    respond_ci, respond_gi, InterrogationResponse, RequestEcho, COT_ACT_CON, COT_ACT_TERM,
    COT_INROGEN_STATION, COT_REQCOGEN, COT_REQCO_GROUP_BASE, COT_UNKNOWN_CA,
};

/// Cap on points emitted in the fleet drift timeline. Aggregates
/// (mean / p99) stay accurate beyond this; only the scatter is trimmed.
pub const MAX_FLEET_TIMELINE_POINTS: usize = 5_000;

/// Cap on the per-endpoint CP56 drift sample arrays. Samples beyond
/// the cap are decimated with a uniform stride (recorded in
/// `sample_stride`), never truncated to a prefix, so a long session's
/// later samples stay represented. Aggregates use every sample.
pub const MAX_DRIFT_SAMPLES: usize = 5_000;

/// Cap on the per-endpoint mismatch list. `mismatches_total` keeps the
/// real count.
pub const MAX_MISMATCH_ENTRIES: usize = 200;

/// Cap on the type-ID sequences and the missing-index list.
/// `*_type_id_counts` keep the full histograms.
pub const MAX_SEQUENCE_ENTRIES: usize = 2_000;

/// Cap on the gap arrays (uniform stride; stats use every gap).
pub const MAX_GAP_SAMPLES: usize = 2_000;

/// Cap on the per-endpoint pacing samples handed to the shell
/// (uniform stride; `pacing_samples_total` keeps the real count).
pub const MAX_PACING_SAMPLES: usize = 2_000;

/// Cap on the per-iteration report list (first and last halves kept).
pub const MAX_ITERATION_ENTRIES: usize = 500;

/// Cap on GI/CI audit events kept in the report (counts stay exact).
pub const MAX_AUDIT_EVENTS: usize = 500;

/// Speed ratios within ±5 % of the reference are labelled "matched".
pub const SPEED_MATCH_TOLERANCE: f64 = 0.05;

/// Timing fails (when the run was paced) if the worst cumulative drift
/// exceeds this many ms *and* [`TIMING_DRIFT_FAIL_REL`] of the
/// iteration's original span.
pub const TIMING_DRIFT_FAIL_MS: f64 = 1_000.0;
/// Relative part of the timing drift threshold.
pub const TIMING_DRIFT_FAIL_REL: f64 = 0.05;
/// Share-of-frames statistic: frames whose drift is within ±this.
pub const DRIFT_WITHIN_MS: f64 = 100.0;

/// Edit-distance budget (half-edits per Myers middle-snake search).
/// Regions that differ by more than this are left unaligned and
/// reported as positional substitutions, keeping worst-case cost at
/// O((N+M)·ALIGN_MAX_D) instead of O(N·M).
pub const ALIGN_MAX_D: usize = 4_096;

// ---------------------------------------------------------------------
// Report structures (serialized into `protocol_specific`)
// ---------------------------------------------------------------------

#[derive(Serialize, Debug, Clone, Default)]
pub struct PlaybackReport {
    pub direction: &'static str,
    /// Expected I-frames in scope: script length × iterations judged,
    /// minus a stopped tail.
    pub expected_iframes: usize,
    /// I-frames in one pass of the source script.
    pub script_iframes: usize,
    /// Delivered I-frames, synthesized GI/CI responses excluded.
    pub delivered_iframes: usize,
    /// Delivered I-frames identified as synthesized GI/CI responses.
    pub synthesized_excluded: usize,
    /// GI/CI response synthesis was on for this run (slave role).
    pub gi_ci_synthesis: bool,
    /// Captured interrogation frames removed from the expected side
    /// because the replayer strips them when synthesis is on.
    pub source_interrogation_stripped: usize,
    /// Command echo was on for this run (slave role).
    pub command_echo: bool,
    /// Captured command confirmations removed from the expected side
    /// because the replayer strips them when command echo is on.
    pub source_command_stripped: usize,
    /// Captured return information caused by a remote command (COT 11)
    /// removed from the expected side because the replayer strips it
    /// when command echo synthesizes return information. COT 12 (local
    /// command) stays expected.
    pub source_return_info_stripped: usize,
    /// Delivered I-frames identified as synthesized command responses
    /// (also counted in `synthesized_excluded`).
    pub command_responses_excluded: usize,
    /// Missing frames excused because the replayer dropped them on
    /// purpose (`drop_iframes` fault).
    pub fault_dropped_excused: usize,
    /// Delivered duplicates removed because the replayer sent them on
    /// purpose (`duplicate_iframes` fault).
    pub fault_duplicates_excluded: usize,
    /// Primary metric: (byte-identical + accepted CP56-only) /
    /// (expected + extra), in percent.
    pub content_score_pct: f64,
    /// Secondary metric: aligned pairs whose type IDs agree. Kept for
    /// reference only; it does not drive the verdict.
    pub matched_type_ids: usize,
    pub type_id_match_pct: f64,
    /// Every expected frame was delivered in order with the right type
    /// ID and nothing extra arrived.
    pub type_id_sequence_match: bool,
    pub byte_identical_count: usize,
    /// CP56-only differences accepted (rewrite on, within tolerance).
    pub cp56_only_count: usize,
    /// CP56-only differences whose stamp is out of tolerance.
    pub cp56_out_of_tolerance_count: usize,
    /// CP56-only differences while rewriting was off (real mismatch).
    pub cp56_changed_count: usize,
    pub modified_count: usize,
    pub missing_count: usize,
    pub extra_count: usize,
    pub reordered_count: usize,
    /// Expected frames never sent because the run was stopped.
    pub not_sent_count: usize,
    /// modified + missing + extra + reordered + cp56_changed.
    pub real_mismatch_count: usize,
    /// Expected-stream indices (iteration × script + position) of
    /// missing frames, capped at [`MAX_SEQUENCE_ENTRIES`].
    pub missing_indices: Vec<usize>,
    pub mismatches: Vec<IFrameDiff>,
    pub mismatches_total: usize,
    pub mismatches_truncated: bool,
    pub iterations: Vec<IterationReport>,
    pub iterations_truncated: bool,
    pub iterations_configured: u64,
    pub iterations_observed: usize,
    /// Passes delivered beyond `iterations_configured` (when that is
    /// known): every frame in them counts as extra (N12).
    pub extra_passes: usize,
    pub iterations_complete: usize,
    pub iterations_clean: usize,
    pub stopped_tail: Option<TailReport>,
    /// False when some region differed by more than [`ALIGN_MAX_D`]
    /// edits and was compared positionally instead.
    pub alignment_complete: bool,
    pub expected_type_ids: Vec<u8>,
    pub delivered_type_ids: Vec<u8>,
    pub type_id_sequences_truncated: bool,
    pub expected_type_id_counts: BTreeMap<u8, usize>,
    pub delivered_type_id_counts: BTreeMap<u8, usize>,
    pub source_stream: WalkStats,
    pub delivered_stream: WalkStats,
}

/// One entry in the bounded mismatch list.
#[derive(Serialize, Debug, Clone)]
pub struct IFrameDiff {
    /// `modified`, `missing`, `extra`, `reordered`, `cp56_changed` or
    /// `cp56_out_of_tolerance`.
    pub kind: &'static str,
    /// Delivered-stream index (synthesized frames excluded), or the
    /// expected-stream index for `missing`.
    pub index: usize,
    pub iteration: usize,
    pub expected_index: Option<usize>,
    pub delivered_index: Option<usize>,
    pub expected_type_id: Option<u8>,
    pub actual_type_id: Option<u8>,
    pub expected_asdu_hex: String,
    pub actual_asdu_hex: String,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct IterationReport {
    /// 1-based.
    pub iteration: usize,
    /// `clean`, `deviations`, `stopped_tail_clean`,
    /// `stopped_tail_deviations`, `not_started` or `extra_pass` (a pass
    /// beyond the configured iteration count; all of it is extra).
    pub status: &'static str,
    pub expected: usize,
    pub identical: usize,
    pub cp56_ok: usize,
    pub cp56_out_of_tolerance: usize,
    pub cp56_changed: usize,
    pub modified: usize,
    pub missing: usize,
    pub extra: usize,
    pub reordered: usize,
    pub not_sent: usize,
    pub score_pct: f64,
    pub original_span_ms: f64,
    pub captured_span_ms: f64,
    pub speedup_factor: f64,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct TailReport {
    pub iteration: usize,
    /// Frames of the final iteration that were sent before the stop.
    pub sent: usize,
    pub script_iframes: usize,
    pub clean: bool,
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
    pub target_type_ids_truncated: bool,
    pub correctness: Option<CorrectnessCheck>,
    pub stream: WalkStats,
}

#[derive(Serialize, Debug, Clone)]
pub struct CorrectnessCheck {
    pub expected_iframes: usize,
    pub actual_iframes: usize,
    /// Aligned pairs with equal type IDs (name kept for the UI; the
    /// comparison is an alignment, not a prefix).
    pub matched_type_id_prefix: usize,
    pub missing_tail: Vec<u8>,
    pub extra_tail: Vec<u8>,
    pub byte_identical_count: usize,
    pub cp56_only_count: usize,
    pub modified_count: usize,
    pub missing_count: usize,
    pub extra_count: usize,
    /// modified + missing + extra.
    pub total_mismatches: usize,
    pub lcs_type_ids: usize,
    pub lcs_similarity: f64,
    pub content_score_pct: f64,
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
    pub drift_samples_ms: Vec<f64>,
    pub sample_frame_indices: Vec<u32>,
    pub sample_type_ids: Vec<u8>,
    pub sample_wall_ms: Vec<f64>,
    /// True when the sample arrays were decimated.
    pub samples_truncated: bool,
    /// Every `sample_stride`-th sample is kept; each kept sample
    /// stands for this many real ones (fleet aggregation weight).
    pub sample_stride: usize,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct TimingReport {
    /// I-frames in one pass of the source script.
    pub original_iframes: usize,
    /// Delivered I-frames used for timing (synthesized excluded).
    pub captured_iframes: usize,
    /// Aligned pairs the timing statistics are computed from.
    pub paired_frames: usize,
    /// Span of one pass of the source script.
    pub original_duration_ms: f64,
    /// Span of the whole delivered session (all iterations).
    pub captured_duration_ms: f64,
    /// Σ original span / Σ captured span over the aligned pairs of
    /// every iteration (>1 = faster than the original).
    pub speedup_factor: f64,
    /// "matched" within ±5 %, else "N.NN× faster" / "N.NN× slower";
    /// "n/a" when there is nothing to measure.
    pub speed_label: String,
    /// Configured pacing speed, when the run replayed original timing.
    pub paced_speed: Option<f64>,
    pub original_mean_gap_ms: f64,
    pub captured_mean_gap_ms: f64,
    pub original_p50_gap_ms: f64,
    pub captured_p50_gap_ms: f64,
    pub original_p99_gap_ms: f64,
    pub captured_p99_gap_ms: f64,
    /// |captured gap − original gap / speed| over consecutive aligned
    /// pairs.
    pub gap_delta_p50_ms: f64,
    pub gap_delta_p95_ms: f64,
    pub gap_delta_max_ms: f64,
    /// Worst |cumulative drift| over aligned pairs, per iteration.
    pub max_abs_drift_ms: f64,
    /// Share of aligned pairs whose drift is within ±[`DRIFT_WITHIN_MS`].
    pub drift_within_pct: f64,
    pub drift_within_ms: f64,
    /// `Some(reason)` when the run was paced and drift exceeded the
    /// threshold. `None` when timing passed or was not judged.
    pub timing_failure: Option<String>,
    pub timing_judged: bool,
    pub original_gaps_ms: Vec<f64>,
    pub captured_gaps_ms: Vec<f64>,
    pub gaps_truncated: bool,
}

/// Framing statistics of one byte stream.
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub bytes: usize,
    pub frames: usize,
    pub i_frames: usize,
    /// Bytes skipped before the first self-consistent frame boundary
    /// (mid-flow capture).
    pub leading_skipped_bytes: usize,
    /// Bytes skipped while resynchronising after a framing error.
    pub resynced_bytes: usize,
    pub resync_events: usize,
    /// Bytes of an incomplete final frame (capture cut mid-frame).
    pub truncated_tail_bytes: usize,
}

impl WalkStats {
    /// Bytes that did not parse. A stream with no frame at all is
    /// reported by the walker as one trailing run, which counts here.
    fn skipped(&self) -> usize {
        let tail = if self.frames == 0 {
            self.truncated_tail_bytes
        } else {
            0
        };
        self.leading_skipped_bytes + self.resynced_bytes + tail
    }
}

// ---------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------

/// Entry point for [`crate::Iec104Replayer::analyze_flow`].
///
/// Returns a [`ProtoSlaveAnalysis`] with IEC 104-specific detail packed
/// inside `protocol_specific` and the common fields (score, verdict,
/// outcome, expected/delivered counts, handshake flag, pacing samples)
/// surfaced so the webui core can roll them into the fleet summary
/// without protocol knowledge.
pub fn analyze_iec104_flow(
    orig_playback: Option<FlowSnapshot>,
    cap_playback: Option<FlowSnapshot>,
    orig_target: Option<FlowSnapshot>,
    cap_target: Option<FlowSnapshot>,
    ctx: &AnalyzeCtx,
) -> ProtoSlaveAnalysis {
    let mut notes: Vec<String> = Vec::new();
    let cp56_cfg = match Iec104ProtoConfig::parse(ctx.proto_config.as_deref()) {
        Ok(c) => c.cp56,
        Err(e) => {
            notes.push(format!(
                "{e}; analysed as if CP56 rewriting was off (the run itself would have refused this config)"
            ));
            Default::default()
        }
    };
    let rewrite_cp56_was_on = cp56_cfg.rewrite_to_now;
    let cp56_zone = cp56_cfg.zone();

    // The replayer applies the run's CA/COT/IOA rewrite map to every
    // script frame and builds its GI/CI inventory from the rewritten
    // frames, so the reference is rewritten the same way.
    let rewrite_map = match load_rewrite_map(ctx.proto_config.as_deref()) {
        Ok(m) => m,
        Err(e) => {
            notes.push(format!(
                "proto_config (rewrite map): {e}; reference not rewritten"
            ));
            Default::default()
        }
    };
    let rewritten_src: Option<Vec<u8>> = match orig_playback.as_ref() {
        Some(orig) if !rewrite_map.is_empty() => {
            let mut buf = orig.payload.to_vec();
            let iframes: Vec<(usize, usize)> = apci::frames(orig.payload)
                .filter(|f| f.is_i())
                .map(|f| (f.offset + 6, f.end()))
                .collect();
            for (a, b) in iframes {
                rewrite_asdu(&mut buf[a..b], &rewrite_map);
            }
            Some(buf)
        }
        _ => None,
    };
    let orig_playback: Option<FlowSnapshot> = match (orig_playback, rewritten_src.as_deref()) {
        (Some(orig), Some(buf)) => Some(FlowSnapshot {
            payload: buf,
            packet_offsets: orig.packet_offsets,
        }),
        (o, _) => o,
    };

    let src = orig_playback.as_ref().map(parse_flow).unwrap_or_default();
    let cap = cap_playback.as_ref().map(parse_flow).unwrap_or_default();
    let cap_tg = cap_target.as_ref().map(parse_flow).unwrap_or_default();
    let orig_tg = orig_target.as_ref().map(parse_flow).unwrap_or_default();

    push_walk_note(&mut notes, "source", &src.stats);
    push_walk_note(&mut notes, "captured", &cap.stats);

    // --- Expected side ---
    // With GI/CI synthesis on, the slave strips the captured
    // interrogation exchanges from its script (it answers live requests
    // instead), so they are not expected either. Likewise for captured
    // command confirmations with command echo on, and captured remote
    // return information (COT 11) when the echo synthesizes its own.
    // Same rule as the replayer: `interrogation::CaptureStrip`.
    let synthesis_on =
        ctx.role == Role::Slave && interrogation::synthesis_enabled(ctx.proto_config.as_deref());
    let command_cfg = commands::commands_config(ctx.proto_config.as_deref());
    let echo_on = ctx.role == Role::Slave && command_cfg.enabled;
    let strip = if ctx.role == Role::Slave {
        interrogation::CaptureStrip::new(synthesis_on, &command_cfg)
    } else {
        interrogation::CaptureStrip::default()
    };
    let mut source_interrogation_stripped = 0usize;
    let mut source_command_stripped = 0usize;
    let mut source_return_info_stripped = 0usize;
    let expected_frames: Vec<IFrame> = src
        .iframes
        .iter()
        .filter(|f| match strip.classify(f.asdu) {
            None => true,
            Some(kind) => {
                *match kind {
                    interrogation::Stripped::Interrogation => &mut source_interrogation_stripped,
                    interrogation::Stripped::Command => &mut source_command_stripped,
                    interrogation::Stripped::ReturnInfo => &mut source_return_info_stripped,
                } += 1;
                false
            }
        })
        .copied()
        .collect();
    if source_interrogation_stripped > 0 {
        notes.push(format!(
            "GI/CI synthesis was on: {source_interrogation_stripped} captured interrogation frames are not replayed and not expected"
        ));
    }
    if source_command_stripped > 0 {
        notes.push(format!(
            "command echo was on: {source_command_stripped} captured command confirmations are not replayed and not expected"
        ));
    }
    if source_return_info_stripped > 0 {
        notes.push(format!(
            "command echo with return information was on: {source_return_info_stripped} captured return-information frames (COT 11, remote command) are not replayed and not expected"
        ));
    }

    // --- Injected faults: deliberate duplicates leave the delivered
    // side; deliberate drops are excused below. ---
    let fault_plan = match FaultPlan::parse(ctx.proto_config.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            notes.push(format!("{e}; analysed as if no faults were configured"));
            FaultPlan::default()
        }
    };
    let faults_on = !fault_plan.is_empty();
    let scan = if faults_on {
        scan_sequence(&cap.iframes, &fault_plan)
    } else {
        NsScan::clean(cap.iframes.len())
    };
    let cap_frames: Vec<IFrame> = cap
        .iframes
        .iter()
        .zip(&scan.keep)
        .filter(|(_, &k)| k)
        .map(|(f, _)| *f)
        .collect();

    // --- Synthesized GI/CI and command responses (slave role only) ---
    let mut inventory = Inventory::default();
    for f in &src.iframes {
        inventory.ingest_asdu(f.asdu);
    }
    let live_requests = if ctx.role == Role::Slave {
        collect_master_requests(&cap_tg.iframes)
    } else {
        Vec::new()
    };
    let mut synth_flags = vec![false; cap_frames.len()];
    let live_commands: Vec<&IFrame> = if echo_on {
        cap_tg
            .iframes
            .iter()
            .filter(|f| {
                commands::is_command_request(f.asdu) && commands::is_command_type(f.asdu[0])
            })
            .collect()
    } else {
        Vec::new()
    };
    // Command answers first: the commands the slave executed change the
    // point values its later GI/CI answers carry (return information),
    // and both the identification and the audit below replay them.
    let (command_responses_excluded, executed) =
        identify_command_responses(&live_commands, &cap_frames, &command_cfg, &mut synth_flags);
    let mut timeline =
        InventoryTimeline::new(&inventory, &command_cfg, cp56_zone, executed.clone());
    identify_synthesized(&live_requests, &cap_frames, &mut timeline, &mut synth_flags);
    let synthesized_excluded = synth_flags.iter().filter(|&&s| s).count();
    if synthesized_excluded > command_responses_excluded {
        notes.push(format!(
            "excluded {} I-frames the slave synthesized in answer to {} live GI/CI request(s) from the playback comparison",
            synthesized_excluded - command_responses_excluded,
            live_requests.len()
        ));
    }
    if command_responses_excluded > 0 {
        notes.push(format!(
            "excluded {command_responses_excluded} I-frames the slave sent in answer to {} live command(s) from the playback comparison",
            live_commands.len()
        ));
    }
    let delivered: Vec<IFrame> = cap_frames
        .iter()
        .zip(&synth_flags)
        .filter(|(_, &s)| !s)
        .map(|(f, _)| *f)
        .collect();

    // --- CP56Time2a drift (only meaningful when rewrite_to_now was on) ---
    let cp56_drift = if rewrite_cp56_was_on {
        cp56_drift_over(
            &cap.iframes,
            ctx.captured_first_ts_ns,
            cp56_zone,
            ctx.cp56_tolerance_ms,
        )
    } else {
        None
    };
    if rewrite_cp56_was_on && cp56_drift.is_none() && !cap.iframes.is_empty() {
        notes.push(
            "fresh-timestamps mode was enabled but the captured flow contained no CP56Time2a \
             fields (the ASDU types in this pcap carry no time tag)"
                .into(),
        );
    }

    // --- Playback comparison ---
    let cmp_cfg = CompareCfg {
        rewrite_cp56: rewrite_cp56_was_on,
        zone: cp56_zone,
        tolerance_ms: ctx.cp56_tolerance_ms,
        epoch_ns: ctx.captured_first_ts_ns,
        iterations_configured: ctx.run.iterations_per_session,
        // A session the peer ended in reaction to an injected fault is
        // judged like a stopped run: the unsent tail is not missing.
        stopped_early: ctx.run.stopped_early || faults_on,
        // Faults stall the sender on purpose: timing is not judged.
        paced_speed: if faults_on { None } else { ctx.run.paced_speed },
    };
    if faults_on && ctx.run.paced_speed.is_some() {
        notes.push("faults were injected: pacing is measured but not judged".into());
    }
    let cmp = compare_playback(&expected_frames, &delivered, &cmp_cfg);
    if !cmp.alignment_complete {
        notes.push(format!(
            "some regions differed by more than {ALIGN_MAX_D} edits and were compared positionally"
        ));
    }
    if cmp.iterations_observed > 1 {
        notes.push(format!(
            "captured session contains {} passes of the {}-frame source script; each pass is judged separately",
            cmp.iterations_observed,
            expected_frames.len()
        ));
    }
    if cmp.report.extra_passes > 0 {
        notes.push(format!(
            "{} pass(es) beyond the {} configured iteration(s) were delivered; their frames count as extra",
            cmp.report.extra_passes, cmp_cfg.iterations_configured
        ));
    }

    let mut playback = cmp.report;
    playback.direction = match ctx.role {
        Role::Master => "master → server",
        Role::Slave => "slave → master",
    };
    playback.synthesized_excluded = synthesized_excluded;
    playback.gi_ci_synthesis = synthesis_on;
    playback.source_interrogation_stripped = source_interrogation_stripped;
    playback.command_echo = echo_on;
    playback.source_command_stripped = source_command_stripped;
    playback.source_return_info_stripped = source_return_info_stripped;
    playback.command_responses_excluded = command_responses_excluded;
    playback.fault_duplicates_excluded = scan.duplicates;
    // Deliberately dropped frames are not replay infidelity.
    let excused = scan.dropped.min(playback.missing_count);
    if excused > 0 {
        playback.fault_dropped_excused = excused;
        playback.missing_count -= excused;
        playback.expected_iframes = playback.expected_iframes.saturating_sub(excused);
        playback.real_mismatch_count = playback.real_mismatch_count.saturating_sub(excused);
        notes.push(format!(
            "{excused} missing I-frame(s) were dropped on purpose (drop_iframes fault) and are not counted"
        ));
    }
    if scan.duplicates > 0 {
        notes.push(format!(
            "{} duplicate I-frame(s) sent on purpose (duplicate_iframes fault) were removed from the delivered side",
            scan.duplicates
        ));
    }
    let faults_report =
        faults_on.then(|| faults_report(&fault_plan, &scan, &cap, &cap_tg, ctx.role));
    playback.source_stream = src.stats.clone();
    playback.delivered_stream = cap.stats.clone();

    // --- Target-side analysis ---
    let target_tids: Vec<u8> = cap_tg.iframes.iter().map(|f| type_id_of(f.asdu)).collect();
    let startdt_handshake_ok = match ctx.role {
        Role::Master => cap_tg.u_codes.iter().any(|c| c == "STARTDT_CON"),
        Role::Slave => cap_tg.u_codes.iter().any(|c| c == "STARTDT_ACT"),
    };
    let correctness = if ctx.mode_correct {
        Some(compare_target(&orig_tg.iframes, &cap_tg.iframes))
    } else {
        None
    };
    let (target_type_ids, target_type_ids_truncated) = capped(&target_tids, MAX_SEQUENCE_ENTRIES);
    let target = TargetReport {
        direction: target_direction(ctx.role),
        u_frames: cap_tg.u_frames,
        s_frames: cap_tg.s_frames,
        i_frames: cap_tg.iframes.len(),
        u_codes_seen: dedup_codes(&cap_tg.u_codes),
        startdt_handshake_ok,
        target_type_ids,
        target_type_ids_truncated,
        correctness,
        stream: cap_tg.stats.clone(),
    };

    // --- GI / CI audit (slave role: the master interrogates, the
    // slave-replayer synthesizes responses) ---
    // The audit walks the whole slave-side stream (fault duplicates
    // included), so the executed commands are re-indexed into it.
    let gi_ci_audit = match (ctx.role, cap_target.as_ref(), cap_playback.as_ref()) {
        (Role::Slave, Some(_), Some(_)) => {
            let kept: Vec<usize> = scan
                .keep
                .iter()
                .enumerate()
                .filter(|(_, &k)| k)
                .map(|(i, _)| i)
                .collect();
            let executed = executed.iter().map(|&(at, cmd)| (kept[at], cmd)).collect();
            let mut timeline =
                InventoryTimeline::new(&inventory, &command_cfg, cp56_zone, executed);
            Some(audit_requests(&live_requests, &cap.iframes, &mut timeline))
        }
        _ => None,
    };

    // --- Verdict ---
    let gi_ci_failed = gi_ci_audit
        .as_ref()
        .map(|a| a.gi_partial + a.gi_non_compliant + a.ci_partial + a.ci_non_compliant)
        .unwrap_or(0);
    let vin = VerdictInputs {
        reference_present: orig_playback.is_some(),
        reference_skipped_bytes: src.stats.skipped(),
        expected: playback.expected_iframes,
        delivered: playback.delivered_iframes,
        good: playback.byte_identical_count + playback.cp56_only_count,
        modified: playback.modified_count,
        missing: playback.missing_count,
        extra: playback.extra_count,
        reordered: playback.reordered_count,
        cp56_changed: playback.cp56_changed_count,
        cp56_out_of_tolerance: playback
            .cp56_out_of_tolerance_count
            .max(cp56_drift.as_ref().map(|d| d.out_of_tolerance).unwrap_or(0)),
        not_sent: playback.not_sent_count,
        iterations_complete: playback.iterations_complete,
        iterations_clean: playback.iterations_clean,
        stopped_tail: playback.stopped_tail.clone(),
        stopped_early: ctx.run.stopped_early || faults_on,
        handshake_ok: startdt_handshake_ok,
        gi_ci_failed,
        timing_failure: cmp.timing.timing_failure.clone(),
        target: target.correctness.as_ref().map(TargetVerdict::from),
        faults: faults_report.as_ref().map(|f| f.summary.clone()),
    };
    let verdict = decide_verdict(&vin);
    if let Some(f) = &faults_report {
        notes.push(f.summary.clone());
    }

    let protocol_specific = json!({
        "playback": playback,
        "target": target,
        "timing": cmp.timing,
        "cp56_drift": cp56_drift,
        "gi_ci_audit": gi_ci_audit,
        "faults": faults_report,
        "verdict_dimensions": verdict.dimensions,
    });

    ProtoSlaveAnalysis {
        score_pct: verdict.score,
        verdict: verdict.name,
        verdict_reason: verdict.reason,
        expected_messages: playback.expected_iframes,
        delivered_messages: playback.delivered_iframes,
        handshake_ok: startdt_handshake_ok,
        notes,
        protocol_specific,
        pacing_samples: cmp.pacing_samples,
        pacing_samples_total: cmp.pacing_samples_total,
        outcome: verdict.outcome,
    }
}

fn push_walk_note(notes: &mut Vec<String>, side: &str, st: &WalkStats) {
    if st.leading_skipped_bytes > 0 {
        notes.push(format!(
            "{side} stream starts mid-frame: skipped {} leading bytes before the first frame boundary",
            st.leading_skipped_bytes
        ));
    }
    if st.resync_events > 0 {
        notes.push(format!(
            "{side} stream had {} framing error(s); resynchronised past {} bytes",
            st.resync_events, st.resynced_bytes
        ));
    }
    if st.truncated_tail_bytes > 0 {
        notes.push(format!(
            "{side} stream ends inside a frame ({} trailing bytes ignored)",
            st.truncated_tail_bytes
        ));
    }
}

fn dedup_codes(codes: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in codes {
        if !out.contains(c) {
            out.push(c.clone());
        }
    }
    out
}

fn type_id_of(asdu: &[u8]) -> u8 {
    asdu.first().copied().unwrap_or(0)
}

/// Uniform-stride decimation: keeps every `stride`-th element so the
/// result has at most `cap` entries. Returns the stride (1 = kept all).
fn decimate<T: Clone>(v: &[T], cap: usize) -> (Vec<T>, usize) {
    if v.len() <= cap || cap == 0 {
        return (v.to_vec(), 1);
    }
    let stride = v.len().div_ceil(cap);
    (v.iter().step_by(stride).cloned().collect(), stride)
}

/// Prefix cap for sequences shown verbatim (type-ID sequences).
fn capped<T: Clone>(v: &[T], cap: usize) -> (Vec<T>, bool) {
    if v.len() <= cap {
        (v.to_vec(), false)
    } else {
        (v[..cap].to_vec(), true)
    }
}

// ---------------------------------------------------------------------
// Fleet drift aggregation
// ---------------------------------------------------------------------

/// Fleet-level CP56Time2a drift aggregator: walk each slave's
/// `protocol_specific` blob for its `cp56_drift.drift_samples_ms` +
/// `cp56_drift.sample_wall_ms` arrays, merge them on one time axis and
/// decimate to [`MAX_FLEET_TIMELINE_POINTS`] by weighted systematic
/// sampling. Each endpoint's samples carry its `sample_stride` as
/// weight, so an endpoint whose samples were decimated 10:1 is not
/// under-represented against one that kept every sample.
pub fn aggregate_iec104_fleet_drift(
    per_slave: &BTreeMap<String, serde_json::Value>,
    iteration_starts_ms: &[f64],
) -> Option<FleetDriftTimeline> {
    let mut all: Vec<(f64, f64, f64)> = Vec::new();
    let mut total_samples = 0usize;
    for v in per_slave.values() {
        let Some(dr) = v.get("cp56_drift") else {
            continue;
        };
        if dr.is_null() {
            continue;
        }
        let drift = dr.get("drift_samples_ms").and_then(|x| x.as_array());
        let walls = dr.get("sample_wall_ms").and_then(|x| x.as_array());
        let (Some(drift), Some(walls)) = (drift, walls) else {
            continue;
        };
        let stride = dr
            .get("sample_stride")
            .and_then(|x| x.as_u64())
            .unwrap_or(1)
            .max(1) as f64;
        total_samples += dr
            .get("samples")
            .and_then(|x| x.as_u64())
            .map(|n| n as usize)
            .unwrap_or(drift.len());
        let n = drift.len().min(walls.len());
        for i in 0..n {
            if let (Some(d), Some(w)) = (drift[i].as_f64(), walls[i].as_f64()) {
                all.push((w, d, stride));
            }
        }
    }
    if all.is_empty() {
        return None;
    }
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let (kept, decimated) = weighted_decimate(&all, MAX_FLEET_TIMELINE_POINTS);
    Some(FleetDriftTimeline {
        samples: kept,
        total_samples: total_samples.max(all.len()),
        decimated: decimated || total_samples > all.len(),
        iteration_starts_ms: iteration_starts_ms.to_vec(),
    })
}

/// Weighted random sampling without replacement (Efraimidis–Spirakis)
/// over time-sorted `(t, value, weight)` triples: keeps about `cap`
/// points, each chosen with probability proportional to its weight,
/// returned in time order. A fixed hash of the index replaces the
/// random source, so the output is deterministic. Returns `(points,
/// decimated)`.
pub fn weighted_decimate(sorted: &[(f64, f64, f64)], cap: usize) -> (Vec<[f64; 2]>, bool) {
    if sorted.len() <= cap {
        return (sorted.iter().map(|&(t, d, _)| [t, d]).collect(), false);
    }
    let mut keyed: Vec<(f64, usize)> = sorted
        .iter()
        .enumerate()
        .map(|(i, s)| {
            // splitmix64 → uniform (0, 1)
            let mut z = (i as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let u = ((z >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
            let w = s.2.max(1e-12);
            (u.ln() / w, i)
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

// ---------------------------------------------------------------------
// Framing: the shared `apci` walker (resyncs on junk)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct IFrame<'a> {
    ts_ns: u64,
    /// N(S) as sent on the wire.
    ns: u16,
    asdu: &'a [u8],
}

impl IFrame<'_> {
    fn ts_ms(&self) -> f64 {
        self.ts_ns as f64 / 1e6
    }
}

#[derive(Debug, Default)]
struct ParsedFlow<'a> {
    iframes: Vec<IFrame<'a>>,
    u_codes: Vec<String>,
    /// (ms, name) of every U-frame.
    u_events: Vec<(f64, &'static str)>,
    /// Timestamp (ms) of every frame, in stream order.
    frame_ts_ms: Vec<f64>,
    u_frames: usize,
    s_frames: usize,
    stats: WalkStats,
}

fn parse_flow<'a>(flow: &FlowSnapshot<'a>) -> ParsedFlow<'a> {
    let p: &'a [u8] = flow.payload;
    let mut out = ParsedFlow {
        stats: WalkStats {
            bytes: p.len(),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut walker = apci::frames(p);
    for f in walker.by_ref() {
        if f.skipped > 0 {
            if out.stats.frames == 0 {
                out.stats.leading_skipped_bytes += f.skipped;
            } else {
                out.stats.resynced_bytes += f.skipped;
                out.stats.resync_events += 1;
            }
        }
        out.stats.frames += 1;
        match f.kind {
            apci::FrameKind::I => {
                let c = f.apci();
                out.iframes.push(IFrame {
                    ts_ns: flow.ts_for_byte(f.offset),
                    ns: (u16::from(c[0]) >> 1) | (u16::from(c[1]) << 7),
                    asdu: f.asdu().unwrap_or_default(),
                })
            }
            apci::FrameKind::S => out.s_frames += 1,
            apci::FrameKind::U => {
                out.u_frames += 1;
                let name = u_code_name(f.apci()[0]);
                out.u_codes.push(name.to_string());
                out.u_events
                    .push((flow.ts_for_byte(f.offset) as f64 / 1e6, name));
            }
        }
        out.frame_ts_ms
            .push(flow.ts_for_byte(f.offset) as f64 / 1e6);
    }
    out.stats.i_frames = out.iframes.len();
    out.stats.truncated_tail_bytes = walker.trailing_bytes();
    out
}

fn u_code_name(code: u8) -> &'static str {
    match code {
        U_STARTDT_ACT => "STARTDT_ACT",
        U_STARTDT_CON => "STARTDT_CON",
        U_STOPDT_ACT => "STOPDT_ACT",
        U_STOPDT_CON => "STOPDT_CON",
        U_TESTFR_ACT => "TESTFR_ACT",
        U_TESTFR_CON => "TESTFR_CON",
        _ => "U_OTHER",
    }
}

// ---------------------------------------------------------------------
// ASDU comparison helpers
// ---------------------------------------------------------------------

/// Outcome of comparing two ASDU buffers. Fresh-timestamps mode (or a
/// live target with its own clock) will produce different CP56Time2a
/// bytes for the same underlying event.
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
    let in_cp56 = |i: usize| offs_a.iter().any(|&o| i >= o && i < o + 7);
    if a.iter()
        .zip(b)
        .enumerate()
        .all(|(i, (x, y))| x == y || in_cp56(i))
    {
        AsduCmp::Cp56Only
    } else {
        AsduCmp::Different
    }
}

/// Content hash used as the alignment key: FNV-1a over the ASDU with
/// every CP56Time2a field masked, so a frame whose only change is a
/// rewritten time tag still aligns with its source frame.
fn content_key(asdu: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let offs = cp56_field_offsets(asdu);
    let mut h = OFFSET ^ asdu.len() as u64;
    for (i, &b) in asdu.iter().enumerate() {
        let masked = offs.iter().any(|&o| i >= o && i < o + 7);
        h ^= if masked { 0 } else { b as u64 };
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Every CP56Time2a in an ASDU as `(unix_ns, iv, su)`, decoded in `zone`.
fn cp56_stamps(asdu: &[u8], zone: Cp56Zone) -> Vec<(u64, bool, bool)> {
    let mut out = Vec::new();
    for off in cp56_field_offsets(asdu) {
        let mut arr = [0u8; 7];
        arr.copy_from_slice(&asdu[off..off + 7]);
        match zone {
            Cp56Zone::Utc => out.push(decode_cp56time2a(&arr)),
            Cp56Zone::Local => {
                // Undecodable local stamps (DST gap) are skipped, not
                // read as epoch 0.
                if let Some((ns, iv)) = decode_cp56time2a_local(&arr) {
                    out.push((ns, iv, arr[3] & 0x80 != 0));
                }
            }
        }
    }
    out
}

/// Largest |stamp − wire-send time| over the CP56 fields of one frame.
fn frame_max_drift_ms(f: &IFrame, epoch_ns: u64, zone: Cp56Zone) -> Option<f64> {
    let send_ns = epoch_ns.saturating_add(f.ts_ns) as i128;
    cp56_stamps(f.asdu, zone)
        .into_iter()
        .map(|(ns, _, _)| ((send_ns - ns as i128) as f64 / 1e6).abs())
        .reduce(f64::max)
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
    percentile_sorted(&s, p)
}

fn percentile_sorted(s: &[f64], p: f64) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let n = s.len();
    let idx = ((n as f64 - 1.0) * p).round() as usize;
    s[idx.min(n - 1)]
}

fn pct(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        (num as f64 / den as f64 * 100.0).clamp(0.0, 100.0)
    }
}

// ---------------------------------------------------------------------
// Sequence alignment (Myers O(ND), linear space)
// ---------------------------------------------------------------------

/// Signed-index scratch vector for the Myers search.
struct V {
    off: isize,
    v: Vec<isize>,
}

impl V {
    fn new(max_d: usize) -> Self {
        let off = max_d as isize + 2;
        V {
            off,
            v: vec![0; 2 * (max_d + 2) + 1],
        }
    }
}

impl std::ops::Index<isize> for V {
    type Output = isize;
    fn index(&self, k: isize) -> &isize {
        &self.v[(k + self.off) as usize]
    }
}

impl std::ops::IndexMut<isize> for V {
    fn index_mut(&mut self, k: isize) -> &mut isize {
        &mut self.v[(k + self.off) as usize]
    }
}

/// Align two sequences and return the matched index pairs `(i, j)`
/// (`a[i] == b[j]`) of a longest common subsequence, in increasing
/// order. Uses Myers' linear-space O((N+M)·D) algorithm, so two
/// 100k-frame streams that differ by a handful of frames align in
/// milliseconds with O(N+M) memory.
///
/// Regions whose edit distance exceeds [`ALIGN_MAX_D`] are left
/// unaligned (the second return value is then `false`); callers treat
/// them as positional substitutions.
pub fn align_sequences<T: PartialEq>(a: &[T], b: &[T]) -> (Vec<(usize, usize)>, bool) {
    let mut out = Vec::new();
    let cap = ALIGN_MAX_D.min((a.len() + b.len()).div_ceil(2) + 1);
    let mut vf = V::new(cap);
    let mut vb = V::new(cap);
    let mut complete = true;
    conquer(
        a,
        0,
        a.len(),
        b,
        0,
        b.len(),
        &mut vf,
        &mut vb,
        cap,
        &mut out,
        &mut complete,
    );
    (out, complete)
}

#[allow(clippy::too_many_arguments)]
fn conquer<T: PartialEq>(
    a: &[T],
    mut a_lo: usize,
    a_hi: usize,
    b: &[T],
    mut b_lo: usize,
    b_hi: usize,
    vf: &mut V,
    vb: &mut V,
    cap: usize,
    out: &mut Vec<(usize, usize)>,
    complete: &mut bool,
) {
    while a_lo < a_hi && b_lo < b_hi && a[a_lo] == b[b_lo] {
        out.push((a_lo, b_lo));
        a_lo += 1;
        b_lo += 1;
    }
    let (mut sa, mut sb) = (a_hi, b_hi);
    while sa > a_lo && sb > b_lo && a[sa - 1] == b[sb - 1] {
        sa -= 1;
        sb -= 1;
    }
    if sa > a_lo && sb > b_lo {
        let n = sa - a_lo;
        let m = sb - b_lo;
        match middle_snake(&a[a_lo..sa], &b[b_lo..sb], vf, vb, cap) {
            Some((x, y)) if (x, y) != (0, 0) && (x, y) != (n, m) && x <= n && y <= m => {
                conquer(
                    a,
                    a_lo,
                    a_lo + x,
                    b,
                    b_lo,
                    b_lo + y,
                    vf,
                    vb,
                    cap,
                    out,
                    complete,
                );
                conquer(a, a_lo + x, sa, b, b_lo + y, sb, vf, vb, cap, out, complete);
            }
            _ => *complete = false,
        }
    }
    for k in 0..(a_hi - sa) {
        out.push((sa + k, sb + k));
    }
}

/// Find the start of the middle snake of an optimal edit path between
/// `a` and `b` (both non-empty, first and last elements differing).
/// Returns `None` when the half edit distance exceeds `cap`.
fn middle_snake<T: PartialEq>(
    a: &[T],
    b: &[T],
    vf: &mut V,
    vb: &mut V,
    cap: usize,
) -> Option<(usize, usize)> {
    let n = a.len() as isize;
    let m = b.len() as isize;
    let delta = n - m;
    let odd = delta & 1 == 1;
    vf[1] = 0;
    vb[1] = 0;
    let d_max = ((n + m + 1) / 2 + 1).min(cap as isize);
    for d in 0..d_max {
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && vf[k - 1] < vf[k + 1]) {
                vf[k + 1]
            } else {
                vf[k - 1] + 1
            };
            let mut y = x - k;
            let (x0, y0) = (x, y);
            while x >= 0 && y >= 0 && x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            vf[k] = x;
            if odd && (k - delta).abs() < d && vf[k] + vb[-(k - delta)] >= n {
                return (x0 >= 0 && y0 >= 0).then_some((x0 as usize, y0 as usize));
            }
            k += 2;
        }
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && vb[k - 1] < vb[k + 1]) {
                vb[k + 1]
            } else {
                vb[k - 1] + 1
            };
            let mut y = x - k;
            while x >= 0
                && y >= 0
                && x < n
                && y < m
                && a[(n - x - 1) as usize] == b[(m - y - 1) as usize]
            {
                x += 1;
                y += 1;
            }
            vb[k] = x;
            if !odd && (k - delta).abs() <= d && vb[k] + vf[-(k - delta)] >= n {
                let (sx, sy) = (n - x, m - y);
                return (sx >= 0 && sy >= 0).then_some((sx as usize, sy as usize));
            }
            k += 2;
        }
    }
    None
}

/// Smallest `L` such that `b` aligns against `a[..L]` with the fewest
/// edits (a forward Myers pass that stops when `b` is consumed). Used
/// to anchor a delivered stream at the start of a repeated script.
/// Returns `a.len()` when the edit budget runs out.
fn prefix_extent<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    let n = a.len() as isize;
    let m = b.len() as isize;
    if m == 0 {
        return 0;
    }
    let cap = ALIGN_MAX_D.min(a.len() + b.len());
    let mut v = V::new(cap);
    v[1] = 0;
    for d in 0..=cap as isize {
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && v[k - 1] < v[k + 1]) {
                v[k + 1]
            } else {
                v[k - 1] + 1
            };
            let mut y = x - k;
            while x >= 0 && y >= 0 && x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[k] = x;
            if y >= m && x <= n {
                return x.max(0) as usize;
            }
            k += 2;
        }
    }
    a.len()
}

/// Length of the longest common subsequence of two `u8` streams,
/// computed with [`align_sequences`] (no greedy fallback).
pub fn lcs_length(a: &[u8], b: &[u8]) -> usize {
    align_sequences(a, b).0.len()
}

/// Edit script derived from an alignment: matched pairs, positional
/// substitutions inside each gap, and the leftover missing / extra
/// indices.
#[derive(Debug, Default)]
struct EditScript {
    /// `(expected_idx, delivered_idx, keys_equal)` in increasing order.
    pairs: Vec<(usize, usize, bool)>,
    missing: Vec<usize>,
    extra: Vec<usize>,
    /// `(expected_idx, delivered_idx)` of frames delivered with the
    /// right content at the wrong position.
    reordered: Vec<(usize, usize)>,
    complete: bool,
}

fn edit_script(exp: &[u64], del: &[u64]) -> EditScript {
    let (matched, complete) = align_sequences(exp, del);
    let mut es = EditScript {
        complete,
        ..Default::default()
    };
    let (mut pe, mut pd) = (0usize, 0usize);
    let sentinel = (exp.len(), del.len());
    for &(e, d) in matched.iter().chain(std::iter::once(&sentinel)) {
        let ge = e - pe;
        let gd = d - pd;
        let k = ge.min(gd);
        for i in 0..k {
            es.pairs.push((pe + i, pd + i, false));
        }
        es.missing.extend(pe + k..e);
        es.extra.extend(pd + k..d);
        if e < exp.len() && d < del.len() {
            es.pairs.push((e, d, true));
        }
        pe = e + 1;
        pd = d + 1;
    }
    // Reorders: a missing frame whose content shows up as an extra
    // frame elsewhere was delivered, just at the wrong position.
    if !es.missing.is_empty() && !es.extra.is_empty() {
        let mut by_key: HashMap<u64, Vec<usize>> = HashMap::new();
        for &e in es.missing.iter().rev() {
            by_key.entry(exp[e]).or_default().push(e);
        }
        let mut keep_extra = Vec::with_capacity(es.extra.len());
        let mut moved: Vec<usize> = Vec::new();
        for &d in &es.extra {
            match by_key.get_mut(&del[d]).and_then(|v| v.pop()) {
                Some(e) => {
                    es.reordered.push((e, d));
                    moved.push(e);
                }
                None => keep_extra.push(d),
            }
        }
        es.extra = keep_extra;
        moved.sort_unstable();
        es.missing.retain(|e| moved.binary_search(e).is_err());
    }
    es
}

// ---------------------------------------------------------------------
// Playback comparison
// ---------------------------------------------------------------------

struct CompareCfg {
    rewrite_cp56: bool,
    zone: Cp56Zone,
    tolerance_ms: f64,
    epoch_ns: u64,
    iterations_configured: u64,
    stopped_early: bool,
    paced_speed: Option<f64>,
}

struct CompareResult {
    report: PlaybackReport,
    timing: TimingReport,
    pacing_samples: Vec<[f64; 2]>,
    pacing_samples_total: usize,
    alignment_complete: bool,
    iterations_observed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairClass {
    Identical,
    Cp56Ok,
    Cp56OutOfTolerance,
    Cp56Changed,
    Modified,
}

fn classify_pair(exp: &[u8], got: &IFrame, cfg: &CompareCfg) -> PairClass {
    match compare_asdu(exp, got.asdu) {
        AsduCmp::Identical => PairClass::Identical,
        AsduCmp::Different => PairClass::Modified,
        AsduCmp::Cp56Only if !cfg.rewrite_cp56 => PairClass::Cp56Changed,
        AsduCmp::Cp56Only => match frame_max_drift_ms(got, cfg.epoch_ns, cfg.zone) {
            Some(d) if d <= cfg.tolerance_ms => PairClass::Cp56Ok,
            _ => PairClass::Cp56OutOfTolerance,
        },
    }
}

/// Compare the delivered stream against the source script, possibly
/// repeated (loop-within-session), and build the playback report,
/// per-iteration verdicts and aligned timing.
fn compare_playback(src: &[IFrame], del: &[IFrame], cfg: &CompareCfg) -> CompareResult {
    let e_len = src.len();
    let mut report = PlaybackReport {
        script_iframes: e_len,
        delivered_iframes: del.len(),
        iterations_configured: cfg.iterations_configured,
        alignment_complete: true,
        ..Default::default()
    };
    let src_tids: Vec<u8> = src.iter().map(|f| type_id_of(f.asdu)).collect();
    let del_tids: Vec<u8> = del.iter().map(|f| type_id_of(f.asdu)).collect();
    for &t in &del_tids {
        *report.delivered_type_id_counts.entry(t).or_default() += 1;
    }
    let (et, t1) = capped(&src_tids, MAX_SEQUENCE_ENTRIES);
    let (dt, t2) = capped(&del_tids, MAX_SEQUENCE_ENTRIES);
    report.expected_type_ids = et;
    report.delivered_type_ids = dt;
    report.type_id_sequences_truncated = t1 || t2;

    let mut timing = TimingReport {
        original_iframes: e_len,
        captured_iframes: del.len(),
        paced_speed: cfg.paced_speed,
        drift_within_ms: DRIFT_WITHIN_MS,
        speed_label: "n/a".into(),
        ..Default::default()
    };
    let orig_gaps: Vec<f64> = src
        .windows(2)
        .map(|w| w[1].ts_ms() - w[0].ts_ms())
        .collect();
    timing.original_duration_ms = orig_gaps.iter().sum();
    timing.captured_duration_ms = match (del.first(), del.last()) {
        (Some(a), Some(b)) => b.ts_ms() - a.ts_ms(),
        _ => 0.0,
    };

    if e_len == 0 {
        return CompareResult {
            report,
            timing,
            pacing_samples: Vec::new(),
            pacing_samples_total: 0,
            alignment_complete: true,
            iterations_observed: 0,
        };
    }

    // Iterations: align against the script repeated enough times to
    // cover the delivered stream.
    let copies = del.len().div_ceil(e_len).max(1);
    let src_keys: Vec<u64> = src.iter().map(|f| content_key(f.asdu)).collect();
    let mut exp_keys: Vec<u64> = Vec::with_capacity(copies * e_len);
    for _ in 0..copies {
        exp_keys.extend_from_slice(&src_keys);
    }
    let del_keys: Vec<u64> = del.iter().map(|f| content_key(f.asdu)).collect();
    // The repeated script makes alignments ambiguous: the tail of the
    // delivered stream could pair with any copy. Anchor it at the
    // start by aligning only against the shortest script prefix that
    // the delivered stream can reach with the fewest edits; the rest
    // is the not-sent tail. At least one full pass is always aligned,
    // so a stream whose content is all wrong pairs up positionally
    // (modified) instead of reading as "everything missing + extra".
    let reach = prefix_extent(&exp_keys, &del_keys).max(e_len);
    let mut es = edit_script(&exp_keys[..reach], &del_keys);
    es.missing.extend(reach..exp_keys.len());
    report.alignment_complete = es.complete;

    // Iterations actually touched by the delivered stream.
    let last_touched = es
        .pairs
        .iter()
        .map(|p| p.0)
        .chain(es.reordered.iter().map(|r| r.0))
        .max();
    let observed = last_touched.map(|e| e / e_len + 1).unwrap_or(0);
    let last_e = last_touched.unwrap_or(0);
    let tail_excused = cfg.stopped_early || (cfg.iterations_configured == 0 && observed > 1);
    // Passes past a known iteration count were never owed: everything
    // delivered in them is extra, nothing in them is missing (N12).
    let configured = cfg.iterations_configured as usize;
    let beyond = |it: usize| configured > 0 && it >= configured;
    let extra_diff = |d: usize, it: usize| IFrameDiff {
        kind: "extra",
        index: d,
        iteration: it + 1,
        expected_index: None,
        delivered_index: Some(d),
        expected_type_id: None,
        actual_type_id: Some(del_tids[d]),
        expected_asdu_hex: String::new(),
        actual_asdu_hex: to_hex(del[d].asdu),
    };

    let mut iters: Vec<IterationReport> = (0..observed.max(1))
        .map(|i| IterationReport {
            iteration: i + 1,
            expected: e_len,
            ..Default::default()
        })
        .collect();

    let mut mismatches: Vec<IFrameDiff> = Vec::new();
    let mut mismatches_total = 0usize;
    let mut push_mm = |d: IFrameDiff| {
        mismatches_total += 1;
        if mismatches.len() < MAX_MISMATCH_ENTRIES {
            mismatches.push(d);
        }
    };

    // Matched and substituted pairs.
    let mut pair_classes: Vec<(usize, usize, PairClass)> = Vec::with_capacity(es.pairs.len());
    for &(e, d, _) in &es.pairs {
        let pos = e % e_len;
        let it = e / e_len;
        let class = classify_pair(src[pos].asdu, &del[d], cfg);
        pair_classes.push((e, d, class));
        if beyond(it) {
            iters[it].extra += 1;
            push_mm(extra_diff(d, it));
            continue;
        }
        if src_tids[pos] == del_tids[d] {
            report.matched_type_ids += 1;
        }
        let ir = &mut iters[it];
        let kind = match class {
            PairClass::Identical => {
                ir.identical += 1;
                None
            }
            PairClass::Cp56Ok => {
                ir.cp56_ok += 1;
                None
            }
            PairClass::Cp56OutOfTolerance => {
                ir.cp56_out_of_tolerance += 1;
                Some("cp56_out_of_tolerance")
            }
            PairClass::Cp56Changed => {
                ir.cp56_changed += 1;
                Some("cp56_changed")
            }
            PairClass::Modified => {
                ir.modified += 1;
                Some("modified")
            }
        };
        if let Some(kind) = kind {
            push_mm(IFrameDiff {
                kind,
                index: d,
                iteration: it + 1,
                expected_index: Some(e),
                delivered_index: Some(d),
                expected_type_id: Some(src_tids[pos]),
                actual_type_id: Some(del_tids[d]),
                expected_asdu_hex: to_hex(src[pos].asdu),
                actual_asdu_hex: to_hex(del[d].asdu),
            });
        }
    }
    for &(e, d) in &es.reordered {
        let pos = e % e_len;
        let it = (e / e_len).min(iters.len() - 1);
        if beyond(it) {
            iters[it].extra += 1;
            push_mm(extra_diff(d, it));
            continue;
        }
        iters[it].reordered += 1;
        push_mm(IFrameDiff {
            kind: "reordered",
            index: d,
            iteration: it + 1,
            expected_index: Some(e),
            delivered_index: Some(d),
            expected_type_id: Some(src_tids[pos]),
            actual_type_id: Some(del_tids[d]),
            expected_asdu_hex: to_hex(src[pos].asdu),
            actual_asdu_hex: to_hex(del[d].asdu),
        });
    }
    // Missing frames; the part after the last delivered frame is the
    // not-sent tail, excused when the run was stopped.
    let mut missing_indices: Vec<usize> = Vec::new();
    for &e in &es.missing {
        let it = e / e_len;
        if it >= iters.len() || beyond(it) {
            // Repeated copy never started (insert-inflated), or a pass
            // that was not owed.
            continue;
        }
        if e > last_e && tail_excused {
            iters[it].not_sent += 1;
            continue;
        }
        iters[it].missing += 1;
        if missing_indices.len() < MAX_SEQUENCE_ENTRIES {
            missing_indices.push(e);
        }
        let pos = e % e_len;
        push_mm(IFrameDiff {
            kind: "missing",
            index: e,
            iteration: it + 1,
            expected_index: Some(e),
            delivered_index: None,
            expected_type_id: Some(src_tids[pos]),
            actual_type_id: None,
            expected_asdu_hex: to_hex(src[pos].asdu),
            actual_asdu_hex: String::new(),
        });
    }
    // Extra frames belong to the iteration of the nearest preceding pair.
    for &d in &es.extra {
        let it = match pair_classes.partition_point(|p| p.1 < d) {
            0 => 0,
            i => pair_classes[i - 1].0 / e_len,
        };
        let it = it.min(iters.len() - 1);
        iters[it].extra += 1;
        push_mm(IFrameDiff {
            kind: "extra",
            index: d,
            iteration: it + 1,
            expected_index: None,
            delivered_index: Some(d),
            expected_type_id: None,
            actual_type_id: Some(del_tids[d]),
            expected_asdu_hex: String::new(),
            actual_asdu_hex: to_hex(del[d].asdu),
        });
    }
    // Iterations the run was configured for but never started.
    let never_started = configured.saturating_sub(observed.max(1));
    let never_started_frames = never_started.saturating_mul(e_len);

    // --- Per-iteration status, totals ---
    for (i, ir) in iters.iter_mut().enumerate() {
        if beyond(i) {
            ir.expected = 0;
            ir.score_pct = 0.0;
            ir.status = "extra_pass";
            report.extra_count += ir.extra;
            report.extra_passes += 1;
            continue;
        }
        let is_last = i + 1 == observed.max(1);
        let in_scope = ir.expected - ir.not_sent;
        let good = ir.identical + ir.cp56_ok;
        ir.expected = in_scope;
        ir.score_pct = pct(good, in_scope + ir.extra);
        let clean = good == in_scope && ir.extra == 0 && ir.reordered == 0;
        ir.status = match (is_last && ir.not_sent > 0, clean) {
            (true, true) => "stopped_tail_clean",
            (true, false) => "stopped_tail_deviations",
            (false, true) => "clean",
            (false, false) => "deviations",
        };
        report.byte_identical_count += ir.identical;
        report.cp56_only_count += ir.cp56_ok;
        report.cp56_out_of_tolerance_count += ir.cp56_out_of_tolerance;
        report.cp56_changed_count += ir.cp56_changed;
        report.modified_count += ir.modified;
        report.missing_count += ir.missing;
        report.extra_count += ir.extra;
        report.reordered_count += ir.reordered;
        report.not_sent_count += ir.not_sent;
        report.expected_iframes += in_scope;
        if ir.not_sent == 0 {
            report.iterations_complete += 1;
            if clean {
                report.iterations_clean += 1;
            }
        }
        if is_last && ir.not_sent > 0 {
            report.stopped_tail = Some(TailReport {
                iteration: ir.iteration,
                sent: e_len - ir.not_sent,
                script_iframes: e_len,
                clean,
            });
        }
    }
    if never_started > 0 {
        if cfg.stopped_early {
            report.not_sent_count += never_started_frames;
        } else {
            report.missing_count += never_started_frames;
            report.expected_iframes += never_started_frames;
            mismatches_total += never_started_frames;
        }
        for k in 0..never_started.min(MAX_ITERATION_ENTRIES) {
            iters.push(IterationReport {
                iteration: observed.max(1) + k + 1,
                status: "not_started",
                expected: if cfg.stopped_early { 0 } else { e_len },
                missing: if cfg.stopped_early { 0 } else { e_len },
                not_sent: if cfg.stopped_early { e_len } else { 0 },
                ..Default::default()
            });
        }
    }
    // Expected histogram over the frames in scope (script × iterations).
    let full_iters = report.iterations_complete + if cfg.stopped_early { 0 } else { never_started };
    for &t in &src_tids {
        *report.expected_type_id_counts.entry(t).or_default() += full_iters;
    }
    if let Some(tail) = &report.stopped_tail {
        for &t in &src_tids[..tail.sent.min(e_len)] {
            *report.expected_type_id_counts.entry(t).or_default() += 1;
        }
    }
    report.expected_type_id_counts.retain(|_, v| *v > 0);

    report.real_mismatch_count = report.modified_count
        + report.missing_count
        + report.extra_count
        + report.reordered_count
        + report.cp56_changed_count;
    report.content_score_pct = pct(
        report.byte_identical_count + report.cp56_only_count,
        report.expected_iframes + report.extra_count,
    );
    report.type_id_match_pct = pct(report.matched_type_ids, report.expected_iframes);
    report.type_id_sequence_match = report.expected_iframes > 0
        && report.matched_type_ids == es.pairs.len()
        && report.missing_count == 0
        && report.extra_count == 0
        && report.reordered_count == 0;
    report.missing_indices = missing_indices;
    report.mismatches = mismatches;
    report.mismatches_total = mismatches_total;
    report.mismatches_truncated = mismatches_total > report.mismatches.len();
    report.iterations_observed = observed;

    // --- Timing over aligned pairs, per iteration ---
    let speed = cfg.paced_speed.filter(|s| *s > 0.0).unwrap_or(1.0);
    let mut drifts_abs: Vec<f64> = Vec::new();
    let mut pacing: Vec<[f64; 2]> = Vec::new();
    let mut gap_deltas: Vec<f64> = Vec::new();
    let mut sum_orig_span = 0.0;
    let mut sum_cap_span = 0.0;
    let mut max_orig_span: f64 = 0.0;
    let mut start = 0usize;
    while start < es.pairs.len() {
        let it = es.pairs[start].0 / e_len;
        let mut end = start;
        while end < es.pairs.len() && es.pairs[end].0 / e_len == it {
            end += 1;
        }
        let group = &es.pairs[start..end];
        let (e0, d0, _) = group[0];
        let (e1, d1, _) = group[group.len() - 1];
        let orig_zero = src[e0 % e_len].ts_ms();
        let cap_zero = del[d0].ts_ms();
        let orig_span = src[e1 % e_len].ts_ms() - orig_zero;
        let cap_span = del[d1].ts_ms() - cap_zero;
        sum_orig_span += orig_span;
        sum_cap_span += cap_span;
        max_orig_span = max_orig_span.max(orig_span);
        if it < iters.len() {
            iters[it].original_span_ms = orig_span;
            iters[it].captured_span_ms = cap_span;
            iters[it].speedup_factor = if cap_span > 0.0 {
                orig_span / cap_span
            } else {
                0.0
            };
        }
        for (k, &(e, d, _)) in group.iter().enumerate() {
            let orig_rel = src[e % e_len].ts_ms() - orig_zero;
            let cap_rel = del[d].ts_ms() - cap_zero;
            let drift = cap_rel - orig_rel / speed;
            drifts_abs.push(drift.abs());
            pacing.push([del[d].ts_ms(), drift]);
            if k > 0 {
                let (pe, pd, _) = group[k - 1];
                if pe + 1 == e && pd + 1 == d {
                    let og = src[e % e_len].ts_ms() - src[pe % e_len].ts_ms();
                    let cg = del[d].ts_ms() - del[pd].ts_ms();
                    gap_deltas.push((cg - og / speed).abs());
                }
            }
        }
        start = end;
    }
    // Captured gaps between consecutive delivered frames of the same
    // iteration (never across an iteration boundary).
    let mut iter_of_del: Vec<Option<usize>> = vec![None; del.len()];
    for &(e, d, _) in &es.pairs {
        iter_of_del[d] = Some(e / e_len);
    }
    let mut cap_gaps: Vec<f64> = Vec::new();
    for d in 1..del.len() {
        let same = match (iter_of_del[d - 1], iter_of_del[d]) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        if same {
            cap_gaps.push(del[d].ts_ms() - del[d - 1].ts_ms());
        }
    }
    timing.paired_frames = es.pairs.len();
    timing.speedup_factor = if sum_cap_span > 0.0 {
        sum_orig_span / sum_cap_span
    } else {
        0.0
    };
    timing.speed_label = speed_label(timing.speedup_factor, sum_orig_span, sum_cap_span);
    timing.original_mean_gap_ms = mean(&orig_gaps);
    timing.captured_mean_gap_ms = mean(&cap_gaps);
    timing.original_p50_gap_ms = percentile(&orig_gaps, 0.5);
    timing.captured_p50_gap_ms = percentile(&cap_gaps, 0.5);
    timing.original_p99_gap_ms = percentile(&orig_gaps, 0.99);
    timing.captured_p99_gap_ms = percentile(&cap_gaps, 0.99);
    gap_deltas.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    timing.gap_delta_p50_ms = percentile_sorted(&gap_deltas, 0.5);
    timing.gap_delta_p95_ms = percentile_sorted(&gap_deltas, 0.95);
    timing.gap_delta_max_ms = gap_deltas.last().copied().unwrap_or(0.0);
    timing.max_abs_drift_ms = drifts_abs.iter().copied().fold(0.0, f64::max);
    timing.drift_within_pct = pct(
        drifts_abs.iter().filter(|d| **d <= DRIFT_WITHIN_MS).count(),
        drifts_abs.len(),
    );
    if let Some(s) = cfg.paced_speed.filter(|s| *s > 0.0) {
        timing.timing_judged = true;
        let threshold = TIMING_DRIFT_FAIL_MS.max(TIMING_DRIFT_FAIL_REL * max_orig_span / s);
        if timing.max_abs_drift_ms > threshold {
            timing.timing_failure = Some(format!(
                "pacing drift reached {:.0} ms (threshold {:.0} ms at {s}× speed; replay ran {})",
                timing.max_abs_drift_ms, threshold, timing.speed_label
            ));
        }
    }
    let (og, s1) = decimate(&orig_gaps, MAX_GAP_SAMPLES);
    let (cg, s2) = decimate(&cap_gaps, MAX_GAP_SAMPLES);
    timing.original_gaps_ms = og;
    timing.captured_gaps_ms = cg;
    timing.gaps_truncated = s1 > 1 || s2 > 1;

    let pacing_total = pacing.len();
    let (pacing, _) = decimate(&pacing, MAX_PACING_SAMPLES);

    // Bounded iteration list: keep the first and last halves.
    if iters.len() > MAX_ITERATION_ENTRIES {
        let half = MAX_ITERATION_ENTRIES / 2;
        let tail = iters.split_off(iters.len() - half);
        iters.truncate(half);
        iters.extend(tail);
        report.iterations_truncated = true;
    }
    report.iterations = iters;

    CompareResult {
        report,
        timing,
        pacing_samples: pacing,
        pacing_samples_total: pacing_total,
        alignment_complete: es.complete,
        iterations_observed: observed,
    }
}

/// Honest speed label: "matched" only within ±[`SPEED_MATCH_TOLERANCE`].
pub fn speed_label(speedup: f64, orig_span_ms: f64, cap_span_ms: f64) -> String {
    if speedup <= 0.0 || orig_span_ms <= 0.0 || cap_span_ms <= 0.0 {
        return "n/a".into();
    }
    if (speedup - 1.0).abs() <= SPEED_MATCH_TOLERANCE {
        "matched".into()
    } else if speedup > 1.0 {
        format!("{speedup:.2}× faster")
    } else {
        format!("{:.2}× slower", 1.0 / speedup)
    }
}

// ---------------------------------------------------------------------
// Target side (correct mode)
// ---------------------------------------------------------------------

fn compare_target(expected: &[IFrame], actual: &[IFrame]) -> CorrectnessCheck {
    let exp_tids: Vec<u8> = expected.iter().map(|f| type_id_of(f.asdu)).collect();
    let act_tids: Vec<u8> = actual.iter().map(|f| type_id_of(f.asdu)).collect();
    let exp_keys: Vec<u64> = expected.iter().map(|f| content_key(f.asdu)).collect();
    let act_keys: Vec<u64> = actual.iter().map(|f| content_key(f.asdu)).collect();
    let es = edit_script(&exp_keys, &act_keys);
    let mut matched_tid = 0usize;
    let mut byte_id = 0usize;
    let mut cp56 = 0usize;
    let mut modified = 0usize;
    for &(e, a, _) in &es.pairs {
        if exp_tids[e] == act_tids[a] {
            matched_tid += 1;
        }
        // The live target stamps events with its own clock, so a
        // CP56-only difference on the target side is expected.
        match compare_asdu(expected[e].asdu, actual[a].asdu) {
            AsduCmp::Identical => byte_id += 1,
            AsduCmp::Cp56Only => cp56 += 1,
            AsduCmp::Different => modified += 1,
        }
    }
    let missing = es.missing.len() + es.reordered.len();
    let extra = es.extra.len() + es.reordered.len();
    let lcs = lcs_length(&exp_tids, &act_tids);
    let similarity = if exp_tids.is_empty() {
        1.0
    } else {
        lcs as f64 / exp_tids.len() as f64
    };
    let kind = classify_script(&exp_tids, &act_tids, lcs, byte_id);
    let missing_tail = if act_tids.len() < exp_tids.len() {
        capped(&exp_tids[act_tids.len()..], MAX_SEQUENCE_ENTRIES).0
    } else {
        Vec::new()
    };
    let extra_tail = if act_tids.len() > exp_tids.len() {
        capped(&act_tids[exp_tids.len()..], MAX_SEQUENCE_ENTRIES).0
    } else {
        Vec::new()
    };
    CorrectnessCheck {
        expected_iframes: exp_tids.len(),
        actual_iframes: act_tids.len(),
        matched_type_id_prefix: matched_tid,
        missing_tail,
        extra_tail,
        byte_identical_count: byte_id,
        cp56_only_count: cp56,
        modified_count: modified,
        missing_count: missing,
        extra_count: extra,
        total_mismatches: modified + missing + extra,
        lcs_type_ids: lcs,
        lcs_similarity: similarity,
        content_score_pct: if exp_tids.is_empty() && act_tids.is_empty() {
            100.0
        } else {
            pct(byte_id + cp56, exp_tids.len() + extra)
        },
        original_type_ids: capped(&exp_tids, MAX_SEQUENCE_ENTRIES).0,
        target_script_kind: kind,
    }
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

// ---------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------

/// Target-side facts the verdict needs (correct mode).
#[derive(Debug, Clone, PartialEq)]
struct TargetVerdict {
    kind: &'static str,
    expected: usize,
    actual: usize,
    total_mismatches: usize,
    modified_only: bool,
    score: f64,
    lcs: usize,
    lcs_similarity: f64,
}

impl From<&CorrectnessCheck> for TargetVerdict {
    fn from(c: &CorrectnessCheck) -> Self {
        TargetVerdict {
            kind: c.target_script_kind,
            expected: c.expected_iframes,
            actual: c.actual_iframes,
            total_mismatches: c.total_mismatches,
            modified_only: c.missing_count == 0 && c.extra_count == 0,
            score: c.content_score_pct,
            lcs: c.lcs_type_ids,
            lcs_similarity: c.lcs_similarity,
        }
    }
}

/// Everything [`decide_verdict`] looks at. Plain data so the verdict
/// table can be tested without building byte streams.
#[derive(Debug, Clone, Default)]
struct VerdictInputs {
    reference_present: bool,
    reference_skipped_bytes: usize,
    expected: usize,
    delivered: usize,
    good: usize,
    modified: usize,
    missing: usize,
    extra: usize,
    reordered: usize,
    cp56_changed: usize,
    cp56_out_of_tolerance: usize,
    not_sent: usize,
    iterations_complete: usize,
    iterations_clean: usize,
    stopped_tail: Option<TailReport>,
    stopped_early: bool,
    handshake_ok: bool,
    gi_ci_failed: usize,
    timing_failure: Option<String>,
    target: Option<TargetVerdict>,
    /// Fault summary when faults were configured.
    faults: Option<String>,
}

/// Pass/fail per verdict dimension, serialized next to the verdict.
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct VerdictDimensions {
    pub content: bool,
    pub time_tags: bool,
    pub gi_ci: bool,
    /// `None` when timing was not judged (run not paced or unknown).
    pub timing: Option<bool>,
    pub handshake: bool,
    /// `None` outside correct mode.
    pub target: Option<bool>,
    /// Injected faults: not a pass/fail dimension but a summary ("N
    /// fault(s) configured …; peer reaction: …"). `None` when the run
    /// injected no faults.
    pub faults: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct Verdict {
    name: &'static str,
    reason: String,
    score: f64,
    outcome: VerdictOutcome,
    dimensions: VerdictDimensions,
}

/// Verdict policy for one captured session.
///
/// * The **score** is content fidelity: (byte-identical + accepted
///   CP56-only frames) / (expected + extra), clamped to 0..=100. In
///   correct mode it is the mean of the playback and target scores.
/// * The **verdict** passes only if every dimension passes: content
///   (`real_mismatch_count == 0`), time tags (no CP56 stamp out of
///   tolerance), the GI/CI audit (every exchange compliant), timing
///   (when the run was paced) and the STARTDT handshake, plus the
///   target script in correct mode.
///
/// | verdict | outcome | when |
/// |---|---|---|
/// | `no_reference` | inconclusive | no source flow, or nothing expected but frames delivered, or the source did not parse |
/// | `no_iframes_expected` | pass | the source cleanly carries no I-frames and none were delivered |
/// | `stopped_before_delivery` | inconclusive | run stopped before the first frame went out |
/// | `no_delivery` | fail | frames expected, none delivered |
/// | `partial_delivery` | fail | modified / missing / extra / reordered frames, or CP56 changed with rewrite off |
/// | `handshake_incomplete` | fail | content fine but no STARTDT (score capped at 50) |
/// | `target_silent` / `divergent_script` / `subset_script` / `structurally_identical` / `partial` | fail | correct mode, target deviates |
/// | `degraded` | fail | content fine but time tags, GI/CI audit or timing fail |
/// | `stopped_clean` | pass | every frame sent before a user stop was clean |
/// | `identical` / `good_delivery` | pass | everything passes (correct / generic mode) |
fn decide_verdict(v: &VerdictInputs) -> Verdict {
    let content_score = pct(v.good, v.expected + v.extra);
    let real_mismatches = v.modified + v.missing + v.extra + v.reordered + v.cp56_changed;
    let dims = VerdictDimensions {
        content: real_mismatches == 0,
        time_tags: v.cp56_out_of_tolerance == 0,
        gi_ci: v.gi_ci_failed == 0,
        timing: v.timing_failure.as_ref().map(|_| false),
        handshake: v.handshake_ok,
        target: v.target.as_ref().map(|t| t.total_mismatches == 0),
        faults: v.faults.clone(),
    };
    let mk = |name: &'static str, reason: String, score: f64, outcome: VerdictOutcome| Verdict {
        name,
        reason,
        score: score.clamp(0.0, 100.0),
        outcome,
        dimensions: dims.clone(),
    };

    if !v.reference_present {
        return mk(
            "no_reference",
            "no source flow for this endpoint; nothing to compare against".into(),
            0.0,
            VerdictOutcome::Inconclusive,
        );
    }
    if v.expected == 0 && v.not_sent == 0 {
        if v.reference_skipped_bytes > 0 {
            return mk(
                "no_reference",
                format!(
                    "source stream did not parse ({} bytes skipped, 0 I-frames recovered)",
                    v.reference_skipped_bytes
                ),
                0.0,
                VerdictOutcome::Inconclusive,
            );
        }
        if v.delivered > 0 {
            return mk(
                "no_reference",
                format!(
                    "source carries no I-frames but {} were delivered; nothing to score them against",
                    v.delivered
                ),
                0.0,
                VerdictOutcome::Inconclusive,
            );
        }
        let why = if v.handshake_ok {
            "no I-frames in source pcap; target completed STARTDT handshake"
        } else {
            "no I-frames in source pcap; nothing to deliver"
        };
        return mk(
            "no_iframes_expected",
            why.into(),
            100.0,
            VerdictOutcome::Pass,
        );
    }
    if v.delivered == 0 {
        if v.stopped_early && v.expected == 0 {
            return mk(
                "stopped_before_delivery",
                "run was stopped before any I-frame was sent".into(),
                0.0,
                VerdictOutcome::Inconclusive,
            );
        }
        return mk(
            "no_delivery",
            "outstation's side produced zero I-frames in the captured session".into(),
            0.0,
            VerdictOutcome::Fail,
        );
    }

    let iter_note = |v: &VerdictInputs| -> String {
        let mut s = String::new();
        if v.iterations_complete > 1 || v.stopped_tail.is_some() {
            s.push_str(&format!(
                "; {}/{} full iterations clean",
                v.iterations_clean, v.iterations_complete
            ));
            if let Some(t) = &v.stopped_tail {
                s.push_str(&format!(
                    " + stopped tail {}/{} frames {}",
                    t.sent,
                    t.script_iframes,
                    if t.clean { "clean" } else { "with deviations" }
                ));
            }
        }
        s
    };

    if !dims.content {
        let mut parts = Vec::new();
        for (n, label) in [
            (v.modified, "modified"),
            (v.missing, "missing"),
            (v.extra, "extra"),
            (v.reordered, "reordered"),
            (v.cp56_changed, "time tags changed with CP56 rewrite off"),
        ] {
            if n > 0 {
                parts.push(format!("{n} {label}"));
            }
        }
        let score = match &v.target {
            Some(t) => (content_score + t.score) / 2.0,
            None => content_score,
        };
        return mk(
            "partial_delivery",
            format!(
                "{}/{} expected I-frames delivered intact; {}{}",
                v.good,
                v.expected,
                parts.join(", "),
                iter_note(v)
            ),
            score,
            VerdictOutcome::Fail,
        );
    }
    if !v.handshake_ok {
        return mk(
            "handshake_incomplete",
            "content matched but the STARTDT handshake was not seen".into(),
            content_score.min(50.0),
            VerdictOutcome::Fail,
        );
    }
    if let Some(t) = &v.target {
        if t.total_mismatches > 0 || t.actual != t.expected {
            let combined = (content_score + t.score) / 2.0;
            let (name, reason, score) = match t.kind {
                "silent" => (
                    "target_silent",
                    "target sent zero I-frames: only handshake and ACKs".to_string(),
                    combined.min(50.0),
                ),
                "divergent" => (
                    "divergent_script",
                    format!(
                        "target ran its own command script (type-id overlap {:.0}%, {} target I-frames vs {} original)",
                        t.lcs_similarity * 100.0,
                        t.actual,
                        t.expected
                    ),
                    combined,
                ),
                "subset" => (
                    "subset_script",
                    format!(
                        "target replayed a subset of the original script ({}/{} I-frames in order)",
                        t.lcs, t.expected
                    ),
                    combined,
                ),
                _ if t.modified_only => (
                    "structurally_identical",
                    format!(
                        "playback matched; target sent the right frames in order but {} differ in content",
                        t.total_mismatches
                    ),
                    combined,
                ),
                _ => (
                    "partial",
                    format!(
                        "playback matched; target script deviates ({} mismatches, target score {:.0}%)",
                        t.total_mismatches, t.score
                    ),
                    combined,
                ),
            };
            return mk(name, reason, score, VerdictOutcome::Fail);
        }
    }
    let mut failed_dims = Vec::new();
    if !dims.time_tags {
        failed_dims.push(format!(
            "{} CP56 time tag(s) out of tolerance",
            v.cp56_out_of_tolerance
        ));
    }
    if !dims.gi_ci {
        failed_dims.push(format!(
            "{} GI/CI exchange(s) not compliant",
            v.gi_ci_failed
        ));
    }
    if let Some(t) = &v.timing_failure {
        failed_dims.push(t.clone());
    }
    if !failed_dims.is_empty() {
        let score = match &v.target {
            Some(t) => (content_score + t.score) / 2.0,
            None => content_score,
        };
        return mk(
            "degraded",
            format!(
                "content matched ({} frames) but {}{}",
                v.good,
                failed_dims.join("; "),
                iter_note(v)
            ),
            score,
            VerdictOutcome::Fail,
        );
    }
    if v.stopped_tail.is_some() || (v.stopped_early && v.not_sent > 0) {
        let why = if v.faults.is_some() {
            "session ended after injected faults"
        } else {
            "run stopped"
        };
        return mk(
            "stopped_clean",
            format!(
                "{why}: every one of the {} I-frames sent before the stop was intact{}",
                v.good,
                iter_note(v)
            ),
            100.0,
            VerdictOutcome::Pass,
        );
    }
    let iters = if v.iterations_complete > 1 {
        format!(" over {} clean iterations", v.iterations_complete)
    } else {
        String::new()
    };
    if v.target.is_some() {
        return mk(
            "identical",
            format!("every playback I-frame and every target I-frame matched the original{iters}"),
            100.0,
            VerdictOutcome::Pass,
        );
    }
    mk(
        "good_delivery",
        format!(
            "all {} expected I-frames delivered intact{iters}; STARTDT ok",
            v.expected
        ),
        100.0,
        VerdictOutcome::Pass,
    )
}

// ---------------------------------------------------------------------
// CP56Time2a drift
// ---------------------------------------------------------------------

/// Compare every CP56Time2a in `frames` to the frame's wire-send time.
/// `epoch_ns` is the absolute UTC ns of the captured pcap's first
/// packet, added to each frame's relative timestamp.
fn cp56_drift_over(
    frames: &[IFrame],
    epoch_ns: u64,
    zone: Cp56Zone,
    tolerance_ms: f64,
) -> Option<Cp56DriftReport> {
    let mut signed: Vec<f64> = Vec::new();
    let mut idx: Vec<u32> = Vec::new();
    let mut tids: Vec<u8> = Vec::new();
    let mut walls: Vec<f64> = Vec::new();
    let mut iframes_with_cp56 = 0usize;
    let mut invalid_flag_count = 0usize;
    let mut summer_flag_count = 0usize;
    for (i, f) in frames.iter().enumerate() {
        let stamps = cp56_stamps(f.asdu, zone);
        if stamps.is_empty() {
            continue;
        }
        iframes_with_cp56 += 1;
        let send_ns = epoch_ns.saturating_add(f.ts_ns) as i128;
        for (stamp_ns, iv, su) in stamps {
            invalid_flag_count += iv as usize;
            summer_flag_count += su as usize;
            signed.push((send_ns - stamp_ns as i128) as f64 / 1e6);
            idx.push(i.min(u32::MAX as usize) as u32);
            tids.push(type_id_of(f.asdu));
            walls.push(f.ts_ms());
        }
    }
    if signed.is_empty() {
        return None;
    }
    let samples = signed.len();
    let mut abs: Vec<f64> = signed.iter().map(|d| d.abs()).collect();
    abs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let out_of_tolerance = abs.iter().filter(|&&d| d > tolerance_ms).count();
    let (drift_samples_ms, stride) = decimate(&signed, MAX_DRIFT_SAMPLES);
    Some(Cp56DriftReport {
        samples,
        iframes_with_cp56,
        mean_ms: mean(&abs),
        p50_ms: percentile_sorted(&abs, 0.5),
        p99_ms: percentile_sorted(&abs, 0.99),
        max_ms: abs.last().copied().unwrap_or(0.0),
        out_of_tolerance,
        tolerance_ms,
        mean_signed_ms: mean(&signed),
        invalid_flag_count,
        summer_flag_count,
        drift_samples_ms,
        sample_frame_indices: decimate(&idx, MAX_DRIFT_SAMPLES).0,
        sample_type_ids: decimate(&tids, MAX_DRIFT_SAMPLES).0,
        sample_wall_ms: decimate(&walls, MAX_DRIFT_SAMPLES).0,
        samples_truncated: stride > 1,
        sample_stride: stride,
    })
}

/// Drift over every I-frame of one flow (test convenience).
#[cfg(test)]
fn compute_cp56_drift(
    flow: &FlowSnapshot,
    capture_epoch_ns: u64,
    zone: Cp56Zone,
    tolerance_ms: f64,
) -> Option<Cp56DriftReport> {
    cp56_drift_over(
        &parse_flow(flow).iframes,
        capture_epoch_ns,
        zone,
        tolerance_ms,
    )
}

// ---------------------------------------------------------------------
// Command echo: synthesized command responses
// ---------------------------------------------------------------------

/// Flag the delivered frames the slave sent in answer to the live
/// master's commands (`cmds`, in time order): for each command the
/// first unflagged answer after it ([`commands::answers`]); after a
/// positive ActCon to an executed process command also the return
/// information (when configured) and the ActTerm; for a broadcast,
/// every station's answer.
///
/// Returns the number of frames flagged and the commands the slave
/// accepted: (index in `frames` of the first positive ActCon, command
/// ASDU), in stream order. The slave applies a command to its point
/// inventory when it queues that ActCon, so the index places the state
/// change among the other synthesized answers ([`InventoryTimeline`]).
fn identify_command_responses<'a>(
    cmds: &[&IFrame<'a>],
    frames: &[IFrame],
    cfg: &commands::CommandsConfig,
    synth: &mut [bool],
) -> (usize, Vec<(usize, &'a [u8])>) {
    let ri_cot = match cfg.return_info {
        commands::ReturnInfo::None => None,
        commands::ReturnInfo::Spontaneous => Some(commands::COT_SPONTANEOUS),
        commands::ReturnInfo::Retrem => Some(commands::COT_RETREM),
    };
    let mut flagged = 0usize;
    let mut executed = Vec::new();
    for cmd in cmds {
        let c = cmd.asdu;
        let start = frames.partition_point(|f| f.ts_ms() + 0.5 < cmd.ts_ms());
        let horizon = cmd.ts_ms() + SYNTH_SEARCH_MS;
        let broadcast = c.len() >= DUI_LEN && common_address(c) == 0xFFFF;
        let mut j = start;
        let mut want_term = false;
        let mut want_ri = false;
        while j < frames.len() && frames[j].ts_ms() <= horizon {
            let f = frames[j].asdu;
            if synth[j] {
                j += 1;
                continue;
            }
            if commands::answers(c, f) {
                let part = commands::reply_part(f);
                let first = !want_term && flagged_none(part);
                if first || (want_term && part == commands::Part::ActTerm) || broadcast {
                    synth[j] = true;
                    flagged += 1;
                    if first && part == commands::Part::ActCon && !broadcast {
                        executed.push((j, c));
                    }
                    if part == commands::Part::ActTerm {
                        break;
                    }
                    if first
                        && part == commands::Part::ActCon
                        && commands::is_process_command(c[0])
                        && !commands::is_select(c)
                    {
                        want_term = true;
                        want_ri = ri_cot.is_some();
                    } else if !broadcast {
                        break;
                    }
                }
            } else if want_ri
                && f.len() >= DUI_LEN + IOA_LEN
                && f[0] < 45
                && Some(cot_value(f)) == ri_cot
                && common_address(f) == common_address(c)
                && crate::asdu::read_ioa(f, DUI_LEN) == crate::asdu::read_ioa(c, DUI_LEN)
            {
                synth[j] = true;
                flagged += 1;
                want_ri = false;
            }
            j += 1;
        }
    }
    executed.sort_by_key(|&(at, _)| at);
    (flagged, executed)
}

/// A first answer is anything but an ActTerm.
fn flagged_none(part: commands::Part) -> bool {
    part != commands::Part::ActTerm
}

// ---------------------------------------------------------------------
// Injected faults
// ---------------------------------------------------------------------

/// What the capture shows of the injected faults.
#[derive(Serialize, Debug, Clone, Default)]
pub struct FaultsReport {
    /// Faults in the plan, and their kinds.
    pub configured: usize,
    pub kinds: Vec<&'static str>,
    pub seed: u64,
    /// Sequence numbers skipped on the wire (deliberate drops).
    pub dropped_ns: usize,
    /// Delivered frames repeated with the same N(S) and content.
    pub duplicates: usize,
    /// Delivered frames with an out-of-sequence N(S) after which the
    /// sequence resumed.
    pub corrupted_ns: usize,
    /// Bytes on the replayer's side that did not frame (malformed
    /// APDUs and anything after them).
    pub malformed_bytes: usize,
    /// STOPDT acts the replayer sent.
    pub stopdt_sent: usize,
    /// Capture time (ms) of the first fault, estimated from the plan
    /// and the evidence; `None` if no fault fired within the capture.
    pub first_fault_ms: Option<f64>,
    /// The peer sent STOPDT act after the first fault.
    pub peer_stopdt: bool,
    /// Frames the peer sent after the first fault.
    pub peer_frames_after_first_fault: usize,
    /// How long the captured session lasted after the first fault.
    pub session_end_after_first_fault_ms: Option<f64>,
    pub summary: String,
}

/// Result of walking the delivered N(S) sequence.
struct NsScan {
    /// Frames to keep (deliberate duplicates are dropped).
    keep: Vec<bool>,
    dropped: usize,
    duplicates: usize,
    corrupted: usize,
    first_ts_ms: Option<f64>,
}

impl NsScan {
    fn clean(n: usize) -> Self {
        NsScan {
            keep: vec![true; n],
            dropped: 0,
            duplicates: 0,
            corrupted: 0,
            first_ts_ms: None,
        }
    }
}

/// Classify the delivered N(S) sequence against the fault plan: a
/// repeat of the previous frame (same N(S), same ASDU) is a deliberate
/// duplicate, a single out-of-sequence N(S) after which the sequence
/// resumes is a corrupted N(S), and a forward jump is deliberately
/// dropped frames. Only kinds the plan contains are recognised.
fn scan_sequence(frames: &[IFrame], plan: &FaultPlan) -> NsScan {
    const MASK: u16 = 0x7fff;
    let (drop_on, dup_on, corrupt_on) = (
        plan.has("drop_iframes"),
        plan.has("duplicate_iframes"),
        plan.has("corrupt_ns"),
    );
    let mut sc = NsScan::clean(frames.len());
    let mut expect: Option<u16> = None;
    let first = |sc: &mut NsScan, f: &IFrame| {
        sc.first_ts_ms = Some(sc.first_ts_ms.map_or(f.ts_ms(), |t: f64| t.min(f.ts_ms())));
    };
    for i in 0..frames.len() {
        let f = &frames[i];
        let Some(e) = expect else {
            expect = Some((f.ns + 1) & MASK);
            continue;
        };
        if f.ns == e {
            expect = Some((e + 1) & MASK);
            continue;
        }
        if dup_on && i > 0 && f.ns == frames[i - 1].ns && f.asdu == frames[i - 1].asdu {
            sc.keep[i] = false;
            sc.duplicates += 1;
            first(&mut sc, f);
            continue;
        }
        let resumes = frames.get(i + 1).is_some_and(|n| n.ns == (e + 1) & MASK);
        if corrupt_on
            && (resumes || f.ns == e.wrapping_add(crate::faults::CORRUPT_NS_OFFSET) & MASK)
        {
            sc.corrupted += 1;
            first(&mut sc, f);
            expect = Some((e + 1) & MASK);
            continue;
        }
        let gap = f.ns.wrapping_sub(e) & MASK;
        if drop_on && gap < 0x4000 {
            sc.dropped += gap as usize;
            first(&mut sc, f);
        }
        expect = Some((f.ns + 1) & MASK);
    }
    sc
}

fn faults_report(
    plan: &FaultPlan,
    scan: &NsScan,
    cap: &ParsedFlow,
    cap_tg: &ParsedFlow,
    role: Role,
) -> FaultsReport {
    let mut kinds: Vec<&'static str> = plan.faults.iter().map(|f| f.kind.name()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let all_ts = cap.frame_ts_ms.iter().chain(&cap_tg.frame_ts_ms);
    let start = all_ts.clone().copied().fold(f64::INFINITY, f64::min);
    let end = all_ts.copied().fold(f64::NEG_INFINITY, f64::max);
    let stopdt_sent: Vec<f64> = cap
        .u_events
        .iter()
        .filter(|(_, n)| *n == "STOPDT_ACT")
        .map(|(t, _)| *t)
        .collect();
    // Earliest trigger that falls inside the capture, and the earliest
    // evidence of a fault on the wire.
    let mut first: Option<f64> = scan.first_ts_ms;
    let mut consider = |t: f64| {
        if t.is_finite() && t <= end {
            first = Some(first.map_or(t, |x| x.min(t)));
        }
    };
    for f in &plan.faults {
        match f.at {
            crate::faults::Trigger::Ms(ms) => consider(start + ms as f64),
            crate::faults::Trigger::Frame(n) => {
                if let Some(fr) = cap.iframes.get(n as usize) {
                    consider(fr.ts_ms());
                }
            }
        }
    }
    // A master's STOPDT before its last one is the stopdt fault.
    if role == Role::Master && stopdt_sent.len() > 1 {
        consider(stopdt_sent[0]);
    }
    let malformed_bytes = cap.stats.resynced_bytes + cap.stats.truncated_tail_bytes;
    let mut r = FaultsReport {
        configured: plan.faults.len(),
        kinds,
        seed: plan.seed,
        dropped_ns: scan.dropped,
        duplicates: scan.duplicates,
        corrupted_ns: scan.corrupted,
        malformed_bytes,
        stopdt_sent: stopdt_sent.len(),
        first_fault_ms: first,
        ..Default::default()
    };
    let mut evidence = Vec::new();
    for (n, what) in [
        (scan.dropped, "dropped N(S)"),
        (scan.duplicates, "duplicated frame(s)"),
        (scan.corrupted, "corrupted N(S)"),
        (malformed_bytes, "unframeable byte(s)"),
    ] {
        if n > 0 {
            evidence.push(format!("{n} {what}"));
        }
    }
    let evidence = if evidence.is_empty() {
        "no frame-level evidence".to_string()
    } else {
        evidence.join(", ")
    };
    let Some(t0) = first else {
        r.summary = format!(
            "{} fault(s) configured ({}); none fired within the captured session",
            r.configured,
            r.kinds.join(", ")
        );
        return r;
    };
    r.peer_stopdt = cap_tg
        .u_events
        .iter()
        .any(|(t, n)| *t >= t0 && *n == "STOPDT_ACT");
    r.peer_frames_after_first_fault = cap_tg.frame_ts_ms.iter().filter(|&&t| t >= t0).count();
    r.session_end_after_first_fault_ms = Some((end - t0).max(0.0));
    let mut reaction = Vec::new();
    if r.peer_stopdt {
        reaction.push("sent STOPDT act".to_string());
    }
    if r.peer_frames_after_first_fault == 0 {
        reaction.push("went silent".to_string());
    } else {
        reaction.push(format!(
            "sent {} frame(s) after the first fault",
            r.peer_frames_after_first_fault
        ));
    }
    r.summary = format!(
        "{} fault(s) configured ({}); in the capture: {evidence}; peer reaction: {}; the session ended {:.0} ms after the first fault (whether the peer closed or reset the connection is in the run report's fault_reaction)",
        r.configured,
        r.kinds.join(", "),
        reaction.join(", "),
        (end - t0).max(0.0)
    );
    r
}

// ---------------------------------------------------------------------
// GI / CI: synthesized-frame identification and audit.
//
// The slave-replayer answers live master interrogations (C_IC_NA_1,
// C_CI_NA_1) with responses built from the source-pcap inventory by
// `responder::build_gi_response` / `build_ci_response`. The analyzer
// regenerates the same responses to (1) find and exclude those frames
// from the playback comparison and (2) judge each exchange against
// the spec in `protocol_specific.gi_ci_audit`.
// ---------------------------------------------------------------------

/// IEC 60870-5-104 §5.3 default t1 = 15s. Used as the upper bound on
/// the ActCon delay that still counts as compliant.
const T1_MS_RECOMMENDED: f64 = 15_000.0;

/// Reasonable upper bound on how long after the last data frame an
/// ActTerm may arrive while still counting the response as compliant.
const ACTTERM_DELAY_MS_RECOMMENDED: f64 = 10_000.0;

/// How long after a live request synthesized frames are searched for.
const SYNTH_SEARCH_MS: f64 = 2.0 * T1_MS_RECOMMENDED;

#[derive(Serialize, Debug, Clone)]
pub struct GiCiEvent {
    /// "GI" for C_IC_NA_1 (type 100), "CI" for C_CI_NA_1 (type 101).
    pub kind: &'static str,
    /// Wall-clock time (ms from capture start) the master sent the request.
    pub request_ts_ms: f64,
    /// QOI byte (GI) or QCC byte (CI) carried in the request.
    pub qualifier: u8,
    pub ca: u16,
    pub oa: u8,
    /// Stations expected to answer (several for a broadcast CA).
    pub stations: usize,
    /// The responder rejects this request (unknown CA, bad qualifier),
    /// so a negative confirmation is the correct answer.
    pub expected_negative: bool,
    /// Every station's ActCon was found (worst delay reported below).
    pub actcon_present: bool,
    pub actcon_delay_ms: Option<f64>,
    pub data_frame_count: usize,
    pub data_element_count: usize,
    pub actterm_present: bool,
    /// Delay between the last data frame and the ActTerm (or between
    /// ActCon and ActTerm if the response carried no data).
    pub actterm_delay_ms: Option<f64>,
    /// Every observed data frame carried the COT bucket the spec
    /// expects for this qualifier (e.g. COT 22 for QOI 22).
    pub all_cots_match_bucket: bool,
    /// Each confirmation had the expected P/N polarity.
    pub polarity_ok: bool,
    /// Slave's actual data frames matched the inventory-derived
    /// expected response byte-for-byte (CP56-only diffs allowed).
    pub bytewise_matches_inventory: bool,
    /// Element count the inventory-derived expected response would
    /// have carried.
    pub expected_data_element_count: usize,
    /// Aggregated verdict — "compliant", "partial", or "non_compliant".
    pub verdict: &'static str,
    pub notes: Vec<String>,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct GiCiAudit {
    pub gi_total: usize,
    pub gi_compliant: usize,
    pub gi_partial: usize,
    pub gi_non_compliant: usize,
    pub ci_total: usize,
    pub ci_compliant: usize,
    pub ci_partial: usize,
    pub ci_non_compliant: usize,
    pub events: Vec<GiCiEvent>,
    /// True when `events` was capped at [`MAX_AUDIT_EVENTS`]; the
    /// counters above stay exact.
    pub events_truncated: bool,
}

#[derive(Debug, Clone, Copy)]
struct RequestRec {
    ts_ms: f64,
    type_id: u8,
    qualifier: u8,
    ca: u16,
    oa: u8,
    cot_byte: u8,
}

impl RequestRec {
    /// The response the slave-replayer builds for this request
    /// (mirrors `session::try_queue_master_command_response`): per
    /// answering CA an ActCon, data and an ActTerm; a broadcast fans
    /// out over every known CA, a rejection is a lone negative ActCon.
    fn expected_response(&self, inv: &Inventory) -> InterrogationResponse {
        let echo = RequestEcho {
            ca: self.ca,
            oa: self.oa,
            test: self.cot_byte & 0x80 != 0,
        };
        if self.type_id == 100 {
            respond_gi(inv, echo, self.qualifier)
        } else {
            respond_ci(inv, echo, self.qualifier)
        }
    }

    fn in_data_bucket(&self, cot: u8) -> bool {
        if self.type_id == 100 {
            (20..=36).contains(&cot)
        } else {
            (37..=41).contains(&cot)
        }
    }
}

fn count_elements(asdu: &[u8]) -> usize {
    let (_sq, n) = vsq(asdu);
    n as usize
}

/// Live GI/CI activation requests (type 100/101, COT 6) in a
/// master-side stream.
fn collect_master_requests(frames: &[IFrame]) -> Vec<RequestRec> {
    frames
        .iter()
        .filter(|f| f.asdu.len() > DUI_LEN + IOA_LEN)
        .filter(|f| matches!(f.asdu[0], 100 | 101) && cot_value(f.asdu) == 6)
        .map(|f| RequestRec {
            ts_ms: f.ts_ms(),
            type_id: f.asdu[0],
            qualifier: f.asdu[DUI_LEN + IOA_LEN],
            ca: common_address(f.asdu),
            oa: f.asdu[3],
            cot_byte: f.asdu[2],
        })
        .collect()
}

/// The slave's point inventory as it evolves during the run.
///
/// The slave answers GI/CI from an inventory built from the capture,
/// but a command it executes with return information on updates the
/// commanded point ([`commands::respond_command`]), and a later
/// interrogation answers with the new value. To judge those answers
/// against what the slave really held, the analyzer replays the same
/// state changes: every command the slave accepted (a positive ActCon
/// was delivered) is run through `respond_command` on the analyzer's
/// copy of the inventory, in delivered-stream order. The slave queues
/// all its answers in one FIFO, so a command whose ActCon precedes an
/// interrogation's ActCon was applied before that interrogation was
/// answered, and one whose ActCon follows it was not.
///
/// The replay accepts what the slave accepted: the time-tag age and
/// unknown-IOA checks are off (the positive ActCon shows the command
/// passed them) and the return information's time tag is irrelevant
/// (interrogation answers carry no time tag).
struct InventoryTimeline<'a> {
    base: &'a Inventory,
    /// (frame index of the positive ActCon, command), in index order.
    /// Empty when the run synthesized no return information.
    executed: Vec<(usize, &'a [u8])>,
    cfg: commands::CommandsConfig,
    zone: Cp56Zone,
    /// `base` with `executed[..applied]` applied; built on first use.
    current: Option<Inventory>,
    applied: usize,
}

impl<'a> InventoryTimeline<'a> {
    fn new(
        base: &'a Inventory,
        cfg: &commands::CommandsConfig,
        zone: Cp56Zone,
        mut executed: Vec<(usize, &'a [u8])>,
    ) -> Self {
        // Without return information a command never changes a point.
        if !cfg.enabled || cfg.return_info == commands::ReturnInfo::None {
            executed.clear();
        }
        executed.sort_by_key(|&(at, _)| at);
        Self {
            base,
            executed,
            cfg: commands::CommandsConfig {
                enabled: true,
                return_info: cfg.return_info,
                max_age_ms: 0,
                unknown_ioa: commands::UnknownIoa::Accept,
            },
            zone,
            current: None,
            applied: 0,
        }
    }

    /// A timeline without state changes.
    fn fixed(base: &'a Inventory) -> Self {
        Self::new(
            base,
            &commands::CommandsConfig::default(),
            Cp56Zone::Utc,
            Vec::new(),
        )
    }

    /// The inventory as the slave held it when it queued frame `idx`:
    /// every command confirmed before `idx` applied.
    fn before(&mut self, idx: usize) -> &Inventory {
        if self.executed.is_empty() {
            return self.base;
        }
        let n = self.executed.partition_point(|&(at, _)| at < idx);
        if n < self.applied {
            // Requests are audited in order, so this is rare: start over.
            self.current = None;
            self.applied = 0;
        }
        let inv = self.current.get_or_insert_with(|| self.base.clone());
        let book = commands::CommandBook::default();
        let ctx = commands::CommandContext {
            cfg: &self.cfg,
            book: &book,
            now_unix_ns: 0,
            zone: self.zone,
        };
        for &(_, cmd) in &self.executed[self.applied..n] {
            commands::respond_command(inv, &ctx, cmd);
        }
        self.applied = n;
        inv
    }
}

/// Is `asdu` a confirmation (ActCon, negative or not, or an unknown-CA
/// rejection) of interrogation `req`? Its position in the stream is
/// where the slave built the answer.
fn confirms_request(req: &RequestRec, asdu: &[u8]) -> bool {
    asdu.len() >= DUI_LEN
        && asdu[0] == req.type_id
        && matches!(cot_value(asdu), COT_ACT_CON | COT_UNKNOWN_CA)
        && (req.ca == CA_BROADCAST || common_address(asdu) == req.ca)
}

/// Flag the delivered frames the slave synthesized in answer to live
/// master requests.
///
/// For each request the inventory-derived response (ActCon, data,
/// ActTerm) is matched in order, as a subsequence, against the frames
/// sent after the request (CP56-only differences allowed). The
/// replayer drains its response queue before each script frame, so
/// the first matching frames are the synthesized ones even when a
/// script frame with the same content follows. When the content match
/// is incomplete (e.g. the responder answered differently), the
/// audited window is used instead: the first ActCon for the request's
/// (type, CA) up to its ActTerm, keeping only frames of that CA in the
/// request's COT bucket.
///
/// The expected response comes from the inventory as it stood when the
/// slave answered (`timeline`), so values changed by earlier commands
/// match. Frames already flagged in `synth` are skipped.
fn identify_synthesized(
    requests: &[RequestRec],
    frames: &[IFrame],
    timeline: &mut InventoryTimeline,
    synth: &mut [bool],
) {
    for req in requests {
        let start = frames.partition_point(|f| f.ts_ms() + 0.5 < req.ts_ms);
        let horizon = req.ts_ms + SYNTH_SEARCH_MS;
        let answered_at = (start..frames.len())
            .take_while(|&j| frames[j].ts_ms() <= horizon)
            .find(|&j| !synth[j] && confirms_request(req, frames[j].asdu))
            .unwrap_or(start);
        let response = req.expected_response(timeline.before(answered_at));
        let cas: Vec<u16> = if response.per_ca.is_empty() {
            vec![req.ca]
        } else {
            response.per_ca.iter().map(|r| r.ca).collect()
        };
        let expected: Vec<Vec<u8>> = response.into_asdus();
        let mut p = 0usize;
        for j in start..frames.len() {
            if p == expected.len() || frames[j].ts_ms() > horizon {
                break;
            }
            if synth[j] {
                continue;
            }
            if matches!(
                compare_asdu(&expected[p], frames[j].asdu),
                AsduCmp::Identical | AsduCmp::Cp56Only
            ) {
                synth[j] = true;
                p += 1;
            }
        }
        if p < expected.len() {
            mark_audited_window(req, &cas, frames, start, horizon, synth);
        }
    }
}

fn mark_audited_window(
    req: &RequestRec,
    cas: &[u16],
    frames: &[IFrame],
    start: usize,
    horizon: f64,
    synth: &mut [bool],
) {
    for &ca in cas {
        let is = |f: &IFrame, cot: u8| {
            f.asdu.len() >= DUI_LEN
                && f.asdu[0] == req.type_id
                && cot_value(f.asdu) == cot
                && common_address(f.asdu) == ca
        };
        let Some(ac) = (start..frames.len())
            .take_while(|&j| frames[j].ts_ms() <= horizon)
            .find(|&j| {
                !synth[j] && (is(&frames[j], COT_ACT_CON) || is(&frames[j], COT_UNKNOWN_CA))
            })
        else {
            continue;
        };
        synth[ac] = true;
        if is_negative(frames[ac].asdu) {
            continue;
        }
        for j in ac + 1..frames.len() {
            let f = &frames[j];
            if f.ts_ms() > horizon || is(f, COT_ACT_CON) {
                break;
            }
            if is(f, COT_ACT_TERM) {
                synth[j] = true;
                break;
            }
            if f.asdu.len() >= DUI_LEN
                && common_address(f.asdu) == ca
                && req.in_data_bucket(cot_value(f.asdu))
            {
                synth[j] = true;
            }
        }
    }
}

/// Negative confirmation: P/N bit set, or COT 46 (unknown CA).
fn is_negative(asdu: &[u8]) -> bool {
    asdu.len() >= DUI_LEN && (asdu[2] & 0x40 != 0 || cot_value(asdu) == COT_UNKNOWN_CA)
}

fn expected_data_cot_for_request(req: &RequestRec) -> u8 {
    if req.type_id == 100 {
        match req.qualifier {
            20 => COT_INROGEN_STATION,
            g @ 21..=36 => g,
            _ => COT_INROGEN_STATION,
        }
    } else {
        let qcq = req.qualifier & 0x3f;
        match qcq {
            5 => COT_REQCOGEN,
            g @ 1..=4 => COT_REQCO_GROUP_BASE + (g - 1),
            _ => COT_REQCOGEN,
        }
    }
}

/// Pair every master-side request with its slave-side response burst
/// (ActCon → data frames → ActTerm), then judge each pairing against
/// the four spec-compliance criteria.
pub fn audit_master_commands(
    cap_target: &FlowSnapshot,
    cap_playback: &FlowSnapshot,
    src_inv: &Inventory,
) -> GiCiAudit {
    let requests = collect_master_requests(&parse_flow(cap_target).iframes);
    audit_requests(
        &requests,
        &parse_flow(cap_playback).iframes,
        &mut InventoryTimeline::fixed(src_inv),
    )
}

/// Judge every request's answer. Each request is checked against the
/// inventory as the slave held it when it answered (`timeline`): the
/// state changes of the commands confirmed before the request's ActCon
/// are applied first.
fn audit_requests(
    requests: &[RequestRec],
    frames: &[IFrame],
    timeline: &mut InventoryTimeline,
) -> GiCiAudit {
    struct SlaveFrame<'a> {
        /// Index in `frames`.
        idx: usize,
        ts_ms: f64,
        type_id: u8,
        cot_low: u8,
        ca: u16,
        element_count: usize,
        asdu: &'a [u8],
    }
    let slave_frames: Vec<SlaveFrame> = frames
        .iter()
        .enumerate()
        .filter(|(_, f)| f.asdu.len() >= DUI_LEN)
        .map(|(idx, f)| SlaveFrame {
            idx,
            ts_ms: f.ts_ms(),
            type_id: f.asdu[0],
            cot_low: cot_value(f.asdu),
            ca: common_address(f.asdu),
            element_count: count_elements(f.asdu),
            asdu: f.asdu,
        })
        .collect();
    let mut audit = GiCiAudit::default();
    let mut search_cursor = 0usize;

    for req in requests {
        let kind: &'static str = if req.type_id == 100 { "GI" } else { "CI" };
        let answered_at = (search_cursor..slave_frames.len())
            .find(|&i| {
                let f = &slave_frames[i];
                f.ts_ms + 0.5 >= req.ts_ms && confirms_request(req, f.asdu)
            })
            .map(|i| slave_frames[i].idx)
            .unwrap_or_else(|| frames.partition_point(|f| f.ts_ms() + 0.5 < req.ts_ms));
        let response = req.expected_response(timeline.before(answered_at));
        let mut event = GiCiEvent {
            kind,
            request_ts_ms: req.ts_ms,
            qualifier: req.qualifier,
            ca: req.ca,
            oa: req.oa,
            stations: response.per_ca.len(),
            expected_negative: response.negative(),
            actcon_present: !response.per_ca.is_empty(),
            actcon_delay_ms: None,
            data_frame_count: 0,
            data_element_count: 0,
            actterm_present: !response.per_ca.is_empty(),
            actterm_delay_ms: None,
            all_cots_match_bucket: true,
            polarity_ok: true,
            bytewise_matches_inventory: true,
            expected_data_element_count: 0,
            verdict: "non_compliant",
            notes: Vec::new(),
        };
        if response.per_ca.is_empty() {
            event
                .notes
                .push("no station in the source inventory answers this request".into());
        }
        let expected_cot = expected_data_cot_for_request(req);
        let mut cursor = search_cursor;
        let mut actcon_ok = true;
        let mut actterm_ok = true;

        // One sub-window per answering station, in wire order.
        for r in &response.per_ca {
            event.expected_data_element_count +=
                r.data.iter().map(|a| count_elements(a)).sum::<usize>();
            let is_ctl = |f: &SlaveFrame, cot: u8| {
                f.type_id == req.type_id && f.ca == r.ca && f.cot_low == cot
            };
            let actcon_idx = (cursor..slave_frames.len()).find(|&i| {
                let f = &slave_frames[i];
                (is_ctl(f, COT_ACT_CON) || is_ctl(f, COT_UNKNOWN_CA)) && f.ts_ms + 0.5 >= req.ts_ms
            });
            let Some(ac_idx) = actcon_idx else {
                event.actcon_present = false;
                event.actterm_present = event.actterm_present && r.negative;
                actcon_ok = false;
                event.notes.push(format!(
                    "CA {}: no matching ActCon found in slave-side stream",
                    r.ca
                ));
                continue;
            };
            let actcon = &slave_frames[ac_idx];
            let delay = actcon.ts_ms - req.ts_ms;
            event.actcon_delay_ms =
                Some(event.actcon_delay_ms.map_or(delay, |d: f64| d.max(delay)));
            actcon_ok &= delay.abs() <= T1_MS_RECOMMENDED;
            let got_negative = is_negative(actcon.asdu);
            if got_negative != r.negative {
                event.polarity_ok = false;
                event.notes.push(format!(
                    "CA {}: expected a {} confirmation, got a {} one",
                    r.ca,
                    if r.negative { "negative" } else { "positive" },
                    if got_negative { "negative" } else { "positive" }
                ));
            }
            if r.negative || got_negative {
                cursor = ac_idx + 1;
                continue;
            }

            // The matching ActTerm, or the next ActCon for the same
            // (type, ca), bounds this station's window.
            let mut term_idx: Option<usize> = None;
            let mut window_end = slave_frames.len();
            for (j, f) in slave_frames.iter().enumerate().skip(ac_idx + 1) {
                if is_ctl(f, COT_ACT_TERM) {
                    term_idx = Some(j);
                    window_end = j;
                    break;
                }
                if is_ctl(f, COT_ACT_CON) {
                    window_end = j;
                    break;
                }
            }
            let mut last_data_ts: Option<f64> = None;
            let mut data_frames: Vec<&SlaveFrame> = Vec::new();
            for f in &slave_frames[(ac_idx + 1)..window_end] {
                if f.ca != r.ca || !req.in_data_bucket(f.cot_low) {
                    continue;
                }
                event.data_frame_count += 1;
                event.data_element_count += f.element_count;
                if f.cot_low != expected_cot {
                    event.all_cots_match_bucket = false;
                }
                data_frames.push(f);
                last_data_ts = Some(f.ts_ms);
            }
            match term_idx {
                Some(ti) => {
                    let basis = last_data_ts.unwrap_or(actcon.ts_ms);
                    let d = slave_frames[ti].ts_ms - basis;
                    event.actterm_delay_ms =
                        Some(event.actterm_delay_ms.map_or(d, |x: f64| x.max(d)));
                    actterm_ok &= d.abs() <= ACTTERM_DELAY_MS_RECOMMENDED;
                }
                None => {
                    event.actterm_present = false;
                    actterm_ok = false;
                    event.notes.push(format!(
                        "CA {}: no matching ActTerm found in slave-side stream",
                        r.ca
                    ));
                }
            }

            // Bytewise verification against the inventory-derived
            // response. CP56-only diffs are accepted (the slave may
            // have rewritten timestamps to the wire-send moment).
            let bytes_ok = r.data.len() == data_frames.len()
                && r.data.iter().zip(data_frames.iter()).all(|(exp, got)| {
                    matches!(
                        compare_asdu(exp, got.asdu),
                        AsduCmp::Identical | AsduCmp::Cp56Only
                    )
                });
            if !bytes_ok {
                event.bytewise_matches_inventory = false;
                event.notes.push(format!(
                    "CA {}: data frames did not match inventory-derived expected response ({} actual vs {} expected frames)",
                    r.ca,
                    data_frames.len(),
                    r.data.len()
                ));
                // Diagnostic: the first diverging pair as hex, capped
                // at 128 bytes per side.
                for (i, (exp, got)) in r.data.iter().zip(data_frames.iter()).enumerate() {
                    if matches!(compare_asdu(exp, got.asdu), AsduCmp::Different) {
                        let cap = |b: &[u8]| -> String {
                            let n = b.len().min(128);
                            let mut s = to_hex(&b[..n]);
                            if b.len() > n {
                                s.push('…');
                            }
                            s
                        };
                        event.notes.push(format!(
                            "diverging frame #{}: expected={} actual={}",
                            i,
                            cap(exp),
                            cap(got.asdu)
                        ));
                        break;
                    }
                }
            }
            cursor = term_idx.map(|i| i + 1).unwrap_or(window_end);
        }

        if !event.all_cots_match_bucket {
            event.notes.push(format!(
                "one or more data frames carried a COT outside the expected bucket (expected {})",
                expected_cot
            ));
        }
        event.verdict = if !actcon_ok || !event.actcon_present || !event.actterm_present {
            "non_compliant"
        } else if actterm_ok
            && event.all_cots_match_bucket
            && event.bytewise_matches_inventory
            && event.polarity_ok
        {
            "compliant"
        } else {
            "partial"
        };

        // Advance past this event so a later request with the same CA
        // cannot reuse our ActCon.
        search_cursor = cursor.max(search_cursor);
        push_event(&mut audit, event);
    }

    audit
}

fn push_event(audit: &mut GiCiAudit, ev: GiCiEvent) {
    let (total, compliant, partial, non) = match ev.kind {
        "GI" => (
            &mut audit.gi_total,
            &mut audit.gi_compliant,
            &mut audit.gi_partial,
            &mut audit.gi_non_compliant,
        ),
        _ => (
            &mut audit.ci_total,
            &mut audit.ci_compliant,
            &mut audit.ci_partial,
            &mut audit.ci_non_compliant,
        ),
    };
    *total += 1;
    match ev.verdict {
        "compliant" => *compliant += 1,
        "partial" => *partial += 1,
        _ => *non += 1,
    }
    if audit.events.len() < MAX_AUDIT_EVENTS {
        audit.events.push(ev);
    } else {
        audit.events_truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asdu::{element_len, encode_cp56time2a, write_ioa};
    use crate::responder::{build_gi_response, respond_gi};
    use protoplay::RunFacts;

    // ---------------- builders ----------------

    /// APDU stream with one packet per frame, `step_ns` apart.
    fn stream_at(asdus: &[Vec<u8>], t0_ns: u64, step_ns: u64) -> (Vec<u8>, Vec<(u64, usize)>) {
        let mut p = Vec::new();
        let mut offs = Vec::new();
        for (i, a) in asdus.iter().enumerate() {
            offs.push((t0_ns + i as u64 * step_ns, p.len()));
            p.extend_from_slice(&wrap_iframe(a, i as u16, 0));
        }
        (p, offs)
    }

    fn stream(asdus: &[Vec<u8>]) -> (Vec<u8>, Vec<(u64, usize)>) {
        stream_at(asdus, 0, 100_000_000)
    }

    fn wrap_iframe(asdu: &[u8], ns: u16, nr: u16) -> Vec<u8> {
        let len = asdu.len() + 4;
        let mut out = Vec::with_capacity(2 + len);
        out.push(0x68);
        out.push(len as u8);
        out.push(((ns & 0x7f) << 1) as u8);
        out.push((ns >> 7) as u8);
        out.push(((nr & 0x7f) << 1) as u8);
        out.push((nr >> 7) as u8);
        out.extend_from_slice(asdu);
        out
    }

    fn startdt_act() -> (Vec<u8>, Vec<(u64, usize)>) {
        (vec![0x68, 4, 0x07, 0, 0, 0], vec![(0, 0)])
    }

    fn sp(cot: u8, ioa: u8, val: u8) -> Vec<u8> {
        vec![1, 1, cot, 0, 1, 0, ioa, 0, 0, val]
    }

    fn me(cot: u8, ioa: u8, val: u8) -> Vec<u8> {
        vec![13, 1, cot, 0, 1, 0, ioa, 0, 0, val, 0, 0, 0, 0]
    }

    /// M_SP_TB_1 (type 30) with one CP56Time2a stamp.
    fn sp_tb(ioa: u8, val: u8, stamp_ns: u64) -> Vec<u8> {
        let mut a = vec![30, 1, 3, 0, 1, 0, ioa, 0, 0, val];
        a.extend_from_slice(&encode_cp56time2a(stamp_ns, false, false));
        a
    }

    fn gi_actcon() -> Vec<u8> {
        vec![100, 1, 7, 0, 1, 0, 0, 0, 0, 20]
    }

    fn gi_actterm() -> Vec<u8> {
        vec![100, 1, 10, 0, 1, 0, 0, 0, 0, 20]
    }

    fn gi_request() -> Vec<u8> {
        vec![100, 1, 6, 0, 1, 0, 0, 0, 0, 20]
    }

    fn ctx_with(run: RunFacts, proto_config: Option<&str>) -> AnalyzeCtx {
        AnalyzeCtx {
            role: Role::Slave,
            mode_correct: false,
            captured_first_ts_ns: 0,
            target_port: 2404,
            proto_config: proto_config.map(str::to_string),
            cp56_tolerance_ms: 50.0,
            run,
        }
    }

    fn ctx() -> AnalyzeCtx {
        ctx_with(RunFacts::default(), None)
    }

    struct Out {
        r: ProtoSlaveAnalysis,
    }

    impl Out {
        fn pb(&self, k: &str) -> &serde_json::Value {
            &self.r.protocol_specific["playback"][k]
        }
        fn n(&self, k: &str) -> u64 {
            self.pb(k).as_u64().unwrap_or_else(|| panic!("{k} missing"))
        }
    }

    fn run_with(exp: &[Vec<u8>], got: &[Vec<u8>], c: &AnalyzeCtx) -> Out {
        let (ep, eo) = stream(exp);
        let (gp, go) = stream(got);
        let (tp, to) = startdt_act();
        Out {
            r: analyze_iec104_flow(
                Some(FlowSnapshot {
                    payload: &ep,
                    packet_offsets: &eo,
                }),
                Some(FlowSnapshot {
                    payload: &gp,
                    packet_offsets: &go,
                }),
                None,
                Some(FlowSnapshot {
                    payload: &tp,
                    packet_offsets: &to,
                }),
                c,
            ),
        }
    }

    fn run(exp: &[Vec<u8>], got: &[Vec<u8>]) -> Out {
        run_with(exp, got, &ctx())
    }

    fn script10() -> Vec<Vec<u8>> {
        (0..10).map(|i| me(3, i, i)).collect()
    }

    // ---------------- regression tests from the audit probe ----------------

    #[test]
    fn probe_a_wrong_values_same_type_ids_is_not_a_pass() {
        // F058: type IDs line up but every IOA/value is wrong.
        let exp: Vec<_> = (0..10).map(|i| me(3, i, 10)).collect();
        let got: Vec<_> = (0..10).map(|i| me(3, i + 50, 99)).collect();
        let o = run(&exp, &got);
        assert_eq!(o.r.verdict, "partial_delivery");
        assert_eq!(o.r.outcome, VerdictOutcome::Fail);
        assert_eq!(o.r.score_pct, 0.0);
        assert_eq!(o.n("modified_count"), 10);
        assert_eq!(o.n("real_mismatch_count"), 10);
        // The type-ID metric survives as a secondary statistic.
        assert_eq!(o.n("matched_type_ids"), 10);
    }

    const SYNTH_OFF: &str = r#"{"gi_ci_synthesis":false}"#;

    fn gi_bearing_script() -> Vec<Vec<u8>> {
        let mut exp = vec![gi_actcon()];
        exp.extend((0..5).map(|i| sp(20, i, 1)));
        exp.push(gi_actterm());
        exp.extend((0..10).map(|i| me(3, i, i)));
        exp
    }

    fn without_bursts(script: &[Vec<u8>]) -> Vec<Vec<u8>> {
        script
            .iter()
            .filter(|a| !interrogation::is_captured_interrogation_frame(a))
            .cloned()
            .collect()
    }

    #[test]
    fn probe_b_verbatim_replay_of_gi_bearing_source_scores_100_with_synthesis_off() {
        // F012 / F059: with synthesis off the replayer sends the
        // captured GI burst verbatim; a byte-perfect replay of a
        // capture that starts with a station GI must score 100 %.
        let exp = gi_bearing_script();
        let o = run_with(&exp, &exp, &ctx_with(RunFacts::default(), Some(SYNTH_OFF)));
        assert_eq!(o.r.verdict, "good_delivery", "{}", o.r.verdict_reason);
        assert_eq!(o.r.score_pct, 100.0);
        assert_eq!(o.r.outcome, VerdictOutcome::Pass);
        assert_eq!(o.pb("type_id_sequence_match"), true);
        assert_eq!(o.pb("gi_ci_synthesis"), false);
        assert_eq!(o.n("source_interrogation_stripped"), 0);
        assert_eq!(o.n("byte_identical_count"), 17);
    }

    #[test]
    fn gi_bearing_source_with_synthesis_on_expects_the_bursts_stripped() {
        // F018 mirror: with synthesis on the replayer strips captured
        // interrogation exchanges, and so does the expected side.
        let exp = gi_bearing_script();
        let o = run(&exp, &without_bursts(&exp));
        assert_eq!(o.r.verdict, "good_delivery", "{}", o.r.verdict_reason);
        assert_eq!(o.pb("gi_ci_synthesis"), true);
        assert_eq!(o.n("source_interrogation_stripped"), 7);
        assert_eq!(o.n("byte_identical_count"), 10);

        // A replayer that still sent the captured burst is caught.
        let o = run(&exp, &exp);
        assert_eq!(o.r.verdict, "partial_delivery");
        assert_eq!(o.n("extra_count"), 7);
    }

    fn live_gi_run(
        script: &[Vec<u8>],
        replayed: &[Vec<u8>],
        cfg: Option<&str>,
    ) -> (ProtoSlaveAnalysis, usize) {
        let mut inv = Inventory::default();
        let (sp_payload, _) = stream(script);
        inv.ingest_payload(&sp_payload);
        let synth = build_gi_response(
            &inv,
            RequestEcho {
                ca: 1,
                oa: 0,
                test: false,
            },
            20,
        );
        assert!(synth.len() >= 3);
        let mut delivered = synth.clone();
        delivered.extend(replayed.iter().cloned());
        let r = run_with_request(
            script,
            &delivered,
            &gi_request(),
            &ctx_with(RunFacts::default(), cfg),
        );
        (r, synth.len())
    }

    #[test]
    fn live_gi_synthesized_response_is_excluded_in_both_modes() {
        // Source script carries its own captured GI burst. The live
        // master sends a GI; the slave answers with a synthesized burst
        // and then replays the script: without the captured burst when
        // synthesis is on, with it when synthesis is off.
        let mut script = vec![gi_actcon()];
        script.extend((0..3).map(|i| sp(20, i, 1)));
        script.push(gi_actterm());
        script.extend((0..5).map(|i| me(3, i, i)));

        for (cfg, replayed) in [
            (None, without_bursts(&script)),
            (Some(SYNTH_OFF), script.clone()),
        ] {
            let (r, n_synth) = live_gi_run(&script, &replayed, cfg);
            assert_eq!(
                r.verdict, "good_delivery",
                "{cfg:?}: {} {:?}",
                r.verdict_reason, r.notes
            );
            assert_eq!(r.score_pct, 100.0);
            let pb = &r.protocol_specific["playback"];
            assert_eq!(pb["synthesized_excluded"], n_synth);
            assert_eq!(pb["delivered_iframes"], replayed.len());
            let audit = &r.protocol_specific["gi_ci_audit"];
            assert_eq!(audit["gi_total"], 1);
            assert_eq!(audit["gi_compliant"], 1, "{cfg:?}");
        }
    }

    /// Run one slave-role analysis where the live master sent `req`
    /// at 0.9 s and the slave delivered `delivered` from 1.0 s on.
    fn run_with_request(
        script: &[Vec<u8>],
        delivered: &[Vec<u8>],
        req: &[u8],
        c: &AnalyzeCtx,
    ) -> ProtoSlaveAnalysis {
        let (ep, eo) = stream(script);
        let (gp, go) = stream_at(delivered, 1_000_000_000, 100_000_000);
        let mut tp = vec![0x68, 4, 0x07, 0, 0, 0];
        tp.extend_from_slice(&wrap_iframe(req, 0, 0));
        let to = vec![(0u64, 0usize), (900_000_000, 6)];
        analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &ep,
                packet_offsets: &eo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            c,
        )
    }

    /// Frames at explicit times (ns), numbered from 0.
    fn timed(frames: &[(u64, Vec<u8>)]) -> (Vec<u8>, Vec<(u64, usize)>) {
        let mut p = Vec::new();
        let mut offs = Vec::new();
        for (i, (t, a)) in frames.iter().enumerate() {
            offs.push((*t, p.len()));
            p.extend_from_slice(&wrap_iframe(a, i as u16, 0));
        }
        (p, offs)
    }

    /// Slave-role analysis with a timed delivered stream and a timed
    /// master stream (after STARTDT act at 0).
    fn run_timed(
        script: &[Vec<u8>],
        delivered: &[(u64, Vec<u8>)],
        master: &[(u64, Vec<u8>)],
        cfg: Option<&str>,
    ) -> ProtoSlaveAnalysis {
        let (ep, eo) = stream(script);
        let (gp, go) = timed(delivered);
        let mut tp = vec![0x68, 4, 0x07, 0, 0, 0];
        let mut to = vec![(0u64, 0usize)];
        for (i, (t, a)) in master.iter().enumerate() {
            to.push((*t, tp.len()));
            tp.extend_from_slice(&wrap_iframe(a, i as u16, 0));
        }
        analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &ep,
                packet_offsets: &eo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            &ctx_with(RunFacts::default(), cfg),
        )
    }

    /// T12b: a GI answered before a command carries the capture's value,
    /// one answered after it the commanded value; the audit replays the
    /// command between the two and judges each against what the slave
    /// held at the time.
    #[test]
    fn gi_audit_follows_command_driven_inventory_changes() {
        const RI_SPONT: &str = r#"{"commands":{"return_info":"spontaneous"}}"#;
        let script = vec![sp(3, 100, 0), me(3, 1, 5)];
        let inv = inventory_of(&script);
        let echo = RequestEcho {
            ca: 1,
            oa: 0,
            test: false,
        };
        let gi_old = build_gi_response(&inv, echo, 20);
        let mut after = inv.clone();
        after.ingest_asdu(&sp(3, 100, 1));
        let gi_new = build_gi_response(&after, echo, 20);
        assert_ne!(gi_old, gi_new);
        let cmd = vec![45, 1, 6, 0, 1, 0, 100, 0, 0, 1];
        let reply = |cot: u8| {
            let mut a = cmd.clone();
            a[2] = cot;
            a
        };
        let master = vec![
            (900_000_000, gi_request()),
            (1_400_000_000, cmd.clone()),
            (2_000_000_000, gi_request()),
        ];
        let ms = |n: u64| n * 1_000_000;
        let build = |second_gi: &[Vec<u8>]| {
            let mut d: Vec<(u64, Vec<u8>)> = Vec::new();
            for (i, a) in gi_old.iter().enumerate() {
                d.push((ms(1000 + 10 * i as u64), a.clone()));
            }
            d.push((ms(1200), script[0].clone()));
            d.push((ms(1300), script[1].clone()));
            d.push((ms(1410), reply(7)));
            d.push((ms(1420), sp(3, 100, 1)));
            d.push((ms(1430), reply(10)));
            for (i, a) in second_gi.iter().enumerate() {
                d.push((ms(2010 + 10 * i as u64), a.clone()));
            }
            d
        };

        let r = run_timed(&script, &build(&gi_new), &master, Some(RI_SPONT));
        let audit = &r.protocol_specific["gi_ci_audit"];
        assert_eq!(audit["gi_total"], 2, "{audit:#}");
        assert_eq!(audit["gi_compliant"], 2, "{audit:#}");
        assert_eq!(
            r.verdict, "good_delivery",
            "{} {:?}",
            r.verdict_reason, r.notes
        );
        assert_eq!(r.score_pct, 100.0);
        let pb = &r.protocol_specific["playback"];
        assert_eq!(pb["command_responses_excluded"], 3);
        assert_eq!(pb["synthesized_excluded"], 3 + 2 * gi_old.len());
        assert_eq!(pb["delivered_iframes"], 2);

        // A slave that kept the old value after the command is caught.
        let r = run_timed(&script, &build(&gi_old), &master, Some(RI_SPONT));
        let audit = &r.protocol_specific["gi_ci_audit"];
        assert_eq!(audit["gi_compliant"], 1, "{audit:#}");
        assert_eq!(audit["events"][1]["verdict"], "partial", "{audit:#}");
        assert_eq!(audit["events"][1]["bytewise_matches_inventory"], false);

        // Without return information a command changes nothing, so the
        // unchanged answer is the right one.
        let no_ri = r#"{"commands":{"return_info":"none"}}"#;
        let mut d = build(&gi_old);
        d.retain(|(_, a)| a != &sp(3, 100, 1));
        let r = run_timed(&script, &d, &master, Some(no_ri));
        assert_eq!(r.protocol_specific["gi_ci_audit"]["gi_compliant"], 2);
        assert_eq!(r.score_pct, 100.0, "{} {:?}", r.verdict_reason, r.notes);
    }

    /// T12b: with command echo and return information on, captured COT 11
    /// return information is not expected; COT 12 (local command) is.
    #[test]
    fn captured_remote_return_info_is_not_expected_with_return_info_on() {
        let script = vec![sp(3, 1, 0), sp(11, 1, 1), sp(12, 2, 1), me(3, 3, 7)];
        let replayed = vec![script[0].clone(), script[2].clone(), script[3].clone()];
        for cfg in [
            r#"{"commands":{"return_info":"spontaneous"}}"#,
            r#"{"commands":{"return_info":"retrem"}}"#,
        ] {
            let o = run_with(
                &script,
                &replayed,
                &ctx_with(RunFacts::default(), Some(cfg)),
            );
            assert_eq!(o.r.score_pct, 100.0, "{cfg}: {:?}", o.r.notes);
            assert_eq!(o.n("source_return_info_stripped"), 1);
            assert_eq!(o.n("expected_iframes"), 3);
        }
        // Return information off, or command echo off: replayed verbatim.
        for cfg in [
            r#"{"commands":{"return_info":"none"}}"#,
            r#"{"commands":{"enabled":false,"return_info":"retrem"}}"#,
        ] {
            let o = run_with(&script, &script, &ctx_with(RunFacts::default(), Some(cfg)));
            assert_eq!(o.r.score_pct, 100.0, "{cfg}: {:?}", o.r.notes);
            assert_eq!(o.n("source_return_info_stripped"), 0);
            assert_eq!(o.n("expected_iframes"), 4);
        }
    }

    fn inventory_of(script: &[Vec<u8>]) -> Inventory {
        let mut inv = Inventory::default();
        let (p, _) = stream(script);
        inv.ingest_payload(&p);
        inv
    }

    #[test]
    fn broadcast_gi_fans_out_and_every_station_reply_is_excluded() {
        // Two stations (CA 1 and CA 2) in the source; the master sends
        // a GI to CA 0xFFFF and the responder answers per station.
        let mut script: Vec<Vec<u8>> = (0..3).map(|i| me(3, i, i)).collect();
        script.extend((0..3).map(|i| vec![13, 1, 3, 0, 2, 0, i, 0, 0, i, 0, 0, 0, 0]));
        let inv = inventory_of(&script);
        let req = vec![100, 1, 6, 0, 0xff, 0xff, 0, 0, 0, 20];
        let resp = respond_gi(
            &inv,
            RequestEcho {
                ca: 0xffff,
                oa: 0,
                test: false,
            },
            20,
        );
        assert_eq!(resp.per_ca.len(), 2);
        let synth = resp.into_asdus();
        let mut delivered = synth.clone();
        delivered.extend(script.iter().cloned());
        let r = run_with_request(&script, &delivered, &req, &ctx());
        assert_eq!(
            r.verdict, "good_delivery",
            "{} {:?}",
            r.verdict_reason, r.notes
        );
        assert_eq!(
            r.protocol_specific["playback"]["synthesized_excluded"],
            synth.len()
        );
        let audit = &r.protocol_specific["gi_ci_audit"];
        assert_eq!(audit["gi_compliant"], 1, "{audit:#}");
        assert_eq!(audit["events"][0]["stations"], 2);
    }

    #[test]
    fn unknown_ca_gets_a_negative_reply_that_is_compliant() {
        let script = script10();
        let inv = inventory_of(&script);
        let req = vec![100, 1, 6, 0, 7, 0, 0, 0, 0, 20];
        let resp = respond_gi(
            &inv,
            RequestEcho {
                ca: 7,
                oa: 0,
                test: false,
            },
            20,
        );
        assert!(resp.negative());
        let synth = resp.into_asdus();
        let mut delivered = synth.clone();
        delivered.extend(script.iter().cloned());
        let r = run_with_request(&script, &delivered, &req, &ctx());
        assert_eq!(
            r.verdict, "good_delivery",
            "{} {:?}",
            r.verdict_reason, r.notes
        );
        assert_eq!(
            r.protocol_specific["playback"]["synthesized_excluded"],
            synth.len()
        );
        let ev = &r.protocol_specific["gi_ci_audit"]["events"][0];
        assert_eq!(ev["expected_negative"], true);
        assert_eq!(ev["verdict"], "compliant", "{ev:#}");

        // A positive answer where a rejection was due is not compliant.
        let mut wrong = vec![
            vec![100, 1, 7, 0, 7, 0, 0, 0, 0, 20],
            vec![100, 1, 10, 0, 7, 0, 0, 0, 0, 20],
        ];
        wrong.extend(script.iter().cloned());
        let r = run_with_request(&script, &wrong, &req, &ctx());
        assert_eq!(r.verdict, "degraded", "{}", r.verdict_reason);
    }

    #[test]
    fn rewrite_map_is_applied_to_the_reference_and_inventory() {
        // The run remapped CA 1 -> 5. The replayer sends rewritten
        // frames and answers a GI to CA 5 from the rewritten inventory.
        let script = script10();
        let mapped: Vec<Vec<u8>> = script
            .iter()
            .map(|a| {
                let mut a = a.clone();
                a[4] = 5;
                a
            })
            .collect();
        let c = ctx_with(RunFacts::default(), Some(r#"{"common_address":{"1":5}}"#));
        let inv = inventory_of(&mapped);
        let req = vec![100, 1, 6, 0, 5, 0, 0, 0, 0, 20];
        let synth = respond_gi(
            &inv,
            RequestEcho {
                ca: 5,
                oa: 0,
                test: false,
            },
            20,
        )
        .into_asdus();
        assert!(synth.len() > 2);
        let mut delivered = synth.clone();
        delivered.extend(mapped.iter().cloned());
        let r = run_with_request(&script, &delivered, &req, &c);
        assert_eq!(
            r.verdict, "good_delivery",
            "{} {:?}",
            r.verdict_reason, r.notes
        );
        assert_eq!(r.protocol_specific["gi_ci_audit"]["gi_compliant"], 1);
    }

    #[test]
    fn probe_c_loop_with_one_corrupted_frame_is_judged_per_iteration() {
        // F060: 2 iterations, one corrupted frame in iteration 2.
        let exp = script10();
        let mut got = exp.clone();
        got.extend(exp.clone());
        got[15][9] = 0xEE;
        let o = run(&exp, &got);
        assert_eq!(o.r.verdict, "partial_delivery");
        assert!(o.r.score_pct <= 100.0);
        assert!((o.r.score_pct - 95.0).abs() < 1e-9, "{}", o.r.score_pct);
        let iters = o.pb("iterations").as_array().unwrap();
        assert_eq!(iters.len(), 2);
        assert_eq!(iters[0]["status"], "clean");
        assert_eq!(iters[1]["status"], "deviations");
        assert_eq!(iters[1]["modified"], 1);
    }

    #[test]
    fn probe_d_stopped_mid_loop_gives_clean_tail_verdict() {
        // F060: clean run stopped halfway through iteration 2.
        let exp = script10();
        let mut got = exp.clone();
        got.extend(exp[..5].to_vec());
        let stopped = ctx_with(
            RunFacts {
                iterations_per_session: 0,
                stopped_early: true,
                paced_speed: None,
            },
            None,
        );
        let o = run_with(&exp, &got, &stopped);
        assert_eq!(o.r.verdict, "stopped_clean", "{}", o.r.verdict_reason);
        assert_eq!(o.r.outcome, VerdictOutcome::Pass);
        assert_eq!(o.r.score_pct, 100.0);
        assert_eq!(o.n("not_sent_count"), 5);
        assert_eq!(o.pb("stopped_tail")["sent"], 5);
        assert_eq!(o.n("iterations_clean"), 1);

        // Same capture, but the run claims it completed 2 iterations:
        // the missing half iteration is a failure.
        let completed = ctx_with(
            RunFacts {
                iterations_per_session: 2,
                stopped_early: false,
                paced_speed: None,
            },
            None,
        );
        let o = run_with(&exp, &got, &completed);
        assert_eq!(o.r.verdict, "partial_delivery");
        assert_eq!(o.n("missing_count"), 5);
        assert!((o.r.score_pct - 75.0).abs() < 1e-9);
    }

    #[test]
    fn passes_beyond_the_configured_count_are_extra() {
        // N12 (probe C3): 3 clean passes delivered, 2 configured.
        let exp = script10();
        let mut got = exp.clone();
        got.extend(exp.clone());
        got.extend(exp.clone());
        let c = ctx_with(
            RunFacts {
                iterations_per_session: 2,
                ..Default::default()
            },
            None,
        );
        let o = run_with(&exp, &got, &c);
        assert_ne!(o.r.verdict, "good_delivery", "{}", o.r.verdict_reason);
        assert_ne!(o.r.outcome, VerdictOutcome::Pass);
        assert_eq!(o.n("extra_count"), 10);
        assert_eq!(o.n("extra_passes"), 1);
        assert_eq!(o.n("missing_count"), 0);
        assert_eq!(o.n("expected_iframes"), 20);
        assert_eq!(o.n("iterations_clean"), 2);
        let iters = o.pb("iterations").as_array().unwrap();
        assert_eq!(iters.len(), 3);
        assert_eq!(iters[2]["status"], "extra_pass");
        assert_eq!(iters[2]["extra"], 10);
        assert!(o
            .r
            .notes
            .iter()
            .any(|n| n.contains("beyond the 2 configured")));
        // A partial extra pass is flagged too, and owes nothing.
        let mut got = exp.clone();
        got.extend(exp.clone());
        got.extend(exp[..4].to_vec());
        let o = run_with(&exp, &got, &c);
        assert_eq!(o.n("extra_count"), 4);
        assert_eq!(o.n("missing_count"), 0);
        assert_eq!(o.n("not_sent_count"), 0);
        // Unknown count (0): repeated passes are judged, not extra.
        let o = run(&exp, &[exp.clone(), exp.clone(), exp.clone()].concat());
        assert_eq!(o.n("extra_passes"), 0);
        assert_eq!(o.r.verdict, "good_delivery");
    }

    #[test]
    fn configured_iterations_that_never_started_are_missing() {
        let exp = script10();
        let c = ctx_with(
            RunFacts {
                iterations_per_session: 3,
                ..Default::default()
            },
            None,
        );
        let o = run_with(&exp, &exp, &c);
        assert_eq!(o.r.verdict, "partial_delivery");
        assert_eq!(o.n("missing_count"), 20);
        assert_eq!(o.n("expected_iframes"), 30);
        let iters = o.pb("iterations").as_array().unwrap();
        assert_eq!(iters.len(), 3);
        assert_eq!(iters[2]["status"], "not_started");
    }

    #[test]
    fn clean_loop_is_good_delivery_with_n_iterations() {
        let exp = script10();
        let mut got = exp.clone();
        got.extend(exp.clone());
        got.extend(exp.clone());
        let o = run(&exp, &got);
        assert_eq!(o.r.verdict, "good_delivery");
        assert_eq!(o.r.score_pct, 100.0);
        assert_eq!(o.n("iterations_clean"), 3);
        assert_eq!(o.n("expected_iframes"), 30);
    }

    #[test]
    fn probe_e_one_dropped_frame_is_one_gap_not_a_cascade() {
        // F064.
        let exp: Vec<_> = (0..10)
            .map(|i| if i % 2 == 0 { me(3, i, i) } else { sp(3, i, 1) })
            .collect();
        let mut got = exp.clone();
        got.remove(1);
        let o = run(&exp, &got);
        assert_eq!(o.r.verdict, "partial_delivery");
        assert_eq!(o.n("missing_count"), 1);
        assert_eq!(o.n("modified_count"), 0);
        assert_eq!(o.n("extra_count"), 0);
        assert_eq!(o.pb("missing_indices"), &json!([1]));
        assert!((o.r.score_pct - 90.0).abs() < 1e-9);
    }

    #[test]
    fn inserted_and_reordered_frames_are_classified() {
        let exp = script10();
        let mut got = exp.clone();
        got.insert(4, sp(3, 77, 1));
        let o = run(&exp, &got);
        assert_eq!(o.n("extra_count"), 1);
        assert_eq!(o.n("missing_count"), 0);
        assert!((o.r.score_pct - 100.0 * 10.0 / 11.0).abs() < 1e-9);

        let mut got = exp.clone();
        let moved = got.remove(2);
        got.insert(7, moved);
        let o = run(&exp, &got);
        assert_eq!(o.n("reordered_count"), 1);
        assert_eq!(o.n("missing_count"), 0);
        assert_eq!(o.n("extra_count"), 0);
        assert_eq!(o.r.verdict, "partial_delivery");
    }

    #[test]
    fn probe_f_orphan_without_source_is_no_reference() {
        // F061 / F062: no source flow must not read as 100 %.
        let (gp, go) = stream(&script10());
        let (tp, to) = startdt_act();
        let r = analyze_iec104_flow(
            None,
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            &ctx(),
        );
        assert_eq!(r.verdict, "no_reference");
        assert_eq!(r.score_pct, 0.0);
        assert_eq!(r.outcome, VerdictOutcome::Inconclusive);
    }

    #[test]
    fn midflow_source_is_resynchronised() {
        // F061: tail of a previous frame whose value byte was 0x68.
        let exp = script10();
        let (ep, eo) = stream(&exp);
        let mut pre = vec![0x00, 0x68, 0x01, 0x00];
        let shift = pre.len();
        pre.extend(ep);
        let eo: Vec<_> = std::iter::once((0u64, 0usize))
            .chain(eo.into_iter().map(|(t, o)| (t, o + shift)))
            .collect();
        let mut got = exp.clone();
        got[4][9] = 0xEE;
        let (gp, go) = stream(&got);
        let (tp, to) = startdt_act();
        let r = analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &pre,
                packet_offsets: &eo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            &ctx(),
        );
        assert_eq!(r.expected_messages, 10);
        assert_eq!(r.verdict, "partial_delivery");
        assert!((r.score_pct - 90.0).abs() < 1e-9);
        assert!(r.notes.iter().any(|n| n.contains("starts mid-frame")));
    }

    #[test]
    fn unparseable_source_is_no_reference() {
        let junk = vec![0x68u8, 0x01, 0x02, 0x68, 0x00, 0x11, 0x22, 0x33, 0x44];
        let jo = vec![(0u64, 0usize)];
        let (gp, go) = stream(&script10());
        let (tp, to) = startdt_act();
        let r = analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &junk,
                packet_offsets: &jo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            &ctx(),
        );
        assert_eq!(r.verdict, "no_reference");
        assert_eq!(r.score_pct, 0.0);
    }

    #[test]
    fn walker_resyncs_past_a_corrupt_frame_mid_stream() {
        let (mut p, _) = stream(&script10());
        // Corrupt frame #3's length byte so it no longer parses.
        let frame_len = 2 + 4 + 14;
        p[3 * frame_len + 1] = 0x02;
        let offs = vec![(0u64, 0usize)];
        let st = parse_flow(&FlowSnapshot {
            payload: &p,
            packet_offsets: &offs,
        })
        .stats;
        assert_eq!(st.resync_events, 1);
        assert_eq!(st.frames, 9);
        assert_eq!(st.resynced_bytes, frame_len);
    }

    #[test]
    fn walker_reports_truncated_tail() {
        let (mut p, _) = stream(&script10());
        p.truncate(p.len() - 3);
        let offs = vec![(0u64, 0usize)];
        let st = parse_flow(&FlowSnapshot {
            payload: &p,
            packet_offsets: &offs,
        })
        .stats;
        assert_eq!(st.frames, 9);
        assert_eq!(st.truncated_tail_bytes, 2 + 4 + 14 - 3);
        assert_eq!(st.resync_events, 0);
    }

    // ---------------- injected faults ----------------

    /// Delivered stream with explicit N(S) per frame, 100 ms apart.
    fn with_ns(frames: &[(u16, Vec<u8>)]) -> (Vec<u8>, Vec<(u64, usize)>) {
        let mut p = Vec::new();
        let mut offs = Vec::new();
        for (i, (ns, a)) in frames.iter().enumerate() {
            offs.push((i as u64 * 100_000_000, p.len()));
            p.extend_from_slice(&wrap_iframe(a, *ns, 0));
        }
        (p, offs)
    }

    fn run_faulty(
        exp: &[Vec<u8>],
        got: &[(u16, Vec<u8>)],
        cfg: Option<&str>,
        tg: (Vec<u8>, Vec<(u64, usize)>),
    ) -> ProtoSlaveAnalysis {
        let (ep, eo) = stream(exp);
        let (gp, go) = with_ns(got);
        analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &ep,
                packet_offsets: &eo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tg.0,
                packet_offsets: &tg.1,
            }),
            &ctx_with(RunFacts::default(), cfg),
        )
    }

    fn numbered(script: &[Vec<u8>]) -> Vec<(u16, Vec<u8>)> {
        script
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u16, a.clone()))
            .collect()
    }

    const DROP_PLAN: &str =
        r#"{"faults":[{"at":{"frame":3},"kind":"drop_iframes","pct":50,"duration_ms":1000}]}"#;
    const DUP_PLAN: &str =
        r#"{"faults":[{"at":{"frame":2},"kind":"duplicate_iframes","pct":50,"duration_ms":1000}]}"#;

    #[test]
    fn deliberately_dropped_frame_is_excused() {
        let script = script10();
        let mut got = numbered(&script);
        got.remove(3); // N(S) 3 consumed, never sent
        let r = run_faulty(&script, &got, Some(DROP_PLAN), startdt_act());
        assert_eq!(
            r.verdict, "good_delivery",
            "{} {:?}",
            r.verdict_reason, r.notes
        );
        assert_eq!(r.score_pct, 100.0);
        let ps = &r.protocol_specific;
        assert_eq!(ps["playback"]["fault_dropped_excused"], 1);
        assert_eq!(ps["faults"]["dropped_ns"], 1);
        let dim = ps["verdict_dimensions"]["faults"].as_str().unwrap();
        assert!(
            dim.starts_with("1 fault(s) configured (drop_iframes)"),
            "{dim}"
        );
        assert!(dim.contains("1 dropped N(S)"), "{dim}");
        // Without the fault plan the same capture is a missing frame.
        let r = run_faulty(&script, &got, None, startdt_act());
        assert_eq!(r.verdict, "partial_delivery");
        assert!(r.protocol_specific["verdict_dimensions"]["faults"].is_null());
    }

    #[test]
    fn deliberate_duplicates_and_corrupted_ns_are_not_infidelity() {
        let script = script10();
        let mut got = numbered(&script);
        got.insert(3, got[2].clone()); // frame 2 sent twice
        let r = run_faulty(&script, &got, Some(DUP_PLAN), startdt_act());
        assert_eq!(
            r.verdict, "good_delivery",
            "{} {:?}",
            r.verdict_reason, r.notes
        );
        assert_eq!(
            r.protocol_specific["playback"]["fault_duplicates_excluded"],
            1
        );
        assert_eq!(r.protocol_specific["faults"]["duplicates"], 1);
        let r = run_faulty(&script, &got, None, startdt_act());
        assert_eq!(r.verdict, "partial_delivery");

        let mut got = numbered(&script);
        got[4].0 = 4 + crate::faults::CORRUPT_NS_OFFSET;
        let plan = r#"{"faults":[{"at":{"frame":4},"kind":"corrupt_ns","count":1}]}"#;
        let r = run_faulty(&script, &got, Some(plan), startdt_act());
        assert_eq!(r.verdict, "good_delivery", "{}", r.verdict_reason);
        assert_eq!(r.protocol_specific["faults"]["corrupted_ns"], 1);
    }

    #[test]
    fn session_ended_by_a_fault_is_a_clean_stop_with_peer_reaction() {
        let script = script10();
        let got = numbered(&script[..6]);
        // Peer: STARTDT act at 0, STOPDT act at 550 ms.
        let tg = (
            vec![0x68, 4, 0x07, 0, 0, 0, 0x68, 4, 0x13, 0, 0, 0],
            vec![(0, 0), (550_000_000, 6)],
        );
        let plan = r#"{"faults":[{"at":{"ms":500},"kind":"rst"}]}"#;
        let r = run_faulty(&script, &got, Some(plan), tg.clone());
        assert_eq!(r.verdict, "stopped_clean", "{}", r.verdict_reason);
        assert!(r
            .verdict_reason
            .starts_with("session ended after injected faults"));
        let f = &r.protocol_specific["faults"];
        assert_eq!(f["peer_stopdt"], true);
        assert_eq!(f["first_fault_ms"], 500.0);
        assert_eq!(f["peer_frames_after_first_fault"], 1);
        let s = f["summary"].as_str().unwrap();
        assert!(s.contains("peer reaction: sent STOPDT act"), "{s}");
        // A trigger beyond the capture never fired.
        let late = r#"{"faults":[{"at":{"ms":99999},"kind":"rst"}]}"#;
        let r = run_faulty(&script, &numbered(&script), Some(late), tg);
        assert_eq!(r.verdict, "good_delivery");
        let s = r.protocol_specific["faults"]["summary"].as_str().unwrap();
        assert!(s.contains("none fired"), "{s}");
    }

    #[test]
    fn probe_g_lcs_has_no_greedy_collapse() {
        let mut a: Vec<u8> = vec![99];
        a.extend(std::iter::repeat_n(13u8, 5000));
        let b: Vec<u8> = std::iter::repeat_n(13u8, 5000).collect();
        assert_eq!(lcs_length(&a, &b), 5000);
    }

    // ---------------- CP56 handling ----------------

    const EPOCH: u64 = 1_710_428_966_000_000_000;

    #[test]
    fn cp56_change_with_rewrite_off_is_a_real_mismatch() {
        // F065.
        let exp: Vec<_> = (0..5).map(|i| sp_tb(i, 1, EPOCH + i as u64)).collect();
        let mut got = exp.clone();
        got[2] = sp_tb(2, 1, EPOCH + 10_000_000_000);
        let o = run(&exp, &got);
        assert_eq!(o.r.verdict, "partial_delivery");
        assert_eq!(o.n("cp56_changed_count"), 1);
        assert_eq!(o.n("real_mismatch_count"), 1);
    }

    fn cp56_run(offset_ms: u64) -> Out {
        // Source stamps are old; the replay rewrote each stamp to the
        // wire-send time + `offset_ms`.
        let exp: Vec<_> = (0..5)
            .map(|i| sp_tb(i, 1, EPOCH - 86_400_000_000_000))
            .collect();
        let step = 100_000_000u64;
        let got: Vec<_> = (0..5)
            .map(|i| sp_tb(i, 1, EPOCH + i as u64 * step - offset_ms * 1_000_000))
            .collect();
        let (ep, eo) = stream(&exp);
        let (gp, go) = stream_at(&got, 0, step);
        let (tp, to) = startdt_act();
        let mut c = ctx_with(
            RunFacts::default(),
            Some(r#"{"cp56":{"rewrite_to_now":true,"zone":"utc"}}"#),
        );
        c.captured_first_ts_ns = EPOCH;
        Out {
            r: analyze_iec104_flow(
                Some(FlowSnapshot {
                    payload: &ep,
                    packet_offsets: &eo,
                }),
                Some(FlowSnapshot {
                    payload: &gp,
                    packet_offsets: &go,
                }),
                None,
                Some(FlowSnapshot {
                    payload: &tp,
                    packet_offsets: &to,
                }),
                &c,
            ),
        }
    }

    #[test]
    fn cp56_rewrite_within_tolerance_is_good() {
        let o = cp56_run(5);
        assert_eq!(o.r.verdict, "good_delivery", "{}", o.r.verdict_reason);
        assert_eq!(o.n("cp56_only_count"), 5);
    }

    #[test]
    fn cp56_rewrite_out_of_tolerance_is_degraded() {
        let o = cp56_run(500);
        assert_eq!(o.r.verdict, "degraded", "{}", o.r.verdict_reason);
        assert_eq!(o.r.outcome, VerdictOutcome::Fail);
        assert_eq!(o.n("cp56_out_of_tolerance_count"), 5);
        assert_eq!(o.r.score_pct, 0.0);
        assert_eq!(
            o.r.protocol_specific["verdict_dimensions"]["time_tags"],
            false
        );
    }

    // ---------------- timing ----------------

    #[test]
    fn timing_pairs_by_alignment_and_labels_speed_honestly() {
        // F066: replay ran 3× slower than the original; one frame was
        // dropped early, which must not offset later drift samples.
        let exp = script10();
        let mut got = exp.clone();
        got.remove(1);
        let (ep, eo) = stream_at(&exp, 0, 100_000_000);
        // Delivered frame k is source frame k (k=0) or k+1 (k≥1); place
        // each at 3× its source offset.
        let mut gp = Vec::new();
        let mut go = Vec::new();
        for (k, a) in got.iter().enumerate() {
            let src_idx = if k == 0 { 0 } else { k + 1 } as u64;
            go.push((src_idx * 300_000_000, gp.len()));
            gp.extend_from_slice(&wrap_iframe(a, k as u16, 0));
        }
        let (tp, to) = startdt_act();
        let paced = ctx_with(
            RunFacts {
                paced_speed: Some(1.0),
                ..Default::default()
            },
            None,
        );
        let r = analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &ep,
                packet_offsets: &eo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            &paced,
        );
        let t = &r.protocol_specific["timing"];
        let sp = t["speedup_factor"].as_f64().unwrap();
        assert!((sp - 1.0 / 3.0).abs() < 1e-6, "{sp}");
        assert_eq!(t["speed_label"], "3.00× slower");
        // Drift grows linearly: frame 9 is at 2700 ms vs 900 ms.
        assert!((t["max_abs_drift_ms"].as_f64().unwrap() - 1800.0).abs() < 1e-6);
        assert_eq!(t["timing_judged"], true);
        assert!(t["timing_failure"].is_string());
        // The pacing samples pair by alignment: 9 samples, no phantom
        // drift from the dropped frame.
        assert_eq!(r.pacing_samples.len(), 9);
    }

    #[test]
    fn speed_labels() {
        assert_eq!(speed_label(1.0, 1.0, 1.0), "matched");
        assert_eq!(speed_label(1.04, 1.0, 1.0), "matched");
        assert_eq!(speed_label(0.96, 1.0, 1.0), "matched");
        assert_eq!(speed_label(1.5, 1.0, 1.0), "1.50× faster");
        assert_eq!(speed_label(0.5, 1.0, 1.0), "2.00× slower");
        assert_eq!(speed_label(0.0, 1.0, 1.0), "n/a");
    }

    // ---------------- alignment ----------------

    /// Tiny deterministic PRNG for property tests.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    fn lcs_dp(a: &[u8], b: &[u8]) -> usize {
        let mut prev = vec![0usize; b.len() + 1];
        for x in a {
            let mut cur = vec![0usize; b.len() + 1];
            for (j, y) in b.iter().enumerate() {
                cur[j + 1] = if x == y {
                    prev[j] + 1
                } else {
                    prev[j + 1].max(cur[j])
                };
            }
            prev = cur;
        }
        prev[b.len()]
    }

    #[test]
    fn myers_alignment_is_optimal_and_valid() {
        let mut rng = Lcg(42);
        for case in 0..400 {
            let la = (rng.next() % 40) as usize;
            let lb = (rng.next() % 40) as usize;
            let alpha = 1 + (rng.next() % 4) as u8;
            let a: Vec<u8> = (0..la).map(|_| (rng.next() % alpha as u64) as u8).collect();
            let b: Vec<u8> = (0..lb).map(|_| (rng.next() % alpha as u64) as u8).collect();
            let (pairs, complete) = align_sequences(&a, &b);
            assert!(complete);
            assert_eq!(pairs.len(), lcs_dp(&a, &b), "case {case}: {a:?} vs {b:?}");
            for w in pairs.windows(2) {
                assert!(w[0].0 < w[1].0 && w[0].1 < w[1].1, "case {case}");
            }
            for &(i, j) in &pairs {
                assert_eq!(a[i], b[j]);
            }
        }
    }

    #[test]
    fn myers_scales_to_large_streams() {
        // F064: 150k frames with 60 scattered edits must align quickly
        // and find every edit; fully different 100k streams must stay
        // bounded by ALIGN_MAX_D instead of going quadratic.
        let n = 150_000usize;
        let a: Vec<u64> = (0..n as u64).collect();
        let mut b = a.clone();
        let mut rng = Lcg(7);
        let mut removed = 0;
        for _ in 0..30 {
            let i = (rng.next() as usize) % b.len();
            b.remove(i);
            removed += 1;
        }
        for k in 0..30 {
            let i = (rng.next() as usize) % b.len();
            b.insert(i, 1_000_000 + k);
        }
        let t = std::time::Instant::now();
        let (pairs, complete) = align_sequences(&a, &b);
        let similar = t.elapsed();
        assert!(complete);
        assert_eq!(pairs.len(), n - removed);

        let c: Vec<u64> = (0..100_000u64).map(|x| x + 10_000_000).collect();
        let t = std::time::Instant::now();
        let (pairs, complete) = align_sequences(&a[..100_000], &c);
        let different = t.elapsed();
        assert!(pairs.is_empty());
        assert!(!complete);
        eprintln!("align 150k similar: {similar:?}; 100k fully different: {different:?}");
        assert!(similar.as_secs_f64() < 5.0, "{similar:?}");
        assert!(different.as_secs_f64() < 20.0, "{different:?}");
    }

    #[test]
    fn large_capture_with_one_drop_has_bounded_report() {
        // F067: 50k frames, one early drop.
        let exp: Vec<_> = (0..50_000u32)
            .map(|i| me(3, (i % 200) as u8, (i % 7) as u8))
            .collect();
        let mut got = exp.clone();
        got.remove(3);
        let (ep, eo) = stream_at(&exp, 0, 1_000_000);
        let (gp, go) = stream_at(&got, 0, 1_000_000);
        let (tp, to) = startdt_act();
        let r = analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &ep,
                packet_offsets: &eo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            &ctx(),
        );
        let pb = &r.protocol_specific["playback"];
        assert_eq!(pb["missing_count"], 1);
        assert_eq!(pb["modified_count"], 0);
        assert!(r.score_pct > 99.99);
        let bytes = serde_json::to_string(&r.protocol_specific).unwrap().len();
        assert!(bytes < 400_000, "protocol_specific is {bytes} bytes");
        assert!(r.pacing_samples.len() <= MAX_PACING_SAMPLES);
        assert_eq!(r.pacing_samples_total, 49_999);
    }

    #[test]
    fn mismatch_list_is_capped_with_total() {
        let exp: Vec<_> = (0..300).map(|i| me(3, (i % 250) as u8, 1)).collect();
        let got: Vec<_> = (0..300).map(|i| me(3, (i % 250) as u8, 2)).collect();
        let o = run(&exp, &got);
        assert_eq!(
            o.pb("mismatches").as_array().unwrap().len(),
            MAX_MISMATCH_ENTRIES
        );
        assert_eq!(o.n("mismatches_total"), 300);
        assert_eq!(o.pb("mismatches_truncated"), true);
    }

    #[test]
    fn weighted_decimation_respects_weights() {
        // Endpoint A: 1000 samples at weight 1; endpoint B: 100 samples
        // standing for 10 each. Both should get about half the points.
        let mut v: Vec<(f64, f64, f64)> = Vec::new();
        for i in 0..1000 {
            v.push((i as f64, 0.0, 1.0));
        }
        for i in 0..100 {
            v.push((i as f64 * 10.0 + 0.5, 1.0, 10.0));
        }
        v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        let (kept, decimated) = weighted_decimate(&v, 100);
        assert!(decimated);
        let b = kept.iter().filter(|p| p[1] == 1.0).count();
        assert!((35..=65).contains(&b), "B got {b} of {}", kept.len());
        assert_eq!(kept.len(), 100);
        assert!(kept.windows(2).all(|w| w[0][0] <= w[1][0]));
    }

    // ---------------- verdict table ----------------

    fn clean_inputs() -> VerdictInputs {
        VerdictInputs {
            reference_present: true,
            expected: 10,
            delivered: 10,
            good: 10,
            iterations_complete: 1,
            iterations_clean: 1,
            handshake_ok: true,
            ..Default::default()
        }
    }

    fn target(kind: &'static str, mm: usize, modified_only: bool) -> TargetVerdict {
        TargetVerdict {
            kind,
            expected: 5,
            actual: if mm == 0 { 5 } else { 4 },
            total_mismatches: mm,
            modified_only,
            score: if mm == 0 { 100.0 } else { 60.0 },
            lcs: 4,
            lcs_similarity: 0.8,
        }
    }

    #[test]
    fn verdict_table_covers_every_class() {
        use VerdictOutcome::*;
        type Case = (
            &'static str,
            VerdictInputs,
            &'static str,
            VerdictOutcome,
            f64,
        );
        let tail = TailReport {
            iteration: 2,
            sent: 5,
            script_iframes: 10,
            clean: true,
        };
        let cases: Vec<Case> = vec![
            (
                "clean generic",
                clean_inputs(),
                "good_delivery",
                Pass,
                100.0,
            ),
            (
                "clean correct mode",
                VerdictInputs {
                    target: Some(target("same_script", 0, true)),
                    ..clean_inputs()
                },
                "identical",
                Pass,
                100.0,
            ),
            (
                "no source flow",
                VerdictInputs {
                    reference_present: false,
                    ..clean_inputs()
                },
                "no_reference",
                Inconclusive,
                0.0,
            ),
            (
                "nothing expected, frames delivered",
                VerdictInputs {
                    expected: 0,
                    good: 0,
                    ..clean_inputs()
                },
                "no_reference",
                Inconclusive,
                0.0,
            ),
            (
                "source unparseable",
                VerdictInputs {
                    expected: 0,
                    good: 0,
                    delivered: 0,
                    reference_skipped_bytes: 40,
                    ..clean_inputs()
                },
                "no_reference",
                Inconclusive,
                0.0,
            ),
            (
                "source has no I-frames",
                VerdictInputs {
                    expected: 0,
                    good: 0,
                    delivered: 0,
                    ..clean_inputs()
                },
                "no_iframes_expected",
                Pass,
                100.0,
            ),
            (
                "stopped before first frame",
                VerdictInputs {
                    expected: 0,
                    good: 0,
                    delivered: 0,
                    not_sent: 10,
                    stopped_early: true,
                    ..clean_inputs()
                },
                "stopped_before_delivery",
                Inconclusive,
                0.0,
            ),
            (
                "nothing delivered",
                VerdictInputs {
                    delivered: 0,
                    good: 0,
                    missing: 10,
                    ..clean_inputs()
                },
                "no_delivery",
                Fail,
                0.0,
            ),
            (
                "one modified",
                VerdictInputs {
                    good: 9,
                    modified: 1,
                    ..clean_inputs()
                },
                "partial_delivery",
                Fail,
                90.0,
            ),
            (
                "one missing",
                VerdictInputs {
                    good: 9,
                    missing: 1,
                    delivered: 9,
                    ..clean_inputs()
                },
                "partial_delivery",
                Fail,
                90.0,
            ),
            (
                "one extra",
                VerdictInputs {
                    extra: 1,
                    delivered: 11,
                    ..clean_inputs()
                },
                "partial_delivery",
                Fail,
                100.0 * 10.0 / 11.0,
            ),
            (
                "cp56 changed, rewrite off",
                VerdictInputs {
                    good: 9,
                    cp56_changed: 1,
                    ..clean_inputs()
                },
                "partial_delivery",
                Fail,
                90.0,
            ),
            (
                "no STARTDT",
                VerdictInputs {
                    handshake_ok: false,
                    ..clean_inputs()
                },
                "handshake_incomplete",
                Fail,
                50.0,
            ),
            (
                "target silent",
                VerdictInputs {
                    target: Some(TargetVerdict {
                        actual: 0,
                        ..target("silent", 5, false)
                    }),
                    ..clean_inputs()
                },
                "target_silent",
                Fail,
                50.0,
            ),
            (
                "target divergent",
                VerdictInputs {
                    target: Some(target("divergent", 3, false)),
                    ..clean_inputs()
                },
                "divergent_script",
                Fail,
                80.0,
            ),
            (
                "target subset",
                VerdictInputs {
                    target: Some(target("subset", 1, false)),
                    ..clean_inputs()
                },
                "subset_script",
                Fail,
                80.0,
            ),
            (
                "target bytes differ",
                VerdictInputs {
                    target: Some(TargetVerdict {
                        actual: 5,
                        ..target("same_script", 2, true)
                    }),
                    ..clean_inputs()
                },
                "structurally_identical",
                Fail,
                80.0,
            ),
            (
                "target partial",
                VerdictInputs {
                    target: Some(target("same_script", 2, false)),
                    ..clean_inputs()
                },
                "partial",
                Fail,
                80.0,
            ),
            (
                "cp56 out of tolerance",
                VerdictInputs {
                    good: 8,
                    cp56_out_of_tolerance: 2,
                    ..clean_inputs()
                },
                "degraded",
                Fail,
                80.0,
            ),
            (
                "gi/ci audit failure",
                VerdictInputs {
                    gi_ci_failed: 1,
                    ..clean_inputs()
                },
                "degraded",
                Fail,
                100.0,
            ),
            (
                "timing drift",
                VerdictInputs {
                    timing_failure: Some("pacing drift reached 5000 ms".into()),
                    ..clean_inputs()
                },
                "degraded",
                Fail,
                100.0,
            ),
            (
                "stopped with clean tail",
                VerdictInputs {
                    expected: 15,
                    delivered: 15,
                    good: 15,
                    not_sent: 5,
                    stopped_tail: Some(tail.clone()),
                    stopped_early: true,
                    ..clean_inputs()
                },
                "stopped_clean",
                Pass,
                100.0,
            ),
            (
                "stopped tail with deviation",
                VerdictInputs {
                    expected: 15,
                    delivered: 15,
                    good: 14,
                    modified: 1,
                    not_sent: 5,
                    stopped_tail: Some(TailReport {
                        clean: false,
                        ..tail.clone()
                    }),
                    stopped_early: true,
                    ..clean_inputs()
                },
                "partial_delivery",
                Fail,
                100.0 * 14.0 / 15.0,
            ),
        ];
        for (name, vin, verdict, outcome, score) in cases {
            let v = decide_verdict(&vin);
            assert_eq!(v.name, verdict, "{name}: {}", v.reason);
            assert_eq!(v.outcome, outcome, "{name}");
            assert!(
                (v.score - score).abs() < 1e-9,
                "{name}: {} vs {score}",
                v.score
            );
            assert!((0.0..=100.0).contains(&v.score), "{name}");
            assert_ne!(v.name, "unknown");
        }
    }

    // ---------------- ported unit tests ----------------

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
        let orig = vec![
            45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46, 45, 46,
        ];
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
            36, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        asdu.extend_from_slice(&encode_cp56time2a(stamp_ns, false, false));
        let mut frame = vec![0x68, (asdu.len() + 4) as u8, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&asdu);
        frame
    }

    #[test]
    fn cp56_drift_zero_when_stamp_matches_send_time() {
        const SEND_REL_NS: u64 = 12_345_678_900;
        let iframe = build_type36_iframe(EPOCH + SEND_REL_NS);
        let packet_offsets = vec![(SEND_REL_NS, 0)];
        let flow = FlowSnapshot {
            payload: &iframe,
            packet_offsets: &packet_offsets,
        };
        let drift =
            compute_cp56_drift(&flow, EPOCH, Cp56Zone::Utc, 50.0).expect("should yield drift");
        assert_eq!(drift.samples, 1);
        assert_eq!(drift.iframes_with_cp56, 1);
        assert!(drift.max_ms < 1.0);
        assert_eq!(drift.out_of_tolerance, 0);
        assert_eq!(drift.drift_samples_ms.len(), drift.samples);
        assert_eq!(drift.sample_frame_indices.len(), drift.samples);
        assert_eq!(drift.sample_type_ids.len(), drift.samples);
        assert!(!drift.samples_truncated);
        assert_eq!(drift.sample_stride, 1);
        assert_eq!(drift.sample_frame_indices[0], 0);
        assert_eq!(drift.sample_type_ids[0], 36);
    }

    #[test]
    fn cp56_drift_flags_out_of_tolerance() {
        const SEND_REL_NS: u64 = 5_000_000_000;
        let iframe = build_type36_iframe(EPOCH + SEND_REL_NS - 100_000_000);
        let packet_offsets = vec![(SEND_REL_NS, 0)];
        let flow = FlowSnapshot {
            payload: &iframe,
            packet_offsets: &packet_offsets,
        };
        let drift = compute_cp56_drift(&flow, EPOCH, Cp56Zone::Utc, 50.0).unwrap();
        assert_eq!(drift.out_of_tolerance, 1);
        assert!((drift.mean_ms - 100.0).abs() < 2.0);
        assert!(drift.mean_signed_ms > 80.0);
        assert_eq!(drift.drift_samples_ms.len(), 1);
        assert!((drift.drift_samples_ms[0] - 100.0).abs() < 2.0);
    }

    #[test]
    fn cp56_drift_samples_are_strided_not_prefix_truncated() {
        // F136 (analysis side): a long session keeps samples from its
        // whole span, and the stride is reported as a weight.
        let n = MAX_DRIFT_SAMPLES * 2 + 10;
        let mut payload = Vec::new();
        let mut offs = Vec::new();
        for i in 0..n {
            offs.push((i as u64 * 1_000_000, payload.len()));
            payload.extend_from_slice(&build_type36_iframe(EPOCH + i as u64 * 1_000_000));
        }
        let flow = FlowSnapshot {
            payload: &payload,
            packet_offsets: &offs,
        };
        let d = compute_cp56_drift(&flow, EPOCH, Cp56Zone::Utc, 50.0).unwrap();
        assert_eq!(d.samples, n);
        assert!(d.samples_truncated);
        assert_eq!(d.sample_stride, 3);
        assert!(d.drift_samples_ms.len() <= MAX_DRIFT_SAMPLES);
        assert!(*d.sample_frame_indices.last().unwrap() as usize > n - 4);
    }

    #[test]
    fn compare_asdu_identical_returns_identical() {
        let a = vec![1, 0x01, 0x03, 0, 0x01, 0, 0x01, 0, 0, 0x42];
        assert_eq!(compare_asdu(&a, &a), AsduCmp::Identical);
    }

    #[test]
    fn compare_asdu_cp56_only_diff_classified() {
        let mut a = vec![
            36, 0x01, 0x03, 0, 0x01, 0, 0x01, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0x00,
        ];
        let mut b = a.clone();
        a.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x04, 0x18]);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18]);
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Cp56Only);
        assert_eq!(content_key(&a), content_key(&b));
    }

    #[test]
    fn compare_asdu_real_diff_in_payload_classified() {
        let mut a = vec![
            36, 0x01, 0x03, 0, 0x01, 0, 0x01, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0x00,
        ];
        let mut b = a.clone();
        b[12] = 0xff;
        a.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x04, 0x18]);
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18]);
        assert_eq!(compare_asdu(&a, &b), AsduCmp::Different);
        assert_ne!(content_key(&a), content_key(&b));
    }

    #[test]
    fn compare_asdu_no_cp56_field_is_real_diff() {
        let a = vec![
            13, 0x01, 0x03, 0, 0x01, 0, 0x01, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00,
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
            13, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

    fn one_point_inventory() -> Inventory {
        let mut inv = Inventory::default();
        let elem = element_len(13).unwrap();
        let mut point = vec![0u8; DUI_LEN + IOA_LEN + elem];
        point[0] = 13;
        point[1] = 0x01;
        point[2] = 20;
        point[4] = 1;
        write_ioa(&mut point, DUI_LEN, 100);
        point[DUI_LEN + IOA_LEN] = 0xaa;
        inv.ingest_asdu(&point);
        inv
    }

    fn gi_request_frame(oa: u8) -> Vec<u8> {
        let mut req_asdu = vec![0u8; DUI_LEN + IOA_LEN + 1];
        req_asdu[0] = 100;
        req_asdu[1] = 0x01;
        req_asdu[2] = 6;
        req_asdu[3] = oa;
        req_asdu[4] = 1;
        req_asdu[DUI_LEN + IOA_LEN] = 20;
        wrap_iframe(&req_asdu, 0, 0)
    }

    #[test]
    fn audit_pairs_request_with_compliant_response() {
        let inv = one_point_inventory();
        let req_frame = gi_request_frame(42);
        let echo = RequestEcho {
            ca: 1,
            oa: 42,
            test: false,
        };
        let resp = build_gi_response(&inv, echo, 20);
        assert_eq!(resp.len(), 3);
        let (slave_payload, slave_offsets) = stream_at(&resp, 10_000_000, 10_000_000);
        let master_offsets = vec![(0u64, 0usize)];
        let cap_target = FlowSnapshot {
            payload: &req_frame,
            packet_offsets: &master_offsets,
        };
        let cap_playback = FlowSnapshot {
            payload: &slave_payload,
            packet_offsets: &slave_offsets,
        };
        let audit = audit_master_commands(&cap_target, &cap_playback, &inv);
        assert_eq!(audit.gi_total, 1);
        assert_eq!(audit.ci_total, 0);
        assert_eq!(audit.gi_compliant, 1, "events={:#?}", audit.events);
        let ev = &audit.events[0];
        assert_eq!(ev.kind, "GI");
        assert_eq!(ev.qualifier, 20);
        assert_eq!(ev.ca, 1);
        assert_eq!(ev.oa, 42);
        assert!(ev.actcon_present);
        assert!(ev.actterm_present);
        assert_eq!(ev.data_frame_count, 1);
        assert_eq!(ev.data_element_count, 1);
        assert_eq!(ev.expected_data_element_count, 1);
        assert!(ev.all_cots_match_bucket);
        assert!(ev.bytewise_matches_inventory);
        assert_eq!(ev.verdict, "compliant");
    }

    #[test]
    fn audit_flags_missing_actterm_as_non_compliant() {
        let inv = one_point_inventory();
        let req_frame = gi_request_frame(0);
        let echo = RequestEcho {
            ca: 1,
            oa: 0,
            test: false,
        };
        let resp = build_gi_response(&inv, echo, 20);
        // Drop the ActTerm to simulate a misbehaving slave.
        let (slave_payload, slave_offsets) = stream_at(&resp[..2], 10_000_000, 10_000_000);
        let master_offsets = vec![(0u64, 0usize)];
        let cap_target = FlowSnapshot {
            payload: &req_frame,
            packet_offsets: &master_offsets,
        };
        let cap_playback = FlowSnapshot {
            payload: &slave_payload,
            packet_offsets: &slave_offsets,
        };
        let audit = audit_master_commands(&cap_target, &cap_playback, &inv);
        assert_eq!(audit.gi_total, 1);
        assert_eq!(audit.gi_non_compliant, 1);
        assert_eq!(audit.events[0].verdict, "non_compliant");
        assert!(!audit.events[0].actterm_present);
    }

    #[test]
    fn gi_audit_failure_degrades_the_verdict() {
        // F065: script fine, but the synthesized GI response lacks its
        // ActTerm, so the GI/CI dimension fails.
        let script = script10();
        let mut inv = Inventory::default();
        let (sp_payload, _) = stream(&script);
        inv.ingest_payload(&sp_payload);
        let resp = build_gi_response(
            &inv,
            RequestEcho {
                ca: 1,
                oa: 0,
                test: false,
            },
            20,
        );
        let mut delivered: Vec<Vec<u8>> = resp[..resp.len() - 1].to_vec();
        delivered.extend(script.iter().cloned());
        let (ep, eo) = stream(&script);
        let (gp, go) = stream_at(&delivered, 1_000_000_000, 100_000_000);
        let mut tp = vec![0x68, 4, 0x07, 0, 0, 0];
        tp.extend_from_slice(&gi_request_frame(0));
        let to = vec![(0u64, 0usize), (900_000_000, 6)];
        let r = analyze_iec104_flow(
            Some(FlowSnapshot {
                payload: &ep,
                packet_offsets: &eo,
            }),
            Some(FlowSnapshot {
                payload: &gp,
                packet_offsets: &go,
            }),
            None,
            Some(FlowSnapshot {
                payload: &tp,
                packet_offsets: &to,
            }),
            &ctx(),
        );
        assert_eq!(r.verdict, "degraded", "{}", r.verdict_reason);
        assert_eq!(r.outcome, VerdictOutcome::Fail);
        assert!(r.verdict_reason.contains("GI/CI"));
    }

    #[test]
    fn cp56_drift_walker_survives_zero_length_apci_byte() {
        let mut payload = vec![0u8; 32];
        payload[0] = 0x68;
        payload[1] = 0x00;
        payload[2] = 0x00;
        let packet_offsets = vec![(0u64, 0usize)];
        let flow = FlowSnapshot {
            payload: &payload,
            packet_offsets: &packet_offsets,
        };
        let _ = compute_cp56_drift(&flow, 0, Cp56Zone::Utc, 50.0);
    }
}
