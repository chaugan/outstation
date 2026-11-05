//! Run lifecycle helpers shared by the run routes.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::dto::*;

pub(crate) fn get_proto(name: &str) -> Option<Arc<dyn protoplay::ProtoReplayer>> {
    proto_registry::lookup(name)
}

/// Snapshot the live atomics in a run's context into its serializable
/// progress fields. Called on every read so the HTTP response reflects
/// the latest state.
pub(crate) fn refresh_progress(rs: &mut RunState) {
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
                iter_current: p.iter_current.load(Ordering::Relaxed),
                iter_total: p.iter_total.load(Ordering::Relaxed),
            }
        })
        .collect();
}

pub(crate) const CAPTURE_DIR: &str = "/tmp/outstation-captures";
