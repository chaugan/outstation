//! IEC 104 session drivers: master (outstation impersonates the
//! captured client) and slave (outstation impersonates the captured
//! server).
//!
//! Both drivers:
//!   1. extract the captured I-frame script from the reassembled
//!      payload, restarting the framer at every capture gap so no
//!      spliced (corrupted) APDU is ever sent;
//!   2. establish the connection and hand it to a [`Link`], which owns
//!      the reader thread, sequence numbers, the k/w window, the
//!      t1/t2/t3 timers, STARTDT/STOPDT/TESTFR handling and teardown;
//!   3. walk the script with live N(S)/N(R), pacing through
//!      [`Link::wait_until`] so the peer is serviced during every gap.
//!
//! Master: connect → STARTDT act/con → script → wait for acks → S-frame
//! flush → STOPDT act/con → close.
//!
//! Slave: listen/accept → STARTDT act/con (and any later STARTDT/STOPDT
//! from the master) → script, `loop_iterations` times, with live GI/CI
//! and command answers interleaved → idle-serve (keep answering
//! GI/CI/commands/TESTFR and
//! acknowledging) until the master closes, the run is cancelled, or
//! `session.idle_serve_secs` (default 30 s) elapses → close.
//!
//! Every exit path drops the [`Link`], which shuts the socket down in
//! both directions (FIN) and joins the reader thread.

use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use protoplay::{
    progress_cancelled, session_state, MessageProgress, Pacing, ProtoReport, ProtoRunCfg, Role,
};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tracing::{debug, info, warn};

use crate::asdu::{load_rewrite_map, rewrite_asdu, Iec104ProtoConfig, RewriteMap, SessionConfig};
use crate::commands::CommandBook;
use crate::inventory::Inventory;
use crate::link::{
    now_ns, secs_to_ns, CommandEcho, Cp56Rewrite, Link, LinkEnd, LinkOptions, LinkParams,
    Responder, Transfer,
};

/// How long a slave waits for the master's STARTDT act after accept.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const LISTEN_ACCEPT_TIMEOUT: Duration = Duration::from_secs(600);

#[inline]
fn bump(pg: &Option<MessageProgress>, f: impl FnOnce(&MessageProgress)) {
    if let Some(p) = pg {
        f(p);
    }
}

fn set_state(progress: &Option<MessageProgress>, new_state: u8) {
    bump(progress, |p| p.state.store(new_state, Ordering::Relaxed));
}

/// Compute the target send time (ns, relative to the first captured
/// I-frame) for the I-frame with pacing index `time_idx`, honoring the
/// configured pacing and speed multiplier. Returns `None` if pacing is
/// AsFastAsPossible or there's no timing entry for this index.
fn paced_target_ns(cfg_pacing: Pacing, frame_times_ns: &[u64], time_idx: usize) -> Option<u64> {
    match cfg_pacing {
        Pacing::AsFastAsPossible => None,
        Pacing::OriginalTiming { speed } => {
            let raw = *frame_times_ns.get(time_idx)?;
            if speed <= 0.0 || !speed.is_finite() {
                return Some(raw);
            }
            Some(((raw as f64) / speed) as u64)
        }
    }
}

// ---------------------------------------------------------------------------
// Script extraction
// ---------------------------------------------------------------------------

/// One captured I-frame ASDU to replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScriptFrame {
    pub asdu: Vec<u8>,
    /// Index into `ProtoRunCfg::frame_times_ns`. Those timestamps are
    /// computed over the whole (gap-spliced) stream, so this is the
    /// index of the same frame in that walk, or of the frame just
    /// before it for a frame only found after a gap.
    pub time_idx: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Script {
    pub frames: Vec<ScriptFrame>,
    pub gaps: u64,
    pub skipped_bytes: u64,
    /// I-frames the whole-stream walk sees that straddle a gap and so
    /// were left out.
    pub dropped_frames: u64,
}

impl Script {
    fn record(&self, report: &mut ProtoReport) {
        report.protocol.capture_gaps = self.gaps;
        report.protocol.script_skipped_bytes = self.skipped_bytes;
        report.protocol.script_dropped_frames = self.dropped_frames;
    }

    /// Pacing target of frame `idx`, relative to the first frame of the
    /// script (so stripping a leading frame does not delay the start).
    fn target_ns(&self, cfg: &ProtoRunCfg, idx: usize) -> Option<u64> {
        let t = paced_target_ns(cfg.pacing, &cfg.frame_times_ns, self.frames[idx].time_idx)?;
        let base =
            paced_target_ns(cfg.pacing, &cfg.frame_times_ns, self.frames[0].time_idx).unwrap_or(0);
        Some(t.saturating_sub(base))
    }
}

/// Frame the captured stream into the I-frame script. The stream is
/// cut at every `capture_gaps` offset and each contiguous chunk is
/// framed on its own ([`crate::apci::frames`] resyncs at the start of
/// each chunk), so a frame is never assembled from bytes on both sides
/// of a capture gap.
pub(crate) fn extract_script(cfg: &ProtoRunCfg, side_label: &str) -> Script {
    let mut stream = Vec::new();
    for seg in &cfg.client_segments {
        stream.extend_from_slice(&seg.bytes);
    }
    // The pacing timestamps were computed over the whole stream; keep
    // its I-frame offsets to map each script frame to its timestamp.
    let whole = crate::apci::iframe_offsets(&stream);
    let mut cuts: Vec<usize> = cfg
        .capture_gaps
        .iter()
        .copied()
        .filter(|&g| g > 0 && g < stream.len())
        .collect();
    cuts.sort_unstable();
    cuts.dedup();
    let mut bounds = Vec::with_capacity(cuts.len() + 2);
    bounds.push(0);
    bounds.extend_from_slice(&cuts);
    bounds.push(stream.len());

    let mut script = Script {
        gaps: cuts.len() as u64,
        ..Script::default()
    };
    let mut matched = 0usize;
    for w in bounds.windows(2) {
        let (a, b) = (w[0], w[1]);
        let mut walk = crate::apci::frames(&stream[a..b]);
        for f in walk.by_ref() {
            let Some(asdu) = f.asdu() else { continue };
            let abs = a + f.offset;
            let pp = whole.partition_point(|&o| o <= abs);
            if pp > 0 && whole[pp - 1] == abs {
                matched += 1;
            }
            script.frames.push(ScriptFrame {
                asdu: asdu.to_vec(),
                time_idx: pp.saturating_sub(1),
            });
        }
        script.skipped_bytes += (walk.skipped_bytes() + walk.trailing_bytes()) as u64;
    }
    script.dropped_frames = whole.len().saturating_sub(matched) as u64;
    if script.skipped_bytes > 0 || script.gaps > 0 {
        info!(
            side = side_label,
            gaps = script.gaps,
            skipped_bytes = script.skipped_bytes,
            dropped_frames = script.dropped_frames,
            total_bytes = stream.len(),
            "skipped unframed bytes for APCI resync"
        );
    }
    script
}

fn apply_rewrite(script: &mut Script, map: &RewriteMap) {
    if !map.is_empty() {
        for f in script.frames.iter_mut() {
            rewrite_asdu(&mut f.asdu, map);
        }
    }
}

/// Parse the rewrite map and the structured IEC 104 config.
fn load_config(cfg: &ProtoRunCfg) -> Result<(RewriteMap, Iec104ProtoConfig), String> {
    let map = load_rewrite_map(cfg.proto_config.as_deref())
        .map_err(|e| format!("proto_config (rewrite map): {e}"))?;
    let pc = Iec104ProtoConfig::parse(cfg.proto_config.as_deref()).map_err(|e| format!("{e}"))?;
    for w in pc.session.warnings() {
        warn!("{w}");
    }
    if !map.is_empty() {
        info!(
            ca = map.common_address.len(),
            cot = map.cot.len(),
            ioa = map.ioa.len(),
            "loaded ASDU rewrite map"
        );
    }
    Ok((map, pc))
}

fn link_options(
    role: Role,
    s: &SessionConfig,
    pc: &Iec104ProtoConfig,
    progress: &Option<MessageProgress>,
    responder: Option<Responder>,
    reader_name: String,
) -> LinkOptions {
    LinkOptions {
        role,
        params: LinkParams::from_config(s),
        progress: progress.clone(),
        cp56: Cp56Rewrite {
            enabled: pc.cp56.rewrite_to_now,
            zone: pc.cp56.zone(),
        },
        responder,
        reader_name,
        faults: pc.fault_plan.clone(),
    }
}

/// Final figures: elapsed time, and latency/throughput over the active
/// part of the session (idle-serve time excluded).
fn finish(mut report: ProtoReport, t_start: Instant) -> ProtoReport {
    let total = t_start.elapsed().as_millis() as u64;
    report.elapsed_ms = total.saturating_sub(report.protocol.idle_serve_ms);
    report.finalize_latency();
    report.elapsed_ms = total;
    report
}

fn at_idx(e: &LinkEnd, what: &str, idx: usize) -> String {
    format!("{} {what} at idx {idx}", e.describe())
}

/// The session error for a link end, or `None` when the end is a
/// deliberate fault (`rst`) or the peer's reaction to an injected
/// fault; those are reported in `ProtocolStats::fault_reaction`.
fn fail(link: &Link, e: &LinkEnd, msg: String) -> Option<String> {
    if link.fault_excused(e) {
        info!(end = %e.describe(), "session ended by fault injection or the peer's reaction to it");
        None
    } else {
        Some(msg)
    }
}

// ---------------------------------------------------------------------------
// Master
// ---------------------------------------------------------------------------

pub fn run_session(cfg: ProtoRunCfg) -> ProtoReport {
    let t_start = Instant::now();
    let mut report = ProtoReport::default();
    let progress = cfg.progress.clone();

    let (rewrite_map, pc) = match load_config(&cfg) {
        Ok(x) => x,
        Err(e) => {
            report.error = Some(e);
            return report;
        }
    };
    let mut script = extract_script(&cfg, "client");
    apply_rewrite(&mut script, &rewrite_map);
    script.record(&mut report);
    info!(
        count = script.frames.len(),
        "extracted client I-frame ASDUs from pcap"
    );
    bump(&progress, |p| {
        p.planned
            .store(script.frames.len() as u64, Ordering::Relaxed);
    });

    // 1. Connect.
    let sock = match Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::TCP)) {
        Ok(s) => s,
        Err(e) => {
            report.error = Some(format!("socket: {e}"));
            return report;
        }
    };
    if let Some(iface) = &cfg.bind_iface {
        if let Err(e) = sock.bind_device(Some(iface.as_bytes())) {
            report.error = Some(format!("bind_device({iface}): {e}"));
            return report;
        }
    }
    let bind_addr: SocketAddr = SocketAddrV4::new(cfg.bind_ip, 0).into();
    if let Err(e) = sock.bind(&bind_addr.into()) {
        report.error = Some(format!("bind({}): {e}", cfg.bind_ip));
        return report;
    }
    let tgt: SocketAddr = SocketAddrV4::new(cfg.target_ip, cfg.target_port).into();
    // t0 from proto_config wins; otherwise the run's connect timeout.
    let connect_timeout = pc
        .session
        .t0
        .map(Duration::from_secs_f64)
        .unwrap_or(cfg.connect_timeout);
    if let Err(e) = sock.connect_timeout(&tgt.into(), connect_timeout) {
        report.error = Some(format!("connect({tgt}): {e}"));
        report.elapsed_ms = t_start.elapsed().as_millis() as u64;
        return report;
    }
    report.connected = true;
    let stream: TcpStream = sock.into();
    stream.set_nodelay(cfg.tcp_nodelay).ok();

    // 2. Hand the connection to the link engine.
    let opts = link_options(
        Role::Master,
        &pc.session,
        &pc,
        &progress,
        None,
        "iec104-reader".into(),
    );
    let mut link = match Link::start(stream, opts, report) {
        Ok(l) => l,
        Err(r) => return finish(*r, t_start),
    };
    let error = drive_master(&mut link, &cfg, &script);
    let mut report = link.into_report();
    if report.error.is_none() {
        report.error = error;
    }
    finish(report, t_start)
}

/// STARTDT, script, drain, STOPDT. Returns the session error, if any.
fn drive_master(link: &mut Link, cfg: &ProtoRunCfg, script: &Script) -> Option<String> {
    // 3. STARTDT act → con within t1.
    if let Err(e) = link.master_start() {
        let msg = match &e {
            LinkEnd::Timeout(_) => "timeout waiting for STARTDT con".into(),
            e => format!("STARTDT: {}", e.describe()),
        };
        return fail(link, &e, msg);
    }
    info!("STARTDT handshake complete");

    // 4. Windowed, paced client-I-frame replay. Pacing waits service
    //    the link, so TESTFR, acks and t1/t2/t3 keep running in gaps.
    let epoch = now_ns();
    for (idx, frame) in script.frames.iter().enumerate() {
        if let Some(target) = script.target_ns(cfg, idx) {
            if let Err(e) = link.wait_until(epoch + target) {
                return fail(link, &e, at_idx(&e, "during pace", idx));
            }
        }
        if let Err(e) = link.send_script_frame(&frame.asdu) {
            warn!(error = %e.describe(), idx, "master: send aborted");
            return fail(link, &e, at_idx(&e, "sending I-frame", idx));
        }
    }

    // 5. Wait (t1-bounded) for the server to acknowledge everything,
    //    so every in-flight I-frame gets a latency sample.
    match link.drain_pending() {
        Ok(()) => {}
        // Server hung up after the script; unacked_at_end tells the
        // story, and there is nobody left to STOPDT.
        Err(LinkEnd::PeerClosed) => return None,
        Err(e) => {
            let msg = format!("{} after the last I-frame", e.describe());
            return fail(link, &e, msg);
        }
    }

    // 6. S-frame flush (inside master_stop), STOPDT act → con. A
    //    missing con is recorded as a t1 violation but does not fail an
    //    otherwise complete run.
    match link.master_stop() {
        Ok(()) | Err(LinkEnd::PeerClosed) | Err(LinkEnd::Timeout(_)) => None,
        Err(e) => {
            let msg = format!("STOPDT: {}", e.describe());
            fail(link, &e, msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Slave
// ---------------------------------------------------------------------------

pub fn run_slave_session(cfg: ProtoRunCfg) -> ProtoReport {
    let t_start = Instant::now();
    let mut report = ProtoReport::default();
    let progress = cfg.progress.clone();
    set_state(&progress, session_state::PENDING);

    let (rewrite_map, pc) = match load_config(&cfg) {
        Ok(x) => x,
        Err(e) => {
            report.error = Some(e);
            set_state(&progress, session_state::FAILED);
            return report;
        }
    };
    let mut script = extract_script(&cfg, "server");
    apply_rewrite(&mut script, &rewrite_map);
    script.record(&mut report);

    // Point database for live GI/CI answers, built from the resynced,
    // CA/IOA-rewritten frames (including the captured interrogation
    // responses, which carry values too) so the responder's CA filter
    // matches the addresses the live master uses.
    // Shared on/off switch with the analyzer: `{"gi_ci_synthesis": false}`
    // replays the captured bursts verbatim and answers nothing live.
    // Command echo (`commands.enabled`, default on) answers the
    // master's control-direction commands from the same inventory.
    let synthesize = crate::interrogation::synthesis_enabled(cfg.proto_config.as_deref());
    let echo_commands = pc.commands.enabled;
    let responder = (synthesize || echo_commands).then(|| {
        let mut inventory = Inventory::default();
        let mut book = CommandBook::default();
        for f in &script.frames {
            inventory.ingest_asdu(&f.asdu);
            book.ingest_asdu(&f.asdu);
        }
        info!(
            points = inventory.len(),
            command_points = book.len(),
            gi_ci = synthesize,
            commands = echo_commands,
            "slave: built point inventory for live responses"
        );
        let r = Responder::new(inventory).gi_ci(synthesize);
        if echo_commands {
            r.with_commands(CommandEcho {
                cfg: pc.commands.clone(),
                book,
                zone: pc.cp56.zone(),
            })
        } else {
            r
        }
    });
    // The live master gets synthesized answers to its own GI/CI and
    // commands; replaying the captured exchanges too would hand it
    // unsolicited confirmations and duplicate data (and, with return
    // information on, the capture's COT 11 reports of remote commands
    // it never sent). Same rule as the analyzer:
    // `crate::interrogation::CaptureStrip`.
    let strip = crate::interrogation::CaptureStrip::new(synthesize, &pc.commands);
    let before = script.frames.len();
    let mut stripped_return_info = 0u64;
    script.frames.retain(|f| match strip.classify(&f.asdu) {
        None => true,
        Some(kind) => {
            if kind == crate::interrogation::Stripped::ReturnInfo {
                stripped_return_info += 1;
            }
            false
        }
    });
    report.protocol.stripped_capture_frames = (before - script.frames.len()) as u64;
    info!(
        count = script.frames.len(),
        stripped = report.protocol.stripped_capture_frames,
        stripped_return_info,
        port = cfg.listen_port,
        "slave: extracted server-originated I-frame ASDUs"
    );
    bump(&progress, |p| {
        p.planned
            .store(script.frames.len() as u64, Ordering::Relaxed);
    });

    // Note: the ready-gate and user-editable listen-IP snapshot live
    // in sched (see `run_benchmark_slave`). By the time we get here,
    // `cfg.bind_ip` is the final listen address, already approved.

    // 1. Bind the listener.
    let listen_addr: SocketAddr = SocketAddrV4::new(cfg.bind_ip, cfg.listen_port).into();
    let listener = match TcpListener::bind(listen_addr) {
        Ok(l) => l,
        Err(e) => {
            report.error = Some(format!("bind {listen_addr}: {e}"));
            set_state(&progress, session_state::FAILED);
            return report;
        }
    };
    set_state(&progress, session_state::LISTENING);
    info!(%listen_addr, "slave: listening for master connect");

    // 2. Accept, honouring cancel and LISTEN_ACCEPT_TIMEOUT.
    let accept_deadline = Instant::now() + LISTEN_ACCEPT_TIMEOUT;
    listener.set_nonblocking(true).ok();
    let (stream, peer_addr) = loop {
        if progress_cancelled(&progress) {
            report.error = Some("cancelled while listening".into());
            report.elapsed_ms = t_start.elapsed().as_millis() as u64;
            // Stopped before any master connected: not a failure.
            set_state(&progress, session_state::CANCELLED);
            return report;
        }
        match listener.accept() {
            Ok((s, addr)) => break (s, addr),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= accept_deadline {
                    report.error = Some(format!(
                        "no master connected within {}s",
                        LISTEN_ACCEPT_TIMEOUT.as_secs()
                    ));
                    report.elapsed_ms = t_start.elapsed().as_millis() as u64;
                    set_state(&progress, session_state::FAILED);
                    return report;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                report.error = Some(format!("accept: {e}"));
                report.elapsed_ms = t_start.elapsed().as_millis() as u64;
                set_state(&progress, session_state::FAILED);
                return report;
            }
        }
    };
    // One connection per session: stop accepting.
    drop(listener);
    stream.set_nonblocking(false).ok();
    info!(%peer_addr, "slave: master connected");
    set_state(&progress, session_state::CONNECTED);
    report.connected = true;
    stream.set_nodelay(cfg.tcp_nodelay).ok();

    let opts = link_options(
        Role::Slave,
        &pc.session,
        &pc,
        &progress,
        responder,
        format!("iec104-slave-reader-{}", cfg.listen_port),
    );
    let mut link = match Link::start(stream, opts, report) {
        Ok(l) => l,
        Err(r) => {
            set_state(&progress, session_state::FAILED);
            return finish(*r, t_start);
        }
    };
    let error = drive_slave(&mut link, &cfg, &script, &pc.session);
    let mut report = link.into_report();
    if report.error.is_none() {
        report.error = error;
    }
    let report = finish(report, t_start);
    set_state(
        &progress,
        if report.error.is_some() {
            session_state::FAILED
        } else {
            session_state::COMPLETED
        },
    );
    report
}

/// STARTDT, script loops, idle-serve. Returns the session error.
fn drive_slave(
    link: &mut Link,
    cfg: &ProtoRunCfg,
    script: &Script,
    session: &SessionConfig,
) -> Option<String> {
    let progress = &cfg.progress;

    // 3. Wait for STARTDT act (the link replies con).
    let deadline = now_ns() + HANDSHAKE_TIMEOUT.as_nanos() as u64;
    match link.service(Some(deadline), |l| l.transfer() == Transfer::Started) {
        Ok(()) if link.transfer() == Transfer::Started => {}
        Ok(()) => return Some("timeout waiting for STARTDT act from master".into()),
        Err(e) => {
            let msg = format!("{} waiting for STARTDT act", e.describe());
            return fail(link, &e, msg);
        }
    }
    set_state(progress, session_state::ACTIVE);
    info!("slave: STARTDT handshake complete, now active");

    // 4. Replay the captured script `loop_iterations` times within this
    //    connection (0 = until cancel or disconnect). Sequence numbers
    //    and the window persist across loops. An empty script goes
    //    straight to idle-serve.
    if !script.frames.is_empty() {
        let unlimited = cfg.loop_iterations == 0;
        let loops = if unlimited {
            u64::MAX
        } else {
            cfg.loop_iterations
        };
        bump(progress, |p| {
            p.iter_total
                .store(if unlimited { 0 } else { loops }, Ordering::Relaxed);
        });
        for loop_idx in 0..loops {
            // Per-iteration UI counters restart; cumulative totals stay
            // in the report.
            bump(progress, |p| {
                p.iter_current.store(loop_idx + 1, Ordering::Relaxed);
                p.sent.store(0, Ordering::Relaxed);
                p.bytes_written.store(0, Ordering::Relaxed);
            });
            if loop_idx > 0 {
                info!(loop_idx, "slave: starting next within-session iteration");
            }
            // Pacing is re-anchored every loop so loop 2.. do not fire
            // instantly because every captured timestamp is past.
            let epoch = now_ns();
            for (idx, frame) in script.frames.iter().enumerate() {
                if let Some(target) = script.target_ns(cfg, idx) {
                    if let Err(e) = link.wait_until(epoch + target) {
                        return fail(link, &e, at_idx(&e, "during pace", idx));
                    }
                }
                if let Err(e) = link.send_script_frame(&frame.asdu) {
                    warn!(error = %e.describe(), idx, "slave: send aborted");
                    return fail(link, &e, at_idx(&e, "sending I-frame", idx));
                }
            }
        }
    }

    // 5. Idle-serve: keep the RTU alive (GI/CI answers, TESTFR, acks)
    //    after the script, like a real outstation. The master closing,
    //    or the user stopping the run, is the normal way out.
    let idle_start = now_ns();
    let idle_secs = session
        .idle_serve_secs
        .unwrap_or(crate::asdu::DEFAULT_IDLE_SERVE_SECS);
    let idle_deadline = Some(idle_start + secs_to_ns(idle_secs));
    debug!(idle_secs, "slave: script done, idle-serving");
    let r = link.service(idle_deadline, |_| false);
    link.report.protocol.idle_serve_ms = now_ns().saturating_sub(idle_start) / 1_000_000;
    match r {
        Ok(()) => {
            // idle_serve_secs elapsed: let in-flight frames be
            // acknowledged, acknowledge the master, then close.
            match link.drain_pending() {
                Ok(()) | Err(LinkEnd::PeerClosed) | Err(LinkEnd::Cancelled) => {}
                Err(e) => {
                    let msg = format!("{} after idle-serve", e.describe());
                    return fail(link, &e, msg);
                }
            }
            link.flush_ack();
            None
        }
        Err(LinkEnd::PeerClosed) | Err(LinkEnd::Cancelled) => None,
        Err(e) => {
            let msg = format!("{} during idle-serve", e.describe());
            fail(link, &e, msg)
        }
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;

#[cfg(test)]
#[path = "fault_tests.rs"]
mod fault_tests;
