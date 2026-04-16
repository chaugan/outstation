//! IEC 104 client session state machine.
//!
//! Responsibilities:
//!   1. Open TCP from source IP to target:port.
//!   2. Drive STARTDT handshake.
//!   3. Walk the pcap's client I-frames and re-send them with live N(S)
//!      / N(R) numbers (taking over sequence management from the pcap).
//!   4. Acknowledge server I-frames with S-frames as the window fills.
//!   5. Reply TESTFR act with TESTFR con.
//!   6. Close with STOPDT act → con.
//!
//! Threading: one reader thread framing incoming APDUs into a channel,
//! main thread owning writes + pcap walk + timers.

use std::collections::VecDeque;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use protoplay::{session_state, MessageProgress, Pacing, ProtoReport, ProtoRunCfg};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tracing::{debug, info, warn};

use crate::apdu::{
    write_apdu, Apdu, ApduReader, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON,
    U_TESTFR_ACT, U_TESTFR_CON,
};
use crate::asdu::{
    load_rewrite_map, rewrite_asdu, rewrite_cp56time2a_to_now_zoned, Cp56Zone, RewriteMap,
};

#[inline]
fn wall_clock_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

const DEFAULT_W: u16 = 8;
const DEFAULT_K: u16 = 12;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_POLL: Duration = Duration::from_millis(50);
/// `t1` from the IEC 104 spec: max time the client will wait for the
/// server to acknowledge an outstanding I-frame before declaring the
/// session broken.
const T1_TIMEOUT: Duration = Duration::from_secs(15);

#[inline]
fn now_ns() -> u64 {
    // Reuse raw_replay's monotonic clock so latency samples share a
    // time base with the replay engine's jitter measurements.
    raw_replay::now_ns()
}

/// One in-flight I-frame awaiting acknowledgment.
#[derive(Debug, Clone, Copy)]
struct PendingIFrame {
    ns: u16,
    send_ns: u64,
}

/// Maximum latency samples retained per session. With reservoir
/// sampling this gives unbiased percentile estimation up to ~1%
/// p99 error from any stream length, while bounding per-session
/// memory to ~80 KB. 10k × 8 B = 80 KB.
const LATENCY_RESERVOIR_CAP: usize = 10_000;

/// Reservoir-sample collector for per-session latency. Uses a small
/// inline PCG-style LCG so we don't pull in the `rand` crate.
struct LatencyReservoir {
    capacity: usize,
    samples: Vec<u64>,
    /// Total samples seen, including ones we didn't keep.
    count: u64,
    rng_state: u64,
    /// Fast accept-all path while we're still under capacity. Once
    /// we've filled the reservoir this flips to false and the
    /// random replacement path takes over.
    full: bool,
}

impl LatencyReservoir {
    fn new(capacity: usize) -> Self {
        // Seed the RNG from the monotonic clock so concurrent
        // sessions don't draw the same sequence.
        let seed = now_ns().wrapping_add(0x9E3779B97F4A7C15);
        Self {
            capacity,
            samples: Vec::with_capacity(capacity.min(1024)),
            count: 0,
            rng_state: seed | 1,
            full: false,
        }
    }

    #[inline]
    fn next_rand(&mut self) -> u64 {
        // PCG-style LCG step. Quality is fine for sampling.
        self.rng_state = self
            .rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.rng_state
    }

    fn push(&mut self, sample: u64) {
        self.count = self.count.saturating_add(1);
        if !self.full {
            self.samples.push(sample);
            if self.samples.len() >= self.capacity {
                self.full = true;
            }
            return;
        }
        // Algorithm R: pick uniform i in [0, count); if i < capacity
        // it replaces the i-th sample.
        let r = self.next_rand();
        let i = (r % self.count) as usize;
        if i < self.capacity {
            self.samples[i] = sample;
        }
    }

    fn into_vec(self) -> Vec<u64> {
        self.samples
    }
}

/// Pop every pending I-frame whose `ns` is now considered acknowledged
/// by the server's latest `n(r)` and record the measured send→ack
/// latency for each. Sequence numbers wrap at 2^15, so we compare
/// modulo that range.
fn retire_acked(
    pending: &mut VecDeque<PendingIFrame>,
    server_nr: u16,
    samples: &mut LatencyReservoir,
) {
    let now = now_ns();
    while let Some(front) = pending.front().copied() {
        // An I-frame with sequence `ns` is acked when the server's
        // `n(r)` is strictly greater than `ns` (mod 2^15). We treat
        // a wrap-around difference > 2^14 as "already past".
        let diff = server_nr.wrapping_sub(front.ns) & 0x7fff;
        if diff == 0 || diff > 0x4000 {
            break;
        }
        pending.pop_front();
        let lat_ns = now.saturating_sub(front.send_ns);
        samples.push(lat_ns / 1_000);
    }
}

#[inline]
fn bump(pg: &Option<MessageProgress>, f: impl FnOnce(&MessageProgress)) {
    if let Some(p) = pg {
        f(p);
    }
}

/// Sleep until `target_ns` (monotonic clock, ns since `epoch_ns`),
/// checking the per-session cancel flag on every short slice so a
/// user abort unwinds promptly even during a multi-second wait.
fn pace_sleep_until(epoch_ns: u64, target_ns: u64, progress: &Option<MessageProgress>) {
    loop {
        let now = now_ns();
        if now >= epoch_ns + target_ns {
            return;
        }
        if check_cancel(progress) {
            return;
        }
        let remaining_ns = (epoch_ns + target_ns).saturating_sub(now);
        // 100 ms max slice so a cancel is observed within ~100 ms.
        let slice_ns = remaining_ns.min(100_000_000);
        std::thread::sleep(Duration::from_nanos(slice_ns));
    }
}

/// Compute the target send time (ns, relative to the session's send
/// epoch) for I-frame `idx`, honoring the configured pacing and
/// speed multiplier. Returns `None` if pacing is AsFastAsPossible or
/// there's no timing entry for this index.
fn paced_target_ns(cfg_pacing: Pacing, frame_times_ns: &[u64], idx: usize) -> Option<u64> {
    match cfg_pacing {
        Pacing::AsFastAsPossible => None,
        Pacing::OriginalTiming { speed } => {
            let raw = *frame_times_ns.get(idx)?;
            if speed <= 0.0 || !speed.is_finite() {
                return Some(raw);
            }
            Some(((raw as f64) / speed) as u64)
        }
    }
}

/// Parse client segment bytes into an ordered list of I-frame ASDUs.
/// Drops any embedded U/S frames from the client side — we run the
/// handshake and ACKs ourselves.
fn extract_client_iframes(cfg: &ProtoRunCfg) -> Vec<Vec<u8>> {
    extract_iframes(cfg, "client")
}

fn extract_iframes(cfg: &ProtoRunCfg, side_label: &str) -> Vec<Vec<u8>> {
    let mut stream = Vec::new();
    for seg in &cfg.client_segments {
        stream.extend_from_slice(&seg.bytes);
    }
    let mut reader = ApduReader::new(&stream[..]);
    let mut out = Vec::new();
    loop {
        match reader.next_apdu() {
            Ok(Some(Apdu::I { asdu, .. })) => out.push(asdu),
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, side = side_label, "parse error; stopping reassembly");
                break;
            }
        }
    }
    out
}

pub fn run_session(cfg: ProtoRunCfg) -> ProtoReport {
    let t_start = Instant::now();
    let mut report = ProtoReport::default();
    let progress = cfg.progress.clone();

    let rewrite_map: RewriteMap = match load_rewrite_map(cfg.proto_config.as_deref()) {
        Ok(m) => m,
        Err(e) => {
            report.error = Some(format!("proto_config (rewrite map): {e}"));
            return report;
        }
    };
    if !rewrite_map.is_empty() {
        info!(
            ca = rewrite_map.common_address.len(),
            cot = rewrite_map.cot.len(),
            ioa = rewrite_map.ioa.len(),
            "loaded ASDU rewrite map"
        );
    }

    let mut client_iframes = extract_client_iframes(&cfg);
    if !rewrite_map.is_empty() {
        for asdu in client_iframes.iter_mut() {
            rewrite_asdu(asdu, &rewrite_map);
        }
    }
    info!(
        count = client_iframes.len(),
        "extracted client I-frame ASDUs from pcap"
    );
    bump(&progress, |p| {
        p.planned.store(client_iframes.len() as u64, Ordering::Relaxed);
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
    if let Err(e) = sock.connect_timeout(&tgt.into(), cfg.connect_timeout) {
        report.error = Some(format!("connect({tgt}): {e}"));
        report.elapsed_ms = t_start.elapsed().as_millis() as u64;
        return report;
    }
    report.connected = true;

    let stream: TcpStream = sock.into();
    stream.set_nodelay(true).ok();
    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            report.error = Some(format!("clone stream: {e}"));
            report.elapsed_ms = t_start.elapsed().as_millis() as u64;
            return report;
        }
    };
    let mut write_stream = stream;
    read_stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();

    // 2. Reader thread.
    let (tx, rx): (mpsc::Sender<Apdu>, Receiver<Apdu>) = mpsc::channel();
    thread::Builder::new()
        .name("iec104-reader".into())
        .spawn(move || {
            let mut r = ApduReader::new(read_stream);
            loop {
                match r.next_apdu() {
                    Ok(Some(a)) => {
                        if tx.send(a).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        // Spin back for more, letting the main thread
                        // do work (and detect channel close at shutdown).
                        continue;
                    }
                    Err(e) => {
                        debug!(error = %e, "reader exiting");
                        break;
                    }
                }
            }
        })
        .expect("spawn iec104-reader");

    // 3. STARTDT handshake.
    if let Err(e) = write_apdu(
        &mut write_stream,
        &Apdu::U {
            code: U_STARTDT_ACT,
        },
    ) {
        report.error = Some(format!("send STARTDT act: {e}"));
        report.elapsed_ms = t_start.elapsed().as_millis() as u64;
        return report;
    }
    // STARTDT is protocol plumbing, not a data frame — don't count it
    // in messages_sent (that field must match `planned`, which only
    // tracks I-frames). Bandwidth is still tallied via bytes_written.
    report.bytes_written += 6;
    bump(&progress, |p| {
        p.bytes_written.fetch_add(6, Ordering::Relaxed);
    });
    if !wait_for_u(&rx, U_STARTDT_CON, HANDSHAKE_TIMEOUT) {
        report.error = Some("timeout waiting for STARTDT con".into());
        report.elapsed_ms = t_start.elapsed().as_millis() as u64;
        return report;
    }
    info!("STARTDT handshake complete");

    // 4. Windowed client-I-frame replay.
    //
    //    Each captured client I-frame is sent with live N(S)/N(R). The
    //    k-window is enforced: at most DEFAULT_K I-frames may be in
    //    flight (sent but not yet acknowledged by the server's n(r)).
    //    When the window is full we block on rx until a server frame
    //    frees at least one slot. Per-message latency is measured
    //    send→ack and stored for histogram output.
    let mut my_ns: u16 = 0;
    let mut my_nr: u16 = 0;
    let mut unacked_received: u16 = 0;
    let w = DEFAULT_W;
    let k = DEFAULT_K;
    let mut pending: VecDeque<PendingIFrame> = VecDeque::with_capacity(k as usize);
    let mut latency = LatencyReservoir::new(LATENCY_RESERVOIR_CAP);
    let send_start_ns = now_ns();

    'outer: for (idx, asdu) in client_iframes.iter().enumerate() {
        if check_cancel(&progress) {
            report.error = Some(format!("cancelled at idx {idx}"));
            break 'outer;
        }
        // Honor original-pcap pacing if configured. This sleep is
        // cancellation-aware so the user can abort even during long
        // multi-second waits between captured frames.
        if let Some(target) = paced_target_ns(cfg.pacing, &cfg.frame_times_ns, idx) {
            pace_sleep_until(send_start_ns, target, &progress);
            if check_cancel(&progress) {
                report.error = Some(format!("cancelled during pace at idx {idx}"));
                break 'outer;
            }
        }
        // Keep the unacked window from exceeding k. If it's already at
        // k, block on recv until a server frame advances n(r) and
        // retires at least one pending I-frame, or t1 elapses.
        while pending.len() as u16 >= k {
            report.window_stalls += 1;
            let deadline = Instant::now() + T1_TIMEOUT;
            let mut freed = false;
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(remaining.min(IDLE_POLL)) {
                    Ok(apdu) => {
                        handle_incoming(
                            apdu,
                            &mut write_stream,
                            &mut my_nr,
                            &mut unacked_received,
                            w,
                            &mut pending,
                            &mut report,
                            &progress,
                            &mut latency,
                        );
                        if (pending.len() as u16) < k {
                            freed = true;
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => {
                        report.error = Some(format!(
                            "server closed before acking I-frame idx {idx} (pending={})",
                            pending.len()
                        ));
                        break 'outer;
                    }
                }
            }
            if !freed {
                report.error = Some(format!(
                    "t1 timeout at idx {idx}: server never acked {} pending I-frames",
                    pending.len()
                ));
                break 'outer;
            }
        }

        // Non-blocking drain between sends so we can emit S-frame ACKs
        // for server-originated I-frames promptly and keep pending
        // tight.
        while let Ok(apdu) = rx.try_recv() {
            handle_incoming(
                apdu,
                &mut write_stream,
                &mut my_nr,
                &mut unacked_received,
                w,
                &mut pending,
                &mut report,
                &progress,
                &mut latency,
            );
        }

        let mut patched = asdu.clone();
        if cfg.rewrite_cp56_to_now {
            let zone = Cp56Zone::parse(&cfg.cp56_zone).unwrap_or(Cp56Zone::Local);
            rewrite_cp56time2a_to_now_zoned(&mut patched, wall_clock_unix_ns(), zone);
        }
        let apdu = Apdu::I {
            ns: my_ns,
            nr: my_nr,
            asdu: patched,
        };
        let send_ns = now_ns();
        let wire_len = apdu.serialize().len() as u64;
        if let Err(e) = write_apdu(&mut write_stream, &apdu) {
            warn!(error = %e, "send I-frame failed, aborting");
            report.error = Some(format!("send I-frame at idx {idx}: {e}"));
            break;
        }
        pending.push_back(PendingIFrame { ns: my_ns, send_ns });
        my_ns = (my_ns.wrapping_add(1)) & 0x7fff;
        report.messages_sent += 1;
        report.bytes_written += wire_len;
        bump(&progress, |p| {
            p.sent.fetch_add(1, Ordering::Relaxed);
            p.bytes_written.fetch_add(wire_len, Ordering::Relaxed);
            p.unacked.store(pending.len() as u64, Ordering::Relaxed);
        });
    }

    // Drain remaining server frames for up to t1 so we can record
    // latency samples for every in-flight I-frame before we hand the
    // session off to STOPDT.
    let final_deadline = Instant::now() + T1_TIMEOUT;
    while !pending.is_empty() && Instant::now() < final_deadline {
        let remaining = final_deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(apdu) => handle_incoming(
                apdu,
                &mut write_stream,
                &mut my_nr,
                &mut unacked_received,
                w,
                &mut pending,
                &mut report,
                &progress,
                &mut latency,
            ),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    report.unacked_at_end = pending.len() as u64;
    bump(&progress, |p| {
        p.unacked.store(pending.len() as u64, Ordering::Relaxed);
    });

    // Total elapsed for the I-frame phase — used by finalize_latency
    // for throughput calc.
    let send_elapsed_ms = (now_ns().saturating_sub(send_start_ns)) / 1_000_000;
    report.elapsed_ms = send_elapsed_ms;

    // 5. STOPDT close (best effort). Plumbing frame — bytes only, no
    //    messages_sent bump.
    if let Err(e) = write_apdu(
        &mut write_stream,
        &Apdu::U {
            code: U_STOPDT_ACT,
        },
    ) {
        debug!(error = %e, "STOPDT act failed");
    } else {
        report.bytes_written += 6;
        bump(&progress, |p| {
            p.bytes_written.fetch_add(6, Ordering::Relaxed);
        });
        // Short wait for STOPDT con.
        let _ = wait_for_u(&rx, U_STOPDT_CON, Duration::from_secs(2));
    }
    // Dropping write_stream sends FIN.
    report.elapsed_ms = t_start.elapsed().as_millis() as u64;
    report.latency_samples_us = latency.into_vec();
    report.finalize_latency();
    report
}

/// Process one incoming APDU: advance `my_nr` for I-frames, retire
/// pending I-frames against `n(r)` in S/I frames, auto-ack TESTFR, and
/// emit an S-frame when our receive window hits `w`.
fn handle_incoming(
    apdu: Apdu,
    writer: &mut TcpStream,
    my_nr: &mut u16,
    unacked_received: &mut u16,
    w: u16,
    pending: &mut VecDeque<PendingIFrame>,
    report: &mut ProtoReport,
    progress: &Option<MessageProgress>,
    latency: &mut LatencyReservoir,
) {
    match apdu {
        Apdu::I { nr, asdu, .. } => {
            retire_acked(pending, nr, latency);
            *my_nr = my_nr.wrapping_add(1) & 0x7fff;
            *unacked_received += 1;
            report.messages_received += 1;
            let iframe_bytes = 6 + asdu.len() as u64;
            report.bytes_read += iframe_bytes;
            bump(progress, |p| {
                p.received.fetch_add(1, Ordering::Relaxed);
                p.bytes_read.fetch_add(iframe_bytes, Ordering::Relaxed);
                p.unacked.store(pending.len() as u64, Ordering::Relaxed);
            });
        }
        Apdu::S { nr } => {
            retire_acked(pending, nr, latency);
            report.bytes_read += 6;
            bump(progress, |p| {
                p.bytes_read.fetch_add(6, Ordering::Relaxed);
                p.unacked.store(pending.len() as u64, Ordering::Relaxed);
            });
        }
        Apdu::U { code: U_TESTFR_ACT } => {
            let _ = write_apdu(
                writer,
                &Apdu::U {
                    code: U_TESTFR_CON,
                },
            );
            // TESTFR con is plumbing — bandwidth only, no data counter.
            report.bytes_written += 6;
            report.bytes_read += 6;
            bump(progress, |p| {
                p.bytes_written.fetch_add(6, Ordering::Relaxed);
                p.bytes_read.fetch_add(6, Ordering::Relaxed);
            });
        }
        Apdu::U { .. } => {
            report.bytes_read += 6;
            bump(progress, |p| {
                p.bytes_read.fetch_add(6, Ordering::Relaxed);
            });
        }
    }
    if *unacked_received >= w {
        // Automatic S-frame ack — plumbing, not a data frame.
        let _ = write_apdu(writer, &Apdu::S { nr: *my_nr });
        report.bytes_written += 6;
        *unacked_received = 0;
        bump(progress, |p| {
            p.bytes_written.fetch_add(6, Ordering::Relaxed);
        });
    }
}

fn wait_for_u(rx: &Receiver<Apdu>, code: u8, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(IDLE_POLL)) {
            Ok(Apdu::U { code: c }) if c == code => return true,
            Ok(_other) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Slave-mode session: outstation impersonates the captured server.
//
// Flow:
//   1. Bind a TcpListener on 0.0.0.0:cfg.listen_port.
//   2. accept() exactly one connection from the live master.
//   3. Wait for STARTDT act from the master, reply STARTDT con.
//   4. Walk the captured server-originated I-frames with live N(S)/N(R),
//      pipelined to k, measuring send→ack latency just like master mode.
//   5. Handle inbound client I-frames by advancing my_nr + emitting an
//      S-frame when the receive window fills.
//   6. Handle STOPDT act → con; drop the socket.

const LISTEN_ACCEPT_TIMEOUT: Duration = Duration::from_secs(600);

/// Helper: transition the session-state atomic if progress is present.
fn set_state(progress: &Option<MessageProgress>, new_state: u8) {
    if let Some(p) = progress {
        p.state.store(new_state, Ordering::Relaxed);
    }
}

#[inline]
fn check_cancel(progress: &Option<MessageProgress>) -> bool {
    progress
        .as_ref()
        .map(|p| p.cancel.load(Ordering::Relaxed))
        .unwrap_or(false)
}

pub fn run_slave_session(cfg: ProtoRunCfg) -> ProtoReport {
    let t_start = Instant::now();
    let mut report = ProtoReport::default();
    let progress = cfg.progress.clone();
    set_state(&progress, session_state::PENDING);

    let rewrite_map: RewriteMap = match load_rewrite_map(cfg.proto_config.as_deref()) {
        Ok(m) => m,
        Err(e) => {
            report.error = Some(format!("proto_config (rewrite map): {e}"));
            return report;
        }
    };
    if !rewrite_map.is_empty() {
        info!(
            ca = rewrite_map.common_address.len(),
            cot = rewrite_map.cot.len(),
            ioa = rewrite_map.ioa.len(),
            "loaded ASDU rewrite map (slave)"
        );
    }

    let mut server_iframes = extract_iframes(&cfg, "server");
    if !rewrite_map.is_empty() {
        for asdu in server_iframes.iter_mut() {
            rewrite_asdu(asdu, &rewrite_map);
        }
    }
    info!(
        count = server_iframes.len(),
        port = cfg.listen_port,
        "slave: extracted server-originated I-frame ASDUs"
    );
    bump(&progress, |p| {
        p.planned.store(server_iframes.len() as u64, Ordering::Relaxed);
    });

    // Note: the ready-gate and user-editable listen-IP snapshot live
    // in sched (see `run_benchmark_slave`). By the time we get here,
    // `cfg.bind_ip` is the final listen address, already approved.

    // 1. Bind the listener. `bind_ip` carries the user-chosen local
    //    address (0.0.0.0 for any-interface, or a specific RTU IP the
    //    user has aliased to a host interface).
    let listen_addr: SocketAddr = format!("{}:{}", cfg.bind_ip, cfg.listen_port)
        .parse()
        .expect("valid socket addr");
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
    if let Err(e) = listener.set_nonblocking(false) {
        debug!(error = %e, "set_nonblocking(false) failed");
    }

    // 3. Accept. We block up to LISTEN_ACCEPT_TIMEOUT for the master
    //    to show up, then fail the session. Also honour cancel so the
    //    user can abort a slave that's waiting for a connection.
    let accept_deadline = Instant::now() + LISTEN_ACCEPT_TIMEOUT;
    listener.set_nonblocking(true).ok();
    let (write_stream, peer_addr) = loop {
        if check_cancel(&progress) {
            report.error = Some("cancelled while listening".into());
            report.elapsed_ms = t_start.elapsed().as_millis() as u64;
            set_state(&progress, session_state::FAILED);
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
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                report.error = Some(format!("accept: {e}"));
                report.elapsed_ms = t_start.elapsed().as_millis() as u64;
                set_state(&progress, session_state::FAILED);
                return report;
            }
        }
    };
    listener.set_nonblocking(false).ok();
    info!(%peer_addr, "slave: master connected");
    set_state(&progress, session_state::CONNECTED);
    report.connected = true;

    write_stream.set_nodelay(true).ok();
    let read_stream = match write_stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            report.error = Some(format!("clone stream: {e}"));
            report.elapsed_ms = t_start.elapsed().as_millis() as u64;
            return report;
        }
    };
    let mut write_stream = write_stream;
    read_stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();

    // 3. Reader thread.
    let (tx, rx): (mpsc::Sender<Apdu>, Receiver<Apdu>) = mpsc::channel();
    thread::Builder::new()
        .name(format!("iec104-slave-reader-{}", cfg.listen_port))
        .spawn(move || {
            let mut r = ApduReader::new(read_stream);
            loop {
                match r.next_apdu() {
                    Ok(Some(a)) => {
                        if tx.send(a).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => {
                        debug!(error = %e, "slave reader exiting");
                        break;
                    }
                }
            }
        })
        .expect("spawn iec104-slave-reader");

    // 5. Wait for STARTDT act from the master, reply STARTDT con.
    if !wait_for_u(&rx, U_STARTDT_ACT, HANDSHAKE_TIMEOUT) {
        report.error = Some("timeout waiting for STARTDT act from master".into());
        report.elapsed_ms = t_start.elapsed().as_millis() as u64;
        set_state(&progress, session_state::FAILED);
        return report;
    }
    if let Err(e) = write_apdu(
        &mut write_stream,
        &Apdu::U {
            code: U_STARTDT_CON,
        },
    ) {
        report.error = Some(format!("send STARTDT con: {e}"));
        report.elapsed_ms = t_start.elapsed().as_millis() as u64;
        set_state(&progress, session_state::FAILED);
        return report;
    }
    // STARTDT con is plumbing, not a data frame.
    report.bytes_written += 6;
    bump(&progress, |p| {
        p.bytes_written.fetch_add(6, Ordering::Relaxed);
    });
    set_state(&progress, session_state::ACTIVE);
    info!("slave: STARTDT handshake complete, now active");

    // 5. Windowed send of captured server I-frames.
    let mut my_ns: u16 = 0;
    let mut my_nr: u16 = 0;
    let mut unacked_received: u16 = 0;
    let w = DEFAULT_W;
    let k = DEFAULT_K;
    let mut pending: VecDeque<PendingIFrame> = VecDeque::with_capacity(k as usize);
    let mut latency = LatencyReservoir::new(LATENCY_RESERVOIR_CAP);
    let send_start_ns = now_ns();

    'outer: for (idx, asdu) in server_iframes.iter().enumerate() {
        if check_cancel(&progress) {
            report.error = Some(format!("cancelled at idx {idx}"));
            break 'outer;
        }
        if let Some(target) = paced_target_ns(cfg.pacing, &cfg.frame_times_ns, idx) {
            pace_sleep_until(send_start_ns, target, &progress);
            if check_cancel(&progress) {
                report.error = Some(format!("cancelled during pace at idx {idx}"));
                break 'outer;
            }
        }
        while pending.len() as u16 >= k {
            report.window_stalls += 1;
            let deadline = Instant::now() + T1_TIMEOUT;
            let mut freed = false;
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(remaining.min(IDLE_POLL)) {
                    Ok(apdu) => {
                        handle_incoming(
                            apdu,
                            &mut write_stream,
                            &mut my_nr,
                            &mut unacked_received,
                            w,
                            &mut pending,
                            &mut report,
                            &progress,
                            &mut latency,
                        );
                        if (pending.len() as u16) < k {
                            freed = true;
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => {
                        report.error = Some(format!(
                            "master closed before acking I-frame idx {idx} (pending={})",
                            pending.len()
                        ));
                        break 'outer;
                    }
                }
            }
            if !freed {
                report.error = Some(format!(
                    "t1 timeout at idx {idx}: master never acked {} pending I-frames",
                    pending.len()
                ));
                break 'outer;
            }
        }

        while let Ok(apdu) = rx.try_recv() {
            handle_incoming(
                apdu,
                &mut write_stream,
                &mut my_nr,
                &mut unacked_received,
                w,
                &mut pending,
                &mut report,
                &progress,
                &mut latency,
            );
        }

        let mut patched = asdu.clone();
        if cfg.rewrite_cp56_to_now {
            let zone = Cp56Zone::parse(&cfg.cp56_zone).unwrap_or(Cp56Zone::Local);
            rewrite_cp56time2a_to_now_zoned(&mut patched, wall_clock_unix_ns(), zone);
        }
        let apdu = Apdu::I {
            ns: my_ns,
            nr: my_nr,
            asdu: patched,
        };
        let send_ns = now_ns();
        let wire_len = apdu.serialize().len() as u64;
        if let Err(e) = write_apdu(&mut write_stream, &apdu) {
            warn!(error = %e, "slave: send I-frame failed");
            report.error = Some(format!("send I-frame at idx {idx}: {e}"));
            break;
        }
        pending.push_back(PendingIFrame { ns: my_ns, send_ns });
        my_ns = (my_ns.wrapping_add(1)) & 0x7fff;
        report.messages_sent += 1;
        report.bytes_written += wire_len;
        bump(&progress, |p| {
            p.sent.fetch_add(1, Ordering::Relaxed);
            p.bytes_written.fetch_add(wire_len, Ordering::Relaxed);
            p.unacked.store(pending.len() as u64, Ordering::Relaxed);
        });
    }

    // 6. Drain remaining server frames so pending clears.
    let final_deadline = Instant::now() + T1_TIMEOUT;
    while !pending.is_empty() && Instant::now() < final_deadline {
        let remaining = final_deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(apdu) => handle_incoming(
                apdu,
                &mut write_stream,
                &mut my_nr,
                &mut unacked_received,
                w,
                &mut pending,
                &mut report,
                &progress,
                &mut latency,
            ),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    report.unacked_at_end = pending.len() as u64;
    bump(&progress, |p| {
        p.unacked.store(pending.len() as u64, Ordering::Relaxed);
    });

    // 7. Wait briefly for STOPDT act from master. If it arrives, reply
    //    STOPDT con. Either way, drop the socket to close.
    if wait_for_u(&rx, U_STOPDT_ACT, Duration::from_secs(2)) {
        if write_apdu(
            &mut write_stream,
            &Apdu::U {
                code: U_STOPDT_CON,
            },
        )
        .is_ok()
        {
            // STOPDT con is plumbing.
            report.bytes_written += 6;
            bump(&progress, |p| {
                p.bytes_written.fetch_add(6, Ordering::Relaxed);
            });
        }
    }

    let _ = send_start_ns; // currently unused; reserved for per-session throughput refinement
    report.elapsed_ms = t_start.elapsed().as_millis() as u64;
    report.latency_samples_us = latency.into_vec();
    report.finalize_latency();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Apdu;
    use protoplay::ClientSegment;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};

    /// Helper: assemble a set of I-frames serialized into a single
    /// client_segments byte buffer.
    fn iframes_blob(count: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..count {
            let asdu = vec![
                0x65,
                0x01,
                0x06,
                0x00,
                0x01,
                0x00,
                i as u8,
                (i >> 8) as u8,
                0x00,
                0x00,
            ];
            bytes.extend_from_slice(
                &Apdu::I {
                    ns: i,
                    nr: 0,
                    asdu,
                }
                .serialize(),
            );
        }
        bytes
    }

    #[test]
    fn windowed_send_blocks_until_server_acks() {
        // Plan: 15 client I-frames. k=12. Server reads 12 silently,
        // waits 100ms, sends an S-frame acking all 12. Client should
        // stall after the 12th I-frame, unblock on the S-frame,
        // finish sending the last 3. All 15 should have latency
        // samples; the first 12 should have elevated latency (≥ 100 ms)
        // since they sat in the pending deque until the S-frame.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();

            // STARTDT act -> STARTDT con
            let mut buf = [0u8; 6];
            sock.read_exact(&mut buf).unwrap();
            assert_eq!(buf, [0x68, 4, U_STARTDT_ACT, 0, 0, 0]);
            sock.write_all(&[0x68, 4, U_STARTDT_CON, 0, 0, 0]).unwrap();

            // Read the first 12 I-frames (headers + ASDUs).
            let mut got = 0u16;
            while got < 12 {
                let mut hdr = [0u8; 2];
                sock.read_exact(&mut hdr).unwrap();
                assert_eq!(hdr[0], 0x68);
                let mut body = vec![0u8; hdr[1] as usize];
                sock.read_exact(&mut body).unwrap();
                if body[0] & 0x01 == 0 {
                    got += 1;
                }
            }
            // Delay, then S-frame acking all 12 (n(r)=12).
            std::thread::sleep(Duration::from_millis(120));
            // S-frame: APCI 01 00 cf3 cf4 where (cf4<<7)|(cf3>>1) = 12
            let nr: u16 = 12;
            let cf3 = ((nr << 1) & 0xfe) as u8;
            let cf4 = ((nr >> 7) & 0xff) as u8;
            sock.write_all(&[0x68, 4, 0x01, 0x00, cf3, cf4]).unwrap();

            // Read the remaining I-frames + STOPDT act.
            let mut data = Vec::new();
            let mut tmp = [0u8; 1024];
            while let Ok(n) = sock.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&tmp[..n]);
                if data
                    .windows(6)
                    .any(|w| w == [0x68, 4, U_STOPDT_ACT, 0, 0, 0])
                {
                    sock.write_all(&[0x68, 4, U_STOPDT_CON, 0, 0, 0]).ok();
                    break;
                }
            }
        });

        let cfg = ProtoRunCfg {
            bind_ip: Ipv4Addr::new(127, 0, 0, 1),
            bind_iface: None,
            target_ip: Ipv4Addr::new(127, 0, 0, 1),
            target_port: port,
            client_segments: vec![ClientSegment {
                rel_ts_ns: 0,
                bytes: iframes_blob(15),
            }],
            connect_timeout: Duration::from_secs(2),
            speed: 1.0,
            proto_config: None,
            progress: None,
            role: protoplay::Role::Master,
            listen_port: 0,
            pacing: protoplay::Pacing::AsFastAsPossible,
            frame_times_ns: Vec::new(),
            rewrite_cp56_to_now: false,
            cp56_zone: "local".into(),
        };

        let report = run_session(cfg);
        server.join().unwrap();

        assert!(report.connected, "connect failed: {:?}", report.error);
        assert!(
            report.error.is_none(),
            "unexpected error: {:?}",
            report.error
        );
        // messages_sent now tracks data I-frames only (STARTDT / STOPDT
        // / S-frame acks are plumbing and excluded). The test sends 15
        // client I-frames.
        assert!(
            report.messages_sent >= 15,
            "messages_sent = {}",
            report.messages_sent
        );
        assert!(
            report.window_stalls >= 1,
            "expected window to stall at least once, got {}",
            report.window_stalls
        );
        assert_eq!(
            report.latency_samples_us.len(),
            12,
            "expected 12 latency samples (for the 12 window-full frames), got {}: {:?}",
            report.latency_samples_us.len(),
            report.latency_samples_us
        );
        // Those 12 I-frames waited roughly 120 ms for the S-frame.
        let min = *report.latency_samples_us.iter().min().unwrap();
        assert!(
            min >= 80_000 && min <= 400_000,
            "min latency out of expected window: {min} µs"
        );
        // The last 3 I-frames are sent but never acked (no more
        // S-frames from the server), so they end up in unacked_at_end.
        assert!(
            report.unacked_at_end >= 1,
            "expected some unacked I-frames at end, got {}",
            report.unacked_at_end
        );
        // Latency percentile fields are populated.
        assert!(report.latency_p50_us > 0);
        assert!(report.latency_p99_us >= report.latency_p50_us);
    }

    #[test]
    fn session_handshake_roundtrips_against_mock_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).ok();

            // Expect STARTDT act, reply STARTDT con.
            let mut buf = [0u8; 6];
            sock.read_exact(&mut buf).unwrap();
            assert_eq!(buf, [0x68, 4, U_STARTDT_ACT, 0, 0, 0]);
            sock.write_all(&[0x68, 4, U_STARTDT_CON, 0, 0, 0]).unwrap();

            // Read whatever else comes until the client closes. We
            // accept an I-frame and a STOPDT act; reply STOPDT con.
            let mut received = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = sock.read(&mut buf) {
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                // If we just saw STOPDT act (0x13), reply con and bail.
                if received.windows(6).any(|w| w == [0x68, 4, U_STOPDT_ACT, 0, 0, 0]) {
                    sock.write_all(&[0x68, 4, U_STOPDT_CON, 0, 0, 0]).ok();
                    break;
                }
            }
            received
        });

        // Build a ProtoRunCfg that contains one client I-frame.
        let i_frame = Apdu::I {
            ns: 0,
            nr: 0,
            asdu: vec![
                0x65, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        }
        .serialize();
        let cfg = ProtoRunCfg {
            bind_ip: Ipv4Addr::new(127, 0, 0, 1),
            bind_iface: None,
            target_ip: Ipv4Addr::new(127, 0, 0, 1),
            target_port: port,
            client_segments: vec![ClientSegment {
                rel_ts_ns: 0,
                bytes: i_frame,
            }],
            connect_timeout: Duration::from_secs(2),
            speed: 1.0,
            proto_config: None,
            progress: None,
            role: protoplay::Role::Master,
            listen_port: 0,
            pacing: protoplay::Pacing::AsFastAsPossible,
            frame_times_ns: Vec::new(),
            rewrite_cp56_to_now: false,
            cp56_zone: "local".into(),
        };

        let report = run_session(cfg);
        assert!(report.connected, "not connected: {:?}", report.error);
        assert!(report.error.is_none(), "error: {:?}", report.error);
        // Data-frame semantics: exactly one I-frame is sent. STARTDT /
        // STOPDT are plumbing and no longer counted.
        assert_eq!(
            report.messages_sent, 1,
            "messages_sent = {}",
            report.messages_sent
        );

        let received = server.join().unwrap();
        // Confirm the I-frame reached the server.
        assert!(
            received.windows(3).any(|w| w[0] == 0x68 && w[2] & 0x01 == 0),
            "did not see an I-frame in server receive buffer"
        );
    }
}

