//! Live IEC 60870-5-104 link engine shared by the master and slave
//! session drivers in [`crate::session`].
//!
//! One [`Link`] owns an established TCP connection:
//!
//! * a reader thread frames incoming APDUs with the strict live reader
//!   ([`ApduReader::strict`]), timestamps each one at receive time and
//!   forwards `(recv_ns, Apdu)` over a channel;
//! * the session thread drives everything else through one service
//!   loop, [`Link::service`]. While it waits (for a pacing deadline, a
//!   free k-window slot, an acknowledgement or a STARTDT/STOPDT con) it
//!   handles every incoming APDU and runs the IEC 104 §5 timers:
//!   - t1: an I-frame, STARTDT/STOPDT act or TESTFR act not
//!     acknowledged or confirmed within t1 closes the connection;
//!   - t2: received I-frames are acknowledged with an S-frame at the
//!     latest t2 after the first unacknowledged one (or after w);
//!   - t3: after t3 without receiving anything a TESTFR act is sent;
//!   - cancellation, checked at least every 50 ms;
//!   - in slave mode, synthesized GI/CI responses are sent from the
//!     response queue as soon as the transfer state and the k-window
//!     allow.
//!
//! Received sequence numbers are validated (N(S) against V(R), N(R)
//! against the unacknowledged window up to V(S), modulo 2^15). A
//! violation is recorded in [`protoplay::ProtocolStats`] and closes the
//! connection, as the standard requires.
//!
//! Dropping a [`Link`] shuts the socket down in both directions (so the
//! peer sees FIN even though the reader thread holds a duplicate fd)
//! and joins the reader thread.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use protoplay::{
    progress_cancelled, LatencyReservoir, MessageProgress, ProtoReport, ProtocolError, Role,
    COMMAND_RESPONSE_SAMPLES_CAP, LATENCY_RESERVOIR_CAP, PROTOCOL_ERRORS_CAP,
    SYNTHESIZED_INDICES_CAP,
};
use tracing::{debug, warn};

use crate::apdu::{
    Apdu, ApduReader, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT,
    U_TESTFR_CON,
};
use crate::asdu::{
    common_address, rewrite_cp56time2a_to_now_zoned, Cp56Zone, SessionConfig, DUI_LEN, IOA_LEN,
};
use crate::inventory::Inventory;
use crate::responder::{respond_ci, respond_gi, RequestEcho};

/// Longest the service loop blocks before re-checking cancellation.
pub(crate) const SERVICE_SLICE_NS: u64 = 50_000_000;
/// Socket read timeout of the reader thread; bounds how long it takes
/// to notice the stop flag if a shutdown did not wake it.
const READ_TIMEOUT: Duration = Duration::from_millis(200);
/// Sequence numbers are 15 bits.
const SEQ_MASK: u16 = 0x7fff;

#[inline]
pub(crate) fn now_ns() -> u64 {
    // raw_replay's monotonic clock, so latency samples share a time
    // base with the replay engine's jitter measurements.
    raw_replay::now_ns()
}

#[inline]
fn wall_clock_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub(crate) fn secs_to_ns(secs: f64) -> u64 {
    (secs * 1e9).round().max(0.0) as u64
}

/// Resolved link parameters (IEC 104 §5 k, w, t1, t2, t3).
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkParams {
    pub k: u16,
    pub w: u16,
    pub t1_ns: u64,
    pub t2_ns: u64,
    pub t3_ns: u64,
}

impl LinkParams {
    pub fn from_config(c: &SessionConfig) -> Self {
        Self {
            k: c.k,
            w: c.w,
            t1_ns: secs_to_ns(c.t1),
            t2_ns: secs_to_ns(c.t2),
            t3_ns: secs_to_ns(c.t3),
        }
    }
}

/// What the reader thread forwards to the session thread.
enum RxEvent {
    Frame {
        recv_ns: u64,
        apdu: Apdu,
    },
    /// The peer sent bytes that do not frame (bad start octet, bad
    /// length, invalid control field). The reader stops after this.
    Malformed(String),
    /// Socket error other than a read timeout. The reader stops.
    Failed(io::ErrorKind, String),
}

/// STARTDT/STOPDT data-transfer state (IEC 104 §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transfer {
    Stopped,
    /// Master: STARTDT act sent, waiting for con.
    PendingStart,
    Started,
    /// Master: STOPDT act sent. Slave: STOPDT act received, con owed
    /// once our outstanding I-frames are acknowledged.
    PendingStop,
}

/// Why the service loop stopped short of its goal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkEnd {
    /// The per-session cancel flag was raised.
    Cancelled,
    /// The peer closed (or reset) the connection.
    PeerClosed,
    /// A protocol timer (t1) expired. Already recorded as a violation.
    Timeout(String),
    /// The peer violated the protocol. Already recorded.
    Protocol(String),
    /// Local socket error.
    Io(String),
}

impl LinkEnd {
    pub fn describe(&self) -> String {
        match self {
            LinkEnd::Cancelled => "cancelled".into(),
            LinkEnd::PeerClosed => "peer closed the connection".into(),
            LinkEnd::Timeout(m) => m.clone(),
            LinkEnd::Protocol(m) => format!("protocol violation: {m}"),
            LinkEnd::Io(m) => m.clone(),
        }
    }
}

/// One in-flight I-frame awaiting acknowledgment.
#[derive(Debug, Clone, Copy)]
struct PendingIFrame {
    ns: u16,
    send_ns: u64,
}

/// At most this many interrogations (distinct (type, CA) requests) are
/// answered at once; further activations get a negative ActCon.
pub(crate) const MAX_OUTSTANDING_INTERROGATIONS: usize = 8;
/// Hard cap on queued synthesized ASDUs. An activation that arrives
/// with the queue this full is dropped (and recorded), so a peer that
/// floods GI/CI while never acknowledging cannot grow memory.
pub(crate) const RESPONSE_QUEUE_CAP: usize = 4096;

/// One synthesized ASDU waiting to be sent.
struct Queued {
    asdu: Vec<u8>,
    /// Receive time of the command this ASDU answers; set on the first
    /// ASDU of a response so the command-to-response time is measured.
    cmd_recv_ns: Option<u64>,
    /// (type, request CA) of the interrogation this frame belongs to,
    /// for a full (positive) response; `None` for a rejection.
    key: Option<(u8, u16)>,
}

/// What [`Responder::on_command`] did with an ASDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandOutcome {
    /// Not a GI/CI activation.
    NotACommand,
    /// Full response queued (it may itself be a negative ActCon, e.g.
    /// for an unknown CA or an unsupported qualifier).
    Answered,
    /// The same interrogation is still being answered, or too many
    /// are: a negative ActCon is queued instead of another response.
    Rejected,
    /// Response queue full: nothing queued.
    Dropped,
}

/// Slave-mode GI/CI answering: the point inventory and the queue of
/// synthesized response ASDUs.
pub(crate) struct Responder {
    inventory: Inventory,
    queue: VecDeque<Queued>,
    /// Queued-but-unsent frame count per outstanding interrogation.
    outstanding: HashMap<(u8, u16), usize>,
}

impl Responder {
    pub fn new(inventory: Inventory) -> Self {
        Self {
            inventory,
            queue: VecDeque::new(),
            outstanding: HashMap::new(),
        }
    }

    /// If `asdu` is a GI (`C_IC_NA_1`, type 100) or CI (`C_CI_NA_1`,
    /// type 101) activation, queue the spec-correct response (ActCon →
    /// data → ActTerm, built by [`crate::responder`]). A request for an
    /// interrogation that is still being answered, or one beyond
    /// [`MAX_OUTSTANDING_INTERROGATIONS`], is answered with a negative
    /// ActCon; with [`RESPONSE_QUEUE_CAP`] frames queued it is dropped.
    fn on_command(&mut self, asdu: &[u8], recv_ns: u64) -> CommandOutcome {
        if asdu.len() < DUI_LEN + IOA_LEN + 1 {
            return CommandOutcome::NotACommand;
        }
        let type_id = asdu[0];
        if !matches!(type_id, 100 | 101) {
            return CommandOutcome::NotACommand;
        }
        if asdu[2] & 0x3f != 6 {
            // Activation only; ActCon/ActTerm never come from a master.
            return CommandOutcome::NotACommand;
        }
        if self.queue.len() >= RESPONSE_QUEUE_CAP {
            return CommandOutcome::Dropped;
        }
        let echo = RequestEcho {
            ca: common_address(asdu),
            oa: asdu[3],
            test: asdu[2] & 0x80 != 0,
        };
        let key = (type_id, echo.ca);
        if self.outstanding.contains_key(&key)
            || self.outstanding.len() >= MAX_OUTSTANDING_INTERROGATIONS
        {
            // Mirror of the request: COT 7 with P/N = 1, T echoed.
            let mut neg = asdu.to_vec();
            neg[2] = (asdu[2] & 0x80) | 0x40 | 7;
            self.queue.push_back(Queued {
                asdu: neg,
                cmd_recv_ns: Some(recv_ns),
                key: None,
            });
            return CommandOutcome::Rejected;
        }
        let qualifier = asdu[DUI_LEN + IOA_LEN]; // QOI (100) or QCC (101)
        let response = if type_id == 100 {
            respond_gi(&self.inventory, echo, qualifier)
        } else {
            respond_ci(&self.inventory, echo, qualifier)
        };
        if response.negative() {
            debug!(
                type_id,
                ca = echo.ca,
                qualifier,
                "interrogation rejected with negative ActCon"
            );
        }
        let asdus = response.into_asdus();
        if !asdus.is_empty() {
            self.outstanding.insert(key, asdus.len());
        }
        for (i, asdu) in asdus.into_iter().enumerate() {
            self.queue.push_back(Queued {
                asdu,
                cmd_recv_ns: (i == 0).then_some(recv_ns),
                key: Some(key),
            });
        }
        CommandOutcome::Answered
    }

    fn pop(&mut self) -> Option<Queued> {
        let q = self.queue.pop_front()?;
        if let Some(key) = q.key {
            if let Some(n) = self.outstanding.get_mut(&key) {
                *n -= 1;
                if *n == 0 {
                    self.outstanding.remove(&key);
                }
            }
        }
        Some(q)
    }
}

/// CP56Time2a rewrite applied to every outgoing I-frame.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Cp56Rewrite {
    pub enabled: bool,
    pub zone: Cp56Zone,
}

pub(crate) struct LinkOptions {
    pub role: Role,
    pub params: LinkParams,
    pub progress: Option<MessageProgress>,
    pub cp56: Cp56Rewrite,
    pub responder: Option<Responder>,
    pub reader_name: String,
}

pub(crate) struct Link {
    writer: TcpStream,
    rx: Receiver<RxEvent>,
    reader: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    params: LinkParams,
    role: Role,
    progress: Option<MessageProgress>,
    /// The session report; filled in as the link runs.
    pub report: ProtoReport,
    latency: LatencyReservoir,
    cp56: Cp56Rewrite,
    /// Connection-established time, for `ProtocolError::at_ms`.
    epoch_ns: u64,
    /// V(S): N(S) of the next I-frame we send.
    vs: u16,
    /// V(R): N(S) we expect on the next received I-frame.
    vr: u16,
    /// Received I-frames not yet acknowledged to the peer.
    unacked_rx: u16,
    /// Receive time of the oldest of those (t2 reference).
    oldest_unacked_rx_ns: Option<u64>,
    pending: VecDeque<PendingIFrame>,
    /// Last time anything was received (t3 reference).
    last_rx_ns: u64,
    /// TESTFR act we sent, awaiting con (t1 reference).
    testfr_sent_ns: Option<u64>,
    /// STARTDT/STOPDT act we sent (master): (con code, sent at).
    u_act: Option<(u8, u64)>,
    transfer: Transfer,
    /// Slave: STOPDT con owed once `pending` drains.
    stop_con_owed: bool,
    responder: Option<Responder>,
}

impl Link {
    /// Take over an established connection: spawn the reader thread
    /// and return the link. On failure the report comes back with
    /// `error` set; the stream is closed by dropping it.
    pub fn start(
        stream: TcpStream,
        opts: LinkOptions,
        mut report: ProtoReport,
    ) -> Result<Link, Box<ProtoReport>> {
        let read_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                report.error = Some(format!("clone stream: {e}"));
                let _ = stream.shutdown(Shutdown::Both);
                return Err(Box::new(report));
            }
        };
        read_stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let stop_r = stop.clone();
        let reader = match thread::Builder::new()
            .name(opts.reader_name)
            .spawn(move || reader_loop(read_stream, tx, stop_r))
        {
            Ok(h) => h,
            Err(e) => {
                report.error = Some(format!("spawn reader thread: {e}"));
                let _ = stream.shutdown(Shutdown::Both);
                return Err(Box::new(report));
            }
        };
        let now = now_ns();
        Ok(Link {
            writer: stream,
            rx,
            reader: Some(reader),
            stop,
            params: opts.params,
            role: opts.role,
            progress: opts.progress,
            report,
            latency: LatencyReservoir::new(LATENCY_RESERVOIR_CAP),
            cp56: opts.cp56,
            epoch_ns: now,
            vs: 0,
            vr: 0,
            unacked_rx: 0,
            oldest_unacked_rx_ns: None,
            pending: VecDeque::new(),
            last_rx_ns: now,
            testfr_sent_ns: None,
            u_act: None,
            transfer: Transfer::Stopped,
            stop_con_owed: false,
            responder: opts.responder,
        })
    }

    pub fn transfer(&self) -> Transfer {
        self.transfer
    }

    /// Can an I-frame go out right now?
    pub fn can_send(&self) -> bool {
        self.transfer == Transfer::Started && self.pending.len() < self.params.k as usize
    }

    fn cancelled(&self) -> bool {
        // Session cancel or run-level cancel.
        progress_cancelled(&self.progress)
    }

    // ------------------------------------------------------------------
    // Service loop
    // ------------------------------------------------------------------

    /// Run the link until `done` holds or `deadline_ns` (monotonic) is
    /// reached, whichever comes first. Returns `Ok` in both cases; the
    /// caller re-checks its own condition. Every incoming APDU is
    /// handled and every timer serviced while waiting.
    pub fn service(
        &mut self,
        deadline_ns: Option<u64>,
        done: impl Fn(&Link) -> bool,
    ) -> Result<(), LinkEnd> {
        loop {
            loop {
                match self.rx.try_recv() {
                    Ok(ev) => self.handle(ev)?,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return Err(LinkEnd::PeerClosed),
                }
            }
            let now = now_ns();
            self.check_timers(now)?;
            self.drain_responses()?;
            if self.cancelled() {
                return Err(LinkEnd::Cancelled);
            }
            if done(self) {
                return Ok(());
            }
            if deadline_ns.is_some_and(|d| now >= d) {
                return Ok(());
            }
            let mut wake = now + SERVICE_SLICE_NS;
            if let Some(d) = deadline_ns {
                wake = wake.min(d);
            }
            if let Some(t) = self.next_timer_ns() {
                wake = wake.min(t);
            }
            let wait = wake.saturating_sub(now).max(100_000);
            match self.rx.recv_timeout(Duration::from_nanos(wait)) {
                Ok(ev) => self.handle(ev)?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(LinkEnd::PeerClosed),
            }
        }
    }

    /// Service the link until `deadline_ns`.
    pub fn wait_until(&mut self, deadline_ns: u64) -> Result<(), LinkEnd> {
        self.service(Some(deadline_ns), |_| false)
    }

    /// Service the link until every I-frame we sent is acknowledged
    /// (bounded by t1).
    pub fn drain_pending(&mut self) -> Result<(), LinkEnd> {
        self.service(None, |l| l.pending.is_empty())
    }

    /// Send one captured I-frame, first waiting (servicing the link)
    /// until the transfer is started and the k-window has room. Queued
    /// synthesized responses go first.
    pub fn send_script_frame(&mut self, asdu: &[u8]) -> Result<(), LinkEnd> {
        if self.transfer == Transfer::Started && self.pending.len() >= self.params.k as usize {
            self.report.window_stalls += 1;
        }
        self.service(None, |l| l.can_send())?;
        self.send_i(asdu.to_vec(), false)
    }

    /// Master: STARTDT act, then wait for con (t1).
    pub fn master_start(&mut self) -> Result<(), LinkEnd> {
        self.send_u(U_STARTDT_ACT)?;
        self.u_act = Some((U_STARTDT_CON, now_ns()));
        self.transfer = Transfer::PendingStart;
        self.service(None, |l| l.transfer == Transfer::Started)
    }

    /// Master: acknowledge everything received, STOPDT act, then wait
    /// for con (t1).
    pub fn master_stop(&mut self) -> Result<(), LinkEnd> {
        if self.unacked_rx > 0 {
            self.send_s()?;
        }
        self.send_u(U_STOPDT_ACT)?;
        self.u_act = Some((U_STOPDT_CON, now_ns()));
        self.transfer = Transfer::PendingStop;
        self.service(None, |l| l.transfer == Transfer::Stopped)
    }

    /// Best-effort S-frame for any unacknowledged received I-frames.
    pub fn flush_ack(&mut self) {
        if self.unacked_rx > 0 {
            let _ = self.send_s();
        }
    }

    /// Finish: record end-of-session figures and hand back the report.
    /// The connection is shut down and the reader joined when the link
    /// is dropped right after.
    pub fn into_report(mut self) -> ProtoReport {
        self.report.unacked_at_end = self.pending.len() as u64;
        self.report.latency_samples_us =
            std::mem::replace(&mut self.latency, LatencyReservoir::new(1)).into_vec();
        if let Some(p) = &self.progress {
            p.unacked
                .store(self.pending.len() as u64, Ordering::Relaxed);
        }
        std::mem::take(&mut self.report)
    }

    // ------------------------------------------------------------------
    // Timers
    // ------------------------------------------------------------------

    fn next_timer_ns(&self) -> Option<u64> {
        let p = &self.params;
        let mut next: Option<u64> = None;
        let mut consider = |t: u64| next = Some(next.map_or(t, |n| n.min(t)));
        if let Some(f) = self.pending.front() {
            consider(f.send_ns + p.t1_ns);
        }
        if let Some(t) = self.testfr_sent_ns {
            consider(t + p.t1_ns);
        }
        if let Some((_, t)) = self.u_act {
            consider(t + p.t1_ns);
        }
        if let Some(t) = self.oldest_unacked_rx_ns {
            consider(t + p.t2_ns);
        }
        if self.testfr_sent_ns.is_none() && self.u_act.is_none() {
            consider(self.last_rx_ns + p.t3_ns);
        }
        next
    }

    fn check_timers(&mut self, now: u64) -> Result<(), LinkEnd> {
        let p = self.params;
        if let Some(f) = self.pending.front().copied() {
            if now.saturating_sub(f.send_ns) >= p.t1_ns {
                let msg = format!(
                    "t1 expired: I-frame N(S)={} not acknowledged within {:.1} s ({} unacknowledged)",
                    f.ns,
                    p.t1_ns as f64 / 1e9,
                    self.pending.len()
                );
                self.violation("t1_timeout", msg.clone(), true);
                return Err(LinkEnd::Timeout(msg));
            }
        }
        if let Some(t) = self.testfr_sent_ns {
            if now.saturating_sub(t) >= p.t1_ns {
                let msg = format!(
                    "t1 expired: no TESTFR con within {:.1} s",
                    p.t1_ns as f64 / 1e9
                );
                self.violation("t1_timeout", msg.clone(), true);
                return Err(LinkEnd::Timeout(msg));
            }
        }
        if let Some((code, t)) = self.u_act {
            if now.saturating_sub(t) >= p.t1_ns {
                let msg = format!(
                    "t1 expired: no {} within {:.1} s",
                    u_name(code),
                    p.t1_ns as f64 / 1e9
                );
                self.violation("t1_timeout", msg.clone(), true);
                return Err(LinkEnd::Timeout(msg));
            }
        }
        if let Some(t) = self.oldest_unacked_rx_ns {
            if now.saturating_sub(t) >= p.t2_ns {
                self.send_s()?;
            }
        }
        if self.testfr_sent_ns.is_none()
            && self.u_act.is_none()
            && now.saturating_sub(self.last_rx_ns) >= p.t3_ns
        {
            self.send_u(U_TESTFR_ACT)?;
            self.testfr_sent_ns = Some(now);
            self.report.protocol.keepalives_sent += 1;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Receive side
    // ------------------------------------------------------------------

    fn handle(&mut self, ev: RxEvent) -> Result<(), LinkEnd> {
        match ev {
            RxEvent::Frame { recv_ns, apdu } => self.handle_frame(recv_ns, apdu),
            RxEvent::Malformed(m) => {
                self.violation("malformed_frame", m.clone(), true);
                Err(LinkEnd::Protocol(m))
            }
            RxEvent::Failed(kind, m) => {
                if is_peer_close(kind) {
                    Err(LinkEnd::PeerClosed)
                } else {
                    Err(LinkEnd::Io(format!("receive: {m}")))
                }
            }
        }
    }

    fn handle_frame(&mut self, recv_ns: u64, apdu: Apdu) -> Result<(), LinkEnd> {
        self.last_rx_ns = self.last_rx_ns.max(recv_ns);
        match apdu {
            Apdu::I { ns, nr, asdu } => {
                let len = 6 + asdu.len() as u64;
                self.report.messages_received += 1;
                self.report.bytes_read += len;
                if let Some(p) = &self.progress {
                    p.received.fetch_add(1, Ordering::Relaxed);
                    p.bytes_read.fetch_add(len, Ordering::Relaxed);
                }
                if ns != self.vr {
                    let msg = format!(
                        "received I-frame N(S)={ns}, expected V(R)={} (lost, duplicated or reordered frame)",
                        self.vr
                    );
                    self.violation("ns_mismatch", msg.clone(), true);
                    return Err(LinkEnd::Protocol(msg));
                }
                self.check_nr(nr, "I")?;
                self.retire(nr, recv_ns);
                self.vr = (self.vr + 1) & SEQ_MASK;
                self.unacked_rx += 1;
                self.oldest_unacked_rx_ns.get_or_insert(recv_ns);
                // GI/CI are only answered in the started state: a master
                // may not send them otherwise, and queueing them would
                // let it build an unbounded backlog while we cannot send.
                if self.role == Role::Slave && self.transfer == Transfer::Started {
                    if let Some(r) = &mut self.responder {
                        if r.on_command(&asdu, recv_ns) == CommandOutcome::Dropped {
                            self.violation(
                                "interrogation_flood",
                                format!(
                                    "GI/CI activation dropped: {RESPONSE_QUEUE_CAP} response frames already queued"
                                ),
                                false,
                            );
                        }
                    }
                }
                if self.unacked_rx >= self.params.w {
                    self.send_s()?;
                }
            }
            Apdu::S { nr } => {
                self.report.bytes_read += 6;
                if let Some(p) = &self.progress {
                    p.bytes_read.fetch_add(6, Ordering::Relaxed);
                }
                self.check_nr(nr, "S")?;
                self.retire(nr, recv_ns);
            }
            Apdu::U { code } => {
                self.report.bytes_read += 6;
                if let Some(p) = &self.progress {
                    p.bytes_read.fetch_add(6, Ordering::Relaxed);
                }
                self.handle_u(code)?;
            }
        }
        if self.stop_con_owed && self.pending.is_empty() {
            // Slave: every I-frame sent before STOPDT act is now
            // acknowledged, so the confirmation may go out.
            self.send_u(U_STOPDT_CON)?;
            self.stop_con_owed = false;
            self.transfer = Transfer::Stopped;
        }
        if let Some(p) = &self.progress {
            p.unacked
                .store(self.pending.len() as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    /// N(R) must lie in [V(A), V(S)] modulo 2^15, where V(A) is the
    /// oldest unacknowledged N(S) (or V(S) when nothing is in flight).
    fn check_nr(&mut self, nr: u16, frame: &str) -> Result<(), LinkEnd> {
        let va = self.pending.front().map_or(self.vs, |p| p.ns);
        let span = self.vs.wrapping_sub(va) & SEQ_MASK;
        let off = nr.wrapping_sub(va) & SEQ_MASK;
        if off > span {
            let msg = format!(
                "received {frame}-frame N(R)={nr} outside the unacknowledged window {va}..={} (acknowledges frames never sent, or goes backwards)",
                self.vs
            );
            self.violation("nr_out_of_window", msg.clone(), true);
            return Err(LinkEnd::Protocol(msg));
        }
        Ok(())
    }

    /// Retire every pending I-frame acknowledged by `nr` (already
    /// validated by [`Link::check_nr`]) and record its ack latency.
    fn retire(&mut self, nr: u16, recv_ns: u64) {
        while let Some(front) = self.pending.front().copied() {
            if front.ns == nr {
                break;
            }
            self.pending.pop_front();
            self.latency
                .push(recv_ns.saturating_sub(front.send_ns) / 1_000);
        }
    }

    fn handle_u(&mut self, code: u8) -> Result<(), LinkEnd> {
        match code {
            U_TESTFR_ACT => self.send_u(U_TESTFR_CON)?,
            U_TESTFR_CON => self.testfr_sent_ns = None,
            U_STARTDT_ACT => {
                if self.role == Role::Slave {
                    // Also covers a duplicate STARTDT act while started
                    // and a STARTDT that overtakes a pending STOPDT con.
                    self.send_u(U_STARTDT_CON)?;
                    self.transfer = Transfer::Started;
                    self.stop_con_owed = false;
                } else {
                    self.violation(
                        "unexpected_u_frame",
                        "STARTDT act from the controlled station".into(),
                        false,
                    );
                }
            }
            U_STOPDT_ACT => {
                if self.role == Role::Slave {
                    // Acknowledge what we received, stop sending, and
                    // confirm once our own I-frames are acknowledged.
                    if self.unacked_rx > 0 {
                        self.send_s()?;
                    }
                    self.transfer = Transfer::PendingStop;
                    self.stop_con_owed = true;
                } else {
                    self.violation(
                        "unexpected_u_frame",
                        "STOPDT act from the controlled station".into(),
                        false,
                    );
                }
            }
            U_STARTDT_CON | U_STOPDT_CON => {
                if self.u_act.is_some_and(|(c, _)| c == code) {
                    self.u_act = None;
                    self.transfer = if code == U_STARTDT_CON {
                        Transfer::Started
                    } else {
                        Transfer::Stopped
                    };
                } else {
                    self.violation(
                        "unexpected_u_frame",
                        format!("unsolicited {}", u_name(code)),
                        false,
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn violation(&mut self, kind: &str, detail: String, fatal: bool) {
        warn!(kind, %detail, fatal, "IEC 104 protocol violation");
        let stats = &mut self.report.protocol;
        stats.protocol_violations += 1;
        if stats.protocol_errors.len() < PROTOCOL_ERRORS_CAP {
            stats.protocol_errors.push(ProtocolError {
                at_ms: now_ns().saturating_sub(self.epoch_ns) / 1_000_000,
                kind: kind.into(),
                detail,
                fatal,
            });
        }
    }

    // ------------------------------------------------------------------
    // Send side
    // ------------------------------------------------------------------

    fn write(&mut self, apdu: &Apdu) -> Result<u64, LinkEnd> {
        let bytes = apdu.serialize();
        if let Err(e) = self.writer.write_all(&bytes) {
            return Err(if is_peer_close(e.kind()) {
                LinkEnd::PeerClosed
            } else {
                LinkEnd::Io(format!("send {}: {e}", apdu_name(apdu)))
            });
        }
        let len = bytes.len() as u64;
        self.report.bytes_written += len;
        if let Some(p) = &self.progress {
            p.bytes_written.fetch_add(len, Ordering::Relaxed);
        }
        Ok(len)
    }

    fn send_u(&mut self, code: u8) -> Result<(), LinkEnd> {
        self.write(&Apdu::U { code }).map(|_| ())
    }

    fn send_s(&mut self) -> Result<(), LinkEnd> {
        self.write(&Apdu::S { nr: self.vr })?;
        self.unacked_rx = 0;
        self.oldest_unacked_rx_ns = None;
        self.report.protocol.acks_sent += 1;
        Ok(())
    }

    /// Send an I-frame with live N(S)/N(R). Caller checked
    /// [`Link::can_send`].
    fn send_i(&mut self, mut asdu: Vec<u8>, synthesized: bool) -> Result<(), LinkEnd> {
        debug_assert!(self.can_send());
        if self.cp56.enabled {
            rewrite_cp56time2a_to_now_zoned(&mut asdu, wall_clock_unix_ns(), self.cp56.zone);
        }
        let apdu = Apdu::I {
            ns: self.vs,
            nr: self.vr,
            asdu,
        };
        let send_ns = now_ns();
        self.write(&apdu)?;
        self.pending.push_back(PendingIFrame {
            ns: self.vs,
            send_ns,
        });
        self.vs = (self.vs + 1) & SEQ_MASK;
        // The I-frame's N(R) acknowledges everything received so far.
        self.unacked_rx = 0;
        self.oldest_unacked_rx_ns = None;
        if synthesized {
            let stats = &mut self.report.protocol;
            stats.synthesized_frames += 1;
            if stats.synthesized_send_indices.len() < SYNTHESIZED_INDICES_CAP {
                stats
                    .synthesized_send_indices
                    .push(self.report.messages_sent);
            }
        }
        self.report.messages_sent += 1;
        if let Some(p) = &self.progress {
            p.sent.fetch_add(1, Ordering::Relaxed);
            p.unacked
                .store(self.pending.len() as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Send queued synthesized responses while the window allows.
    fn drain_responses(&mut self) -> Result<(), LinkEnd> {
        while self.can_send() {
            let Some(q) = self.responder.as_mut().and_then(Responder::pop) else {
                break;
            };
            if let Some(t) = q.cmd_recv_ns {
                let us = now_ns().saturating_sub(t) / 1_000;
                let v = &mut self.report.protocol.command_response_us;
                if v.len() < COMMAND_RESPONSE_SAMPLES_CAP {
                    v.push(us);
                }
            }
            self.send_i(q.asdu, true)?;
        }
        Ok(())
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        // shutdown() acts on the socket, not the fd, so the peer sees
        // FIN even though the reader thread holds a dup'd descriptor,
        // and the reader's blocked read returns EOF at once.
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.writer.shutdown(Shutdown::Both);
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

fn reader_loop(stream: TcpStream, tx: Sender<RxEvent>, stop: Arc<AtomicBool>) {
    let mut r = ApduReader::strict(stream);
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match r.next_apdu() {
            Ok(Some(apdu)) => {
                let recv_ns = now_ns();
                if tx.send(RxEvent::Frame { recv_ns, apdu }).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let _ = tx.send(RxEvent::Malformed(e.to_string()));
                break;
            }
            Err(e) => {
                if !stop.load(Ordering::Relaxed) {
                    debug!(error = %e, "iec104 reader exiting");
                    let _ = tx.send(RxEvent::Failed(e.kind(), e.to_string()));
                }
                break;
            }
        }
    }
}

fn is_peer_close(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn u_name(code: u8) -> &'static str {
    match code {
        U_STARTDT_ACT => "STARTDT act",
        U_STARTDT_CON => "STARTDT con",
        U_STOPDT_ACT => "STOPDT act",
        U_STOPDT_CON => "STOPDT con",
        U_TESTFR_ACT => "TESTFR act",
        U_TESTFR_CON => "TESTFR con",
        _ => "U-frame",
    }
}

fn apdu_name(apdu: &Apdu) -> &'static str {
    match apdu {
        Apdu::I { .. } => "I-frame",
        Apdu::S { .. } => "S-frame",
        Apdu::U { code } => u_name(*code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gi(ca: u16) -> Vec<u8> {
        vec![100, 1, 6, 0, ca as u8, (ca >> 8) as u8, 0, 0, 0, 20]
    }

    fn responder(cas: u16) -> Responder {
        let mut inv = Inventory::default();
        for ca in 1..=cas {
            inv.ingest_asdu(&[1, 1, 3, 0, ca as u8, (ca >> 8) as u8, 1, 0, 0, 1]);
        }
        Responder::new(inv)
    }

    fn drain(r: &mut Responder) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| r.pop().map(|q| q.asdu)).collect()
    }

    #[test]
    fn duplicate_interrogation_gets_negative_actcon() {
        let mut r = responder(1);
        assert_eq!(r.on_command(&gi(1), 1), CommandOutcome::Answered);
        assert_eq!(r.queue.len(), 3);
        assert_eq!(r.on_command(&gi(1), 2), CommandOutcome::Rejected);
        assert_eq!(r.on_command(&gi(1), 3), CommandOutcome::Rejected);
        let out = drain(&mut r);
        assert_eq!(out.len(), 5);
        // Positive ActCon, data, ActTerm, then two negative ActCons.
        assert_eq!(out[0][2], 7);
        assert_eq!(out[2][2], 10);
        assert_eq!(out[3][2], 0x40 | 7);
        assert_eq!(out[4][2], 0x40 | 7);
        assert!(r.outstanding.is_empty());
        // Once sent, the same interrogation is answered in full again.
        assert_eq!(r.on_command(&gi(1), 4), CommandOutcome::Answered);
        assert_eq!(r.queue.len(), 3);
    }

    #[test]
    fn outstanding_interrogations_are_capped() {
        let cas = MAX_OUTSTANDING_INTERROGATIONS as u16 + 1;
        let mut r = responder(cas);
        for ca in 1..cas {
            assert_eq!(r.on_command(&gi(ca), 0), CommandOutcome::Answered);
        }
        let full = r.queue.len();
        assert_eq!(r.on_command(&gi(cas), 0), CommandOutcome::Rejected);
        assert_eq!(r.queue.len(), full + 1);
        // A CI is a different interrogation, but the global cap applies.
        let ci = [101, 1, 6, 0, 1, 0, 0, 0, 0, 5];
        assert_eq!(r.on_command(&ci, 0), CommandOutcome::Rejected);
        // Non-commands are ignored.
        assert_eq!(
            r.on_command(&[1, 1, 3, 0, 1, 0, 1, 0, 0, 1], 0),
            CommandOutcome::NotACommand
        );
        assert_eq!(
            r.on_command(&[100, 1, 7, 0, 1, 0, 0, 0, 0, 20], 0),
            CommandOutcome::NotACommand
        );
    }

    #[test]
    fn response_queue_is_bounded() {
        let mut r = responder(1);
        let mut dropped = 0;
        for i in 0..RESPONSE_QUEUE_CAP + 50 {
            if r.on_command(&gi(1), i as u64) == CommandOutcome::Dropped {
                dropped += 1;
            }
        }
        assert_eq!(r.queue.len(), RESPONSE_QUEUE_CAP);
        assert!(dropped >= 50);
    }
}
