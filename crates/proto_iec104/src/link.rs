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
//!   - in slave mode, synthesized GI/CI and command responses are
//!     sent from the response queue as soon as the transfer state and
//!     the k-window allow;
//!   - the fault plan ([`crate::faults`]): faults fire from here, at a
//!     time or before the N-th I-frame, and act on the send, ack and
//!     keep-alive paths below.
//!
//! Command round trips are measured per command type in both roles
//! (slave: master command → our ActCon / ActTerm; master: replayed
//! command → the live slave's ActCon / ActTerm), see
//! [`protoplay::CommandTypeStats`].
//!
//! Received sequence numbers are validated (N(S) against V(R), N(R)
//! against the unacknowledged window up to V(S), modulo 2^15). A
//! violation is recorded in [`protoplay::ProtocolStats`] and closes the
//! connection, as the standard requires.
//!
//! Dropping a [`Link`] shuts the socket down in both directions (so the
//! peer sees FIN even though the reader thread holds a duplicate fd)
//! and joins the reader thread.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use protoplay::{
    progress_cancelled, CommandTypeStats, FaultReaction, LatencyReservoir, MessageProgress,
    NegativeConfirmation, ProtoReport, ProtocolError, Role, COMMAND_LATENCY_SAMPLES_CAP,
    COMMAND_RESPONSE_SAMPLES_CAP, LATENCY_RESERVOIR_CAP, NEGATIVE_CONFIRMATIONS_CAP,
    PROTOCOL_ERRORS_CAP, SYNTHESIZED_INDICES_CAP,
};
use tracing::{debug, warn};

use crate::apdu::{
    Apdu, ApduReader, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT,
    U_TESTFR_CON,
};
use crate::asdu::{
    common_address, cot_value, read_ioa, rewrite_cp56time2a_to_now_zoned, Cp56Zone, SessionConfig,
    DUI_LEN, IOA_LEN,
};
use crate::commands::{
    self, is_command_type, respond_command, CommandBook, CommandContext, CommandsConfig, Part,
};
use crate::faults::{Action, FaultInjector, FaultPlan, CORRUPT_NS_OFFSET};
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
    /// A configured fault ended the session on purpose (`rst`).
    Injected(String),
}

impl LinkEnd {
    pub fn describe(&self) -> String {
        match self {
            LinkEnd::Cancelled => "cancelled".into(),
            LinkEnd::PeerClosed => "peer closed the connection".into(),
            LinkEnd::Timeout(m) => m.clone(),
            LinkEnd::Protocol(m) => format!("protocol violation: {m}"),
            LinkEnd::Io(m) | LinkEnd::Injected(m) => m.clone(),
        }
    }
}

/// One in-flight I-frame awaiting acknowledgment.
#[derive(Debug, Clone, Copy)]
struct PendingIFrame {
    ns: u16,
    send_ns: u64,
    /// Dropped by fault injection: its N(S) was consumed but nothing
    /// went on the wire, so it yields no latency sample.
    dropped: bool,
}

/// At most this many interrogations (distinct (type, CA) requests) are
/// answered at once; further activations get a negative ActCon.
pub(crate) const MAX_OUTSTANDING_INTERROGATIONS: usize = 8;
/// Hard cap on queued synthesized ASDUs. An activation that arrives
/// with the queue this full is dropped (and recorded), so a peer that
/// floods GI/CI while never acknowledging cannot grow memory.
pub(crate) const RESPONSE_QUEUE_CAP: usize = 4096;

/// Cap on command exchanges (control-direction commands from the
/// master) whose response is still queued; further commands get a
/// negative confirmation.
pub(crate) const MAX_OUTSTANDING_COMMANDS: usize = 64;

/// Command-exchange metadata carried by every queued ASDU of a GI/CI
/// or command response, for the per-type round-trip metrics.
#[derive(Debug, Clone, Copy)]
struct CmdTag {
    type_id: u8,
    /// Receive time of the command.
    recv_ns: u64,
    /// First / last ASDU of the response.
    first: bool,
    last: bool,
}

/// One synthesized ASDU waiting to be sent.
struct Queued {
    asdu: Vec<u8>,
    tag: Option<CmdTag>,
    /// (type, request CA) of the interrogation this frame belongs to,
    /// for a full (positive) response; `None` for a rejection.
    key: Option<(u8, u16)>,
    /// Last frame of a command (not GI/CI) exchange.
    ends_command: bool,
    /// Send verbatim: a command mirror echoes the command's own time
    /// tag, so the CP56 rewrite does not apply.
    raw_time: bool,
    /// When it was queued (the `delay` fault holds it from here).
    queued_ns: u64,
}

/// What [`Responder::on_command`] did with an ASDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandOutcome {
    /// Not a GI/CI activation nor (with command echo on) a command.
    NotACommand,
    /// Full response queued (it may itself be a negative ActCon, e.g.
    /// for an unknown CA or an unsupported qualifier).
    Answered,
    /// The same interrogation is still being answered, or too many
    /// interrogations / commands are: a negative confirmation is queued
    /// instead of a response.
    Rejected,
    /// Response queue full: nothing queued.
    Dropped,
}

/// Command echo settings and the command addresses learned from the
/// capture.
pub(crate) struct CommandEcho {
    pub cfg: CommandsConfig,
    pub book: CommandBook,
    pub zone: Cp56Zone,
}

/// Slave-mode answering: the point inventory and the queue of
/// synthesized response ASDUs for GI/CI ([`crate::responder`]) and
/// control-direction commands ([`crate::commands`]).
pub(crate) struct Responder {
    inventory: Inventory,
    queue: VecDeque<Queued>,
    /// Queued-but-unsent frame count per outstanding interrogation.
    outstanding: HashMap<(u8, u16), usize>,
    /// Answer GI/CI.
    gi_ci: bool,
    commands: Option<CommandEcho>,
    /// Command exchanges with frames still queued.
    commands_outstanding: usize,
}

impl Responder {
    /// GI/CI answering only.
    pub fn new(inventory: Inventory) -> Self {
        Self {
            inventory,
            queue: VecDeque::new(),
            outstanding: HashMap::new(),
            gi_ci: true,
            commands: None,
            commands_outstanding: 0,
        }
    }

    /// Turn GI/CI answering on or off.
    pub fn gi_ci(mut self, on: bool) -> Self {
        self.gi_ci = on;
        self
    }

    /// Also answer control-direction commands.
    pub fn with_commands(mut self, echo: CommandEcho) -> Self {
        self.commands = Some(echo);
        self
    }

    fn push(&mut self, q: Queued) {
        self.queue.push_back(q);
    }

    /// Queue the answer to `asdu` if it is a GI (`C_IC_NA_1`, 100) or
    /// CI (`C_CI_NA_1`, 101) activation, or (with command echo on) a
    /// control-direction command.
    ///
    /// GI/CI: the spec-correct response (ActCon → data → ActTerm, built
    /// by [`crate::responder`]). A request for an interrogation that is
    /// still being answered, or one beyond
    /// [`MAX_OUTSTANDING_INTERROGATIONS`], gets a negative ActCon.
    ///
    /// Commands: the response built by [`crate::commands`]; beyond
    /// [`MAX_OUTSTANDING_COMMANDS`] a negative confirmation.
    ///
    /// With [`RESPONSE_QUEUE_CAP`] frames queued the request is dropped.
    fn on_command(&mut self, asdu: &[u8], recv_ns: u64) -> CommandOutcome {
        if asdu.len() < DUI_LEN {
            return CommandOutcome::NotACommand;
        }
        let type_id = asdu[0];
        if matches!(type_id, 100 | 101) {
            if self.gi_ci {
                return self.on_interrogation(asdu, recv_ns);
            }
            return CommandOutcome::NotACommand;
        }
        if self.commands.is_none() || !is_command_type(type_id) {
            return CommandOutcome::NotACommand;
        }
        if self.queue.len() >= RESPONSE_QUEUE_CAP {
            return CommandOutcome::Dropped;
        }
        let tag = |first: bool, last: bool| {
            Some(CmdTag {
                type_id,
                recv_ns,
                first,
                last,
            })
        };
        if self.commands_outstanding >= MAX_OUTSTANDING_COMMANDS {
            let cot = if cot_value(asdu) == commands::COT_DEACT {
                commands::COT_DEACT_CON
            } else {
                commands::COT_ACT_CON
            };
            let mut neg = asdu.to_vec();
            neg[2] = (asdu[2] & 0x80) | 0x40 | cot;
            self.push(Queued {
                asdu: neg,
                tag: tag(true, true),
                key: None,
                ends_command: true,
                raw_time: true,
                queued_ns: recv_ns,
            });
            self.commands_outstanding += 1;
            return CommandOutcome::Rejected;
        }
        let Some(echo) = &self.commands else {
            return CommandOutcome::NotACommand;
        };
        let ctx = CommandContext {
            cfg: &echo.cfg,
            book: &echo.book,
            now_unix_ns: wall_clock_unix_ns(),
            zone: echo.zone,
        };
        let Some(resp) = respond_command(&mut self.inventory, &ctx, asdu) else {
            return CommandOutcome::NotACommand;
        };
        if resp.negative() {
            debug!(type_id, cot = resp.frames[0].1[2], "command rejected");
        }
        let n = resp.frames.len();
        for (i, (part, a)) in resp.frames.into_iter().enumerate() {
            self.push(Queued {
                asdu: a,
                tag: tag(i == 0, i + 1 == n),
                key: None,
                ends_command: i + 1 == n,
                raw_time: part != Part::ReturnInfo && part != Part::ReadReply,
                queued_ns: recv_ns,
            });
        }
        self.commands_outstanding += 1;
        CommandOutcome::Answered
    }

    fn on_interrogation(&mut self, asdu: &[u8], recv_ns: u64) -> CommandOutcome {
        let type_id = asdu[0];
        if asdu.len() < DUI_LEN + IOA_LEN + 1 || asdu[2] & 0x3f != 6 {
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
        let tag = |first: bool, last: bool| {
            Some(CmdTag {
                type_id,
                recv_ns,
                first,
                last,
            })
        };
        if self.outstanding.contains_key(&key)
            || self.outstanding.len() >= MAX_OUTSTANDING_INTERROGATIONS
        {
            // Mirror of the request: COT 7 with P/N = 1, T echoed.
            let mut neg = asdu.to_vec();
            neg[2] = (asdu[2] & 0x80) | 0x40 | 7;
            self.push(Queued {
                asdu: neg,
                tag: tag(true, true),
                key: None,
                ends_command: false,
                raw_time: false,
                queued_ns: recv_ns,
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
        let n = asdus.len();
        for (i, asdu) in asdus.into_iter().enumerate() {
            self.push(Queued {
                asdu,
                tag: tag(i == 0, i + 1 == n),
                key: Some(key),
                ends_command: false,
                raw_time: false,
                queued_ns: recv_ns,
            });
        }
        CommandOutcome::Answered
    }

    fn front_queued_ns(&self) -> Option<u64> {
        self.queue.front().map(|q| q.queued_ns)
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
        if q.ends_command {
            self.commands_outstanding = self.commands_outstanding.saturating_sub(1);
        }
        Some(q)
    }
}

/// Master role: a replayed command awaiting the live slave's answer.
struct SentCommand {
    /// DUI + IOA (+ qualifier) of the command.
    head: Vec<u8>,
    send_ns: u64,
    confirmed: bool,
}

/// Most replayed commands tracked at once (master role); the oldest is
/// given up (and counted unanswered if it never got a confirmation).
const MAX_TRACKED_COMMANDS: usize = 1024;

/// Peer behaviour observed after the first injected fault.
#[derive(Debug, Default)]
struct Reaction {
    closed: bool,
    reset: bool,
    stopdt: bool,
    stopdt_con: bool,
    errors: Vec<String>,
    first_ns: Option<u64>,
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
    /// Faults to inject on this connection.
    pub faults: FaultPlan,
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
    /// N(R) last sent to the peer (S-frame or I-frame).
    last_sent_nr: u16,
    /// Per command type round-trip figures.
    cmd_stats: BTreeMap<u8, CommandTypeStats>,
    negative_confirmations: Vec<NegativeConfirmation>,
    /// Master: replayed commands awaiting the slave's answer.
    sent_commands: VecDeque<SentCommand>,
    // --- fault injection ---
    faults: Option<FaultInjector>,
    /// I-frames the link attempted to send (sent or dropped).
    frames_attempted: u64,
    /// `slow_ack`: deferred S-frame due at this time.
    ack_due_ns: Option<u64>,
    /// `rst`: close abortively (RST) when dropped.
    abort: bool,
    /// Master `stopdt` fault: send STARTDT act once STOPDT is confirmed.
    restart_after_stop: bool,
    /// Slave `stopdt` fault: our unsolicited STOPDT act is out.
    slave_stopdt_sent: bool,
    /// A `stopdt` fault that fired outside data transfer, carried out
    /// once the transfer is started (record index).
    deferred_stopdt: Option<usize>,
    /// The connection was reset by the peer (vs. closed).
    peer_reset_seen: bool,
    reaction: Reaction,
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
            last_sent_nr: 0,
            cmd_stats: BTreeMap::new(),
            negative_confirmations: Vec::new(),
            sent_commands: VecDeque::new(),
            faults: FaultInjector::new(&opts.faults, now),
            frames_attempted: 0,
            ack_due_ns: None,
            abort: false,
            restart_after_stop: false,
            slave_stopdt_sent: false,
            deferred_stopdt: None,
            peer_reset_seen: false,
            reaction: Reaction::default(),
        })
    }

    pub fn transfer(&self) -> Transfer {
        self.transfer
    }

    /// Can an I-frame go out right now?
    pub fn can_send(&self) -> bool {
        self.transfer == Transfer::Started && self.pending.len() < self.params.k as usize
    }

    /// Has any configured fault fired on this connection?
    pub fn faults_fired(&self) -> bool {
        self.faults.as_ref().is_some_and(|f| f.fired_count() > 0)
    }

    /// Is `e` the peer's (or our own deliberate) reaction to an
    /// injected fault rather than a replay failure? Such an end is
    /// recorded in the fault reaction, not as the session error.
    pub fn fault_excused(&self, e: &LinkEnd) -> bool {
        matches!(e, LinkEnd::Injected(_))
            || (self.faults_fired()
                && matches!(
                    e,
                    LinkEnd::PeerClosed | LinkEnd::Timeout(_) | LinkEnd::Protocol(_)
                ))
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
        let r = self.service_loop(deadline_ns, done);
        if let Err(e) = &r {
            self.note_end(e);
        }
        r
    }

    fn service_loop(
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
            self.poll_faults(now)?;
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
        // `delay` fault: hold the frame, servicing the link meanwhile.
        let now = now_ns();
        if let Some((d, rec)) = self.faults.as_ref().and_then(|f| f.delay(now)) {
            if let Some(f) = self.faults.as_mut() {
                f.note(rec, None);
            }
            self.wait_until(now + d)?;
        }
        self.service(None, |l| l.can_send())?;
        let r = self.send_i(asdu.to_vec(), false, false);
        if let Err(e) = &r {
            self.note_end(e);
        }
        r
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
        self.restart_after_stop = false;
        self.deferred_stopdt = None;
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
        // Master: replayed commands still waiting for any answer.
        for c in std::mem::take(&mut self.sent_commands) {
            if !c.confirmed {
                self.cmd_entry(c.head[0]).unanswered += 1;
            }
        }
        let stats = &mut self.report.protocol;
        stats.commands = std::mem::take(&mut self.cmd_stats).into_values().collect();
        stats.negative_confirmations = std::mem::take(&mut self.negative_confirmations);
        if let Some(f) = self.faults.take() {
            if f.fired_count() > 0 {
                let first = f.first_fire_ns().unwrap_or(0);
                let n = f.fired_count();
                let r = std::mem::take(&mut self.reaction);
                let mut reaction = FaultReaction {
                    peer_closed: r.closed && !r.reset,
                    peer_reset: r.reset,
                    peer_stopdt: r.stopdt,
                    protocol_errors: r.errors,
                    first_reaction_ms: r.first_ns.map(|t| t.saturating_sub(first) / 1_000_000),
                    summary: String::new(),
                };
                reaction.summary = reaction_summary(n, &reaction, r.stopdt_con);
                let stats = &mut self.report.protocol;
                stats.faults_injected = f.into_records();
                stats.fault_reaction = Some(reaction);
            }
        }
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

    /// Are acknowledgements held back right now (`withhold_acks`)?
    fn acks_withheld(&self, now: u64) -> bool {
        self.faults
            .as_ref()
            .is_some_and(|f| f.withholding(now).is_some())
    }

    /// N(R) to put in an outgoing I-frame: V(R), or the last N(R)
    /// already sent while a fault holds acknowledgements back.
    fn nr_to_send(&self, now: u64) -> u16 {
        match &self.faults {
            Some(f) if f.withholding(now).is_some() || f.slow_ack(now).is_some() => {
                self.last_sent_nr
            }
            _ => self.vr,
        }
    }

    fn next_timer_ns(&self) -> Option<u64> {
        let p = &self.params;
        let now = now_ns();
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
        let withheld = self.acks_withheld(now);
        if let Some(t) = self.oldest_unacked_rx_ns {
            if !withheld && self.ack_due_ns.is_none() {
                consider(t + p.t2_ns);
            }
        }
        if let Some(t) = self.ack_due_ns {
            consider(t);
        }
        let silenced = self
            .faults
            .as_ref()
            .is_some_and(|f| f.testfr_silenced(now).is_some());
        if self.testfr_sent_ns.is_none() && self.u_act.is_none() && !silenced {
            consider(self.last_rx_ns + p.t3_ns);
        }
        if let Some(f) = &self.faults {
            if let Some(t) = f.next_deadline_ns(now) {
                consider(t);
            }
            if let (Some((d, _)), Some(q)) = (
                f.delay(now),
                self.responder.as_ref().and_then(Responder::front_queued_ns),
            ) {
                // Only a future release time; a held frame that is
                // already due waits for the window, not a timer.
                if q + d > now {
                    consider(q + d);
                }
            }
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
        if let Some(t) = self.ack_due_ns {
            if now >= t {
                // Deferred (`slow_ack`) acknowledgement.
                self.ack_due_ns = None;
                if self.unacked_rx > 0 && !self.acks_withheld(now) {
                    self.send_s()?;
                }
            }
        }
        if let Some(t) = self.oldest_unacked_rx_ns {
            if now.saturating_sub(t) >= p.t2_ns {
                self.ack_due(now)?;
            }
        }
        let silenced = self
            .faults
            .as_ref()
            .is_some_and(|f| f.testfr_silenced(now).is_some());
        if self.testfr_sent_ns.is_none()
            && self.u_act.is_none()
            && !silenced
            && now.saturating_sub(self.last_rx_ns) >= p.t3_ns
        {
            self.send_u(U_TESTFR_ACT)?;
            self.testfr_sent_ns = Some(now);
            self.report.protocol.keepalives_sent += 1;
        }
        Ok(())
    }

    /// An acknowledgement is due (t2 or w): send the S-frame, unless a
    /// fault withholds it (`withhold_acks`) or defers it (`slow_ack`).
    fn ack_due(&mut self, now: u64) -> Result<(), LinkEnd> {
        if self.acks_withheld(now) || self.ack_due_ns.is_some() {
            return Ok(());
        }
        if let Some(f) = self.faults.as_mut() {
            if let Some((extra, rec)) = f.slow_ack(now) {
                f.note(rec, None);
                self.ack_due_ns = Some(now + extra);
                return Ok(());
            }
        }
        self.send_s()
    }

    // ------------------------------------------------------------------
    // Fault injection
    // ------------------------------------------------------------------

    /// Fire due faults and carry out the one-shot ones.
    fn poll_faults(&mut self, now: u64) -> Result<(), LinkEnd> {
        let master = self.role == Role::Master;
        let Some(f) = self.faults.as_mut() else {
            return Ok(());
        };
        let mut actions = f.poll(now, self.frames_attempted, master);
        if let Some(rec) = self.deferred_stopdt.take() {
            actions.push((Action::Stopdt, rec));
        }
        for (action, rec) in actions {
            match action {
                Action::Rst => {
                    self.abort = true;
                    return Err(LinkEnd::Injected(
                        "fault injection: connection aborted with RST".into(),
                    ));
                }
                Action::Stopdt => {
                    if self.transfer != Transfer::Started {
                        // Not in data transfer yet (or already
                        // stopping): carry it out once started.
                        self.deferred_stopdt = Some(rec);
                    } else if master {
                        if self.unacked_rx > 0 {
                            self.send_s()?;
                        }
                        self.send_u(U_STOPDT_ACT)?;
                        self.u_act = Some((U_STOPDT_CON, now));
                        self.transfer = Transfer::PendingStop;
                        self.restart_after_stop = true;
                        self.fault_note(rec);
                    } else {
                        self.send_u(U_STOPDT_ACT)?;
                        self.slave_stopdt_sent = true;
                        self.fault_note(rec);
                    }
                }
                Action::Malformed(count) => {
                    for _ in 0..count {
                        // Start octet, then a length octet below the
                        // minimum of 4: no receiver can frame it.
                        self.write_raw(&[0x68, 0x02, 0x00, 0x00], "malformed APDU")?;
                        self.fault_note(rec);
                    }
                }
            }
        }
        Ok(())
    }

    fn fault_note(&mut self, rec: usize) {
        if let Some(f) = self.faults.as_mut() {
            f.note(rec, None);
        }
    }

    /// Record how the session ended, for the fault reaction.
    fn note_end(&mut self, e: &LinkEnd) {
        if e == &LinkEnd::PeerClosed {
            if self.peer_reset_seen {
                self.reaction.reset = true;
            } else {
                self.reaction.closed = true;
            }
            self.mark_reaction();
        }
    }

    /// Timestamp the first reaction after the first fault.
    fn mark_reaction(&mut self) {
        if self.faults_fired() && self.reaction.first_ns.is_none() {
            self.reaction.first_ns = Some(now_ns());
        }
    }

    // ------------------------------------------------------------------
    // Command round trips
    // ------------------------------------------------------------------

    fn cmd_entry(&mut self, type_id: u8) -> &mut CommandTypeStats {
        self.cmd_stats
            .entry(type_id)
            .or_insert_with(|| CommandTypeStats {
                type_id,
                ..Default::default()
            })
    }

    /// Count the first answer to a command of `type_id` (`latency_us`
    /// after it), and the negative ones in detail.
    fn record_confirmation(&mut self, type_id: u8, part: Part, latency_us: u64, reply: &[u8]) {
        let st = self.cmd_entry(type_id);
        match part {
            Part::Negative => st.negative += 1,
            Part::DeactCon => st.deact_con += 1,
            _ => st.act_con += 1,
        }
        if st.actcon_us.len() < COMMAND_LATENCY_SAMPLES_CAP {
            st.actcon_us.push(latency_us);
        }
        if part == Part::Negative
            && self.negative_confirmations.len() < NEGATIVE_CONFIRMATIONS_CAP
            && reply.len() >= DUI_LEN + IOA_LEN
        {
            self.negative_confirmations.push(NegativeConfirmation {
                at_ms: now_ns().saturating_sub(self.epoch_ns) / 1_000_000,
                type_id,
                ca: common_address(reply),
                ioa: read_ioa(reply, DUI_LEN),
                cot: cot_value(reply),
            });
        }
    }

    fn record_termination(&mut self, type_id: u8, latency_us: u64) {
        let st = self.cmd_entry(type_id);
        st.act_term += 1;
        if st.actterm_us.len() < COMMAND_LATENCY_SAMPLES_CAP {
            st.actterm_us.push(latency_us);
        }
    }

    /// Master: a replayed command went out.
    fn track_sent_command(&mut self, asdu: &[u8], send_ns: u64) {
        if !commands::is_command_request(asdu) || asdu.len() < DUI_LEN + IOA_LEN {
            return;
        }
        self.cmd_entry(asdu[0]).commands += 1;
        if self.sent_commands.len() >= MAX_TRACKED_COMMANDS {
            if let Some(old) = self.sent_commands.pop_front() {
                if !old.confirmed {
                    self.cmd_entry(old.head[0]).unanswered += 1;
                }
            }
        }
        let head_len = asdu.len().min(DUI_LEN + IOA_LEN + 5);
        self.sent_commands.push_back(SentCommand {
            head: asdu[..head_len].to_vec(),
            send_ns,
            confirmed: false,
        });
    }

    /// Master: match an I-frame from the slave to a replayed command.
    fn match_command_reply(&mut self, asdu: &[u8], recv_ns: u64) {
        let Some(i) = self
            .sent_commands
            .iter()
            .position(|c| commands::answers(&c.head, asdu))
        else {
            return;
        };
        let part = commands::reply_part(asdu);
        let (type_id, latency_us, confirmed) = {
            let c = &self.sent_commands[i];
            (
                c.head[0],
                recv_ns.saturating_sub(c.send_ns) / 1_000,
                c.confirmed,
            )
        };
        let done = match part {
            Part::ActTerm => {
                self.record_termination(type_id, latency_us);
                true
            }
            Part::ActCon => {
                if !confirmed {
                    self.record_confirmation(type_id, part, latency_us, asdu);
                }
                // Select, system commands and broadcasts get no
                // ActTerm worth waiting for... except GI/CI.
                let c = &self.sent_commands[i];
                commands::is_select(&c.head) || matches!(type_id, 102..=107)
            }
            _ => {
                if !confirmed {
                    self.record_confirmation(type_id, part, latency_us, asdu);
                }
                true
            }
        };
        if done {
            self.sent_commands.remove(i);
        } else {
            self.sent_commands[i].confirmed = true;
        }
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
                if kind == io::ErrorKind::ConnectionReset {
                    self.peer_reset_seen = true;
                }
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
                if let Some(f) = self.faults.as_mut() {
                    if let Some(rec) = f.withholding(recv_ns) {
                        f.note(rec, None);
                    }
                }
                // GI/CI and commands are only answered in the started
                // state: a master may not send them otherwise, and
                // queueing them would let it build an unbounded backlog
                // while we cannot send.
                if self.role == Role::Slave && self.transfer == Transfer::Started {
                    if let Some(r) = &mut self.responder {
                        let outcome = r.on_command(&asdu, recv_ns);
                        if outcome != CommandOutcome::NotACommand {
                            self.cmd_entry(asdu[0]).commands += 1;
                        }
                        if outcome == CommandOutcome::Dropped {
                            let what = if matches!(asdu[0], 100 | 101) {
                                ("interrogation_flood", "GI/CI activation")
                            } else {
                                ("command_flood", "command")
                            };
                            self.violation(
                                what.0,
                                format!(
                                    "{} dropped: {RESPONSE_QUEUE_CAP} response frames already queued",
                                    what.1
                                ),
                                false,
                            );
                        }
                    }
                }
                if self.role == Role::Master && !self.sent_commands.is_empty() {
                    self.match_command_reply(&asdu, recv_ns);
                }
                if self.unacked_rx >= self.params.w {
                    self.ack_due(recv_ns.max(now_ns()))?;
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
            if !front.dropped {
                self.latency
                    .push(recv_ns.saturating_sub(front.send_ns) / 1_000);
            }
        }
    }

    fn handle_u(&mut self, code: u8) -> Result<(), LinkEnd> {
        match code {
            U_TESTFR_ACT => {
                let silenced = self
                    .faults
                    .as_ref()
                    .and_then(|f| f.testfr_silenced(now_ns()));
                match silenced {
                    Some(rec) => self.fault_note(rec),
                    None => self.send_u(U_TESTFR_CON)?,
                }
            }
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
                if self.faults_fired() {
                    self.reaction.stopdt = true;
                    self.mark_reaction();
                }
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
                    if code == U_STOPDT_CON && self.restart_after_stop {
                        // `stopdt` fault (master): resume the transfer.
                        self.restart_after_stop = false;
                        self.send_u(U_STARTDT_ACT)?;
                        self.u_act = Some((U_STARTDT_CON, now_ns()));
                        self.transfer = Transfer::PendingStart;
                    }
                } else if code == U_STOPDT_CON && self.slave_stopdt_sent {
                    // The master confirmed our deliberate STOPDT act.
                    self.slave_stopdt_sent = false;
                    self.reaction.stopdt_con = true;
                    self.mark_reaction();
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
        if self.faults_fired() {
            if !self.reaction.errors.iter().any(|k| k == kind) {
                self.reaction.errors.push(kind.into());
            }
            self.mark_reaction();
        }
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
        self.write_raw(&apdu.serialize(), apdu_name(apdu))
    }

    fn write_raw(&mut self, bytes: &[u8], what: &str) -> Result<u64, LinkEnd> {
        if let Err(e) = self.writer.write_all(bytes) {
            if e.kind() == io::ErrorKind::ConnectionReset {
                self.peer_reset_seen = true;
            }
            return Err(if is_peer_close(e.kind()) {
                LinkEnd::PeerClosed
            } else {
                LinkEnd::Io(format!("send {what}: {e}"))
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
        self.last_sent_nr = self.vr;
        self.ack_due_ns = None;
        self.unacked_rx = 0;
        self.oldest_unacked_rx_ns = None;
        self.report.protocol.acks_sent += 1;
        Ok(())
    }

    /// Send an I-frame with live N(S)/N(R). Caller checked
    /// [`Link::can_send`]. `raw_time` skips the CP56 rewrite (command
    /// mirrors echo the command's own time tag).
    ///
    /// Fault injection acts here: `drop_iframes` consumes the N(S)
    /// without sending, `corrupt_ns` puts a wrong N(S) on the wire,
    /// `duplicate_iframes` writes the frame twice, and while
    /// `withhold_acks` / `slow_ack` is active the frame repeats the
    /// last N(R) already sent.
    fn send_i(
        &mut self,
        mut asdu: Vec<u8>,
        synthesized: bool,
        raw_time: bool,
    ) -> Result<(), LinkEnd> {
        debug_assert!(self.can_send());
        let now = now_ns();
        self.frames_attempted += 1;
        let ns = self.vs;
        if self.faults.as_mut().is_some_and(|f| f.roll_drop(now, ns)) {
            self.pending.push_back(PendingIFrame {
                ns,
                send_ns: now,
                dropped: true,
            });
            self.vs = (self.vs + 1) & SEQ_MASK;
            return Ok(());
        }
        if self.cp56.enabled && !raw_time {
            rewrite_cp56time2a_to_now_zoned(&mut asdu, wall_clock_unix_ns(), self.cp56.zone);
        }
        let wire_ns = if self.faults.as_mut().is_some_and(|f| f.take_corrupt(ns)) {
            ns.wrapping_add(CORRUPT_NS_OFFSET) & SEQ_MASK
        } else {
            ns
        };
        let nr = self.nr_to_send(now);
        let track = self.role == Role::Master && !synthesized;
        if track {
            self.track_sent_command(&asdu, now);
        }
        let apdu = Apdu::I {
            ns: wire_ns,
            nr,
            asdu,
        };
        let send_ns = now_ns();
        let bytes = apdu.serialize();
        self.write_raw(&bytes, "I-frame")?;
        if self
            .faults
            .as_mut()
            .is_some_and(|f| f.roll_duplicate(now, ns))
        {
            self.write_raw(&bytes, "duplicate I-frame")?;
        }
        self.pending.push_back(PendingIFrame {
            ns,
            send_ns,
            dropped: false,
        });
        self.vs = (self.vs + 1) & SEQ_MASK;
        self.last_sent_nr = nr;
        if nr == self.vr {
            // The I-frame's N(R) acknowledges everything received so far.
            self.unacked_rx = 0;
            self.oldest_unacked_rx_ns = None;
            self.ack_due_ns = None;
        }
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
            let Some(front) = self.responder.as_ref().and_then(Responder::front_queued_ns) else {
                break;
            };
            let now = now_ns();
            // Frame triggers may fire between two frames of a burst.
            self.poll_faults(now)?;
            if !self.can_send() {
                break;
            }
            let delay = self.faults.as_ref().and_then(|f| f.delay(now));
            if let Some((d, _)) = delay {
                if now < front + d {
                    break;
                }
            }
            let Some(q) = self.responder.as_mut().and_then(Responder::pop) else {
                break;
            };
            if let Some((_, rec)) = delay {
                self.fault_note(rec);
            }
            if let Some(tag) = q.tag {
                let us = now.saturating_sub(tag.recv_ns) / 1_000;
                if tag.first {
                    let v = &mut self.report.protocol.command_response_us;
                    if v.len() < COMMAND_RESPONSE_SAMPLES_CAP {
                        v.push(us);
                    }
                    let part = commands::reply_part(&q.asdu);
                    self.record_confirmation(tag.type_id, part, us, &q.asdu);
                }
                if tag.last
                    && q.asdu.len() >= DUI_LEN
                    && q.asdu[0] == tag.type_id
                    && commands::reply_part(&q.asdu) == Part::ActTerm
                {
                    self.record_termination(tag.type_id, us);
                }
            }
            self.send_i(q.asdu, true, q.raw_time)?;
        }
        Ok(())
    }
}

/// One-line description of the peer's reaction to `n` faults.
fn reaction_summary(n: usize, r: &FaultReaction, stopdt_con: bool) -> String {
    let mut parts = Vec::new();
    if r.peer_reset {
        parts.push("reset the connection".to_string());
    } else if r.peer_closed {
        parts.push("closed the connection".to_string());
    }
    if r.peer_stopdt {
        parts.push("sent STOPDT act".to_string());
    }
    if stopdt_con {
        parts.push("confirmed our STOPDT act".to_string());
    }
    if !r.protocol_errors.is_empty() {
        parts.push(format!("protocol errors: {}", r.protocol_errors.join(", ")));
    }
    let what = if parts.is_empty() {
        "none observed (the session carried on)".to_string()
    } else {
        parts.join("; ")
    };
    let when = r
        .first_reaction_ms
        .map(|ms| format!(", {ms} ms after the first fault"))
        .unwrap_or_default();
    format!("{n} fault(s) injected; peer reaction: {what}{when}")
}

impl Drop for Link {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if self.abort {
            // `rst` fault: SO_LINGER 0 makes the last close send RST.
            // Shutting down only the read side wakes the reader without
            // sending anything; once it has dropped its duplicate fd,
            // the writer (dropped right after this) is the last one.
            let _ = socket2::SockRef::from(&self.writer).set_linger(Some(Duration::ZERO));
            let _ = self.writer.shutdown(Shutdown::Read);
            if let Some(h) = self.reader.take() {
                let _ = h.join();
            }
            return;
        }
        // shutdown() acts on the socket, not the fd, so the peer sees
        // FIN even though the reader thread holds a dup'd descriptor,
        // and the reader's blocked read returns EOF at once.
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

    fn command_responder() -> Responder {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&[1, 1, 3, 0, 1, 0, 1, 0, 0, 0]);
        Responder::new(inv).with_commands(CommandEcho {
            cfg: CommandsConfig::default(),
            book: CommandBook::default(),
            zone: Cp56Zone::Utc,
        })
    }

    #[test]
    fn outstanding_commands_are_capped_and_flood_is_dropped() {
        let sc = [45, 1, 6, 0, 1, 0, 1, 0, 0, 1];
        let mut r = command_responder();
        for _ in 0..MAX_OUTSTANDING_COMMANDS {
            assert_eq!(r.on_command(&sc, 0), CommandOutcome::Answered);
        }
        assert_eq!(r.on_command(&sc, 0), CommandOutcome::Rejected);
        let out = drain(&mut r);
        assert_eq!(out.len(), 2 * MAX_OUTSTANDING_COMMANDS + 1);
        assert_eq!(out.last().unwrap()[2], 0x40 | 7);
        assert_eq!(r.commands_outstanding, 0);
        assert_eq!(r.on_command(&sc, 0), CommandOutcome::Answered);
        // A master that never acknowledges cannot grow the queue.
        let mut dropped = 0;
        for _ in 0..RESPONSE_QUEUE_CAP + 10 {
            if r.on_command(&sc, 0) == CommandOutcome::Dropped {
                dropped += 1;
            }
        }
        assert_eq!(r.queue.len(), RESPONSE_QUEUE_CAP);
        assert!(dropped >= 10);
        // GI/CI off, commands on: a GI is not answered.
        let mut r = command_responder().gi_ci(false);
        assert_eq!(r.on_command(&gi(1), 0), CommandOutcome::NotACommand);
        // Monitor-direction frames are never commands.
        assert_eq!(
            r.on_command(&[1, 1, 3, 0, 1, 0, 1, 0, 0, 1], 0),
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
