//! Plugin interface for protocol-aware client-session replayers.
//!
//! Each protocol implementation lives in its own `proto_*` crate and
//! exposes a type implementing [`ProtoReplayer`]. The main `outstation`
//! binary builds a registry of available modules at startup and routes
//! TCP flows to the right module based on user configuration.
//!
//! ## Contract
//!
//! A protocol replayer receives the full set of **client** TCP payload
//! segments from the pcap (in capture order, each with its relative
//! timestamp) and drives a live session against the user-specified
//! target. It is expected to:
//!
//! * handle its own handshake/teardown sequence,
//! * respond to whatever the live server sends,
//! * re-number any stateful sequence counters to match live state,
//! * apply any configured rewrite maps (e.g., IEC 104 COT/IOA rewrites).
//!
//! The replayer owns socket creation — it gets connection parameters
//! from [`ProtoRunCfg`] and opens its own [`socket2::Socket`], bound to
//! the source IP and SO_BINDTODEVICE-pinned to the source veth. This
//! gives each module freedom to customize socket options (keepalives,
//! buffer sizes, etc.) without bloating the trait.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;

/// Protocol-agnostic session lifecycle states. Live in a shared
/// `AtomicU8` so the caller can observe transitions without locks.
pub mod session_state {
    pub const PENDING: u8 = 0;
    pub const LISTENING: u8 = 1;
    pub const CONNECTED: u8 = 2;
    pub const ACTIVE: u8 = 3;
    pub const COMPLETED: u8 = 4;
    pub const FAILED: u8 = 5;
    /// Session exited because the user stopped the run or aborted this
    /// specific slot. Distinct from FAILED so the UI can show a neutral
    /// "cancelled" badge instead of a red error.
    pub const CANCELLED: u8 = 6;
}

/// A single client-side TCP payload segment.
#[derive(Debug, Clone)]
pub struct ClientSegment {
    /// Timestamp relative to the flow's first packet, in nanoseconds.
    pub rel_ts_ns: u64,
    /// Raw TCP payload bytes from this segment.
    pub bytes: Vec<u8>,
}

/// Live counters a protocol replayer updates as it runs, so a UI can
/// show in-flight progress without waiting for the session to finish.
/// All fields are [`Arc<AtomicU64>`] so the scheduler can share them
/// with the replayer thread and snapshot them concurrently from the
/// HTTP handler. Counters are relaxed — sub-millisecond drift across
/// fields is acceptable for UI display.
#[derive(Debug, Clone, Default)]
pub struct MessageProgress {
    /// Total messages the replayer plans to send for this session.
    /// Filled in by the replayer once it has parsed the pcap payload.
    pub planned: Arc<AtomicU64>,
    /// Client messages sent on the wire in the current iteration.
    pub sent: Arc<AtomicU64>,
    /// Sum of `sent` over finished iterations; see
    /// [`MessageProgress::fold_iteration`].
    pub sent_done_iters: Arc<AtomicU64>,
    /// Sum of `bytes_written` over finished iterations.
    pub bytes_done_iters: Arc<AtomicU64>,
    /// Sequence counter guarding the fold of the per-iteration counters
    /// into the `*_done_iters` totals (odd while a fold is under way),
    /// so readers of a total never see it dip. See [`fold_counters`].
    pub fold_seq: Arc<AtomicU64>,
    /// Server messages received so far.
    pub received: Arc<AtomicU64>,
    pub bytes_written: Arc<AtomicU64>,
    pub bytes_read: Arc<AtomicU64>,
    /// Client messages that have been sent but are still awaiting the
    /// server's acknowledgement. Ping-pongs as ACKs come in.
    pub unacked: Arc<AtomicU64>,
    /// Gate the replayer waits on before proceeding with its
    /// connect/bind/listen step. In slave-mode benchmark runs the
    /// caller keeps this `false` until the user explicitly starts
    /// each RTU listener; `run_slave_session` spins on this flag
    /// (checking `cancel` too) before opening its `TcpListener`.
    ///
    /// Master-mode callers set it to `true` before invoking `run()`.
    pub ready: Arc<AtomicBool>,
    /// Current session state, one of [`session_state`] constants.
    /// Set by the replayer as it transitions through its lifecycle
    /// (listening → connected → active → completed/failed).
    pub state: Arc<AtomicU8>,
    /// Per-session cancel flag. The replayer should check this flag
    /// at every natural yielding point (ready-wait loop, accept loop,
    /// between I-frame sends, inside drain loops) and unwind cleanly
    /// when flipped. Independent from run-level `ctx.cancel` so the
    /// webui can stop one RTU without killing the whole run.
    pub cancel: Arc<AtomicBool>,
    /// Current iteration the protocol is on (1-based, 0 before start).
    /// Updated by replayers that loop the script within one session
    /// (see `ProtoRunCfg::loop_iterations`); shared with the per-source
    /// progress so the live UI shows "iter X / Y" without polling
    /// outside the protocol layer.
    pub iter_current: Arc<AtomicU64>,
    /// Total iterations planned for this session (0 = unlimited).
    pub iter_total: Arc<AtomicU64>,
    /// Run-level cancel flag shared by every session of the run (the
    /// scheduler passes `RunContext::cancel` here). Replayers should
    /// treat it exactly like [`MessageProgress::cancel`]; use
    /// [`MessageProgress::is_cancelled`], which checks both.
    pub run_cancel: Arc<AtomicBool>,
}

impl MessageProgress {
    /// True if either this session or the whole run was cancelled.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || self.run_cancel.load(Ordering::Relaxed)
    }

    /// Start a new iteration: move `sent` and `bytes_written` into the
    /// `*_done_iters` totals and restart them at zero. The totals
    /// ([`MessageProgress::sent_total`]) never dip while this runs.
    /// Call it only from the thread that sends.
    pub fn fold_iteration(&self) {
        fold_counters(
            &self.fold_seq,
            &[
                (&self.sent, &self.sent_done_iters),
                (&self.bytes_written, &self.bytes_done_iters),
            ],
        );
    }

    /// Messages sent over all iterations, monotonic.
    pub fn sent_total(&self) -> u64 {
        read_folded(&self.fold_seq, &self.sent, &self.sent_done_iters)
    }
}

/// Move every `current` counter into its `done` total and zero it, as
/// one step for readers using [`read_folded`] with the same `seq` (a
/// seqlock: `seq` is odd while the fold runs). A reader of
/// `done + current` therefore never sees the amount in neither (a dip)
/// nor in both (a spike). Only one thread may fold a given `seq`, and
/// nobody else may write the `current` counters during the fold (both
/// hold when the sending thread folds its own counters).
pub fn fold_counters(seq: &AtomicU64, pairs: &[(&AtomicU64, &AtomicU64)]) {
    let s = seq.load(Ordering::Relaxed);
    seq.store(s.wrapping_add(1), Ordering::Relaxed);
    std::sync::atomic::fence(Ordering::Release);
    for (current, done) in pairs {
        let v = current.swap(0, Ordering::Relaxed);
        done.fetch_add(v, Ordering::Relaxed);
    }
    seq.store(s.wrapping_add(2), Ordering::Release);
}

/// `done + current`, consistent with respect to [`fold_counters`] on
/// the same `seq`: monotonic as long as the counters only grow between
/// folds.
pub fn read_folded(seq: &AtomicU64, current: &AtomicU64, done: &AtomicU64) -> u64 {
    let mut spins = 0u32;
    loop {
        let s1 = seq.load(Ordering::Acquire);
        if s1 & 1 == 0 {
            let v = done
                .load(Ordering::Relaxed)
                .saturating_add(current.load(Ordering::Relaxed));
            std::sync::atomic::fence(Ordering::Acquire);
            if seq.load(Ordering::Relaxed) == s1 {
                return v;
            }
        }
        spins += 1;
        if spins % 64 == 0 {
            std::thread::yield_now();
        } else {
            std::hint::spin_loop();
        }
    }
}

/// Cancellation check for the common `Option<MessageProgress>` shape.
/// `None` (no progress sink) is never cancelled.
#[inline]
pub fn progress_cancelled(progress: &Option<MessageProgress>) -> bool {
    progress.as_ref().is_some_and(MessageProgress::is_cancelled)
}

/// Longest time any cancellable wait sleeps before re-checking its
/// cancel condition. Bounds STOP latency for every helper below.
pub const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Sleep until `deadline`, waking at least every
/// [`CANCEL_POLL_INTERVAL`] to evaluate `cancelled`. Returns `true` if
/// the deadline was reached and `false` if the wait was cancelled.
pub fn sleep_until_cancellable(deadline: Instant, cancelled: impl Fn() -> bool) -> bool {
    loop {
        if cancelled() {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::sleep((deadline - now).min(CANCEL_POLL_INTERVAL));
    }
}

/// Sleep for `dur` in [`CANCEL_POLL_INTERVAL`] slices. Same return
/// convention as [`sleep_until_cancellable`].
pub fn sleep_cancellable(dur: Duration, cancelled: impl Fn() -> bool) -> bool {
    match Instant::now().checked_add(dur) {
        Some(deadline) => sleep_until_cancellable(deadline, cancelled),
        // Absurd duration: sleep "forever", i.e. until cancelled.
        None => loop {
            if cancelled() {
                return false;
            }
            std::thread::sleep(CANCEL_POLL_INTERVAL);
        },
    }
}

/// Run `poll(slice)` repeatedly until it returns `Some`, `deadline`
/// passes, or `cancelled()` is true. `slice` is the remaining time
/// capped at [`CANCEL_POLL_INTERVAL`], so a blocking receive inside
/// `poll` (e.g. `Receiver::recv_timeout(slice)`) never holds off a
/// cancel for more than 100 ms. Returns [`Wait::Done`] with the value,
/// [`Wait::TimedOut`] or [`Wait::Cancelled`].
pub fn poll_until_cancellable<T>(
    deadline: Instant,
    cancelled: impl Fn() -> bool,
    mut poll: impl FnMut(Duration) -> Option<T>,
) -> Wait<T> {
    loop {
        if cancelled() {
            return Wait::Cancelled;
        }
        let now = Instant::now();
        if now >= deadline {
            return Wait::TimedOut;
        }
        if let Some(v) = poll((deadline - now).min(CANCEL_POLL_INTERVAL)) {
            return Wait::Done(v);
        }
    }
}

/// Outcome of [`poll_until_cancellable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wait<T> {
    Done(T),
    TimedOut,
    Cancelled,
}

/// Default number of latency samples kept per session.
pub const LATENCY_RESERVOIR_CAP: usize = 10_000;

/// Bounded uniform sample of a latency stream (Vitter's Algorithm R).
/// Keeps at most `capacity` values no matter how many are pushed, so
/// per-session memory stays bounded across any number of iterations.
/// Uses a tiny inline LCG so the crate needs no `rand` dependency.
#[derive(Debug, Clone)]
pub struct LatencyReservoir {
    capacity: usize,
    samples: Vec<u64>,
    seen: u64,
    rng_state: u64,
}

impl LatencyReservoir {
    /// New reservoir, seeded from the clock plus a per-process counter
    /// so concurrent sessions draw different sequences.
    pub fn new(capacity: usize) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let salt = NEXT
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0xD1B5_4A32_D192_ED03);
        Self::with_seed(capacity, clock ^ salt)
    }

    /// Deterministic variant for tests.
    pub fn with_seed(capacity: usize, seed: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            samples: Vec::with_capacity(capacity.clamp(1, 1024)),
            seen: 0,
            rng_state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15) | 1,
        }
    }

    #[inline]
    fn next_rand(&mut self) -> u64 {
        self.rng_state = self
            .rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // Use the high bits; the low bits of an LCG are weak.
        self.rng_state >> 16
    }

    pub fn push(&mut self, sample: u64) {
        self.seen = self.seen.saturating_add(1);
        if self.samples.len() < self.capacity {
            self.samples.push(sample);
            return;
        }
        let i = (self.next_rand() % self.seen) as usize;
        if i < self.capacity {
            self.samples[i] = sample;
        }
    }

    pub fn extend(&mut self, samples: impl IntoIterator<Item = u64>) {
        for s in samples {
            self.push(s);
        }
    }

    /// Number of values pushed so far (kept or not).
    pub fn seen(&self) -> u64 {
        self.seen
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.samples
    }

    pub fn into_vec(self) -> Vec<u64> {
        self.samples
    }
}

/// Controls how the replayer paces its own sends. Benchmark mode
/// defaults to firing as fast as the protocol's flow control allows
/// (`AsFastAsPossible`); the other variant waits between sends to
/// match the original pcap's inter-frame cadence.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Pacing {
    /// Pipelined as fast as possible, limited only by the protocol's
    /// own window (e.g., IEC 104 k=12).
    #[default]
    AsFastAsPossible,
    /// Sleep before each send so frame `i` is emitted at
    /// `session_epoch + frame_times_ns[i] / speed`. Requires the
    /// caller to populate `ProtoRunCfg::frame_times_ns`.
    OriginalTiming { speed: f64 },
}

/// Which side of the captured conversation the replayer will act as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    /// Tool impersonates the captured client (e.g. SCADA master). It
    /// opens TCP connections outward to `target_ip:target_port` and
    /// drives the captured client-side payload against a live server.
    #[default]
    Master,
    /// Tool impersonates the captured server (e.g. RTU / IED). It
    /// opens a `TcpListener` on [`ProtoRunCfg::listen_port`], accepts
    /// an inbound connection from the target master, and replays the
    /// captured server-originated payload as responses.
    Slave,
}

/// Configuration for running one flow through a protocol replayer.
#[derive(Debug, Clone)]
pub struct ProtoRunCfg {
    /// In [`Role::Master`] this is the source IP the client socket will
    /// `bind()` to (matches the captured RTU IP in benchmark mode).
    /// In [`Role::Slave`] it is ignored — listen sockets always bind on
    /// `0.0.0.0` so the target can reach them however its routing
    /// table sends it.
    pub bind_ip: Ipv4Addr,
    pub bind_iface: Option<String>,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    /// Whether to set `TCP_NODELAY` on the session's TCP socket.
    /// Disables Nagle's coalescing so each application write hits
    /// the wire as its own segment. Real production IEC 104 RTUs
    /// almost universally run with NODELAY because the protocol is
    /// event-driven and the 40 ms Nagle ceiling fights low-latency
    /// event delivery. Resolved from `BenchmarkConfig::tcp_nodelay`
    /// (None = role-default: slave true, master false; Some(b) =
    /// explicit override).
    pub tcp_nodelay: bool,
    pub client_segments: Vec<ClientSegment>,
    pub connect_timeout: Duration,
    /// Original flow timing: start-of-flow timestamp in seconds, used
    /// by modules that pace writes to match pcap timing.
    pub speed: f64,
    /// Free-form per-module config as JSON or YAML string. Modules that
    /// need structured config (e.g., IEC 104 COT/IOA rewrite maps) parse
    /// this field themselves.
    pub proto_config: Option<String>,
    /// Optional shared progress sink. The replayer updates this as
    /// messages flow so the caller can poll live counters without
    /// waiting for [`ProtoReplayer::run`] to return.
    pub progress: Option<MessageProgress>,
    /// Which side of the captured conversation this session plays.
    pub role: Role,
    /// [`Role::Slave`] only: local TCP port to listen on for an
    /// inbound connection from the target master. One listener per
    /// session; the caller picks a distinct port per concurrent RTU.
    pub listen_port: u16,
    /// Per-session pacing strategy. Default = as-fast-as-possible.
    pub pacing: Pacing,
    /// When [`Pacing::OriginalTiming`] is selected, one entry per
    /// I-frame in the captured send list: the relative timestamp
    /// (ns from the first I-frame) at which the replayer should
    /// emit that frame. Empty vec disables per-frame pacing.
    pub frame_times_ns: Vec<u64>,
    /// How many times to replay the captured script *within a single
    /// connection*. `1` (default) means play once and close (current
    /// behaviour). `n > 1` means play `n` times back-to-back inside
    /// one accept/handshake/close cycle. `0` means loop forever until
    /// the per-session cancel flag flips. Mostly relevant in slave
    /// mode: real RTUs hold their TCP session open indefinitely, so
    /// looping within one session is more spec-realistic than the
    /// outer "fresh handshake per iteration" model.
    pub loop_iterations: u64,
    /// Byte offsets into the concatenated `client_segments` stream at
    /// which the capture lost bytes (TCP reassembly gaps, see
    /// `pcapload::ReassembledFlow::gaps`). The bytes on either side of
    /// each offset were spliced together, so a protocol framer must
    /// restart at every offset instead of reading a frame across it.
    /// Empty = the stream is contiguous.
    pub capture_gaps: Vec<usize>,
    // Note: protocol-specific knobs (e.g. IEC 104 CP56Time2a rewrite
    // settings, ASDU rewrite map) live inside `proto_config` JSON.
    // The protocol replayer parses what it needs from there.
}

/// Result of a single-flow replay.
#[derive(Debug, Clone, Default)]
pub struct ProtoReport {
    pub connected: bool,
    pub bytes_written: u64,
    pub bytes_read: u64,
    /// Wall-clock length of the session (all iterations when merged),
    /// idle-serve included. See [`ProtoReport::active_ms`].
    pub elapsed_ms: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub error: Option<String>,

    // --- benchmark stats ---
    /// Raw per-message **ack latency** samples in microseconds: the
    /// time from writing a data message to receiving the peer's
    /// protocol-level acknowledgement of it (IEC 104: the N(R) in an
    /// S- or I-frame). The receive side is timestamped in the reader
    /// thread when the frame arrives, not when the session loop gets
    /// round to it. Note that this includes the peer's ack-deferral
    /// policy (IEC 104 w / t2), so it is not a pure responsiveness
    /// measure. One entry per message whose acknowledgement was seen.
    /// Kept so the web UI can render a histogram. The `latency_*_us`
    /// fields below are percentiles of these samples.
    pub latency_samples_us: Vec<u64>,
    pub latency_min_us: u64,
    pub latency_p50_us: u64,
    pub latency_p90_us: u64,
    pub latency_p99_us: u64,
    pub latency_max_us: u64,
    pub latency_mean_us: u64,
    /// Client messages per second over the session's active time
    /// ([`ProtoReport::active_ms`]), idle-serve excluded.
    pub throughput_msgs_per_sec: f64,
    /// Number of times the send loop blocked waiting for the server
    /// to free the flow-control window.
    pub window_stalls: u64,
    /// Messages still in flight (sent, not yet acknowledged) when the
    /// session ended.
    pub unacked_at_end: u64,
    /// Protocol-level conformance and session-behaviour detail
    /// (violations, synthesized frames, stripped capture frames, idle
    /// time). Protocols that do not track these leave it at default.
    pub protocol: ProtocolStats,
}

/// Cap on [`ProtocolStats::protocol_errors`] entries kept per session.
pub const PROTOCOL_ERRORS_CAP: usize = 64;
/// Cap on [`ProtocolStats::synthesized_send_indices`] entries.
pub const SYNTHESIZED_INDICES_CAP: usize = 100_000;
/// Cap on [`ProtocolStats::command_response_us`] samples (the first
/// ones are kept).
pub const COMMAND_RESPONSE_SAMPLES_CAP: usize = 10_000;

/// Cap on the per-type ActCon / ActTerm latency samples in
/// [`CommandTypeStats`] (the first ones are kept).
pub const COMMAND_LATENCY_SAMPLES_CAP: usize = 2_000;
/// Cap on [`ProtocolStats::negative_confirmations`] entries.
pub const NEGATIVE_CONFIRMATIONS_CAP: usize = 200;
/// Cap on [`ProtocolStats::faults_injected`] entries.
pub const FAULT_RECORDS_CAP: usize = 256;

/// One protocol violation or protocol-level failure seen on a session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProtocolError {
    /// Milliseconds since the connection was established.
    pub at_ms: u64,
    /// Short machine-readable class, e.g. `"ns_mismatch"`,
    /// `"nr_out_of_window"`, `"malformed_frame"`, `"t1_timeout"`,
    /// `"unexpected_u_frame"`.
    pub kind: String,
    /// Human-readable detail (expected vs. received values).
    pub detail: String,
    /// True if the session closed the connection because of it.
    pub fatal: bool,
}

/// Application-level command round trips of one command type
/// (IEC 104: the ASDU type ID, e.g. 45 = C_SC_NA_1, 100 = C_IC_NA_1).
///
/// Slave role: commands received from the live master and answered by
/// the replayer; latencies run from receiving the command to sending
/// our confirmation / termination. Master role: commands replayed from
/// the capture; latencies run from sending the command to receiving the
/// live slave's confirmation / termination.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CommandTypeStats {
    pub type_id: u8,
    /// Commands seen (slave: received; master: sent).
    pub commands: u64,
    /// Positive activation confirmations (or, for a read command, the
    /// requested data).
    pub act_con: u64,
    /// Negative confirmations (P/N = 1, or COT 44..=47).
    pub negative: u64,
    /// Activation terminations.
    pub act_term: u64,
    /// Deactivation confirmations.
    pub deact_con: u64,
    /// Master role: commands that got no confirmation at all before
    /// the session ended.
    pub unanswered: u64,
    /// Command → first confirmation (positive, negative or DeactCon)
    /// in microseconds, capped at [`COMMAND_LATENCY_SAMPLES_CAP`].
    pub actcon_us: Vec<u64>,
    /// Command → ActTerm in microseconds, capped likewise.
    pub actterm_us: Vec<u64>,
}

impl CommandTypeStats {
    fn merge(&mut self, o: CommandTypeStats) {
        self.commands += o.commands;
        self.act_con += o.act_con;
        self.negative += o.negative;
        self.act_term += o.act_term;
        self.deact_con += o.deact_con;
        self.unanswered += o.unanswered;
        for (dst, src) in [
            (&mut self.actcon_us, o.actcon_us),
            (&mut self.actterm_us, o.actterm_us),
        ] {
            let room = COMMAND_LATENCY_SAMPLES_CAP.saturating_sub(dst.len());
            dst.extend(src.into_iter().take(room));
        }
    }
}

/// One negative command confirmation (slave role: one we sent; master
/// role: one the live slave sent).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NegativeConfirmation {
    /// Milliseconds since the connection was established.
    pub at_ms: u64,
    pub type_id: u8,
    /// Common address and information object address of the command.
    pub ca: u16,
    pub ioa: u32,
    /// Cause of transmission of the negative reply (7, 9, 44..=47).
    pub cot: u8,
}

/// One deliberately injected fault (IEC 104 `proto_config.faults`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FaultRecord {
    /// Milliseconds since the connection was established at which the
    /// fault fired.
    pub at_ms: u64,
    /// Fault kind as configured, e.g. `"drop_iframes"`.
    pub kind: String,
    /// What was done (parameters, affected sequence numbers).
    pub detail: String,
    /// Frames the fault acted on (dropped, duplicated, corrupted,
    /// delayed, malformed frames sent, TESTFR acts ignored, acks held).
    pub frames_affected: u64,
}

/// How the peer reacted once the first fault was injected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FaultReaction {
    /// The peer closed the connection (FIN).
    pub peer_closed: bool,
    /// The peer reset the connection (RST).
    pub peer_reset: bool,
    /// The peer sent STOPDT act.
    pub peer_stopdt: bool,
    /// Distinct protocol error kinds recorded after the first fault
    /// (see [`ProtocolError::kind`]).
    pub protocol_errors: Vec<String>,
    /// Milliseconds from the first fault to the first reaction above.
    pub first_reaction_ms: Option<u64>,
    /// One-line summary, e.g. "3 faults injected; peer reaction:
    /// closed the connection 120 ms after the first fault".
    pub summary: String,
}

/// Protocol-level session detail reported next to the generic
/// counters in [`ProtoReport`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProtocolStats {
    /// Number of protocol violations by the peer (sequence-number
    /// errors, malformed frames, unexpected control frames) plus
    /// protocol timer expiries. Every one is counted even when
    /// `protocol_errors` is capped.
    pub protocol_violations: u64,
    /// Detail for the first [`PROTOCOL_ERRORS_CAP`] violations.
    pub protocol_errors: Vec<ProtocolError>,
    /// Data messages the replayer generated itself (IEC 104 slave:
    /// GI/CI and command responses) rather than replaying from the
    /// capture. They
    /// are included in `messages_sent`.
    pub synthesized_frames: u64,
    /// 0-based index, among all data messages sent on this session
    /// (`messages_sent` order), of each synthesized message, so the
    /// analyzer can tell them apart from replayed ones. Capped at
    /// [`SYNTHESIZED_INDICES_CAP`]. When reports from several
    /// connections are merged, indices are offset by the earlier
    /// sessions' `messages_sent`.
    pub synthesized_send_indices: Vec<u64>,
    /// Application-level response time in microseconds: from receiving
    /// a command the replayer answers itself (IEC 104 slave: GI/CI
    /// activation or control-direction command) to sending the first
    /// response frame (ActCon or negative confirmation).
    /// Capped at [`COMMAND_RESPONSE_SAMPLES_CAP`].
    pub command_response_us: Vec<u64>,
    /// Captured frames removed from the replay script because the
    /// replayer synthesizes their equivalent live (IEC 104 slave:
    /// captured GI/CI ActCon, Inrogen/Reqcogen data and ActTerm, and
    /// captured command confirmations and read replies).
    pub stripped_capture_frames: u64,
    /// Number of capture gaps in the replayed stream.
    pub capture_gaps: u64,
    /// Bytes of the captured stream that did not frame (leading
    /// partial frame, bytes around capture gaps, truncated tail).
    pub script_skipped_bytes: u64,
    /// Captured frames that straddled a capture gap and were dropped
    /// instead of being sent corrupted.
    pub script_dropped_frames: u64,
    /// Time spent serving the peer after the captured script ended
    /// (IEC 104 slave idle-serve phase), in milliseconds.
    pub idle_serve_ms: u64,
    /// Standalone acknowledgement frames sent (IEC 104 S-frames).
    pub acks_sent: u64,
    /// Keep-alive probes sent (IEC 104 TESTFR act after t3 idle).
    pub keepalives_sent: u64,
    /// Slave role: master connections that ended before the master's
    /// STARTDT act (a port probe, a master that redialled); the
    /// listener kept accepting after each.
    pub connections_before_startdt: u64,
    /// Per command type round-trip figures, sorted by type ID.
    pub commands: Vec<CommandTypeStats>,
    /// Negative command confirmations, capped at
    /// [`NEGATIVE_CONFIRMATIONS_CAP`].
    pub negative_confirmations: Vec<NegativeConfirmation>,
    /// Deliberately injected faults, capped at [`FAULT_RECORDS_CAP`].
    pub faults_injected: Vec<FaultRecord>,
    /// Peer reaction to the injected faults; `None` when no fault
    /// fired.
    pub fault_reaction: Option<FaultReaction>,
}

impl ProtocolStats {
    /// Fold `other` (a later connection of the same session slot) into
    /// `self`. `send_offset` is the number of data messages already
    /// accounted in `self`'s report, used to rebase
    /// `synthesized_send_indices`.
    pub fn merge(&mut self, other: ProtocolStats, send_offset: u64) {
        self.protocol_violations += other.protocol_violations;
        let room = PROTOCOL_ERRORS_CAP.saturating_sub(self.protocol_errors.len());
        self.protocol_errors
            .extend(other.protocol_errors.into_iter().take(room));
        self.synthesized_frames += other.synthesized_frames;
        let room = SYNTHESIZED_INDICES_CAP.saturating_sub(self.synthesized_send_indices.len());
        self.synthesized_send_indices.extend(
            other
                .synthesized_send_indices
                .into_iter()
                .take(room)
                .map(|i| i + send_offset),
        );
        let room = COMMAND_RESPONSE_SAMPLES_CAP.saturating_sub(self.command_response_us.len());
        self.command_response_us
            .extend(other.command_response_us.into_iter().take(room));
        // Script-level figures are identical for every connection of
        // the same slot, so keep one copy rather than summing.
        self.stripped_capture_frames = self
            .stripped_capture_frames
            .max(other.stripped_capture_frames);
        self.capture_gaps = self.capture_gaps.max(other.capture_gaps);
        self.script_skipped_bytes = self.script_skipped_bytes.max(other.script_skipped_bytes);
        self.script_dropped_frames = self.script_dropped_frames.max(other.script_dropped_frames);
        self.idle_serve_ms += other.idle_serve_ms;
        self.acks_sent += other.acks_sent;
        self.keepalives_sent += other.keepalives_sent;
        self.connections_before_startdt += other.connections_before_startdt;
        for c in other.commands {
            match self.commands.iter_mut().find(|x| x.type_id == c.type_id) {
                Some(x) => x.merge(c),
                None => self.commands.push(c),
            }
        }
        self.commands.sort_by_key(|c| c.type_id);
        let room = NEGATIVE_CONFIRMATIONS_CAP.saturating_sub(self.negative_confirmations.len());
        self.negative_confirmations
            .extend(other.negative_confirmations.into_iter().take(room));
        let room = FAULT_RECORDS_CAP.saturating_sub(self.faults_injected.len());
        self.faults_injected
            .extend(other.faults_injected.into_iter().take(room));
        if let Some(o) = other.fault_reaction {
            match &mut self.fault_reaction {
                None => self.fault_reaction = Some(o),
                Some(r) => {
                    r.peer_closed |= o.peer_closed;
                    r.peer_reset |= o.peer_reset;
                    r.peer_stopdt |= o.peer_stopdt;
                    for k in o.protocol_errors {
                        if !r.protocol_errors.contains(&k) {
                            r.protocol_errors.push(k);
                        }
                    }
                    r.first_reaction_ms = r.first_reaction_ms.or(o.first_reaction_ms);
                    if r.summary.len() < 512 {
                        r.summary = format!("{}; then: {}", r.summary, o.summary);
                    }
                }
            }
        }
    }
}

impl ProtoReport {
    /// Active time of the session in milliseconds: `elapsed_ms` (the
    /// total, wall clock) minus the time spent idle-serving the peer
    /// after the script ([`ProtocolStats::idle_serve_ms`]). Both add up
    /// when reports are merged, so this stays the sum of the active
    /// times (N4).
    pub fn active_ms(&self) -> u64 {
        self.elapsed_ms.saturating_sub(self.protocol.idle_serve_ms)
    }

    /// Compute latency percentile fields and throughput from the raw
    /// `latency_samples_us` and the session's active time
    /// ([`ProtoReport::active_ms`]). Call this once at the end of a
    /// session, after all samples have been recorded and `elapsed_ms`,
    /// `protocol.idle_serve_ms` and `messages_sent` are set.
    pub fn finalize_latency(&mut self) {
        // Throughput does not depend on the latency samples; a session
        // that never saw an ACK still sent messages.
        let active_ms = self.active_ms();
        self.throughput_msgs_per_sec = if active_ms > 0 {
            (self.messages_sent as f64) * 1000.0 / (active_ms as f64)
        } else {
            0.0
        };
        if self.latency_samples_us.is_empty() {
            self.latency_min_us = 0;
            self.latency_max_us = 0;
            self.latency_p50_us = 0;
            self.latency_p90_us = 0;
            self.latency_p99_us = 0;
            self.latency_mean_us = 0;
            return;
        }
        let mut v = self.latency_samples_us.clone();
        v.sort_unstable();
        let n = v.len();
        let at = |p: f64| -> u64 {
            let idx = ((n as f64 - 1.0) * p).round() as usize;
            v[idx.min(n - 1)]
        };
        self.latency_min_us = v[0];
        self.latency_max_us = v[n - 1];
        self.latency_p50_us = at(0.50);
        self.latency_p90_us = at(0.90);
        self.latency_p99_us = at(0.99);
        let sum: u128 = v.iter().map(|x| *x as u128).sum();
        self.latency_mean_us = (sum / n as u128) as u64;
    }
}

/// Status of a registered protocol module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Fully implemented; safe to use in production.
    Ready,
    /// Compiles and registers, but `run` returns an error. Exists so
    /// the web UI can list the module and callers can fall back.
    Stub,
}

/// Generic, protocol-agnostic viability summary the analyser produces
/// at pcap-upload time so the UI can warn about pcaps that are too
/// large or session-rich to comfortably replay on the host.
///
/// All counts are on a per-protocol basis: a master-mode benchmark
/// would spawn `sessions_master_mode` outgoing sessions; a slave-mode
/// benchmark would bind `sessions_slave_mode` listeners.
#[derive(Debug, Clone, Default)]
pub struct ProtoViability {
    /// Sum of TCP payload bytes from the client side of all flows
    /// the protocol considers "interesting" (typically: server_port
    /// matches one of `well_known_ports()`).
    pub client_payload_bytes: u64,
    /// Same for the server side.
    pub server_payload_bytes: u64,
    /// Distinct client IPs observed talking to the protocol's well-
    /// known port. Master-mode session count.
    pub sessions_master_mode: u64,
    /// Distinct server IPs observed listening on the protocol's
    /// well-known port. Slave-mode session count.
    pub sessions_slave_mode: u64,
    /// Rough peak working-set estimate in MB for replaying this
    /// pcap on this host.
    pub estimated_peak_mb: u64,
    /// One of: "ok", "caution", "heavy", "not_recommended".
    pub verdict: String,
    /// Human-readable reason for the verdict.
    pub verdict_reason: String,
    /// Extra observations the UI can render as bullet notes
    /// (e.g. "165 of 171 flows are mid-flow").
    pub notes: Vec<String>,
    /// Per-RTU breakdown for slave-mode (one entry per distinct
    /// server IP on the protocol's well-known port). Drives the
    /// pre-run "select RTUs" picker AND the per-RTU traffic chart
    /// so the operator can quickly see how heavy each slave is.
    /// Empty when the protocol either ignores the question or saw
    /// no slave-side endpoints.
    pub slave_rtus: Vec<RtuTraffic>,
    /// Same per-endpoint shape for master-mode (per distinct client IP).
    pub master_clients: Vec<RtuTraffic>,
}

/// Per-endpoint traffic snapshot used by the run-config picker.
#[derive(Debug, Clone, Default)]
pub struct RtuTraffic {
    /// IPv4 dotted-quad string of the endpoint.
    pub ip: String,
    /// Reassembled payload bytes the protocol would replay for this
    /// endpoint (server-side bytes for slave-mode, client-side for
    /// master-mode).
    pub payload_bytes: u64,
    /// Number of protocol-level messages observed (e.g. IEC 104
    /// I-frames). Useful as a proxy for "how busy is this RTU."
    pub messages: u64,
    /// Wall-clock span of the flow in milliseconds (last packet ts
    /// minus first packet ts, both relative to the pcap start).
    /// Zero when the flow has fewer than two packets.
    pub duration_ms: u64,
}

/// The contract every protocol replayer must satisfy.
pub trait ProtoReplayer: Send + Sync {
    fn name(&self) -> &'static str;
    fn well_known_ports(&self) -> &'static [u16];
    fn readiness(&self) -> Readiness;
    fn run(&self, cfg: ProtoRunCfg) -> ProtoReport;

    /// Validate a protocol-specific `proto_config` JSON string up front,
    /// so a bad config is rejected when the run is submitted instead of
    /// surfacing later as a session error. Default: accept anything.
    fn validate_config(&self, _proto_config: Option<&str>) -> anyhow::Result<()> {
        Ok(())
    }

    /// Extract one timestamp per protocol-level message in the
    /// reassembled flow `payload`. Each timestamp is in nanoseconds,
    /// **relative to the first message** (so `out[0]` is always 0).
    /// `packet_offsets` is the byte-offset to packet-timestamp mapping
    /// from the source pcap reassembly; the implementation can binary-
    /// search it to resolve any byte position to a wall-clock send time.
    ///
    /// Used by [`Pacing::OriginalTiming`] in the scheduler so the live
    /// replay can fire each message at its captured cadence.
    ///
    /// Default impl returns an empty `Vec`, in which case the scheduler
    /// falls through to as-fast-as-possible behaviour for that flow.
    /// Protocols that wrap their messages in length-prefixed framing
    /// (IEC 104, DNP3, modbus-tcp, ...) override this with the framing-
    /// specific message-start scan.
    fn extract_message_times_ns(
        &self,
        _payload: &[u8],
        _packet_offsets: &[(u64, usize)],
    ) -> Vec<u64> {
        Vec::new()
    }

    /// Walk a loaded pcap and produce a protocol-aware viability
    /// summary: per-side payload bytes, per-mode session count, a
    /// memory estimate and a verdict + notes for the UI.
    ///
    /// `file_size_bytes` is passed in (rather than re-stat'd) so
    /// callers that hold the value already don't pay for a syscall;
    /// implementations include it in the memory estimate.
    ///
    /// Default impl returns a generic skeleton based on
    /// [`Self::well_known_ports`] — counts flows whose `server.port`
    /// matches any of those ports and produces a verdict from raw
    /// session counts. Protocols that need richer analysis (e.g.
    /// IEC 104's mid-flow vs handshake breakdown) override this.
    fn quick_viability(&self, p: &dyn LoadedPcapView, file_size_bytes: u64) -> ProtoViability {
        use std::collections::HashSet;
        let ports: &[u16] = self.well_known_ports();
        let mut client_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut server_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut client_bytes = 0u64;
        let mut server_bytes = 0u64;
        for f in p.flows() {
            let (sip, sp) = match f.server {
                Some(x) => x,
                None => continue,
            };
            if !ports.contains(&sp) {
                continue;
            }
            let (cip, _) = match f.client {
                Some(x) => x,
                None => continue,
            };
            client_ips.insert(cip);
            server_ips.insert(sip);
            let (cb, sb) = p.flow_payload_bytes(f.flow_idx);
            client_bytes += cb;
            server_bytes += sb;
        }
        let m = client_ips.len() as u64;
        let s = server_ips.len() as u64;
        let max_sess = m.max(s);
        let mb = |b: u64| b.div_ceil(1024 * 1024);
        let est = mb(file_size_bytes) + mb(client_bytes.max(server_bytes)) + max_sess * 2 + 32;
        let (verdict, reason): (&str, String) = if max_sess == 0 {
            (
                "ok",
                format!("no flows for protocol {} on ports {:?}", self.name(), ports),
            )
        } else {
            (
                "ok",
                format!("{} session(s) detected for {}", max_sess, self.name()),
            )
        };
        ProtoViability {
            client_payload_bytes: client_bytes,
            server_payload_bytes: server_bytes,
            sessions_master_mode: m,
            sessions_slave_mode: s,
            estimated_peak_mb: est,
            verdict: verdict.into(),
            verdict_reason: reason,
            notes: Vec::new(),
            slave_rtus: Vec::new(),
            master_clients: Vec::new(),
        }
    }

    /// Per-slave deep analysis: compare the four reassembled flow sides
    /// (captured-vs-original × playback-vs-target) and return a
    /// protocol-specific drill-down plus a handful of common fields the
    /// core rollup uses. Default impl returns [`ProtoSlaveAnalysis::default`]
    /// — protocols implement this to participate in the analyze page.
    ///
    /// Each [`FlowSnapshot`] is `Option` because a slave might be missing
    /// from either pcap (e.g. expected but never reached the wire).
    fn analyze_flow(
        &self,
        _orig_playback: Option<FlowSnapshot>,
        _cap_playback: Option<FlowSnapshot>,
        _orig_target: Option<FlowSnapshot>,
        _cap_target: Option<FlowSnapshot>,
        _ctx: &AnalyzeCtx,
    ) -> ProtoSlaveAnalysis {
        ProtoSlaveAnalysis::default()
    }

    /// Fold per-slave `protocol_specific` JSON blobs into a single
    /// fleet-level drift timeline. Called after all per-slave
    /// [`Self::analyze_flow`] invocations have finished, so the protocol
    /// can reach inside each blob to pull whatever "drift sample" series
    /// it cares about (IEC 104: CP56Time2a drift; others: their own
    /// metric) and aggregate onto a single time axis.
    ///
    /// `iteration_starts_ms` is computed by the core (from SYN bursts in
    /// the captured pcap) and passed in so the aggregator can annotate
    /// the timeline with loop boundaries without re-walking the pcap.
    ///
    /// Default returns `None` — protocols that want a fleet chart
    /// override this.
    fn aggregate_fleet_drift(
        &self,
        _per_slave: &BTreeMap<String, serde_json::Value>,
        _iteration_starts_ms: &[f64],
    ) -> Option<FleetDriftTimeline> {
        None
    }
}

/// Minimal view a [`ProtoReplayer::quick_viability`] impl needs over
/// a loaded pcap. Defined here so `protoplay` doesn't need a hard
/// dependency on the `pcapload` crate; webui adapts a real
/// `pcapload::LoadedPcap` into this shape on the call.
pub trait LoadedPcapView {
    /// Iterate every TCP flow.
    fn flows(&self) -> Box<dyn Iterator<Item = FlowView> + '_>;
    /// Reassembled-payload byte counts for one flow:
    /// `(client_bytes, server_bytes)`. Either can be zero if a
    /// reassembly attempt failed (e.g. mid-flow capture with gaps).
    fn flow_payload_bytes(&self, flow_idx: usize) -> (u64, u64);
    /// Reassembled server-side payload bytes for one flow. Used by
    /// protocols that want to inspect the on-wire data during quick
    /// viability (IEC 104 builds a CA/IOA inventory from each slave-
    /// side stream so the upload summary shows point counts). Default
    /// returns empty so existing impls compile unchanged.
    fn flow_server_payload(&self, _flow_idx: usize) -> Vec<u8> {
        Vec::new()
    }
    /// Reassemble one side of a flow once and hand it to `f` without
    /// copying (P07). `f` is not called when that side carries no
    /// payload. The default is built on
    /// [`LoadedPcapView::flow_server_payload`] (server side only, no
    /// gap information); real views override it.
    fn with_flow_side(
        &self,
        flow_idx: usize,
        side: FlowSide,
        f: &mut dyn FnMut(&FlowSideView<'_>),
    ) {
        if side == FlowSide::Server {
            let payload = self.flow_server_payload(flow_idx);
            if !payload.is_empty() {
                f(&FlowSideView {
                    payload: &payload,
                    gap_offsets: &[],
                    missing_bytes: 0,
                });
            }
        }
    }
    /// Packets in the capture (for the memory estimate); 0 = unknown.
    fn packet_count(&self) -> u64 {
        0
    }
}

/// One side of a TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSide {
    /// Bytes the client sent (master role replays them).
    Client,
    /// Bytes the server sent (slave role replays them).
    Server,
}

/// One reassembled side of a flow, see
/// [`LoadedPcapView::with_flow_side`].
#[derive(Debug, Clone, Copy)]
pub struct FlowSideView<'a> {
    pub payload: &'a [u8],
    /// Payload offsets of the capture gaps (TCP sequence holes), in
    /// order; an offset of 0 is a lost first segment.
    pub gap_offsets: &'a [usize],
    /// Sequence-space bytes the capture lost.
    pub missing_bytes: u64,
}

/// How well one captured flow side lends itself to replay, to pick one
/// flow per endpoint when an endpoint appears in several (reconnects,
/// port reuse). The scheduler and the upload viability rank flows the
/// same way (N18): the longest contiguous run of bytes first (the most
/// that replays without a hole), then fewer gaps, then more bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowQuality {
    /// Longest stretch of payload without a capture gap inside it.
    pub longest_chunk: usize,
    /// Capture gaps, a lost first segment included.
    pub gaps: usize,
    pub payload_bytes: usize,
    /// Sequence-space bytes the capture lost.
    pub missing_bytes: u64,
}

impl FlowQuality {
    /// Quality of a side with `payload_len` bytes and capture gaps at
    /// `gap_offsets` (sorted payload offsets).
    pub fn new(payload_len: usize, gap_offsets: &[usize], missing_bytes: u64) -> Self {
        let mut longest = 0usize;
        let mut start = 0usize;
        for &o in gap_offsets {
            let o = o.min(payload_len);
            longest = longest.max(o.saturating_sub(start));
            start = start.max(o);
        }
        longest = longest.max(payload_len.saturating_sub(start));
        Self {
            longest_chunk: longest,
            gaps: gap_offsets.len(),
            payload_bytes: payload_len,
            missing_bytes,
        }
    }

    /// Quality of a reassembled side.
    pub fn of(side: &FlowSideView<'_>) -> Self {
        Self::new(side.payload.len(), side.gap_offsets, side.missing_bytes)
    }

    /// Strictly better replay candidate than `other` (ties keep the
    /// flow seen first).
    pub fn better_than(&self, other: &FlowQuality) -> bool {
        (
            self.longest_chunk,
            std::cmp::Reverse(self.gaps),
            self.payload_bytes,
        ) > (
            other.longest_chunk,
            std::cmp::Reverse(other.gaps),
            other.payload_bytes,
        )
    }
}

/// Minimal flow descriptor a viability impl needs.
#[derive(Debug, Clone, Copy)]
pub struct FlowView {
    pub flow_idx: usize,
    pub client: Option<(std::net::Ipv4Addr, u16)>,
    pub server: Option<(std::net::Ipv4Addr, u16)>,
    pub saw_syn: bool,
}

/// Lightweight borrowed view of a reassembled TCP flow, passed to
/// [`ProtoReplayer::analyze_flow`]. Sidesteps a hard `pcapload`
/// dependency on `protoplay`: callers holding a `pcapload::ReassembledFlow`
/// construct a snapshot with `FlowSnapshot { payload: &rf.payload,
/// packet_offsets: &rf.packet_offsets }` on the call.
#[derive(Debug, Clone, Copy)]
pub struct FlowSnapshot<'a> {
    /// TCP-reassembled byte stream of the one-sided flow.
    pub payload: &'a [u8],
    /// Byte-offset → packet-timestamp mapping, sorted by offset.
    /// `(pkt_rel_ts_ns, byte_offset_where_that_packet's_payload_starts)`.
    pub packet_offsets: &'a [(u64, usize)],
}

impl<'a> FlowSnapshot<'a> {
    /// Return the relative (ns-from-pcap-start) timestamp of the packet
    /// whose payload starts at or before `byte_offset`. Binary-searches
    /// `packet_offsets` (which must be sorted by the offset field).
    pub fn ts_for_byte(&self, byte_offset: usize) -> u64 {
        let mut lo = 0usize;
        let mut hi = self.packet_offsets.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.packet_offsets[mid].1 <= byte_offset {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            self.packet_offsets.first().map(|p| p.0).unwrap_or(0)
        } else {
            self.packet_offsets[lo - 1].0
        }
    }
}

/// Context the webui analyzer hands to a protocol's [`ProtoReplayer::analyze_flow`].
/// Carries the per-run knobs (role, mode, timestamp epoch, tolerance) plus the
/// run's full `proto_config` JSON — each protocol parses what it needs.
#[derive(Debug, Clone)]
pub struct AnalyzeCtx {
    /// Which side outstation acted as: [`Role::Master`] (drove the client
    /// side) or [`Role::Slave`] (drove the server side).
    pub role: Role,
    /// Whether to run the "correct mode" target-side diff (byte-level
    /// target behaviour comparison vs the original server). When false,
    /// only delivery + handshake are scored.
    pub mode_correct: bool,
    /// Absolute UTC epoch (ns since Unix epoch) of the captured pcap's
    /// first packet. Added to per-byte relative timestamps by analyzers
    /// that need absolute wall time (e.g. IEC 104 CP56Time2a drift).
    pub captured_first_ts_ns: u64,
    /// The well-known target port for this run (e.g. 2404 for IEC 104).
    pub target_port: u16,
    /// Same free-form string the run was configured with; each protocol
    /// parses its own sub-object (e.g. IEC 104 reads `{"cp56": {...}}`).
    pub proto_config: Option<String>,
    /// Drift-tolerance knob passed separately because it's an analyzer-
    /// only concept — not part of the run's proto_config (the runner
    /// never needs it).
    pub cp56_tolerance_ms: f64,
    /// Facts about the run (or this endpoint's session) the capture is
    /// judged against. `RunFacts::default()` means "unknown": the
    /// analyzer then infers loop iterations from the stream and does
    /// not judge timing.
    pub run: RunFacts,
}

/// Run-level facts a protocol analyzer needs to judge one captured
/// session fairly. Supplied by the caller (the webui shell) per
/// endpoint; every field has a conservative default.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunFacts {
    /// Script iterations this TCP session was configured to play
    /// back-to-back (loop-within-session). `0` = unknown or unbounded:
    /// the analyzer detects iterations as restarts of the script.
    pub iterations_per_session: u64,
    /// The run (or this endpoint's session) ended on a user stop or
    /// cancel, so a truncated final iteration is expected and is
    /// reported as a stopped tail rather than as missing frames.
    pub stopped_early: bool,
    /// Pacing speed factor when the run replayed original timing
    /// (`1.0` = real time). `None` = as-fast-as-possible or unknown:
    /// timing is measured and reported but not judged.
    pub paced_speed: Option<f64>,
}

/// Pass/fail class of a per-endpoint verdict, so the protocol-agnostic
/// fleet rollup never has to interpret protocol verdict strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOutcome {
    /// The replay was verified correct.
    Pass,
    /// The replay was verified to deviate (or did not happen).
    Fail,
    /// Nothing could be verified (no reference, unparseable input…).
    /// The default, so a protocol that never sets it cannot be counted
    /// as correct by accident.
    #[default]
    Inconclusive,
}

/// Per-slave result the analyzer shell gets back from [`ProtoReplayer::analyze_flow`].
///
/// The shell stitches these into the top-level `SlaveDetail` / `SlaveSummary`
/// structures: the protocol-specific payload lands under
/// `SlaveDetail.protocol_specific`, and the common fields drive the fleet
/// rollup so the shell doesn't have to know any protocol vocabulary.
#[derive(Debug, Clone)]
pub struct ProtoSlaveAnalysis {
    pub score_pct: f64,
    pub verdict: &'static str,
    pub verdict_reason: String,
    /// How many protocol-level messages the original pcap expected the
    /// playback side to deliver. IEC 104 = I-frame count; Modbus =
    /// transaction count; DNP3 = fragment count; etc.
    pub expected_messages: usize,
    /// How many the captured pcap actually saw on the wire.
    pub delivered_messages: usize,
    /// Protocol-level "did the handshake complete" flag (IEC 104:
    /// STARTDT_CON or _ACT seen; TLS: CertificateVerify+Finished; etc.).
    /// Feeds the summary table's green/red dot.
    pub handshake_ok: bool,
    /// Per-slave notes appended to the core's own notes. Good place for
    /// protocol-level observations (e.g. "live target replayed a subset
    /// of the original script").
    pub notes: Vec<String>,
    /// Opaque protocol-specific drill-down JSON. Rendered by the proto's
    /// UI fragment on the slave-detail page. Shape is entirely the
    /// protocol's — for IEC 104: `{ playback, target, cp56_drift, timing, ... }`.
    pub protocol_specific: serde_json::Value,
    /// Per-message pacing-drift samples `[capture_wall_ms, drift_ms]`,
    /// used by the core's fleet pacing timeline builder. Every protocol
    /// has a "when should each message have gone out" concept, so this
    /// is a generic field rather than protocol_specific.
    pub pacing_samples: Vec<[f64; 2]>,
    /// How many pacing samples `pacing_samples` stands for before the
    /// protocol decimated it. `0` means "not decimated" (same as
    /// `pacing_samples.len()`). Lets the fleet timeline weight each
    /// endpoint by its real frame count.
    pub pacing_samples_total: usize,
    /// Pass / fail / inconclusive class of `verdict`, used by the
    /// fleet rollup.
    pub outcome: VerdictOutcome,
}

impl Default for ProtoSlaveAnalysis {
    fn default() -> Self {
        Self {
            score_pct: 0.0,
            verdict: "unknown",
            verdict_reason: String::new(),
            expected_messages: 0,
            delivered_messages: 0,
            handshake_ok: false,
            notes: Vec::new(),
            protocol_specific: serde_json::Value::Null,
            pacing_samples: Vec::new(),
            pacing_samples_total: 0,
            outcome: VerdictOutcome::Inconclusive,
        }
    }
}

/// Protocol-agnostic time-series wrapper for fleet-level drift charts.
///
/// Returned by [`ProtoReplayer::aggregate_fleet_drift`]: each protocol
/// decides what "drift" means (IEC 104 CP56Time2a stamp-vs-wire; Modbus
/// transaction-round-trip; …) and packs its per-slave samples into this
/// shape. The webui renders it with one template regardless of protocol.
#[derive(Serialize, Debug, Clone)]
pub struct FleetDriftTimeline {
    /// `[capture_wall_ms, drift_ms]` per kept sample after decimation.
    pub samples: Vec<[f64; 2]>,
    /// Total samples observed before decimation (samples.len() will be ≤ this).
    pub total_samples: usize,
    /// True iff decimation discarded samples.
    pub decimated: bool,
    /// Wall-clock ms of each detected iteration boundary. Empty for
    /// single-iteration runs. Lets the UI annotate the chart.
    pub iteration_starts_ms: Vec<f64>,
}

/// Boilerplate helper for stub implementations.
pub fn stub_report(name: &str) -> ProtoReport {
    ProtoReport {
        error: Some(format!(
            "proto_{name} is a v1 stub — fall back to raw or generic TCP session"
        )),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_quality_prefers_the_longest_contiguous_run() {
        let clean = FlowQuality::new(1000, &[], 0);
        assert_eq!(clean.longest_chunk, 1000);
        let gapped = FlowQuality::new(1200, &[300], 50);
        assert_eq!(gapped.longest_chunk, 900);
        assert_eq!(gapped.gaps, 1);
        assert!(clean.better_than(&gapped));
        assert!(!gapped.better_than(&clean));
        // A lost first segment splits nothing but counts as a gap.
        let lead = FlowQuality::new(1000, &[0], 6);
        assert_eq!(lead.longest_chunk, 1000);
        assert!(clean.better_than(&lead));
        // A big flow with one small hole beats a short clean one.
        let short = FlowQuality::new(100, &[], 0);
        assert!(gapped.better_than(&short));
        // Ties keep the first.
        assert!(!clean.better_than(&clean));
        assert_eq!(FlowQuality::new(10, &[3, 3, 8], 1).longest_chunk, 5);
    }

    #[test]
    fn protocol_stats_merge_respects_caps() {
        let mut a = ProtocolStats {
            command_response_us: vec![1; COMMAND_RESPONSE_SAMPLES_CAP - 1],
            synthesized_send_indices: vec![0, 1],
            protocol_errors: vec![ProtocolError::default(); PROTOCOL_ERRORS_CAP],
            protocol_violations: PROTOCOL_ERRORS_CAP as u64,
            ..Default::default()
        };
        let b = ProtocolStats {
            command_response_us: vec![2; 10],
            synthesized_send_indices: vec![0, 3],
            protocol_errors: vec![ProtocolError::default(); 3],
            protocol_violations: 3,
            stripped_capture_frames: 4,
            ..Default::default()
        };
        a.merge(b.clone(), 10);
        assert_eq!(a.command_response_us.len(), COMMAND_RESPONSE_SAMPLES_CAP);
        assert_eq!(a.synthesized_send_indices, vec![0, 1, 10, 13]);
        assert_eq!(a.protocol_errors.len(), PROTOCOL_ERRORS_CAP);
        assert_eq!(a.protocol_violations, PROTOCOL_ERRORS_CAP as u64 + 3);
        a.merge(b, 20);
        assert_eq!(a.stripped_capture_frames, 4);
    }

    #[test]
    fn finalize_latency_basic() {
        let mut r = ProtoReport {
            latency_samples_us: (1..=100).collect(), // 1..100 µs uniform
            messages_sent: 100,
            elapsed_ms: 100,
            ..Default::default()
        };
        r.finalize_latency();
        assert_eq!(r.latency_min_us, 1);
        assert_eq!(r.latency_max_us, 100);
        // With 100 evenly-spaced samples, p50 lands around the middle,
        // p99 lands near the top. Exact index is (n-1)*p rounded.
        assert!(
            r.latency_p50_us >= 49 && r.latency_p50_us <= 52,
            "p50 was {}",
            r.latency_p50_us
        );
        assert!(r.latency_p99_us >= 98, "p99 was {}", r.latency_p99_us);
        assert_eq!(r.latency_mean_us, 50);
        // 100 messages in 100 ms -> 1000 msg/s
        assert_eq!(r.throughput_msgs_per_sec as u64, 1000);
    }

    #[test]
    fn finalize_latency_empty_is_noop() {
        let mut r = ProtoReport::default();
        r.finalize_latency();
        assert_eq!(r.latency_p99_us, 0);
        assert_eq!(r.latency_mean_us, 0);
    }

    #[test]
    fn finalize_latency_throughput_without_samples() {
        let mut r = ProtoReport {
            messages_sent: 50,
            elapsed_ms: 500,
            ..Default::default()
        };
        r.finalize_latency();
        assert_eq!(r.throughput_msgs_per_sec as u64, 100);
    }

    #[test]
    fn reservoir_is_bounded_and_counts_everything() {
        let mut r = LatencyReservoir::with_seed(100, 7);
        r.extend(0..10_000u64);
        assert_eq!(r.len(), 100);
        assert_eq!(r.seen(), 10_000);
        // Uniform sample of 0..10000: the mean should be near 5000.
        let mean = r.as_slice().iter().sum::<u64>() / 100;
        assert!((3000..7000).contains(&mean), "mean {mean}");
    }

    #[test]
    fn reservoir_keeps_all_below_capacity() {
        let mut r = LatencyReservoir::with_seed(10, 1);
        r.extend([5, 6, 7]);
        assert_eq!(r.into_vec(), vec![5, 6, 7]);
    }

    #[test]
    fn progress_cancel_checks_run_and_session_flags() {
        let p = MessageProgress::default();
        assert!(!p.is_cancelled());
        p.run_cancel.store(true, Ordering::Relaxed);
        assert!(p.is_cancelled());
        let q = MessageProgress::default();
        q.cancel.store(true, Ordering::Relaxed);
        assert!(progress_cancelled(&Some(q)));
        assert!(!progress_cancelled(&None));
    }

    #[test]
    fn cancellable_sleep_returns_promptly() {
        let flag = AtomicBool::new(true);
        let t = Instant::now();
        assert!(!sleep_cancellable(Duration::from_secs(3600), || flag.load(Ordering::Relaxed)));
        assert!(t.elapsed() < Duration::from_millis(50));
        // Huge durations must not overflow Instant arithmetic.
        assert!(!sleep_cancellable(Duration::MAX, || true));
        assert!(sleep_cancellable(Duration::from_millis(5), || false));
    }

    #[test]
    fn poll_until_cancellable_outcomes() {
        let deadline = Instant::now() + Duration::from_millis(30);
        let r: Wait<u8> = poll_until_cancellable(
            deadline,
            || false,
            |slice| {
                assert!(slice <= CANCEL_POLL_INTERVAL);
                std::thread::sleep(slice.min(Duration::from_millis(5)));
                None
            },
        );
        assert_eq!(r, Wait::TimedOut);
        let deadline = Instant::now() + Duration::from_secs(5);
        let r = poll_until_cancellable(deadline, || false, |_| Some(3u8));
        assert_eq!(r, Wait::Done(3));
        let r: Wait<u8> = poll_until_cancellable(deadline, || true, |_| None);
        assert_eq!(r, Wait::Cancelled);
    }
}
