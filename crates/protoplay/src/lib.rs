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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8};
use std::sync::Arc;
use std::time::Duration;

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
    /// Client messages sent on the wire so far.
    pub sent: Arc<AtomicU64>,
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
}

/// Controls how the replayer paces its own sends. Benchmark mode
/// defaults to firing as fast as the protocol's flow control allows
/// (`AsFastAsPossible`); the other variant waits between sends to
/// match the original pcap's inter-frame cadence.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Pacing {
    /// Pipelined as fast as possible, limited only by the protocol's
    /// own window (e.g., IEC 104 k=12).
    AsFastAsPossible,
    /// Sleep before each send so frame `i` is emitted at
    /// `session_epoch + frame_times_ns[i] / speed`. Requires the
    /// caller to populate `ProtoRunCfg::frame_times_ns`.
    OriginalTiming { speed: f64 },
}

impl Default for Pacing {
    fn default() -> Self {
        Self::AsFastAsPossible
    }
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
    pub elapsed_ms: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub error: Option<String>,

    // --- benchmark stats ---
    /// Raw per-message latency samples in microseconds, one entry per
    /// client message whose matching server acknowledgement was seen.
    /// Kept so the web UI can render a histogram.
    pub latency_samples_us: Vec<u64>,
    pub latency_min_us: u64,
    pub latency_p50_us: u64,
    pub latency_p90_us: u64,
    pub latency_p99_us: u64,
    pub latency_max_us: u64,
    pub latency_mean_us: u64,
    /// Client messages per second sustained over the active session.
    pub throughput_msgs_per_sec: f64,
    /// Number of times the send loop blocked waiting for the server
    /// to free the flow-control window.
    pub window_stalls: u64,
    /// Messages still in flight (sent, not yet acknowledged) when the
    /// session ended.
    pub unacked_at_end: u64,
}

impl ProtoReport {
    /// Compute latency percentile fields and throughput from the raw
    /// `latency_samples_us` and the session's active send window.
    /// Call this once at the end of a session, after all samples have
    /// been recorded and `elapsed_ms` and `messages_sent` are set.
    pub fn finalize_latency(&mut self) {
        if self.latency_samples_us.is_empty() {
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
        if self.elapsed_ms > 0 {
            self.throughput_msgs_per_sec =
                (self.messages_sent as f64) * 1000.0 / (self.elapsed_ms as f64);
        }
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
    fn quick_viability(
        &self,
        p: &dyn LoadedPcapView,
        file_size_bytes: u64,
    ) -> ProtoViability {
        use std::collections::HashSet;
        let ports: &[u16] = self.well_known_ports();
        let mut client_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut server_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut client_bytes = 0u64;
        let mut server_bytes = 0u64;
        for f in p.flows() {
            let (sip, sp) = match f.server { Some(x) => x, None => continue };
            if !ports.contains(&sp) { continue; }
            let (cip, _) = match f.client { Some(x) => x, None => continue };
            client_ips.insert(cip);
            server_ips.insert(sip);
            let (cb, sb) = p.flow_payload_bytes(f.flow_idx);
            client_bytes += cb;
            server_bytes += sb;
        }
        let m = client_ips.len() as u64;
        let s = server_ips.len() as u64;
        let max_sess = m.max(s);
        let mb = |b: u64| (b + 1024 * 1024 - 1) / (1024 * 1024);
        let est = mb(file_size_bytes) + mb(client_bytes.max(server_bytes)) + max_sess * 2 + 32;
        let (verdict, reason): (&str, String) = if max_sess == 0 {
            ("ok", format!("no flows for protocol {} on ports {:?}", self.name(), ports))
        } else {
            ("ok", format!("{} session(s) detected for {}", max_sess, self.name()))
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
    let mut r = ProtoReport::default();
    r.error = Some(format!(
        "proto_{name} is a v1 stub — fall back to raw or generic TCP session"
    ));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_latency_basic() {
        let mut r = ProtoReport::default();
        r.latency_samples_us = (1..=100).collect(); // 1..100 µs uniform
        r.messages_sent = 100;
        r.elapsed_ms = 100;
        r.finalize_latency();
        assert_eq!(r.latency_min_us, 1);
        assert_eq!(r.latency_max_us, 100);
        // With 100 evenly-spaced samples, p50 lands around the middle,
        // p99 lands near the top. Exact index is (n-1)*p rounded.
        assert!(r.latency_p50_us >= 49 && r.latency_p50_us <= 52, "p50 was {}", r.latency_p50_us);
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
}
