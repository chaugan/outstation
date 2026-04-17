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

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8};
use std::sync::Arc;
use std::time::Duration;

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
        }
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
}

/// Minimal flow descriptor a viability impl needs.
#[derive(Debug, Clone, Copy)]
pub struct FlowView {
    pub flow_idx: usize,
    pub client: Option<(std::net::Ipv4Addr, u16)>,
    pub server: Option<(std::net::Ipv4Addr, u16)>,
    pub saw_syn: bool,
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
