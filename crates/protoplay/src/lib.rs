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
    /// If true, every CP56Time2a timestamp field inside an IEC 104
    /// ASDU is rewritten to the wall-clock moment the carrying frame
    /// is actually emitted, so SCADA sees fresh timestamps while
    /// intra-pcap gaps are still honored by the scheduler. The IV
    /// (invalid) flag bit from the source field is preserved per
    /// element. The SU (summer-time) bit is set according to
    /// [`cp56_zone`] at encode time.
    pub rewrite_cp56_to_now: bool,
    /// Timezone convention used when `rewrite_cp56_to_now` is on.
    /// `"utc"` — bytes encode UTC, SU always 0. `"local"` — bytes
    /// encode the server's local calendar with SU following DST
    /// (matches most plant SCADA HMIs). Default: "local".
    pub cp56_zone: String,
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

/// The contract every protocol replayer must satisfy.
pub trait ProtoReplayer: Send + Sync {
    fn name(&self) -> &'static str;
    fn well_known_ports(&self) -> &'static [u16];
    fn readiness(&self) -> Readiness;
    fn run(&self, cfg: ProtoRunCfg) -> ProtoReport;
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
