//! Orchestrator: glue the topology, loader, rewriter, and replayer into
//! a single run. One bridge port per source, one replayer thread per
//! port. Raw-replay workers build their plans, meet at a start barrier
//! and then all pace against one shared epoch, so their relative
//! schedules agree (also across iterations).
//!
//! Host safety (interface names, protected NICs, journaled guards) is
//! enforced by `netctl`; this crate passes the run id, state directory
//! and [`netctl::Protection`] through and never deletes or reuses
//! anything it cannot prove it created.

use std::net::{IpAddr, Ipv4Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use netctl::{
    reclaim_run_ifaces, EgressGuard, GatewayGuard, IfaceNames, MacAddr, PortKind, Protection,
    Topology,
};
use pcapload::LoadedPcap;
use raw_replay::{
    now_ns, realtime_thread_budget, run_plan_at, schedule_offset_ns, try_set_realtime, Capture,
    Pace, Plan, RawReplayer, RunControls, RunStats, CAPTURE_RT_PRIORITY, REPLAY_RT_PRIORITY,
};
use rewrite::rewrite_in_place;
use tracing::{info, warn};

mod bench;
mod raw;
mod slave;

pub use bench::run_benchmark;
pub use raw::run;

use bench::*;
#[cfg(test)]
use raw::*;
use slave::*;

/// Shared, concurrent view of a running replay. Cloned into the
/// webui's `RunState` so HTTP handlers can read live progress
/// without locking the sched thread. All counters are relaxed —
/// eventually-consistent cross-field reads are acceptable for the UI.
///
/// Units: `planned`/`sent`/`bytes` always count frames (raw) or
/// protocol messages (benchmark), never sessions. Sessions are counted
/// separately in `sessions_total`/`sessions_done`. Prefer
/// [`RunContext::progress`] over reading the atomics directly.
#[derive(Clone, Default)]
pub struct RunContext {
    /// Run-level cancel. Workers exit within ~100 ms of it flipping.
    /// [`RunContext::cancel_all`] also flips every per-session flag.
    pub cancel: Arc<AtomicBool>,
    /// Total frames (raw) the whole run plans to send, across all
    /// iterations. 0 = unknown up front (benchmark, or unlimited
    /// iterations).
    pub planned: Arc<AtomicU64>,
    /// Frames/messages sent so far, monotonic across iterations. Raw
    /// mode updates it live; benchmark mode adds each session
    /// iteration's total when that iteration ends.
    pub sent: Arc<AtomicU64>,
    /// Wire bytes (raw) / payload bytes (benchmark), like `sent`.
    pub bytes: Arc<AtomicU64>,
    /// Total send errors across all workers.
    pub send_errors: Arc<AtomicU64>,
    /// Benchmark: sessions in the run.
    pub sessions_total: Arc<AtomicU64>,
    /// Benchmark: sessions that have finished (any outcome).
    pub sessions_done: Arc<AtomicU64>,
    /// Monotonic-clock nanoseconds of the shared replay epoch / first
    /// send (0 until then). Used for throughput derivation.
    pub started_packets_at_ns: Arc<AtomicU64>,
    /// Per-worker progress. Indexed by worker position; each entry has
    /// its own atomics so workers don't contend on the global counters.
    pub per_source: Arc<Mutex<Vec<SourceProgress>>>,
}

/// Point-in-time progress summary, see [`RunContext::progress`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgressSnapshot {
    /// Frames/messages sent so far, all sources, all iterations (live).
    pub frames_sent_total: u64,
    /// Bytes sent so far, all sources, all iterations (live).
    pub bytes_sent_total: u64,
    /// Whole-run plan (raw, bounded iterations); 0 if unknown.
    pub frames_planned_total: u64,
    /// Sum of each source's current-iteration count. Together with
    /// `iteration_planned` this gives a per-iteration percentage that
    /// never exceeds 100%.
    pub iteration_sent: u64,
    pub iteration_planned: u64,
    pub sessions_done: u64,
    pub sessions_total: u64,
}

impl RunContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the run-level cancel has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Cancel the run and every session in it.
    pub fn cancel_all(&self) {
        self.cancel.store(true, Ordering::Relaxed);
        for p in self.sources().iter() {
            p.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Lock the per-source table, tolerating poisoning (a panicked
    /// worker must not take the UI down with it).
    pub fn sources(&self) -> MutexGuard<'_, Vec<SourceProgress>> {
        self.per_source.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Consistent-enough progress numbers for the UI. Throughput
    /// samplers should difference `frames_sent_total` (monotonic).
    pub fn progress(&self) -> ProgressSnapshot {
        let sp = self.sources();
        let mut s = ProgressSnapshot {
            frames_planned_total: self.planned.load(Ordering::Relaxed),
            sessions_done: self.sessions_done.load(Ordering::Relaxed),
            sessions_total: self.sessions_total.load(Ordering::Relaxed),
            ..Default::default()
        };
        for p in sp.iter() {
            s.frames_sent_total += p.snapshot_sent_total();
            s.bytes_sent_total += p.snapshot_bytes_total();
            s.iteration_sent += p.snapshot_sent();
            s.iteration_planned += p.snapshot_planned();
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct SourceProgress {
    pub src_ip: Option<Ipv4Addr>,
    pub src_mac: MacAddr,
    pub tap: String,
    /// Frames (raw replay) or client messages (benchmark) the worker
    /// plans to send **per iteration**. Raw mode sets it once; in
    /// benchmark mode the protocol module fills it in after parsing.
    pub planned: Arc<AtomicU64>,
    /// Sent in the current iteration (reset at each iteration start).
    pub sent: Arc<AtomicU64>,
    /// Bytes in the current iteration (reset at each iteration start).
    pub bytes: Arc<AtomicU64>,
    /// Sum of `sent` over completed iterations. `sent_done_iters + sent`
    /// is the monotonic total, see [`SourceProgress::snapshot_sent_total`].
    pub sent_done_iters: Arc<AtomicU64>,
    /// Sum of `bytes` over completed iterations.
    pub bytes_done_iters: Arc<AtomicU64>,
    /// Seqlock counter of the fold of `sent`/`bytes` into the
    /// `*_done_iters` totals (see [`protoplay::fold_counters`]), shared
    /// with the protocol module's [`protoplay::MessageProgress`].
    pub fold_seq: Arc<AtomicU64>,
    /// Benchmark-only: server messages received by this session.
    pub received: Arc<AtomicU64>,
    /// Benchmark-only: messages sent but not yet acknowledged.
    pub unacked: Arc<AtomicU64>,
    /// Slave-benchmark gate: the listener thread waits on this flag
    /// before binding its TcpListener. The webui flips it to true when
    /// the user clicks the per-slave "start listening" button.
    /// Raw replay and master benchmark workers set it to `true` at
    /// worker creation so they never wait.
    pub ready: Arc<AtomicBool>,
    /// Session lifecycle state, one of `protoplay::session_state::*`.
    pub state: Arc<AtomicU8>,
    /// Per-session cancel flag. Independent of `RunContext::cancel`
    /// so a single RTU can be stopped without killing the run.
    pub cancel: Arc<AtomicBool>,
    /// Slave-benchmark: the TCP port this session listens on. Zero
    /// for any other mode.
    pub listen_port: u16,
    /// Slave-benchmark: the local address the listener binds to
    /// (defaults to the RTU's captured IP). Editable per-slave via
    /// PATCH /api/runs/:id/slaves/:idx before the slave starts.
    pub listen_ip: Arc<Mutex<Ipv4Addr>>,
    /// Current iteration number (1-based); `0` before the first one.
    pub iter_current: Arc<AtomicU64>,
    /// Total iterations planned (`0` = unlimited / loop until cancel).
    pub iter_total: Arc<AtomicU64>,
    /// Why the session failed; set together with the `FAILED` state.
    /// `None` while running and for completed or cancelled sessions.
    pub error: Arc<Mutex<Option<String>>>,
    /// Benchmark-only: ack latency of every acknowledged message so
    /// far (all iterations), shared with the protocol module's
    /// [`protoplay::MessageProgress::ack_latency`].
    pub ack_latency: Arc<protoplay::LiveLatencyHist>,
}

impl SourceProgress {
    fn new(
        src_ip: Option<Ipv4Addr>,
        src_mac: MacAddr,
        tap: String,
        state: u8,
        ready: bool,
    ) -> Self {
        Self {
            src_ip,
            src_mac,
            tap,
            planned: Default::default(),
            sent: Default::default(),
            bytes: Default::default(),
            sent_done_iters: Default::default(),
            bytes_done_iters: Default::default(),
            fold_seq: Default::default(),
            received: Default::default(),
            unacked: Default::default(),
            ready: Arc::new(AtomicBool::new(ready)),
            state: Arc::new(AtomicU8::new(state)),
            cancel: Default::default(),
            listen_port: 0,
            listen_ip: Arc::new(Mutex::new(Ipv4Addr::UNSPECIFIED)),
            iter_current: Default::default(),
            iter_total: Default::default(),
            error: Default::default(),
            ack_latency: Default::default(),
        }
    }

    pub fn snapshot_sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn snapshot_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
    /// Monotonic total across iterations (never dips, also not while
    /// an iteration starts).
    pub fn snapshot_sent_total(&self) -> u64 {
        protoplay::read_folded(&self.fold_seq, &self.sent, &self.sent_done_iters)
    }
    /// Monotonic total across iterations.
    pub fn snapshot_bytes_total(&self) -> u64 {
        protoplay::read_folded(&self.fold_seq, &self.bytes, &self.bytes_done_iters)
    }
    pub fn snapshot_planned(&self) -> u64 {
        self.planned.load(Ordering::Relaxed)
    }
    pub fn snapshot_received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
    pub fn snapshot_unacked(&self) -> u64 {
        self.unacked.load(Ordering::Relaxed)
    }
    pub fn snapshot_state(&self) -> u8 {
        self.state.load(Ordering::Relaxed)
    }
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    pub fn snapshot_listen_ip(&self) -> Ipv4Addr {
        *self.listen_ip.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Ack-latency histogram so far (benchmark sessions).
    pub fn snapshot_ack_latency(&self) -> protoplay::LatencyHistSnapshot {
        self.ack_latency.snapshot()
    }
    /// The session's failure reason, if it failed.
    pub fn snapshot_error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Record the terminal state; a `FAILED` state also records `error`.
    fn set_final(&self, state: u8, error: Option<&str>) {
        *self.error.lock().unwrap_or_else(|e| e.into_inner()) =
            if state == protoplay::session_state::FAILED {
                Some(error.unwrap_or("session failed").to_string())
            } else {
                None
            };
        self.state.store(state, Ordering::Relaxed);
    }

    /// Start iteration `iter` (1-based): fold the previous iteration's
    /// counters into the `*_done_iters` totals and reset the
    /// per-iteration ones, as one step for readers of the totals (N5:
    /// they never see a dip). Called by the sending thread.
    pub fn begin_iteration(&self, iter: u64) {
        protoplay::fold_counters(
            &self.fold_seq,
            &[
                (&self.sent, &self.sent_done_iters),
                (&self.bytes, &self.bytes_done_iters),
            ],
        );
        self.received.store(0, Ordering::Relaxed);
        self.unacked.store(0, Ordering::Relaxed);
        self.iter_current.store(iter, Ordering::Relaxed);
    }

    fn message_progress(&self, run_cancel: &Arc<AtomicBool>) -> protoplay::MessageProgress {
        protoplay::MessageProgress {
            planned: Arc::clone(&self.planned),
            sent: Arc::clone(&self.sent),
            sent_done_iters: Arc::clone(&self.sent_done_iters),
            bytes_done_iters: Arc::clone(&self.bytes_done_iters),
            fold_seq: Arc::clone(&self.fold_seq),
            received: Arc::clone(&self.received),
            bytes_written: Arc::clone(&self.bytes),
            bytes_read: Arc::new(AtomicU64::new(0)),
            unacked: Arc::clone(&self.unacked),
            ready: Arc::clone(&self.ready),
            state: Arc::clone(&self.state),
            cancel: Arc::clone(&self.cancel),
            iter_current: Arc::clone(&self.iter_current),
            iter_total: Arc::clone(&self.iter_total),
            run_cancel: Arc::clone(run_cancel),
            ack_latency: Arc::clone(&self.ack_latency),
        }
    }
}

/// Sleep for `dur`, returning early (within 100 ms) once `cancelled()`.
fn sleep_interruptible(dur: Duration, cancelled: impl Fn() -> bool) {
    protoplay::sleep_cancellable(dur, cancelled);
}

/// Warm-up pause between bringing a run's interfaces up and sending.
/// Returns `false` when the run was cancelled during it.
fn warmup_elapsed(ctx: &RunContext, secs: u64) -> bool {
    sleep_interruptible(Duration::from_secs(secs), || ctx.is_cancelled());
    !ctx.is_cancelled()
}

/// Spawn a named worker or session thread inside the caller's tracing
/// span (the webui's `run{id}`), so its log lines carry the run id
/// (F079).
fn spawn_named<T: Send + 'static>(
    name: String,
    body: impl FnOnce() -> T + Send + 'static,
) -> std::io::Result<thread::JoinHandle<T>> {
    // The caller's dispatcher too, so a scoped (thread-local)
    // subscriber, as in tests, also sees the thread's events.
    let dispatch = tracing::dispatcher::get_default(|d| d.clone());
    let span = tracing::Span::current();
    thread::Builder::new().name(name).spawn(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            let _entered = span.enter();
            body()
        })
    })
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Run id. Names the run's interfaces (see [`netctl::IfaceNames`]),
    /// tags its ownership markers and iptables comments.
    pub run_id: u64,
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    /// Bridge name override (`^pcr[a-z0-9_]{0,8}$`). `None` derives it
    /// from `run_id` (recommended).
    pub bridge_name: Option<String>,
    /// Port-name prefix override (`^pcr[a-z0-9_]{0,8}$`). `None`
    /// derives it from `run_id` (recommended).
    pub tap_prefix: Option<String>,
    /// Physical NIC to enslave. Refused if protected (default route,
    /// protected address, bridge, bridge port) unless
    /// `force_protected_nic`.
    pub egress_nic: Option<String>,
    pub speed: f64,
    pub top_speed: bool,
    /// Put replay workers on SCHED_FIFO. Ignored with `top_speed`, and
    /// at most `cores - 1` workers are promoted.
    pub realtime: bool,
    /// If Some, only these source IPs are replayed. If None, every IPv4
    /// source in the pcap gets its own port.
    pub filter_sources: Option<Vec<Ipv4Addr>>,
    /// Also replay non-IP (GOOSE/SV/raw L2) sources, indexed by src MAC.
    /// Each non-IP MAC gets its own port; frames are injected verbatim.
    pub include_non_ip: bool,
    /// Seconds to wait between bringing the bridge + per-source ports
    /// up and actually injecting packets. Gives the caller a window to
    /// attach Wireshark/tcpdump to the now-visible interfaces before
    /// frames start flowing.
    pub startup_delay_secs: u64,
    /// If Some, capture every frame that flows through the bridge to
    /// this pcap file.
    pub capture_path: Option<PathBuf>,
    /// Largest capture file in bytes; at the cap the capture stops
    /// recording and the report says `capture_truncated`. `None` = no
    /// cap.
    pub capture_max_bytes: Option<u64>,
    /// Number of times to replay the pcap. `0` means loop forever
    /// until cancelled. Passes are aligned on the shared epoch:
    /// pass `k` starts at `epoch + k * (pcap span / speed + 1 ms)`.
    pub iterations: u64,
    /// Directory holding the crash-recovery journals. `None` uses
    /// [`netctl::DEFAULT_STATE_DIR`].
    pub state_dir: Option<PathBuf>,
    /// Addresses whose NICs must never be enslaved (the web server's
    /// own local address, typically).
    pub protected_addrs: Vec<IpAddr>,
    /// Explicit operator override for protected NICs.
    pub force_protected_nic: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            run_id: 0,
            target_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: [0; 6],
            bridge_name: None,
            tap_prefix: None,
            egress_nic: None,
            speed: 1.0,
            top_speed: false,
            realtime: false,
            filter_sources: None,
            include_non_ip: true,
            startup_delay_secs: 0,
            capture_path: None,
            capture_max_bytes: None,
            iterations: 1,
            state_dir: None,
            protected_addrs: Vec::new(),
            force_protected_nic: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceReport {
    /// None for non-IP (L2-only) sources.
    pub src_ip: Option<Ipv4Addr>,
    pub src_mac: MacAddr,
    pub tap: String,
    pub kind: SourceKind,
    pub stats: RunStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Ipv4,
    NonIp,
}

#[derive(Debug, Clone, Default)]
pub struct RunReport {
    pub per_source: Vec<SourceReport>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
    /// Path to the pcap the replay was captured into, if
    /// [`RunConfig::capture_path`] was set.
    pub capture_path: Option<PathBuf>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
    /// Frames the capture lost to a full kernel queue (the capture file
    /// is missing them; its analysis under-counts delivery).
    pub captured_dropped: u64,
    /// The capture reached [`RunConfig::capture_max_bytes`] and holds
    /// only the start of the run.
    pub capture_truncated: bool,
    /// The capture recorded what it had to: `false` when one was
    /// requested but could not be opened on every interface it needed,
    /// or holds no frame although frames were sent. `true` when no
    /// capture was requested.
    pub capture_ok: bool,
    /// Non-fatal problems (guard warnings, realtime policy, worker
    /// errors, capture and teardown failures) worth showing in the
    /// run's status.
    pub warnings: Vec<String>,
}

fn state_dir_or_default(d: &Option<PathBuf>) -> PathBuf {
    d.clone()
        .unwrap_or_else(|| PathBuf::from(netctl::DEFAULT_STATE_DIR))
}

/// Everything a run sets up on the host. Fields drop in declaration
/// order, which is the teardown order: capture, topology (deletes the
/// bridge, which frees an enslaved NIC), then the guards. So any early
/// return still leaves the host clean.
#[derive(Default)]
struct RunResources {
    capture: Option<Capture>,
    topo: Option<Topology>,
    egress: Option<EgressGuard>,
    gateway: Option<GatewayGuard>,
}

impl RunResources {
    /// Explicit teardown that reports what went wrong.
    fn finish(mut self, warnings: &mut Vec<String>) {
        if let Some(c) = self.capture.take() {
            c.stop();
        }
        if let Some(t) = self.topo.take() {
            if let Err(e) = t.teardown() {
                warn!(error = %e, "topology teardown had errors");
                warnings.push(format!("topology teardown: {e:#}"));
            }
        }
        if let Some(g) = self.egress.take() {
            if let Err(e) = g.release() {
                warn!(error = %format!("{e:#}"), "egress guard restore failed");
                warnings.push(format!("egress guard restore: {e:#}"));
            }
        }
        if let Some(g) = self.gateway.take() {
            if let Err(e) = g.release() {
                warn!(error = %format!("{e:#}"), "gateway guard restore failed");
                warnings.push(format!("gateway guard restore: {e:#}"));
            }
        }
    }
}

/// Create the bridge, enslave the egress NIC and install the egress
/// guard. Fails closed: any error leaves nothing behind.
fn bring_up_topology(
    res: &mut RunResources,
    names: &IfaceNames,
    egress_nic: Option<&str>,
    peer: Ipv4Addr,
    peer_port: Option<u16>,
    state_dir: &Path,
    prot: &Protection,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if let Some(nic) = egress_nic {
        // Check before touching anything.
        netctl::check_nic_allowed(nic, "enslave", prot)?;
    }
    match reclaim_run_ifaces(names.run_id) {
        Ok(n) if n > 0 => info!(count = n, "reclaimed stale interfaces of this run id"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "reclaim of stale run interfaces failed"),
    }
    let mut topo = Topology::new(&names.bridge, names.run_id)?;
    // Isolate the run's interfaces from the host stack before any
    // exists (fail closed): only `peer` may reach session addresses.
    topo.harden(&names.tap_prefix, Some(peer), peer_port, state_dir)
        .context("isolate run interfaces from the host")?;
    topo.create_bridge().context("create bridge")?;
    res.topo = Some(topo);
    if let Some(nic) = egress_nic {
        let topo = res.topo.as_mut().context("topology missing")?;
        topo.enslave_existing(nic, prot)
            .with_context(|| format!("enslave {nic}"))?;
        info!(nic, "enslaved egress NIC");
        let guard = EgressGuard::install(&names.bridge, nic, names.run_id, state_dir)
            .with_context(|| format!("egress safety guard for {nic}"))?;
        warnings.extend(guard.warnings().iter().cloned());
        res.egress = Some(guard);
    }
    Ok(())
}

/// Start the run's mirror capture. Returns `false` if it could not
/// record everything it should (no capture, or the replies on an
/// enslaved NIC are not recorded); the reason is in `warnings`.
fn start_capture(
    res: &mut RunResources,
    names: &IfaceNames,
    path: &Path,
    opts: CaptureOpts,
    warnings: &mut Vec<String>,
) -> bool {
    // Two vantage points, so that every wire frame of the run is
    // recorded exactly once (B1):
    // * a dedicated dummy device every run port mirrors its *ingress*
    //   to (tc mirred): each replayed or session frame, once, as it
    //   enters the bridge, however often the bridge floods it;
    // * the enslaved NIC, incoming only and only frames addressed to
    //   the run's MACs (or broadcast/multicast): the target's replies.
    //   Its outgoing frames are the ports' frames, already recorded.
    // Not the bridge device (it sees only a fraction of forwarded
    // traffic), nor an extra bridge port (only floods once MACs are
    // learned), nor port egress (a flood is seen once per port).
    let port = match names.capture_port() {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!("capture disabled: {e:#}"));
            return false;
        }
    };
    let Some(topo) = res.topo.as_mut() else {
        warnings.push("capture disabled: no topology".into());
        return false;
    };
    if let Err(e) = topo.add_capture_mirror(&port) {
        warn!(error = %format!("{e:#}"), "could not create capture mirror");
        warnings.push(format!("could not create capture mirror: {e:#}"));
        return false;
    }
    let cap = match Capture::start_with_priority(&port, path, opts.rt_priority) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, path = %path.display(), "capture failed to start");
            warnings.push(format!("capture failed to start: {e:#}"));
            return false;
        }
    };
    cap.set_max_bytes(opts.max_bytes);
    let mut complete = true;
    let filter = raw_replay::bpf::incoming_to_macs_filter(topo.port_macs());
    for nic in topo.enslaved() {
        let added = cap.add_iface_with_filter(nic, &filter).or_else(|e| {
            // The kernel charges a socket filter against
            // net.core.optmem_max: with a few hundred session MACs the
            // per-MAC filter no longer fits (ENOMEM above ~527 MACs at
            // the 128 KiB default, ~81 at the older 20 KiB one). Record
            // every incoming frame instead of no replies at all.
            warn!(nic, error = %format!("{e:#}"),
                "capture: per-MAC reply filter rejected; recording every incoming frame on the NIC");
            warnings.push(format!(
                "capture on {nic}: the per-MAC reply filter for {} sessions did not fit \
                 ({e:#}); every incoming frame on {nic} is recorded, including other LAN traffic",
                topo.port_macs().len()
            ));
            let all = raw_replay::bpf::skip_outgoing(&raw_replay::bpf::accept_all());
            cap.add_iface_with_filter(nic, &all)
        });
        if let Err(e) = added {
            warn!(nic, error = %format!("{e:#}"), "capture: cannot record replies on the NIC");
            warnings.push(format!(
                "capture records no replies from the target: capture on {nic} failed: {e:#}"
            ));
            complete = false;
        }
    }
    info!(path = %path.display(), ifaces = ?cap.ifaces(), "capture started");
    res.capture = Some(cap);
    complete
}

/// SCHED_FIFO priority of every run's capture reader, whatever the
/// run's `realtime` setting (T17c, reverting N8). The promotion is best
/// effort: without `CAP_SYS_NICE` (or with no RT budget)
/// [`try_set_realtime`] fails quietly and the reader keeps the default
/// policy.
///
/// Why always: the reader only ever blocks in `poll` and then drains
/// what the kernel queued, and its kernel filter limits that to the
/// run's own traffic, so the CPU it can take is bounded by the run's
/// frame rate and it cannot spin; the kernel's RT throttling
/// (`sched_rt_runtime_us`) bounds it further. The risk of starving
/// other tasks is therefore small, while a reader that loses the CPU to
/// the run's own sessions overflows its socket queue, and every frame
/// lost there corrupts the analysis verdict (full-speed slave-200: 46 k
/// frames dropped at RT priority, 237 k without; scale report §6.5).
pub(crate) fn capture_rt_priority() -> Option<i32> {
    Some(CAPTURE_RT_PRIORITY)
}

/// Capture settings of a run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CaptureOpts {
    /// SCHED_FIFO priority of the reader thread, if any.
    rt_priority: Option<i32>,
    /// Byte cap of the capture file.
    max_bytes: Option<u64>,
}

/// What became of a run's capture, for the report.
#[derive(Debug, Default)]
struct CaptureOutcome {
    stats: Option<raw_replay::CaptureStats>,
    /// Requested but not (fully) opened.
    open_failed: bool,
    requested: bool,
}

impl CaptureOutcome {
    /// `capture_ok` given whether frames or messages were sent.
    fn ok(&self, traffic_sent: bool) -> bool {
        if !self.requested {
            return true;
        }
        let header_only = self.stats.as_ref().is_none_or(|st| st.packets == 0);
        !self.open_failed && !(traffic_sent && header_only)
    }
}

/// Stop the capture (after a short delay for frames still in flight)
/// and return its counters; a lossy capture adds a warning.
fn finish_capture(c: Capture, warnings: &mut Vec<String>) -> raw_replay::CaptureStats {
    std::thread::sleep(Duration::from_millis(200));
    let st = c.finish();
    info!(
        packets = st.packets,
        bytes = st.bytes,
        dropped = st.dropped,
        "capture stopped"
    );
    if st.dropped > 0 {
        warnings.push(format!(
            "capture lost {} frames (kernel receive queue full); its analysis may report \
             frames as missing that were delivered",
            st.dropped
        ));
    }
    if st.truncated {
        warnings.push(format!(
            "capture stopped at its byte cap after {} frames ({} bytes); it holds only the \
             start of the run",
            st.packets, st.bytes
        ));
    }
    st
}

impl RunReport {
    /// Record the capture's outcome (counters, truncation, `capture_ok`).
    fn set_capture(&mut self, c: &CaptureOutcome) {
        if let Some(st) = &c.stats {
            self.capture_path = Some(st.path.clone());
            self.captured_packets = st.packets;
            self.captured_bytes = st.bytes;
            self.captured_dropped = st.dropped;
            self.capture_truncated = st.truncated;
        }
        self.capture_ok = c.ok(self.total_packets > 0);
    }
}

impl BenchmarkReport {
    /// Record the capture's outcome (counters, truncation, `capture_ok`).
    fn set_capture(&mut self, c: &CaptureOutcome) {
        if let Some(st) = &c.stats {
            self.capture_path = Some(st.path.clone());
            self.captured_packets = st.packets;
            self.captured_bytes = st.bytes;
            self.captured_dropped = st.dropped;
            self.capture_truncated = st.truncated;
        }
        let traffic = self.total_messages_sent + self.total_messages_received > 0;
        self.capture_ok = c.ok(traffic);
    }
}

/// [`finish_capture`] for a run's mirror capture.
fn collect_capture(
    res: &mut RunResources,
    warnings: &mut Vec<String>,
) -> Option<raw_replay::CaptureStats> {
    res.capture.take().map(|c| finish_capture(c, warnings))
}

// -----------------------------------------------------------------------------
// Benchmark mode (v1.1): stateful session replay driving a real live target.
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrencyModel {
    /// All sessions open simultaneously. Pure load-test shape.
    AllAtOnce,
    /// Sessions start at the relative times their SYNs appeared in the
    /// original capture. Preserves the original load profile.
    StaggeredPcapTiming,
}

#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Run id: names interfaces, tags markers and iptables comments.
    pub run_id: u64,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    /// Name of the ProtoReplayer module to use (e.g. "iec104").
    pub proto_name: String,
    /// Bridge name override; `None` derives it from `run_id`.
    pub bridge_name: Option<String>,
    /// Port-name prefix override; `None` derives it from `run_id`.
    pub tap_prefix: Option<String>,
    pub egress_nic: Option<String>,
    pub concurrency: ConcurrencyModel,
    pub connect_timeout_secs: u64,
    pub startup_delay_secs: u64,
    pub capture_path: Option<PathBuf>,
    /// Largest capture file in bytes; see [`RunConfig::capture_max_bytes`].
    pub capture_max_bytes: Option<u64>,
    /// Accepted for symmetry with raw mode; a benchmark's sessions are
    /// not real-time threads. The capture reader runs at SCHED_FIFO
    /// whether or not this is set ([`capture_rt_priority`]).
    pub realtime: bool,
    /// Free-form JSON/YAML passed through to the ProtoReplayer.
    pub proto_config: Option<String>,
    /// Which side of the captured conversation the tool plays.
    /// `Master` (default) = outstation connects out as the client of
    /// `target_ip:target_port`. `Slave` = outstation binds a listener
    /// per captured RTU and waits for the target master to connect in.
    pub role: protoplay::Role,
    /// Slave-only: TCP port every listener binds on top of its
    /// per-session `listen_ip`. Default 2404.
    pub listen_port_base: u16,
    /// How the replayer should pace its own I-frame sends.
    pub pacing: protoplay::Pacing,
    /// Number of times to repeat the captured script. `0` means
    /// loop forever until cancelled. Default `1`.
    pub iterations: u64,
    /// SCADA-gateway mode (see doc/scada-lab.md). When
    /// `scada_gateway_ip` is set, the run installs a /32 alias for
    /// this IP on `scada_gateway_iface` for the duration of the run.
    /// If `upstream_nat_iface` is also set, IP forwarding is enabled
    /// and a tagged MASQUERADE rule is added. All side effects are
    /// journaled and undone on run teardown.
    pub scada_gateway_ip: Option<Ipv4Addr>,
    pub scada_gateway_iface: Option<String>,
    pub upstream_nat_iface: Option<String>,
    /// Slave-only: NIC that receives `/32 noprefixroute` aliases for
    /// listen IPs that are not already local. `None` falls back to the
    /// default-route NIC, which is protected and therefore refused
    /// unless `force_protected_nic` is set.
    pub alias_iface: Option<String>,
    /// Directory holding the crash-recovery journals (aliases and
    /// guards). `None` uses [`netctl::DEFAULT_STATE_DIR`].
    pub state_dir: Option<PathBuf>,
    /// Addresses whose NICs must never be enslaved or aliased.
    pub protected_addrs: Vec<IpAddr>,
    /// Explicit operator override for protected NICs.
    pub force_protected_nic: bool,
    /// Master-mode only: override the per-session bind IP.
    pub master_bind_ip: Option<Ipv4Addr>,
    /// Whether to set TCP_NODELAY on each session's socket. `None`
    /// resolves to the role default (slave true, master false).
    pub tcp_nodelay: Option<bool>,
    /// Optional subset of captured endpoints to actually run (server
    /// IPs in slave mode, client IPs in master mode).
    pub selected_endpoints: Option<std::collections::HashSet<Ipv4Addr>>,
    /// Slave-only: replay the script `iterations` times inside a
    /// single TCP session instead of reconnecting per iteration.
    pub loop_within_session: bool,
    /// Master-only: pause between two iterations of a session (each
    /// iteration is one connection), whatever the pacing. Connect
    /// failures of an unbounded run back off from here. See
    /// [`IterationPolicy`].
    pub iteration_gap: Duration,
}

/// Default [`BenchmarkConfig::iteration_gap`].
pub const DEFAULT_ITERATION_GAP: Duration = Duration::from_secs(1);
/// Longest wait between reconnect attempts of an unbounded master run
/// whose target refuses or does not answer.
pub const MAX_CONNECT_BACKOFF: Duration = Duration::from_secs(30);
/// Base of the connect backoff when the configured gap is shorter.
const MIN_CONNECT_BACKOFF: Duration = Duration::from_millis(500);

/// How a master session spaces its iterations (O1). Without it an
/// unbounded run on a short capture reconnected 8-12 times a second:
/// each iteration ended right after its last I-frame was acknowledged.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IterationPolicy {
    /// Shortest iteration, measured from its start: with original
    /// timing, the captured flow's span (first to last packet, either
    /// direction) divided by the speed, so the server's trailing
    /// traffic gets its time too. Zero otherwise.
    pub min_iteration: Duration,
    /// Pause after every iteration (but the last).
    pub gap: Duration,
    /// Unbounded runs retry a connection that failed, backing off
    /// exponentially (from `max(gap, 500 ms)`, doubling, capped at
    /// [`MAX_CONNECT_BACKOFF`]). Bounded runs stop at the first error.
    pub retry_connect: bool,
}

impl IterationPolicy {
    /// The policy of a master session of `cfg` whose captured flow
    /// spans `flow_span_ns`.
    pub fn for_master(cfg: &BenchmarkConfig, flow_span_ns: u64) -> Self {
        let min_iteration = match cfg.pacing {
            protoplay::Pacing::OriginalTiming { speed } if speed > 0.0 && speed.is_finite() => {
                Duration::from_secs_f64(flow_span_ns as f64 / 1e9 / speed)
            }
            _ => Duration::ZERO,
        };
        Self {
            min_iteration,
            gap: cfg.iteration_gap,
            retry_connect: cfg.iterations == 0,
        }
    }

    /// How long to wait after an iteration that took `elapsed`, with
    /// `connect_failures` failed connections in a row (0 after a
    /// successful one).
    pub fn wait_after(&self, elapsed: Duration, connect_failures: u32) -> Duration {
        if connect_failures > 0 {
            let base = self.gap.max(MIN_CONNECT_BACKOFF);
            let factor = 1u32 << (connect_failures - 1).min(16);
            return base.saturating_mul(factor).min(MAX_CONNECT_BACKOFF);
        }
        self.min_iteration.saturating_sub(elapsed) + self.gap
    }
}

/// Outcome of [`master_iterations`].
#[derive(Debug, Default)]
pub struct MasterLoopOutcome {
    pub report: protoplay::ProtoReport,
    /// Stopped by a cancel (before the planned iterations were done).
    pub cancelled_mid_run: bool,
    /// Iterations started, including failed connection attempts.
    pub attempts: u64,
}

/// Run up to `target_iters` iterations of one master session with
/// `run_one(iteration index)`, spaced by `policy`, merging their
/// reports. Stops at the first error, except a failed connection of a
/// run that retries ([`IterationPolicy::retry_connect`]), and when
/// `cancelled` turns true (also during a wait).
pub fn master_iterations(
    target_iters: u64,
    policy: IterationPolicy,
    cancelled: &dyn Fn() -> bool,
    mut run_one: impl FnMut(u64) -> protoplay::ProtoReport,
) -> MasterLoopOutcome {
    let mut acc = SessionAccumulator::new();
    let mut out = MasterLoopOutcome::default();
    let mut connect_failures = 0u32;
    let mut last_connect_error: Option<String> = None;
    let mut iter_idx = 0u64;
    while iter_idx < target_iters {
        if cancelled() {
            out.cancelled_mid_run = true;
            break;
        }
        let started = std::time::Instant::now();
        let r = run_one(iter_idx);
        out.attempts += 1;
        let retry = r.error.is_some() && !r.connected && policy.retry_connect;
        if retry {
            // Not an iteration: the target was unreachable. Keep only
            // the error text for the record, and retry later.
            connect_failures = connect_failures.saturating_add(1);
            last_connect_error.clone_from(&r.error);
            warn!(
                attempt = connect_failures,
                error = ?r.error,
                "master: connection failed; retrying after a backoff"
            );
        } else {
            connect_failures = 0;
            let had_error = r.error.is_some();
            merge_proto_report(&mut acc, r);
            iter_idx += 1;
            if had_error || iter_idx >= target_iters {
                break;
            }
        }
        let wait = policy.wait_after(started.elapsed(), connect_failures);
        sleep_interruptible(wait, cancelled);
    }
    if cancelled() && iter_idx < target_iters {
        out.cancelled_mid_run = true;
    }
    out.report = acc.into_report();
    if let (None, Some(e)) = (&out.report.error, last_connect_error) {
        if !out.report.connected {
            out.report.error = Some(e);
        }
    }
    out
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            run_id: 0,
            target_ip: Ipv4Addr::UNSPECIFIED,
            target_port: 2404,
            proto_name: "iec104".into(),
            bridge_name: None,
            tap_prefix: None,
            egress_nic: None,
            concurrency: ConcurrencyModel::AllAtOnce,
            connect_timeout_secs: 5,
            startup_delay_secs: 0,
            capture_path: None,
            capture_max_bytes: None,
            realtime: false,
            proto_config: None,
            role: protoplay::Role::Master,
            listen_port_base: 2404,
            pacing: protoplay::Pacing::AsFastAsPossible,
            iterations: 1,
            scada_gateway_ip: None,
            scada_gateway_iface: None,
            upstream_nat_iface: None,
            alias_iface: None,
            state_dir: None,
            protected_addrs: Vec::new(),
            force_protected_nic: false,
            master_bind_ip: None,
            tcp_nodelay: None,
            selected_endpoints: None,
            loop_within_session: false,
            iteration_gap: DEFAULT_ITERATION_GAP,
        }
    }
}

/// How well a reassembled flow side replays ([`protoplay::FlowQuality`]).
pub(crate) fn replay_quality(r: &pcapload::ReassembledFlow) -> protoplay::FlowQuality {
    let gaps: Vec<usize> = r.gaps.iter().map(|g| g.offset).collect();
    protoplay::FlowQuality::new(r.payload.len(), &gaps, r.missing_bytes())
}

/// Keep the best of several candidate flows per IP: `candidates` are
/// `(flow index, endpoint IP)`; each is reassembled and replaces the
/// IP's current best only if `quality` ranks it strictly better (ties
/// keep the earlier flow). Only the current best per IP is held.
/// Returns `(flow index, ip, reassembly)` in the order the IPs first
/// reassembled. A failed reassembly is logged and skipped.
pub(crate) fn best_flow_per_ip<T>(
    candidates: impl IntoIterator<Item = (usize, Ipv4Addr)>,
    mut reassemble: impl FnMut(usize) -> Result<T>,
    quality: impl Fn(&T) -> protoplay::FlowQuality,
) -> Vec<(usize, Ipv4Addr, T)> {
    let mut order: Vec<Ipv4Addr> = Vec::new();
    let mut best: std::collections::HashMap<Ipv4Addr, (usize, protoplay::FlowQuality, T)> =
        Default::default();
    let mut flows_seen: std::collections::HashMap<Ipv4Addr, usize> = Default::default();
    for (idx, ip) in candidates {
        *flows_seen.entry(ip).or_default() += 1;
        let t = match reassemble(idx) {
            Ok(t) => t,
            Err(e) => {
                warn!(flow = idx, %ip, error = %e, "reassembly failed; trying the next flow");
                continue;
            }
        };
        let q = quality(&t);
        match best.get(&ip) {
            None => {
                order.push(ip);
                best.insert(ip, (idx, q, t));
            }
            Some((_, cur, _)) if q.better_than(cur) => {
                best.insert(ip, (idx, q, t));
            }
            Some(_) => {}
        }
    }
    order
        .into_iter()
        .filter_map(|ip| {
            let (idx, q, t) = best.remove(&ip)?;
            let n = flows_seen.get(&ip).copied().unwrap_or(1);
            if n > 1 {
                info!(%ip, flow = idx, flows = n, gaps = q.gaps, bytes = q.payload_bytes,
                    "endpoint has several flows; replaying the most contiguous, largest");
            }
            Some((idx, ip, t))
        })
        .collect()
}

/// The flow each endpoint replays, keyed by endpoint (client IP in
/// master role, server IP in slave role), exactly as
/// [`run_benchmark`] picks it among the flows whose server port is
/// `port`: the best replayed side by [`protoplay::FlowQuality`]. The
/// analyzer uses it as each endpoint's reference flow (N18).
pub fn replayed_flows(
    pcap: &LoadedPcap,
    role: protoplay::Role,
    port: u16,
) -> std::collections::BTreeMap<Ipv4Addr, usize> {
    let (dir, master) = match role {
        protoplay::Role::Master => (pcapload::StreamDir::ClientToServer, true),
        protoplay::Role::Slave => (pcapload::StreamDir::ServerToClient, false),
    };
    let candidates = pcap.flows.iter().enumerate().filter_map(|(idx, f)| {
        let (server_ip, server_port) = f.server?;
        if server_port != port {
            return None;
        }
        let ip = if master { f.client?.0 } else { server_ip };
        Some((idx, ip))
    });
    best_flow_per_ip(
        candidates,
        |idx| pcap.reassemble(idx, dir).map(|r| replay_quality(&r)),
        |q| *q,
    )
    .into_iter()
    .map(|(idx, ip, _)| (ip, idx))
    .collect()
}

/// Resolve `iterations` into an actual loop count: 0 → unlimited
/// (u64::MAX), N → N. Caller is expected to break on cancel.
#[inline]
pub fn effective_iterations(n: u64) -> u64 {
    if n == 0 {
        u64::MAX
    } else {
        n
    }
}

/// Accumulates per-iteration [`protoplay::ProtoReport`]s of one session
/// into a single report with **one** bounded latency reservoir across
/// all iterations (F026/F075).
#[derive(Debug, Clone)]
pub struct SessionAccumulator {
    report: protoplay::ProtoReport,
    reservoir: protoplay::LatencyReservoir,
}

impl Default for SessionAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionAccumulator {
    pub fn new() -> Self {
        Self::with_reservoir(protoplay::LatencyReservoir::new(
            protoplay::LATENCY_RESERVOIR_CAP,
        ))
    }

    pub fn with_reservoir(reservoir: protoplay::LatencyReservoir) -> Self {
        Self {
            report: protoplay::ProtoReport::default(),
            reservoir,
        }
    }

    /// The merged report so far, with percentiles and throughput
    /// already recomputed.
    pub fn report(&self) -> &protoplay::ProtoReport {
        &self.report
    }

    pub fn into_report(self) -> protoplay::ProtoReport {
        self.report
    }
}

/// Merge a per-iteration report into `acc`: counters add, latency
/// samples go through the shared bounded reservoir, the first error
/// wins, and percentiles/throughput are recomputed with
/// [`protoplay::ProtoReport::finalize_latency`] so the merged report is
/// always self-consistent. `elapsed_ms` (total) and
/// `protocol.idle_serve_ms` both add up, so throughput stays messages
/// per second of active time ([`protoplay::ProtoReport::active_ms`]),
/// whatever the idle-serve tails (N4).
pub fn merge_proto_report(acc: &mut SessionAccumulator, mut new: protoplay::ProtoReport) {
    let r = &mut acc.report;
    r.protocol
        .merge(std::mem::take(&mut new.protocol), r.messages_sent);
    r.connected = r.connected || new.connected;
    r.messages_sent = r.messages_sent.saturating_add(new.messages_sent);
    r.messages_received = r.messages_received.saturating_add(new.messages_received);
    r.bytes_written = r.bytes_written.saturating_add(new.bytes_written);
    r.bytes_read = r.bytes_read.saturating_add(new.bytes_read);
    r.elapsed_ms = r.elapsed_ms.saturating_add(new.elapsed_ms);
    r.window_stalls = r.window_stalls.saturating_add(new.window_stalls);
    r.unacked_at_end = new.unacked_at_end;
    acc.reservoir.extend(new.latency_samples_us);
    if r.error.is_none() && new.error.is_some() {
        r.error = new.error;
    }
    r.latency_samples_us = acc.reservoir.as_slice().to_vec();
    r.finalize_latency();
}

#[derive(Debug, Clone)]
pub struct SessionReport {
    pub src_ip: Ipv4Addr,
    pub src_mac: MacAddr,
    pub tap: String,
    pub flow_idx: usize,
    pub started_at_ns: u64,
    pub proto_report: protoplay::ProtoReport,
    /// The session was stopped (run stop or per-session cancel) before
    /// it finished. Its `proto_report.error`, if any, says where it was
    /// stopped; it is not a failure.
    pub cancelled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BenchmarkReport {
    pub per_session: Vec<SessionReport>,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub aggregate_latency_samples_us: Vec<u64>,
    pub aggregate_latency_min_us: u64,
    pub aggregate_latency_p50_us: u64,
    pub aggregate_latency_p90_us: u64,
    pub aggregate_latency_p99_us: u64,
    pub aggregate_latency_max_us: u64,
    pub aggregate_throughput_msgs_per_sec: f64,
    pub capture_path: Option<PathBuf>,
    pub captured_packets: u64,
    pub captured_bytes: u64,
    /// Frames the capture lost to a full kernel queue (the capture file
    /// is missing them; its analysis under-counts delivery).
    pub captured_dropped: u64,
    /// The capture reached [`BenchmarkConfig::capture_max_bytes`] and
    /// holds only the start of the run.
    pub capture_truncated: bool,
    /// See [`RunReport::capture_ok`]: `false` when the capture could
    /// not record every session it had to, or holds no frame although
    /// the sessions exchanged messages.
    pub capture_ok: bool,
    /// Non-fatal problems (capture, guard-restore, alias and teardown
    /// failures, panicked sessions) worth showing in the run's status.
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests;
