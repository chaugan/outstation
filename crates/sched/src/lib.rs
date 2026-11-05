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
        }
    }

    pub fn snapshot_sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn snapshot_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
    /// Monotonic total across iterations.
    pub fn snapshot_sent_total(&self) -> u64 {
        self.sent_done_iters.load(Ordering::Relaxed) + self.sent.load(Ordering::Relaxed)
    }
    /// Monotonic total across iterations.
    pub fn snapshot_bytes_total(&self) -> u64 {
        self.bytes_done_iters.load(Ordering::Relaxed) + self.bytes.load(Ordering::Relaxed)
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
    /// per-iteration ones. A concurrent reader may briefly see the
    /// folded amount twice; samplers should take deltas with a floor
    /// of zero.
    pub fn begin_iteration(&self, iter: u64) {
        let s = self.sent.swap(0, Ordering::Relaxed);
        self.sent_done_iters.fetch_add(s, Ordering::Relaxed);
        let b = self.bytes.swap(0, Ordering::Relaxed);
        self.bytes_done_iters.fetch_add(b, Ordering::Relaxed);
        self.received.store(0, Ordering::Relaxed);
        self.unacked.store(0, Ordering::Relaxed);
        self.iter_current.store(iter, Ordering::Relaxed);
    }

    fn message_progress(&self, run_cancel: &Arc<AtomicBool>) -> protoplay::MessageProgress {
        protoplay::MessageProgress {
            planned: Arc::clone(&self.planned),
            sent: Arc::clone(&self.sent),
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
        }
    }
}

/// Sleep for `dur`, returning early (within 100 ms) once `cancelled()`.
fn sleep_interruptible(dur: Duration, cancelled: impl Fn() -> bool) {
    protoplay::sleep_cancellable(dur, cancelled);
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
    /// Non-fatal problems (guard warnings, realtime policy, worker
    /// errors) worth showing in the run's status.
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

fn start_capture(
    res: &mut RunResources,
    names: &IfaceNames,
    path: &Path,
    rt_priority: Option<i32>,
    warnings: &mut Vec<String>,
) {
    // Capture on a dedicated dummy device that every run port mirrors
    // its ingress and egress to (tc mirred), not on the bridge device
    // (which only sees a fraction of forwarded traffic) nor on an
    // extra bridge port (which only sees floods once MACs are learned).
    let port = match names.capture_port() {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!("capture disabled: {e:#}"));
            return;
        }
    };
    let Some(topo) = res.topo.as_mut() else {
        return;
    };
    match topo.add_capture_mirror(&port) {
        Ok(()) => match Capture::start_with_priority(&port, path, rt_priority) {
            Ok(c) => {
                info!(path = %path.display(), iface = %port, "capture started");
                res.capture = Some(c);
            }
            Err(e) => {
                warn!(error = %e, path = %path.display(), "capture failed to start");
                warnings.push(format!("capture failed to start: {e:#}"));
            }
        },
        Err(e) => {
            warn!(error = %format!("{e:#}"), "could not create capture mirror");
            warnings.push(format!("could not create capture mirror: {e:#}"));
        }
    }
}

/// Stop the capture (after a short flush delay) and copy its counters.
fn collect_capture(res: &mut RunResources) -> (Option<PathBuf>, u64, u64) {
    let Some(c) = res.capture.take() else {
        return (None, 0, 0);
    };
    std::thread::sleep(Duration::from_millis(200));
    let packets = c.packets.load(Ordering::Relaxed);
    let bytes = c.bytes.load(Ordering::Relaxed);
    let path = c.path.clone();
    c.stop();
    info!(packets, bytes, "capture stopped");
    (Some(path), packets, bytes)
}

// -----------------------------------------------------------------------------
// Start barrier.
// -----------------------------------------------------------------------------

/// Start barrier for raw-replay workers. Every worker arrives (with or
/// without a usable plan); the coordinator waits for all of them, then
/// publishes one epoch everybody paces against. Unlike
/// `std::sync::Barrier` it can be aborted, so a failed spawn or a
/// cancel never leaves workers blocked forever.
#[derive(Default)]
struct StartGate {
    state: Mutex<GateState>,
    cv: Condvar,
}

#[derive(Default)]
struct GateState {
    arrived: usize,
    epoch: Option<u64>,
    aborted: bool,
}

impl StartGate {
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Arrive without waiting (worker failed before it could replay).
    fn arrive_failed(&self) {
        self.lock().arrived += 1;
        self.cv.notify_all();
    }

    /// Arrive and wait for the epoch. `None` if aborted or cancelled.
    fn arrive_and_wait(&self, cancel: &AtomicBool) -> Option<u64> {
        let mut g = self.lock();
        g.arrived += 1;
        self.cv.notify_all();
        loop {
            if let Some(e) = g.epoch {
                return Some(e);
            }
            if g.aborted || cancel.load(Ordering::Relaxed) {
                return None;
            }
            g = self
                .cv
                .wait_timeout(g, protoplay::CANCEL_POLL_INTERVAL)
                .map(|(g, _)| g)
                .unwrap_or_else(|e| e.into_inner().0);
        }
    }

    /// Wait until `n` workers arrived. `false` if cancelled first.
    fn wait_for(&self, n: usize, cancel: &AtomicBool) -> bool {
        let mut g = self.lock();
        while g.arrived < n {
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
            g = self
                .cv
                .wait_timeout(g, protoplay::CANCEL_POLL_INTERVAL)
                .map(|(g, _)| g)
                .unwrap_or_else(|e| e.into_inner().0);
        }
        true
    }

    fn open(&self, epoch: u64) {
        self.lock().epoch = Some(epoch);
        self.cv.notify_all();
    }

    fn abort(&self) {
        self.lock().aborted = true;
        self.cv.notify_all();
    }
}

/// Lead time between the barrier and the shared epoch, so every worker
/// is back on a CPU before its first deadline.
const EPOCH_LEAD_NS: u64 = 50_000_000;
/// Gap between the last frame of one pass and the first of the next.
const PASS_GAP_NS: u64 = 1_000_000;

/// Epoch of pass `k` (0-based) given the pass length.
fn pass_epoch(epoch0: u64, k: u64, pass_ns: u64) -> u64 {
    epoch0.saturating_add(k.saturating_mul(pass_ns))
}

/// Decide which raw workers may run SCHED_FIFO: none with top speed
/// (they never sleep), otherwise at most `budget` (cores - 1).
fn realtime_plan(realtime: bool, top_speed: bool, workers: usize, budget: usize) -> Vec<bool> {
    let active = realtime && !top_speed;
    (0..workers).map(|i| active && i < budget).collect()
}

/// Validate a raw-run config before anything touches the host.
fn validate_run_cfg(cfg: &RunConfig) -> Result<IfaceNames> {
    if !cfg.top_speed && !(cfg.speed.is_finite() && cfg.speed > 0.0) {
        bail!("speed must be a positive number, got {}", cfg.speed);
    }
    IfaceNames::custom(
        cfg.run_id,
        cfg.bridge_name.as_deref(),
        cfg.tap_prefix.as_deref(),
    )
}

pub fn run(pcap: Arc<LoadedPcap>, cfg: RunConfig, ctx: RunContext) -> Result<RunReport> {
    let names = validate_run_cfg(&cfg)?;
    let state_dir = state_dir_or_default(&cfg.state_dir);
    let prot = Protection::new(cfg.protected_addrs.clone(), cfg.force_protected_nic);
    let mut warnings: Vec<String> = Vec::new();

    // 1. Topology.
    let mut res = RunResources::default();
    bring_up_topology(
        &mut res,
        &names,
        cfg.egress_nic.as_deref(),
        cfg.target_ip,
        None,
        &state_dir,
        &prot,
        &mut warnings,
    )?;

    // 2. Build the list of workers. Each worker owns one bridge port
    //    and one packet index list.
    struct Worker {
        ip: Option<Ipv4Addr>,
        mac: MacAddr,
        kind: SourceKind,
        inject_side: String,
        packet_indices: Vec<usize>,
    }

    let wanted: Option<std::collections::HashSet<Ipv4Addr>> = cfg
        .filter_sources
        .as_ref()
        .map(|v| v.iter().copied().collect());

    let mut workers: Vec<Worker> = Vec::new();
    {
        let topo = res.topo.as_mut().context("topology missing")?;
        for (idx, (ip, src)) in pcap
            .sources
            .iter()
            .filter(|(ip, _)| wanted.as_ref().is_none_or(|s| s.contains(ip)))
            .enumerate()
        {
            let bridge_side = names.port(PortKind::RawIp, idx)?;
            let inject_side = topo
                .add_port(&bridge_side, Some(src.src_mac))
                .with_context(|| format!("add port {bridge_side}"))?;
            workers.push(Worker {
                ip: Some(*ip),
                mac: src.src_mac,
                kind: SourceKind::Ipv4,
                inject_side,
                packet_indices: src.packet_indices.clone(),
            });
        }
        if cfg.include_non_ip {
            for (idx, (mac, info)) in pcap.non_ip_sources.iter().enumerate() {
                let bridge_side = names.port(PortKind::RawL2, idx)?;
                let inject_side = topo
                    .add_port(&bridge_side, Some(*mac))
                    .with_context(|| format!("add port {bridge_side}"))?;
                workers.push(Worker {
                    ip: None,
                    mac: *mac,
                    kind: SourceKind::NonIp,
                    inject_side,
                    packet_indices: info.packet_indices.clone(),
                });
            }
        }
    }

    if workers.is_empty() {
        bail!("nothing to replay (no IPv4 sources and include_non_ip disabled)");
    }
    info!(sources = workers.len(), bridge = %names.bridge, "topology up");

    // Realtime policy (F032/F045).
    let rt_plan = realtime_plan(
        cfg.realtime,
        cfg.top_speed,
        workers.len(),
        realtime_thread_budget(),
    );
    let rt_active = rt_plan.iter().any(|b| *b);
    if cfg.realtime && cfg.top_speed {
        warnings.push(
            "realtime ignored: top-speed workers never sleep and would starve the host".into(),
        );
    } else if cfg.realtime && rt_plan.iter().any(|b| !*b) {
        warnings.push(format!(
            "realtime: only {} of {} workers promoted to SCHED_FIFO (cores - 1)",
            rt_plan.iter().filter(|b| **b).count(),
            workers.len()
        ));
    }

    if let Some(path) = &cfg.capture_path {
        start_capture(
            &mut res,
            &names,
            path,
            rt_active.then_some(CAPTURE_RT_PRIORITY),
            &mut warnings,
        );
    }

    // Pre-populate ctx.per_source and ctx.planned so the webui sees a
    // full picture as soon as the run is queryable.
    let iterations = cfg.iterations;
    let progress: Vec<SourceProgress> = {
        let mut sp = ctx.sources();
        sp.clear();
        for w in &workers {
            let p = SourceProgress::new(
                w.ip,
                w.mac,
                w.inject_side.clone(),
                protoplay::session_state::ACTIVE,
                true,
            );
            p.planned
                .store(w.packet_indices.len() as u64, Ordering::Relaxed);
            p.iter_total.store(iterations, Ordering::Relaxed);
            sp.push(p);
        }
        sp.clone()
    };
    let per_pass: u64 = workers.iter().map(|w| w.packet_indices.len() as u64).sum();
    ctx.planned.store(
        if iterations == 0 {
            0
        } else {
            per_pass.saturating_mul(iterations)
        },
        Ordering::Relaxed,
    );

    if cfg.startup_delay_secs > 0 {
        info!(
            seconds = cfg.startup_delay_secs,
            bridge = %names.bridge,
            "warmup: interfaces are live — attach Wireshark / tcpdump now"
        );
        sleep_interruptible(Duration::from_secs(cfg.startup_delay_secs), || {
            ctx.is_cancelled()
        });
        if ctx.is_cancelled() {
            info!("run cancelled during warmup, tearing down");
            let mut report = RunReport::default();
            res.finish(&mut report.warnings);
            return Ok(report);
        }
        info!("warmup elapsed, starting replay workers");
    }

    // 3. Spawn one worker per port. Workers build their plans, meet at
    //    the start gate and pace against one shared epoch (F031).
    let pace = if cfg.top_speed {
        Pace::TopSpeed
    } else {
        Pace::Original { speed: cfg.speed }
    };
    let span_ns = workers
        .iter()
        .flat_map(|w| w.packet_indices.iter())
        .map(|i| pcap.packets[*i].rel_ts_ns)
        .max()
        .unwrap_or(0);
    let pass_ns = schedule_offset_ns(span_ns, cfg.speed).saturating_add(PASS_GAP_NS);
    let target_ip = cfg.target_ip;
    let target_mac = cfg.target_mac;
    let target_iters = effective_iterations(iterations);
    let gate = Arc::new(StartGate::default());

    let mut handles: Vec<thread::JoinHandle<Result<SourceReport>>> =
        Vec::with_capacity(workers.len());
    for (worker_idx, w) in workers.into_iter().enumerate() {
        let Worker {
            ip,
            mac,
            kind,
            inject_side,
            packet_indices,
        } = w;
        let pcap = Arc::clone(&pcap);
        let thread_name = match ip {
            Some(i) => format!("replay-{i}"),
            None => format!("replay-l2-{:02x}{:02x}{:02x}", mac[3], mac[4], mac[5]),
        };
        let ctx_w = ctx.clone();
        let sp = progress[worker_idx].clone();
        let gate_w = Arc::clone(&gate);
        let promote = rt_plan[worker_idx];

        let spawned =
            thread::Builder::new()
                .name(thread_name)
                .spawn(move || -> Result<SourceReport> {
                    // Fallible preparation, isolated so the gate always
                    // learns about this worker, even on a panic.
                    let prep = catch_unwind(AssertUnwindSafe(|| -> Result<(RawReplayer, Plan)> {
                        let replayer = RawReplayer::bind(&inject_side)
                            .with_context(|| format!("bind AF_PACKET on {inject_side}"))?;
                        let mut plan = Plan::default();
                        let mut rewrite_failures = 0u64;
                        for i in &packet_indices {
                            let pkt = &pcap.packets[*i];
                            let mut data = pkt.ether_frame().into_owned();
                            if kind == SourceKind::Ipv4 {
                                if let Err(e) = rewrite_in_place(&mut data, target_ip, target_mac) {
                                    warn!(error = %e, "frame rewrite failed, skipping");
                                    rewrite_failures += 1;
                                    continue;
                                }
                            }
                            plan.push(pkt.rel_ts_ns, data);
                        }
                        info!(
                            ?ip,
                            tap = inject_side,
                            ?kind,
                            frames = plan.len(),
                            rewrite_failures,
                            "replay worker ready"
                        );
                        Ok((replayer, plan))
                    }));
                    let (replayer, plan) = match prep {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            gate_w.arrive_failed();
                            return Err(e);
                        }
                        Err(_) => {
                            gate_w.arrive_failed();
                            bail!("replay worker for {inject_side} panicked while preparing");
                        }
                    };
                    sp.planned.store(plan.len() as u64, Ordering::Relaxed);
                    if promote && !try_set_realtime(REPLAY_RT_PRIORITY) {
                        warn!(tap = inject_side, "SCHED_FIFO unavailable (CAP_SYS_NICE?)");
                    }
                    let mut acc = RunStats::default();
                    let Some(epoch0) = gate_w.arrive_and_wait(&ctx_w.cancel) else {
                        return Ok(SourceReport {
                            src_ip: ip,
                            src_mac: mac,
                            tap: inject_side,
                            kind,
                            stats: acc,
                        });
                    };
                    let mut weighted_jitter: u128 = 0;
                    for k in 0..target_iters {
                        if ctx_w.is_cancelled() {
                            break;
                        }
                        sp.begin_iteration(k + 1);
                        let stats = run_plan_at(
                            &replayer,
                            &plan,
                            pace,
                            pass_epoch(epoch0, k, pass_ns),
                            RunControls {
                                cancel: Some(&*ctx_w.cancel),
                                sent: Some(&*sp.sent),
                                bytes: Some(&*sp.bytes),
                                send_errors: None,
                                global_sent: Some(&*ctx_w.sent),
                                global_bytes: Some(&*ctx_w.bytes),
                                global_send_errors: Some(&*ctx_w.send_errors),
                            },
                        );
                        acc.sent = acc.sent.saturating_add(stats.sent);
                        acc.bytes = acc.bytes.saturating_add(stats.bytes);
                        acc.send_errors = acc.send_errors.saturating_add(stats.send_errors);
                        weighted_jitter += stats.mean_abs_jitter_ns as u128 * stats.sent as u128;
                        acc.p99_abs_jitter_ns = acc.p99_abs_jitter_ns.max(stats.p99_abs_jitter_ns);
                        if stats.max_jitter_ns.unsigned_abs() > acc.max_jitter_ns.unsigned_abs() {
                            acc.max_jitter_ns = stats.max_jitter_ns;
                        }
                    }
                    acc.elapsed_ns = now_ns().saturating_sub(epoch0);
                    if acc.sent > 0 {
                        acc.mean_abs_jitter_ns = (weighted_jitter / acc.sent as u128) as u64;
                    }
                    sp.state.store(
                        if ctx_w.is_cancelled() {
                            protoplay::session_state::CANCELLED
                        } else {
                            protoplay::session_state::COMPLETED
                        },
                        Ordering::Relaxed,
                    );
                    Ok(SourceReport {
                        src_ip: ip,
                        src_mac: mac,
                        tap: inject_side,
                        kind,
                        stats: acc,
                    })
                });
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => {
                // F034: cancel, join, tear down, report.
                warn!(error = %e, "spawn of replay worker failed; aborting run");
                ctx.cancel_all();
                gate.abort();
                for h in handles {
                    let _ = h.join();
                }
                let mut w = Vec::new();
                res.finish(&mut w);
                return Err(anyhow::Error::new(e).context("spawn replay thread"));
            }
        }
    }

    // All workers built their plans (or failed): publish the epoch.
    if gate.wait_for(handles.len(), &ctx.cancel) {
        let epoch = now_ns() + EPOCH_LEAD_NS;
        ctx.started_packets_at_ns.store(epoch, Ordering::Relaxed);
        gate.open(epoch);
    } else {
        gate.abort();
    }

    // 4. Join and aggregate.
    let mut report = RunReport::default();
    for h in handles {
        match h.join() {
            Ok(Ok(sr)) => {
                report.total_packets += sr.stats.sent;
                report.total_bytes += sr.stats.bytes;
                report.total_errors += sr.stats.send_errors;
                report.per_source.push(sr);
            }
            Ok(Err(e)) => {
                warn!(error = %format!("{e:#}"), "worker returned error");
                report.warnings.push(format!("worker: {e:#}"));
                report.total_errors += 1;
            }
            Err(_) => {
                warn!("worker panicked");
                report.warnings.push("a replay worker panicked".into());
                report.total_errors += 1;
            }
        }
    }

    // 5. Stop the capture (flush first), then tear everything down.
    let (cp, cpk, cby) = collect_capture(&mut res);
    report.capture_path = cp;
    report.captured_packets = cpk;
    report.captured_bytes = cby;
    report.warnings.extend(warnings);
    res.finish(&mut report.warnings);
    Ok(report)
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
        }
    }
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
/// always self-consistent. `elapsed_ms` is the sum of the iterations'
/// active times, so throughput is messages per second of activity.
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
    /// Non-fatal problems worth showing in the run's status.
    pub warnings: Vec<String>,
}

/// Identity of one session, kept by the coordinator so a session whose
/// thread died can still be reported.
#[derive(Clone)]
struct SessionIdent {
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    tap: String,
    flow_idx: usize,
    progress: SourceProgress,
}

impl SessionIdent {
    fn failed_report(&self, msg: &str) -> SessionReport {
        self.progress
            .set_final(protoplay::session_state::FAILED, Some(msg));
        SessionReport {
            src_ip: self.src_ip,
            src_mac: self.src_mac,
            tap: self.tap.clone(),
            flow_idx: self.flow_idx,
            started_at_ns: now_ns(),
            proto_report: protoplay::ProtoReport {
                error: Some(msg.into()),
                ..Default::default()
            },
            cancelled: false,
        }
    }
}

/// Run one protocol iteration, turning a panic into an error report.
fn run_iteration(
    replayer: &dyn protoplay::ProtoReplayer,
    cfg: protoplay::ProtoRunCfg,
) -> protoplay::ProtoReport {
    match catch_unwind(AssertUnwindSafe(|| replayer.run(cfg))) {
        Ok(r) => r,
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            protoplay::ProtoReport {
                error: Some(format!("session panicked: {msg}")),
                ..Default::default()
            }
        }
    }
}

/// Join session threads, folding panics into failed session reports,
/// and compute the aggregate statistics.
fn join_sessions(
    handles: Vec<(SessionIdent, thread::JoinHandle<SessionReport>)>,
    run_start_ns: u64,
) -> BenchmarkReport {
    let mut report = BenchmarkReport::default();
    for (ident, h) in handles {
        let sr = match h.join() {
            Ok(sr) => sr,
            Err(_) => {
                warn!(src = %ident.src_ip, "benchmark worker panicked");
                report
                    .warnings
                    .push(format!("session {} panicked", ident.src_ip));
                ident.failed_report("session thread panicked")
            }
        };
        report.total_messages_sent += sr.proto_report.messages_sent;
        report.total_messages_received += sr.proto_report.messages_received;
        report
            .aggregate_latency_samples_us
            .extend_from_slice(&sr.proto_report.latency_samples_us);
        report.per_session.push(sr);
    }
    if !report.aggregate_latency_samples_us.is_empty() {
        let mut v = report.aggregate_latency_samples_us.clone();
        v.sort_unstable();
        let n = v.len();
        let at = |p: f64| -> u64 {
            let idx = ((n as f64 - 1.0) * p).round() as usize;
            v[idx.min(n - 1)]
        };
        report.aggregate_latency_min_us = v[0];
        report.aggregate_latency_max_us = v[n - 1];
        report.aggregate_latency_p50_us = at(0.50);
        report.aggregate_latency_p90_us = at(0.90);
        report.aggregate_latency_p99_us = at(0.99);
    }
    let run_elapsed_ms = (now_ns().saturating_sub(run_start_ns)) / 1_000_000;
    if run_elapsed_ms > 0 {
        report.aggregate_throughput_msgs_per_sec =
            (report.total_messages_sent as f64) * 1000.0 / (run_elapsed_ms as f64);
    }
    report
}

/// Cancel everything and join what was spawned (F034).
fn abort_sessions(
    ctx: &RunContext,
    handles: Vec<(SessionIdent, thread::JoinHandle<SessionReport>)>,
) {
    ctx.cancel_all();
    for (_, h) in handles {
        let _ = h.join();
    }
}

/// Install the SCADA-gateway guard if configured.
fn install_gateway(
    cfg: &BenchmarkConfig,
    state_dir: &Path,
    prot: &Protection,
) -> Result<Option<GatewayGuard>> {
    match (cfg.scada_gateway_ip, cfg.scada_gateway_iface.as_deref()) {
        (Some(gw_ip), Some(inner)) => Ok(Some(
            GatewayGuard::install(
                inner,
                gw_ip,
                cfg.upstream_nat_iface.as_deref(),
                cfg.run_id,
                state_dir,
                prot,
            )
            .context("SCADA gateway mode")?,
        )),
        (Some(_), None) => bail!("scada_gateway_ip set without scada_gateway_iface"),
        _ => Ok(None),
    }
}

/// Terminal state of a session. A session that ends with an error
/// while its (or the run's) cancel flag is up was stopped, not failed:
/// a listener torn down by STOP before any master connected, or a
/// script cut short by it, is `CANCELLED`. A session that finished
/// cleanly stays `COMPLETED` even if the stop arrived during its
/// idle-serve tail.
fn final_state(cancelled_mid_run: bool, cancel_flag: bool, has_error: bool) -> u8 {
    use protoplay::session_state as ss;
    if cancelled_mid_run || (cancel_flag && has_error) {
        ss::CANCELLED
    } else if has_error {
        ss::FAILED
    } else {
        ss::COMPLETED
    }
}

/// Final per-session bookkeeping shared by master and slave workers.
/// Returns whether the session counts as cancelled.
fn finish_session(
    ctx: &RunContext,
    sp: &SourceProgress,
    pr: &protoplay::ProtoReport,
    cancelled_mid_run: bool,
) -> bool {
    // Leave sent/received/bytes at the LAST iteration's live counts so
    // the per-iteration progress bar lands at ~100%; cumulative totals
    // are in `sent_done_iters + sent` and in the final report.
    sp.unacked.store(pr.unacked_at_end, Ordering::Relaxed);
    let state = final_state(
        cancelled_mid_run,
        ctx.is_cancelled() || sp.is_cancelled(),
        pr.error.is_some(),
    );
    sp.set_final(state, pr.error.as_deref());
    ctx.sessions_done.fetch_add(1, Ordering::Relaxed);
    state == protoplay::session_state::CANCELLED
}

/// Walk the pcap's TCP flows, pick every flow whose server-side port
/// matches the benchmark's target port, reassemble each client's
/// payload, and run one stateful session per client IP against the
/// live target. The `replayer` is the protocol-aware module (shared
/// across all sessions).
pub fn run_benchmark(
    pcap: Arc<LoadedPcap>,
    cfg: BenchmarkConfig,
    replayer: Arc<dyn protoplay::ProtoReplayer>,
    ctx: RunContext,
) -> Result<BenchmarkReport> {
    use protoplay::{ClientSegment, ProtoRunCfg};

    if matches!(cfg.role, protoplay::Role::Slave) {
        return run_benchmark_slave(pcap, cfg, replayer, ctx);
    }

    let names = IfaceNames::custom(
        cfg.run_id,
        cfg.bridge_name.as_deref(),
        cfg.tap_prefix.as_deref(),
    )?;
    let state_dir = state_dir_or_default(&cfg.state_dir);
    let prot = Protection::new(cfg.protected_addrs.clone(), cfg.force_protected_nic);
    let mut warnings = Vec::new();

    // 1. Topology + guards (fail closed).
    let mut res = RunResources::default();
    bring_up_topology(
        &mut res,
        &names,
        cfg.egress_nic.as_deref(),
        cfg.target_ip,
        Some(cfg.target_port),
        &state_dir,
        &prot,
        &mut warnings,
    )?;
    res.gateway = install_gateway(&cfg, &state_dir, &prot)?;

    // 2. Select flows: TCP flows whose server port matches.
    struct FlowPick {
        flow_idx: usize,
        client_ip: Ipv4Addr,
        client_mac: MacAddr,
        first_pkt_rel_ns: u64,
        payload: Vec<u8>,
        capture_gaps: Vec<usize>,
        frame_times_ns: Vec<u64>,
    }

    let mut picks: Vec<FlowPick> = Vec::new();
    for (idx, flow) in pcap.flows.iter().enumerate() {
        let Some((_, server_port)) = flow.server else {
            continue;
        };
        if server_port != cfg.target_port {
            continue;
        }
        let Some((client_ip, _)) = flow.client else {
            continue;
        };
        if let Some(set) = &cfg.selected_endpoints {
            if !set.contains(&client_ip) {
                continue;
            }
        }
        let Some(src_info) = pcap.sources.get(&client_ip) else {
            warn!(%client_ip, "client ip has no MAC in sources table, skipping");
            continue;
        };
        let first_pkt_rel_ns = flow
            .packet_indices
            .first()
            .map(|i| pcap.packets[*i].rel_ts_ns)
            .unwrap_or(0);
        match pcap.reassemble_client_payload(idx) {
            Ok(reassembled) => {
                let frame_times_ns = replayer
                    .extract_message_times_ns(&reassembled.payload, &reassembled.packet_offsets);
                picks.push(FlowPick {
                    flow_idx: idx,
                    client_ip,
                    client_mac: src_info.src_mac,
                    first_pkt_rel_ns,
                    capture_gaps: reassembled.gaps.iter().map(|g| g.offset).collect(),
                    payload: reassembled.payload,
                    frame_times_ns,
                });
            }
            Err(e) => {
                warn!(flow = idx, error = %e, "reassembly failed; skipping flow");
            }
        }
    }

    // Collapse to one session per unique client IP: the first flow
    // that reassembled successfully wins.
    let mut seen_ips: std::collections::HashSet<Ipv4Addr> = Default::default();
    picks.retain(|p| seen_ips.insert(p.client_ip));

    if picks.is_empty() {
        bail!(
            "no flows matching target port {} (tried {} flows)",
            cfg.target_port,
            pcap.flows.len()
        );
    }
    info!(sessions = picks.len(), target = %cfg.target_ip, port = cfg.target_port,
        "benchmark: flows selected");

    // 3. One veth port per session with the client IP + MAC assigned,
    //    so the per-session TCP socket bind() succeeds.
    struct SessionBinding {
        pick_idx: usize,
        src_ip: Ipv4Addr,
        src_mac: MacAddr,
        bridge_side: String,
        inject_side: String,
    }
    let master_override = cfg.master_bind_ip;
    if let Some(ip) = master_override {
        info!(%ip, "master_bind_ip override active — sessions will originate from this address");
    }
    let mut bindings: Vec<SessionBinding> = Vec::with_capacity(picks.len());
    {
        let topo = res.topo.as_mut().context("topology missing")?;
        for (i, p) in picks.iter().enumerate() {
            let effective_src_ip = master_override.unwrap_or(p.client_ip);
            let bridge_side = names.port(PortKind::Session, i)?;
            let inject_side = topo
                .add_port_with_ip(
                    &bridge_side,
                    Some(p.client_mac),
                    Some(effective_src_ip),
                    &prot,
                )
                .with_context(|| format!("add session port {bridge_side}"))?;
            bindings.push(SessionBinding {
                pick_idx: i,
                src_ip: effective_src_ip,
                src_mac: p.client_mac,
                bridge_side,
                inject_side,
            });
        }
    }

    // 4. Mirror capture.
    if let Some(path) = &cfg.capture_path {
        start_capture(&mut res, &names, path, None, &mut warnings);
    }

    // 5. Pre-populate per-session progress. `planned` stays 0 until
    //    the protocol replayer has parsed the client payload.
    let progress: Vec<SourceProgress> = {
        let mut sp = ctx.sources();
        sp.clear();
        for b in &bindings {
            let p = SourceProgress::new(
                Some(b.src_ip),
                b.src_mac,
                b.bridge_side.clone(),
                protoplay::session_state::PENDING,
                true,
            );
            p.iter_total.store(cfg.iterations, Ordering::Relaxed);
            sp.push(p);
        }
        sp.clone()
    };
    ctx.planned.store(0, Ordering::Relaxed);
    ctx.sessions_total
        .store(bindings.len() as u64, Ordering::Relaxed);

    // 6. Warmup.
    if cfg.startup_delay_secs > 0 {
        info!(seconds = cfg.startup_delay_secs, bridge = %names.bridge,
            "benchmark warmup: interfaces are live");
        sleep_interruptible(Duration::from_secs(cfg.startup_delay_secs), || {
            ctx.is_cancelled()
        });
        if ctx.is_cancelled() {
            let mut report = BenchmarkReport::default();
            res.finish(&mut report.warnings);
            return Ok(report);
        }
    }

    // 7. Spawn one session worker per binding.
    let run_start_ns = now_ns();
    ctx.started_packets_at_ns
        .store(run_start_ns, Ordering::Relaxed);
    let mut handles: Vec<(SessionIdent, thread::JoinHandle<SessionReport>)> = Vec::new();

    for b in bindings.into_iter() {
        if ctx.is_cancelled() {
            break;
        }
        // Move the payload + timings out of the pick instead of cloning.
        let pick = &mut picks[b.pick_idx];
        let flow_idx = pick.flow_idx;
        let first_pkt_rel_ns = pick.first_pkt_rel_ns;
        let payload = std::mem::take(&mut pick.payload);
        let capture_gaps = std::mem::take(&mut pick.capture_gaps);
        let frame_times_ns = std::mem::take(&mut pick.frame_times_ns);
        let replayer = Arc::clone(&replayer);
        let cfg_w = cfg.clone();
        let src_ip = b.src_ip;
        let src_mac = b.src_mac;
        let bridge_side = b.bridge_side.clone();
        let inject_side = b.inject_side.clone();
        let ctx_w = ctx.clone();
        let sp = progress[b.pick_idx].clone();
        let session_progress = sp.message_progress(&ctx.cancel);
        let ident = SessionIdent {
            src_ip,
            src_mac,
            tap: inject_side.clone(),
            flow_idx,
            progress: sp.clone(),
        };

        let spawned = thread::Builder::new()
            .name(format!("bench-{src_ip}"))
            .spawn(move || {
                let cancelled = || ctx_w.is_cancelled() || sp.is_cancelled();
                if matches!(cfg_w.concurrency, ConcurrencyModel::StaggeredPcapTiming)
                    && first_pkt_rel_ns > 0
                {
                    sleep_interruptible(Duration::from_nanos(first_pkt_rel_ns), cancelled);
                }
                if cancelled() {
                    sp.set_final(protoplay::session_state::CANCELLED, None);
                    ctx_w.sessions_done.fetch_add(1, Ordering::Relaxed);
                    return SessionReport {
                        src_ip,
                        src_mac,
                        tap: bridge_side,
                        flow_idx,
                        started_at_ns: now_ns(),
                        proto_report: protoplay::ProtoReport {
                            error: Some("cancelled before start".into()),
                            ..Default::default()
                        },
                        cancelled: true,
                    };
                }

                let started_at_ns = now_ns();
                info!(%src_ip, flow_idx, bytes = payload.len(), "benchmark session starting");
                let target_iters = effective_iterations(cfg_w.iterations);
                let mut acc = SessionAccumulator::new();
                let mut cancelled_mid_run = false;
                for iter_idx in 0..target_iters {
                    if cancelled() {
                        cancelled_mid_run = true;
                        break;
                    }
                    sp.begin_iteration(iter_idx + 1);
                    let run_cfg = ProtoRunCfg {
                        bind_ip: src_ip,
                        // The source IP lives on the inject end; frames
                        // sent there enter the bridge via its peer.
                        bind_iface: Some(inject_side.clone()),
                        target_ip: cfg_w.target_ip,
                        target_port: cfg_w.target_port,
                        tcp_nodelay: cfg_w.tcp_nodelay.unwrap_or(false),
                        client_segments: vec![ClientSegment {
                            rel_ts_ns: 0,
                            bytes: payload.clone(),
                        }],
                        connect_timeout: Duration::from_secs(cfg_w.connect_timeout_secs),
                        speed: 1.0,
                        proto_config: cfg_w.proto_config.clone(),
                        progress: Some(session_progress.clone()),
                        role: protoplay::Role::Master,
                        listen_port: 0,
                        pacing: cfg_w.pacing,
                        frame_times_ns: frame_times_ns.clone(),
                        loop_iterations: 1,
                        capture_gaps: capture_gaps.clone(),
                    };
                    let iter_report = run_iteration(&*replayer, run_cfg);
                    ctx_w
                        .sent
                        .fetch_add(iter_report.messages_sent, Ordering::Relaxed);
                    ctx_w
                        .bytes
                        .fetch_add(iter_report.bytes_written, Ordering::Relaxed);
                    let had_error = iter_report.error.is_some();
                    merge_proto_report(&mut acc, iter_report);
                    if had_error {
                        break;
                    }
                }
                let pr = acc.into_report();
                let cancelled = finish_session(&ctx_w, &sp, &pr, cancelled_mid_run);
                info!(
                    %src_ip,
                    messages_sent = pr.messages_sent,
                    messages_received = pr.messages_received,
                    p50_us = pr.latency_p50_us,
                    p99_us = pr.latency_p99_us,
                    cancelled,
                    error = ?pr.error,
                    "benchmark session complete"
                );
                SessionReport {
                    src_ip,
                    src_mac,
                    tap: inject_side,
                    flow_idx,
                    started_at_ns,
                    proto_report: pr,
                    cancelled,
                }
            });
        match spawned {
            Ok(h) => handles.push((ident, h)),
            Err(e) => {
                warn!(error = %e, "spawn of benchmark session failed; aborting run");
                abort_sessions(&ctx, handles);
                let mut w = Vec::new();
                res.finish(&mut w);
                return Err(anyhow::Error::new(e).context("spawn benchmark thread"));
            }
        }
    }

    // 8. Join all sessions and build the report.
    let mut report = join_sessions(handles, run_start_ns);

    // 9. Stop capture, teardown.
    let (cp, cpk, cby) = collect_capture(&mut res);
    report.capture_path = cp;
    report.captured_packets = cpk;
    report.captured_bytes = cby;
    report.warnings.extend(warnings);
    res.finish(&mut report.warnings);
    Ok(report)
}

/// Make `listen_ip` bindable: nothing to do if it is unspecified or
/// already local; otherwise add a `/32 noprefixroute` alias on the
/// configured alias NIC (or the default-route NIC, which is protected
/// and needs `force`). Returns the lease that keeps the alias alive.
fn ensure_listen_alias(
    listen_ip: Ipv4Addr,
    alias_iface: Option<&str>,
    state_dir: &Path,
    prot: &Protection,
) -> Result<Option<netctl::AliasLease>> {
    if listen_ip.is_unspecified() || netctl::ip_is_local(listen_ip)? {
        return Ok(None);
    }
    let iface = match alias_iface {
        Some(i) => i.to_string(),
        None => netctl::protect::default_route_ifaces()?
            .into_iter()
            .next()
            .context("no default-route interface to alias onto; set alias_iface")?,
    };
    let ctx = || {
        format!(
            "listen ip {listen_ip} is not local and needs a /32 alias on {iface} \
             (choose a non-management NIC as alias interface, or force)"
        )
    };
    netctl::check_nic_allowed(&iface, "add listen aliases to", prot).with_context(ctx)?;
    netctl::validate_alias_ip(listen_ip, prot).with_context(ctx)?;
    let lease = netctl::AliasLease::acquire(&iface, listen_ip, state_dir).with_context(ctx)?;
    Ok(Some(lease))
}

/// Pick one flow per unique server (RTU) IP whose server port matches.
/// An RTU is only marked as seen once its reassembly succeeded, so a
/// later clean flow of the same RTU is used when an earlier one has a
/// gap (P02).
fn select_slave_flows<T>(
    flows: impl IntoIterator<Item = (usize, Option<(Ipv4Addr, u16)>)>,
    target_port: u16,
    selected: Option<&std::collections::HashSet<Ipv4Addr>>,
    mut reassemble: impl FnMut(usize, Ipv4Addr) -> Result<T>,
) -> Vec<(usize, Ipv4Addr, T)> {
    let mut picks = Vec::new();
    let mut seen: std::collections::HashSet<Ipv4Addr> = Default::default();
    for (idx, server) in flows {
        let Some((server_ip, server_port)) = server else {
            continue;
        };
        if server_port != target_port || seen.contains(&server_ip) {
            continue;
        }
        if selected.is_some_and(|s| !s.contains(&server_ip)) {
            continue;
        }
        match reassemble(idx, server_ip) {
            Ok(t) => {
                seen.insert(server_ip);
                picks.push((idx, server_ip, t));
            }
            Err(e) => {
                warn!(flow = idx, error = %e, "slave: server reassembly failed, trying next flow");
            }
        }
    }
    picks
}

/// Slave-mode benchmark: outstation binds a TcpListener per captured
/// RTU and waits for the live target master to connect to each. No veth
/// topology — sessions live in the host's own network namespace.
fn run_benchmark_slave(
    pcap: Arc<LoadedPcap>,
    cfg: BenchmarkConfig,
    replayer: Arc<dyn protoplay::ProtoReplayer>,
    ctx: RunContext,
) -> Result<BenchmarkReport> {
    use protoplay::{ClientSegment, ProtoRunCfg};

    let state_dir = state_dir_or_default(&cfg.state_dir);
    let prot = Protection::new(cfg.protected_addrs.clone(), cfg.force_protected_nic);
    if let Some(i) = &cfg.alias_iface {
        // Fail fast on a bad alias NIC rather than per session.
        netctl::check_nic_allowed(i, "add listen aliases to", &prot)?;
    }

    // 1. Pick one flow per RTU.
    struct SlavePick {
        flow_idx: usize,
        server_ip: Ipv4Addr,
        server_mac: MacAddr,
        payload: Vec<u8>,
        capture_gaps: Vec<usize>,
        frame_times_ns: Vec<u64>,
    }
    let picks: Vec<SlavePick> = select_slave_flows(
        pcap.flows.iter().enumerate().map(|(i, f)| (i, f.server)),
        cfg.target_port,
        cfg.selected_endpoints.as_ref(),
        |idx, _| pcap.reassemble_server_payload(idx),
    )
    .into_iter()
    .map(|(flow_idx, server_ip, r)| SlavePick {
        flow_idx,
        server_ip,
        server_mac: pcap
            .sources
            .get(&server_ip)
            .map(|s| s.src_mac)
            .unwrap_or([0; 6]),
        frame_times_ns: replayer.extract_message_times_ns(&r.payload, &r.packet_offsets),
        capture_gaps: r.gaps.iter().map(|g| g.offset).collect(),
        payload: r.payload,
    })
    .collect();

    if picks.is_empty() {
        bail!(
            "slave: no flows matching target port {} with server-side payload",
            cfg.target_port
        );
    }
    info!(
        sessions = picks.len(),
        base_port = cfg.listen_port_base,
        "slave benchmark: listeners planned"
    );

    // 2. Per-RTU progress. listen_ip defaults to the RTU's own address.
    let progress: Vec<SourceProgress> = {
        let mut sp = ctx.sources();
        sp.clear();
        for p in picks.iter() {
            let listen_port = cfg.listen_port_base;
            let mut e = SourceProgress::new(
                Some(p.server_ip),
                p.server_mac,
                format!("{}:{listen_port}", p.server_ip),
                protoplay::session_state::PENDING,
                false,
            );
            e.listen_port = listen_port;
            e.listen_ip = Arc::new(Mutex::new(p.server_ip));
            e.iter_total.store(cfg.iterations, Ordering::Relaxed);
            sp.push(e);
        }
        sp.clone()
    };
    ctx.planned.store(0, Ordering::Relaxed);
    ctx.sessions_total
        .store(picks.len() as u64, Ordering::Relaxed);

    // SCADA-gateway mode (fails closed).
    let res = RunResources {
        gateway: install_gateway(&cfg, &state_dir, &prot)?,
        ..Default::default()
    };

    // 3. Warmup.
    if cfg.startup_delay_secs > 0 {
        info!(
            seconds = cfg.startup_delay_secs,
            "slave warmup: listeners not yet bound — attach tooling to target side"
        );
        sleep_interruptible(Duration::from_secs(cfg.startup_delay_secs), || {
            ctx.is_cancelled()
        });
        if ctx.is_cancelled() {
            let mut report = BenchmarkReport::default();
            res.finish(&mut report.warnings);
            return Ok(report);
        }
    }

    // 4. Spawn one listener thread per RTU.
    let run_start_ns = now_ns();
    ctx.started_packets_at_ns
        .store(run_start_ns, Ordering::Relaxed);
    let mut handles: Vec<(SessionIdent, thread::JoinHandle<SessionReport>)> = Vec::new();

    for (idx, pick) in picks.into_iter().enumerate() {
        if ctx.is_cancelled() {
            break;
        }
        let flow_idx = pick.flow_idx;
        let payload = pick.payload;
        let capture_gaps = pick.capture_gaps;
        let frame_times_ns = pick.frame_times_ns;
        let replayer = Arc::clone(&replayer);
        let cfg_w = cfg.clone();
        let src_ip = pick.server_ip;
        let src_mac = pick.server_mac;
        let listen_port = cfg.listen_port_base;
        let tap_label = format!("{src_ip}:{listen_port}");
        let ctx_w = ctx.clone();
        let sp = progress[idx].clone();
        let session_progress = sp.message_progress(&ctx.cancel);
        let state_dir_w = state_dir.clone();
        let prot_w = prot.clone();
        let ident = SessionIdent {
            src_ip,
            src_mac,
            tap: tap_label.clone(),
            flow_idx,
            progress: sp.clone(),
        };

        let spawned = thread::Builder::new()
            .name(format!("bench-slave-{src_ip}"))
            .spawn(move || {
                let cancelled = || ctx_w.is_cancelled() || sp.is_cancelled();
                let early_report = |msg: &str, state: u8| {
                    sp.set_final(state, Some(msg));
                    ctx_w.sessions_done.fetch_add(1, Ordering::Relaxed);
                    SessionReport {
                        src_ip,
                        src_mac,
                        tap: tap_label.clone(),
                        flow_idx,
                        started_at_ns: now_ns(),
                        proto_report: protoplay::ProtoReport {
                            error: Some(msg.into()),
                            ..Default::default()
                        },
                        cancelled: state == protoplay::session_state::CANCELLED,
                    }
                };
                let cancelled_before_start = || {
                    let msg = if ctx_w.is_cancelled() {
                        "cancelled before start"
                    } else {
                        "slave cancelled before start"
                    };
                    early_report(msg, protoplay::session_state::CANCELLED)
                };
                // Wait for the user to flip `ready` for this slave. A
                // stop also flips `ready` (to wake this loop), so check
                // the cancel flags once more after the gate: a slave
                // that never started is cancelled, not failed.
                while !sp.is_ready() {
                    if cancelled() {
                        return cancelled_before_start();
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                if cancelled() {
                    return cancelled_before_start();
                }

                // Snapshot the user-edited listen IP after the gate.
                let listen_ip = sp.snapshot_listen_ip();
                let alias = match ensure_listen_alias(
                    listen_ip,
                    cfg_w.alias_iface.as_deref(),
                    &state_dir_w,
                    &prot_w,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(%listen_ip, error = %format!("{e:#}"), "listen alias refused");
                        return early_report(&format!("{e:#}"), protoplay::session_state::FAILED);
                    }
                };

                let started_at_ns = now_ns();
                info!(%src_ip, %listen_ip, listen_port, bytes = payload.len(),
                    aliased = alias.is_some(), "slave session opening listener");
                let (target_iters, run_loop_iterations) = if cfg_w.loop_within_session {
                    (1u64, cfg_w.iterations)
                } else {
                    (effective_iterations(cfg_w.iterations), 1u64)
                };
                let mut acc = SessionAccumulator::new();
                let mut cancelled_mid_run = false;
                for iter_idx in 0..target_iters {
                    if cancelled() {
                        cancelled_mid_run = true;
                        break;
                    }
                    sp.begin_iteration(iter_idx + 1);
                    let run_cfg = ProtoRunCfg {
                        bind_ip: listen_ip,
                        bind_iface: None,
                        target_ip: cfg_w.target_ip,
                        target_port: cfg_w.target_port,
                        tcp_nodelay: cfg_w.tcp_nodelay.unwrap_or(true),
                        client_segments: vec![ClientSegment {
                            rel_ts_ns: 0,
                            bytes: payload.clone(),
                        }],
                        connect_timeout: Duration::from_secs(cfg_w.connect_timeout_secs),
                        speed: 1.0,
                        proto_config: cfg_w.proto_config.clone(),
                        progress: Some(session_progress.clone()),
                        role: protoplay::Role::Slave,
                        listen_port,
                        pacing: cfg_w.pacing,
                        frame_times_ns: frame_times_ns.clone(),
                        loop_iterations: run_loop_iterations,
                        capture_gaps: capture_gaps.clone(),
                    };
                    let iter_report = run_iteration(&*replayer, run_cfg);
                    ctx_w
                        .sent
                        .fetch_add(iter_report.messages_sent, Ordering::Relaxed);
                    ctx_w
                        .bytes
                        .fetch_add(iter_report.bytes_written, Ordering::Relaxed);
                    let had_error = iter_report.error.is_some();
                    merge_proto_report(&mut acc, iter_report);
                    if had_error {
                        break;
                    }
                }

                // Drop our reference to the alias (deleted only if we
                // added it and nobody else still uses it).
                if let Some(a) = alias {
                    if let Err(e) = a.release() {
                        warn!(%listen_ip, error = %format!("{e:#}"), "alias cleanup failed");
                    }
                }

                let pr = acc.into_report();
                let cancelled = finish_session(&ctx_w, &sp, &pr, cancelled_mid_run);
                info!(
                    %src_ip,
                    listen_port,
                    messages_sent = pr.messages_sent,
                    messages_received = pr.messages_received,
                    p50_us = pr.latency_p50_us,
                    p99_us = pr.latency_p99_us,
                    cancelled,
                    error = ?pr.error,
                    "slave session complete"
                );
                SessionReport {
                    src_ip,
                    src_mac,
                    tap: tap_label,
                    flow_idx,
                    started_at_ns,
                    proto_report: pr,
                    cancelled,
                }
            });
        match spawned {
            Ok(h) => handles.push((ident, h)),
            Err(e) => {
                warn!(error = %e, "spawn of slave session failed; aborting run");
                abort_sessions(&ctx, handles);
                let mut w = Vec::new();
                res.finish(&mut w);
                return Err(anyhow::Error::new(e).context("spawn slave benchmark thread"));
            }
        }
    }

    // 5. Join all and aggregate.
    let mut report = join_sessions(handles, run_start_ns);
    res.finish(&mut report.warnings);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iter_report(samples: std::ops::Range<u64>, sent: u64, ms: u64) -> protoplay::ProtoReport {
        let mut r = protoplay::ProtoReport {
            latency_samples_us: samples.collect(),
            messages_sent: sent,
            messages_received: sent,
            elapsed_ms: ms,
            connected: true,
            ..Default::default()
        };
        r.finalize_latency();
        r
    }

    #[test]
    fn merge_recomputes_percentiles_and_throughput() {
        // F026: the merged report used to keep p50/p99/max/tput at 0.
        let mut acc = SessionAccumulator::new();
        for _ in 0..3 {
            merge_proto_report(&mut acc, iter_report(1..101, 100, 100));
        }
        let r = acc.report();
        assert_eq!(r.messages_sent, 300);
        assert_eq!(r.elapsed_ms, 300);
        assert!(r.latency_p50_us > 0 && r.latency_p50_us <= 100);
        assert!(r.latency_p99_us >= 90);
        assert_eq!(r.latency_max_us, 100);
        assert_eq!(r.latency_min_us, 1);
        assert_eq!(r.throughput_msgs_per_sec as u64, 1000);
        assert_eq!(r.latency_samples_us.len(), 300);
    }

    #[test]
    fn merge_keeps_one_bounded_reservoir() {
        // F075: samples must not grow with the number of iterations.
        let mut acc =
            SessionAccumulator::with_reservoir(protoplay::LatencyReservoir::with_seed(1000, 3));
        for _ in 0..50 {
            merge_proto_report(&mut acc, iter_report(0..1000, 1000, 10));
        }
        let r = acc.into_report();
        assert_eq!(r.latency_samples_us.len(), 1000);
        assert_eq!(r.messages_sent, 50_000);
        assert_eq!(r.latency_max_us, 999);
    }

    #[test]
    fn merge_keeps_first_error() {
        let mut acc = SessionAccumulator::new();
        merge_proto_report(
            &mut acc,
            protoplay::ProtoReport {
                error: Some("first".into()),
                ..Default::default()
            },
        );
        merge_proto_report(
            &mut acc,
            protoplay::ProtoReport {
                error: Some("second".into()),
                ..Default::default()
            },
        );
        assert_eq!(acc.report().error.as_deref(), Some("first"));
    }

    #[test]
    fn slave_flow_selection_marks_seen_only_after_success() {
        // P02: the first flow of 10.0.0.1 has a gap; the second is clean
        // and must be used instead of dropping the RTU.
        let ip1 = Ipv4Addr::new(10, 0, 0, 1);
        let ip2 = Ipv4Addr::new(10, 0, 0, 2);
        let flows = vec![
            (0, Some((ip1, 2404))),
            (1, Some((ip2, 2404))),
            (2, Some((ip1, 2404))),
            (3, Some((ip1, 2404))),
            (4, Some((ip2, 80))),
            (5, None),
        ];
        let picks = select_slave_flows(flows.clone(), 2404, None, |idx, _| {
            if idx == 0 {
                bail!("gap")
            } else {
                Ok(idx)
            }
        });
        let got: Vec<(usize, Ipv4Addr)> = picks.iter().map(|(i, ip, _)| (*i, *ip)).collect();
        assert_eq!(got, vec![(1, ip2), (2, ip1)]);

        // Endpoint filter is applied before reassembly is attempted.
        let only: std::collections::HashSet<Ipv4Addr> = [ip1].into_iter().collect();
        let mut tried = Vec::new();
        let picks = select_slave_flows(flows, 2404, Some(&only), |idx, _| {
            tried.push(idx);
            Ok(())
        });
        assert_eq!(picks.len(), 1);
        assert_eq!(tried, vec![0]);
    }

    #[test]
    fn realtime_policy() {
        // F032/F045: never with top speed; at most cores-1 threads.
        assert_eq!(realtime_plan(true, true, 4, 11), vec![false; 4]);
        assert_eq!(realtime_plan(false, false, 2, 11), vec![false; 2]);
        assert_eq!(
            realtime_plan(true, false, 5, 3),
            vec![true, true, true, false, false]
        );
        assert_eq!(realtime_plan(true, false, 3, 0), vec![false; 3]);
    }

    #[test]
    fn pass_epochs_are_aligned_and_saturating() {
        assert_eq!(pass_epoch(1_000, 0, 500), 1_000);
        assert_eq!(pass_epoch(1_000, 3, 500), 2_500);
        assert_eq!(pass_epoch(1_000, u64::MAX, 500), u64::MAX);
    }

    #[test]
    fn start_gate_releases_everyone_on_one_epoch() {
        // F031: workers that finish preparing at different times all
        // get the same epoch.
        let gate = Arc::new(StartGate::default());
        let cancel = Arc::new(AtomicBool::new(false));
        let mut hs = Vec::new();
        for i in 0..4u64 {
            let g = Arc::clone(&gate);
            let c = Arc::clone(&cancel);
            hs.push(thread::spawn(move || {
                thread::sleep(Duration::from_millis(10 * i));
                g.arrive_and_wait(&c)
            }));
        }
        let g = Arc::clone(&gate);
        hs.push(thread::spawn(move || {
            g.arrive_failed();
            Some(0)
        }));
        assert!(gate.wait_for(5, &cancel));
        gate.open(42);
        let got: Vec<Option<u64>> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(&got[..4], &[Some(42); 4]);
    }

    #[test]
    fn start_gate_abort_and_cancel_unblock() {
        let gate = Arc::new(StartGate::default());
        let cancel = Arc::new(AtomicBool::new(false));
        let g = Arc::clone(&gate);
        let c = Arc::clone(&cancel);
        let h = thread::spawn(move || g.arrive_and_wait(&c));
        assert!(gate.wait_for(1, &cancel));
        gate.abort();
        assert_eq!(h.join().unwrap(), None);

        let gate = StartGate::default();
        let cancel = AtomicBool::new(true);
        assert!(!gate.wait_for(3, &cancel));
        assert_eq!(gate.arrive_and_wait(&cancel), None);
    }

    #[test]
    fn progress_counters_do_not_exceed_iteration_and_stay_monotonic() {
        // F030: per-iteration progress resets; the total keeps growing.
        let ctx = RunContext::new();
        let p = SourceProgress::new(None, [0; 6], "x".into(), 0, true);
        p.planned.store(10, Ordering::Relaxed);
        ctx.sources().push(p.clone());
        let mut last_total = 0;
        for k in 1..=3 {
            p.begin_iteration(k);
            for _ in 0..10 {
                p.sent.fetch_add(1, Ordering::Relaxed);
            }
            let s = ctx.progress();
            assert!(s.iteration_sent <= s.iteration_planned);
            assert!(s.frames_sent_total > last_total);
            last_total = s.frames_sent_total;
        }
        assert_eq!(ctx.progress().frames_sent_total, 30);
        assert_eq!(p.iter_current.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn cancel_all_flips_every_session() {
        let ctx = RunContext::new();
        for _ in 0..3 {
            ctx.sources()
                .push(SourceProgress::new(None, [0; 6], "x".into(), 0, false));
        }
        ctx.cancel_all();
        assert!(ctx.is_cancelled());
        assert!(ctx.sources().iter().all(|p| p.is_cancelled()));
        let mp = ctx.sources()[0].message_progress(&ctx.cancel);
        assert!(mp.is_cancelled());
    }

    struct PanicReplayer;
    impl protoplay::ProtoReplayer for PanicReplayer {
        fn name(&self) -> &'static str {
            "panic"
        }
        fn well_known_ports(&self) -> &'static [u16] {
            &[]
        }
        fn readiness(&self) -> protoplay::Readiness {
            protoplay::Readiness::Ready
        }
        fn run(&self, _cfg: protoplay::ProtoRunCfg) -> protoplay::ProtoReport {
            panic!("spawn iec104-reader");
        }
    }

    #[test]
    fn session_panic_becomes_error_report() {
        // F034: a panic inside the protocol module must surface as a
        // session error, not a missing session.
        let cfg = protoplay::ProtoRunCfg {
            bind_ip: Ipv4Addr::LOCALHOST,
            bind_iface: None,
            target_ip: Ipv4Addr::LOCALHOST,
            target_port: 1,
            tcp_nodelay: false,
            client_segments: vec![],
            connect_timeout: Duration::from_secs(1),
            speed: 1.0,
            proto_config: None,
            progress: None,
            role: protoplay::Role::Master,
            listen_port: 0,
            pacing: protoplay::Pacing::AsFastAsPossible,
            frame_times_ns: vec![],
            loop_iterations: 1,
            capture_gaps: vec![],
        };
        let r = run_iteration(&PanicReplayer, cfg);
        assert!(r.error.unwrap().contains("spawn iec104-reader"));
    }

    #[test]
    fn final_state_table() {
        use protoplay::session_state as ss;
        // (cancelled at a loop boundary, cancel flag up, error) -> state
        let cases = [
            (false, false, false, ss::COMPLETED),
            (false, false, true, ss::FAILED),
            (true, false, false, ss::CANCELLED),
            (true, true, true, ss::CANCELLED),
            // Stopped while listening / mid-script: the error is the stop.
            (false, true, true, ss::CANCELLED),
            // Finished cleanly while the stop arrived (idle-serve tail).
            (false, true, false, ss::COMPLETED),
        ];
        for (mid, flag, err, want) in cases {
            assert_eq!(final_state(mid, flag, err), want, "{mid} {flag} {err}");
        }
    }

    /// Slave replayer that "listens" until cancelled, like the IEC 104
    /// slave with no master connecting.
    struct ListenUntilCancelled;
    impl protoplay::ProtoReplayer for ListenUntilCancelled {
        fn name(&self) -> &'static str {
            "listen"
        }
        fn well_known_ports(&self) -> &'static [u16] {
            &[2404]
        }
        fn readiness(&self) -> protoplay::Readiness {
            protoplay::Readiness::Ready
        }
        fn run(&self, cfg: protoplay::ProtoRunCfg) -> protoplay::ProtoReport {
            let p = cfg.progress.expect("progress");
            p.state
                .store(protoplay::session_state::LISTENING, Ordering::Relaxed);
            while !p.is_cancelled() {
                thread::sleep(Duration::from_millis(10));
            }
            p.state
                .store(protoplay::session_state::FAILED, Ordering::Relaxed);
            protoplay::ProtoReport {
                error: Some("cancelled while listening".into()),
                ..Default::default()
            }
        }
    }

    #[test]
    fn stopping_a_slave_run_cancels_pending_and_listening_sessions() {
        // T07b: STOP used to count never-started slaves as failed.
        let pcap = Arc::new(
            pcapload::load(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../examples/synth_iec104_rtus200_ts.pcap"),
            )
            .unwrap(),
        );
        let rtus: std::collections::HashSet<Ipv4Addr> = [49, 67, 16]
            .iter()
            .map(|&n| Ipv4Addr::new(192, 168, 10, n))
            .collect();
        let state = tempfile_dir();
        let cfg = BenchmarkConfig {
            role: protoplay::Role::Slave,
            selected_endpoints: Some(rtus),
            state_dir: Some(state.clone()),
            ..Default::default()
        };
        let ctx = RunContext::new();
        let c = ctx.clone();
        let h = thread::spawn(move || {
            run_benchmark_slave(pcap, cfg, Arc::new(ListenUntilCancelled), c)
        });
        // One slave starts listening (on a loopback address: no alias),
        // the other two never get their "start".
        let first = loop {
            let sp = ctx.sources().clone();
            if sp.len() == 3 {
                break sp[0].clone();
            }
            thread::sleep(Duration::from_millis(10));
        };
        *first.listen_ip.lock().unwrap() = Ipv4Addr::new(127, 0, 10, 49);
        first.ready.store(true, Ordering::Relaxed);
        while first.snapshot_state() != protoplay::session_state::LISTENING {
            thread::sleep(Duration::from_millis(10));
        }
        // What the webui's STOP does: cancel everything and wake the
        // pending slaves.
        ctx.cancel_all();
        for p in ctx.sources().iter() {
            p.ready.store(true, Ordering::Relaxed);
        }
        let report = h.join().unwrap().unwrap();
        assert_eq!(report.per_session.len(), 3);
        for s in &report.per_session {
            assert!(
                s.cancelled,
                "{} not cancelled: {:?}",
                s.src_ip, s.proto_report.error
            );
        }
        for p in ctx.sources().iter() {
            assert_eq!(p.snapshot_state(), protoplay::session_state::CANCELLED);
            assert_eq!(p.snapshot_error(), None);
        }
        assert_eq!(ctx.sessions_done.load(Ordering::Relaxed), 3);
        let _ = std::fs::remove_dir_all(state);
    }

    fn tempfile_dir() -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sched-test-{}-{}", std::process::id(), now_ns()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_failed_session_records_its_reason() {
        let p = SourceProgress::new(None, [0; 6], "x".into(), 0, true);
        let ctx = RunContext::new();
        let pr = protoplay::ProtoReport {
            error: Some("no master connected within 600s".into()),
            ..Default::default()
        };
        assert!(!finish_session(&ctx, &p, &pr, false));
        assert_eq!(p.snapshot_state(), protoplay::session_state::FAILED);
        assert_eq!(
            p.snapshot_error().as_deref(),
            Some("no master connected within 600s")
        );
        // A clean session has no reason.
        let q = SourceProgress::new(None, [0; 6], "y".into(), 0, true);
        finish_session(&ctx, &q, &protoplay::ProtoReport::default(), false);
        assert_eq!(q.snapshot_state(), protoplay::session_state::COMPLETED);
        assert_eq!(q.snapshot_error(), None);
    }

    #[test]
    fn loopback_listen_ips_need_no_alias() {
        // T07b: all of 127/8 is local via `lo`; a slave listening there
        // must never be aliased onto a NIC (or refused for lack of one).
        let prot = Protection::new(Vec::new(), false);
        for ip in ["127.0.0.1", "127.0.10.49", "127.254.0.9"] {
            let lease = ensure_listen_alias(
                ip.parse().unwrap(),
                None,
                Path::new("/nonexistent-state-dir"),
                &prot,
            )
            .unwrap();
            assert!(lease.is_none(), "{ip} was aliased");
        }
    }

    #[test]
    fn invalid_names_are_rejected_before_touching_the_host() {
        // F035/F047: a request-supplied name like "br0" or an empty
        // prefix must fail validation, never reach reclaim.
        let cfg = RunConfig {
            bridge_name: Some("br0".into()),
            ..Default::default()
        };
        let e = validate_run_cfg(&cfg).unwrap_err();
        assert!(format!("{e:#}").contains("bridge name"), "{e:#}");
        let cfg = RunConfig {
            tap_prefix: Some(String::new()),
            ..Default::default()
        };
        assert!(validate_run_cfg(&cfg).is_err());
        let cfg = RunConfig {
            speed: 0.0,
            ..Default::default()
        };
        assert!(validate_run_cfg(&cfg).is_err());
        let cfg = RunConfig {
            run_id: 5,
            ..Default::default()
        };
        assert_eq!(validate_run_cfg(&cfg).unwrap().bridge, "pcr5_br");
    }
}
