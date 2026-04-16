//! Orchestrator: glue the topology, loader, rewriter, and replayer into
//! a single run. One TAP per source IP, one replayer thread per TAP, all
//! starting from a shared monotonic epoch so their relative schedules
//! agree.
//!
//! This is the synchronous fire-and-collect version used by the CLI
//! driver. The future web UI will drive the same pieces through a
//! controller that exposes start/stop/stats channels.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use netctl::{reclaim_stale, EgressGuard, MacAddr, Topology};
use pcapload::LoadedPcap;
use raw_replay::{
    now_ns, run_plan_ctl, try_set_realtime, Capture, Pace, Plan, RawReplayer, RunControls, RunStats,
};
use rewrite::rewrite_in_place;
use tracing::{info, warn};

/// Shared, concurrent view of a running replay. Cloned into the
/// webui's `RunState` so HTTP handlers can read live progress
/// without locking the sched thread. All counters are relaxed —
/// eventually-consistent cross-field reads are acceptable for the UI.
#[derive(Clone, Default)]
pub struct RunContext {
    /// When flipped to true, workers exit at the next frame boundary.
    pub cancel: Arc<AtomicBool>,
    /// Total planned frames across all workers. Written once after
    /// the plans are built, then read-only.
    pub planned: Arc<AtomicU64>,
    /// Frames sent by all workers combined.
    pub sent: Arc<AtomicU64>,
    /// Wire bytes sent by all workers combined.
    pub bytes: Arc<AtomicU64>,
    /// Total send errors across all workers.
    pub send_errors: Arc<AtomicU64>,
    /// Monotonic-clock nanoseconds when the first frame was sent
    /// (0 until then). Used for throughput derivation.
    pub started_packets_at_ns: Arc<AtomicU64>,
    /// Per-worker progress. Indexed by worker position; each entry has
    /// its own atomics so workers don't contend on the global counters.
    pub per_source: Arc<Mutex<Vec<SourceProgress>>>,
}

impl RunContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of times cancel was requested (0 or 1, really).
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
pub struct SourceProgress {
    pub src_ip: Option<Ipv4Addr>,
    pub src_mac: MacAddr,
    pub tap: String,
    /// Total frames (raw replay) or client messages (benchmark) the
    /// worker plans to send. Written once after planning, then read-only.
    /// For benchmark mode the count is populated by the protocol module
    /// after it parses the client payload.
    pub planned: Arc<AtomicU64>,
    pub sent: Arc<AtomicU64>,
    pub bytes: Arc<AtomicU64>,
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
    /// Updated by the replayer as it transitions.
    pub state: Arc<AtomicU8>,
    /// Per-session cancel flag. Checked by the replayer at every
    /// natural yielding point. Independent of `RunContext::cancel`
    /// so a single RTU can be stopped without killing the run.
    pub cancel: Arc<AtomicBool>,
    /// Slave-benchmark: the TCP port this session listens on. Zero
    /// for any other mode.
    pub listen_port: u16,
    /// Slave-benchmark: the local address the listener binds to
    /// (defaults to 0.0.0.0 = any interface). Editable per-slave via
    /// PATCH /api/runs/:id/slaves/:idx before the slave starts.
    pub listen_ip: Arc<Mutex<Ipv4Addr>>,
}

impl SourceProgress {
    pub fn snapshot_sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn snapshot_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
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
        *self.listen_ip.lock().unwrap()
    }
}

/// Sleep for `dur`, checking cancel every 100 ms so a stop request
/// during warmup doesn't leave the user staring at an unresponsive UI.
fn sleep_interruptible(dur: Duration, cancel: &AtomicBool) {
    let end = std::time::Instant::now() + dur;
    while std::time::Instant::now() < end {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let slice = Duration::from_millis(100);
        let remaining = end.saturating_duration_since(std::time::Instant::now());
        std::thread::sleep(slice.min(remaining));
    }
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub bridge_name: String,
    pub tap_prefix: String,
    pub egress_nic: Option<String>,
    pub speed: f64,
    pub top_speed: bool,
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
    /// this pcap file. The web UI uses this so the user can download
    /// the replay output without running tcpdump.
    pub capture_path: Option<PathBuf>,
    /// Number of times to replay the pcap. `0` means loop forever
    /// until cancelled. Default `1` (single pass). Workers loop
    /// internally, re-walking their plan; `RunContext::cancel` and
    /// per-source cancel flags break out cleanly between iterations
    /// or mid-iteration.
    pub iterations: u64,
    /// IEC 104 only: rewrite every CP56Time2a timestamp inside each
    /// outgoing ASDU to the wall-clock moment the frame hits the
    /// wire. Ignored for raw-replay sources (non-IEC 104 traffic is
    /// emitted verbatim — rewriting arbitrary bytes would corrupt
    /// application payloads for protocols we can't parse).
    pub rewrite_cp56_to_now: bool,
    /// Timezone convention for CP56Time2a rewrite: `"utc"` or `"local"`.
    pub cp56_zone: String,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            target_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: [0; 6],
            bridge_name: "pcr_br0".into(),
            tap_prefix: "pcr_t".into(),
            egress_nic: None,
            speed: 1.0,
            top_speed: false,
            realtime: false,
            filter_sources: None,
            include_non_ip: true,
            startup_delay_secs: 0,
            capture_path: None,
            iterations: 1,
            rewrite_cp56_to_now: false,
            cp56_zone: "local".into(),
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
}

pub fn run(pcap: Arc<LoadedPcap>, cfg: RunConfig, ctx: RunContext) -> Result<RunReport> {
    // 1. Topology. Reclaim any leftover interfaces from a previously
    //    killed run so `add_port` doesn't trip on "already exists".
    let reclaimed = reclaim_stale(&cfg.bridge_name, &cfg.tap_prefix).unwrap_or(0);
    if reclaimed > 0 {
        info!(count = reclaimed, "reclaimed stale interfaces before run");
    }
    let mut topo = Topology::new(&cfg.bridge_name);
    topo.create_bridge().context("create bridge")?;
    let _egress_guard = if let Some(nic) = &cfg.egress_nic {
        topo.enslave_existing(nic)
            .with_context(|| format!("enslave {nic}"))?;
        info!(nic, "enslaved egress NIC");
        // Disable br_netfilter, NIC tx-checksum offload, and install
        // an iptables drop rule for the bridge so the host stack
        // doesn't interfere with bridged frames. Restored on Drop.
        Some(EgressGuard::install(&cfg.bridge_name, nic))
    } else {
        None
    };

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
    let mut port_counter = 0usize;

    for (ip, src) in &pcap.sources {
        if let Some(set) = &wanted {
            if !set.contains(ip) {
                continue;
            }
        }
        let bridge_side = format!("{}{}", cfg.tap_prefix, port_counter);
        let inject_side = match topo.add_port(&bridge_side, Some(src.src_mac)) {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, iface = %bridge_side, "add_port failed, tearing down");
                topo.teardown().ok();
                return Err(e);
            }
        };
        workers.push(Worker {
            ip: Some(*ip),
            mac: src.src_mac,
            kind: SourceKind::Ipv4,
            inject_side,
            packet_indices: src.packet_indices.clone(),
        });
        port_counter += 1;
    }

    if cfg.include_non_ip {
        for (mac, info) in &pcap.non_ip_sources {
            let bridge_side = format!("{}l{}", cfg.tap_prefix, port_counter);
            let inject_side = match topo.add_port(&bridge_side, Some(*mac)) {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, iface = %bridge_side, "add_port (l2) failed");
                    topo.teardown().ok();
                    return Err(e);
                }
            };
            workers.push(Worker {
                ip: None,
                mac: *mac,
                kind: SourceKind::NonIp,
                inject_side,
                packet_indices: info.packet_indices.clone(),
            });
            port_counter += 1;
        }
    }

    if workers.is_empty() {
        topo.teardown().ok();
        bail!("nothing to replay (no IPv4 sources and include_non_ip disabled)");
    }
    info!(
        sources = workers.len(),
        bridge = %cfg.bridge_name,
        "topology up"
    );

    // Start passive capture *on a dedicated mirror port attached to
    // the bridge*, not on the bridge device itself. AF_PACKET on the
    // bridge device only sees a fraction of forwarded traffic, whereas
    // a bridge-enslaved veth port sees every frame the bridge floods
    // or unicasts toward it. One inject nobody ever writes on, one
    // receive side the capture thread reads from.
    let capture = if let Some(path) = &cfg.capture_path {
        let cap_port_name = "pcr_cap".to_string();
        match topo.add_port(&cap_port_name, None) {
            Ok(_inject) => match Capture::start(&cap_port_name, path) {
                Ok(c) => {
                    info!(path = %path.display(), iface = %cap_port_name, "capture started");
                    Some(c)
                }
                Err(e) => {
                    warn!(error = %e, path = %path.display(), "capture failed to start");
                    None
                }
            },
            Err(e) => {
                warn!(error = %e, "could not create capture mirror port");
                None
            }
        }
    } else {
        None
    };

    // Pre-populate ctx.per_source and ctx.planned so the webui sees a
    // full picture as soon as the run is queryable, even before any
    // frames have been sent.
    {
        let mut sp = ctx.per_source.lock().unwrap();
        sp.clear();
        for w in &workers {
            sp.push(SourceProgress {
                src_ip: w.ip,
                src_mac: w.mac,
                tap: w.inject_side.clone(),
                planned: Arc::new(AtomicU64::new(w.packet_indices.len() as u64)),
                sent: Arc::new(AtomicU64::new(0)),
                bytes: Arc::new(AtomicU64::new(0)),
                received: Arc::new(AtomicU64::new(0)),
                unacked: Arc::new(AtomicU64::new(0)),
                ready: Arc::new(AtomicBool::new(true)),
                state: Arc::new(AtomicU8::new(protoplay::session_state::ACTIVE)),
                cancel: Arc::new(AtomicBool::new(false)),
                listen_port: 0,
                listen_ip: Arc::new(Mutex::new(Ipv4Addr::UNSPECIFIED)),
            });
        }
    }
    let total_planned: u64 = workers
        .iter()
        .map(|w| w.packet_indices.len() as u64)
        .sum();
    ctx.planned.store(total_planned, Ordering::Relaxed);

    if cfg.startup_delay_secs > 0 {
        info!(
            seconds = cfg.startup_delay_secs,
            bridge = %cfg.bridge_name,
            "warmup: interfaces are live — attach Wireshark / tcpdump now"
        );
        sleep_interruptible(
            std::time::Duration::from_secs(cfg.startup_delay_secs),
            &ctx.cancel,
        );
        if ctx.is_cancelled() {
            info!("run cancelled during warmup, tearing down");
            if let Some(c) = capture {
                c.stop();
            }
            topo.teardown().ok();
            return Ok(RunReport::default());
        }
        info!("warmup elapsed, starting replay workers");
    }

    // 3. Spawn one worker per port. All workers read from the same epoch
    //    (`now_ns()` captured after spawn) via the Plan rel_ts_ns they
    //    inherit from the pcap, so their schedules agree.
    let pace = if cfg.top_speed {
        Pace::TopSpeed
    } else {
        Pace::Original { speed: cfg.speed }
    };
    let target_ip = cfg.target_ip;
    let target_mac = cfg.target_mac;
    let realtime = cfg.realtime;
    let iterations = cfg.iterations;

    let mut handles = Vec::with_capacity(workers.len());
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
            None => format!(
                "replay-l2-{:02x}{:02x}{:02x}",
                mac[3], mac[4], mac[5]
            ),
        };
        let cancel_flag = Arc::clone(&ctx.cancel);
        let global_sent = Arc::clone(&ctx.sent);
        let global_bytes = Arc::clone(&ctx.bytes);
        let global_errors = Arc::clone(&ctx.send_errors);
        let started_at = Arc::clone(&ctx.started_packets_at_ns);
        let src_sent = Arc::clone(&ctx.per_source.lock().unwrap()[worker_idx].sent);
        let src_bytes = Arc::clone(&ctx.per_source.lock().unwrap()[worker_idx].bytes);

        let handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || -> Result<SourceReport> {
                if realtime {
                    try_set_realtime(50);
                }
                let replayer = RawReplayer::bind(&inject_side)
                    .with_context(|| format!("bind AF_PACKET on {inject_side}"))?;
                let mut plan = Plan::default();
                let mut rewrite_failures = 0u64;
                for i in &packet_indices {
                    let pkt = &pcap.packets[*i];
                    let mut data = pkt.data.clone();
                    match kind {
                        SourceKind::Ipv4 => {
                            if let Err(e) = rewrite_in_place(&mut data, target_ip, target_mac) {
                                warn!(error = %e, "frame rewrite failed, skipping");
                                rewrite_failures += 1;
                                continue;
                            }
                        }
                        SourceKind::NonIp => {
                            // Inject verbatim — L2 multicast has no L3
                            // addresses to rewrite.
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
                    "starting replay worker"
                );
                // Record the first-send timestamp once across all workers.
                started_at
                    .compare_exchange(0, now_ns(), Ordering::SeqCst, Ordering::SeqCst)
                    .ok();

                // Tee each send into both per-source and global atomics
                // by passing the per-source counters to run_plan_ctl and
                // summing into the global counters in the same loop — but
                // run_plan_ctl only takes one set. Workaround: loop the
                // plan here, call replayer.send directly, and feed both.
                //
                // (Keeping the high-fidelity sleep + jitter tracking by
                // reusing the same hybrid sleep the raw_replay hot loop
                // uses — exposed via run_plan_ctl with per-source
                // controls, plus a post-increment of global atomics.)
                // Loop the plan `iterations` times. iterations=0 → run
                // until cancel. The cancel flag check between iters
                // keeps stop snappy across long-running soak tests.
                let target_iters = effective_iterations(iterations);
                let mut acc = raw_replay::RunStats::default();
                for _iter_idx in 0..target_iters {
                    if cancel_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let stats = run_plan_ctl(
                        &replayer,
                        &plan,
                        pace,
                        RunControls {
                            cancel: Some(&*cancel_flag),
                            sent: Some(&*src_sent),
                            bytes: Some(&*src_bytes),
                            send_errors: None,
                        },
                    );
                    acc.sent = acc.sent.saturating_add(stats.sent);
                    acc.bytes = acc.bytes.saturating_add(stats.bytes);
                    acc.send_errors = acc.send_errors.saturating_add(stats.send_errors);
                    acc.elapsed_ns = stats.elapsed_ns;
                    acc.mean_abs_jitter_ns = stats.mean_abs_jitter_ns;
                    acc.p99_abs_jitter_ns = stats.p99_abs_jitter_ns;
                }
                // Fan-in per-source deltas into global counters so the
                // aggregate progress reflects this worker's contribution.
                global_sent.fetch_add(acc.sent, Ordering::Relaxed);
                global_bytes.fetch_add(acc.bytes, Ordering::Relaxed);
                global_errors.fetch_add(acc.send_errors, Ordering::Relaxed);
                Ok(SourceReport {
                    src_ip: ip,
                    src_mac: mac,
                    tap: inject_side,
                    kind,
                    stats: acc,
                })
            })
            .context("spawn replay thread")?;
        handles.push(handle);
    }

    let _t0 = now_ns(); // for reference only; each worker reads its own

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
                warn!(error = %e, "worker returned error");
                report.total_errors += 1;
            }
            Err(_) => {
                warn!("worker panicked");
                report.total_errors += 1;
            }
        }
    }

    // Stop the bridge capture (if any) before tearing down, so the
    // writer finishes before the bridge disappears. Give the kernel a
    // moment first to flush any in-flight forwarded frames.
    if let Some(c) = capture {
        std::thread::sleep(std::time::Duration::from_millis(200));
        report.captured_packets = c.packets.load(std::sync::atomic::Ordering::Relaxed);
        report.captured_bytes = c.bytes.load(std::sync::atomic::Ordering::Relaxed);
        report.capture_path = Some(c.path.clone());
        c.stop();
        info!(
            packets = report.captured_packets,
            bytes = report.captured_bytes,
            "capture stopped"
        );
    }

    // 5. Teardown (even if some workers failed).
    if let Err(e) = topo.teardown() {
        warn!(error = %e, "topology teardown had errors");
    }

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
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    /// Name of the ProtoReplayer module to use (e.g. "iec104").
    pub proto_name: String,
    pub bridge_name: String,
    pub tap_prefix: String,
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
    /// Each listener binds to its RTU's own IP (auto-aliased onto the
    /// default-route interface) at `listen_port_base`, so 200 RTUs show
    /// up as 200 distinct `rtu_ip:2404` endpoints — no port shifting.
    pub role: protoplay::Role,
    /// Slave-only: TCP port every listener binds on top of its
    /// per-session `listen_ip`. Default 2404.
    pub listen_port_base: u16,
    /// How the replayer should pace its own I-frame sends. Default
    /// [`protoplay::Pacing::AsFastAsPossible`].
    pub pacing: protoplay::Pacing,
    /// Number of times to repeat the captured script. `0` means
    /// loop forever until cancelled. Default `1`. Each iteration
    /// is a fresh connect/handshake/send/close cycle (master) or
    /// accept/handshake/send/close cycle (slave). Per-session
    /// counters and latency samples accumulate across iterations.
    pub iterations: u64,
    /// SCADA-gateway mode (see doc/scada-lab.md). When
    /// `scada_gateway_ip` is set, the run installs a /32 alias for
    /// this IP on `scada_gateway_iface` for the duration of the run
    /// — answering the SCADA guest's gateway ARP on an isolated
    /// vSwitch. If `upstream_nat_iface` is also set, IP forwarding
    /// is enabled and a MASQUERADE rule is added so SCADA's
    /// non-capture egress reaches the real lab. All side effects
    /// are undone on run teardown.
    pub scada_gateway_ip: Option<Ipv4Addr>,
    pub scada_gateway_iface: Option<String>,
    pub upstream_nat_iface: Option<String>,
    /// Path to the alias state file for crash-safe alias reclamation.
    /// If unset, defaults to `/var/lib/outstation/state-aliases.txt`.
    pub alias_state_path: Option<PathBuf>,
    /// If true, every CP56Time2a embedded in an outgoing IEC 104 ASDU
    /// is rewritten to the wall-clock moment its frame hits the wire
    /// (IV flag preserved from the source, SU follows the chosen
    /// timezone). Scheduler pacing is unchanged, so intra-pcap gaps
    /// are honored and, across `iterations`, each loop emits
    /// timestamps that naturally advance with no backward jumps.
    pub rewrite_cp56_to_now: bool,
    /// Timezone for CP56Time2a rewrite: `"utc"` or `"local"`.
    /// Default `"local"` — matches what most plant SCADA systems
    /// expect on the HMI, with SU bit following server DST state.
    pub cp56_zone: String,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            target_ip: Ipv4Addr::UNSPECIFIED,
            target_port: 2404,
            proto_name: "iec104".into(),
            bridge_name: "pcr_br0".into(),
            tap_prefix: "pcr_t".into(),
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
            alias_state_path: None,
            rewrite_cp56_to_now: false,
            cp56_zone: "local".into(),
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

/// Merge a per-iteration [`protoplay::ProtoReport`] into an accumulator.
/// Counters add, latency samples extend, error short-circuits.
pub fn merge_proto_report(acc: &mut protoplay::ProtoReport, new: protoplay::ProtoReport) {
    acc.connected = acc.connected || new.connected;
    acc.messages_sent = acc.messages_sent.saturating_add(new.messages_sent);
    acc.messages_received = acc.messages_received.saturating_add(new.messages_received);
    acc.bytes_written = acc.bytes_written.saturating_add(new.bytes_written);
    acc.bytes_read = acc.bytes_read.saturating_add(new.bytes_read);
    acc.elapsed_ms = acc.elapsed_ms.saturating_add(new.elapsed_ms);
    acc.window_stalls = acc.window_stalls.saturating_add(new.window_stalls);
    acc.unacked_at_end = new.unacked_at_end;
    acc.latency_samples_us.extend(new.latency_samples_us);
    if acc.error.is_none() && new.error.is_some() {
        acc.error = new.error;
    }
}

/// Parse IEC-104-style APDUs out of `payload` and, for each I-frame,
/// emit a timestamp (relative to the first I-frame, ns) derived from
/// the `packet_offsets` table. Generic enough for any length-prefixed
/// protocol where byte 0 = 0x68 and byte 1 = APCI+ASDU length.
///
/// If no I-frames are found or only one is present (nothing to pace
/// against), returns an empty vec.
pub fn iec104_iframe_times_from(
    payload: &[u8],
    packet_offsets: &[(u64, usize)],
) -> Vec<u64> {
    let mut starts: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i + 6 <= payload.len() {
        if payload[i] != 0x68 {
            i += 1;
            continue;
        }
        let ln = payload[i + 1] as usize;
        if i + 2 + ln > payload.len() {
            break;
        }
        let cf1 = payload[i + 2];
        if cf1 & 0x01 == 0 {
            // I-frame start
            starts.push(i);
        }
        i += 2 + ln;
    }
    if starts.len() < 2 {
        return Vec::new();
    }
    // Binary search packet_offsets for each I-frame start byte.
    let ts_for = |byte: usize| -> u64 {
        let mut lo = 0usize;
        let mut hi = packet_offsets.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if packet_offsets[mid].1 <= byte {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            packet_offsets.first().map(|p| p.0).unwrap_or(0)
        } else {
            packet_offsets[lo - 1].0
        }
    };
    let t0 = ts_for(starts[0]);
    starts.iter().map(|&b| ts_for(b).saturating_sub(t0)).collect()
}

#[derive(Debug, Clone)]
pub struct SessionReport {
    pub src_ip: Ipv4Addr,
    pub src_mac: MacAddr,
    pub tap: String,
    pub flow_idx: usize,
    pub started_at_ns: u64,
    pub proto_report: protoplay::ProtoReport,
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

    // 1. Topology. Reclaim any leftover interfaces from a previously
    //    killed run so bridge/veth create calls don't trip on conflict.
    let reclaimed = reclaim_stale(&cfg.bridge_name, &cfg.tap_prefix).unwrap_or(0);
    if reclaimed > 0 {
        info!(count = reclaimed, "reclaimed stale interfaces before benchmark");
    }
    let mut topo = Topology::new(&cfg.bridge_name);
    topo.create_bridge().context("create bridge")?;
    let _egress_guard = if let Some(nic) = &cfg.egress_nic {
        topo.enslave_existing(nic)
            .with_context(|| format!("enslave {nic}"))?;
        info!(nic, "enslaved egress NIC");
        Some(EgressGuard::install(&cfg.bridge_name, nic))
    } else {
        None
    };

    // SCADA-gateway mode: claim the gateway IP on the inner NIC (the
    // one facing the isolated vSwitch SCADA sits on) and optionally
    // enable upstream NAT. Held until the run ends; Drop undoes it.
    let _gateway_guard = if let (Some(gw_ip), Some(inner)) = (
        cfg.scada_gateway_ip,
        cfg.scada_gateway_iface.as_deref(),
    ) {
        let state_path = cfg
            .alias_state_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/outstation/state-aliases.txt"));
        Some(netctl::GatewayGuard::install(
            inner,
            gw_ip,
            cfg.upstream_nat_iface.as_deref(),
            &state_path,
        ))
    } else {
        None
    };

    // 2. Select flows: TCP flows whose server port matches. Prefer
    //    flow.server when present; fall back to canonical tuple if
    //    the client/server roles were not inferred.
    struct FlowPick {
        flow_idx: usize,
        client_ip: Ipv4Addr,
        client_mac: MacAddr,
        first_pkt_rel_ns: u64,
        payload: Vec<u8>,
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
                let frame_times_ns =
                    iec104_iframe_times_from(&reassembled.payload, &reassembled.packet_offsets);
                picks.push(FlowPick {
                    flow_idx: idx,
                    client_ip,
                    client_mac: src_info.src_mac,
                    first_pkt_rel_ns,
                    payload: reassembled.payload,
                    frame_times_ns,
                });
            }
            Err(e) => {
                warn!(flow = idx, error = %e, "reassembly failed; skipping flow");
            }
        }
    }

    // Collapse to one session per unique client IP. If a given client
    // IP has multiple matching flows, take the first one observed.
    let mut seen_ips: std::collections::HashSet<Ipv4Addr> = Default::default();
    picks.retain(|p| seen_ips.insert(p.client_ip));

    if picks.is_empty() {
        topo.teardown().ok();
        bail!(
            "no flows matching target port {} (tried {} flows)",
            cfg.target_port,
            pcap.flows.len()
        );
    }
    info!(
        sessions = picks.len(),
        target = %cfg.target_ip,
        port = cfg.target_port,
        "benchmark: flows selected"
    );

    // 3. Create one veth port per session with the client IP + MAC
    //    assigned, so the per-session TCP socket bind() succeeds.
    struct SessionBinding {
        pick_idx: usize,
        src_ip: Ipv4Addr,
        src_mac: MacAddr,
        bridge_side: String,
        inject_side: String,
    }
    let mut bindings: Vec<SessionBinding> = Vec::with_capacity(picks.len());
    for (i, p) in picks.iter().enumerate() {
        let bridge_side = format!("{}b{}", cfg.tap_prefix, i);
        let inject_side = match topo.add_port_with_ip(
            &bridge_side,
            Some(p.client_mac),
            Some(p.client_ip),
        ) {
            Ok(inj) => inj,
            Err(e) => {
                warn!(error = %e, iface = %bridge_side, "add_port_with_ip failed");
                topo.teardown().ok();
                return Err(e);
            }
        };
        bindings.push(SessionBinding {
            pick_idx: i,
            src_ip: p.client_ip,
            src_mac: p.client_mac,
            bridge_side,
            inject_side,
        });
    }

    // 4. Start the mirror capture.
    let capture = if let Some(path) = &cfg.capture_path {
        let cap_port_name = "pcr_cap".to_string();
        match topo.add_port(&cap_port_name, None) {
            Ok(_inj) => match Capture::start(&cap_port_name, path) {
                Ok(c) => Some(c),
                Err(e) => {
                    warn!(error = %e, "capture failed to start");
                    None
                }
            },
            Err(e) => {
                warn!(error = %e, "could not create capture mirror port");
                None
            }
        }
    } else {
        None
    };

    // 5. Pre-populate RunContext per-source progress. The `planned`
    //    count is left at 0 — the protocol replayer populates it as
    //    soon as it has parsed the client payload.
    {
        let mut sp = ctx.per_source.lock().unwrap();
        sp.clear();
        for b in &bindings {
            sp.push(SourceProgress {
                src_ip: Some(b.src_ip),
                src_mac: b.src_mac,
                tap: b.bridge_side.clone(),
                planned: Arc::new(AtomicU64::new(0)),
                sent: Arc::new(AtomicU64::new(0)),
                bytes: Arc::new(AtomicU64::new(0)),
                received: Arc::new(AtomicU64::new(0)),
                unacked: Arc::new(AtomicU64::new(0)),
                ready: Arc::new(AtomicBool::new(true)),
                state: Arc::new(AtomicU8::new(protoplay::session_state::PENDING)),
                cancel: Arc::new(AtomicBool::new(false)),
                listen_port: 0,
                listen_ip: Arc::new(Mutex::new(Ipv4Addr::UNSPECIFIED)),
            });
        }
    }
    ctx.planned.store(picks.len() as u64, Ordering::Relaxed);

    // 6. Warmup.
    if cfg.startup_delay_secs > 0 {
        info!(
            seconds = cfg.startup_delay_secs,
            bridge = %cfg.bridge_name,
            "benchmark warmup: interfaces are live"
        );
        sleep_interruptible(Duration::from_secs(cfg.startup_delay_secs), &ctx.cancel);
        if ctx.is_cancelled() {
            if let Some(c) = capture {
                c.stop();
            }
            topo.teardown().ok();
            return Ok(BenchmarkReport::default());
        }
    }

    // 7. Spawn one session worker per binding.
    let run_start_ns = now_ns();
    ctx.started_packets_at_ns
        .store(run_start_ns, Ordering::Relaxed);
    let mut handles: Vec<thread::JoinHandle<SessionReport>> = Vec::new();

    for b in bindings.into_iter() {
        if ctx.is_cancelled() {
            break;
        }
        // Mutable borrow so we can move the payload + timings out of
        // the pick entry instead of cloning. After this loop iteration
        // the pick's bytes are freed; the worker thread owns the only
        // copy.
        let pick = &mut picks[b.pick_idx];
        let flow_idx = pick.flow_idx;
        let first_pkt_rel_ns = pick.first_pkt_rel_ns;
        let payload = std::mem::take(&mut pick.payload);
        let frame_times_ns = std::mem::take(&mut pick.frame_times_ns);
        let replayer = Arc::clone(&replayer);
        let cfg_cloned = cfg.clone();
        let src_ip = b.src_ip;
        let src_mac = b.src_mac;
        let bridge_side = b.bridge_side.clone();
        let inject_side = b.inject_side.clone();
        let ctx_worker = ctx.clone();
        let worker_idx = b.pick_idx;

        // Build a MessageProgress sink that shares atomics with this
        // session's SourceProgress entry. The replayer will update
        // sent/received/bytes/planned as it runs, and the webui's
        // refresh_progress reads those atomics on every /api/runs tick.
        let session_progress = {
            let sp = ctx.per_source.lock().unwrap();
            let entry = &sp[worker_idx];
            protoplay::MessageProgress {
                planned: Arc::clone(&entry.planned),
                sent: Arc::clone(&entry.sent),
                received: Arc::clone(&entry.received),
                bytes_written: Arc::clone(&entry.bytes),
                bytes_read: Arc::new(AtomicU64::new(0)),
                unacked: Arc::clone(&entry.unacked),
                ready: Arc::clone(&entry.ready),
                state: Arc::clone(&entry.state),
                cancel: Arc::clone(&entry.cancel),
            }
        };

        let handle = thread::Builder::new()
            .name(format!("bench-{src_ip}"))
            .spawn(move || {
                // Stagger start if requested.
                if matches!(cfg_cloned.concurrency, ConcurrencyModel::StaggeredPcapTiming)
                    && first_pkt_rel_ns > 0
                {
                    let wait = Duration::from_nanos(first_pkt_rel_ns);
                    sleep_interruptible(wait, &ctx_worker.cancel);
                }
                if ctx_worker.is_cancelled() {
                    {
                        let sp = ctx_worker.per_source.lock().unwrap();
                        if let Some(p) = sp.get(worker_idx) {
                            p.state.store(
                                protoplay::session_state::CANCELLED,
                                Ordering::Relaxed,
                            );
                        }
                    }
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
                    };
                }

                let started_at_ns = now_ns();
                info!(%src_ip, flow_idx, bytes = payload.len(), "benchmark session starting");
                // Loop the connect/handshake/send/close cycle across
                // iterations. Each iteration consumes a fresh
                // ProtoRunCfg with the same payload (cloned from the
                // outer Vec because the replayer takes ownership per
                // call), and accumulates into `pr`.
                let target_iters = effective_iterations(cfg_cloned.iterations);
                let mut pr = protoplay::ProtoReport::default();
                let session_progress_arc = std::sync::Arc::new(session_progress);
                let payload_arc = std::sync::Arc::new(payload);
                let frame_times_arc = std::sync::Arc::new(frame_times_ns);
                let mut cancelled_mid_run = false;
                for iter_idx in 0..target_iters {
                    let session_cancelled = {
                        let sp = ctx_worker.per_source.lock().unwrap();
                        sp.get(worker_idx).map(|p| p.is_cancelled()).unwrap_or(false)
                    };
                    if ctx_worker.is_cancelled() || session_cancelled {
                        cancelled_mid_run = true;
                        break;
                    }
                    let run_cfg = ProtoRunCfg {
                        bind_ip: src_ip,
                        bind_iface: Some(bridge_side.clone()),
                        target_ip: cfg_cloned.target_ip,
                        target_port: cfg_cloned.target_port,
                        client_segments: vec![ClientSegment {
                            rel_ts_ns: 0,
                            bytes: (*payload_arc).clone(),
                        }],
                        connect_timeout: Duration::from_secs(cfg_cloned.connect_timeout_secs),
                        speed: 1.0,
                        proto_config: cfg_cloned.proto_config.clone(),
                        progress: Some((*session_progress_arc).clone()),
                        role: protoplay::Role::Master,
                        listen_port: 0,
                        pacing: cfg_cloned.pacing,
                        frame_times_ns: (*frame_times_arc).clone(),
                        rewrite_cp56_to_now: cfg_cloned.rewrite_cp56_to_now,
                        cp56_zone: cfg_cloned.cp56_zone.clone(),
                    };
                    let iter_report = replayer.run(run_cfg);
                    let had_error = iter_report.error.is_some();
                    merge_proto_report(&mut pr, iter_report);
                    if had_error {
                        break;
                    }
                    let _ = iter_idx;
                }

                // Final reconciliation: the replayer's live-updated
                // atomics should already match pr.messages_sent, but
                // snap them to the authoritative totals to close any
                // ordering gap on the last few frames. Also pin the
                // session state so the UI stops showing it as ACTIVE.
                let sp = ctx_worker.per_source.lock().unwrap();
                if let Some(p) = sp.get(worker_idx) {
                    p.sent.store(pr.messages_sent, Ordering::Relaxed);
                    p.bytes.store(pr.bytes_written, Ordering::Relaxed);
                    p.received.store(pr.messages_received, Ordering::Relaxed);
                    p.unacked.store(pr.unacked_at_end, Ordering::Relaxed);
                    let final_state = if cancelled_mid_run {
                        protoplay::session_state::CANCELLED
                    } else if pr.error.is_some() {
                        protoplay::session_state::FAILED
                    } else {
                        protoplay::session_state::COMPLETED
                    };
                    p.state.store(final_state, Ordering::Relaxed);
                }
                drop(sp);
                ctx_worker.sent.fetch_add(1, Ordering::Relaxed);

                info!(
                    %src_ip,
                    messages_sent = pr.messages_sent,
                    messages_received = pr.messages_received,
                    p50_us = pr.latency_p50_us,
                    p99_us = pr.latency_p99_us,
                    cancelled = cancelled_mid_run,
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
                }
            })
            .context("spawn benchmark thread")?;
        handles.push(handle);
    }

    // 8. Join all sessions and build the report.
    let mut report = BenchmarkReport::default();
    for h in handles {
        match h.join() {
            Ok(sr) => {
                report.total_messages_sent += sr.proto_report.messages_sent;
                report.total_messages_received += sr.proto_report.messages_received;
                report
                    .aggregate_latency_samples_us
                    .extend_from_slice(&sr.proto_report.latency_samples_us);
                report.per_session.push(sr);
            }
            Err(_) => warn!("benchmark worker panicked"),
        }
    }

    // Cross-session latency percentiles.
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

    // 9. Stop capture, teardown.
    if let Some(c) = capture {
        std::thread::sleep(Duration::from_millis(200));
        report.captured_packets = c.packets.load(Ordering::Relaxed);
        report.captured_bytes = c.bytes.load(Ordering::Relaxed);
        report.capture_path = Some(c.path.clone());
        c.stop();
    }
    if let Err(e) = topo.teardown() {
        warn!(error = %e, "benchmark teardown had errors");
    }

    Ok(report)
}

/// Slave-mode benchmark: outstation binds a TcpListener per captured
/// RTU on an incrementing port starting at `cfg.listen_port_base` and
/// waits for the live target master to connect to each. No veth
/// topology — sessions live in the host's own network namespace.
fn run_benchmark_slave(
    pcap: Arc<LoadedPcap>,
    cfg: BenchmarkConfig,
    replayer: Arc<dyn protoplay::ProtoReplayer>,
    ctx: RunContext,
) -> Result<BenchmarkReport> {
    use protoplay::{ClientSegment, ProtoRunCfg};

    // 1. Pick one flow per unique server (RTU) IP whose server port
    //    matches the user's target port filter.
    struct SlavePick {
        flow_idx: usize,
        server_ip: Ipv4Addr,
        server_mac: MacAddr,
        payload: Vec<u8>,
        frame_times_ns: Vec<u64>,
    }
    let mut picks: Vec<SlavePick> = Vec::new();
    let mut seen: std::collections::HashSet<Ipv4Addr> = Default::default();
    for (idx, flow) in pcap.flows.iter().enumerate() {
        let Some((_, server_port)) = flow.server else {
            continue;
        };
        if server_port != cfg.target_port {
            continue;
        }
        let Some((server_ip, _)) = flow.server else {
            continue;
        };
        if !seen.insert(server_ip) {
            continue;
        }
        let server_mac = pcap
            .sources
            .get(&server_ip)
            .map(|s| s.src_mac)
            .unwrap_or([0; 6]);
        match pcap.reassemble_server_payload(idx) {
            Ok(r) => {
                let frame_times_ns =
                    iec104_iframe_times_from(&r.payload, &r.packet_offsets);
                picks.push(SlavePick {
                    flow_idx: idx,
                    server_ip,
                    server_mac,
                    payload: r.payload,
                    frame_times_ns,
                });
            }
            Err(e) => {
                warn!(flow = idx, error = %e, "slave: server reassembly failed, skipping");
            }
        }
    }

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

    // 2. Pre-populate RunContext per-source progress, one entry per
    //    RTU/listener so the web UI can draw a live per-session bar.
    //    Default listen_ip to the RTU's own address from the pcap;
    //    that way the per-listener auto-alias in the worker kicks in
    //    without the user having to edit every row by hand.
    {
        let mut sp = ctx.per_source.lock().unwrap();
        sp.clear();
        for (_i, p) in picks.iter().enumerate() {
            // All listeners share the same port; the RTU IP is the
            // discriminator. Binds don't collide because listen_ip is
            // unique per session.
            let listen_port = cfg.listen_port_base;
            let tap = format!("{}:{listen_port}", p.server_ip);
            sp.push(SourceProgress {
                src_ip: Some(p.server_ip),
                src_mac: p.server_mac,
                tap,
                planned: Arc::new(AtomicU64::new(0)),
                sent: Arc::new(AtomicU64::new(0)),
                bytes: Arc::new(AtomicU64::new(0)),
                received: Arc::new(AtomicU64::new(0)),
                unacked: Arc::new(AtomicU64::new(0)),
                ready: Arc::new(AtomicBool::new(false)),
                state: Arc::new(AtomicU8::new(protoplay::session_state::PENDING)),
                cancel: Arc::new(AtomicBool::new(false)),
                listen_port,
                listen_ip: Arc::new(Mutex::new(p.server_ip)),
            });
        }
    }
    ctx.planned.store(picks.len() as u64, Ordering::Relaxed);

    // SCADA-gateway mode: same deal as the master path — claim the
    // gateway IP so SCADA's SYNs to off-subnet slave IPs land on us
    // instead of being routed into the void, and optionally NAT
    // SCADA's non-capture egress out a second NIC.
    let _gateway_guard = if let (Some(gw_ip), Some(inner)) = (
        cfg.scada_gateway_ip,
        cfg.scada_gateway_iface.as_deref(),
    ) {
        let state_path = cfg
            .alias_state_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/outstation/state-aliases.txt"));
        Some(netctl::GatewayGuard::install(
            inner,
            gw_ip,
            cfg.upstream_nat_iface.as_deref(),
            &state_path,
        ))
    } else {
        None
    };

    // 3. Warmup.
    if cfg.startup_delay_secs > 0 {
        info!(
            seconds = cfg.startup_delay_secs,
            "slave warmup: listeners not yet bound — attach tooling to target side"
        );
        sleep_interruptible(Duration::from_secs(cfg.startup_delay_secs), &ctx.cancel);
        if ctx.is_cancelled() {
            return Ok(BenchmarkReport::default());
        }
    }

    // 4. Spawn one listener thread per RTU.
    let run_start_ns = now_ns();
    ctx.started_packets_at_ns
        .store(run_start_ns, Ordering::Relaxed);
    let mut handles: Vec<thread::JoinHandle<SessionReport>> = Vec::new();

    for (idx, pick) in picks.into_iter().enumerate() {
        if ctx.is_cancelled() {
            break;
        }
        let flow_idx = pick.flow_idx;
        // `pick` is owned by this iteration — move payload+timings
        // straight into the worker, no clone (saves ~payload bytes
        // per session at large RTU counts).
        let payload = pick.payload;
        let frame_times_ns = pick.frame_times_ns;
        let replayer = Arc::clone(&replayer);
        let cfg_cloned = cfg.clone();
        let src_ip = pick.server_ip;
        let src_mac = pick.server_mac;
        let listen_port = cfg.listen_port_base;
        let tap_label = format!("{}:{}", src_ip, listen_port);
        let ctx_worker = ctx.clone();
        let worker_idx = idx;

        // (listen_ip is snapshotted inside the worker body, after
        // the ready gate — the user can edit it up until they click
        // start.)
        let session_progress = {
            let sp = ctx.per_source.lock().unwrap();
            let entry = &sp[worker_idx];
            protoplay::MessageProgress {
                planned: Arc::clone(&entry.planned),
                sent: Arc::clone(&entry.sent),
                received: Arc::clone(&entry.received),
                bytes_written: Arc::clone(&entry.bytes),
                bytes_read: Arc::new(AtomicU64::new(0)),
                unacked: Arc::clone(&entry.unacked),
                ready: Arc::clone(&entry.ready),
                state: Arc::clone(&entry.state),
                cancel: Arc::clone(&entry.cancel),
            }
        };

        let handle = thread::Builder::new()
            .name(format!("bench-slave-{src_ip}"))
            .spawn(move || {
                // Wait for the user to flip `ready` for this slave.
                // Also bail on run-level or per-session cancel. Both
                // cancel paths write state=CANCELLED so the UI stops
                // showing the slot as "pending" after a STOP click.
                loop {
                    let run_cancelled = ctx_worker.is_cancelled();
                    let (is_ready, is_cancelled) = {
                        let sp = ctx_worker.per_source.lock().unwrap();
                        let e = &sp[worker_idx];
                        (e.is_ready(), e.is_cancelled())
                    };
                    if run_cancelled || is_cancelled {
                        let msg = if run_cancelled {
                            "cancelled before start"
                        } else {
                            "slave cancelled before start"
                        };
                        let mut pr = protoplay::ProtoReport::default();
                        pr.error = Some(msg.into());
                        let sp = ctx_worker.per_source.lock().unwrap();
                        if let Some(p) = sp.get(worker_idx) {
                            p.state.store(
                                protoplay::session_state::CANCELLED,
                                Ordering::Relaxed,
                            );
                        }
                        drop(sp);
                        return SessionReport {
                            src_ip,
                            src_mac,
                            tap: tap_label,
                            flow_idx,
                            started_at_ns: now_ns(),
                            proto_report: pr,
                        };
                    }
                    if is_ready {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }

                // Snapshot the user-edited listen IP right after the
                // ready gate falls. This is the last moment before
                // the listener actually binds a socket.
                let listen_ip = {
                    let sp = ctx_worker.per_source.lock().unwrap();
                    sp[worker_idx].snapshot_listen_ip()
                };

                // If the user picked a specific IP and it isn't
                // already assigned to a local interface, alias it
                // onto the default-route interface so `bind()` works.
                // We track what we added so we can remove it after
                // the session finishes — and also persist to a state
                // file so a server crash mid-run doesn't leak the
                // alias forever (startup reclaim picks it up).
                let mut added_alias: Option<(String, Ipv4Addr, u8)> = None;
                let alias_state = std::path::PathBuf::from("/var/lib/outstation/state-aliases.txt");
                if !listen_ip.is_unspecified() {
                    let already_local = netctl::list_local_ipv4()
                        .ok()
                        .map(|v| v.iter().any(|x| x.ip == listen_ip))
                        .unwrap_or(false);
                    if !already_local {
                        match netctl::default_route_iface() {
                            Ok(iface) => {
                                let prefix = netctl::find_iface_prefix(&iface).unwrap_or(24);
                                match netctl::add_ip_alias(&iface, listen_ip, prefix) {
                                    Ok(()) => {
                                        netctl::record_alias(
                                            &alias_state,
                                            &iface,
                                            listen_ip,
                                            prefix,
                                        );
                                        info!(
                                            %listen_ip,
                                            %iface,
                                            prefix,
                                            "auto-aliased listen ip"
                                        );
                                        added_alias = Some((iface, listen_ip, prefix));
                                    }
                                    Err(e) => {
                                        warn!(
                                            %listen_ip,
                                            error = %e,
                                            "alias add failed; bind will error"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "could not detect default route iface for alias");
                            }
                        }
                    }
                }

                let started_at_ns = now_ns();
                info!(
                    %src_ip,
                    %listen_ip,
                    listen_port,
                    bytes = payload.len(),
                    aliased = added_alias.is_some(),
                    "slave session opening listener"
                );
                // Loop the listen/accept/handshake/send/close cycle
                // across iterations. Same merge semantics as master.
                let target_iters = effective_iterations(cfg_cloned.iterations);
                let mut pr = protoplay::ProtoReport::default();
                let session_progress_arc = std::sync::Arc::new(session_progress);
                let payload_arc = std::sync::Arc::new(payload);
                let frame_times_arc = std::sync::Arc::new(frame_times_ns);
                let mut cancelled_mid_run = false;
                for iter_idx in 0..target_iters {
                    let session_cancelled = {
                        let sp = ctx_worker.per_source.lock().unwrap();
                        sp.get(worker_idx).map(|p| p.is_cancelled()).unwrap_or(false)
                    };
                    if ctx_worker.is_cancelled() || session_cancelled {
                        cancelled_mid_run = true;
                        break;
                    }
                    let run_cfg = ProtoRunCfg {
                        bind_ip: listen_ip,
                        bind_iface: None,
                        target_ip: cfg_cloned.target_ip,
                        target_port: cfg_cloned.target_port,
                        client_segments: vec![ClientSegment {
                            rel_ts_ns: 0,
                            bytes: (*payload_arc).clone(),
                        }],
                        connect_timeout: Duration::from_secs(cfg_cloned.connect_timeout_secs),
                        speed: 1.0,
                        proto_config: cfg_cloned.proto_config.clone(),
                        progress: Some((*session_progress_arc).clone()),
                        role: protoplay::Role::Slave,
                        listen_port,
                        pacing: cfg_cloned.pacing,
                        frame_times_ns: (*frame_times_arc).clone(),
                        rewrite_cp56_to_now: cfg_cloned.rewrite_cp56_to_now,
                        cp56_zone: cfg_cloned.cp56_zone.clone(),
                    };
                    let iter_report = replayer.run(run_cfg);
                    let had_error = iter_report.error.is_some();
                    merge_proto_report(&mut pr, iter_report);
                    if had_error {
                        break;
                    }
                    let _ = iter_idx;
                }

                // Clean up any alias we added before this session.
                if let Some((iface, ip, prefix)) = added_alias.take() {
                    match netctl::del_ip_alias(&iface, ip, prefix) {
                        Ok(()) => info!(%ip, %iface, "removed temp ip alias"),
                        Err(e) => warn!(%ip, %iface, error = %e, "alias cleanup failed"),
                    }
                    netctl::forget_alias(&alias_state, &iface, ip, prefix);
                }

                let sp = ctx_worker.per_source.lock().unwrap();
                if let Some(p) = sp.get(worker_idx) {
                    p.sent.store(pr.messages_sent, Ordering::Relaxed);
                    p.bytes.store(pr.bytes_written, Ordering::Relaxed);
                    p.received.store(pr.messages_received, Ordering::Relaxed);
                    p.unacked.store(pr.unacked_at_end, Ordering::Relaxed);
                    let final_state = if cancelled_mid_run {
                        protoplay::session_state::CANCELLED
                    } else if pr.error.is_some() {
                        protoplay::session_state::FAILED
                    } else {
                        protoplay::session_state::COMPLETED
                    };
                    p.state.store(final_state, Ordering::Relaxed);
                }
                drop(sp);
                ctx_worker.sent.fetch_add(1, Ordering::Relaxed);

                info!(
                    %src_ip,
                    listen_port,
                    messages_sent = pr.messages_sent,
                    messages_received = pr.messages_received,
                    p50_us = pr.latency_p50_us,
                    p99_us = pr.latency_p99_us,
                    cancelled = cancelled_mid_run,
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
                }
            })
            .context("spawn slave benchmark thread")?;
        handles.push(handle);
    }

    // 5. Join all and aggregate.
    let mut report = BenchmarkReport::default();
    for h in handles {
        match h.join() {
            Ok(sr) => {
                report.total_messages_sent += sr.proto_report.messages_sent;
                report.total_messages_received += sr.proto_report.messages_received;
                report
                    .aggregate_latency_samples_us
                    .extend_from_slice(&sr.proto_report.latency_samples_us);
                report.per_session.push(sr);
            }
            Err(_) => warn!("slave benchmark worker panicked"),
        }
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

    Ok(report)
}
