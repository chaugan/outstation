//! Raw L2 replay ([`run`]): one bridge port and one replay worker per
//! captured source, all pacing against one shared epoch.

use super::*;

// -----------------------------------------------------------------------------
// Start barrier.
// -----------------------------------------------------------------------------

/// Start barrier for raw-replay workers. Every worker arrives (with or
/// without a usable plan); the coordinator waits for all of them, then
/// publishes one epoch everybody paces against. Unlike
/// `std::sync::Barrier` it can be aborted, so a failed spawn or a
/// cancel never leaves workers blocked forever.
#[derive(Default)]
pub(crate) struct StartGate {
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
    pub(crate) fn arrive_failed(&self) {
        self.lock().arrived += 1;
        self.cv.notify_all();
    }

    /// Arrive and wait for the epoch. `None` if aborted or cancelled.
    pub(crate) fn arrive_and_wait(&self, cancel: &AtomicBool) -> Option<u64> {
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
    pub(crate) fn wait_for(&self, n: usize, cancel: &AtomicBool) -> bool {
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

    pub(crate) fn open(&self, epoch: u64) {
        self.lock().epoch = Some(epoch);
        self.cv.notify_all();
    }

    pub(crate) fn abort(&self) {
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
pub(crate) fn pass_epoch(epoch0: u64, k: u64, pass_ns: u64) -> u64 {
    epoch0.saturating_add(k.saturating_mul(pass_ns))
}

/// Decide which raw workers may run SCHED_FIFO: none with top speed
/// (they never sleep), otherwise at most `budget` (cores - 1).
pub(crate) fn realtime_plan(
    realtime: bool,
    top_speed: bool,
    workers: usize,
    budget: usize,
) -> Vec<bool> {
    let active = realtime && !top_speed;
    (0..workers).map(|i| active && i < budget).collect()
}

/// Validate a raw-run config before anything touches the host.
pub(crate) fn validate_run_cfg(cfg: &RunConfig) -> Result<IfaceNames> {
    if !cfg.top_speed && !(cfg.speed.is_finite() && cfg.speed > 0.0) {
        bail!("speed must be a positive number, got {}", cfg.speed);
    }
    IfaceNames::custom(
        cfg.run_id,
        cfg.bridge_name.as_deref(),
        cfg.tap_prefix.as_deref(),
    )
}

/// Replay `pcap` once per source port onto the run's bridge: set up
/// the topology and ports, start the workers on one shared epoch, join
/// them, then tear everything down.
pub fn run(pcap: Arc<LoadedPcap>, cfg: RunConfig, ctx: RunContext) -> Result<RunReport> {
    let names = validate_run_cfg(&cfg)?;
    let state_dir = state_dir_or_default(&cfg.state_dir);
    let prot = Protection::new(cfg.protected_addrs.clone(), cfg.force_protected_nic);
    let mut warnings: Vec<String> = Vec::new();

    // 1. Topology, one port per source, realtime policy, capture.
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
    let workers = add_raw_ports(&pcap, &cfg, &names, &mut res)?;
    info!(sources = workers.len(), bridge = %names.bridge, "topology up");
    let rt_plan = raw_realtime_plan(&cfg, workers.len(), &mut warnings);
    let mut capture = CaptureOutcome {
        requested: cfg.capture_path.is_some(),
        ..Default::default()
    };
    if let Some(path) = &cfg.capture_path {
        let opts = CaptureOpts {
            rt_priority: capture_rt_priority(),
            max_bytes: cfg.capture_max_bytes,
        };
        capture.open_failed = !start_capture(&mut res, &names, path, opts, &mut warnings);
    }
    let progress = init_raw_progress(&ctx, &workers, cfg.iterations);

    // 2. Warmup.
    if cfg.startup_delay_secs > 0 {
        info!(
            seconds = cfg.startup_delay_secs,
            bridge = %names.bridge,
            "warmup: interfaces are live — attach Wireshark / tcpdump now"
        );
        if !warmup_elapsed(&ctx, cfg.startup_delay_secs) {
            info!("run cancelled during warmup, tearing down");
            let mut report = RunReport::default();
            capture.stats = collect_capture(&mut res, &mut warnings);
            report.set_capture(&capture);
            report.warnings = warnings;
            res.finish(&mut report.warnings);
            return Ok(report);
        }
        info!("warmup elapsed, starting replay workers");
    }

    // 3. Workers build their plans, meet at the start gate and pace
    //    against one shared epoch (F031).
    let schedule = RawSchedule::new(&pcap, &cfg, &workers);
    let gate = Arc::new(StartGate::default());
    let handles =
        match spawn_raw_workers(&pcap, workers, &progress, &rt_plan, schedule, &gate, &ctx) {
            Ok(h) => h,
            Err(e) => {
                res.finish(&mut Vec::new());
                return Err(e);
            }
        };
    release_start_gate(&gate, handles.len(), &ctx);

    // 4. Join and aggregate.
    let mut report = join_raw_workers(handles);

    // 5. Stop the capture (flush first), then tear everything down.
    capture.stats = collect_capture(&mut res, &mut warnings);
    report.set_capture(&capture);
    report.warnings.extend(warnings);
    res.finish(&mut report.warnings);
    Ok(report)
}

/// One raw-replay worker: its bridge port and the packets it injects.
struct RawWorker {
    ip: Option<Ipv4Addr>,
    mac: MacAddr,
    kind: SourceKind,
    inject_side: String,
    packet_indices: Vec<usize>,
}

/// Add one bridge port per replayed source (IPv4 sources, then non-IP
/// ones if enabled). Fails if there is nothing to replay.
fn add_raw_ports(
    pcap: &LoadedPcap,
    cfg: &RunConfig,
    names: &IfaceNames,
    res: &mut RunResources,
) -> Result<Vec<RawWorker>> {
    let wanted: Option<std::collections::HashSet<Ipv4Addr>> = cfg
        .filter_sources
        .as_ref()
        .map(|v| v.iter().copied().collect());
    let topo = res.topo.as_mut().context("topology missing")?;
    let mut workers: Vec<RawWorker> = Vec::new();
    let mut specs: Vec<netctl::PortSpec> = Vec::new();
    for (idx, (ip, src)) in pcap
        .sources
        .iter()
        .filter(|(ip, _)| wanted.as_ref().is_none_or(|s| s.contains(ip)))
        .enumerate()
    {
        specs.push(netctl::PortSpec {
            id: names.port(PortKind::RawIp, idx)?,
            mac: Some(src.src_mac),
            src_ip: None,
        });
        workers.push(RawWorker {
            ip: Some(*ip),
            mac: src.src_mac,
            kind: SourceKind::Ipv4,
            inject_side: String::new(),
            packet_indices: src.packet_indices.clone(),
        });
    }
    if cfg.include_non_ip {
        for (idx, (mac, info)) in pcap.non_ip_sources.iter().enumerate() {
            specs.push(netctl::PortSpec {
                id: names.port(PortKind::RawL2, idx)?,
                mac: Some(*mac),
                src_ip: None,
            });
            workers.push(RawWorker {
                ip: None,
                mac: *mac,
                kind: SourceKind::NonIp,
                inject_side: String::new(),
                packet_indices: info.packet_indices.clone(),
            });
        }
    }
    // One batch, built in parallel (T17c).
    let injects = topo
        .add_ports(&specs, &netctl::Protection::default())
        .context("add replay ports")?;
    for (w, inject) in workers.iter_mut().zip(injects) {
        w.inject_side = inject;
    }
    if workers.is_empty() {
        bail!("nothing to replay (no IPv4 sources and include_non_ip disabled)");
    }
    Ok(workers)
}

/// Which workers run SCHED_FIFO (F032/F045), with a warning when the
/// request could not be honoured in full.
fn raw_realtime_plan(cfg: &RunConfig, workers: usize, warnings: &mut Vec<String>) -> Vec<bool> {
    let rt_plan = realtime_plan(
        cfg.realtime,
        cfg.top_speed,
        workers,
        realtime_thread_budget(),
    );
    if cfg.realtime && cfg.top_speed {
        warnings.push(
            "realtime ignored: top-speed workers never sleep and would starve the host".into(),
        );
    } else if cfg.realtime && rt_plan.iter().any(|b| !*b) {
        warnings.push(format!(
            "realtime: only {} of {} workers promoted to SCHED_FIFO (cores - 1)",
            rt_plan.iter().filter(|b| **b).count(),
            workers
        ));
    }
    rt_plan
}

/// Pre-populate `ctx.per_source` and `ctx.planned` so the webui sees a
/// full picture as soon as the run is queryable.
fn init_raw_progress(
    ctx: &RunContext,
    workers: &[RawWorker],
    iterations: u64,
) -> Vec<SourceProgress> {
    let progress: Vec<SourceProgress> = {
        let mut sp = ctx.sources();
        sp.clear();
        for w in workers {
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
    progress
}

/// Pacing parameters shared by every worker of a run.
#[derive(Clone, Copy)]
struct RawSchedule {
    pace: Pace,
    /// Length of one pass (pcap span / speed + [`PASS_GAP_NS`]).
    pass_ns: u64,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_iters: u64,
}

impl RawSchedule {
    fn new(pcap: &LoadedPcap, cfg: &RunConfig, workers: &[RawWorker]) -> Self {
        let span_ns = workers
            .iter()
            .flat_map(|w| w.packet_indices.iter())
            .map(|i| pcap.packets[*i].rel_ts_ns)
            .max()
            .unwrap_or(0);
        Self {
            pace: if cfg.top_speed {
                Pace::TopSpeed
            } else {
                Pace::Original { speed: cfg.speed }
            },
            pass_ns: schedule_offset_ns(span_ns, cfg.speed).saturating_add(PASS_GAP_NS),
            target_ip: cfg.target_ip,
            target_mac: cfg.target_mac,
            target_iters: effective_iterations(cfg.iterations),
        }
    }
}

/// Everything one worker thread owns.
struct RawJob {
    worker: RawWorker,
    pcap: Arc<LoadedPcap>,
    ctx: RunContext,
    sp: SourceProgress,
    gate: Arc<StartGate>,
    promote: bool,
    schedule: RawSchedule,
}

/// Spawn one worker per port. A failed spawn cancels and joins the
/// workers already started and returns the error (F034); the caller
/// tears the host down.
fn spawn_raw_workers(
    pcap: &Arc<LoadedPcap>,
    workers: Vec<RawWorker>,
    progress: &[SourceProgress],
    rt_plan: &[bool],
    schedule: RawSchedule,
    gate: &Arc<StartGate>,
    ctx: &RunContext,
) -> Result<Vec<thread::JoinHandle<Result<SourceReport>>>> {
    let mut handles: Vec<thread::JoinHandle<Result<SourceReport>>> =
        Vec::with_capacity(workers.len());
    for (worker_idx, worker) in workers.into_iter().enumerate() {
        let thread_name = match worker.ip {
            Some(i) => format!("replay-{i}"),
            None => format!(
                "replay-l2-{:02x}{:02x}{:02x}",
                worker.mac[3], worker.mac[4], worker.mac[5]
            ),
        };
        let job = RawJob {
            worker,
            pcap: Arc::clone(pcap),
            ctx: ctx.clone(),
            sp: progress[worker_idx].clone(),
            gate: Arc::clone(gate),
            promote: rt_plan[worker_idx],
            schedule,
        };
        match spawn_named(thread_name, move || raw_worker(job)) {
            Ok(h) => handles.push(h),
            Err(e) => {
                warn!(error = %e, "spawn of replay worker failed; aborting run");
                ctx.cancel_all();
                gate.abort();
                for h in handles {
                    let _ = h.join();
                }
                return Err(anyhow::Error::new(e).context("spawn replay thread"));
            }
        }
    }
    Ok(handles)
}

/// Once every worker built its plan (or failed), publish the epoch;
/// abort the gate if the run was cancelled first.
fn release_start_gate(gate: &StartGate, workers: usize, ctx: &RunContext) {
    if gate.wait_for(workers, &ctx.cancel) {
        let epoch = now_ns() + EPOCH_LEAD_NS;
        ctx.started_packets_at_ns.store(epoch, Ordering::Relaxed);
        gate.open(epoch);
    } else {
        gate.abort();
    }
}

/// Build the worker's frame plan (rewritten for the target) and bind
/// its injection socket.
fn prepare_raw_plan(job: &RawJob) -> Result<(RawReplayer, Plan)> {
    let w = &job.worker;
    let replayer = RawReplayer::bind(&w.inject_side)
        .with_context(|| format!("bind AF_PACKET on {}", w.inject_side))?;
    let mut plan = Plan::default();
    let mut rewrite_failures = 0u64;
    for i in &w.packet_indices {
        let pkt = &job.pcap.packets[*i];
        let mut data = pkt.ether_frame().into_owned();
        if w.kind == SourceKind::Ipv4 {
            if let Err(e) =
                rewrite_in_place(&mut data, job.schedule.target_ip, job.schedule.target_mac)
            {
                warn!(error = %e, "frame rewrite failed, skipping");
                rewrite_failures += 1;
                continue;
            }
        }
        plan.push(pkt.rel_ts_ns, data);
    }
    info!(
        ip = ?w.ip,
        tap = w.inject_side,
        kind = ?w.kind,
        frames = plan.len(),
        rewrite_failures,
        "replay worker ready"
    );
    Ok((replayer, plan))
}

/// Body of one worker thread: prepare, wait at the gate, replay every
/// pass, report.
fn raw_worker(job: RawJob) -> Result<SourceReport> {
    // Fallible preparation, isolated so the gate always learns about
    // this worker, even on a panic.
    let prep = catch_unwind(AssertUnwindSafe(|| prepare_raw_plan(&job)));
    let (replayer, plan) = match prep {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            job.gate.arrive_failed();
            return Err(e);
        }
        Err(_) => {
            job.gate.arrive_failed();
            bail!(
                "replay worker for {} panicked while preparing",
                job.worker.inject_side
            );
        }
    };
    let RawJob {
        worker,
        ctx,
        sp,
        gate,
        promote,
        schedule,
        ..
    } = job;
    sp.planned.store(plan.len() as u64, Ordering::Relaxed);
    if promote && !try_set_realtime(REPLAY_RT_PRIORITY) {
        warn!(
            tap = worker.inject_side,
            "SCHED_FIFO unavailable (CAP_SYS_NICE?)"
        );
    }
    let mut acc = RunStats::default();
    if let Some(epoch0) = gate.arrive_and_wait(&ctx.cancel) {
        acc = replay_passes(&replayer, &plan, &schedule, epoch0, &ctx, &sp);
        sp.state.store(
            if ctx.is_cancelled() {
                protoplay::session_state::CANCELLED
            } else {
                protoplay::session_state::COMPLETED
            },
            Ordering::Relaxed,
        );
    }
    Ok(SourceReport {
        src_ip: worker.ip,
        src_mac: worker.mac,
        tap: worker.inject_side,
        kind: worker.kind,
        stats: acc,
    })
}

/// Replay `plan` for every pass from `epoch0`, accumulating the stats.
fn replay_passes(
    replayer: &RawReplayer,
    plan: &Plan,
    schedule: &RawSchedule,
    epoch0: u64,
    ctx: &RunContext,
    sp: &SourceProgress,
) -> RunStats {
    let mut acc = RunStats::default();
    let mut weighted_jitter: u128 = 0;
    for k in 0..schedule.target_iters {
        if ctx.is_cancelled() {
            break;
        }
        sp.begin_iteration(k + 1);
        let stats = run_plan_at(
            replayer,
            plan,
            schedule.pace,
            pass_epoch(epoch0, k, schedule.pass_ns),
            RunControls {
                cancel: Some(&*ctx.cancel),
                sent: Some(&*sp.sent),
                bytes: Some(&*sp.bytes),
                send_errors: None,
                global_sent: Some(&*ctx.sent),
                global_bytes: Some(&*ctx.bytes),
                global_send_errors: Some(&*ctx.send_errors),
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
    acc
}

/// Join the workers and add up their reports; a failed or panicked
/// worker becomes a warning and an error count.
fn join_raw_workers(handles: Vec<thread::JoinHandle<Result<SourceReport>>>) -> RunReport {
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
    report
}
