//! Benchmark mode: stateful session replay driving a real live target.
//! Session machinery shared by both roles, and the master role
//! ([`run_benchmark`]): one veth port and one client session per
//! captured master IP.

use super::*;

/// Identity of one session, kept by the coordinator so a session whose
/// thread died can still be reported.
#[derive(Clone)]
pub(crate) struct SessionIdent {
    pub(crate) src_ip: Ipv4Addr,
    pub(crate) src_mac: MacAddr,
    pub(crate) tap: String,
    pub(crate) flow_idx: usize,
    pub(crate) progress: SourceProgress,
}

impl SessionIdent {
    pub(crate) fn failed_report(&self, msg: &str) -> SessionReport {
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
pub(crate) fn run_iteration(
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
pub(crate) fn join_sessions(
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
pub(crate) fn abort_sessions(
    ctx: &RunContext,
    handles: Vec<(SessionIdent, thread::JoinHandle<SessionReport>)>,
) {
    ctx.cancel_all();
    for (_, h) in handles {
        let _ = h.join();
    }
}

/// Install the SCADA-gateway guard if configured.
pub(crate) fn install_gateway(
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
pub(crate) fn final_state(cancelled_mid_run: bool, cancel_flag: bool, has_error: bool) -> u8 {
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
pub(crate) fn finish_session(
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

/// Capture settings of a benchmark run, either role: the reader runs
/// at RT priority only with `realtime` on (N8).
pub(crate) fn bench_capture_opts(cfg: &BenchmarkConfig) -> CaptureOpts {
    CaptureOpts {
        rt_priority: cfg.realtime.then_some(CAPTURE_RT_PRIORITY),
        max_bytes: cfg.capture_max_bytes,
    }
}

/// Handles of the running session threads, with the identity the
/// coordinator needs to report a thread that died.
pub(crate) type SessionHandles = Vec<(SessionIdent, thread::JoinHandle<SessionReport>)>;

/// Spawn one session thread. On failure cancel and join the sessions
/// already running (F034) and return the error; the caller tears the
/// host down. `what` names the session kind in the log and the error.
pub(crate) fn spawn_session(
    ctx: &RunContext,
    handles: &mut SessionHandles,
    ident: SessionIdent,
    name: String,
    what: (&str, &str),
    body: impl FnOnce() -> SessionReport + Send + 'static,
) -> Result<()> {
    match spawn_named(name, body) {
        Ok(h) => {
            handles.push((ident, h));
            Ok(())
        }
        Err(e) => {
            warn!(error = %e, "spawn of {} failed; aborting run", what.0);
            abort_sessions(ctx, std::mem::take(handles));
            Err(anyhow::Error::new(e).context(format!("spawn {} thread", what.1)))
        }
    }
}

/// Report of a session that ended before its first iteration.
pub(crate) fn early_session_report(
    ctx: &RunContext,
    sp: &SourceProgress,
    ident: (Ipv4Addr, MacAddr, String, usize),
    msg: &str,
    state: u8,
) -> SessionReport {
    sp.set_final(state, Some(msg));
    ctx.sessions_done.fetch_add(1, Ordering::Relaxed);
    let (src_ip, src_mac, tap, flow_idx) = ident;
    SessionReport {
        src_ip,
        src_mac,
        tap,
        flow_idx,
        started_at_ns: now_ns(),
        proto_report: protoplay::ProtoReport {
            error: Some(msg.into()),
            ..Default::default()
        },
        cancelled: state == protoplay::session_state::CANCELLED,
    }
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

    // 2. Select flows: one per client IP whose server port matches.
    let picks = select_master_flows(&pcap, &cfg, &*replayer)?;

    // 3. One veth port per session with the client IP + MAC assigned,
    //    so the per-session TCP socket bind() succeeds.
    let bindings = add_session_ports(&mut res, &names, &picks, cfg.master_bind_ip, &prot)?;

    // 4. Mirror capture.
    let mut capture = CaptureOutcome {
        requested: cfg.capture_path.is_some(),
        ..Default::default()
    };
    if let Some(path) = &cfg.capture_path {
        let opts = bench_capture_opts(&cfg);
        capture.open_failed = !start_capture(&mut res, &names, path, opts, &mut warnings);
    }

    // 5. Per-session progress.
    let progress = init_master_progress(&ctx, &bindings, cfg.iterations);

    // 6. Warmup.
    if cfg.startup_delay_secs > 0 {
        info!(seconds = cfg.startup_delay_secs, bridge = %names.bridge,
            "benchmark warmup: interfaces are live");
        if !warmup_elapsed(&ctx, cfg.startup_delay_secs) {
            let mut report = BenchmarkReport::default();
            capture.stats = collect_capture(&mut res, &mut warnings);
            report.set_capture(&capture);
            report.warnings = warnings;
            res.finish(&mut report.warnings);
            return Ok(report);
        }
    }

    // 7. One session worker per binding.
    let run_start_ns = now_ns();
    ctx.started_packets_at_ns
        .store(run_start_ns, Ordering::Relaxed);
    let handles = match spawn_master_sessions(picks, bindings, &progress, &cfg, &replayer, &ctx) {
        Ok(h) => h,
        Err(e) => {
            res.finish(&mut Vec::new());
            return Err(e);
        }
    };

    // 8. Join all sessions and build the report.
    let mut report = join_sessions(handles, run_start_ns);

    // 9. Stop capture, teardown.
    capture.stats = collect_capture(&mut res, &mut warnings);
    report.set_capture(&capture);
    report.warnings.extend(warnings);
    res.finish(&mut report.warnings);
    Ok(report)
}

/// One master session's captured flow.
pub(crate) struct FlowPick {
    pub(crate) flow_idx: usize,
    pub(crate) client_ip: Ipv4Addr,
    pub(crate) client_mac: MacAddr,
    pub(crate) first_pkt_rel_ns: u64,
    /// First to last packet of the flow, either direction.
    pub(crate) flow_span_ns: u64,
    pub(crate) payload: Vec<u8>,
    pub(crate) capture_gaps: Vec<usize>,
    pub(crate) frame_times_ns: Vec<u64>,
}

/// TCP flows whose server port is the target port, reassembled from
/// the client side, reduced to the best flow per client IP
/// ([`replay_quality`]: the same ranking for both roles and the upload
/// viability, N18). Only the current best payload per IP is kept while
/// walking the flows (P07). Fails if none matches.
pub(crate) fn select_master_flows(
    pcap: &LoadedPcap,
    cfg: &BenchmarkConfig,
    replayer: &dyn protoplay::ProtoReplayer,
) -> Result<Vec<FlowPick>> {
    let candidates = pcap.flows.iter().enumerate().filter_map(|(idx, flow)| {
        let (_, server_port) = flow.server?;
        let (client_ip, _) = flow.client?;
        if server_port != cfg.target_port {
            return None;
        }
        if cfg
            .selected_endpoints
            .as_ref()
            .is_some_and(|set| !set.contains(&client_ip))
        {
            return None;
        }
        if !pcap.sources.contains_key(&client_ip) {
            warn!(%client_ip, "client ip has no MAC in sources table, skipping");
            return None;
        }
        Some((idx, client_ip))
    });
    let best = best_flow_per_ip(
        candidates,
        |idx| pcap.reassemble_client_payload(idx),
        replay_quality,
    );
    let picks: Vec<FlowPick> = best
        .into_iter()
        .map(|(idx, client_ip, r)| {
            let flow = &pcap.flows[idx];
            let first_pkt_rel_ns = flow
                .packet_indices
                .first()
                .map(|i| pcap.packets[*i].rel_ts_ns)
                .unwrap_or(0);
            let flow_span_ns = flow
                .packet_indices
                .iter()
                .map(|i| pcap.packets[*i].rel_ts_ns)
                .max()
                .unwrap_or(0)
                .saturating_sub(first_pkt_rel_ns);
            FlowPick {
                flow_idx: idx,
                client_ip,
                client_mac: pcap.sources[&client_ip].src_mac,
                first_pkt_rel_ns,
                flow_span_ns,
                frame_times_ns: replayer.extract_message_times_ns(&r.payload, &r.packet_offsets),
                capture_gaps: r.gaps.iter().map(|g| g.offset).collect(),
                payload: r.payload,
            }
        })
        .collect();

    if picks.is_empty() {
        bail!(
            "no flows matching target port {} (tried {} flows)",
            cfg.target_port,
            pcap.flows.len()
        );
    }
    info!(sessions = picks.len(), target = %cfg.target_ip, port = cfg.target_port,
        "benchmark: flows selected");
    Ok(picks)
}

/// The veth port a master session sends from.
struct SessionBinding {
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    bridge_side: String,
    inject_side: String,
}

/// Add one session port per pick (index-aligned with `picks`), carrying
/// the client's IP (or `master_override`) and MAC.
fn add_session_ports(
    res: &mut RunResources,
    names: &IfaceNames,
    picks: &[FlowPick],
    master_override: Option<Ipv4Addr>,
    prot: &Protection,
) -> Result<Vec<SessionBinding>> {
    if let Some(ip) = master_override {
        info!(%ip, "master_bind_ip override active — sessions will originate from this address");
    }
    let topo = res.topo.as_mut().context("topology missing")?;
    let mut bindings: Vec<SessionBinding> = Vec::with_capacity(picks.len());
    for (i, p) in picks.iter().enumerate() {
        let effective_src_ip = master_override.unwrap_or(p.client_ip);
        let bridge_side = names.port(PortKind::Session, i)?;
        let inject_side = topo
            .add_port_with_ip(
                &bridge_side,
                Some(p.client_mac),
                Some(effective_src_ip),
                prot,
            )
            .with_context(|| format!("add session port {bridge_side}"))?;
        bindings.push(SessionBinding {
            src_ip: effective_src_ip,
            src_mac: p.client_mac,
            bridge_side,
            inject_side,
        });
    }
    Ok(bindings)
}

/// Pre-populate per-session progress. `planned` stays 0 until the
/// protocol replayer has parsed the client payload.
fn init_master_progress(
    ctx: &RunContext,
    bindings: &[SessionBinding],
    iterations: u64,
) -> Vec<SourceProgress> {
    let progress: Vec<SourceProgress> = {
        let mut sp = ctx.sources();
        sp.clear();
        for b in bindings {
            let p = SourceProgress::new(
                Some(b.src_ip),
                b.src_mac,
                b.bridge_side.clone(),
                protoplay::session_state::PENDING,
                true,
            );
            p.iter_total.store(iterations, Ordering::Relaxed);
            sp.push(p);
        }
        sp.clone()
    };
    ctx.planned.store(0, Ordering::Relaxed);
    ctx.sessions_total
        .store(bindings.len() as u64, Ordering::Relaxed);
    progress
}

/// Everything one master session thread owns.
struct MasterJob {
    pick: FlowPick,
    binding: SessionBinding,
    policy: IterationPolicy,
    replayer: Arc<dyn protoplay::ProtoReplayer>,
    cfg: BenchmarkConfig,
    ctx: RunContext,
    sp: SourceProgress,
    session_progress: protoplay::MessageProgress,
}

/// Spawn one master session per binding (stopping early on a cancel).
fn spawn_master_sessions(
    picks: Vec<FlowPick>,
    bindings: Vec<SessionBinding>,
    progress: &[SourceProgress],
    cfg: &BenchmarkConfig,
    replayer: &Arc<dyn protoplay::ProtoReplayer>,
    ctx: &RunContext,
) -> Result<SessionHandles> {
    let mut handles: SessionHandles = Vec::new();
    for (i, (pick, binding)) in picks.into_iter().zip(bindings).enumerate() {
        if ctx.is_cancelled() {
            break;
        }
        let sp = progress[i].clone();
        let ident = SessionIdent {
            src_ip: binding.src_ip,
            src_mac: binding.src_mac,
            tap: binding.inject_side.clone(),
            flow_idx: pick.flow_idx,
            progress: sp.clone(),
        };
        let name = format!("bench-{}", binding.src_ip);
        let job = MasterJob {
            policy: IterationPolicy::for_master(cfg, pick.flow_span_ns),
            pick,
            binding,
            replayer: Arc::clone(replayer),
            cfg: cfg.clone(),
            ctx: ctx.clone(),
            session_progress: sp.message_progress(&ctx.cancel),
            sp,
        };
        spawn_session(
            ctx,
            &mut handles,
            ident,
            name,
            ("benchmark session", "benchmark"),
            move || master_session(job),
        )?;
    }
    Ok(handles)
}

/// Body of one master session thread: optional staggered start, then
/// the iterations (one connection each), then the final bookkeeping.
fn master_session(job: MasterJob) -> SessionReport {
    let MasterJob {
        pick,
        binding,
        policy,
        replayer,
        cfg,
        ctx,
        sp,
        session_progress,
    } = job;
    let src_ip = binding.src_ip;
    let cancelled = || ctx.is_cancelled() || sp.is_cancelled();
    if matches!(cfg.concurrency, ConcurrencyModel::StaggeredPcapTiming) && pick.first_pkt_rel_ns > 0
    {
        sleep_interruptible(Duration::from_nanos(pick.first_pkt_rel_ns), cancelled);
    }
    if cancelled() {
        sp.set_final(protoplay::session_state::CANCELLED, None);
        ctx.sessions_done.fetch_add(1, Ordering::Relaxed);
        return SessionReport {
            src_ip,
            src_mac: binding.src_mac,
            tap: binding.bridge_side,
            flow_idx: pick.flow_idx,
            started_at_ns: now_ns(),
            proto_report: protoplay::ProtoReport {
                error: Some("cancelled before start".into()),
                ..Default::default()
            },
            cancelled: true,
        };
    }

    let started_at_ns = now_ns();
    info!(%src_ip, flow_idx = pick.flow_idx, bytes = pick.payload.len(), "benchmark session starting");
    let target_iters = effective_iterations(cfg.iterations);
    let outcome = master_iterations(target_iters, policy, &cancelled, |iter_idx| {
        sp.begin_iteration(iter_idx + 1);
        let run_cfg = master_run_cfg(&cfg, &pick, &binding, &session_progress);
        let iter_report = run_iteration(&*replayer, run_cfg);
        ctx.sent
            .fetch_add(iter_report.messages_sent, Ordering::Relaxed);
        ctx.bytes
            .fetch_add(iter_report.bytes_written, Ordering::Relaxed);
        iter_report
    });
    let cancelled_mid_run = outcome.cancelled_mid_run;
    let pr = outcome.report;
    let cancelled = finish_session(&ctx, &sp, &pr, cancelled_mid_run);
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
        src_mac: binding.src_mac,
        tap: binding.inject_side,
        flow_idx: pick.flow_idx,
        started_at_ns,
        proto_report: pr,
        cancelled,
    }
}

/// The protocol module's configuration for one master iteration.
fn master_run_cfg(
    cfg: &BenchmarkConfig,
    pick: &FlowPick,
    binding: &SessionBinding,
    progress: &protoplay::MessageProgress,
) -> protoplay::ProtoRunCfg {
    protoplay::ProtoRunCfg {
        bind_ip: binding.src_ip,
        // The source IP lives on the inject end; frames sent there
        // enter the bridge via its peer.
        bind_iface: Some(binding.inject_side.clone()),
        target_ip: cfg.target_ip,
        target_port: cfg.target_port,
        tcp_nodelay: cfg.tcp_nodelay.unwrap_or(false),
        client_segments: vec![protoplay::ClientSegment {
            rel_ts_ns: 0,
            bytes: pick.payload.clone(),
        }],
        connect_timeout: Duration::from_secs(cfg.connect_timeout_secs),
        speed: 1.0,
        proto_config: cfg.proto_config.clone(),
        progress: Some(progress.clone()),
        role: protoplay::Role::Master,
        listen_port: 0,
        pacing: cfg.pacing,
        frame_times_ns: pick.frame_times_ns.clone(),
        loop_iterations: 1,
        capture_gaps: pick.capture_gaps.clone(),
    }
}
