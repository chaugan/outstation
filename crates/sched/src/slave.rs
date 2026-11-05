//! Slave-role benchmark ([`run_benchmark_slave`]): one listener per
//! captured RTU in the host's own network namespace, waiting for the
//! live target master to connect.

use super::*;

/// Capture of a slave run (T18): one AF_PACKET socket per interface
/// that carries a listener's sessions, each with a kernel filter that
/// admits only TCP to or from `(listen ip, listen port)` of this run's
/// listeners. Listen IPs are only final once a slave is started (the
/// user may edit them), so each slave registers its address with
/// [`SlaveCapture::watch`] right before it binds.
struct SlaveCapture {
    cap: Capture,
    port: u16,
    /// The SCADA master, when known: the route to it names the
    /// interface the sessions use.
    peer: Option<Ipv4Addr>,
    ips: Mutex<Vec<Ipv4Addr>>,
    warnings: Mutex<Vec<String>>,
}

impl SlaveCapture {
    fn start(path: &Path, port: u16, peer: Ipv4Addr) -> Result<Self> {
        // The reader only blocks in poll and drains bursts; at RT
        // priority a loaded host cannot starve it into dropping frames.
        let cap = Capture::start_filtered(
            path,
            raw_replay::bpf::reject_all(),
            Some(CAPTURE_RT_PRIORITY),
        )?;
        info!(path = %path.display(), port, "slave capture started");
        Ok(Self {
            cap,
            port,
            peer: (!peer.is_unspecified()).then_some(peer),
            ips: Mutex::new(Vec::new()),
            warnings: Mutex::new(Vec::new()),
        })
    }

    fn warn(&self, msg: String) {
        warn!("{msg}");
        let mut w = self.warnings.lock().unwrap_or_else(|e| e.into_inner());
        if w.len() < 16 && !w.contains(&msg) {
            w.push(msg);
        }
    }

    /// Record the sessions of a listener on `listen_ip`. Never fails
    /// the session: problems become run warnings.
    fn watch(&self, listen_ip: Ipv4Addr) {
        if listen_ip.is_unspecified() {
            self.warn(format!(
                "capture: a listener on {listen_ip} (any address) is not recorded;                  give each RTU its own listen IP"
            ));
            return;
        }
        let ifaces = netctl::session_ifaces(listen_ip, self.peer);
        let mut ips = self.ips.lock().unwrap_or_else(|e| e.into_inner());
        if !ips.contains(&listen_ip) {
            ips.push(listen_ip);
            let filter = match raw_replay::bpf::tcp_endpoints_filter(&ips, self.port) {
                Ok(f) => f,
                Err(e) => {
                    ips.pop();
                    drop(ips);
                    self.warn(format!("capture: {listen_ip} not recorded: {e:#}"));
                    return;
                }
            };
            if let Err(e) = self.cap.set_filter(filter) {
                self.warn(format!("capture filter update for {listen_ip}: {e:#}"));
            }
        }
        drop(ips);
        if ifaces.is_empty() {
            self.warn(format!(
                "capture: no interface found that carries {listen_ip}; its sessions are not recorded"
            ));
        }
        for i in ifaces {
            if let Err(e) = self.cap.add_iface(&i) {
                self.warn(format!("capture on {i} for {listen_ip}: {e:#}"));
            }
        }
    }

    /// Stop after a short flush delay: the counters and the warnings.
    fn finish(self) -> (raw_replay::CaptureStats, Vec<String>) {
        let ifaces = self.cap.ifaces();
        let mut w = self
            .warnings
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
        let st = finish_capture(self.cap, &mut w);
        info!(?ifaces, "slave capture stopped");
        (st, w)
    }
}

/// Make `listen_ip` bindable: nothing to do if it is unspecified or
/// already local; otherwise add a `/32 noprefixroute` alias on the
/// configured alias NIC (or the default-route NIC, which is protected
/// and needs `force`). Returns the lease that keeps the alias alive.
pub(crate) fn ensure_listen_alias(
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
pub(crate) fn select_slave_flows<T>(
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
pub(crate) fn run_benchmark_slave(
    pcap: Arc<LoadedPcap>,
    cfg: BenchmarkConfig,
    replayer: Arc<dyn protoplay::ProtoReplayer>,
    ctx: RunContext,
) -> Result<BenchmarkReport> {
    let state_dir = state_dir_or_default(&cfg.state_dir);
    let prot = Protection::new(cfg.protected_addrs.clone(), cfg.force_protected_nic);
    if let Some(i) = &cfg.alias_iface {
        // Fail fast on a bad alias NIC rather than per session.
        netctl::check_nic_allowed(i, "add listen aliases to", &prot)?;
    }

    // 1. Pick one flow per RTU.
    let picks = select_slave_picks(&pcap, &cfg, &*replayer)?;

    // 2. Per-RTU progress. listen_ip defaults to the RTU's own address.
    let progress = init_slave_progress(&ctx, &picks, &cfg);

    // SCADA-gateway mode (fails closed).
    let res = RunResources {
        gateway: install_gateway(&cfg, &state_dir, &prot)?,
        ..Default::default()
    };

    // Capture of the listeners' sessions (T18). A capture that cannot
    // start costs the run its analysis, not the run itself.
    let mut start_warnings: Vec<String> = Vec::new();
    let capture = start_slave_capture(&cfg, &mut start_warnings);

    // 3. Warmup.
    if cfg.startup_delay_secs > 0 {
        info!(
            seconds = cfg.startup_delay_secs,
            "slave warmup: listeners not yet bound — attach tooling to target side"
        );
        if !warmup_elapsed(&ctx, cfg.startup_delay_secs) {
            let mut report = BenchmarkReport::default();
            res.finish(&mut report.warnings);
            return Ok(report);
        }
    }

    // 4. One listener thread per RTU.
    let run_start_ns = now_ns();
    ctx.started_packets_at_ns
        .store(run_start_ns, Ordering::Relaxed);
    let env = SlaveEnv {
        cfg: cfg.clone(),
        replayer,
        ctx: ctx.clone(),
        state_dir,
        prot,
        capture: capture.clone(),
    };
    let handles = match spawn_slave_sessions(picks, &progress, &env) {
        Ok(h) => h,
        Err(e) => {
            drop(env);
            res.finish(&mut Vec::new());
            return Err(e);
        }
    };
    drop(env);

    // 5. Join all and aggregate.
    let mut report = join_sessions(handles, run_start_ns);
    report.warnings.extend(start_warnings);
    finish_slave_capture(capture, &mut report);
    res.finish(&mut report.warnings);
    Ok(report)
}

/// One RTU's captured server-side flow.
struct SlavePick {
    flow_idx: usize,
    server_ip: Ipv4Addr,
    server_mac: MacAddr,
    payload: Vec<u8>,
    capture_gaps: Vec<usize>,
    frame_times_ns: Vec<u64>,
}

/// One flow per RTU ([`select_slave_flows`]), reassembled from the
/// server side. Fails if none matches.
fn select_slave_picks(
    pcap: &LoadedPcap,
    cfg: &BenchmarkConfig,
    replayer: &dyn protoplay::ProtoReplayer,
) -> Result<Vec<SlavePick>> {
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
    Ok(picks)
}

/// Pre-populate per-RTU progress; each listener starts out not ready
/// (the user starts it) and listening on the RTU's captured address.
fn init_slave_progress(
    ctx: &RunContext,
    picks: &[SlavePick],
    cfg: &BenchmarkConfig,
) -> Vec<SourceProgress> {
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
    progress
}

/// Start the slave capture if one was requested; a failure becomes a
/// warning.
fn start_slave_capture(
    cfg: &BenchmarkConfig,
    warnings: &mut Vec<String>,
) -> Option<Arc<SlaveCapture>> {
    let path = cfg.capture_path.as_deref()?;
    match SlaveCapture::start(path, cfg.listen_port_base, cfg.target_ip) {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            warn!(error = %format!("{e:#}"), "slave capture failed to start");
            warnings.push(format!("capture failed to start: {e:#}"));
            None
        }
    }
}

/// Stop the slave capture and put its counters and warnings in the
/// report.
fn finish_slave_capture(capture: Option<Arc<SlaveCapture>>, report: &mut BenchmarkReport) {
    let Some(c) = capture else {
        return;
    };
    match Arc::try_unwrap(c) {
        Ok(c) => {
            let (st, w) = c.finish();
            report.capture_path = Some(st.path);
            report.captured_packets = st.packets;
            report.captured_bytes = st.bytes;
            report.captured_dropped = st.dropped;
            report.warnings.extend(w);
        }
        // Only a session thread that never returned still holds it;
        // dropping the last reference stops the capture.
        Err(_) => report
            .warnings
            .push("capture still referenced by a session; not reported".into()),
    }
}

/// What every slave session shares.
#[derive(Clone)]
struct SlaveEnv {
    cfg: BenchmarkConfig,
    replayer: Arc<dyn protoplay::ProtoReplayer>,
    ctx: RunContext,
    state_dir: PathBuf,
    prot: Protection,
    capture: Option<Arc<SlaveCapture>>,
}

/// Everything one slave session thread owns.
struct SlaveJob {
    pick: SlavePick,
    env: SlaveEnv,
    sp: SourceProgress,
    session_progress: protoplay::MessageProgress,
    tap_label: String,
}

/// Spawn one listener thread per RTU (stopping early on a cancel).
fn spawn_slave_sessions(
    picks: Vec<SlavePick>,
    progress: &[SourceProgress],
    env: &SlaveEnv,
) -> Result<SessionHandles> {
    let ctx = &env.ctx;
    let mut handles: SessionHandles = Vec::new();
    for (idx, pick) in picks.into_iter().enumerate() {
        if ctx.is_cancelled() {
            break;
        }
        let sp = progress[idx].clone();
        let tap_label = format!("{}:{}", pick.server_ip, env.cfg.listen_port_base);
        let ident = SessionIdent {
            src_ip: pick.server_ip,
            src_mac: pick.server_mac,
            tap: tap_label.clone(),
            flow_idx: pick.flow_idx,
            progress: sp.clone(),
        };
        let name = format!("bench-slave-{}", pick.server_ip);
        let job = SlaveJob {
            pick,
            env: env.clone(),
            session_progress: sp.message_progress(&ctx.cancel),
            sp,
            tap_label,
        };
        spawn_session(
            ctx,
            &mut handles,
            ident,
            name,
            ("slave session", "slave benchmark"),
            move || slave_session(job),
        )?;
    }
    Ok(handles)
}

/// Body of one slave session thread: wait for the user's start, make
/// the listen address bindable, register it with the capture, run the
/// iterations, release the alias, report.
fn slave_session(job: SlaveJob) -> SessionReport {
    let SlaveJob {
        pick,
        env,
        sp,
        session_progress,
        tap_label,
    } = job;
    let SlaveEnv {
        cfg,
        replayer,
        ctx,
        state_dir,
        prot,
        capture,
    } = env;
    let src_ip = pick.server_ip;
    let listen_port = cfg.listen_port_base;
    let early = |msg: &str, state: u8| {
        early_session_report(
            &ctx,
            &sp,
            (src_ip, pick.server_mac, tap_label.clone(), pick.flow_idx),
            msg,
            state,
        )
    };
    if !wait_until_ready(&ctx, &sp) {
        let msg = if ctx.is_cancelled() {
            "cancelled before start"
        } else {
            "slave cancelled before start"
        };
        return early(msg, protoplay::session_state::CANCELLED);
    }

    // Snapshot the user-edited listen IP after the gate.
    let listen_ip = sp.snapshot_listen_ip();
    let alias = match ensure_listen_alias(listen_ip, cfg.alias_iface.as_deref(), &state_dir, &prot)
    {
        Ok(a) => a,
        Err(e) => {
            warn!(%listen_ip, error = %format!("{e:#}"), "listen alias refused");
            return early(&format!("{e:#}"), protoplay::session_state::FAILED);
        }
    };

    // Record this listener's sessions from its first SYN.
    if let Some(c) = &capture {
        c.watch(listen_ip);
    }
    drop(capture);

    let started_at_ns = now_ns();
    info!(%src_ip, %listen_ip, listen_port, bytes = pick.payload.len(),
        aliased = alias.is_some(), "slave session opening listener");
    let (acc, cancelled_mid_run) = slave_iterations(
        &cfg,
        &pick,
        listen_ip,
        &*replayer,
        &ctx,
        &sp,
        &session_progress,
    );

    // Drop our reference to the alias (deleted only if we added it and
    // nobody else still uses it).
    if let Some(a) = alias {
        if let Err(e) = a.release() {
            warn!(%listen_ip, error = %format!("{e:#}"), "alias cleanup failed");
        }
    }

    let pr = acc.into_report();
    let cancelled = finish_session(&ctx, &sp, &pr, cancelled_mid_run);
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
        src_mac: pick.server_mac,
        tap: tap_label,
        flow_idx: pick.flow_idx,
        started_at_ns,
        proto_report: pr,
        cancelled,
    }
}

/// Wait for the user to flip `ready` for this slave. A stop also flips
/// `ready` (to wake this loop), so the cancel flags are checked once
/// more after the gate: a slave that never started is cancelled, not
/// failed. Returns `false` when cancelled.
fn wait_until_ready(ctx: &RunContext, sp: &SourceProgress) -> bool {
    let cancelled = || ctx.is_cancelled() || sp.is_cancelled();
    while !sp.is_ready() {
        if cancelled() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    !cancelled()
}

/// Run the slave's iterations (one listener/accept each, or one with
/// the script looped inside), merging their reports. Returns the
/// accumulated report and whether a cancel cut the run short.
fn slave_iterations(
    cfg: &BenchmarkConfig,
    pick: &SlavePick,
    listen_ip: Ipv4Addr,
    replayer: &dyn protoplay::ProtoReplayer,
    ctx: &RunContext,
    sp: &SourceProgress,
    session_progress: &protoplay::MessageProgress,
) -> (SessionAccumulator, bool) {
    let cancelled = || ctx.is_cancelled() || sp.is_cancelled();
    let (target_iters, run_loop_iterations) = if cfg.loop_within_session {
        (1u64, cfg.iterations)
    } else {
        (effective_iterations(cfg.iterations), 1u64)
    };
    let mut acc = SessionAccumulator::new();
    let mut cancelled_mid_run = false;
    for iter_idx in 0..target_iters {
        if cancelled() {
            cancelled_mid_run = true;
            break;
        }
        sp.begin_iteration(iter_idx + 1);
        let run_cfg = protoplay::ProtoRunCfg {
            bind_ip: listen_ip,
            bind_iface: None,
            target_ip: cfg.target_ip,
            target_port: cfg.target_port,
            tcp_nodelay: cfg.tcp_nodelay.unwrap_or(true),
            client_segments: vec![protoplay::ClientSegment {
                rel_ts_ns: 0,
                bytes: pick.payload.clone(),
            }],
            connect_timeout: Duration::from_secs(cfg.connect_timeout_secs),
            speed: 1.0,
            proto_config: cfg.proto_config.clone(),
            progress: Some(session_progress.clone()),
            role: protoplay::Role::Slave,
            listen_port: cfg.listen_port_base,
            pacing: cfg.pacing,
            frame_times_ns: pick.frame_times_ns.clone(),
            loop_iterations: run_loop_iterations,
            capture_gaps: pick.capture_gaps.clone(),
        };
        let iter_report = run_iteration(replayer, run_cfg);
        ctx.sent
            .fetch_add(iter_report.messages_sent, Ordering::Relaxed);
        ctx.bytes
            .fetch_add(iter_report.bytes_written, Ordering::Relaxed);
        let had_error = iter_report.error.is_some();
        merge_proto_report(&mut acc, iter_report);
        if had_error {
            break;
        }
    }
    (acc, cancelled_mid_run)
}
