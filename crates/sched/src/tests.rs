//! Unit tests of the scheduler.

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
fn effective_iterations_maps_zero_to_unbounded() {
    assert_eq!(effective_iterations(0), u64::MAX);
    assert_eq!(effective_iterations(1), 1);
    assert_eq!(effective_iterations(7), 7);
    assert_eq!(effective_iterations(u64::MAX), u64::MAX);
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
fn slave_flow_selection_picks_the_best_flow_per_rtu() {
    // P02: the first flow of 10.0.0.1 does not reassemble; N18: of its
    // other flows the most contiguous, largest one wins, not the first.
    let ip1 = Ipv4Addr::new(10, 0, 0, 1);
    let ip2 = Ipv4Addr::new(10, 0, 0, 2);
    let flows = vec![
        (0, Some((ip1, 2404))),
        (1, Some((ip2, 2404))),
        (2, Some((ip1, 2404))),
        (3, Some((ip1, 2404))),
        (4, Some((ip2, 80))),
        (5, None),
        (6, Some((ip1, 2404))),
    ];
    // (payload length, gap offsets) per flow.
    let shape = |idx: usize| -> (usize, Vec<usize>) {
        match idx {
            2 => (100, vec![]),
            3 => (500, vec![]),
            6 => (900, vec![100, 200]), // longest run 700
            _ => (50, vec![]),
        }
    };
    let quality = |t: &(usize, Vec<usize>)| protoplay::FlowQuality::new(t.0, &t.1, 0);
    let picks = select_slave_flows(
        flows.clone(),
        2404,
        None,
        |idx| {
            if idx == 0 {
                bail!("no payload")
            } else {
                Ok(shape(idx))
            }
        },
        quality,
    );
    let got: Vec<(usize, Ipv4Addr)> = picks.iter().map(|(i, ip, _)| (*i, *ip)).collect();
    assert_eq!(got, vec![(1, ip2), (6, ip1)]);

    // Endpoint filter is applied before reassembly is attempted.
    let only: std::collections::HashSet<Ipv4Addr> = [ip2].into_iter().collect();
    let mut tried = Vec::new();
    let picks = select_slave_flows(
        flows,
        2404,
        Some(&only),
        |idx| {
            tried.push(idx);
            Ok(shape(idx))
        },
        quality,
    );
    assert_eq!(picks.len(), 1);
    assert_eq!(tried, vec![1]);
}

/// N18: master selection ranks a reconnect's flows the same way, on
/// real reassemblies: a later clean flow beats an earlier one with a
/// capture gap.
#[test]
fn best_flow_per_ip_prefers_a_clean_later_flow() {
    let ip = Ipv4Addr::new(10, 0, 0, 9);
    let runs: Vec<(usize, Vec<usize>)> = vec![(400, vec![50]), (380, vec![]), (380, vec![])];
    let got = best_flow_per_ip(
        (0..3).map(|i| (i, ip)),
        |i| Ok(runs[i].clone()),
        |t: &(usize, Vec<usize>)| protoplay::FlowQuality::new(t.0, &t.1, 0),
    );
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].0, 1,
        "clean 380 beats 400 with a gap (run 350); ties keep the first"
    );
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

/// N5: a reader sampling the total while iterations start never sees
/// it dip (before, `sent` was zeroed before its amount reached
/// `sent_done_iters`), and the protocol's own within-session fold
/// (shared counters) keeps it monotonic as well.
#[test]
fn totals_never_dip_while_iterations_start() {
    let p = SourceProgress::new(None, [0; 6], "x".into(), 0, true);
    let mp = p.message_progress(&Arc::new(AtomicBool::new(false)));
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let p = p.clone();
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let mut last = 0u64;
            let mut samples = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let t = p.snapshot_sent_total();
                assert!(t >= last, "total dipped from {last} to {t}");
                last = t;
                samples += 1;
            }
            (last, samples)
        })
    };
    for k in 1..=20_000u64 {
        if k % 2 == 0 {
            p.begin_iteration(k);
        } else {
            mp.fold_iteration();
        }
        for _ in 0..3 {
            p.sent.fetch_add(1, Ordering::Relaxed);
        }
    }
    stop.store(true, Ordering::Relaxed);
    let (last, samples) = reader.join().unwrap();
    assert!(samples > 0);
    assert!(last <= 60_000);
    assert_eq!(p.snapshot_sent_total(), 60_000);
    assert_eq!(mp.sent_total(), 60_000);
    assert_eq!(p.snapshot_sent(), 3);
}

/// N4 (scratchpad/reaudit/mergeprobe): one slave iteration sends 1000
/// messages in 10 s of activity and then idle-serves 30 s. Throughput
/// is 100 msg/s per iteration and stays 100 msg/s once merged; the
/// merged report keeps the total and the active time apart.
#[test]
fn merged_throughput_is_over_active_time() {
    let iteration = || {
        let mut r = protoplay::ProtoReport {
            messages_sent: 1000,
            latency_samples_us: (1..=1000).collect(),
            elapsed_ms: 40_000,
            connected: true,
            ..Default::default()
        };
        r.protocol.idle_serve_ms = 30_000;
        r.finalize_latency();
        r
    };
    let one = iteration();
    assert_eq!(one.throughput_msgs_per_sec, 100.0);
    assert_eq!(one.active_ms(), 10_000);
    let mut acc = SessionAccumulator::new();
    merge_proto_report(&mut acc, iteration());
    assert_eq!(acc.report().throughput_msgs_per_sec, 100.0);
    merge_proto_report(&mut acc, iteration());
    let r = acc.report();
    assert_eq!(r.throughput_msgs_per_sec, 100.0);
    assert_eq!(r.elapsed_ms, 80_000);
    assert_eq!(r.protocol.idle_serve_ms, 60_000);
    assert_eq!(r.active_ms(), 20_000);
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
    let h =
        thread::spawn(move || run_benchmark_slave(pcap, cfg, Arc::new(ListenUntilCancelled), c));
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
    let d = std::env::temp_dir().join(format!("sched-test-{}-{}", std::process::id(), now_ns()));
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

fn ok_report(sent: u64) -> protoplay::ProtoReport {
    protoplay::ProtoReport {
        connected: true,
        messages_sent: sent,
        ..Default::default()
    }
}

fn refused() -> protoplay::ProtoReport {
    protoplay::ProtoReport {
        error: Some("connect(10.0.0.1:2404): Connection refused".into()),
        ..Default::default()
    }
}

/// O1: original timing makes an iteration last at least the flow's
/// span / speed, and every pacing mode leaves the gap in between.
#[test]
fn iteration_policy_honours_flow_span_and_gap() {
    let cfg = BenchmarkConfig {
        pacing: protoplay::Pacing::OriginalTiming { speed: 2.0 },
        iterations: 0,
        ..Default::default()
    };
    let p = IterationPolicy::for_master(&cfg, 3_000_000_000);
    assert_eq!(p.min_iteration, Duration::from_millis(1500));
    assert_eq!(p.gap, DEFAULT_ITERATION_GAP);
    assert!(p.retry_connect);
    // A 200 ms iteration waits out the span, then the gap.
    assert_eq!(
        p.wait_after(Duration::from_millis(200), 0),
        Duration::from_millis(1300) + DEFAULT_ITERATION_GAP
    );
    // A long iteration only gets the gap.
    assert_eq!(
        p.wait_after(Duration::from_secs(9), 0),
        DEFAULT_ITERATION_GAP
    );
    // Fast pacing: no minimum, still the gap; bounded: no retries.
    let fast = BenchmarkConfig {
        iterations: 3,
        iteration_gap: Duration::from_millis(250),
        ..Default::default()
    };
    let p = IterationPolicy::for_master(&fast, 3_000_000_000);
    assert_eq!(p.min_iteration, Duration::ZERO);
    assert!(!p.retry_connect);
    assert_eq!(p.wait_after(Duration::ZERO, 0), Duration::from_millis(250));
    // Connect failures back off exponentially from max(gap, 500 ms)
    // up to the cap.
    let waits: Vec<Duration> = (1..=8).map(|n| p.wait_after(Duration::ZERO, n)).collect();
    assert_eq!(waits[0], Duration::from_millis(500));
    assert_eq!(waits[1], Duration::from_secs(1));
    assert_eq!(waits[2], Duration::from_secs(2));
    assert_eq!(waits[7], MAX_CONNECT_BACKOFF);
    assert!(waits.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(p.wait_after(Duration::ZERO, u32::MAX), MAX_CONNECT_BACKOFF);
    // A degenerate speed never divides by zero.
    let odd = BenchmarkConfig {
        pacing: protoplay::Pacing::OriginalTiming { speed: 0.0 },
        ..Default::default()
    };
    assert_eq!(
        IterationPolicy::for_master(&odd, 5).min_iteration,
        Duration::ZERO
    );
}

/// O1: a short capture no longer reconnects in a tight loop: an
/// unbounded session starts its iterations at least
/// `max(span / speed, iteration time) + gap` apart.
#[test]
fn unbounded_master_iterations_are_spaced() {
    let policy = IterationPolicy {
        min_iteration: Duration::from_millis(120),
        gap: Duration::from_millis(40),
        retry_connect: true,
    };
    let starts = Mutex::new(Vec::new());
    let t0 = std::time::Instant::now();
    let stop = AtomicBool::new(false);
    let out = master_iterations(u64::MAX, policy, &|| stop.load(Ordering::Relaxed), |i| {
        starts.lock().unwrap().push(t0.elapsed());
        if i == 4 {
            stop.store(true, Ordering::Relaxed);
        }
        // The session itself ends quickly (short capture).
        std::thread::sleep(Duration::from_millis(5));
        ok_report(2)
    });
    let starts = starts.into_inner().unwrap();
    assert_eq!(starts.len(), 5);
    for w in starts.windows(2) {
        assert!(
            w[1] - w[0] >= Duration::from_millis(160),
            "iterations too close: {starts:?}"
        );
    }
    assert!(out.cancelled_mid_run);
    assert_eq!(out.report.messages_sent, 10);
    assert!(out.report.error.is_none());
}

/// O1: an unbounded run keeps retrying a target that refuses, with
/// growing pauses, and recovers when it comes back; a bounded run
/// stops at the first failure as before.
#[test]
fn connect_failures_back_off_and_recover() {
    let policy = IterationPolicy {
        min_iteration: Duration::ZERO,
        gap: Duration::ZERO,
        retry_connect: true,
    };
    let starts = Mutex::new(Vec::new());
    let t0 = std::time::Instant::now();
    let out = master_iterations(2, policy, &|| false, |_| {
        let mut s = starts.lock().unwrap();
        s.push(t0.elapsed());
        if s.len() <= 2 {
            refused()
        } else {
            ok_report(1)
        }
    });
    let starts = starts.into_inner().unwrap();
    assert_eq!(starts.len(), 4, "2 refused attempts + 2 iterations");
    assert!(starts[1] - starts[0] >= Duration::from_millis(500));
    assert!(starts[2] - starts[1] >= Duration::from_millis(1000));
    // After a success the gap is back to the configured one (0).
    assert!(starts[3] - starts[2] < Duration::from_millis(400));
    assert_eq!(out.attempts, 4);
    assert!(out.report.error.is_none(), "{:?}", out.report.error);
    assert!(out.report.connected);
    assert_eq!(out.report.messages_sent, 2);
    assert!(!out.cancelled_mid_run);

    // Never reachable: stopped by a cancel during the backoff, with
    // the connect error kept.
    let stop = AtomicBool::new(false);
    let tries = AtomicU64::new(0);
    let t = std::time::Instant::now();
    let out = master_iterations(u64::MAX, policy, &|| stop.load(Ordering::Relaxed), |_| {
        if tries.fetch_add(1, Ordering::Relaxed) == 1 {
            stop.store(true, Ordering::Relaxed);
        }
        refused()
    });
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "cancel cut the wait"
    );
    assert!(out.cancelled_mid_run);
    assert!(!out.report.connected);
    assert!(out.report.error.as_deref().unwrap().contains("refused"));

    // Bounded: the first failure ends the session.
    let bounded = IterationPolicy {
        retry_connect: false,
        ..policy
    };
    let calls = AtomicU64::new(0);
    let out = master_iterations(5, bounded, &|| false, |_| {
        calls.fetch_add(1, Ordering::Relaxed);
        refused()
    });
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(out.report.error.is_some());
    assert!(!out.cancelled_mid_run);
}

/// F079: worker and session threads run inside the caller's span (the
/// webui's `run{id}`), so their log lines carry the run id.
#[test]
fn spawned_threads_inherit_the_run_span() {
    use tracing_subscriber::layer::SubscriberExt;
    let subscriber =
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().with_test_writer());
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("run", id = 7);
        let _g = span.enter();
        let h = spawn_named("t".into(), || {
            tracing::Span::current()
                .metadata()
                .map(|m| m.name().to_string())
        })
        .unwrap();
        assert_eq!(h.join().unwrap().as_deref(), Some("run"));
    });
}

/// N15: `capture_ok` is false when a requested capture could not open
/// every interface it needed, or holds nothing although traffic was
/// sent; the byte cap shows as `capture_truncated`.
#[test]
fn capture_ok_and_truncation_reach_the_reports() {
    let stats = |packets: u64, truncated: bool| raw_replay::CaptureStats {
        path: PathBuf::from("/x.pcap"),
        packets,
        bytes: packets * 60,
        dropped: 0,
        truncated,
    };
    let none = CaptureOutcome::default();
    assert!(none.ok(true), "no capture requested");
    let good = CaptureOutcome {
        stats: Some(stats(10, false)),
        open_failed: false,
        requested: true,
    };
    assert!(good.ok(true));
    let partial = CaptureOutcome {
        open_failed: true,
        ..CaptureOutcome {
            stats: Some(stats(10, false)),
            open_failed: false,
            requested: true,
        }
    };
    assert!(!partial.ok(true));
    let header_only = CaptureOutcome {
        stats: Some(stats(0, false)),
        open_failed: false,
        requested: true,
    };
    assert!(!header_only.ok(true));
    assert!(header_only.ok(false), "nothing sent, nothing to record");
    let never_started = CaptureOutcome {
        stats: None,
        open_failed: true,
        requested: true,
    };
    assert!(!never_started.ok(false));

    let mut r = RunReport {
        total_packets: 5,
        ..Default::default()
    };
    r.set_capture(&CaptureOutcome {
        stats: Some(stats(3, true)),
        open_failed: false,
        requested: true,
    });
    assert!(r.capture_ok && r.capture_truncated);
    assert_eq!(r.captured_packets, 3);
    let mut b = BenchmarkReport {
        total_messages_received: 2,
        ..Default::default()
    };
    b.set_capture(&header_only);
    assert!(!b.capture_ok);
}

/// N8: a benchmark's capture reader runs at RT priority only with
/// realtime on; the byte cap is passed through.
#[test]
fn benchmark_capture_is_realtime_only_on_request() {
    let cfg = BenchmarkConfig {
        capture_max_bytes: Some(1 << 20),
        ..Default::default()
    };
    assert_eq!(
        bench_capture_opts(&cfg),
        CaptureOpts {
            rt_priority: None,
            max_bytes: Some(1 << 20),
        }
    );
    let rt = BenchmarkConfig {
        realtime: true,
        ..cfg
    };
    assert_eq!(
        bench_capture_opts(&rt).rt_priority,
        Some(CAPTURE_RT_PRIORITY)
    );
}

/// N15: a slave run stopped during its warmup still reports why its
/// capture failed (the warning used to be dropped on that path).
#[test]
fn warmup_cancel_keeps_the_capture_warning() {
    let pcap = Arc::new(
        pcapload::load(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/synth_iec104_rtus200_ts.pcap"),
        )
        .unwrap(),
    );
    let state = tempfile_dir();
    let cfg = BenchmarkConfig {
        role: protoplay::Role::Slave,
        startup_delay_secs: 30,
        capture_path: Some(PathBuf::from("/proc/no-such-dir/cap.pcap")),
        state_dir: Some(state.clone()),
        ..Default::default()
    };
    let ctx = RunContext::new();
    let c = ctx.clone();
    let h =
        thread::spawn(move || run_benchmark_slave(pcap, cfg, Arc::new(ListenUntilCancelled), c));
    thread::sleep(Duration::from_millis(300));
    ctx.cancel_all();
    let report = h.join().unwrap().unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("capture failed to start")),
        "{:?}",
        report.warnings
    );
    assert!(!report.capture_ok);
    let _ = std::fs::remove_dir_all(state);
}
