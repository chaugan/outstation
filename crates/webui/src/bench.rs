//! Headless benchmark (`outstation bench`, T09).
//!
//! Runs one benchmark through the same code path as the server
//! (`runbuild` → `build_job` → sched via [`SchedExecutor`] → the same
//! status derivation and report conversion), analyses its own mirror
//! capture with the fidelity analyser, evaluates `--assert` expressions
//! and writes a JSON report.
//!
//! Exit codes: [`EXIT_PASS`] (0) when every assertion passed,
//! [`EXIT_ASSERT_FAILED`] (1) when at least one failed, and
//! [`EXIT_RUN_ERROR`] (2) when the run itself failed, was interrupted,
//! or could not start (bad profile, unreadable pcap).
//!
//! SIGINT/SIGTERM cancel the run; the worker gets up to
//! [`SIGNAL_GRACE`] to unwind its guards (a second signal stops
//! waiting), then `netctl::cleanup_all(state_dir)` restores the host.
//! Like `outstation cleanup`, that reclaims every outstation-owned
//! interface on the host, so do not interrupt a bench while the web
//! server has a run active on the same host.

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use tracing::{info, warn};

use crate::analysis::{self, AnalysisMode};
use crate::dto::*;
use crate::error::panic_message;
use crate::runbuild::{self, RunMode};
use crate::runs::{derive_status, refresh_progress, RunExecutor, RunJob, RunOutcome};

pub const EXIT_PASS: i32 = 0;
pub const EXIT_ASSERT_FAILED: i32 = 1;
pub const EXIT_RUN_ERROR: i32 = 2;

/// How long an interrupted run may take to unwind before cleanup runs
/// anyway.
pub const SIGNAL_GRACE: Duration = Duration::from_secs(30);

/// Report schema identifier, bumped on incompatible changes.
pub const REPORT_SCHEMA: &str = "outstation-bench-report/1";

// ---------------------------------------------------------------------------
// Assertions

/// A metric an assertion can test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    /// Fleet fidelity score, percent (analysis).
    Score,
    /// Fleet ack latency percentiles and maximum, milliseconds.
    P50Ms,
    P90Ms,
    P99Ms,
    MaxMs,
    /// Fleet throughput, messages per second.
    Throughput,
    /// Sessions that ended with an error.
    SessionsFailed,
    /// Delivered / expected messages over all endpoints, percent
    /// (analysis).
    DeliveredPct,
    /// Endpoints whose analysis outcome is `fail` (analysis).
    VerdictFailures,
}

impl Metric {
    pub const ALL: [Metric; 9] = [
        Metric::Score,
        Metric::P50Ms,
        Metric::P90Ms,
        Metric::P99Ms,
        Metric::MaxMs,
        Metric::Throughput,
        Metric::SessionsFailed,
        Metric::DeliveredPct,
        Metric::VerdictFailures,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Metric::Score => "score",
            Metric::P50Ms => "p50_ms",
            Metric::P90Ms => "p90_ms",
            Metric::P99Ms => "p99_ms",
            Metric::MaxMs => "max_ms",
            Metric::Throughput => "throughput",
            Metric::SessionsFailed => "sessions_failed",
            Metric::DeliveredPct => "delivered_pct",
            Metric::VerdictFailures => "verdict_failures",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Op {
    #[serde(rename = ">=")]
    Ge,
    #[serde(rename = "<=")]
    Le,
    #[serde(rename = "==")]
    Eq,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = "<")]
    Lt,
}

impl Op {
    /// Longest first, so `>=` is never read as `>`.
    const TOKENS: [(&'static str, Op); 5] = [
        (">=", Op::Ge),
        ("<=", Op::Le),
        ("==", Op::Eq),
        (">", Op::Gt),
        ("<", Op::Lt),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Eq => "==",
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }

    pub fn holds(self, actual: f64, want: f64) -> bool {
        match self {
            Op::Ge => actual >= want,
            Op::Le => actual <= want,
            Op::Gt => actual > want,
            Op::Lt => actual < want,
            Op::Eq => (actual - want).abs() <= 1e-9 * want.abs().max(1.0),
        }
    }
}

/// `<metric><op><number>`, e.g. `score>=99` or `p99_ms <= 500`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Assertion {
    pub metric: Metric,
    pub op: Op,
    pub value: f64,
}

impl fmt::Display for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            self.metric.name(),
            self.op.as_str(),
            self.value
        )
    }
}

impl FromStr for Assertion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (pos, tok, op) = s
            .char_indices()
            .find_map(|(i, _)| {
                Op::TOKENS
                    .iter()
                    .find(|(t, _)| s[i..].starts_with(t))
                    .map(|(t, op)| (i, *t, *op))
            })
            .ok_or_else(|| {
                format!("assertion {s:?} has no operator (use one of >=, <=, ==, >, <)")
            })?;
        let name = s[..pos].trim();
        let num = s[pos + tok.len()..].trim();
        let metric = Metric::ALL
            .into_iter()
            .find(|m| m.name() == name)
            .ok_or_else(|| {
                let names: Vec<&str> = Metric::ALL.iter().map(|m| m.name()).collect();
                format!(
                    "assertion {s:?}: unknown metric {name:?} (one of {})",
                    names.join(", ")
                )
            })?;
        let value: f64 = num
            .parse()
            .ok()
            .filter(|v: &f64| v.is_finite())
            .ok_or_else(|| format!("assertion {s:?}: {num:?} is not a finite number"))?;
        Ok(Assertion { metric, op, value })
    }
}

/// The metrics assertions are evaluated against. `None` = not
/// available (no analysis, no benchmark report).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct BenchMetrics {
    pub score: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p90_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub throughput: Option<f64>,
    pub sessions_failed: Option<f64>,
    pub delivered_pct: Option<f64>,
    pub verdict_failures: Option<f64>,
}

impl BenchMetrics {
    pub fn get(&self, m: Metric) -> Option<f64> {
        match m {
            Metric::Score => self.score,
            Metric::P50Ms => self.p50_ms,
            Metric::P90Ms => self.p90_ms,
            Metric::P99Ms => self.p99_ms,
            Metric::MaxMs => self.max_ms,
            Metric::Throughput => self.throughput,
            Metric::SessionsFailed => self.sessions_failed,
            Metric::DeliveredPct => self.delivered_pct,
            Metric::VerdictFailures => self.verdict_failures,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssertionResult {
    /// The assertion as written canonically, e.g. `p99_ms<=500`.
    pub expr: String,
    pub metric: Metric,
    pub op: Op,
    pub threshold: f64,
    /// `null` when the metric was not available (counts as a failure).
    pub actual: Option<f64>,
    pub passed: bool,
    pub message: String,
}

pub fn evaluate(asserts: &[Assertion], m: &BenchMetrics) -> Vec<AssertionResult> {
    asserts
        .iter()
        .map(|a| {
            let actual = m.get(a.metric);
            let passed = actual.is_some_and(|v| a.op.holds(v, a.value));
            let message = match actual {
                None => format!("{a}: {} is not available", a.metric.name()),
                Some(v) if passed => format!("{a}: ok ({} = {v})", a.metric.name()),
                Some(v) => format!("{a}: FAILED ({} = {v})", a.metric.name()),
            };
            AssertionResult {
                expr: a.to_string(),
                metric: a.metric,
                op: a.op,
                threshold: a.value,
                actual,
                passed,
                message,
            }
        })
        .collect()
}

/// Metrics from the run's benchmark report and its analysis.
pub(crate) fn metrics_of(
    bench: Option<&BenchmarkReportJson>,
    analysis: Option<&analysis::AnalysisSummary>,
) -> BenchMetrics {
    let ms = |us: u64| us as f64 / 1000.0;
    let has_latency = bench.is_some_and(|b| b.per_session.iter().any(|s| s.messages_sent > 0));
    let lat = |f: fn(&BenchmarkReportJson) -> u64| bench.filter(|_| has_latency).map(|b| ms(f(b)));
    let (delivered_pct, verdict_failures) = match analysis {
        Some(a) => {
            let exp: usize = a.slaves.iter().map(|s| s.expected_iframes).sum();
            let del: usize = a.slaves.iter().map(|s| s.delivered_iframes).sum();
            (
                Some(if exp > 0 {
                    del as f64 * 100.0 / exp as f64
                } else {
                    0.0
                }),
                Some(
                    a.slaves
                        .iter()
                        .filter(|s| s.outcome == protoplay::VerdictOutcome::Fail)
                        .count() as f64,
                ),
            )
        }
        None => (None, None),
    };
    BenchMetrics {
        score: analysis.map(|a| a.score_pct),
        p50_ms: lat(|b| b.aggregate_latency_p50_us),
        p90_ms: lat(|b| b.aggregate_latency_p90_us),
        p99_ms: lat(|b| b.aggregate_latency_p99_us),
        max_ms: lat(|b| b.aggregate_latency_max_us),
        throughput: bench.map(|b| b.aggregate_throughput_msgs_per_sec),
        sessions_failed: bench.map(|b| b.sessions_failed() as f64),
        delivered_pct,
        verdict_failures,
    }
}

// ---------------------------------------------------------------------------
// Report

/// Fleet latency of the run, milliseconds.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LatencyMs {
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    /// Weighted fleet histogram (bins in µs, see `LatencyHistogramJson`).
    pub histogram: Option<LatencyHistogramJson>,
}

/// The JSON written by `--report` (and printed with `--report -`).
#[derive(Serialize)]
pub struct BenchReport {
    pub schema: &'static str,
    pub version: &'static str,
    pub started_at: u64,
    pub finished_at: u64,
    pub profile: String,
    pub pcap: String,
    pub capture: Option<String>,
    /// Canonical request the run used.
    pub request: serde_json::Value,
    /// Same shape as one row of `GET /api/runs`.
    pub run: Option<RunSummary>,
    /// Per-session rows of the benchmark report.
    pub sessions: Vec<SessionReportJson>,
    pub latency: Option<LatencyMs>,
    /// Analysis summary (same shape as `GET /api/analyses/:id`).
    pub analysis: Option<serde_json::Value>,
    pub analysis_error: Option<String>,
    /// The run's own warnings (capture failures, guard restore or
    /// teardown errors) (N15).
    pub warnings: Vec<String>,
    pub metrics: BenchMetrics,
    pub assertions: Vec<AssertionResult>,
    /// True when every assertion passed (and there was no run error).
    pub passed: bool,
    pub interrupted: bool,
    /// Run error, if any (exit code 2).
    pub error: Option<String>,
    pub exit_code: i32,
}

impl BenchReport {
    fn empty(opts: &BenchOptions) -> Self {
        Self {
            schema: REPORT_SCHEMA,
            version: env!("CARGO_PKG_VERSION"),
            started_at: crate::events::now_secs(),
            finished_at: 0,
            profile: opts.profile.display().to_string(),
            pcap: opts
                .pcap
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            capture: None,
            request: serde_json::Value::Null,
            run: None,
            sessions: Vec::new(),
            latency: None,
            analysis: None,
            analysis_error: None,
            warnings: Vec::new(),
            metrics: BenchMetrics::default(),
            assertions: Vec::new(),
            passed: false,
            interrupted: false,
            error: None,
            exit_code: EXIT_RUN_ERROR,
        }
    }

    /// Settle `passed` and `exit_code` from the error and assertions.
    fn settle(&mut self) {
        self.finished_at = crate::events::now_secs();
        let all_ok = self.assertions.iter().all(|a| a.passed);
        self.passed = self.error.is_none() && all_ok;
        self.exit_code = if self.error.is_some() {
            EXIT_RUN_ERROR
        } else if all_ok {
            EXIT_PASS
        } else {
            EXIT_ASSERT_FAILED
        };
    }
}

/// Write the report atomically (`-` = stdout).
pub fn write_report(path: &Path, report: &BenchReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    if path == Path::new("-") {
        println!("{json}");
        return Ok(());
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("create temp file in {}", dir.display()))?;
    use std::io::Write;
    tmp.write_all(json.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .with_context(|| format!("write report {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Running

#[derive(Debug, Clone)]
pub struct BenchOptions {
    /// Source pcap. Without it the profile's `pcap_id` is looked up in
    /// the library (`<state_dir>/library`).
    pub pcap: Option<PathBuf>,
    /// Run request JSON: a `POST /api/run` body, or a profile as
    /// returned by `GET /api/profiles/:id` (`{name, request}`).
    pub profile: PathBuf,
    pub asserts: Vec<Assertion>,
    pub report: Option<PathBuf>,
    /// Journals, captures and (by default) the library live here.
    pub state_dir: PathBuf,
    /// Where to write the mirror capture; default
    /// `<state_dir>/captures/bench_<run id>.pcap`.
    pub capture: Option<PathBuf>,
    /// Analyse in `correct` mode (target is the device in the pcap).
    pub correct_mode: bool,
    /// CP56Time2a drift tolerance (ms) for the analysis (F066).
    pub cp56_tolerance_ms: f64,
}

/// Load a profile file into a validated benchmark request. A missing
/// `mode` defaults to `benchmark`; `raw` is refused.
pub fn load_profile(text: &str) -> Result<runbuild::RunRequest> {
    let mut v: serde_json::Value = serde_json::from_str(text).context("profile is not JSON")?;
    if let Some(inner) = v.get("request").filter(|r| r.is_object()) {
        v = inner.clone();
    }
    let Some(obj) = v.as_object_mut() else {
        bail!("profile must be a JSON object");
    };
    obj.entry("mode")
        .or_insert_with(|| serde_json::Value::String("benchmark".into()));
    let req = runbuild::from_json(v)?;
    if req.mode != RunMode::Benchmark {
        bail!("outstation bench runs benchmarks only; the profile has mode \"raw\"");
    }
    runbuild::validate_settings(&req)?;
    Ok(req)
}

/// Run id for a CLI run: far above ids the server hands out, so the
/// derived interface names do not collide with server runs.
fn cli_run_id() -> u64 {
    1_000_000 + u64::from(std::process::id()) % 600_000
}

async fn next_signal(term: &mut Option<tokio::signal::unix::Signal>) -> &'static str {
    let t = async {
        match term {
            Some(s) => {
                s.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        r = tokio::signal::ctrl_c() => {
            if r.is_err() {
                std::future::pending::<()>().await;
            }
            "SIGINT"
        }
        _ = t => "SIGTERM",
    }
}

/// Run the benchmark, analyse it, evaluate assertions. Never panics on
/// run failures: they end up in `error` with exit code 2.
pub fn run(opts: &BenchOptions) -> BenchReport {
    let mut rep = BenchReport::empty(opts);
    if let Err(e) = run_inner(opts, &mut rep) {
        rep.error = Some(format!("{e:#}"));
    }
    rep.settle();
    rep
}

fn run_inner(opts: &BenchOptions, rep: &mut BenchReport) -> Result<()> {
    // Never run next to a server (or another bench) on the same state
    // directory: their host cleanup would tear down each other's run
    // (N7).
    let _lock = crate::statelock::StateLock::acquire(&opts.state_dir, "bench")
        .context("refusing to run a benchmark on a state directory in use")?;
    let text = std::fs::read_to_string(&opts.profile)
        .with_context(|| format!("read profile {}", opts.profile.display()))?;
    let req = load_profile(&text)?;
    rep.request = runbuild::canonical_json(&req);
    let pcap_path = match (&opts.pcap, req.pcap_id.as_deref().filter(|s| !s.is_empty())) {
        (Some(p), _) => p.clone(),
        (None, Some(id)) => {
            let lib = opts.state_dir.join("library");
            crate::library::library_pcap_path(&lib, id)
                .map_err(|e| anyhow::anyhow!("pcap_id {id}: {}", e.message))?
        }
        (None, None) => bail!("no pcap: pass --pcap or set pcap_id in the profile"),
    };
    rep.pcap = pcap_path.display().to_string();
    let pcap = Arc::new(
        pcapload::load(&pcap_path).with_context(|| format!("load {}", pcap_path.display()))?,
    );

    let run_id = cli_run_id();
    let captures = opts.state_dir.join("captures");
    std::fs::create_dir_all(&captures).with_context(|| format!("create {}", captures.display()))?;
    let capture = opts
        .capture
        .clone()
        .unwrap_or_else(|| captures.join(format!("bench_{run_id}.pcap")));
    rep.capture = Some(capture.display().to_string());

    let (job, mut rs) = crate::routes::runs::build_job(&req, &opts.state_dir, Vec::new());
    let RunJob::Benchmark(mut cfg, replayer) = job else {
        bail!("not a benchmark job");
    };
    cfg.run_id = run_id;
    cfg.capture_path = Some(capture.clone());
    let ctx = sched::RunContext::new();
    rs.id = run_id;
    rs.started_at = rep.started_at;
    rs.started_by = Some("cli".into());
    rs.pcap = pcap_path.clone();
    rs.pcap_id = req.pcap_id.clone();
    rs.capture_file = Some(capture.clone());
    rs.ctx = ctx.clone();
    info!(run_id, pcap = %pcap_path.display(), capture = %capture.display(), "bench starting");

    // Slave role waits for a per-RTU "start"; headless runs start all.
    let done = Arc::new(AtomicBool::new(false));
    let starter = (req.role == runbuild::RoleReq::Slave).then(|| {
        let ctx = ctx.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                for p in ctx.sources().iter() {
                    p.ready.store(true, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    });

    let (tx, rx) = tokio::sync::oneshot::channel();
    let worker_ctx = ctx.clone();
    std::thread::Builder::new()
        .name(format!("bench-run-{run_id}"))
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                RunOutcome::Benchmark(
                    crate::runs::SchedExecutor.run_benchmark(pcap, cfg, replayer, worker_ctx),
                )
            }))
            .unwrap_or_else(|p| RunOutcome::Panicked(panic_message(&*p)));
            let _ = tx.send(outcome);
        })
        .context("spawn run thread")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build signal runtime")?;
    let (outcome, signal) = rt.block_on(async {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        let mut rx = rx;
        let mut signal: Option<&'static str> = None;
        tokio::select! {
            r = &mut rx => return (r.ok(), signal),
            s = next_signal(&mut term) => {
                warn!(signal = s, "interrupted; stopping the run");
                signal = Some(s);
                ctx.cancel_all();
            }
        }
        tokio::select! {
            r = &mut rx => (r.ok(), signal),
            _ = tokio::time::sleep(SIGNAL_GRACE) => {
                warn!("run did not stop within the grace period");
                (None, signal)
            }
            s = next_signal(&mut term) => {
                warn!(signal = s, "second signal; not waiting for the run any longer");
                (None, signal)
            }
        }
    });
    done.store(true, Ordering::Relaxed);
    if let Some(h) = starter {
        let _ = h.join();
    }
    if let Some(sig) = signal {
        rep.interrupted = true;
        match netctl::cleanup_all(&opts.state_dir) {
            Ok(r) => info!(
                actions = r.total_actions(),
                errors = r.errors.len(),
                "host cleanup after {sig}"
            ),
            Err(e) => warn!(error = %format!("{e:#}"), "host cleanup failed"),
        }
    }
    let outcome = outcome
        .unwrap_or_else(|| RunOutcome::Abandoned("run did not finish after the interrupt".into()));

    // Same finalisation as the server's `finalize`.
    refresh_progress(&mut rs);
    let (status, err) = derive_status(ctx.is_cancelled(), &outcome);
    if let RunOutcome::Benchmark(Ok(r)) = &outcome {
        rs.benchmark = Some(r.into());
    }
    rs.status = status;
    rs.error = err;
    rs.finished_at = Some(crate::events::now_secs());
    if let Some(b) = &rs.benchmark {
        rep.sessions = b.per_session.clone();
        rep.latency = Some(LatencyMs {
            min_ms: b.aggregate_latency_min_us as f64 / 1000.0,
            p50_ms: b.aggregate_latency_p50_us as f64 / 1000.0,
            p90_ms: b.aggregate_latency_p90_us as f64 / 1000.0,
            p99_ms: b.aggregate_latency_p99_us as f64 / 1000.0,
            max_ms: b.aggregate_latency_max_us as f64 / 1000.0,
            histogram: b.aggregate_latency_histogram.clone(),
        });
    }
    rep.run = Some(rs.summary());

    // Analyse the run's own mirror capture, unless it failed (N15).
    let unavailable = if capture.is_file() {
        crate::analysis_run::capture_problem(&rs, &capture)
    } else {
        None
    };
    if let Some(b) = &rs.benchmark {
        rep.warnings = b.warnings.clone();
    }
    let summary = if let Some(why) = &unavailable {
        rep.analysis_error = Some(format!("capture unavailable: {why}"));
        None
    } else if capture.is_file() {
        let mode = if opts.correct_mode {
            AnalysisMode::Correct
        } else {
            AnalysisMode::Generic
        };
        match crate::analysis_run::analyze_run(&rs, &capture, mode, opts.cp56_tolerance_ms) {
            Ok(r) => Some(r.split().0),
            Err(e) => {
                rep.analysis_error = Some(format!("{e:#}"));
                None
            }
        }
    } else {
        rep.analysis_error = Some(format!("no capture at {}", capture.display()));
        None
    };
    rep.metrics = metrics_of(rs.benchmark.as_ref(), summary.as_ref());
    rep.analysis = summary.and_then(|s| serde_json::to_value(&s).ok());
    rep.assertions = evaluate(&opts.asserts, &rep.metrics);

    if let Some(sig) = signal {
        bail!("interrupted by {sig}; run {}", status.as_str());
    }
    if let Some(why) = unavailable {
        bail!("capture unavailable, the run cannot be judged: {why}");
    }
    if status == RunStatus::Failed {
        bail!(
            "run failed: {}",
            rs.error.as_deref().unwrap_or("unknown error")
        );
    }
    Ok(())
}

/// One-screen human summary for stdout.
pub fn summary_text(r: &BenchReport) -> String {
    let mut s = String::new();
    use std::fmt::Write as _;
    if let Some(run) = &r.run {
        let _ = writeln!(
            s,
            "run {}: {} ({} sessions, {} failed)",
            run.id,
            run.status.as_str(),
            run.benchmark.as_ref().map(|b| b.sessions).unwrap_or(0),
            run.benchmark
                .as_ref()
                .map(|b| b.sessions_failed)
                .unwrap_or(0),
        );
    }
    if let Some(l) = &r.latency {
        let _ = writeln!(
            s,
            "latency ms: p50 {:.3}  p90 {:.3}  p99 {:.3}  max {:.3}",
            l.p50_ms, l.p90_ms, l.p99_ms, l.max_ms
        );
    }
    match (&r.analysis, &r.analysis_error) {
        (Some(a), _) => {
            let _ = writeln!(
                s,
                "analysis: {} (score {:.2}%)",
                a["verdict"].as_str().unwrap_or("?"),
                a["score_pct"].as_f64().unwrap_or(0.0)
            );
        }
        (None, Some(e)) => {
            let _ = writeln!(s, "analysis: unavailable: {e}");
        }
        _ => {}
    }
    for w in &r.warnings {
        let _ = writeln!(s, "warning: {w}");
    }
    for a in &r.assertions {
        let _ = writeln!(s, "  {}", a.message);
    }
    if let Some(e) = &r.error {
        let _ = writeln!(s, "error: {e}");
    }
    let _ = writeln!(
        s,
        "result: {} (exit {})",
        if r.passed { "PASS" } else { "FAIL" },
        r.exit_code
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::DEFAULT_CP56_TOLERANCE_MS;

    fn a(s: &str) -> Assertion {
        s.parse().unwrap()
    }

    #[test]
    fn parses_every_operator_and_metric() {
        assert_eq!(
            a("score>=99"),
            Assertion {
                metric: Metric::Score,
                op: Op::Ge,
                value: 99.0
            }
        );
        assert_eq!(a(" p99_ms <= 500 ").op, Op::Le);
        assert_eq!(a("sessions_failed==0").op, Op::Eq);
        assert_eq!(a("throughput>1e3").value, 1000.0);
        assert_eq!(a("max_ms<2.5").op, Op::Lt);
        assert_eq!(a("delivered_pct>=-0").value, 0.0);
        for m in Metric::ALL {
            assert_eq!(a(&format!("{}>=1", m.name())).metric, m);
        }
        assert_eq!(a("p50_ms>=1.5").to_string(), "p50_ms>=1.5");
    }

    #[test]
    fn rejects_bad_assertions() {
        for bad in [
            "",
            "score",
            "score=99",
            "score=>99",
            ">=99",
            "latency>=1",
            "score>=",
            "score>=abc",
            "score>=NaN",
            "score>=inf",
            "Score>=1",
        ] {
            assert!(bad.parse::<Assertion>().is_err(), "{bad:?} parsed");
        }
        let e = "p99>=1".parse::<Assertion>().unwrap_err();
        assert!(e.contains("p99_ms"), "{e}");
    }

    #[test]
    fn evaluation_handles_ops_and_missing_metrics() {
        let m = BenchMetrics {
            score: Some(99.5),
            p99_ms: Some(500.0),
            sessions_failed: Some(0.0),
            ..Default::default()
        };
        let r = evaluate(
            &[
                a("score>=99"),
                a("score>99.5"),
                a("p99_ms<=500"),
                a("p99_ms<500"),
                a("sessions_failed==0"),
                a("delivered_pct>=99"),
            ],
            &m,
        );
        let passed: Vec<bool> = r.iter().map(|x| x.passed).collect();
        assert_eq!(passed, [true, false, true, false, true, false]);
        assert_eq!(r[5].actual, None);
        assert!(r[5].message.contains("not available"));
        assert!(Op::Eq.holds(0.1 + 0.2, 0.3), "float tolerance");
    }

    fn report_with(asserts: Vec<AssertionResult>, error: Option<&str>) -> BenchReport {
        let mut r = BenchReport::empty(&BenchOptions {
            pcap: Some("/x.pcap".into()),
            profile: "/p.json".into(),
            asserts: vec![],
            report: None,
            state_dir: "/s".into(),
            capture: None,
            correct_mode: false,
            cp56_tolerance_ms: DEFAULT_CP56_TOLERANCE_MS,
        });
        r.assertions = asserts;
        r.error = error.map(str::to_string);
        r.settle();
        r
    }

    #[test]
    fn exit_codes_and_report_shape() {
        let m = BenchMetrics {
            score: Some(100.0),
            ..Default::default()
        };
        let ok = evaluate(&[a("score>=99")], &m);
        let bad = evaluate(&[a("score<99")], &m);
        assert_eq!(report_with(ok.clone(), None).exit_code, EXIT_PASS);
        assert_eq!(report_with(bad, None).exit_code, EXIT_ASSERT_FAILED);
        assert_eq!(
            report_with(ok.clone(), Some("boom")).exit_code,
            EXIT_RUN_ERROR
        );
        assert_eq!(report_with(vec![], None).exit_code, EXIT_PASS);

        let mut r = report_with(ok, None);
        r.metrics = m;
        let v = serde_json::to_value(r).unwrap();
        for k in [
            "schema",
            "version",
            "started_at",
            "finished_at",
            "profile",
            "pcap",
            "capture",
            "request",
            "run",
            "sessions",
            "latency",
            "analysis",
            "analysis_error",
            "metrics",
            "assertions",
            "passed",
            "interrupted",
            "error",
            "exit_code",
        ] {
            assert!(v.get(k).is_some(), "report lacks {k}: {v}");
        }
        assert_eq!(v["schema"], REPORT_SCHEMA);
        assert_eq!(v["assertions"][0]["op"], ">=");
        assert_eq!(v["assertions"][0]["metric"], "score");
        assert_eq!(v["metrics"]["score"], 100.0);
        assert!(v["metrics"]["p99_ms"].is_null());
    }

    #[test]
    fn profiles_default_to_benchmark_and_accept_api_exports() {
        let r = load_profile(r#"{"target_ip":"10.0.0.5","role":"slave"}"#).unwrap();
        assert_eq!(r.mode, RunMode::Benchmark);
        let r = load_profile(
            r#"{"id":3,"name":"x","request":{"target_ip":"10.0.0.5","mode":"benchmark",
                "iterations":4}}"#,
        )
        .unwrap();
        assert_eq!(r.iterations, 4);
        assert!(load_profile(r#"{"target_ip":"10.0.0.5","mode":"raw"}"#).is_err());
        assert!(load_profile(r#"{"target_ip":"10.0.0.5","speed":0}"#).is_err());
        assert!(load_profile(r#"{"target_ip":"10.0.0.5","pcap":"/etc/passwd"}"#).is_err());
        assert!(load_profile("[1]").is_err());
        // T17c: gateway mode in master role is refused with its code.
        let e = load_profile(
            r#"{"target_ip":"10.0.0.5","role":"master","scada_gateway_ip":"10.0.0.254","scada_gateway_iface":"eth0"}"#,
        )
        .unwrap_err();
        let re = e.downcast_ref::<runbuild::RequestError>().unwrap();
        assert_eq!(re.code, "gateway_requires_slave", "{e:#}");
    }

    #[test]
    fn metrics_come_from_bench_and_analysis() {
        let b = BenchmarkReportJson {
            per_session: vec![
                SessionReportJson {
                    messages_sent: 10,
                    ..Default::default()
                },
                SessionReportJson {
                    error: Some("x".into()),
                    ..Default::default()
                },
            ],
            aggregate_latency_p99_us: 1500,
            aggregate_throughput_msgs_per_sec: 12.5,
            ..Default::default()
        };
        let m = metrics_of(Some(&b), None);
        assert_eq!(m.p99_ms, Some(1.5));
        assert_eq!(m.sessions_failed, Some(1.0));
        assert_eq!(m.throughput, Some(12.5));
        assert_eq!((m.score, m.delivered_pct), (None, None));
        let m = metrics_of(None, None);
        assert_eq!(m, BenchMetrics::default());
    }
}
