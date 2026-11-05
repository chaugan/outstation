//! Prometheus text exposition at `GET /metrics` (T13), hand-rolled:
//! format 0.0.4, no client library.
//!
//! Counters derived from run history (`outstation_frames_sent_total`,
//! `outstation_bytes_sent_total`, the latency histogram, run durations)
//! sum every run this process knows: runs restored from the database,
//! the live counters of a running run, and the totals of runs deleted
//! since start. A deleted run's totals are folded in under the same
//! lock the scrape takes, so the counters never step backwards.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::dto::*;
use crate::error::LockExt;
use crate::health::Health;
use crate::state::AppState;

/// How an analysis was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnalysisSource {
    /// Uploaded capture (`POST /api/analyze`).
    Manual,
    /// Automatically after a benchmark run finished.
    Auto,
    /// By a compare request for a run without an analysis.
    OnDemand,
}

impl AnalysisSource {
    pub(crate) const ALL: [AnalysisSource; 3] = [Self::Manual, Self::Auto, Self::OnDemand];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Auto => "auto",
            Self::OnDemand => "on_demand",
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

/// Totals of runs that were deleted while this process ran.
#[derive(Debug, Default)]
pub(crate) struct Folded {
    frames: u64,
    bytes: u64,
    duration_sum_secs: u64,
    duration_count: u64,
    hist: Option<Vec<u64>>,
    hist_underflow: u64,
    hist_overflow: u64,
}

#[derive(Debug, Default)]
pub(crate) struct Metrics {
    pub(crate) uploads_ok: AtomicU64,
    pub(crate) uploads_failed: AtomicU64,
    pub(crate) analyses_running: AtomicU64,
    /// Open live-progress WebSockets (N23).
    pub(crate) live_sockets: AtomicU64,
    /// `[source][ok=0 / error=1]`, this process only.
    analyses: [[AtomicU64; 2]; 3],
    /// Taken by the scrape and by run deletion (before any run lock).
    pub(crate) folded: Mutex<Folded>,
}

impl Metrics {
    pub(crate) fn count_analysis(&self, source: AnalysisSource, ok: bool) {
        self.analyses[source.idx()][usize::from(!ok)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_upload(&self, ok: bool) {
        if ok {
            &self.uploads_ok
        } else {
            &self.uploads_failed
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

/// What one run contributes to the history-derived counters.
struct RunTotals<'a> {
    frames: u64,
    bytes: u64,
    /// Terminal runs only.
    duration_secs: Option<u64>,
    hist: Option<&'a LatencyHistogramJson>,
}

fn run_totals(rs: &RunState) -> RunTotals<'_> {
    if !rs.status.is_terminal() {
        let pg = rs.ctx.progress();
        return RunTotals {
            frames: pg.frames_sent_total,
            bytes: pg.bytes_sent_total,
            duration_secs: None,
            hist: None,
        };
    }
    let frames = rs
        .benchmark
        .as_ref()
        .map(|b| b.total_messages_sent)
        .or_else(|| rs.report.as_ref().map(|r| r.total_packets))
        .unwrap_or(rs.sent);
    let bytes = rs
        .report
        .as_ref()
        .map(|r| r.total_bytes)
        .unwrap_or(rs.bytes_progress)
        .max(rs.bytes_progress);
    RunTotals {
        frames,
        bytes,
        duration_secs: rs.finished_at.map(|f| f.saturating_sub(rs.started_at)),
        hist: rs
            .benchmark
            .as_ref()
            .and_then(|b| b.aggregate_latency_histogram.as_ref()),
    }
}

fn add_hist(acc: &mut Option<Vec<u64>>, under: &mut u64, over: &mut u64, h: &LatencyHistogramJson) {
    // Only histograms with the standard layout are summed.
    if h.counts.len() != HIST_BINS || h.log10_min_us != HIST_LOG_MIN {
        return;
    }
    let a = acc.get_or_insert_with(|| vec![0; HIST_BINS]);
    for (x, c) in a.iter_mut().zip(&h.counts) {
        *x += c;
    }
    *under += h.underflow;
    *over += h.overflow;
}

/// Fold a run that is about to be deleted into the totals. Call with
/// `folded` locked, then remove the run from the map before unlocking.
pub(crate) fn fold_deleted(f: &mut Folded, rs: &RunState) {
    let t = run_totals(rs);
    f.frames += t.frames;
    f.bytes += t.bytes;
    if let Some(d) = t.duration_secs {
        f.duration_sum_secs += d;
        f.duration_count += 1;
    }
    if let Some(h) = t.hist {
        add_hist(&mut f.hist, &mut f.hist_underflow, &mut f.hist_overflow, h);
    }
}

/// Escape a Prometheus label value.
pub(crate) fn esc(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

/// Format a sample value (Prometheus accepts Go float syntax).
fn num(v: f64) -> String {
    if v.is_finite() {
        format!("{v}")
    } else if v.is_nan() {
        "NaN".into()
    } else if v > 0.0 {
        "+Inf".into()
    } else {
        "-Inf".into()
    }
}

struct Out(String);

impl Out {
    fn head(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }
    fn sample(&mut self, name: &str, labels: &[(&str, &str)], v: f64) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (i, (k, val)) in labels.iter().enumerate() {
                if i > 0 {
                    self.0.push(',');
                }
                let _ = write!(self.0, "{k}=\"{}\"", esc(val));
            }
            self.0.push('}');
        }
        let _ = writeln!(self.0, " {}", num(v));
    }
    fn one(&mut self, name: &str, kind: &str, help: &str, v: f64) {
        self.head(name, kind, help);
        self.sample(name, &[], v);
    }
}

/// Upper bound in seconds of histogram bin `i` (0-based).
fn bin_upper_secs(i: usize) -> f64 {
    let w = (HIST_LOG_MAX - HIST_LOG_MIN) / HIST_BINS as f64;
    10f64.powf(HIST_LOG_MIN + (i as f64 + 1.0) * w) / 1e6
}

/// Active run: id, seconds running, sessions by state, frames, bytes.
type ActiveFacts = (u64, u64, Vec<(String, u64)>, u64, u64);

/// Render the exposition. `health` comes from [`crate::health::gather`].
pub(crate) fn render(state: &AppState, health: &Health) -> String {
    let m = &state.metrics;
    let mut o = Out(String::with_capacity(8 * 1024));

    o.head(
        "outstation_build_info",
        "gauge",
        "Build information; always 1.",
    );
    o.sample(
        "outstation_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1.0,
    );
    o.one(
        "outstation_uptime_seconds",
        "gauge",
        "Seconds since the server started.",
        state.started.elapsed().as_secs_f64(),
    );

    // -- runs (history-derived; under the fold lock) -------------------
    let folded = m.folded.lock_safe();
    let mut by_status = [0u64; 5];
    let mut frames = folded.frames;
    let mut bytes = folded.bytes;
    let mut dur_sum = folded.duration_sum_secs;
    let mut dur_count = folded.duration_count;
    let mut hist = folded.hist.clone();
    let mut under = folded.hist_underflow;
    let mut over = folded.hist_overflow;
    let mut active: Option<ActiveFacts> = None;
    let mut last_bench: Option<(u64, u64, u64, u64)> = None;
    let now = crate::events::now_secs();
    for e in state.all_runs() {
        let rs = e.lock_safe();
        let si = match rs.status {
            RunStatus::Running => 0,
            RunStatus::Completed => 1,
            RunStatus::Partial => 2,
            RunStatus::Stopped => 3,
            RunStatus::Failed => 4,
        };
        by_status[si] += 1;
        let t = run_totals(&rs);
        frames += t.frames;
        bytes += t.bytes;
        if let Some(d) = t.duration_secs {
            dur_sum += d;
            dur_count += 1;
        }
        if let Some(h) = t.hist {
            add_hist(&mut hist, &mut under, &mut over, h);
        }
        if let (Some(b), true) = (&rs.benchmark, rs.status.is_terminal()) {
            if last_bench.is_none_or(|(id, ..)| rs.id > id) {
                last_bench = Some((
                    rs.id,
                    b.aggregate_latency_p50_us,
                    b.aggregate_latency_p99_us,
                    b.per_session.len() as u64,
                ));
            }
        }
        if !rs.status.is_terminal() {
            let mut states: std::collections::BTreeMap<String, u64> = Default::default();
            for p in rs.ctx.per_source.lock_safe().iter() {
                *states
                    .entry(state_to_str(p.snapshot_state()).to_string())
                    .or_default() += 1;
            }
            active = Some((
                rs.id,
                now.saturating_sub(rs.started_at),
                states.into_iter().collect(),
                t.frames,
                t.bytes,
            ));
        }
    }
    drop(folded);

    o.head(
        "outstation_runs",
        "gauge",
        "Runs known to the server, by status.",
    );
    for (i, s) in ["running", "completed", "partial", "stopped", "failed"]
        .iter()
        .enumerate()
    {
        o.sample("outstation_runs", &[("status", s)], by_status[i] as f64);
    }
    o.one(
        "outstation_frames_sent_total",
        "counter",
        "Frames (raw replay) and messages (benchmark) sent by all runs, including the active one.",
        frames as f64,
    );
    o.one(
        "outstation_bytes_sent_total",
        "counter",
        "Bytes sent by all runs, including the active one.",
        bytes as f64,
    );
    o.head(
        "outstation_run_duration_seconds",
        "summary",
        "Wall-clock duration of finished runs.",
    );
    o.sample("outstation_run_duration_seconds_sum", &[], dur_sum as f64);
    o.sample(
        "outstation_run_duration_seconds_count",
        &[],
        dur_count as f64,
    );

    let (aid, adur, astates, aframes, abytes) = active.unwrap_or_default();
    o.one(
        "outstation_active_run_id",
        "gauge",
        "Id of the active run, 0 when idle.",
        aid as f64,
    );
    o.one(
        "outstation_active_run_duration_seconds",
        "gauge",
        "How long the active run has been running, 0 when idle.",
        adur as f64,
    );
    o.one(
        "outstation_active_run_frames_sent",
        "gauge",
        "Frames/messages sent so far by the active run.",
        aframes as f64,
    );
    o.one(
        "outstation_active_run_bytes_sent",
        "gauge",
        "Bytes sent so far by the active run.",
        abytes as f64,
    );
    o.head(
        "outstation_active_run_sessions",
        "gauge",
        "Sessions/sources of the active run, by lifecycle state.",
    );
    for st in [
        "pending",
        "listening",
        "connected",
        "active",
        "completed",
        "failed",
        "cancelled",
    ] {
        let n = astates
            .iter()
            .find(|(k, _)| k == st)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        o.sample("outstation_active_run_sessions", &[("state", st)], n as f64);
    }

    // Aggregate latency histogram over every finished benchmark run.
    let name = "outstation_benchmark_latency_seconds";
    o.head(
        name,
        "histogram",
        "Message acknowledgement latency of finished benchmark runs (weighted fleet \
         histograms summed; _sum estimated from bucket midpoints).",
    );
    let counts = hist.unwrap_or_else(|| vec![0; HIST_BINS]);
    let w = (HIST_LOG_MAX - HIST_LOG_MIN) / HIST_BINS as f64;
    let mut cum = under;
    // Underflow samples are below the first edge (10 µs).
    let mut sum = under as f64 * 5e-6;
    o.sample(
        &format!("{name}_bucket"),
        &[("le", &num(10f64.powf(HIST_LOG_MIN) / 1e6))],
        cum as f64,
    );
    for (i, c) in counts.iter().enumerate() {
        cum += c;
        let mid = 10f64.powf(HIST_LOG_MIN + (i as f64 + 0.5) * w) / 1e6;
        sum += *c as f64 * mid;
        o.sample(
            &format!("{name}_bucket"),
            &[("le", &num(bin_upper_secs(i)))],
            cum as f64,
        );
    }
    cum += over;
    sum += over as f64 * 10f64.powf(HIST_LOG_MAX) / 1e6;
    o.sample(&format!("{name}_bucket"), &[("le", "+Inf")], cum as f64);
    o.sample(&format!("{name}_sum"), &[], sum);
    o.sample(&format!("{name}_count"), &[], cum as f64);

    let (lid, p50, p99, sessions) = last_bench.unwrap_or_default();
    o.one(
        "outstation_last_benchmark_run_id",
        "gauge",
        "Id of the newest finished benchmark run, 0 if none.",
        lid as f64,
    );
    o.head(
        "outstation_last_benchmark_latency_seconds",
        "gauge",
        "Fleet latency quantiles of the newest finished benchmark run.",
    );
    o.sample(
        "outstation_last_benchmark_latency_seconds",
        &[("quantile", "0.5")],
        p50 as f64 / 1e6,
    );
    o.sample(
        "outstation_last_benchmark_latency_seconds",
        &[("quantile", "0.99")],
        p99 as f64 / 1e6,
    );
    o.one(
        "outstation_last_benchmark_sessions",
        "gauge",
        "Sessions of the newest finished benchmark run.",
        sessions as f64,
    );

    // -- uploads and analyses -------------------------------------------
    o.head(
        "outstation_uploads_total",
        "counter",
        "Library uploads handled by this process.",
    );
    o.sample(
        "outstation_uploads_total",
        &[("result", "ok")],
        m.uploads_ok.load(Ordering::Relaxed) as f64,
    );
    o.sample(
        "outstation_uploads_total",
        &[("result", "error")],
        m.uploads_failed.load(Ordering::Relaxed) as f64,
    );
    o.head(
        "outstation_analyses_total",
        "counter",
        "Analyses run by this process, by source and result.",
    );
    for s in AnalysisSource::ALL {
        for (r, res) in ["ok", "error"].iter().enumerate() {
            o.sample(
                "outstation_analyses_total",
                &[("source", s.as_str()), ("result", res)],
                m.analyses[s.idx()][r].load(Ordering::Relaxed) as f64,
            );
        }
    }
    o.one(
        "outstation_analyses_running",
        "gauge",
        "Analyses in progress.",
        m.analyses_running.load(Ordering::Relaxed) as f64,
    );
    o.one(
        "outstation_live_websockets",
        "gauge",
        "Open live-progress WebSocket streams.",
        m.live_sockets.load(Ordering::Relaxed) as f64,
    );
    if let Ok(counts) = state.db.analysis_counts() {
        o.head(
            "outstation_analyses_stored",
            "gauge",
            "Analyses stored in the database, by source.",
        );
        for s in AnalysisSource::ALL {
            let n = counts
                .iter()
                .find(|(k, _)| k == s.as_str())
                .map(|(_, v)| *v)
                .unwrap_or(0);
            o.sample(
                "outstation_analyses_stored",
                &[("source", s.as_str())],
                n as f64,
            );
        }
    }

    // -- health ----------------------------------------------------------
    if let Some(f) = health.free {
        o.one(
            "outstation_free_disk_bytes",
            "gauge",
            "Free bytes on the state directory's filesystem.",
            f as f64,
        );
    }
    o.one(
        "outstation_min_free_disk_bytes",
        "gauge",
        "Configured free-space floor for uploads and captures.",
        state.cfg.min_free_bytes as f64,
    );
    o.one(
        "outstation_db_writable",
        "gauge",
        "1 when the run database accepts writes.",
        f64::from(u8::from(health.db.is_ok())),
    );
    o.head(
        "outstation_guard_journal_entries",
        "gauge",
        "Host-state journal entries (undone on cleanup), by journal.",
    );
    o.sample(
        "outstation_guard_journal_entries",
        &[("journal", "guards")],
        health.journal.guards as f64,
    );
    o.sample(
        "outstation_guard_journal_entries",
        &[("journal", "aliases")],
        health.journal.aliases as f64,
    );
    if let Some(c) = &health.caps {
        o.head(
            "outstation_capability",
            "gauge",
            "1 when the process holds the capability.",
        );
        for (k, v) in [
            ("net_admin", c.net_admin),
            ("net_raw", c.net_raw),
            ("net_bind_service", c.net_bind_service),
            ("sys_nice", c.sys_nice),
        ] {
            o.sample(
                "outstation_capability",
                &[("cap", k)],
                f64::from(u8::from(v)),
            );
        }
    }
    o.head(
        "outstation_degraded",
        "gauge",
        "1 for each active degraded-health reason (see /api/status).",
    );
    for d in &health.degraded {
        o.sample("outstation_degraded", &[("reason", d.code)], 1.0);
    }
    o.one(
        "outstation_up",
        "gauge",
        "1 when no degraded reason is present.",
        f64::from(u8::from(health.degraded.is_empty())),
    );
    o.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(esc(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(esc("x\ny"), "x\\ny");
    }

    #[test]
    fn bucket_edges_match_the_histogram_layout() {
        assert!((bin_upper_secs(0) - 10f64.powf(1.25) / 1e6).abs() < 1e-12);
        assert!((bin_upper_secs(HIST_BINS - 1) - 10.0).abs() < 1e-9);
        assert_eq!(num(f64::INFINITY), "+Inf");
        assert_eq!(num(0.5), "0.5");
    }

    #[test]
    fn histograms_add_up_and_foreign_layouts_are_skipped() {
        let mut acc = None;
        let (mut u, mut o) = (0, 0);
        let mut h = LatencyHistogramJson::default();
        h.counts[3] = 5;
        h.underflow = 1;
        add_hist(&mut acc, &mut u, &mut o, &h);
        add_hist(&mut acc, &mut u, &mut o, &h);
        assert_eq!(acc.as_ref().unwrap()[3], 10);
        assert_eq!(u, 2);
        h.counts = vec![1; 3];
        add_hist(&mut acc, &mut u, &mut o, &h);
        assert_eq!(acc.unwrap().iter().sum::<u64>(), 10);
    }
}
