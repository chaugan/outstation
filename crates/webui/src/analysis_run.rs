//! Analysing a run's capture against its source pcap: the shared path
//! behind the manual upload (`POST /api/analyze`), the automatic
//! post-run analysis, on-demand analysis for compare, and the headless
//! `outstation bench` CLI (T08, T09, T10).
//!
//! The run facts the analyser needs (F060, F066) come from the run's
//! persisted request: `loop_within_session`, the pacing speed when
//! pacing was `original`, and the source pcap's server port.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use tracing::{info, warn};

use crate::analysis::{self, analyze, AnalysisMode, RoleHint};
use crate::db::{Db, StoredAnalysis};
use crate::dto::*;
use crate::error::{AppError, LockExt};
use crate::metrics::AnalysisSource;
use crate::state::AppState;

/// Run facts the analysis judges against (F060, F062, F066, F093).
pub(crate) fn run_info_of(rs: &RunState) -> analysis::RunInfo {
    let facts = rs
        .request
        .clone()
        .and_then(|v| crate::runbuild::from_json(v).ok())
        .map(|r| crate::runbuild::analysis_facts(&r));
    analysis::RunInfo {
        status: match rs.status {
            RunStatus::Completed => analysis::RunStatusHint::Completed,
            RunStatus::Partial => analysis::RunStatusHint::Partial,
            RunStatus::Stopped => analysis::RunStatusHint::Stopped,
            RunStatus::Failed => analysis::RunStatusHint::Failed,
            RunStatus::Running => analysis::RunStatusHint::Running,
        },
        error: rs.error.clone(),
        messages_sent: Some(
            rs.benchmark
                .as_ref()
                .map(|b| b.total_messages_sent)
                .unwrap_or(rs.sent),
        ),
        endpoints: rs
            .per_source_progress
            .iter()
            .filter_map(|p| {
                Some(analysis::SelectedEndpoint {
                    source_ip: p.src_ip.as_deref()?.parse().ok()?,
                    listen_ip: p.listen_ip.parse().ok(),
                    listen_port: (p.listen_port != 0).then_some(p.listen_port),
                    state: p.state.clone(),
                    cancelled: p.cancelled,
                    sent: p.sent,
                })
            })
            .collect(),
        iterations: rs
            .per_source_progress
            .iter()
            .map(|p| p.iter_total)
            .max()
            .unwrap_or(1),
        // Unknown for runs that predate the persisted request: the
        // analyser then falls back to capture-driven detection.
        loop_within_session: facts.map(|f| f.loop_within_session),
        paced_speed: facts.and_then(|f| f.paced_speed),
        source_port: facts.map(|f| f.source_port),
        capture_dropped: rs
            .benchmark
            .as_ref()
            .map(|b| b.captured_dropped)
            .unwrap_or(0),
        capture_truncated: rs
            .benchmark
            .as_ref()
            .and_then(|b| b.capture_truncated)
            .unwrap_or(false),
        capture_warnings: rs
            .benchmark
            .as_ref()
            .map(|b| {
                b.warnings
                    .iter()
                    .filter(|w| analysis::is_capture_warning(w))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default(),
        capture_ok: rs.benchmark.as_ref().and_then(|b| b.capture_ok),
    }
}

/// Can `rs` be analysed? Errors carry the API status and code.
pub(crate) fn check_analyzable(rs: &RunState) -> Result<(), AppError> {
    if rs.mode != "benchmark" {
        return Err(
            AppError::BadRequest("analysis currently targets benchmark runs only")
                .code("not_benchmark"),
        );
    }
    if !rs.status.is_terminal() {
        return Err(AppError::Conflict(
            "run_running",
            format!(
                "run {} is still running; analyse it once it has finished",
                rs.id
            ),
        ));
    }
    if !rs.pcap.is_file() {
        return Err(AppError::NotFound(format!(
            "source pcap of run {} is no longer in the library (pcap_id {})",
            rs.id,
            rs.pcap_id.as_deref().unwrap_or("?")
        ))
        .code("source_pcap_missing"));
    }
    if proto_registry::lookup(&rs.proto).is_none() {
        return Err(AppError::BadRequest(format!(
            "unknown protocol: {}",
            rs.proto
        )));
    }
    Ok(())
}

/// Size of a classic pcap file with a global header and no packets.
const PCAP_HEADER_ONLY: u64 = 24;

/// Why the run's own capture cannot be trusted for an analysis, if it
/// cannot (N15): the scheduler said the capture failed, a capture
/// warning says it never started, or the file holds no frames although
/// the run sent some. Analysing such a capture would report a false
/// `no_delivery`.
pub(crate) fn capture_problem(rs: &RunState, capture: &Path) -> Option<String> {
    let (ok, warnings, sent, packets) = match (&rs.benchmark, &rs.report) {
        (Some(b), _) => (
            b.capture_ok,
            b.warnings.as_slice(),
            b.total_messages_sent,
            b.captured_packets,
        ),
        (None, Some(r)) => (
            r.capture_ok,
            r.warnings.as_slice(),
            r.total_packets,
            r.captured_packets,
        ),
        (None, None) => return None,
    };
    let capture_warning = warnings.iter().find(|w| {
        let w = w.to_ascii_lowercase();
        w.contains("capture failed")
            || w.contains("capture disabled")
            || w.contains("capture mirror")
            || (w.contains("capture") && w.contains("failed"))
    });
    if ok == Some(false) {
        return Some(
            capture_warning
                .cloned()
                .unwrap_or_else(|| "the run's capture failed".into()),
        );
    }
    let len = std::fs::metadata(capture).map(|m| m.len()).unwrap_or(0);
    if sent > 0 && packets == 0 && len <= PCAP_HEADER_ONLY {
        return Some(match capture_warning {
            Some(w) => format!("the capture holds no frames although {sent} were sent ({w})"),
            None => format!("the capture holds no frames although {sent} were sent"),
        });
    }
    None
}

/// The run's own capture, if it is still on disk inside `captures_dir`.
pub(crate) fn run_capture(rs: &RunState, captures_dir: &Path) -> Option<PathBuf> {
    rs.capture_file
        .clone()
        .filter(|p| crate::captures::is_regular_file_inside(p, captures_dir))
}

/// Analyse `captured` against the source pcap of `rs`. Blocking: call
/// it on the blocking pool or a worker thread.
pub fn analyze_run(
    rs: &RunState,
    captured: &Path,
    mode: AnalysisMode,
    cp56_tolerance_ms: f64,
) -> anyhow::Result<analysis::AnalysisReport> {
    let replayer = proto_registry::lookup(&rs.proto)
        .ok_or_else(|| anyhow::anyhow!("unknown protocol: {}", rs.proto))?;
    let role = match rs.role {
        "slave" => RoleHint::Slave,
        _ => RoleHint::Master,
    };
    analyze(
        replayer.as_ref(),
        &analysis::AnalyzeRequest {
            original_pcap_path: &rs.pcap,
            captured_pcap_path: captured,
            run_id: rs.id,
            target_port: rs.target_port,
            role,
            mode,
            proto_config: rs.proto_config.clone(),
            cp56_tolerance_ms,
            run: run_info_of(rs),
        },
    )
}

/// Store the bounded summary and per-endpoint details. Blocking.
pub(crate) fn store_blocking(
    db: &Db,
    report: analysis::AnalysisReport,
    source: AnalysisSource,
) -> anyhow::Result<StoredAnalysis> {
    let run_id = report.run_id;
    let (summary, details) = report.split();
    let summary_json = serde_json::to_string(&summary)?;
    let details: Vec<(String, String)> = details
        .into_iter()
        .map(|(ep, d)| Ok((ep, serde_json::to_string(&d)?)))
        .collect::<anyhow::Result<_>>()?;
    let id = db.insert_analysis_from(
        run_id,
        summary.verdict,
        summary.score_pct,
        &summary_json,
        &details,
        source.as_str(),
    )?;
    Ok(StoredAnalysis {
        id,
        run_id,
        created_at: crate::events::now_secs(),
        verdict: summary.verdict.to_string(),
        score_pct: summary.score_pct,
        source: source.as_str().to_string(),
    })
}

/// Point the in-memory run at its newest analysis.
pub(crate) fn note_analysis(state: &AppState, a: &StoredAnalysis) {
    if let Some(e) = state.get_run(a.run_id) {
        e.lock_safe().latest_analysis = Some(a.into());
    }
}

/// Analyse a finished run's own capture and store the result, on the
/// blocking pool, holding a heavy-work permit (waits for one).
pub(crate) async fn analyze_and_store(
    state: &AppState,
    rs: RunState,
    capture: PathBuf,
    source: AnalysisSource,
    cp56_tolerance_ms: f64,
) -> Result<(StoredAnalysis, analysis::AnalysisReport), AppError> {
    let db = state.db.clone();
    let m = state.metrics.clone();
    m.analyses_running.fetch_add(1, Ordering::Relaxed);
    let res = tokio::task::spawn_blocking(move || {
        let report = analyze_run(&rs, &capture, AnalysisMode::Generic, cp56_tolerance_ms)
            .map_err(|e| AppError::BadRequest(format!("analyze run {}: {e:#}", rs.id)))?;
        let stored = store_blocking(&db, report.clone(), source)
            .map_err(|e| AppError::Internal(format!("store analysis: {e:#}")))?;
        Ok::<_, AppError>((stored, report))
    })
    .await
    .map_err(|e| AppError::Internal(format!("analyze task: {e}")))
    .and_then(|r| r);
    m.analyses_running.fetch_sub(1, Ordering::Relaxed);
    m.count_analysis(source, res.is_ok());
    if let Ok((a, _)) = &res {
        note_analysis(state, a);
    }
    res
}

fn set_auto(state: &AppState, id: u64, a: AutoAnalysis) {
    if let Some(e) = state.get_run(id) {
        e.lock_safe().auto_analysis = Some(a);
    }
}

/// After a benchmark run reached a terminal status: analyse its own
/// capture automatically and store the result (T08). Skipped (with the
/// reason on the run) when auto-analysis is disabled, there is no
/// capture, or the source pcap is gone. Never blocks the caller.
pub(crate) fn spawn_auto_analysis(state: &AppState, id: u64) {
    if !state.cfg.auto_analyze {
        return;
    }
    let Some(entry) = state.get_run(id) else {
        return;
    };
    let (rs, capture) = {
        let mut rs = entry.lock_safe();
        if rs.mode != "benchmark" {
            return;
        }
        let skip = |rs: &mut RunState, why: String| {
            info!(id, reason = %why, "auto-analysis skipped");
            rs.auto_analysis = Some(AutoAnalysis {
                state: "skipped",
                error: Some(why),
                analysis_id: None,
            });
        };
        let Some(capture) = run_capture(&rs, &state.cfg.captures_dir()) else {
            skip(&mut rs, "the run left no capture".into());
            return;
        };
        if let Some(why) = capture_problem(&rs, &capture) {
            warn!(id, reason = %why, "auto-analysis skipped: capture unavailable");
            skip(&mut rs, format!("capture unavailable: {why}"));
            return;
        }
        if let Err(e) = check_analyzable(&rs) {
            skip(&mut rs, e.message);
            return;
        }
        rs.auto_analysis = Some(AutoAnalysis {
            state: "queued",
            error: None,
            analysis_id: None,
        });
        (rs.clone(), capture)
    };
    let Some(rt) = state.rt.clone() else {
        set_auto(
            state,
            id,
            AutoAnalysis {
                state: "skipped",
                error: Some("no async runtime to run the analysis on".into()),
                analysis_id: None,
            },
        );
        return;
    };
    let st = state.clone();
    rt.spawn(async move {
        let started_by = rs.started_by.clone().unwrap_or_default();
        let permit = st.heavy.clone().acquire_owned().await;
        if st.shutdown.is_cancelled() || permit.is_err() {
            set_auto(
                &st,
                id,
                AutoAnalysis {
                    state: "skipped",
                    error: Some("server is shutting down".into()),
                    analysis_id: None,
                },
            );
            return;
        }
        set_auto(
            &st,
            id,
            AutoAnalysis {
                state: "running",
                error: None,
                analysis_id: None,
            },
        );
        let tol = st.cfg.cp56_tolerance_ms;
        match analyze_and_store(&st, rs, capture, AnalysisSource::Auto, tol).await {
            Ok((a, report)) => {
                info!(
                    id,
                    analysis = a.id,
                    verdict = report.verdict,
                    "auto-analysis stored"
                );
                set_auto(
                    &st,
                    id,
                    AutoAnalysis {
                        state: "done",
                        error: None,
                        analysis_id: Some(a.id),
                    },
                );
                st.emit("analysis_finished", id, &started_by, None, report.verdict);
            }
            Err(e) => {
                warn!(id, error = %e, "auto-analysis failed");
                set_auto(
                    &st,
                    id,
                    AutoAnalysis {
                        state: "failed",
                        error: Some(e.message),
                        analysis_id: None,
                    },
                );
                st.emit("analysis_failed", id, &started_by, None, "failed");
            }
        }
        drop(permit);
    });
}

/// Most runs [`queue_startup_backlog`] analyses after a restart.
pub(crate) const STARTUP_BACKLOG_LIMIT: usize = 20;

/// After a restart: queue auto-analysis for finished benchmark runs
/// that never got one (O3): a run stopped by SIGTERM finishes while the
/// server shuts down, too late to be analysed, and one cut off by a
/// crash is only marked failed on the next start. Only runs with a
/// capture, no stored analysis, nothing tried in this process, and
/// that analysis accepts are picked; the newest `limit` are queued
/// (oldest first, so the newest lands last on the event stream) and
/// the rest are marked skipped, with the reason, and logged. Returns
/// the queued run ids. A no-op when auto-analysis is off.
pub(crate) fn queue_startup_backlog(state: &AppState, limit: usize) -> Vec<u64> {
    if !state.cfg.auto_analyze {
        return Vec::new();
    }
    let captures_dir = state.cfg.captures_dir();
    let mut due: Vec<u64> = state
        .all_runs()
        .iter()
        .filter_map(|e| {
            let rs = e.lock_safe();
            let due = rs.mode == "benchmark"
                && rs.latest_analysis.is_none()
                && rs.auto_analysis.is_none()
                && run_capture(&rs, &captures_dir).is_some()
                && check_analyzable(&rs).is_ok();
            due.then_some(rs.id)
        })
        .collect();
    due.sort_unstable_by(|a, b| b.cmp(a));
    let older = due.split_off(due.len().min(limit));
    if !older.is_empty() {
        warn!(
            queued = due.len(),
            skipped = older.len(),
            ids = ?older,
            "startup: too many finished runs without an analysis; \
             analysing only the newest, the rest can be analysed on demand"
        );
        for id in &older {
            set_auto(
                state,
                *id,
                AutoAnalysis {
                    state: "skipped",
                    error: Some(format!(
                        "not analysed after the restart (only the newest {limit} are); \
                         analyse it on demand"
                    )),
                    analysis_id: None,
                },
            );
        }
    }
    if !due.is_empty() {
        info!(ids = ?due, "startup: queueing auto-analysis of finished runs");
    }
    due.reverse();
    for id in &due {
        spawn_auto_analysis(state, *id);
    }
    due
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(request: Option<serde_json::Value>) -> RunState {
        let mut rs = crate::persist::stored_to_runstate(
            &crate::db::StoredRun {
                id: 1,
                status: "completed".into(),
                target_ip: "10.0.0.1".into(),
                mode: "benchmark".into(),
                role: "slave".into(),
                ..Default::default()
            },
            Path::new("/nonexistent"),
            Path::new("/nonexistent"),
        )
        .unwrap();
        rs.request = request;
        rs
    }

    #[test]
    fn facts_come_from_the_persisted_request() {
        let info = run_info_of(&run(Some(json!({
            "target_ip": "10.0.0.1", "mode": "benchmark", "role": "slave",
            "loop_within_session": true, "pacing": "original", "speed": 2.0,
            "target_port": 2405, "listen_port_base": 3000, "iterations": 4
        }))));
        assert_eq!(info.loop_within_session, Some(true));
        assert_eq!(info.paced_speed, Some(2.0));
        assert_eq!(info.source_port, Some(2405));
        assert_eq!(info.status, analysis::RunStatusHint::Completed);

        let info = run_info_of(&run(Some(json!({
            "target_ip": "10.0.0.1", "mode": "benchmark", "role": "master",
            "loop_within_session": true
        }))));
        assert_eq!(info.loop_within_session, Some(false));
        assert_eq!(info.paced_speed, None);
        assert_eq!(info.source_port, Some(2404));

        // Runs that predate stored requests: unknown, not guessed.
        let info = run_info_of(&run(None));
        assert_eq!(
            (info.loop_within_session, info.paced_speed, info.source_port),
            (None, None, None)
        );
    }

    /// T17c: the run's capture warnings and `capture_ok` reach the
    /// analysis; other warnings do not.
    #[test]
    fn capture_warnings_are_passed_to_the_analysis() {
        let mut rs = run(None);
        rs.benchmark = Some(BenchmarkReportJson {
            warnings: vec![
                "capture on eth1: the per-MAC reply filter for 600 sessions did not fit".into(),
                "topology teardown: teardown had 1 errors".into(),
            ],
            capture_ok: Some(true),
            ..Default::default()
        });
        let info = run_info_of(&rs);
        assert_eq!(info.capture_warnings.len(), 1);
        assert!(info.capture_warnings[0].contains("per-MAC"));
        assert_eq!(info.capture_ok, Some(true));
    }

    #[test]
    fn analyzability_checks() {
        let mut rs = run(None);
        assert_eq!(
            check_analyzable(&rs).unwrap_err().code,
            "source_pcap_missing"
        );
        rs.mode = "raw";
        assert_eq!(check_analyzable(&rs).unwrap_err().code, "not_benchmark");
        rs.mode = "benchmark";
        rs.status = RunStatus::Running;
        assert_eq!(check_analyzable(&rs).unwrap_err().code, "run_running");
    }

    #[test]
    fn capture_problems_are_detected() {
        let d = tempfile::tempdir().unwrap();
        let header_only = d.path().join("h.pcap");
        std::fs::write(&header_only, [0u8; 24]).unwrap();
        let full = d.path().join("f.pcap");
        std::fs::write(&full, [0u8; 200]).unwrap();
        let mut rs = run(None);
        assert_eq!(
            capture_problem(&rs, &header_only),
            None,
            "no report: unknown"
        );
        rs.benchmark = Some(BenchmarkReportJson {
            total_messages_sent: 10,
            ..Default::default()
        });
        // Header only although 10 messages were sent.
        let why = capture_problem(&rs, &header_only).unwrap();
        assert!(why.contains("no frames although 10"), "{why}");
        // Frames on disk: fine.
        rs.benchmark.as_mut().unwrap().captured_packets = 12;
        assert_eq!(capture_problem(&rs, &full), None);
        // The scheduler says the capture failed: never trusted.
        let b = rs.benchmark.as_mut().unwrap();
        b.capture_ok = Some(false);
        b.warnings = vec!["capture failed to start: EPERM".into()];
        assert_eq!(
            capture_problem(&rs, &full).as_deref(),
            Some("capture failed to start: EPERM")
        );
        // Nothing sent and nothing captured: an honest empty capture.
        let b = rs.benchmark.as_mut().unwrap();
        b.capture_ok = None;
        b.warnings.clear();
        b.total_messages_sent = 0;
        b.captured_packets = 0;
        assert_eq!(capture_problem(&rs, &header_only), None);
    }
}
