//! `GET /api/runs/:a/compare/:b` (T10): compare two finished benchmark
//! runs. Run `a` is the baseline.
//!
//! Query parameters (all optional):
//! * thresholds, see [`Thresholds`]: `score_drop`, `delivered_drop`,
//!   `p50_increase_pct`, `p99_increase_pct`, `latency_min_us`,
//!   `throughput_drop_pct`;
//! * `analysis_a`, `analysis_b`: compare these stored analyses instead
//!   of each run's newest one;
//! * `analyze` (default `true`): when a run has no stored analysis but
//!   still has its capture, analyse it on demand (stored with source
//!   `on_demand`). With `analyze=false`, or without a capture, a run
//!   with no analysis gives 409 `analysis_missing`.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::analysis_run::{analyze_and_store, check_analyzable, run_capture};
use crate::compare::{compare, Comparison, Side, Thresholds};
use crate::dto::*;
use crate::error::{ApiPath, ApiQuery, AppError, LockExt};
use crate::metrics::AnalysisSource;
use crate::routes::runs::busy;
use crate::state::AppState;

/// Query string. Thresholds are listed one by one: `serde(flatten)`
/// cannot parse numbers out of a query string.
#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CompareQuery {
    score_drop: Option<f64>,
    delivered_drop: Option<f64>,
    p50_increase_pct: Option<f64>,
    p99_increase_pct: Option<f64>,
    latency_min_us: Option<f64>,
    throughput_drop_pct: Option<f64>,
    analysis_a: Option<u64>,
    analysis_b: Option<u64>,
    analyze: Option<bool>,
}

impl CompareQuery {
    fn thresholds(&self) -> Thresholds {
        let d = Thresholds::default();
        Thresholds {
            score_drop: self.score_drop.unwrap_or(d.score_drop),
            delivered_drop: self.delivered_drop.unwrap_or(d.delivered_drop),
            p50_increase_pct: self.p50_increase_pct.unwrap_or(d.p50_increase_pct),
            p99_increase_pct: self.p99_increase_pct.unwrap_or(d.p99_increase_pct),
            latency_min_us: self.latency_min_us.unwrap_or(d.latency_min_us),
            throughput_drop_pct: self.throughput_drop_pct.unwrap_or(d.throughput_drop_pct),
        }
    }
}

/// Which run and analysis one side of the comparison used.
#[derive(Serialize)]
pub(crate) struct SideInfo {
    run_id: u64,
    status: RunStatus,
    pcap_id: Option<String>,
    role: &'static str,
    started_at: u64,
    analysis_id: u64,
    /// `manual`, `auto` or `on_demand`.
    analysis_source: String,
    /// True when this request ran the analysis.
    analyzed_now: bool,
}

#[derive(Serialize)]
pub(crate) struct CompareResp {
    a: SideInfo,
    b: SideInfo,
    #[serde(flatten)]
    comparison: Comparison,
    warnings: Vec<String>,
}

struct Loaded {
    info: SideInfo,
    summary: serde_json::Value,
    bench: Option<BenchmarkReportJson>,
}

/// A finished benchmark run, or the error that rules it out.
fn comparable_run(state: &AppState, id: u64) -> Result<RunState, AppError> {
    let rs = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?
        .lock_safe()
        .clone();
    if rs.mode != "benchmark" {
        return Err(
            AppError::BadRequest(format!("run {id} is not a benchmark run")).code("not_benchmark"),
        );
    }
    if !rs.status.is_terminal() {
        return Err(AppError::Conflict(
            "run_running",
            format!("run {id} is still running; compare it once it has finished"),
        ));
    }
    Ok(rs)
}

async fn load_side(
    state: &AppState,
    rs: RunState,
    pick: Option<u64>,
    analyze: bool,
) -> Result<Loaded, AppError> {
    let id = rs.id;
    let db_err = |e: anyhow::Error| AppError::Internal(format!("read analyses: {e:#}"));
    let list = state.db.analyses_for_run(id).map_err(db_err)?;
    let chosen = match pick {
        Some(aid) => Some(list.into_iter().find(|a| a.id == aid).ok_or_else(|| {
            AppError::NotFound(format!("analysis {aid} does not belong to run {id}"))
        })?),
        None => list.into_iter().next(),
    };
    let (stored, summary, analyzed_now) = match chosen {
        Some(a) => {
            let json = state
                .db
                .analysis_summary(a.id)
                .map_err(db_err)?
                .ok_or_else(|| AppError::NotFound(format!("analysis {} not found", a.id)))?;
            let v = serde_json::from_str(&json)
                .map_err(|e| AppError::Internal(format!("stored analysis is not JSON: {e}")))?;
            (a, v, false)
        }
        None => {
            let capture = run_capture(&rs, &state.cfg.captures_dir());
            let Some(capture) = capture.filter(|_| analyze) else {
                return Err(AppError::Conflict(
                    "analysis_missing",
                    format!(
                        "run {id} has no stored analysis{}",
                        if analyze {
                            " and no capture to analyse"
                        } else {
                            " (on-demand analysis disabled by analyze=false)"
                        }
                    ),
                )
                .with("run_id", id.into())
                .with(
                    "has_capture",
                    rs.capture_file.as_ref().is_some_and(|p| p.is_file()).into(),
                ));
            };
            check_analyzable(&rs)?;
            let _permit = state
                .heavy
                .clone()
                .try_acquire_owned()
                .map_err(|_| busy())?;
            let (a, report) =
                analyze_and_store(state, rs.clone(), capture, AnalysisSource::OnDemand).await?;
            let (summary, _) = report.split();
            let v = serde_json::to_value(&summary)
                .map_err(|e| AppError::Internal(format!("serialize analysis: {e}")))?;
            (a, v, true)
        }
    };
    Ok(Loaded {
        info: SideInfo {
            run_id: id,
            status: rs.status,
            pcap_id: rs.pcap_id.clone(),
            role: rs.role,
            started_at: rs.started_at,
            analysis_id: stored.id,
            analysis_source: stored.source,
            analyzed_now,
        },
        summary,
        bench: rs.benchmark,
    })
}

pub(crate) async fn api_run_compare(
    State(state): State<AppState>,
    ApiPath((a, b)): ApiPath<(u64, u64)>,
    ApiQuery(q): ApiQuery<CompareQuery>,
) -> Result<Json<CompareResp>, AppError> {
    let thresholds = q.thresholds();
    thresholds
        .validate()
        .map_err(|e| AppError::BadRequest(e).code("invalid_query"))?;
    let analyze = q.analyze.unwrap_or(true);
    // Rule out unknown, running and raw runs before analysing anything.
    let (ra, rb) = (comparable_run(&state, a)?, comparable_run(&state, b)?);
    let la = load_side(&state, ra, q.analysis_a, analyze).await?;
    let lb = load_side(&state, rb, q.analysis_b, analyze).await?;
    let mut warnings = Vec::new();
    if a == b {
        warnings.push("comparing a run with itself".to_string());
    }
    if la.info.pcap_id != lb.info.pcap_id {
        warnings.push(format!(
            "the runs replayed different pcaps ({} vs {}); RTU sets may differ",
            la.info.pcap_id.as_deref().unwrap_or("?"),
            lb.info.pcap_id.as_deref().unwrap_or("?")
        ));
    }
    if la.info.role != lb.info.role {
        warnings.push(format!(
            "the runs used different roles ({} vs {})",
            la.info.role, lb.info.role
        ));
    }
    let comparison = compare(
        &Side {
            summary: &la.summary,
            bench: la.bench.as_ref(),
        },
        &Side {
            summary: &lb.summary,
            bench: lb.bench.as_ref(),
        },
        &thresholds,
    );
    Ok(Json(CompareResp {
        a: la.info,
        b: lb.info,
        comparison,
        warnings,
    }))
}
