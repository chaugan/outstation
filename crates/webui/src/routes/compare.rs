//! `GET /api/runs/:a/compare/:b` (T10): compare two finished benchmark
//! runs. Run `a` is the baseline.
//!
//! Query parameters (all optional):
//! * thresholds, see [`Thresholds`]: `score_drop`, `delivered_drop`,
//!   `p50_increase_pct`, `p99_increase_pct`, `latency_min_us`,
//!   `throughput_drop_pct`;
//! * `analysis_a`, `analysis_b`: compare these stored analyses instead
//!   of each run's newest one;
//!
//! Strictly read-only: GET is not covered by the same-origin guard, so
//! it never analyses. A run without a stored analysis gives 409
//! `analysis_missing` (`run_id`, `has_capture`); the client then calls
//! `POST /api/runs/:id/analyze` and retries.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::analysis_run::run_capture;
use crate::compare::{compare, Comparison, Side, Thresholds};
use crate::dto::*;
use crate::error::{ApiPath, ApiQuery, AppError, LockExt};
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

fn load_side(state: &AppState, rs: RunState, pick: Option<u64>) -> Result<Loaded, AppError> {
    let id = rs.id;
    let db_err = |e: anyhow::Error| AppError::Internal(format!("read analyses: {e:#}"));
    let list = state.db.analyses_for_run(id).map_err(db_err)?;
    let chosen = match pick {
        Some(aid) => Some(list.into_iter().find(|a| a.id == aid).ok_or_else(|| {
            AppError::NotFound(format!("analysis {aid} does not belong to run {id}"))
        })?),
        None => list.into_iter().next(),
    };
    let Some(stored) = chosen else {
        // GET stays read-only (it is not covered by the same-origin
        // guard): analysing is POST /api/runs/:id/analyze.
        let has_capture = run_capture(&rs, &state.cfg.captures_dir()).is_some();
        return Err(AppError::Conflict(
            "analysis_missing",
            format!(
                "run {id} has no stored analysis{}",
                if has_capture {
                    format!("; POST /api/runs/{id}/analyze, then retry")
                } else {
                    " and no capture to analyse".to_string()
                }
            ),
        )
        .with("run_id", id.into())
        .with("has_capture", has_capture.into()));
    };
    let json = state
        .db
        .analysis_summary(stored.id)
        .map_err(db_err)?
        .ok_or_else(|| AppError::NotFound(format!("analysis {} not found", stored.id)))?;
    let summary = serde_json::from_str(&json)
        .map_err(|e| AppError::Internal(format!("stored analysis is not JSON: {e}")))?;
    Ok(Loaded {
        info: SideInfo {
            run_id: id,
            status: rs.status,
            pcap_id: rs.pcap_id.clone(),
            role: rs.role,
            started_at: rs.started_at,
            analysis_id: stored.id,
            analysis_source: stored.source,
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
    // Rule out unknown, running and raw runs before analysing anything.
    let (ra, rb) = (comparable_run(&state, a)?, comparable_run(&state, b)?);
    let la = load_side(&state, ra, q.analysis_a)?;
    let lb = load_side(&state, rb, q.analysis_b)?;
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
