//! Post-run fidelity analysis upload endpoint.
//!
//! `POST /api/analyze[?run_id=N]` with a multipart body: `file` (the
//! captured pcap), optional `mode` (`generic`/`correct`), `run_id` and
//! `cp56_tolerance_ms`. The upload is streamed into a private temp file
//! under `<state>/tmp` (0700 dir, random O_EXCL name) that is removed
//! when the request ends, on success and on error (F051).
//!
//! Every analysis is persisted (F067): the bounded summary in
//! `analyses`, each endpoint's bounded detail in `analysis_details`.
//! `GET /api/runs/:id/analyses` lists a run's analyses,
//! `GET /api/analyses/:id` returns a summary and
//! `GET /api/analyses/:id/endpoints/:ip` returns one endpoint's detail,
//! so the UI can fetch per-RTU drill-downs lazily.

use axum::extract::{Multipart, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use std::sync::atomic::Ordering;

use crate::analysis::{self, AnalysisMode};
use crate::analysis_run::{analyze_run, note_analysis, store_blocking};
use crate::db::StoredAnalysis;
use crate::dto::*;
use crate::error::{ApiPath, ApiQuery, AppError, LockExt};
use crate::metrics::AnalysisSource;
use crate::routes::library::{
    check_free_space, declared_length, multipart_error, stream_field_to_file, UploadLimits,
};
use crate::routes::runs::busy;
use crate::state::*;

#[derive(Deserialize, Default)]
pub(crate) struct AnalyzeQuery {
    #[serde(default)]
    run_id: Option<u64>,
}

/// Analysis report plus how the run was chosen and any warnings.
#[derive(Serialize)]
pub(crate) struct AnalyzeResponse {
    #[serde(flatten)]
    report: analysis::AnalysisReport,
    /// `"explicit"` when the caller named the run, `"latest"` when the
    /// newest finished benchmark run was picked.
    run_selection: &'static str,
    warnings: Vec<String>,
    /// Id of the stored analysis (`GET /api/analyses/:id`); `None` if
    /// persisting failed (see `warnings`).
    analysis_id: Option<u64>,
}

fn parse_run_id(s: &str) -> Result<u64, AppError> {
    s.trim()
        .parse()
        .map_err(|_| AppError::BadRequest(format!("run_id {s:?} is not a run id")))
}

pub(crate) async fn api_analyze(
    State(state): State<AppState>,
    ApiQuery(q): ApiQuery<AnalyzeQuery>,
    headers: HeaderMap,
    mut mp: Multipart,
) -> Result<Json<AnalyzeResponse>, AppError> {
    let _permit = state
        .heavy
        .clone()
        .try_acquire_owned()
        .map_err(|_| busy())?;
    check_free_space(&state, declared_length(&headers))?;

    let tmp_dir = state.cfg.tmp_dir();
    crate::library::prepare_private_dir(&tmp_dir)
        .map_err(|e| AppError::Internal(format!("prepare tmp dir: {e:#}")))?;
    // NamedTempFile: random name, O_EXCL, deleted on drop.
    let tmp = tempfile::Builder::new()
        .prefix("analyze_")
        .suffix(".pcap")
        .tempfile_in(&tmp_dir)
        .map_err(|e| AppError::Internal(format!("create temp file: {e}")))?;

    let mut got_file = false;
    let mut size: u64 = 0;
    let mut mode: AnalysisMode = AnalysisMode::Generic;
    let mut field_run_id: Option<u64> = None;
    let mut cp56_tolerance_ms: f64 = state.cfg.cp56_tolerance_ms;
    while let Some(mut field) = mp.next_field().await.map_err(multipart_error)? {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        match name.as_str() {
            "file" => {
                let std_file = tmp
                    .reopen()
                    .map_err(|e| AppError::Internal(format!("open temp file: {e}")))?;
                let mut f = tokio::fs::File::from_std(std_file);
                let mut limits = UploadLimits::new(&state);
                size = stream_field_to_file(&mut field, &mut f, &mut limits).await?;
                got_file = true;
            }
            "mode" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read mode: {e}")))?;
                mode = match s.trim().to_ascii_lowercase().as_str() {
                    "correct" => AnalysisMode::Correct,
                    "generic" | "" => AnalysisMode::Generic,
                    other => {
                        return Err(AppError::BadRequest(format!(
                            "mode must be generic or correct, got {other:?}"
                        )))
                    }
                };
            }
            "run_id" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read run_id: {e}")))?;
                if !s.trim().is_empty() {
                    field_run_id = Some(parse_run_id(&s)?);
                }
            }
            "cp56_tolerance_ms" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read cp56 tol: {e}")))?;
                let v: f64 = s.trim().parse().map_err(|_| {
                    AppError::BadRequest(format!("cp56_tolerance_ms {s:?} is not a number"))
                })?;
                cp56_tolerance_ms =
                    analysis::check_cp56_tolerance(v).map_err(AppError::BadRequest)?;
            }
            _ => {}
        }
    }
    if !got_file {
        return Err(AppError::BadRequest(
            "missing 'file' part in multipart body",
        ));
    }
    if size == 0 {
        return Err(AppError::BadRequest("captured pcap is empty"));
    }
    let run_id = match (q.run_id, field_run_id) {
        (Some(a), Some(b)) if a != b => {
            return Err(AppError::BadRequest(format!(
                "run_id given twice with different values ({a} in the query, {b} in the form)"
            )))
        }
        (a, b) => a.or(b),
    };

    let mut warnings = Vec::new();
    let (rs, selection) = match run_id {
        Some(id) => {
            let e = state
                .get_run(id)
                .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?;
            let rs = e.lock_safe().clone();
            (rs, "explicit")
        }
        None => {
            // Newest finished benchmark run.
            let mut v: Vec<RunState> = state
                .all_runs()
                .into_iter()
                .filter_map(|e| {
                    let rs = e.lock_safe();
                    (rs.status.is_terminal() && rs.mode == "benchmark").then(|| rs.clone())
                })
                .collect();
            v.sort_by_key(|r| std::cmp::Reverse(r.id));
            let rs = v.into_iter().next().ok_or_else(|| {
                AppError::NotFound("no finished benchmark run to analyze against")
            })?;
            warnings.push(format!(
                "no run_id given; compared against the newest finished benchmark run #{}",
                rs.id
            ));
            (rs, "latest")
        }
    };
    crate::analysis_run::check_analyzable(&rs)?;
    let tmp_path = tmp.path().to_path_buf();
    let m = state.metrics.clone();
    m.analyses_running.fetch_add(1, Ordering::Relaxed);
    let res = tokio::task::spawn_blocking({
        let rs = rs.clone();
        move || analyze_run(&rs, &tmp_path, mode, cp56_tolerance_ms)
    })
    .await;
    m.analyses_running.fetch_sub(1, Ordering::Relaxed);
    let report = res
        .map_err(|e| AppError::Internal(format!("analyze task: {e}")))
        .and_then(|r| r.map_err(|e| AppError::BadRequest(format!("analyze run {}: {e:#}", rs.id))));
    m.count_analysis(AnalysisSource::Manual, report.is_ok());
    let report = report?;
    if let Some(w) = &report.run_warning {
        warnings.push(format!("run #{}: {w}", rs.id));
    }
    let analysis_id = match persist(&state, report.clone()).await {
        Ok(a) => {
            note_analysis(&state, &a);
            Some(a.id)
        }
        Err(e) => {
            warnings.push(format!("analysis not saved: {e:#}"));
            None
        }
    };
    // `tmp` drops here (and on every early return above), removing the
    // uploaded capture.
    drop(tmp);
    Ok(Json(AnalyzeResponse {
        report,
        run_selection: selection,
        warnings,
        analysis_id,
    }))
}

/// Store the bounded summary and per-endpoint details.
async fn persist(
    state: &AppState,
    report: analysis::AnalysisReport,
) -> anyhow::Result<StoredAnalysis> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || store_blocking(&db, report, AnalysisSource::Manual)).await?
}

fn parse_stored(json: Option<String>, what: &str) -> Result<Json<serde_json::Value>, AppError> {
    let json = json.ok_or_else(|| AppError::NotFound(format!("{what} not found")))?;
    serde_json::from_str(&json)
        .map(Json)
        .map_err(|e| AppError::Internal(format!("stored {what} is not JSON: {e}")))
}

/// `GET /api/runs/:id/analyses`: stored analyses of a run, newest first.
pub(crate) async fn api_run_analyses(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Json<Vec<StoredAnalysisJson>>, AppError> {
    let rows = state
        .db
        .analyses_for_run(id)
        .map_err(|e| AppError::Internal(format!("list analyses: {e:#}")))?;
    Ok(Json(
        rows.into_iter().map(StoredAnalysisJson::from).collect(),
    ))
}

#[derive(Serialize)]
pub(crate) struct StoredAnalysisJson {
    id: u64,
    run_id: u64,
    created_at: u64,
    verdict: String,
    score_pct: f64,
    /// `manual`, `auto` or `on_demand`.
    source: String,
}

impl From<StoredAnalysis> for StoredAnalysisJson {
    fn from(a: StoredAnalysis) -> Self {
        Self {
            id: a.id,
            run_id: a.run_id,
            created_at: a.created_at,
            verdict: a.verdict,
            score_pct: a.score_pct,
            source: a.source,
        }
    }
}

/// `GET /api/analyses/:id`: the stored summary (no per-endpoint detail).
pub(crate) async fn api_analysis_summary(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let json = state
        .db
        .analysis_summary(id)
        .map_err(|e| AppError::Internal(format!("read analysis: {e:#}")))?;
    parse_stored(json, &format!("analysis {id}"))
}

/// `GET /api/analyses/:id/endpoints/:ip`: one endpoint's detail.
pub(crate) async fn api_analysis_detail(
    State(state): State<AppState>,
    ApiPath((id, endpoint)): ApiPath<(u64, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let json = state
        .db
        .analysis_detail(id, &endpoint)
        .map_err(|e| AppError::Internal(format!("read analysis detail: {e:#}")))?;
    parse_stored(json, &format!("endpoint {endpoint} of analysis {id}"))
}

#[derive(Serialize)]
pub(crate) struct RunAnalyzeResp {
    analysis_id: u64,
    run_id: u64,
    verdict: String,
    score_pct: f64,
    source: String,
    created_at: u64,
}

/// `POST /api/runs/:id/analyze`: analyse a finished benchmark run's own
/// capture now and store it (source `on_demand`). Mutating, so it sits
/// behind the same-origin guard and the heavy-work limit (429 `busy`).
/// 409 `capture_missing` when the run has no capture on disk.
#[derive(Deserialize, Default)]
pub(crate) struct RunAnalyzeQuery {
    /// CP56Time2a drift tolerance for this analysis; default the
    /// server's `--cp56-tolerance-ms` (F066).
    #[serde(default)]
    cp56_tolerance_ms: Option<f64>,
}

pub(crate) async fn api_run_analyze(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
    ApiQuery(q): ApiQuery<RunAnalyzeQuery>,
) -> Result<Json<RunAnalyzeResp>, AppError> {
    let tol =
        analysis::check_cp56_tolerance(q.cp56_tolerance_ms.unwrap_or(state.cfg.cp56_tolerance_ms))
            .map_err(AppError::BadRequest)?;
    let rs = state
        .get_run(id)
        .ok_or_else(|| AppError::NotFound(format!("run {id} not found")))?
        .lock_safe()
        .clone();
    crate::analysis_run::check_analyzable(&rs)?;
    let capture =
        crate::analysis_run::run_capture(&rs, &state.cfg.captures_dir()).ok_or_else(|| {
            AppError::Conflict(
                "capture_missing",
                format!("run {id} has no capture to analyse (never written or evicted)"),
            )
        })?;
    if let Some(why) = crate::analysis_run::capture_problem(&rs, &capture) {
        return Err(AppError::Conflict(
            "capture_unavailable",
            format!("capture unavailable: {why}"),
        ));
    }
    let _permit = state
        .heavy
        .clone()
        .try_acquire_owned()
        .map_err(|_| busy())?;
    let (a, _) =
        crate::analysis_run::analyze_and_store(&state, rs, capture, AnalysisSource::OnDemand, tol)
            .await?;
    Ok(Json(RunAnalyzeResp {
        analysis_id: a.id,
        run_id: a.run_id,
        verdict: a.verdict,
        score_pct: a.score_pct,
        source: a.source,
        created_at: a.created_at,
    }))
}
