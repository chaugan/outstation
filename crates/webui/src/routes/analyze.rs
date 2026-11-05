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

use crate::analysis::{self, analyze, AnalysisMode, RoleHint, DEFAULT_CP56_TOLERANCE_MS};
use crate::db::StoredAnalysis;
use crate::dto::*;
use crate::error::{ApiPath, ApiQuery, AppError, LockExt};
use crate::routes::library::{
    check_free_space, declared_length, multipart_error, stream_field_to_file,
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
    let mut cp56_tolerance_ms: f64 = DEFAULT_CP56_TOLERANCE_MS;
    while let Some(mut field) = mp.next_field().await.map_err(multipart_error)? {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        match name.as_str() {
            "file" => {
                let std_file = tmp
                    .reopen()
                    .map_err(|e| AppError::Internal(format!("open temp file: {e}")))?;
                let mut f = tokio::fs::File::from_std(std_file);
                size = stream_field_to_file(&mut field, &mut f, state.cfg.max_upload_bytes).await?;
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
                if !(v.is_finite() && v >= 0.0) {
                    return Err(AppError::BadRequest("cp56_tolerance_ms must be >= 0"));
                }
                cp56_tolerance_ms = v;
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
    if rs.mode != "benchmark" {
        return Err(AppError::BadRequest(
            "analysis currently targets benchmark runs only",
        ));
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

    let role_hint = match rs.role {
        "slave" => RoleHint::Slave,
        _ => RoleHint::Master,
    };
    let replayer = proto_registry::lookup(&rs.proto)
        .ok_or_else(|| AppError::BadRequest(format!("unknown protocol: {}", rs.proto)))?;
    let run_info = run_info_of(&rs);
    let tmp_path = tmp.path().to_path_buf();
    let report = tokio::task::spawn_blocking({
        let original_pcap = rs.pcap.clone();
        let proto_config = rs.proto_config.clone();
        let run_id = rs.id;
        let target_port = rs.target_port;
        move || {
            analyze(
                replayer.as_ref(),
                &analysis::AnalyzeRequest {
                    original_pcap_path: &original_pcap,
                    captured_pcap_path: &tmp_path,
                    run_id,
                    target_port,
                    role: role_hint,
                    mode,
                    proto_config,
                    cp56_tolerance_ms,
                    run: run_info,
                },
            )
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("analyze task: {e}")))?
    .map_err(|e| AppError::BadRequest(format!("analyze run {}: {e:#}", rs.id)))?;
    if let Some(w) = &report.run_warning {
        warnings.push(format!("run #{}: {w}", rs.id));
    }
    let analysis_id = match persist(&state, report.clone()).await {
        Ok(id) => Some(id),
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

/// Run facts the analysis judges against (F060, F062, F093).
fn run_info_of(rs: &RunState) -> analysis::RunInfo {
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
        // Not persisted on RunState yet (T08 stores the full request).
        loop_within_session: None,
        paced_speed: None,
        source_port: None,
    }
}

/// Store the bounded summary and per-endpoint details.
async fn persist(state: &AppState, report: analysis::AnalysisReport) -> anyhow::Result<u64> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let run_id = report.run_id;
        let (summary, details) = report.split();
        let summary_json = serde_json::to_string(&summary)?;
        let details: Vec<(String, String)> = details
            .into_iter()
            .map(|(ep, d)| Ok((ep, serde_json::to_string(&d)?)))
            .collect::<anyhow::Result<_>>()?;
        db.insert_analysis(
            run_id,
            summary.verdict,
            summary.score_pct,
            &summary_json,
            &details,
        )
    })
    .await?
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
}

impl From<StoredAnalysis> for StoredAnalysisJson {
    fn from(a: StoredAnalysis) -> Self {
        Self {
            id: a.id,
            run_id: a.run_id,
            created_at: a.created_at,
            verdict: a.verdict,
            score_pct: a.score_pct,
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
