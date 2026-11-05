//! Post-run fidelity analysis upload endpoint.
//!
//! `POST /api/analyze[?run_id=N]` with a multipart body: `file` (the
//! captured pcap), optional `mode` (`generic`/`correct`), `run_id` and
//! `cp56_tolerance_ms`. The upload is streamed into a private temp file
//! under `<state>/tmp` (0700 dir, random O_EXCL name) that is removed
//! when the request ends, on success and on error (F051).

use axum::extract::{Multipart, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::analysis::{self, analyze, AnalysisMode, RoleHint, DEFAULT_CP56_TOLERANCE_MS};
use crate::dto::*;
use crate::error::{ApiQuery, AppError, LockExt};
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
    if matches!(rs.status, RunStatus::Failed) {
        warnings.push(format!(
            "run #{} failed{}; the comparison may be meaningless",
            rs.id,
            rs.error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        ));
    }
    let sent = rs
        .benchmark
        .as_ref()
        .map(|b| b.total_messages_sent)
        .unwrap_or(rs.sent);
    if sent == 0 {
        warnings.push(format!(
            "run #{} sent no messages; there is nothing to compare",
            rs.id
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
    let tmp_path = tmp.path().to_path_buf();
    let report = tokio::task::spawn_blocking({
        let original_pcap = rs.pcap.clone();
        let proto_config = rs.proto_config.clone();
        let run_id = rs.id;
        let target_port = rs.target_port;
        move || {
            analyze(
                replayer.as_ref(),
                &original_pcap,
                &tmp_path,
                run_id,
                target_port,
                role_hint,
                mode,
                proto_config,
                cp56_tolerance_ms,
            )
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("analyze task: {e}")))?
    .map_err(|e| AppError::BadRequest(format!("analyze run {}: {e:#}", rs.id)))?;
    // `tmp` drops here (and on every early return above), removing the
    // uploaded capture.
    drop(tmp);
    Ok(Json(AnalyzeResponse {
        report,
        run_selection: selection,
        warnings,
    }))
}
