//! Post-run fidelity analysis upload endpoint.

use axum::extract::{Multipart, State};
use axum::Json;

use crate::analysis;
use crate::analysis::{analyze, AnalysisMode, RoleHint, DEFAULT_CP56_TOLERANCE_MS};
use crate::dto::*;
use crate::error::AppError;
use crate::state::*;

/// Look up `ip` in the host's address table. Returns the owning
/// interface name if found.
pub(crate) async fn api_analyze(
    State(state): State<AppState>,
    mut mp: Multipart,
) -> Result<Json<analysis::AnalysisReport>, AppError> {
    let mut captured_bytes: Option<Vec<u8>> = None;
    let mut mode: AnalysisMode = AnalysisMode::Generic;
    let mut run_id_opt: Option<u64> = None;
    let mut cp56_tolerance_ms: f64 = DEFAULT_CP56_TOLERANCE_MS;
    while let Some(mut field) = mp
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        match name.as_str() {
            "file" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read chunk: {e}")))?
                {
                    buf.extend_from_slice(&chunk);
                }
                captured_bytes = Some(buf);
            }
            "mode" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read mode: {e}")))?;
                mode = if s.trim().eq_ignore_ascii_case("correct") {
                    AnalysisMode::Correct
                } else {
                    AnalysisMode::Generic
                };
            }
            "run_id" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read run_id: {e}")))?;
                run_id_opt = s.trim().parse().ok();
            }
            "cp56_tolerance_ms" => {
                let s = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read cp56 tol: {e}")))?;
                if let Ok(v) = s.trim().parse::<f64>() {
                    if v >= 0.0 {
                        cp56_tolerance_ms = v;
                    }
                }
            }
            _ => {}
        }
    }

    let bytes = captured_bytes
        .ok_or_else(|| AppError::BadRequest("missing 'file' part in multipart body".into()))?;
    if bytes.is_empty() {
        return Err(AppError::BadRequest("captured pcap is empty".into()));
    }

    // Pick the target run: explicit id, else most recent completed/stopped/failed run.
    let picked = {
        let map = state.runs.lock().unwrap();
        if let Some(id) = run_id_opt {
            map.get(&id).cloned()
        } else {
            let mut vs: Vec<RunState> = map
                .values()
                .filter(|r| !matches!(r.status, RunStatus::Running))
                .cloned()
                .collect();
            vs.sort_by_key(|r| std::cmp::Reverse(r.id));
            vs.into_iter().next()
        }
    };
    let rs =
        picked.ok_or_else(|| AppError::NotFound("no completed run to analyze against".into()))?;

    if rs.mode != "benchmark" {
        return Err(AppError::BadRequest(
            "analysis currently targets benchmark runs only".into(),
        ));
    }

    let role_hint = match rs.role {
        "slave" => RoleHint::Slave,
        _ => RoleHint::Master,
    };
    let target_port = rs.target_port;

    // Persist the captured pcap to a temp file so pcapload can mmap
    // it the way it wants. Dropped at end of scope.
    let tmp_dir = std::env::temp_dir().join("outstation-analysis");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| AppError::Internal(format!("create tmp: {e}")))?;
    let tmp_path = tmp_dir.join(format!("capt_{}.pcap", rs.id));
    std::fs::write(&tmp_path, &bytes).map_err(|e| AppError::Internal(format!("write tmp: {e}")))?;

    // Look up the replayer for this run's protocol. The analyzer
    // dispatches CP56 / ASDU / handshake logic through the replayer's
    // `analyze_flow` method, so each protocol parses whatever it needs
    // out of `rs.proto_config` itself.
    let replayer = proto_registry::lookup(&rs.proto)
        .ok_or_else(|| AppError::BadRequest(format!("unknown protocol: {}", rs.proto)))?;
    let proto_config = rs.proto_config.clone();
    let report = tokio::task::spawn_blocking({
        let original_pcap = rs.pcap.clone();
        let tmp_path = tmp_path.clone();
        let run_id = rs.id;
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
    .map_err(|e| AppError::BadRequest(format!("analyze: {e}")))?;

    // Leave the file behind for now; /tmp gets swept by the OS.
    Ok(Json(report))
}
