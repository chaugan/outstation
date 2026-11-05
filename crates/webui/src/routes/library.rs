//! Pcap library HTTP endpoints.

use std::path::Path as StdPath;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::AppError;
use crate::library::*;
use crate::state::*;

#[allow(dead_code)]
pub(crate) async fn api_library_list(State(state): State<AppState>) -> Json<Vec<LibraryEntry>> {
    let dir: &StdPath = state.library_dir.as_ref();
    let mut out: Vec<LibraryEntry> = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Json(out);
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("pcap") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(e) = load_library_entry(dir, stem) {
            out.push(e);
        }
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.uploaded_at_ms));
    Json(out)
}

pub(crate) async fn api_library_upload(
    State(state): State<AppState>,
    mut mp: Multipart,
) -> Result<Json<LibraryEntry>, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let mut field = mp
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
        .ok_or_else(|| AppError::BadRequest("empty upload".into()))?;

    let original_name = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "upload.pcap".to_string());

    // Stream the field into a temp file within the library dir so it's on
    // the same filesystem for atomic rename.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let id = format!("pcr_{nanos}");
    let tmp_path = dir.join(format!(".{id}.part"));
    let final_path = dir.join(format!("{id}.pcap"));

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(|e| AppError::Internal(format!("open tmp: {e}")))?;
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| AppError::BadRequest(format!("read chunk: {e}")))?
        {
            f.write_all(&chunk)
                .map_err(|e| AppError::Internal(format!("write: {e}")))?;
        }
        f.sync_all().ok();
    }
    std::fs::rename(&tmp_path, &final_path)
        .map_err(|e| AppError::Internal(format!("rename: {e}")))?;

    // Fast validation: check the magic bytes only. Multi-GB pcaps
    // would otherwise block the HTTP handler for tens of seconds
    // while we walked every packet. Full parse runs in a background
    // thread below.
    if let Err(e) = pcapload::validate(&final_path) {
        let _ = std::fs::remove_file(&final_path);
        return Err(AppError::BadRequest(format!("not a pcap: {e}")));
    }

    let size_bytes = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
    let uploaded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Initial sidecar: viability=None means "still analyzing". The
    // background thread below will rewrite the sidecar with full
    // metadata once the parse completes. The library list endpoint
    // surfaces this transient state to the UI.
    let pending = LibraryEntry {
        id: id.clone(),
        name: original_name.clone(),
        uploaded_at_ms,
        size_bytes,
        packets: 0,
        ip_sources: 0,
        non_ip_sources: 0,
        tcp_flows: 0,
        duration_ms: 0.0,
        pcap_start_unix_ms: None,
        pcap_end_unix_ms: None,
        mac_collisions: 0,
        viability: None,
    };
    save_library_entry(dir, &pending).map_err(|e| AppError::Internal(format!("sidecar: {e}")))?;
    info!(id = %pending.id, name = %pending.name, size_bytes, "pcap uploaded, analysis spawning");

    // Spawn the analyzer. Cheap pcaps finish before the user
    // notices; multi-GB pcaps take seconds-to-minutes and the UI's
    // library poll picks up the populated sidecar when it's done.
    let dir_owned = dir.to_path_buf();
    let final_path_owned = final_path.clone();
    let id_for_thread = id.clone();
    let original_name_for_thread = original_name.clone();
    std::thread::Builder::new()
        .name(format!("library-analyze-{id}"))
        .spawn(move || {
            let qi = quick_inspect(&final_path_owned);
            if qi.packets == 0 {
                // Parse failed after passing the magic check — rare
                // (truncated body, exotic linktype). Mark the sidecar
                // with a sentinel and leave it for the user to delete.
                warn!(id = %id_for_thread, "background parse failed; leaving stub sidecar");
                let stub = LibraryEntry {
                    id: id_for_thread.clone(),
                    name: format!("{original_name_for_thread} (parse failed)"),
                    uploaded_at_ms,
                    size_bytes,
                    packets: 0,
                    ip_sources: 0,
                    non_ip_sources: 0,
                    tcp_flows: 0,
                    duration_ms: 0.0,
                    pcap_start_unix_ms: None,
                    pcap_end_unix_ms: None,
                    mac_collisions: 0,
                    viability: Some(Viability {
                        client_payload_bytes: 0,
                        server_payload_bytes: 0,
                        sessions_master_mode: 0,
                        sessions_slave_mode: 0,
                        estimated_peak_mb: 0,
                        verdict: "not_recommended".into(),
                        verdict_reason: "background parse failed — file may be truncated or use an unsupported link type".into(),
                        notes: vec![],
                        slave_rtus: vec![],
                        master_clients: vec![],
                    }),
                };
                let _ = save_library_entry(&dir_owned, &stub);
                return;
            }
            let final_entry = LibraryEntry {
                id: id_for_thread.clone(),
                name: original_name_for_thread,
                uploaded_at_ms,
                size_bytes,
                packets: qi.packets,
                ip_sources: qi.ip_sources,
                non_ip_sources: qi.non_ip_sources,
                tcp_flows: qi.tcp_flows,
                duration_ms: qi.duration_ms,
                pcap_start_unix_ms: qi.pcap_start_unix_ms,
                pcap_end_unix_ms: qi.pcap_end_unix_ms,
                mac_collisions: qi.mac_collisions,
                viability: qi.viability,
            };
            if let Err(e) = save_library_entry(&dir_owned, &final_entry) {
                warn!(id = %id_for_thread, error = %e, "sidecar rewrite failed");
            } else {
                info!(id = %id_for_thread, packets = qi.packets, "background analysis complete");
            }
        })
        .map_err(|e| AppError::Internal(format!("spawn analyzer: {e}")))?;

    Ok(Json(pending))
}

pub(crate) async fn api_library_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if !library_entry_id_valid(&id) {
        return Err(AppError::BadRequest(format!("invalid id: {id}")));
    }
    let dir: &StdPath = state.library_dir.as_ref();
    let pcap_p = dir.join(format!("{id}.pcap"));
    let sidecar_p = library_sidecar_path(dir, &id);
    if !pcap_p.exists() && !sidecar_p.exists() {
        return Err(AppError::NotFound(format!("pcap id not found: {id}")));
    }
    let _ = std::fs::remove_file(&pcap_p);
    let _ = std::fs::remove_file(&sidecar_p);
    info!(%id, "pcap deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct RenameReq {
    pub(crate) name: String,
}

pub(crate) async fn api_library_rename(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RenameReq>,
) -> Result<Json<LibraryEntry>, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let mut entry = load_library_entry(dir, &id)
        .ok_or_else(|| AppError::NotFound(format!("pcap id not found: {id}")))?;
    let trimmed = req.name.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(AppError::BadRequest("name must be 1..256 chars".into()));
    }
    entry.name = trimmed.to_string();
    save_library_entry(dir, &entry).map_err(|e| AppError::Internal(format!("sidecar: {e}")))?;
    Ok(Json(entry))
}

pub(crate) async fn api_library_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let path = library_pcap_path(dir, &id)?;
    let entry = load_library_entry(dir, &id);
    let bytes =
        std::fs::read(&path).map_err(|e| AppError::Internal(format!("read {path:?}: {e}")))?;
    let fname = entry
        .map(|e| e.name)
        .unwrap_or_else(|| format!("{id}.pcap"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.tcpdump.pcap"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{fname}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    Ok((headers, bytes).into_response())
}
