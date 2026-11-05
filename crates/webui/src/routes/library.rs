//! Pcap library HTTP endpoints.

use std::path::{Path as StdPath, PathBuf};

use axum::extract::{Multipart, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::{ApiJson, ApiPath, ApiQuery, AppError, LockExt};
use crate::library::*;
use crate::state::*;

fn list_entries(dir: &StdPath) -> Vec<LibraryEntry> {
    let mut out: Vec<LibraryEntry> = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
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
    out
}

pub(crate) async fn api_library_list(
    State(state): State<AppState>,
) -> Result<Json<Vec<LibraryEntry>>, AppError> {
    let dir: PathBuf = state.library_dir.as_ref().clone();
    let out = tokio::task::spawn_blocking(move || list_entries(&dir))
        .await
        .map_err(|e| AppError::Internal(format!("list task: {e}")))?;
    Ok(Json(out))
}

/// Refuse an upload when the state filesystem is short on space.
pub(crate) fn check_free_space(state: &AppState, incoming: u64) -> Result<(), AppError> {
    if let Some(free) = crate::sysinfo::free_bytes(&state.cfg.state_dir) {
        if free < state.cfg.min_free_bytes.saturating_add(incoming) {
            return Err(AppError::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "disk_full",
                format!(
                    "not enough free disk in {} ({free} bytes free, keeping {} in reserve)",
                    state.cfg.state_dir.display(),
                    state.cfg.min_free_bytes
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn declared_length(headers: &HeaderMap) -> u64 {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Map a multipart error, keeping its status (413 for the body limit).
pub(crate) fn multipart_error(e: axum::extract::multipart::MultipartError) -> AppError {
    let status = e.status();
    let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
        "too_large"
    } else {
        "upload_aborted"
    };
    AppError::new(status, code, format!("read upload: {e}"))
}

/// Byte limits one upload is streamed against (F051).
pub(crate) struct UploadLimits {
    /// The configured per-upload cap.
    max: u64,
    /// Bytes that may be written before free space in the state dir
    /// drops below the reserve, measured when the upload started.
    disk_budget: Option<u64>,
    /// Bytes left under the library quota, for library uploads.
    quota_left: Option<u64>,
    state_dir: PathBuf,
    min_free: u64,
}

/// Re-measure free space every this many bytes of an upload, so
/// concurrent writers (a run capture) are noticed too.
const FREE_RECHECK_BYTES: u64 = 16 * 1024 * 1024;

impl UploadLimits {
    pub(crate) fn new(state: &AppState) -> Self {
        let min_free = state.cfg.min_free_bytes;
        Self {
            max: state.cfg.max_upload_bytes,
            disk_budget: crate::sysinfo::free_bytes(&state.cfg.state_dir)
                .map(|f| f.saturating_sub(min_free)),
            quota_left: None,
            state_dir: state.cfg.state_dir.clone(),
            min_free,
        }
    }

    /// Also hold the upload to the library quota.
    pub(crate) fn with_library_quota(mut self, state: &AppState) -> Result<Self, AppError> {
        let quota = state.cfg.library_max_bytes;
        if quota > 0 {
            let used = library_bytes(&state.library_dir);
            if used >= quota {
                return Err(library_full(used, quota));
            }
            self.quota_left = Some(quota - used);
        }
        Ok(self)
    }

    fn check(&self, written: u64, recheck: bool) -> Result<(), AppError> {
        if written > self.max {
            return Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                format!("upload exceeds the {}-byte limit", self.max),
            ));
        }
        if let Some(left) = self.quota_left {
            if written > left {
                return Err(AppError::new(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "library_full",
                    format!(
                        "upload exceeds the library quota ({left} bytes left); \
                         delete pcaps from the library or raise --library-max-mb"
                    ),
                ));
            }
        }
        let low = self.disk_budget.is_some_and(|b| written > b)
            || (recheck
                && crate::sysinfo::free_bytes(&self.state_dir).is_some_and(|f| f < self.min_free));
        if low {
            return Err(AppError::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "disk_full",
                format!(
                    "upload stopped: free disk in {} would drop below the {}-byte reserve",
                    self.state_dir.display(),
                    self.min_free
                ),
            ));
        }
        Ok(())
    }
}

fn library_full(used: u64, quota: u64) -> AppError {
    AppError::new(
        StatusCode::INSUFFICIENT_STORAGE,
        "library_full",
        format!(
            "the library holds {used} bytes of its {quota}-byte quota; delete pcaps \
             or raise --library-max-mb"
        ),
    )
}

/// Total size of the library's pcaps and in-progress uploads.
pub(crate) fn library_bytes(dir: &StdPath) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.ends_with(".pcap") || n.ends_with(".part")
                })
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// Stream one multipart field into `file`, enforcing `limits` while
/// the bytes arrive: the size cap, the library quota and the free-disk
/// reserve, which a chunked upload without Content-Length would
/// otherwise only meet at the end (F051).
pub(crate) async fn stream_field_to_file(
    field: &mut axum::extract::multipart::Field<'_>,
    file: &mut tokio::fs::File,
    limits: &UploadLimits,
) -> Result<u64, AppError> {
    use tokio::io::AsyncWriteExt;
    let mut written: u64 = 0;
    let mut next_recheck = FREE_RECHECK_BYTES;
    while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
        written += chunk.len() as u64;
        let recheck = written >= next_recheck;
        if recheck {
            next_recheck = written + FREE_RECHECK_BYTES;
        }
        limits.check(written, recheck)?;
        file.write_all(&chunk).await.map_err(|e| {
            AppError::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "write_failed",
                format!("write upload: {e}"),
            )
        })?;
    }
    file.flush()
        .await
        .map_err(|e| AppError::Internal(format!("flush upload: {e}")))?;
    let _ = file.sync_all().await;
    Ok(written)
}

pub(crate) async fn api_library_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    mp: Multipart,
) -> Result<Json<LibraryEntry>, AppError> {
    let r = library_upload(&state, headers, mp).await;
    state.metrics.count_upload(r.is_ok());
    r
}

async fn library_upload(
    state: &AppState,
    headers: HeaderMap,
    mut mp: Multipart,
) -> Result<Json<LibraryEntry>, AppError> {
    let _permit = state
        .heavy
        .clone()
        .try_acquire_owned()
        .map_err(|_| crate::routes::runs::busy())?;
    check_free_space(state, declared_length(&headers))?;
    let limits = UploadLimits::new(state).with_library_quota(state)?;
    if let Some(left) = limits.quota_left {
        let declared = declared_length(&headers);
        if declared > left {
            return Err(library_full(
                state.cfg.library_max_bytes - left,
                state.cfg.library_max_bytes,
            ));
        }
    }
    let dir: &StdPath = state.library_dir.as_ref();
    let mut field = mp
        .next_field()
        .await
        .map_err(multipart_error)?
        .ok_or_else(|| AppError::BadRequest("empty upload"))?;

    let original_name = field
        .file_name()
        .map(|s| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect::<String>()
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "upload.pcap".to_string());

    // Stream into a hidden .part file in the library dir (same
    // filesystem, so the rename is atomic). The guard removes it on
    // every error path, including a client abort (F077, F091).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let id = format!("pcr_{nanos}");
    let tmp_path = dir.join(format!(".{id}.part"));
    let final_path = dir.join(format!("{id}.pcap"));
    let part = PartGuard::new(tmp_path.clone());
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .await
        .map_err(|e| AppError::Internal(format!("open tmp: {e}")))?;
    stream_field_to_file(&mut field, &mut f, &limits).await?;
    drop(f);

    // Fast validation: check the magic bytes only. Full parse runs in a
    // background thread below.
    let tp = tmp_path.clone();
    tokio::task::spawn_blocking(move || pcapload::validate(&tp))
        .await
        .map_err(|e| AppError::Internal(format!("validate task: {e}")))?
        .map_err(|e| AppError::BadRequest(format!("not a pcap: {e}")).code("not_a_pcap"))?;
    std::fs::rename(&tmp_path, &final_path)
        .map_err(|e| AppError::Internal(format!("rename: {e}")))?;
    part.keep();
    let final_guard = PartGuard::new(final_path.clone());

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
        load_error: None,
    };
    save_library_entry(dir, &pending).map_err(|e| AppError::Internal(format!("sidecar: {e}")))?;
    final_guard.keep();
    info!(id = %pending.id, name = %pending.name, size_bytes, "pcap uploaded, analysis spawning");

    // Spawn the analyzer. Cheap pcaps finish before the user
    // notices; multi-GB pcaps take seconds-to-minutes and the UI's
    // library poll picks up the populated sidecar when it's done.
    let dir_owned = dir.to_path_buf();
    let final_path_owned = final_path.clone();
    let pending_owned = pending.clone();
    std::thread::Builder::new()
        .name(format!("library-analyze-{id}"))
        .spawn(move || {
            let entry = finished_entry(&pending_owned, &final_path_owned);
            if let Err(e) = save_library_entry(&dir_owned, &entry) {
                warn!(id = %entry.id, error = %e, "sidecar rewrite failed");
            } else if entry.load_error.is_none() {
                info!(id = %entry.id, packets = entry.packets, "background analysis complete");
            }
        })
        .map_err(|e| AppError::Internal(format!("spawn analyzer: {e}")))?;

    Ok(Json(pending))
}

/// Runs whose source pcap is library entry `id`.
fn dependent_runs(state: &AppState, id: &str, pcap_path: &StdPath) -> Vec<u64> {
    let mut v: Vec<u64> = state
        .all_runs()
        .into_iter()
        .filter_map(|e| {
            let rs = e.lock_safe();
            (rs.pcap_id.as_deref() == Some(id) || rs.pcap == pcap_path).then_some(rs.id)
        })
        .collect();
    v.sort_unstable();
    v
}

#[derive(Deserialize, Default)]
pub(crate) struct DeleteQuery {
    #[serde(default)]
    force: Option<String>,
}

/// Delete a library pcap. If runs still reference it, answer 409 with
/// their ids unless `?force=1` (F101): their gap histograms and
/// fidelity analysis stop working once the source is gone.
pub(crate) async fn api_library_delete(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<DeleteQuery>,
) -> Result<StatusCode, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let pcap_p = contained_path(dir, &id, "pcap")?;
    let sidecar_p = contained_path(dir, &id, "json")?;
    if !pcap_p.exists() && !sidecar_p.exists() {
        return Err(AppError::NotFound(format!("pcap id not found: {id}")));
    }
    let force = matches!(q.force.as_deref(), Some("1" | "true" | "yes"));
    let deps = dependent_runs(&state, &id, &pcap_p);
    if !deps.is_empty() && !force {
        return Err(AppError::Conflict(
            "pcap_in_use",
            format!(
                "{} run(s) use this pcap; deleting it breaks their gap histograms and \
                 fidelity analysis. Repeat with ?force=1 to delete anyway.",
                deps.len()
            ),
        )
        .with("runs", serde_json::json!(deps)));
    }
    let _ = std::fs::remove_file(&pcap_p);
    let _ = std::fs::remove_file(&sidecar_p);
    info!(%id, forced = force, dependent_runs = deps.len(), "pcap deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct RenameReq {
    name: String,
}

pub(crate) async fn api_library_rename(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<RenameReq>,
) -> Result<Json<LibraryEntry>, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    // Validates the id and containment before touching the filesystem.
    contained_path(dir, &id, "json")?;
    let mut entry = load_library_entry(dir, &id)
        .ok_or_else(|| AppError::NotFound(format!("pcap id not found: {id}")))?;
    let trimmed = req.name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 256 || trimmed.chars().any(char::is_control)
    {
        return Err(AppError::BadRequest(
            "name must be 1..256 printable characters",
        ));
    }
    entry.id = id;
    entry.name = trimmed.to_string();
    save_library_entry(dir, &entry).map_err(|e| AppError::Internal(format!("sidecar: {e}")))?;
    Ok(Json(entry))
}

pub(crate) async fn api_library_download(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, AppError> {
    let dir: &StdPath = state.library_dir.as_ref();
    let path = library_pcap_path(dir, &id)?;
    let name = load_library_entry(dir, &id)
        .map(|e| e.name)
        .unwrap_or_else(|| format!("{id}.pcap"));
    crate::routes::stream_file(&path, &name).await
}
