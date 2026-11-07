//! Named run profiles (T08): stored run requests the UI can load into
//! the run form and the `outstation bench --profile` CLI can read.
//!
//! * `GET /api/profiles` → `[Profile]`, sorted by name.
//! * `POST /api/profiles` `{name, request}` → 201 `Profile`.
//! * `GET /api/profiles/:id` → `Profile`.
//! * `PUT /api/profiles/:id` `{name?, request?}` → `Profile`.
//! * `DELETE /api/profiles/:id` → 204.
//!
//! `Profile` = `{id, name, request, created_at, updated_at}`. The
//! request is validated like a `POST /api/run` body except that
//! `pcap_id` is optional (a profile may be pcap-agnostic), and is
//! stored in canonical form (defaults filled in, ignored fields
//! dropped). Name collisions give 409 `profile_exists`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::db::{ProfileWrite, StoredProfile};
use crate::error::{ApiJson, ApiPath, AppError};
use crate::runbuild;
use crate::state::AppState;

/// Longest accepted profile name, in characters.
const MAX_NAME_CHARS: usize = 100;

#[derive(Serialize)]
pub(crate) struct ProfileJson {
    id: u64,
    name: String,
    request: serde_json::Value,
    created_at: u64,
    updated_at: u64,
}

impl From<StoredProfile> for ProfileJson {
    fn from(p: StoredProfile) -> Self {
        Self {
            id: p.id,
            name: p.name,
            request: serde_json::from_str(&p.request_json).unwrap_or(serde_json::Value::Null),
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct ProfileBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    request: Option<serde_json::Value>,
}

fn invalid(msg: impl Into<String>) -> AppError {
    AppError::BadRequest(msg).code("invalid_request")
}

pub(crate) fn clean_name(name: &str) -> Result<String, AppError> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME_CHARS || n.chars().any(char::is_control) {
        return Err(invalid(format!(
            "profile name must be 1..={MAX_NAME_CHARS} characters without control characters"
        )));
    }
    Ok(n.to_string())
}

/// Validate a profile request and return its canonical JSON text.
pub(crate) fn canonical_request(v: serde_json::Value) -> Result<String, AppError> {
    if !v.is_object() {
        return Err(invalid("request must be a JSON object"));
    }
    let req = runbuild::from_json(v).map_err(AppError::from)?;
    runbuild::validate_settings(&req).map_err(AppError::from)?;
    Ok(runbuild::canonical_json(&req).to_string())
}

fn db_err(e: anyhow::Error) -> AppError {
    AppError::Internal(format!("profiles: {e:#}"))
}

fn write_result(w: ProfileWrite, name: Option<&str>, id: u64) -> Result<ProfileJson, AppError> {
    match w {
        ProfileWrite::Ok(p) => Ok(p.into()),
        ProfileWrite::NameTaken => Err(AppError::Conflict(
            "profile_exists",
            format!(
                "a profile named {:?} already exists",
                name.unwrap_or_default()
            ),
        )),
        ProfileWrite::NotFound => Err(AppError::NotFound(format!("profile {id} not found"))),
    }
}

pub(crate) async fn api_profiles_list(
    State(state): State<AppState>,
) -> Result<Json<Vec<ProfileJson>>, AppError> {
    let rows = state.db.list_profiles().map_err(db_err)?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

pub(crate) async fn api_profile_get(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Json<ProfileJson>, AppError> {
    state
        .db
        .get_profile(id)
        .map_err(db_err)?
        .map(|p| Json(p.into()))
        .ok_or_else(|| AppError::NotFound(format!("profile {id} not found")))
}

pub(crate) async fn api_profile_create(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<ProfileBody>,
) -> Result<(StatusCode, Json<ProfileJson>), AppError> {
    let name = clean_name(body.name.as_deref().unwrap_or(""))?;
    let request = canonical_request(body.request.ok_or_else(|| invalid("request is required"))?)?;
    let w = state.db.insert_profile(&name, &request).map_err(db_err)?;
    Ok((StatusCode::CREATED, Json(write_result(w, Some(&name), 0)?)))
}

pub(crate) async fn api_profile_update(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
    ApiJson(body): ApiJson<ProfileBody>,
) -> Result<Json<ProfileJson>, AppError> {
    let name = body.name.as_deref().map(clean_name).transpose()?;
    let request = body.request.map(canonical_request).transpose()?;
    if name.is_none() && request.is_none() {
        return Err(invalid("nothing to update: give name and/or request"));
    }
    let w = state
        .db
        .update_profile(id, name.as_deref(), request.as_deref())
        .map_err(db_err)?;
    Ok(Json(write_result(w, name.as_deref(), id)?))
}

pub(crate) async fn api_profile_delete(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
) -> Result<StatusCode, AppError> {
    if state.db.delete_profile(id).map_err(db_err)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound(format!("profile {id} not found")))
    }
}
