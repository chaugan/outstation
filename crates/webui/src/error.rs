//! API error type and JSON-rejecting extractors.
//!
//! Every error the API returns has the same shape:
//!
//! ```json
//! { "error": "human readable message", "code": "machine_code", ...extra }
//! ```
//!
//! `extra` carries structured context for a few codes (the active run
//! on `run_active`, the dependent runs on `pcap_in_use`).

use axum::async_trait;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;

#[derive(Debug)]
pub(crate) struct AppError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl AppError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            extra: None,
        }
    }

    #[allow(non_snake_case)]
    pub(crate) fn BadRequest(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    #[allow(non_snake_case)]
    pub(crate) fn NotFound(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    #[allow(non_snake_case)]
    pub(crate) fn Internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }

    #[allow(non_snake_case)]
    pub(crate) fn Conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    /// Replace the machine-readable code.
    pub(crate) fn code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }

    /// Attach extra top-level fields to the JSON body.
    pub(crate) fn with(mut self, key: &str, value: serde_json::Value) -> Self {
        self.extra
            .get_or_insert_with(serde_json::Map::new)
            .insert(key.to_string(), value);
        self
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}): {}", self.status, self.code, self.message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut body = self.extra.unwrap_or_default();
        body.insert("error".into(), serde_json::Value::String(self.message));
        body.insert("code".into(), serde_json::Value::String(self.code.into()));
        (self.status, Json(serde_json::Value::Object(body))).into_response()
    }
}

/// Body for the router fallback, so unknown routes also answer in the
/// common error shape.
pub(crate) async fn not_found_fallback() -> AppError {
    AppError::NotFound("no such endpoint")
}

/// `Json<T>` whose rejections (wrong content type, malformed JSON,
/// unknown enum variants, ...) use the common error shape.
pub(crate) struct ApiJson<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(ApiJson(v)),
            Err(r) => {
                let code = match &r {
                    JsonRejection::MissingJsonContentType(_) => "unsupported_media_type",
                    JsonRejection::JsonSyntaxError(_) => "invalid_json",
                    JsonRejection::JsonDataError(_) => "invalid_request",
                    _ => "bad_request",
                };
                Err(AppError::new(r.status(), code, r.body_text()))
            }
        }
    }
}

/// `Path<T>` with JSON rejections.
pub(crate) struct ApiPath<T>(pub T);

#[async_trait]
impl<T, S> FromRequestParts<S> for ApiPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(v)) => Ok(ApiPath(v)),
            Err(r) => {
                let r: PathRejection = r;
                Err(AppError::new(r.status(), "invalid_path", r.body_text()))
            }
        }
    }
}

/// `Query<T>` with JSON rejections.
pub(crate) struct ApiQuery<T>(pub T);

#[async_trait]
impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(v)) => Ok(ApiQuery(v)),
            Err(r) => {
                let r: QueryRejection = r;
                Err(AppError::new(r.status(), "invalid_query", r.body_text()))
            }
        }
    }
}

/// Mutex lock that tolerates poisoning. A panic while holding one of
/// the server's locks must not turn every later request into a panic
/// (F086); the protected data is plain state that stays usable.
pub(crate) trait LockExt<T> {
    fn lock_safe(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockExt<T> for std::sync::Mutex<T> {
    fn lock_safe(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Map a panic payload caught by `CatchPanicLayer` to the common error
/// shape.
pub(crate) fn panic_response(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let msg = panic_message(&*err);
    tracing::error!(panic = %msg, "request handler panicked");
    AppError::Internal(format!("internal error: handler panicked: {msg}")).into_response()
}

pub(crate) fn panic_message(err: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = err.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}
