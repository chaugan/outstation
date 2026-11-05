//! HTTP route handlers, grouped by area.

pub(crate) mod analyze;
pub(crate) mod library;
pub(crate) mod live;
pub(crate) mod misc;
pub(crate) mod net;
pub(crate) mod runs;
pub(crate) mod slaves;

use std::path::Path;

use axum::body::Body;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

use crate::error::AppError;
use crate::library::content_disposition;

/// Stream a pcap file as an attachment without reading it into memory
/// (F053, F087, F149).
pub(crate) async fn stream_file(path: &Path, download_name: &str) -> Result<Response, AppError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::NotFound(format!("open file: {e}")).code("file_missing"))?;
    let len = file
        .metadata()
        .await
        .map_err(|e| AppError::Internal(format!("stat file: {e}")))?
        .len();
    let body = Body::from_stream(ReaderStream::new(file));
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.tcpdump.pcap"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition(download_name))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    Ok(resp)
}
