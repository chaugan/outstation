//! Static assets, status, protocol list and pcap inspection.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{ApiJson, AppError};
use crate::library::library_pcap_path;
use crate::state::{ActiveRun, AppState};
use crate::sysinfo::{capabilities, free_bytes, Capabilities};

// Populated by `build.rs` after it splices each proto crate's
// `static/*.js` into the `@@PROTO_STATIC_JS@@` placeholder in
// `src/index.html`. Having the served HTML come out of OUT_DIR means
// adding a new protocol is just dropping a `static/<name>_ui.js`
// file under its crate — no webui edits required.
pub(crate) const EMBEDDED_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/index.html"));
pub(crate) const EMBEDDED_ECHARTS: &str = include_str!("../echarts.min.js");

pub(crate) async fn serve_index() -> Html<&'static str> {
    Html(EMBEDDED_HTML)
}

pub(crate) async fn serve_echarts() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    (headers, EMBEDDED_ECHARTS).into_response()
}

#[derive(Serialize)]
pub(crate) struct DbStatus {
    path: Option<String>,
    ephemeral: bool,
    writable: bool,
    error: Option<String>,
}

/// `GET /api/status`: real health, not a constant (F076).
#[derive(Serialize)]
pub(crate) struct StatusJson {
    /// False when any `degraded` reason is present.
    ok: bool,
    version: &'static str,
    uptime_secs: u64,
    db: DbStatus,
    state_dir: String,
    library_dir: String,
    captures_dir: String,
    free_disk_bytes: Option<u64>,
    min_free_bytes: u64,
    capabilities: Option<Capabilities>,
    active_run: Option<ActiveRun>,
    shutting_down: bool,
    degraded: Vec<String>,
}

pub(crate) async fn api_status(State(state): State<AppState>) -> Json<StatusJson> {
    let st = state.clone();
    let (db_res, free, caps) = tokio::task::spawn_blocking(move || {
        (
            st.db.check_writable(),
            free_bytes(&st.cfg.state_dir),
            capabilities(),
        )
    })
    .await
    .unwrap_or_else(|e| (Err(anyhow::anyhow!("status task: {e}")), None, None));
    let mut degraded = Vec::new();
    if let Err(e) = &db_res {
        degraded.push(format!("run database is not writable: {e:#}"));
    }
    if state.cfg.ephemeral {
        degraded.push("ephemeral mode: run history is not persisted".into());
    }
    match free {
        Some(f) if f < state.cfg.min_free_bytes => degraded.push(format!(
            "low disk: {f} bytes free in {}",
            state.cfg.state_dir.display()
        )),
        None => degraded.push("free disk space unknown".into()),
        _ => {}
    }
    if let Some(c) = &caps {
        if !(c.net_admin && c.net_raw) {
            degraded.push("missing CAP_NET_ADMIN/CAP_NET_RAW: runs will fail".into());
        }
    }
    Json(StatusJson {
        ok: degraded.is_empty(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started.elapsed().as_secs(),
        db: DbStatus {
            path: state.db.path().map(|p| p.display().to_string()),
            ephemeral: state.cfg.ephemeral,
            writable: db_res.is_ok(),
            error: db_res.err().map(|e| format!("{e:#}")),
        },
        state_dir: state.cfg.state_dir.display().to_string(),
        library_dir: state.cfg.library_dir.display().to_string(),
        captures_dir: state.cfg.captures_dir().display().to_string(),
        free_disk_bytes: free,
        min_free_bytes: state.cfg.min_free_bytes,
        capabilities: caps,
        active_run: state.active_run(),
        shutting_down: state.shutdown.is_cancelled(),
        degraded,
    })
}

#[derive(Serialize)]
pub(crate) struct ProtoJson {
    pub(crate) name: &'static str,
    pub(crate) status: &'static str,
    pub(crate) ports: Vec<u16>,
}

pub(crate) async fn api_protocols() -> Json<Vec<ProtoJson>> {
    let registry = proto_registry::build();
    let out = registry
        .iter()
        .map(|m| ProtoJson {
            name: m.name(),
            status: match m.readiness() {
                protoplay::Readiness::Ready => "ready",
                protoplay::Readiness::Stub => "stub",
            },
            ports: m.well_known_ports().to_vec(),
        })
        .collect();
    Json(out)
}

#[derive(Deserialize)]
pub(crate) struct InspectReq {
    /// Library id of the pcap to inspect.
    #[serde(default)]
    pub(crate) pcap_id: Option<String>,
    /// Rejected when present: raw filesystem paths are not accepted.
    #[serde(default)]
    pub(crate) path: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct InspectResp {
    pub(crate) packets: usize,
    pub(crate) sources: Vec<InspectSource>,
    pub(crate) non_ip_sources: Vec<InspectNonIp>,
    pub(crate) tcp_flows: Vec<InspectFlow>,
    pub(crate) duration_ms: f64,
}

#[derive(Serialize)]
pub(crate) struct InspectSource {
    pub(crate) src_ip: String,
    pub(crate) src_mac: String,
    pub(crate) packet_count: u64,
    pub(crate) byte_count: u64,
    pub(crate) flow_count: usize,
    pub(crate) mac_collision: bool,
}

#[derive(Serialize)]
pub(crate) struct InspectNonIp {
    pub(crate) src_mac: String,
    pub(crate) packet_count: u64,
    pub(crate) byte_count: u64,
    pub(crate) ethertypes: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct InspectFlow {
    pub(crate) client: String,
    pub(crate) server: String,
    pub(crate) packets: usize,
    pub(crate) state: String,
}

pub(crate) async fn api_inspect(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<InspectReq>,
) -> Result<Json<InspectResp>, AppError> {
    if req.path.is_some() {
        return Err(AppError::BadRequest(
            "raw filesystem paths are not accepted; pass a library pcap_id",
        )
        .code("raw_path_rejected"));
    }
    let id = req
        .pcap_id
        .ok_or_else(|| AppError::BadRequest("pcap_id is required").code("invalid_request"))?;
    let path = library_pcap_path(&state.library_dir, &id)?;
    let p = crate::routes::runs::load_blocking(path).await?;
    let sources: Vec<InspectSource> = p
        .sources
        .iter()
        .map(|(ip, s)| {
            let m = s.src_mac;
            InspectSource {
                src_ip: ip.to_string(),
                src_mac: format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                ),
                packet_count: s.packet_count,
                byte_count: s.byte_count,
                flow_count: s.flow_indices.len(),
                mac_collision: s.mac_collision,
            }
        })
        .collect();
    let non_ip_sources: Vec<InspectNonIp> = p
        .non_ip_sources
        .iter()
        .map(|(mac, info)| {
            let m = *mac;
            InspectNonIp {
                src_mac: format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                ),
                packet_count: info.packet_count,
                byte_count: info.byte_count,
                ethertypes: info
                    .ethertypes
                    .iter()
                    .map(|e| format!("0x{e:04x}"))
                    .collect(),
            }
        })
        .collect();
    let tcp_flows: Vec<InspectFlow> = p
        .flows
        .iter()
        .map(|f| {
            let client = f
                .client
                .map(|(ip, port)| format!("{ip}:{port}"))
                .unwrap_or_else(|| "?".into());
            let server = f
                .server
                .map(|(ip, port)| format!("{ip}:{port}"))
                .unwrap_or_else(|| "?".into());
            let mut state = String::new();
            if f.saw_syn {
                state.push_str("SYN ");
            }
            if f.saw_syn_ack {
                state.push_str("SYN-ACK ");
            }
            if f.saw_fin {
                state.push_str("FIN ");
            }
            if f.saw_rst {
                state.push_str("RST ");
            }
            InspectFlow {
                client,
                server,
                packets: f.packet_indices.len(),
                state: state.trim().into(),
            }
        })
        .collect();
    Ok(Json(InspectResp {
        packets: p.packets.len(),
        sources,
        non_ip_sources,
        tcp_flows,
        duration_ms: (p.last_ts_ns.saturating_sub(p.first_ts_ns)) as f64 / 1e6,
    }))
}
