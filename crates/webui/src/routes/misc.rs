//! Static assets, status, protocol list and pcap inspection.

use std::path::PathBuf;

use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use pcapload::load;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

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
pub(crate) struct StatusJson {
    pub(crate) ok: bool,
    pub(crate) version: &'static str,
}

pub(crate) async fn api_status() -> Json<StatusJson> {
    Json(StatusJson {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
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
    pub(crate) path: PathBuf,
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
    Json(req): Json<InspectReq>,
) -> Result<Json<InspectResp>, AppError> {
    let p = load(&req.path).map_err(|e| AppError::BadRequest(format!("load pcap: {e}")))?;
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
