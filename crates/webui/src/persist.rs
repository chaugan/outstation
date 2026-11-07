//! Mapping between in-memory run state and SQLite rows.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sched::RunContext;
use serde::de::DeserializeOwned;
use tracing::warn;

use crate::db::StoredRun;
use crate::dto::*;

fn to_json<T: serde::Serialize>(id: u64, what: &str, v: &T) -> Option<String> {
    match serde_json::to_string(v) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(id, what, error = %e, "failed to serialise run field");
            None
        }
    }
}

pub(crate) fn runstate_to_stored(rs: &RunState) -> StoredRun {
    StoredRun {
        id: rs.id,
        started_at: rs.started_at,
        finished_at: rs.finished_at,
        status: rs.status.as_str().to_string(),
        pcap: rs.pcap.display().to_string(),
        pcap_id: rs.pcap_id.clone(),
        started_by: rs.started_by.clone(),
        target_ip: rs.target_ip.to_string(),
        target_mac: rs.target_mac.clone(),
        mode: rs.mode.to_string(),
        role: rs.role.to_string(),
        target_port: rs.target_port,
        speed: rs.speed,
        top_speed: rs.top_speed,
        realtime: rs.realtime,
        proto: Some(rs.proto.clone()),
        proto_config: rs.proto_config.clone(),
        planned: rs.planned,
        sent: rs.sent,
        bytes: rs.bytes_progress,
        error: rs.error.clone(),
        report_json: rs.report.as_ref().and_then(|r| to_json(rs.id, "report", r)),
        benchmark_json: rs
            .benchmark
            .as_ref()
            .and_then(|b| to_json(rs.id, "benchmark", b)),
        per_source_json: to_json(rs.id, "per_source", &rs.per_source_progress),
        throughput_json: to_json(rs.id, "throughput", &rs.throughput_history),
        request_json: rs.request.as_ref().map(|v| v.to_string()),
        rerun_of: rs.rerun_of,
    }
}

/// Decode an optional JSON column. A decode failure is logged and the
/// field is dropped; the rest of the run still loads (F090).
fn from_json<T: DeserializeOwned>(id: u64, what: &str, s: Option<&str>) -> Option<T> {
    let s = s?;
    match serde_json::from_str(s) {
        Ok(v) => Some(v),
        Err(e) => {
            warn!(id, what, error = %e, "stored run field could not be decoded; dropping it");
            None
        }
    }
}

/// Library id implied by a pcap path inside `library_dir`.
pub(crate) fn pcap_id_from_path(library_dir: &Path, pcap: &Path) -> Option<String> {
    if pcap.parent()? != library_dir || pcap.extension()? != "pcap" {
        return None;
    }
    let stem = pcap.file_stem()?.to_str()?;
    crate::library::library_entry_id_valid(stem).then(|| stem.to_string())
}

pub(crate) fn stored_to_runstate(
    s: &StoredRun,
    library_dir: &Path,
    captures_dir: &Path,
) -> Result<RunState> {
    let target_ip: Ipv4Addr = s
        .target_ip
        .parse()
        .with_context(|| format!("run {}: bad target_ip {:?}", s.id, s.target_ip))?;
    let mode: &'static str = match s.mode.as_str() {
        "benchmark" => "benchmark",
        "raw" => "raw",
        other => return Err(anyhow!("run {}: unknown mode {other:?}", s.id)),
    };
    let role: &'static str = match s.role.as_str() {
        "master" => "master",
        "slave" => "slave",
        _ => "",
    };
    let report: Option<RunReportJson> = from_json(s.id, "report", s.report_json.as_deref());
    let mut benchmark: Option<BenchmarkReportJson> =
        from_json(s.id, "benchmark", s.benchmark_json.as_deref());
    if let Some(b) = benchmark.as_mut() {
        b.upgrade_legacy();
    }
    let per_source_progress: Vec<SourceProgressJson> =
        from_json(s.id, "per_source", s.per_source_json.as_deref()).unwrap_or_default();
    let throughput_history: Vec<u64> =
        from_json(s.id, "throughput", s.throughput_json.as_deref()).unwrap_or_default();
    let pcap = PathBuf::from(&s.pcap);
    let recorded_capture = report
        .as_ref()
        .and_then(|r| r.capture_path.clone())
        .or_else(|| benchmark.as_ref().and_then(|b| b.capture_path.clone()));
    Ok(RunState {
        id: s.id,
        status: RunStatus::from_str(&s.status),
        started_at: s.started_at,
        finished_at: s.finished_at,
        started_by: s.started_by.clone(),
        pcap_id: s
            .pcap_id
            .clone()
            .or_else(|| pcap_id_from_path(library_dir, &pcap)),
        pcap,
        target_ip,
        target_mac: s.target_mac.clone(),
        speed: s.speed,
        top_speed: s.top_speed,
        realtime: s.realtime,
        error: s.error.clone(),
        report,
        benchmark,
        mode,
        role,
        target_port: s.target_port,
        proto: s.proto.clone().unwrap_or_else(default_proto_name),
        proto_config: s.proto_config.clone(),
        planned: s.planned,
        sent: s.sent,
        bytes_progress: s.bytes,
        per_source_progress,
        throughput_history,
        capture_file: crate::captures::locate_capture(
            captures_dir,
            s.id,
            recorded_capture.as_deref(),
        ),
        request: from_json(s.id, "request", s.request_json.as_deref()),
        rerun_of: s.rerun_of,
        latest_analysis: None,
        auto_analysis: None,
        ctx: RunContext::new(),
    })
}
