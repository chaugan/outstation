//! Mapping between in-memory run state and SQLite rows.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use sched::RunContext;

use crate::db::StoredRun;
use crate::dto::*;

pub(crate) fn runstate_to_stored(rs: &RunState) -> StoredRun {
    StoredRun {
        id: rs.id,
        started_at: rs.started_at,
        status: rs.status.as_str().to_string(),
        pcap: rs.pcap.display().to_string(),
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
        report_json: rs
            .report
            .as_ref()
            .and_then(|r| serde_json::to_string(r).ok()),
        benchmark_json: rs
            .benchmark
            .as_ref()
            .and_then(|b| serde_json::to_string(b).ok()),
        per_source_json: serde_json::to_string(&rs.per_source_progress).ok(),
        throughput_json: serde_json::to_string(&rs.throughput_history).ok(),
    }
}

pub(crate) fn stored_to_runstate(s: &StoredRun) -> Option<RunState> {
    let target_ip: Ipv4Addr = s.target_ip.parse().ok()?;
    let mode: &'static str = match s.mode.as_str() {
        "benchmark" => "benchmark",
        _ => "raw",
    };
    let role: &'static str = match s.role.as_str() {
        "master" => "master",
        "slave" => "slave",
        _ => "",
    };
    let report: Option<RunReportJson> = s
        .report_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());
    let benchmark: Option<BenchmarkReportJson> = s
        .benchmark_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());
    let per_source_progress: Vec<SourceProgressJson> = s
        .per_source_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    let throughput_history: Vec<u64> = s
        .throughput_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    Some(RunState {
        id: s.id,
        status: RunStatus::from_str(&s.status),
        started_at: s.started_at,
        pcap: PathBuf::from(&s.pcap),
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
        ctx: RunContext::new(),
    })
}
