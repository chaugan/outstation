//! IEC 60870-5-104 client-session replayer.
//!
//! Parses the client-side APDU stream from the pcap, drives the
//! STARTDT handshake against the target, replays each captured I-frame
//! with fresh N(S)/N(R) sequence numbers, acknowledges server I-frames
//! with S-frames inside window w, and closes with STOPDT.
//!
//! ASDU contents are forwarded verbatim in v1. The hook for COT/IOA
//! rewriting is the `proto_config` JSON field — a follow-up will parse
//! the ASDU header, apply rewrites, and reserialize before send.

use std::collections::BTreeMap;

use protoplay::{
    AnalyzeCtx, FleetDriftTimeline, FlowSnapshot, LoadedPcapView, ProtoReplayer, ProtoReport,
    ProtoRunCfg, ProtoSlaveAnalysis, ProtoViability, Readiness, Role,
};

pub mod analysis;
pub mod apdu;
pub mod asdu;
pub mod session;

pub struct Iec104Replayer;

impl Iec104Replayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Iec104Replayer {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoReplayer for Iec104Replayer {
    fn name(&self) -> &'static str {
        "iec104"
    }

    fn well_known_ports(&self) -> &'static [u16] {
        &[2404]
    }

    fn readiness(&self) -> Readiness {
        Readiness::Ready
    }

    fn run(&self, cfg: ProtoRunCfg) -> ProtoReport {
        match cfg.role {
            Role::Master => session::run_session(cfg),
            Role::Slave => session::run_slave_session(cfg),
        }
    }

    /// Walk the IEC 104 APCI framing in `payload` and emit one
    /// timestamp per I-frame, derived from `packet_offsets`. The first
    /// I-frame anchors at 0; subsequent frames are wall-clock-relative
    /// to it. Length-prefixed frames are detected by the 0x68 start
    /// byte + 1-byte APCI+ASDU length, with an I-frame discriminated
    /// by the low bit of CF1 being 0.
    fn extract_message_times_ns(
        &self,
        payload: &[u8],
        packet_offsets: &[(u64, usize)],
    ) -> Vec<u64> {
        let mut starts: Vec<usize> = Vec::new();
        let mut i = 0usize;
        while i + 6 <= payload.len() {
            if payload[i] != 0x68 {
                i += 1;
                continue;
            }
            let ln = payload[i + 1] as usize;
            if i + 2 + ln > payload.len() {
                break;
            }
            let cf1 = payload[i + 2];
            if cf1 & 0x01 == 0 {
                // I-frame
                starts.push(i);
            }
            i += 2 + ln;
        }
        if starts.len() < 2 {
            return Vec::new();
        }
        let ts_for = |byte: usize| -> u64 {
            let mut lo = 0usize;
            let mut hi = packet_offsets.len();
            while lo < hi {
                let mid = (lo + hi) / 2;
                if packet_offsets[mid].1 <= byte {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if lo == 0 {
                packet_offsets.first().map(|p| p.0).unwrap_or(0)
            } else {
                packet_offsets[lo - 1].0
            }
        };
        let t0 = ts_for(starts[0]);
        starts.iter().map(|&b| ts_for(b).saturating_sub(t0)).collect()
    }

    /// IEC 104-aware pcap viability analysis. Counts unique
    /// client/server IPs on port 2404, sums per-side TCP payload
    /// bytes, computes a memory estimate for fleet replay, and
    /// distinguishes mid-flow vs clean-handshake flows in the
    /// notes — surfaced in the UI so users know when to expect
    /// the replayer's mid-flow synthesis to fire.
    fn quick_viability(
        &self,
        p: &dyn LoadedPcapView,
        file_size_bytes: u64,
    ) -> ProtoViability {
        use std::collections::HashSet;
        const TARGET_PORT: u16 = 2404;
        let mut client_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut server_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut client_payload_bytes: u64 = 0;
        let mut server_payload_bytes: u64 = 0;
        let mut midflow_flows: u64 = 0;
        let mut clean_handshake_flows: u64 = 0;
        for f in p.flows() {
            let (server_ip, server_port) = match f.server { Some(x) => x, None => continue };
            if server_port != TARGET_PORT { continue; }
            let (client_ip, _) = match f.client { Some(x) => x, None => continue };
            client_ips.insert(client_ip);
            server_ips.insert(server_ip);
            if f.saw_syn {
                clean_handshake_flows += 1;
            } else {
                midflow_flows += 1;
            }
            let (cb, sb) = p.flow_payload_bytes(f.flow_idx);
            client_payload_bytes += cb;
            server_payload_bytes += sb;
        }
        let sessions_master_mode = client_ips.len() as u64;
        let sessions_slave_mode = server_ips.len() as u64;
        let mb = |b: u64| (b + 1024 * 1024 - 1) / (1024 * 1024);
        let parsed_store_mb = mb(file_size_bytes);
        let max_session_count = sessions_master_mode.max(sessions_slave_mode);
        let session_payload_mb = mb(client_payload_bytes.max(server_payload_bytes));
        let reservoir_mb = mb(max_session_count * 80 * 1024);
        let stack_mb = max_session_count * 2;
        let estimated_peak_mb =
            parsed_store_mb + session_payload_mb + reservoir_mb + stack_mb + 32;
        let (verdict, verdict_reason): (&str, String) = if file_size_bytes
            > 8 * 1024 * 1024 * 1024
            || max_session_count > 1500
        {
            (
                "not_recommended",
                format!(
                    "{} sessions and a {} MB pcap exceed comfortable single-host limits",
                    max_session_count,
                    file_size_bytes / (1024 * 1024)
                ),
            )
        } else if file_size_bytes > 2 * 1024 * 1024 * 1024 || max_session_count > 500 {
            (
                "heavy",
                format!(
                    "{} sessions / {} MB pcap - needs a roomy host (>= {} MB free RAM)",
                    max_session_count,
                    file_size_bytes / (1024 * 1024),
                    estimated_peak_mb
                ),
            )
        } else if file_size_bytes > 500 * 1024 * 1024 || max_session_count > 100 {
            (
                "caution",
                format!(
                    "{} sessions / {} MB pcap - feasible but expect ~{} MB peak RAM",
                    max_session_count,
                    file_size_bytes / (1024 * 1024),
                    estimated_peak_mb
                ),
            )
        } else if max_session_count == 0 {
            (
                "ok",
                "no IEC 104 flows on port 2404 - fine for raw replay; benchmark mode has nothing to drive".into(),
            )
        } else {
            (
                "ok",
                format!(
                    "{} session(s) and {} MB pcap - easy to replay on this host",
                    max_session_count,
                    file_size_bytes / (1024 * 1024)
                ),
            )
        };
        let mut notes = Vec::new();
        if max_session_count == 0 {
            notes.push(
                "no TCP flow with server_port=2404 found - benchmark mode would have nothing to do"
                    .into(),
            );
        } else {
            notes.push(format!(
                "{} unique client IPs talk to port 2404 (master-mode session count)",
                sessions_master_mode
            ));
            notes.push(format!(
                "{} unique server IPs listen on port 2404 (slave-mode session count)",
                sessions_slave_mode
            ));
            notes.push(format!(
                "{} MB of client TCP payload, {} MB of server TCP payload across all relevant flows",
                client_payload_bytes / (1024 * 1024),
                server_payload_bytes / (1024 * 1024),
            ));
            if midflow_flows > 0 {
                notes.push(format!(
                    "{} of {} flows are mid-flow (no SYN observed) - the replayer will synthesize a fresh TCP+STARTDT prelude and resync to the first clean APCI boundary; {} flows had a clean handshake in the capture",
                    midflow_flows,
                    midflow_flows + clean_handshake_flows,
                    clean_handshake_flows,
                ));
            }
        }
        if file_size_bytes > 1024 * 1024 * 1024 {
            notes.push(
                "pcap is larger than 1 GB; pcapload reads it fully into RAM (no mmap path yet)"
                    .into(),
            );
        }
        if max_session_count > 256 {
            notes.push(
                "session count exceeds 256 - ensure `ulimit -n` is large enough for one socket per session".into(),
            );
        }
        ProtoViability {
            client_payload_bytes,
            server_payload_bytes,
            sessions_master_mode,
            sessions_slave_mode,
            estimated_peak_mb,
            verdict: verdict.into(),
            verdict_reason,
            notes,
        }
    }

    /// IEC 104 analyzer: walk playback vs target, both original vs
    /// captured, emit playback / target / timing / cp56_drift sub-
    /// reports. Delegates to [`analysis::analyze_iec104_flow`].
    fn analyze_flow(
        &self,
        orig_playback: Option<FlowSnapshot>,
        cap_playback: Option<FlowSnapshot>,
        orig_target: Option<FlowSnapshot>,
        cap_target: Option<FlowSnapshot>,
        ctx: &AnalyzeCtx,
    ) -> ProtoSlaveAnalysis {
        analysis::analyze_iec104_flow(orig_playback, cap_playback, orig_target, cap_target, ctx)
    }

    /// IEC 104 fleet-level drift aggregator: reads each slave's
    /// `cp56_drift.{drift_samples_ms, sample_wall_ms}` arrays from
    /// `protocol_specific`, merges + decimates.
    fn aggregate_fleet_drift(
        &self,
        per_slave: &BTreeMap<String, serde_json::Value>,
        iteration_starts_ms: &[f64],
    ) -> Option<FleetDriftTimeline> {
        analysis::aggregate_iec104_fleet_drift(per_slave, iteration_starts_ms)
    }
}
