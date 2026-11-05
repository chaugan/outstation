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
pub mod apci;
pub mod apdu;
pub mod asdu;
pub mod inventory;
pub mod responder;
pub mod session;

/// Cheap I-frame counter used by `quick_viability` to attribute
/// per-RTU message counts without decoding ASDU bodies. Uses the
/// canonical [`apci::frames`] walker, so it counts exactly the I-frames
/// the replayer will send and the pacing extractor will time.
fn count_iframes(payload: &[u8]) -> usize {
    apci::count_iframes(payload)
}

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
    /// to it. Framing (including resync on a mid-flow capture) is the
    /// canonical [`apci::frames`] walk, so index `k` of the result
    /// times the same `k`-th I-frame the replayer extracts.
    fn extract_message_times_ns(
        &self,
        payload: &[u8],
        packet_offsets: &[(u64, usize)],
    ) -> Vec<u64> {
        let starts = apci::iframe_offsets(payload);
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
        starts
            .iter()
            .map(|&b| ts_for(b).saturating_sub(t0))
            .collect()
    }

    /// IEC 104-aware pcap viability analysis. Counts unique
    /// client/server IPs on port 2404, sums per-side TCP payload
    /// bytes, computes a memory estimate for fleet replay, and
    /// distinguishes mid-flow vs clean-handshake flows in the
    /// notes — surfaced in the UI so users know when to expect
    /// the replayer's mid-flow synthesis to fire.
    fn quick_viability(&self, p: &dyn LoadedPcapView, file_size_bytes: u64) -> ProtoViability {
        use std::collections::HashSet;
        const TARGET_PORT: u16 = 2404;
        let mut client_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut server_ips: HashSet<std::net::Ipv4Addr> = HashSet::new();
        let mut client_payload_bytes: u64 = 0;
        let mut server_payload_bytes: u64 = 0;
        let mut midflow_flows: u64 = 0;
        let mut clean_handshake_flows: u64 = 0;
        let mut slave_flow_indices: Vec<(usize, std::net::Ipv4Addr)> = Vec::new();
        for f in p.flows() {
            let (server_ip, server_port) = match f.server {
                Some(x) => x,
                None => continue,
            };
            if server_port != TARGET_PORT {
                continue;
            }
            let (client_ip, _) = match f.client {
                Some(x) => x,
                None => continue,
            };
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
            slave_flow_indices.push((f.flow_idx, server_ip));
        }
        let sessions_master_mode = client_ips.len() as u64;
        let sessions_slave_mode = server_ips.len() as u64;
        let mb = |b: u64| b.div_ceil(1024 * 1024);
        // pcapload holds the file plus ~90 B of metadata per packet: ~2x for IEC 104-sized frames.
        let parsed_store_mb = mb(file_size_bytes.saturating_mul(2));
        let max_session_count = sessions_master_mode.max(sessions_slave_mode);
        let session_payload_mb = mb(client_payload_bytes.max(server_payload_bytes));
        let reservoir_mb = mb(max_session_count * 80 * 1024);
        let stack_mb = max_session_count * 2;
        let estimated_peak_mb = parsed_store_mb + session_payload_mb + reservoir_mb + stack_mb + 32;
        let (verdict, verdict_reason): (&str, String) = if file_size_bytes > 8 * 1024 * 1024 * 1024
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
        let mut per_rtu_bytes: std::collections::BTreeMap<std::net::Ipv4Addr, u64> =
            std::collections::BTreeMap::new();
        let mut per_rtu_msgs: std::collections::BTreeMap<std::net::Ipv4Addr, u64> =
            std::collections::BTreeMap::new();
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

            // CA / IOA inventory overview — ingest each slave flow's
            // server-side payload into a per-RTU point database so the
            // upload summary tells the operator how rich each RTU's
            // dataset is. This is the same Inventory the slave-replayer
            // builds at session start to back GI/CI synthesis. We also
            // record per-RTU bytes + I-frame counts here so the run-
            // config picker can show a traffic chart per RTU.
            let mut per_rtu_iao_count: std::collections::BTreeMap<std::net::Ipv4Addr, usize> =
                std::collections::BTreeMap::new();
            let mut total_unique_cas: std::collections::BTreeSet<u16> =
                std::collections::BTreeSet::new();
            let mut total_ioa_count: usize = 0;
            let mut type_id_counts: std::collections::BTreeMap<u8, usize> =
                std::collections::BTreeMap::new();
            let mut rtus_with_inventory: usize = 0;
            // An RTU can appear in several flows (reconnects, port
            // reuse): sum bytes and I-frames across them and merge
            // their points into one inventory per RTU.
            let mut per_rtu_inv: std::collections::BTreeMap<
                std::net::Ipv4Addr,
                inventory::Inventory,
            > = std::collections::BTreeMap::new();
            for (flow_idx, server_ip) in &slave_flow_indices {
                let payload = p.flow_server_payload(*flow_idx);
                *per_rtu_bytes.entry(*server_ip).or_insert(0) += payload.len() as u64;
                *per_rtu_msgs.entry(*server_ip).or_insert(0) += count_iframes(&payload) as u64;
                if payload.is_empty() {
                    continue;
                }
                per_rtu_inv
                    .entry(*server_ip)
                    .or_default()
                    .ingest_payload(&payload);
            }
            for (server_ip, inv) in &per_rtu_inv {
                if inv.is_empty() {
                    continue;
                }
                rtus_with_inventory += 1;
                per_rtu_iao_count.insert(*server_ip, inv.len());
                for ((ca, _ioa), entry) in &inv.entries {
                    total_unique_cas.insert(*ca);
                    total_ioa_count += 1;
                    *type_id_counts.entry(entry.type_id).or_insert(0) += 1;
                }
            }
            if rtus_with_inventory > 0 {
                let counts: Vec<usize> = per_rtu_iao_count.values().copied().collect();
                let min_ioa = *counts.iter().min().unwrap_or(&0);
                let max_ioa = *counts.iter().max().unwrap_or(&0);
                let mean_ioa = if counts.is_empty() {
                    0
                } else {
                    counts.iter().sum::<usize>() / counts.len()
                };
                notes.push(format!(
                    "CA/IOA inventory: {} unique (CA, IOA) points across {} common address(es) on {} RTU(s) (per-RTU IOAs: min {}, mean {}, max {})",
                    total_ioa_count,
                    total_unique_cas.len(),
                    rtus_with_inventory,
                    min_ioa,
                    mean_ioa,
                    max_ioa,
                ));
                if !type_id_counts.is_empty() {
                    let mut top: Vec<(u8, usize)> =
                        type_id_counts.iter().map(|(t, c)| (*t, *c)).collect();
                    top.sort_by_key(|t| std::cmp::Reverse(t.1));
                    let top_str: Vec<String> = top
                        .iter()
                        .take(5)
                        .map(|(t, c)| format!("type {} ({})", t, c))
                        .collect();
                    notes.push(format!(
                        "dominant ASDU types in inventory: {}",
                        top_str.join(", ")
                    ));
                }
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
        let mut sorted_servers: Vec<std::net::Ipv4Addr> = server_ips.into_iter().collect();
        sorted_servers.sort();
        let slave_rtus: Vec<protoplay::RtuTraffic> = sorted_servers
            .into_iter()
            .map(|ip| protoplay::RtuTraffic {
                ip: ip.to_string(),
                payload_bytes: per_rtu_bytes.get(&ip).copied().unwrap_or(0),
                messages: per_rtu_msgs.get(&ip).copied().unwrap_or(0),
                duration_ms: 0,
            })
            .collect();
        let mut sorted_clients: Vec<std::net::Ipv4Addr> = client_ips.into_iter().collect();
        sorted_clients.sort();
        let master_clients: Vec<protoplay::RtuTraffic> = sorted_clients
            .into_iter()
            .map(|ip| protoplay::RtuTraffic {
                ip: ip.to_string(),
                payload_bytes: 0,
                messages: 0,
                duration_ms: 0,
            })
            .collect();
        ProtoViability {
            client_payload_bytes,
            server_payload_bytes,
            sessions_master_mode,
            sessions_slave_mode,
            estimated_peak_mb,
            verdict: verdict.into(),
            verdict_reason,
            notes,
            slave_rtus,
            master_clients,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Apdu;
    use protoplay::{FlowView, LoadedPcapView};

    fn sp_frame(ns: u16, ioa: u8) -> Vec<u8> {
        Apdu::I {
            ns,
            nr: 0,
            asdu: vec![1, 1, 3, 0, 1, 0, ioa, 0, 0, 1],
        }
        .serialize()
    }

    /// Mid-flow stream: a leading partial frame with a stray 0x68, ten
    /// I-frames interleaved with S frames, a truncated tail. One packet
    /// per I-frame with ts = 1000 * (index + 1) ns.
    fn midflow_stream() -> (Vec<u8>, Vec<(u64, usize)>) {
        let mut s = vec![0x12, 0x68, 0x01, 0x00];
        let mut offs = vec![(0u64, 0usize)];
        for k in 0..10u16 {
            offs.push((1000 * (k as u64 + 1), s.len()));
            s.extend(sp_frame(k, k as u8));
            if k % 4 == 0 {
                s.extend(Apdu::S { nr: k }.serialize());
            }
        }
        s.extend(&sp_frame(10, 10)[..5]);
        (s, offs)
    }

    #[test]
    fn counts_and_times_agree_on_midflow_capture() {
        let (s, offs) = midflow_stream();
        assert_eq!(count_iframes(&s), 10);
        let times = Iec104Replayer.extract_message_times_ns(&s, &offs);
        assert_eq!(times.len(), 10);
        // Frame k sits in packet k+1, so relative times are 1000*k.
        let want: Vec<u64> = (0..10).map(|k| 1000 * k).collect();
        assert_eq!(times, want);
    }

    #[test]
    fn lone_start_byte_and_short_garbage() {
        assert_eq!(count_iframes(&[0x68]), 0);
        assert_eq!(count_iframes(&[0x68, 0x02, 0x00, 0x00, 0x00, 0x00]), 0);
        assert!(Iec104Replayer
            .extract_message_times_ns(&[0x68], &[(0, 0)])
            .is_empty());
    }

    struct FakePcap {
        flows: Vec<(FlowView, Vec<u8>)>,
    }

    impl LoadedPcapView for FakePcap {
        fn flows(&self) -> Box<dyn Iterator<Item = FlowView> + '_> {
            Box::new(self.flows.iter().map(|f| f.0))
        }
        fn flow_payload_bytes(&self, flow_idx: usize) -> (u64, u64) {
            (0, self.flows[flow_idx].1.len() as u64)
        }
        fn flow_server_payload(&self, flow_idx: usize) -> Vec<u8> {
            self.flows[flow_idx].1.clone()
        }
    }

    /// P02 consumer half: an RTU seen in two flows (reconnect) reports
    /// the sum of both flows' bytes and I-frames, not the last flow's.
    #[test]
    fn viability_sums_per_rtu_bytes_across_flows() {
        let rtu: std::net::Ipv4Addr = "10.0.0.5".parse().unwrap();
        let master: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
        let mk = |idx: usize, port: u16, n: u16| {
            let mut payload = Vec::new();
            for k in 0..n {
                payload.extend(sp_frame(k, (idx * 50) as u8 + k as u8));
            }
            (
                FlowView {
                    flow_idx: idx,
                    client: Some((master, port)),
                    server: Some((rtu, 2404)),
                    saw_syn: true,
                },
                payload,
            )
        };
        let pcap = FakePcap {
            flows: vec![mk(0, 40000, 3), mk(1, 40001, 5)],
        };
        let total_bytes: u64 = pcap.flows.iter().map(|f| f.1.len() as u64).sum();
        let v = Iec104Replayer.quick_viability(&pcap, 1000);
        assert_eq!(v.slave_rtus.len(), 1);
        assert_eq!(v.slave_rtus[0].payload_bytes, total_bytes);
        assert_eq!(v.slave_rtus[0].messages, 8);
        assert!(
            v.notes
                .iter()
                .any(|n| n.contains("8 unique (CA, IOA) points")),
            "{:?}",
            v.notes
        );
    }
}
