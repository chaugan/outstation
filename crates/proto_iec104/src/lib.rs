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
pub mod commands;
pub mod faults;
pub mod interrogation;
pub mod inventory;
mod link;
#[cfg(test)]
mod mockpeer;
pub mod responder;
pub mod session;
pub mod viability;

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

    fn validate_config(&self, proto_config: Option<&str>) -> anyhow::Result<()> {
        asdu::validate_proto_config(proto_config)
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

    /// IEC 104-aware pcap viability analysis, see [`viability`]:
    /// session counts per role, per-endpoint figures of the flow each
    /// endpoint would replay, a memory estimate and notes (mid-flow
    /// captures, reconnects, TCP gaps, the CA/IOA inventory).
    fn quick_viability(&self, p: &dyn LoadedPcapView, file_size_bytes: u64) -> ProtoViability {
        viability::quick_viability(p, file_size_bytes)
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
        /// (flow, server payload, gap offsets in the server payload)
        flows: Vec<(FlowView, Vec<u8>, Vec<usize>)>,
    }

    impl LoadedPcapView for FakePcap {
        fn flows(&self) -> Box<dyn Iterator<Item = FlowView> + '_> {
            Box::new(self.flows.iter().map(|f| f.0))
        }
        fn flow_payload_bytes(&self, flow_idx: usize) -> (u64, u64) {
            (0, self.flows[flow_idx].1.len() as u64)
        }
        fn with_flow_side(
            &self,
            flow_idx: usize,
            side: protoplay::FlowSide,
            f: &mut dyn FnMut(&protoplay::FlowSideView<'_>),
        ) {
            let (_, payload, gaps) = &self.flows[flow_idx];
            if side == protoplay::FlowSide::Server && !payload.is_empty() {
                f(&protoplay::FlowSideView {
                    payload,
                    gap_offsets: gaps,
                    missing_bytes: 10 * gaps.len() as u64,
                });
            }
        }
        fn packet_count(&self) -> u64 {
            1000
        }
    }

    fn rtu_flow(
        idx: usize,
        port: u16,
        n: u16,
        gaps: Vec<usize>,
    ) -> (FlowView, Vec<u8>, Vec<usize>) {
        let rtu: std::net::Ipv4Addr = "10.0.0.5".parse().unwrap();
        let master: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
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
            gaps,
        )
    }

    /// N18: an RTU seen in several flows (reconnects) is described by
    /// the flow it replays, the most contiguous and largest one, not by
    /// the first flow nor by the sum; the notes say so and report the
    /// gaps of the replayed flows.
    #[test]
    fn viability_describes_the_best_flow_per_rtu() {
        // Flow 0: 5 frames with a gap after the first one; flow 1: 3
        // clean frames; flow 2: 2 clean frames.
        let pcap = FakePcap {
            flows: vec![
                rtu_flow(0, 40000, 5, vec![16]),
                rtu_flow(1, 40001, 3, vec![]),
                rtu_flow(2, 40002, 2, vec![]),
            ],
        };
        let v = Iec104Replayer.quick_viability(&pcap, 1000);
        assert_eq!(v.slave_rtus.len(), 1);
        // Flow 0's longest contiguous run is 4 frames (64 bytes), flow
        // 1's is 3 (48): flow 0 wins on contiguity.
        assert_eq!(v.slave_rtus[0].payload_bytes, 80);
        assert_eq!(v.slave_rtus[0].messages, 5);
        assert_eq!(v.server_payload_bytes, 80);
        let notes = v.notes.join("\n");
        assert!(
            notes.contains("1 RTU(s) and 1 master(s) appear in several flows"),
            "{notes}"
        );
        assert!(
            notes.contains(
                "1 of the 1 flows the slave role would replay have TCP capture gaps (10 bytes"
            ),
            "{notes}"
        );
        assert!(notes.contains("5 unique (CA, IOA) points"), "{notes}");

        // A clean flow as long as the gapped flow's longest run wins
        // (fewer gaps), whatever the order.
        let pcap = FakePcap {
            flows: vec![
                rtu_flow(0, 40000, 5, vec![16]),
                rtu_flow(1, 40001, 4, vec![]),
            ],
        };
        let v = Iec104Replayer.quick_viability(&pcap, 1000);
        assert_eq!(v.slave_rtus[0].payload_bytes, 64);
        assert_eq!(v.slave_rtus[0].messages, 4);
        assert!(!v.notes.join("\n").contains("capture gaps"));
        // 1000 packets: the parsed capture costs more than the file.
        assert!(v.estimated_peak_mb >= 33, "{}", v.estimated_peak_mb);
    }
}
