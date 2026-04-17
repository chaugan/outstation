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

use protoplay::{ProtoReplayer, ProtoReport, ProtoRunCfg, Readiness, Role};

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
}
