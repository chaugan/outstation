//! IEC 60870-6 TASE.2/ICCP client replayer — v1 stub.
//!
//! ICCP is MMS-based (same TPKT/COTP/ISO-8650 stack as IEC 61850 MMS),
//! but with a distinct application-layer profile. Shares the TPKT/COTP
//! framing scaffolding with `proto_iec61850_mms` when both mature.

use protoplay::{ProtoReplayer, ProtoReport, ProtoRunCfg, Readiness};

pub struct IccpReplayer;

impl ProtoReplayer for IccpReplayer {
    fn name(&self) -> &'static str {
        "iec60870_6_iccp"
    }
    fn well_known_ports(&self) -> &'static [u16] {
        // Typically iso-tsap (102), but deployments vary.
        &[102]
    }
    fn readiness(&self) -> Readiness {
        Readiness::Stub
    }
    fn run(&self, _cfg: ProtoRunCfg) -> ProtoReport {
        protoplay::stub_report("iec60870_6_iccp")
    }
}
