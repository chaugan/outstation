//! IEC 61850 MMS (TPKT/COTP/ISO-8650/MMS stack) client replayer — v1 stub.

use protoplay::{ProtoReplayer, ProtoReport, ProtoRunCfg, Readiness};

pub struct Iec61850MmsReplayer;

impl ProtoReplayer for Iec61850MmsReplayer {
    fn name(&self) -> &'static str {
        "iec61850_mms"
    }
    fn well_known_ports(&self) -> &'static [u16] {
        // 102 = iso-tsap, used by TPKT/COTP which carries MMS.
        &[102]
    }
    fn readiness(&self) -> Readiness {
        Readiness::Stub
    }
    fn run(&self, _cfg: ProtoRunCfg) -> ProtoReport {
        protoplay::stub_report("iec61850_mms")
    }
}
