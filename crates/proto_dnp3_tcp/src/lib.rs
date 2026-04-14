//! DNP3 over TCP client replayer — v1 stub.

use protoplay::{ProtoReplayer, ProtoReport, ProtoRunCfg, Readiness};

pub struct Dnp3TcpReplayer;

impl ProtoReplayer for Dnp3TcpReplayer {
    fn name(&self) -> &'static str {
        "dnp3_tcp"
    }
    fn well_known_ports(&self) -> &'static [u16] {
        &[20000]
    }
    fn readiness(&self) -> Readiness {
        Readiness::Stub
    }
    fn run(&self, _cfg: ProtoRunCfg) -> ProtoReport {
        protoplay::stub_report("dnp3_tcp")
    }
}
