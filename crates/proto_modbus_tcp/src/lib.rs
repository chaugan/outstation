//! Modbus/TCP client replayer — v1 stub.

use protoplay::{ProtoReplayer, ProtoReport, ProtoRunCfg, Readiness};

pub struct ModbusTcpReplayer;

impl ProtoReplayer for ModbusTcpReplayer {
    fn name(&self) -> &'static str {
        "modbus_tcp"
    }
    fn well_known_ports(&self) -> &'static [u16] {
        &[502]
    }
    fn readiness(&self) -> Readiness {
        Readiness::Stub
    }
    fn run(&self, _cfg: ProtoRunCfg) -> ProtoReport {
        protoplay::stub_report("modbus_tcp")
    }
}
