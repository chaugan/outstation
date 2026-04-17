//! Single source of truth for the set of compiled-in IEC / SCADA
//! protocol replayers. Both the CLI (`outstation list-protocols`) and
//! the web UI's `/api/protocols` route call into here so the list
//! never drifts between surfaces.
//!
//! Adding a new protocol is one line in [`build`] plus the new crate's
//! `ProtoReplayer` impl. See `doc/adding-a-protocol.md` for the recipe.

use std::sync::Arc;

use protoplay::ProtoReplayer;

/// Construct one instance of every compiled-in protocol replayer.
/// Returned in a stable order so listings render predictably.
pub fn build() -> Vec<Arc<dyn ProtoReplayer>> {
    vec![
        Arc::new(proto_iec104::Iec104Replayer::new()),
        Arc::new(proto_modbus_tcp::ModbusTcpReplayer),
        Arc::new(proto_dnp3_tcp::Dnp3TcpReplayer),
        Arc::new(proto_iec61850_mms::Iec61850MmsReplayer),
        Arc::new(proto_iec60870_6_iccp::IccpReplayer),
    ]
}

/// Look up a single replayer by its [`ProtoReplayer::name`]. Returns
/// `None` for unknown names so callers can render a 404.
pub fn lookup(name: &str) -> Option<Arc<dyn ProtoReplayer>> {
    build().into_iter().find(|p| p.name() == name)
}
