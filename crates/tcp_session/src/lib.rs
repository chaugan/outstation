//! Generic TCP client session replayer.
//!
//! Given a reassembled client-side byte stream, open a real TCP socket
//! from a specified source IP (typically bound to the source's
//! bridge-side veth via `SO_BINDTODEVICE`) to the target, and write the
//! stream. Timing is best-effort: inter-segment gaps from the original
//! pcap are lost since the kernel now decides when bytes go on the wire.
//!
//! This crate intentionally knows nothing about protocols. For stateful
//! protocols that require responding to server bytes (IEC 104, Modbus,
//! MMS) use the protocol-aware modules in `protoplay`.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct FlowReplayCfg {
    /// Source IPv4 to bind the socket to. The kernel needs this IP
    /// assigned to an interface it can route from.
    pub bind_ip: Ipv4Addr,
    /// Optional device to pin the socket to with `SO_BINDTODEVICE`.
    /// Matching the bridge-side veth that owns `bind_ip` gives the
    /// right routing on a shared bridge.
    pub bind_iface: Option<String>,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub payload: Vec<u8>,
    pub connect_timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub connected: bool,
    pub bytes_written: u64,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

pub fn replay_flow(cfg: FlowReplayCfg) -> SessionStats {
    let t0 = Instant::now();
    let mut stats = SessionStats::default();

    let sock = match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => {
            stats.error = Some(format!("socket: {e}"));
            return stats;
        }
    };

    if let Some(iface) = &cfg.bind_iface {
        if let Err(e) = sock.bind_device(Some(iface.as_bytes())) {
            stats.error = Some(format!("bind_device({iface}): {e}"));
            return stats;
        }
    }

    let bind_addr: SocketAddr = SocketAddrV4::new(cfg.bind_ip, 0).into();
    if let Err(e) = sock.bind(&bind_addr.into()) {
        stats.error = Some(format!("bind({}): {e}", cfg.bind_ip));
        return stats;
    }

    let tgt: SocketAddr = SocketAddrV4::new(cfg.target_ip, cfg.target_port).into();
    if let Err(e) = sock.connect_timeout(&tgt.into(), cfg.connect_timeout) {
        stats.error = Some(format!("connect({tgt}): {e}"));
        stats.elapsed_ms = t0.elapsed().as_millis() as u64;
        return stats;
    }
    stats.connected = true;
    info!(bind_ip = %cfg.bind_ip, %tgt, bytes = cfg.payload.len(), "session connected");

    let std_sock: std::net::TcpStream = sock.into();
    let mut stream: TcpStream = std_sock;
    if let Err(e) = stream.write_all(&cfg.payload) {
        warn!(error = %e, "write failed");
        stats.error = Some(format!("write: {e}"));
    } else {
        stats.bytes_written = cfg.payload.len() as u64;
    }
    // Dropping `stream` sends FIN.
    stats.elapsed_ms = t0.elapsed().as_millis() as u64;
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_constructs() {
        // Compile-time check that the API is ergonomic; no network.
        let _cfg = FlowReplayCfg {
            bind_ip: Ipv4Addr::new(10, 0, 0, 1),
            bind_iface: Some("eth0".into()),
            target_ip: Ipv4Addr::new(10, 0, 0, 2),
            target_port: 2404,
            payload: vec![0x68, 0x04, 0x07, 0x00, 0x00, 0x00],
            connect_timeout: Duration::from_secs(2),
        };
    }
}
