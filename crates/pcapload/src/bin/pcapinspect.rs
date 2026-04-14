use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use pcapload::{load, PacketKind};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "pcapinspect", about = "Show sources and flows in a pcap")]
struct Cli {
    file: PathBuf,
    #[arg(long)]
    verbose: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let p = load(&cli.file)?;

    println!("file         : {}", p.path.display());
    println!("link type    : {}", p.link_type);
    println!("packets      : {}", p.packets.len());
    println!("non-ip       : {}", p.non_ip_count);
    println!("malformed    : {}", p.malformed_count);
    println!(
        "duration     : {:.3} s",
        (p.last_ts_ns.saturating_sub(p.first_ts_ns)) as f64 / 1e9
    );
    println!("sources      : {}", p.sources.len());
    println!("tcp flows    : {}", p.flows.len());
    println!();

    println!(
        "{:<17} {:<17} {:>10} {:>12} {:>6} {}",
        "src ip", "src mac", "packets", "bytes", "flows", "mac_collision"
    );
    for (ip, s) in &p.sources {
        println!(
            "{:<17} {:<17} {:>10} {:>12} {:>6} {}",
            ip.to_string(),
            format_mac(s.src_mac),
            s.packet_count,
            s.byte_count,
            s.flow_indices.len(),
            s.mac_collision
        );
    }

    if !p.flows.is_empty() {
        println!();
        println!(
            "{:<4} {:<21} {:<21} {:>8} {}",
            "idx", "client", "server", "packets", "state"
        );
        for (i, f) in p.flows.iter().enumerate() {
            let client = f
                .client
                .map(|(ip, port)| format!("{}:{}", ip, port))
                .unwrap_or_else(|| "?".into());
            let server = f
                .server
                .map(|(ip, port)| format!("{}:{}", ip, port))
                .unwrap_or_else(|| "?".into());
            let mut state = String::new();
            if f.saw_syn {
                state.push_str("SYN ");
            }
            if f.saw_syn_ack {
                state.push_str("SYN-ACK ");
            }
            if f.saw_fin {
                state.push_str("FIN ");
            }
            if f.saw_rst {
                state.push_str("RST ");
            }
            println!(
                "{:<4} {:<21} {:<21} {:>8} {}",
                i,
                client,
                server,
                f.packet_indices.len(),
                state.trim()
            );
        }
    }

    if cli.verbose {
        println!();
        for (i, pkt) in p.packets.iter().enumerate() {
            let kind = match &pkt.kind {
                PacketKind::Tcp { role, flags, .. } => format!("TCP {:?} flags={:02x}", role, flags),
                PacketKind::Udp => "UDP".into(),
                PacketKind::Icmp => "ICMP".into(),
                PacketKind::IpOther { proto } => format!("IP proto={}", proto),
                PacketKind::NonIp { ethertype } => format!("non-ip eth=0x{:04x}", ethertype),
                PacketKind::Malformed => "MALFORMED".into(),
            };
            println!(
                "{:>6} {:>14} ns {:>4} B  {}",
                i,
                pkt.rel_ts_ns,
                pkt.data.len(),
                kind
            );
        }
    }
    Ok(())
}

fn format_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}
