//! Top-level `outstation` binary — the user-facing CLI. For now it
//! exposes only the synchronous `run` path; the web UI will eventually
//! live beside it as `outstation serve`.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use netctl::parse_mac;
use pcapload::load;
use sched::{run as run_sched, RunConfig, RunContext};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "outstation",
    about = "Stateful SCADA traffic simulator and multi-source pcap replayer"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the sources and TCP flows found in a pcap.
    ListSources {
        pcap: PathBuf,
    },
    /// List all registered protocol-aware replayer modules.
    ListProtocols,
    /// Replay a pcap. Every IPv4 source gets its own TAP on an
    /// auto-managed bridge; the bridge optionally enslaves a physical
    /// NIC for real egress.
    Run(RunArgs),
    /// Start the web UI (axum backend + embedded SPA).
    Serve {
        /// Address to bind, e.g. 127.0.0.1:8080
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: std::net::SocketAddr,
    },
}

fn build_proto_registry() -> Vec<Box<dyn protoplay::ProtoReplayer>> {
    vec![
        Box::new(proto_iec104::Iec104Replayer::new()),
        Box::new(proto_modbus_tcp::ModbusTcpReplayer),
        Box::new(proto_dnp3_tcp::Dnp3TcpReplayer),
        Box::new(proto_iec61850_mms::Iec61850MmsReplayer),
        Box::new(proto_iec60870_6_iccp::IccpReplayer),
    ]
}

#[derive(clap::Args)]
struct RunArgs {
    /// Pcap file to replay.
    #[arg(long)]
    pcap: PathBuf,

    /// Rewrite destination IP to this value for every IPv4 packet.
    #[arg(long)]
    target_ip: Ipv4Addr,

    /// Rewrite destination MAC to this value (XX:XX:XX:XX:XX:XX).
    /// In v1 this must be supplied by the caller; ARP resolution is
    /// planned for a later iteration.
    #[arg(long)]
    target_mac: String,

    /// Physical interface to enslave to the bridge so traffic can leave
    /// the host. Omit for isolated loopback/dev runs — the bridge and
    /// its TAPs will still be created, but nothing will reach the LAN.
    #[arg(long)]
    nic: Option<String>,

    #[arg(long, default_value = "pcr_br0")]
    bridge: String,

    #[arg(long, default_value = "pcr_t")]
    tap_prefix: String,

    /// Replay speed multiplier (ignored with --top-speed).
    #[arg(long, default_value_t = 1.0)]
    speed: f64,

    #[arg(long)]
    top_speed: bool,

    /// Promote replay threads to SCHED_FIFO (needs CAP_SYS_NICE).
    #[arg(long)]
    realtime: bool,

    /// Replay only these source IPs. Repeat to pass more than one.
    #[arg(long = "only-src")]
    only_src: Vec<Ipv4Addr>,

    /// Do not replay non-IP (GOOSE/SV/raw L2) sources.
    #[arg(long)]
    skip_non_ip: bool,

    /// Seconds to wait after bringing interfaces up before starting
    /// packet injection. Gives you time to attach Wireshark to the
    /// bridge or per-source ports before frames flow.
    #[arg(long, default_value_t = 0)]
    warmup: u64,

    /// Rewrite every CP56Time2a timestamp inside outgoing IEC 104
    /// ASDUs to the actual wall-clock moment the frame hits the wire,
    /// so the SCADA system sees fresh event timestamps. Intra-pcap
    /// inter-frame spacing is preserved via the scheduler.
    #[arg(long)]
    fresh_timestamps: bool,

    /// Timezone for CP56Time2a when `--fresh-timestamps` is set:
    /// `"local"` (default) encodes the server's local calendar with
    /// the SU flag following DST — matches most plant SCADA HMIs.
    /// `"utc"` encodes UTC with SU always 0 — matches ICCP-style
    /// inter-utility links.
    #[arg(long, default_value = "local")]
    cp56_zone: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ListSources { pcap } => {
            let p = load(&pcap)?;
            println!("{} sources, {} flows, {} packets, {} non-ip",
                p.sources.len(), p.flows.len(), p.packets.len(), p.non_ip_count);
            for (ip, s) in &p.sources {
                println!(
                    "  {:<15} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  {:>8} pkts  {:>3} flows{}",
                    ip,
                    s.src_mac[0], s.src_mac[1], s.src_mac[2],
                    s.src_mac[3], s.src_mac[4], s.src_mac[5],
                    s.packet_count,
                    s.flow_indices.len(),
                    if s.mac_collision { "  MAC collision" } else { "" }
                );
            }
        }
        Cmd::ListProtocols => {
            let registry = build_proto_registry();
            println!(
                "{:<20} {:<8} {}",
                "name", "status", "well-known ports"
            );
            for m in &registry {
                let status = match m.readiness() {
                    protoplay::Readiness::Ready => "ready",
                    protoplay::Readiness::Stub => "stub",
                };
                let ports: Vec<String> = m
                    .well_known_ports()
                    .iter()
                    .map(|p| p.to_string())
                    .collect();
                println!("{:<20} {:<8} {}", m.name(), status, ports.join(","));
            }
        }
        Cmd::Run(args) => run_cmd(args)?,
        Cmd::Serve { bind } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                webui::serve(bind).await
            })?;
        }
    }
    Ok(())
}

fn run_cmd(args: RunArgs) -> Result<()> {
    let pcap = load(&args.pcap).context("load pcap")?;
    let pcap = Arc::new(pcap);
    let target_mac = parse_mac(&args.target_mac)?;

    let cfg = RunConfig {
        target_ip: args.target_ip,
        target_mac,
        bridge_name: args.bridge,
        tap_prefix: args.tap_prefix,
        egress_nic: args.nic,
        speed: args.speed,
        top_speed: args.top_speed,
        realtime: args.realtime,
        filter_sources: if args.only_src.is_empty() {
            None
        } else {
            Some(args.only_src)
        },
        include_non_ip: !args.skip_non_ip,
        startup_delay_secs: args.warmup,
        capture_path: None,
        iterations: 1,
        rewrite_cp56_to_now: args.fresh_timestamps,
        cp56_zone: args.cp56_zone.clone(),
    };

    let report = run_sched(pcap, cfg, RunContext::default()).context("run failed")?;

    println!(
        "-- totals: {} packets, {} bytes, {} errors across {} sources --",
        report.total_packets,
        report.total_bytes,
        report.total_errors,
        report.per_source.len()
    );
    println!(
        "{:<15} {:<17} {:<10} {:>8} {:>12} {:>10} {:>10} {:>10}",
        "src ip", "src mac", "tap", "sent", "bytes", "elapsed ms", "mean us", "p99 us"
    );
    for sr in &report.per_source {
        let m = sr.src_mac;
        let ip = sr
            .src_ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| format!("(L2:{:?})", sr.kind));
        println!(
            "{:<15} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} {:<10} {:>8} {:>12} {:>10.1} {:>10.1} {:>10.1}",
            ip,
            m[0], m[1], m[2], m[3], m[4], m[5],
            sr.tap,
            sr.stats.sent,
            sr.stats.bytes,
            sr.stats.elapsed_ns as f64 / 1e6,
            sr.stats.mean_abs_jitter_ns as f64 / 1e3,
            sr.stats.p99_abs_jitter_ns as f64 / 1e3,
        );
    }
    Ok(())
}
