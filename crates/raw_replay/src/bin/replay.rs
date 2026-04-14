//! `replay`: load a pcap, filter to one source IP, rewrite the
//! destination, and inject it on an interface with pcap-accurate timing.
//!
//! This is a development harness for the `raw_replay` crate — the
//! orchestrator (`sched`) will eventually own the full multi-source
//! lifecycle. For now this binary gives us something we can point at a
//! veth pair and measure jitter on.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use pcapload::load;
use raw_replay::{plan_for_source, run_plan, try_set_realtime, Pace, RawReplayer};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "replay", about = "Replay one source from a pcap onto an interface")]
struct Cli {
    /// Pcap file to read.
    #[arg(long)]
    pcap: PathBuf,

    /// Source IP in the pcap to replay (all matching packets).
    #[arg(long)]
    src: Ipv4Addr,

    /// Egress interface (already up, typically a TAP on a bridge).
    #[arg(long)]
    iface: String,

    /// Rewrite destination IP to this value before sending. If omitted,
    /// frames go out with the original dst IP and dst MAC untouched.
    #[arg(long)]
    target_ip: Option<Ipv4Addr>,

    /// Rewrite destination MAC to this value (format: XX:XX:XX:XX:XX:XX).
    /// Required if --target-ip is set.
    #[arg(long)]
    target_mac: Option<String>,

    /// Replay speed multiplier. Ignored in top-speed mode.
    #[arg(long, default_value_t = 1.0)]
    speed: f64,

    /// Ignore pcap timestamps and blast packets back-to-back.
    #[arg(long)]
    top_speed: bool,

    /// Try to promote the replay thread to SCHED_FIFO.
    #[arg(long)]
    realtime: bool,
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("MAC must be XX:XX:XX:XX:XX:XX");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).context("bad hex in MAC")?;
    }
    Ok(out)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    let pcap = load(&cli.pcap).context("load pcap")?;
    println!(
        "loaded {} packets, {} sources, {} tcp flows",
        pcap.packets.len(),
        pcap.sources.len(),
        pcap.flows.len()
    );

    let mut plan = plan_for_source(&pcap, cli.src)?;
    println!("source {} → {} frames", cli.src, plan.len());

    // Optional rewrite pass.
    if let Some(target_ip) = cli.target_ip {
        let mac_s = cli
            .target_mac
            .as_deref()
            .context("--target-mac is required when --target-ip is set")?;
        let mac = parse_mac(mac_s)?;
        for sf in &mut plan.frames {
            rewrite::rewrite_in_place(&mut sf.frame, target_ip, mac)
                .context("frame rewrite failed")?;
        }
        println!("rewrote frames to target {target_ip} / {mac_s}");
    }

    let replayer = RawReplayer::bind(&cli.iface).context("bind AF_PACKET")?;

    if cli.realtime {
        try_set_realtime(50);
    }

    let pace = if cli.top_speed {
        Pace::TopSpeed
    } else {
        Pace::Original { speed: cli.speed }
    };

    println!("replaying on {} ({:?})", cli.iface, pace);
    let stats = run_plan(&replayer, &plan, pace);
    println!("-- stats --");
    println!("sent                : {}", stats.sent);
    println!("bytes               : {}", stats.bytes);
    println!("send errors         : {}", stats.send_errors);
    println!(
        "elapsed             : {:.3} ms",
        stats.elapsed_ns as f64 / 1e6
    );
    println!(
        "mean |jitter|       : {:.1} µs",
        stats.mean_abs_jitter_ns as f64 / 1e3
    );
    println!(
        "p99 |jitter|        : {:.1} µs",
        stats.p99_abs_jitter_ns as f64 / 1e3
    );
    println!(
        "max signed jitter   : {:.1} µs",
        stats.max_jitter_ns as f64 / 1e3
    );
    Ok(())
}
