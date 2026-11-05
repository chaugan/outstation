//! Top-level `outstation` binary — the user-facing CLI: pcap
//! inspection, a synchronous `run`, the web UI (`serve`), a headless
//! benchmark with assertions (`bench`) and host cleanup (`cleanup`).

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
    ListSources { pcap: PathBuf },
    /// List all registered protocol-aware replayer modules.
    ListProtocols,
    /// Replay a pcap. Every IPv4 source gets its own TAP on an
    /// auto-managed bridge; the bridge optionally enslaves a physical
    /// NIC for real egress.
    Run(RunArgs),
    /// Start the web UI (axum backend + embedded SPA).
    Serve(ServeArgs),
    /// Run one benchmark headless (same code path as the web UI),
    /// analyse its own capture, check assertions and write a JSON
    /// report. Exit 0 = all assertions passed, 1 = an assertion
    /// failed, 2 = the run failed or was interrupted.
    Bench(BenchArgs),
    /// Undo host network changes left by runs (IP aliases, bridges,
    /// veths and, once available, iptables/sysctl state). Safe to run
    /// at any time; used as the systemd unit's ExecStopPost.
    Cleanup {
        /// State directory (default: parent of OUTSTATION_LIBRARY_DIR,
        /// i.e. /var/lib/outstation).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Address to bind, e.g. 127.0.0.1:8080. The systemd unit binds
    /// 0.0.0.0:8080 for LAN access.
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: std::net::SocketAddr,

    /// Extra Host header names to accept (repeatable or
    /// comma-separated), on top of IP literals, localhost and this
    /// machine's host names. Also read from OUTSTATION_ALLOW_HOSTS.
    #[arg(long = "allow-host", value_name = "HOST")]
    allow_host: Vec<String>,

    /// Keep run history in memory only. Without this flag the server
    /// refuses to start when the run database cannot be opened.
    #[arg(long)]
    ephemeral: bool,

    /// Largest accepted upload (library and analysis), in MiB.
    /// Default 1024 or OUTSTATION_MAX_UPLOAD_MB.
    #[arg(long, value_name = "MIB")]
    max_upload_mb: Option<u64>,

    /// Total size cap for stored replay captures, in MiB. Oldest
    /// captures are evicted first. Default 10240 or
    /// OUTSTATION_CAPTURE_MAX_MB.
    #[arg(long, value_name = "MIB")]
    capture_max_mb: Option<u64>,

    /// Do not analyse finished benchmark runs automatically. Also
    /// OUTSTATION_AUTO_ANALYZE=0.
    #[arg(long)]
    no_auto_analyze: bool,
}

#[derive(clap::Args)]
struct BenchArgs {
    /// Source pcap. Without it, the profile's `pcap_id` is looked up in
    /// `<state-dir>/library`.
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// Run request JSON: a `POST /api/run` body or a profile exported
    /// from `GET /api/profiles/:id`. `mode` defaults to benchmark.
    #[arg(long)]
    profile: PathBuf,

    /// Assertion `<metric><op><number>`, repeatable. Metrics: score,
    /// p50_ms, p90_ms, p99_ms, max_ms, throughput, sessions_failed,
    /// delivered_pct, verdict_failures. Ops: >=, <=, ==, >, <.
    #[arg(long = "assert", value_name = "EXPR", value_parser = parse_assertion)]
    asserts: Vec<webui::bench::Assertion>,

    /// Write the JSON report here (`-` = stdout).
    #[arg(long)]
    report: Option<PathBuf>,

    /// State directory for host-state journals and captures (default:
    /// parent of OUTSTATION_LIBRARY_DIR, i.e. /var/lib/outstation).
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Mirror capture path (default
    /// `<state-dir>/captures/bench_<run id>.pcap`).
    #[arg(long)]
    capture: Option<PathBuf>,

    /// Analyse in "correct" mode: the target is the device recorded in
    /// the pcap, so its replies are compared byte for byte too.
    #[arg(long)]
    correct: bool,
}

fn parse_assertion(s: &str) -> Result<webui::bench::Assertion, String> {
    s.parse()
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
}

/// ANSI colours only on an interactive terminal, never under journald
/// (F079).
fn use_ansi() -> bool {
    use std::io::IsTerminal;
    std::env::var_os("JOURNAL_STREAM").is_none()
        && std::env::var_os("NO_COLOR").is_none()
        && std::io::stdout().is_terminal()
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(use_ansi())
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ListSources { pcap } => {
            let p = load(&pcap)?;
            println!(
                "{} sources, {} flows, {} packets, {} non-ip",
                p.sources.len(),
                p.flows.len(),
                p.packets.len(),
                p.non_ip_count
            );
            for (ip, s) in &p.sources {
                println!(
                    "  {:<15} {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  {:>8} pkts  {:>3} flows{}",
                    ip,
                    s.src_mac[0],
                    s.src_mac[1],
                    s.src_mac[2],
                    s.src_mac[3],
                    s.src_mac[4],
                    s.src_mac[5],
                    s.packet_count,
                    s.flow_indices.len(),
                    if s.mac_collision {
                        "  MAC collision"
                    } else {
                        ""
                    }
                );
            }
        }
        Cmd::ListProtocols => {
            let registry = proto_registry::build();
            println!("{:<20} {:<8} well-known ports", "name", "status");
            for m in &registry {
                let status = match m.readiness() {
                    protoplay::Readiness::Ready => "ready",
                    protoplay::Readiness::Stub => "stub",
                };
                let ports: Vec<String> =
                    m.well_known_ports().iter().map(|p| p.to_string()).collect();
                println!("{:<20} {:<8} {}", m.name(), status, ports.join(","));
            }
        }
        Cmd::Run(args) => run_cmd(args)?,
        Cmd::Serve(args) => {
            let mut cfg = webui::ServeConfig::from_env(args.bind);
            for h in &args.allow_host {
                cfg.allow_hosts.extend(webui::split_hosts(h));
            }
            cfg.ephemeral = args.ephemeral;
            if let Some(mb) = args.max_upload_mb {
                cfg.max_upload_bytes = mb.saturating_mul(1024 * 1024);
            }
            if let Some(mb) = args.capture_max_mb {
                cfg.capture_max_total_bytes = mb.saturating_mul(1024 * 1024);
            }
            if args.no_auto_analyze {
                cfg.auto_analyze = false;
            }
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move { webui::serve(cfg).await })?;
        }
        Cmd::Bench(args) => {
            let code = bench_cmd(args);
            std::process::exit(code);
        }
        Cmd::Cleanup { state_dir } => {
            let dir = state_dir.unwrap_or_else(webui::default_state_dir);
            webui::host_cleanup(&dir)?;
        }
    }
    Ok(())
}

fn bench_cmd(args: BenchArgs) -> i32 {
    let opts = webui::bench::BenchOptions {
        pcap: args.pcap,
        profile: args.profile,
        asserts: args.asserts,
        report: args.report,
        state_dir: args.state_dir.unwrap_or_else(webui::default_state_dir),
        capture: args.capture,
        correct_mode: args.correct,
    };
    let mut report = webui::bench::run(&opts);
    if let Some(path) = &opts.report {
        if let Err(e) = webui::bench::write_report(path, &report) {
            eprintln!("error: {e:#}");
            report.exit_code = webui::bench::EXIT_RUN_ERROR;
        }
    }
    if opts.report.as_deref() != Some(std::path::Path::new("-")) {
        print!("{}", webui::bench::summary_text(&report));
    }
    report.exit_code
}

fn run_cmd(args: RunArgs) -> Result<()> {
    let pcap = load(&args.pcap).context("load pcap")?;
    let pcap = Arc::new(pcap);
    let target_mac = parse_mac(&args.target_mac)?;

    let cfg = RunConfig {
        target_ip: args.target_ip,
        target_mac,
        bridge_name: Some(args.bridge),
        tap_prefix: Some(args.tap_prefix),
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
        ..RunConfig::default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_flags_parse() {
        let cli = Cli::try_parse_from([
            "outstation",
            "serve",
            "--bind",
            "0.0.0.0:8080",
            "--allow-host",
            "a.lan,b.lan",
            "--allow-host",
            "c.lan",
            "--ephemeral",
            "--max-upload-mb",
            "10",
        ])
        .unwrap();
        let Cmd::Serve(a) = cli.cmd else {
            panic!("not serve")
        };
        assert_eq!(a.bind.port(), 8080);
        assert!(a.ephemeral);
        let hosts: Vec<String> = a
            .allow_host
            .iter()
            .flat_map(|h| webui::split_hosts(h))
            .collect();
        assert_eq!(hosts, ["a.lan", "b.lan", "c.lan"]);
        assert_eq!(a.max_upload_mb, Some(10));
    }

    #[test]
    fn bench_flags_parse() {
        let cli = Cli::try_parse_from([
            "outstation",
            "bench",
            "--pcap",
            "/x.pcap",
            "--profile",
            "run.json",
            "--assert",
            "score>=99",
            "--assert",
            "p99_ms<=500",
            "--assert",
            "sessions_failed==0",
            "--report",
            "out.json",
            "--state-dir",
            "/s",
        ])
        .unwrap();
        let Cmd::Bench(b) = cli.cmd else {
            panic!("not bench")
        };
        assert_eq!(b.asserts.len(), 3);
        assert_eq!(b.asserts[1].to_string(), "p99_ms<=500");
        assert_eq!(b.report, Some(PathBuf::from("out.json")));
        assert_eq!(b.state_dir, Some(PathBuf::from("/s")));
        // A bad assertion is a usage error before anything runs.
        assert!(Cli::try_parse_from([
            "outstation",
            "bench",
            "--profile",
            "r.json",
            "--assert",
            "latency<1"
        ])
        .is_err());
        let Cmd::Serve(a) = Cli::try_parse_from(["outstation", "serve", "--no-auto-analyze"])
            .unwrap()
            .cmd
        else {
            panic!("not serve")
        };
        assert!(a.no_auto_analyze);
    }

    #[test]
    fn serve_defaults_to_loopback_and_cleanup_parses() {
        let Cmd::Serve(a) = Cli::try_parse_from(["outstation", "serve"]).unwrap().cmd else {
            panic!("not serve")
        };
        assert_eq!(a.bind.to_string(), "127.0.0.1:8080");
        let Cmd::Cleanup { state_dir } =
            Cli::try_parse_from(["outstation", "cleanup", "--state-dir", "/x"])
                .unwrap()
                .cmd
        else {
            panic!("not cleanup")
        };
        assert_eq!(state_dir, Some(PathBuf::from("/x")));
    }
}
