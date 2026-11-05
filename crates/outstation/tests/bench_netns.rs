//! Privileged end-to-end tests of `outstation bench` (T09).
//!
//! They build bridges and veths, enslave a NIC and start a mirror
//! capture, so they are `#[ignore]`d and refuse to run unless they are
//! inside a throwaway network namespace named `ostest-*` with
//! `OUTSTATION_NETNS_TEST=1` set. Never run them in the host namespace.
//!
//! Run them with `scripts/netns-bench-test.sh`, which creates four
//! namespaces (outstation host, LAN switch + target, LAN attacker,
//! management network; see the script's header), starts a mock IEC 104
//! slave (`scripts/iec104-mock-slave.py`) on 10.77.0.1:2404, runs this
//! binary with `--ignored --test-threads=1` in the outstation-host
//! namespace and deletes them all again:
//!
//! ```sh
//! NS_A=ostest-me-a NS_T=ostest-me-t NS_X=ostest-me-x NS_M=ostest-me-m \
//!     scripts/netns-bench-test.sh
//! ```
//!
//! Env: `OUTSTATION_BENCH_TARGET` (mock slave IP),
//! `OUTSTATION_BENCH_NIC` (this namespace's LAN NIC),
//! `OUTSTATION_NS_LAN` (attacker namespace on the LAN, 10.77.0.9) and
//! `OUTSTATION_NS_MGMT` (management namespace behind this host,
//! 10.66.0.2; this host has 10.66.0.1 there and a host-only
//! 10.88.0.1).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};

fn require_test_netns() {
    assert_eq!(
        std::env::var("OUTSTATION_NETNS_TEST").as_deref(),
        Ok("1"),
        "set OUTSTATION_NETNS_TEST=1 and run inside an ostest-* netns \
         (scripts/netns-bench-test.sh)"
    );
    let out = Command::new("ip")
        .args(["netns", "identify"])
        .output()
        .expect("run `ip netns identify`");
    let ns = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        ns.starts_with("ostest-"),
        "refusing to run outside an ostest-* network namespace (current: {ns:?})"
    );
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/synth_iec104_rtus200_ts.pcap")
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set (scripts/netns-bench-test.sh)"))
}

/// Write a master-role profile into `dir`.
fn profile(dir: &Path, extra: Value) -> PathBuf {
    let mut p = json!({
        "mode": "benchmark",
        "role": "master",
        "target_ip": env("OUTSTATION_BENCH_TARGET"),
        "nic": env("OUTSTATION_BENCH_NIC"),
        // The veth carries this namespace's default route: protected
        // unless forced.
        "force": true,
        "warmup_secs": 0,
        "iterations": 1
    });
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    let path = dir.join("run.json");
    std::fs::write(&path, p.to_string()).unwrap();
    path
}

fn bench_cmd(dir: &Path, profile: &Path, asserts: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_outstation"));
    c.arg("bench")
        .arg("--pcap")
        .arg(fixture())
        .arg("--profile")
        .arg(profile)
        .arg("--report")
        .arg(dir.join("report.json"))
        .arg("--state-dir")
        .arg(dir.join("state"));
    for a in asserts {
        c.arg("--assert").arg(a);
    }
    c
}

fn report(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("report.json")).unwrap()).unwrap()
}

fn no_outstation_ifaces() -> bool {
    let out = Command::new("ip").args(["-o", "link"]).output().unwrap();
    !String::from_utf8_lossy(&out.stdout).contains(": pcr")
}

#[test]
#[ignore = "privileged: run via scripts/netns-bench-test.sh inside ostest-* netns"]
fn bench_passes_and_fails_on_assertions() {
    require_test_netns();
    let dir = tempfile::tempdir().unwrap();
    let p = profile(dir.path(), json!({}));
    let out = bench_cmd(
        dir.path(),
        &p,
        &["sessions_failed==0", "p99_ms<=1000", "verdict_failures==0"],
    )
    .output()
    .unwrap();
    let r = report(dir.path());
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}\nreport: {r:#}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(r["passed"], true);
    assert_eq!(r["run"]["status"], "completed");
    assert!(r["analysis"].is_object(), "{r:#}");
    assert!(r["metrics"]["score"].is_number());
    assert!(Path::new(r["capture"].as_str().unwrap()).is_file());
    assert!(no_outstation_ifaces(), "run left interfaces behind");

    // An impossible assertion: exit 1, run itself fine.
    let out = bench_cmd(dir.path(), &p, &["score>100"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let r = report(dir.path());
    assert_eq!(r["error"], Value::Null);
    assert_eq!(r["assertions"][0]["passed"], false);
}

#[test]
#[ignore = "privileged: run via scripts/netns-bench-test.sh inside ostest-* netns"]
fn sigint_stops_the_run_and_cleans_up() {
    require_test_netns();
    let dir = tempfile::tempdir().unwrap();
    // Unbounded, paced: runs until interrupted.
    let p = profile(
        dir.path(),
        json!({"iterations": 0, "pacing": "original", "speed": 1.0}),
    );
    let mut child = bench_cmd(dir.path(), &p, &[]).spawn().unwrap();
    std::thread::sleep(Duration::from_secs(4));
    assert!(!no_outstation_ifaces(), "run never built its topology");
    // SAFETY: plain kill(2) on our own child.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(2));
    let r = report(dir.path());
    assert_eq!(r["interrupted"], true);
    assert!(r["error"].as_str().unwrap().contains("SIGINT"), "{r:#}");
    assert!(no_outstation_ifaces(), "SIGINT left interfaces behind");
    assert_eq!(tagged_rules(), 0, "SIGINT left iptables rules behind");
    let state = dir.path().join("state");
    for f in ["state-guards.txt", "state-aliases.txt"] {
        let left = std::fs::read_to_string(state.join(f)).unwrap_or_default();
        assert!(left.trim().is_empty(), "{f} still has entries: {left}");
    }
}

/// iptables rules tagged by any outstation run, raw + filter.
fn tagged_rules() -> usize {
    ["raw", "filter"]
        .iter()
        .map(|t| {
            let out = Command::new("iptables")
                .args(["-t", t, "-S"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| l.contains("outstation-run-"))
                .count()
        })
        .sum()
}

/// Run `args` inside namespace `ns`; true when it exits 0.
fn in_ns(ns: &str, args: &[&str]) -> bool {
    Command::new("ip")
        .args(["netns", "exec", ns])
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn in_ns_out(ns: &str, args: &[&str]) -> String {
    let o = Command::new("ip")
        .args(["netns", "exec", ns])
        .args(args)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn set_ip_forward(on: bool) {
    std::fs::write(
        "/proc/sys/net/ipv4/ip_forward",
        if on { "1\n" } else { "0\n" },
    )
    .unwrap();
}

/// ICMP packets the management namespace's INPUT chain has seen.
fn mgmt_icmp_seen(mgmt: &str) -> u64 {
    let out = in_ns_out(mgmt, &["iptables", "-nvxL", "INPUT"]);
    out.lines()
        .find(|l| l.contains("icmp"))
        .and_then(|l| l.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// A LAN host that knows a session port's address and MAC can neither
/// reach the outstation host's own addresses through it nor route
/// through the host into its management network, even with
/// `ip_forward=1` (which also resets every interface's `forwarding`).
#[test]
#[ignore = "privileged: run via scripts/netns-bench-test.sh inside ostest-* netns"]
fn lan_cannot_reach_or_route_through_session_ports() {
    require_test_netns();
    let lan = env("OUTSTATION_NS_LAN");
    let mgmt = env("OUTSTATION_NS_MGMT");
    let session_ip = "192.168.86.1"; // the fixture's master address
    let dir = tempfile::tempdir().unwrap();
    let p = profile(
        dir.path(),
        json!({"iterations": 0, "pacing": "original", "speed": 1.0}),
    );
    let mut child = bench_cmd(dir.path(), &p, &[])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let a = Command::new("ip").args(["-o", "addr"]).output().unwrap();
        if String::from_utf8_lossy(&a.stdout).contains(&format!("{session_ip}/32")) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "session port never came up"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_secs(1));
    in_ns(
        &mgmt,
        &["iptables", "-I", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
    );

    // Count what reaches this host's stack (mangle INPUT runs after
    // the raw-table DROP), and what reaches the management network.
    for dst in [session_ip, "10.88.0.1"] {
        let d = format!("{dst}/32");
        let ok = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-I",
                "INPUT",
                "-s",
                "10.77.0.9/32",
                "-d",
                &d,
                "-p",
                "icmp",
            ])
            .status()
            .unwrap()
            .success();
        assert!(ok, "install counter for {dst}");
    }
    let host_seen = |dst: &str| -> u64 {
        let out = Command::new("iptables")
            .args(["-t", "mangle", "-nvxL", "INPUT"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains(dst) && l.contains("10.77.0.9"))
            .filter_map(|l| l.split_whitespace().next()?.parse::<u64>().ok())
            .sum()
    };

    let attack = || -> Vec<String> {
        let mut reached = Vec::new();
        // The session address itself: only the target may talk to it.
        let before = host_seen(session_ip);
        in_ns(&lan, &["ping", "-c", "2", "-W", "1", session_ip]);
        if host_seen(session_ip) > before {
            reached.push(format!("host stack via session address {session_ip}"));
        }
        // A host-only address and the management network, via the
        // session port's MAC.
        for dst in ["10.88.0.1", "10.66.0.2"] {
            let route = format!("{dst}/32");
            in_ns(
                &lan,
                &[
                    "ip", "route", "replace", &route, "via", session_ip, "dev", "os-x", "onlink",
                ],
            );
            let (h0, m0) = (host_seen(dst), mgmt_icmp_seen(&mgmt));
            if in_ns(&lan, &["ping", "-c", "2", "-W", "1", dst]) {
                reached.push(format!("ping {dst} answered"));
            }
            if host_seen(dst) > h0 {
                reached.push(format!("host stack accepted packets for {dst}"));
            }
            if mgmt_icmp_seen(&mgmt) > m0 {
                reached.push(format!("packets for {dst} forwarded into the mgmt network"));
            }
        }
        reached
    };

    // The attacker could resolve the session port (the attack path is
    // real), and still reaches nothing.
    set_ip_forward(false);
    let reached = attack();
    let neigh = in_ns_out(&lan, &["ip", "neigh", "show", session_ip]);
    set_ip_forward(true);
    let reached_fwd = attack();
    set_ip_forward(false);

    // SAFETY: plain kill(2) on our own child.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let _ = child.wait();
    assert!(
        neigh.contains("lladdr"),
        "attacker never resolved {session_ip}: {neigh:?}"
    );
    assert!(reached.is_empty(), "LAN reached: {reached:?}");
    assert!(
        reached_fwd.is_empty(),
        "with ip_forward=1, LAN reached: {reached_fwd:?}"
    );
    assert!(no_outstation_ifaces());
    assert_eq!(tagged_rules(), 0);
}
