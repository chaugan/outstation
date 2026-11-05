//! Privileged end-to-end tests of `outstation bench` (T09).
//!
//! They build bridges and veths, enslave a NIC and start a mirror
//! capture, so they are `#[ignore]`d and refuse to run unless they are
//! inside a throwaway network namespace named `ostest-*` with
//! `OUTSTATION_NETNS_TEST=1` set. Never run them in the host namespace.
//!
//! Run them with `scripts/netns-bench-test.sh`, which creates two
//! namespaces joined by a veth pair, starts a mock IEC 104 slave
//! (`scripts/iec104-mock-slave.py`) on 10.77.0.1:2404 in the second,
//! runs this binary with `--ignored --test-threads=1` in the first and
//! deletes both namespaces again:
//!
//! ```sh
//! NS_A=ostest-me-1 NS_B=ostest-me-2 scripts/netns-bench-test.sh
//! ```
//!
//! Env: `OUTSTATION_BENCH_TARGET` (mock slave IP) and
//! `OUTSTATION_BENCH_NIC` (this namespace's end of the veth pair).

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
    let state = dir.path().join("state");
    for f in ["state-guards.txt", "state-aliases.txt"] {
        let left = std::fs::read_to_string(state.join(f)).unwrap_or_default();
        assert!(left.trim().is_empty(), "{f} still has entries: {left}");
    }
}
