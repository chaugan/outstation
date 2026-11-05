//! N15: a benchmark whose capture failed must not be judged as
//! `no_delivery`. Unprivileged slave-role run on loopback (the re-audit
//! repro): the sessions work, but the AF_PACKET capture is refused, so
//! the capture file holds only its header. `outstation bench` must
//! exit 2 with "capture unavailable" and the run's warnings, instead of
//! failing an assertion (exit 1) on a false analysis.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn repo(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(p)
}

fn python_ok() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn failed_capture_is_a_run_error_not_a_verdict() {
    if !python_ok() {
        eprintln!("skipped: python3 not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("lo2.pcap");
    let st = Command::new("python3")
        .arg(repo("examples/gen_iec104_traffic.py"))
        .args([
            "-n",
            "2",
            "-d",
            "2",
            "--subnet",
            "127.0.10.0/24",
            "--master-ip",
            "127.0.0.1",
            "--seed",
            "7",
            "--start-time",
            "1700000000",
            "-o",
        ])
        .arg(&pcap)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "generator failed");
    let profile = dir.path().join("prof.json");
    std::fs::write(
        &profile,
        r#"{"mode":"benchmark","role":"slave","target_ip":"127.0.0.1","pacing":"fast",
            "proto_config":"{\"session\":{\"idle_serve_secs\":1}}","warmup_secs":0}"#,
    )
    .unwrap();
    let report = dir.path().join("out.json");
    let state = dir.path().join("state");
    let bench = Command::new(env!("CARGO_BIN_EXE_outstation"))
        .arg("bench")
        .arg("--pcap")
        .arg(&pcap)
        .arg("--profile")
        .arg(&profile)
        .args(["--assert", "score>=99"])
        .arg("--report")
        .arg(&report)
        .arg("--state-dir")
        .arg(&state)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let master = Command::new("python3")
        .arg(repo("scripts/iec104-mock-master.py"))
        .args(["--port", "2404", "--quiet", "1", "--connect-timeout", "20"])
        .args(["127.0.10.2", "127.0.10.3"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut bench = bench;
    while bench.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "bench did not finish");
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = bench.wait_with_output().unwrap();
    let m = master.wait_with_output().unwrap();
    let text = format!(
        "{}{}\nmaster: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&m.stdout)
    );
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    let packets = r["run"]["benchmark"]["captured_packets"]
        .as_u64()
        .unwrap_or(0);
    if packets > 0 {
        eprintln!("skipped: the capture worked here (privileged runner?): {text}");
        return;
    }
    assert!(
        r["run"]["benchmark"]["total_messages_sent"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "the sessions sent nothing; the repro did not run: {text}"
    );
    assert_eq!(out.status.code(), Some(2), "{text}");
    let err = r["error"].as_str().unwrap_or("");
    assert!(err.contains("capture unavailable"), "{r:#}");
    assert!(
        r["analysis_error"]
            .as_str()
            .unwrap_or("")
            .contains("capture unavailable"),
        "{r:#}"
    );
    assert!(r["analysis"].is_null(), "no verdict on a failed capture");
    assert!(text.contains("capture unavailable"), "{text}");
}
