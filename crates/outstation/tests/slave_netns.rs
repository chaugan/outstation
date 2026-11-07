//! Privileged end-to-end tests of slave-role `outstation bench` with its
//! capture (T18): outstation impersonates RTUs, a mock IEC 104 master
//! (`scripts/iec104-mock-master.py`) connects to them, and the run's own
//! capture must score the run and hold nothing but the run's sessions.
//!
//! They add listen aliases and open AF_PACKET sockets, so they are
//! `#[ignore]`d and refuse to run unless they are inside a throwaway
//! network namespace named `ostest-*` with `OUTSTATION_NETNS_TEST=1`
//! set. Never run them in the host namespace. Run them with
//! `scripts/netns-slave-test.sh`, which builds this topology and deletes
//! it again:
//!
//! ```text
//!   $NS_O (outstation, RTU listeners)        $NS_P (SCADA master side)
//!   s-o 10.79.0.1/24  <------- veth ------->  s-p 10.79.0.2/24
//!   + /32 aliases for the RTU listen IPs      route 192.168.10.0/24 dev s-p
//! ```
//!
//! Env: `OUTSTATION_SLAVE_NIC` (s-o), `OUTSTATION_SLAVE_MASTER_IP`
//! (10.79.0.2), `OUTSTATION_SLAVE_PEER_NS` (`$NS_P`), and
//! `OUTSTATION_SLAVE_OWN_IP` (10.79.0.1).

use std::collections::{BTreeSet, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const PORT: u16 = 2404;

fn require_test_netns() {
    assert_eq!(
        std::env::var("OUTSTATION_NETNS_TEST").as_deref(),
        Ok("1"),
        "set OUTSTATION_NETNS_TEST=1 and run inside an ostest-* netns \
         (scripts/netns-slave-test.sh)"
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

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set (scripts/netns-slave-test.sh)"))
}

fn repo(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(p)
}

fn fixture() -> PathBuf {
    repo("examples/synth_iec104_rtus200_ts.pcap")
}

/// RTUs of the fixture used by these tests (its server addresses are
/// 192.168.10.x).
const RTUS: [u8; 6] = [49, 67, 16, 132, 156, 106];

/// A test's working directory: a fresh temporary directory, removed on
/// drop unless `OUTSTATION_KEEP_DIRS=1`, which keeps (and prints) it so
/// a failure's report and capture can be inspected.
struct WorkDir {
    path: PathBuf,
    _tmp: Option<tempfile::TempDir>,
}

fn work_dir() -> WorkDir {
    let d = tempfile::tempdir().unwrap();
    if std::env::var("OUTSTATION_KEEP_DIRS").as_deref() == Ok("1") {
        let path = d.keep();
        eprintln!("working directory kept: {}", path.display());
        WorkDir { path, _tmp: None }
    } else {
        WorkDir {
            path: d.path().to_path_buf(),
            _tmp: Some(d),
        }
    }
}

fn write_profile(dir: &Path, p: &Value) -> PathBuf {
    let path = dir.join("run.json");
    std::fs::write(&path, p.to_string()).unwrap();
    path
}

fn bench(dir: &Path, pcap: &Path, profile: &Path, asserts: &[&str]) -> Child {
    let mut c = Command::new(env!("CARGO_BIN_EXE_outstation"));
    c.arg("bench")
        .arg("--pcap")
        .arg(pcap)
        .arg("--profile")
        .arg(profile)
        .arg("--report")
        .arg(dir.join("report.json"))
        .arg("--state-dir")
        .arg(dir.join("state"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for a in asserts {
        c.arg("--assert").arg(a);
    }
    c.spawn().unwrap()
}

/// The mock master, in `ns` (or here when `None`), against `ips`.
fn mock_master(ns: Option<&str>, ips: &[Ipv4Addr]) -> Child {
    let script = repo("scripts/iec104-mock-master.py");
    let mut c = match ns {
        Some(ns) => {
            let mut c = Command::new("ip");
            c.args(["netns", "exec", ns, "python3"]);
            c
        }
        None => Command::new("python3"),
    };
    c.arg(script)
        .args(["--port", &PORT.to_string(), "--quiet", "2"])
        .args(ips.iter().map(|i| i.to_string()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Unrelated traffic: a TCP server on `server` exchanging data with a
/// client in `client_ns`, plus probes of the listen IPs on other ports
/// and protocols, repeated for `secs`.
const NOISE: &str = r#"
import socket, sys, threading, time
server, probe, secs = sys.argv[1], sys.argv[2], float(sys.argv[3])
mode = sys.argv[4]
end = time.monotonic() + secs
if mode == "server":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((server, 2404)); s.listen(8); s.settimeout(0.5)
    while time.monotonic() < end:
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        with c:
            data = c.recv(4096)
            c.sendall(b"\x68\x04\x0b\x00\x00\x00" + data)
    sys.exit(0)
while time.monotonic() < end:
    try:
        with socket.create_connection((server, 2404), timeout=1) as c:
            c.sendall(b"\x68\x04\x07\x00\x00\x00 unrelated")
            c.recv(4096)
    except OSError:
        pass
    for port in (8080, 2405):
        try:
            socket.create_connection((probe, port), timeout=0.3).close()
        except OSError:
            pass
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.sendto(b"udp noise", (probe, 2404)); u.close()
    time.sleep(0.2)
"#;

fn noise(ns: Option<&str>, args: &[&str]) -> Child {
    let mut c = match ns {
        Some(ns) => {
            let mut c = Command::new("ip");
            c.args(["netns", "exec", ns, "python3"]);
            c
        }
        None => Command::new("python3"),
    };
    c.args(["-c", NOISE])
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_with_timeout(child: &mut Child, secs: u64) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn output(child: Child) -> String {
    let o = child.wait_with_output().unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Every frame of a classic little-endian pcap.
fn frames(path: &Path) -> Vec<Vec<u8>> {
    let b = std::fs::read(path).unwrap();
    assert_eq!(&b[..4], &[0xd4, 0xc3, 0xb2, 0xa1], "not a classic LE pcap");
    let mut v = Vec::new();
    let mut off = 24;
    while off + 16 <= b.len() {
        let incl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
        v.push(b[off + 16..off + 16 + incl].to_vec());
        off += 16 + incl;
    }
    v
}

/// (src, sport, dst, dport, seq, ack, flags, payload length) of a TCP
/// frame; `None` for anything else.
type Seg = (Ipv4Addr, u16, Ipv4Addr, u16, u32, u32, u8, usize);

fn tcp_seg(f: &[u8]) -> Option<Seg> {
    if f.len() < 34 || f[12..14] != [0x08, 0x00] || f[23] != 6 {
        return None;
    }
    let ihl = usize::from(f[14] & 0x0f) * 4;
    let t = 14 + ihl;
    if f.len() < t + 20 {
        return None;
    }
    let ip = |o: usize| Ipv4Addr::new(f[o], f[o + 1], f[o + 2], f[o + 3]);
    let be16 = |o: usize| u16::from_be_bytes([f[o], f[o + 1]]);
    let be32 = |o: usize| u32::from_be_bytes([f[o], f[o + 1], f[o + 2], f[o + 3]]);
    let total = usize::from(be16(16));
    let doff = usize::from(f[t + 12] >> 4) * 4;
    Some((
        ip(26),
        be16(t),
        ip(30),
        be16(t + 2),
        be32(t + 4),
        be32(t + 8),
        f[t + 13],
        total.saturating_sub(ihl + doff),
    ))
}

/// The capture holds only TCP to or from (listen ip, PORT), has
/// traffic for every listener, and no frame twice (byte-identical).
fn assert_capture_is_private(capture: &Path, listen: &[Ipv4Addr]) {
    let set: HashSet<Ipv4Addr> = listen.iter().copied().collect();
    let fs = frames(capture);
    assert!(!fs.is_empty(), "empty capture");
    let mut seen_eps = BTreeSet::new();
    let mut seen_frames: HashSet<&[u8]> = HashSet::new();
    let mut dups = 0;
    for (i, f) in fs.iter().enumerate() {
        let s = tcp_seg(f).unwrap_or_else(|| panic!("frame {i} is not IPv4 TCP: {f:02x?}"));
        let ours = (set.contains(&s.0) && s.1 == PORT) || (set.contains(&s.2) && s.3 == PORT);
        assert!(ours, "frame {i} is not a session of this run: {s:?}");
        seen_eps.insert(if s.1 == PORT { s.0 } else { s.2 });
        // A frame captured twice (e.g. both copies of a loopback frame)
        // is byte-identical. A TCP retransmission is not: it carries a
        // new IP ID and TCP timestamp, and under load the kernel
        // legitimately sends some (tail-loss probes), so compare whole
        // frames, not segment headers.
        if !seen_frames.insert(f.as_slice()) {
            dups += 1;
        }
    }
    assert_eq!(
        seen_eps.len(),
        set.len(),
        "listeners without captured traffic"
    );
    assert_eq!(dups, 0, "{dups} frames captured twice");
    eprintln!(
        "capture {}: {} frames, all from {} listener(s)",
        capture.display(),
        fs.len(),
        seen_eps.len()
    );
}

fn report(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("report.json")).unwrap()).unwrap()
}

/// Run a slave bench against the mock master and return the report.
fn run_slave_bench(
    dir: &Path,
    pcap: &Path,
    profile: Value,
    listen: &[Ipv4Addr],
    master_ns: Option<&str>,
    noise_runs: Vec<Child>,
) -> Value {
    let p = write_profile(dir, &profile);
    let mut b = bench(
        dir,
        pcap,
        &p,
        &["score>=99", "sessions_failed==0", "verdict_failures==0"],
    );
    let mut m = mock_master(master_ns, listen);
    let m_status = wait_with_timeout(&mut m, 180);
    let m_out = output(m);
    let b_status = wait_with_timeout(&mut b, 180);
    let b_out = output(b);
    for mut n in noise_runs {
        let _ = n.kill();
        let _ = n.wait();
    }
    let r = report(dir);
    assert!(
        m_status.is_some_and(|s| s.success()),
        "mock master: {m_status:?}\n{m_out}\nbench: {b_out}"
    );
    assert_eq!(
        b_status.and_then(|s| s.code()),
        Some(0),
        "bench: {b_out}\nmaster: {m_out}\nreport: {r:#}"
    );
    r
}

fn check_report(r: &Value, n: usize) {
    assert_eq!(r["passed"], true, "{r:#}");
    assert_eq!(r["run"]["status"], "completed", "{r:#}");
    assert_eq!(r["run"]["role"], "slave");
    assert_eq!(r["run"]["sources"], n);
    assert_eq!(r["run"]["sources_failed"], 0);
    assert_eq!(
        r["run"]["benchmark"]["captured_dropped"], 0,
        "the capture lost frames"
    );
    let score = r["metrics"]["score"].as_f64().unwrap();
    eprintln!("verdict {} score {score}", r["analysis"]["verdict"]);
    assert!(score >= 99.0, "score {score}: {:#}", r["analysis"]);
    assert_eq!(r["analysis"]["role"], "slave");
    assert_eq!(r["analysis"]["fleet"]["unpaired"], 0, "{:#}", r["analysis"]);
    assert_eq!(r["analysis"]["slaves"].as_array().unwrap().len(), n);
}

/// RTUs on a LAN: listen aliases on the NIC, the master in another
/// namespace, unrelated traffic on the same NIC and port.
#[test]
#[ignore = "privileged: run via scripts/netns-slave-test.sh inside ostest-* netns"]
fn slave_bench_scores_full_marks_over_a_lan() {
    require_test_netns();
    let peer_ns = env("OUTSTATION_SLAVE_PEER_NS");
    let own_ip = env("OUTSTATION_SLAVE_OWN_IP");
    let listen: Vec<Ipv4Addr> = RTUS
        .iter()
        .map(|&n| Ipv4Addr::new(192, 168, 10, n))
        .collect();
    let work = work_dir();
    let dir = work.path.as_path();
    let noise_runs = vec![
        // An unrelated IEC 104 server on this host's own address...
        noise(None, &[&own_ip, "0.0.0.0", "40", "server"]),
        // ...its client, and probes of the listen IPs on other ports
        // and protocols, from the master's namespace.
        noise(
            Some(&peer_ns),
            &[&own_ip, &listen[0].to_string(), "40", "client"],
        ),
    ];
    let r = run_slave_bench(
        dir,
        &fixture(),
        json!({
            "mode": "benchmark",
            "role": "slave",
            "target_ip": env("OUTSTATION_SLAVE_MASTER_IP"),
            "alias_iface": env("OUTSTATION_SLAVE_NIC"),
            "selected_rtus": listen,
            "warmup_secs": 0,
            "iterations": 1
        }),
        &listen,
        Some(&peer_ns),
        noise_runs,
    );
    check_report(&r, listen.len());
    let capture = PathBuf::from(r["capture"].as_str().unwrap());
    assert_capture_is_private(&capture, &listen);
    // The listen aliases are gone again.
    let a = Command::new("ip").args(["-o", "addr"]).output().unwrap();
    let a = String::from_utf8_lossy(&a.stdout);
    assert!(!a.contains("192.168.10."), "aliases left behind: {a}");
}

/// Copy of the fixture with every 192.168.x.y address moved to
/// 127.0.x.y (RTUs 127.0.10.x, master 127.0.86.1).
fn loopback_fixture(dir: &Path) -> PathBuf {
    let mut b = std::fs::read(fixture()).unwrap();
    let mut off = 24;
    while off + 16 <= b.len() {
        let incl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
        let f = off + 16;
        if incl >= 34 && b[f + 12..f + 14] == [0x08, 0x00] {
            for a in [f + 26, f + 30] {
                if b[a..a + 2] == [192, 168] {
                    b[a] = 127;
                    b[a + 1] = 0;
                }
            }
            // IPv4 header checksum.
            let ihl = usize::from(b[f + 14] & 0x0f) * 4;
            b[f + 24] = 0;
            b[f + 25] = 0;
            let mut sum: u32 = 0;
            for w in b[f + 14..f + 14 + ihl].chunks(2) {
                sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
            }
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let c = !(sum as u16);
            b[f + 24..f + 26].copy_from_slice(&c.to_be_bytes());
        }
        off += 16 + incl;
    }
    let p = dir.join("rtus_on_loopback.pcap");
    std::fs::write(&p, b).unwrap();
    p
}

/// RTUs on 127/8 (T07b: local, no alias) with the master on this host:
/// the sessions run over `lo`, captured once each, with unrelated
/// loopback traffic on the same port left out.
#[test]
#[ignore = "privileged: run via scripts/netns-slave-test.sh inside ostest-* netns"]
fn slave_bench_on_loopback_rtus() {
    require_test_netns();
    let listen: Vec<Ipv4Addr> = RTUS[..4]
        .iter()
        .map(|&n| Ipv4Addr::new(127, 0, 10, n))
        .collect();
    let work = work_dir();
    let dir = work.path.as_path();
    let pcap = loopback_fixture(dir);
    let noise_runs = vec![
        noise(None, &["127.0.0.5", "0.0.0.0", "40", "server"]),
        noise(None, &["127.0.0.5", &listen[0].to_string(), "40", "client"]),
    ];
    let r = run_slave_bench(
        dir,
        &pcap,
        json!({
            "mode": "benchmark",
            "role": "slave",
            "target_ip": "127.0.0.1",
            "selected_rtus": listen,
            "warmup_secs": 0,
            "iterations": 1
        }),
        &listen,
        None,
        noise_runs,
    );
    check_report(&r, listen.len());
    let capture = PathBuf::from(r["capture"].as_str().unwrap());
    assert_capture_is_private(&capture, &listen);
}
