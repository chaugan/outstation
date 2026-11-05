//! Privileged tests of what a run puts on the wire and into its own
//! capture (T16b: B1, O1, O2).
//!
//! They build bridges and veths, enslave a NIC and capture on it, so
//! they are `#[ignore]`d and refuse to run unless they are inside a
//! throwaway network namespace named `ostest-*` with
//! `OUTSTATION_NETNS_TEST=1` set. Never run them in the host namespace.
//! `scripts/netns-bench-test.sh` runs them in its outstation-host
//! namespace, next to `bench_netns`:
//!
//! ```sh
//! NS_A=ostest-me-a NS_T=ostest-me-t NS_X=ostest-me-x NS_M=ostest-me-m \
//!     scripts/netns-bench-test.sh
//! ```
//!
//! The LAN side is watched from the target's namespace: the test runs
//! its own binary there (`lan_capture_helper`, through
//! `ip netns exec`), which records what crosses the target's end of the
//! LAN veth in each direction until told to stop. Each run is then
//! compared frame by frame with the run's capture and with the frames
//! the run was meant to send.
//!
//! Env: `OUTSTATION_BENCH_TARGET` (mock IEC 104 slave on the LAN,
//! 10.77.0.1:2404, owned by the bridge `lan` in the target namespace),
//! `OUTSTATION_BENCH_NIC` (this namespace's LAN NIC),
//! `OUTSTATION_NS_TARGET` (the target namespace) and
//! `OUTSTATION_LAN_PORT` (the target's end of the LAN veth there).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use raw_replay::bpf;
use sched::{BenchmarkConfig, RunConfig, RunContext};

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

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set (scripts/netns-bench-test.sh)"))
}

fn sh(args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn target_ip() -> Ipv4Addr {
    env("OUTSTATION_BENCH_TARGET").parse().unwrap()
}

/// MAC of the target's bridge `lan` (it owns the target IP).
fn target_mac() -> [u8; 6] {
    let out = sh(&[
        "ip",
        "-n",
        &env("OUTSTATION_NS_TARGET"),
        "-o",
        "link",
        "show",
        "lan",
    ]);
    let i = out.find("link/ether ").expect("lan has a MAC") + "link/ether ".len();
    netctl::parse_mac(&out[i..i + 17]).unwrap()
}

/// MAC of this namespace's LAN NIC.
fn nic_mac() -> [u8; 6] {
    let a = std::fs::read_to_string(format!(
        "/sys/class/net/{}/address",
        env("OUTSTATION_BENCH_NIC")
    ))
    .unwrap();
    netctl::parse_mac(a.trim()).unwrap()
}

// ---------------------------------------------------------------------------
// pcap files

fn write_pcap(path: &Path, frames: &[(u64, Vec<u8>)]) {
    let mut b = Vec::new();
    for v in [0xa1b2_c3d4u32, 0x0004_0002, 0, 0, 65535, 1] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    for (ts_us, f) in frames {
        let ts = 1_700_000_000_000_000 + ts_us;
        b.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        b.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        b.extend_from_slice(&(f.len() as u32).to_le_bytes());
        b.extend_from_slice(&(f.len() as u32).to_le_bytes());
        b.extend_from_slice(f);
    }
    std::fs::write(path, b).unwrap();
}

/// Frames of a classic little-endian pcap.
fn read_pcap(path: &Path) -> Vec<Vec<u8>> {
    let b = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut out = Vec::new();
    let mut off = 24;
    while off + 16 <= b.len() {
        let incl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
        out.push(b[off + 16..off + 16 + incl].to_vec());
        off += 16 + incl;
    }
    out
}

/// Ethernet + IPv4 + TCP (checksums left for the rewrite / ignored).
#[allow(clippy::too_many_arguments)]
fn tcp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = Vec::with_capacity(54 + payload.len());
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + 20 + payload.len()) as u16;
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&ack.to_be_bytes());
    f.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;
const SYN: u8 = 0x02;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;

fn src_mac(n: u8) -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, 0x10, n]
}

fn src_ip(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 10, n)
}

/// `sources` sources (192.168.10.2..), `per_source` frames each,
/// interleaved 1 ms apart, to a closed port: the target answers every
/// one of them with a RST.
fn raw_pcap(dir: &Path, sources: u8, per_source: u32) -> PathBuf {
    let orig_dst = Ipv4Addr::new(192, 168, 86, 1);
    let orig_mac = [0x02, 0, 0, 0, 0x86, 1];
    let mut frames = Vec::new();
    for i in 0..per_source {
        for s in 0..sources {
            let n = 2 + s;
            let payload = format!("src {n} frame {i:06} ........");
            frames.push((
                u64::from(i) * u64::from(sources) * 1000 + u64::from(s) * 1000,
                tcp_frame(
                    src_mac(n),
                    orig_mac,
                    src_ip(n),
                    40_000 + u16::from(n),
                    orig_dst,
                    2405,
                    1000 + i * 64,
                    7 + i,
                    PSH_ACK,
                    payload.as_bytes(),
                ),
            ));
        }
    }
    let p = dir.join("raw.pcap");
    write_pcap(&p, &frames);
    p
}

// ---------------------------------------------------------------------------
// LAN-side capture (in the target namespace)

/// Accept only outgoing frames.
fn only_outgoing() -> Vec<bpf::Insn> {
    let ins = |code: u16, jt: u8, jf: u8, k: u32| bpf::Insn { code, jt, jf, k };
    vec![
        // ld [pkttype]
        ins(0x20, 0, 0, (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE) as u32),
        // jeq PACKET_OUTGOING
        ins(0x15, 0, 1, u32::from(libc::PACKET_OUTGOING)),
        ins(0x06, 0, 0, bpf::SNAPLEN),
        ins(0x06, 0, 0, 0),
    ]
}

/// Not a test: the LAN-side recorder `LanCapture` runs in the target
/// namespace. Does nothing unless `OUTSTATION_LAN_HELPER_DIR` is set.
#[test]
#[ignore = "privileged helper, run by the tests in this file"]
fn lan_capture_helper() {
    let Ok(dir) = std::env::var("OUTSTATION_LAN_HELPER_DIR") else {
        return;
    };
    require_test_netns();
    let dir = PathBuf::from(dir);
    let iface = env("OUTSTATION_LAN_PORT");
    let cin = raw_replay::Capture::start_filtered(
        dir.join("in.pcap"),
        bpf::skip_outgoing(&bpf::accept_all()),
        Some(raw_replay::CAPTURE_RT_PRIORITY),
    )
    .unwrap();
    cin.add_iface(&iface).unwrap();
    let cout = raw_replay::Capture::start_filtered(
        dir.join("out.pcap"),
        only_outgoing(),
        Some(raw_replay::CAPTURE_RT_PRIORITY),
    )
    .unwrap();
    cout.add_iface(&iface).unwrap();
    std::fs::write(dir.join("ready"), "").unwrap();
    let t0 = Instant::now();
    while !dir.join("stop").exists() && t0.elapsed() < Duration::from_secs(300) {
        std::thread::sleep(Duration::from_millis(20));
    }
    // Let the last replies cross.
    std::thread::sleep(Duration::from_millis(300));
    let a = cin.finish();
    let b = cout.finish();
    std::fs::write(dir.join("done"), format!("{} {}", a.dropped, b.dropped)).unwrap();
}

/// What crossed the target's end of the LAN veth while it ran.
struct LanCapture {
    dir: PathBuf,
    child: Child,
}

struct LanFrames {
    /// Frames that arrived from outstation's side.
    from_us: Vec<Vec<u8>>,
    /// Frames the target side sent towards outstation.
    to_us: Vec<Vec<u8>>,
}

impl LanCapture {
    fn start(dir: &Path) -> Self {
        let dir = dir.join("lan");
        std::fs::create_dir_all(&dir).unwrap();
        let exe = std::env::current_exe().unwrap();
        let child = Command::new("ip")
            .args(["netns", "exec", &env("OUTSTATION_NS_TARGET"), "env"])
            .arg("OUTSTATION_NETNS_TEST=1")
            .arg(format!("OUTSTATION_LAN_HELPER_DIR={}", dir.display()))
            .arg(format!(
                "OUTSTATION_LAN_PORT={}",
                env("OUTSTATION_LAN_PORT")
            ))
            .arg(exe)
            .args([
                "--ignored",
                "--exact",
                "lan_capture_helper",
                "--test-threads=1",
            ])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let t0 = Instant::now();
        while !dir.join("ready").exists() {
            assert!(
                t0.elapsed() < Duration::from_secs(20),
                "LAN capture helper never got ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { dir, child }
    }

    /// Stop and collect. Frames the enslaved NIC's own (host) stack
    /// sent, e.g. its IPv6 router solicitations after it came up, are
    /// left out of `from_us`: they are the host's, not the run's, and
    /// the run does not touch the NIC's IPv6 settings.
    fn stop(mut self) -> LanFrames {
        std::fs::write(self.dir.join("stop"), "").unwrap();
        let st = self.child.wait().unwrap();
        assert!(st.success(), "LAN capture helper failed: {st}");
        let done = std::fs::read_to_string(self.dir.join("done")).unwrap();
        assert_eq!(done, "0 0", "the LAN capture itself dropped frames");
        let nic_mac = nic_mac();
        let (host, from_us): (Vec<Vec<u8>>, Vec<Vec<u8>>) = read_pcap(&self.dir.join("in.pcap"))
            .into_iter()
            .partition(|f| src_mac_of(f) == nic_mac);
        if !host.is_empty() {
            eprintln!("{} frames from the NIC's own stack ignored", host.len());
        }
        LanFrames {
            from_us,
            to_us: read_pcap(&self.dir.join("out.pcap")),
        }
    }
}

// ---------------------------------------------------------------------------
// comparisons

fn multiset(frames: &[Vec<u8>]) -> HashMap<Vec<u8>, i64> {
    let mut m = HashMap::new();
    for f in frames {
        *m.entry(f.clone()).or_insert(0) += 1;
    }
    m
}

fn describe(f: &[u8]) -> String {
    let n = f.len().min(54);
    let hex: String = f[..n].iter().map(|b| format!("{b:02x}")).collect();
    format!("{} bytes {hex}…", f.len())
}

/// Assert `got` holds exactly the frames of `want`, as often.
fn assert_same_frames(what: &str, got: &[Vec<u8>], want: &[Vec<u8>]) {
    let (g, w) = (multiset(got), multiset(want));
    if g == w {
        return;
    }
    let mut missing = Vec::new();
    let mut extra = Vec::new();
    for (f, n) in &w {
        let d = n - g.get(f).copied().unwrap_or(0);
        if d > 0 {
            missing.push(format!("{d}x {}", describe(f)));
        }
    }
    for (f, n) in &g {
        let d = n - w.get(f).copied().unwrap_or(0);
        if d > 0 {
            extra.push(format!("{d}x {}", describe(f)));
        }
    }
    panic!(
        "{what}: {} frames, want {}; {} missing, {} extra\nmissing: {:#?}\nextra: {:#?}",
        got.len(),
        want.len(),
        missing.len(),
        extra.len(),
        &missing[..missing.len().min(8)],
        &extra[..extra.len().min(8)],
    );
}

fn src_mac_of(f: &[u8]) -> [u8; 6] {
    f[6..12].try_into().unwrap()
}

fn dst_mac_of(f: &[u8]) -> [u8; 6] {
    f[0..6].try_into().unwrap()
}

fn is_ipv4(f: &[u8]) -> bool {
    f.len() >= 34 && f[12..14] == [0x08, 0x00]
}

fn ip_src(f: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(f[26], f[27], f[28], f[29])
}

fn ip_dst(f: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(f[30], f[31], f[32], f[33])
}

/// TCP flags of an IPv4/TCP frame.
fn tcp_flags(f: &[u8]) -> Option<u8> {
    if !is_ipv4(f) || f[23] != 6 {
        return None;
    }
    let ihl = usize::from(f[14] & 0x0f) * 4;
    f.get(14 + ihl + 13).copied()
}

fn tcp_payload(f: &[u8]) -> &[u8] {
    let ihl = usize::from(f[14] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
    let doff = usize::from(f[14 + ihl + 12] >> 4) * 4;
    &f[14 + ihl + doff..(14 + total).min(f.len())]
}

fn netns_state_dir(dir: &Path) -> PathBuf {
    let d = dir.join("state");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn no_outstation_ifaces() -> bool {
    !sh(&["ip", "-o", "link"]).contains(": pcr")
}

// ---------------------------------------------------------------------------
// raw replay

/// One raw run of `pcap` with a LAN capture around it; checks that the
/// run's capture holds every wire frame exactly once (B1), that only
/// the replayed frames reach the LAN (O2), and that the target's
/// replies are in the capture exactly once too.
fn raw_run_one_to_one(label: &str, run_id: u64, sources: u8, per_source: u32, top_speed: bool) {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = raw_pcap(dir.path(), sources, per_source);
    let pcap = Arc::new(pcapload::load(&pcap_path).unwrap());
    let (tip, tmac) = (target_ip(), target_mac());
    // The target answers each segment with a RST; it needs the
    // sources' MACs for that (they never answer ARP).
    let ns_t = env("OUTSTATION_NS_TARGET");
    for s in 0..sources {
        let n = 2 + s;
        sh(&[
            "ip",
            "-n",
            &ns_t,
            "neigh",
            "replace",
            &src_ip(n).to_string(),
            "lladdr",
            &netctl::format_mac(src_mac(n)),
            "dev",
            "lan",
            "nud",
            "permanent",
        ]);
    }
    let expected: Vec<Vec<u8>> = pcap
        .packets
        .iter()
        .map(|p| {
            let mut f = p.ether_frame().into_owned();
            rewrite::rewrite_in_place(&mut f, tip, tmac).unwrap();
            f
        })
        .collect();
    assert_eq!(expected.len() as u32, u32::from(sources) * per_source);
    let ours: Vec<[u8; 6]> = (0..sources).map(|s| src_mac(2 + s)).collect();

    let lan = LanCapture::start(dir.path());
    let capture = dir.path().join("run.pcap");
    let cfg = RunConfig {
        run_id,
        target_ip: tip,
        target_mac: tmac,
        egress_nic: Some(env("OUTSTATION_BENCH_NIC")),
        // The NIC carries this namespace's default route.
        force_protected_nic: true,
        speed: 4.0,
        top_speed,
        include_non_ip: false,
        capture_path: Some(capture.clone()),
        iterations: 1,
        state_dir: Some(netns_state_dir(dir.path())),
        ..Default::default()
    };
    let t0 = Instant::now();
    let report = sched::run(pcap, cfg, RunContext::new()).unwrap();
    let took = t0.elapsed();
    let lan = lan.stop();
    assert!(
        no_outstation_ifaces(),
        "{label}: run left interfaces behind"
    );

    assert_eq!(
        report.total_packets,
        expected.len() as u64,
        "{label}: {report:?}"
    );
    assert_eq!(report.total_errors, 0, "{label}: {:?}", report.warnings);
    assert_eq!(
        report.captured_dropped, 0,
        "{label}: capture dropped frames"
    );
    let cap = read_pcap(&capture);
    assert_eq!(
        report.captured_packets,
        cap.len() as u64,
        "{label}: report vs file (B2)"
    );

    // O2: the LAN saw the replayed frames, each once, and nothing else
    // from our side (no IGMP, ARP or IPv6 of the run's interfaces).
    assert_same_frames(&format!("{label}: LAN, from us"), &lan.from_us, &expected);

    // B1: the run's capture holds each replayed frame exactly once ...
    let (cap_ours, cap_lan): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
        cap.into_iter().partition(|f| ours.contains(&src_mac_of(f)));
    assert_same_frames(&format!("{label}: capture, replayed"), &cap_ours, &expected);
    // ... and each reply of the target exactly once.
    let rst = |frames: &[Vec<u8>]| -> Vec<Vec<u8>> {
        frames
            .iter()
            .filter(|f| tcp_flags(f).is_some_and(|fl| fl & RST != 0) && ip_src(f) == tip)
            .cloned()
            .collect()
    };
    let lan_rst = rst(&lan.to_us);
    assert!(
        lan_rst.len() as u64 >= report.total_packets / 2,
        "{label}: the target answered only {} of {} segments",
        lan_rst.len(),
        report.total_packets
    );
    assert_same_frames(
        &format!("{label}: capture, replies"),
        &rst(&cap_lan),
        &lan_rst,
    );
    // Everything else the capture got from the LAN did cross it.
    let lan_to_us = multiset(&lan.to_us);
    for f in &cap_lan {
        assert!(
            lan_to_us.contains_key(f),
            "{label}: captured a LAN frame that never crossed the LAN: {}",
            describe(f)
        );
        let d = dst_mac_of(f);
        assert!(
            d[0] & 1 == 1 || ours.contains(&d),
            "{label}: captured a LAN frame for another host: {}",
            describe(f)
        );
    }
    eprintln!(
        "{label}: {} frames in {:.0} ms, {} replies, capture {} frames, 0 dropped",
        report.total_packets,
        took.as_secs_f64() * 1000.0,
        lan_rst.len(),
        report.captured_packets
    );
}

#[test]
#[ignore = "privileged: run via scripts/netns-bench-test.sh inside ostest-* netns"]
fn raw_capture_paced_holds_each_wire_frame_once() {
    require_test_netns();
    raw_run_one_to_one("5 sources, speed 4", 71, 5, 40, false);
}

#[test]
#[ignore = "privileged: run via scripts/netns-bench-test.sh inside ostest-* netns"]
fn raw_capture_top_speed_holds_each_wire_frame_once() {
    require_test_netns();
    raw_run_one_to_one("5 sources, top speed", 72, 5, 40, true);
    // A long burst: the capture keeps up (no kernel drops) with
    // 5 x 4000 frames at top speed plus as many replies.
    raw_run_one_to_one("5 sources, top speed, 20000 frames", 73, 5, 4000, true);
}

// ---------------------------------------------------------------------------
// master benchmark

/// A captured IEC 104 master flow: one GI I-frame from the client, the
/// server's answers stretching the flow to `span_ms`.
fn master_pcap(dir: &Path, span_ms: u64) -> PathBuf {
    let (cmac, smac) = (src_mac(2), [0x02, 0, 0, 0, 0x86, 1]);
    let (c, s) = (src_ip(2), Ipv4Addr::new(192, 168, 86, 1));
    let gi = [
        0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14,
    ];
    let actcon = [
        0x68, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x64, 0x01, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14,
    ];
    let actterm = [
        0x68, 0x0e, 0x02, 0x00, 0x02, 0x00, 0x64, 0x01, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14,
    ];
    let frames = vec![
        (
            0,
            tcp_frame(cmac, smac, c, 40_002, s, 2404, 100, 0, SYN, &[]),
        ),
        (
            500,
            tcp_frame(smac, cmac, s, 2404, c, 40_002, 900, 101, SYN | ACK, &[]),
        ),
        (
            1000,
            tcp_frame(cmac, smac, c, 40_002, s, 2404, 101, 901, ACK, &[]),
        ),
        (
            2000,
            tcp_frame(cmac, smac, c, 40_002, s, 2404, 101, 901, PSH_ACK, &gi),
        ),
        (
            3000,
            tcp_frame(smac, cmac, s, 2404, c, 40_002, 901, 117, PSH_ACK, &actcon),
        ),
        (
            span_ms * 1000,
            tcp_frame(smac, cmac, s, 2404, c, 40_002, 917, 117, PSH_ACK, &actterm),
        ),
    ];
    let p = dir.join("master.pcap");
    write_pcap(&p, &frames);
    p
}

/// O1 + O2 for the master role: an unbounded run with original pacing
/// on a short capture spaces its connections by the captured flow's
/// span plus the iteration gap (it used to reconnect 8-12 times a
/// second), ends every connection with STOPDT and a FIN, puts only its
/// session's frames on the LAN, and its capture holds each of them
/// (and each frame the target sent it) exactly once.
#[test]
#[ignore = "privileged: run via scripts/netns-bench-test.sh inside ostest-* netns"]
fn master_unbounded_run_is_spaced_quiet_and_captured_once() {
    require_test_netns();
    let dir = tempfile::tempdir().unwrap();
    // Flow span 1.5 s; the GI itself is acknowledged within a few ms.
    let pcap = Arc::new(pcapload::load(master_pcap(dir.path(), 1500)).unwrap());
    let tip = target_ip();
    let capture = dir.path().join("run.pcap");
    let cfg = BenchmarkConfig {
        run_id: 74,
        target_ip: tip,
        target_port: 2404,
        egress_nic: Some(env("OUTSTATION_BENCH_NIC")),
        force_protected_nic: true,
        capture_path: Some(capture.clone()),
        pacing: protoplay::Pacing::OriginalTiming { speed: 1.0 },
        iterations: 0,
        iteration_gap: Duration::from_millis(500),
        state_dir: Some(netns_state_dir(dir.path())),
        ..Default::default()
    };
    let lan = LanCapture::start(dir.path());
    let ctx = RunContext::new();
    let cancel = ctx.cancel.clone();
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(5500));
        cancel.store(true, Ordering::Relaxed);
    });
    let report = sched::run_benchmark(
        pcap,
        cfg,
        Arc::new(proto_iec104::Iec104Replayer::new()),
        ctx,
    )
    .unwrap();
    stopper.join().unwrap();
    let lan = lan.stop();
    assert!(no_outstation_ifaces(), "run left interfaces behind");
    assert_eq!(report.per_session.len(), 1, "{report:?}");
    assert_eq!(report.captured_dropped, 0);

    let session = src_ip(2);
    let mac = src_mac(2);
    // O1: iterations start >= 1.5 s (span) + 0.5 s (gap) apart: in
    // 5.5 s that is 3 connections (at 0, ~2 and ~4 s), never dozens.
    let syns: Vec<&Vec<u8>> = lan
        .from_us
        .iter()
        .filter(|f| tcp_flags(f) == Some(SYN))
        .collect();
    assert!(
        (2..=3).contains(&syns.len()),
        "{} connections in 5.5 s: {:?}",
        syns.len(),
        report.per_session[0].proto_report.error
    );
    // Every completed connection ended with STOPDT act and our FIN,
    // never with a RST from us.
    let stopdt = lan
        .from_us
        .iter()
        .filter(|f| tcp_flags(f).is_some() && tcp_payload(f) == [0x68, 0x04, 0x13, 0, 0, 0])
        .count();
    let fins = lan
        .from_us
        .iter()
        .filter(|f| tcp_flags(f).is_some_and(|fl| fl & FIN != 0))
        .count();
    let rsts = lan
        .from_us
        .iter()
        .filter(|f| tcp_flags(f).is_some_and(|fl| fl & RST != 0))
        .count();
    assert!(
        stopdt + 1 >= syns.len(),
        "{stopdt} STOPDT for {} connections",
        syns.len()
    );
    assert!(
        fins + 1 >= syns.len(),
        "{fins} FINs for {} connections",
        syns.len()
    );
    assert_eq!(rsts, 0, "the master reset a connection");

    // O2: nothing but the session's own ARP and TCP left our side.
    for f in &lan.from_us {
        let arp_of_session = f.len() >= 42
            && f[12..14] == [0x08, 0x06]
            && Ipv4Addr::new(f[28], f[29], f[30], f[31]) == session;
        let tcp_of_session = tcp_flags(f).is_some() && ip_src(f) == session && ip_dst(f) == tip;
        assert!(
            arp_of_session || tcp_of_session,
            "a frame that is not session traffic reached the LAN: {}",
            describe(f)
        );
    }

    // B1: the capture holds what we sent and what was sent to us, each
    // exactly once.
    let cap = read_pcap(&capture);
    assert_eq!(report.captured_packets, cap.len() as u64);
    let (cap_ours, cap_lan): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
        cap.into_iter().partition(|f| src_mac_of(f) == mac);
    assert_same_frames("capture, session frames", &cap_ours, &lan.from_us);
    let to_session = |frames: &[Vec<u8>]| -> Vec<Vec<u8>> {
        frames
            .iter()
            .filter(|f| dst_mac_of(f) == mac)
            .cloned()
            .collect()
    };
    let replies = to_session(&lan.to_us);
    assert!(replies.len() >= syns.len() * 3, "{} replies", replies.len());
    assert_same_frames("capture, replies", &to_session(&cap_lan), &replies);
}

/// Sets a sysctl of this network namespace and restores it on drop.
struct SysctlOverride {
    path: PathBuf,
    old: String,
}

impl SysctlOverride {
    fn set(key: &str, value: &str) -> Self {
        let path = Path::new("/proc/sys").join(key.replace('.', "/"));
        let old = std::fs::read_to_string(&path).unwrap().trim().to_string();
        std::fs::write(&path, value).unwrap();
        Self { path, old }
    }
}

impl Drop for SysctlOverride {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, &self.old);
    }
}

/// The kernel charges a socket filter against `net.core.optmem_max`:
/// with a few hundred sessions the per-MAC reply filter on the egress
/// NIC no longer fits (ENOMEM, measured at 528 MACs with the 128 KiB
/// default and at 82 with the older 20 KiB default). The capture then
/// recorded no replies at all and the analysis reported every endpoint
/// as never connected. Now it falls back to recording every incoming
/// frame and says so. A tiny optmem_max in this namespace makes even a
/// one-session filter too big (and leaves room for the fallback).
#[test]
#[ignore = "privileged: run via scripts/netns-bench-test.sh inside ostest-* netns"]
fn master_capture_keeps_replies_when_the_mac_filter_does_not_fit() {
    require_test_netns();
    let dir = tempfile::tempdir().unwrap();
    let pcap = Arc::new(pcapload::load(master_pcap(dir.path(), 200)).unwrap());
    let capture = dir.path().join("run.pcap");
    let cfg = BenchmarkConfig {
        run_id: 75,
        target_ip: target_ip(),
        target_port: 2404,
        egress_nic: Some(env("OUTSTATION_BENCH_NIC")),
        force_protected_nic: true,
        capture_path: Some(capture.clone()),
        iterations: 1,
        state_dir: Some(netns_state_dir(dir.path())),
        ..Default::default()
    };
    let report = {
        let _optmem = SysctlOverride::set("net.core.optmem_max", "512");
        sched::run_benchmark(
            pcap,
            cfg,
            Arc::new(proto_iec104::Iec104Replayer::new()),
            RunContext::new(),
        )
        .unwrap()
    };
    assert!(no_outstation_ifaces(), "run left interfaces behind");
    assert_eq!(report.per_session.len(), 1, "{report:?}");
    assert!(
        report.per_session[0].proto_report.error.is_none(),
        "{:?}",
        report.per_session[0].proto_report.error
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("every incoming frame")),
        "no fallback warning: {:?}",
        report.warnings
    );
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.contains("records no replies")),
        "{:?}",
        report.warnings
    );
    // The target's replies to the session are in the capture.
    let mac = src_mac(2);
    let replies = read_pcap(&capture)
        .into_iter()
        .filter(|f| dst_mac_of(f) == mac && tcp_flags(f).is_some() && ip_src(f) == target_ip())
        .count();
    assert!(
        replies >= 3,
        "{replies} replies from the target in the capture"
    );
}
