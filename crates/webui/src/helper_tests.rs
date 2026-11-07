//! Unit tests of small pure helpers (N10): the gap histogram, the MAC
//! scraper for `arping` output and the iteration-start detector.

use std::path::PathBuf;

use crate::analysis::detect_iteration_starts;
use crate::netprobe::extract_mac;
use crate::routes::runs::bucket_gaps;

fn packet(ts_ns: u64) -> pcapload::Packet {
    pcapload::Packet {
        ts_ns,
        rel_ts_ns: ts_ns,
        data: pcapload::PacketData::from_vec(Vec::new()),
        src_mac: None,
        src_ip: None,
        kind: pcapload::PacketKind::Malformed,
        link_type: 1,
        l3_offset: 14,
    }
}

#[test]
fn bucket_gaps_is_a_20_bucket_log_histogram() {
    // Fewer than two packets: no gaps, all buckets empty.
    assert_eq!(bucket_gaps(&[]), vec![0; 20]);
    assert_eq!(bucket_gaps(&[packet(5)]), vec![0; 20]);
    // Buckets are 0.35 decades wide from 1 µs: 1 µs -> 0, 1 ms -> 8,
    // 10 s and above clamp into 19, below 1 µs into 0; zero gaps
    // (duplicate timestamps) are skipped.
    let ts = [
        0,
        1_000,          // 1 µs
        1_001_000,      // 1 ms
        1_001_000,      // 0 (skipped)
        1_001_100,      // 100 ns, below the range
        10_001_001_100, // 10 s
        30_001_001_100, // 20 s, above the range
    ];
    let pkts: Vec<_> = ts.iter().map(|&t| packet(t)).collect();
    let b = bucket_gaps(&pkts);
    assert_eq!(b.len(), 20);
    assert_eq!(b[0], 2, "{b:?}");
    assert_eq!(b[8], 1, "{b:?}");
    assert_eq!(b[19], 2, "{b:?}");
    assert_eq!(b.iter().sum::<u64>(), 5);
}

#[test]
fn extract_mac_finds_the_first_mac() {
    let iputils = "ARPING 10.0.0.5 from 0.0.0.0 eth0\n\
                   Unicast reply from 10.0.0.5 [AA:BB:CC:00:11:22]  0.712ms\n";
    assert_eq!(extract_mac(iputils).as_deref(), Some("aa:bb:cc:00:11:22"));
    assert_eq!(
        extract_mac("02:00:00:00:00:01").as_deref(),
        Some("02:00:00:00:00:01")
    );
    assert_eq!(extract_mac("Sent 2 probes, Received 0 response(s)"), None);
    assert_eq!(extract_mac(""), None);
    assert_eq!(extract_mac("aa:bb:cc:dd:ee:f"), None, "16 chars only");
    assert_eq!(extract_mac("aa-bb-cc-dd-ee-ff"), None, "wrong separator");
    // Non-ASCII output (a localized arping) must not panic on a char
    // boundary.
    assert_eq!(
        extract_mac("Antwort von 10.0.0.5 [aa:bb:cc:dd:ee:ff] — läuft").as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
    assert_eq!(extract_mac("ääääääääääääääääääää"), None);
}

/// A pcap with one SYN to `port` per entry of `syn_ms` (ms), each from
/// its own client port.
fn syn_pcap(port: u16, syn_ms: &[u64]) -> pcapload::LoadedPcap {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]); // ns magic, LE
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (i, &ms) in syn_ms.iter().enumerate() {
        let mut f = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
        f.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend_from_slice(&(40000 + i as u16).to_be_bytes());
        f.extend_from_slice(&port.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        let ts = ms * 1_000_000;
        out.extend_from_slice(&((ts / 1_000_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((ts % 1_000_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&f);
    }
    pcapload::load_bytes(&out, PathBuf::from("syns.pcap")).expect("load")
}

#[test]
fn detect_iteration_starts_clusters_syn_bursts() {
    // Three bursts of 10 handshakes, 20 s apart, plus stray SYNs.
    let mut syns = Vec::new();
    for burst in [0u64, 20_000, 40_000] {
        syns.extend((0..10).map(|k| burst + 100 + k * 50));
    }
    syns.extend([7_000, 33_000]);
    let p = syn_pcap(2404, &syns);
    assert_eq!(
        detect_iteration_starts(&p, 2404, 10),
        vec![0.0, 20_000.0, 40_000.0]
    );
    // Another port, or no endpoints expected: nothing.
    assert!(detect_iteration_starts(&p, 502, 10).is_empty());
    assert!(detect_iteration_starts(&p, 2404, 0).is_empty());
    // Bursts closer than 5 s coalesce into one start.
    let close: Vec<u64> = (0..10)
        .map(|k| k * 10)
        .chain((0..10).map(|k| 2_000 + k * 10))
        .collect();
    let p = syn_pcap(2404, &close);
    assert_eq!(detect_iteration_starts(&p, 2404, 10), vec![0.0]);
    // A burst below the threshold (30 % of the endpoints, at least 5)
    // is not an iteration start.
    let p = syn_pcap(2404, &[0, 10, 20, 30]);
    assert!(detect_iteration_starts(&p, 2404, 10).is_empty());
}
