//! Regression tests for the pcap-ingestion audit findings P01–P12
//! (P09 belongs to proto_iec104). Every capture is generated in-test by
//! `common`, a port of the audit's Python generators.

mod common;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use common::*;
use pcapload::{load_bytes, LoadedPcap, PacketKind, StreamDir, StreamGap};

fn load(bytes: &[u8]) -> LoadedPcap {
    load_bytes(bytes, PathBuf::from("test.pcap")).expect("load")
}

fn streams(p: &LoadedPcap, flow: usize) -> (Vec<u8>, Vec<u8>) {
    let c = p.reassemble_client_payload(flow).expect("client").payload;
    let s = p.reassemble_server_payload(flow).expect("server").payload;
    (c, s)
}

fn assert_base_streams(p: &LoadedPcap) {
    let b = base();
    assert_eq!(p.flows.len(), 1, "flows: {:?}", p.flows);
    let (c, s) = streams(p, 0);
    assert_eq!(c, b.client);
    assert_eq!(s, b.server);
    let r = p.reassemble(0, StreamDir::ServerToClient).unwrap();
    assert!(r.is_contiguous());
    assert!(r.anchored_at_syn);
}

#[test]
fn base_variants_reassemble_exactly() {
    let b = base();
    for (be, ns) in [(false, false), (true, false), (false, true), (true, true)] {
        let p = load(&write_pcap(&b.pkts, 1, be, ns));
        assert_base_streams(&p);
        assert!(p.ingest_notes().is_empty(), "{:?}", p.ingest_notes());
    }
    assert_base_streams(&load(&pcapng(&b.pkts, None)));
    assert_base_streams(&load(&pcapng(&b.pkts, Some(9))));
}

#[test]
fn retransmit_and_reorder_are_byte_exact() {
    let b = base();
    let mut r = b.pkts.clone();
    let dup = r[6].clone();
    r.insert(7, dup);
    r.swap(9, 10);
    let p = load(&pcap(&r));
    let s = p.reassemble(0, StreamDir::ServerToClient).unwrap();
    assert_eq!(s.payload, b.server);
    assert_eq!(s.dup_segments, 1);
    assert_eq!(s.dup_bytes, 20);
    assert!(s.is_contiguous());
}

// ---- P01: sequence wraparound ----

#[test]
fn p01_seq_wraparound_keeps_order() {
    let w = session(0xFFFF_FFF0 - 30, 0xFFFF_FFFF - 40, 6, 1_000_000_000, true);
    let p = load(&pcap(&w.pkts));
    let (c, s) = streams(&p, 0);
    assert_eq!(c, w.client);
    assert_eq!(s, w.server);
}

#[test]
fn p01_wraparound_without_syn_and_out_of_order() {
    // Mid-stream capture whose first captured segment is *not* the
    // lowest sequence number, straddling 2^32.
    let w = session(0xFFFF_FFF0 - 30, 0xFFFF_FFFF - 40, 6, 1_000_000_000, false);
    let mut pk = w.pkts.clone();
    // Server segments are at 1, 3..=8. Move the first server segment
    // after the second one.
    let first_server = pk.remove(1);
    pk.insert(3, first_server);
    let p = load(&pcap(&pk));
    let r = p.reassemble(0, StreamDir::ServerToClient).unwrap();
    assert_eq!(r.payload, w.server);
    assert!(r.is_contiguous());
    assert!(!r.anchored_at_syn);
}

// ---- P02: gap tolerance ----

#[test]
fn p02_mid_stream_gap_is_spliced_and_reported() {
    let b = base();
    let missing = b.pkts[9].1.len() - 54; // payload of the dropped segment
    let pk: Vec<Pkt> = b
        .pkts
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 9)
        .map(|(_, p)| p.clone())
        .collect();
    let p = load(&pcap(&pk));
    // Client side is untouched.
    assert_eq!(p.reassemble_client_payload(0).unwrap().payload, b.client);
    // Old entry point no longer bails.
    let r = p.reassemble_server_payload(0).unwrap();
    let gap_at = STARTDT_CON.len() + 3 * missing;
    let mut expected = b.server[..gap_at].to_vec();
    expected.extend_from_slice(&b.server[gap_at + missing..]);
    assert_eq!(r.payload, expected);
    assert_eq!(
        r.gaps,
        vec![StreamGap {
            offset: gap_at,
            missing: missing as u64
        }]
    );
    let chunks: Vec<(usize, &[u8])> = r.contiguous_chunks().collect();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[1].0, gap_at);
    // Each chunk starts on an APCI boundary here, so a per-chunk
    // framer sees whole frames.
    assert!(chunks.iter().all(|(_, c)| c[0] == 0x68));
}

#[test]
fn p02_snaplen_truncated_segment_becomes_gap() {
    let b = base();
    let mut pk = b.pkts.clone();
    // Cut 5 payload bytes off a server segment, as a short snaplen would.
    let n = pk[8].1.len();
    pk[8].1.truncate(n - 5);
    let p = load(&pcap(&pk));
    let r = p.reassemble(0, StreamDir::ServerToClient).unwrap();
    assert_eq!(r.payload.len(), b.server.len() - 5);
    assert_eq!(r.missing_bytes(), 5);
}

// ---- P03: link layers ----

fn map_frames(f: impl Fn(&[u8]) -> Vec<u8>) -> Vec<Pkt> {
    base().pkts.iter().map(|(t, d)| (*t, f(d))).collect()
}

#[test]
fn p03_vlan_qinq_and_9100_tags_are_peeled() {
    for tags in [
        &[0x8100u16][..],
        &[0x88a8, 0x8100][..],
        &[0x9100, 0x8100][..],
    ] {
        let pk = map_frames(|d| vlan(d, tags));
        let p = load(&pcap(&pk));
        assert_base_streams(&p);
        assert_eq!(p.ingest.vlan_tagged_packets, pk.len() as u64);
        assert_eq!(p.sources[&Ipv4Addr::from(CIP)].src_mac, CMAC);
        // Raw replay gets an untagged frame with IPv4 at offset 14.
        let ef = p.packets[3].ether_frame();
        assert_eq!(&ef[12..14], &[0x08, 0x00]);
        assert_eq!(&ef[14..], l3_of(&base().pkts[3].1));
    }
}

#[test]
fn p03_tagged_non_ip_frames_replay_verbatim() {
    // VLAN-tagged GOOSE keeps its tag for L2 replay.
    let mut goose = vec![0x01, 0x0c, 0xcd, 0x01, 0, 0];
    goose.extend_from_slice(&[0xaa; 6]);
    goose.extend_from_slice(&[0x81, 0x00, 0x80, 0x00, 0x88, 0xb8, 1, 2, 3, 4]);
    let p = load(&pcap(&[(0, goose.clone())]));
    assert!(matches!(
        p.packets[0].kind,
        PacketKind::NonIp { ethertype: 0x88b8 }
    ));
    assert_eq!(&*p.packets[0].ether_frame(), &goose[..]);
    assert_eq!(p.non_ip_sources[&[0xaa; 6]].ethertypes, vec![0x88b8]);
}

#[test]
fn p03_cooked_and_raw_link_types() {
    let cases: Vec<(u32, Vec<Pkt>, bool)> = vec![
        (113, map_frames(sll), true),
        (276, map_frames(sll2), true),
        (101, map_frames(|d| l3_of(d).to_vec()), false),
        (228, map_frames(|d| l3_of(d).to_vec()), false),
    ];
    for (lt, pk, has_mac) in cases {
        let p = load(&write_pcap(&pk, lt, false, false));
        assert_eq!(p.link_type, lt);
        assert_base_streams(&p);
        let client = &p.sources[&Ipv4Addr::from(CIP)];
        if has_mac {
            assert_eq!(client.src_mac, CMAC, "link type {lt}");
        } else {
            assert_eq!(client.src_mac, [0x02, 0x00, 10, 0, 0, 1], "link type {lt}");
        }
        // Raw replay gets a synthesised Ethernet header.
        let ef = p.packets[3].ether_frame();
        assert_eq!(&ef[12..14], &[0x08, 0x00], "link type {lt}");
        assert_eq!(&ef[14..], l3_of(&base().pkts[3].1), "link type {lt}");
        assert_eq!(&ef[6..12], &client.src_mac);
    }
}

#[test]
fn p03_pcapng_sll2_interface() {
    let pk = map_frames(sll2);
    let mut ng = shb();
    ng.extend(idb(276, None));
    for (t, d) in &pk {
        ng.extend(epb(0, t / 1000, d));
    }
    let p = load(&ng);
    assert_eq!(p.link_type, 276);
    assert_base_streams(&p);
}

#[test]
fn p03_ipv6_and_unsupported_links_are_counted() {
    let pk = map_frames(to_v6);
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 0);
    assert_eq!(p.ingest.ipv6_packets, pk.len() as u64);
    let notes = p.ingest_notes();
    assert!(notes.iter().any(|n| n.contains("IPv6")), "{notes:?}");

    // Classic pcap with an unsupported link type: clear error.
    let err = load_bytes(&write_pcap(&pk, 147, false, false), PathBuf::new()).unwrap_err();
    assert!(err.to_string().contains("supported"), "{err}");

    // pcapng: Ethernet interface plus an unsupported one.
    let b = base();
    let mut ng = shb();
    ng.extend(idb(1, None));
    ng.extend(idb(147, None));
    for (t, d) in &b.pkts {
        ng.extend(epb(0, t / 1000, d));
    }
    ng.extend(epb(1, 0, &[1, 2, 3]));
    ng.extend(epb(7, 0, &[1, 2, 3])); // interface without an IDB
    let p = load(&ng);
    assert_base_streams(&p);
    assert_eq!(p.ingest.unsupported_link_packets, 2);
    assert!(p
        .ingest_notes()
        .iter()
        .any(|n| n.contains("unsupported link type(s) 147")));
}

// ---- P04: timestamps ----

#[test]
fn p04_backwards_timestamp_never_underflows() {
    let b = base();
    let mut pk = b.pkts.clone();
    pk[1].0 = pk[0].0 - 500_000_000;
    let p = load(&pcap(&pk));
    assert_eq!(p.ingest.ts_backwards, 1);
    assert_eq!(p.first_ts_ns, pk[1].0);
    assert_eq!(p.last_ts_ns, pk.last().unwrap().0);
    let span = p.last_ts_ns - p.first_ts_ns;
    assert_eq!(p.packets[1].rel_ts_ns, 0);
    assert_eq!(p.packets[0].rel_ts_ns, 500_000_000);
    assert!(p.packets.iter().all(|x| x.rel_ts_ns <= span));
    assert!(p.ingest_notes().iter().any(|n| n.contains("earlier")));
}

// ---- P05: 4-tuple reuse ----

#[test]
fn p05_reconnect_after_fin_is_a_new_flow() {
    let s1 = session(1000, 5000, 6, 1_000_000_000_000, true);
    let s2 = session(900_000, 7_000_000, 6, 1_100_000_000_000, true);
    let mut pk = s1.pkts.clone();
    let fin_seq = 1000 + 1 + s1.client.len() as u32;
    pk.push((1_050_000_000_000, frame(true, fin_seq, 0, FIN | ACK, &[])));
    pk.extend(s2.pkts.iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 2);
    assert_eq!(p.ingest.flows_split, 1);
    assert_eq!(p.flows[1].previous_on_tuple, Some(0));
    assert_eq!(streams(&p, 0), (s1.client.clone(), s1.server.clone()));
    assert_eq!(streams(&p, 1), (s2.client.clone(), s2.server.clone()));
    // Both flows recorded once under each source.
    assert_eq!(p.sources[&Ipv4Addr::from(CIP)].flow_indices, vec![0, 1]);
    assert_eq!(p.sources[&Ipv4Addr::from(SIP)].flow_indices, vec![0, 1]);
}

#[test]
fn p05_reconnect_with_close_isn_and_no_fin_is_split() {
    let s3 = session(1000, 5000, 6, 1_000_000_000_000, true);
    let s4 = session(1001, 5001, 6, 1_100_000_000_000, true);
    let mut pk = s3.pkts.clone();
    pk.extend(s4.pkts.iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 2);
    assert_eq!(streams(&p, 0), (s3.client, s3.server));
    assert_eq!(streams(&p, 1), (s4.client, s4.server));
}

#[test]
fn p05_seq_jump_without_handshake_is_split() {
    let a = session(1000, 5000, 3, 1_000_000_000_000, false);
    let b = session(0x8000_0000, 0x9000_0000, 3, 1_100_000_000_000, false);
    let mut pk = a.pkts.clone();
    pk.extend(b.pkts.iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 2);
    assert_eq!(streams(&p, 0), (a.client, a.server));
    assert_eq!(streams(&p, 1), (b.client, b.server));
}

/// N16 (re-audit a3_stale_after_syn): after a FIN and a reconnect with
/// new ISNs, the server retransmits the old connection's last data
/// segment, captured right after the new SYN-ACK. It belongs to the old
/// flow; the reconnect stays one flow with both streams intact (it used
/// to split into extra flows, losing the client's first 6 bytes).
#[test]
fn n16_stale_retransmit_after_a_new_syn_does_not_split_the_reconnect() {
    let s1 = session(1000, 5000, 7, 1_000_000_000_000, true);
    let s2 = session(900_000, 7_000_000, 7, 1_100_000_000_000, true);
    let fin_seq = 1000 + 1 + s1.client.len() as u32;
    let mut pk = s1.pkts.clone();
    pk.push((1_050_000_000_000, frame(true, fin_seq, 0, FIN | ACK, &[])));
    // s1's last server data segment.
    let stale = s1
        .pkts
        .iter()
        .rev()
        .find(|(_, f)| f[26..30] == SIP && f.len() > 54)
        .unwrap()
        .1
        .clone();
    pk.extend(s2.pkts[..2].iter().cloned());
    pk.push((1_100_000_001_500, stale));
    pk.extend(s2.pkts[2..].iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 2, "flows: {:?}", p.flows);
    assert_eq!(p.ingest.flows_split, 1);
    assert_eq!(streams(&p, 0), (s1.client.clone(), s1.server.clone()));
    assert_eq!(streams(&p, 1), (s2.client.clone(), s2.server.clone()));
    let r = p.reassemble(0, StreamDir::ServerToClient).unwrap();
    assert_eq!(r.dup_segments, 1, "the stale copy is a duplicate");
}

/// N17 (re-audit a4_same_isn): a reconnect that reuses the same ISNs
/// without FIN or RST (an embedded stack with a fixed ISN after a cable
/// pull) is a new connection: a SYN after data split it, instead of the
/// second session being dropped as retransmits.
#[test]
fn n17_reconnect_with_the_same_isn_and_no_fin_is_split() {
    let s3 = session(1000, 5000, 6, 1_000_000_000_000, true);
    let s4 = session(1000, 5000, 6, 1_100_000_000_000, true);
    let mut pk = s3.pkts.clone();
    pk.extend(s4.pkts.iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 2, "flows: {:?}", p.flows);
    assert_eq!(p.flows[1].previous_on_tuple, Some(0));
    assert_eq!(streams(&p, 0), (s3.client, s3.server));
    assert_eq!(streams(&p, 1), (s4.client, s4.server));
}

/// T17c: a capture merged from two vantage points can hold a flow's
/// SYN-ACK and the server's first data before the client's SYN. The SYN
/// whose ISN the SYN-ACK acknowledges is that flow's own: one flow,
/// both streams intact (it used to split off with the client's half).
#[test]
fn late_own_syn_after_its_syn_ack_does_not_split() {
    let b = base();
    // SYN, SYN-ACK, ACK, STARTDT act, STARTDT con, ... ->
    // SYN-ACK, STARTDT con, SYN, ACK, STARTDT act, ...
    let p0 = &b.pkts;
    let mut pk = vec![
        p0[1].clone(),
        p0[4].clone(),
        p0[0].clone(),
        p0[2].clone(),
        p0[3].clone(),
    ];
    pk.extend(p0[5..].iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 1, "flows: {:?}", p.flows);
    assert_eq!(p.ingest.flows_split, 0);
    assert!(p.flows[0].saw_syn && p.flows[0].saw_syn_ack);
    assert_eq!(p.flows[0].client_isn, Some(1000));
    assert_eq!(p.flows[0].client, Some((Ipv4Addr::from(CIP), CPORT)));
    assert_eq!(streams(&p, 0), (b.client.clone(), b.server.clone()));

    // A SYN with another ISN in the same place is still a new flow.
    let other = session(77_000, 5000, 6, 1_700_000_000_000_000_000, true);
    let mut pk = vec![p0[1].clone(), p0[4].clone(), other.pkts[0].clone()];
    pk.extend(p0[5..].iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 2, "flows: {:?}", p.flows);
    assert_eq!(p.ingest.flows_split, 1);
}

#[test]
fn p05_retransmitted_syn_does_not_split() {
    let b = base();
    let mut pk = b.pkts.clone();
    let syn = pk[0].clone();
    pk.insert(1, syn);
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 1);
    assert_eq!(p.ingest.flows_split, 0);
    assert_eq!(streams(&p, 0), (b.client, b.server));
}

// ---- P06: O(n) ingest ----

/// `n` single-SYN flows from one source to distinct ports.
fn many_flows(n: u32) -> Vec<Pkt> {
    (0..n)
        .map(|i| {
            let t = tcp_hdr(1024 + (i % 60_000) as u16, 2404, i, 0, SYN, &[]);
            let dst = [10, 1, (i / 60_000) as u8, 1];
            (
                u64::from(i) * 10_000,
                eth(CMAC, SMAC, 0x0800, &ip4(CIP, dst, 6, &t, 1, 0x4000)),
            )
        })
        .collect()
}

/// Best of three load times.
fn load_time(bytes: &[u8]) -> std::time::Duration {
    (0..3)
        .map(|_| {
            let start = std::time::Instant::now();
            let p = load(bytes);
            let took = start.elapsed();
            assert!(!p.flows.is_empty());
            took
        })
        .min()
        .unwrap()
}

#[test]
fn p06_many_flows_from_one_source() {
    let n: u32 = 60_000;
    let p = load(&pcap(&many_flows(n)));
    assert_eq!(p.flows.len(), n as usize);
    let fi = &p.sources[&Ipv4Addr::from(CIP)].flow_indices;
    assert_eq!(fi.len(), n as usize);
    assert!(fi.windows(2).all(|w| w[0] < w[1]));
}

/// P06: ingest time grows linearly with the number of flows of one
/// source. Four times the flows must take well under 16 times as long
/// (the quadratic version's ratio); linear ingest is near 4. Best of
/// three runs each, so a busy machine does not fail the check.
#[test]
fn p06_ingest_scales_linearly() {
    let small = pcap(&many_flows(15_000));
    let large = pcap(&many_flows(60_000));
    let (t1, t4) = (load_time(&small), load_time(&large));
    let ratio = t4.as_secs_f64() / t1.as_secs_f64().max(1e-6);
    assert!(
        ratio < 9.0,
        "4x the flows took {ratio:.1}x as long ({t1:?} vs {t4:?})"
    );
}

// ---- P07: shared buffer ----

#[test]
fn p07_packets_share_one_buffer() {
    let b = base();
    let bytes = pcap(&b.pkts);
    let p = load(&bytes);
    // Consecutive packet views sit exactly one 16-byte record header
    // apart in a single buffer: nothing was copied per packet.
    for w in p.packets.windows(2) {
        let a = w[0].data.as_ptr() as usize;
        let c = w[1].data.as_ptr() as usize;
        assert_eq!(c - a, w[0].data.len() + 16);
    }
    let ng = load(&pcapng(&b.pkts, None));
    let first = ng.packets[0].data.as_ptr() as usize;
    let last = ng.packets.last().unwrap().data.as_ptr() as usize;
    assert!(last > first && last - first < pcapng(&b.pkts, None).len());
    assert_eq!(&*p.packets[3].data, &b.pkts[3].1[..]);
}

// ---- P08: truncated tails ----

#[test]
fn p08_truncated_classic_tail_keeps_packets() {
    let b = base();
    let raw = pcap(&b.pkts);
    // Body cut short.
    let p = load(&raw[..raw.len() - 7]);
    assert_eq!(p.packets.len(), b.pkts.len() - 1);
    let why = p.ingest.truncated_tail.clone().expect("warning");
    assert!(why.contains("truncated record body"), "{why}");
    assert!(p.ingest_notes()[0].contains("truncated"));
    // Header cut short.
    let cut = 24 + 16 + b.pkts[0].1.len() + 9;
    let p = load(&raw[..cut]);
    assert_eq!(p.packets.len(), 1);
    assert!(p
        .ingest
        .truncated_tail
        .unwrap()
        .contains("truncated record header"));
    // No complete record at all is still an error, with the reason.
    let err = load_bytes(&raw[..30], PathBuf::new()).unwrap_err();
    assert!(err.to_string().contains("truncated"), "{err}");
    assert!(load_bytes(&raw[..10], PathBuf::new()).is_err());
}

#[test]
fn p08_truncated_pcapng_tail_keeps_packets() {
    let b = base();
    let ng = pcapng(&b.pkts, None);
    let p = load(&ng[..ng.len() - 10]);
    assert_eq!(p.packets.len(), b.pkts.len() - 1);
    assert!(p.ingest.truncated_tail.is_some());
}

// ---- P10: IP fragments and TCP data offset ----

#[test]
fn p10_fragments_are_counted_not_parsed_as_tcp() {
    let b = base();
    let d = &b.pkts[8].1;
    let l4 = &d[14 + 20..];
    // Second fragment is >= 20 bytes so it would parse as a TCP header.
    let mut big = l4[..20].to_vec();
    for _ in 0..8 {
        big.extend_from_slice(&[0x68, 0x04, 0x43, 0, 0, 0]);
    }
    let f1 = eth(SMAC, CMAC, 0x0800, &ip4(SIP, CIP, 6, &big[..24], 9, 0x2000));
    let f2 = eth(SMAC, CMAC, 0x0800, &ip4(SIP, CIP, 6, &big[24..], 9, 3));
    let mut pk: Vec<Pkt> = b.pkts[..8].to_vec();
    pk.push((b.pkts[8].0, f1));
    pk.push((b.pkts[8].0, f2));
    pk.extend(b.pkts[9..].iter().cloned());
    let p = load(&pcap(&pk));
    assert_eq!(p.flows.len(), 1, "no phantom flow from a fragment");
    assert_eq!(p.ingest.ip_fragments, 2);
    assert!(matches!(
        p.packets[8].kind,
        PacketKind::IpFragment { proto: 6 }
    ));
    // Fragments still belong to their source for raw replay.
    assert_eq!(p.sources[&Ipv4Addr::from(SIP)].packet_count, 8 + 1);
    // The fragmented segment is a gap in the server stream.
    let r = p.reassemble(0, StreamDir::ServerToClient).unwrap();
    assert_eq!(r.gaps.len(), 1);
    assert_eq!(p.reassemble_client_payload(0).unwrap().payload, b.client);
}

#[test]
fn p10_bad_tcp_data_offset_is_malformed() {
    let b = base();
    let mut pk = b.pkts.clone();
    // data offset 3 (< 5) on a client data segment.
    pk[5].1[14 + 20 + 12] = 3 << 4;
    // TCP header cut short (IP total length too small for TCP).
    let short = eth(CMAC, SMAC, 0x0800, &ip4(CIP, SIP, 6, &[0u8; 10], 1, 0));
    pk.push((pk.last().unwrap().0 + 1, short));
    let p = load(&pcap(&pk));
    assert_eq!(p.malformed_count, 2);
    assert!(matches!(p.packets[5].kind, PacketKind::Malformed));
    let r = p.reassemble(0, StreamDir::ClientToServer).unwrap();
    assert_eq!(r.gaps.len(), 1);
}

#[test]
fn tso_zero_total_length_uses_captured_length() {
    let b = base();
    let mut pk = b.pkts.clone();
    pk[8].1[16] = 0;
    pk[8].1[17] = 0;
    let p = load(&pcap(&pk));
    assert_base_streams(&p);
}

// ---- P11: anchor at ISN+1 ----

#[test]
fn p11_lost_first_segment_after_syn_is_a_leading_gap() {
    let b = base();
    let pk: Vec<Pkt> = b
        .pkts
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 3) // client STARTDT_ACT
        .map(|(_, p)| p.clone())
        .collect();
    let p = load(&pcap(&pk));
    let r = p.reassemble_client_payload(0).unwrap();
    assert!(r.anchored_at_syn);
    assert_eq!(
        r.gaps,
        vec![StreamGap {
            offset: 0,
            missing: STARTDT_ACT.len() as u64
        }]
    );
    assert_eq!(r.payload, b.client[STARTDT_ACT.len()..]);
    // A leading gap does not split the chunk list.
    assert_eq!(r.contiguous_chunks().count(), 1);
}

#[test]
fn midstream_capture_starts_at_lowest_seq() {
    // gen_more.py's midstream_lead68: no SYN, first segment starts
    // with the tail of a previous frame.
    let lead = [0x68u8, 0x14, 0x00];
    let frames: Vec<Vec<u8>> = (0..5).map(|i| iframe(i, 0, &asdu_c_ic(1))).collect();
    let mut seg0 = lead.to_vec();
    seg0.extend_from_slice(&frames[0]);
    let mut c = 1000u32;
    let mut pk = vec![(0u64, frame(true, c, 5000, PSH | ACK, &seg0))];
    c += seg0.len() as u32;
    let mut expected = seg0.clone();
    for (i, f) in frames[1..].iter().enumerate() {
        pk.push((
            (i as u64 + 1) * 1_000_000_000,
            frame(true, c, 5000, PSH | ACK, f),
        ));
        c += f.len() as u32;
        expected.extend_from_slice(f);
    }
    let p = load(&pcap(&pk));
    let r = p.reassemble_client_payload(0).unwrap();
    assert_eq!(r.payload, expected);
    assert!(r.is_contiguous());
    assert!(!r.anchored_at_syn);
}

// ---- P12: multi-section pcapng ----

#[test]
fn p12_interface_ids_reset_per_section() {
    let b = base();
    let mut ng = shb();
    ng.extend(idb(1, None));
    for (t, d) in &b.pkts[..9] {
        ng.extend(epb(0, t / 1000, d));
    }
    // Section 2: interface 0 is SLL, interface 1 is Ethernet.
    ng.extend(shb());
    ng.extend(idb(113, None));
    ng.extend(idb(1, None));
    for (t, d) in &b.pkts[9..] {
        ng.extend(epb(1, t / 1000, d));
    }
    let p = load(&ng);
    assert_eq!(p.packets.len(), b.pkts.len());
    assert_base_streams(&p);
}

#[test]
fn p12_simple_packet_blocks_use_interface_zero() {
    let b = base();
    // Interface 0 is Ethernet: SPBs are loaded.
    let mut ng = shb();
    ng.extend(idb(1, None));
    for (_, d) in &b.pkts {
        ng.extend(spb(d));
    }
    let p = load(&ng);
    assert_eq!(p.packets.len(), b.pkts.len());
    assert_base_streams(&p);
    // Interface 0 is unsupported: SPBs are skipped and counted, even
    // though interface 1 is Ethernet.
    let mut ng = shb();
    ng.extend(idb(147, None));
    ng.extend(idb(1, None));
    for (_, d) in &b.pkts {
        ng.extend(spb(d));
    }
    let p = load(&ng);
    assert_eq!(p.packets.len(), 0);
    assert_eq!(p.ingest.unsupported_link_packets, b.pkts.len() as u64);
}
