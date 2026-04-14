use super::*;

/// Assemble a classic pcap file in memory from a list of frames with
/// relative nanosecond timestamps. Uses the nanosecond-resolution magic.
fn make_pcap(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    // Global header: magic (ns, little-endian), version 2.4, thiszone 0,
    // sigfigs 0, snaplen 65535, network 1 (ethernet).
    out.extend_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]);
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (ts_ns, data) in frames {
        let sec = (ts_ns / 1_000_000_000) as u32;
        let nsec = (ts_ns % 1_000_000_000) as u32;
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&nsec.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn eth_ip_tcp(
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header (20 bytes)
    let total_len: u16 = 20 + 20;
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]); // id
    f.extend_from_slice(&[0x00, 0x00]); // flags/frag
    f.push(64); // ttl
    f.push(6); // tcp
    f.extend_from_slice(&[0x00, 0x00]); // checksum (left 0 for test)
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    // TCP header (20 bytes)
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes()); // seq
    f.extend_from_slice(&0u32.to_be_bytes()); // ack
    f.push(0x50); // data offset 5, reserved 0
    f.push(flags);
    f.extend_from_slice(&0xffffu16.to_be_bytes()); // window
    f.extend_from_slice(&[0x00, 0x00]); // checksum
    f.extend_from_slice(&[0x00, 0x00]); // urg
    f
}

fn eth_ip_udp(src_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    let total_len: u16 = 20 + 8;
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&[0x00, 0x00]);
    f.push(64);
    f.push(17);
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    f.extend_from_slice(&5000u16.to_be_bytes());
    f.extend_from_slice(&6000u16.to_be_bytes());
    f.extend_from_slice(&8u16.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    f
}

#[test]
fn splits_by_source_and_identifies_flows() {
    let mac_a: MacAddr = [0x02, 0, 0, 0, 0, 0xa1];
    let mac_b: MacAddr = [0x02, 0, 0, 0, 0, 0xb1];
    let mac_c: MacAddr = [0x02, 0, 0, 0, 0, 0xc1];
    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let ip_c = [10, 0, 0, 3];

    // Flow 1: A -> B, TCP, full handshake then data.
    // Flow 2: C -> B, UDP, single packet.
    let frames: Vec<(u64, Vec<u8>)> = vec![
        (0, eth_ip_tcp(mac_a, ip_a, ip_b, 40000, 80, TCP_SYN)),                     // client SYN
        (1_000_000, eth_ip_tcp(mac_b, ip_b, ip_a, 80, 40000, TCP_SYN | TCP_ACK)),   // server SYN-ACK
        (2_000_000, eth_ip_tcp(mac_a, ip_a, ip_b, 40000, 80, TCP_ACK)),              // client ACK
        (3_000_000, eth_ip_tcp(mac_a, ip_a, ip_b, 40000, 80, TCP_ACK)),              // client data
        (4_000_000, eth_ip_tcp(mac_a, ip_a, ip_b, 40000, 80, TCP_FIN | TCP_ACK)),   // client FIN
        (5_000_000, eth_ip_udp(mac_c, ip_c, ip_b)),                                  // UDP from C
    ];
    let pcap_bytes = make_pcap(&frames);
    let loaded = load_bytes(&pcap_bytes, PathBuf::from("test.pcap")).unwrap();

    assert_eq!(loaded.packets.len(), 6);
    // Three distinct source IPs.
    assert_eq!(loaded.sources.len(), 3);
    let a = &loaded.sources[&Ipv4Addr::new(10, 0, 0, 1)];
    let b = &loaded.sources[&Ipv4Addr::new(10, 0, 0, 2)];
    let c = &loaded.sources[&Ipv4Addr::new(10, 0, 0, 3)];
    assert_eq!(a.src_mac, mac_a);
    assert_eq!(b.src_mac, mac_b);
    assert_eq!(c.src_mac, mac_c);
    assert_eq!(a.packet_count, 4);
    assert_eq!(b.packet_count, 1);
    assert_eq!(c.packet_count, 1);
    assert!(!a.mac_collision);

    // One TCP flow (A<->B), one UDP (no flow object).
    assert_eq!(loaded.flows.len(), 1);
    let flow = &loaded.flows[0];
    assert!(flow.saw_syn);
    assert!(flow.saw_syn_ack);
    assert!(flow.saw_fin);
    assert!(!flow.saw_rst);
    assert_eq!(flow.client, Some((Ipv4Addr::new(10, 0, 0, 1), 40000)));
    assert_eq!(flow.server, Some((Ipv4Addr::new(10, 0, 0, 2), 80)));
    assert_eq!(flow.packet_indices.len(), 5);

    // Relative timestamps are monotonic and start at 0.
    assert_eq!(loaded.packets[0].rel_ts_ns, 0);
    assert_eq!(loaded.packets[5].rel_ts_ns, 5_000_000);
}

#[test]
fn mac_collision_is_flagged() {
    let mac_a1: MacAddr = [0x02, 0, 0, 0, 0, 0x01];
    let mac_a2: MacAddr = [0x02, 0, 0, 0, 0, 0x02];
    let ip_a = [10, 0, 0, 10];
    let ip_b = [10, 0, 0, 20];
    let frames = vec![
        (0, eth_ip_udp(mac_a1, ip_a, ip_b)),
        (1, eth_ip_udp(mac_a1, ip_a, ip_b)),
        (2, eth_ip_udp(mac_a2, ip_a, ip_b)),
    ];
    let loaded = load_bytes(&make_pcap(&frames), PathBuf::from("x.pcap")).unwrap();
    let a = &loaded.sources[&Ipv4Addr::new(10, 0, 0, 10)];
    assert!(a.mac_collision);
    assert_eq!(a.src_mac, mac_a1); // most common
}

fn eth_ip_tcp_with_payload(
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    let total_len: u16 = 20 + 20 + payload.len() as u16;
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&[0x00, 0x00]);
    f.push(64);
    f.push(6);
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(0x50);
    f.push(flags);
    f.extend_from_slice(&0xffffu16.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(payload);
    f
}

#[test]
fn reassembles_client_stream_with_retransmit() {
    let client_mac: MacAddr = [0x02, 0, 0, 0, 0, 0x01];
    let server_mac: MacAddr = [0x02, 0, 0, 0, 0, 0x02];
    let c_ip = [10, 0, 0, 1];
    let s_ip = [10, 0, 0, 2];

    // Flow: SYN, SYN-ACK, ACK, client sends "HELLO" (seq=1000),
    // retransmit of "HELLO" overlapped (seq=1000), then "WORLD" (seq=1005), FIN.
    let frames = vec![
        (0, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_SYN, 999, &[])),
        (1_000_000, eth_ip_tcp_with_payload(server_mac, s_ip, c_ip, 80, 40000, TCP_SYN | TCP_ACK, 500, &[])),
        (2_000_000, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_ACK, 1000, &[])),
        (3_000_000, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_ACK, 1000, b"HELLO")),
        (4_000_000, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_ACK, 1000, b"HELLO")), // retransmit
        (5_000_000, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_ACK, 1005, b"WORLD")),
        (6_000_000, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_FIN | TCP_ACK, 1010, &[])),
    ];
    let pcap_bytes = make_pcap(&frames);
    let loaded = load_bytes(&pcap_bytes, PathBuf::from("t.pcap")).unwrap();
    assert_eq!(loaded.flows.len(), 1);

    let r = loaded.reassemble_client_payload(0).unwrap();
    assert_eq!(r.client, (Ipv4Addr::new(10, 0, 0, 1), 40000));
    assert_eq!(r.server, (Ipv4Addr::new(10, 0, 0, 2), 80));
    assert_eq!(&r.payload, b"HELLOWORLD");
    // 5 retransmit bytes were dropped.
    assert_eq!(r.dup_bytes, 5);
}

#[test]
fn reassembly_detects_gap() {
    let client_mac: MacAddr = [0x02, 0, 0, 0, 0, 0x01];
    let server_mac: MacAddr = [0x02, 0, 0, 0, 0, 0x02];
    let c_ip = [10, 0, 0, 1];
    let s_ip = [10, 0, 0, 2];
    // SYN (seq 999) then a client segment at seq 1100 — gap from 1000..1100.
    let frames = vec![
        (0, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_SYN, 999, &[])),
        (1_000_000, eth_ip_tcp_with_payload(server_mac, s_ip, c_ip, 80, 40000, TCP_SYN | TCP_ACK, 500, &[])),
        (2_000_000, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_ACK, 1000, b"AA")),
        (3_000_000, eth_ip_tcp_with_payload(client_mac, c_ip, s_ip, 40000, 80, TCP_ACK, 1100, b"BB")),
    ];
    let loaded = load_bytes(&make_pcap(&frames), PathBuf::from("gap.pcap")).unwrap();
    let err = loaded.reassemble_client_payload(0).unwrap_err();
    assert!(err.to_string().contains("gap"), "unexpected error: {err}");
}

#[test]
fn non_ip_frames_are_counted_but_not_sourced_by_ip() {
    // GOOSE-style: dst 01:0c:cd:01:00:00, src aa.., ethertype 0x88b8.
    let frame = vec![
        0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x88, 0xb8,
        0xde, 0xad, 0xbe, 0xef,
    ];
    let loaded = load_bytes(&make_pcap(&[(0, frame)]), PathBuf::from("goose.pcap")).unwrap();
    assert_eq!(loaded.non_ip_count, 1);
    assert_eq!(loaded.sources.len(), 0);
    assert!(matches!(
        loaded.packets[0].kind,
        PacketKind::NonIp { ethertype: 0x88b8 }
    ));
}

#[test]
fn non_ip_sources_are_indexed_by_mac() {
    let mac_a: MacAddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let mac_b: MacAddr = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab];
    let goose = |src: MacAddr, ethertype: u16, pad: u8| -> Vec<u8> {
        let mut v = vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00];
        v.extend_from_slice(&src);
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(&[pad, pad, pad, pad]);
        v
    };
    let frames = vec![
        (0, goose(mac_a, 0x88b8, 0x01)),                   // GOOSE from A
        (1_000_000, goose(mac_a, 0x88ba, 0x02)),           // SV from A
        (2_000_000, goose(mac_b, 0x88b8, 0x03)),           // GOOSE from B
        (3_000_000, goose(mac_a, 0x88b8, 0x04)),           // GOOSE from A again
    ];
    let loaded = load_bytes(&make_pcap(&frames), PathBuf::from("l2.pcap")).unwrap();
    assert_eq!(loaded.non_ip_count, 4);
    assert_eq!(loaded.non_ip_sources.len(), 2);
    let a = &loaded.non_ip_sources[&mac_a];
    let b = &loaded.non_ip_sources[&mac_b];
    assert_eq!(a.packet_count, 3);
    assert_eq!(b.packet_count, 1);
    // Both GOOSE and SV should be observed under A.
    assert!(a.ethertypes.contains(&0x88b8));
    assert!(a.ethertypes.contains(&0x88ba));
}
