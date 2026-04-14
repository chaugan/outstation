//! In-place L2/L3/L4 header rewrite for pcap replay.
//!
//! Given an Ethernet frame carrying IPv4, overwrite the destination MAC
//! and destination IP and recompute every affected checksum so the packet
//! is a legal on-the-wire frame toward a new target. Non-IPv4 frames are
//! left untouched (GOOSE/SV/ARP handled by the L2 replayer).

use std::net::Ipv4Addr;

use anyhow::{bail, Result};

pub const ETH_HDR_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// One's complement 16-bit sum across a series of byte slices, used for
/// IPv4, TCP, and UDP checksums (RFC 1071). The slices are logically
/// concatenated; odd-length boundaries are handled.
pub fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut hold: Option<u8> = None;
    for chunk in chunks {
        let mut i = 0;
        if let Some(h) = hold.take() {
            if !chunk.is_empty() {
                sum += ((h as u32) << 8) | (chunk[0] as u32);
                i = 1;
            } else {
                hold = Some(h);
            }
        }
        while i + 1 < chunk.len() {
            sum += ((chunk[i] as u32) << 8) | (chunk[i + 1] as u32);
            i += 2;
        }
        if i < chunk.len() {
            hold = Some(chunk[i]);
        }
    }
    if let Some(h) = hold {
        sum += (h as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Checksum an IPv4 header with its checksum field zeroed.
pub fn ipv4_header_checksum(ip_header: &[u8]) -> u16 {
    internet_checksum(&[ip_header])
}

/// Checksum an IPv4 TCP/UDP segment given its pseudo-header fields.
/// The segment's own checksum field must be zeroed in `l4`.
pub fn l4_checksum_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> u16 {
    let len = l4.len() as u16;
    let pseudo = [
        src[0], src[1], src[2], src[3],
        dst[0], dst[1], dst[2], dst[3],
        0, proto,
        (len >> 8) as u8, (len & 0xff) as u8,
    ];
    internet_checksum(&[&pseudo, l4])
}

/// Rewrite destination MAC and destination IP of an Ethernet/IPv4 frame
/// in place, recomputing the IPv4 header checksum and the TCP/UDP
/// checksum if present. ICMP checksums do not depend on IP addresses and
/// are left alone. Non-IPv4 frames update only the destination MAC.
///
/// Fragmented IPv4 payloads beyond the first fragment do not carry an L4
/// header, so their L4 checksum is not touched. The first fragment's L4
/// checksum would need the full reassembled segment to recompute, so we
/// also skip it and let the caller handle fragmented flows separately.
pub fn rewrite_in_place(
    frame: &mut [u8],
    target_ip: Ipv4Addr,
    target_mac: [u8; 6],
) -> Result<()> {
    if frame.len() < ETH_HDR_LEN {
        bail!("frame shorter than Ethernet header");
    }
    frame[0..6].copy_from_slice(&target_mac);

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return Ok(());
    }

    if frame.len() < ETH_HDR_LEN + 20 {
        bail!("frame shorter than minimum IPv4 header");
    }
    let ip = ETH_HDR_LEN;
    let ihl = (frame[ip] & 0x0f) as usize;
    if ihl < 5 {
        bail!("invalid IPv4 IHL {ihl}");
    }
    let ip_hdr_end = ip + ihl * 4;
    if frame.len() < ip_hdr_end {
        bail!("frame shorter than declared IPv4 header length");
    }

    let total_len = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]) as usize;
    let flags_frag = u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]);
    let more_fragments = flags_frag & 0x2000 != 0;
    let frag_offset = flags_frag & 0x1fff;
    let proto = frame[ip + 9];

    // Write dst IP and recompute IP header checksum.
    frame[ip + 10] = 0;
    frame[ip + 11] = 0;
    frame[ip + 16..ip + 20].copy_from_slice(&target_ip.octets());
    let ck = ipv4_header_checksum(&frame[ip..ip_hdr_end]);
    frame[ip + 10] = (ck >> 8) as u8;
    frame[ip + 11] = (ck & 0xff) as u8;

    // Second and later fragments carry no L4 header.
    if more_fragments || frag_offset != 0 {
        tracing::debug!("skipping L4 checksum on fragmented packet");
        return Ok(());
    }

    // Trim L4 slice to declared IPv4 total length (captures may include
    // link-layer padding which should not participate in L4 checksum).
    let ip_end = (ip + total_len).min(frame.len());
    if ip_hdr_end >= ip_end {
        return Ok(());
    }
    let l4_len = ip_end - ip_hdr_end;

    // Split borrow so we can read the IP source/dest while mutating L4.
    let (ip_bytes, tail) = frame.split_at_mut(ip_hdr_end);
    let src_ip: [u8; 4] = ip_bytes[ip + 12..ip + 16].try_into().unwrap();
    let dst_ip: [u8; 4] = ip_bytes[ip + 16..ip + 20].try_into().unwrap();
    let l4 = &mut tail[..l4_len];

    match proto {
        IPPROTO_TCP => {
            if l4.len() < 20 {
                return Ok(());
            }
            l4[16] = 0;
            l4[17] = 0;
            let ck = l4_checksum_ipv4(src_ip, dst_ip, IPPROTO_TCP, l4);
            l4[16] = (ck >> 8) as u8;
            l4[17] = (ck & 0xff) as u8;
        }
        IPPROTO_UDP => {
            if l4.len() < 8 {
                return Ok(());
            }
            l4[6] = 0;
            l4[7] = 0;
            let ck = l4_checksum_ipv4(src_ip, dst_ip, IPPROTO_UDP, l4);
            // RFC 768: an all-zero checksum means "not computed"; wire it
            // as 0xFFFF instead, which is equivalent in one's complement.
            let ck = if ck == 0 { 0xffff } else { ck };
            l4[6] = (ck >> 8) as u8;
            l4[7] = (ck & 0xff) as u8;
        }
        IPPROTO_ICMP => {
            // No pseudo-header dependency; payload untouched, checksum stays.
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TCP SYN frame with known-good checksums.
    /// Returns (frame, original_dst_mac, original_dst_ip).
    fn make_tcp_syn() -> Vec<u8> {
        // Ethernet: dst 11:22:33:44:55:66, src aa:bb:cc:dd:ee:ff, type 0x0800
        let eth = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00,
        ];
        // IPv4: version=4, ihl=5, tos=0, total_len=44, id=0, flags/frag=0,
        // ttl=64, proto=TCP, cksum=0, src=10.0.0.1, dst=20.0.0.1
        let mut ipv4 = vec![
            0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            10, 0, 0, 1,
            20, 0, 0, 1,
        ];
        // TCP: src_port=12345, dst_port=80, seq=1, ack=0,
        // data_offset=6 (24 bytes, 4 bytes of options), flags=SYN,
        // window=0xffff, cksum=0, urg=0, options: MSS=1460
        let mut tcp = vec![
            0x30, 0x39, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x60, 0x02, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
            0x02, 0x04, 0x05, 0xb4,
        ];
        // Fill in IP checksum.
        let ck = ipv4_header_checksum(&ipv4);
        ipv4[10] = (ck >> 8) as u8;
        ipv4[11] = (ck & 0xff) as u8;
        // Fill in TCP checksum.
        let ck = l4_checksum_ipv4([10, 0, 0, 1], [20, 0, 0, 1], IPPROTO_TCP, &tcp);
        tcp[16] = (ck >> 8) as u8;
        tcp[17] = (ck & 0xff) as u8;

        let mut frame = eth.to_vec();
        frame.extend(ipv4);
        frame.extend(tcp);
        frame
    }

    fn make_udp_echo() -> Vec<u8> {
        let eth = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00,
        ];
        let payload = b"hello";
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut ipv4 = vec![
            0x45, 0x00,
            (total_len >> 8) as u8, (total_len & 0xff) as u8,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00,
            10, 0, 0, 2,
            20, 0, 0, 2,
        ];
        let ck = ipv4_header_checksum(&ipv4);
        ipv4[10] = (ck >> 8) as u8;
        ipv4[11] = (ck & 0xff) as u8;

        let mut udp = vec![
            0x13, 0x88, 0x13, 0x89,
            (udp_len >> 8) as u8, (udp_len & 0xff) as u8,
            0x00, 0x00,
        ];
        udp.extend_from_slice(payload);
        let ck = l4_checksum_ipv4([10, 0, 0, 2], [20, 0, 0, 2], IPPROTO_UDP, &udp);
        let ck = if ck == 0 { 0xffff } else { ck };
        udp[6] = (ck >> 8) as u8;
        udp[7] = (ck & 0xff) as u8;

        let mut frame = eth.to_vec();
        frame.extend(ipv4);
        frame.extend(udp);
        frame
    }

    #[test]
    fn tcp_rewrite_keeps_checksums_valid() {
        let mut frame = make_tcp_syn();
        // Sanity: original IP checksum verifies to zero.
        assert_eq!(internet_checksum(&[&frame[14..34]]), 0);

        rewrite_in_place(
            &mut frame,
            "30.0.0.99".parse().unwrap(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        )
        .unwrap();

        assert_eq!(&frame[0..6], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(&frame[30..34], &[30, 0, 0, 99]);
        // IPv4 header still valid.
        assert_eq!(internet_checksum(&[&frame[14..34]]), 0);
        // TCP segment still valid against new pseudo-header.
        let pseudo = [
            10u8, 0, 0, 1, 30, 0, 0, 99, 0, IPPROTO_TCP,
            0, 24,
        ];
        assert_eq!(internet_checksum(&[&pseudo, &frame[34..58]]), 0);
    }

    #[test]
    fn udp_rewrite_keeps_checksums_valid() {
        let mut frame = make_udp_echo();
        rewrite_in_place(
            &mut frame,
            "30.0.0.42".parse().unwrap(),
            [0xaa; 6],
        )
        .unwrap();
        assert_eq!(&frame[0..6], &[0xaa; 6]);
        assert_eq!(&frame[30..34], &[30, 0, 0, 42]);
        assert_eq!(internet_checksum(&[&frame[14..34]]), 0);
        let udp_len = frame.len() - 34;
        let pseudo = [
            10u8, 0, 0, 2, 30, 0, 0, 42, 0, IPPROTO_UDP,
            (udp_len >> 8) as u8, (udp_len & 0xff) as u8,
        ];
        assert_eq!(internet_checksum(&[&pseudo, &frame[34..]]), 0);
    }

    #[test]
    fn non_ipv4_only_updates_mac() {
        // GOOSE frame: EtherType 0x88B8, opaque payload.
        let mut frame = vec![
            0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x88, 0xb8,
        ];
        frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        let before_payload = frame[14..].to_vec();

        rewrite_in_place(&mut frame, "1.2.3.4".parse().unwrap(), [0x99; 6]).unwrap();
        assert_eq!(&frame[0..6], &[0x99; 6]);
        assert_eq!(&frame[14..], &before_payload[..]);
    }

    #[test]
    fn too_short_frame_errors() {
        let mut f = vec![0u8; 10];
        assert!(rewrite_in_place(&mut f, "1.2.3.4".parse().unwrap(), [0; 6]).is_err());
    }
}
