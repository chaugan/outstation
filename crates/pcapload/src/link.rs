//! Link-layer normalisation.
//!
//! Every supported capture link type is reduced to the same shape: the
//! byte offset of the layer-3 header inside the captured frame, the
//! layer-3 protocol (as an Ethernet ethertype), and whatever MAC
//! addresses the link header carries. Downstream code (classification,
//! reassembly, raw replay) then works from the L3 offset and never
//! assumes a 14-byte Ethernet header.

use crate::MacAddr;

/// LINKTYPE_ETHERNET (DLT_EN10MB).
pub const LINKTYPE_ETHERNET: u32 = 1;
/// LINKTYPE_RAW: raw IPv4 or IPv6, version taken from the first nibble.
pub const LINKTYPE_RAW: u32 = 101;
/// LINKTYPE_LINUX_SLL: Linux "cooked" capture v1 (`tcpdump -i any` on
/// older libpcap).
pub const LINKTYPE_LINUX_SLL: u32 = 113;
/// LINKTYPE_IPV4: raw IPv4.
pub const LINKTYPE_IPV4: u32 = 228;
/// LINKTYPE_IPV6: raw IPv6. Accepted so IPv6-only interfaces are
/// counted as IPv6 rather than as an unsupported link type.
pub const LINKTYPE_IPV6: u32 = 229;
/// LINKTYPE_LINUX_SLL2: Linux "cooked" capture v2 (`tcpdump -i any`
/// on libpcap >= 1.10).
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// 802.1Q customer VLAN tag.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// 802.1ad service tag (QinQ outer tag).
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
/// Pre-standard QinQ outer tag used by some vendors.
pub const ETHERTYPE_QINQ_OLD: u16 = 0x9100;

const ARPHRD_ETHER: u16 = 1;

/// True if [`parse`] understands this link type.
pub fn is_supported(link_type: u32) -> bool {
    matches!(
        link_type,
        LINKTYPE_ETHERNET
            | LINKTYPE_RAW
            | LINKTYPE_LINUX_SLL
            | LINKTYPE_IPV4
            | LINKTYPE_IPV6
            | LINKTYPE_LINUX_SLL2
    )
}

/// Human-readable list for error messages.
pub const SUPPORTED_LINK_TYPES: &str =
    "ETHERNET (1), RAW (101), LINUX_SLL (113), IPV4 (228), IPV6 (229), LINUX_SLL2 (276)";

/// The result of peeling the link-layer header off one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3View {
    /// Offset of the L3 header in the captured frame.
    pub l3_offset: usize,
    /// L3 protocol as an Ethernet ethertype (after any VLAN tags).
    pub ethertype: u16,
    /// Source MAC, when the link header carries a 6-byte address.
    pub src_mac: Option<MacAddr>,
    /// Destination MAC (Ethernet only).
    pub dst_mac: Option<MacAddr>,
    /// Number of 802.1Q / 802.1ad / 0x9100 tags that were peeled.
    pub vlan_tags: u8,
}

/// Peel the link-layer header of `data` for capture link type
/// `link_type`. Returns `None` when the frame is too short for its
/// link header or the link type is unsupported.
pub fn parse(link_type: u32, data: &[u8]) -> Option<L3View> {
    match link_type {
        LINKTYPE_ETHERNET => {
            if data.len() < 14 {
                return None;
            }
            let dst_mac: MacAddr = data[0..6].try_into().ok()?;
            let src_mac: MacAddr = data[6..12].try_into().ok()?;
            let (ethertype, l3_offset, vlan_tags) = peel_vlan(data, 12)?;
            Some(L3View {
                l3_offset,
                ethertype,
                src_mac: Some(src_mac),
                dst_mac: Some(dst_mac),
                vlan_tags,
            })
        }
        LINKTYPE_LINUX_SLL => {
            // pkttype(2) hatype(2) halen(2) addr(8) protocol(2)
            if data.len() < 16 {
                return None;
            }
            let hatype = u16::from_be_bytes([data[2], data[3]]);
            let halen = u16::from_be_bytes([data[4], data[5]]);
            let src_mac = (hatype == ARPHRD_ETHER && halen == 6)
                .then(|| data[6..12].try_into().ok())
                .flatten();
            let (ethertype, l3_offset, vlan_tags) = peel_vlan(data, 14)?;
            Some(L3View {
                l3_offset,
                ethertype,
                src_mac,
                dst_mac: None,
                vlan_tags,
            })
        }
        LINKTYPE_LINUX_SLL2 => {
            // protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1)
            // halen(1) addr(8)
            if data.len() < 20 {
                return None;
            }
            let hatype = u16::from_be_bytes([data[8], data[9]]);
            let halen = data[11];
            let src_mac = (hatype == ARPHRD_ETHER && halen == 6)
                .then(|| data[12..18].try_into().ok())
                .flatten();
            let mut ethertype = u16::from_be_bytes([data[0], data[1]]);
            let mut l3_offset = 20;
            let mut vlan_tags = 0;
            if is_vlan_tpid(ethertype) {
                // SLL2 puts the tag TPID in the protocol field and the
                // TCI + inner ethertype at the start of the payload.
                let (et, off, tags) = peel_vlan_payload(data, 20, ethertype)?;
                ethertype = et;
                l3_offset = off;
                vlan_tags = tags;
            }
            Some(L3View {
                l3_offset,
                ethertype,
                src_mac,
                dst_mac: None,
                vlan_tags,
            })
        }
        LINKTYPE_RAW => {
            let first = *data.first()?;
            let ethertype = match first >> 4 {
                4 => ETHERTYPE_IPV4,
                6 => ETHERTYPE_IPV6,
                _ => 0,
            };
            Some(L3View {
                l3_offset: 0,
                ethertype,
                src_mac: None,
                dst_mac: None,
                vlan_tags: 0,
            })
        }
        LINKTYPE_IPV4 => Some(L3View {
            l3_offset: 0,
            ethertype: ETHERTYPE_IPV4,
            src_mac: None,
            dst_mac: None,
            vlan_tags: 0,
        }),
        LINKTYPE_IPV6 => Some(L3View {
            l3_offset: 0,
            ethertype: ETHERTYPE_IPV6,
            src_mac: None,
            dst_mac: None,
            vlan_tags: 0,
        }),
        _ => None,
    }
}

fn is_vlan_tpid(et: u16) -> bool {
    matches!(et, ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_OLD)
}

/// Read the ethertype at `et_off` and skip any stacked VLAN tags.
/// Returns `(inner_ethertype, l3_offset, tags_peeled)`.
fn peel_vlan(data: &[u8], et_off: usize) -> Option<(u16, usize, u8)> {
    let et = u16::from_be_bytes([*data.get(et_off)?, *data.get(et_off + 1)?]);
    if is_vlan_tpid(et) {
        peel_vlan_payload(data, et_off + 2, et)
    } else {
        Some((et, et_off + 2, 0))
    }
}

/// `off` points at a TCI that follows a VLAN TPID. Skip tags until a
/// non-VLAN ethertype is found. A truncated tag stack yields `None`.
fn peel_vlan_payload(data: &[u8], mut off: usize, mut et: u16) -> Option<(u16, usize, u8)> {
    let mut tags = 0u8;
    while is_vlan_tpid(et) {
        // TCI(2) then the next ethertype(2).
        if data.len() < off + 4 {
            return None;
        }
        et = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
        tags = tags.saturating_add(1);
        if tags > 8 {
            // Pathological stack; refuse rather than loop forever on
            // crafted input (the loop is bounded by `data.len()` anyway).
            return None;
        }
    }
    Some((et, off, tags))
}

/// Deterministic locally-administered MAC for an IPv4 address, used
/// when the capture's link layer carries no MAC (raw IP, SLL from a
/// non-Ethernet device, or the destination side of SLL/SLL2).
pub fn synthetic_mac(ip: std::net::Ipv4Addr) -> MacAddr {
    let o = ip.octets();
    [0x02, 0x00, o[0], o[1], o[2], o[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_qinq_is_peeled() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x00, 0x65, 0x08, 0x00]);
        f.extend_from_slice(&[0x45; 20]);
        let v = parse(LINKTYPE_ETHERNET, &f).unwrap();
        assert_eq!(v.ethertype, ETHERTYPE_IPV4);
        assert_eq!(v.l3_offset, 22);
        assert_eq!(v.vlan_tags, 2);
    }

    #[test]
    fn ethernet_9100_tag_is_peeled() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x91, 0x00, 0x00, 0x64, 0x08, 0x00]);
        let v = parse(LINKTYPE_ETHERNET, &f).unwrap();
        assert_eq!(
            (v.ethertype, v.l3_offset, v.vlan_tags),
            (ETHERTYPE_IPV4, 18, 1)
        );
    }

    #[test]
    fn truncated_tag_stack_is_rejected() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x81, 0x00, 0x00]);
        assert!(parse(LINKTYPE_ETHERNET, &f).is_none());
    }

    #[test]
    fn raw_ip_version_nibble() {
        assert_eq!(
            parse(LINKTYPE_RAW, &[0x45]).unwrap().ethertype,
            ETHERTYPE_IPV4
        );
        assert_eq!(
            parse(LINKTYPE_RAW, &[0x60]).unwrap().ethertype,
            ETHERTYPE_IPV6
        );
        assert!(parse(LINKTYPE_RAW, &[]).is_none());
        assert!(parse(999, &[0x45; 40]).is_none());
    }
}
