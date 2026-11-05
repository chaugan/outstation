//! Parse a pcap or pcapng capture, classify every frame, and build an
//! index of sources and TCP flows.
//!
//! Scope:
//! * classic pcap: 0xa1b2c3d4 (µs) and 0xa1b23c4d (ns), both byte
//!   orders;
//! * pcapng: multiple sections (interface tables reset on every Section
//!   Header Block), per-interface link type and `if_tsresol`; Enhanced,
//!   Simple (interface 0) and obsolete Packet Blocks;
//! * link types: Ethernet with 802.1Q / 802.1ad / 0x9100 tags peeled,
//!   Linux cooked capture v1 and v2 (`tcpdump -i any`), raw IP and raw
//!   IPv4. See [`link`]. Packets on other link types are skipped and
//!   counted in [`IngestStats`];
//! * IPv4 only. IPv6 packets are kept (as [`PacketKind::NonIp`]) but
//!   counted separately so the UI can explain missing flows;
//! * IPv4 fragments are counted and never parsed as TCP;
//! * TCP flows are keyed by the canonical 4-tuple. A reused 4-tuple
//!   (new SYN after FIN/RST or with a different ISN, or a sequence
//!   jump far outside any window) starts a new flow;
//! * reassembly with gap reporting, see [`ReassembledFlow`].
//!
//! Memory: the file is read once into a shared buffer and every
//! [`Packet::data`] is a view into it, so a loaded capture costs the
//! file size plus roughly 100 bytes of metadata per packet.
//!
//! A truncated final record (a capture that was killed mid-write)
//! keeps every packet before it; the reason is in
//! [`IngestStats::truncated_tail`].

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tracing::{debug, warn};

pub mod link;
pub mod parse;
mod reassembly;

pub use reassembly::{ReassembledFlow, StreamDir, StreamGap};

use link::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, LINKTYPE_ETHERNET};

pub type MacAddr = [u8; 6];

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// TCP flag bits.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// A segment whose sequence number is this far (either way) from the
/// next expected sequence number on an established 4-tuple belongs to a
/// different connection. 16 MiB is far beyond any IEC 104 window and
/// still makes a random-ISN reconnect split with >99 % probability.
const SEQ_JUMP_NEW_FLOW: u32 = 1 << 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

impl FiveTuple {
    /// Canonical ordering so both directions of a flow share the same key.
    fn canonical(self) -> (Ipv4Addr, u16, Ipv4Addr, u16) {
        let (a_ip, a_port) = (self.src_ip, self.src_port);
        let (b_ip, b_port) = (self.dst_ip, self.dst_port);
        if (a_ip, a_port) <= (b_ip, b_port) {
            (a_ip, a_port, b_ip, b_port)
        } else {
            (b_ip, b_port, a_ip, a_port)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowRole {
    Client,
    Server,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum PacketKind {
    Tcp {
        flow_idx: usize,
        role: FlowRole,
        flags: u8,
    },
    Udp,
    Icmp,
    IpOther {
        proto: u8,
    },
    /// An IPv4 fragment (MF set or non-zero fragment offset). Never
    /// parsed as TCP/UDP: a non-first fragment has no L4 header, and a
    /// first fragment carries only part of the segment. Counted in
    /// [`IngestStats::ip_fragments`].
    IpFragment {
        proto: u8,
    },
    /// Not IPv4. Includes IPv6 (`ethertype == 0x86dd`).
    NonIp {
        ethertype: u16,
    },
    Malformed,
}

/// Captured bytes of one packet: a cheap, clonable view into the
/// buffer holding the whole capture file.
///
/// Derefs to `&[u8]`. Use `.to_vec()` for an owned copy.
#[derive(Clone)]
pub struct PacketData {
    buf: Arc<Vec<u8>>,
    start: usize,
    len: u32,
}

impl PacketData {
    /// Wrap an owned frame (used when bytes do not come from a capture
    /// buffer, e.g. in tests).
    pub fn from_vec(v: Vec<u8>) -> Self {
        let len = u32::try_from(v.len()).expect("packet larger than 4 GiB");
        Self {
            buf: Arc::new(v),
            start: 0,
            len,
        }
    }

    fn shared(buf: &Arc<Vec<u8>>, start: usize, len: usize) -> Self {
        debug_assert!(start + len <= buf.len());
        Self {
            buf: Arc::clone(buf),
            start,
            len: len as u32,
        }
    }
}

impl Deref for PacketData {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[self.start..self.start + self.len as usize]
    }
}

impl AsRef<[u8]> for PacketData {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl fmt::Debug for PacketData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PacketData({} bytes)", self.len)
    }
}

impl PartialEq for PacketData {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for PacketData {}

#[derive(Debug, Clone)]
pub struct Packet {
    pub ts_ns: u64,
    /// Nanoseconds since the earliest timestamp in the file. Never
    /// underflows, even for out-of-order timestamps (see
    /// [`IngestStats::ts_backwards`]).
    pub rel_ts_ns: u64,
    /// The frame exactly as captured, link-layer header included. For
    /// replay onto an Ethernet device use [`Packet::ether_frame`].
    pub data: PacketData,
    /// Source MAC from the link header, or a synthetic
    /// locally-administered MAC (see [`link::synthetic_mac`]) for IPv4
    /// packets on link types without one.
    pub src_mac: Option<MacAddr>,
    pub src_ip: Option<Ipv4Addr>,
    pub kind: PacketKind,
    /// Capture link type of this packet (pcapng interfaces may differ).
    pub link_type: u16,
    /// Offset of the L3 header in `data` (after any VLAN tags).
    pub l3_offset: u16,
}

impl Packet {
    /// The L3 (IP) part of the frame.
    pub fn l3(&self) -> &[u8] {
        self.data.get(self.l3_offset as usize..).unwrap_or(&[])
    }

    /// The packet as an untagged Ethernet II frame, suitable for raw
    /// injection and for `rewrite::rewrite_in_place`.
    ///
    /// * Untagged Ethernet: borrowed as-is.
    /// * VLAN-tagged Ethernet carrying IPv4: tags stripped, so the IPv4
    ///   header sits at offset 14. Tagged non-IP frames (GOOSE, SV) are
    ///   returned verbatim, tags included.
    /// * SLL / SLL2 / raw IP: a 14-byte Ethernet header is synthesised
    ///   from the captured or synthetic MACs and the L3 protocol.
    pub fn ether_frame(&self) -> Cow<'_, [u8]> {
        let link_type = u32::from(self.link_type);
        let Some(view) = link::parse(link_type, &self.data) else {
            return Cow::Borrowed(&self.data);
        };
        if link_type == LINKTYPE_ETHERNET
            && (view.vlan_tags == 0 || view.ethertype != ETHERTYPE_IPV4)
        {
            return Cow::Borrowed(&self.data);
        }
        let l3 = &self.data[view.l3_offset..];
        let dst_ip = (view.ethertype == ETHERTYPE_IPV4 && l3.len() >= 20)
            .then(|| Ipv4Addr::new(l3[16], l3[17], l3[18], l3[19]));
        let dst_mac = view
            .dst_mac
            .or_else(|| dst_ip.map(link::synthetic_mac))
            .unwrap_or([0xff; 6]);
        let src_mac = self
            .src_mac
            .or(view.src_mac)
            .unwrap_or([0x02, 0, 0, 0, 0, 0]);
        let mut out = Vec::with_capacity(14 + l3.len());
        out.extend_from_slice(&dst_mac);
        out.extend_from_slice(&src_mac);
        out.extend_from_slice(&view.ethertype.to_be_bytes());
        out.extend_from_slice(l3);
        Cow::Owned(out)
    }
}

#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub src_ip: Ipv4Addr,
    pub src_mac: MacAddr,
    pub mac_collision: bool,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packet_indices: Vec<usize>,
    pub flow_indices: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub canonical: (Ipv4Addr, u16, Ipv4Addr, u16),
    pub client: Option<(Ipv4Addr, u16)>,
    pub server: Option<(Ipv4Addr, u16)>,
    pub packet_indices: Vec<usize>,
    pub saw_syn: bool,
    pub saw_syn_ack: bool,
    pub saw_fin: bool,
    pub saw_rst: bool,
    /// ISN of the captured SYN, if any.
    pub client_isn: Option<u32>,
    /// ISN of the captured SYN-ACK, if any.
    pub server_isn: Option<u32>,
    /// Index of the earlier flow on the same 4-tuple that this one was
    /// split from (port reuse / reconnect).
    pub previous_on_tuple: Option<usize>,
}

/// Counters and warnings collected while loading. Everything here is
/// something the user may need to know to understand why a flow or
/// packet is missing; [`LoadedPcap::ingest_notes`] turns it into text.
#[derive(Debug, Clone, Default)]
pub struct IngestStats {
    /// IPv6 packets (kept as `NonIp`, not analysed).
    pub ipv6_packets: u64,
    /// Packets on interfaces whose link type is not supported. They are
    /// not in [`LoadedPcap::packets`].
    pub unsupported_link_packets: u64,
    /// Distinct unsupported link types seen (`u32::MAX` = packet named
    /// an interface id with no Interface Description Block).
    pub unsupported_link_types: Vec<u32>,
    /// Frames whose 802.1Q / 802.1ad tags were peeled.
    pub vlan_tagged_packets: u64,
    /// IPv4 fragments (not reassembled, never parsed as TCP).
    pub ip_fragments: u64,
    /// Packets whose timestamp is earlier than the packet before them.
    pub ts_backwards: u64,
    /// TCP flows that were split off an earlier flow on the same
    /// 4-tuple.
    pub flows_split: u64,
    /// Set when the file ends mid-record. The packets before it are
    /// kept; this holds the parser's error text.
    pub truncated_tail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LoadedPcap {
    pub path: PathBuf,
    pub link_type: u32,
    /// Earliest packet timestamp in the file (not necessarily the first
    /// record's when timestamps go backwards).
    pub first_ts_ns: u64,
    /// Latest packet timestamp in the file.
    pub last_ts_ns: u64,
    pub packets: Vec<Packet>,
    pub sources: BTreeMap<Ipv4Addr, SourceInfo>,
    pub flows: Vec<Flow>,
    /// Non-IP senders indexed by source MAC. Used by `l2_replay` for
    /// GOOSE / SV / raw L2 replay where IP does not apply.
    pub non_ip_sources: BTreeMap<MacAddr, NonIpSourceInfo>,
    pub non_ip_count: u64,
    pub malformed_count: u64,
    /// Why some packets or flows may be missing. See
    /// [`LoadedPcap::ingest_notes`].
    pub ingest: IngestStats,
}

impl LoadedPcap {
    /// Human-readable notes about packets that were skipped or could
    /// only be partly analysed. Empty for a clean capture. Meant to be
    /// shown next to the viability verdict.
    pub fn ingest_notes(&self) -> Vec<String> {
        let s = &self.ingest;
        let mut notes = Vec::new();
        if let Some(t) = &s.truncated_tail {
            notes.push(format!(
                "capture file is truncated ({t}); the {} packets before the cut were loaded",
                self.packets.len()
            ));
        }
        if s.unsupported_link_packets > 0 {
            let types: Vec<String> = s
                .unsupported_link_types
                .iter()
                .map(|t| t.to_string())
                .collect();
            notes.push(format!(
                "{} packets on unsupported link type(s) {} were skipped (supported: {})",
                s.unsupported_link_packets,
                types.join(", "),
                link::SUPPORTED_LINK_TYPES
            ));
        }
        if s.ipv6_packets > 0 {
            notes.push(format!(
                "{} IPv6 packets were ignored; only IPv4 TCP flows are analysed",
                s.ipv6_packets
            ));
        }
        if s.ip_fragments > 0 {
            notes.push(format!(
                "{} IPv4 fragments were not reassembled; TCP streams that relied on them show gaps",
                s.ip_fragments
            ));
        }
        if self.malformed_count > 0 {
            notes.push(format!(
                "{} malformed packets were skipped",
                self.malformed_count
            ));
        }
        if s.ts_backwards > 0 {
            notes.push(format!(
                "{} packets have a timestamp earlier than the packet before them; times are measured from the earliest timestamp",
                s.ts_backwards
            ));
        }
        if s.flows_split > 0 {
            notes.push(format!(
                "{} TCP connections reused an earlier connection's address/port pair and were analysed as separate flows",
                s.flows_split
            ));
        }
        if s.vlan_tagged_packets > 0 {
            notes.push(format!(
                "{} VLAN-tagged frames; tags were stripped for analysis",
                s.vlan_tagged_packets
            ));
        }
        notes
    }
}

#[derive(Debug, Clone)]
pub struct NonIpSourceInfo {
    pub src_mac: MacAddr,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packet_indices: Vec<usize>,
    /// Ethertypes seen under this MAC (e.g., {0x88b8, 0x88ba}).
    pub ethertypes: Vec<u16>,
}

pub fn load<P: AsRef<Path>>(path: P) -> Result<LoadedPcap> {
    let path = path.as_ref().to_path_buf();
    let mut f = File::open(&path).with_context(|| format!("open {path:?}"))?;
    let size = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let mut bytes = Vec::with_capacity(size);
    f.read_to_end(&mut bytes).context("read")?;
    load_vec(bytes, path)
}

/// Fast magic-byte check. Reads only the first 32 bytes of the file
/// and verifies it's classic pcap (any of the 4 known magics) or
/// pcapng (Section Header Block magic). Cheap enough to call before
/// kicking off a slow full parse.
pub fn validate(path: &Path) -> Result<()> {
    let mut f = File::open(path).with_context(|| format!("open {path:?}"))?;
    let mut head = [0u8; 32];
    let n = f.read(&mut head).context("read header")?;
    if n < 4 {
        bail!("file is too short to be a pcap ({n} bytes)");
    }
    let m = &head[..4];
    let is_classic = m == [0xd4, 0xc3, 0xb2, 0xa1]
        || m == [0xa1, 0xb2, 0xc3, 0xd4]
        || m == [0x4d, 0x3c, 0xb2, 0xa1]
        || m == [0xa1, 0xb2, 0x3c, 0x4d];
    let is_pcapng = m == [0x0a, 0x0d, 0x0d, 0x0a];
    if !(is_classic || is_pcapng) {
        bail!(
            "not a pcap or pcapng file (magic {m:02x?}); supported formats are classic pcap and pcapng"
        );
    }
    Ok(())
}

/// Parse a capture held in memory. Copies `bytes` once into the shared
/// packet buffer; use [`load_vec`] to hand over an owned buffer instead.
pub fn load_bytes(bytes: &[u8], path: PathBuf) -> Result<LoadedPcap> {
    load_vec(bytes.to_vec(), path)
}

/// Parse a capture, taking ownership of its bytes. Packets reference
/// this buffer directly; nothing is copied.
pub fn load_vec(bytes: Vec<u8>, path: PathBuf) -> Result<LoadedPcap> {
    let buf = Arc::new(bytes);
    // Dispatch on file format. Classic pcap starts with one of four
    // 4-byte magic sequences; pcapng starts with a Section Header
    // Block (block type 0x0A0D0D0A).
    if buf.len() >= 4 && buf[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
        return load_pcapng(&buf, path);
    }
    load_classic_pcap(&buf, path)
}

/// Offset of `inner` inside `buf`, if `inner` is a sub-slice of it.
fn offset_in(buf: &[u8], inner: &[u8]) -> Option<usize> {
    let start = (inner.as_ptr() as usize).checked_sub(buf.as_ptr() as usize)?;
    (start.checked_add(inner.len())? <= buf.len()).then_some(start)
}

fn load_classic_pcap(buf: &Arc<Vec<u8>>, path: PathBuf) -> Result<LoadedPcap> {
    let mut parser = parse::PcapParser::new(buf)?;
    if !link::is_supported(parser.link_type) {
        bail!(
            "unsupported link type {} (supported: {})",
            parser.link_type,
            link::SUPPORTED_LINK_TYPES
        );
    }
    let link_type = parser.link_type;
    let mut builder = IngestBuilder::new();
    loop {
        match parser.next_record() {
            Ok(Some(rec)) => {
                let data = match offset_in(buf, rec.data) {
                    Some(start) => PacketData::shared(buf, start, rec.data.len()),
                    None => PacketData::from_vec(rec.data.to_vec()),
                };
                builder.push(rec.ts_ns, link_type, data);
            }
            Ok(None) => break,
            Err(e) => {
                if builder.packets.is_empty() {
                    return Err(e);
                }
                builder.truncated(format!("{e:#}"));
                break;
            }
        }
    }
    Ok(builder.finish(path, link_type))
}

fn ns_per_tick_from_resol(byte: u8) -> u64 {
    let exp = (byte & 0x7f) as u32;
    let base2 = (byte & 0x80) != 0;
    // seconds-per-tick = base ^ (-exp); ns/tick = 1e9 * sec/tick.
    if base2 {
        // 2^-exp seconds. ns_per_tick = 1e9 / 2^exp.
        if exp >= 63 {
            return 1;
        }
        let denom = 1u64 << exp;
        ((1_000_000_000f64 / denom as f64).round() as u64).max(1)
    } else {
        // 10^-exp seconds. ns_per_tick = 1e9 / 10^exp.
        // exp=0 → 1e9 (sec); exp=3 → 1e6 (ms); exp=6 → 1e3 (µs);
        // exp=9 → 1 (ns); exp>9 → sub-ns; clamp to 1.
        let mut ns = 1_000_000_000u64;
        for _ in 0..exp {
            ns /= 10;
            if ns == 0 {
                return 1;
            }
        }
        ns.max(1)
    }
}

fn load_pcapng(buf: &Arc<Vec<u8>>, path: PathBuf) -> Result<LoadedPcap> {
    use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
    use pcap_file::pcapng::{Block, PcapNgParser};

    // Parse straight from the shared buffer so packet bytes are
    // borrowed slices of it (zero copy).
    let (mut rest, mut parser) =
        PcapNgParser::new(buf).context("open pcapng (wireshark-native format)")?;

    // pcapng allows multiple interfaces each with its own link type
    // and timestamp resolution. pcap-file v2 hands back EPB.timestamp
    // as a `Duration` whose value is the *raw* 64-bit ts read from
    // the wire — it does NOT scale by the IDB's `if_tsresol` option.
    // We have to compute ns/tick per interface ourselves and multiply.
    //
    // tsresol byte: bit 7 = 1 → base 2, else base 10. Lower 7 bits
    // are the negative exponent. Default (option absent) is 10^-6 s.
    //
    // Interface ids are scoped to a section: both tables are reset on
    // every Section Header Block.
    let mut iface_links: Vec<u32> = Vec::new();
    let mut iface_ns_per_tick: Vec<u64> = Vec::new();
    let mut any_iface = false;
    let mut first_supported_link: Option<u32> = None;
    let mut builder = IngestBuilder::new();

    let push = |builder: &mut IngestBuilder,
                links: &[u32],
                iface: usize,
                ts_ns: u64,
                data: &Cow<'_, [u8]>| {
        let Some(&lt) = links.get(iface) else {
            builder.skip_unsupported_link(u32::MAX);
            return;
        };
        if !link::is_supported(lt) {
            builder.skip_unsupported_link(lt);
            return;
        }
        let pd = match offset_in(buf, data) {
            Some(start) => PacketData::shared(buf, start, data.len()),
            None => PacketData::from_vec(data.to_vec()),
        };
        builder.push(ts_ns, lt, pd);
    };

    while !rest.is_empty() {
        let (next, block) = match parser.next_block(rest) {
            Ok(x) => x,
            Err(e) => {
                if builder.packets.is_empty() {
                    return Err(anyhow::Error::new(e).context("read pcapng block"));
                }
                builder.truncated(format!(
                    "bad or incomplete pcapng block at offset {}: {e}",
                    buf.len() - rest.len()
                ));
                break;
            }
        };
        rest = next;
        match block {
            Block::SectionHeader(_) => {
                iface_links.clear();
                iface_ns_per_tick.clear();
            }
            Block::InterfaceDescription(idb) => {
                any_iface = true;
                let lt = u32::from(idb.linktype);
                if link::is_supported(lt) && first_supported_link.is_none() {
                    first_supported_link = Some(lt);
                }
                iface_links.push(lt);
                let mut npt: u64 = 1_000; // default tsresol = 6 → µs → 1000 ns/tick
                for opt in idb.options.iter() {
                    if let InterfaceDescriptionOption::IfTsResol(byte) = opt {
                        npt = ns_per_tick_from_resol(*byte);
                    }
                }
                iface_ns_per_tick.push(npt);
            }
            Block::EnhancedPacket(epb) => {
                let iface = epb.interface_id as usize;
                let npt = iface_ns_per_tick.get(iface).copied().unwrap_or(1_000);
                let raw_ticks = epb.timestamp.as_nanos() as u64;
                let ts_ns = raw_ticks.saturating_mul(npt);
                push(&mut builder, &iface_links, iface, ts_ns, &epb.data);
            }
            Block::Packet(pb) => {
                let iface = pb.interface_id as usize;
                let npt = iface_ns_per_tick.get(iface).copied().unwrap_or(1_000);
                let ts_ns = pb.timestamp.saturating_mul(npt);
                push(&mut builder, &iface_links, iface, ts_ns, &pb.data);
            }
            Block::SimplePacket(spb) => {
                // SPBs have no interface id or timestamp: they belong to
                // the section's first interface.
                let ts_ns = builder.last_ts.saturating_add(1);
                push(&mut builder, &iface_links, 0, ts_ns, &spb.data);
            }
            _ => {}
        }
    }

    if !any_iface {
        bail!("pcapng has no Interface Description Block — cannot infer link type");
    }
    let Some(link_type) = first_supported_link else {
        bail!(
            "pcapng contains no interface with a supported link type (supported: {})",
            link::SUPPORTED_LINK_TYPES
        );
    };
    Ok(builder.finish(path, link_type))
}

/// Per-flow state only needed during ingest.
#[derive(Default)]
struct FlowTrack {
    /// Next expected sequence number per direction (0 = the canonical
    /// low side, 1 = the other).
    next_seq: [Option<u32>; 2],
    /// Whether this direction's source has had the flow recorded in its
    /// `flow_indices` (keeps ingest O(1) per packet).
    src_recorded: [bool; 2],
    /// Any payload-bearing segment seen.
    payload_seen: bool,
    /// Acknowledgement number of the first SYN-ACK: the client ISN + 1
    /// of the SYN it answers.
    syn_ack_ack: Option<u32>,
}

/// Shared packet-ingest state used by both classic pcap and pcapng
/// loaders so each packet flows through the same classify/flows/
/// source-indexing logic regardless of input format.
struct IngestBuilder {
    packets: Vec<Packet>,
    sources: BTreeMap<Ipv4Addr, SourceInfoBuilder>,
    non_ip_sources: BTreeMap<MacAddr, NonIpSourceInfoBuilder>,
    flows: Vec<Flow>,
    tracks: Vec<FlowTrack>,
    flow_key_to_idx: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), usize>,
    non_ip_count: u64,
    malformed_count: u64,
    min_ts: Option<u64>,
    max_ts: u64,
    last_ts: u64,
    stats: IngestStats,
}

/// Result of classifying one frame.
struct Classified {
    kind: PacketKind,
    src_mac: Option<MacAddr>,
    src_ip: Option<Ipv4Addr>,
    l3_offset: usize,
    /// For TCP: which direction of the flow (0 = canonical low side).
    tcp_dir: Option<usize>,
}

impl IngestBuilder {
    fn new() -> Self {
        Self {
            packets: Vec::new(),
            sources: BTreeMap::new(),
            non_ip_sources: BTreeMap::new(),
            flows: Vec::new(),
            tracks: Vec::new(),
            flow_key_to_idx: HashMap::new(),
            non_ip_count: 0,
            malformed_count: 0,
            min_ts: None,
            max_ts: 0,
            last_ts: 0,
            stats: IngestStats::default(),
        }
    }

    fn truncated(&mut self, why: String) {
        warn!(
            reason = %why,
            kept = self.packets.len(),
            "capture is truncated; keeping packets parsed so far"
        );
        self.stats.truncated_tail = Some(why);
    }

    fn skip_unsupported_link(&mut self, lt: u32) {
        self.stats.unsupported_link_packets += 1;
        if !self.stats.unsupported_link_types.contains(&lt) {
            self.stats.unsupported_link_types.push(lt);
        }
    }

    fn push(&mut self, ts_ns: u64, link_type: u32, data: PacketData) {
        if self.min_ts.is_some() && ts_ns < self.last_ts {
            self.stats.ts_backwards += 1;
        }
        self.min_ts = Some(self.min_ts.map_or(ts_ns, |m| m.min(ts_ns)));
        self.max_ts = self.max_ts.max(ts_ns);
        self.last_ts = ts_ns;

        let pkt_idx = self.packets.len();
        let c = self.classify(link_type, &data, pkt_idx);

        if let (Some(mac), Some(ip)) = (c.src_mac, c.src_ip) {
            let entry = self
                .sources
                .entry(ip)
                .or_insert_with(|| SourceInfoBuilder::new(ip, mac));
            entry.observe(mac, data.len() as u64, pkt_idx);
            if let (PacketKind::Tcp { flow_idx, .. }, Some(dir)) = (&c.kind, c.tcp_dir) {
                let track = &mut self.tracks[*flow_idx];
                let canon = self.flows[*flow_idx].canonical;
                // Both ends may share one IP (two ports on one host):
                // record the flow under that source only once.
                let other_same_ip = canon.0 == canon.2 && track.src_recorded[1 - dir];
                if !track.src_recorded[dir] {
                    track.src_recorded[dir] = true;
                    if !other_same_ip {
                        entry.flow_indices.push(*flow_idx);
                    }
                }
            }
        } else if let (Some(mac), None, PacketKind::NonIp { ethertype }) =
            (c.src_mac, c.src_ip, &c.kind)
        {
            let entry = self
                .non_ip_sources
                .entry(mac)
                .or_insert_with(|| NonIpSourceInfoBuilder::new(mac));
            entry.observe(*ethertype, data.len() as u64, pkt_idx);
        }

        self.packets.push(Packet {
            ts_ns,
            rel_ts_ns: 0, // filled in by finish() once the minimum is known
            data,
            src_mac: c.src_mac,
            src_ip: c.src_ip,
            kind: c.kind,
            link_type: link_type as u16,
            l3_offset: c.l3_offset as u16,
        });
    }

    fn malformed(
        &mut self,
        src_mac: Option<MacAddr>,
        src_ip: Option<Ipv4Addr>,
        l3_offset: usize,
    ) -> Classified {
        self.malformed_count += 1;
        Classified {
            kind: PacketKind::Malformed,
            src_mac,
            src_ip,
            l3_offset,
            tcp_dir: None,
        }
    }

    fn classify(&mut self, link_type: u32, data: &[u8], this_pkt_idx: usize) -> Classified {
        let Some(view) = link::parse(link_type, data) else {
            return self.malformed(None, None, 0);
        };
        if view.vlan_tags > 0 {
            self.stats.vlan_tagged_packets += 1;
        }
        let l3_off = view.l3_offset;
        if view.ethertype != ETHERTYPE_IPV4 {
            if view.ethertype == ETHERTYPE_IPV6 {
                self.stats.ipv6_packets += 1;
            }
            self.non_ip_count += 1;
            return Classified {
                kind: PacketKind::NonIp {
                    ethertype: view.ethertype,
                },
                src_mac: view.src_mac,
                src_ip: None,
                l3_offset: l3_off,
                tcp_dir: None,
            };
        }
        let l3 = &data[l3_off..];
        let Some(ip) = Ipv4Header::parse(l3) else {
            return self.malformed(view.src_mac, None, l3_off);
        };
        let src_ip = ip.src;
        let src_mac = Some(view.src_mac.unwrap_or_else(|| link::synthetic_mac(src_ip)));
        let ok = |kind| Classified {
            kind,
            src_mac,
            src_ip: Some(src_ip),
            l3_offset: l3_off,
            tcp_dir: None,
        };
        if ip.is_fragment {
            self.stats.ip_fragments += 1;
            return ok(PacketKind::IpFragment { proto: ip.proto });
        }

        match ip.proto {
            IPPROTO_TCP => {
                let Some(seg) = TcpSegment::parse(l3, &ip) else {
                    return self.malformed(src_mac, Some(src_ip), l3_off);
                };
                let (flow_idx, dir) = self.flow_for(&ip, &seg, this_pkt_idx);
                let flow = &self.flows[flow_idx];
                let role = match flow.client {
                    Some((c_ip, c_port)) if c_ip == src_ip && c_port == seg.src_port => {
                        FlowRole::Client
                    }
                    Some(_) => FlowRole::Server,
                    None => FlowRole::Unknown,
                };
                debug!(canon = ?flow.canonical, flags = seg.flags, ?role, "classified TCP packet");
                Classified {
                    kind: PacketKind::Tcp {
                        flow_idx,
                        role,
                        flags: seg.flags,
                    },
                    src_mac,
                    src_ip: Some(src_ip),
                    l3_offset: l3_off,
                    tcp_dir: Some(dir),
                }
            }
            IPPROTO_UDP => ok(PacketKind::Udp),
            IPPROTO_ICMP => ok(PacketKind::Icmp),
            other => ok(PacketKind::IpOther { proto: other }),
        }
    }

    /// Find (or create) the flow a TCP segment belongs to, update its
    /// state and return `(flow_idx, direction)`.
    fn flow_for(
        &mut self,
        ip: &Ipv4Header,
        seg: &TcpSegment<'_>,
        this_pkt_idx: usize,
    ) -> (usize, usize) {
        let (src_ip, dst_ip) = (ip.src, ip.dst);
        let (src_port, dst_port) = (seg.src_port, seg.dst_port);
        let canon = FiveTuple {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
        .canonical();
        let dir = usize::from((src_ip, src_port) != (canon.0, canon.1));
        let flags = seg.flags;
        let is_syn = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
        let is_syn_ack = flags & TCP_SYN != 0 && flags & TCP_ACK != 0;

        let existing = self.flow_key_to_idx.get(&canon).copied();
        let mut split = false;
        // Flow the segment joins when it does not split: normally the
        // current one on the 4-tuple, but a stale segment of an earlier
        // connection (a retransmit captured after the reconnect's SYN)
        // goes back to that connection instead of splitting the new
        // one apart (N16).
        let mut target = existing;
        if let Some(idx) = existing {
            let f = &self.flows[idx];
            let t = &self.tracks[idx];
            if is_syn {
                // A fresh SYN after the connection closed, with a
                // different ISN, or after data has flowed (a reconnect
                // reusing a fixed ISN without FIN/RST, N17) is a new
                // connection. A retransmitted SYN (same ISN, before any
                // data) is not. Nor is the flow's own SYN recorded after
                // the SYN-ACK that acknowledges its ISN (a capture
                // merged from two vantage points slightly out of
                // order, T17c): the ISN match is exact, so a reconnect
                // is never mistaken for it.
                let own_late_syn = !f.saw_syn
                    && !f.saw_fin
                    && !f.saw_rst
                    && t.syn_ack_ack == Some(seg.seq.wrapping_add(1));
                split = !own_late_syn
                    && (f.saw_fin
                        || f.saw_rst
                        || t.payload_seen
                        || f.client_isn.is_some_and(|isn| isn != seg.seq));
            } else if flags & TCP_SYN == 0 {
                let cur = self.seq_dist(idx, dir, seg.seq);
                if cur != Some(0) {
                    match self.closest_earlier_flow(idx, dir, seg.seq) {
                        // Closer to where an earlier connection left
                        // off than to the current one.
                        Some((prev, d)) if cur.is_none_or(|c| d < c) => target = Some(prev),
                        // Sequence number nowhere near where this
                        // direction left off: a different connection
                        // whose handshake was not captured.
                        _ => {
                            split =
                                flags & TCP_RST == 0 && cur.is_some_and(|c| c > SEQ_JUMP_NEW_FLOW);
                        }
                    }
                }
            }
        }

        let flow_idx = match target {
            Some(idx) if !split => idx,
            _ => {
                let idx = self.flows.len();
                if split {
                    self.stats.flows_split += 1;
                }
                self.flows.push(Flow {
                    canonical: canon,
                    client: None,
                    server: None,
                    packet_indices: Vec::new(),
                    saw_syn: false,
                    saw_syn_ack: false,
                    saw_fin: false,
                    saw_rst: false,
                    client_isn: None,
                    server_isn: None,
                    previous_on_tuple: existing,
                });
                self.tracks.push(FlowTrack::default());
                self.flow_key_to_idx.insert(canon, idx);
                idx
            }
        };

        let flow = &mut self.flows[flow_idx];
        let track = &mut self.tracks[flow_idx];
        flow.packet_indices.push(this_pkt_idx);

        // Assign roles.
        if is_syn {
            flow.saw_syn = true;
            flow.client_isn.get_or_insert(seg.seq);
            flow.client = Some((src_ip, src_port));
            flow.server = Some((dst_ip, dst_port));
        }
        if is_syn_ack {
            flow.saw_syn_ack = true;
            flow.server_isn.get_or_insert(seg.seq);
            track.syn_ack_ack.get_or_insert(seg.ack);
            // In case SYN wasn't observed.
            if flow.client.is_none() {
                flow.client = Some((dst_ip, dst_port));
                flow.server = Some((src_ip, src_port));
            }
        }
        if flags & TCP_FIN != 0 {
            flow.saw_fin = true;
        }
        if flags & TCP_RST != 0 {
            flow.saw_rst = true;
        }
        // Mid-flow capture: no SYN or SYN-ACK observed for this flow.
        // Seed roles using the well-known-port heuristic (lower port = server).
        // Falls back to first-packet direction only when ports tie.
        if flow.client.is_none() {
            let (client_side, server_side) = if dst_port < src_port {
                ((src_ip, src_port), (dst_ip, dst_port))
            } else if src_port < dst_port {
                ((dst_ip, dst_port), (src_ip, src_port))
            } else {
                ((src_ip, src_port), (dst_ip, dst_port))
            };
            flow.client = Some(client_side);
            flow.server = Some(server_side);
        }

        // Track where this direction's sequence space has got to.
        if flags & TCP_RST == 0 {
            let consumed = seg
                .payload_len_declared
                .wrapping_add(u32::from(flags & TCP_SYN != 0))
                .wrapping_add(u32::from(flags & TCP_FIN != 0));
            let end = seg.seq.wrapping_add(consumed);
            let advance = match track.next_seq[dir] {
                None => true,
                Some(next) => (end.wrapping_sub(next) as i32) > 0,
            };
            if advance {
                track.next_seq[dir] = Some(end);
            }
        }
        if seg.payload_len_declared > 0 {
            track.payload_seen = true;
        }
        (flow_idx, dir)
    }

    /// Distance of `seq` from where direction `dir` of flow `idx` left
    /// off; `None` if that direction has not been seen.
    fn seq_dist(&self, idx: usize, dir: usize, seq: u32) -> Option<u32> {
        self.tracks[idx].next_seq[dir].map(|next| (seq.wrapping_sub(next) as i32).unsigned_abs())
    }

    /// Among the earlier flows on the same 4-tuple (following
    /// `previous_on_tuple`, a few steps back), the one whose direction
    /// `dir` left off closest to `seq`, if within
    /// [`SEQ_JUMP_NEW_FLOW`], with that distance.
    fn closest_earlier_flow(&self, idx: usize, dir: usize, seq: u32) -> Option<(usize, u32)> {
        let mut best: Option<(usize, u32)> = None;
        let mut prev = self.flows[idx].previous_on_tuple;
        for _ in 0..8 {
            let Some(p) = prev else { break };
            if let Some(d) = self
                .seq_dist(p, dir, seq)
                .filter(|d| *d <= SEQ_JUMP_NEW_FLOW)
            {
                if best.is_none_or(|(_, b)| d < b) {
                    best = Some((p, d));
                }
            }
            prev = self.flows[p].previous_on_tuple;
        }
        best
    }

    fn finish(self, path: PathBuf, link_type: u32) -> LoadedPcap {
        let IngestBuilder {
            mut packets,
            sources,
            non_ip_sources,
            flows,
            non_ip_count,
            malformed_count,
            min_ts,
            max_ts,
            stats,
            ..
        } = self;
        let base = min_ts.unwrap_or(0);
        for p in &mut packets {
            p.rel_ts_ns = p.ts_ns.saturating_sub(base);
        }
        if stats.ts_backwards > 0 {
            warn!(
                count = stats.ts_backwards,
                "capture has out-of-order timestamps; relative times use the earliest as zero"
            );
        }
        let sources: BTreeMap<_, _> = sources
            .into_iter()
            .map(|(ip, b)| (ip, b.finish()))
            .collect();
        let non_ip_sources: BTreeMap<_, _> = non_ip_sources
            .into_iter()
            .map(|(mac, b)| (mac, b.finish()))
            .collect();
        LoadedPcap {
            path,
            link_type,
            first_ts_ns: base,
            last_ts_ns: max_ts,
            packets,
            sources,
            flows,
            non_ip_sources,
            non_ip_count,
            malformed_count,
            ingest: stats,
        }
    }
}

/// The parts of an IPv4 header the loader needs.
pub(crate) struct Ipv4Header {
    hdr_len: usize,
    /// End of the IP datagram within the L3 slice: `total_length`
    /// clamped to the captured bytes. A zero `total_length` (TSO/GSO
    /// on the capturing host) means "use the captured length".
    end: usize,
    /// Payload length the header declares (total_length - header).
    declared_l4: usize,
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    /// MF set or fragment offset non-zero.
    is_fragment: bool,
}

impl Ipv4Header {
    fn parse(l3: &[u8]) -> Option<Self> {
        if l3.len() < 20 || l3[0] >> 4 != 4 {
            return None;
        }
        let hdr_len = (l3[0] & 0x0f) as usize * 4;
        if hdr_len < 20 || l3.len() < hdr_len {
            return None;
        }
        let total_len = u16::from_be_bytes([l3[2], l3[3]]) as usize;
        let (end, declared_l4) = if total_len == 0 {
            (l3.len(), l3.len() - hdr_len)
        } else if total_len < hdr_len {
            return None;
        } else {
            (total_len.min(l3.len()), total_len - hdr_len)
        };
        let flags_frag = u16::from_be_bytes([l3[6], l3[7]]);
        let is_fragment = flags_frag & 0x2000 != 0 || flags_frag & 0x1fff != 0;
        Some(Self {
            hdr_len,
            end,
            declared_l4,
            proto: l3[9],
            src: Ipv4Addr::new(l3[12], l3[13], l3[14], l3[15]),
            dst: Ipv4Addr::new(l3[16], l3[17], l3[18], l3[19]),
            is_fragment,
        })
    }
}

/// A parsed TCP segment, borrowing its payload from the frame.
pub(crate) struct TcpSegment<'a> {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    /// Acknowledgement number (meaningful with ACK set).
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    /// Captured payload bytes (shorter than declared when the capture
    /// used a snaplen).
    pub(crate) payload: &'a [u8],
    /// Payload length according to the IP header, i.e. how much
    /// sequence space the segment consumes.
    pub(crate) payload_len_declared: u32,
}

impl<'a> TcpSegment<'a> {
    /// Parse the TCP header that follows `ip` in `l3`. Returns `None`
    /// when the header is cut short, the data offset is below 5 words,
    /// or the data offset points past the declared datagram.
    fn parse(l3: &'a [u8], ip: &Ipv4Header) -> Option<Self> {
        let tcp = l3.get(ip.hdr_len..ip.end)?;
        if tcp.len() < 20 {
            return None;
        }
        let data_off = (tcp[12] >> 4) as usize * 4;
        if data_off < 20 || ip.declared_l4 < data_off {
            return None;
        }
        let payload = tcp.get(data_off..).unwrap_or(&[]);
        Some(Self {
            src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
            seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
            flags: tcp[13],
            payload,
            payload_len_declared: (ip.declared_l4 - data_off) as u32,
        })
    }
}

/// Parse the TCP segment of an already-classified packet. `None` for
/// non-TCP packets, fragments and malformed headers.
pub(crate) fn tcp_segment(pkt: &Packet) -> Option<TcpSegment<'_>> {
    if !matches!(pkt.kind, PacketKind::Tcp { .. }) {
        return None;
    }
    let l3 = pkt.l3();
    let ip = Ipv4Header::parse(l3)?;
    if ip.proto != IPPROTO_TCP || ip.is_fragment {
        return None;
    }
    TcpSegment::parse(l3, &ip)
}

struct NonIpSourceInfoBuilder {
    src_mac: MacAddr,
    packet_count: u64,
    byte_count: u64,
    packet_indices: Vec<usize>,
    ethertypes: Vec<u16>,
}

impl NonIpSourceInfoBuilder {
    fn new(src_mac: MacAddr) -> Self {
        Self {
            src_mac,
            packet_count: 0,
            byte_count: 0,
            packet_indices: Vec::new(),
            ethertypes: Vec::new(),
        }
    }
    fn observe(&mut self, ethertype: u16, bytes: u64, pkt_idx: usize) {
        self.packet_count += 1;
        self.byte_count += bytes;
        self.packet_indices.push(pkt_idx);
        if !self.ethertypes.contains(&ethertype) {
            self.ethertypes.push(ethertype);
        }
    }
    fn finish(self) -> NonIpSourceInfo {
        NonIpSourceInfo {
            src_mac: self.src_mac,
            packet_count: self.packet_count,
            byte_count: self.byte_count,
            packet_indices: self.packet_indices,
            ethertypes: self.ethertypes,
        }
    }
}

struct SourceInfoBuilder {
    src_ip: Ipv4Addr,
    mac_counts: HashMap<MacAddr, u64>,
    initial_mac: MacAddr,
    packet_count: u64,
    byte_count: u64,
    packet_indices: Vec<usize>,
    flow_indices: Vec<usize>,
}

impl SourceInfoBuilder {
    fn new(src_ip: Ipv4Addr, first_mac: MacAddr) -> Self {
        Self {
            src_ip,
            mac_counts: HashMap::new(),
            initial_mac: first_mac,
            packet_count: 0,
            byte_count: 0,
            packet_indices: Vec::new(),
            flow_indices: Vec::new(),
        }
    }

    fn observe(&mut self, mac: MacAddr, bytes: u64, pkt_idx: usize) {
        *self.mac_counts.entry(mac).or_insert(0) += 1;
        self.packet_count += 1;
        self.byte_count += bytes;
        self.packet_indices.push(pkt_idx);
    }

    fn finish(self) -> SourceInfo {
        let mac_collision = self.mac_counts.len() > 1;
        let chosen = self
            .mac_counts
            .iter()
            .max_by_key(|(_, n)| *n)
            .map(|(m, _)| *m)
            .unwrap_or(self.initial_mac);
        if mac_collision {
            warn!(
                ip = %self.src_ip,
                macs = self.mac_counts.len(),
                chosen = ?chosen,
                "multiple MACs observed for one source IP"
            );
        }
        SourceInfo {
            src_ip: self.src_ip,
            src_mac: chosen,
            mac_collision,
            packet_count: self.packet_count,
            byte_count: self.byte_count,
            packet_indices: self.packet_indices,
            flow_indices: self.flow_indices,
        }
    }
}

#[cfg(test)]
mod tests;
