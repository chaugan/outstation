//! Parse a classic pcap file, classify every Ethernet/IPv4 frame, and
//! build an index of sources and TCP flows.
//!
//! Scope for v1:
//! * classic pcap (no pcapng yet); both 0xa1b2c3d4 (µs) and 0xa1b23c4d (ns);
//!   both big- and little-endian magic.
//! * LINKTYPE_ETHERNET only.
//! * classifies packets as TCP / UDP / ICMP / other-IP / non-IP;
//! * indexes by (src_mac, src_ip) with collision detection;
//! * identifies TCP flows by a canonical 5-tuple and records directionality.
//!
//! Out of scope for now: payload reassembly, fragmentation, IPv6, VLAN.
//! Those get added when the consumers need them.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::{debug, warn};

pub mod parse;

pub type MacAddr = [u8; 6];

const LINKTYPE_ETHERNET: u32 = 1;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// TCP flag bits.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

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
    Tcp { flow_idx: usize, role: FlowRole, flags: u8 },
    Udp,
    Icmp,
    IpOther { proto: u8 },
    NonIp { ethertype: u16 },
    Malformed,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub ts_ns: u64,
    pub rel_ts_ns: u64,
    pub data: Vec<u8>,
    pub src_mac: Option<MacAddr>,
    pub src_ip: Option<Ipv4Addr>,
    pub kind: PacketKind,
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
}

#[derive(Debug, Clone)]
pub struct LoadedPcap {
    pub path: PathBuf,
    pub link_type: u32,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
    pub packets: Vec<Packet>,
    pub sources: BTreeMap<Ipv4Addr, SourceInfo>,
    pub flows: Vec<Flow>,
    /// Non-IP senders indexed by source MAC. Used by `l2_replay` for
    /// GOOSE / SV / raw L2 replay where IP does not apply.
    pub non_ip_sources: BTreeMap<MacAddr, NonIpSourceInfo>,
    pub non_ip_count: u64,
    pub malformed_count: u64,
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
    let size = f.seek(SeekFrom::End(0)).context("seek end")?;
    f.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(size as usize);
    f.read_to_end(&mut bytes).context("read")?;
    load_bytes(&bytes, path)
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

pub fn load_bytes(bytes: &[u8], path: PathBuf) -> Result<LoadedPcap> {
    // Dispatch on file format. Classic pcap starts with one of four
    // 4-byte magic sequences; pcapng starts with a Section Header
    // Block (block type 0x0A0D0D0A).
    if bytes.len() >= 4 && &bytes[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
        return load_pcapng(bytes, path);
    }
    load_classic_pcap(bytes, path)
}

fn load_classic_pcap(bytes: &[u8], path: PathBuf) -> Result<LoadedPcap> {
    let mut parser = parse::PcapParser::new(bytes)?;
    if parser.link_type != LINKTYPE_ETHERNET {
        bail!(
            "unsupported link type {} (only LINKTYPE_ETHERNET=1 in v1)",
            parser.link_type
        );
    }

    let mut builder = IngestBuilder::new();
    while let Some(rec) = parser.next_record()? {
        builder.push(rec.ts_ns, rec.data.to_vec());
    }
    Ok(builder.finish(path, parser.link_type))
}

fn load_pcapng(bytes: &[u8], path: PathBuf) -> Result<LoadedPcap> {
    use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
    use pcap_file::pcapng::{Block, PcapNgReader};
    use pcap_file::DataLink;
    use std::io::Cursor;

    let mut reader = PcapNgReader::new(Cursor::new(bytes))
        .context("open pcapng (wireshark-native format)")?;

    // pcapng allows multiple interfaces each with its own link type
    // and timestamp resolution. pcap-file v2 hands back EPB.timestamp
    // as a `Duration` whose value is the *raw* 64-bit ts read from
    // the wire — it does NOT scale by the IDB's `if_tsresol` option.
    // We have to compute ns/tick per interface ourselves and multiply.
    //
    // tsresol byte: bit 7 = 1 → base 2, else base 10. Lower 7 bits
    // are the negative exponent. Default (option absent) is 10^-6 s.
    let mut iface_links: Vec<DataLink> = Vec::new();
    let mut iface_ns_per_tick: Vec<u64> = Vec::new();
    let mut builder = IngestBuilder::new();

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

    while let Some(block_res) = reader.next_block() {
        let block = block_res.context("read pcapng block")?;
        match block {
            Block::InterfaceDescription(idb) => {
                iface_links.push(idb.linktype);
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
                let link = iface_links.get(iface).copied().unwrap_or(DataLink::ETHERNET);
                if !matches!(link, DataLink::ETHERNET) {
                    continue;
                }
                let npt = iface_ns_per_tick.get(iface).copied().unwrap_or(1_000);
                let raw_ticks = epb.timestamp.as_nanos() as u64;
                let ts_ns = raw_ticks.saturating_mul(npt);
                builder.push(ts_ns, epb.data.to_vec());
            }
            Block::SimplePacket(spb) => {
                let ts_ns = builder.last_ts.saturating_add(1);
                builder.push(ts_ns, spb.data.to_vec());
            }
            _ => {}
        }
    }

    if iface_links.is_empty() {
        bail!("pcapng has no Interface Description Block — cannot infer link type");
    }
    if !iface_links.iter().any(|l| matches!(l, DataLink::ETHERNET)) {
        bail!("pcapng contains no Ethernet interfaces (only LINKTYPE_ETHERNET is supported)");
    }
    Ok(builder.finish(path, LINKTYPE_ETHERNET))
}

/// Shared packet-ingest state used by both classic pcap and pcapng
/// loaders so each packet flows through the same classify/flows/
/// source-indexing logic regardless of input format.
struct IngestBuilder {
    packets: Vec<Packet>,
    sources: BTreeMap<Ipv4Addr, SourceInfoBuilder>,
    non_ip_sources: BTreeMap<MacAddr, NonIpSourceInfoBuilder>,
    flows: Vec<Flow>,
    flow_key_to_idx: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), usize>,
    non_ip_count: u64,
    malformed_count: u64,
    first_ts: Option<u64>,
    last_ts: u64,
}

impl IngestBuilder {
    fn new() -> Self {
        Self {
            packets: Vec::new(),
            sources: BTreeMap::new(),
            non_ip_sources: BTreeMap::new(),
            flows: Vec::new(),
            flow_key_to_idx: HashMap::new(),
            non_ip_count: 0,
            malformed_count: 0,
            first_ts: None,
            last_ts: 0,
        }
    }

    fn push(&mut self, ts_ns: u64, data: Vec<u8>) {
        if self.first_ts.is_none() {
            self.first_ts = Some(ts_ns);
        }
        self.last_ts = ts_ns;
        let rel = ts_ns - self.first_ts.unwrap_or(ts_ns);

        let (kind, src_mac, src_ip) = classify(
            &data,
            &mut self.flows,
            &mut self.flow_key_to_idx,
            self.packets.len(),
            &mut self.malformed_count,
            &mut self.non_ip_count,
        );

        if let (Some(mac), Some(ip)) = (src_mac, src_ip) {
            let entry = self
                .sources
                .entry(ip)
                .or_insert_with(|| SourceInfoBuilder::new(ip, mac));
            entry.observe(mac, data.len() as u64, self.packets.len());
            if let PacketKind::Tcp { flow_idx, .. } = &kind {
                if !entry.flow_indices.contains(flow_idx) {
                    entry.flow_indices.push(*flow_idx);
                }
            }
        } else if let (Some(mac), None, PacketKind::NonIp { ethertype }) =
            (src_mac, src_ip, &kind)
        {
            let entry = self
                .non_ip_sources
                .entry(mac)
                .or_insert_with(|| NonIpSourceInfoBuilder::new(mac));
            entry.observe(*ethertype, data.len() as u64, self.packets.len());
        }

        self.packets.push(Packet {
            ts_ns,
            rel_ts_ns: rel,
            data,
            src_mac,
            src_ip,
            kind,
        });
    }

    fn finish(self, path: PathBuf, link_type: u32) -> LoadedPcap {
        let IngestBuilder {
            packets,
            sources,
            non_ip_sources,
            flows,
            non_ip_count,
            malformed_count,
            first_ts,
            last_ts,
            ..
        } = self;
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
            first_ts_ns: first_ts.unwrap_or(0),
            last_ts_ns: last_ts,
            packets,
            sources,
            flows,
            non_ip_sources,
            non_ip_count,
            malformed_count,
        }
    }
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

fn classify(
    data: &[u8],
    flows: &mut Vec<Flow>,
    flow_key_to_idx: &mut HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), usize>,
    this_pkt_idx: usize,
    malformed_count: &mut u64,
    non_ip_count: &mut u64,
) -> (PacketKind, Option<MacAddr>, Option<Ipv4Addr>) {
    if data.len() < 14 {
        *malformed_count += 1;
        return (PacketKind::Malformed, None, None);
    }
    let src_mac: MacAddr = data[6..12].try_into().unwrap();
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        *non_ip_count += 1;
        return (PacketKind::NonIp { ethertype }, Some(src_mac), None);
    }
    if data.len() < 14 + 20 {
        *malformed_count += 1;
        return (PacketKind::Malformed, Some(src_mac), None);
    }
    let ihl = (data[14] & 0x0f) as usize;
    if ihl < 5 || data.len() < 14 + ihl * 4 {
        *malformed_count += 1;
        return (PacketKind::Malformed, Some(src_mac), None);
    }
    let proto = data[23];
    let src_ip = Ipv4Addr::from([data[26], data[27], data[28], data[29]]);
    let dst_ip = Ipv4Addr::from([data[30], data[31], data[32], data[33]]);
    let l4_off = 14 + ihl * 4;

    match proto {
        IPPROTO_TCP => {
            if data.len() < l4_off + 20 {
                return (PacketKind::Malformed, Some(src_mac), Some(src_ip));
            }
            let src_port = u16::from_be_bytes([data[l4_off], data[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([data[l4_off + 2], data[l4_off + 3]]);
            let flags = data[l4_off + 13];
            let tuple = FiveTuple {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            };
            let canon = tuple.canonical();
            let flow_idx = match flow_key_to_idx.get(&canon) {
                Some(&idx) => idx,
                None => {
                    let idx = flows.len();
                    flows.push(Flow {
                        canonical: canon,
                        client: None,
                        server: None,
                        packet_indices: Vec::new(),
                        saw_syn: false,
                        saw_syn_ack: false,
                        saw_fin: false,
                        saw_rst: false,
                    });
                    flow_key_to_idx.insert(canon, idx);
                    idx
                }
            };
            let flow = &mut flows[flow_idx];
            flow.packet_indices.push(this_pkt_idx);

            // Assign roles.
            let is_syn = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
            let is_syn_ack = flags & TCP_SYN != 0 && flags & TCP_ACK != 0;
            if is_syn {
                flow.saw_syn = true;
                flow.client = Some((src_ip, src_port));
                flow.server = Some((dst_ip, dst_port));
            }
            if is_syn_ack {
                flow.saw_syn_ack = true;
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
            let role = match flow.client {
                Some((c_ip, c_port)) if c_ip == src_ip && c_port == src_port => FlowRole::Client,
                Some(_) => FlowRole::Server,
                None => FlowRole::Unknown,
            };
            debug!(
                ?canon, flags, ?role, "classified TCP packet"
            );
            (
                PacketKind::Tcp {
                    flow_idx,
                    role,
                    flags,
                },
                Some(src_mac),
                Some(src_ip),
            )
        }
        IPPROTO_UDP => (PacketKind::Udp, Some(src_mac), Some(src_ip)),
        IPPROTO_ICMP => (PacketKind::Icmp, Some(src_mac), Some(src_ip)),
        other => (PacketKind::IpOther { proto: other }, Some(src_mac), Some(src_ip)),
    }
}

/// A reassembled TCP flow payload ready for session-mode replay.
#[derive(Debug, Clone)]
pub struct ReassembledFlow {
    pub flow_idx: usize,
    pub client: (Ipv4Addr, u16),
    pub server: (Ipv4Addr, u16),
    pub payload: Vec<u8>,
    /// Number of client bytes that were retransmits, silently dropped.
    pub dup_bytes: usize,
    /// One entry per contributing source packet:
    /// `(pkt_rel_ts_ns, byte_offset_in_payload_where_that_packet_starts)`.
    /// Used by callers that want to correlate payload bytes back to
    /// their source packet's timestamp (e.g., pacing a replay to
    /// match the original inter-frame cadence).
    pub packet_offsets: Vec<(u64, usize)>,
}

impl ReassembledFlow {
    /// Look up the source-packet timestamp for a byte in the
    /// reassembled payload. Returns the rel-ts (ns) of the latest
    /// packet whose payload starts at or before `byte_offset`.
    pub fn ts_for_byte(&self, byte_offset: usize) -> u64 {
        // packet_offsets is sorted by byte offset. Binary search for
        // the last entry with offset <= byte_offset.
        let mut lo = 0usize;
        let mut hi = self.packet_offsets.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.packet_offsets[mid].1 <= byte_offset {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return self
                .packet_offsets
                .first()
                .map(|p| p.0)
                .unwrap_or(0);
        }
        self.packet_offsets[lo - 1].0
    }
}

impl LoadedPcap {
    /// Reassemble the client-side byte stream of a TCP flow. Returns
    /// `Err` if the flow has gaps, missing SYN, or is simply empty — the
    /// caller should fall back to raw injection for those flows.
    pub fn reassemble_client_payload(&self, flow_idx: usize) -> anyhow::Result<ReassembledFlow> {
        use anyhow::{anyhow, bail};
        let flow = self
            .flows
            .get(flow_idx)
            .ok_or_else(|| anyhow!("flow index {flow_idx} out of range"))?;
        let client = flow
            .client
            .ok_or_else(|| anyhow!("flow has no identified client side"))?;
        let server = flow
            .server
            .ok_or_else(|| anyhow!("flow has no identified server side"))?;

        // Gather client segments as (seq, payload_bytes, rel_ts_ns).
        let mut segments: Vec<(u32, Vec<u8>, u64)> = Vec::new();
        for &pkt_idx in &flow.packet_indices {
            let pkt = &self.packets[pkt_idx];
            if pkt.src_ip != Some(client.0) {
                continue;
            }
            let data = &pkt.data;
            if data.len() < 14 + 20 + 20 {
                continue;
            }
            let ihl = (data[14] & 0x0f) as usize;
            let ip_end = 14 + ihl * 4;
            if data.len() < ip_end + 20 || data[23] != IPPROTO_TCP {
                continue;
            }
            let src_port = u16::from_be_bytes([data[ip_end], data[ip_end + 1]]);
            if src_port != client.1 {
                continue;
            }
            let seq = u32::from_be_bytes([
                data[ip_end + 4],
                data[ip_end + 5],
                data[ip_end + 6],
                data[ip_end + 7],
            ]);
            let data_off = ((data[ip_end + 12] >> 4) & 0x0f) as usize;
            let tcp_hdr_len = data_off * 4;
            let payload_start = ip_end + tcp_hdr_len;
            let total_ip_len = u16::from_be_bytes([data[16], data[17]]) as usize;
            let ip_payload_end = (14 + total_ip_len).min(data.len());
            if payload_start >= ip_payload_end {
                continue;
            }
            segments.push((seq, data[payload_start..ip_payload_end].to_vec(), pkt.rel_ts_ns));
        }
        if segments.is_empty() {
            bail!("flow {flow_idx} has no client payload bytes");
        }
        segments.sort_by_key(|(s, _, _)| *s);

        let base = segments[0].0;
        let mut expected = base;
        let mut out = Vec::new();
        let mut dup_bytes = 0usize;
        let mut packet_offsets: Vec<(u64, usize)> = Vec::new();
        for (seq, payload, ts) in segments {
            let diff = seq.wrapping_sub(expected);
            if diff == 0 {
                packet_offsets.push((ts, out.len()));
                out.extend_from_slice(&payload);
                expected = expected.wrapping_add(payload.len() as u32);
            } else if diff & 0x8000_0000 != 0 {
                let skip = expected.wrapping_sub(seq) as usize;
                if skip >= payload.len() {
                    dup_bytes += payload.len();
                    continue;
                }
                dup_bytes += skip;
                packet_offsets.push((ts, out.len()));
                out.extend_from_slice(&payload[skip..]);
                expected = expected.wrapping_add((payload.len() - skip) as u32);
            } else {
                bail!(
                    "gap in client stream: expected seq {expected}, got {seq} (flow {flow_idx})"
                );
            }
        }
        Ok(ReassembledFlow {
            flow_idx,
            client,
            server,
            payload: out,
            dup_bytes,
            packet_offsets,
        })
    }

    /// Mirror of [`LoadedPcap::reassemble_client_payload`] that extracts
    /// the **server-originated** byte stream of a TCP flow. Used by
    /// slave-mode benchmark replay: outstation accepts the master's
    /// connection and plays these bytes back as the server side.
    pub fn reassemble_server_payload(&self, flow_idx: usize) -> anyhow::Result<ReassembledFlow> {
        use anyhow::{anyhow, bail};
        let flow = self
            .flows
            .get(flow_idx)
            .ok_or_else(|| anyhow!("flow index {flow_idx} out of range"))?;
        let client = flow
            .client
            .ok_or_else(|| anyhow!("flow has no identified client side"))?;
        let server = flow
            .server
            .ok_or_else(|| anyhow!("flow has no identified server side"))?;

        let mut segments: Vec<(u32, Vec<u8>, u64)> = Vec::new();
        for &pkt_idx in &flow.packet_indices {
            let pkt = &self.packets[pkt_idx];
            if pkt.src_ip != Some(server.0) {
                continue;
            }
            let data = &pkt.data;
            if data.len() < 14 + 20 + 20 {
                continue;
            }
            let ihl = (data[14] & 0x0f) as usize;
            let ip_end = 14 + ihl * 4;
            if data.len() < ip_end + 20 || data[23] != IPPROTO_TCP {
                continue;
            }
            let src_port = u16::from_be_bytes([data[ip_end], data[ip_end + 1]]);
            if src_port != server.1 {
                continue;
            }
            let seq = u32::from_be_bytes([
                data[ip_end + 4],
                data[ip_end + 5],
                data[ip_end + 6],
                data[ip_end + 7],
            ]);
            let data_off = ((data[ip_end + 12] >> 4) & 0x0f) as usize;
            let tcp_hdr_len = data_off * 4;
            let payload_start = ip_end + tcp_hdr_len;
            let total_ip_len = u16::from_be_bytes([data[16], data[17]]) as usize;
            let ip_payload_end = (14 + total_ip_len).min(data.len());
            if payload_start >= ip_payload_end {
                continue;
            }
            segments.push((seq, data[payload_start..ip_payload_end].to_vec(), pkt.rel_ts_ns));
        }
        if segments.is_empty() {
            bail!("flow {flow_idx} has no server payload bytes");
        }
        segments.sort_by_key(|(s, _, _)| *s);

        let base = segments[0].0;
        let mut expected = base;
        let mut out = Vec::new();
        let mut dup_bytes = 0usize;
        let mut packet_offsets: Vec<(u64, usize)> = Vec::new();
        for (seq, payload, ts) in segments {
            let diff = seq.wrapping_sub(expected);
            if diff == 0 {
                packet_offsets.push((ts, out.len()));
                out.extend_from_slice(&payload);
                expected = expected.wrapping_add(payload.len() as u32);
            } else if diff & 0x8000_0000 != 0 {
                let skip = expected.wrapping_sub(seq) as usize;
                if skip >= payload.len() {
                    dup_bytes += payload.len();
                    continue;
                }
                dup_bytes += skip;
                packet_offsets.push((ts, out.len()));
                out.extend_from_slice(&payload[skip..]);
                expected = expected.wrapping_add((payload.len() - skip) as u32);
            } else {
                bail!(
                    "gap in server stream: expected seq {expected}, got {seq} (flow {flow_idx})"
                );
            }
        }
        Ok(ReassembledFlow {
            flow_idx,
            client,
            server,
            payload: out,
            dup_bytes,
            packet_offsets,
        })
    }
}

#[cfg(test)]
mod tests;
