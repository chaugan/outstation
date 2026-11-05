//! Upload-time viability of an IEC 104 capture: session counts, the
//! per-endpoint figures behind the run-config picker, a memory estimate
//! and notes.
//!
//! Both roles replay one flow per endpoint (P02/N18): when an RTU (or a
//! master) appears in several flows, the most contiguous, largest one
//! ([`protoplay::FlowQuality`], the same ranking the scheduler uses).
//! The figures describe that flow; the notes say how many endpoints had
//! more and how many replayed flows have capture gaps. Each flow side
//! is reassembled once (P07).

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use protoplay::{FlowQuality, FlowSide, FlowSideView, LoadedPcapView, ProtoViability, RtuTraffic};

use crate::count_iframes;
use crate::inventory::Inventory;

const TARGET_PORT: u16 = 2404;

/// Memory per captured packet beyond its bytes in the file buffer:
/// `size_of::<pcapload::Packet>()` (~88 B) plus its entries in the flow
/// and source index lists, plus vector slack. Checked against the real
/// size in pcapload's tests.
pub const PER_PACKET_RAM_BYTES: u64 = 128;

/// The flow an endpoint replays, and what it would send.
struct Best {
    quality: FlowQuality,
    messages: u64,
    /// Server side only: its CA/IOA points.
    inventory: Option<Inventory>,
}

/// Best flow per endpoint for one side, plus how many flows each
/// endpoint had.
#[derive(Default)]
struct SideBest {
    best: BTreeMap<Ipv4Addr, Best>,
    flows: BTreeMap<Ipv4Addr, u64>,
}

impl SideBest {
    fn offer(&mut self, ip: Ipv4Addr, v: &FlowSideView<'_>, with_inventory: bool) {
        let quality = FlowQuality::of(v);
        if self
            .best
            .get(&ip)
            .is_some_and(|b| !quality.better_than(&b.quality))
        {
            return;
        }
        let inventory = with_inventory.then(|| {
            let mut inv = Inventory::default();
            inv.ingest_payload(v.payload);
            inv
        });
        self.best.insert(
            ip,
            Best {
                quality,
                messages: count_iframes(v.payload) as u64,
                inventory,
            },
        );
    }

    fn payload_bytes(&self) -> u64 {
        self.best
            .values()
            .map(|b| b.quality.payload_bytes as u64)
            .sum()
    }

    /// Endpoints seen in more than one flow.
    fn multi_flow(&self) -> usize {
        self.flows.values().filter(|n| **n > 1).count()
    }

    /// Replayed flows with capture gaps, and the bytes they lack.
    fn gapped(&self) -> (usize, u64) {
        self.best
            .values()
            .filter(|b| b.quality.gaps > 0)
            .fold((0, 0), |(n, m), b| (n + 1, m + b.quality.missing_bytes))
    }

    fn traffic(&self, ips: &BTreeSet<Ipv4Addr>) -> Vec<RtuTraffic> {
        ips.iter()
            .map(|ip| {
                let b = self.best.get(ip);
                RtuTraffic {
                    ip: ip.to_string(),
                    payload_bytes: b.map_or(0, |b| b.quality.payload_bytes as u64),
                    messages: b.map_or(0, |b| b.messages),
                    duration_ms: 0,
                }
            })
            .collect()
    }
}

/// See the module docs.
pub fn quick_viability(p: &dyn LoadedPcapView, file_size_bytes: u64) -> ProtoViability {
    let mut client_ips: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut server_ips: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut midflow_flows: u64 = 0;
    let mut clean_handshake_flows: u64 = 0;
    let mut masters = SideBest::default();
    let mut rtus = SideBest::default();
    for f in p.flows() {
        let Some((server_ip, server_port)) = f.server else {
            continue;
        };
        if server_port != TARGET_PORT {
            continue;
        }
        let Some((client_ip, _)) = f.client else {
            continue;
        };
        client_ips.insert(client_ip);
        server_ips.insert(server_ip);
        if f.saw_syn {
            clean_handshake_flows += 1;
        } else {
            midflow_flows += 1;
        }
        *masters.flows.entry(client_ip).or_default() += 1;
        *rtus.flows.entry(server_ip).or_default() += 1;
        p.with_flow_side(f.flow_idx, FlowSide::Client, &mut |v| {
            masters.offer(client_ip, v, false)
        });
        p.with_flow_side(f.flow_idx, FlowSide::Server, &mut |v| {
            rtus.offer(server_ip, v, true)
        });
    }
    let client_payload_bytes = masters.payload_bytes();
    let server_payload_bytes = rtus.payload_bytes();
    let sessions_master_mode = client_ips.len() as u64;
    let sessions_slave_mode = server_ips.len() as u64;
    let max_session_count = sessions_master_mode.max(sessions_slave_mode);
    let estimated_peak_mb = estimate_peak_mb(
        file_size_bytes,
        p.packet_count(),
        max_session_count,
        client_payload_bytes.max(server_payload_bytes),
    );
    let (verdict, verdict_reason) = verdict(max_session_count, file_size_bytes, estimated_peak_mb);

    let mut notes = Vec::new();
    if max_session_count == 0 {
        notes.push(
            "no TCP flow with server_port=2404 found - benchmark mode would have nothing to do"
                .into(),
        );
    } else {
        notes.push(format!(
            "{sessions_master_mode} unique client IPs talk to port 2404 (master-mode session count)"
        ));
        notes.push(format!(
            "{sessions_slave_mode} unique server IPs listen on port 2404 (slave-mode session count)"
        ));
        notes.push(format!(
            "{} MB of client TCP payload, {} MB of server TCP payload in the flows that would be replayed",
            client_payload_bytes / (1024 * 1024),
            server_payload_bytes / (1024 * 1024),
        ));
        flow_choice_notes(&mut notes, &masters, &rtus);
        if midflow_flows > 0 {
            notes.push(format!(
                "{} of {} flows are mid-flow (no SYN observed) - the replayer will synthesize a fresh TCP+STARTDT prelude and resync to the first clean APCI boundary; {} flows had a clean handshake in the capture",
                midflow_flows,
                midflow_flows + clean_handshake_flows,
                clean_handshake_flows,
            ));
        }
        inventory_notes(&mut notes, &rtus);
    }
    if file_size_bytes > 1024 * 1024 * 1024 {
        notes.push(
            "pcap is larger than 1 GB; pcapload reads it fully into RAM (no mmap path yet)".into(),
        );
    }
    if max_session_count > 256 {
        notes.push(
            "session count exceeds 256 - ensure `ulimit -n` is large enough for one socket per session".into(),
        );
    }
    ProtoViability {
        client_payload_bytes,
        server_payload_bytes,
        sessions_master_mode,
        sessions_slave_mode,
        estimated_peak_mb,
        verdict: verdict.into(),
        verdict_reason,
        notes,
        slave_rtus: rtus.traffic(&server_ips),
        master_clients: masters.traffic(&client_ips),
    }
}

/// Peak working set in MB: the parsed capture (the file buffer plus
/// [`PER_PACKET_RAM_BYTES`] per packet, so small frames cost
/// relatively more; twice the file when the packet count is unknown),
/// the replayed payloads, latency reservoirs, thread stacks and a base.
fn estimate_peak_mb(file_size: u64, packets: u64, sessions: u64, payload_bytes: u64) -> u64 {
    let mb = |b: u64| b.div_ceil(1024 * 1024);
    let parsed = if packets > 0 {
        file_size.saturating_add(packets.saturating_mul(PER_PACKET_RAM_BYTES))
    } else {
        file_size.saturating_mul(2)
    };
    mb(parsed) + mb(payload_bytes) + mb(sessions * 80 * 1024) + sessions * 2 + 32
}

fn verdict(sessions: u64, file_size: u64, peak_mb: u64) -> (&'static str, String) {
    let file_mb = file_size / (1024 * 1024);
    if file_size > 8 * 1024 * 1024 * 1024 || sessions > 1500 {
        (
            "not_recommended",
            format!(
                "{sessions} sessions and a {file_mb} MB pcap exceed comfortable single-host limits"
            ),
        )
    } else if file_size > 2 * 1024 * 1024 * 1024 || sessions > 500 {
        (
            "heavy",
            format!(
                "{sessions} sessions / {file_mb} MB pcap - needs a roomy host (>= {peak_mb} MB free RAM)"
            ),
        )
    } else if file_size > 500 * 1024 * 1024 || sessions > 100 {
        (
            "caution",
            format!("{sessions} sessions / {file_mb} MB pcap - feasible but expect ~{peak_mb} MB peak RAM"),
        )
    } else if sessions == 0 {
        (
            "ok",
            "no IEC 104 flows on port 2404 - fine for raw replay; benchmark mode has nothing to drive".into(),
        )
    } else {
        (
            "ok",
            format!("{sessions} session(s) and {file_mb} MB pcap - easy to replay on this host"),
        )
    }
}

/// Which flow each endpoint replays, and the TCP gaps in those flows.
fn flow_choice_notes(notes: &mut Vec<String>, masters: &SideBest, rtus: &SideBest) {
    let (multi_rtus, multi_masters) = (rtus.multi_flow(), masters.multi_flow());
    if multi_rtus + multi_masters > 0 {
        notes.push(format!(
            "{multi_rtus} RTU(s) and {multi_masters} master(s) appear in several flows (reconnects, port reuse): each replays only its most contiguous, largest flow, and the per-endpoint figures describe that flow"
        ));
    }
    for (role, side) in [("slave", rtus), ("master", masters)] {
        let (n, missing) = side.gapped();
        if n > 0 {
            notes.push(format!(
                "{n} of the {} flows the {role} role would replay have TCP capture gaps ({missing} bytes never captured): frames across a gap are dropped, not replayed",
                side.best.len()
            ));
        }
    }
}

/// CA/IOA inventory overview of the RTUs' replayed flows: the same
/// inventory the slave builds at session start to answer GI/CI.
fn inventory_notes(notes: &mut Vec<String>, rtus: &SideBest) {
    let mut per_rtu: Vec<usize> = Vec::new();
    let mut cas: BTreeSet<u16> = BTreeSet::new();
    let mut points = 0usize;
    let mut types: BTreeMap<u8, usize> = BTreeMap::new();
    for inv in rtus.best.values().filter_map(|b| b.inventory.as_ref()) {
        if inv.is_empty() {
            continue;
        }
        per_rtu.push(inv.len());
        for ((ca, _ioa), entry) in &inv.entries {
            cas.insert(*ca);
            points += 1;
            *types.entry(entry.type_id).or_insert(0) += 1;
        }
    }
    if per_rtu.is_empty() {
        return;
    }
    let min = per_rtu.iter().min().copied().unwrap_or(0);
    let max = per_rtu.iter().max().copied().unwrap_or(0);
    let mean = per_rtu.iter().sum::<usize>() / per_rtu.len();
    notes.push(format!(
        "CA/IOA inventory: {points} unique (CA, IOA) points across {} common address(es) on {} RTU(s) (per-RTU IOAs: min {min}, mean {mean}, max {max})",
        cas.len(),
        per_rtu.len(),
    ));
    let mut top: Vec<(u8, usize)> = types.into_iter().collect();
    top.sort_by_key(|t| std::cmp::Reverse(t.1));
    let top: Vec<String> = top
        .iter()
        .take(5)
        .map(|(t, c)| format!("type {t} ({c})"))
        .collect();
    if !top.is_empty() {
        notes.push(format!(
            "dominant ASDU types in inventory: {}",
            top.join(", ")
        ));
    }
}
