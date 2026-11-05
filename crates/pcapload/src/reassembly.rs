//! TCP byte-stream reassembly for one direction of a flow.
//!
//! See [`ReassembledFlow`] for the gap policy.

use std::net::Ipv4Addr;

use anyhow::{anyhow, bail, Result};
use tracing::warn;

use crate::{tcp_segment, LoadedPcap, TCP_SYN};

/// Which half of a TCP connection to reassemble.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamDir {
    /// Bytes sent by the flow's client (the side that sent the SYN, or
    /// the higher port when no handshake was captured).
    ClientToServer,
    /// Bytes sent by the flow's server.
    ServerToClient,
}

impl StreamDir {
    fn label(self) -> &'static str {
        match self {
            StreamDir::ClientToServer => "client",
            StreamDir::ServerToClient => "server",
        }
    }
}

/// A hole in a reassembled stream: `missing` sequence-space bytes were
/// never captured. They belong **before** `payload[offset]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamGap {
    /// Offset in [`ReassembledFlow::payload`] where the missing bytes
    /// would have been. `0` with a SYN-anchored stream means the first
    /// data segment(s) after the handshake were lost.
    pub offset: usize,
    /// Number of missing bytes (sequence-space distance).
    pub missing: u64,
}

/// A reassembled TCP flow payload ready for session-mode replay.
///
/// # Gap policy
///
/// Reassembly never fails because of a hole in the sequence space.
/// Each hole becomes a **zero-length splice**: the bytes on both sides
/// of the hole are concatenated in `payload` and a [`StreamGap`] marker
/// records where the hole was and how big it was.
///
/// This was chosen over splitting into separate buffers because every
/// consumer in the workspace takes one contiguous `&[u8]` plus
/// `packet_offsets`, and IEC 104 consumers already resynchronise on
/// APCI boundaries: a frame walker that finds a bad start byte or an
/// implausible length after the splice scans forward to the next
/// self-consistent `0x68 LEN … 0x68` boundary, exactly as it does for
/// a capture that starts mid-stream. Consumers that must never let a
/// frame straddle a hole can either restart their framer at each
/// `gaps[i].offset`, or iterate [`ReassembledFlow::contiguous_chunks`]
/// and frame each chunk on its own.
///
/// A stream is anchored at the sender's ISN+1 when its SYN (or SYN-ACK)
/// was captured, so lost leading data shows up as a gap at offset 0.
/// Without a SYN the stream starts at the lowest captured sequence
/// number. Sequence numbers are compared with wrapping arithmetic, so
/// streams that cross 2^32 reassemble in order.
#[derive(Debug, Clone)]
pub struct ReassembledFlow {
    pub flow_idx: usize,
    pub client: (Ipv4Addr, u16),
    pub server: (Ipv4Addr, u16),
    /// Which direction this payload was taken from.
    pub dir: StreamDir,
    pub payload: Vec<u8>,
    /// Bytes that were retransmits or overlaps, silently dropped.
    pub dup_bytes: usize,
    /// Payload-bearing segments that were entirely duplicate.
    pub dup_segments: usize,
    /// One entry per contributing source packet:
    /// `(pkt_rel_ts_ns, byte_offset_in_payload_where_that_packet_starts)`.
    /// Used by callers that want to correlate payload bytes back to
    /// their source packet's timestamp (e.g., pacing a replay to
    /// match the original inter-frame cadence).
    pub packet_offsets: Vec<(u64, usize)>,
    /// Holes in the sequence space, in payload order. Empty for a
    /// complete stream. See the type-level docs for the policy.
    pub gaps: Vec<StreamGap>,
    /// True when the stream was anchored at a captured SYN's ISN+1.
    pub anchored_at_syn: bool,
}

impl ReassembledFlow {
    /// Look up the source-packet timestamp for a byte in the
    /// reassembled payload. Returns the rel-ts (ns) of the latest
    /// packet whose payload starts at or before `byte_offset`.
    pub fn ts_for_byte(&self, byte_offset: usize) -> u64 {
        // packet_offsets is sorted by byte offset. Binary search for
        // the last entry with offset <= byte_offset.
        let lo = self
            .packet_offsets
            .partition_point(|&(_, off)| off <= byte_offset);
        if lo == 0 {
            return self.packet_offsets.first().map(|p| p.0).unwrap_or(0);
        }
        self.packet_offsets[lo - 1].0
    }

    /// True when no sequence-space hole was found.
    pub fn is_contiguous(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Total number of sequence-space bytes that were never captured.
    pub fn missing_bytes(&self) -> u64 {
        self.gaps.iter().map(|g| g.missing).sum()
    }

    /// Split `payload` at every interior gap. Yields
    /// `(offset_in_payload, chunk)`; each chunk is a run of bytes with
    /// no hole inside it. A gap at offset 0 does not split anything.
    pub fn contiguous_chunks(&self) -> impl Iterator<Item = (usize, &[u8])> + '_ {
        let mut cuts: Vec<usize> = self
            .gaps
            .iter()
            .map(|g| g.offset)
            .filter(|&o| o > 0 && o < self.payload.len())
            .collect();
        cuts.dedup();
        cuts.push(self.payload.len());
        let mut start = 0usize;
        cuts.into_iter().filter_map(move |end| {
            if end <= start {
                return None;
            }
            let chunk = (start, &self.payload[start..end]);
            start = end;
            Some(chunk)
        })
    }
}

/// One payload-bearing segment, borrowed from the capture buffer.
struct Seg<'a> {
    /// Unwrapped stream position (relative to the anchor).
    pos: i64,
    bytes: &'a [u8],
    ts: u64,
}

impl LoadedPcap {
    /// Reassemble one direction of a TCP flow.
    ///
    /// Errors only when the flow index is unknown, the flow has no
    /// client/server identification, or the direction carries no
    /// payload at all. Holes are reported in [`ReassembledFlow::gaps`].
    pub fn reassemble(&self, flow_idx: usize, dir: StreamDir) -> Result<ReassembledFlow> {
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
        let (src_ip, src_port) = match dir {
            StreamDir::ClientToServer => client,
            StreamDir::ServerToClient => server,
        };

        // Pass 1: borrow every payload-bearing segment (no copies) and
        // find this side's ISN if its SYN was captured.
        let mut isn: Option<u32> = None;
        let mut raw: Vec<(u32, &[u8], u64)> = Vec::new();
        for &pkt_idx in &flow.packet_indices {
            let pkt = &self.packets[pkt_idx];
            if pkt.src_ip != Some(src_ip) {
                continue;
            }
            let Some(seg) = tcp_segment(pkt) else {
                continue;
            };
            if seg.src_port != src_port {
                continue;
            }
            let mut data_seq = seg.seq;
            if seg.flags & TCP_SYN != 0 {
                isn.get_or_insert(seg.seq);
                // SYN consumes one sequence number; any SYN data
                // starts right after it.
                data_seq = seg.seq.wrapping_add(1);
            }
            if !seg.payload.is_empty() {
                raw.push((data_seq, seg.payload, pkt.rel_ts_ns));
            }
        }
        if raw.is_empty() {
            bail!("flow {flow_idx} has no {} payload bytes", dir.label());
        }

        // Pass 2: unwrap sequence numbers. Each segment is placed
        // relative to the previous one in capture order using a signed
        // 32-bit difference, so wraparound past 2^32 and streams longer
        // than 4 GiB both stay ordered.
        let anchor = match isn {
            Some(isn) => isn.wrapping_add(1),
            None => raw[0].0,
        };
        let mut segs: Vec<Seg<'_>> = Vec::with_capacity(raw.len());
        let mut prev_seq = anchor;
        let mut prev_pos: i64 = 0;
        for (seq, bytes, ts) in raw {
            let pos = prev_pos + i64::from(seq.wrapping_sub(prev_seq) as i32);
            segs.push(Seg { pos, bytes, ts });
            prev_seq = seq;
            prev_pos = pos;
        }
        // Stable: equal positions keep capture order, so the first
        // transmission of a retransmitted segment wins.
        segs.sort_by_key(|s| s.pos);

        let mut expected: i64 = if isn.is_some() { 0 } else { segs[0].pos };
        let upper: usize = segs.iter().map(|s| s.bytes.len()).sum();
        let mut out = Vec::with_capacity(upper);
        let mut dup_bytes = 0usize;
        let mut dup_segments = 0usize;
        let mut gaps: Vec<StreamGap> = Vec::new();
        let mut packet_offsets: Vec<(u64, usize)> = Vec::with_capacity(segs.len());
        for s in segs {
            let len = s.bytes.len() as i64;
            if s.pos > expected {
                gaps.push(StreamGap {
                    offset: out.len(),
                    missing: (s.pos - expected) as u64,
                });
                expected = s.pos;
            }
            let skip = expected - s.pos;
            if skip >= len {
                dup_bytes += s.bytes.len();
                dup_segments += 1;
                continue;
            }
            let skip = skip as usize;
            dup_bytes += skip;
            packet_offsets.push((s.ts, out.len()));
            out.extend_from_slice(&s.bytes[skip..]);
            expected = s.pos + len;
        }

        Ok(ReassembledFlow {
            flow_idx,
            client,
            server,
            dir,
            payload: out,
            dup_bytes,
            dup_segments,
            packet_offsets,
            gaps,
            anchored_at_syn: isn.is_some(),
        })
    }

    /// Reassemble the client-side byte stream of a TCP flow.
    ///
    /// Kept for existing callers; equivalent to
    /// [`LoadedPcap::reassemble`] with [`StreamDir::ClientToServer`].
    /// Holes no longer cause an error: they are logged, spliced and
    /// recorded in [`ReassembledFlow::gaps`]. Returns `Err` only if
    /// the flow is unknown or the client sent no payload.
    pub fn reassemble_client_payload(&self, flow_idx: usize) -> Result<ReassembledFlow> {
        let r = self.reassemble(flow_idx, StreamDir::ClientToServer)?;
        log_gaps(&r);
        Ok(r)
    }

    /// Mirror of [`LoadedPcap::reassemble_client_payload`] that extracts
    /// the **server-originated** byte stream of a TCP flow. Used by
    /// slave-mode benchmark replay: outstation accepts the master's
    /// connection and plays these bytes back as the server side.
    pub fn reassemble_server_payload(&self, flow_idx: usize) -> Result<ReassembledFlow> {
        let r = self.reassemble(flow_idx, StreamDir::ServerToClient)?;
        log_gaps(&r);
        Ok(r)
    }
}

fn log_gaps(r: &ReassembledFlow) {
    if let Some(first) = r.gaps.first() {
        warn!(
            flow = r.flow_idx,
            side = r.dir.label(),
            gaps = r.gaps.len(),
            missing_bytes = r.missing_bytes(),
            first_gap_offset = first.offset,
            "TCP stream has capture gaps; bytes on either side were spliced"
        );
    }
}
