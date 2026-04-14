//! Streaming parser for classic pcap files.
//!
//! Supports both microsecond (0xa1b2c3d4) and nanosecond (0xa1b23c4d)
//! timestamp variants in either endianness.

use anyhow::{bail, Result};

const PCAP_MAGIC_US_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const PCAP_MAGIC_US_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
const PCAP_MAGIC_NS_LE: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
const PCAP_MAGIC_NS_BE: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];

pub struct PcapParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    little_endian: bool,
    ns_resolution: bool,
    pub link_type: u32,
    pub snaplen: u32,
}

pub struct PcapRecord<'a> {
    pub ts_ns: u64,
    pub orig_len: u32,
    pub data: &'a [u8],
}

impl<'a> PcapParser<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 24 {
            bail!("pcap file shorter than global header");
        }
        let magic = &bytes[..4];
        let (little_endian, ns_resolution) = match magic {
            m if m == PCAP_MAGIC_US_LE => (true, false),
            m if m == PCAP_MAGIC_US_BE => (false, false),
            m if m == PCAP_MAGIC_NS_LE => (true, true),
            m if m == PCAP_MAGIC_NS_BE => (false, true),
            _ => bail!("not a classic pcap file (magic {:02x?})", magic),
        };
        let read_u32 = |off: usize| -> u32 {
            let b = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
            if little_endian {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let snaplen = read_u32(16);
        let link_type = read_u32(20);
        Ok(Self {
            bytes,
            pos: 24,
            little_endian,
            ns_resolution,
            link_type,
            snaplen,
        })
    }

    pub fn next_record(&mut self) -> Result<Option<PcapRecord<'a>>> {
        if self.pos >= self.bytes.len() {
            return Ok(None);
        }
        if self.bytes.len() < self.pos + 16 {
            bail!("truncated packet header at offset {}", self.pos);
        }
        let read_u32 = |b: &[u8]| -> u32 {
            let arr = [b[0], b[1], b[2], b[3]];
            if self.little_endian {
                u32::from_le_bytes(arr)
            } else {
                u32::from_be_bytes(arr)
            }
        };
        let ts_sec = read_u32(&self.bytes[self.pos..]);
        let ts_sub = read_u32(&self.bytes[self.pos + 4..]);
        let incl_len = read_u32(&self.bytes[self.pos + 8..]) as usize;
        let orig_len = read_u32(&self.bytes[self.pos + 12..]);
        self.pos += 16;
        if self.bytes.len() < self.pos + incl_len {
            bail!("truncated packet body at offset {}", self.pos);
        }
        let data = &self.bytes[self.pos..self.pos + incl_len];
        self.pos += incl_len;
        let ts_ns = if self.ns_resolution {
            ts_sec as u64 * 1_000_000_000 + ts_sub as u64
        } else {
            ts_sec as u64 * 1_000_000_000 + ts_sub as u64 * 1_000
        };
        Ok(Some(PcapRecord {
            ts_ns,
            orig_len,
            data,
        }))
    }
}
