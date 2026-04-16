#!/usr/bin/env python3
"""Anonymise an IEC 60870-5-104 pcap.

Reads a pcap (libpcap or pcapng) and produces a new libpcap where every
source/destination IPv4 address, every Ethernet MAC, every IEC 104
Common Address, and every IEC 104 Information Object Address has been
replaced with a randomised value. The remap is consistent across the
whole pcap: the same original value always lands on the same new one,
so TCP flows stay intact and protocol semantics hold.

Pure Python 3 stdlib — runs offline on Windows/Linux without pip.
Designed for sharing demo pcaps without leaking real lab topology.
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


# --- link types -----------------------------------------------------------

LINKTYPE_ETHERNET = 1

# --- libpcap --------------------------------------------------------------

PCAP_MAGIC_US_LE = 0xA1B2C3D4
PCAP_MAGIC_NS_LE = 0xA1B23C4D

# --- pcapng ---------------------------------------------------------------

PCAPNG_BLOCK_SHB = 0x0A0D0D0A
PCAPNG_BLOCK_IDB = 0x00000001
PCAPNG_BLOCK_PB  = 0x00000002  # deprecated "Packet Block"
PCAPNG_BLOCK_SPB = 0x00000003
PCAPNG_BLOCK_EPB = 0x00000006
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

# --- ethernet / IPv4 / L4 -------------------------------------------------

ETHERTYPE_IPV4   = 0x0800
ETHERTYPE_VLAN   = 0x8100
ETHERTYPE_QINQ_A = 0x88A8  # 802.1ad outer VLAN

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

IEC104_PORT = 2404
IEC104_START_BYTE = 0x68

# --- IEC 104 ASDU element sizes ------------------------------------------
#
# Ported from crates/proto_iec104/src/asdu.rs:121-173. Maps Type ID to the
# size (bytes) of ONE information element excluding the 3-byte IOA. Types
# absent from this table are left alone in the rewrite walk (conservative
# fallback — matches the Rust behaviour).

ELEMENT_LEN = {
    1:   1,         # M_SP_NA_1
    2:   1 + 3,     # M_SP_TA_1
    3:   1,         # M_DP_NA_1
    4:   1 + 3,     # M_DP_TA_1
    5:   1 + 1,     # M_ST_NA_1
    6:   1 + 1 + 3, # M_ST_TA_1
    7:   4 + 1,     # M_BO_NA_1
    8:   4 + 1 + 3, # M_BO_TA_1
    9:   2 + 1,     # M_ME_NA_1
    10:  2 + 1 + 3, # M_ME_TA_1
    11:  2 + 1,     # M_ME_NB_1
    12:  2 + 1 + 3, # M_ME_TB_1
    13:  4 + 1,     # M_ME_NC_1
    14:  4 + 1 + 3, # M_ME_TC_1
    15:  4 + 1,     # M_IT_NA_1
    16:  4 + 1 + 3, # M_IT_TA_1
    30:  1 + 7,     # M_SP_TB_1
    31:  1 + 7,     # M_DP_TB_1
    32:  1 + 1 + 7, # M_ST_TB_1
    33:  4 + 1 + 7, # M_BO_TB_1
    34:  2 + 1 + 7, # M_ME_TD_1
    35:  2 + 1 + 7, # M_ME_TE_1
    36:  4 + 1 + 7, # M_ME_TF_1
    37:  4 + 1 + 7, # M_IT_TB_1
    45:  1,         # C_SC_NA_1
    46:  1,         # C_DC_NA_1
    47:  1,         # C_RC_NA_1
    48:  2 + 1,     # C_SE_NA_1
    49:  2 + 1,     # C_SE_NB_1
    50:  4 + 1,     # C_SE_NC_1
    51:  4,         # C_BO_NA_1
    58:  1 + 7,     # C_SC_TA_1
    59:  1 + 7,     # C_DC_TA_1
    60:  1 + 7,     # C_RC_TA_1
    61:  2 + 1 + 7, # C_SE_TA_1
    62:  2 + 1 + 7, # C_SE_TB_1
    63:  4 + 1 + 7, # C_SE_TC_1
    64:  4 + 7,     # C_BO_TA_1
    70:  1,         # M_EI_NA_1
    100: 1,         # C_IC_NA_1
    101: 1,         # C_CI_NA_1
    102: 0,         # C_RD_NA_1 (no element)
    103: 7,         # C_CS_NA_1 (bare CP56)
    104: 1,         # C_TS_NA_1
    105: 1,         # C_RP_NA_1
    106: 3,         # C_CD_NA_1
    107: 1 + 7,     # C_TS_TA_1
}


# --- checksums ------------------------------------------------------------

def internet_checksum(*chunks):
    """One's-complement 16-bit sum (RFC 1071) across the concatenation of
    the given byte chunks. Handles odd-length chunks by carrying a held
    high byte forward. Returns the 16-bit complement.
    """
    s = 0
    hold = None
    for chunk in chunks:
        i = 0
        if hold is not None:
            if chunk:
                s += (hold << 8) | chunk[0]
                i = 1
            else:
                # empty chunk — keep hold for next
                continue
            hold = None
        while i + 1 < len(chunk):
            s += (chunk[i] << 8) | chunk[i + 1]
            i += 2
        if i < len(chunk):
            hold = chunk[i]
    if hold is not None:
        s += hold << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# --- pcap / pcapng readers -----------------------------------------------

def _read_libpcap(f, magic):
    """Read the remaining 20 bytes of the libpcap global header, then
    yield (ts_float, linktype, raw_packet_bytes) for each record."""
    rest = f.read(20)
    if len(rest) < 20:
        raise ValueError("truncated libpcap global header")
    if magic == b"\xa1\xb2\xc3\xd4":
        endian, ns = ">", False
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian, ns = "<", False
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ns = ">", True
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ns = "<", True
    else:
        raise ValueError(f"unknown libpcap magic {magic!r}")
    # Global header: version major/minor, thiszone, sigfigs, snaplen, network
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", rest)
    divisor = 1_000_000_000.0 if ns else 1_000_000.0
    while True:
        hdr = f.read(16)
        if not hdr:
            return
        if len(hdr) < 16:
            raise ValueError("truncated libpcap record header")
        ts_s, ts_sub, caplen, origlen = struct.unpack(endian + "IIII", hdr)
        data = f.read(caplen)
        if len(data) < caplen:
            raise ValueError(f"truncated record body ({len(data)} of {caplen})")
        _ = origlen  # original wire length — we don't use it
        yield (ts_s + ts_sub / divisor, linktype, data)


def _read_pcapng(f):
    """Yield (ts_float, linktype, raw_packet_bytes) for each EPB/SPB/PB
    across every Section Header in the file. SHB determines endianness."""
    endian = "<"
    interfaces = []  # list[(linktype, tsresol_divisor)]
    # Re-read the first 4 magic bytes we already consumed + read rest of first block
    # Caller has already consumed the 4 magic bytes; parse from where they are.
    # Each block: type(4) + total_len(4) + body + total_len(4). The SHB's
    # byte-order-magic sets endianness for everything that follows within
    # that section.
    # We were called right after reading the 4-byte SHB type. Resume:
    first_len_raw = f.read(4)
    if len(first_len_raw) < 4:
        raise ValueError("truncated pcapng first block length")
    # Tentatively little-endian; confirmed from byte-order-magic inside SHB body.
    total_len = struct.unpack("<I", first_len_raw)[0]
    body = f.read(total_len - 12)
    trailer = f.read(4)
    if len(trailer) < 4:
        raise ValueError("truncated pcapng first block trailer")
    if len(body) < 4:
        raise ValueError("pcapng SHB body too short")
    # Byte-order-magic sits at the start of the SHB body.
    bom = body[:4]
    if bom == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    elif bom == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    else:
        raise ValueError(f"pcapng byte-order-magic not recognised: {bom!r}")
    # If endian guess was wrong, re-parse total_len.
    if endian == ">":
        total_len = struct.unpack(">I", first_len_raw)[0]

    # Loop over the remaining blocks.
    while True:
        hdr = f.read(8)
        if not hdr:
            return
        if len(hdr) < 8:
            raise ValueError("truncated pcapng block header")
        block_type, block_total_len = struct.unpack(endian + "II", hdr)
        if block_total_len < 12 or block_total_len % 4 != 0:
            raise ValueError(f"invalid pcapng block_total_length {block_total_len}")
        body = f.read(block_total_len - 12)
        trailer = f.read(4)
        if len(trailer) < 4:
            raise ValueError("truncated pcapng block trailer")
        trailer_len = struct.unpack(endian + "I", trailer)[0]
        if trailer_len != block_total_len:
            raise ValueError(
                f"pcapng block length mismatch: header={block_total_len} trailer={trailer_len}"
            )

        if block_type == PCAPNG_BLOCK_SHB:
            # New section: reset interface table, reconfirm endianness.
            interfaces = []
            bom = body[:4]
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise ValueError(f"pcapng byte-order-magic: {bom!r}")
            continue

        if block_type == PCAPNG_BLOCK_IDB:
            # linktype u16, reserved u16, snaplen u32, then options
            linktype, _reserved, _snap = struct.unpack(endian + "HHI", body[:8])
            tsresol = 6  # pcapng default: microseconds (10^-6)
            # Walk options for if_tsresol (option code 9).
            off = 8
            while off + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[off:off + 4])
                off += 4
                if code == 0:
                    break  # opt_endofopt
                if olen > 0 and off + olen <= len(body):
                    if code == 9 and olen >= 1:
                        raw = body[off]
                        if raw & 0x80:
                            # Base 2 — uncommon; best-effort approximation.
                            bits = raw & 0x7F
                            # Convert to nearest base-10 resolution.
                            tsresol = max(0, int(round(bits * 0.30103)))
                        else:
                            tsresol = raw & 0x7F
                off += olen
                # Options are padded to 4-byte boundary.
                pad = (4 - (olen % 4)) % 4
                off += pad
            interfaces.append((linktype, 10 ** tsresol))
            continue

        if block_type == PCAPNG_BLOCK_EPB:
            # interface_id u32, ts_high u32, ts_low u32, caplen u32, origlen u32
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, caplen, _orig = struct.unpack(
                endian + "IIIII", body[:20]
            )
            if iface_id >= len(interfaces):
                # Missing IDB — skip quietly.
                continue
            linktype, divisor = interfaces[iface_id]
            raw_ts = (ts_hi << 32) | ts_lo
            ts = raw_ts / divisor
            data = body[20:20 + caplen]
            yield (ts, linktype, bytes(data))
            continue

        if block_type == PCAPNG_BLOCK_SPB:
            # origlen u32, then packet data padded to 4 bytes
            if len(body) < 4:
                continue
            _orig = struct.unpack(endian + "I", body[:4])[0]
            if interfaces:
                linktype, _div = interfaces[0]
            else:
                linktype = LINKTYPE_ETHERNET
            data = body[4:4 + _orig]
            yield (0.0, linktype, bytes(data))
            continue

        if block_type == PCAPNG_BLOCK_PB:
            # Deprecated. interface_id u16, drops u16, ts_high u32, ts_low u32,
            # caplen u32, origlen u32
            if len(body) < 20:
                continue
            iface_id, _drops, ts_hi, ts_lo, caplen, _orig = struct.unpack(
                endian + "HHIIII", body[:20]
            )
            if iface_id >= len(interfaces):
                continue
            linktype, divisor = interfaces[iface_id]
            raw_ts = (ts_hi << 32) | ts_lo
            ts = raw_ts / divisor
            data = body[20:20 + caplen]
            yield (ts, linktype, bytes(data))
            continue

        # Any other block type (Name Resolution, Interface Stats, etc.) —
        # skip silently. We don't lose data because we're not transcribing
        # pcapng options to the libpcap output.


def read_pcap(path):
    """Dispatch to the right reader based on magic. Yields
    (ts_float, linktype, raw_packet_bytes)."""
    f = open(path, "rb")
    magic = f.read(4)
    if len(magic) < 4:
        f.close()
        raise ValueError(f"file too short to contain a pcap magic: {path}")
    libpcap_magics = (
        b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
    )
    try:
        if magic in libpcap_magics:
            yield from _read_libpcap(f, magic)
        elif magic == b"\n\r\r\n":
            yield from _read_pcapng(f)
        else:
            raise ValueError(f"not a pcap/pcapng file: unknown magic {magic!r}")
    finally:
        f.close()


# --- libpcap writer -------------------------------------------------------

def write_libpcap(path, records, linktype=LINKTYPE_ETHERNET):
    """Write classic libpcap (µs precision, little-endian magic
    0xA1B2C3D4). `records` is an iterable of (ts_float, raw_bytes)."""
    with open(path, "wb") as f:
        f.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_US_LE, 2, 4, 0, 0, 65535, linktype,
        ))
        for ts, data in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            elif usec < 0:
                # Can happen with negative fractional from float rounding.
                sec -= 1
                usec += 1_000_000
            f.write(struct.pack("<IIII", sec & 0xFFFFFFFF, usec, len(data), len(data)))
            f.write(data)


# --- remap ---------------------------------------------------------------

class SubnetPool:
    """Iterator over a shuffled list of host addresses inside a CIDR
    block, returned as 4-byte big-endian `bytes`."""

    def __init__(self, cidr, rng):
        try:
            net_str, bits_str = cidr.split("/")
            bits = int(bits_str)
        except ValueError as e:
            raise ValueError(f"bad CIDR {cidr!r}: {e}")
        if not (0 <= bits <= 32):
            raise ValueError(f"prefix length {bits} out of range for IPv4")
        base = struct.unpack("!I", socket.inet_aton(net_str))[0]
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        base &= mask
        total = 1 << (32 - bits)
        # Exclude .0 (network) and .(total-1) (broadcast) for /0..30.
        # For /31 and /32 include everything.
        if bits <= 30:
            hosts = [base + i for i in range(1, total - 1)]
        else:
            hosts = [base + i for i in range(total)]
        rng.shuffle(hosts)
        self._iter = iter(hosts)
        self._capacity = len(hosts)
        self.cidr = cidr

    def capacity(self):
        return self._capacity

    def next_ip(self):
        try:
            host = next(self._iter)
        except StopIteration:
            raise RuntimeError(
                f"subnet {self.cidr} pool exhausted: input pcap has more unique IPs "
                f"than {self._capacity} — pick a larger --subnet"
            )
        return struct.pack("!I", host)


class Remap:
    """Consistent per-value remaps for IPs, MACs, IEC 104 CAs and IOAs."""

    def __init__(self, subnet_cidr, rng):
        self.rng = rng
        self.pool = SubnetPool(subnet_cidr, rng)
        self.ip_map = {}
        self.mac_map = {}
        # Preserve broadcast/sentinel CAs so replay semantics hold.
        self.ca_map = {0: 0, 0xFFFF: 0xFFFF}
        self.ca_used = {0, 0xFFFF}
        # Preserve IOA=0 (clock-sync, interrogation sentinel).
        self.ioa_map = {0: 0}
        self.ioa_used = {0}

    # -- IPs --
    def remap_ip(self, ip_bytes):
        existing = self.ip_map.get(ip_bytes)
        if existing is not None:
            return existing
        new = self.pool.next_ip()
        self.ip_map[ip_bytes] = new
        return new

    # -- MACs --
    def remap_mac(self, mac_bytes):
        existing = self.mac_map.get(mac_bytes)
        if existing is not None:
            return existing
        # Preserve multicast/broadcast class bits rather than randomising into
        # unicast — addresses like 01:0c:cd:01:... (GOOSE) must stay multicast.
        first = mac_bytes[0]
        if first & 0x01:
            # Group bit set — multicast or broadcast. Leave as-is; it's a
            # protocol-defined address, not a host identifier.
            self.mac_map[mac_bytes] = mac_bytes
            return mac_bytes
        # Unicast: generate a locally-administered random MAC.
        new = bytes([0x02] + [self.rng.randrange(256) for _ in range(5)])
        # Avoid collision with an already-assigned MAC (unlikely, but cheap).
        while new in self.mac_map.values():
            new = bytes([0x02] + [self.rng.randrange(256) for _ in range(5)])
        self.mac_map[mac_bytes] = new
        return new

    # -- CA (16-bit) --
    def remap_ca(self, ca):
        existing = self.ca_map.get(ca)
        if existing is not None:
            return existing
        # Random 1..0xFFFE that isn't already used.
        for _ in range(256):
            candidate = self.rng.randrange(1, 0xFFFF)
            if candidate not in self.ca_used:
                self.ca_map[ca] = candidate
                self.ca_used.add(candidate)
                return candidate
        # Fallback — scan.
        for candidate in range(1, 0xFFFF):
            if candidate not in self.ca_used:
                self.ca_map[ca] = candidate
                self.ca_used.add(candidate)
                return candidate
        raise RuntimeError("CA space exhausted (65534 unique CAs — unlikely)")

    # -- IOA (24-bit) --
    def remap_ioa(self, ioa):
        existing = self.ioa_map.get(ioa)
        if existing is not None:
            return existing
        # Random 24-bit in [1, 0xFFFFFF].
        for _ in range(1024):
            candidate = self.rng.randrange(1, 0x1000000)
            if candidate not in self.ioa_used:
                self.ioa_map[ioa] = candidate
                self.ioa_used.add(candidate)
                return candidate
        raise RuntimeError("IOA space too crowded — increase randomness budget")


# --- IEC 104 ASDU walker -------------------------------------------------

def rewrite_asdu_inplace(asdu, remap, stats):
    """Rewrite CA and every IOA inside an ASDU buffer. Matches the
    walker in crates/proto_iec104/src/asdu.rs:178-252."""
    if len(asdu) < 6:
        return
    type_id = asdu[0]
    vsq = asdu[1]
    sq = (vsq & 0x80) != 0
    n = vsq & 0x7F

    # Common Address (LE u16 at offset 4..6). Preserve COT flag bits in byte 2.
    ca = asdu[4] | (asdu[5] << 8)
    new_ca = remap.remap_ca(ca)
    if new_ca != ca:
        asdu[4] = new_ca & 0xFF
        asdu[5] = (new_ca >> 8) & 0xFF
        stats["ca_rewrites"] += 1

    elem = ELEMENT_LEN.get(type_id)
    if elem is None or n == 0:
        # Unknown type or empty object list — leave IOAs alone.
        if elem is None:
            stats["unknown_types"].add(type_id)
        return

    if sq:
        # Single base IOA at offset 6, then n consecutive elements. Remap
        # only the base — sequence semantics (base+1, base+2, …) preserved.
        if len(asdu) < 9:
            return
        ioa = asdu[6] | (asdu[7] << 8) | (asdu[8] << 16)
        new_ioa = remap.remap_ioa(ioa)
        if new_ioa != ioa:
            asdu[6] = new_ioa & 0xFF
            asdu[7] = (new_ioa >> 8) & 0xFF
            asdu[8] = (new_ioa >> 16) & 0xFF
            stats["ioa_rewrites"] += 1
    else:
        stride = 3 + elem
        off = 6
        for _ in range(n):
            if off + 3 > len(asdu):
                break
            ioa = asdu[off] | (asdu[off + 1] << 8) | (asdu[off + 2] << 16)
            new_ioa = remap.remap_ioa(ioa)
            if new_ioa != ioa:
                asdu[off] = new_ioa & 0xFF
                asdu[off + 1] = (new_ioa >> 8) & 0xFF
                asdu[off + 2] = (new_ioa >> 16) & 0xFF
                stats["ioa_rewrites"] += 1
            off += stride
            if off > len(asdu):
                break


def rewrite_iec104_stream(tcp_payload, remap, stats):
    """Walk a TCP-payload bytearray as an IEC 104 APDU stream, rewriting
    every I-frame's ASDU in place. S- and U-frames are left alone (they
    carry no CA/IOA). Preserves total length — the rewrite never changes
    ASDU size."""
    i = 0
    length = len(tcp_payload)
    while i + 6 <= length:
        if tcp_payload[i] != IEC104_START_BYTE:
            # Desync — likely a partial APDU straddling this segment.
            # Stop rewriting conservatively; subsequent bytes untouched.
            break
        ln = tcp_payload[i + 1]
        if ln < 4 or i + 2 + ln > length:
            break
        cf1 = tcp_payload[i + 2]
        # I-frame = low bit of CF1 is 0. (S-frame CF1=0x01; U-frame CF1 low 2 bits = 11.)
        if (cf1 & 0x01) == 0:
            asdu_start = i + 6
            asdu_end = i + 2 + ln
            asdu_view = tcp_payload[asdu_start:asdu_end]
            buf = bytearray(asdu_view)
            rewrite_asdu_inplace(buf, remap, stats)
            tcp_payload[asdu_start:asdu_end] = buf
        i += 2 + ln


# --- packet rewrite ------------------------------------------------------

def _read_u16_be(b, off):
    return (b[off] << 8) | b[off + 1]


def _write_u16_be(b, off, v):
    b[off] = (v >> 8) & 0xFF
    b[off + 1] = v & 0xFF


def rewrite_packet(raw, linktype, remap, stats):
    """Return the rewritten raw-bytes for a single captured frame.

    `raw` is consumed but we return a fresh `bytes`, so callers can
    accumulate outputs without worrying about mutation sharing.
    """
    if linktype != LINKTYPE_ETHERNET or len(raw) < 14:
        # Non-Ethernet link or malformed: pass through unchanged.
        stats["non_ethernet"] += 1
        return bytes(raw)

    buf = bytearray(raw)

    # Ethernet header: dst MAC (6) + src MAC (6) + ethertype (2)
    dst_mac = bytes(buf[0:6])
    src_mac = bytes(buf[6:12])
    buf[0:6] = remap.remap_mac(dst_mac)
    buf[6:12] = remap.remap_mac(src_mac)

    # Walk past VLAN tags (802.1Q single and 802.1ad double).
    off = 12
    ethertype = _read_u16_be(buf, off)
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ_A) and off + 4 + 2 <= len(buf):
        off += 4  # 4-byte VLAN tag
        ethertype = _read_u16_be(buf, off)
    off += 2  # past the final ethertype

    if ethertype != ETHERTYPE_IPV4:
        stats["non_ipv4"] += 1
        return bytes(buf)

    # IPv4 header
    ip = off
    if len(buf) < ip + 20:
        stats["short_ipv4"] += 1
        return bytes(buf)
    vihl = buf[ip]
    version = vihl >> 4
    ihl = vihl & 0x0F
    if version != 4 or ihl < 5:
        stats["short_ipv4"] += 1
        return bytes(buf)
    ip_hdr_end = ip + ihl * 4
    if len(buf) < ip_hdr_end:
        stats["short_ipv4"] += 1
        return bytes(buf)

    total_len = _read_u16_be(buf, ip + 2)
    flags_frag = _read_u16_be(buf, ip + 6)
    more_fragments = (flags_frag & 0x2000) != 0
    frag_offset = flags_frag & 0x1FFF
    proto = buf[ip + 9]

    src_ip = bytes(buf[ip + 12:ip + 16])
    dst_ip = bytes(buf[ip + 16:ip + 20])
    new_src = remap.remap_ip(src_ip)
    new_dst = remap.remap_ip(dst_ip)
    buf[ip + 12:ip + 16] = new_src
    buf[ip + 16:ip + 20] = new_dst

    # Recompute IPv4 header checksum (zero then fill).
    buf[ip + 10] = 0
    buf[ip + 11] = 0
    cksum = internet_checksum(bytes(buf[ip:ip_hdr_end]))
    _write_u16_be(buf, ip + 10, cksum)

    # Later fragments carry no L4 header. First fragment with MF=1 carries
    # a truncated L4 that can't be checksummed without reassembly.
    if more_fragments or frag_offset != 0:
        stats["fragmented"] += 1
        return bytes(buf)

    # L4 region runs from ip_hdr_end up to ip + total_len (captures may
    # include link-layer trailing padding, which shouldn't be included).
    ip_end = min(ip + total_len, len(buf))
    if ip_hdr_end >= ip_end:
        return bytes(buf)
    l4_len = ip_end - ip_hdr_end

    if proto == IP_PROTO_TCP:
        if l4_len < 20:
            return bytes(buf)
        data_off = (buf[ip_hdr_end + 12] >> 4) * 4
        if data_off < 20 or data_off > l4_len:
            return bytes(buf)
        src_port = _read_u16_be(buf, ip_hdr_end + 0)
        dst_port = _read_u16_be(buf, ip_hdr_end + 2)

        # IEC 104: rewrite CA + IOAs inside the ASDU payload.
        if (src_port == IEC104_PORT or dst_port == IEC104_PORT) and l4_len > data_off:
            payload_start = ip_hdr_end + data_off
            payload_end = ip_end
            stream = bytearray(buf[payload_start:payload_end])
            rewrite_iec104_stream(stream, remap, stats)
            buf[payload_start:payload_end] = stream

        # Zero + recompute TCP checksum (field at offset 16 in TCP header).
        buf[ip_hdr_end + 16] = 0
        buf[ip_hdr_end + 17] = 0
        pseudo = new_src + new_dst + bytes([0, IP_PROTO_TCP]) + struct.pack("!H", l4_len)
        cksum = internet_checksum(pseudo, bytes(buf[ip_hdr_end:ip_end]))
        _write_u16_be(buf, ip_hdr_end + 16, cksum)

    elif proto == IP_PROTO_UDP:
        if l4_len < 8:
            return bytes(buf)
        buf[ip_hdr_end + 6] = 0
        buf[ip_hdr_end + 7] = 0
        pseudo = new_src + new_dst + bytes([0, IP_PROTO_UDP]) + struct.pack("!H", l4_len)
        cksum = internet_checksum(pseudo, bytes(buf[ip_hdr_end:ip_end]))
        # RFC 768: an all-zero UDP checksum means "not computed"; on the
        # wire 0xFFFF is the equivalent one's-complement representation.
        if cksum == 0:
            cksum = 0xFFFF
        _write_u16_be(buf, ip_hdr_end + 6, cksum)

    else:
        # ICMP and other protos: no pseudo-header dependency on the IPs,
        # so no recomputation needed.
        pass

    return bytes(buf)


# --- mapping sidecar ----------------------------------------------------

def _ip_to_str(b):
    return socket.inet_ntoa(b)


def _mac_to_str(b):
    return ":".join(f"{x:02x}" for x in b)


def build_mapping_json(remap, input_path, output_path, subnet, seed):
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input_pcap": str(input_path),
        "output_pcap": str(output_path),
        "subnet": subnet,
        "seed": seed,
        "ip_map":  {_ip_to_str(k):  _ip_to_str(v)  for k, v in remap.ip_map.items()},
        "mac_map": {_mac_to_str(k): _mac_to_str(v) for k, v in remap.mac_map.items()},
        "ca_map":  {str(k): v for k, v in remap.ca_map.items() if k not in (0, 0xFFFF)},
        "ioa_map": {str(k): v for k, v in remap.ioa_map.items() if k != 0},
    }


# --- main ---------------------------------------------------------------

def _detect_format(path):
    with open(path, "rb") as f:
        m = f.read(4)
    if m in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
             b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        return "libpcap"
    if m == b"\n\r\r\n":
        return "pcapng"
    return "unknown"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("input_pcap", type=Path, help="input pcap or pcapng file")
    ap.add_argument(
        "--subnet", required=True,
        help="target CIDR for remapped IPs, e.g. 10.200.0.0/16",
    )
    ap.add_argument(
        "-o", "--output", type=Path, default=None,
        help="output pcap path (default: <UTC timestamp>_<input-stem>_anon.pcap)",
    )
    ap.add_argument(
        "--mapping-file", type=Path, default=None,
        help="where to write the JSON remap audit file "
             "(default: <output>.mapping.json)",
    )
    ap.add_argument(
        "--seed", type=int, default=None,
        help="deterministic seed for all remaps (omit for system randomness)",
    )
    ap.add_argument(
        "-v", "--verbose", action="store_true",
        help="print per-packet progress",
    )
    args = ap.parse_args(argv)

    if not args.input_pcap.exists():
        sys.exit(f"input not found: {args.input_pcap}")

    input_format = _detect_format(args.input_pcap)
    if input_format == "unknown":
        sys.exit(f"{args.input_pcap} is not a recognised pcap/pcapng file")

    rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()

    try:
        remap = Remap(args.subnet, rng)
    except ValueError as e:
        sys.exit(str(e))

    if args.output is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = args.input_pcap.stem
        args.output = args.input_pcap.parent / f"{ts}_{stem}_anon.pcap"
    if args.mapping_file is None:
        args.mapping_file = args.output.with_suffix(".mapping.json")

    stats = {
        "total_packets": 0,
        "non_ethernet": 0,
        "non_ipv4": 0,
        "short_ipv4": 0,
        "fragmented": 0,
        "ca_rewrites": 0,
        "ioa_rewrites": 0,
        "unknown_types": set(),
    }

    input_size = args.input_pcap.stat().st_size
    in_linktype = [LINKTYPE_ETHERNET]  # captured by first yielded record

    def _records():
        for ts, linktype, raw in read_pcap(args.input_pcap):
            stats["total_packets"] += 1
            if stats["total_packets"] == 1:
                in_linktype[0] = linktype
            new_raw = rewrite_packet(raw, linktype, remap, stats)
            if args.verbose and stats["total_packets"] % 1000 == 0:
                print(f"  ... {stats['total_packets']} packets processed",
                      file=sys.stderr)
            yield (ts, new_raw)

    write_libpcap(args.output, _records(), linktype=LINKTYPE_ETHERNET)

    mapping = build_mapping_json(
        remap, args.input_pcap, args.output, args.subnet, args.seed
    )
    with open(args.mapping_file, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)

    out_size = args.output.stat().st_size
    print(f"read  {args.input_pcap.name} "
          f"({stats['total_packets']:,} packets, {input_format}, "
          f"{input_size/1_000_000:.1f} MB)")
    print(f"wrote {args.output.name} "
          f"({stats['total_packets']:,} packets, {out_size/1_000_000:.1f} MB)")
    print(f"  ips  remapped: {len(remap.ip_map):<6d}  "
          f"macs remapped: {len(remap.mac_map)}")
    print(f"  cas  rewrites: {stats['ca_rewrites']:<6d}  "
          f"ioas rewrites: {stats['ioa_rewrites']}")
    if stats["non_ipv4"] or stats["fragmented"] or stats["short_ipv4"]:
        print(f"  passed through: {stats['non_ipv4']} non-IPv4, "
              f"{stats['fragmented']} fragmented, "
              f"{stats['short_ipv4']} short/malformed IPv4")
    if stats["unknown_types"]:
        types_str = ", ".join(str(t) for t in sorted(stats["unknown_types"]))
        print(f"  note: {len(stats['unknown_types'])} IEC 104 ASDU type(s) "
              f"not in the size table ({types_str}) — "
              f"their IOAs were left unchanged")
    print(f"mapping audit: {args.mapping_file.name}")


if __name__ == "__main__":
    main()
