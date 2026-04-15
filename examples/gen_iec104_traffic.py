#!/usr/bin/env python3
"""Generate synthetic IEC 60870-5-104 traffic pcaps for multiple RTUs.

Topology matches real IEC 104: one SCADA master (TCP client) connects to
N RTUs (TCP servers, each listening on :2404). Per RTU the master does
TESTFR/STARTDT, issues a general interrogation, and then the RTU streams
spontaneous monitor data (single-points, double-points, short floats)
with periodic S-frame acknowledgements and TESTFR keepalives. Output is
a fresh libpcap file per invocation.
"""

import argparse
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone

# --- libpcap framing ------------------------------------------------------

LINKTYPE_ETHERNET = 1
PCAP_MAGIC = 0xA1B2C3D4


def write_pcap(path, records):
    with open(path, "wb") as f:
        f.write(
            struct.pack(
                "<IHHiIII",
                PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET,
            )
        )
        for ts, data in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)


# --- checksums ------------------------------------------------------------

def _csum(data):
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# --- L2/L3/L4 builders ----------------------------------------------------

ETHERTYPE_IPV4 = 0x0800
IP_PROTO_TCP = 6

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


def build_eth(dst_mac, src_mac):
    return dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4)


def build_ip(src_ip, dst_ip, payload, ident):
    total = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident, 0x4000, 64, IP_PROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    c = _csum(hdr)
    hdr = hdr[:10] + struct.pack("!H", c) + hdr[12:]
    return hdr + payload


def build_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, win, payload):
    off = 5 << 4
    hdr = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        off, flags, win, 0, 0,
    )
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + b"\x00\x06"
        + struct.pack("!H", len(hdr) + len(payload))
    )
    c = _csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
    return hdr + payload


# --- IEC 60870-5-104 -----------------------------------------------------

STARTDT_ACT = 0x07
STARTDT_CON = 0x0B
STOPDT_ACT = 0x13
STOPDT_CON = 0x23
TESTFR_ACT = 0x43
TESTFR_CON = 0x83

COT_CYCLIC = 1
COT_BACKGROUND = 2
COT_SPONT = 3
COT_INIT = 4
COT_ACT = 6
COT_ACTCON = 7
COT_ACTTERM = 10
COT_INROGEN = 20

M_SP_NA_1 = 1   # single point
M_DP_NA_1 = 3   # double point
M_ME_NA_1 = 9   # measured value, normalized
M_ME_NC_1 = 13  # measured value, short float
M_EI_NA_1 = 70  # end of initialization
C_SC_NA_1 = 45
C_IC_NA_1 = 100


def apci_u(ctrl):
    return bytes([0x68, 4, ctrl, 0, 0, 0])


def apci_s(recv_seq):
    return bytes(
        [
            0x68, 4,
            0x01, 0x00,
            (recv_seq << 1) & 0xFF,
            (recv_seq >> 7) & 0xFF,
        ]
    )


def apci_i(send_seq, recv_seq, asdu_bytes):
    length = 4 + len(asdu_bytes)
    if length > 253:
        raise ValueError("ASDU too large for single APDU")
    return (
        bytes(
            [
                0x68, length,
                (send_seq << 1) & 0xFF,
                (send_seq >> 7) & 0xFF,
                (recv_seq << 1) & 0xFF,
                (recv_seq >> 7) & 0xFF,
            ]
        )
        + asdu_bytes
    )


def asdu(type_id, cot, common_addr, objects, orig=0, test=False, neg=False):
    vsq = len(objects) & 0x7F  # SQ=0: discrete elements
    cot_byte = (cot & 0x3F) | (0x80 if test else 0) | (0x40 if neg else 0)
    header = (
        bytes([type_id, vsq, cot_byte, orig & 0xFF])
        + struct.pack("<H", common_addr & 0xFFFF)
    )
    body = b"".join(
        struct.pack("<I", ioa)[:3] + element for ioa, element in objects
    )
    return header + body


def siq(on, quality=0):
    return bytes([(on & 1) | (quality & 0xF0)])


def diq(state, quality=0):
    # 0=indeterminate, 1=off, 2=on, 3=indeterminate
    return bytes([(state & 0x03) | (quality & 0xF0)])


def float_short(value, qds=0):
    return struct.pack("<f", value) + bytes([qds])


# --- session state --------------------------------------------------------

class Session:
    """Builds timestamped Ethernet frames for one master<->RTU TCP flow.

    The master is the TCP client (connects out from an ephemeral port).
    The RTU is the TCP server (listens on :2404). Direction "mst" means
    master-to-RTU; direction "rtu" means RTU-to-master.
    """

    def __init__(self, master, rtu, events, rng):
        self.master = master
        self.rtu = rtu
        self.events = events
        self.rng = rng
        self.mst_seq = rng.randrange(1, 2**31)
        self.rtu_seq = rng.randrange(1, 2**31)
        self.mst_ack = 0
        self.rtu_ack = 0
        self.mst_ipid = rng.randrange(1000, 60000)
        self.rtu_ipid = rng.randrange(1000, 60000)
        # IEC 104 per-direction I-frame send counters.
        self.mst_ns = 0  # N(S) for frames the master sends
        self.rtu_ns = 0  # N(S) for frames the RTU sends

    def _bump_ipid(self, side):
        if side == "mst":
            self.mst_ipid = (self.mst_ipid + 1) & 0xFFFF
            return self.mst_ipid
        self.rtu_ipid = (self.rtu_ipid + 1) & 0xFFFF
        return self.rtu_ipid

    def _emit(self, t, direction, payload, flags):
        if direction == "mst":
            src_ip, dst_ip = self.master["ip"], self.rtu["ip"]
            sport, dport = self.master["port"], self.rtu["port"]
            seq, ack = self.mst_seq, self.mst_ack
            src_mac, dst_mac = self.master["mac"], self.rtu["mac"]
            ipid = self._bump_ipid("mst")
            win = 64240
        else:
            src_ip, dst_ip = self.rtu["ip"], self.master["ip"]
            sport, dport = self.rtu["port"], self.master["port"]
            seq, ack = self.rtu_seq, self.rtu_ack
            src_mac, dst_mac = self.rtu["mac"], self.master["mac"]
            ipid = self._bump_ipid("rtu")
            win = 29200

        tcp = build_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, win, payload)
        ip = build_ip(src_ip, dst_ip, tcp, ipid)
        eth = build_eth(dst_mac, src_mac)
        self.events.append((t, eth + ip))

        advance = len(payload)
        if flags & (TCP_SYN | TCP_FIN):
            advance += 1
        if direction == "mst":
            self.mst_seq = (self.mst_seq + advance) & 0xFFFFFFFF
            self.rtu_ack = self.mst_seq
        else:
            self.rtu_seq = (self.rtu_seq + advance) & 0xFFFFFFFF
            self.mst_ack = self.rtu_seq


# --- session scripting ----------------------------------------------------

def _spont_element(kind, rng):
    if kind == M_SP_NA_1:
        return siq(rng.randint(0, 1))
    if kind == M_DP_NA_1:
        return diq(rng.choice([1, 2]))
    return float_short(rng.uniform(-1000.0, 1000.0))


def run_session(sess, t0, duration, rng, mean_interval, jitter):
    t = t0
    ca = sess.rtu["asdu_addr"]

    # TCP three-way handshake: master connects to RTU listening on :2404
    sess._emit(t, "mst", b"", TCP_SYN)
    t += rng.uniform(0.0005, 0.003)
    sess._emit(t, "rtu", b"", TCP_SYN | TCP_ACK)
    t += rng.uniform(0.00005, 0.0006)
    sess._emit(t, "mst", b"", TCP_ACK)

    # TESTFR act/con: master probes link, RTU confirms.
    t += rng.uniform(0.05, 0.4)
    sess._emit(t, "mst", apci_u(TESTFR_ACT), TCP_PSH | TCP_ACK)
    t += rng.uniform(0.0008, 0.01)
    sess._emit(t, "rtu", apci_u(TESTFR_CON), TCP_PSH | TCP_ACK)

    # STARTDT act/con: master opens data transfer, RTU confirms.
    t += rng.uniform(0.05, 0.4)
    sess._emit(t, "mst", apci_u(STARTDT_ACT), TCP_PSH | TCP_ACK)
    t += rng.uniform(0.0008, 0.01)
    sess._emit(t, "rtu", apci_u(STARTDT_CON), TCP_PSH | TCP_ACK)

    # RTU announces end of initialisation (M_EI_NA_1, COT=init).
    t += rng.uniform(0.005, 0.08)
    ei = asdu(M_EI_NA_1, cot=COT_INIT, common_addr=ca,
              objects=[(0, bytes([0x00]))])
    sess._emit(t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, ei), TCP_PSH | TCP_ACK)
    sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF

    # General interrogation: master requests a snapshot, RTU confirms,
    # streams every point with COT=inrogen, then sends ActTerm.
    t += rng.uniform(0.01, 0.08)
    gi_act = asdu(C_IC_NA_1, cot=COT_ACT, common_addr=ca,
                  objects=[(0, bytes([20]))])  # QOI=20 (station interrogation)
    sess._emit(t, "mst", apci_i(sess.mst_ns, sess.rtu_ns, gi_act), TCP_PSH | TCP_ACK)
    sess.mst_ns = (sess.mst_ns + 1) & 0x7FFF

    t += rng.uniform(0.001, 0.01)
    gi_con = asdu(C_IC_NA_1, cot=COT_ACTCON, common_addr=ca,
                  objects=[(0, bytes([20]))])
    sess._emit(t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, gi_con), TCP_PSH | TCP_ACK)
    sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF

    for point in sess.rtu["points"]:
        t += rng.uniform(0.0005, 0.004)
        kind = rng.choice([M_SP_NA_1, M_DP_NA_1, M_ME_NC_1])
        frame = asdu(kind, cot=COT_INROGEN, common_addr=ca,
                     objects=[(point, _spont_element(kind, rng))])
        sess._emit(t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, frame),
                   TCP_PSH | TCP_ACK)
        sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF

    t += rng.uniform(0.001, 0.01)
    gi_term = asdu(C_IC_NA_1, cot=COT_ACTTERM, common_addr=ca,
                   objects=[(0, bytes([20]))])
    sess._emit(t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, gi_term), TCP_PSH | TCP_ACK)
    sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF

    # Master acknowledges the inrogen burst with one S-frame.
    t += rng.uniform(0.005, 0.03)
    sess._emit(t, "mst", apci_s(sess.rtu_ns), TCP_PSH | TCP_ACK)

    # Spontaneous monitor stream: RTU pushes events, master S-acks
    # periodically, either side may probe with TESTFR.
    points = sess.rtu["points"]
    end = t0 + duration
    next_s_ack = t + rng.uniform(5, 15)
    next_testfr = t + rng.uniform(20, 45)

    while t < end:
        point = rng.choice(points)
        kind = rng.choices(
            [M_SP_NA_1, M_DP_NA_1, M_ME_NC_1],
            weights=[3, 2, 4],
        )[0]
        frame = asdu(kind, cot=COT_SPONT, common_addr=ca,
                     objects=[(point, _spont_element(kind, rng))])
        sess._emit(t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, frame),
                   TCP_PSH | TCP_ACK)
        sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF

        # Sub-events share a single monotonic cursor so Python emit
        # order matches wall-clock order after the global sort.
        sub_t = t + rng.uniform(0.0005, 0.002)

        if t >= next_s_ack:
            sess._emit(sub_t, "mst", apci_s(sess.rtu_ns), TCP_PSH | TCP_ACK)
            sub_t += rng.uniform(0.0005, 0.003)
            next_s_ack = t + rng.uniform(8, 20)

        if t >= next_testfr:
            sess._emit(sub_t, "mst", apci_u(TESTFR_ACT), TCP_PSH | TCP_ACK)
            sub_t += rng.uniform(0.0008, 0.005)
            sess._emit(sub_t, "rtu", apci_u(TESTFR_CON), TCP_PSH | TCP_ACK)
            sub_t += rng.uniform(0.0005, 0.002)
            next_testfr = t + rng.uniform(25, 60)

        dt = rng.expovariate(1.0 / max(mean_interval, 0.05))
        dt *= rng.uniform(max(0.0, 1 - jitter), 1 + jitter)
        t = max(sub_t, t + max(0.01, dt))

    # Orderly shutdown, always strictly after the last emitted packet.
    t = max(t, end) + rng.uniform(0.05, 0.3)
    sess._emit(t, "mst", apci_u(STOPDT_ACT), TCP_PSH | TCP_ACK)
    t += rng.uniform(0.001, 0.01)
    sess._emit(t, "rtu", apci_u(STOPDT_CON), TCP_PSH | TCP_ACK)


# --- addressing helpers ---------------------------------------------------

def parse_cidr(cidr):
    net, bits = cidr.split("/")
    bits = int(bits)
    base = struct.unpack("!I", socket.inet_aton(net))[0]
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return base & mask, 1 << (32 - bits)


def ip_at(base, offset):
    return socket.inet_ntoa(struct.pack("!I", base + offset))


def parse_mac(s):
    parts = s.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError(f"bad MAC: {s}")
    return bytes(int(p, 16) for p in parts)


def random_mac(rng):
    # Locally-administered unicast
    return bytes(
        [0x02, rng.randrange(256), rng.randrange(256),
         rng.randrange(256), rng.randrange(256), rng.randrange(256)]
    )


# --- main -----------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-n", "--rtus", type=int, default=5,
                    help="number of synthetic RTUs (default: 5)")
    ap.add_argument("-d", "--duration", type=float, default=120.0,
                    help="seconds of traffic per RTU (default: 120)")
    ap.add_argument("--master-ip", default="10.20.100.108",
                    help="SCADA master IP, the TCP client "
                         "(default: 10.20.100.108)")
    ap.add_argument("--master-mac", type=parse_mac,
                    default=parse_mac("02:00:5e:00:64:6c"),
                    help="SCADA master MAC (default: 02:00:5e:00:64:6c)")
    ap.add_argument("--rtu-port", type=int, default=2404,
                    help="IEC 104 listen port on each RTU (default: 2404)")
    ap.add_argument("--subnet", default="10.20.102.0/24",
                    help="subnet the RTUs are allocated from "
                         "(default: 10.20.102.0/24)")
    ap.add_argument("--rtu-start-offset", type=int, default=2,
                    help="lowest host offset to use inside --subnet "
                         "(default: 2, so .0 is network, .1 stays free "
                         "for a gateway)")
    ap.add_argument("-o", "--output", default=None,
                    help="output pcap (default: timestamped file in CWD)")
    ap.add_argument("--seed", type=int, default=None,
                    help="deterministic PRNG seed")
    ap.add_argument("--start-time", type=float, default=None,
                    help="epoch seconds for the first packet (default: now)")
    ap.add_argument("--mean-interval", type=float, default=3.0,
                    help="mean spontaneous-event interval per RTU, seconds")
    ap.add_argument("--jitter", type=float, default=0.5,
                    help="inter-event jitter fraction 0..1 (default: 0.5)")
    ap.add_argument("--points-per-rtu", type=int, default=12,
                    help="number of distinct IOAs each RTU reports (default: 12)")
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)

    base, size = parse_cidr(args.subnet)
    low = max(1, args.rtu_start_offset)
    high = size - 1  # exclude broadcast
    master_host_int = struct.unpack("!I", socket.inet_aton(args.master_ip))[0]

    # Walk offsets in order, skipping the master if it happens to sit in
    # the same subnet. Deterministic, compact allocation — .2, .3, .4 …
    available = [
        off
        for off in range(low, high)
        if base + off != master_host_int
    ]
    if len(available) < args.rtus:
        sys.exit(
            f"subnet {args.subnet} with --rtu-start-offset {args.rtu_start_offset} "
            f"only has {len(available)} host slots, need {args.rtus}"
        )

    rtus = []
    for i, off in enumerate(available[: args.rtus]):
        points = sorted(rng.sample(range(1, 10000), args.points_per_rtu))
        rtus.append(
            {
                "idx": i,
                "ip": ip_at(base, off),
                "port": args.rtu_port,
                "mac": random_mac(rng),
                "asdu_addr": rng.randrange(1, 65534),
                "points": points,
            }
        )

    events = []
    start = args.start_time if args.start_time is not None else time.time()

    for rtu in rtus:
        # The master is a single host; only its source port varies per
        # session so each conversation has a unique 5-tuple.
        master = {
            "ip": args.master_ip,
            "port": rng.randrange(32768, 61000),
            "mac": args.master_mac,
        }
        sess = Session(master, rtu, events, rng)
        offset = rng.uniform(0, min(3.0, max(args.duration * 0.1, 0.01)))
        run_session(sess, start + offset, args.duration, rng,
                    args.mean_interval, args.jitter)

    events.sort(key=lambda x: x[0])

    if args.output is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        args.output = f"synth_iec104_{stamp}_rtus{args.rtus}.pcap"

    write_pcap(args.output, events)

    print(
        f"wrote {len(events)} packets: 1 master ({args.master_ip}) "
        f"-> {args.rtus} RTU listener(s) over {args.duration:g}s -> {args.output}"
    )
    for rtu in rtus:
        print(
            f"  rtu{rtu['idx']:02d}  listen={rtu['ip']}:{rtu['port']}  "
            f"asdu={rtu['asdu_addr']}  points={len(rtu['points'])}"
        )


if __name__ == "__main__":
    main()
