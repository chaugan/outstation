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

# ASDUs without a time tag.
M_SP_NA_1 = 1   # single point
M_DP_NA_1 = 3   # double point
M_ME_NA_1 = 9   # measured value, normalized
M_ME_NB_1 = 11  # measured value, scaled
M_ME_NC_1 = 13  # measured value, short float
M_IT_NA_1 = 15  # integrated totals (counter)
M_EI_NA_1 = 70  # end of initialization
C_SC_NA_1 = 45  # single command
C_SE_NC_1 = 50  # set-point short float
C_IC_NA_1 = 100 # station interrogation
C_CI_NA_1 = 101 # counter interrogation

# ASDUs with a 7-byte CP56Time2a time tag appended to every element.
M_SP_TB_1 = 30
M_DP_TB_1 = 31
M_ME_TD_1 = 34  # NVA + QDS + CP56
M_ME_TE_1 = 35  # SVA + QDS + CP56
M_ME_TF_1 = 36  # float + QDS + CP56  (most common in real traffic)
M_IT_TB_1 = 37  # BCR + CP56
C_SC_TA_1 = 58  # single command with CP56
C_SE_TC_1 = 63  # set-point float with CP56
C_CS_NA_1 = 103 # clock synchronisation (bare CP56)


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


def nva(value_norm, qds=0):
    # Normalised value: signed 16-bit in [-1.0, 1.0).
    v = max(-32768, min(32767, int(round(value_norm * 32767))))
    return struct.pack("<h", v) + bytes([qds])


def sva(value_int, qds=0):
    v = max(-32768, min(32767, int(value_int)))
    return struct.pack("<h", v) + bytes([qds])


def bcr(counter_value, seq=0, iv=False, ca=False, cy=False):
    # Binary counter reading: 4-byte value + 1-byte qualifier.
    qual = (seq & 0x1F) | (0x20 if cy else 0) | (0x40 if ca else 0) | (0x80 if iv else 0)
    return struct.pack("<I", counter_value & 0xFFFFFFFF) + bytes([qual])


def sco(on, qu=0, se=0):
    # Single command object: bits 0=SCS, 1=reserved, 2..7=QU, 7=S/E.
    return bytes([(on & 1) | ((qu & 0x1F) << 2) | ((se & 1) << 7)])


def qos(ql=0, se=0):
    # Qualifier of set-point command.
    return bytes([(ql & 0x7F) | ((se & 1) << 7)])


def cp56time2a(unix_time_sec, iv=False, su=False):
    """Encode a CP56Time2a 7-byte field for the given UTC epoch seconds.

    IV (invalid) and SU (summer time) flag bits are caller-supplied so a
    replay can faithfully reproduce "data-quality" scenarios. Day-of-week
    is always populated from the calendar date (some older RTUs reject
    DOW=0 even though the spec allows it).
    """
    dt = datetime.fromtimestamp(unix_time_sec, tz=timezone.utc)
    ms_in_min = dt.second * 1000 + dt.microsecond // 1000
    iso_dow = dt.isoweekday()  # Mon=1 .. Sun=7
    year_mod = dt.year - 2000
    return bytes([
        ms_in_min & 0xFF,
        (ms_in_min >> 8) & 0xFF,
        (0x80 if iv else 0) | (dt.minute & 0x3F),
        (0x80 if su else 0) | (dt.hour & 0x1F),
        ((iso_dow & 0x07) << 5) | (dt.day & 0x1F),
        dt.month & 0x0F,
        year_mod & 0x7F,
    ])


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

def _payload_for(kind, rng, counters, counter_ioa_set):
    """Build the per-element payload bytes for a monitor-side ASDU.

    For counter types the caller passes `counters[ioa]` state so the
    generated stream looks like a monotonic counter reading. Everything
    else uses freshly-sampled random values.
    """
    if kind in (M_SP_NA_1, M_SP_TB_1):
        return siq(rng.randint(0, 1))
    if kind in (M_DP_NA_1, M_DP_TB_1):
        return diq(rng.choice([1, 2]))
    if kind in (M_ME_NA_1, M_ME_TD_1):
        return nva(rng.uniform(-0.95, 0.95))
    if kind == M_ME_NB_1 or kind == M_ME_TE_1:
        return sva(rng.randint(-30000, 30000))
    if kind in (M_ME_NC_1, M_ME_TF_1):
        return float_short(rng.uniform(-1000.0, 1000.0))
    if kind in (M_IT_NA_1, M_IT_TB_1):
        # Internal stub: caller overrides with a monotonic counter.
        return bcr(0)
    raise ValueError(f"unsupported kind: {kind}")


# Type catalogue for the monitor-side spontaneous / inrogen stream.
# Weights are intentionally realistic: float measurements dominate,
# single/double points common, scaled values and counters rarer.
MONITOR_WEIGHTS_NO_TS = [
    (M_SP_NA_1, 6),
    (M_DP_NA_1, 3),
    (M_ME_NC_1, 10),
    (M_ME_NA_1, 2),
    (M_ME_NB_1, 2),
    (M_IT_NA_1, 1),
]
MONITOR_WEIGHTS_WITH_TS = [
    (M_SP_TB_1, 6),
    (M_DP_TB_1, 3),
    (M_ME_TF_1, 10),  # float + CP56 — the workhorse
    (M_ME_TD_1, 2),
    (M_ME_TE_1, 2),
    (M_IT_TB_1, 1),
]


def pick_monitor_kind(rng, with_timestamps):
    table = MONITOR_WEIGHTS_WITH_TS if with_timestamps else MONITOR_WEIGHTS_NO_TS
    kinds, weights = zip(*table)
    return rng.choices(kinds, weights=weights, k=1)[0]


def monitor_element_bytes(kind, rng, counter_state, wall_time_sec):
    """Return the per-IOA element bytes (no IOA prefix) for a single
    monitor object of `kind`. Counter types draw from and update the
    per-IOA `counter_state` dict so the value stream advances realistically.
    `wall_time_sec` is the UTC epoch to embed if the type carries CP56."""
    if kind == M_IT_NA_1:
        # Counter value advances slowly; pick the first counter slot.
        ioa = next(iter(counter_state), 1)
        counter_state[ioa] = counter_state.get(ioa, rng.randrange(1000, 10_000)) + rng.randint(0, 7)
        return bcr(counter_state[ioa], seq=rng.randrange(0, 32))
    if kind == M_IT_TB_1:
        ioa = next(iter(counter_state), 1)
        counter_state[ioa] = counter_state.get(ioa, rng.randrange(1000, 10_000)) + rng.randint(0, 7)
        return bcr(counter_state[ioa], seq=rng.randrange(0, 32)) + cp56time2a(wall_time_sec)
    body = _payload_for(kind, rng, counter_state, set())
    # TB variants append CP56 after the base element bytes.
    if kind in (M_SP_TB_1, M_DP_TB_1, M_ME_TD_1, M_ME_TE_1, M_ME_TF_1):
        return body + cp56time2a(wall_time_sec)
    return body


def run_session(sess, t0, duration, rng, mean_interval, jitter,
                with_timestamps, master_commands, clock_sync):
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

    # Optional: master sends a clock-sync command right after init.
    # Type 103 (C_CS_NA_1) carries a bare CP56Time2a and is the best
    # real-world example of a timestamp crossing the wire.
    if clock_sync:
        t += rng.uniform(0.02, 0.1)
        cs_frame = asdu(C_CS_NA_1, cot=COT_ACT, common_addr=ca,
                        objects=[(0, cp56time2a(t))])
        sess._emit(t, "mst", apci_i(sess.mst_ns, sess.rtu_ns, cs_frame),
                   TCP_PSH | TCP_ACK)
        sess.mst_ns = (sess.mst_ns + 1) & 0x7FFF
        t += rng.uniform(0.002, 0.015)
        cs_con = asdu(C_CS_NA_1, cot=COT_ACTCON, common_addr=ca,
                      objects=[(0, cp56time2a(t))])
        sess._emit(t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, cs_con),
                   TCP_PSH | TCP_ACK)
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

    # Inrogen burst: one monitor frame per IOA, kind drawn from the
    # mix. Type-per-IOA is pinned so the same point reports the same
    # type every time — matches how real RTUs expose their points.
    counter_state = {}
    ioa_kinds = {}
    for point in sess.rtu["points"]:
        # Counter IOAs get counter types; rest use non-counter mix.
        if rng.random() < 0.15:
            ioa_kinds[point] = M_IT_TB_1 if with_timestamps else M_IT_NA_1
            counter_state[point] = rng.randrange(1000, 100_000)
        else:
            ioa_kinds[point] = pick_monitor_kind(rng, with_timestamps)

    for point in sess.rtu["points"]:
        t += rng.uniform(0.0005, 0.004)
        kind = ioa_kinds[point]
        # For inrogen bursts we still stamp with `t` if the type
        # carries CP56 — the RTU is reporting "current value as of now".
        per_counter = {point: counter_state[point]} if point in counter_state else {}
        elem = monitor_element_bytes(kind, rng, per_counter, t)
        if point in counter_state:
            counter_state[point] = per_counter[point]
        frame = asdu(kind, cot=COT_INROGEN, common_addr=ca,
                     objects=[(point, elem)])
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
    # periodically, either side may probe with TESTFR, optionally
    # master also issues occasional commands.
    points = sess.rtu["points"]
    end = t0 + duration
    next_s_ack = t + rng.uniform(5, 15)
    next_testfr = t + rng.uniform(20, 45)
    next_command = t + rng.uniform(30, 90) if master_commands else end + 1
    next_counter_interrogation = t + rng.uniform(40, 120)
    # Pick a small subset of points as "commandable outputs" so
    # master commands always target a valid IOA.
    commandable = rng.sample(points, min(3, len(points))) if points else []

    while t < end:
        point = rng.choice(points)
        kind = ioa_kinds[point]
        per_counter = {point: counter_state[point]} if point in counter_state else {}
        elem = monitor_element_bytes(kind, rng, per_counter, t)
        if point in counter_state:
            counter_state[point] = per_counter[point]
        frame = asdu(kind, cot=COT_SPONT, common_addr=ca,
                     objects=[(point, elem)])
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

        # Optional master-side command (C_SC_NA_1 or C_SC_TA_1) against
        # one of the commandable IOAs. RTU replies ActCon then ActTerm,
        # and emits a spontaneous status update for that point.
        if t >= next_command and commandable:
            target_ioa = rng.choice(commandable)
            on = rng.randint(0, 1)
            if with_timestamps:
                cmd_kind = C_SC_TA_1
                cmd_elem = sco(on, qu=0, se=0) + cp56time2a(sub_t)
            else:
                cmd_kind = C_SC_NA_1
                cmd_elem = sco(on, qu=0, se=0)
            cmd_act = asdu(cmd_kind, cot=COT_ACT, common_addr=ca,
                           objects=[(target_ioa, cmd_elem)])
            sess._emit(sub_t, "mst", apci_i(sess.mst_ns, sess.rtu_ns, cmd_act),
                       TCP_PSH | TCP_ACK)
            sess.mst_ns = (sess.mst_ns + 1) & 0x7FFF
            sub_t += rng.uniform(0.005, 0.03)

            # RTU ActCon.
            cmd_con_elem = sco(on, qu=0, se=0)
            if with_timestamps:
                cmd_con_elem += cp56time2a(sub_t)
            cmd_con = asdu(cmd_kind, cot=COT_ACTCON, common_addr=ca,
                           objects=[(target_ioa, cmd_con_elem)])
            sess._emit(sub_t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, cmd_con),
                       TCP_PSH | TCP_ACK)
            sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF
            sub_t += rng.uniform(0.01, 0.08)

            # RTU ActTerm.
            cmd_term = asdu(cmd_kind, cot=COT_ACTTERM, common_addr=ca,
                            objects=[(target_ioa, cmd_con_elem)])
            sess._emit(sub_t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, cmd_term),
                       TCP_PSH | TCP_ACK)
            sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF
            next_command = t + rng.uniform(40, 150)

        # Occasional counter interrogation request: master sends
        # C_CI_NA_1, RTU replies with ActCon then freezes every counter
        # point as a burst of counter frames.
        if t >= next_counter_interrogation and counter_state:
            ci_act = asdu(C_CI_NA_1, cot=COT_ACT, common_addr=ca,
                          objects=[(0, bytes([5]))])  # QCC=5 general
            sess._emit(sub_t, "mst", apci_i(sess.mst_ns, sess.rtu_ns, ci_act),
                       TCP_PSH | TCP_ACK)
            sess.mst_ns = (sess.mst_ns + 1) & 0x7FFF
            sub_t += rng.uniform(0.002, 0.015)
            ci_con = asdu(C_CI_NA_1, cot=COT_ACTCON, common_addr=ca,
                          objects=[(0, bytes([5]))])
            sess._emit(sub_t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, ci_con),
                       TCP_PSH | TCP_ACK)
            sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF
            sub_t += rng.uniform(0.002, 0.01)
            for ioa, val in list(counter_state.items()):
                kind = M_IT_TB_1 if with_timestamps else M_IT_NA_1
                elem_body = bcr(val, seq=rng.randrange(0, 32))
                if with_timestamps:
                    elem_body += cp56time2a(sub_t)
                ct_frame = asdu(kind, cot=37, common_addr=ca,  # COT=37 requested by counter-interrogation
                                objects=[(ioa, elem_body)])
                sess._emit(sub_t, "rtu", apci_i(sess.rtu_ns, sess.mst_ns, ct_frame),
                           TCP_PSH | TCP_ACK)
                sess.rtu_ns = (sess.rtu_ns + 1) & 0x7FFF
                sub_t += rng.uniform(0.0005, 0.003)
            next_counter_interrogation = t + rng.uniform(60, 180)

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
    ap.add_argument("--no-timestamps", dest="with_timestamps",
                    action="store_false", default=True,
                    help="use legacy NA-series ASDUs with no CP56Time2a "
                         "embedded (old behaviour). Default is ON, which "
                         "emits TB-series types (30/31/34/35/36/37, and "
                         "58 + 103 for commands) — required if you want "
                         "to exercise outstation's --fresh-timestamps "
                         "rewrite feature.")
    ap.add_argument("--no-master-commands", dest="master_commands",
                    action="store_false", default=True,
                    help="suppress master-side C_SC commands during the "
                         "spontaneous phase. Default is ON so a single "
                         "capture exercises both directions.")
    ap.add_argument("--no-clock-sync", dest="clock_sync",
                    action="store_false", default=True,
                    help="skip the C_CS_NA_1 (type 103) clock-sync "
                         "exchange after init. Default is ON.")
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
                    args.mean_interval, args.jitter,
                    with_timestamps=args.with_timestamps,
                    master_commands=args.master_commands,
                    clock_sync=args.clock_sync)

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
