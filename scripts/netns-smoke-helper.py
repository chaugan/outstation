#!/usr/bin/env python3
"""Helpers for scripts/netns-smoke.sh (Python stdlib only).

Subcommands:

  json EXPR            Read JSON from stdin, evaluate the Python
                       expression EXPR with the document bound to `d`,
                       print the result (strings raw, None as empty,
                       everything else as JSON). Exit 1 if EXPR raises.
  pcap-replay SRC CAP TARGET_IP TARGET_MAC [ONLY_SRC]
                       Compare a raw-replay capture CAP with its source
                       pcap SRC: every IPv4 frame of SRC (from the
                       comma-separated ONLY_SRC addresses, if given)
                       rewritten to TARGET_IP/TARGET_MAC should appear in
                       CAP exactly as often (keyed by src ip, ports,
                       seq/ack, flags and L4 payload; checksums and TTL
                       are ignored). Prints a JSON summary: `missing`
                       frames never captured, `unexpected` extra copies.
  pcap-count CAP       Frame count and IPv4/TCP breakdown of a pcap, as
                       JSON.
  sse FILE             Parse a captured text/event-stream into a JSON
                       list of {"event": name, "data": parsed data}.
  metrics FILE         Parse a Prometheus text exposition into a JSON
                       object {"name{labels}": value}.
"""
import collections
import json
import struct
import sys


def read_pcap(path):
    """Yield the frames of a classic pcap file (either byte order,
    micro- or nanosecond timestamps). Returns (linktype, [frames])."""
    with open(path, "rb") as f:
        b = f.read()
    if len(b) < 24:
        raise ValueError(f"{path}: too short for a pcap header")
    magic = b[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError(f"{path}: not a classic pcap (magic {magic.hex()})")
    linktype = struct.unpack(endian + "I", b[20:24])[0]
    frames = []
    off = 24
    while off + 16 <= len(b):
        incl = struct.unpack(endian + "I", b[off + 8 : off + 12])[0]
        frames.append(b[off + 16 : off + 16 + incl])
        off += 16 + incl
    return linktype, frames


def ip4(b):
    return ".".join(str(x) for x in b)


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def parse_eth(f):
    """(dst_mac, src_mac, l3) for an Ethernet frame, skipping VLAN tags,
    or None when it is not IPv4."""
    if len(f) < 14:
        return None
    et = struct.unpack(">H", f[12:14])[0]
    off = 14
    while et in (0x8100, 0x88A8) and len(f) >= off + 4:
        et = struct.unpack(">H", f[off + 2 : off + 4])[0]
        off += 4
    if et != 0x0800:
        return None
    return mac(f[0:6]), mac(f[6:12]), f[off:]


def tcp_key(l3):
    """Identity of an IPv4 packet that survives an L3 rewrite of the
    destination: (src ip, proto, sport, dport, seq, ack, flags, payload)
    for TCP, (src ip, proto, payload) for anything else."""
    if len(l3) < 20:
        return None
    ihl = (l3[0] & 0x0F) * 4
    total = struct.unpack(">H", l3[2:4])[0]
    proto = l3[9]
    src = ip4(l3[12:16])
    body = l3[ihl:total] if total >= ihl else l3[ihl:]
    if proto == 6 and len(body) >= 20:
        sport, dport, seq, ack = struct.unpack(">HHII", body[:12])
        doff = (body[12] >> 4) * 4
        flags = body[13]
        return (src, proto, sport, dport, seq, ack, flags, bytes(body[doff:]))
    return (src, proto, bytes(body))


def cmd_pcap_replay(src, cap, target_ip, target_mac, only_src=""):
    target_mac = target_mac.lower()
    only = {ip for ip in only_src.split(",") if ip}
    _, sframes = read_pcap(src)
    _, cframes = read_pcap(cap)
    want = collections.Counter()
    for f in sframes:
        e = parse_eth(f)
        if e is None:
            continue
        k = tcp_key(e[2])
        if k is not None and (not only or k[0] in only):
            want[k] += 1
    got = collections.Counter()
    to_target = 0
    other = 0
    for f in cframes:
        e = parse_eth(f)
        if e is None:
            other += 1
            continue
        dst_mac, _, l3 = e
        if dst_mac == target_mac and len(l3) >= 20 and ip4(l3[16:20]) == target_ip:
            to_target += 1
            k = tcp_key(l3)
            if k is not None:
                got[k] += 1
        else:
            other += 1
    missing = sum((want - got).values())
    unexpected = sum((got - want).values())
    print(
        json.dumps(
            {
                "source_ipv4_frames": sum(want.values()),
                "captured_frames": len(cframes),
                "captured_to_target": to_target,
                "captured_other": other,
                "missing": missing,
                "unexpected": unexpected,
            }
        )
    )


def cmd_pcap_count(cap):
    linktype, frames = read_pcap(cap)
    ipv4 = tcp = 0
    for f in frames:
        e = parse_eth(f) if linktype == 1 else None
        if e is None:
            continue
        ipv4 += 1
        if len(e[2]) >= 20 and e[2][9] == 6:
            tcp += 1
    print(json.dumps({"linktype": linktype, "frames": len(frames), "ipv4": ipv4, "tcp": tcp}))


def cmd_sse(path):
    events = []
    name, data = None, []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line == "":
                if name is not None or data:
                    raw = "\n".join(data)
                    try:
                        parsed = json.loads(raw)
                    except ValueError:
                        parsed = raw
                    events.append({"event": name or "message", "data": parsed})
                name, data = None, []
            elif line.startswith(":"):
                continue
            elif line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
    print(json.dumps(events))


def cmd_metrics(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, val = line.rpartition(" ")
            try:
                out[key] = float(val)
            except ValueError:
                pass
    print(json.dumps(out))


def cmd_json(expr):
    raw = sys.stdin.read()
    d = json.loads(raw) if raw.strip() else None
    try:
        # EXPR is a literal written in netns-smoke.sh, never data from
        # the server or the network; the server's JSON is only `d`.
        v = eval(expr, {"json": json, "d": d})  # noqa: S307
    except Exception as e:  # noqa: BLE001
        print(f"json helper: {expr!r} failed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
    if v is None:
        print("")
    elif isinstance(v, str):
        print(v)
    elif isinstance(v, bool):
        print("true" if v else "false")
    else:
        print(json.dumps(v))


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "json" and len(args) == 1:
        cmd_json(args[0])
    elif cmd == "pcap-replay" and len(args) in (4, 5):
        cmd_pcap_replay(*args)
    elif cmd == "pcap-count" and len(args) == 1:
        cmd_pcap_count(args[0])
    elif cmd == "sse" and len(args) == 1:
        cmd_sse(args[0])
    elif cmd == "metrics" and len(args) == 1:
        cmd_metrics(args[0])
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
