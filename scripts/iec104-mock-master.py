#!/usr/bin/env python3
"""Minimal IEC 60870-5-104 master (controlling station) for privileged
end-to-end tests of slave runs, where outstation impersonates the RTUs.

For every <ip> it connects to <ip>:<port> (retrying until the listener
is up), sends STARTDT act, acknowledges received I-frames with S-frames
(at least every 8 frames, and when the slave goes quiet), answers
TESTFR act, sends one general interrogation (C_IC_NA_1, COT 6, the
station's common address), and closes the connection once the slave has
been quiet for --quiet seconds. Nothing else.

Usage: iec104-mock-master.py [--port 2404] [--quiet 2.0] [--connect-timeout 60]
                             [--ca N] <ip> [<ip> ...]

Exit status 0 when every station completed (connected, got STARTDT con
and at least one I-frame), 1 otherwise. One line per station on stdout.
"""
import argparse
import socket
import struct
import sys
import threading
import time

STARTDT_ACT, STARTDT_CON = 0x07, 0x0B
TESTFR_ACT, TESTFR_CON = 0x43, 0x83
ACK_EVERY = 8


def recv_apdu(conn):
    """One APDU (start byte, length, body) or None on close/timeout."""
    head = b""
    while len(head) < 2:
        chunk = conn.recv(2 - len(head))
        if not chunk:
            return None
        head += chunk
    if head[0] != 0x68:
        raise ValueError(f"bad start byte {head[0]:#x}")
    body = b""
    while len(body) < head[1]:
        chunk = conn.recv(head[1] - len(body))
        if not chunk:
            return None
        body += chunk
    return body


def s_frame(nr):
    return bytes([0x68, 4, 0x01, 0x00, (nr << 1) & 0xFF, (nr >> 7) & 0xFF])


def i_frame(ns, nr, asdu):
    return (
        bytes([0x68, 4 + len(asdu)])
        + struct.pack("<HH", ns << 1, nr << 1)
        + asdu
    )


def gi_asdu(ca):
    # C_IC_NA_1 (100), SQ=0 n=1, COT 6 (act), OA 0, CA, IOA 0, QOI 20.
    return bytes([100, 1, 6, 0]) + struct.pack("<H", ca) + bytes([0, 0, 0, 20])


def connect(ip, port, deadline):
    while True:
        try:
            return socket.create_connection((ip, port), timeout=2.0)
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)


def station(ip, args, results):
    deadline = time.monotonic() + args.connect_timeout
    try:
        conn = connect(ip, args.port, deadline)
    except OSError as e:
        results[ip] = f"FAIL connect: {e}"
        return
    received = 0  # our V(R)
    unacked = 0
    ca = args.ca
    got_con = False
    with conn:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.sendall(bytes([0x68, 4, STARTDT_ACT, 0, 0, 0]))
        conn.settimeout(args.quiet)
        gi_sent = False
        try:
            while True:
                try:
                    body = recv_apdu(conn)
                except socket.timeout:
                    if unacked:
                        conn.sendall(s_frame(received))
                        unacked = 0
                        continue
                    break  # quiet: done
                if body is None:
                    break
                c1 = body[0]
                if c1 & 0x01 == 0:  # I-frame
                    received = (received + 1) % 32768
                    unacked += 1
                    if ca is None and len(body) >= 10:
                        ca = struct.unpack_from("<H", body, 8)[0]
                    if unacked >= ACK_EVERY:
                        conn.sendall(s_frame(received))
                        unacked = 0
                elif c1 & 0x03 == 0x03:  # U-frame
                    if c1 == STARTDT_CON:
                        got_con = True
                    elif c1 == TESTFR_ACT:
                        conn.sendall(bytes([0x68, 4, TESTFR_CON, 0, 0, 0]))
                if got_con and not gi_sent and (ca is not None or received > 0):
                    conn.sendall(i_frame(0, received, gi_asdu(ca or 1)))
                    unacked = 0
                    gi_sent = True
            if unacked:
                conn.sendall(s_frame(received))
        except (OSError, ValueError) as e:
            results[ip] = f"FAIL {e} after {received} I-frames"
            return
    ok = got_con and received > 0
    results[ip] = f"{'OK' if ok else 'FAIL'} startdt_con={got_con} iframes={received}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ips", nargs="+")
    ap.add_argument("--port", type=int, default=2404)
    ap.add_argument("--quiet", type=float, default=2.0)
    ap.add_argument("--connect-timeout", type=float, default=60.0)
    ap.add_argument("--ca", type=int, default=None)
    args = ap.parse_args()
    results = {}
    threads = [
        threading.Thread(target=station, args=(ip, args, results), daemon=True)
        for ip in args.ips
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok = True
    for ip in args.ips:
        r = results.get(ip, "FAIL no result")
        ok = ok and r.startswith("OK")
        print(f"{ip}:{args.port} {r}", flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
