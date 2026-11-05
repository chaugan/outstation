#!/usr/bin/env python3
"""Minimal IEC 60870-5-104 slave (controlled station) for privileged
end-to-end tests: answers STARTDT/STOPDT/TESTFR and acknowledges every
I-frame with an S-frame. Nothing else.

Usage: iec104-mock-slave.py <listen-ip> [port]
"""
import socket
import sys
import threading


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve(conn):
    received = 0
    with conn:
        while True:
            head = recv_exact(conn, 2)
            if head is None or head[0] != 0x68:
                return
            body = recv_exact(conn, head[1])
            if body is None or len(body) < 4:
                return
            c1 = body[0]
            if c1 & 0x01 == 0:  # I-frame
                received = (received + 1) % 32768
                nr = received << 1
                conn.sendall(bytes([0x68, 4, 0x01, 0x00, nr & 0xFF, nr >> 8]))
            elif c1 & 0x03 == 0x03:  # U-frame
                reply = {0x07: 0x0B, 0x13: 0x23, 0x43: 0x83}.get(c1)
                if reply is not None:
                    conn.sendall(bytes([0x68, 4, reply, 0, 0, 0]))


def main():
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2404
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(64)
    print(f"mock IEC 104 slave on {ip}:{port}", flush=True)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
