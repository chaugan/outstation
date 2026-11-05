#!/usr/bin/env python3
"""Helpers for scripts/netns-scale.sh (Python stdlib only).

Subcommands:

  merge OUT IN...      Merge classic pcaps (same link type) into OUT,
                       ordered by timestamp.
  sample OUT [--comm NAME]... [--primary NAME] [--interval S]
                       Sample every process of this network namespace
                       whose comm is one of NAME (default: outstation)
                       every S seconds (default 0.2): CPU time (utime +
                       stime, all threads), VmRSS, thread count and open
                       fds, summed per comm. Runs until the --primary
                       comm has appeared and is gone again, or until
                       SIGTERM/SIGINT, then writes OUT (JSON: a
                       timeline of [epoch, {comm: [cpu_s, rss_kb,
                       threads, fds]}]). Needs root for other users'
                       /proc/<pid>/fd.
  fast-slave IP PORT [--procs N]
                       IEC 104 controlled station for master-role runs,
                       same behaviour as iec104-mock-slave.py (answers
                       STARTDT/STOPDT/TESTFR, acknowledges I-frames) but
                       event driven: N processes (default 4) share the
                       listener with SO_REUSEPORT, each an epoll loop.
                       Acknowledges once per read with the current V(R)
                       instead of once per I-frame.
  fast-master [--port P] [--quiet S] [--connect-timeout S] [--procs N]
              [--ca CA] [--t2 S] IP...
                       IEC 104 controlling station for slave-role runs,
                       same behaviour as iec104-mock-master.py (STARTDT,
                       one GI, an S-frame at least every 8 I-frames and
                       when the station goes quiet, TESTFR con, close
                       after --quiet seconds of silence), but event
                       driven: the IPs are split over N processes
                       (default 4), each an epoll loop. Same output and
                       exit status as the threaded mock. --t2 S also
                       acknowledges pending I-frames after S seconds
                       without a new one (like the IEC 104 t2 timer),
                       without closing; needed for original-timing runs
                       with a long --quiet.
  iframe-rate CAPTURE SIDE
                       I-frames in a run capture sent by SIDE (`client`:
                       from the TCP client, i.e. master-role sessions;
                       `server`: from the TCP server, slave-role RTUs),
                       counted once per frame (TCP retransmissions and
                       duplicate copies by seq are dropped). Prints JSON:
                       total, first/last timestamp, active rate and the
                       peak one-second rate.
  summarize DIR        Read one run's files in DIR (report.json,
                       bench.log, time.txt, sample-tool.json,
                       sample-peer.json, peer.out, rate.json, meta.json)
                       and print one JSON object of metrics.
  table JSON...        Print a Markdown table: every run, then the
                       median per scenario.
"""
import collections
import datetime
import heapq
import json
import os
import selectors
import signal
import socket
import statistics
import struct
import sys
import time

# ---------------------------------------------------------------------------
# pcap


def pcap_records(path):
    """Yield (ts_sec, ts_frac, raw record bytes incl. header) and expose
    the global header via the first yielded value's file."""
    with open(path, "rb") as f:
        f.read(24)
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            ts, frac, incl, _orig = struct.unpack("<IIII", h)
            yield (ts, frac, h + f.read(incl))


def pcap_header(path):
    with open(path, "rb") as f:
        h = f.read(24)
    if h[:4] not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        raise SystemExit(f"{path}: not a little-endian classic pcap")
    return h


def cmd_merge(argv):
    out, ins = argv[0], argv[1:]
    hdr = pcap_header(ins[0])
    with open(out, "wb") as o:
        o.write(hdr)
        for r in heapq.merge(*[pcap_records(p) for p in ins], key=lambda r: (r[0], r[1])):
            o.write(r[2])


def cmd_iframe_rate(argv):
    path, side = argv[0], argv[1]
    hdr = pcap_header(path)
    nano = hdr[:4] == b"\x4d\x3c\xb2\xa1"
    linktype = struct.unpack("<I", hdr[20:24])[0]
    if linktype != 1:
        raise SystemExit(f"{path}: link type {linktype}, want Ethernet")
    seen = set()
    stamps = []
    dup = 0
    for ts, frac, rec in pcap_records(path):
        f = rec[16:]
        if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
            continue
        ihl = (f[14] & 0x0F) * 4
        t = 14 + ihl
        sport, dport, seq = struct.unpack("!HHI", f[t : t + 8])
        doff = (f[t + 12] >> 4) * 4
        tot = struct.unpack("!H", f[16:18])[0]
        pay = f[t + doff : 14 + tot]
        if not pay:
            continue
        from_server = sport == 2404
        if (side == "server") != from_server:
            continue
        key = (f[26:30], sport, f[30:34], dport, seq)
        if key in seen:
            dup += 1
            continue
        seen.add(key)
        stamp = ts + frac / (1e9 if nano else 1e6)
        i = 0
        n = 0
        while i + 2 <= len(pay) and pay[i] == 0x68:
            ln = pay[i + 1]
            if i + 2 + ln > len(pay):
                break
            if ln >= 4 and pay[i + 2] & 0x01 == 0:
                n += 1
            i += 2 + ln
        stamps.extend([stamp] * n)
    if not stamps:
        print(json.dumps({"total": 0}))
        return
    stamps.sort()
    buckets = collections.Counter(int(s) for s in stamps)
    span = stamps[-1] - stamps[0]
    print(
        json.dumps(
            {
                "total": len(stamps),
                "duplicates_dropped": dup,
                "first": stamps[0],
                "last": stamps[-1],
                "active_s": round(span, 3),
                "active_rate": round(len(stamps) / span, 1) if span > 0 else None,
                "peak_1s_rate": max(buckets.values()),
            }
        )
    )


# ---------------------------------------------------------------------------
# sampler


def _netns_of(pid):
    try:
        return os.readlink(f"/proc/{pid}/ns/net")
    except OSError:
        return None


def _proc_sample(pid, tick):
    try:
        with open(f"/proc/{pid}/stat") as f:
            st = f.read()
        fields = st[st.rindex(")") + 2 :].split()
        cpu = (int(fields[11]) + int(fields[12])) / tick
        threads = int(fields[17])
        rss = 0
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                    break
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        return cpu, rss, threads, fds
    except (OSError, ValueError, IndexError):
        return None


def cmd_sample(argv):
    out = argv[0]
    comms, primary, interval = [], None, 0.2
    i = 1
    while i < len(argv):
        if argv[i] == "--comm":
            comms.append(argv[i + 1])
            i += 2
        elif argv[i] == "--primary":
            primary = argv[i + 1]
            i += 2
        elif argv[i] == "--interval":
            interval = float(argv[i + 1])
            i += 2
        else:
            raise SystemExit(f"sample: unknown argument {argv[i]}")
    comms = comms or ["outstation"]
    tick = os.sysconf("SC_CLK_TCK")
    me = _netns_of("self")
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    timeline = []
    seen_primary = False
    # Highest CPU time seen per pid, so a process that exits between two
    # samples still counts with its last value.
    last_cpu = {}
    me_pid = str(os.getpid())
    while not stop:
        now = time.time()
        agg = {c: [0.0, 0, 0, 0] for c in comms}
        present = set()
        for d in os.listdir("/proc"):
            if not d.isdigit() or d == me_pid:
                continue
            try:
                with open(f"/proc/{d}/comm") as f:
                    comm = f.read().strip()
            except OSError:
                continue
            if comm not in agg or _netns_of(d) != me:
                continue
            s = _proc_sample(d, tick)
            if s is None:
                continue
            present.add(comm)
            last_cpu[(comm, d)] = s[0]
            a = agg[comm]
            a[1] += s[1]
            a[2] += s[2]
            a[3] += s[3]
        for (comm, _pid), cpu in last_cpu.items():
            agg[comm][0] += cpu
        timeline.append([round(now, 3), agg])
        if primary:
            if primary in present:
                seen_primary = True
            elif seen_primary:
                break
        time.sleep(interval)
    with open(out, "w") as f:
        json.dump({"interval": interval, "comms": comms, "timeline": timeline}, f)


# ---------------------------------------------------------------------------
# fast IEC 104 peers

STARTDT_ACT, STARTDT_CON = 0x07, 0x0B
STOPDT_ACT, STOPDT_CON = 0x13, 0x23
TESTFR_ACT, TESTFR_CON = 0x43, 0x83
U_REPLY = {STARTDT_ACT: STARTDT_CON, STOPDT_ACT: STOPDT_CON, TESTFR_ACT: TESTFR_CON}


def s_frame(vr):
    return bytes([0x68, 4, 0x01, 0x00, (vr << 1) & 0xFF, (vr >> 7) & 0xFF])


def u_frame(c1):
    return bytes([0x68, 4, c1, 0, 0, 0])


def fork_workers(n, fn):
    """Run fn(index) in n child processes; return the worst exit code."""
    pids = []
    for k in range(n):
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                code = fn(k) or 0
            finally:
                os._exit(code)
        pids.append(pid)

    def forward(sig, _frame):
        for p in pids:
            try:
                os.kill(p, sig)
            except OSError:
                pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    worst = 0
    for p in pids:
        while True:
            try:
                _, status = os.waitpid(p, 0)
                break
            except InterruptedError:
                continue
        worst = max(worst, os.waitstatus_to_exitcode(status) & 0xFF)
    return worst


def cmd_fast_slave(argv):
    ip, port = argv[0], int(argv[1])
    procs = int(argv[argv.index("--procs") + 1]) if "--procs" in argv else 4

    def worker(_k):
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        ls.bind((ip, port))
        ls.listen(1024)
        ls.setblocking(False)
        sel = selectors.DefaultSelector()
        sel.register(ls, selectors.EVENT_READ, None)
        state = {}  # conn -> [buf, vr]
        while True:
            for key, _ in sel.select():
                if key.data is None:
                    try:
                        c, _ = ls.accept()
                    except BlockingIOError:
                        continue
                    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    c.setblocking(True)
                    state[c] = [b"", 0]
                    sel.register(c, selectors.EVENT_READ, 1)
                    continue
                c = key.fileobj
                st = state[c]
                try:
                    data = c.recv(262144)
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(c)
                    c.close()
                    del state[c]
                    continue
                buf = st[0] + data if st[0] else data
                i, n, got_i, out = 0, len(buf), False, []
                bad = False
                while i + 2 <= n:
                    if buf[i] != 0x68:
                        bad = True
                        break
                    ln = buf[i + 1]
                    if i + 2 + ln > n:
                        break
                    c1 = buf[i + 2]
                    if c1 & 0x01 == 0:
                        st[1] = (st[1] + 1) & 0x7FFF
                        got_i = True
                    elif c1 & 0x03 == 0x03 and c1 in U_REPLY:
                        out.append(u_frame(U_REPLY[c1]))
                    i += 2 + ln
                st[0] = buf[i:]
                if got_i:
                    out.append(s_frame(st[1]))
                try:
                    if out:
                        c.sendall(b"".join(out))
                except OSError:
                    bad = True
                if bad:
                    sel.unregister(c)
                    c.close()
                    del state[c]

    print(f"fast IEC 104 slave on {ip}:{port} ({procs} processes)", flush=True)
    sys.exit(fork_workers(procs, worker))


def gi_asdu(ca):
    return bytes([100, 1, 6, 0]) + struct.pack("<H", ca) + bytes([0, 0, 0, 20])


def cmd_fast_master(argv):
    port, quiet, ctimeout, procs, ca_arg, t2 = 2404, 2.0, 60.0, 4, None, None
    ips = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--port":
            port = int(argv[i + 1])
            i += 2
        elif a == "--quiet":
            quiet = float(argv[i + 1])
            i += 2
        elif a == "--connect-timeout":
            ctimeout = float(argv[i + 1])
            i += 2
        elif a == "--procs":
            procs = int(argv[i + 1])
            i += 2
        elif a == "--ca":
            ca_arg = int(argv[i + 1])
            i += 2
        elif a == "--t2":
            t2 = float(argv[i + 1])
            i += 2
        else:
            ips.append(a)
            i += 1
    procs = max(1, min(procs, len(ips)))
    rfd, wfd = os.pipe()

    def worker(k):
        os.close(rfd)
        mine = ips[k::procs]
        deadline = time.monotonic() + ctimeout
        sel = selectors.DefaultSelector()
        results = {}
        conns = {}  # sock -> state dict
        pending = list(mine)  # IPs still to (re)connect
        retry_at = {}

        def start(ip):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                s.connect((ip, port))
            except BlockingIOError:
                pass
            except OSError as e:
                s.close()
                return e
            st = {"ip": ip, "up": False, "buf": b"", "vr": 0, "unacked": 0,
                  "ca": ca_arg, "con": False, "gi": False, "last": time.monotonic()}
            conns[s] = st
            sel.register(s, selectors.EVENT_WRITE, st)
            return None

        def finish(s, verdict):
            st = conns.pop(s)
            try:
                sel.unregister(s)
            except (KeyError, ValueError):
                pass
            s.close()
            results[st["ip"]] = verdict

        def connected(s, st):
            st["up"] = True
            st["last"] = time.monotonic()
            s.setblocking(True)
            s.sendall(u_frame(STARTDT_ACT))
            sel.modify(s, selectors.EVENT_READ, st)

        def retry(s, err):
            st = conns.pop(s)
            sel.unregister(s)
            s.close()
            if time.monotonic() > deadline:
                results[st["ip"]] = f"FAIL connect: {err}"
            else:
                retry_at[st["ip"]] = time.monotonic() + 0.2

        while len(results) < len(mine):
            now = time.monotonic()
            for ip in [ip for ip in pending]:
                pending.remove(ip)
                e = start(ip)
                if e is not None:
                    if time.monotonic() > deadline:
                        results[ip] = f"FAIL connect: {e}"
                    else:
                        retry_at[ip] = now + 0.2
            for ip, t in list(retry_at.items()):
                if t <= now:
                    del retry_at[ip]
                    pending.append(ip)
            for key, ev in sel.select(timeout=0.05):
                s, st = key.fileobj, key.data
                if not st["up"]:
                    err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if err:
                        retry(s, os.strerror(err))
                        continue
                    connected(s, st)
                    continue
                try:
                    data = s.recv(262144)
                except OSError as e:
                    finish(s, f"FAIL {e} after {st['vr']} I-frames")
                    continue
                if not data:
                    ok = st["con"] and st["vr"] > 0
                    finish(s, f"{'OK' if ok else 'FAIL'} startdt_con={st['con']} iframes={st['vr']}")
                    continue
                st["last"] = time.monotonic()
                buf = st["buf"] + data if st["buf"] else data
                i, n, out = 0, len(buf), []
                while i + 2 <= n:
                    if buf[i] != 0x68:
                        break
                    ln = buf[i + 1]
                    if i + 2 + ln > n:
                        break
                    c1 = buf[i + 2]
                    if c1 & 0x01 == 0:
                        st["vr"] = (st["vr"] + 1) & 0x7FFF
                        st["unacked"] += 1
                        if st["ca"] is None and ln >= 10:
                            st["ca"] = struct.unpack_from("<H", buf, i + 8)[0]
                    elif c1 == STARTDT_CON:
                        st["con"] = True
                    elif c1 == TESTFR_ACT:
                        out.append(u_frame(TESTFR_CON))
                    if st["con"] and not st["gi"] and (st["ca"] is not None or st["vr"] > 0):
                        # The GI's N(R) acknowledges everything so far.
                        g = gi_asdu(st["ca"] or 1)
                        out.append(bytes([0x68, 4 + len(g)]) + struct.pack("<HH", 0, st["vr"] << 1) + g)
                        st["unacked"] = 0
                        st["gi"] = True
                    i += 2 + ln
                st["buf"] = buf[i:]
                if st["unacked"] >= 8:
                    out.append(s_frame(st["vr"]))
                    st["unacked"] = 0
                if out:
                    try:
                        s.sendall(b"".join(out))
                    except OSError as e:
                        finish(s, f"FAIL {e} after {st['vr']} I-frames")
            now = time.monotonic()
            for s, st in list(conns.items()):
                if not st["up"]:
                    if now - st["last"] > 2.0:
                        # The handshake may have completed while this
                        # loop was busy: never drop a live connection.
                        try:
                            s.getpeername()
                        except OSError:
                            retry(s, "timed out")
                            continue
                        connected(s, st)
                    continue
                if t2 is not None and st["unacked"] and now - st["last"] >= t2:
                    try:
                        s.sendall(s_frame(st["vr"]))
                    except OSError:
                        pass
                    st["unacked"] = 0
                    continue
                if now - st["last"] >= quiet:
                    if st["unacked"]:
                        try:
                            s.sendall(s_frame(st["vr"]))
                        except OSError:
                            pass
                        st["unacked"] = 0
                        st["last"] = now
                        continue
                    ok = st["con"] and st["vr"] > 0
                    finish(s, f"{'OK' if ok else 'FAIL'} startdt_con={st['con']} iframes={st['vr']}")
        os.write(wfd, (json.dumps(results) + "\n").encode())
        return 0 if all(v.startswith("OK") for v in results.values()) else 1

    code = fork_workers(procs, worker)
    os.close(wfd)
    data = b""
    while True:
        chunk = os.read(rfd, 65536)
        if not chunk:
            break
        data += chunk
    results = {}
    for line in data.decode().splitlines():
        results.update(json.loads(line))
    ok = True
    for ip in ips:
        r = results.get(ip, "FAIL no result")
        ok = ok and r.startswith("OK")
        print(f"{ip}:{port} {r}", flush=True)
    sys.exit(0 if ok and code == 0 else 1)


# ---------------------------------------------------------------------------
# summaries


def _load(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _ts(line):
    """Epoch seconds of a tracing log line (RFC 3339 prefix), or None."""
    try:
        return datetime.datetime.fromisoformat(line.split(" ", 1)[0]).timestamp()
    except (ValueError, IndexError):
        return None


def _first(lines, needle):
    for line in lines:
        if needle in line:
            return _ts(line)
    return None


def _last(lines, needle):
    for line in reversed(lines):
        if needle in line:
            return _ts(line)
    return None


def _cpu_in(timeline, comm, t0, t1):
    """Mean CPU% of `comm` between t0 and t1 (100 = one core)."""
    pts = [(t, a[comm][0]) for t, a in timeline if comm in a]
    if not pts or t0 is None or t1 is None or t1 <= t0:
        return None
    before = [p for p in pts if p[0] <= t0] or pts[:1]
    after = [p for p in pts if p[0] >= t1] or pts[-1:]
    a, b = before[-1], after[0]
    if b[0] <= a[0]:
        return None
    return round(100.0 * (b[1] - a[1]) / (b[0] - a[0]), 1)


def _peak(timeline, comm, idx):
    vals = [a[comm][idx] for _, a in timeline if comm in a]
    return max(vals) if vals else None


def _peak_in(timeline, comm, idx, t0, t1, scale=1):
    if t0 is None or t1 is None:
        return None
    vals = [a[comm][idx] for t, a in timeline if comm in a and t0 <= t <= t1]
    return round(max(vals) * scale, 1) if vals else None


def _time_v(path):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                k, _, v = line.partition(": ")
                if k == "Maximum resident set size (kbytes)":
                    out["peak_rss_mb"] = round(int(v) / 1024, 1)
                elif k == "User time (seconds)":
                    out["user_s"] = float(v)
                elif k == "System time (seconds)":
                    out["sys_s"] = float(v)
                elif k.startswith("Elapsed (wall clock) time"):
                    parts = [float(x) for x in v.split(":")]
                    s = 0.0
                    for p in parts:
                        s = s * 60 + p
                    out["wall_s"] = s
    except OSError:
        pass
    return out


def cmd_summarize(argv):
    d = argv[0]
    meta = _load(os.path.join(d, "meta.json"), {})
    rep = _load(os.path.join(d, "report.json"), {}) or {}
    try:
        with open(os.path.join(d, "bench.log")) as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    tv = _time_v(os.path.join(d, "time.txt"))
    tool = _load(os.path.join(d, "sample-tool.json"), {}) or {}
    peer = _load(os.path.join(d, "sample-peer.json"), {}) or {}
    rate = _load(os.path.join(d, "rate.json"), {}) or {}
    run = rep.get("run") or {}
    b = run.get("benchmark") or {}
    an = rep.get("analysis") or {}
    role = meta.get("role")
    n = meta.get("sessions")

    t_start = _first(lines, "bench starting")
    if role == "master":
        t_ports0 = _first(lines, "benchmark: flows selected")
        t_ports1 = _first(lines, "capture started")
        t_traffic0 = _first(lines, "benchmark session starting")
        t_traffic1 = _last(lines, "benchmark session complete") or _last(lines, "capture stopped")
    else:
        t_ports0 = _first(lines, "listeners planned")
        t_ports1 = _last(lines, "slave: listening for master connect")
        t_traffic0 = _first(lines, "slave: listening for master connect")
        t_traffic1 = _last(lines, "slave session complete")
    t_cap_stop = _first(lines, "capture stopped")
    t_netctl_last = _last(lines, "netctl::")
    t_end = (tool.get("timeline") or [[None]])[-1][0]

    def dt(a, c):
        return round(c - a, 3) if a is not None and c is not None else None

    ports_s = dt(t_ports0, t_ports1)
    tl = tool.get("timeline") or []
    ptl = peer.get("timeline") or []
    peer_comm = (peer.get("comms") or ["python3"])[0]
    total = b.get("total_messages_sent")
    out = {
        "scenario": meta.get("scenario"),
        "role": role,
        "peer": meta.get("peer"),
        "sessions": n,
        "repeat": meta.get("repeat"),
        "exit_code": rep.get("exit_code"),
        "status": run.get("status"),
        "error": rep.get("error"),
        "sessions_failed": b.get("sessions_failed"),
        "msgs": total,
        "msgs_per_s": round(b["aggregate_throughput_msgs_per_sec"]) if b.get("aggregate_throughput_msgs_per_sec") else None,
        "active_msgs_per_s": rate.get("active_rate"),
        "peak_1s_msgs": rate.get("peak_1s_rate"),
        "p50_ms": (rep.get("latency") or {}).get("p50_ms"),
        "p99_ms": (rep.get("latency") or {}).get("p99_ms"),
        "max_ms": (rep.get("latency") or {}).get("max_ms"),
        "cpu_traffic_pct": _cpu_in(tl, "outstation", t_traffic0, t_traffic1),
        "cpu_total_s": round(tv.get("user_s", 0) + tv.get("sys_s", 0), 2) if tv else None,
        "user_s": tv.get("user_s"),
        "sys_s": tv.get("sys_s"),
        "wall_s": tv.get("wall_s"),
        "peak_rss_mb": tv.get("peak_rss_mb"),
        "traffic_rss_mb": _peak_in(tl, "outstation", 1, t_traffic0, t_traffic1, 1 / 1024),
        "peak_threads": _peak(tl, "outstation", 2),
        "peak_fds": _peak(tl, "outstation", 3),
        "setup_s": dt(t_start, t_traffic0) if role == "master" else dt(t_start, t_ports1),
        "ports_s": ports_s,
        "per_session_setup_ms": round(1000 * ports_s / n, 1) if ports_s and n else None,
        "traffic_s": dt(t_traffic0, t_traffic1),
        "teardown_s": dt(t_cap_stop, t_netctl_last) if role == "master" else max(0.0, dt(t_traffic1, t_netctl_last) or 0.0),
        "post_run_s": dt(t_cap_stop, t_end),
        "peer_cpu_traffic_pct": _cpu_in(ptl, peer_comm, t_traffic0, t_traffic1),
        "peer_procs": meta.get("peer_procs"),
        "peer_ok": meta.get("peer_ok"),
        "loadavg_before": meta.get("loadavg_before"),
        "captured_packets": b.get("captured_packets"),
        "captured_dropped": b.get("captured_dropped"),
        "verdict": an.get("verdict"),
        "score": an.get("score_pct"),
    }
    print(json.dumps(out))


COLS = [
    ("sessions", "N"),
    ("peer", "peer"),
    ("status", "status"),
    ("msgs", "I-frames"),
    ("msgs_per_s", "msgs/s (tool)"),
    ("active_msgs_per_s", "msgs/s (wire)"),
    ("peak_1s_msgs", "peak 1 s"),
    ("p50_ms", "p50 ms"),
    ("p99_ms", "p99 ms"),
    ("cpu_traffic_pct", "CPU % (traffic)"),
    ("cpu_total_s", "CPU s"),
    ("traffic_rss_mb", "RSS MB (traffic)"),
    ("peak_rss_mb", "peak RSS MB"),
    ("peak_threads", "threads"),
    ("peak_fds", "fds"),
    ("setup_s", "setup s"),
    ("per_session_setup_ms", "ms/session"),
    ("traffic_s", "traffic s"),
    ("teardown_s", "teardown s"),
    ("post_run_s", "after s"),
    ("peer_cpu_traffic_pct", "peer CPU %"),
    ("captured_dropped", "dropped"),
    ("verdict", "verdict"),
    ("score", "score"),
]


def _fmt(v):
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.1f}" if abs(v) < 1000 else f"{v:.0f}"
    return str(v)


def cmd_table(argv):
    rows = []
    for p in argv:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    head = ["scenario", "run"] + [c[1] for c in COLS]
    print("| " + " | ".join(head) + " |")
    print("|" + "---|" * len(head))
    groups = collections.OrderedDict()
    for r in rows:
        groups.setdefault((r["scenario"], r.get("peer"), r["sessions"]), []).append(r)
        print("| " + " | ".join([r["scenario"], str(r.get("repeat"))] + [_fmt(r.get(k)) for k, _ in COLS]) + " |")
    print()
    print("Median per scenario:")
    print()
    print("| " + " | ".join(["scenario", "runs"] + [c[1] for c in COLS]) + " |")
    print("|" + "---|" * (len(COLS) + 2))
    for (scen, _peer, _n), rs in groups.items():
        cells = []
        for k, _ in COLS:
            vals = [r.get(k) for r in rs if r.get(k) is not None]
            if vals and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
                cells.append(_fmt(statistics.median(vals)))
            elif vals:
                c = collections.Counter(str(v) for v in vals)
                cells.append("/".join(f"{k2}" + (f"×{n}" if n > 1 else "") for k2, n in c.most_common()))
            else:
                cells.append("-")
        print("| " + " | ".join([scen, str(len(rs))] + cells) + " |")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    cmd, argv = sys.argv[1], sys.argv[2:]
    fn = {
        "merge": cmd_merge,
        "sample": cmd_sample,
        "fast-slave": cmd_fast_slave,
        "fast-master": cmd_fast_master,
        "iframe-rate": cmd_iframe_rate,
        "summarize": cmd_summarize,
        "table": cmd_table,
    }.get(cmd)
    if fn is None:
        print(__doc__)
        sys.exit(2)
    fn(argv)


if __name__ == "__main__":
    main()
