# pcapreplay

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Linux](https://img.shields.io/badge/platform-linux-informational.svg)](#requirements)

A multi-source pcap replayer for Linux that turns captured network traces into real traffic on the wire. Built for benchmarking and regression-testing SCADA systems with real captured RTU traffic.

Driven entirely from a browser UI — upload a pcap, configure a run, press start, watch live progress and latency charts. No CLI workflow, no scripting. The browser owns the full loop.

---

## Table of contents

- [Why](#why)
- [What makes it different](#what-makes-it-different)
- [How it works](#how-it-works)
- [Features](#features)
- [Protocol support](#protocol-support)
- [Quick start](#quick-start)
- [Generating synthetic IEC 104 pcaps](#generating-synthetic-iec-104-pcaps)
- [Examples directory](#examples-directory)
- [Documentation](#documentation)
- [Crate layout](#crate-layout)
- [Requirements](#requirements)
- [Safety and scope](#safety-and-scope)
- [License](#license)

---

## Why

Running realistic traffic against a SCADA server is harder than it sounds. You can capture a pcap from production with traffic from 200 RTUs, but you can't just `tcpreplay` it — the target SCADA has a whitelist of real RTU IPs, it expects real TCP sessions, the captured flows need to be reassembled per-RTU and driven through the IEC 60870-5-104 state machine (STARTDT, k-window, I-frames, S-frame acks, TESTFR), and you need per-message latency measurements out the other end so you can tell whether the SCADA is handling the load.

pcapreplay does all of this from a single binary with a browser UI. It scales to ~200 RTUs / ~10 k messages per second on a single modest VM, and the whole thing is designed around letting you run it against a real SCADA test server **without changing anything inside the SCADA guest** (see [`doc/scada-lab.en.md`](doc/scada-lab.en.md)).

## What makes it different

Most pcap replay tools treat a capture as bytes to retransmit. pcapreplay treats a capture as *behaviour to impersonate*. `tcpreplay` streams L2 packets at an interface with optional address rewrite; `tcpliveplay` drives exactly one live TCP flow but has no application-layer knowledge; Scapy scripts and `bittwist` work one flow at a time and leave everything else to you. None of them can stand in for 200 RTUs, measure per-message latency under real load, or tell you after the fact whether the replay was faithful. This is the shape of the gap:

- **Protocol participant, not a packet blaster.** In benchmark mode pcapreplay opens a real TCP socket and runs a full IEC 60870-5-104 state machine — APCI framing, I/S/U frames, live N(S)/N(R) sequencing, k-window flow control, t1/t2/t3 timers, STARTDT/STOPDT, TESTFR keepalives, per-frame ACK tracking (`crates/proto_iec104/src/session.rs`). A live SCADA master or slave on the other end gets a real counterpart it can actually talk to, not a stream of stale packets with fresh checksums.
- **Many-to-one and one-to-many SCADA fan-out on a single host.** One run impersonates **200 RTUs to one master** (slave mode) or **200 masters to one SCADA server** (master mode), all on one host, all on standard port 2404, differentiated purely by IP. Slave mode auto-installs and auto-removes /32 IP aliases per listener; master mode builds per-session veth ports on a private bridge so 200 outgoing TCP clients cleanly bind to 200 distinct source addresses. Neither of these requires hand-rolled shell scripting to operate.
- **Built-in fidelity analysis.** After a run the analyser reopens the mirrored capture pcap from the wire and compares it flow-by-flow against the source pcap: how many I-frames were delivered, whether the type-ID sequence matches, how many frames are byte-identical, the drift in inter-frame timing, and a verdict / score (`crates/webui/src/analysis.rs`). No other replay tool I know of ships verification as a first-class feature — with `tcpreplay` you capture on the wire yourself and diff by hand if you care at all.
- **Timing-preserving pacing.** `Pacing::OriginalTiming { speed }` replays each I-frame at its original pcap-relative timestamp so the temporal shape of the telemetry feed is preserved — the natural pauses, the bursts, the outliers. A real 175-second IEC 104 session replays with ~20 ms total wall-clock drift and <1 ms mean inter-frame delta (see [`fidelity_report_run2.md`](fidelity_report_run2.md)). `AsFastAsPossible` is available when you want raw throughput instead. `tcpreplay`'s `--mbps` / `--multiplier` are packet-rate knobs, not protocol-frame-aware pacing — they can't keep a "pause 6 seconds, then burst 4 frames" shape.
- **Two-way: master *and* slave.** pcapreplay can impersonate either side of the conversation — test your substation RTUs, then swap and test the control centre's master — from the same UI, without changing tools. Most replay tools do one direction at best.
- **Per-session live observability.** Every RTU is a row in the UI with its own state (`pending` / `listening` / `connected` / `active` / `completed` / `failed` / `cancelled`), live send/receive counters, byte counts, and per-session stop. An ECharts hub-and-spoke diagram renders the active topology in real time with animated streams per direction and per-rate bucket. `START ALL` / `STOP` fan out across the whole run with one click.
- **Benchmark metrics, not "did it finish".** Per-session send→ack latency sampled into a bounded reservoir, rolled up to p50/p90/p99 histograms across the whole run; window-stall counts, unacked-at-end tallies, throughput in msg/s, per-session byte accounting. If you're load-testing a real SCADA server, the latency distribution is the thing that actually matters — and you get it without additional tooling.
- **Synthetic SCADA traffic generation.** `gen_iec104_traffic.py` produces standards-conformant IEC 104 pcaps at arbitrary scale — configurable RTU count, IP subnet, ASDU address space, points per RTU, inter-event cadence, sequential or random IP allocation. Useful when you want to stress-test against scenarios you don't have real captures for.
- **Safe for the host it runs on.** Every topology change is wrapped in RAII guards that restore on drop: bridge lifecycle, veth pairs, IP aliases, sysctls, iptables rules, NIC tx-checksum offload. A state file on disk lets aliases be reclaimed after a crash. A killed or panicked run does not leave your network in a weird state next boot.
- **Browser, not CLI.** Upload, configure, run, monitor, stop, abort, download the replay capture, read the fidelity report — all in one UI. No shell scripting, no per-RTU `ip addr add`, no bespoke glue. A pcap library, SQLite-backed run history, per-run delete, per-pcap viability analysis at upload time. Single binary `pcapreplay serve`, single systemd unit.

The one-line version: *every other pcap replay tool treats a capture as traffic to retransmit; pcapreplay treats a capture as behaviour to impersonate*, and ships the protocol stack, the per-flow fan-out, the live UI, and the post-run fidelity verification needed to back that up.

## How it works

```
                         ┌──────────────────────────────────────┐
       browser UI ───▶   │    webui crate  (axum + SPA)         │
   (upload pcap,         │    ─ pcap library                    │
    configure run,       │    ─ run config form                 │
    watch live)          │    ─ live diagram / latency charts   │
                         │    ─ SQLite run history              │
                         └────────────────┬─────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│              sched crate  (orchestrator + RunContext)           │
│                                                                 │
│   run()                      │     run_benchmark()              │
│   ─ raw replay path          │     ─ stateful session replay    │
│   ─ per-source veth worker   │     ─ per-RTU TCP client         │
│   ─ AF_PACKET injection      │     ─ IEC 104 windowed send loop │
│   ─ µs-accurate scheduler    │     ─ send→ack latency measured  │
└──────────┬──────────────────────────────┬──────────────────────┘
           │                              │
           ▼                              ▼
   ┌──────────────┐                ┌──────────────────┐
   │ raw_replay   │                │ proto_iec104     │
   │ + rewrite    │                │ (ProtoReplayer)  │
   │ + pcapload   │                │                  │
   └──────┬───────┘                └─────────┬────────┘
          │                                  │
          └──────────────┬───────────────────┘
                         ▼
                  ┌───────────────┐
                  │ netctl crate  │  bridge + veth lifecycle,
                  │               │  IP aliases, egress guard,
                  │               │  SCADA-gateway guard
                  └───────┬───────┘
                          │
                          ▼
                    Linux kernel
                 (AF_PACKET, veth, bridge, iptables)
```

Every run is reversible: the bridge, veth pairs, IP aliases, sysctl state, iptables rules, and tx-checksum NIC settings are all captured in RAII guards that restore on Drop. A crash-safe state file lets the server reclaim orphaned aliases on restart.

## Features

### Two replay modes

- **Raw replay** — per-source veth ports on an auto-managed Linux bridge, per-frame L2/L3 rewrite with checksum recompute, AF_PACKET injection at microsecond accuracy. For feeding IDS / logger / historian systems.
- **Stateful session replay (benchmark mode)**, with two roles:
  - **Master** — pcapreplay connects out as a TCP client of `target_ip:target_port`, one real session per captured RTU, driven by a protocol-aware replayer. Pipelined to the protocol's native k-window; per-message send→ack latency recorded via reservoir sampling and rendered as p50/p90/p99 histograms.
  - **Slave** — pcapreplay binds one listener per captured RTU on the RTU's own IP at `listen_port_base` (default 2404), auto-aliases the RTU IP onto the default-route interface, and waits for a live master to connect in. Works with external master tools like RedisAnt's `iec104client`.

### Slave-mode ergonomics

- Each listener is pre-populated with the RTU's captured IP as its `listen_ip`, so 200 sessions come up as 200 distinct `rtu_ip:2404` endpoints on one NIC without any manual config. Aliases are added before bind and removed on session end; a state file at `/var/lib/pcapreplay/state-aliases.txt` lets startup reclaim them after a crash.
- All listeners share the same port (no port shifting) — only the IP discriminates sessions. A real SCADA master can walk the RTU IP list with `:2404` everywhere instead of chasing 200 different ports.
- **START ALL** button in the run detail panel fans out the ready flag to every pending listener in one click. **STOP** on the run card fans out cancellation to all sessions in one click and flips them to `CANCELLED` so the UI doesn't keep showing stale `PENDING` rows.
- Each session reports its own state (`PENDING → LISTENING → CONNECTED → ACTIVE → COMPLETED / CANCELLED / FAILED`) with live send/receive counts, byte counts, and per-session abort.

### Post-run fidelity analysis

- The analyser (`crates/webui/src/analysis.rs`) re-opens the mirror capture from the run and compares it flow-by-flow against the source pcap: expected vs delivered I-frame counts, type-ID sequence agreement, byte-identical frame count, inter-frame timing drift (mean / p50 / p99), and a verdict (`good_delivery`, `partial_delivery`, `no_session`) with a score.
- Flow pairing is pinned on the captured session's server IP, so in a 200-RTU pcap the analyser always compares the right source flow against the right captured flow.
- A sample report produced end-to-end from a 200-RTU run is in [`fidelity_report_run2.md`](fidelity_report_run2.md).

### Networking

- Multi-RTU pcaps are dispatched one worker per source IP, each with its own veth port on a private Linux bridge. Source IPs and source MACs are preserved byte-identical to the capture; only the destination is rewritten.
- Automatic /32 alias management on a chosen egress NIC, with state-file-backed reclaim so a crashed process doesn't leak aliases across restarts.
- **SCADA-gateway mode** — pcapreplay can claim the SCADA test server's default-gateway IP on an isolated vSwitch, so off-subnet return traffic routes back to pcapreplay without changing anything inside the SCADA guest. Optional upstream NAT keeps SCADA's non-capture egress flowing out a second NIC. Walkthrough in [`doc/scada-lab.en.md`](doc/scada-lab.en.md).
- Egress safety guard disables `bridge-nf-call-iptables` and NIC TX checksum offload for the duration of a run, installs an `iptables raw PREROUTING DROP` rule so injected bytes never leak into the host's own stack, and reverts everything on run teardown.

### Runtime

- Single-binary `pcapreplay serve` that hosts the browser UI over axum.
- Live network diagram rendered with ECharts (vendored locally, no CDN) — animated streams with real rate, separate send/receive lanes, per-session bucketing, 200-stream cap.
- Live per-RTU progress bars, throughput sparkline, cooperative stop button.
- Post-run artifacts: downloadable replay pcap (the bytes that actually hit the wire), inter-frame gap histogram (original vs captured overlay), per-session latency histogram.
- SQLite-backed run history — all runs persisted across restarts, in-process runs marked failed on startup so the UI never shows phantom "running" rows, per-run delete endpoint and UI button.
- Pcap library: upload, rename, delete, per-pcap viability analysis at upload time.
- Scales to ~200 concurrent RTU sessions, ~10 k messages/sec aggregate, ~30–60 minute pcaps on commodity hardware.

## Protocol support

| Protocol | Crate | Status |
|---|---|---|
| IEC 60870-5-104 | `proto_iec104` | **shipped** — full k/w-window state machine, STARTDT/STOPDT/TESTFR, ASDU rewrite (common address / COT / IOA), send→ack latency |
| Modbus/TCP | `proto_modbus_tcp` | stub |
| DNP3 over TCP | `proto_dnp3_tcp` | stub |
| IEC 61850 MMS | `proto_iec61850_mms` | stub |
| IEC 60870-6 ICCP | `proto_iec60870_6_iccp` | stub |

New protocols plug in by implementing the `ProtoReplayer` trait in `crates/protoplay/src/lib.rs` — nothing in `sched`, `webui`, or the run pipeline is specific to IEC 104.

## Quick start

```sh
# Build
cargo build --release

# Run (needs CAP_NET_ADMIN + CAP_NET_RAW — use sudo or the systemd unit)
sudo ./target/release/pcapreplay serve --bind 0.0.0.0:8080

# Open the UI in a browser
xdg-open http://localhost:8080
```

For a production install, see [`systemd/install.sh`](systemd/install.sh) which sets up the unit, ambient capabilities, and directory layout (library at `/var/lib/pcapreplay/library`, captures at `/tmp/pcapreplay-captures`, SQLite history at `/var/lib/pcapreplay/runs.sqlite`).

### First run in 60 seconds

1. Open the UI. Go to **Pcap Library** and drop in a pcap or pcapng file.
2. Wait for the per-upload viability analysis to finish (packet count, RTU count, TCP flows).
3. Go to **Run Configuration**. Pick the pcap. Enter the target IP (and MAC for raw mode). Pick egress NIC.
4. Tick **benchmark mode**. Choose role (`master` = tool connects out, `slave` = tool listens). Choose pacing (`fast` for throughput tests, `original` for realism).
5. Optional: tick **act as scada gateway** and fill in the gateway IP + inner NIC (see [`doc/scada-lab.en.md`](doc/scada-lab.en.md)).
6. **START RUN**. Watch the live diagram, the per-RTU progress bars, the throughput sparkline, and the latency histogram.
7. When it's done, click **DETAILS** on the run card to see p50/p90/p99 latency, per-session breakdown, and download the replay capture.

## Generating synthetic IEC 104 pcaps

If you don't yet have a real capture to replay, or want to stress-test at a specific scale, use the traffic generator in [`examples/gen_iec104_traffic.py`](examples/gen_iec104_traffic.py). It produces standards-conformant IEC 60870-5-104 pcaps with one TCP conversation per RTU — master-initiated three-way handshake, TESTFR/STARTDT handshake, general interrogation → inrogen burst → ActTerm, then a spontaneous monitor stream with periodic S-frame acks and TESTFR keepalives, then STOPDT close. Zero-dependency: standard library Python 3 only.

### Minimal example

```sh
python3 examples/gen_iec104_traffic.py \
  --rtus 200 \
  --duration 180 \
  --subnet 192.168.10.0/24 \
  --rtu-start-offset 2 \
  --master-ip 192.168.86.1 \
  --mean-interval 1.5 \
  --seed 20260414 \
  -o synth_iec104_rtus200_lan10.pcap
```

That writes a ~2.8 MB pcap with 200 RTU listeners bound sequentially to `192.168.10.2..201:2404`, one external master at `192.168.86.1`, and ~180 s of simulated telemetry per RTU at a 1.5 s mean inter-event gap.

### Useful flags

| flag | default | meaning |
|---|---|---|
| `-n`, `--rtus` | `5` | number of synthetic RTUs to generate |
| `-d`, `--duration` | `120` | seconds of telemetry per RTU |
| `--master-ip` | `10.20.100.108` | SCADA master IP (TCP client side) |
| `--master-mac` | `02:00:5e:00:64:6c` | master L2 address |
| `--rtu-port` | `2404` | TCP port the RTUs listen on |
| `--subnet` | `10.20.102.0/24` | CIDR the RTU IPs are allocated from |
| `--rtu-start-offset` | `2` | lowest host offset inside `--subnet` (so `.1` stays free for a gateway) |
| `--mean-interval` | `3.0` | mean gap between spontaneous events per RTU, seconds |
| `--jitter` | `0.5` | fractional jitter on the inter-event distribution |
| `--points-per-rtu` | `12` | distinct IOAs each RTU reports |
| `--seed` | _random_ | deterministic PRNG seed for reproducible pcaps |
| `--start-time` | _now_ | epoch seconds for the first packet |
| `-o`, `--output` | _timestamped_ | output path (default: `synth_iec104_<UTC>_rtus<N>.pcap` in CWD) |

RTU IPs are allocated **sequentially** starting at `--rtu-start-offset`, skipping the master if it happens to fall in the same subnet. Each RTU gets its own random MAC, random ASDU common address (`1..65534`), and a sorted sample of `--points-per-rtu` random IOAs from `1..9999`. Spontaneous events are exponentially distributed around `--mean-interval` with uniform jitter, and each event is a single-point / double-point / short-float measurement drawn at weighted random.

### Typical workflow end-to-end

1. `python3 examples/gen_iec104_traffic.py -n 200 -d 180 --subnet 192.168.10.0/24 -o my_rtus.pcap`
2. Upload `my_rtus.pcap` to the pcapreplay library via the browser UI.
3. New run → `slave` role → `listen_port_base = 2404` → `protocol = iec104` → **START RUN**.
4. Click **START ALL** in the run detail panel to arm every listener.
5. Point your master tool at any RTU IP in `192.168.10.2..` on port 2404 (all 200 listen on the same port).
6. When the run ends, click **DOWNLOAD CAPTURE** on the run card, then re-upload the captured pcap to `POST /api/analyze?run_id=<id>` to get a JSON fidelity report.

See [`fidelity_report_run2.md`](fidelity_report_run2.md) for a human-readable version of one such report — 100 % byte-identical delivery, ~20 ms total drift over 175 seconds.

## Examples directory

Everything needed to reproduce a working 200-RTU replay lives under [`examples/`](examples/):

- [`examples/gen_iec104_traffic.py`](examples/gen_iec104_traffic.py) — the synthetic IEC 104 traffic generator described above.
- [`examples/synth_iec104_rtus200_lan10.pcap`](examples/synth_iec104_rtus200_lan10.pcap) — a 200-RTU pcap on `192.168.10.2..201` with one master at `192.168.86.1`, ~180 s duration, ~2.8 MB, suitable for slave-mode runs against an external IEC 104 master on any LAN where the RTU subnet is routable.

Upload the pcap directly in the browser UI to skip the generator step.

## Documentation

- [`doc/scada-lab.en.md`](doc/scada-lab.en.md) — SCADA engineer's guide (English). Lab topology, step-by-step VMware/Proxmox/libvirt setup, SCADA-gateway mode walkthrough, result reading, troubleshooting.
- [`doc/scada-lab.md`](doc/scada-lab.md) — same guide in Norwegian.

## Crate layout

```
pcapreplay/
├── Cargo.toml                     workspace root, resolver = 2
├── crates/
│   ├── netctl/                    bridge + veth lifecycle, IP aliases,
│   │                              egress safety guard, SCADA-gateway guard
│   ├── pcapload/                  pcap + pcapng parsers, source/flow
│   │                              indexing, TCP reassembly
│   ├── rewrite/                   in-place L2/L3/L4 header rewrite
│   ├── raw_replay/                AF_PACKET sender with µs scheduling
│   ├── sched/                     orchestrator: run() and run_benchmark()
│   ├── tcp_session/               generic TCP client replayer
│   ├── protoplay/                 ProtoReplayer trait + shared types
│   ├── proto_iec104/              IEC 60870-5-104 windowed replayer
│   ├── proto_modbus_tcp/          stub
│   ├── proto_dnp3_tcp/             stub
│   ├── proto_iec61850_mms/        stub
│   ├── proto_iec60870_6_iccp/     stub
│   ├── pcapreplay/                thin binary shell for `serve`
│   └── webui/                     axum server, embedded SPA, SQLite history
├── doc/                           end-user guides (EN + NO)
├── examples/                      synthetic traffic generator + sample pcap
└── systemd/                       pcapreplay.service + install.sh
```

## Requirements

- Linux 5.10+ with `veth`, `AF_PACKET`, and `bridge-nf` available.
- Root or `CAP_NET_ADMIN + CAP_NET_RAW` ambient capabilities.
- Rust 1.75+ (stable).
- `iproute2` (`ip` command), `iptables`, `ethtool` in `$PATH`.

## Safety and scope

This is a security / reliability testing tool. It actively injects spoofed traffic onto the wire. **Only use it against systems you own or have explicit authorization to test.**

The egress safety guard minimizes accidental leakage onto production networks (bridge-nf disabled, tx-checksum offload off, iptables raw-PREROUTING drop rule installed), but it is not a substitute for running in an isolated lab. The recommended deployment is the dedicated virtual lab described in [`doc/scada-lab.en.md`](doc/scada-lab.en.md), with both the replay box and the device under test on an isolated vSwitch.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([`LICENSE-MIT`](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
