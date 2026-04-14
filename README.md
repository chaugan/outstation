# pcapreplay

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Linux](https://img.shields.io/badge/platform-linux-informational.svg)](#requirements)

A multi-source pcap replayer for Linux that turns captured network traces into real traffic on the wire. Built for benchmarking and regression-testing SCADA systems with real captured RTU traffic.

Driven entirely from a browser UI — upload a pcap, configure a run, press start, watch live progress and latency charts. No CLI workflow, no scripting. The browser owns the full loop.

---

## Table of contents

- [Why](#why)
- [How it works](#how-it-works)
- [Features](#features)
- [Protocol support](#protocol-support)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Crate layout](#crate-layout)
- [Requirements](#requirements)
- [Safety and scope](#safety-and-scope)
- [License](#license)

---

## Why

Running realistic traffic against a SCADA server is harder than it sounds. You can capture a pcap from production with traffic from 200 RTUs, but you can't just `tcpreplay` it — the target SCADA has a whitelist of real RTU IPs, it expects real TCP sessions, the captured flows need to be reassembled per-RTU and driven through the IEC 60870-5-104 state machine (STARTDT, k-window, I-frames, S-frame acks, TESTFR), and you need per-message latency measurements out the other end so you can tell whether the SCADA is handling the load.

pcapreplay does all of this from a single binary with a browser UI. It scales to ~200 RTUs / ~10 k messages per second on a single modest VM, and the whole thing is designed around letting you run it against a real SCADA test server **without changing anything inside the SCADA guest** (see [`doc/scada-lab.en.md`](doc/scada-lab.en.md)).

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
- **Stateful session replay (benchmark mode)** — one real TCP client session per captured RTU against a live target, driven by a protocol-aware replayer. Pipelined to the protocol's native k-window; per-message send→ack latency recorded via reservoir sampling and rendered as p50/p90/p99 histograms.

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
