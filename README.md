# pcapreplay

A multi-source pcap replayer for Linux that turns captured network traces into real traffic on the wire. Built for benchmarking and regression-testing SCADA systems with real captured RTU traffic.

Driven entirely from a browser UI — upload a pcap, configure a run, press start, watch live progress and latency charts. No CLI workflow required.

## Features

### Two replay modes

- **Raw replay** — per-source veth ports on an auto-managed Linux bridge, per-frame L2/L3 rewrite with checksum recompute, AF_PACKET injection at microsecond accuracy. Used for feeding IDS / logger / historian systems.
- **Stateful session replay (benchmark mode)** — one real TCP client session per captured RTU against a live target, driven by a protocol-aware replayer. First protocol implemented: **IEC 60870-5-104**. Pipelined to the protocol's native k-window; per-message send→ack latency recorded as reservoir samples and rendered as p50/p90/p99 histograms.

### Networking

- Multi-RTU pcaps are dispatched to one worker per source IP, each with its own veth port on the bridge. Source IPs and source MACs are preserved byte-identical to the capture.
- Automatic /32 alias management on a chosen egress NIC, with state-file-backed reclaim so a crashed process doesn't leak aliases across restarts.
- **SCADA-gateway mode** — pcapreplay can claim SCADA's default-gateway IP on an isolated vSwitch, so off-subnet traffic from a SCADA test server routes back to pcapreplay without changing anything inside the SCADA guest. Optional upstream NAT keeps SCADA's non-capture egress flowing out a second NIC. See [`doc/scada-lab.en.md`](doc/scada-lab.en.md).
- Egress safety guard disables `bridge-nf-call-iptables` and NIC TX checksum offload for the duration of a run, installs an `iptables raw PREROUTING DROP` rule so injected bytes never leak into the host's own stack, and reverts everything on run teardown.

### Runtime

- Single-binary `pcapreplay serve` that hosts the browser UI over axum.
- Live network diagram rendered with ECharts (vendored locally, no CDN) — animated streams with real rate, separate send/receive lanes, per-session bucketing, 200-stream cap.
- Live per-RTU progress bars, throughput sparkline, cooperative stop button.
- Post-run artifacts: downloadable replay pcap, inter-frame gap histogram (original vs captured), per-session latency histogram.
- SQLite-backed run history — all runs persisted across restarts; in-process runs marked failed on startup so the UI never shows phantom "running" rows; per-run delete endpoint and UI button.
- Pcap library: upload, rename, delete, per-pcap viability analysis at upload time.

## Quick start

```sh
# Build
cargo build --release

# Run (needs CAP_NET_ADMIN + CAP_NET_RAW — use sudo or the systemd unit)
sudo ./target/release/pcapreplay serve --bind 0.0.0.0:8080

# Then open the UI
$BROWSER http://localhost:8080
```

For a production install, see [`systemd/install.sh`](systemd/install.sh) which sets up the unit, ambient capabilities, and directory layout.

## Documentation

- [`doc/scada-lab.en.md`](doc/scada-lab.en.md) — SCADA engineer's guide (English). Lab topology, step-by-step VMware/Proxmox/libvirt setup, SCADA-gateway mode walkthrough, result reading, troubleshooting.
- [`doc/scada-lab.md`](doc/scada-lab.md) — same guide in Norwegian.
- [`HANDOVER/HANDOVER.md`](HANDOVER/HANDOVER.md) — 5-minute orientation brief for contributors.
- [`HANDOVER/PLAN.md`](HANDOVER/PLAN.md) — full architecture and design notes.

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
│   ├── proto_dnp3_tcp/            stub
│   ├── proto_iec61850_mms/        stub
│   ├── proto_iec60870_6_iccp/     stub
│   ├── pcapreplay/                thin binary shell for `serve`
│   └── webui/                     axum server, embedded SPA, SQLite history
├── doc/                           end-user guides
├── HANDOVER/                      contributor docs
└── systemd/                       pcapreplay.service + install.sh
```

## Requirements

- Linux 5.10+ (veth, AF_PACKET, bridge-nf).
- Root or `CAP_NET_ADMIN + CAP_NET_RAW` ambient capabilities.
- Rust 1.75+ (stable).
- `iproute2` (`ip` command), `iptables`, `ethtool` in `$PATH`.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

## Safety and scope

This is a security-testing tool. Only use it against systems you own or have explicit authorization to test. It actively injects spoofed traffic onto the wire; the egress safety guard minimizes accidental leakage onto production networks, but it is not a substitute for running in an isolated lab.
