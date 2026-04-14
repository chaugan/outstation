# pcapreplay — SCADA engineer's guide

*How to run a realistic replay of IEC 60870-5-104 traffic against a SCADA server in a virtual test lab, without touching the SCADA server itself.*

---

## Contents

1. [What the tool is](#1-what-the-tool-is)
2. [What it does in practice](#2-what-it-does-in-practice)
3. [The networking problem — why replay is hard](#3-the-networking-problem)
4. [Recommended lab topology](#4-recommended-lab-topology)
5. [Step by step: lab setup](#5-step-by-step-lab-setup)
6. [Step by step: running a replay](#6-running-a-replay)
7. [Reading the results](#7-reading-the-results)
8. [Troubleshooting](#8-troubleshooting)
9. [Glossary](#9-glossary)

---

## 1. What the tool is

**pcapreplay** is a tool for replaying captured network traffic — typically IEC 60870-5-104 from real RTUs — against a test target, in a way that lets you:

- **Benchmark** a SCADA server by unleashing a realistic number of RTU sessions against it simultaneously, measuring latency, throughput, and whether any messages are lost.
- **Regression-test** a SCADA upgrade by replaying the same traffic before and after, then comparing the response.
- **Simulate load** — for example 200 RTUs each sending 50 messages per second — from a single Linux VM.
- **Feed IDS / logger / historian systems** with realistic traffic without needing the physical RTUs in the loop.

The tool is driven entirely from a browser UI (`http://<replay-vm>:8080`). There is no CLI workflow — you upload pcap files, configure a run, press start, and watch the results in the same UI.

### Two replay modes

| Mode | What happens | Use case |
|---|---|---|
| **Raw replay** | Packets from the pcap are injected raw via AF_PACKET, source addresses preserved, destination rewritten to your target. No TCP state, no acks. | Feeding IDSes, wire-tap analysis, logger regression. |
| **Benchmark / stateful session replay** | The tool opens a real TCP session per RTU in the pcap, drives a protocol-aware replay (IEC 104), waits for acks, and measures latency. | Load-testing a SCADA server, session regression, response timing. |

This guide focuses on benchmark mode against a SCADA server, because that's where a SCADA engineer typically needs it.

---

## 2. What it does in practice

Say you have a pcap captured from production, with traffic from 200 RTUs all talking to a SCADA master over IEC 60870-5-104. The pcap is 3 GB and covers one hour.

You point pcapreplay at a SCADA test system, pick "benchmark" mode, and hit start. Here's what happens:

1. **Pcap analysis.** The tool reads the file, identifies all TCP flows, groups packets per source IP (per RTU), and extracts the IEC 104 messages.
2. **Session setup.** For each RTU in the pcap, the tool creates a TCP socket bound to that RTU's original source IP (via automatic IP aliases on a local interface) and connects to the SCADA test server on port 2404.
3. **IEC 104 handshake.** Each session sends `STARTDT act` and waits for `STARTDT con` back from SCADA. The k-window is negotiated (defaults: `k=12`, `w=8`).
4. **Message flow.** Each session streams its I-frames against SCADA at the configured pace (as-fast-as-possible or original pcap timing), waits for S-frame acks, measures send→ack latency per message.
5. **Live reporting.** The browser UI shows a live network diagram with animated packet streams (real direction and rate), per-RTU progress bars, throughput in packets per second, and an incrementally-updated latency histogram.
6. **Shutdown.** When all sessions finish, the report is persisted to a SQLite database, everything actually sent on the wire is saved as a replay pcap (downloadable for verification), and you see aggregate statistics: p50/p90/p99 latency, messages sent/received, errors, per-session details.

---

## 3. The networking problem

This is probably the most important part to understand.

### The problem

Your pcap contains traffic from 200 RTUs spread across many different subnets — e.g. `192.168.10.0/24`, `172.16.5.0/24`, `10.50.0.0/16`, and so on. These IPs are the *real* production RTU addresses.

The SCADA test server likely has a whitelist: it only accepts connections from source addresses it knows — which are the same RTU addresses it sees in production.

So far, so good: pcapreplay sends packets with the real source IPs, SCADA accepts them because the whitelist matches, the TCP SYN lands.

**But** — SCADA has to reply to the SYN. SCADA's kernel looks in its routing table: *"where do I send packets destined for 192.168.10.42?"* If SCADA sits on `10.0.0.0/24`, it has no directly-connected route to `192.168.10.0/24`. It forwards the reply to its default gateway. The default gateway has no route either. The reply is dropped.

The TCP handshake never completes. No IEC 104 session is established. The benchmark fails before it starts.

### Why "just configure it on SCADA" doesn't fly

The obvious fix — *"just add static routes on SCADA pointing the RTU subnets back at pcapreplay"* — isn't always acceptable:

- The SCADA server may be a near-production test system that must remain "untouched".
- You don't have root on SCADA.
- Any change has to be documented, approved, and rolled back — overhead.
- The test is supposed to be **non-invasive**: SCADA should behave exactly the way it does in production.

We need a solution where we manipulate **SCADA's network environment**, not SCADA itself.

### The solution: isolated virtual switch

If both pcapreplay and SCADA run as virtual machines — which they do in this setup — we can put them both on an **isolated virtual switch** where pcapreplay is the only L2 neighbor SCADA can see.

Then the following happens automatically:

1. SCADA tries to send a TCP SYN-ACK to `192.168.10.42`.
2. Its routing table says: "off-subnet, send via default gateway `10.0.0.1`."
3. SCADA issues an ARP: *"who has `10.0.0.1`?"*.
4. On an isolated switch, pcapreplay is the only thing that hears the ARP. Pcapreplay has `10.0.0.1` installed as a local /32 alias on its inner NIC and replies: *"I do."*
5. SCADA sends the SYN-ACK to pcapreplay's MAC.
6. Pcapreplay's kernel accepts the frame, and because `192.168.10.42` is also a local alias, the kernel routes the packet up to user space where the benchmark session bound to `192.168.10.42:0` is waiting. The handshake completes.

SCADA **has not been reconfigured**. It still thinks it's talking to its default gateway. The whitelist still matches because we never touched the source IP. Everything inside the guest is identical to production — *except* that the physical layer has been shifted to an isolated virtual switch.

---

## 4. Recommended lab topology

### Topology

```
┌─────────────────────┐        ┌──────────────────────────┐
│                     │        │                          │
│    SCADA (VM)       │        │     pcapreplay (VM)      │
│                     │        │                          │
│   eth0              │        │  eth0 (inner)            │
│   10.0.0.50/24      ├────────┤  10.0.0.1/24   (*)       │
│   gw: 10.0.0.1      │        │  + 192.168.10.0/24 alias │
│                     │        │  + 172.16.5.0/24 alias   │
│                     │        │  + ...                   │
│                     │        │                          │
└─────────────────────┘        │  eth1 (outer)            │
                               │  10.20.30.40/24          │
          isolated vSwitch     │  gw: 10.20.30.1          │
          "vswitch_test"       └───────────┬──────────────┘
                                           │
                                           │
                                   real lab network
                                   (internet, admin, NTP,
                                    updates for SCADA)
```

(*) `10.0.0.1` is an example — it should be the same IP SCADA already has configured as its default gateway. We use the IP SCADA *already thinks* is the gateway; we don't create any new SCADA-side configuration.

### Components

- **SCADA VM**: your existing SCADA test server. No changes. Just moved onto the new isolated switch.
- **pcapreplay VM**: a clean Ubuntu / Debian / RHEL install with the `pcapreplay` binary and two vNICs.
- **Isolated virtual switch** (called `vswitch_test` here): on VMware ESXi, a port group without an uplink; in vSphere, a "private" vSwitch; in Proxmox, a Linux Bridge with no physical interface; in VirtualBox, an "Internal Network"; in libvirt/KVM, `<forward mode='none'/>`.

### Why two vNICs on pcapreplay?

- **eth0 (inner)**: the only link to SCADA. This is where every RTU alias and the gateway alias live.
- **eth1 (outer)**: the pcapreplay VM itself needs real-lab access for admin/SSH/updates. Optionally, eth1 is also used as a NAT egress so SCADA can still reach the real world (NTP, updates) via pcapreplay. This is optional — if SCADA should be fully isolated during the test, you can skip eth1.

---

## 5. Step by step: lab setup

You do this once per test lab. After that, it's just pcap upload and button clicks in the UI.

### 5.1 Create the isolated switch

**VMware vSphere / ESXi:**

1. *Host → Networking → Virtual switches → Add standard virtual switch*.
2. Name it `vswitch_test`.
3. **Do not attach a physical uplink.** This switch must not be connected to any NIC.
4. *Port groups → Add port group*, name it `pg_scada_test`, uplink `vswitch_test`.
5. Leave VLAN ID at 0.

**Proxmox VE:**

1. *Datacenter → Node → Network → Create → Linux Bridge*, name it `vmbr_test`.
2. Leave "Bridge ports" empty.
3. Do not assign an IP.

**libvirt / virt-manager:**

```xml
<network>
  <name>isolated-test</name>
  <forward mode='none'/>
  <bridge name='virbr-test' stp='on'/>
</network>
```

Load with `sudo virsh net-define isolated.xml && sudo virsh net-start isolated-test && sudo virsh net-autostart isolated-test`.

### 5.2 Move the SCADA VM onto the new switch

1. Shut down the SCADA VM, or — if supported — hot-swap the vNIC.
2. In the VM settings: change the network adapter from the current switch to `pg_scada_test` / `vmbr_test` / `isolated-test`.
3. Do not change anything inside the SCADA guest. IP address, netmask, default gateway, DNS — all unchanged.
4. Start SCADA again.

Important: after the move SCADA will have no connectivity until the pcapreplay VM is also attached to the same isolated switch. This is expected.

### 5.3 Create the pcapreplay VM

1. Create a new VM with 4 vCPU, 8 GB RAM (for 200 RTUs), 40 GB disk.
2. Install Ubuntu Server 22.04 LTS or similar.
3. Add **two** vNICs:
   - `eth0` → **`vswitch_test` / `pg_scada_test`** (inner — faces SCADA).
   - `eth1` → your normal lab switch (outer — faces the real world).
4. Set a static IP on `eth0`. Use **the same IP SCADA already has configured as its default gateway** — e.g. `10.0.0.1/24`. Do not set a gateway on this NIC.
5. Set an IP on `eth1` that fits the real lab network, and set the default gateway there.
6. Install pcapreplay and the systemd unit (see `systemd/install.sh` in the repo).

Verify by pinging SCADA from pcapreplay: `ping 10.0.0.50`. If it answers, the physical layer is good.

### 5.4 Open the web UI

From your workstation, open `http://<pcapreplay-eth1-ip>:8080` in a browser. You should see sections for "Pcap Library", "Run Configuration", "Runs", and "Network Diagram".

---

## 6. Running a replay

### 6.1 Upload the pcap

1. Go to the **Pcap Library** section.
2. Drag-and-drop your pcap or pcapng file into the upload area.
3. Wait for analysis to finish — you'll see packet count, RTU count, TCP flows, duration, and a "viability" verdict indicating whether the pcap is suitable for benchmark mode.

### 6.2 Configure the run

In the **Run Configuration** section:

1. **Pick pcap**: click the pcap you just uploaded.
2. **Target IP**: the SCADA test server's IP, e.g. `10.0.0.50`.
3. **Target port**: `2404` for IEC 104 (default).
4. **Egress NIC**: select `eth0` (the inner NIC, facing SCADA). This is where AF_PACKET injection and TCP sessions go out.
5. **Flags** → tick **"benchmark mode"**.
6. **Role**: "target is server · tool connects out as master" (default).
7. **Protocol**: `iec104`.
8. **Pacing**: pick "as fast as possible" for max load, or "original pcap timing" for realism.
9. **Iterations**: how many times to run the script. `1` for a single pass, `0` for an infinite loop.

### 6.3 Enable SCADA-gateway mode

This is the new, critical step:

1. Tick **"act as scada gateway"** at the bottom of the benchmark panel.
2. **SCADA-side gateway IP**: the IP SCADA has as its default gateway — in our example `10.0.0.1`. This is the IP pcapreplay will install as a /32 alias for the duration of the run.
3. **Inner NIC**: pick `eth0` (same as the egress NIC — the one that faces SCADA).
4. **Upstream NAT NIC** *(optional)*: pick `eth1` if SCADA should keep its real-world access (updates, NTP, admin) during the test. pcapreplay will then enable IP forwarding and add a MASQUERADE rule on `eth1`. Leave empty if SCADA should be fully isolated during the test.

### 6.4 Start

Press **START RUN**. What happens under the hood:

1. pcapreplay adds `10.0.0.1/32` as an alias on `eth0`.
2. IP forwarding is enabled (if NAT was chosen).
3. A MASQUERADE rule is inserted: `iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE`.
4. For each RTU in the pcap, that RTU's IP is added as a /32 alias on `eth0` via the existing auto-alias machinery.
5. The `pcr_br0` bridge is created, veth interfaces per source are set up.
6. Sessions connect to SCADA one at a time (or in parallel, depending on concurrency setting).
7. SCADA answers ARPs for `10.0.0.1` (via us) and for the RTU IPs (also via us, directly on L2 — though this isn't strictly needed since traffic flows via default gateway).
8. Sessions stream I-frames, measure latency, log to SQLite.

The UI shows a live network diagram with animated packet streams, per-RTU progress bars, and latency sparkline.

### 6.5 When the run finishes

pcapreplay cleans everything up automatically:

- The /32 alias on `eth0` is removed.
- IP forwarding is restored to its previous value.
- The MASQUERADE rule is deleted.
- The veth interfaces and `pcr_br0` bridge are torn down.
- All changes are reversible.

If the pcapreplay process crashes mid-run, the aliases and MASQUERADE rule are left behind. On the next startup pcapreplay reads the state file at `/var/lib/pcapreplay/state-aliases.txt` and removes orphaned aliases automatically. You'll see a warning in the log: *"reclaimed N orphaned ip alias(es) from a previous run"*.

---

## 7. Reading the results

When a run finishes you see a "Run card" in the **RUNS** section. Click **DETAILS** to expand it.

### Aggregate numbers

- **Total messages sent / received**: should match the I-frame count in the pcap (sent) and what SCADA acknowledged (received).
- **Aggregate latency p50/p90/p99/max**: send→ack time per message, aggregated across all RTUs. This is the single most important number for SCADA benchmarking.
- **Aggregate throughput (msgs/sec)**: sum of all sessions' messages per second.

### Per-session details

One row per RTU, with:

- **connected**: whether the TCP handshake actually completed — your first sanity check.
- **messages sent / received / bytes**
- **latency p50/p90/p99/max**: per-session latency.
- **window stalls**: how many times the session had to wait for a `w`-ack from SCADA because the k-window was full. A high number means SCADA is falling behind on acking.
- **unacked at end**: messages that were sent but didn't get acked before the session closed. Should be 0.
- **error**: if the session failed, the error message lives here.

### Captured pcap

pcapreplay records everything it actually sent on the wire during the run to `/tmp/pcapreplay-captures/run_<id>.pcap`. You can download it via the **DOWNLOAD CAPTURE** button and open it in Wireshark to verify that what went out matches your expectations.

### Timing comparison

Under **DETAILS** there's also a histogram comparison of inter-frame gaps in the original pcap vs what was actually sent. This lets you judge how accurate the pacing was. Typical delta: millisecond-level on the p99 tail, which is normal for userspace scheduling on Linux.

### SQLite persistence

Every run is stored in `/var/lib/pcapreplay/runs.sqlite`. After a server restart all historical runs are still there with their reports intact, and you can delete individual runs via the **DELETE** button on each run card.

---

## 8. Troubleshooting

### SCADA can't reach pcapreplay

From the pcapreplay VM:

```sh
ping 10.0.0.50                       # SCADA's IP
ip addr show eth0                    # should show 10.0.0.1/24
ip neigh | grep 10.0.0.50            # should show SCADA's MAC
```

If the ping fails, double-check that both VMs are actually on the same isolated switch in the hypervisor.

### The TCP session never establishes

In the per-session row, `connected` stays `false` after 10 seconds.

- **Verify the gateway alias is installed**: `ip addr show eth0 | grep "10.0.0.1"`. Should be there during the run.
- **Verify the RTU IP alias is installed**: `ip addr show eth0 | grep "192.168.10.42"` (or whichever RTU you're testing).
- **Check that SCADA actually has `10.0.0.1` as its default gateway**: `ip route` on SCADA — even though we don't change anything on SCADA, it's fine to read its config.
- **Check that the source IP matches SCADA's whitelist**. This is the most common problem: you're using a pcap from a different environment, and the SCADA test server doesn't accept those source IPs.

### pcapreplay's own kernel sends TCP RSTs

If in Wireshark (on the pcapreplay side) you see the pcapreplay kernel replying with RST to SYN-ACKs from SCADA, the RTU IP isn't installed as a local alias and the kernel doesn't know it's a "local" address. This only happens if the pre-emptive auto-alias machinery failed. Check `/var/log/syslog` for errors from `netctl::add_ip_alias`.

### SCADA loses all internet access

You forgot to tick "upstream NAT NIC". SCADA is stranded with only pcapreplay as its neighbor and can't reach anything beyond it. Either enable NAT mode on the next run, or accept that SCADA is isolated during the test (often the best choice anyway).

### The run hangs on warmup

Benchmark mode has an optional warmup interval (default 0 seconds). If you set a high value, it's expected that sessions won't start sending until warmup is done. Warmup exists so you can attach Wireshark / tcpdump to `eth0` before the traffic begins.

### pcapreplay crashed and left aliases behind

Restart pcapreplay: `sudo systemctl restart pcapreplay` (or manually restart the binary). It cleans up on startup and logs `reclaimed N orphaned ip alias(es)`.

To clean up by hand:

```sh
sudo cat /var/lib/pcapreplay/state-aliases.txt
sudo ip addr del 10.0.0.1/32 dev eth0
sudo iptables -t nat -D POSTROUTING -o eth1 -j MASQUERADE
sudo sysctl net.ipv4.ip_forward=0
```

---

## 9. Glossary

| Term | Meaning |
|---|---|
| **IEC 60870-5-104** | Standard for SCADA communication, TCP-based, port 2404. Carries I/S/U frames, flow-controlled via a sliding k-window. |
| **I-frame** | "Information frame" — the actual payload carrying ASDU data (measurements, commands, events). |
| **S-frame** | "Supervisory frame" — ack frame confirming receipt of N I-frames. |
| **U-frame** | "Unnumbered frame" — control frames (STARTDT, STOPDT, TESTFR). |
| **k-window** | Maximum number of unacked I-frames a sender is allowed to have outstanding. Default k=12. |
| **w-window** | Receiver must send an S-frame ack at the latest after w received I-frames. Default w=8. |
| **ASDU** | "Application Service Data Unit" — the content of an I-frame: type ID, COT (cause of transmission), common address, IOA (information object address), values. |
| **RTU** | "Remote Terminal Unit" — a field station that reports to SCADA. In this lab each RTU is represented by one TCP session from pcapreplay. |
| **SCADA master** | The system that collects data from RTUs. When we run benchmark in "master" role, pcapreplay is the client and SCADA is the server. |
| **pcap / pcapng** | Packet capture formats. pcapreplay supports both. |
| **AF_PACKET** | Linux mechanism for sending/receiving raw Ethernet frames directly, bypassing the TCP/IP stack. Used by pcapreplay for raw replay mode. |
| **MASQUERADE** | iptables NAT rule that rewrites the source address to the egress NIC's address. Used here to give SCADA upstream access. |
| **Isolated vSwitch** | A virtual switch with no physical uplink. Only VMs attached to the same switch can talk to each other. |
| **/32 alias** | An IP address added to a NIC with a /32 netmask, meaning "only this single address, no subnet route". Used to park the gateway IP and RTU IPs on `eth0` without affecting the routing table. |

---

## Contact and resources

- Project README: [`README.md`](../README.md) at the repo root.
- Protocol code: `crates/proto_iec104/`.
- SCADA-gateway implementation: `crates/netctl/src/lib.rs` (search for `GatewayGuard`).

Happy testing.
