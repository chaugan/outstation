# outstation: SCADA engineer's guide

*How to test a SCADA master, an RTU or a front end with replayed IEC 60870-5-104 traffic in a virtual lab, without changing anything inside the system under test.*

The Norwegian version is [scada-lab.md](scada-lab.md). This English version is the reference; the Norwegian one follows it.

---

## Contents

1. [What the tool does](#1-what-the-tool-does)
2. [Pick your scenario](#2-pick-your-scenario)
3. [Lab topology](#3-lab-topology)
4. [Gateway mode: when the SCADA master is on another subnet](#4-gateway-mode-when-the-scada-master-is-on-another-subnet)
5. [Scenario A: testing a SCADA master](#5-scenario-a-testing-a-scada-master)
6. [Scenario B: testing an RTU or a server](#6-scenario-b-testing-an-rtu-or-a-server)
7. [Lab setup step by step](#7-lab-setup-step-by-step)
8. [Reading the results](#8-reading-the-results)
9. [Repeatable tests: profiles, re-runs, compare, CI](#9-repeatable-tests-profiles-re-runs-compare-ci)
10. [Cleanup and safety](#10-cleanup-and-safety)
11. [Troubleshooting](#11-troubleshooting)
12. [Glossary](#12-glossary)

---

## 1. What the tool does

**outstation** takes a capture (pcap or pcapng) of real IEC 60870-5-104 traffic and plays one side of it live against the system you want to test:

- **It plays the RTUs** (slave role): one listener per captured RTU, on the RTU's own IP and port 2404. Your SCADA master connects to them as it would in production. The replayed RTUs send the captured telemetry, answer the master's General and Counter Interrogations, and confirm its commands.
- **It plays the master** (master role): one client session per captured master, connecting to the RTU, gateway or front end you are testing, and sending the captured master traffic (interrogations, commands, clock sync).

During the run it measures per-message latency. Afterwards it compares its own capture of the run with the source pcap and gives every RTU a verdict and a score.

Use it to:

- **load-test** a SCADA master with a realistic number of RTU sessions at captured rates;
- **regression-test** an upgrade by running the same capture before and after and comparing the runs;
- **check interrogation and command handling** of a master against replayed RTUs that answer correctly;
- **check how a peer copes with faults**: withheld acknowledgements, lost frames, sequence errors, silence, resets;
- **feed IDS, loggers and historians** with realistic traffic (raw replay).

You can drive it from the browser UI (`http://<outstation-host>:8080`), from scripts through the [HTTP API](api.md), or headless with `outstation bench`, which fits CI pipelines (see [section 9](#9-repeatable-tests-profiles-re-runs-compare-ci)).

There are two replay modes:

| Mode | What happens | Use |
|---|---|---|
| **Stateful session** (benchmark) | Real TCP sessions running the IEC 104 link layer: STARTDT, k/w windows, acknowledgements, t1/t2/t3, TESTFR. Latency is measured. | Testing SCADA masters, RTUs and front ends |
| **Raw L2 replay** | Every captured frame is injected as it was, from its original source addresses, with only the destination rewritten. No TCP state. | IDS, loggers, wire-tap analysis |

This guide is about stateful sessions.

---

## 2. Pick your scenario

| You test | outstation plays | Role in the UI | Main settings |
|---|---|---|---|
| **A. A SCADA master** (control centre, HMI front end that dials RTUs) | the RTUs | *Target is a master* (slave role) | Alias NIC for the RTU IPs; gateway mode if the master reaches the RTUs through its default gateway |
| **B. An RTU, a protocol gateway or a server that masters connect to** | the master(s) | *Target is a server* (master role) | Target IP and port; egress NIC towards the target |

In IEC 104 the controlled station (the RTU) is the TCP server and the controlling station (the master) is the TCP client. So to test a master, outstation listens; to test an RTU, outstation connects.

---

## 3. Lab topology

Run outstation on its own Linux VM with two NICs:

```
┌────────────────────────┐        ┌────────────────────────────┐
│  System under test     │        │  outstation (VM)           │
│  e.g. SCADA master     │        │                            │
│                        │        │  eth0 (inner)              │
│  eth0  10.0.0.50/24    ├────────┤  10.0.0.2/24               │
│  gw    10.0.0.1        │        │  + RTU IPs as /32 aliases  │
│                        │        │    during a run            │
└────────────────────────┘        │  + 10.0.0.1/32 in gateway  │
                                  │    mode, during a run      │
       isolated vSwitch           │                            │
       "vswitch_test"             │  eth1 (outer)              │
                                  │  10.20.30.40/24            │
                                  │  default gw 10.20.30.1     │
                                  └─────────────┬──────────────┘
                                                │
                                         lab network
                                     (admin, SSH, NTP, updates)
```

- **Isolated virtual switch** (`vswitch_test`): a switch with no physical uplink. Only the system under test and outstation's inner NIC are on it, so injected traffic cannot leak into other networks.
- **eth0 (inner)**: faces the system under test. Give it a free address in the test system's subnet (here `10.0.0.2/24`), no gateway.
- **eth1 (outer)**: management and the UI. It carries the default route, so outstation protects it: runs will not alias addresses onto it or enslave it unless you override that.

The UI has no authentication. Reach it over eth1 only from your workstation, or bind it to loopback and use an SSH tunnel ([operations](operations.md#the-systemd-unit)).

---

## 4. Gateway mode: when the SCADA master is on another subnet

This matters for scenario A when the captured RTU IPs are not in the master's own subnet.

**The problem.** The master (say `10.0.0.50/24`, gateway `10.0.0.1`) dials RTU `192.168.10.42:2404`. That address is off its subnet, so the master sends the SYN to its default gateway: it ARPs for `10.0.0.1`. On an isolated switch there is no router, and the SYN goes nowhere.

**The usual fixes touch something you may not be allowed to change:** a static route on the master, or a route on the lab router pointing the RTU subnets at outstation. If you control the lab router, that route is fine and gateway mode is not needed.

**Gateway mode** changes only the master's environment. For the duration of the run, outstation adds the master's default-gateway IP (`10.0.0.1`) as a `/32` alias on its inner NIC. On the isolated switch outstation is the only one who answers the master's ARP for its gateway, so the master sends every off-subnet packet to outstation. Packets for an RTU IP land on the local RTU alias and reach the replayed RTU's listener. Replies go straight back to `10.0.0.50`, which is on outstation's connected subnet.

The master is not reconfigured: it still talks to "its gateway", and the RTU IPs are the ones it knows from production.

Optional **upstream NAT**: name the outer NIC (`eth1`) and outstation also enables IP forwarding and adds a tagged MASQUERADE rule on it, so the master keeps reaching NTP, updates and the like through outstation during the test. Leave it empty to keep the master fully isolated.

Everything gateway mode does is journaled and undone when the run ends. Gateway mode refuses the outstation host's own default gateway as the gateway IP.

---

## 5. Scenario A: testing a SCADA master

outstation plays the RTUs in the capture. Each RTU gets a listener on its captured IP and port 2404 (the *listen port base*). All listeners share the port; only the IP tells them apart, so the master can use its production RTU list unchanged.

### 5.1 Configure the run

In **Configure**:

1. **Source pcap**: the capture. The library shows how many RTUs it holds and a viability verdict (`ok`, `caution`, `heavy`, `not_recommended`) with an estimate of peak memory.
2. **Replay mode**: *Stateful session*. **Protocol**: `iec104`. **Role**: *Target is a master*.
3. **Master IP** (optional): the SCADA master's address. It is used to find the interface the master's traffic arrives on, so that it is captured too.
4. **Listen port base**: `2404` unless your master uses another port.
5. **Alias NIC for RTU listen IPs**: `eth0`, the inner NIC. RTU IPs that are not already on the host are added there as `/32 noprefixroute` aliases while their listener runs. Without it the aliases would go on the default-route NIC, which is protected, and those sessions fail.
6. **Pacing**: *Original pcap timing* replays the captured cadence (scaled by the speed factor); *As fast as possible* tests throughput.
7. **Iterations**: how many passes over the script (`0` = until stopped). Tick *Loop iterations within one TCP session* to behave like an RTU that keeps its session open; otherwise each iteration is a new connection.
8. **IEC 104 options**:
   - *Fresh timestamps* rewrites CP56Time2a time tags to the moment each frame is sent, so the master sees current event times. Choose local time or UTC.
   - *Answer GI/CI live* (default on): the replayed RTUs answer General and Counter Interrogations themselves, from the point values in the capture, and the captured interrogation bursts are left out of the script.
   - *IEC 104 link parameters*: k, w, t0–t3 and *Idle serve after script* (how long the RTUs keep answering after the script ends, default 30 s).
   - Command echo (on by default) confirms the master's commands like a real RTU. Optional return information and fault injection go into the `proto_config` JSON: see the [IEC 104 reference](iec104-config.md).
9. **SCADA gateway** (if needed, [section 4](#4-gateway-mode-when-the-scada-master-is-on-another-subnet)): tick *Act as the SCADA side's gateway*, enter the master's gateway IP (`10.0.0.1`), pick `eth0` as *Inner NIC facing SCADA*, and optionally `eth1` as *Upstream NAT NIC*.
10. **RTUs to simulate**: the picker lists every RTU in the capture with its message count and traffic volume. Start with one or a few RTUs to check the setup, then run the whole fleet.

### 5.2 Start and watch

1. Press **Start run**. If someone else's run is active you get an error naming who started it and when; only one run can be active.
2. The run appears in **Runs**. Listeners wait in `pending`. Use this moment to attach a capture tool if you want one, or change a listen IP.
3. Press **Start all pending** on the run card (or start RTUs one by one in the session table).
4. Let the master connect. Each session moves `listening → connected → active → completed`. The live diagram and the session table show per-RTU message rates.
5. The run ends when every session has finished its script and idle-serve window, or when you press **Stop**.

When the run ends it is analysed automatically from outstation's own capture of the RTU sessions ([section 8](#8-reading-the-results)).

---

## 6. Scenario B: testing an RTU or a server

outstation plays the master. Each captured master (each distinct client IP talking to the target port) becomes one session that connects to the **target IP** and replays that master's side of the conversation: STARTDT, interrogations, commands, clock sync, acknowledgements.

**One session per captured master.** A capture of one SCADA master polling 200 RTUs gives **one** session: the master's first conversation in the capture that reassembles cleanly. To test a particular RTU, use a capture of that RTU's link (filter the pcap first if needed). Captures with several masters, such as a front end serving multiple control centres, give one session per master; the picker (*Masters to replay*) selects among them.

### 6.1 Network

Each session gets its own veth port on a private bridge, carrying the captured master's IP and MAC, and binds its socket to that port. The bridge enslaves the **egress NIC** (`eth0`, the inner NIC), so the sessions appear on the test segment with their captured addresses.

The target must reach those addresses on that segment: it ARPs for them, and each port answers for its own address. That works when:

- the captured master IPs are in the target's subnet; or
- you set **Master bind IP** to a free address in the target's subnet, and every session uses it; or
- the target's route to the master subnet points out of the test segment directly.

Run interfaces are isolated from the host: forwarding off, strict ARP, IPv6 off, and tagged firewall rules that drop everything arriving on them except the target's replies to a session address.

### 6.2 Configure and run

1. **Replay mode**: *Stateful session*. **Role**: *Target is a server*.
2. **Target IP** and **Target port** (`2404`): the RTU or server under test.
3. **Egress NIC**: `eth0`. If the NIC is protected (it carries the default route, or the address you reached the UI on) the run is refused unless you override protection under **Safety**. In the recommended topology the inner NIC is not protected.
4. **Session start**: *All sessions at once*, or *Staggered to pcap timing* to start each master at its captured offset.
5. **Pacing**, **Iterations**, **IEC 104 options** as in scenario A. GI/CI answering and command echo only apply to slave role; in master role the captured commands are sent and the target's confirmations are timed.
6. **Start run**. The sessions connect, run the script, flush their acknowledgements, send STOPDT and close.

Raw-replay and master-role runs record their capture by mirroring the run's ports, which needs `tc` on the host ([operations](operations.md#troubleshooting)).

---

## 7. Lab setup step by step

You do this once per lab.

### 7.1 Create the isolated switch

**VMware vSphere / ESXi:**

1. *Host → Networking → Virtual switches → Add standard virtual switch*, name it `vswitch_test`.
2. **Do not attach a physical uplink.**
3. *Port groups → Add port group*, name it `pg_scada_test`, on `vswitch_test`, VLAN 0.

**Proxmox VE:**

1. *Datacenter → Node → Network → Create → Linux Bridge*, name it `vmbr_test`.
2. Leave *Bridge ports* empty and assign no IP.

**libvirt / virt-manager:**

```xml
<network>
  <name>isolated-test</name>
  <forward mode='none'/>
  <bridge name='virbr-test' stp='on'/>
</network>
```

```sh
sudo virsh net-define isolated.xml && sudo virsh net-start isolated-test && sudo virsh net-autostart isolated-test
```

### 7.2 Move the system under test onto the switch

1. Shut down the VM, or hot-swap its vNIC if your hypervisor supports it.
2. Change its network adapter to `pg_scada_test` / `vmbr_test` / `isolated-test`.
3. Change nothing inside the guest: address, netmask, gateway and DNS stay as they are.
4. Start it again. It has no connectivity until outstation is attached too; that is expected.

### 7.3 Create the outstation VM

1. A Linux VM (for example Ubuntu Server LTS). The capture's viability verdict estimates the memory a run needs; the 165-RTU run in [reports/](../reports/README.md) used a 12 vCPU / 12 GB VM.
2. Two vNICs: `eth0` on the isolated switch, `eth1` on the lab network.
3. `eth0`: a free static address in the test system's subnet, no gateway. `eth1`: lab address and default gateway.
4. Install the tools the service needs: `iproute2`, `iptables`, `ethtool`, and `iputils-arping` for the UI's ARP lookup.
5. Build and install:

   ```sh
   cargo build --release -p outstation
   sudo ./systemd/install.sh
   ```

6. Check the link: `ping 10.0.0.50` from outstation.

### 7.4 Open the UI

Open `http://<eth1-address>:8080`. The header shows the server's health; a warning there (for example missing capabilities or low disk) is explained in [operations](operations.md#health-and-metrics).

---

## 8. Reading the results

### 8.1 The run

The run card shows the status (`completed`, `partial` when some sessions failed, `stopped`, `failed`), messages sent and received, and the capture download. **Details** adds:

- **Ack latency** min/p50/p90/p99/max: time from sending an I-frame to the peer's acknowledgement, across all sessions, with a histogram.
- **Per session**: sent and received messages, latency percentiles, messages per second, **window stalls** (how often the session waited because the peer had not acknowledged k frames; a high number means the peer is slow to acknowledge), **unacked at end**, and the session's error, if any.
- The **gap histogram** compares inter-frame gaps in the source with the replay.

### 8.2 The analysis

Every finished stateful run with a capture is analysed automatically. **Analysis** lists the stored analyses of a run; you can also upload a capture taken on the target side with Wireshark or tcpdump.

- **Fleet verdict**: `all_correct`, `partial`, `failed`, `inconclusive`, or `run_failed` when the run itself failed or sent nothing.
- **Per RTU**: score (frames delivered intact, as a percentage), verdict and reason. `good_delivery` passes; `degraded` means the content was right but time tags, the GI/CI audit or timing failed; `partial_delivery` means frames were missing, extra, changed or reordered; `never_connected` means the master never connected to that RTU.
- **Verdict dimensions** per RTU: content, time tags, GI/CI, timing, handshake, and faults when injected.
- **GI/CI audit**: for every interrogation the master sent, whether ActCon came within 15 s, every data frame had the right group COT, ActTerm followed, and the data matched the RTU's point values.
- **Timing**: captured versus replayed duration, a speed label ("matched" within ±5 %) and pacing drift.
- **CP56 drift** (with fresh timestamps): each time tag against its real send time.

The full list of verdicts is in the [IEC 104 reference](iec104-config.md#analysis-report).

---

## 9. Repeatable tests: profiles, re-runs, compare, CI

- **Re-run**: `POST /api/runs/<id>/rerun` starts a new run with exactly the stored request of an earlier one. The protection override is never carried over.
- **Profiles**: save a run request under a name (`/api/profiles`) and reuse it.
- **Compare**: `GET /api/runs/<a>/compare/<b>` gives fleet and per-RTU differences in score, delivered frames, latency and throughput, and flags regressions beyond thresholds you choose. Use it before and after an upgrade of the system under test.
- **CI**: `outstation bench` runs one benchmark from a profile, analyses it and checks assertions:

  ```sh
  sudo outstation bench --pcap fleet.pcap --profile master-test.json \
      --assert 'score>=99' --assert 'p99_ms<=500' --report out.json
  ```

  Exit code 0 means every assertion passed, 1 an assertion failed, 2 the run failed.

Re-runs, profiles and compare are available in the UI (run cards, Configure → Profiles, the Compare view), through the API and through `bench`. See the [API reference](api.md) for examples; scripts must send an `Origin` header.

---

## 10. Cleanup and safety

Every change a run makes to outstation's host (bridges and veths, IP aliases, the gateway alias, forwarding, NAT and firewall rules, NIC settings) is written to a journal first and undone when the run ends. After a crash the service undoes the leftovers when it starts again, and the systemd unit runs `outstation cleanup` whenever the service stops. You can run `sudo outstation cleanup` by hand while the service is stopped.

The system under test is never changed. outstation does inject traffic with spoofed source addresses, so keep the test segment isolated and test only systems you are authorised to test.

---

## 11. Troubleshooting

### The master cannot reach the RTUs (scenario A)

On outstation, during the run:

```sh
ip addr show eth0              # RTU IPs as /32, and the gateway IP in gateway mode
ip neigh | grep 10.0.0.50      # the master's MAC
sudo tcpdump -ni eth0 port 2404
```

- No SYNs at all: the master is not sending to outstation. Check that it is on the isolated switch, and in gateway mode that the gateway IP is its real default gateway (`ip route` on the master; reading it changes nothing).
- SYNs arrive but no SYN-ACK: the RTU's listener is not up. Check that it was started (**Start all pending**), and look at the session's error. "needs a /32 alias on …" means the alias NIC is missing or protected.
- The master rejects the session: its whitelist does not contain the captured RTU addresses. Use a capture from the same environment.

### The target never answers (scenario B)

- `tcpdump -ni eth0 port 2404` on outstation: are SYNs going out with the captured master address?
- Does the target answer ARP for that address? If the master IP is outside the target's subnet, use **Master bind IP** ([section 6.1](#61-network)).
- "connect timeout": raise `t0` in the IEC 104 link parameters (default 5 s here).

### Sessions drop with `t1_timeout`

The peer did not acknowledge within t1 (15 s by default). It may be overloaded or have a smaller window; the session's `protocol_errors` and `window_stalls` tell you more. Adjust k, w and the timers to match the peer's configuration.

### The run is refused

- 409 "run … is active": someone else's run is active.
- A NIC is "protected": you picked the default-route NIC or the one you reached the UI on. Choose the inner NIC, or override protection if you mean it.

### The master loses internet access during the test

Gateway mode without upstream NAT isolates it. Add `eth1` as the upstream NAT NIC, or accept the isolation (often the better choice).

### outstation crashed

Restart it (`sudo systemctl restart outstation`); startup undoes what the crashed run left. The service log lists what was undone.

More in [operations](operations.md#troubleshooting).

---

## 12. Glossary

| Term | Meaning |
|---|---|
| **IEC 60870-5-104** | SCADA telecontrol protocol over TCP, port 2404. Carries I-, S- and U-frames with k/w flow control |
| **Controlling station (master)** | The SCADA side that collects data and sends commands. In IEC 104 it is the TCP **client** |
| **Controlled station (RTU, slave)** | The field station that reports data and executes commands. In IEC 104 it is the TCP **server** |
| **Slave role** | outstation plays the RTUs and listens; the system under test is a master (scenario A) |
| **Master role** | outstation plays the master and connects; the system under test is an RTU or a server (scenario B) |
| **I-frame** | Information frame carrying an ASDU (measurements, events, commands) |
| **S-frame** | Supervisory frame acknowledging received I-frames |
| **U-frame** | Control frame: STARTDT, STOPDT, TESTFR |
| **k / w** | At most k unacknowledged I-frames in flight (default 12); acknowledge at the latest after w received (default 8) |
| **t1 / t2 / t3** | Acknowledgement timeout (15 s), latest acknowledgement delay (10 s), idle time before TESTFR (20 s) |
| **ASDU** | Application data unit: type ID, cause of transmission (COT), common address (CA), information object address (IOA), values |
| **GI / CI** | General Interrogation (type 100) and Counter Interrogation (type 101): the master asks for all current values |
| **CP56Time2a** | The 7-octet time tag in time-stamped ASDUs |
| **Isolated vSwitch** | A virtual switch without a physical uplink |
| **/32 alias** | An extra single address on a NIC, without a subnet route |
| **MASQUERADE** | NAT rule that rewrites the source address to the outgoing NIC's address |

---

- Project overview: [README](../README.md)
- [HTTP API](api.md), [IEC 104 reference](iec104-config.md), [Operations](operations.md)
