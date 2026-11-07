# Scale benchmark: 200 to 800 IEC 104 sessions on one host

**Date:** 2026-11-05
**Version:** branch `audit/t17` at the merge of `audit-fixes` `a9fd9b6` (merge commit `828a95e`), release build, plus the two fixes of §6.1 and §6.2. Section 4.4 also lists the runs made before that merge.
**Host:** AMD Ryzen 5 3600 (6 cores / 12 threads), 62.7 GiB RAM, Linux 7.0.0-38-generic, Python 3.14.4. It is a shared lab machine: the 1-minute load average before each run was 1.0 to 5.1 (other services and builds), and it is recorded per run.
**Topology:** outstation, its peers and the "network" are all on this one host, in network namespaces joined by veth pairs and a Linux bridge (§2).
**Script:** [`scripts/netns-scale.sh`](../scripts/netns-scale.sh), helper [`scripts/netns-scale-helper.py`](../scripts/netns-scale-helper.py).

---

## 1. Headline

Medians of 3 runs each, as fast as possible (`pacing: fast`), event-driven peers with 4 processes:

| | master role, 200 sessions | master role, 400 | slave role, 200 RTUs | slave role, 400 RTUs |
|---|---|---|---|---|
| I-frames per run | 2,319,150 | 4,662,180 | 1,500,005 | 2,994,515 |
| I-frames/s on the wire | **704,085** | **640,588** | **237,523** | **255,266** |
| I-frames/s, outstation's own figure | 697,069 | 634,828 | 171,861 | 182,148 |
| ack latency p50 / p99 | 2.6 / 5.9 ms | 4.4 / 7.1 ms | 0.42 / 2.7 ms | 0.39 / 2.2 ms |
| outstation CPU while sending | 4.9 cores | 5.1 cores | 2.3 cores | 2.3 cores |
| RSS while sending / peak with the analysis | 199 / 566 MB | 382 / 1,127 MB | 135 / 620 MB | 242 / 1,181 MB |
| threads / open fds (peak) | 403 / 414 | 804 / 814 | 277 / 713 | 485 / 1,571 |
| setup before traffic (per session) | 11.0 s (54 ms) | 27.1 s (67 ms) | 6.8 s (34 ms) | 12.7 s (31 ms) |
| teardown | 9.6 s | 20.2 s | none after the run | none after the run |
| sessions failed | 0 | 0 | 0 | 0 |
| `captured_dropped` | 0 | 0 | 237,037 | 192,301 |
| analysis | `partial`, 99.77 % | `partial`, 99.97 % | `partial`, 82.75 % | `partial`, 92.02 % |

- **Throughput is not the limit for realistic loads.** 200 masters push about 700 k I-frames/s; 200 RTUs stream about 240 k I-frames/s (slave role is bounded by the IEC 104 window: k = 12 unacknowledged frames per session, the master acknowledging every 8). The 165-RTU production capture of the [April report](2026-04-17-fleet-replay-showcase.md) ran at about 680 I-frames/s.
- **CPU follows the message rate, not the session count**: about 7-8 µs of outstation CPU per I-frame in master role and 9-10 µs in slave role at full speed; 0.15 cores for 200 masters at original timing (2,145 I-frames/s), 0.32 cores for 200 RTUs at 10× speed (9,000 I-frames/s).
- **Memory**: about 0.45-0.65 MB per master session and 0.4 MB per RTU while sending, on top of the loaded capture (roughly its file size). The analysis afterwards needs 2-5 times as much for a few seconds.
- **The fidelity verdict is reliable at paced rates, not at full speed.** At original timing (sped up 10× and 100×, up to 41 k I-frames/s) 200 RTUs score `all_correct` 100 % in 6 of 6 runs with nothing dropped. At full speed the slave capture loses frames (§6.4) and master runs show an ordering artefact (§6.3); every session still completes and the peers receive everything.
- **800 sessions** run in slave role (all 800 complete, 174 k I-frames/s). In master role 508 of 800 connected: the rest failed because this test host's kernel neighbour table overflowed (§5), a limit of putting both ends on one kernel. Setup then takes 77 s and teardown 47 s.
- **Fixed in this lane**: the master capture lost every reply above 527 sessions (§6.1), and slave runs above ~250 RTUs ran out of file descriptors under the systemd default limit (§6.2).
- **Gateway mode does not work in master role with an egress NIC** (§7).
- **After T17c** (§10): every full-speed run of 200 and 400 sessions, both roles, scores `all_correct` with no frame lost by the capture; master-role setup takes 3.2-3.4 ms per session (0.8 s for 200, 1.5 s for 400) and teardown 0.9-1.7 s; gateway mode is refused in master role.

---

## 2. Method

### Topology

```
  ostest-*-t (LAN + target)         ostest-*-a (outstation)               ostest-*-p (SCADA master side)
  bridge "lan" 10.77.0.1/24  <-->   os-a (egress NIC, default route,
  IEC 104 slave peer :2404          enslaved by master-role runs)
                                    s-o 10.79.0.1/24              <-->    s-p 10.79.0.2/24
                                    (+ the run's /32 RTU aliases)          route 192.168.8.0/22 dev s-p
                                                                           IEC 104 master peer
```

Each run gets fresh namespaces (deleted afterwards), its own state directory and its own capture. `outstation bench` runs in `ostest-*-a` under `/usr/bin/time -v` (and `prlimit` for the §6.2 runs). Profiles:

- master-N: `{"role":"master","target_ip":"10.77.0.1","nic":"os-a","force":true,"iterations":30,"iteration_gap_ms":0,"pacing":"fast"}`
- slave-N: `{"role":"slave","target_ip":"10.79.0.2","alias_iface":"s-o","iterations":5,"loop_within_session":true,"pacing":"fast"}`
- `@SPEED` variants: `"pacing":"original","speed":SPEED` and one iteration.

### Traffic

All captures come from [`examples/gen_iec104_traffic.py`](../examples/gen_iec104_traffic.py):

- **master-N**: master role needs one captured master per session, and the generator writes one master per file, so N single-RTU captures are generated (`-n 1 -d 36000 --mean-interval 60`, master `10.20.1xx.yy` with its own MAC, RTU `10.21.0.0/16`) and merged. The master side of each holds about 390 I-frames (GI, clock sync, counter interrogations, commands). Each session replays it 30 times, one connection per iteration, no gap. 54 MB of pcap for 200 sessions, 108 MB for 400.
- **slave-N**: one capture with N RTUs (`-n N -d 300 --mean-interval 0.2 --subnet 192.168.8.0/22`), about 1,500 I-frames per RTU, looped 5 times inside one connection. 30 MB for 200 RTUs, 60 MB for 400, 119 MB for 800.

### Peers

The repository's threaded mocks (`scripts/iec104-mock-slave.py`, `iec104-mock-master.py`) are too slow for this (§4.3), so the helper has event-driven versions with the same protocol behaviour, run as 4 processes:

- `fast-slave`: answers STARTDT/STOPDT/TESTFR and acknowledges received I-frames, once per read (the mock acknowledges every frame). The processes share the listener with `SO_REUSEPORT`; listen backlog 1,024.
- `fast-master`: connects to every RTU IP (retrying until the listener is up), STARTDT, one GI, an S-frame at least every 8 I-frames and when the station goes quiet, closes after 0.5 s of silence. The RTU IPs are split over the processes.

Correction: in the slave-role runs of §3 and §4 other than the "GI fixed" ones, `fast-master` read the station's common address from the wrong offset and sent its GI to a wrong CA, so each replayed RTU answered with a negative ActCon instead of its GI response (1,500,005 instead of 1,501,671 I-frames per 200-RTU run, 0.1 %). Every frame was still acknowledged and every session completed. A rerun with the corrected peer (slave-200, 3 runs, idle host) is within the spread of the earlier runs: 289,639 I-frames/s on the wire, p50 / p99 0.45 / 2.4 ms, 2.3 cores, 176 k frames dropped by the capture, `partial` 87.0 %.

### What is measured

| Metric | Source |
|---|---|
| I-frames/s, outstation's figure | `aggregate_throughput_msgs_per_sec` of the bench report: I-frames sent by outstation over the run, from the first session start to the last session end (in slave role this includes listener setup and the peer's close delay) |
| I-frames/s on the wire | the run's own capture: distinct I-frames sent by outstation's side, first to last; also the busiest second ("peak 1 s") |
| ack latency | bench report, fleet p50/p99 of send-to-acknowledgement per I-frame (includes the peer's acknowledgement policy) |
| CPU % while sending | a /proc sampler (every 100 ms) over outstation's process: CPU time between the first session start and the last session end; 100 % = one core |
| CPU s, peak RSS | `/usr/bin/time -v` for the whole bench, including setup, teardown and the analysis |
| RSS while sending, threads, fds | the /proc sampler (peak within the sending window, or the whole run) |
| setup | bench log: from "bench starting" to the first session (master) or the last listener up (slave); per session = the port or listener phase divided by N |
| teardown | bench log: from "capture stopped" to the last host-state restore (master); slave aliases are removed as each session ends |
| `captured_dropped`, verdict, score | bench report and its built-in analysis (generic mode) |
| peer CPU | the same sampler on the peer's processes |

The median of 3 runs is reported for every 200- and 400-session scenario; 800 sessions ran once each.

---

## 3. Results at full speed (merged code)

Medians of 3 runs:

| scenario | I-frames/s wire | tool | peak 1 s | p50 ms | p99 ms | CPU % | CPU s | RSS MB sending / peak | threads | fds | setup s | ms/session | teardown s | peer CPU % | dropped | verdict, score |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| master-200 | 704,085 | 697,069 | 730,130 | 2.6 | 5.9 | 494 | 30.3 | 199 / 566 | 403 | 414 | 11.0 | 54.1 | 9.6 | 357 | 0 | partial ×3, 99.77 |
| master-400 | 640,588 | 634,828 | 667,599 | 4.4 | 7.1 | 507 | 71.9 | 382 / 1,127 | 804 | 814 | 27.1 | 67.3 | 20.2 | 363 | 0 | partial ×3, 99.97 |
| slave-200 | 237,523 | 171,861 | 328,868 | 0.42 | 2.7 | 227 | 24.6 | 135 / 620 | 277 | 713 | 6.8 | 33.5 | 0 | 103 | 237,037 | partial ×3, 82.75 |
| slave-400 | 255,266 | 182,148 | 375,976 | 0.39 | 2.2 | 235 | 51.8 | 242 / 1,181 | 485 | 1,571 | 12.7 | 31.4 | 0 | 101 | 192,301 | partial ×3, 92.02 |
| slave-200, peer GI fixed | 289,639 | 175,020 | 309,349 | 0.45 | 2.4 | 229 | 24.6 | 136 / 622 | 285 | 583 | 6.0 | 29.5 | 0 | 104 | 176,038 | partial ×3, 87.04 |
| slave-200, `realtime` | 312,600 | 175,050 | 378,494 | 0.42 | 2.3 | 233 | 24.3 | 136 / 608 | 287 | 630 | 5.9 | 29.4 | 0 | 105 | 60,252 | partial ×2, all_correct ×1, 96.58 |

Every session of every run completed and every peer station saw its I-frames. The partial verdicts are capture and analysis artefacts, explained in §6.3 to §6.5.

## 4. Other runs

### 4.1 Paced (original timing), merged code

| scenario | I-frames/s wire | p50 ms | p99 ms | CPU % | RSS MB sending / peak | threads | fds | setup s | dropped | verdict, score |
|---|---|---|---|---|---|---|---|---|---|---|
| slave-200@10 | 9,041 | 59.2 | 260.5 | 32 | 126 / 321 | 404 | 649 | 5.2 | 0 | all_correct ×3, 100 |
| slave-200@100 | 40,907 | 6.0 | 26.1 | 98 | 126 / 312 | 398 | 661 | 5.4 | 0 | all_correct ×3, 100 |
| master-200@1000 | 2,145 | 0.08 | 0.15 | 15 | 149 / 213 | 403 | 414 | 10.9 | 0 | all_correct ×1, partial ×2, 99.50 |

The paced slave latencies are the peer's: it acknowledges every 8th I-frame, so at 45 frames/s per RTU a frame waits for 7 more. The two partial master runs have 1 and 2 of 200 sessions reported as "never connected" although they sent all their I-frames: the same capture-order artefact as §6.3 (the same runs before the merge were `all_correct` ×3).

### 4.2 800 sessions (one run each), merged code

| scenario | I-frames | I-frames/s wire | p50 / p99 ms | CPU % | RSS MB sending / peak | threads | fds | setup s (ms/session) | teardown s | failed | dropped | verdict, score |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| master-800 | 5,974,380 | 542,528 | 5.3 / 9.1 | 471 | 674 / 1,642 | 1,311 | 1,322 | 76.6 (95) | 46.7 | 292 | 0 | partial, 63.49 |
| slave-800 | 5,987,110 | 173,934 | 0.38 / 1.8 | 226 | 467 / 2,317 | 880 | 3,135 | 34.9 (43) | 0 | 0 | 190,303 | partial, 96.83 |

The 292 failed master sessions are `connect(10.77.0.1:2404): timed out` (287) and `No route to host` (5); the kernel logged `neighbour: arp_cache: neighbor table overflow!`. See §5. The 508 that connected were analysed as correct. Before the fix in §6.1 the same run reported `no_delivery`, score 0.

### 4.3 The repository's threaded mocks (before the merge)

Same scenarios with `PEER=mock` (one Python process, one thread per connection):

| scenario | I-frames/s wire | p50 / p99 ms | outstation CPU % | mock CPU % | dropped | verdict |
|---|---|---|---|---|---|---|
| master-200 | 44,932 | 44.7 / 104.2 | 150 | 342 | 0 | all_correct ×2, partial ×1 (99.99) |
| slave-200 | 54,298 | 34.0 / 81.0 | 83 | 283 | 0 | all_correct ×3 |

The mock is the bottleneck: it uses 2.8-3.4 cores (its threads contend for the GIL) while outstation idles at 0.8-1.5 cores, and it adds 30-45 ms of latency. Its listen backlog of 64 also drops SYNs when 200 sessions connect at once (they retry after 1 s). Use it for functional tests, not for throughput.

### 4.4 Before the re-audit merge (same script, same host)

| scenario | I-frames/s wire | p50 / p99 ms | CPU % | dropped | verdict, score |
|---|---|---|---|---|---|
| master-200 | 652,131 | 2.6 / 6.3 | 464 | 0 | partial ×3, 99.84 |
| master-400 | 604,316 | 4.5 / 11.5 | 478 | 0 | partial ×3, 99.97 |
| slave-200 | 254,950 | 0.40 / 2.1 | 231 | 46,524 | partial ×3, 97.34 |
| slave-400 | 280,501 | 0.40 / 2.2 | 233 | 68,970 | partial ×3, 98.03 |
| slave-800 (1 run) | 203,362 | 0.38 / 2.1 | 234 | 73,938 | partial, 98.93 |
| slave-200@10 / @100 | 8,720 / 40,062 | 59.2 / 6.0 (p50) | 34 / 96 | 0 | all_correct ×3 each |
| master-200@1000 | 2,145 | 0.08 (p50) | 16 | 0 | all_correct ×3 |

Master-role throughput went up by 6-8 % with the merge; the slave capture drops went up 3-5 times (§6.5).

### 4.5 Peer processes (before the merge, one run each)

| peer processes | master-200 I-frames/s | outstation / peer CPU % | slave-200 I-frames/s | outstation / peer CPU % |
|---|---|---|---|---|
| 2 | 392,317 | 309 / 191 | 258,874 | 195 / 74 |
| 4 | 652,131 (median of 3) | 464 / 344 | 254,950 (median of 3) | 231 / 102 |
| 8 | 644,296 | 437 / 374 | 214,560 | 205 / 111 |

In master role the fast peer needs 3.5 cores to keep up and outstation and peer together use 8-9 of the 12 hardware threads: the master-role figure is bounded by this host's CPU, so treat it as a lower bound for outstation alone. In slave role the peer uses about one core whatever its process count, and the rate is set by the protocol window (k = 12, acknowledgements every 8 frames) and the per-session round trip.

### 4.6 Open-file limit of 1,024 (merged code, with the fix of §6.2)

`NOFILE=1024:65536 scripts/netns-scale.sh slave-400`: outstation raised its own limit; 400 of 400 sessions completed with 1,538 fds open (before the fix: 123 failed, §6.2).

---

## 5. Limits of the test setup, not of outstation

- **One kernel for both ends.** Above about 500 sessions in master role, each session's port resolves the target separately (one neighbour entry per port in outstation's namespace) and the target resolves every session address (one entry each in its namespace). The kernel's IPv4 neighbour table is shared by all namespaces, and `net.ipv4.neigh.default.gc_thresh3` (1,024 here; host-wide, so this lane may not change it) caps it: 800 sessions need about 1,600 entries. On a real deployment the target's entries live on the target, but outstation's host still needs one entry per session, so **beyond about 1,000 master sessions raise `gc_thresh3` on the outstation host**.
- **One CPU for both ends.** At full speed in master role the peer needs as much CPU as outstation; the master-role numbers are bounded by the host (§4.5). Kernel time (veth, bridge, TCP) is charged to the processes that send, so outstation's CPU figures include its share of the network stack: 70-85 % of its CPU time is system time.
- **Python peers.** The threaded mocks top out at about 50 k I-frames/s (§4.3); the event-driven peers acknowledge once per read rather than once per frame, which lowers the measured latency compared with a per-frame acknowledger.
- **Shared host.** Load average 1-5 from other work before the runs; the run-to-run spread is within ±5 % for master-role throughput and wider for slave-role capture drops.
- **Synthetic traffic.** The generated captures have regular structure; real captures with larger ASDUs or more sessions per IP behave differently.

## 6. Product problems found at scale

### 6.1 Master role above ~527 sessions: the capture lost every reply (fixed in this lane)

The master-role capture records the target's replies on the enslaved NIC through a classic-BPF filter with one test per session MAC (`raw_replay::bpf::incoming_to_macs_filter`, 5 instructions per MAC). The builder falls back to "keep every incoming frame" only above the 4,096-instruction limit (817 MACs). But the kernel charges a socket filter against `net.core.optmem_max`, and the attach fails with ENOMEM much earlier. Measured with a stand-alone `SO_ATTACH_FILTER` probe of the same program shape in a fresh namespace:

| `net.core.optmem_max` | largest filter that attaches |
|---|---|
| 131072 (the default on this 7.0 kernel) | 527 MACs (2,642 instructions) |
| 20480 (the default of older kernels) | 81 MACs (412 instructions) |

When the attach failed, the run logged `capture: cannot record replies on the NIC ... Cannot allocate memory (os error 12)`, the capture held only the sessions' own frames, and the analysis reported every endpoint as never connected: master-800 came out `no_delivery`, score 0, although 509 of its sessions had run correctly. On a host with the older 20 KiB default this happens from 82 sessions up.

Fix (`dfe8df1`): when the per-MAC filter is rejected, the NIC is captured with the accept-all-incoming filter instead, with a run warning ("the per-MAC reply filter for N sessions did not fit ...; every incoming frame on NIC is recorded, including other LAN traffic"). Regression test `master_capture_keeps_replies_when_the_mac_filter_does_not_fit` in `crates/sched/tests/capture_netns.rs` (privileged, run by `scripts/netns-bench-test.sh`) sets `optmem_max=512` in its namespace so that even a one-session filter does not fit; it fails without the fix.

Still open at the time: the analysis did not carry the run's capture warnings into its notes, so a capture without replies read as "never connected" rather than "inconclusive". Since T17c the notes and `run_warning` carry them (§10.2).

### 6.2 Slave runs above ~250 RTUs ran out of file descriptors under the systemd default (fixed in this lane)

A slave-role run holds about 4 descriptors per RTU, a master-role run about 2 per session (§1 and §4.2: 3,135 fds at 800 RTUs). systemd starts services with a soft `RLIMIT_NOFILE` of 1,024 (`DefaultLimitNOFILE=1024:524288`), and so do many login shells; `systemd/outstation.service` sets no `LimitNOFILE`, and outstation did not raise the limit itself.

Repro (binary before `ccd5e08`): `NOFILE=1024 scripts/netns-scale.sh slave-400`. 123 of 400 sessions failed, 113 of them with ``spawn `ip -o addr show`: Too many open files (os error 24)`` while adding their listen alias.

Fix (`ccd5e08`): at startup outstation raises the soft limit to the hard limit (at most 2^20) and warns when it stays below 4,096. Unit test `nofile_limit_is_raised_to_the_hard_limit` (it lowers the soft limit to 1,024 first). With the fix the same run completes 400 of 400 (§4.6).

### 6.3 Master runs: a few sessions flagged although they ran correctly (fixed in T17c, §10)

In every full-speed master run 0.5-9 % of the sessions get `handshake_incomplete` ("session k/30: content matched but the STARTDT handshake was not seen"), with `captured_dropped` 0 and every I-frame delivered; at original timing (merged code) 1-2 of 200 sessions are sometimes reported as "never connected" although they sent all their I-frames.

Cause, from a kept capture (`KEEP_CAPTURES=1`): every frame is there, with correct timestamps, but the capture file is written in arrival order from its two vantage points (the ports' ingress mirror and the NIC's incoming filter), not in timestamp order. For a flagged connection the target's SYN-ACK, ACK and STARTDT con (NIC reader) are in the file before the session's SYN and STARTDT act (mirror reader). `pcapload` builds flows in file order: it opens the flow at the SYN-ACK, records the STARTDT con as payload, and when the SYN arrives it starts a new flow (client ISN unknown and payload already seen: the `split` test in the flow tracker, `crates/pcapload/src/lib.rs`). The STARTDT con ends up in the orphan flow, and the analyzer (`startdt_handshake_ok` = the target's stream contains STARTDT_CON) reports the handshake missing, or, when the split takes the session's payload with it, no session at all. `pcapload` warns "capture has out-of-order timestamps" for these captures.

Repro: `REPEAT=1 KEEP_CAPTURES=1 scripts/netns-scale.sh master-200`, then list a flagged session's connections in `runs/master-200-fast-r1/capture.pcap` in file order. Possible fixes: let the capture writer merge its readers by timestamp (a short reorder window), or sort packets by timestamp in `pcapload` before building flows.

### 6.4 Slave runs at full speed: the capture cannot keep up (fixed in T17c, §10.3)

At 240-320 k I-frames/s the slave capture (one AF_PACKET socket on the alias NIC, 32 MiB receive buffer) loses 4-16 % of the frames. The run reports them in `captured_dropped`, the analysis says "the capture lost N frames (kernel receive queue full); frames reported missing may have been delivered", and the verdict is `partial`. Every session completed. At 10× and 100× original timing (up to 41 k I-frames/s) nothing is dropped and 200 RTUs score `all_correct`. Use original timing for fidelity verdicts and full speed for throughput.

### 6.5 Re-audit change N8: the slave capture no longer runs at RT priority by default (reverted in T17c, §10)

Since the re-audit merge the slave capture thread gets RT priority only when the run sets `realtime` (`crates/sched/src/slave.rs`, "RT priority only when the run asks for realtime (N8)"); T18b had made it RT by default because the capture overflowed under CPU load. At full speed the drops went from 46.5 k (median, slave-200, before the merge) to 237 k after it; with `"realtime": true` they are 60 k (and 0 in one of three runs). Suggest saying in the docs that heavy slave runs whose capture is to be analysed should set `realtime`.

### 6.6 Smaller observations

- **Setup and teardown are serial and grow faster than the session count in master role**: 54 ms per session at 200, 67 ms at 400, 95 ms at 800 (one `ip`/`sysctl`/`iptables` call at a time, and each iptables check scans a longer chain), and teardown takes almost as long again (9.6 s, 20.2 s, 46.7 s). Slave role: 30-34 ms per listener at 200-400, 43 ms at 800, overlapping with traffic. *Fixed for master role in T17c (§10.2, item 6).*
- **A slave session whose first master connection closes before STARTDT ends for good** ("peer closed the connection waiting for STARTDT act") and does not listen again. Seen with an early version of the fast master peer that dropped half-open connections; a real master that probes the port before connecting for real would hit it too. *Fixed in T17c (§10.2, item 5).*
- **Cosmetic**: in master role with many captured masters the analysis note "master IP renamed: captured=10.20.100.10 live=10.20.100.173" names one session's address, although every session has its own master. *Fixed in T17c (§10.2, item 7).*
- **Capture filter sizes in slave role**: the per-RTU filter (4 instructions per RTU) fits 1,019 RTUs before the 4,096-instruction limit; its option-memory limit was not reached at 800 RTUs. Above the limit an RTU is not recorded, with a warning (from the code, not measured).

## 7. SCADA-gateway mode with an egress NIC in master role (refused since T17c, §10.2)

Question left by T15: does gateway mode work in master role when the run enslaves an egress NIC? It does not. Repro: [`scripts/netns-gateway-egress.sh`](../scripts/netns-gateway-egress.sh). One session, master `10.20.100.10` (off the RTU's subnet), RTU `10.77.0.1/24` whose default gateway `10.77.0.254` does not exist on the isolated LAN, egress NIC `os-a` (not the default-route NIC, so no `force` is needed for it):

| case | result |
|---|---|
| 1. RTU routes everything on-link, no gateway mode (control) | completed |
| 2. RTU `default via 10.77.0.254`, no gateway mode | fails: `connect(10.77.0.1:2404): timed out`; the RTU's neighbour entry for .254 is `FAILED` (expected: this is what gateway mode is for) |
| 3. as 2, `scada_gateway_ip` 10.77.0.254 on `scada_gateway_iface` `os-a` | refused before traffic: "refusing to add the SCADA gateway alias to os-a: os-a is already a port of another bridge" (the bridge is the run's own) |
| 4. as 3 with `force` | the alias goes onto `os-a`, which is a port of the run bridge, so nothing answers the RTU's ARP for .254 (`INCOMPLETE`); the session times out |
| 5. as 2, gateway alias on a second, non-enslaved NIC `os-g` in the same LAN | the RTU resolves .254 to `os-g` (`REACHABLE`), so its replies arrive on `os-g` instead of the session's own port; the session fails with `No route to host` |

Gateway mode was built for slave role, where the RTU addresses are local aliases and the replies come back on the same NIC. In master role a session's replies have to come back through its own bridge port, so the gateway address would have to be answered from the run bridge (proxy ARP towards the session ports), which nothing does today. Suggestions: refuse `scada_gateway_*` in master role (or when `scada_gateway_iface` equals `nic`) with a message that points at the alternatives, and say in the lab guide that gateway mode is for slave role. Alternatives in master role: a route on the device under test or the lab router towards outstation's bridge, or captured masters on the device's own subnet.

## 8. Reproducing

```sh
cargo build --release -p outstation
OUTSTATION_BIN=target/release/outstation scripts/netns-scale.sh                       # 200 and 400, both roles, 3 runs each
OUTSTATION_BIN=target/release/outstation scripts/netns-scale.sh slave-200@10 master-200@1000
REPEAT=1 OUTSTATION_BIN=target/release/outstation scripts/netns-scale.sh master-800 slave-800
PEER=mock OUTSTATION_BIN=target/release/outstation scripts/netns-scale.sh master-200 slave-200
NOFILE=1024:65536 REPEAT=1 OUTSTATION_BIN=target/release/outstation scripts/netns-scale.sh slave-400
REALTIME=1 OUTSTATION_BIN=target/release/outstation scripts/netns-scale.sh slave-200
OUTSTATION_BIN=target/release/outstation scripts/netns-gateway-egress.sh
```

The script prints one JSON line per run and a Markdown table of every run and the medians, and keeps everything (bench reports, logs, samples, `results.jsonl`, `results.md`, `env.txt`) in its work directory.

## 9. Raw numbers (merged code, every run)

"load" is the 1-minute load average before the run. The `realtime` rows are the slave-200 runs with `REALTIME=1`, the `NOFILE=1024` row is slave-400 with `NOFILE=1024:65536`, and the `GI fixed` rows are slave-200 with the corrected master peer (§2).

| scenario | run | load | I-frames | msgs/s tool | msgs/s wire | peak 1 s | p50 ms | p99 ms | CPU % | CPU s | RSS MB traffic | RSS MB peak | threads | fds | setup s | ms/sess | traffic s | teardown s | failed | dropped | verdict | score |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| master-200 | 1 | 2.6 | 2,319,150 | 712,270 | 720,102 | 750,822 | 2.52 | 5.49 | 507 | 30.3 | 201 | 567 | 403 | 414 | 10.9 | 54.0 | 3.2 | 9.6 | 0 | 0 | partial | 99.87 |
| master-200 | 2 | 2.0 | 2,319,150 | 697,069 | 704,085 | 708,910 | 2.63 | 5.93 | 490 | 30.3 | 199 | 566 | 403 | 414 | 11.0 | 54.3 | 3.3 | 9.5 | 0 | 0 | partial | 99.73 |
| master-200 | 3 | 4.1 | 2,319,150 | 693,318 | 700,191 | 730,130 | 2.56 | 5.89 | 494 | 30.4 | 199 | 565 | 404 | 414 | 11.0 | 54.1 | 3.3 | 9.6 | 0 | 0 | partial | 99.77 |
| slave-200 | 1 | 4.9 | 1,500,005 | 151,210 | 192,097 | 363,211 | 0.39 | 2.73 | 195 | 24.6 | 134 | 608 | 273 | 706 | 7.7 | 38.2 | 8.7 | 0.0 | 0 | 247,420 | partial | 79.68 |
| slave-200 | 2 | 4.6 | 1,500,005 | 175,789 | 237,523 | 319,792 | 0.42 | 2.09 | 228 | 24.6 | 135 | 620 | 282 | 859 | 6.8 | 33.5 | 7.3 | 0.0 | 0 | 237,037 | partial | 82.75 |
| slave-200 | 3 | 4.0 | 1,500,005 | 171,861 | 288,935 | 328,868 | 0.44 | 2.68 | 227 | 24.6 | 135 | 623 | 277 | 713 | 6.1 | 30.3 | 7.5 | 0.0 | 0 | 143,595 | partial | 91.02 |
| master-400 | 1 | 3.6 | 4,662,180 | 634,828 | 640,588 | 674,997 | 4.41 | 6.98 | 509 | 71.9 | 382 | 1126 | 804 | 814 | 27.1 | 67.3 | 7.3 | 20.2 | 0 | 0 | partial | 99.97 |
| master-400 | 2 | 3.9 | 4,662,180 | 629,599 | 635,291 | 657,609 | 4.45 | 7.12 | 507 | 72.3 | 380 | 1127 | 805 | 814 | 27.1 | 67.2 | 7.3 | 20.2 | 0 | 0 | partial | 99.99 |
| master-400 | 3 | 5.0 | 4,662,180 | 635,261 | 640,897 | 667,599 | 4.30 | 7.10 | 507 | 71.7 | 383 | 1128 | 804 | 814 | 27.1 | 67.3 | 7.3 | 20.3 | 0 | 0 | partial | 99.95 |
| slave-400 | 1 | 3.8 | 2,994,515 | 182,403 | 228,100 | 349,312 | 0.39 | 2.20 | 236 | 52.0 | 240 | 1194 | 485 | 1621 | 13.8 | 34.1 | 15.2 | 0.0 | 0 | 251,315 | partial | 91.70 |
| slave-400 | 2 | 5.0 | 2,994,515 | 182,148 | 255,266 | 375,976 | 0.42 | 1.99 | 235 | 51.8 | 243 | 1181 | 484 | 1562 | 12.7 | 31.4 | 15.2 | 0.0 | 0 | 168,785 | partial | 93.82 |
| slave-400 | 3 | 5.1 | 2,994,515 | 173,978 | 272,880 | 391,050 | 0.39 | 2.23 | 224 | 51.6 | 242 | 1159 | 486 | 1571 | 11.6 | 28.7 | 15.9 | 0.0 | 0 | 192,301 | partial | 92.02 |
| slave-200@10 | 1 | 4.8 | 300,161 | 8,017 | 8,760 | 10,200 | 59.20 | 260.49 | 32 | 17.2 | 126 | 322 | 404 | 734 | 5.3 | 26.3 | 36.2 | 0.0 | 0 | 0 | all_correct | 100.00 |
| slave-200@10 | 2 | 3.7 | 300,161 | 8,194 | 9,049 | 10,224 | 59.19 | 260.53 | 32 | 17.0 | 126 | 321 | 404 | 618 | 5.2 | 25.5 | 35.4 | 0.0 | 0 | 0 | all_correct | 100.00 |
| slave-200@10 | 3 | 3.1 | 300,161 | 8,198 | 9,041 | 10,232 | 59.19 | 260.51 | 32 | 17.2 | 126 | 319 | 404 | 649 | 5.1 | 25.4 | 35.4 | 0.0 | 0 | 0 | all_correct | 100.00 |
| slave-200@100 | 1 | 2.4 | 300,161 | 28,519 | 40,907 | 74,066 | 5.98 | 26.06 | 98 | 15.2 | 127 | 314 | 401 | 585 | 5.4 | 26.6 | 9.3 | 0.0 | 0 | 0 | all_correct | 100.00 |
| slave-200@100 | 2 | 2.7 | 300,161 | 28,406 | 40,979 | 72,866 | 5.99 | 26.18 | 98 | 15.3 | 126 | 312 | 398 | 871 | 5.4 | 26.7 | 9.3 | 0.0 | 0 | 0 | all_correct | 100.00 |
| slave-200@100 | 3 | 3.1 | 300,161 | 28,411 | 40,836 | 73,874 | 6.00 | 26.07 | 98 | 15.3 | 126 | 312 | 398 | 661 | 5.4 | 26.9 | 9.4 | 0.0 | 0 | 0 | all_correct | 100.00 |
| master-200@1000 | 1 | 3.5 | 77,305 | 2,145 | 2,146 | 2,194 | 0.08 | 0.15 | 15 | 15.8 | 149 | 213 | 403 | 414 | 10.9 | 53.8 | 36.0 | 9.3 | 0 | 0 | partial | 99.50 |
| master-200@1000 | 2 | 2.4 | 77,305 | 2,144 | 2,144 | 2,190 | 0.08 | 0.15 | 15 | 15.9 | 149 | 213 | 403 | 414 | 10.8 | 53.5 | 36.1 | 9.3 | 0 | 0 | all_correct | 100.00 |
| master-200@1000 | 3 | 1.4 | 77,305 | 2,145 | 2,145 | 2,208 | 0.08 | 0.17 | 15 | 15.9 | 149 | 213 | 403 | 414 | 10.9 | 54.0 | 36.0 | 9.3 | 0 | 0 | partial | 99.00 |
| master-800 | 1 | 1.0 | 5,974,380 | 538,232 | 542,528 | 576,829 | 5.32 | 9.12 | 471 | 146.7 | 674 | 1642 | 1311 | 1322 | 76.6 | 95.4 | 11.0 | 46.7 | 292 | 0 | partial | 63.49 |
| slave-800 | 1 | 4.5 | 5,987,110 | 164,626 | 173,934 | 359,186 | 0.38 | 1.84 | 226 | 112.3 | 467 | 2317 | 880 | 3135 | 34.9 | 43.4 | 35.0 | 0.0 | 0 | 190,303 | partial | 96.83 |
| slave-200 realtime | 1 | 2.7 | 1,500,005 | 175,050 | 266,440 | 378,494 | 0.41 | 2.27 | 233 | 24.3 | 134 | 618 | 279 | 630 | 7.4 | 36.9 | 7.3 | 0.0 | 0 | 60,252 | partial | 96.58 |
| slave-200 realtime | 2 | 4.5 | 1,500,005 | 177,663 | 312,600 | 313,497 | 0.50 | 2.20 | 236 | 24.4 | 136 | 608 | 291 | 626 | 5.9 | 29.1 | 7.2 | 0.0 | 0 | 68,877 | partial | 96.05 |
| slave-200 realtime | 3 | 3.9 | 1,500,005 | 174,156 | 324,479 | 402,319 | 0.42 | 2.40 | 232 | 24.1 | 136 | 595 | 287 | 714 | 5.9 | 29.4 | 7.4 | 0.0 | 0 | 0 | all_correct | 100.00 |
| slave-400 NOFILE=1024 | 1 | 4.0 | 2,994,515 | 182,281 | 276,573 | 408,343 | 0.42 | 2.06 | 232 | 50.6 | 256 | 1173 | 482 | 1538 | 11.2 | 27.6 | 15.2 | 0.0 | 0 | 167,862 | partial | 92.15 |
| slave-200 GI fixed | 1 | 0.4 | 1,501,671 | 175,020 | 289,639 | 309,349 | 0.48 | 2.41 | 229 | 24.6 | 134 | 614 | 285 | 503 | 6.0 | 29.5 | 7.3 | 0.0 | 0 | 173,874 | partial | 85.82 |
| slave-200 GI fixed | 2 | 0.9 | 1,501,671 | 174,390 | 290,931 | 336,977 | 0.45 | 2.26 | 229 | 24.5 | 136 | 632 | 288 | 583 | 5.9 | 29.4 | 7.4 | 0.0 | 0 | 177,420 | partial | 87.99 |
| slave-200 GI fixed | 3 | 1.2 | 1,501,671 | 175,613 | 286,414 | 293,840 | 0.45 | 2.42 | 231 | 24.7 | 136 | 622 | 285 | 787 | 6.0 | 29.7 | 7.3 | 0.0 | 0 | 176,038 | partial | 87.04 |

## 10. After T17c

T17c (lane fx3, branch `audit/fx3`) fixed the engine problems of §6 and §7. Same host, same script and scenarios, release build of `18015b8`; medians of 3 runs each. The "before" column is a fresh run of the binary at `475292a` (the T17 merge) on the same afternoon, so that both sides saw the same host load (1-minute load average 2.5-9 before the runs; the host was busy with other lanes' builds).

### 10.1 Headline

| | master-200 before | master-200 after | master-400 before | master-400 after | slave-200 before | slave-200 after | slave-400 after |
|---|---|---|---|---|---|---|---|
| verdict | partial ×3, 99.6 | **all_correct ×3, 100** | partial ×3, 100.0 (rounded) | **all_correct ×3, 100** | partial ×3, 85.5 | **all_correct ×3, 100** | **all_correct ×3, 100** |
| `captured_dropped` | 0 | 0 | 0 | 0 | 175,885 | **0** | **0** |
| setup before traffic | 11.1 s | **0.8 s** | 27.4 s | **1.5 s** | 6.0 s | 6.2 s | 12.1 s |
| per session | 54.6 ms | **3.4 ms** | 67.9 ms | **3.2 ms** | 29.4 ms | 30.7 ms | 30.0 ms |
| teardown | 9.5 s | **0.9 s** | 20.2 s | **1.7 s** | none | none | none |
| I-frames/s on the wire | 681,434 | 716,169 | 621,487 | 657,404 | 278,578 | 324,388 | 264,852 |
| ack latency p50 / p99 | 2.7 / 6.5 ms | 2.3 / 6.0 ms | 4.5 / 7.9 ms | 4.3 / 7.1 ms | 0.5 / 2.2 ms | 0.4 / 2.3 ms | 0.4 / 2.2 ms |
| outstation CPU while sending | n/a (1) | 4.4 cores | n/a (1) | 4.6 cores | n/a (1) | 2.0 cores | 2.0 cores |
| outstation CPU s, whole bench | 30.6 | **23.7** | 72.5 | **51.1** | 24.6 | 22.1 | 45.9 |
| RSS while sending / peak | n/a (1) / 563 MB | 267 / 571 MB | n/a (1) / 1,127 MB | 451 / 1,138 MB | n/a (1) / 616 MB | 172 / 600 MB | 278 / 1,153 MB |

(1) The /proc sampler matches the process by name and missed the renamed "before" binary; §3 has those figures for the same code (master-200: 4.9 cores, 199 MB; master-400: 5.1 cores, 382 MB; slave-200: 2.3 cores, 135 MB).

Every one of the 12 runs completed with every session, and every one scored `all_correct` at full speed. The extra ~70 MB of RSS while sending is the capture's receive rings (§10.3), 32 MiB per capture socket, mapped up front.

### 10.2 What changed, item by item

1. **Gateway mode in master role is refused** (§7): `scada_gateway_ip`, `scada_gateway_iface` or `upstream_nat_iface` in a master-role benchmark is a 400 `gateway_requires_slave` (POST /api/run, re-run, profiles, `outstation bench`), with a message naming the alternatives; sched refuses it too. `scripts/netns-gateway-egress.sh` now expects it: cases 1 (completes) and 2 (fails) as before, cases 3 to 6 refused before any host change, exit 1 otherwise. Lab guide (en/no), api.md and README updated.
2. **Capture ordering** (§6.3): the capture writer merges its sockets by kernel timestamp (a bounded reorder buffer, k-way by `SO_TIMESTAMP`/ring time, flushed by a watermark: the poll time less 20 ms, lowered to the last timestamp read from any socket that still has frames queued; at most 128 Ki frames, 64 MiB or 500 ms). pcapload additionally keeps a SYN that its flow's SYN-ACK already acknowledged (exact ISN match) in the flow instead of splitting it. Result: 0 "out-of-order timestamps" warnings in the kept master captures (each "before" master run had one) and `all_correct` in 9 of 9 full-speed master runs, against `partial` in 6 of 6 before. Check: `KEEP_CAPTURES=1 scripts/netns-scale.sh master-200`, 3 runs, `all_correct` ×3 (twice: after the ordering fix alone, §10.4, and with everything).
3. **Capture at RT priority again, and through a ring** (§6.4, §6.5): every run's capture reader asks for SCHED_FIFO whatever `realtime` says (it only blocks and drains the run's own frames; losing frames corrupts verdicts). That alone cut the slave-200 drops from 175,885 to 48,357. The reader then got a TPACKET_V3 receive ring per socket (§10.3), and the drops went to 0 in 12 of 12 runs, slave-400 included.
4. **The analysis shows the capture's warnings**: filter fallback, listeners or NICs not recorded, `capture_ok == false`, drops and truncation are copied into the analysis notes and summarised in `run_warning`.
5. **Slave reconnect** (§6.6): a master that closes or resets its connection before STARTDT no longer ends the slave session; the listener stays open until STARTDT and accepts the next master (counted in `protocol.connections_before_startdt`).
6. **Setup and teardown** (§6.6): ports are built by a pool of 8 threads, the session addresses are validated against one snapshot of the host, every session ACCEPT goes in with one journaled `iptables-restore --noflush`, and the capture mirror's tc filters go through one `tc -batch` (every `tc` start dumps all host links: that alone was 5 of the 6.5 s of a 400-session setup with the pool). Teardown deletes ports in parallel and removes the rules in one transaction. Per-session cost is now flat (3.4 ms at 200, 3.2 ms at 400) instead of growing (54.6, 67.9). Fail-closed behaviour and the journal are unchanged: every rule is journaled before it is applied, a failed batch is undone, and only created ports are tracked for teardown.
7. **The master-IP note** compares the full sets of captured and live masters: one rename is named, many-to-one is summarised with every address, and master role without a rename shows no single master.

### 10.3 The capture ring

A `recvmsg` per frame and a 32 MiB socket buffer charged at about 1 KiB per small frame (skb truesize) let the reader fall behind at 300 k frames/s. Each capture socket now maps a TPACKET_V3 ring of 32 blocks of 1 MiB: frames are packed back to back (about 100 bytes for a small IEC 104 frame), the reader takes a whole block per wakeup, and the kernel timestamp comes with every frame. The block timeout is 2 ms, which the reorder hold covers. Without a ring (the kernel refuses one), the socket is read frame by frame as before. Every frame header is bounds-checked against its block before it is read (security review).

Measured in steps on slave-200 (medians of 3, `captured_dropped` / score): before 175,885 / 85.5; RT priority 48,357 / 97.2; RT priority and ring 0 / 100. The ring also lowered the CPU used while sending (master-200: 495 % to 439 %; slave-200: 227 % to 203 %).

One master-400 run of an intermediate build (4 port workers, ring, 2 runs) lost 318 frames on both capture sockets in the same second, which points at a reader stall (the shared disk was 97 % full and busy) rather than at the ring's size; none of the 12 final runs lost a frame.

### 10.4 Intermediate runs

| build | scenario | setup s (ms/session) | teardown s | CPU s | dropped | verdict, score |
|---|---|---|---|---|---|---|
| ordering + RT priority (`10cf14e`) | master-200 | 11.3 (55.8) | 9.6 | 32.3 | 0 | all_correct ×3, 100 |
| ordering + RT priority | slave-200 | 6.5 (32.4) | none | 24.8 | 48,357 | partial ×3, 97.2 |
| + parallel setup, tc per port (`9e64f35`) | master-200 | 2.1 (9.8) | 0.9 | 35.3 | 0 | all_correct ×3, 100 |
| + parallel setup, tc per port | master-400 | 6.5 (15.8) | 1.7 | 94.5 | 0 | all_correct ×3, 100 |
| + ring (`f845c56`) | slave-200 | 6.2 (30.5) | none | 22.6 | 0 | all_correct ×3, 100 |
| + ring | master-200 | 2.1 (9.9) | 0.8 | 32.7 | 0 | all_correct ×3, 100 |

The parallel setup with one `tc` pair per port used more CPU than the serial one (master-400: 94.5 against 72.5 s): eight `tc` processes at a time each dumping 800+ links. The `tc -batch` mirror removed that (51.1 s, and 1.5 s of setup).

### 10.5 Still open

- **Slave-role setup** is unchanged at about 30 ms per listener (alias, journal entry, capture filter update), overlapping with traffic: T17c parallelised master role only.
- **Neighbour table** (§5) and **one CPU for both ends** (§4.5) are limits of this test host, not of outstation.
- **The capture writer runs on the reader thread**: a long write stall (a full or slow disk) still makes the kernel drop frames, and the run then says so (`captured_dropped`, notes, `run_warning`).

Raw numbers: `results.jsonl` of each run in the lane's work directories (`scale-before`, `scale-a`, `scale-b`, `scale-c`, `scale-final`, `scale-final2`); the command lines are those of §8 with `NS_PREFIX=ostest-fx3-scale`.
