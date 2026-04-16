# 165-RTU IEC 104 fleet replay — fidelity and scale demonstration

**Date:** 2026-04-17
**Source pcap:** anonymised real-world IEC 60870-5-104 capture, 222 074 packets, 31.6 MB, 3 minutes 43 seconds wall-clock, 165 distinct RTU servers + 1 master.
**Replay host:** Ubuntu 24.04 VM on Proxmox, 12 GB RAM, 12 vCPU.
**Live target:** vendor IEC 104 master on a separate Windows host, connecting to all 165 replayed RTUs concurrently.
**Result:** `verdict: all_correct, score_pct: 100.0, fully_correct: 165 / 165`.

This report summarises a single benchmark run that exercised outstation's
slave-mode replay against a real third-party IEC 104 master, with a
real-world capture from a production-shaped substation environment.

---

## 1. Headline

| Metric | Value |
|---|---|
| Verdict | **`all_correct`** |
| Aggregate score | **100.0 %** |
| RTUs simulated concurrently | **165** |
| RTUs fully correct | **165 of 165** |
| RTUs partial / failed | **0 / 0** |
| Total I-frames delivered | **151 068 of 151 068** |
| Real protocol mismatches | **0** |
| Total wire packets exchanged | **273 604** |
| Live capture size | **45.7 MB** |
| Run duration (wall clock) | **3 m 43 s** (matches source pcap) |

```json
{
  "verdict": "all_correct",
  "verdict_reason": "all 165 slaves replayed correctly",
  "score_pct": 100.0,
  "fleet": {
    "slave_count": 165, "attempted": 165,
    "fully_correct": 165, "partial": 0, "failed": 0,
    "aggregate_score_pct": 100.0
  }
}
```

---

## 2. Scale on a single host

A single `outstation serve` process — one binary, one systemd unit —
stood up **165 distinct IEC 60870-5-104 server endpoints simultaneously**,
each on its own /32 IP alias on the egress NIC, each listening on the
canonical port 2404, each driven by its own per-RTU TCP session and
IEC 104 state machine.

| What outstation did, in parallel | Count |
|---|---|
| `/32` IP aliases auto-installed on the egress NIC | 165 |
| TCP listeners bound on `<rtu_ip>:2404` | 165 |
| Live IEC 104 sessions accepted from the master | 165 |
| Per-session state machines (APCI / NS / NR / k-window / t1 / t2 / t3) | 165 |
| Per-session latency reservoirs sampled to p50/p90/p99 | 165 |
| Per-session live progress rows in the browser UI | 165 |

Every alias was added at run start and removed at run teardown via
RAII guards backed by a state file on disk for crash-safe reclamation.
No manual `ip addr add`, no per-RTU shell scripting, no leftover
network state after the run.

Average load per session: **~1 658 packets and ~916 I-frames per RTU**
over 3 minutes. The heaviest RTUs:

| RTU | I-frames delivered | Total packets |
|---|---:|---:|
| 192.168.10.73 | 12 005 | 16 686 |
| 192.168.10.4  | 11 181 | 12 211 |
| 192.168.10.45 |  9 423 | 15 476 |
| 192.168.10.62 |  8 086 | 13 938 |
| 192.168.10.30 |  7 477 | 13 621 |

The lightest RTUs delivered as little as a single I-frame each — these
are devices that produce only sporadic spontaneous data in the source
pcap and were correctly mirrored as such, not synthesised into a
busier signal than reality.

---

## 3. Protocol fidelity: zero deviations on 151 068 frames

The post-run analyser walked the live capture flow-by-flow and compared
every I-frame against the corresponding ASDU in the source pcap. The
three-way classification distinguishes byte-identical frames, frames
that differ only in their embedded `CP56Time2a` timestamp (expected when
fresh-timestamps mode is on), and "real" mismatches in the rest of the
ASDU payload.

| Classification | Count | Share |
|---|---:|---:|
| Byte-identical (no timestamp in ASDU type) | 315 | 0.21 % |
| `CP56Time2a`-only (timestamp rewritten as designed) | 150 753 | 99.79 % |
| **Real protocol mismatch** | **0** | **0.00 %** |

For every one of the 151 068 delivered I-frames, every byte outside the
embedded timestamp matched the source pcap exactly. The type-ID
sequence per RTU matched in order, frame for frame. The
fresh-timestamps mode rewrote 150 753 `CP56Time2a` fields to the
wall-clock moment each frame hit the wire, exactly as it was supposed
to.

Per-RTU verdict distribution:

| Verdict | RTUs | Meaning |
|---|---:|---|
| `good_delivery` | 124 | All expected I-frames delivered, master ACKed cleanly |
| `no_iframes_expected` | 41 | Source pcap had a session for this RTU but no I-frames; STARTDT handshake completed and the empty session was correctly mirrored |
| `partial_delivery` | **0** | — |
| `no_delivery` | **0** | — |
| `failed` | **0** | — |

---

## 4. Timing fidelity: ms-precision over a multi-minute run

`Pacing::OriginalTiming` was used — every I-frame emitted at its
original pcap-relative timestamp, preserving the temporal shape of the
captured telemetry feed (the bursts, the long gaps, the outliers).

Worst-case duration drift across the three longest-running RTUs:

| RTU | Original duration | Captured duration | Drift | Drift (% of duration) |
|---|---:|---:|---:|---:|
| 192.168.10.182 | 222 020 ms | 222 201 ms | +180.68 ms | 0.081 % |
| 192.168.10.200 | 222 990 ms | 223 123 ms | +133.27 ms | 0.060 % |
| 192.168.10.14  | 222 010 ms | 222 127 ms | +117.83 ms | 0.053 % |

A 222-second SCADA conversation reproduced with **less than 200 ms of
total wall-clock drift**, on a host running 165 such conversations in
parallel. Inter-frame gap histograms (mean / p50 / p99) on the live
side track the original within sub-millisecond accuracy.

---

## 5. Master IP rewrite handled transparently

The source pcap was captured from a production environment with the
master at `192.168.10.10`. The live test ran against a vendor master
on a different network at `192.168.86.223`. The analyser auto-detected
both IPs and surfaced the rename in the report:

```json
"master_ip_mapping": {
  "captured": "192.168.10.10",
  "live":     "192.168.86.223",
  "renamed":  true
}
```

Per-slave matching anchored on the slave IP (preserved from the source
pcap and re-aliased on the replay host), so the IP rename had no
impact on the comparison — outstation correctly attributed every live
flow to its corresponding RTU in the source despite the master-side
address change.

---

## 6. What "100 %" means here

The aggregate score is not a coincidence of generous bucketing. To hit
`all_correct` on a fleet run, every one of the following must hold for
every attempted RTU:

- TCP three-way handshake completes with the live master.
- IEC 104 STARTDT handshake completes (master sends `STARTDT_act`,
  slave replies `STARTDT_con`).
- Every expected I-frame from the source pcap reaches the wire with
  the correct ASDU type-ID, in the correct sequence position.
- Every delivered I-frame matches the source byte-for-byte outside
  the `CP56Time2a` field.
- The master's `S`-frame and `I`-frame ACKs land within the slave's
  k-window and t1 bounds, keeping the session alive end-to-end.
- The master closes the session cleanly (no RST, no t1 timeout).

For 165 RTUs concurrently, with ~916 I-frames per RTU on average and
the heaviest RTU producing 12 005 I-frames over 3.5 minutes against
the live master's flow control, the run hit zero deviations across
**151 068 frames**.

---

## 7. Reproducibility

1. Upload the source pcap via the web UI's pcap library tab.
2. Configure a slave-role benchmark with `Pacing::OriginalTiming` and
   the live master pointed at the replay host's egress IP via a
   static route to the captured RTU subnet.
3. Generate the live master's RTU connection list directly from the
   source pcap (one entry per detected slave IP).
4. Start the run from the UI; click "Start All Slaves" once the
   warmup window opens; the live master dials all 165 endpoints.
5. Capture the live wire side from the master host.
6. Upload the capture to the analyser endpoint to produce the
   structured fleet report shown above.

---

## 8. Source data

- Source pcap: 33 MB, 222 074 packets, 165 RTU servers + 1 master,
  3 m 43 s wall-clock.
- Live capture: 45.7 MB, 273 604 packets, taken on the master host.
- Analyser output: structured JSON, ~40 MB pretty-printed (full
  per-slave drill-down).
- All artefacts anonymised — IPs, MACs, IEC 104 common addresses, and
  IEC 104 information object addresses are randomised but
  topologically consistent.
