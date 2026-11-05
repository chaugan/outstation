# IEC 104 configuration and reports

This page covers everything specific to the IEC 60870-5-104 replayer (`proto_iec104`):

- the `proto_config` settings of a benchmark run;
- what the link engine does on the wire;
- the per-session counters in a run report;
- the analysis report, its verdicts and its verdict dimensions.

The code is the reference. The relevant files are [`asdu.rs`](../crates/proto_iec104/src/asdu.rs) (`Iec104ProtoConfig`, rewrite map, CP56), [`link.rs`](../crates/proto_iec104/src/link.rs) (timers and windows), [`interrogation.rs`](../crates/proto_iec104/src/interrogation.rs), [`responder.rs`](../crates/proto_iec104/src/responder.rs), [`commands.rs`](../crates/proto_iec104/src/commands.rs), [`faults.rs`](../crates/proto_iec104/src/faults.rs) and [`analysis.rs`](../crates/proto_iec104/src/analysis.rs).

## Contents

- [`proto_config` at a glance](#proto_config-at-a-glance)
- [Rewrite map](#rewrite-map)
- [`cp56`: fresh timestamps](#cp56-fresh-timestamps)
- [`session`: link parameters](#session-link-parameters)
- [What the link engine does](#what-the-link-engine-does)
- [`gi_ci_synthesis`: live GI and CI answers](#gi_ci_synthesis-live-gi-and-ci-answers)
- [`commands`: command echo](#commands-command-echo)
- [`faults` and `fault_seed`: fault injection](#faults-and-fault_seed-fault-injection)
- [Session report fields](#session-report-fields)
- [Analysis report](#analysis-report)

## `proto_config` at a glance

`proto_config` is a field of the [run request](api.md#the-run-request). It holds a **JSON string**; inside it is one object:

```json
{
  "common_address": {"1": 100},
  "cot": {},
  "ioa": {"1001": 2001},
  "cp56": {"rewrite_to_now": true, "zone": "local"},
  "session": {"k": 12, "w": 8, "t0": 30, "t1": 15, "t2": 10, "t3": 20, "idle_serve_secs": 30},
  "gi_ci_synthesis": true,
  "commands": {"enabled": true, "return_info": "none", "max_age_ms": 10000, "unknown_ioa": "negative"},
  "fault_seed": 42,
  "faults": [{"at": {"ms": 5000}, "kind": "withhold_acks", "duration_ms": 20000}]
}
```

Every key is optional. An absent, empty, `null` or `{}` config means the defaults.

In a run request it is embedded as a string:

```json
{"mode": "benchmark", "role": "slave", "proto_config": "{\"session\":{\"t3\":30},\"commands\":{\"return_info\":\"retrem\"}}", …}
```

**Validation.** `POST /api/run` checks only that `proto_config` is valid JSON. The IEC 104 rules below are applied when the sessions start. A bad value (out of range, a typo inside `cp56`, `session` or `commands`, an unknown fault kind) fails every session with a `proto_config (…)` error, and the run ends `failed`. Unknown keys at the top level are ignored. The UI's IEC 104 form builds `cp56`, `session` and `gi_ci_synthesis` for you; `commands` and `faults` are entered as JSON.

| Key | Roles | Default |
|---|---|---|
| `common_address`, `cot`, `ioa` | both | no rewrite |
| `cp56` | both | no rewrite, local zone |
| `session` | both (`idle_serve_secs`: slave) | k=12, w=8, t1=15, t2=10, t3=20 |
| `gi_ci_synthesis` | slave | `true` |
| `commands` | slave | enabled |
| `faults`, `fault_seed` | both | none |

## Rewrite map

Top-level `common_address`, `cot` and `ioa` objects map captured values to new ones. Keys are strings (JSON requires it) holding decimal numbers; values are numbers.

| Key | Key range | Value range |
|---|---|---|
| `common_address` | 0..65535 | 0..65535 |
| `cot` | 0..255 | 0..255 (the full COT octet) |
| `ioa` | 0..16777215 | 0..16777215 |

IOAs are 3 octets on the wire. Larger numbers are not rejected; only their low 24 bits are written.

Every replayed ASDU is rewritten before it is sent. Values not in a map are left alone. The slave's point inventory (for GI, CI and commands) is built from the rewritten frames, so a live master interrogates the new addresses. The analyzer applies the same map to the expected side.

## `cp56`: fresh timestamps

| Field | Default | Meaning |
|---|---|---|
| `rewrite_to_now` (alias `rewrite_cp56_to_now`) | `false` | Rewrite every CP56Time2a in outgoing ASDUs to the wall-clock moment the frame is sent. The IV (invalid) bit is kept from the source |
| `zone` (alias `cp56_zone`) | `"local"` | `"local"`: local time, SU bit set during summer time. `"utc"`: UTC, SU = 0 |

Unknown keys and other zones are errors. With rewriting on, the analyzer accepts a CP56-only difference when the stamp is within the drift tolerance of the actual send time (default 50 ms, `cp56_tolerance_ms` on upload). With rewriting off, any change to a time tag is a mismatch.

## `session`: link parameters

| Field | Default | Range | Meaning |
|---|---|---|---|
| `k` | 12 | 1..32767 | Most unacknowledged I-frames we send before waiting |
| `w` | 8 | 1..32767 | We acknowledge at the latest after w received I-frames |
| `t0` | see below | > 0, ≤ 86400 s | Master role: TCP connect timeout |
| `t1` | 15 | > 0, ≤ 86400 s | An I-frame, STARTDT/STOPDT act or TESTFR act not acknowledged or confirmed within t1 closes the connection |
| `t2` | 10 | > 0, < t1 | Received I-frames are acknowledged (S-frame) at the latest t2 after the first unacknowledged one |
| `t3` | 20 | > 0, ≤ 86400 s | After t3 without receiving anything we send TESTFR act |
| `idle_serve_secs` | 30 | ≥ 0 | Slave role: keep serving the master (GI/CI, commands, TESTFR, acks) this long after the script ends, unless the master closes first or the run is stopped |

Timers are seconds and may be fractional. `t2 >= t1` is an error. A `w` above two thirds of `k` is allowed but logged as a warning (IEC 60870-5-104 §5.5 recommends w ≤ 2k/3). `w` and `t2` here govern how fast *we* acknowledge; the latency we measure depends on the *peer's* `w` and `t2` ([Session report fields](#session-report-fields)).

**t0 default.** When `t0` is absent the run's connect timeout is used, which is **5 s**, not the IEC default of 30 s. Set `t0` explicitly for slow targets. In slave role t0 is not used: an armed listener waits up to 600 s for the master to connect, then up to 60 s for STARTDT act. Both limits are fixed.

To impersonate an RTU that never hangs up, set a large `idle_serve_secs` or use `iterations: 0` with `loop_within_session`.

## What the link engine does

One engine ([`link.rs`](../crates/proto_iec104/src/link.rs)) runs both roles. While it waits for anything (a pacing deadline, a free k-window slot, an acknowledgement, a STARTDT or STOPDT confirmation) it keeps serving the peer.

Implemented:

- **APCI framing.** A strict reader: a bad start octet, a bad length or an invalid control field is a protocol violation and closes the connection. U-frames must be one of the six single-function codes.
- **Sequence numbers.** Live N(S)/N(R), modulo 2^15. Every received N(S) is checked against V(R) and every received N(R) against the unacknowledged window up to V(S). A violation is recorded and closes the connection.
- **k and w.** We never have more than k unacknowledged I-frames out; we acknowledge after w received I-frames. Outgoing I-frames also carry the current N(R).
- **t1, t2, t3** as in the table above. TESTFR act from the peer is answered with TESTFR con.
- **STARTDT and STOPDT.**
  - Master: connect, STARTDT act, wait for con within t1, run the script, wait for acknowledgements, flush an S-frame, STOPDT act, wait for con, close.
  - Slave: accept, wait for STARTDT act and confirm it, run the script. A STOPDT act from the master is confirmed once our outstanding I-frames are acknowledged, and sending stops until the next STARTDT.
- **Teardown.** Every exit shuts the socket down in both directions (the peer sees FIN) and joins the reader thread.
- **Command timing.** Command round trips are measured per command type in both roles.
- **Receive timestamps.** Taken in the reader thread, so latency does not include our own scheduling delay.

Protocol errors are recorded in the session report with one of these kinds: `ns_mismatch`, `nr_out_of_window`, `malformed_frame`, `unexpected_u_frame`, `t1_timeout`.

Not implemented:

- IEC 62351 (TLS, authentication);
- redundancy groups (IEC 104 Edition 2 standby connections) and automatic reconnects;
- configurable ASDU field sizes: COT is 2 octets, common address 2, IOA 3, as IEC 104 fixes them;
- IPv6;
- in master role we do not answer commands or interrogations: the captured master traffic is replayed and the live slave's confirmations are measured;
- the post-run analyzer does not judge the peer's t1/t2/t3 behaviour from the capture. Timer expiries and sequence errors seen live are in the session report (`protocol_violations`).

## `gi_ci_synthesis`: live GI and CI answers

Slave role. Default `true`; only an explicit `false` turns it off.

When on, the slave answers the live master's General Interrogation (`C_IC_NA_1`, type 100) and Counter Interrogation (`C_CI_NA_1`, type 101) itself, from a per-RTU point inventory built from the captured (rewritten) server-side frames:

- **Inventory.** Each monitor-direction point (type IDs 1..21 and 30..40) seen in the capture, with its latest value and the GI groups (COT 21..36) and CI groups (COT 38..41) it was seen in. Command mirrors, end of initialisation and confirmations are never points.
- **Answer.** ActCon (COT 7) → data frames with COT 20+group (GI) or 37+group (CI) → ActTerm (COT 10). Time-tagged points are sent in their untimed form. Protection events (17..19, 38..40) are never interrogated; integrated totals (15, 16, 37) answer CI only. ASDUs are packed to fit the 253-octet APDU.
- **Addressing.** Answers are filtered by the request's common address. CA 0xFFFF (broadcast) is answered once per known station. An unknown CA gets a negative reply with COT 46. An unsupported qualifier (QOI outside 20..36, QCC request outside 1..5) gets a negative ActCon. QCC freeze or reset is confirmed with ActCon → ActTerm and no data.
- **Limits.** At most 8 interrogations are answered at once, and the response queue holds at most 4096 ASDUs; further requests get a negative confirmation or are dropped and recorded.
- **Script.** The captured interrogation exchanges (type 100/101 confirmations and every ASDU with COT 20..41) are removed from the replayed script, so the master does not get stale or unsolicited answers. `stripped_capture_frames` counts them.

When off, the captured interrogation bursts are replayed where they were recorded and live interrogations get no answer.

## `commands`: command echo

Slave role. The slave answers the live master's control-direction commands the way a real outstation would.

| Field | Default | Values |
|---|---|---|
| `enabled` | `true` | Answer commands |
| `return_info` | `"none"` | `"none"`, `"spontaneous"` (monitor update with COT 3) or `"retrem"` (COT 11) after an executed command |
| `max_age_ms` | 10000 | Time-tagged commands whose CP56Time2a differs from our clock by more are rejected; 0 disables the check; at most 86400000 |
| `unknown_ioa` | `"negative"` | `"negative"`: COT 47 for a process command at an IOA the capture never showed; `"accept"`: answer as if it were known |

Unknown keys are errors.

| Command | Answer |
|---|---|
| C_SC, C_DC, C_RC (45..47), C_SE_NA/NB/NC (48..50), C_BO (51), and the time-tagged 58..64, select (S/E = 1) | ActCon |
| the same, execute (S/E = 0; C_BO has no S/E) | ActCon, optional return information, ActTerm |
| the same, COT 8 (deactivate) | DeactCon (COT 9) |
| C_RD_NA_1 (102) read | The point's current value with COT 5 |
| C_CS_NA_1 (103) clock sync | ActCon with the time echoed |
| C_RP_NA_1 (105) reset process, C_TS_TA_1 (107) test | ActCon |

Rejections mirror the command with P/N = 1: unknown type → COT 44; a COT the type does not take → COT 45; unknown CA → COT 46; unknown IOA → COT 47; a time tag outside `max_age_ms`, a not-permitted double or regulating state, or a malformed ASDU → negative ActCon (or DeactCon).

An IOA is known when the capture shows the RTU confirming a command there, or carries a monitor point there. Return information is sent only when the inventory has a matching monitor point that can carry the commanded value; that point's value is then updated, so later GI and read answers show it.

With echo on, captured command confirmations are removed from the script. With `return_info` other than `"none"`, captured COT 11 return information is removed as well (COT 12, a local operation, is kept).

## `faults` and `fault_seed`: fault injection

A per-session plan of deliberate misbehaviour, to see how the peer reacts. Both roles.

```json
{
  "fault_seed": 42,
  "faults": [
    {"at": {"ms": 5000},   "kind": "withhold_acks",     "duration_ms": 20000},
    {"at": {"frame": 120}, "kind": "drop_iframes",      "pct": 10, "duration_ms": 2000},
    {"at": {"ms": 30000},  "kind": "rst"}
  ]
}
```

- `at.ms` counts from the moment the TCP connection is established (0..86400000). `at.frame` fires just before the N-th I-frame we send (0-based; replayed, synthesized and dropped frames all count). Give exactly one of the two.
- `fault_seed` (a non-negative integer, default `0x1EC10400`) seeds the dice behind the percentage faults, so a plan is reproducible frame for frame.
- At most 256 faults. Parsing is strict: unknown kinds, unknown or missing keys and out-of-range values are errors.

| Kind | Parameters | Effect |
|---|---|---|
| `withhold_acks` | `duration_ms` | No S-frames, and our I-frames repeat the last N(R) already sent, so the peer's t1 runs out |
| `drop_iframes` | `pct`, `duration_ms` | Each outgoing I-frame is dropped with probability `pct`; its N(S) is used up, so the next frame is out of sequence at the peer |
| `duplicate_iframes` | `pct`, `duration_ms` | Each outgoing I-frame is sent twice with the same N(S), with probability `pct` |
| `corrupt_ns` | `count` | The next `count` I-frames carry a wrong N(S) (V(S) + 16384); V(S) itself advances normally |
| `testfr_silence` | `duration_ms` | TESTFR act is neither answered nor sent |
| `delay` | `ms`, `duration_ms` | Every outgoing I-frame is held `ms` longer |
| `rst` | none | Abortive close (RST); the session ends |
| `stopdt` | none | Master: STOPDT act, then STARTDT act once confirmed. Slave: an unsolicited STOPDT act (a controlled station must not send one) |
| `malformed_apdu` | `count` | `count` APDUs with an invalid length octet |
| `slow_ack` | `extra_ms`, optional `duration_ms` | Every acknowledgement goes out `extra_ms` late; without `duration_ms`, until the session ends |

Ranges: `duration_ms` 1..86400000; `pct` greater than 0, up to 100; `count` 1..1000; `ms` and `extra_ms` 1..600000.

The analyzer does not count deliberate faults as replay infidelity: duplicates are removed from the delivered side, dropped frames are excused, a session the peer ended in reaction is judged like a stopped run, and timing is not judged. The `faults` verdict dimension summarises what the capture shows.

## Session report fields

Each session of a benchmark run (`benchmark.per_session[]` in `GET /api/runs/:id`, `sessions[]` in a `bench` report) carries a `protocol` object:

| Field | Meaning |
|---|---|
| `protocol_violations` | Peer violations plus timer expiries, all counted |
| `protocol_errors[]` | `{at_ms, kind, detail, fatal}` for the first violations; `kind` as listed [above](#what-the-link-engine-does) |
| `synthesized_frames` | Data frames we generated (GI/CI and command answers); included in `messages_sent` |
| `stripped_capture_frames` | Captured frames left out of the script because we answer live instead |
| `command_response_count`, `command_response_p50_us`, `command_response_max_us` | Slave: time from receiving a command or interrogation to our first answer |
| `capture_gaps`, `script_skipped_bytes`, `script_dropped_frames` | Gaps in the captured stream, bytes that did not frame, frames dropped because they straddled a gap |
| `idle_serve_ms` | Slave: time spent serving after the script ended |
| `acks_sent`, `keepalives_sent` | S-frames and TESTFR acts we sent |

The engine also records, per session, per-command-type round trips (`commands[]`: `{type_id, commands, act_con, negative, act_term, deact_con, unanswered, actcon_us[], actterm_us[]}`), `negative_confirmations[]`, `faults_injected[]` (`{at_ms, kind, detail, frames_affected}`) and `fault_reaction` (`{peer_closed, peer_reset, peer_stopdt, protocol_errors[], first_reaction_ms, summary}`). All four appear in each session's `protocol` object in `GET /api/runs/:id` and in the `bench` JSON report; the analyzer's `faults` section additionally judges the fault side from the capture.

Latency (`latency_*_us`) is the time from sending an I-frame to the peer acknowledging it (the S-frame or I-frame N(R) that covers it, timestamped on receipt). It is not a command round trip.

**Ack latency is bounded by the peer's w and t2, not the network.** The peer acknowledges on its own schedule: after it has received `w` I-frames, or `t2` after the first unacknowledged one, whichever comes first (the `w` and `t2` that matter are the peer's, not the ones in `session` above). In slave role the live master sends few or no I-frames of its own, so it acknowledges with S-frames by that rule: with sparse telemetry the latency approaches the master's t2 (often 10 s), with dense telemetry it is the time `w` frames take to go out. Read slave-role latency as the master's acknowledgement policy, and compare runs only against the same master settings. In master role an RTU that sends data carries N(R) in its own I-frames and so usually acknowledges sooner.

## Analysis report

The analyzer compares a capture of a run against the run's source pcap, endpoint by endpoint. It runs automatically after every benchmark run with a capture, on demand, or on an uploaded capture (see [the API](api.md#analysis)).

### Which endpoints are judged

The run's selected endpoints (RTUs in slave role, masters in master role) are authoritative:

- a selected endpoint with no captured session is `never_connected`, a failure;
- captured traffic on the run's port that matches no selected endpoint is listed as `unpaired` and not scored;
- every captured TCP session of an endpoint is analysed; the endpoint gets its worst session's verdict, and reconnects are counted.

### Fleet

Top level of the report: `run_id`, `run_status`, `run_warning`, `mode` (`generic` or `correct`), `role`, `protocol`, `original_pcap`, `captured_size_bytes`, `captured_total_packets`, `verdict`, `verdict_reason`, `score_pct`, `notes[]`, `fleet`, `slaves[]`, `master_ip_mapping`, `fleet_drift_timeline`, `fleet_pacing_timeline`.

`fleet`: `slave_count`, `attempted`, `never_connected`, `unpaired`, `inconclusive`, `fully_correct`, `partial`, `failed`, `reconnects`, `aggregate_score_pct` (mean over scored endpoints), `frame_weighted_score_pct` (weighted by expected frames), `best`, `worst`.

| Fleet verdict | When |
|---|---|
| `all_correct` | Every judged endpoint passed, and the run was not stopped |
| `stopped_clean` | The run was stopped before it finished, and everything it sent before the stop was clean. `run_warning` says it was stopped. A stopped run is never `all_correct` |
| `partial` | Some passed, some failed |
| `failed` | Every judged endpoint failed with score 0 |
| `inconclusive` | Nothing failed, but some endpoints could not be verified |
| `no_delivery` | No judged endpoint has a captured session |
| `no_session` | No endpoint to judge |
| `run_failed` | The run itself failed or sent nothing (`run_warning` says why); a run that delivered nothing scores 0 |

`slaves[]` (one row per endpoint, also in master role, where `slave_ip` holds the master's IP): `slave_ip`, `score_pct`, `verdict`, `verdict_reason`, `outcome` (`pass`, `fail` or `inconclusive`), `expected_iframes`, `delivered_iframes`, `packets`, `startdt_handshake_ok`, `sessions`, `reconnects`.

### Endpoint verdicts

| Verdict | Outcome | When |
|---|---|---|
| `good_delivery` | pass | Everything passes (generic mode) |
| `identical` | pass | Everything passes, including the target's script (correct mode) |
| `stopped_clean` | pass | The run was stopped, and every frame sent before that was clean. An endpoint whose own session failed is never excused by the stop: its missing frames count as a failure |
| `no_iframes_expected` | pass | The source carries no I-frames and none were delivered |
| `degraded` | fail | Content is fine, but time tags, the GI/CI audit or timing failed |
| `partial_delivery` | fail | Modified, missing, extra or reordered frames, or time tags changed with CP56 rewriting off |
| `no_delivery` | fail | Frames expected, none delivered |
| `handshake_incomplete` | fail | Content is fine but no STARTDT handshake (score capped at 50) |
| `target_silent`, `divergent_script`, `subset_script`, `structurally_identical`, `partial` | fail | Correct mode: the target's replies deviate |
| `missing_sessions` | fail | Fewer captured sessions than configured iterations |
| `never_connected` | fail | Selected but never captured |
| `no_reference` | inconclusive | No source flow, the source did not parse, or frames delivered against a source with none |
| `stopped_before_delivery` | inconclusive | Stopped before the first frame |
| `unpaired` | not judged | Captured, but not one of the run's endpoints |

### Score

The score is content fidelity: (byte-identical frames + accepted CP56-only differences) / (expected + extra), clamped to 0..100. Delivered frames are aligned to the expected script with a Myers diff over content hashes (CP56 bytes masked), so one lost frame costs one frame, not the rest of the session. In correct mode the score is the mean of the playback and target scores. Loop runs are judged per iteration, with a stopped tail when the run was stopped.

The expected side leaves out what the slave answers live (captured interrogation exchanges, command confirmations, remote return information). The delivered side leaves out our synthesized GI/CI and command answers and deliberate fault duplicates.

### Verdict dimensions

`protocol_specific.verdict_dimensions` explains why an endpoint passed or failed. The verdict passes only when every judged dimension does.

| Dimension | Passes when |
|---|---|
| `content` | No modified, missing, extra or reordered frames, and no changed time tags with rewriting off |
| `time_tags` | No CP56 stamp outside the drift tolerance |
| `gi_ci` | Every live interrogation exchange is compliant (see below) |
| `timing` | The largest pacing drift stayed within max(1000 ms, 5 % of the captured span divided by the speed factor); `null` when the run was not paced at original timing |
| `handshake` | STARTDT completed |
| `target` | Correct mode only: the target's script matches; otherwise `null` |
| `faults` | Not pass/fail: a summary of the injected faults and the peer's reaction, or `null` |

### Protocol-specific sections

`protocol_specific` holds, per endpoint:

- `playback`: expected, delivered and script counts, `content_score_pct`, byte-identical, modified, missing, extra and reordered counts, `real_mismatch_count`, bounded `mismatches[]` (each with `kind`: missing, extra, modified or reordered), per-iteration results, the stopped tail, type-ID sequences (capped at 2000) and `*_type_id_counts`, plus what was excluded: `synthesized_excluded`, `source_interrogation_stripped`, `command_echo`, `source_command_stripped`, `command_responses_excluded`, `source_return_info_stripped`, `fault_dropped_excused`, `fault_duplicates_excluded`;
- `target`: the peer's U, S and I frame counts, U-codes seen, STARTDT detection and, in correct mode, the target-script comparison;
- `timing`: original vs captured duration, `speedup_factor`, `speed_label` ("matched" within ±5 %, else "N.NN× faster" or "slower"), gap statistics, drift and `timing_failure`;
- `cp56_drift`: with rewriting on, each stamp against its send time: mean, max, out-of-tolerance count, IV and SU flags;
- `gi_ci_audit`: counts of compliant, partial and non-compliant GI and CI exchanges, and per event: ActCon present and within 15 s, ActTerm present and within 10 s of the last data frame, every data frame in the right COT group, correct P/N polarity, and data byte-identical to the inventory-derived answer;
- `faults`: `configured`, `kinds[]`, `seed`, `dropped_ns`, `duplicates`, `corrupted_ns`, `malformed_bytes`, `stopdt_sent`, `first_fault_ms`, `peer_stopdt`, `peer_frames_after_first_fault`, `session_end_after_first_fault_ms`, `summary`;
- `verdict_dimensions`, as above.
