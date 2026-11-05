# Audit fix plan

This plan tracks the fixes for the 2026-11-05 multi-agent audit: 152 findings (`F000`–`F151`) plus the 12 findings of the pcap-ingestion lane (`P01`–`P12`). The full report and the finding index live outside the repo, in the session scratchpad: `outstation-audit-report.md`, `findings_index.txt` and `findings.json`.

**Process.** All work happens on branch `audit-fixes`. Each lane works in its own git worktree on `audit/<lane>`, with one commit per logical fix that names the finding IDs it closes. Lanes are merged into `audit-fixes`, which must pass `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` before the plan box is ticked. `audit-fixes` is pushed to origin after each merge.

**Decisions (user, 2026-11-05):**
- The UI keeps binding 0.0.0.0 and has no authentication. Concurrent use is handled by telling users: a second run gets a 409 that names who started the active run and when, and every connected UI shows a banner when someone else starts or stops a run.
- Same-origin and Host checks are added. They are not authentication; they block cross-site and DNS-rebinding drive-bys. An env var or flag is provided for extra allowed hosts.
- Scope covers every defect plus the product features (bench CLI, run profiles and re-run, auto-analysis, run compare, command echo, fault injection, health and metrics, UI restructure). IEC 62351 TLS, redundancy groups and reconnect storms are out of scope unless requested later.
- Privileged validation uses sudo, but only inside dedicated network namespaces (`ip netns`), never against the host's real NICs.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done (merged into `audit-fixes`, CI-green).

---

## Wave 0: groundwork

- [x] **T00 CI and toolchain truth.** Add a GitHub Actions workflow (fmt, clippy `-D warnings`, test, MSRV job, cargo-deny/audit, `node --check` on the extracted SPA JS). Set the real MSRV in `Cargo.toml` and the README badge. Clear the existing clippy warnings. Refs: F084, F085, F134, F080 (CI half).

## Wave 1: parallel lanes, disjoint files

- [x] **T01 pcap ingestion** (`crates/pcapload`, `crates/tcp_session`). Refs: P01–P12.
  - Sequence-number wraparound (P01).
  - Gap-tolerant reassembly that reports gaps instead of bailing (P02, library part).
  - Strip 802.1Q/ad/QinQ tags; normalise SLL, SLL2 and raw-IP link types; count and report IPv6 and ignored packets (P03).
  - `saturating_sub` on timestamps, relative to the minimum timestamp (P04).
  - Split connections on SYN reuse (P05).
  - Make the ingest O(n) (P06).
  - Shared-buffer packet storage, about 1× memory (P07).
  - Tolerate a truncated tail and keep the error text (P08).
  - Detect IP fragments and validate `data_off` (P10).
  - Anchor at ISN+1 (P11).
  - Reset pcapng sections (P12).
  - Fix the stale header comment. Remove the dead `tcp_session` crate, or fix its timeouts.
- [x] **T02 IEC 104 core: framing and ASDU layer** (`proto_iec104/src/{lib,apdu,asdu,inventory,responder}.rs` + new `apci.rs`). Refs: F011, F014, F015, F016, F019, F020, F021, F022, F081, F083, P09.
  - One `apci::frames()` iterator with resync, used by `count_iframes`, `extract_message_times_ns`, the picker and the inventory.
  - Fix the `element_len` table, with a table test.
  - Monitor-type-only inventory with timed→untimed type mapping.
  - CA-filtered GI/CI that fans out on 0xFFFF and returns a negative ActCon for an unknown CA or unsupported QOI/QCC.
  - Handle FRZ bits.
  - Surface cp56 config errors, and fix the TZ-vs-SU decode.
  - Single-bit U-frame validation; replace `remove(0)` in the resync with a proper buffer.
  - Sum `per_rtu_bytes` across flows instead of overwriting (P02, consumer part).
- [x] **T03 Host safety and scheduler** (`crates/netctl`, `crates/sched`, `crates/raw_replay`). Refs: F026, F028, F030 (sched part), F031, F032, F033, F034, F035, F038, F039, F040, F041, F043, F045, F047, F075, F137 (library part), P02 (`seen` ordering in `sched:1300`), P04 (raw pacing guard).
  - Derive bridge and tap names from the run id. `reclaim_stale` deletes only interfaces marked as ours.
  - Refuse the default-route NIC, the NIC carrying the request's local address, real bridges (fix `is_bridge`) and existing bridge ports.
  - /32 `noprefixroute` aliases; distinguish Added from AlreadyPresent, with refcounts.
  - Locked, path-configurable alias state file that is not truncated when a delete fails.
  - Persisted guard journal (iptables comments plus sysctl/offload snapshots) with `netctl::cleanup_all()`.
  - Fail-closed EgressGuard.
  - `finalize_latency()` with one reservoir across iterations.
  - Cancellable sleeps everywhere.
  - Shared epoch and Barrier for raw replay.
  - SCHED_FIFO policy: cap at cores−1, no FIFO with top-speed, no spin for gaps over 1 ms.
  - Join and tear down on spawn failure; no `expect()` in spawn paths.
  - Correct sent and progress counters.
- [x] **T04 webui backend: split, then fix** (`crates/webui/src/{lib,db}.rs` → modules, `crates/outstation/src/main.rs`, `systemd/`). Refs: F027, F029, F036, F037, F042, F044, F046, F048, F049, F050, F051, F052, F053, F054, F055, F056, F057, F071, F072, F073, F074, F076, F077, F078, F079, F086, F087, F088 (backend), F089, F090, F091, F092, F094, F101 (backend), F108 (backend), F132, F133, F146, F148, F149, F151.
  - Split `lib.rs` into `routes/`, `dto`, `persist`, `library`, `netprobe` and `runs` modules.
  - Single-active-run lock. A 409 names the active run, client IP and start time. Broadcast an event channel (SSE or WS) for run started/stopped, which the UI shows as a banner.
  - Validate the request, then allocate the run id. `catch_unwind` around workers; stop and delete can finalize a run with no worker; final status derived from session errors.
  - Same-origin and Host middleware (non-GET requests and WS upgrades), with `--allow-host`.
  - Library-id-only pcap references (no raw paths).
  - `spawn_blocking` and streamed downloads.
  - Streamed `/api/analyze` upload to a temp file with cleanup; disk-space and size quotas; a concurrency limit.
  - Captures under the state dir, with retention and a byte cap.
  - DB: `user_version` migration ladder, skip and log bad rows, AUTOINCREMENT ids, `finished_at` on orphans, `#[serde(default)]` on report structs, fail-or-`--ephemeral` instead of a silent `:memory:` fallback.
  - Slim `/api/runs` summary plus `/api/runs/:id` detail plus `?status=running`.
  - Weighted, pre-binned aggregate latency histogram.
  - Fix the throughput counter.
  - `.part` cleanup at startup and on error; rename-id validation; RFC 6266 `Content-Disposition`.
  - Library delete warns about and lists dependent runs (409 unless `force`).
  - Accept `run_id` from the query string as well as the multipart field.
  - Reject stub protocols; add a `/api/protocols`-driven selector.
  - `parking_lot` or poison-tolerant locks, plus `CatchPanicLayer`.
  - Graceful SIGTERM/SIGINT: cancel runs, join workers, run `cleanup_all`.
  - `outstation cleanup` subcommand.
  - Unit `ExecStartPre`/`ExecStopPost`, `TimeoutStopSec`, extra hardening.
  - Fix `install.sh`.
  - Real `/api/status` health (DB writable, free disk, capabilities, active guards).
  - Plain-text logs under journald; run-id tracing spans.

- [x] **T04b Integration of T03 and T04** (orchestrator, after both merge).
  - `host_cleanup()` → `netctl::cleanup_all(state_dir)`, wired to SIGTERM, `outstation cleanup` and ExecStopPost.
  - `api_run` fills `protected_addrs` for RunConfig and BenchmarkConfig with the request's local socket address (ConnectInfo / the bound listener address), from a security review.
  - Thread the `force` override through RunReq with a UI confirmation.

- [ ] **T04c Leftovers from wave 1.**
  - Per-run capture size cap while writing: a hook in sched/raw_replay capture (F055/F149 remainder). Until then, a low-disk watchdog stops the run.
  - The UI must expose `alias_iface` and `force` (with a confirmation dialog), or slave runs with non-local RTU IPs fail. Owned by T07.
  - curl/script clients now need an `Origin` header for POST/DELETE/PATCH; document this in the README and smoke scripts (T15, T16).

## Wave 2: depends on wave 1

- [x] **T05 IEC 104 session state machine** (`proto_iec104/src/session.rs`). Refs: F000, F001, F002, F003, F004, F005, F006, F008, F009, F010, F013, F017, F018, F023, F024, F025, F140, F141, F142, F143, F144, F145, F147, F150.
  - One `wait_until(deadline)` helper that services rx, t1, t2 (S-frame) and t3 (TESTFR).
  - Configurable k/w/t0–t3 via `proto_config`.
  - Started/Stopped/PendingStop states with STARTDT/STOPDT con replies and gated sends; S-flush before STOPDT.
  - Check N(S) against V(R) and N(R) against V(S), and report protocol errors.
  - Ack timestamps taken in the reader thread.
  - GI/CI response queue drained from every wait loop, within k, plus an idle-serve phase after the script ends.
  - Strip captured GI bursts when synthesis is on, and tag synthesized frames.
  - Inventory built from rewritten, resynced frames.
  - `early_break` on send error; idle-serve when the script is empty.
  - `shutdown(Both)` RAII guard and a joined reader.
  - Mock-peer tests for the slave and master paths, TESTFR, STOPDT, wraparound, misbehaving peers and GI timing. Port the scratch probes.
- [x] **T06 Fidelity analysis** (`proto_iec104/src/analysis.rs`, `webui/src/analysis.rs`). Refs: F012, F058, F059, F060, F061, F062, F063, F064, F065, F066, F067, F068 (report half), F069, F093 (backend), F136.
  - Symmetric or synthesized-only GI filter.
  - Content-based score: byte-identical plus CP56-only, with `real_mismatch_count==0` required.
  - Clamp the score; per-iteration and stopped-tail verdicts.
  - `no_reference`, `never_connected` and `unpaired` verdicts. The run's selected RTUs are authoritative.
  - Analyse all TCP sessions per RTU.
  - Myers/Hirschberg alignment.
  - Verdict includes CP56 tolerance, the GI/CI audit and timing.
  - Timing stats exclude synthesized frames; honest speed labels.
  - Paginated or lazy per-RTU detail, with the report persisted to the DB.
  - Run-status check: refuse or warn when the run failed or sent nothing.
  - Table-driven verdict and rollup tests. Adopt the T02 frame iterator.
- [x] **T07 Frontend fixes and SPA split** (`webui/src/index.html` → `webui/src/ui/*.{css,js}` spliced by `build.rs`, `proto_iec104/static/iec104_ui.js`). Refs: F088 (frontend), F095, F096, F097, F098, F099, F100 (rename half), F102, F103, F104, F105, F106, F107, F109, F110, F111, F112, F113, F114, F115, F116, F117, F118, F119, F120, F121, F122, F123, F124, F125, F126.
  - Split the SPA into modules.
  - Block START on invalid JSON; pre-flight validation with inline errors.
  - Fix the stuck ANALYZING panel.
  - Persist the picker selection; add filter, sort and shift-range to the picker.
  - Fix the dropzone layout; make the main flow keyboard-operable.
  - `api()` error handling; poller resilience with a real connection indicator; one poller using the slim endpoint.
  - WebSocket in-flight guard.
  - Keyed DOM updates (no innerHTML wipe).
  - Surface errors from mutating calls.
  - Gap-histogram backoff.
  - Lazy drill-downs; revoke blob URLs.
  - Library names in run cards.
  - Scalable run cards (summary plus filter plus sort).
  - Diagram that scales to 200 RTUs, with a legend and a text alternative.
  - Labels, `aria-live` regions, focus preservation.
  - Phone layout; type scale and AA contrast.
  - Consistent buttons and focus rings.
  - Fix the µs label.
  - Concurrent-run banner, using the T04 event channel.

- [x] **T07b Backend issues found by the frontend lane.**
  1. Slave listen IPs in 127.0.0.0/8 are treated as non-local and aliased; all of 127/8 is local on Linux.
  2. `per_source_progress` has no per-session failure reason.
  3. Stopping a slave run counts pending sessions as failed.
  4. Stale `listen_port_base + n − 1 ≤ 65535` check, although every slave shares one port on its own IP.
  5. Analysing a run that sent 0 messages gives a `partial` verdict rather than a clear failure or inconclusive result.

- [x] **T12b Fault and command caveats** (from the T11/T12 lane).
  - With `return_info` on, captured COT 11/12 return-information frames are still replayed next to the live ones; strip them when echo plus return info is on.
  - GI after a command with return info can be judged non-compliant, because the analyzer's inventory comes from the capture. Track the command-updated values in the audit.

## Wave 3: product features

- [x] **T08 Run profiles, re-run and auto-analysis.** Persist the full RunRequest. Add "Re-run" and "Load config", with config kept in the URL and local storage. Run analysis automatically when a run ends, and add an explicit run picker for manual analysis. Refs: F100, F108, F131 (part); product items #3 and #4.
- [x] **T09 Headless bench CLI.** `outstation bench --profile run.json --assert score>=99 --assert p99_ms<=500 --report out.json`. It runs, captures, analyses its own mirror and exits non-zero on failure. Refs: F131; product item #2.
- [x] **T10 Run-to-run compare.** `/api/runs/:a/compare/:b` returns per-RTU score, delivered and latency deltas, with a UI view. Product item #5.
- [x] **T11 Responder command echo.** C_SC/C_DC/C_RC/C_SE/C_BO → ActCon/ActTerm plus optional return information; C_CS clock sync; C_RD read. Add command→ActCon/ActTerm timing metrics. Refs: F009 (metric), F139; product item #7.
- [x] **T12 Fault injection (FaultPlan).** In `proto_config`: withhold acks, drop or duplicate N%, corrupt N(S), TESTFR silence, RST at time T, delay. Refs: F139; product item #8.
- [x] **T13 Health and metrics.** Prometheus `/metrics` (runs, sessions, frames, latency histograms, guard state) and a degraded-health banner in the UI. Product item #9.
- [x] **T14 UI restructure** (folded into T07, so the frontend is reworked only once). Library / Configure / Runs / Analysis / Compare views with navigation. IEC 104 role and pacing settings move out from behind the benchmark checkbox. Refs: F127.

- [x] **T18 Slave-mode capture.** Slave runs (the main "test a SCADA master" scenario) have no mirror capture, so auto-analysis and `bench` score assertions cannot cover them. Capture the RTU listen-IP traffic on the alias NIC with a BPF filter limited to the run's listen IPs and port, store it like the other captures, and enable auto-analysis and bench scoring for slave runs.
- [x] **T19 UI for the wave-3 features.**
  - Re-run and "Load config" from a run, plus named profiles (save, load, delete).
  - Compare view with a run picker, regression highlighting and thresholds; when an analysis is missing, POST `/api/runs/:id/analyze` and retry.
  - Auto-analysis state on run cards; SSE `analysis_finished` and `analysis_failed` trigger a refresh.
  - Command and fault report sections (`commands[]`, `negative_confirmations`, `faults_injected`, `fault_reaction`, the analyzer's `faults` dimension), plus configuration editors for `commands` and `faults` under advanced IEC 104.
  - Health detail from `degraded_detail`, and a link to `/metrics`.

- [~] **T18b Root-cause the flaky slave LAN e2e test.** It failed 1 in 11 runs, right after the bench suite.

## Wave 4: docs, privileged validation, final audit

- [x] **T15 Docs truth pass.**
  - README: the timers, the scale claim backed by a measured sizing benchmark, the safety and LAN-exposure guidance, capture locations, the API (`run_id`) and the new features.
  - Rewrite `doc/scada-lab.en.md` and `doc/scada-lab.md`.
  - Fix `doc/adding-a-protocol.md`.
  - Annotate `fidelity_report_run2.md`.
  - Refs: F007, F068, F128, F129, F130, F133, F135, F138; product items #1, #6 and #10.
- [x] **T16 Privileged netns smoke suite.** `scripts/netns-smoke.sh` runs with sudo inside dedicated namespaces. It covers slave and master runs against a mock peer, concurrent-run rejection, SIGTERM mid-run cleanup, crash reclaim, a pre-existing alias that survives teardown, and refusal of the default-route NIC. It replaces `smoke_v12.sh`, `test_capture.sh` and `test_run_api.sh`. Refs: F080, F084 (e2e half).
- [ ] **T16b Bugs found by the smoke suite.**
  - B1: the raw mirror capture records each flooded frame once per run port (`mirror_port` mirrors ingress and egress on every port), and at top speed with many sources it drops some frames.
  - B2: `collect_capture` reads its counters before `stop()`, so `captured_packets` can be lower than the file.
  - O1: an unbounded master run with original pacing reconnects 8–12 times a second on short captures; an iteration should last the capture's span divided by speed.
  - O2: inject ports send IGMPv3 reports onto the LAN with the RTU's MAC.
  - O3: a run stopped by SIGTERM is never auto-analysed, neither at shutdown nor after a restart.
- [ ] **T17 Final verification.** Run the full test, clippy and CI suite; live-UI Playwright pass (Chromium and WebKit, desktop and phone); a 200-RTU load run inside the netns, recording CPU, RSS, fds and msg/s; a re-audit of the diff against this plan. Every finding ID is accounted for (fixed, or won't-fix with a reason) in the table below.

---

## Finding → task map

F000 T05 · F001 T05 · F002 T05 · F003 T05 · F004 T05 · F005 T05 · F006 T05 · F007 T15 · F008 T05 · F009 T05/T11 · F010 T05 · F011 T02 · F012 T06 · F013 T05 · F014 T02 · F015 T02 · F016 T02 · F017 T02 (done early) · F018 T05 · F019 T02 · F020 T02 · F021 T02 · F022 T02 · F023 T05 · F024 T05 · F025 T05 · F026 T03 · F027 T04 · F028 T03 · F029 T04 · F030 T03/T04 · F031 T03 · F032 T03 · F033 T03 · F034 T03 · F035 T03 · F036 T04 · F037 T04 · F038 T03 · F039 T03 · F040 T03 · F041 T03 · F042 T04 · F043 T03 · F044 T04 · F045 T03 · F046 T04 · F047 T03 · F048 T04 · F049 T04 · F050 T04 · F051 T04 · F052 T04 · F053 T04 · F054 T04 · F055 T04 · F056 T04 · F057 T04 · F058 T06 · F059 T06 · F060 T06 · F061 T06 · F062 T06 · F063 T06 · F064 T06 · F065 T06 · F066 T06 · F067 T06 · F068 T06/T15 · F069 T06 · F070 T04 · F071 T04 · F072 T04 · F073 T04 · F074 T04 · F075 T03 · F076 T04 · F077 T04 · F078 T04 · F079 T04 · F080 T00/T16 · F081 T02 · F082 T04/T05 (tests) · F083 T02 · F084 T00/T16 · F085 T00 · F086 T04 · F087 T04 · F088 T04/T07 · F089 T04 · F090 T04 · F091 T04 · F092 T04 · F093 T06/T08 · F094 T04 · F095 T07 · F096 T07 · F097 T07 · F098 T07 · F099 T07 · F100 T07/T08 · F101 T04/T07 · F102 T07 · F103 T07 · F104 T07 · F105 T07 · F106 T07 · F107 T07 · F108 T04/T08 · F109 T07 · F110 T07 · F111 T07 · F112 T07 · F113 T07 · F114 T07 · F115 T07 · F116 T07 · F117 T07 · F118 T07 · F119 T07 · F120 T07 · F121 T07 · F122 T07 · F123 T07 · F124 T07 · F125 T07 · F126 T07 · F127 T14 · F128 T15 · F129 T15 · F130 T15 · F131 T08/T09 · F132 T04 · F133 T04/T15 · F134 T00 · F135 T15 · F136 T04/T06 · F137 T03/T04 · F138 T15 · F139 T11/T12 · F140 T05 · F141 T05 · F142 T05 · F143 T05 · F144 T05 · F145 T05 · F146 T04 · F147 T05 · F148 T04 · F149 T04 · F150 T05 · F151 T04 · P01–P12 T01 (P02 consumer parts in T02/T03, P04 raw-pacing guard in T03, P09 in T02)

## Progress log

- 2026-11-05: Plan written. Branch `audit-fixes` created from `4c9a2d4`.
- 2026-11-05: T00 done.
  - Added `.github/workflows/ci.yml` (fmt, clippy `-D warnings`, test, MSRV 1.85, SPA JS syntax check, rustsec audit).
  - MSRV corrected from 1.75 to 1.85 (verified with `cargo +1.85 check`).
  - Cleared all ~45 clippy warnings.
  - `clippy.toml` pins the clippy MSRV and sets the argument-count threshold.
- 2026-11-05: Wave 1 started. T01–T04 run in parallel worktrees (`/opt/code/outstation-wt/{pcap,iec104-core,host-sched,webui-backend}`), on branches `audit/<lane>`.
- 2026-11-05: T06 (analysis) started early in `/opt/code/outstation-wt/analysis`, because it touches only the two analysis.rs files.
- 2026-11-05: T02 merged (`3bec39b`). Workspace tests: 119 passed.
  - Added a shared `apci` frame walker, fixed the element sizes, made GI/CI CA-aware, added negative ActCon and FRZ handling, and made CP56 decode TZ-correct.
  - One T05 item was done early: the session builds its inventory from rewritten, resynced frames (F017). Without it, the new CA filter would reject every GI when a CA rewrite map is set.
  - Remaining for others: T06 adopts `apci` and `respond_*().per_ca` in analysis.rs; T05 needs the frame-boundary check on the live `ApduReader`.
- 2026-11-05: T01 merged. Workspace tests: 149 passed.
  - P01–P12 fixed, except that P07 is partly fixed: RSS went from 2.9× to about 2× the file size, and the remainder is per-packet metadata.
  - Removed the dead `tcp_session` crate.
  - Gap-tolerant reassembly records gaps (`StreamGap`). Consumers must reframe at gap offsets; T05 does this for the session replay path.
- 2026-11-05: T03 merged. Workspace tests: 204 passed. T03 is complete except F028, which is partly fixed: the session-internal waits went to T05.
  - Run-id-derived names and the ifalias ownership marker.
  - NIC and address protection.
  - /32 noprefixroute aliases with refcounts.
  - A locked, atomic state journal and `netctl::cleanup_all`.
  - Fail-closed guards.
  - A latency reservoir across iterations.
  - Cancellable sleeps and a shared epoch.
  - The SCHED_FIFO policy.
  - Six netns tests, run with `scripts/netns-test.sh`.
- 2026-11-05: Security-review follow-ups.
  - The port-IP exemption is limited to the run's own interfaces, not any `pcr*` interface.
  - Captures no longer read or migrate from world-writable /tmp, and downloads are confined to `captures_dir`.
- 2026-11-05: T04 merged together with the T04b integration. Workspace tests: 247 passed.
  - Single-run 409 with the client IP, plus an SSE `/api/events` feed.
  - Host/Origin guard.
  - Library-id-only pcap references.
  - Streamed I/O and durable captures.
  - DB migrations and id integrity.
  - Graceful shutdown, which calls `netctl::cleanup_all`.
  - The local request address goes into `protected_addrs`.
  - Partly fixed: F055/F149 (no per-run capture size cap yet; tracked in T04c) and F133 (docs part moved to T15).
- 2026-11-05: T07 started, with T14 folded in, in `/opt/code/outstation-wt/frontend`. T06 finished its first pass and is now adapting to T04's split and to T05's GI-burst stripping.
- 2026-11-05: T06 merged. Workspace tests: 293 passed.
  - Content-based scoring with Myers alignment over masked hashes.
  - Per-iteration and per-session verdicts.
  - New `never_connected`, `unpaired`, `no_reference` and `run_failed` verdicts.
  - Verdict dimensions, honest speed labels and bounded detail.
  - DB schema v3 persists analyses, with lazy per-endpoint detail routes.
  - The shared `interrogation` module defines the captured GI/CI burst rule and the `gi_ci_synthesis` switch.
  - Partly fixed: F060 and F066. They need the run's `loop_within_session`, `paced_speed` and `source_port`, which T08 will persist.
  - Expected interim gap until T05 merges: with synthesis on, the analyzer expects stripped bursts, but the current replayer still sends them.
- 2026-11-05: Backend halves of T08, T09, T10 and T13 started in `/opt/code/outstation-wt/features`. The UI halves follow after T07 merges.
- 2026-11-05: T05 merged. Workspace tests: 315 passed.
  - New `link.rs` engine with t1, t2 and t3, transfer state, sequence validation and reader timestamps.
  - GI/CI answers sent promptly, within k, with flood caps.
  - Burst stripping uses the shared rule.
  - Every exit sends FIN.
  - Mock-peer tests.
  - F009 is partly fixed: the metric is documented as ack latency and a command-response metric was added, but the peer's ack cadence is not recorded.
  - Orchestrator change: slave idle-serve defaults to 30 s, so runs still finish on their own.
  - New report fields for the UI: `protocol_violations`, `protocol_errors`, `stripped_capture_frames`, `synthesized_frames`, `idle_serve_ms`, `command_response_us`, `acks_sent` and `keepalives_sent`.
- 2026-11-05: T11 and T12 started in `/opt/code/outstation-wt/proto-features`.
- 2026-11-05: T07 and T14 merged. Workspace tests: 316 passed.
  - The SPA is split into `ui/*.css` and `ui/*.js`, spliced by build.rs.
  - Library, Configure, Runs and Analysis views with hash routing.
  - A single poller, the SSE banner, keyed DOM updates, a scalable diagram and run cards.
  - Accessibility: labels, live regions, contrast and a 12px minimum.
  - IEC 104 link parameters, plus the force/alias_iface flow with a confirmation dialog.
  - `scripts/ui-smoke.mjs` passes all checks in Chromium (1440 and 390) and WebKit (1440), re-run by the orchestrator against a fresh release build.
  - Partly fixed: F100 (re-run and URL state go to T08) and F101 (relies on the server's 409).
  - Five backend issues logged as T07b.
- 2026-11-05: Security review (HIGH) on the features lane's netctl change (inject-side IPs and a hub bridge). Isolation sysctls, raw/FORWARD drop rules and netns tests were sent back to the features lane; to be verified at its merge.
- 2026-11-05: T11 and T12 merged. Workspace tests: 350 passed; the suite ran 3 times with no flakes after fixing a racy upload test.
  - Command echo: SbO, set-points, clock sync, read, test and reset, with return info and negative COTs.
  - Per-type command ActCon and ActTerm latency in both roles.
  - A FaultPlan with ten fault kinds, peer-reaction detection and a `faults` verdict dimension.
  - Two minor caveats logged as T12b.
- 2026-11-05: T08, T09, T10 and T13 (backends) merged. Workspace tests: 384 passed.
  - Run requests persisted, plus re-run, profiles and auto-analysis.
  - The `outstation bench` CLI with assertions and exit codes.
  - Compare: GET is read-only; on-demand analysis is a POST.
  - `/metrics` and `degraded_detail`.
  - The e2e test found two existing bugs, both fixed: master-role sessions could never connect, and the mirror capture missed unicast traffic.
  - Host isolation for run interfaces: per-interface sysctls, tagged raw/FORWARD DROP rules, and capture via tc mirred instead of hub mode.
- 2026-11-05: Orchestrator security fixes.
  - Session ACCEPT narrowed to the target's TCP source port.
  - Isolation rules kept when interface teardown is incomplete.
  - Privileged suites: `netns-test.sh` 7/7, `netns-bench-test.sh` 3/3; host interface and iptables counts unchanged.
- 2026-11-05: T12b merged. Workspace tests: 389 passed. Captured COT 11 frames are stripped when return info is synthesized, and the GI audit follows command-driven inventory changes.
- 2026-11-05: New tasks.
  - T18: slave runs have no mirror capture (an existing gap).
  - T19: UI for the wave-3 features.
- 2026-11-05: Started backend2 (T07b, T18) and ui2 (T19) in parallel.
- 2026-11-05: T07b and T18 merged. Workspace tests: 404 passed.
  - 127/8 counts as local.
  - Per-session failure reasons.
  - Stopped sessions are cancelled, not failed.
  - Stale port check removed.
  - A run that delivered nothing gets `run_failed` with a score of 0.
  - Slave runs now capture through a kernel-BPF-filtered AF_PACKET socket on the RTU-IP and master-route interfaces, so auto-analysis and bench scoring work in slave role.
  - Privileged suites rerun by the orchestrator: netns-test 7/7, netns-bench-test 3/3, netns-slave-test 2/2 on 10 of 11 runs. The one flaky failure, right after the bench suite, went back to the lane for a root cause (T18b). Host interface and iptables counts unchanged.
- 2026-11-05: T15 (docs) and T16 (privileged HTTP smoke suite) started in parallel with T19 (UI) and T18b (flake).
- 2026-11-05: T19 merged. Workspace tests: 405 passed.
  - Re-run and "Load into Configure", with force always re-confirmed.
  - Profiles CRUD.
  - Compare view with an analysis_missing → analyze → retry flow.
  - Auto-analysis state, plus SSE-driven refresh.
  - Command and fault-plan editors, and reports.
  - `degraded_detail` health banner and a /metrics link.
  - ui-smoke: 203 checks pass in Chromium 1440/390 and WebKit 1440.
  - With this, T08 and T10 are complete.
- 2026-11-05: Orchestrator: IEC 104 `proto_config` is validated at submit through `ProtoReplayer::validate_config`, returning 400 `invalid_proto_config`.
- 2026-11-05: Orchestrator fixed a race found by a flaky test: the single-run slot was released after the terminal status became visible, giving a spurious 409. A too-tight timing assertion in raw_replay was also relaxed. The full suite then passed 4 runs in a row (406 tests). Note: commit 804c131 was pushed after a red test run; the cause was this race, now fixed.
- 2026-11-05: T15 merged.
  - README truth pass: conformance from link.rs, an honest Scale section, safety and LAN exposure, the new features. Old screenshots removed (T17 refreshes them).
  - New `doc/api.md`, `doc/iec104-config.md` and `doc/operations.md`.
  - Lab guide rewritten around the two scenarios, in English and Norwegian.
  - `adding-a-protocol.md` fixed; errata and caveats added to the reports.
  - The orchestrator reconciled the docs with T19, fixed the `cleanup --help` text and re-ran the link check (0 problems).
  - Left for T17 to measure: max throughput, CPU and memory per session, per-session setup time, and gateway mode with an egress NIC.
- 2026-11-05: T16 merged.
  - `scripts/netns-smoke.sh` drives the real `serve` over HTTP across 4 namespaces, covering 10 cases including SIGTERM, SIGKILL + `cleanup`, and restart persistence, with full host-state diffing in the namespace.
  - Two runs: 9 PASS + 1 XFAIL each.
  - Stale root scripts removed.
  - Raw-capture bugs and behaviour issues logged as T16b.
