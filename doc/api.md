# HTTP API reference

`outstation serve` exposes one HTTP API. The browser UI uses it, and so can scripts and CI jobs. Everything here comes from the router in [`crates/webui/src/lib.rs`](../crates/webui/src/lib.rs) and the handlers under [`crates/webui/src/routes/`](../crates/webui/src/routes/).

There is **no authentication**. Read [Safety](../README.md#safety) before exposing the port on a network.

## Contents

- [Conventions](#conventions)
- [The Host and Origin rule](#the-host-and-origin-rule)
- [Errors](#errors)
- [Server](#server): status, metrics, protocols, events
- [Library](#library): pcap upload, list, rename, delete, download, inspect
- [Runs](#runs): start, list, detail, stop, re-run, delete, live progress, capture, gaps
- [Slave controls](#slave-controls)
- [Profiles](#profiles)
- [Analysis](#analysis)
- [Compare](#compare)
- [Network helpers](#network-helpers): NICs, ARP, IP check
- [The run request](#the-run-request)

## Conventions

- Bodies are JSON (`Content-Type: application/json`) unless a route says multipart.
- Times are Unix seconds (`started_at`, `finished_at`, `created_at`), except `uploaded_at_ms` and the `*_unix_ms` library fields, which are milliseconds.
- Latencies are microseconds (`*_us`).
- Ids are integers, except library pcap ids, which are strings like `pcr_1793882398548649944`.
- The examples assume the server at `http://127.0.0.1:8080` and set `B=http://127.0.0.1:8080`.

## The Host and Origin rule

Every request passes a same-origin guard ([`security.rs`](../crates/webui/src/security.rs)). It blocks DNS rebinding and cross-site requests from a browser. It is not authentication.

1. **Host.** The `Host` header must be an IP literal, `localhost`, one of this machine's host names (kernel host name, `hostname.domainname`, resolver canonical name), or a name allowed with `serve --allow-host NAME` or `OUTSTATION_ALLOW_HOSTS=name1,name2`. Otherwise: 403 `host_not_allowed` (no header at all: 403 `host_missing`).
2. **Origin.** Every request that is not `GET`, `HEAD` or `OPTIONS`, and every WebSocket upgrade, must carry an `Origin` whose `host[:port]` equals the `Host` header (case-insensitive). A browser sends it on its own. When there is no `Origin`, `Sec-Fetch-Site: same-origin` is accepted instead.
   - A different origin: 403 `cross_origin`.
   - Neither header: 403 `origin_required`.

**Scripts must send `Origin` on every POST, PUT, PATCH and DELETE.** Copy the scheme, host and port you put in the URL:

```sh
B=http://127.0.0.1:8080
curl -X POST -H "Origin: $B" "$B/api/runs/7/stop"
```

`curl http://127.0.0.1:8080/...` sends `Host: 127.0.0.1:8080`, so the matching origin is `http://127.0.0.1:8080`. Behind a reverse proxy, the proxy must pass the original `Host` and `Origin` through, and its public name must be allowed with `--allow-host`.

Plain `GET` requests need no `Origin`. That is why `GET /api/runs/:a/compare/:b` never writes anything: an analysis it needs is started with a POST.

## Errors

Every error has the same JSON shape, sometimes with extra fields:

```json
{"error": "human-readable message", "code": "machine_code"}
```

| Status | `code` | When |
|---|---|---|
| 400 | `bad_request` | Generic bad input (bad IP, bad multipart field, …) |
| 400 | `invalid_request` | The body failed validation (range, missing field, bad JSON in `proto_config`) |
| 400 | `invalid_json` | The body is not JSON |
| 415 | `unsupported_media_type` | A JSON route without `Content-Type: application/json` |
| 422 | `invalid_request` | A JSON field with the wrong type or an unknown enum value (`"role": "boss"`) |
| 400 | `invalid_path`, `invalid_query` | A path or query parameter does not parse |
| 400 | `invalid_id` | Not a library pcap id |
| 400 | `raw_path_rejected` | A raw filesystem path (`pcap`, `path`) instead of a library id |
| 400 | `protocol_not_ready` | A benchmark with a stub protocol |
| 400 | `pcap_unreadable`, `not_a_pcap` | The pcap does not load, or the upload is not a pcap |
| 400 | `not_benchmark` | Analysis or compare on a raw-replay run |
| 403 | `host_missing`, `host_not_allowed`, `cross_origin`, `origin_required` | [Host and Origin rule](#the-host-and-origin-rule) |
| 404 | `not_found` | Unknown run, analysis, profile, pcap or route |
| 404 | `capture_missing`, `file_missing` | The capture or file is not on disk (never written, or evicted) |
| 404 | `source_pcap_missing` | The run's source pcap was deleted from the library |
| 409 | `run_active` | A run is already active. Extra fields: `active_run_id`, `client_ip`, `started_at` |
| 409 | `run_running` | Delete, analyse or compare on a run that is still running |
| 409 | `run_finished` | A slave control on a finished run |
| 409 | `pcap_in_use` | Deleting a pcap that runs still use. Extra field: `runs` (ids) |
| 409 | `request_missing` | Re-run of a run recorded before run requests were stored |
| 409 | `profile_exists` | A profile with that name exists |
| 409 | `capture_missing` | `POST /api/runs/:id/analyze` and the run has no capture |
| 409 | `capture_unavailable` | `POST /api/runs/:id/analyze` and the run's capture failed (see the run's `warnings`) |
| 409 | `analysis_missing` | Compare and a run has no stored analysis. Extra fields: `run_id`, `has_capture` |
| 413 | `too_large` | Upload above the size cap |
| 429 | `busy` | Too many heavy requests at once (analysis, upload, gap histogram); retry |
| 500 | `internal` | Server error, including a caught handler panic |
| 503 | `shutting_down` | The server is stopping |
| 503 | `db_unavailable` | The run could not be recorded in the database |
| 507 | `disk_full` | Free space in the state directory would drop below the reserve |
| 507 | `write_failed` | Writing the upload failed |

Multipart uploads that break off can also return `upload_aborted` with the status the multipart reader reported.

## Server

### `GET /`

The single-page UI. `GET /echarts.min.js` serves the embedded chart library.

### `GET /api/status`

Health. Fields:

| Field | Meaning |
|---|---|
| `ok` | `true` when `degraded` is empty |
| `version`, `uptime_secs` | Build version, seconds since start |
| `db` | `{path, ephemeral, writable, error}` |
| `state_dir`, `library_dir`, `captures_dir` | Where data lives (see [operations](operations.md#state-directory)) |
| `free_disk_bytes`, `min_free_bytes` | Free space in the state directory and the configured reserve |
| `capabilities` | `{cap_eff, net_admin, net_raw, net_bind_service, sys_nice}` of the process |
| `active_run` | `{run_id, client_ip, started_at}` or `null` |
| `shutting_down` | `true` after SIGTERM |
| `degraded` | Human-readable reasons |
| `degraded_detail` | `[{code, message}]`, codes listed in [operations](operations.md#health-and-metrics) |
| `journal_pending` | `{guards, aliases, error}`: host-state journal entries not yet undone |
| `auto_analyze` | Whether finished benchmark runs are analysed automatically |

### `GET /metrics`

Prometheus text format. The metric names are listed in [operations](operations.md#health-and-metrics).

### `GET /api/protocols`

```json
[{"name":"iec104","status":"ready","ports":[2404]},
 {"name":"modbus_tcp","status":"stub","ports":[502]}, …]
```

`status` is `ready` or `stub`. Stub protocols cannot run benchmarks (400 `protocol_not_ready`). The UI builds its protocol selector from this list.

### `GET /api/events`

Server-sent events about the run lifecycle. On connect the stream sends one `hello` event:

```
event: hello
data: {"type":"hello","active":{"run_id":1,"client_ip":"127.0.0.1","started_at":1793882409}}
```

`active` is `null` when no run is active. After that, one event per change:

| Event | When | `status` |
|---|---|---|
| `run_started` | A run was started | `running` |
| `run_stopped` | Someone asked a run to stop | `stopping` |
| `run_finished` | A run reached a final state | `completed`, `partial`, `stopped` or `failed` |
| `analysis_finished` | Auto-analysis of a run stored its result | the fleet verdict |
| `analysis_failed` | Auto-analysis failed | `failed` |

Each data object is `{"type", "run_id", "client_ip", "client_id", "time", "status"}`. `client_ip` is the client that started the run (for `run_stopped`, the client that asked to stop it). `client_id` echoes the optional `X-Client-Id` header (up to 64 printable characters) of the request that caused the event; the UI sends a per-tab id so it can tell its own actions from someone else's. A keep-alive comment arrives every 15 s.

```sh
curl -N "$B/api/events"
```

## Library

Pcaps are referenced by library id everywhere. Raw filesystem paths are refused.

### `GET /api/pcaps`

Library entries, newest first:

| Field | Meaning |
|---|---|
| `id`, `name` | Library id and display name (the uploaded file name) |
| `uploaded_at_ms`, `size_bytes` | Upload time, file size |
| `packets`, `ip_sources`, `non_ip_sources`, `tcp_flows`, `duration_ms` | Parsed summary (0 while the background parse runs) |
| `pcap_start_unix_ms`, `pcap_end_unix_ms`, `mac_collisions` | Capture time span, sources sharing a MAC |
| `viability` | `null` while parsing; then `{verdict, verdict_reason, notes[], sessions_master_mode, sessions_slave_mode, client_payload_bytes, server_payload_bytes, estimated_peak_mb, slave_rtus[], master_clients[]}`. `verdict` is `ok`, `caution`, `heavy` or `not_recommended`. `slave_rtus` and `master_clients` are `[{ip, payload_bytes, messages, duration_ms}]` and feed the RTU picker |

Viability is computed by the IEC 104 replayer for every upload (see [adding a protocol](adding-a-protocol.md#what-is-still-iec-104-specific)).

### `POST /api/pcaps` (multipart)

Upload one file in the first multipart part. Returns the new entry with `viability: null`; the full parse runs in the background and the list shows the result when it is done. Errors: 413 `too_large` (`--max-upload-mb`), 507 `disk_full`, 400 `not_a_pcap`, 429 `busy`.

```sh
curl -H "Origin: $B" -F file=@capture.pcapng "$B/api/pcaps"
```

### `PATCH /api/pcaps/:id`

Rename: `{"name": "…"}` (1 to 256 printable characters). Returns the entry.

### `DELETE /api/pcaps/:id[?force=1]`

204. While runs still reference the pcap: 409 `pcap_in_use` with `runs: [ids]`, because their gap histograms and analysis need the source. `?force=1` (or `true`, `yes`) deletes anyway.

### `GET /api/pcaps/:id/download`

Streams the pcap with its library name as the file name.

### `POST /api/inspect`

`{"pcap_id": "…"}`. Parses the pcap and returns `{packets, duration_ms, sources[], non_ip_sources[], tcp_flows[]}`:

- `sources`: `{src_ip, src_mac, packet_count, byte_count, flow_count, mac_collision}`;
- `non_ip_sources`: `{src_mac, packet_count, byte_count, ethertypes[]}`;
- `tcp_flows`: `{client, server, packets, state}`, where `state` lists `SYN`, `SYN-ACK`, `FIN`, `RST` as seen.

## Runs

Only one run can be active at a time. A second start gets 409 `run_active`, which names who started the active run and when.

### `POST /api/run`

Start a run. The body is a [run request](#the-run-request). Returns `{"id": N}`.

```sh
curl -H "Origin: $B" -H 'Content-Type: application/json' "$B/api/run" -d '{
  "pcap_id": "pcr_1793882398548649944",
  "mode": "benchmark", "role": "slave",
  "target_ip": "10.0.0.50",
  "alias_iface": "eth1",
  "pacing": "original", "speed": 1.0
}'
```

The request is validated completely before a run id is allocated. A rejected request leaves nothing behind.

### `GET /api/runs[?status=S][&limit=N][&before=ID]`

Slim summaries, newest first, one page at a time. `S` is one of `running`, `completed`, `partial`, `stopped`, `failed`; any other value is 400. `limit` is the page size (default 100, at most 1000); `before` returns only runs with a smaller id. When older runs exist, the response carries the headers `X-Next-Before: <id>` (pass it as `before` for the next page) and `X-Has-More: true`. The newest runs come from memory (`--runs-in-memory`, default 500 finished runs); older pages, and `GET /api/runs/:id` of an older run, are read from the database. Each row:

- identity and request echo: `id, status, started_at, finished_at, started_by, pcap, pcap_id, target_ip, target_mac, speed, top_speed, realtime, error, mode, role, target_port, proto`;
- progress: `planned, sent, bytes_progress, throughput_history` (messages or frames per second, last 120 s);
- counts: `sources, sources_failed, sources_cancelled, has_capture`;
- `report` (raw runs): `{total_packets, total_bytes, total_errors, capture_path, captured_packets, captured_bytes, captured_dropped}`;
- `report` and `benchmark` both also carry `warnings[]` (non-fatal problems: capture failures, a truncated capture, guard restore or teardown errors) and `capture_ok` (false when a requested capture failed or holds no frame although frames were sent; absent in rows that predate it); the detail also has `capture_truncated`;
- `source_states`: session count by state (`pending`, `listening`, `active`, `failed`, …). `per_source_progress` is always empty in the list: live rows come from `GET /api/runs/:id` and the run's WebSocket;
- `benchmark` (benchmark runs): `{total_messages_sent, total_messages_received, aggregate_latency_{min,p50,p90,p99,max}_us, aggregate_throughput_msgs_per_sec, capture_path, captured_packets, captured_bytes, captured_dropped, sessions, sessions_failed, sessions_cancelled, protocol_violations}`. `captured_dropped` counts frames the kernel dropped from the capture socket (it should be 0; non-zero adds a run warning and an analysis note that "missing" frames may be capture loss);
- `rerun_of`, `latest_analysis` (`{id, verdict, score, source, created_at}` or `null`), `auto_analysis` (`{state, error, analysis_id}` or `null`; `state` is `queued`, `running`, `done`, `failed` or `skipped`).

Run status values: `running`, `completed`, `partial` (some but not all sessions failed), `stopped`, `failed`.

### `GET /api/runs/:id`

The full run: everything in the summary plus

- `request`: the canonical run request, with defaults filled in (use it for "load config");
- `proto_config`, `capture_file`, `has_capture`;
- `per_source_progress`: per session `{src_ip, src_mac, tap, planned, sent, bytes, received, unacked, listen_port, listen_ip, state, ready, cancelled, iter_current, iter_total, error}`. `state` is `pending`, `listening`, `connected`, `active`, `completed`, `failed` or `cancelled`;
- `report.per_source[]` (raw runs): `{src_ip, src_mac, tap, kind, sent, bytes, send_errors, elapsed_ms, mean_jitter_us, p99_jitter_us}`;
- `benchmark.per_session[]` (benchmark runs): `{src_ip, src_mac, tap, connected, messages_sent, messages_received, bytes_written, bytes_read, elapsed_ms, latency_{min,p50,p90,p99,max}_us, throughput_msgs_per_sec, window_stalls, unacked_at_end, error, cancelled, latency_histogram, protocol}`. `protocol` holds the IEC 104 session counters described in [IEC 104 configuration](iec104-config.md#session-report-fields);
- `benchmark.aggregate_latency_histogram` and each session's `latency_histogram`: `{log10_min_us: 1, log10_max_us: 7, counts[24], underflow, overflow, total}`, 24 log-spaced bins from 10 µs to 10 s.

### `POST /api/runs/:id/stop`

Asks the run to stop. 202 `{id, status: "running"}` while it winds down; 200 with the final status when it has already finished. A run marked running without a live worker is finalised as stopped on the spot (200).

### `POST /api/runs/:id/rerun[?force=true]`

Starts a new run with the stored request of run `:id`. Returns `{id, rerun_of, request}`. Same validation and 409 rules as `POST /api/run`. `force` is never copied from the old run: pass `?force=true` to confirm it again. Old runs without a stored request give 409 `request_missing`.

### `DELETE /api/runs/:id`

204. Removes the run, its stored analyses and its capture. 409 `run_running` while the run's worker is alive; stop it first.

### `GET /api/runs/:id/live` (WebSocket)

Progress stream, one JSON text frame every 200 ms until the run ends (one final frame is sent in the terminal state). The upgrade request must carry `Origin`.

```json
{"run_id":3,"status":"running","mode":"benchmark","role":"slave","planned":1200,"sent":480,"bytes":51234,
 "pps_sent":12,"pps_recv":3,
 "per_session":[{"src_ip":"192.168.10.2","src_mac":"02:00:00:00:00:02","listen_ip":"192.168.10.2","cancelled":false,
                 "state":"active","planned":88,"sent":40,"received":9,"unacked":2,
                 "listen_port":2404,"pps_sent":1,"pps_recv":1,"iter_current":1,"iter_total":1}]}
```

Rates are messages per second over a 1.5 s window. A failed session also has `error`. The stream ends at once when the client sends a Close frame or the connection drops. The web UI feeds the running run's card from this stream and polls `GET /api/runs` only every 4 s while it is fresh.

### `GET /api/runs/:id/download`

Streams the run's capture as `run_<id>.pcap`. 404 `capture_missing` when there is none (never written, or evicted by retention).

### `GET /api/runs/:id/gaps`

Inter-packet gap histograms of the source pcap and the capture: `{buckets_ns[21], original[20], captured[20], pcap_id, run_id}`, 20 log-spaced buckets from 1 µs to 10 s. Needs both files on disk (404 otherwise). Heavy (429 `busy`).

## Slave controls

For a running slave-role benchmark. `:idx` is the session's position in `per_source_progress`. A finished run gives 409 `run_finished`.

| Route | Effect |
|---|---|
| `POST /api/runs/:id/slaves/:idx/start` | Arm one pending listener (202) |
| `POST /api/runs/:id/slaves/start_all` | Arm every pending listener. Returns `{started, total}` |
| `POST /api/runs/:id/slaves/:idx/stop` | Cancel one session (202) |
| `PATCH /api/runs/:id/slaves/:idx` | `{"listen_ip": "a.b.c.d"}`: change a pending listener's IP before it starts (202) |

Slave listeners start in `pending` and bind only once armed, so you can attach a capture or change listen IPs first.

```sh
curl -X POST -H "Origin: $B" "$B/api/runs/3/slaves/start_all"
```

## Profiles

A profile is a named [run request](#the-run-request): `{id, name, request, created_at, updated_at}`. The request is validated like a run request except that `pcap_id` is optional, and it is stored in canonical form. `outstation bench --profile` accepts a profile file as well.

| Route | Result |
|---|---|
| `GET /api/profiles` | All profiles, sorted by name |
| `POST /api/profiles` `{name, request}` | 201 with the profile; 409 `profile_exists` |
| `GET /api/profiles/:id` | The profile |
| `PUT /api/profiles/:id` `{name?, request?}` | The updated profile (at least one field) |
| `DELETE /api/profiles/:id` | 204 |

Names are 1 to 100 characters without control characters.

```sh
curl -H "Origin: $B" -H 'Content-Type: application/json' "$B/api/profiles" \
  -d '{"name":"rtu-fleet-slave","request":{"target_ip":"10.0.0.50","mode":"benchmark","role":"slave","alias_iface":"eth1"}}'
curl -s "$B/api/profiles/1" > rtu-fleet-slave.json   # usable with outstation bench --profile
```

## Analysis

Analysis compares a capture of a benchmark run against the run's source pcap. The report format is described in [IEC 104 configuration](iec104-config.md#analysis-report). Raw-replay runs cannot be analysed (400 `not_benchmark`).

Every finished benchmark run with a capture is analysed automatically unless the server runs with `--no-auto-analyze`; see `auto_analysis` on the run. A run that finished while the server was shutting down (SIGTERM), or was cut off by a crash, is analysed after the next start: the newest 20 finished benchmark runs with a capture and no analysis are queued, older ones get `auto_analysis` `skipped` and can be analysed on demand. Analyses are stored. Each has a `source`: `auto`, `manual` (upload) or `on_demand`.

### `POST /api/runs/:id/analyze[?cp56_tolerance_ms=N]`

Analyse the run's own capture now and store the result. `cp56_tolerance_ms` (0 to 3 600 000) sets the CP56Time2a drift tolerance for this analysis; the default is the server's `--cp56-tolerance-ms` (50 unless configured). Returns `{analysis_id, run_id, verdict, score_pct, source: "on_demand", created_at}`. Errors: 409 `run_running`, 409 `capture_missing`, 409 `capture_unavailable` (the run's capture failed or holds no frames although the run sent some; the message says why), 404 `source_pcap_missing`, 400 `not_benchmark`, 429 `busy`.

### `POST /api/analyze[?run_id=N]` (multipart)

Analyse a capture you took yourself (for example with Wireshark on the target side). Parts:

| Part | Meaning |
|---|---|
| `file` | The captured pcap (required) |
| `mode` | `generic` (default) or `correct`: also compare the target's replies byte for byte, when the target is the device recorded in the pcap |
| `run_id` | The run to compare against; may also be given in the query string (both must agree) |
| `cp56_tolerance_ms` | CP56Time2a drift tolerance in ms (0 to 3 600 000); default the server's `--cp56-tolerance-ms` |

Without `run_id` the newest finished benchmark run is used, and a warning says so. The response is the stored analysis summary (the same shape as `GET /api/analyses/:id`, without per-endpoint detail) plus `run_selection` (`explicit` or `latest`), `warnings[]` and `analysis_id`. Fetch an endpoint's detail with `GET /api/analyses/:id/endpoints/:endpoint`. Only when the analysis could not be stored (`analysis_id` is null, and `warnings` says why) does the reply include `details_by_ip`. The summary's `fleet_gi_ci_audit` sums the endpoints' IEC 104 GI/CI audit counters.

```sh
curl -H "Origin: $B" -F file=@target-side.pcap -F mode=generic "$B/api/analyze?run_id=7"
```

### Stored analyses

| Route | Result |
|---|---|
| `GET /api/runs/:id/analyses` | `[{id, run_id, created_at, verdict, score_pct, source}]`, newest first |
| `GET /api/analyses/:id` | The stored summary: the report without per-endpoint detail |
| `GET /api/analyses/:id/endpoints/:endpoint` | One endpoint's stored detail; `:endpoint` is the endpoint IP as listed in `slaves[].slave_ip` |
| `GET /api/analyses/:id/report.html[?download=1]` | The analysis as one self-contained HTML page (inline CSS, no scripts or external assets, print-friendly): verdict, warnings, run facts, fleet counts, every endpoint and its detail. `download=1` sends it as an attachment |

## Compare

### `GET /api/runs/:a/compare/:b`

Compares two finished benchmark runs; `a` is the baseline. It uses each run's newest stored analysis unless `analysis_a` / `analysis_b` pick one. It never analyses anything itself: when a run has no analysis it returns 409 `analysis_missing` with `run_id` and `has_capture`; call `POST /api/runs/:id/analyze` and retry.

Query parameters, all optional (defaults in brackets):

| Parameter | Regression when b is worse than a by more than |
|---|---|
| `score_drop` [1] | this many score points |
| `delivered_drop` [1] | this many delivered-percentage points |
| `p50_increase_pct` [20], `p99_increase_pct` [20] | this many percent of a's latency |
| `latency_min_us` [1000] | latency increases below this are never flagged |
| `throughput_drop_pct` [10] | this many percent of a's fleet throughput |
| `analysis_a`, `analysis_b` | analysis ids to use |

Response:

- `a`, `b`: `{run_id, status, pcap_id, role, started_at, analysis_id, analysis_source}`;
- `fleet`: `{a, b, delta, verdict_changed}`. Each side has `verdict, score, frame_weighted_score, rtus, fully_correct, partial, failed, never_connected, expected, delivered, delivered_pct, sessions, sessions_failed, msgs_sent, msgs_received, p50_us, p90_us, p99_us, max_us, throughput`;
- `rtus[]`: `{rtu, a, b, delta, verdict_changed, regressions[]}`, keyed by RTU IP. Each side has `score, verdict, outcome, expected, delivered, delivered_pct, p50_us, p99_us, msgs_sent, errors, error`;
- `only_in_a`, `only_in_b`: RTUs present in one run only;
- `regressions[]`: `{scope: "fleet"|"rtu", rtu, metric, a, b, threshold, message}`;
- `regressed` (bool), `thresholds`, `warnings[]` (same run twice, different pcaps, different roles).

```sh
curl -s "$B/api/runs/12/compare/15?p99_increase_pct=10" | jq '.regressed, .regressions'
```

## Network helpers

| Route | Body | Result |
|---|---|---|
| `GET /api/nics` | | `[{name, mac, ipv4[], up, loopback, bridge, bridge_port, default_route}]`. `bridge_port` and `default_route` NICs are protected |
| `POST /api/arp` | `{ip, iface?}` | `{ip, iface, mac, error}` via `arping` (default iface: the default-route NIC) |
| `POST /api/verify-ip` | `{ip, iface?}` | `{ip, iface, in_use, locally_assigned, mac, error}`: whether an address is already taken, via the host's own addresses and `arping -D` |

`arping` comes from `iputils-arping`. Without it these routes return `error` instead of failing.

## The run request

The body of `POST /api/run`, the `request` of a stored run and a profile, and the `--profile` file of `outstation bench`. Defined in [`runbuild.rs`](../crates/webui/src/runbuild.rs). Unknown enum values are rejected with 422; unknown keys are ignored.

| Field | Default | Meaning |
|---|---|---|
| `pcap_id` | required | Library id of the source pcap (optional in profiles) |
| `mode` | `raw` | `raw` (L2 replay) or `benchmark` (stateful sessions). `bench` defaults it to `benchmark` |
| `target_ip` | required | Raw: destination written into every frame. Master role: the server the sessions connect to. Slave role: the SCADA master's IP (optional, `0.0.0.0` if unknown; used to find the capture interface) |
| `target_mac` | | Raw only, required there |
| `nic` | none | NIC to enslave to the run bridge for real egress (raw, master role). Empty: the bridge stays on this host |
| `role` | `master` | `master`: we are the client and connect to `target_ip:target_port`. `slave`: we listen as the captured servers (RTUs) |
| `target_port` | 2404 | Server port. Flows are picked from the pcap by this port in both roles |
| `listen_port_base` | 2404 | Slave: the port every listener binds, each on its own IP |
| `proto_name` | `iec104` | A `ready` protocol from `/api/protocols` |
| `proto_config` | none | Protocol settings as a **JSON string** (not an object), e.g. `"{\"session\":{\"t1\":15}}"`. IEC 104: [reference](iec104-config.md) |
| `pacing` | `fast` | `fast` (as fast as the k-window allows) or `original` (captured timing scaled by `speed`) |
| `speed` | 1.0 | 0.001 to 1000. Original pacing and raw replay |
| `concurrency` | `all_at_once` | Master: `all_at_once` or `staggered` (start sessions at their captured offsets) |
| `iterations` | 1 | Passes over the script; 0 = until stopped |
| `iteration_gap_ms` | 1000 | Master: pause between two iterations (connections) of a session, at most 3600000. With `original` pacing an iteration also lasts at least the captured flow's span / `speed`. An unbounded run (`iterations` 0) retries a refused connection, backing off from max(gap, 0.5 s) up to 30 s |
| `loop_within_session` | false | Slave: loop inside one TCP session instead of reconnecting per iteration |
| `warmup_secs` | 5 | Delay after setup, before traffic (at most 3600) |
| `selected_rtus` | all | Subset of endpoints: server IPs in slave role, client IPs in master role |
| `master_bind_ip` | captured | Master: one source IP for every session instead of each captured master IP |
| `tcp_nodelay` | by role | `true`/`false`; `null` = on for slave, off for master |
| `alias_iface` | default-route NIC | Slave: NIC that receives RTU listen IPs that are not already local, as `/32 noprefixroute` aliases |
| `scada_gateway_ip`, `scada_gateway_iface` | none | SCADA-gateway mode; both or neither ([lab guide](scada-lab.en.md#4-gateway-mode-when-the-scada-master-is-on-another-subnet)) |
| `upstream_nat_iface` | none | Gateway mode: NAT the SCADA side's other traffic out of this NIC |
| `force` | false | Override NIC and address protection. Never inherited by a re-run |
| `top_speed`, `realtime`, `skip_non_ip`, `only_src` | | Raw replay: ignore timing, SCHED_FIFO, skip non-IP frames, replay only these source IPs |
| `bridge`, `tap_prefix` | | Accepted and ignored: interface names derive from the run id |
| `pcap` | | Rejected (400 `raw_path_rejected`) |

Interface names must be 1 to 15 characters of `[A-Za-z0-9._-]` and must not start with `-`.

`force` lifts these refusals: the default-route NIC, the NIC carrying the address the UI was reached on, real bridges, existing bridge ports, and addresses held by other interfaces. Loopback, our own `pcr*` interfaces and invalid alias addresses (gateway, multicast, …) are refused even with `force`.
