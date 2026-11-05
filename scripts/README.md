# scripts/

Test and maintenance scripts. Nothing here is needed to build or run
outstation.

The privileged suites (`netns-*.sh`) need `sudo`, but they only ever
change state inside throwaway network namespaces whose names start with
`ostest-`. They refuse other names, refuse to start when one of their
namespaces already exists, and delete their namespaces on exit (also on
failure or Ctrl-C). They never touch the host namespace's interfaces,
routes, iptables rules, sysctls or NIC offloads. Run them on a lab or
CI machine, not on a host that is replaying traffic at the time.

| Script | Privileged | What it does |
|---|---|---|
| `netns-smoke.sh` | yes | End-to-end smoke suite for the real `outstation serve` (release build), driven only over HTTP. See below. |
| `netns-smoke-helper.py` | no | Helper for `netns-smoke.sh`: JSON queries, a pcap reader that compares a raw-replay capture with its source, SSE and Prometheus parsers. Python stdlib only. |
| `netns-test.sh` | yes | netctl's host-safety tests (`crates/netctl/tests/netns.rs`) in one namespace: veths, bridges, aliases, iptables rules, sysctl journals, cleanup. |
| `netns-bench-test.sh` | yes | `outstation bench` in master role (`crates/outstation/tests/bench_netns.rs`): assertions and exit codes, SIGINT cleanup, and isolation (a LAN host can neither reach the host's own addresses through a session port nor route into its management network). Then raw and master runs watched from the LAN side (`crates/sched/tests/capture_netns.rs`): the run's capture holds every wire frame exactly once, sent and received, also at top speed, and keeps the target's replies when the per-MAC NIC filter does not fit in the socket's option memory; only replayed or session frames reach the LAN; an unbounded master run spaces its connections and closes each with STOPDT and a FIN. |
| `netns-slave-test.sh` | yes | `outstation bench` in slave role (`crates/outstation/tests/slave_netns.rs`): a mock master against impersonated RTUs, score, and a capture that holds only the run's own sessions. |
| `netns-scale.sh` | yes | Scale benchmark: `outstation bench` in master role (N captured masters, against a slave peer) and slave role (N RTUs, a master peer), as fast as possible or at original timing (`slave-200@10`). Records msgs/s, ack latency, CPU, RSS, threads, fds, setup and teardown time, `captured_dropped` and the analysis verdict per run, and the median of `REPEAT` runs. Results in [reports/2026-11-05-scale-benchmark.md](../reports/2026-11-05-scale-benchmark.md). |
| `netns-scale-helper.py` | no | Helper for `netns-scale.sh` and `netns-screenshots.sh`: pcap merge, a /proc sampler, event-driven IEC 104 peers (`fast-slave`, `fast-master`, several processes each), the wire I-frame rate of a capture, per-run summaries and the results table. Python stdlib only. |
| `netns-gateway-egress.sh` | yes | SCADA-gateway mode in master role with an egress NIC: two control cases (on-link RTU completes; RTU behind a missing gateway fails) and four gateway variants that must be refused with `gateway_requires_slave` before any host change (gateway mode is slave-role only; see the scale report §7). Exit 1 if a case behaves otherwise. |
| `netns-screenshots.sh` | yes | Refreshes `doc/images/ui-*.jpg` from a real `outstation serve` with real runs (200-RTU slave run with its live diagram, a re-run at speed 2, a master run), using `ui-screenshots.mjs` with Chromium inside the namespace. |
| `ui-screenshots.mjs` | no | Playwright screenshots of Library, Configure, Runs, Analysis and Compare (1440 wide, JPEG). |
| `iec104-mock-slave.py` | no | Minimal IEC 104 controlled station: answers STARTDT/STOPDT/TESTFR and S-acks every I-frame. Target for master-role runs. |
| `iec104-mock-master.py` | no | Minimal IEC 104 controlling station: connects to each given RTU IP, STARTDT, one general interrogation, acks, closes when the slave goes quiet. Peer for slave-role runs. |
| `check-spa-js.py` | no | `node --check` over the SPA's JavaScript, as `build.rs` splices it (run in CI). |
| `ui-smoke.mjs` | no | Playwright browser smoke test of a running web UI (Chromium and WebKit, desktop and phone): accessibility, layout and the main run flow. |

Every script prints its own usage in its header comment.

## netns-smoke.sh

```sh
scripts/netns-smoke.sh                       # builds the release binary first
OUTSTATION_BIN=target/release/outstation scripts/netns-smoke.sh
ONLY="1 2 3" KEEP_WORK=1 scripts/netns-smoke.sh
```

It builds four namespaces (`ostest-smoke-{a,t,m,p}`, override with
`NS_A`/`NS_T`/`NS_M`/`NS_P`): the outstation host running `serve`, a LAN
with the mock slave, a management network the HTTP client (curl) sits
in, and a SCADA-master network for the mock master. The topology is
drawn in the script's header. A small pcap is generated with
`examples/gen_iec104_traffic.py` (4 RTUs, 20 s), so the suite does not
depend on any capture outside the repository.

Cases, in order (later cases reuse the server and runs of earlier ones):

1. Upload a pcap, inspect it, viability verdict and notes present; a
   POST without `Origin` is refused.
2. Raw replay with a mirror capture, 1 and 5 sources, top speed and
   paced: `has_capture`, download, the capture holds every replayed
   frame exactly once and nothing else (compared frame by frame with
   the source), `captured_packets` equals the file, nothing dropped,
   gap histogram.
3. Master benchmark against the mock slave: completed, auto-analysis
   `done` with verdict `all_correct`, and `/api/events` (read with
   `curl -N`) delivered `run_started`, `run_finished`,
   `analysis_finished`.
4. Slave benchmark with the mock master: `start_all`, auto-analysis
   `done`, score 100. An address the operator put on the alias NIC
   before the run survives it; the run's own aliases are removed.
5. A second `POST /api/run` (and a re-run) while a run is active gives
   409 `run_active` with `client_ip`; stopping mid-run gives `stopped`.
6. The default-route NIC is refused without `force` (the run fails and
   nothing is touched) and accepted with it.
7. A master run with SCADA-gateway mode is refused (400
   `gateway_requires_slave`; gateway mode is slave-role only). Then
   SIGTERM mid-run, twice: an unbounded slave run with SCADA gateway
   and upstream NAT (gateway alias, `ip_forward`, NAT rule, RTU
   aliases), and an unbounded master run (bridge, veths, filter rules,
   a NIC offload). Each time the namespace is back to its baseline: no
   `pcr*` interfaces, no `outstation-run-*` rules, sysctls, offloads,
   addresses and routes restored. The master run's server exits within
   `TimeoutStopSec` (30 s); after a restart that run is `stopped` with
   `finished_at`, and the restart auto-analyses it (it finished too
   late during the shutdown).
8. SIGKILL mid-run, the same two runs: the leftovers are there,
   `outstation cleanup --state-dir` restores the baseline (and is a
   no-op the second time), the restarted server's startup cleanup
   undoes nothing, and the run is `failed` ("interrupted by server
   restart") with `finished_at`.
9. Re-run (a stored `force` is not inherited), profiles CRUD, compare
   (409 `analysis_missing` → `POST /api/runs/:id/analyze` → 200), and
   `/metrics` agrees with `/api/runs` and the stored analyses.
10. Restart persistence: run history, captures (byte-identical
    downloads), analyses, profiles and the library survive a restart;
    `DELETE /api/runs/:id` removes the run and its capture.

"Baseline" is a snapshot of the outstation namespace taken right after
the first server start: links (with bridge membership), addresses,
routes, the raw/filter/nat/mangle iptables tables, the
`net.ipv4`/`net.ipv6`/`net.bridge` sysctls and the NICs' checksum
offloads. Every case that runs something compares against it.

The suite prints a table with one row per case (`PASS`, `FAIL`, `SKIP`
when an earlier case it depends on failed, or `XFAIL` when the only
failures are known product bugs marked with `known_bug`) and the time
each case took, and exits non-zero on any `FAIL` or `SKIP`. Logs, the
server's state directory and every snapshot are kept in the work dir
when something failed (or with `KEEP_WORK=1`).

No product bug is currently marked as an expected failure. Mark a
check that fails because of a reported bug with
`known_bug ID MSG CMD...`; it then reports `XFAIL` (or `XPASS` once
the bug is fixed, as a reminder to drop the marker). The raw-capture
bugs SMOKE-B1 (flooded frames recorded once per run port) and SMOKE-B2
(`captured_packets` read before the capture stopped) were fixed in
T16b.

### Scripted clients and the Origin header

The server's same-origin guard refuses state-changing requests (POST,
PUT, PATCH, DELETE) and WebSocket upgrades that carry neither an
`Origin` matching the `Host` nor `Sec-Fetch-Site: same-origin`. curl
and other scripted clients must send one:

```sh
curl -H "Origin: http://10.0.0.5:8080" -H 'Content-Type: application/json' \
     --data @run.json http://10.0.0.5:8080/api/run
```

GET requests (including `/api/events` and `/metrics`) need no Origin.

## netns-screenshots.sh

```sh
cargo build --release -p outstation
OUTSTATION_BIN=target/release/outstation scripts/netns-screenshots.sh   # writes doc/images/ui-*.jpg
scripts/netns-screenshots.sh /tmp/shots                                 # somewhere else
```

Rebuilds the README screenshots from scratch: four namespaces, a real
`outstation serve`, the 200-RTU example capture played in slave role at
original timing against a master peer (the live diagram is taken while
it runs), a re-run at speed 2, a 20-master run, auto-analyses, then
Chromium (Playwright, run as the invoking user inside the management
namespace) takes Library, Configure, Runs, Analysis and Compare. It
needs Playwright with Chromium (`PLAYWRIGHT_DIR`, default
`/opt/code/tools/browser/node_modules/playwright`). Each image is 1440
wide, JPEG quality 80; the script fails when one is over 400 KB. Look at
every image before committing it.

## netns-scale.sh

```sh
OUTSTATION_BIN=target/release/outstation scripts/netns-scale.sh                  # master-200 slave-200 master-400 slave-400, 3 runs each
REPEAT=1 scripts/netns-scale.sh slave-200@10 master-800                          # @SPEED = original timing
PEER=mock scripts/netns-scale.sh master-200                                      # the threaded Python mocks
NOFILE=1024:65536 REALTIME=1 KEEP_CAPTURES=1 scripts/netns-scale.sh slave-400
```

Each run gets fresh namespaces; the work directory keeps every bench
report, log and sample, `results.jsonl` and `results.md` (every run and
the median per scenario). Run it on an otherwise idle host: outstation
and its peers share the CPU.
