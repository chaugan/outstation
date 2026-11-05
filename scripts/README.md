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
| `netns-bench-test.sh` | yes | `outstation bench` in master role (`crates/outstation/tests/bench_netns.rs`): assertions and exit codes, SIGINT cleanup, and isolation (a LAN host can neither reach the host's own addresses through a session port nor route into its management network). |
| `netns-slave-test.sh` | yes | `outstation bench` in slave role (`crates/outstation/tests/slave_netns.rs`): a mock master against impersonated RTUs, score, and a capture that holds only the run's own sessions. |
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
2. Raw replay with a mirror capture: `has_capture`, download, the
   capture holds every replayed frame (compared frame by frame with the
   source), gap histogram.
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
7. SIGTERM mid-run (an unbounded run with SCADA gateway and upstream
   NAT, so a sysctl, an alias, NAT and filter rules and a NIC offload
   are all leased): the server exits within `TimeoutStopSec` (30 s) and
   the namespace is back to its baseline: no `pcr*` interfaces, no
   `outstation-run-*` rules, sysctls, offloads, addresses and routes
   restored. After a restart the run is `stopped` with `finished_at`.
8. SIGKILL mid-run: the leftovers are there, `outstation cleanup
   --state-dir` restores the baseline (and is a no-op the second time),
   the restarted server's startup cleanup undoes nothing, and the run is
   `failed` ("interrupted by server restart") with `finished_at`.
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

Known product bugs the suite marks as expected failures:

- **SMOKE-B1** (raw replay capture): the capture device mirrors ingress
  *and* egress of every run port, so a frame the run bridge floods
  (the target MAC is not learned, which is normal for a passive target)
  is recorded once per run port. With 5 sources each frame appears 5
  times (147 frames sent, 735 captured), `captured_packets` and the gap
  histogram are inflated, and at top speed the amplified burst makes
  the capture drop frames outright.
- **SMOKE-B2** (raw and master capture counters): `captured_packets` is
  read before the capture thread is stopped, so frames written after
  the read are in the file but not in the count. A race; it is reported
  only on runs that hit it.

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
