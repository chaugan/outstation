# Operations

Installing, running, monitoring and upgrading `outstation serve`, and what to do when something goes wrong. For the HTTP API see [api.md](api.md); for the lab setup see the [SCADA lab guide](scada-lab.en.md).

## Contents

- [Install](#install)
- [The systemd unit](#the-systemd-unit)
- [Configuration](#configuration)
- [State directory](#state-directory)
- [Host changes and cleanup](#host-changes-and-cleanup)
- [Health and metrics](#health-and-metrics)
- [Upgrades and database migrations](#upgrades-and-database-migrations)
- [Troubleshooting](#troubleshooting)
- [Privileged test scripts](#privileged-test-scripts)

## Install

Build a release binary, then run the installer as root:

```sh
cargo build --release -p outstation
sudo ./systemd/install.sh            # restarts the service only if no run is active
sudo ./systemd/install.sh --restart  # restart even if a run is active (stops it)
```

[`systemd/install.sh`](../systemd/install.sh):

- creates the `outstation` system user;
- installs the binary to `/usr/local/bin/outstation` (through a temporary name and a rename, so a running process keeps its old binary);
- creates `/var/lib/outstation` (mode 0750, owned by `outstation`);
- installs [`systemd/outstation.service`](../systemd/outstation.service) and enables it;
- starts or restarts the service. When the running instance reports an active run (`GET /api/runs?status=running`), it installs the new files but does not restart, and tells you to restart later;
- prints the URLs the UI is reachable on.

Host tools the service calls: `ip` and `tc` (iproute2), `iptables` (with the `comment` match and the `raw`, `nat` and `filter` tables), `sysctl` (procps), `ethtool`, and optionally `arping` (iputils-arping) for the UI's ARP lookup and IP check. The kernel needs veth, bridge, dummy, AF_PACKET, and for raw and master-role captures the `clsact` qdisc, `matchall` filter and `mirred` action.

## The systemd unit

[`systemd/outstation.service`](../systemd/outstation.service), in short:

| Setting | Why |
|---|---|
| `ExecStart=/usr/local/bin/outstation serve --bind 0.0.0.0:8080` | LAN access to the UI. There is no authentication: see below |
| `ExecStopPost=-/usr/local/bin/outstation cleanup` | Undo host network changes even after a crash or a SIGKILL. A no-op after a clean stop. The `-` keeps a cleanup failure from failing the unit |
| `TimeoutStopSec=30`, `KillMode=mixed` | Time for the graceful shutdown below |
| `Restart=on-failure`, `RestartSec=2` | |
| `User=outstation`, `AmbientCapabilities=` and `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_NICE` | Not root. Ambient capabilities are inherited by the `ip`, `tc`, `iptables`, `sysctl`, `ethtool` and `arping` subprocesses |
| `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `LockPersonality`, `RestrictSUIDSGID`, `RestrictNamespaces`, `SystemCallArchitectures=native`, `UMask=0027` | Hardening |
| `ProtectKernelTunables=no` | The run guards write sysctls (`bridge-nf-call-iptables`, `ip_forward`, per-interface settings) |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX` | Sessions, netlink, raw replay and capture, journald |
| `RestrictRealtime=no` | SCHED_FIFO for raw replay with `realtime` |
| `StateDirectory=outstation`, `ReadWritePaths=/var/lib/outstation` | Everything the service writes lives here. Nothing lives in its private `/tmp` |
| `ReadWritePaths=-/run/xtables.lock` | `ProtectSystem=strict` makes `/run` read-only, and iptables-legacy takes its lock at `/run/xtables.lock`. iptables-nft does not use that file. The leading `-` makes systemd ignore the path when it does not exist |
| `MemoryDenyWriteExecute=yes` | Hardening: no memory mapping that is both writable and executable |

**No system call filter.** The unit sets no `SystemCallFilter`. The service runs helper programs (`ip`, `tc`, `iptables` in its legacy or nft variant, `sysctl`, `ethtool`, `arping`), and the system calls they need vary by distribution and version. A filter cannot be checked without a live privileged run on your host. To try one, add a drop-in with `systemctl edit outstation`:

```ini
[Service]
# Untested: verify with a full run (slave, master, raw, gateway) and `outstation cleanup`.
SystemCallFilter=@system-service @network-io
SystemCallErrorNumber=EPERM
```

With `EPERM`, a blocked call fails instead of killing the process, so the run errors at setup or cleanup and the cause is in the service log. Remove the drop-in (`systemctl revert outstation`) if runs or cleanup start failing.

**Graceful stop.** On SIGTERM or SIGINT the server refuses new runs, closes event streams, cancels the active run, waits up to 20 s for run workers to unwind (each restores its host changes as it ends), waits up to 5 s for open HTTP connections, then runs the same cleanup as `outstation cleanup`. A run cut short by a stop is recorded as stopped.

**LAN exposure.** Anyone who can reach port 8080 can start runs, change host networking through them (IP aliases, bridges, NIC enslavement, forwarding and NAT in gateway mode) and delete history. To keep the UI local, change the unit to `--bind 127.0.0.1:8080` (with `systemctl edit outstation`) and reach it through an SSH tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 lab-host     # then open http://127.0.0.1:8080
```

Otherwise restrict port 8080 at the network layer. The Host and Origin checks ([api.md](api.md#the-host-and-origin-rule)) only stop browser-borne attacks.

## Configuration

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--bind ADDR` | | `127.0.0.1:8080` (the unit: `0.0.0.0:8080`) | Listen address |
| `--allow-host NAME` (repeatable, comma-separated) | `OUTSTATION_ALLOW_HOSTS` | none | Extra `Host` names to accept, on top of IP literals, `localhost` and this machine's names. Needed behind a reverse proxy or a DNS alias |
| `--ephemeral` | | off | Keep run history in memory only. Without it the server refuses to start when the database cannot be opened |
| `--max-upload-mb N` | `OUTSTATION_MAX_UPLOAD_MB` | 1024 | Largest library or analysis upload |
| `--capture-max-mb N` | `OUTSTATION_CAPTURE_MAX_MB` | 10240 | Total size of stored run captures; oldest evicted first |
| | `OUTSTATION_CAPTURE_MAX_COUNT` | 200 | Most run captures kept |
| | `OUTSTATION_MIN_FREE_MB` | 512 | Free-space reserve in the state directory |
| `--library-max-mb N` | `OUTSTATION_LIBRARY_MAX_MB` | none | Total size quota of the pcap library; an upload that would exceed it is refused with 507 `quota_exceeded` |
| `--no-auto-analyze` | `OUTSTATION_AUTO_ANALYZE=0` | on | Do not analyse finished benchmark runs automatically |
| `--runs-in-memory N` | `OUTSTATION_RUNS_IN_MEMORY` | 500 | Finished runs kept in memory. Older runs stay in the database and are read from it on demand (`GET /api/runs` pages through them) |
| `--cp56-tolerance-ms N` | `OUTSTATION_CP56_TOLERANCE_MS` | 50 | CP56Time2a drift tolerance of automatic and on-demand analyses (`outstation bench` takes the same flag) |
| | `OUTSTATION_LIBRARY_DIR` | `/var/lib/outstation/library` | Library directory. The state directory is its parent |
| | `RUST_LOG` | `info` | Log filter, e.g. `RUST_LOG=debug,hyper=info` |

Add environment variables with `systemctl edit outstation`:

```ini
[Service]
Environment=OUTSTATION_ALLOW_HOSTS=outstation.lab.example
Environment=OUTSTATION_CAPTURE_MAX_MB=20480
```

**Disk limits.** An upload is refused (507 `disk_full`) when free space would drop below the reserve. The check runs before the upload and again while its bytes arrive, so a chunked upload without `Content-Length` is stopped as soon as it would cross the reserve. With a library quota, concurrent uploads reserve their share of it as they stream, so together they never exceed it (507 `quota_exceeded`). While a run is active, the server checks free space every 5 s and stops the run when it falls below half the reserve; the run's `error` says so. Captures are evicted after each run until both the size and the count cap hold; the active run's capture is never evicted. There is no per-run size cap yet, so one long run can still write a large capture.

Logs go to stdout. Under journald (`journalctl -u outstation`) they are plain text without colour; every line of a run carries `run{id=N}`.

## State directory

Default `/var/lib/outstation` (the parent of `OUTSTATION_LIBRARY_DIR`):

| Path | Contents |
|---|---|
| `library/pcr_<n>.pcap` | Uploaded pcaps |
| `library/pcr_<n>.json` | Sidecar: display name, parse summary, viability |
| `library/.pcr_<n>.part` | Upload in progress; removed on error and at startup |
| `captures/run_<id>.pcap` | Capture of run `<id>`; subject to retention |
| `captures/bench_<id>.pcap` | Default capture of an `outstation bench` run; not subject to retention |
| `runs.sqlite` | Run history, run requests, analyses and profiles |
| `state-aliases.txt` | Journal of IP aliases we added (`<iface> <ip> <prefix>` per line) |
| `state-guards.txt` | Journal of sysctl and offload prior values and tagged iptables rules |
| `outstation.lock` | Held (`flock`) by the running `serve` or `bench`; holds its pid and role. See below |
| `*.lock` | Lock files of the journals |
| `tmp/` | Private (0700) temp files, e.g. an analysis upload while it is analysed; swept at startup |

Back up `runs.sqlite` and `library/`. Captures can be large; keep them only if you need to re-analyse.

## Host changes and cleanup

Every change a run makes to the host is journaled before it is made and removed from the journal after it is undone:

- interfaces: a run bridge `pcr<tag>_br` and ports `pcr<tag>_<kind><n>`, where `<tag>` is the run id in base 36. Each carries the ifalias `outstation:<run id>`;
- `/32 noprefixroute` IP aliases (slave listen IPs, the gateway IP in gateway mode). Aliases that were already present are left alone;
- sysctls (`net.bridge.bridge-nf-call-iptables`, `net.ipv4.ip_forward`) and NIC TX checksum offload, with their prior values;
- iptables rules tagged `-m comment --comment outstation-run-<id>`.

Normally each run undoes its changes when it ends. The safety net:

- **at startup** the server runs the cleanup before it accepts requests;
- **at shutdown** it runs it after the run workers have finished;
- **`outstation cleanup [--state-dir DIR]`** runs it by hand, and the unit runs it as `ExecStopPost`.

The cleanup deletes every interface marked `outstation:<id>` (which also frees an enslaved NIC), every iptables rule in the journal and any other rule tagged `outstation-run-*` in the raw, nat, filter and mangle tables, restores journaled sysctls and offloads, and removes journaled aliases. Entries it cannot undo stay in the journal and are reported (`cleanup_pending` in `/api/status`).

**One process per state directory.** `outstation serve` and `outstation bench` hold an exclusive lock on `<state>/outstation.lock` for as long as they run. The kernel releases it when the process exits, however it exits, so a crash never leaves a stale lock. While it is held:

- a second `outstation serve` with the same state directory refuses to start ("the state directory is in use by another outstation process (pid=N role=serve …)"), instead of running its startup cleanup over the live run;
- `outstation bench` refuses with exit code 2;
- `outstation cleanup` refuses and exits non-zero. `outstation cleanup --force` cleans up anyway and tears down the active run. The unit's `ExecStopPost` cleanup runs after the server has exited, so it never needs `--force`.

The lock is per state directory. The cleanup itself is host-wide: it removes every outstation-marked interface and tagged rule in the network namespace, whichever state directory the run belongs to. So do not run two servers with different state directories on one host (or network namespace), and do not run `outstation cleanup --force` while a run is active.

## Health and metrics

`GET /api/status` (see [api.md](api.md#get-apistatus)) reports `ok: false` and lists reasons in `degraded_detail` when something is wrong. The UI shows them in a banner.

| Code | Meaning | What to do |
|---|---|---|
| `db_not_writable` | The run database rejects writes | Check permissions and space on the state directory |
| `ephemeral` | Started with `--ephemeral` | History is lost on restart |
| `low_disk` | Free space below `OUTSTATION_MIN_FREE_MB` | Delete captures or pcaps, or lower `--capture-max-mb` |
| `disk_unknown` | Free space could not be read | |
| `missing_capabilities` | No CAP_NET_ADMIN or CAP_NET_RAW: runs will fail | Run through the systemd unit or with sudo |
| `capabilities_unknown` | Capabilities could not be read | |
| `journal_unreadable` | A host-state journal cannot be read | Check the files in the state directory |
| `cleanup_pending` | Journal entries left by an earlier run, with no run active | `sudo systemctl restart outstation`, or stop the service and run `outstation cleanup` |
| `shutting_down` | SIGTERM received | |

`GET /metrics` serves Prometheus text format:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `outstation_up` | gauge | | 1 when no degraded reason is present |
| `outstation_degraded` | gauge | `reason` | 1 per active degraded code |
| `outstation_build_info` | gauge | `version` | Always 1 |
| `outstation_uptime_seconds` | gauge | | |
| `outstation_runs` | gauge | `status` | Runs known to the server |
| `outstation_frames_sent_total`, `outstation_bytes_sent_total` | counter | | Frames (raw) and messages (benchmark) and bytes sent by all runs |
| `outstation_run_duration_seconds` | summary | | Duration of finished runs (`_sum`, `_count`) |
| `outstation_active_run_id` | gauge | | 0 when idle |
| `outstation_active_run_duration_seconds`, `outstation_active_run_frames_sent`, `outstation_active_run_bytes_sent` | gauge | | The active run so far |
| `outstation_active_run_sessions` | gauge | `state` | Sessions of the active run by state |
| `outstation_benchmark_latency_seconds` | histogram | `le` | Acknowledgement latency of all finished benchmark runs |
| `outstation_last_benchmark_run_id`, `outstation_last_benchmark_sessions` | gauge | | The newest finished benchmark run |
| `outstation_last_benchmark_latency_seconds` | gauge | `quantile` (0.5, 0.99) | Its fleet latency |
| `outstation_uploads_total` | counter | `result` | Library uploads |
| `outstation_analyses_total` | counter | `source`, `result` | Analyses run by this process |
| `outstation_analyses_running` | gauge | | |
| `outstation_analyses_stored` | gauge | `source` | Analyses in the database |
| `outstation_free_disk_bytes`, `outstation_min_free_disk_bytes` | gauge | | |
| `outstation_db_writable` | gauge | | |
| `outstation_guard_journal_entries` | gauge | `journal` (`guards`, `aliases`) | Host changes not yet undone |
| `outstation_capability` | gauge | `cap` | 1 per capability held |

`/metrics` is a plain GET with no authentication, like the rest of the API.

## Upgrades and database migrations

1. Build the new release and run `sudo ./systemd/install.sh`. It does not restart the service while a run is active.
2. On startup the server migrates `runs.sqlite` in place, one step per schema version (`PRAGMA user_version`, currently 4), each step in a transaction. Rows that cannot be read are skipped and logged, not fatal.
3. A database written by a newer version is refused: the server will not start. Keep a copy of `runs.sqlite` before upgrading if you may need to go back.

Runs recorded before schema 4 have no stored run request, so they cannot be re-run (409 `request_missing`).

## Troubleshooting

**The run fails with an `iptables` error.** Install `iptables` with the `comment` match and the `raw` table. Every call uses `iptables -w`, so it waits for the xtables lock instead of failing when firewalld, Docker or another tool holds it; a run that hangs at setup may be waiting for that lock. The guards fail closed: when a rule cannot be installed the run fails at setup and what was already done is rolled back.

**No capture, so no analysis.** Raw and master-role runs mirror the ingress of their bridge ports into a capture device with `tc` (`clsact` qdisc, `matchall` filter, `mirred` action), and record the target's replies on the enslaved NIC (incoming frames to the run's MACs, broadcast and multicast, through an AF_PACKET filter), so each wire frame is in the capture exactly once. Without `tc` or those kernel modules the run still goes ahead, but without a capture: the run has no download, and `auto_analysis` is `skipped` with "the run left no capture". The reason is in the service log ("could not create capture mirror") and in the run's `warnings` (`benchmark.warnings` or `report.warnings`, also shown on the run card). Slave-role capture uses a filtered AF_PACKET socket and does not need `tc`.

**Capture unavailable.** When the capture started but failed (for example AF_PACKET refused without `CAP_NET_RAW`), the file holds only its header although the run sent frames. Such a capture is not analysed, since it would read as a false `no_delivery`: `auto_analysis` is `skipped` with "capture unavailable: <reason>", `POST /api/runs/:id/analyze` answers 409 `capture_unavailable`, and `outstation bench` exits 2 with the reason (its report has `analysis_error` and the run's `warnings`).

**Raw replay frames arrive untagged.** Raw replay removes 802.1Q VLAN tags (stacked tags and 802.1ad too) from IPv4 frames before sending, so captured traffic replayed onto a trunk port goes out untagged. There is no option to keep the tags. To get the traffic onto a VLAN, send it from an access port in that VLAN, or from a VLAN subinterface used as the egress NIC. Tagged non-IP frames (GOOSE, SV) are sent as captured, tags included. Captures on SLL/SLL2 or raw-IP link types get a synthesized untagged Ethernet header.

**`missing_capabilities` or "Operation not permitted".** Run through the systemd unit, or start the server with `sudo`. Do not rely on `setcap` on the binary: file capabilities are not passed to the `ip`, `tc` and `iptables` subprocesses, which need them too.

**403 `host_not_allowed`.** You reached the UI by a name the server does not know. Add it with `--allow-host` or `OUTSTATION_ALLOW_HOSTS`.

**403 `origin_required` from a script.** Send `Origin: http://<host:port>` matching the URL ([api.md](api.md#the-host-and-origin-rule)).

**409 `run_active`.** Someone else's run is active; the error says who started it and when. Every connected UI shows a banner while it runs.

**Slave sessions fail with "listen ip … is not local and needs a /32 alias on …".** Without `alias_iface`, RTU listen IPs go on the default-route NIC, which is protected, so every session that needs an alias fails. Pick another NIC in "Alias NIC for RTU listen IPs", or confirm the override if you really mean that NIC. Listen IPs that are already local (including all of 127.0.0.0/8) need no alias.

**The run cannot use a NIC or an address.** The default-route NIC, the NIC carrying the address you reached the UI on, real bridges, bridge ports and addresses held by other interfaces are refused unless you set `force` (the UI asks you to confirm). Loopback, the host's default gateway, multicast, broadcast and reserved addresses are always refused.

**`cleanup_pending` after a crash.** Restart the service; startup cleanup handles it. If an entry keeps failing, the error is in the log and in `journal_pending.error`.

**A run is stopped with "free disk … fell to …".** The low-disk watchdog stopped it. Free space or lower the capture cap.

## Privileged test scripts

`scripts/netns-*.sh` run end-to-end tests that need root. Each one creates throwaway network namespaces named `ostest-*` with `sudo ip netns`, runs the tests inside them, and deletes them on exit. They never touch the host's own interfaces, routes or firewall. They need `sudo`, iproute2, iptables, ethtool and python3, and use the mock IEC 104 peers [`scripts/iec104-mock-master.py`](../scripts/iec104-mock-master.py) and [`scripts/iec104-mock-slave.py`](../scripts/iec104-mock-slave.py). Read the header of each script for its topology and options. CI runs only the unprivileged checks ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).
