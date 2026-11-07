#!/usr/bin/env bash
# End-to-end smoke suite for the real `outstation serve` binary (release
# build), driven only over HTTP with curl, inside throwaway network
# namespaces. Nothing outside them is touched: every interface, address,
# route, iptables rule and sysctl the suite or the server changes lives
# in a namespace named ostest-smoke-*, and the namespaces are deleted on
# exit (trap), also when the suite fails or is interrupted.
#
#   $NS_M (management, curl)        $NS_A (outstation serve)            $NS_T (LAN + target)
#   os-n 10.66.0.2 <----veth---->   os-m 10.66.0.1:8080 (UI/API)        bridge "lan" 10.77.0.1/24
#                                   os-a (default route, protected) <-> os-b (port of lan)
#                                                                       mock IEC 104 slave :2404
#   $NS_P (SCADA master side)       os-s 10.79.0.1/24
#   s-p 10.79.0.2 <------veth---->    + 192.168.10.2/32 (pre-existing, operator-owned alias)
#   route 192.168.10.0/24 dev s-p   gwin   (dummy: SCADA-gateway inner NIC)
#   mock IEC 104 master             uplink (dummy 10.44.0.1/24: upstream NAT NIC)
#
# Cases (each prints its checks; a PASS/FAIL table with timings ends
# the run):
#   1  upload a pcap (generated with examples/gen_iec104_traffic.py),
#      inspect it, viability notes present; Origin guard refuses a POST
#      without Origin
#   2  raw replay with a mirror capture (1 and 5 sources, top speed
#      and paced): has_capture, download, the capture holds each
#      replayed frame exactly once and nothing else, gap histogram
#   3  master benchmark against the mock slave: completed, auto-analysis
#      done with verdict all_correct, SSE run_started / run_finished /
#      analysis_finished
#   4  slave benchmark with the mock master: start_all, auto-analysis
#      done, score 100; a pre-existing alias on the alias NIC survives
#      teardown, the run's own aliases do not
#   5  concurrent POST /api/run (and rerun) -> 409 run_active with
#      client_ip; stop mid-run -> stopped, host restored
#   6  default-route NIC refused without force (run fails, host
#      untouched), accepted with force
#   7  a master run with SCADA-gateway mode is refused (400
#      gateway_requires_slave: gateway mode is slave-role only). SIGTERM
#      mid-run, twice: an unbounded slave run with SCADA gateway +
#      upstream NAT (gateway alias, ip_forward, NAT rule, RTU aliases)
#      and an unbounded master run (bridge, veths, rules, NIC
#      offloads): host restored each time; the master run exits within
#      TimeoutStopSec (30 s), no pcr* interfaces, no outstation-run-*
#      rules, sysctls/offloads/addresses restored; it is "stopped" with
#      finished_at after a restart, and the restart auto-analyses it
#   8  SIGKILL mid-run, the same two runs: leftovers exist, `outstation
#      cleanup` restores everything (twice for the master run:
#      idempotent), restart is a no-op cleanup, run is failed/orphaned
#      with finished_at
#   9  re-run (force not inherited), profiles CRUD, compare with the
#      409 analysis_missing -> POST analyze -> 200 path, /metrics
#      consistent with /api/runs and stored analyses
#   10 restart persistence: runs, captures (byte-identical downloads),
#      analyses, profiles and the library survive; DELETE a run
#
# Usage: scripts/netns-smoke.sh
# Env:   ONLY="1 3 5"               run only these cases (later cases may
#                                   SKIP when they need an earlier one)
#        NS_A / NS_T / NS_M / NS_P  namespaces (default ostest-smoke-{a,t,m,p};
#                                   must start with "ostest-")
#        OUTSTATION_BIN             use this binary instead of building
#                                   `cargo build --release -p outstation`
#        WORK                       work dir (default: mktemp under $TMPDIR or
#                                   /tmp); kept on failure or with KEEP_WORK=1
#        CARGO_TARGET_DIR           honoured by cargo
# Needs: sudo, iproute2, iptables, ethtool, curl, python3 (stdlib only).
# Exit:  0 when every case passed (expected failures of known product
#        bugs, marked XFAIL with known_bug, do not fail the suite), 1
#        otherwise.
set -uo pipefail

NS_A="${NS_A:-ostest-smoke-a}"
NS_T="${NS_T:-ostest-smoke-t}"
NS_M="${NS_M:-ostest-smoke-m}"
NS_P="${NS_P:-ostest-smoke-p}"
for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
  case "$ns" in
    ostest-*) ;;
    *) echo "namespace names must start with ostest-" >&2; exit 2 ;;
  esac
  if sudo ip netns list | grep -qw "^$ns"; then
    echo "namespace $ns already exists; delete it first" >&2
    exit 1
  fi
done

cd "$(dirname "$0")/.."
REPO="$(pwd)"
HELPER="$REPO/scripts/netns-smoke-helper.py"

API_IP=10.66.0.1
BASE="http://$API_IP:8080"
CLIENT_IP=10.66.0.2
TARGET_IP=10.77.0.1        # mock slave (master-role target)
MASTER_IP=10.79.0.2        # mock master (slave-role peer)
FAKE_MAC=02:00:00:00:aa:01 # raw replay destination MAC nobody owns
OWN_ALIAS=192.168.10.2     # operator alias on os-s, also an RTU of the pcap
GW_IP=10.55.0.1            # SCADA gateway alias
STOP_TIMEOUT=30            # systemd/outstation.service TimeoutStopSec

# --- binary --------------------------------------------------------------
if [ -n "${OUTSTATION_BIN:-}" ]; then
  BIN="$OUTSTATION_BIN"
else
  echo "building outstation (release)..."
  BIN="$(cargo build --release -p outstation --message-format=json 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
            and m["target"]["name"] == "outstation":
        print(m["executable"])
')"
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "could not build or find the outstation binary" >&2
  exit 1
fi
echo "binary: $BIN"

WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ostest-smoke.XXXXXX")}"
mkdir -p "$WORK"
STATE="$WORK/state"
mkdir -p "$STATE/library"
echo "work dir: $WORK"

# --- teardown ------------------------------------------------------------
SERVER_PID=""
SERVE_N=0
OVERALL_FAIL=0
teardown() {
  local rc=$?
  for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true
  done
  sleep 0.2
  for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
    sudo ip netns del "$ns" 2>/dev/null || true
  done
  wait 2>/dev/null
  if [ "$OVERALL_FAIL" -eq 0 ] && [ "$rc" -eq 0 ] && [ "${KEEP_WORK:-0}" != 1 ]; then
    sudo rm -rf -- "$WORK"
  else
    echo "logs and state kept in $WORK"
  fi
}
trap teardown EXIT
trap 'exit 130' INT TERM

# --- topology ------------------------------------------------------------
nsx() { local ns=$1; shift; sudo ip netns exec "$ns" "$@"; }

setup_topology() {
  for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
    sudo ip netns add "$ns"
    sudo ip -n "$ns" link set lo up
  done
  # No IPv6 anywhere: keeps captures and snapshots free of router
  # solicitations and link-local churn.
  for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
    nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  done
  # A new namespace may inherit ip_forward=1; start from 0 so the
  # SCADA-gateway lease (ip_forward=1) is visible and must be undone.
  nsx "$NS_A" sysctl -qw net.ipv4.ip_forward=0
  # LAN with the mock slave.
  sudo ip -n "$NS_T" link add lan type bridge
  sudo ip -n "$NS_T" link set lan up
  sudo ip -n "$NS_T" addr add "$TARGET_IP/24" dev lan
  sudo ip -n "$NS_A" link add os-a type veth peer name os-b netns "$NS_T"
  sudo ip -n "$NS_T" link set os-b master lan
  sudo ip -n "$NS_T" link set os-b up
  sudo ip -n "$NS_A" link set os-a up
  sudo ip -n "$NS_T" route add default dev lan
  # os-a carries the default route: protected unless forced.
  sudo ip -n "$NS_A" route add default dev os-a
  # Management network: the API is reached from here.
  sudo ip -n "$NS_A" link add os-m type veth peer name os-n netns "$NS_M"
  sudo ip -n "$NS_A" addr add "$API_IP/24" dev os-m
  sudo ip -n "$NS_A" link set os-m up
  sudo ip -n "$NS_M" addr add "$CLIENT_IP/24" dev os-n
  sudo ip -n "$NS_M" link set os-n up
  # SCADA master side for slave runs.
  sudo ip -n "$NS_A" link add os-s type veth peer name s-p netns "$NS_P"
  sudo ip -n "$NS_A" addr add 10.79.0.1/24 dev os-s
  sudo ip -n "$NS_A" addr add "$OWN_ALIAS/32" dev os-s
  sudo ip -n "$NS_A" link set os-s up
  sudo ip -n "$NS_P" addr add "$MASTER_IP/24" dev s-p
  sudo ip -n "$NS_P" link set s-p up
  sudo ip -n "$NS_P" route add 192.168.10.0/24 dev s-p
  # SCADA-gateway inner NIC and upstream NAT NIC.
  sudo ip -n "$NS_A" link add gwin type dummy
  sudo ip -n "$NS_A" link set gwin up
  sudo ip -n "$NS_A" link add uplink type dummy
  sudo ip -n "$NS_A" addr add 10.44.0.1/24 dev uplink
  sudo ip -n "$NS_A" link set uplink up
  # Mock IEC 104 slave on the LAN.
  nsx "$NS_T" python3 "$REPO/scripts/iec104-mock-slave.py" "$TARGET_IP" 2404 \
    >"$WORK/mock-slave.log" 2>&1 &
}

# --- helpers -------------------------------------------------------------
H() { python3 "$HELPER" "$@"; }
# jv EXPR: evaluate EXPR on the last response body ($RESP).
jv() { printf '%s' "$RESP" | H json "$1"; }
# jvs JSON EXPR
jvs() { printf '%s' "$1" | H json "$2"; }

# api METHOD PATH [curl args...]: sets HTTP and RESP. Always sends the
# Origin header the same-origin guard requires for state changes.
api() {
  local m=$1 p=$2
  shift 2
  HTTP=$(nsx "$NS_M" curl -sS -o "$WORK/resp.body" -w '%{http_code}' -X "$m" \
    -H "Origin: $BASE" --max-time 120 "$@" "$BASE$p" 2>"$WORK/curl.err") || HTTP=000
  RESP=$(cat "$WORK/resp.body" 2>/dev/null || true)
}
post_json() { api POST "$1" -H 'Content-Type: application/json' --data "$2"; }
# download PATH FILE: GET PATH into FILE; sets HTTP.
download() {
  rm -f "$2"
  HTTP=$(nsx "$NS_M" curl -sS -o "$2" -w '%{http_code}' --max-time 120 "$BASE$1" 2>"$WORK/curl.err") || HTTP=000
}

CASE_FAILS=0
CASE_XFAIL=0
CASE_SKIP=0
ok() { echo "    ok   $*"; }
bad() { echo "    FAIL $*"; CASE_FAILS=$((CASE_FAILS + 1)); }
# check MSG CMD...: run CMD; ok/FAIL with MSG. Returns CMD's status.
check() {
  local msg=$1
  shift
  if "$@"; then ok "$msg"; return 0; fi
  bad "$msg"
  return 1
}
# known_bug ID MSG CMD...: a check that currently fails because of a
# reported product bug. Failure is XFAIL (not counted); success is
# XPASS (the bug looks fixed: drop the marker).
known_bug() {
  local id=$1 msg=$2
  shift 2
  if "$@"; then
    echo "    XPASS [$id] $msg (bug fixed? remove the known_bug marker)"
  else
    echo "    XFAIL [$id] $msg"
    CASE_XFAIL=$((CASE_XFAIL + 1))
  fi
}
eq() { [ "$1" == "$2" ] || { echo "      got '$1', want '$2'"; return 1; }; }
contains() { case "$1" in *"$2"*) return 0 ;; esac; echo "      '$2' not in: ${1:0:400}"; return 1; }
ge() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' "$1" "$2" \
  || { echo "      $1 < $2"; return 1; }; }
need() {
  local v
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "    SKIP prerequisite $v missing (an earlier case failed)"
      CASE_SKIP=1
      return 1
    fi
  done
}
now() { date +%s.%N; }
elapsed() { python3 -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):.1f}")' "$1" "$2"; }

RESULTS=()
run_case() {
  local id=$1 name=$2 fn=$3
  CASE_FAILS=0 CASE_XFAIL=0 CASE_SKIP=0
  if [ -n "${ONLY:-}" ] && ! [[ " $ONLY " == *" $id "* ]]; then
    RESULTS+=("$id|$name|-|0.0")
    return 0
  fi
  echo
  echo "=== case $id: $name"
  local t0 t1 rc res
  t0=$(now)
  "$fn"
  rc=$?
  t1=$(now)
  stop_active_runs
  if [ "$CASE_SKIP" -eq 1 ]; then
    res=SKIP
  elif [ "$rc" -ne 0 ] || [ "$CASE_FAILS" -gt 0 ]; then
    res=FAIL
  elif [ "$CASE_XFAIL" -gt 0 ]; then
    res=XFAIL
  else
    res=PASS
  fi
  case "$res" in PASS | XFAIL) ;; *) OVERALL_FAIL=1 ;; esac
  RESULTS+=("$id|$name|$res|$(elapsed "$t0" "$t1")")
  echo "--- case $id: $res"
}

# A case that failed half-way must not leave its run active for the
# next one.
stop_active_runs() {
  [ -n "$SERVER_PID" ] || return 0
  local id
  api GET "/api/runs?status=running"
  [ "$HTTP" = 200 ] || return 0
  for id in $(jv '" ".join(str(r["id"]) for r in d)'); do
    echo "    (stopping run $id left active by this case)"
    api POST "/api/runs/$id/stop"
    wait_run "$id" 30 >/dev/null
  done
}

# --- server lifecycle ----------------------------------------------------
# start_server [serve args...]
start_server() {
  SERVE_N=$((SERVE_N + 1))
  SERVE_LOG="$WORK/serve-$SERVE_N.log"
  rm -f "$WORK/serve.pid"
  nsx "$NS_A" sh -c 'echo $$ >"$1"; shift; exec "$@"' sh "$WORK/serve.pid" \
    env RUST_LOG=info NO_COLOR=1 OUTSTATION_LIBRARY_DIR="$STATE/library" \
    OUTSTATION_MIN_FREE_MB=16 "$BIN" serve --bind "$API_IP:8080" "$@" \
    >"$SERVE_LOG" 2>&1 &
  local i
  for ((i = 0; i < 150; i++)); do
    if [ -s "$WORK/serve.pid" ]; then
      api GET /api/status
      if [ "$HTTP" = 200 ]; then
        SERVER_PID=$(cat "$WORK/serve.pid")
        echo "    server #$SERVE_N up (pid $SERVER_PID, log $SERVE_LOG)"
        return 0
      fi
    fi
    sleep 0.2
  done
  echo "    server #$SERVE_N did not come up; log:"
  tail -20 "$SERVE_LOG" | sed 's/^/      /'
  return 1
}

alive() { [ -n "$1" ] && [ -d "/proc/$1" ]; }

# stop_server SIGNAL: sets STOP_SECS (time until the process is gone).
stop_server() {
  local sig=$1 t0 i
  STOP_SECS=""
  [ -n "$SERVER_PID" ] || return 1
  t0=$(now)
  sudo kill -s "$sig" "$SERVER_PID"
  for ((i = 0; i < 600; i++)); do
    alive "$SERVER_PID" || break
    sleep 0.1
  done
  STOP_SECS=$(elapsed "$t0" "$(now)")
  if alive "$SERVER_PID"; then
    echo "      server still alive ${STOP_SECS}s after SIG$sig; killing it"
    sudo kill -9 "$SERVER_PID"
    sleep 0.5
    SERVER_PID=""
    return 1
  fi
  SERVER_PID=""
  return 0
}

# Read the SSE stream from the management namespace in the background.
start_sse() {
  SSE_LOG="$WORK/sse-$SERVE_N.log"
  nsx "$NS_M" sh -c 'echo $$ >"$1"; shift; exec "$@"' sh "$WORK/sse.pid" \
    curl -sN --max-time 900 "$BASE/api/events" >"$SSE_LOG" 2>&1 &
}

# --- host state ----------------------------------------------------------
# snapshot FILE: everything a run may change in $NS_A, normalised.
snapshot() {
  nsx "$NS_A" sh -c '
    echo "## links"
    ip -o link show | awk "{n=\$2; sub(/@.*/,\"\",n); sub(/:\$/,\"\",n); m=\"-\";
      for(i=1;i<=NF;i++) if(\$i==\"master\") m=\$(i+1); print n, \$3, \"master=\" m}" | sort
    echo "## addresses"
    ip -o addr show | awk "{print \$2, \$3, \$4}" | sort
    echo "## routes"
    ip route show table all | sort
    for t in raw filter nat mangle; do echo "## iptables $t"; iptables -t $t -S; done
    echo "## sysctls"
    sysctl -a 2>/dev/null | grep -E "^net\.(ipv4\.(ip_forward|conf\.)|ipv6\.conf\.|bridge\.)" | sort
    echo "## offloads"
    for i in os-a os-s os-m; do ethtool -k $i | grep -E "^(tx-checksumming|[[:space:]]+tx-checksum-)" | sed "s/^/$i /"; done
  ' >"$1" 2>&1
}

# same_as_baseline FILE: compare FILE with the baseline snapshot.
same_as_baseline() {
  if diff -u "$WORK/snap-baseline.txt" "$1" >"$1.diff"; then
    return 0
  fi
  echo "      host state differs from the baseline:"
  sed 's/^/        /' "$1.diff" | head -40
  return 1
}

# leftovers: one-line summary of the run state that cleanup must undo.
leftovers() {
  nsx "$NS_A" sh -c '
    links=$(ip -o link show | grep -c ": pcr")
    rules=0; for t in raw filter nat mangle; do
      r=$(iptables -t $t -S | grep -c outstation-run-); rules=$((rules + r)); done
    fwd=$(cat /proc/sys/net/ipv4/ip_forward)
    gw=$(ip -o addr show dev gwin | grep -c "'"$GW_IP"'/32")
    txc=$(ethtool -k os-a | sed -n "s/^tx-checksumming: \([a-z]*\).*/\1/p")
    echo "pcr_links=$links tagged_rules=$rules ip_forward=$fwd gw_alias=$gw os_a_tx_checksum=$txc"
  '
}
lo_field() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"; }

# --- run helpers ---------------------------------------------------------
# wait_run ID TIMEOUT_S: poll until terminal; sets RUN_STATUS, RESP.
wait_run() {
  local id=$1 t=$2 i
  RUN_STATUS=""
  for ((i = 0; i < t * 4; i++)); do
    api GET "/api/runs/$id"
    if [ "$HTTP" = 200 ]; then
      RUN_STATUS=$(jv 'd["status"]')
      [ "$RUN_STATUS" != running ] && return 0
    fi
    sleep 0.25
  done
  echo "      run $id still '$RUN_STATUS' after ${t}s"
  return 1
}

# wait_auto ID TIMEOUT_S: poll until auto-analysis settles; sets AUTO_STATE.
wait_auto() {
  local id=$1 t=$2 i
  AUTO_STATE=""
  for ((i = 0; i < t * 4; i++)); do
    api GET "/api/runs/$id"
    AUTO_STATE=$(jv '(d.get("auto_analysis") or {}).get("state") or ""')
    case "$AUTO_STATE" in done | failed | skipped) return 0 ;; esac
    sleep 0.25
  done
  echo "      auto-analysis of run $id still '$AUTO_STATE' after ${t}s"
  return 1
}

# wait_active ID: the run's topology is up and a session is running.
wait_active() {
  local id=$1 i
  for ((i = 0; i < 120; i++)); do
    api GET "/api/runs/$id"
    if [ "$(jv 'd["status"]')" != running ]; then
      echo "      run $id ended before it became active: $(jv 'd["status"]') $(jv 'd.get("error")')"
      return 1
    fi
    # The run's topology (bridge, rules, leases) lives for the whole
    # run; sessions come and go between iterations.
    if [ "$(jv 'any(p["iter_current"] >= 1 for p in d["per_source_progress"])')" = true ]; then
      local lo
      lo=$(leftovers)
      if [ "$(lo_field "$lo" pcr_links)" -gt 0 ] && [ "$(lo_field "$lo" tagged_rules)" -gt 0 ]; then
        return 0
      fi
    fi
    sleep 0.25
  done
  echo "      run $id never became active: $(jv '[(p["state"], p["sent"], p["iter_current"]) for p in d["per_source_progress"]]') $(leftovers)"
  return 1
}

# start_run BODY: POST /api/run; sets RID.
start_run() {
  RID=""
  post_json /api/run "$1"
  if [ "$HTTP" != 200 ]; then
    echo "      POST /api/run -> $HTTP $RESP"
    return 1
  fi
  RID=$(jv 'd["id"]')
}

master_body() { # [extra JSON members]
  printf '{"pcap_id":"%s","mode":"benchmark","role":"master","target_ip":"%s","nic":"os-a","warmup_secs":0%s}' \
    "$PCAP_ID" "$TARGET_IP" "${1:-}"
}
LONG_EXTRA=',"force":true,"iterations":0,"pacing":"original","speed":1.0'
GW_EXTRA=',"scada_gateway_ip":"'"$GW_IP"'","scada_gateway_iface":"gwin","upstream_nat_iface":"uplink"'
# Gateway mode is slave-role only (T17c): an unbounded slave run with
# the SCADA gateway and upstream NAT, its RTUs aliased on os-s.
slave_gw_body() {
  printf '{"pcap_id":"%s","mode":"benchmark","role":"slave","target_ip":"%s","alias_iface":"os-s","selected_rtus":%s,"warmup_secs":0,"iterations":0,"loop_within_session":true%s}' \
    "$PCAP_ID" "$MASTER_IP" "$RTUS_JSON" "$GW_EXTRA"
}

# slave_gw_phase SIGNAL: start an unbounded slave run with gateway mode,
# start its listeners, wait for its leases (gateway alias,
# ip_forward=1, the tagged NAT rule, an RTU alias on os-s), then stop
# the server with SIGNAL. TERM: the server must restore the host. KILL:
# the leases stay until `outstation cleanup` undoes them from the
# journal. Leaves the server stopped.
slave_gw_phase() {
  local sig=$1 i lo first ok=""
  start_run "$(slave_gw_body)" || { bad "start slave gateway run"; return 1; }
  local gw_run=$RID
  api POST "/api/runs/$RID/slaves/start_all"
  check "slave gateway run: start_all -> 200" eq "$HTTP" 200 || echo "      $RESP"
  first=$(jvs "$RTUS_JSON" 'd[0]')
  for ((i = 0; i < 80; i++)); do
    lo=$(leftovers)
    if [ "$(lo_field "$lo" gw_alias)" = 1 ] && [ "$(lo_field "$lo" ip_forward)" = 1 ] \
      && [ "$(lo_field "$lo" tagged_rules)" -gt 0 ] \
      && nsx "$NS_A" ip -o addr show dev os-s | grep -q " $first/32"; then
      ok=yes
      break
    fi
    sleep 0.25
  done
  echo "      slave gateway run $gw_run mid-run: $lo"
  check "slave gateway run: gateway alias, ip_forward=1, tagged NAT rule, RTU alias" eq "$ok" yes
  stop_server "$sig"
  if [ "$sig" = TERM ]; then
    check "slave gateway run: graceful shutdown logged" contains "$(cat "$SERVE_LOG")" "shutdown complete"
    snapshot "$WORK/snap-gw-term.txt"
    check "slave gateway run: SIGTERM restored the host" same_as_baseline "$WORK/snap-gw-term.txt"
  else
    lo=$(leftovers)
    echo "      slave gateway run after SIGKILL: $lo"
    check "slave gateway run: leases left by SIGKILL" eq \
      "$(lo_field "$lo" ip_forward)$(lo_field "$lo" gw_alias)" 11
    nsx "$NS_A" env RUST_LOG=info NO_COLOR=1 "$BIN" cleanup --state-dir "$STATE" >"$WORK/cleanup-gw.log" 2>&1
    check "slave gateway run: outstation cleanup -> exit 0" eq "$?" 0
    snapshot "$WORK/snap-gw-kill.txt"
    check "slave gateway run: cleanup restored everything" same_as_baseline "$WORK/snap-gw-kill.txt"
    local j
    j=$(sudo cat "$STATE/state-guards.txt" "$STATE/state-aliases.txt" 2>/dev/null | grep -c .)
    check "slave gateway run: guard and alias journals empty" eq "$j" 0
  fi
}

# =========================================================================
# Cases
# =========================================================================
PCAP="$WORK/smoke.pcap"
PCAP_ID=""
RTUS_JSON=""
RAW_RUN="" MASTER_RUN="" SLAVE_RUN="" STOP_RUN="" REFUSED_RUN="" FORCED_RUN=""
TERM_RUN="" KILL_RUN="" RERUN_FAIL="" RERUN_OK="" PROFILE_KEEP=""

case_upload() {
  python3 "$REPO/examples/gen_iec104_traffic.py" -n 4 -d 20 --seed 7 \
    --master-ip 192.168.86.1 --subnet 192.168.10.0/24 --start-time 1700000000 \
    -o "$PCAP" >"$WORK/gen.log" 2>&1 || { bad "generate pcap"; return 1; }
  ok "generated $(H pcap-count "$PCAP")"
  # The guard: a state-changing request without Origin is refused.
  HTTP=$(nsx "$NS_M" curl -s -o "$WORK/resp.body" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data '{}' "$BASE/api/inspect")
  RESP=$(cat "$WORK/resp.body")
  check "POST without Origin -> 403 origin_required" eq "$HTTP/$(jv 'd["code"]')" 403/origin_required
  api POST /api/pcaps -F "file=@$PCAP;filename=smoke.pcap"
  check "upload -> 200" eq "$HTTP" 200 || { echo "      $RESP"; return 1; }
  PCAP_ID=$(jv 'd["id"]')
  ok "pcap_id $PCAP_ID"
  local i v=""
  for ((i = 0; i < 100; i++)); do
    api GET /api/pcaps
    v=$(jv '[e for e in d if e["id"]=="'"$PCAP_ID"'"][0]')
    [ "$(jvs "$v" 'd["viability"] is not None')" = true ] && break
    sleep 0.2
  done
  check "library entry analysed" eq "$(jvs "$v" 'd["viability"] is not None')" true || return 1
  check "packets counted" eq "$(jvs "$v" 'd["packets"] > 0')" true
  check "viability verdict set" eq "$(jvs "$v" 'd["viability"]["verdict"] in ("ok","caution","heavy","not_recommended")')" true
  check "viability notes present" eq "$(jvs "$v" 'isinstance(d["viability"]["notes"], list) and len(d["viability"]["notes"]) > 0')" true
  echo "      verdict: $(jvs "$v" 'd["viability"]["verdict"] + " - " + d["viability"]["verdict_reason"]')"
  jvs "$v" '"\n".join("      note: " + n for n in d["viability"]["notes"])'
  check "4 slave RTUs, 1 master client" eq \
    "$(jvs "$v" '[len(d["viability"]["slave_rtus"]), len(d["viability"]["master_clients"])]')" "[4, 1]"
  RTUS_JSON=$(jvs "$v" 'sorted(r["ip"] for r in d["viability"]["slave_rtus"])')
  post_json /api/inspect "{\"pcap_id\":\"$PCAP_ID\"}"
  check "inspect -> 200" eq "$HTTP" 200 || return 1
  check "inspect: 5 sources, 4 TCP flows" eq "$(jv '[len(d["sources"]), len(d["tcp_flows"])]')" "[5, 4]"
  check "inspect: packet count matches the library" eq "$(jv 'd["packets"]')" "$(jvs "$v" 'd["packets"]')"
  post_json /api/inspect '{"path":"/etc/passwd"}'
  check "inspect by raw path -> 400 raw_path_rejected" eq "$HTTP/$(jv 'd["code"]')" 400/raw_path_rejected
}

# raw_run EXTRA_JSON TAG: raw replay to the fake MAC, download the
# capture and compare it with the source; sets RID, RAW_CMP, RAW_SENT,
# RAW_CAP_PK.
raw_run() {
  RAW_CMP="" RAW_SENT="" RAW_CAP_PK=""
  start_run "{\"pcap_id\":\"$PCAP_ID\",\"mode\":\"raw\",\"target_ip\":\"$TARGET_IP\",\"target_mac\":\"$FAKE_MAC\",\"nic\":\"os-a\",\"force\":true,\"skip_non_ip\":true,\"warmup_secs\":0$1}" || {
    bad "start raw run ($2)"; return 1; }
  wait_run "$RID" 90 || { bad "raw run finished ($2)"; return 1; }
  check "$2: completed" eq "$RUN_STATUS" completed || echo "      error: $(jv 'd.get("error")')"
  check "$2: has_capture" eq "$(jv 'd["has_capture"]')" true
  RAW_SENT=$(jv 'd["report"]["total_packets"]')
  RAW_CAP_PK=$(jv 'd["report"]["captured_packets"]')
  local only
  only=$(jv '",".join(d["request"]["only_src"])')
  echo "      report: $(jv 'len(d["report"]["per_source"])') sources, sent $RAW_SENT, captured $RAW_CAP_PK, errors $(jv 'd["report"]["total_errors"]')"
  download "/api/runs/$RID/download" "$WORK/raw-$RID.pcap"
  check "$2: download -> 200" eq "$HTTP" 200 || return 1
  RAW_CMP=$(H pcap-replay "$PCAP" "$WORK/raw-$RID.pcap" "$TARGET_IP" "$FAKE_MAC" "$only")
  echo "      capture: $RAW_CMP"
  local file_frames
  file_frames=$(jvs "$RAW_CMP" 'd["captured_frames"]')
  check "$2: report.captured_packets == frames in the file" eq "$RAW_CAP_PK" "$file_frames"
  check "$2: capture dropped nothing" eq "$(jv 'd["report"].get("captured_dropped", 0)')" 0
  check "$2: every replayed frame is in the capture" eq "$(jvs "$RAW_CMP" 'd["missing"]')" 0
  # Each replayed frame exactly once, and nothing else: the fake target
  # MAC answers nothing, and the run's own interfaces send nothing of
  # their own (no IGMP from the bridge, no IPv6).
  check "$2: each frame captured exactly once, nothing else" eq \
    "$(jvs "$RAW_CMP" '[d["captured_to_target"], d["unexpected"], d["captured_other"]]')" "[$RAW_SENT, 0, 0]"
}

case_raw_capture() {
  need PCAP_ID || return 1
  # One source at top speed: one bridge port, so the capture must hold
  # each replayed frame exactly once.
  raw_run ',"top_speed":true,"only_src":["192.168.10.3"]' "1 source, top speed" || return 1
  # All five sources: the frames to the (unlearned) target MAC are
  # flooded across the run bridge, yet each is captured once (B1).
  raw_run ',"top_speed":true' "5 sources, top speed" || return 1
  raw_run ',"speed":4.0' "5 sources, speed 4" || return 1
  RAW_RUN=$RID
  api GET "/api/runs/$RAW_RUN/gaps"
  check "gap histogram -> 200" eq "$HTTP" 200
  check "gap histogram: original and captured gaps counted" eq \
    "$(jv 'sum(d["original"]) > 0 and sum(d["captured"]) > 0')" true
  echo "      gaps: original $(jv 'sum(d["original"])'), captured $(jv 'sum(d["captured"])')"
  snapshot "$WORK/snap-raw.txt"
  check "host state restored after the raw runs" same_as_baseline "$WORK/snap-raw.txt"
}

case_master() {
  need PCAP_ID || return 1
  start_run "$(master_body ',"force":true,"iterations":1')" || { bad "start master run"; return 1; }
  MASTER_RUN=$RID
  wait_run "$RID" 120 || { bad "master run finished"; return 1; }
  check "master run completed" eq "$RUN_STATUS" completed || echo "      error: $(jv 'd.get("error")')"
  echo "      sent $(jv 'd["benchmark"]["total_messages_sent"]') msgs, sessions $(jv 'len(d["benchmark"]["per_session"])'), p99 $(jv 'd["benchmark"]["aggregate_latency_p99_us"]') us"
  check "no failed sessions" eq "$(jv '[s["error"] for s in d["benchmark"]["per_session"] if s["error"]]')" "[]"
  wait_auto "$RID" 60
  check "auto-analysis done" eq "$AUTO_STATE" done || echo "      $(jv 'd.get("auto_analysis")')"
  check "verdict all_correct" eq "$(jv '(d.get("latest_analysis") or {}).get("verdict")')" all_correct
  echo "      analysis: $(jv 'd.get("latest_analysis")')"
  local i ev=""
  for ((i = 0; i < 40; i++)); do
    ev=$(H sse "$SSE_LOG")
    [ "$(jvs "$ev" 'any(e["event"]=="analysis_finished" and e["data"]["run_id"]=='"$RID"' for e in d)')" = true ] && break
    sleep 0.25
  done
  local kinds
  kinds=$(jvs "$ev" '[e["event"] for e in d if e["event"]=="hello" or (isinstance(e["data"], dict) and e["data"].get("run_id")=='"$RID"')]')
  echo "      SSE for run $RID: $kinds"
  check "SSE run_started, run_finished, analysis_finished in order" eq \
    "$(jvs "$kinds" '[k for k in d if k in ("run_started","run_finished","analysis_finished")]')" \
    '["run_started", "run_finished", "analysis_finished"]'
  check "SSE run_finished carries status and client_ip" eq \
    "$(jvs "$ev" '[(e["data"]["status"], e["data"]["client_ip"]) for e in d if e["event"]=="run_finished" and e["data"]["run_id"]=='"$RID"']')" \
    "[[\"completed\", \"$CLIENT_IP\"]]"
  check "SSE analysis_finished carries the verdict" eq \
    "$(jvs "$ev" '[e["data"]["status"] for e in d if e["event"]=="analysis_finished" and e["data"]["run_id"]=='"$RID"']')" '["all_correct"]'
  snapshot "$WORK/snap-master.txt"
  check "host state restored after the master run" same_as_baseline "$WORK/snap-master.txt"
}

case_slave() {
  need PCAP_ID RTUS_JSON || return 1
  start_run "{\"pcap_id\":\"$PCAP_ID\",\"mode\":\"benchmark\",\"role\":\"slave\",\"target_ip\":\"$MASTER_IP\",\"alias_iface\":\"os-s\",\"selected_rtus\":$RTUS_JSON,\"warmup_secs\":0,\"iterations\":1}" || {
    bad "start slave run"; return 1; }
  SLAVE_RUN=$RID
  local i n=0
  for ((i = 0; i < 80; i++)); do
    api GET "/api/runs/$RID"
    n=$(jv 'len([p for p in d["per_source_progress"] if p["state"]=="pending"])')
    [ "$n" = 4 ] && break
    sleep 0.25
  done
  check "4 listeners pending" eq "$n" 4 || { echo "      $(jv 'd["per_source_progress"]')"; return 1; }
  api POST "/api/runs/$RID/slaves/start_all"
  check "start_all -> 200" eq "$HTTP" 200 || echo "      $RESP"
  local ips
  ips=$(jvs "$RTUS_JSON" '" ".join(d)')
  # shellcheck disable=SC2086
  nsx "$NS_P" timeout 150 python3 "$REPO/scripts/iec104-mock-master.py" --port 2404 --quiet 2 $ips \
    >"$WORK/mock-master.log" 2>&1
  local mrc=$?
  sed 's/^/      master: /' "$WORK/mock-master.log"
  check "mock master completed every station" eq "$mrc" 0
  wait_run "$RID" 120 || { bad "slave run finished"; return 1; }
  check "slave run completed" eq "$RUN_STATUS" completed || echo "      error: $(jv 'd.get("error")')"
  check "4 sources, none failed" eq "$(jv '[len(d["per_source_progress"]), [p["state"] for p in d["per_source_progress"] if p["state"]!="completed"]]')" "[4, []]"
  check "has_capture" eq "$(jv 'd["has_capture"]')" true
  wait_auto "$RID" 60
  check "auto-analysis done" eq "$AUTO_STATE" done || echo "      $(jv 'd.get("auto_analysis")')"
  echo "      analysis: $(jv 'd.get("latest_analysis")')"
  check "score 100" eq "$(jv '(d.get("latest_analysis") or {}).get("score")')" 100.0
  local addrs
  addrs=$(nsx "$NS_A" ip -o -4 addr show dev os-s | awk '{print $4}' | sort | tr '\n' ' ')
  check "pre-existing alias $OWN_ALIAS survived, run aliases removed" eq "$addrs" "10.79.0.1/24 $OWN_ALIAS/32 "
  snapshot "$WORK/snap-slave.txt"
  check "host state restored after the slave run" same_as_baseline "$WORK/snap-slave.txt"
}

case_concurrent() {
  need PCAP_ID MASTER_RUN || return 1
  start_run "$(master_body "$LONG_EXTRA")" || { bad "start long run"; return 1; }
  STOP_RUN=$RID
  check "long run active" wait_active "$RID" || return 1
  post_json /api/run "$(master_body ',"force":true')"
  check "second POST /api/run -> 409" eq "$HTTP" 409
  check "code run_active, active_run_id, client_ip" eq \
    "$(jv '[d["code"], d["active_run_id"], d["client_ip"]]')" "[\"run_active\", $RID, \"$CLIENT_IP\"]"
  api POST "/api/runs/$MASTER_RUN/rerun?force=true"
  check "rerun while active -> 409 run_active" eq "$HTTP/$(jv 'd["code"]')" 409/run_active
  api GET "/api/runs?status=running"
  check "exactly one running run" eq "$(jv '[r["id"] for r in d]')" "[$RID]"
  api GET "/api/runs/$RID"
  echo "      running $(( $(date +%s) - $(jv 'd["started_at"]') ))s: iteration $(jv 'max(p["iter_current"] for p in d["per_source_progress"])'), $(jv 'd["sent"]') sent this iteration"
  api POST "/api/runs/$RID/stop"
  check "stop -> 202" eq "$HTTP" 202
  wait_run "$RID" 30 || { bad "run stopped in time"; return 1; }
  check "status stopped" eq "$RUN_STATUS" stopped
  check "finished_at set" eq "$(jv 'd["finished_at"] is not None')" true
  check "sessions cancelled, not failed" eq \
    "$(jv '[s["cancelled"] for s in d["benchmark"]["per_session"]] == [True]*len(d["benchmark"]["per_session"])')" true
  api POST "/api/runs/$RID/stop"
  check "stop again -> 200 (already terminal)" eq "$HTTP/$(jv 'd["status"]')" 200/stopped
  snapshot "$WORK/snap-stop.txt"
  check "host state restored after stop" same_as_baseline "$WORK/snap-stop.txt"
}

case_protected() {
  need PCAP_ID || return 1
  post_json /api/run "$(master_body ',"iterations":1')"
  if [ "$HTTP" = 200 ]; then
    REFUSED_RUN=$(jv 'd["id"]')
    wait_run "$REFUSED_RUN" 30 || { bad "refused run finished"; return 1; }
    check "default-route NIC without force: run failed" eq "$RUN_STATUS" failed
    check "error explains the refusal" contains "$(jv 'd.get("error") or ""')" "refusing to"
    check "error names the default route and force" contains "$(jv 'd.get("error") or ""')" "force"
    echo "      error: $(jv 'd.get("error")')"
  else
    check "default-route NIC without force refused at POST" contains "$RESP" "refusing to"
  fi
  snapshot "$WORK/snap-refused.txt"
  check "nothing touched by the refused run" same_as_baseline "$WORK/snap-refused.txt"
  start_run "$(master_body ',"force":true,"iterations":1')" || { bad "start forced run"; return 1; }
  FORCED_RUN=$RID
  wait_run "$RID" 120 || { bad "forced run finished"; return 1; }
  check "with force: run completed" eq "$RUN_STATUS" completed || echo "      error: $(jv 'd.get("error")')"
  snapshot "$WORK/snap-forced.txt"
  check "host state restored after the forced run" same_as_baseline "$WORK/snap-forced.txt"
}

case_sigterm() {
  need PCAP_ID RTUS_JSON SERVER_PID || return 1
  # Gateway mode is refused in master role (T17c).
  post_json /api/run "$(master_body "$LONG_EXTRA$GW_EXTRA")"
  check "master run with gateway mode -> 400 gateway_requires_slave" eq \
    "$HTTP/$(jv 'd.get("code")')" 400/gateway_requires_slave
  # The gateway leases first: an unbounded slave run with gateway mode,
  # stopped with SIGTERM.
  slave_gw_phase TERM || return 1
  start_server || { bad "restart"; return 1; }
  start_run "$(master_body "$LONG_EXTRA")" || { bad "start long run"; return 1; }
  TERM_RUN=$RID
  check "long run active" wait_active "$RID" || return 1
  local lo
  lo=$(leftovers)
  echo "      mid-run: $lo"
  check "mid-run: pcr interfaces, tagged rules, tx-checksum off" eq \
    "$( [ "$(lo_field "$lo" pcr_links)" -gt 0 ] && [ "$(lo_field "$lo" tagged_rules)" -gt 0 ] && echo yes)$(lo_field "$lo" os_a_tx_checksum)" \
    "yesoff"
  stop_server TERM
  local rc=$?
  echo "      exited ${STOP_SECS}s after SIGTERM"
  check "exited within TimeoutStopSec (${STOP_TIMEOUT}s)" eq "$rc$(ge "$STOP_TIMEOUT" "$STOP_SECS" >/dev/null && echo in)" 0in
  check "graceful shutdown logged" contains "$(cat "$SERVE_LOG")" "shutdown complete"
  echo "      after: $(leftovers)"
  snapshot "$WORK/snap-sigterm.txt"
  check "no pcr*, no outstation-run-* rules, sysctls/offloads/addresses restored" same_as_baseline "$WORK/snap-sigterm.txt"
  start_server || { bad "restart"; return 1; }
  api GET "/api/runs/$RID"
  check "after restart: run is stopped" eq "$(jv 'd["status"]')" stopped
  check "after restart: finished_at set" eq "$(jv 'd["finished_at"] is not None')" true
  # It finished during shutdown, too late to be analysed: the restart
  # picks it up (O3).
  wait_auto "$RID" 60
  check "after restart: stopped run auto-analysed" eq \
    "$AUTO_STATE/$(jv '(d.get("latest_analysis") or {}).get("source")')" done/auto
  check "startup backlog logged" contains "$(cat "$SERVE_LOG")" "queueing auto-analysis of finished runs"
}

case_sigkill() {
  need PCAP_ID RTUS_JSON SERVER_PID || return 1
  # The gateway leases first: an unbounded slave run with gateway mode,
  # killed, then `outstation cleanup`. The restart skips auto-analysis
  # (case 9 needs a run without a stored analysis).
  slave_gw_phase KILL || return 1
  start_server --no-auto-analyze || { bad "restart"; return 1; }
  start_run "$(master_body "$LONG_EXTRA")" || { bad "start long run"; return 1; }
  KILL_RUN=$RID
  check "long run active" wait_active "$RID" || return 1
  stop_server KILL
  local lo
  lo=$(leftovers)
  echo "      after SIGKILL: $lo"
  check "leftovers exist: pcr interfaces, tagged rules, tx-checksum off" eq \
    "$( [ "$(lo_field "$lo" pcr_links)" -gt 0 ] && [ "$(lo_field "$lo" tagged_rules)" -gt 0 ] && echo yes)$(lo_field "$lo" os_a_tx_checksum)" \
    "yesoff"
  local jn
  jn=$(sudo cat "$STATE/state-guards.txt" 2>/dev/null | grep -c .)
  echo "      guard journal: $jn entries"
  check "guard journal records the leases" ge "$jn" 1
  nsx "$NS_A" env RUST_LOG=info NO_COLOR=1 "$BIN" cleanup --state-dir "$STATE" >"$WORK/cleanup-1.log" 2>&1
  check "outstation cleanup -> exit 0" eq "$?" 0
  sed 's/^/      cleanup: /' "$WORK/cleanup-1.log" | grep -E "undid|restored|removed|error" | head -12
  echo "      after cleanup: $(leftovers)"
  snapshot "$WORK/snap-cleanup.txt"
  check "cleanup restored everything" same_as_baseline "$WORK/snap-cleanup.txt"
  local j
  j=$(sudo cat "$STATE/state-guards.txt" "$STATE/state-aliases.txt" 2>/dev/null | grep -c .)
  check "guard and alias journals empty" eq "$j" 0
  nsx "$NS_A" env RUST_LOG=info NO_COLOR=1 "$BIN" cleanup --state-dir "$STATE" >"$WORK/cleanup-2.log" 2>&1
  check "second cleanup -> exit 0" eq "$?" 0
  check "second cleanup undid nothing" eq "$(grep -c 'undid host changes' "$WORK/cleanup-2.log")" 0
  # Restart without auto-analysis: case 9 needs a run without a stored
  # analysis for the compare 409 path.
  start_server --no-auto-analyze || { bad "restart"; return 1; }
  check "startup cleanup undid nothing (idempotent)" eq "$(grep -c 'undid host changes' "$SERVE_LOG")" 0
  snapshot "$WORK/snap-restart.txt"
  check "host state unchanged by the restart" same_as_baseline "$WORK/snap-restart.txt"
  api GET "/api/runs/$RID"
  check "after restart: run failed (orphaned)" eq "$(jv 'd["status"]')" failed
  check "after restart: error says interrupted" contains "$(jv 'd.get("error") or ""')" "interrupted by server restart"
  check "after restart: finished_at set" eq "$(jv 'd["finished_at"] is not None')" true
  api GET "/api/runs?status=running"
  check "no run left running" eq "$RESP" "[]"
}

case_rerun_compare_metrics() {
  need PCAP_ID MASTER_RUN SERVER_PID || return 1
  # Re-run without ?force: force is not inherited, the default-route
  # NIC is refused again.
  api POST "/api/runs/$MASTER_RUN/rerun"
  check "rerun -> 200" eq "$HTTP" 200 || { echo "      $RESP"; return 1; }
  RERUN_FAIL=$(jv 'd["id"]')
  check "rerun_of and force:false echoed" eq "$(jv '[d["rerun_of"], d["request"]["force"]]')" "[$MASTER_RUN, false]"
  wait_run "$RERUN_FAIL" 30
  check "rerun without force failed (protected NIC)" eq "$RUN_STATUS" failed
  api POST "/api/runs/$MASTER_RUN/rerun?force=true"
  check "rerun?force=true -> 200" eq "$HTTP" 200 || return 1
  RERUN_OK=$(jv 'd["id"]')
  wait_run "$RERUN_OK" 120
  check "forced rerun completed" eq "$RUN_STATUS" completed
  check "rerun_of recorded" eq "$(jv 'd["rerun_of"]')" "$MASTER_RUN"
  check "no auto-analysis (server runs with --no-auto-analyze)" eq "$(jv 'd.get("latest_analysis")')" ""

  # Compare: 409 analysis_missing -> POST analyze -> 200.
  api GET "/api/runs/$MASTER_RUN/compare/$RERUN_OK"
  check "compare -> 409 analysis_missing" eq "$HTTP/$(jv 'd["code"]')" 409/analysis_missing
  check "409 names the run and has_capture" eq "$(jv '[d["run_id"], d["has_capture"]]')" "[$RERUN_OK, true]"
  api POST "/api/runs/$RERUN_OK/analyze"
  check "POST analyze -> 200" eq "$HTTP" 200 || echo "      $RESP"
  check "on-demand verdict all_correct" eq "$(jv '[d["verdict"], d["source"]]')" '["all_correct", "on_demand"]'
  api GET "/api/runs/$MASTER_RUN/compare/$RERUN_OK"
  check "compare -> 200" eq "$HTTP" 200 || { echo "      $RESP"; return 1; }
  check "compare sides and sources" eq \
    "$(jv '[d["a"]["run_id"], d["b"]["run_id"], d["a"]["analysis_source"], d["b"]["analysis_source"]]')" \
    "[$MASTER_RUN, $RERUN_OK, \"auto\", \"on_demand\"]"
  check "same RTU set on both sides" eq "$(jv '[d["only_in_a"], d["only_in_b"], len(d["rtus"]) > 0]')" "[[], [], true]"
  echo "      regressed=$(jv 'd["regressed"]') regressions=$(jv '[r.get("metric") or r for r in d["regressions"]]')"
  api GET "/api/runs/$MASTER_RUN/compare/$RAW_RUN"
  check "compare with a raw run -> 400 not_benchmark" eq "$HTTP/$(jv 'd["code"]')" 400/not_benchmark

  # Profiles CRUD.
  local req pid
  req=$(master_body ',"iterations":2')
  post_json /api/profiles "{\"name\":\"smoke master\",\"request\":$req}"
  check "create profile -> 201" eq "$HTTP" 201 || { echo "      $RESP"; return 1; }
  pid=$(jv 'd["id"]')
  check "stored canonical (defaults filled)" eq "$(jv '[d["request"]["iterations"], d["request"]["pacing"], d["request"]["listen_port_base"], "bridge" in d["request"]]')" '[2, "fast", 2404, false]'
  post_json /api/profiles "{\"name\":\"smoke master\",\"request\":$req}"
  check "duplicate name -> 409 profile_exists" eq "$HTTP/$(jv 'd["code"]')" 409/profile_exists
  post_json /api/profiles '{"name":"bad","request":{"target_ip":"10.0.0.1","mode":"warp"}}'
  check "invalid request -> 400/422" contains "400 422" "$HTTP"
  api GET "/api/profiles/$pid"
  check "get profile" eq "$HTTP/$(jv 'd["name"]')" "200/smoke master"
  api PUT "/api/profiles/$pid" -H 'Content-Type: application/json' --data '{"name":"smoke renamed"}'
  check "rename profile" eq "$HTTP/$(jv 'd["name"]')/$(jv 'd["request"]["iterations"]')" "200/smoke renamed/2"
  post_json /api/profiles "{\"name\":\"smoke keep\",\"request\":$(master_body ',"force":true')}"
  PROFILE_KEEP=$(jv 'd["id"]')
  api GET /api/profiles
  check "list sorted by name" eq "$(jv '[p["name"] for p in d]')" '["smoke keep", "smoke renamed"]'
  api DELETE "/api/profiles/$pid"
  check "delete profile -> 204" eq "$HTTP" 204
  api GET "/api/profiles/$pid"
  check "deleted profile -> 404" eq "$HTTP" 404

  # Metrics consistent with the runs and analyses performed.
  check_metrics
}

# check_metrics: /metrics agrees with /api/runs and the stored analyses.
check_metrics() {
  api GET /api/runs
  local runs="$RESP" analyses="[]" id
  for id in $(jvs "$runs" '" ".join(str(r["id"]) for r in d)'); do
    api GET "/api/runs/$id/analyses"
    analyses=$(printf '%s\n%s' "$analyses" "$RESP" | python3 -c '
import json, sys
a, b = sys.stdin.read().split("\n", 1)
print(json.dumps(json.loads(a) + json.loads(b)))')
  done
  api GET /metrics
  check "/metrics -> 200" eq "$HTTP" 200 || return 1
  printf '%s' "$RESP" >"$WORK/metrics.txt"
  local m
  m=$(H metrics "$WORK/metrics.txt")
  check "outstation_up 1, idle" eq "$(jvs "$m" '[d.get("outstation_up"), d.get("outstation_active_run_id")]')" "[1.0, 0.0]"
  local want got
  want=$(jvs "$runs" '{s: sum(1 for r in d if r["status"]==s) for s in ("running","completed","partial","stopped","failed")}')
  got=$(jvs "$m" '{s: int(d["outstation_runs{status=\"%s\"}" % s]) for s in ("running","completed","partial","stopped","failed")}')
  echo "      runs by status: $got"
  check "outstation_runs by status == /api/runs" eq "$got" "$want"
  want=$(jvs "$runs" 'sum((r["benchmark"] or {}).get("total_messages_sent") if r["benchmark"] else (r["report"]["total_packets"] if r["report"] else r["sent"]) for r in d)')
  check "outstation_frames_sent_total == sum over runs" eq "$(jvs "$m" 'int(d["outstation_frames_sent_total"])')" "$want"
  want=$(jvs "$runs" 'max([r["id"] for r in d if r["benchmark"] and r["status"]!="running"] or [0])')
  check "outstation_last_benchmark_run_id == newest finished benchmark" eq "$(jvs "$m" 'int(d["outstation_last_benchmark_run_id"])')" "$want"
  want=$(jvs "$runs" 'sum(1 for r in d if r["finished_at"])')
  check "outstation_run_duration_seconds_count == finished runs" eq "$(jvs "$m" 'int(d["outstation_run_duration_seconds_count"])')" "$want"
  want=$(jvs "$analyses" '{s: sum(1 for a in d if a["source"]==s) for s in ("auto","manual","on_demand")}')
  got=$(jvs "$m" '{s: int(d.get("outstation_analyses_stored{source=\"%s\"}" % s, -1)) for s in ("auto","manual","on_demand")}')
  echo "      analyses stored: $got"
  check "outstation_analyses_stored == stored analyses by source" eq "$got" "$want"
  check "outstation_analyses_total{on_demand,ok} == 1 (this process)" eq \
    "$(jvs "$m" 'int(d["outstation_analyses_total{source=\"on_demand\",result=\"ok\"}"])')" 1
}

# Persisted state as seen over the API, normalised for comparison.
api_state() {
  api GET /api/runs
  local runs="$RESP" id out
  out=$(jvs "$runs" '[[r["id"], r["status"], r["finished_at"], r["has_capture"], r["rerun_of"], (r["latest_analysis"] or {}).get("id"), r["error"]] for r in d]')
  echo "runs $out"
  for id in $(jvs "$runs" '" ".join(str(r["id"]) for r in d)'); do
    api GET "/api/runs/$id/analyses"
    echo "analyses $id $(jv '[[a.get("id"), a.get("verdict"), a.get("source")] for a in d]' 2>/dev/null || echo "$RESP")"
    if [ "$(jvs "$runs" '[r["has_capture"] for r in d if r["id"]=='"$id"'][0]')" = true ]; then
      download "/api/runs/$id/download" "$WORK/dl-$id.pcap"
      echo "capture $id $HTTP $(sha256sum <"$WORK/dl-$id.pcap" | cut -c1-16)"
    fi
  done
  api GET /api/profiles
  echo "profiles $(jv '[[p["id"], p["name"], p["request"]] for p in d]')"
  api GET /api/pcaps
  echo "pcaps $(jv '[[e["id"], e["name"], e["packets"], e["viability"]["verdict"]] for e in d]')"
}

case_persistence() {
  need SERVER_PID || return 1
  api_state >"$WORK/api-before.txt"
  check "captures downloadable before restart" eq "$(grep -c '^capture .* 200 ' "$WORK/api-before.txt")" \
    "$(grep -c '^capture ' "$WORK/api-before.txt")"
  stop_server TERM
  check "SIGTERM while idle: exited" eq "$?" 0
  # Without auto-analysis: the orphaned run of case 8 has no analysis
  # and would otherwise be analysed by the startup backlog (case 7
  # checks that), changing the state compared here.
  start_server --no-auto-analyze || { bad "restart"; return 1; }
  api_state >"$WORK/api-after.txt"
  if diff -u "$WORK/api-before.txt" "$WORK/api-after.txt" >"$WORK/api.diff"; then
    ok "run history, captures (sha256), analyses, profiles and library identical after restart"
  else
    bad "API state differs after restart"
    sed 's/^/        /' "$WORK/api.diff" | head -30
  fi
  echo "      $(grep -c '^capture ' "$WORK/api-after.txt") captures, $(grep '^analyses' "$WORK/api-after.txt" | grep -vc '\[\]$') runs with analyses"
  check "startup cleanup undid nothing" eq "$(grep -c 'undid host changes' "$SERVE_LOG")" 0
  need KILL_RUN || return 1
  api GET "/api/runs/$KILL_RUN"
  local cap
  cap=$(jv 'd.get("capture_file") or ""')
  check "orphaned run $KILL_RUN has a capture file" eq "$(jv 'd["has_capture"]')$( [ -n "$cap" ] && sudo test -f "$cap" && echo -file)" true-file
  api DELETE "/api/runs/$KILL_RUN"
  check "DELETE run -> 204" eq "$HTTP" 204
  api GET "/api/runs/$KILL_RUN"
  check "deleted run -> 404" eq "$HTTP" 404
  check "its capture file is gone" eq "$( [ -n "$cap" ] && sudo test -e "$cap" && echo present || echo gone)" gone
  api GET /api/runs
  check "deleted run gone from the list" eq "$(jv '[r["id"] for r in d if r["id"]=='"$KILL_RUN"']')" "[]"
  api DELETE "/api/pcaps/$PCAP_ID"
  check "deleting a pcap that runs use -> 409" eq "$HTTP" 409
}

# =========================================================================
setup_topology
start_server || exit 1
start_sse
snapshot "$WORK/snap-baseline.txt"
echo "baseline host state: $(grep -c . "$WORK/snap-baseline.txt") lines; $(leftovers)"

run_case 1 "upload + inspect + viability" case_upload
run_case 2 "raw run with mirror capture" case_raw_capture
run_case 3 "master benchmark + auto-analysis + SSE" case_master
run_case 4 "slave benchmark + score + own alias kept" case_slave
run_case 5 "concurrent run rejected + stop" case_concurrent
run_case 6 "protected NIC needs force" case_protected
run_case 7 "SIGTERM mid-run restores host" case_sigterm
run_case 8 "SIGKILL + outstation cleanup + restart" case_sigkill
run_case 9 "rerun, profiles, compare, metrics" case_rerun_compare_metrics
run_case 10 "restart persistence + delete" case_persistence

if [ -n "$SERVER_PID" ]; then
  stop_server TERM || OVERALL_FAIL=1
fi

echo
echo "================ netns smoke results ================"
printf '%-4s %-44s %-6s %8s\n' case name result seconds
for r in "${RESULTS[@]}"; do
  IFS='|' read -r id name res secs <<<"$r"
  printf '%-4s %-44s %-6s %8s\n' "$id" "$name" "$res" "$secs"
done
if [ "$OVERALL_FAIL" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
exit 0
