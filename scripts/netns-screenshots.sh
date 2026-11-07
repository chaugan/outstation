#!/usr/bin/env bash
# Refresh the README's UI screenshots (doc/images/ui-*.jpg) from a real
# `outstation serve` (release build) with real, completed runs, inside
# throwaway network namespaces. Nothing outside them is touched.
#
#   $NS_M (browser, curl)       $NS_A (outstation serve)          $NS_P (SCADA master side)
#   os-n 10.66.0.2 <--veth-->   os-m 10.66.0.1:8080               s-p 10.79.0.2/24
#                               s-o 10.79.0.1/24 <----veth---->   route 192.168.10.0/24 dev s-p
#                               os-a (egress NIC, forced) <-+      mock IEC 104 master
#                                                           |     $NS_T: bridge "lan" 10.77.0.1/24,
#                                                           +-->  mock IEC 104 slave
#
# Runs, all real:
#   A  slave role, the 200-RTU example capture, original timing (about
#      200 s), a master peer (netns-scale-helper.py fast-master)
#      connecting to all 200 RTUs; the live
#      diagram is captured while it runs
#   B  the same at speed 2 (for Compare A vs B)
#   C  master role, 20 captured masters, as fast as possible, against
#      the mock slave
# Every run is auto-analysed. Then scripts/ui-screenshots.mjs, run with
# Chromium inside $NS_M, takes Library, Configure, Runs, Analysis and
# Compare.
#
# Usage: scripts/netns-screenshots.sh [OUT_DIR]   (default doc/images)
#        e.g. OUTSTATION_BIN=target/release/outstation scripts/netns-screenshots.sh
#        Rerun it unchanged after UI changes; it overwrites doc/images/ui-*.jpg
#        (ui-library, ui-configure, ui-runs-live, ui-runs, ui-analysis,
#        ui-compare; 1440 wide, JPEG, each under 400 KB) and takes about 8
#        minutes (run A plays 200 s of capture at original timing).
#        Exit 1 when an image is over 400 KB.
# Env:   NS_PREFIX (default ostest-shots; must start with "ostest-"),
#        OUTSTATION_BIN, WORK, PLAYWRIGHT_DIR, CARGO_TARGET_DIR.
# Needs: sudo, iproute2, iptables, ethtool, curl, python3, node, and
#        Playwright with Chromium (LD_LIBRARY_PATH for its system
#        libraries is taken from /opt/code/tools/browser/sysdeps when
#        present).
set -uo pipefail

NS_PREFIX="${NS_PREFIX:-ostest-shots}"
case "$NS_PREFIX" in ostest-*) ;; *) echo "NS_PREFIX must start with ostest-" >&2; exit 2 ;; esac
NS_A="$NS_PREFIX-a"
NS_T="$NS_PREFIX-t"
NS_M="$NS_PREFIX-m"
NS_P="$NS_PREFIX-p"
for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
  if sudo ip netns list | grep -qw "^$ns"; then
    echo "namespace $ns already exists; delete it first" >&2
    exit 1
  fi
done
cd "$(dirname "$0")/.."
REPO="$(pwd)"
OUT="${1:-$REPO/doc/images}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
HELPER="$REPO/scripts/netns-scale-helper.py"
if [ -n "${OUTSTATION_BIN:-}" ]; then
  BIN="$OUTSTATION_BIN"
else
  BIN="$(cargo build --release -p outstation --message-format=json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "outstation":
        print(m["executable"])
')"
fi
[ -x "$BIN" ] || { echo "no outstation binary" >&2; exit 1; }
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ostest-shots.XXXXXX")}"
mkdir -p "$WORK/state/library"
WORK="$(cd "$WORK" && pwd)"
SYSDEPS=/opt/code/tools/browser/sysdeps/extracted/usr/lib/x86_64-linux-gnu
BASE=http://10.66.0.1:8080
echo "binary: $BIN"
echo "work dir: $WORK"

teardown() {
  local ns
  for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
  done
  sleep 1
  for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true
    sudo ip netns del "$ns" 2>/dev/null || true
  done
}
trap 'teardown; wait 2>/dev/null' EXIT
trap 'exit 130' INT TERM
nsx() { local ns=$1; shift; sudo ip netns exec "$ns" "$@"; }

for ns in "$NS_A" "$NS_T" "$NS_M" "$NS_P"; do
  sudo ip netns add "$ns"
  sudo ip -n "$ns" link set lo up
  nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
done
sudo ip -n "$NS_T" link add lan type bridge
sudo ip -n "$NS_T" link set lan up
sudo ip -n "$NS_T" addr add 10.77.0.1/24 dev lan
sudo ip -n "$NS_A" link add os-a type veth peer name os-b netns "$NS_T"
sudo ip -n "$NS_T" link set os-b master lan
sudo ip -n "$NS_T" link set os-b up
sudo ip -n "$NS_A" link set os-a up
sudo ip -n "$NS_T" route add default dev lan
sudo ip -n "$NS_A" route add default dev os-a
sudo ip -n "$NS_A" link add os-m type veth peer name os-n netns "$NS_M"
sudo ip -n "$NS_A" addr add 10.66.0.1/24 dev os-m
sudo ip -n "$NS_A" link set os-m up
sudo ip -n "$NS_M" addr add 10.66.0.2/24 dev os-n
sudo ip -n "$NS_M" link set os-n up
sudo ip -n "$NS_A" link add s-o type veth peer name s-p netns "$NS_P"
sudo ip -n "$NS_A" addr add 10.79.0.1/24 dev s-o
sudo ip -n "$NS_A" link set s-o up
sudo ip -n "$NS_P" addr add 10.79.0.2/24 dev s-p
sudo ip -n "$NS_P" link set s-p up
sudo ip -n "$NS_P" route add 192.168.10.0/24 dev s-p
nsx "$NS_T" python3 "$REPO/scripts/iec104-mock-slave.py" 10.77.0.1 2404 >"$WORK/mock-slave.log" 2>&1 &

nsx "$NS_A" env RUST_LOG=info NO_COLOR=1 OUTSTATION_LIBRARY_DIR="$WORK/state/library" \
  OUTSTATION_MIN_FREE_MB=16 "$BIN" serve --bind 10.66.0.1:8080 >"$WORK/serve.log" 2>&1 &

api() { # METHOD PATH [curl args]
  local m=$1 p=$2
  shift 2
  nsx "$NS_M" curl -sS -X "$m" -H "Origin: $BASE" --max-time 120 "$@" "$BASE$p"
}
js() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
for _ in $(seq 1 100); do api GET /api/status >/dev/null 2>&1 && break; sleep 0.2; done
api GET /api/status >/dev/null || { echo "server did not come up" >&2; tail -20 "$WORK/serve.log"; exit 1; }

upload() { # FILE NAME
  api POST /api/pcaps -F "file=@$1;filename=$2" | js 'd["id"]'
}
wait_viability() { # ID
  for _ in $(seq 1 240); do
    [ "$(api GET /api/pcaps | js "next((e.get('viability') is not None) for e in d if e['id']=='$1')")" = True ] && return 0
    sleep 0.5
  done
  return 1
}
wait_done() { # RUN_ID: run finished and auto-analysis settled
  local st
  for _ in $(seq 1 2400); do
    st=$(api GET "/api/runs/$1" | js 'd["status"] + " " + str((d.get("auto_analysis") or {}).get("state"))')
    case "$st" in
      "running "*) ;;
      *" done" | *" failed" | *" skipped") echo "    run $1: $st"; return 0 ;;
    esac
    sleep 0.5
  done
  echo "    run $1 did not finish: $st"
  return 1
}
start_run() { # JSON -> id
  api POST /api/run -H 'Content-Type: application/json' --data "$1" | js 'd["id"]'
}
start_all() { # RUN_ID: arm the pending slave listeners (they wait for this)
  for _ in $(seq 1 40); do
    [ "$(api POST "/api/runs/$1/slaves/start_all" | js 'd.get("started", 0)')" -gt 0 ] && return 0
    sleep 0.5
  done
  echo "    could not arm the listeners of run $1" >&2
  return 1
}
RTUS=$(python3 -c 'print(" ".join(f"192.168.10.{i}" for i in range(2, 202)))')
mock_master() { # LOG
  # shellcheck disable=SC2086
  # Acks within 0.2 s (t2), closes after 30 s of silence: original timing
  # has gaps of several seconds per RTU.
  nsx "$NS_P" python3 "$HELPER" fast-master --procs 2 --t2 0.2 --quiet 30 --connect-timeout 120 $RTUS >"$1" 2>&1 &
  MM_PID=$!
}
shots() { # mode args... (the browser runs as the invoking user, in $NS_M)
  nsx "$NS_M" sudo -u "$(id -un)" env HOME="$HOME" \
    LD_LIBRARY_PATH="$SYSDEPS${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    ${PLAYWRIGHT_DIR:+PLAYWRIGHT_DIR="$PLAYWRIGHT_DIR"} node "$REPO/scripts/ui-screenshots.mjs" "$@"
}

echo "uploading captures..."
P1=$(upload "$REPO/examples/synth_iec104_rtus200_ts.pcap" synth_iec104_rtus200_ts.pcap)
mkdir -p "$WORK/m"
for i in $(seq 0 19); do
  python3 "$REPO/examples/gen_iec104_traffic.py" -n 1 -d 300 --seed $((500 + i)) --start-time 1760000000 \
    --master-ip "10.20.100.$((10 + i))" --master-mac "$(printf '02:00:5e:01:00:%02x' "$i")" \
    --subnet 10.21.0.0/16 --rtu-start-offset $((i + 2)) -o "$WORK/m/m$i.pcap" >/dev/null
done
python3 "$HELPER" merge "$WORK/masters20.pcap" "$WORK"/m/m*.pcap
P2=$(upload "$WORK/masters20.pcap" synth_iec104_masters20.pcap)
wait_viability "$P1" && wait_viability "$P2" || { echo "viability check did not finish" >&2; exit 1; }
echo "    library: $P1 $P2"

SLAVE_BODY='{"pcap_id":"'"$P1"'","mode":"benchmark","role":"slave","target_ip":"10.79.0.2","alias_iface":"s-o","warmup_secs":0,"iterations":1,"pacing":"original","speed":SPEED}'
echo "run A: slave role, 200 RTUs, original timing"
mock_master "$WORK/mock-master-a.log"
A=$(start_run "${SLAVE_BODY/SPEED/1.0}")
[ -n "$A" ] || { echo "run A did not start" >&2; exit 1; }
start_all "$A" || exit 1
sleep 45
shots live "$BASE" "$OUT" "$A"
wait_done "$A" || exit 1
wait "$MM_PID"

echo "run B: same at speed 2"
mock_master "$WORK/mock-master-b.log"
B=$(start_run "${SLAVE_BODY/SPEED/2.0}")
start_all "$B" || exit 1
wait_done "$B" || exit 1
wait "$MM_PID"

echo "run C: master role, 20 masters, as fast as possible"
C=$(start_run '{"pcap_id":"'"$P2"'","mode":"benchmark","role":"master","target_ip":"10.77.0.1","nic":"os-a","force":true,"warmup_secs":0,"iterations":1,"pacing":"fast"}')
wait_done "$C" || exit 1

for r in "$A" "$B" "$C"; do
  api GET "/api/runs/$r" | js '"    run %s: %s, %s sessions, auto-analysis %s" % (d["id"], d["status"], d.get("sessions_total", d.get("sources")), json.dumps(d.get("auto_analysis")))'
done
AN=$(api GET "/api/runs/$A" | js '(d.get("auto_analysis") or {}).get("analysis_id") or ""')
shots final "$BASE" "$OUT" "$A" "$B" "$P1" "$AN"
# The README embeds these: keep each under 400 KB.
big=0
for f in "$OUT"/ui-*.jpg; do
  sz=$(stat -c %s "$f")
  if [ "$sz" -gt 409600 ]; then
    echo "WARNING: $f is $sz bytes (over 400 KB)" >&2
    big=1
  fi
done
echo "screenshots in $OUT"
exit "$big"
