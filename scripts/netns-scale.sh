#!/usr/bin/env bash
# Scale benchmark for `outstation bench` (release build) inside
# throwaway network namespaces. Nothing outside them is touched: every
# interface, address, route, iptables rule and sysctl the benchmark or
# outstation changes lives in a namespace named $NS_PREFIX-*, and the
# namespaces are deleted after every run and on exit (trap).
#
#   $NS_PREFIX-t (LAN + target)         $NS_PREFIX-a (outstation)          $NS_PREFIX-p (SCADA master side)
#   bridge "lan" 10.77.0.1/24     <-->  os-a (default route, forced)
#   IEC 104 slave peer :2404            s-o 10.79.0.1/24             <-->  s-p 10.79.0.2/24
#                                       (+ /32 RTU aliases of the run)     route 192.168.8.0/22 dev s-p
#                                                                          IEC 104 master peer
#
# Scenarios (arguments; default "master-200 slave-200 master-400 slave-400"):
#   A suffix @SPEED (e.g. slave-200@10) replays the capture once with
#   original timing at that speed instead of as fast as possible.
#   master-N  master role, N sessions (N distinct captured masters, one
#             RTU each), pacing "fast" (as fast as possible), against a
#             slave peer in $NS_PREFIX-t. outstation enslaves os-a into
#             its run bridge and adds one veth port per session.
#   slave-N   slave role, N impersonated RTUs (one captured master),
#             pacing "fast", the master peer in $NS_PREFIX-p connects to
#             every RTU IP (aliases on s-o) and sends one GI.
#
# Each scenario runs $REPEAT times on a fresh topology. Per run it keeps
# the bench report, the log, `/usr/bin/time -v`, a /proc sampler of the
# outstation process (CPU, RSS, threads, fds) and of the peer, the
# I-frame rate seen on the wire (from the run's own capture) and prints
# one summary line; at the end a Markdown table of every run and the
# median per scenario ($WORK/results.md, raw lines in
# $WORK/results.jsonl).
#
# Traffic comes from examples/gen_iec104_traffic.py:
#   master-N: N single-RTU captures, each with its own master IP/MAC,
#             $MASTER_DURATION s long with --mean-interval 60 (the
#             master side carries GI, clock sync, counter interrogations
#             and commands: ~400 I-frames per session), merged into one.
#             Each session replays it $MASTER_ITERATIONS times (a new
#             connection per iteration, iteration_gap_ms 0).
#   slave-N:  one capture with N RTUs, $SLAVE_DURATION s with
#             --mean-interval $SLAVE_INTERVAL (~1,500 I-frames per RTU),
#             looped $SLAVE_ITERATIONS times within one connection
#             (loop_within_session).
#
# Peers (PEER):
#   fast (default)  scripts/netns-scale-helper.py fast-slave/fast-master:
#                   event-driven, $PEER_PROCS processes (SO_REUSEPORT
#                   listener, or the RTU IPs split across processes).
#   mock            the threaded scripts/iec104-mock-slave.py and
#                   iec104-mock-master.py (one process; GIL-bound and a
#                   listen backlog of 64 - see the report).
#
# Usage: scripts/netns-scale.sh [SCENARIO...]
# Env:   REPEAT=3  PEER=fast|mock  PEER_PROCS=4
#        NS_PREFIX (default ostest-scale; must start with "ostest-")
#        OUTSTATION_BIN  use this binary instead of building
#                        `cargo build --release -p outstation`
#        WORK            work dir (default: mktemp under $TMPDIR or /tmp);
#                        always kept (it holds the results)
#        PCAP_DIR        where generated pcaps are cached (default $WORK/pcaps)
#        KEEP_CAPTURES=1 keep each run's capture (default: deleted after
#                        the wire rate was read from it)
#        MASTER_DURATION=36000  MASTER_ITERATIONS=30
#        SLAVE_DURATION=300  SLAVE_INTERVAL=0.2  SLAVE_ITERATIONS=5
#        PEER_QUIET=0.5  quiet time after which the master peer closes
#        REALTIME=1      set "realtime": true in the profiles (SCHED_FIFO
#                        replay threads; the slave capture thread gets RT
#                        priority only then)
#        NOFILE=SOFT[:HARD]  run outstation with this open-file limit
#                        (e.g. 1024, the soft limit systemd gives services)
#        CARGO_TARGET_DIR honoured by cargo
# Needs: sudo, iproute2, iptables, ethtool, python3 (stdlib), /usr/bin/time.
# Exit:  0 when every run completed with exit code 0, 1 otherwise.
set -uo pipefail

NS_PREFIX="${NS_PREFIX:-ostest-scale}"
case "$NS_PREFIX" in
  ostest-*) ;;
  *) echo "NS_PREFIX must start with ostest-" >&2; exit 2 ;;
esac
NS_A="$NS_PREFIX-a"
NS_T="$NS_PREFIX-t"
NS_P="$NS_PREFIX-p"
for ns in "$NS_A" "$NS_T" "$NS_P"; do
  if sudo ip netns list | grep -qw "^$ns"; then
    echo "namespace $ns already exists; delete it first" >&2
    exit 1
  fi
done

REPEAT="${REPEAT:-3}"
PEER="${PEER:-fast}"
PEER_PROCS="${PEER_PROCS:-4}"
MASTER_DURATION="${MASTER_DURATION:-36000}"
SLAVE_DURATION="${SLAVE_DURATION:-300}"
SLAVE_INTERVAL="${SLAVE_INTERVAL:-0.2}"
PEER_QUIET="${PEER_QUIET:-0.5}"
MASTER_ITERATIONS="${MASTER_ITERATIONS:-30}"
SLAVE_ITERATIONS="${SLAVE_ITERATIONS:-5}"
case "$PEER" in fast | mock) ;; *) echo "PEER must be fast or mock" >&2; exit 2 ;; esac
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=(master-200 slave-200 master-400 slave-400)
for s in "${SCENARIOS[@]}"; do
  [[ "$s" =~ ^(master|slave)-[0-9]+(@[0-9]+(\.[0-9]+)?)?$ ]] || { echo "bad scenario '$s' (want master-N, slave-N, master-N@SPEED or slave-N@SPEED)" >&2; exit 2; }
  n=${s#*-}
  n=${n%@*}
  if [ "$n" -lt 1 ] || [ "$n" -gt 1000 ]; then echo "$s: N must be 1..1000" >&2; exit 2; fi
done

cd "$(dirname "$0")/.."
REPO="$(pwd)"
HELPER="$REPO/scripts/netns-scale-helper.py"
GEN="$REPO/examples/gen_iec104_traffic.py"
TARGET_IP=10.77.0.1
MASTER_IP=10.79.0.2
RTU_SUBNET=192.168.8.0/22

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
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ostest-scale.XXXXXX")}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
PCAP_DIR="${PCAP_DIR:-$WORK/pcaps}"
mkdir -p "$PCAP_DIR" "$WORK/runs"
echo "binary: $BIN"
echo "work dir: $WORK"

# --- environment ---------------------------------------------------------
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git: $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null) ($(git -C "$REPO" status --porcelain 2>/dev/null | wc -l) uncommitted paths)"
  echo "nproc: $(nproc)"
  echo "cpu: $(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
  echo "mem: $(awk '/^MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
  echo "kernel: $(uname -r)"
  echo "python: $(python3 -V 2>&1)"
  echo "loadavg at start: $(cut -d' ' -f1-3 /proc/loadavg)"
  echo "peer: $PEER ($PEER_PROCS processes for fast)"
  echo "realtime: ${REALTIME:-0}"
  echo "open-file limit for outstation: ${NOFILE:-inherited ($(ulimit -Sn) soft, $(ulimit -Hn) hard)}"
  echo "repeat: $REPEAT, master iterations: $MASTER_ITERATIONS, slave iterations: $SLAVE_ITERATIONS (loop within session)"
} | tee "$WORK/env.txt"

# --- teardown ------------------------------------------------------------
teardown_ns() {
  local ns
  for ns in "$NS_A" "$NS_T" "$NS_P"; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true
  done
  sleep 0.2
  for ns in "$NS_A" "$NS_T" "$NS_P"; do
    sudo ip netns del "$ns" 2>/dev/null || true
  done
}
on_exit() {
  teardown_ns
  wait 2>/dev/null
  echo "results kept in $WORK"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

nsx() { local ns=$1; shift; sudo ip netns exec "$ns" "$@"; }

setup_topology() {
  local ns
  for ns in "$NS_A" "$NS_T" "$NS_P"; do
    sudo ip netns add "$ns"
    sudo ip -n "$ns" link set lo up
    nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
    # Room for a few hundred concurrent handshakes on either side.
    nsx "$ns" sysctl -qw net.core.somaxconn=4096 net.ipv4.tcp_max_syn_backlog=4096
  done
  # LAN with the slave peer (master-role target).
  sudo ip -n "$NS_T" link add lan type bridge
  sudo ip -n "$NS_T" link set lan up
  sudo ip -n "$NS_T" addr add "$TARGET_IP/24" dev lan
  sudo ip -n "$NS_A" link add os-a type veth peer name os-b netns "$NS_T"
  sudo ip -n "$NS_T" link set os-b master lan
  sudo ip -n "$NS_T" link set os-b up
  sudo ip -n "$NS_A" link set os-a up
  # Replies to the sessions' (captured) master addresses go out on the LAN.
  sudo ip -n "$NS_T" route add default dev lan
  sudo ip -n "$NS_A" route add default dev os-a
  # SCADA master side for slave runs.
  sudo ip -n "$NS_A" link add s-o type veth peer name s-p netns "$NS_P"
  sudo ip -n "$NS_A" addr add 10.79.0.1/24 dev s-o
  sudo ip -n "$NS_A" link set s-o up
  sudo ip -n "$NS_P" addr add "$MASTER_IP/24" dev s-p
  sudo ip -n "$NS_P" link set s-p up
  sudo ip -n "$NS_P" route add "$RTU_SUBNET" dev s-p
}

# --- traffic -------------------------------------------------------------
master_ip_of() { echo "10.20.$((100 + $1 / 200)).$((10 + $1 % 200))"; }

# master_pcap N: N single-RTU sessions, each with its own master.
master_pcap() {
  local n=$1 out="$PCAP_DIR/master-$1.pcap" i files=()
  if [ ! -s "$out" ]; then
    mkdir -p "$PCAP_DIR/master-parts"
    for ((i = 0; i < n; i++)); do
      local f="$PCAP_DIR/master-parts/m$i-$MASTER_DURATION.pcap"
      if [ ! -s "$f" ]; then
        python3 "$GEN" -n 1 -d "$MASTER_DURATION" --mean-interval 60 --seed $((1000 + i)) \
          --start-time 1760000000 --master-ip "$(master_ip_of "$i")" \
          --master-mac "$(printf '02:00:5e:01:%02x:%02x' $((i / 256)) $((i % 256)))" \
          --subnet 10.21.0.0/16 --rtu-start-offset $((i + 2)) -o "$f" >/dev/null || return 1
      fi
      files+=("$f")
    done
    python3 "$HELPER" merge "$out.tmp" "${files[@]}" && mv "$out.tmp" "$out" || return 1
  fi
  echo "$out"
}

# slave_pcap N: one master, N RTUs.
slave_pcap() {
  local n=$1 out="$PCAP_DIR/slave-$1.pcap"
  if [ ! -s "$out" ]; then
    python3 "$GEN" -n "$n" -d "$SLAVE_DURATION" --mean-interval "$SLAVE_INTERVAL" --seed 1 \
      --start-time 1760000000 --subnet "$RTU_SUBNET" -o "$out.tmp" >/dev/null \
      && mv "$out.tmp" "$out" || return 1
  fi
  echo "$out"
}

rtu_ips() { # N
  python3 -c '
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[2])
print(" ".join(str(net.network_address + 2 + i) for i in range(int(sys.argv[1]))))' "$1" "$RTU_SUBNET"
}

# --- one run -------------------------------------------------------------
OVERALL_FAIL=0

# run_one ROLE N SPEED REP (SPEED empty: as fast as possible)
run_one() {
  local role=$1 n=$2 speed=$3 rep=$4 scen="$1-$2${3:+@$3}"
  local dir="$WORK/runs/$scen-$PEER-r$rep" pcap profile peer_pid ts_pid ps_pid code
  local pacing='"pacing":"fast"' m_iter=$MASTER_ITERATIONS s_iter=$SLAVE_ITERATIONS
  [ "${REALTIME:-0}" = 1 ] && pacing="$pacing"',"realtime":true'
  if [ -n "$speed" ]; then
    # Original timing: one pass of the capture, sped up.
    pacing='"pacing":"original","speed":'"$speed"
    m_iter=1
    s_iter=1
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  if [ "$role" = master ]; then
    pcap=$(master_pcap "$n") || { echo "pcap generation failed" >&2; return 1; }
    printf '{"mode":"benchmark","role":"master","target_ip":"%s","nic":"os-a","force":true,"warmup_secs":0,"iterations":%d,"iteration_gap_ms":0,%s}\n' \
      "$TARGET_IP" "$m_iter" "$pacing" >"$dir/profile.json"
  else
    pcap=$(slave_pcap "$n") || { echo "pcap generation failed" >&2; return 1; }
    printf '{"mode":"benchmark","role":"slave","target_ip":"%s","alias_iface":"s-o","warmup_secs":0,"iterations":%d,"loop_within_session":true,%s}\n' \
      "$MASTER_IP" "$s_iter" "$pacing" >"$dir/profile.json"
  fi
  echo
  local load0
  load0=$(cut -d' ' -f1 /proc/loadavg)
  echo "=== $scen peer=$PEER run $rep/$REPEAT ($(basename "$pcap"), load average $load0)"
  setup_topology

  local peer_ns
  if [ "$role" = master ]; then
    peer_ns=$NS_T
    if [ "$PEER" = fast ]; then
      nsx "$NS_T" python3 "$HELPER" fast-slave "$TARGET_IP" 2404 --procs "$PEER_PROCS" >"$dir/peer.out" 2>&1 &
    else
      nsx "$NS_T" python3 "$REPO/scripts/iec104-mock-slave.py" "$TARGET_IP" 2404 >"$dir/peer.out" 2>&1 &
    fi
    peer_pid=$!
    sleep 0.5
  else
    peer_ns=$NS_P
  fi
  # Samplers: outstation in $NS_A, the peer's processes in its namespace.
  nsx "$NS_A" python3 "$HELPER" sample "$dir/sample-tool.json" --comm outstation --interval 0.1 &
  ts_pid=$!
  nsx "$peer_ns" python3 "$HELPER" sample "$dir/sample-peer.json" --comm python3 --interval 0.1 &
  ps_pid=$!
  sleep 0.3

  nsx "$NS_A" env RUST_LOG=info NO_COLOR=1 prlimit ${NOFILE:+--nofile="$NOFILE"} -- /usr/bin/time -v -o "$dir/time.txt" \
    "$BIN" bench --pcap "$pcap" --profile "$dir/profile.json" --report "$dir/report.json" \
    --state-dir "$dir/state" --capture "$dir/capture.pcap" >"$dir/bench.log" 2>&1 &
  local bench_pid=$!
  if [ "$role" = slave ]; then
    # shellcheck disable=SC2046
    if [ "$PEER" = fast ]; then
      nsx "$NS_P" python3 "$HELPER" fast-master --procs "$PEER_PROCS" --quiet "$PEER_QUIET" \
        --connect-timeout 600 $(rtu_ips "$n") >"$dir/peer.out" 2>&1 &
    else
      nsx "$NS_P" python3 "$REPO/scripts/iec104-mock-master.py" --quiet "$PEER_QUIET" \
        --connect-timeout 600 $(rtu_ips "$n") >"$dir/peer.out" 2>&1 &
    fi
    peer_pid=$!
  fi
  wait "$bench_pid"
  code=$?
  if [ "$role" = slave ]; then
    wait "$peer_pid"
    echo "peer_exit=$?" >>"$dir/peer.out"
  fi
  sudo kill -TERM "$ts_pid" "$ps_pid" 2>/dev/null
  wait "$ts_pid" "$ps_pid" 2>/dev/null
  teardown_ns
  wait 2>/dev/null
  sudo chown -R "$(id -u):$(id -g)" "$dir"

  local side=client
  [ "$role" = slave ] && side=server
  if [ -s "$dir/capture.pcap" ]; then
    python3 "$HELPER" iframe-rate "$dir/capture.pcap" "$side" >"$dir/rate.json" || true
    [ "${KEEP_CAPTURES:-0}" = 1 ] || rm -f "$dir/capture.pcap"
  fi
  local ok
  ok=$(grep -c ' OK ' "$dir/peer.out" 2>/dev/null)
  printf '{"scenario":"%s","role":"%s","sessions":%d,"repeat":%d,"peer":"%s","peer_procs":%d,"peer_ok":%s,"bench_exit":%d,"loadavg_before":%s}\n' \
    "$scen" "$role" "$n" "$rep" "$PEER" "$([ "$PEER" = fast ] && echo "$PEER_PROCS" || echo 1)" \
    "${ok:-0}" "$code" "$load0" >"$dir/meta.json"
  python3 "$HELPER" summarize "$dir" | tee -a "$WORK/results.jsonl"
  if [ "$code" -ne 0 ]; then
    echo "    bench exit $code; last lines of $dir/bench.log:"
    grep -v ' INFO ' "$dir/bench.log" | tail -8 | sed 's/^/      /'
    OVERALL_FAIL=1
  fi
}

for scen in "${SCENARIOS[@]}"; do
  role=${scen%%-*}
  n=${scen#*-}
  speed=""
  if [[ "$n" == *@* ]]; then speed=${n#*@}; n=${n%@*}; fi
  for ((r = 1; r <= REPEAT; r++)); do
    run_one "$role" "$n" "$speed" "$r"
  done
done

python3 "$HELPER" table "$WORK/results.jsonl" | tee "$WORK/results.md"
exit "$OVERALL_FAIL"
