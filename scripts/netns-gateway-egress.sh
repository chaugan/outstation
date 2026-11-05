#!/usr/bin/env bash
# Does SCADA-gateway mode work in master role when the run enslaves an
# egress NIC? Runs `outstation bench` (release build) in throwaway
# network namespaces; nothing outside them is touched.
#
#   $NS_M (management)          $NS_A (outstation)              $NS_T (LAN + RTU under test)
#   os-n 10.66.0.2 <--veth-->   os-m 10.66.0.1 (default route)  bridge "lan" 10.77.0.1/24
#                               os-a (egress NIC, no address)   mock IEC 104 slave :2404
#                               os-a <-----------veth---------> os-b (port of lan)
#
# The captured master (the session's source address) is 10.20.100.10,
# off the RTU's subnet. A real RTU then sends its replies to its default
# gateway, here 10.77.0.254, which does not exist on the isolated LAN:
# the situation gateway mode is meant for (doc/scada-lab.en.md §4).
#
# Cases (one `outstation bench` each, master role, nic os-a, one session):
#   1  control: the RTU routes everything on-link (`default dev lan`),
#      no gateway mode                                    -> must pass
#   2  RTU `default via 10.77.0.254`, no gateway mode     -> fails (expected)
#   3  RTU via .254, gateway mode on the egress NIC os-a  -> ?
#   4  as 3 with force                                    -> ?
#   5  RTU via .254, gateway mode on a separate NIC (os-g, a second veth
#      into the same LAN, not enslaved)                   -> ?
# For each it prints the bench result, the session error, and what the
# RTU learned for its gateway (`ip neigh` in $NS_T).
#
# Usage: scripts/netns-gateway-egress.sh
# Env:   NS_PREFIX (default ostest-gw; must start with "ostest-"),
#        OUTSTATION_BIN (default: cargo build --release -p outstation),
#        WORK (default: mktemp), CARGO_TARGET_DIR honoured by cargo.
# Needs: sudo, iproute2, iptables, ethtool, python3.
set -uo pipefail

NS_PREFIX="${NS_PREFIX:-ostest-gw}"
case "$NS_PREFIX" in ostest-*) ;; *) echo "NS_PREFIX must start with ostest-" >&2; exit 2 ;; esac
NS_A="$NS_PREFIX-a"
NS_T="$NS_PREFIX-t"
NS_M="$NS_PREFIX-m"
for ns in "$NS_A" "$NS_T" "$NS_M"; do
  if sudo ip netns list | grep -qw "^$ns"; then
    echo "namespace $ns already exists; delete it first" >&2
    exit 1
  fi
done
cd "$(dirname "$0")/.."
REPO="$(pwd)"
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
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ostest-gw.XXXXXX")}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
echo "binary: $BIN"
echo "work dir: $WORK"

teardown() {
  local ns
  for ns in "$NS_A" "$NS_T" "$NS_M"; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill -9 2>/dev/null || true
  done
  sleep 0.2
  for ns in "$NS_A" "$NS_T" "$NS_M"; do sudo ip netns del "$ns" 2>/dev/null || true; done
}
trap 'teardown; wait 2>/dev/null' EXIT
trap 'exit 130' INT TERM
nsx() { local ns=$1; shift; sudo ip netns exec "$ns" "$@"; }

# One single-session master capture, master 10.20.100.10 -> RTU.
PCAP="$WORK/master1.pcap"
python3 "$REPO/examples/gen_iec104_traffic.py" -n 1 -d 600 --mean-interval 30 --seed 7 \
  --start-time 1760000000 --master-ip 10.20.100.10 --subnet 10.21.0.0/16 -o "$PCAP" >/dev/null

# setup RTU_ROUTE: "onlink" or "via"
setup() {
  local ns
  for ns in "$NS_A" "$NS_T" "$NS_M"; do
    sudo ip netns add "$ns"
    sudo ip -n "$ns" link set lo up
    nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  done
  sudo ip -n "$NS_T" link add lan type bridge
  sudo ip -n "$NS_T" link set lan up
  sudo ip -n "$NS_T" addr add 10.77.0.1/24 dev lan
  sudo ip -n "$NS_A" link add os-a type veth peer name os-b netns "$NS_T"
  sudo ip -n "$NS_A" link add os-g type veth peer name os-h netns "$NS_T"
  for p in os-b os-h; do
    sudo ip -n "$NS_T" link set "$p" master lan
    sudo ip -n "$NS_T" link set "$p" up
  done
  sudo ip -n "$NS_A" link set os-a up
  sudo ip -n "$NS_A" link set os-g up
  if [ "$1" = onlink ]; then
    sudo ip -n "$NS_T" route add default dev lan
  else
    sudo ip -n "$NS_T" route add default via 10.77.0.254 dev lan
  fi
  sudo ip -n "$NS_A" link add os-m type veth peer name os-n netns "$NS_M"
  sudo ip -n "$NS_A" addr add 10.66.0.1/24 dev os-m
  sudo ip -n "$NS_A" link set os-m up
  sudo ip -n "$NS_M" addr add 10.66.0.2/24 dev os-n
  sudo ip -n "$NS_M" link set os-n up
  sudo ip -n "$NS_A" route add default via 10.66.0.2
  nsx "$NS_T" python3 "$REPO/scripts/iec104-mock-slave.py" 10.77.0.1 2404 >"$WORK/mock.log" 2>&1 &
  disown
  sleep 0.5
}

RESULTS=()
# case ID NAME ROUTE EXTRA_JSON
run_case() {
  local id=$1 name=$2 route=$3 extra=$4 dir="$WORK/case$1"
  mkdir -p "$dir"
  echo
  echo "=== case $id: $name"
  setup "$route"
  printf '{"mode":"benchmark","role":"master","target_ip":"10.77.0.1","nic":"os-a","warmup_secs":0,"iterations":1,"pacing":"fast"%s}\n' \
    "$extra" >"$dir/profile.json"
  echo "    profile: $(cat "$dir/profile.json")"
  # Watch the gateway alias while the run is up.
  (for _ in $(seq 1 40); do
     nsx "$NS_A" ip -o addr show 2>/dev/null | grep -q 10.77.0.254 && { echo "gateway alias seen on: $(nsx "$NS_A" ip -o addr show | awk '/10.77.0.254/ {print $2}')"; nsx "$NS_A" ip -o link show "$(nsx "$NS_A" ip -o addr show | awk '/10.77.0.254/ {print $2; exit}')" | grep -o 'master [^ ]*' || echo "(not a bridge port)"; break; }
     sleep 0.25
   done) >"$dir/alias.txt" 2>&1 &
  local watch=$!
  nsx "$NS_A" env RUST_LOG=info NO_COLOR=1 "$BIN" bench --pcap "$PCAP" --profile "$dir/profile.json" \
    --report "$dir/report.json" --state-dir "$dir/state" >"$dir/bench.log" 2>&1
  local code=$?
  wait "$watch" 2>/dev/null
  local neigh
  neigh=$(nsx "$NS_T" ip neigh show 10.77.0.254 | head -1)
  sudo chown -R "$(id -u):$(id -g)" "$dir"
  local err status
  status=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print((r.get("run") or {}).get("status"), "|", r.get("error") or "", "|", ";".join(sorted({s.get("error") or "ok" for s in r.get("sessions") or []})))' "$dir/report.json" 2>/dev/null)
  echo "    bench exit $code; run status | error | session errors: $status"
  echo "    gateway alias: $(tr '\n' ' ' <"$dir/alias.txt")"
  echo "    RTU neighbour entry for its gateway 10.77.0.254: ${neigh:-none}"
  grep -E ' (WARN|ERROR) ' "$dir/bench.log" | grep -v 'protected NIC used' | head -3 | cut -c1-240 | sed 's/^/    log: /'
  RESULTS+=("$id|$name|exit $code|$status")
  teardown
}

run_case 1 "control: RTU routes on-link, no gateway mode" onlink ''
run_case 2 "RTU via 10.77.0.254, no gateway mode" via ''
run_case 3 "RTU via 10.77.0.254, gateway mode on the egress NIC os-a" via \
  ',"scada_gateway_ip":"10.77.0.254","scada_gateway_iface":"os-a"'
run_case 4 "as 3, with force" via \
  ',"scada_gateway_ip":"10.77.0.254","scada_gateway_iface":"os-a","force":true'
run_case 5 "RTU via 10.77.0.254, gateway mode on a second, non-enslaved NIC os-g" via \
  ',"scada_gateway_ip":"10.77.0.254","scada_gateway_iface":"os-g"'

echo
printf '%s\n' "${RESULTS[@]}"
