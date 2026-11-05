#!/usr/bin/env bash
# End-to-end test of `outstation bench` inside four throwaway network
# namespaces. Nothing outside them is touched.
#
#   $NS_M (management)        $NS_A (outstation host)        $NS_T (LAN switch + target)
#   os-n 10.66.0.2 <--veth--> os-m 10.66.0.1                 bridge "lan" 10.77.0.1/24
#                             hostonly 10.88.0.1 (dummy)     mock IEC 104 slave :2404
#                             os-a <--------------veth-----> os-b (port of lan)
#                                                            os-x2 (port of lan)
#                                                                 ^ veth
#                                                  $NS_X (LAN attacker) os-x 10.77.0.9
#
# outstation runs in $NS_A in master role, enslaves os-a into its run
# bridge (force: os-a carries the namespace's default route), replays
# the fixture's master traffic to the mock, mirrors its ports into a
# capture and analyses it. The Rust tests in
# crates/outstation/tests/bench_netns.rs check the exit codes and the
# report, that SIGINT cleans the host up, and that $NS_X can neither
# reach $NS_A's host-only address nor route into $NS_M through a
# session port (also with ip_forward=1).
#
# Then the Rust tests in crates/sched/tests/capture_netns.rs run raw
# and master runs against the same LAN while watching it from $NS_T
# (os-b): the run's capture holds every wire frame exactly once (sent
# and received), nothing but replayed or session frames reaches the
# LAN, and an unbounded master run spaces its connections.
#
# Usage: scripts/netns-bench-test.sh [extra test-binary args]
# Env:   NS_A / NS_T / NS_X / NS_M (defaults ostest-bench-{a,t,x,m}; must
#        start with "ostest-"), CARGO_TARGET_DIR (honoured by cargo).
# Needs: sudo, iproute2 (ip, tc, bridge), iptables, ethtool, ping,
#        python3.
set -euo pipefail

NS_A="${NS_A:-ostest-bench-a}"
NS_T="${NS_T:-ostest-bench-t}"
NS_X="${NS_X:-ostest-bench-x}"
NS_M="${NS_M:-ostest-bench-m}"
for ns in "$NS_A" "$NS_T" "$NS_X" "$NS_M"; do
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

# test_bin PACKAGE TEST: build an integration-test binary, print its path.
test_bin() {
  cargo test -p "$1" --test "$2" --no-run --message-format=json 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
            and m["target"]["name"] == sys.argv[1]:
        print(m["executable"])
' "$2"
}
bin="$(test_bin outstation bench_netns)"
cap_bin="$(test_bin sched capture_netns)"
if [ -z "$bin" ] || [ -z "$cap_bin" ]; then
  echo "could not build the bench_netns / capture_netns test binaries" >&2
  exit 1
fi

cleanup() {
  sudo ip netns pids "$NS_T" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
  for ns in "$NS_A" "$NS_T" "$NS_X" "$NS_M"; do
    sudo ip netns del "$ns" 2>/dev/null || true
  done
}
trap cleanup EXIT
for ns in "$NS_A" "$NS_T" "$NS_X" "$NS_M"; do
  sudo ip netns add "$ns"
  sudo ip -n "$ns" link set lo up
done
# LAN: a bridge in $NS_T joining outstation's NIC and the attacker.
sudo ip -n "$NS_T" link add lan type bridge
sudo ip -n "$NS_T" link set lan up
sudo ip -n "$NS_T" addr add 10.77.0.1/24 dev lan
sudo ip -n "$NS_A" link add os-a type veth peer name os-b netns "$NS_T"
sudo ip -n "$NS_X" link add os-x type veth peer name os-x2 netns "$NS_T"
for p in os-b os-x2; do
  sudo ip -n "$NS_T" link set "$p" master lan
  sudo ip -n "$NS_T" link set "$p" up
done
sudo ip -n "$NS_A" link set os-a up
sudo ip -n "$NS_X" addr add 10.77.0.9/24 dev os-x
sudo ip -n "$NS_X" link set os-x up
# Replies to the replayed source addresses go back over the LAN.
sudo ip -n "$NS_T" route add default dev lan
# Outstation's sessions reach the target through the bridge port.
sudo ip -n "$NS_A" route add default dev os-a
# Management network behind the outstation host, and a host-only
# address that must never be reachable from the LAN.
sudo ip -n "$NS_A" link add os-m type veth peer name os-n netns "$NS_M"
sudo ip -n "$NS_A" addr add 10.66.0.1/24 dev os-m
sudo ip -n "$NS_A" link set os-m up
sudo ip -n "$NS_M" addr add 10.66.0.2/24 dev os-n
sudo ip -n "$NS_M" link set os-n up
sudo ip -n "$NS_M" route add default via 10.66.0.1
sudo ip -n "$NS_A" link add hostonly type dummy
sudo ip -n "$NS_A" addr add 10.88.0.1/32 dev hostonly
sudo ip -n "$NS_A" link set hostonly up

sudo ip netns exec "$NS_T" python3 scripts/iec104-mock-slave.py 10.77.0.1 2404 &
sleep 0.5

sudo ip netns exec "$NS_A" env OUTSTATION_NETNS_TEST=1 \
  OUTSTATION_BENCH_TARGET=10.77.0.1 OUTSTATION_BENCH_NIC=os-a \
  OUTSTATION_NS_LAN="$NS_X" OUTSTATION_NS_MGMT="$NS_M" \
  "$bin" --ignored --test-threads=1 "$@"

sudo ip netns exec "$NS_A" env OUTSTATION_NETNS_TEST=1 \
  OUTSTATION_BENCH_TARGET=10.77.0.1 OUTSTATION_BENCH_NIC=os-a \
  OUTSTATION_NS_TARGET="$NS_T" OUTSTATION_LAN_PORT=os-b \
  "$cap_bin" --ignored --test-threads=1 "$@"
