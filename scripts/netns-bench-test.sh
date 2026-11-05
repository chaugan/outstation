#!/usr/bin/env bash
# End-to-end test of `outstation bench` inside two throwaway network
# namespaces. Nothing outside them is touched.
#
#   $NS_A (outstation side)  os-a <--veth--> os-b  $NS_B (target side)
#                                                  10.77.0.1:2404 mock
#                                                  IEC 104 slave
#
# outstation runs in $NS_A in master role, enslaves os-a into its run
# bridge (force: os-a carries the namespace's default route), replays
# the fixture's master traffic to the mock, mirrors the bridge into a
# capture and analyses it. The Rust tests in
# crates/outstation/tests/bench_netns.rs then check the exit codes, the
# report and that SIGINT cleans the host up.
#
# Usage: scripts/netns-bench-test.sh [extra test-binary args]
# Env:   NS_A / NS_B (default ostest-bench-a / ostest-bench-b; must start
#        with "ostest-"), CARGO_TARGET_DIR (honoured by cargo).
# Needs: sudo, iproute2, iptables, ethtool, python3.
set -euo pipefail

NS_A="${NS_A:-ostest-bench-a}"
NS_B="${NS_B:-ostest-bench-b}"
for ns in "$NS_A" "$NS_B"; do
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

bin="$(cargo test -p outstation --test bench_netns --no-run --message-format=json 2>/dev/null \
  | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
            and m["target"]["name"] == "bench_netns":
        print(m["executable"])
')"
if [ -z "$bin" ]; then
  echo "could not build the bench_netns test binary" >&2
  exit 1
fi

cleanup() {
  sudo ip netns pids "$NS_B" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
  sudo ip netns del "$NS_A" 2>/dev/null || true
  sudo ip netns del "$NS_B" 2>/dev/null || true
}
trap cleanup EXIT
sudo ip netns add "$NS_A"
sudo ip netns add "$NS_B"
sudo ip -n "$NS_A" link add os-a type veth peer name os-b netns "$NS_B"
sudo ip -n "$NS_A" link set lo up
sudo ip -n "$NS_B" link set lo up
sudo ip -n "$NS_A" link set os-a up
sudo ip -n "$NS_B" addr add 10.77.0.1/24 dev os-b
sudo ip -n "$NS_B" link set os-b up
# Replies to the replayed source addresses go back over the veth.
sudo ip -n "$NS_B" route add default dev os-b
# Outstation's sessions reach the target through the bridge port.
sudo ip -n "$NS_A" route add default dev os-a

sudo ip netns exec "$NS_B" python3 scripts/iec104-mock-slave.py 10.77.0.1 2404 &
sleep 0.5

sudo ip netns exec "$NS_A" env OUTSTATION_NETNS_TEST=1 \
  OUTSTATION_BENCH_TARGET=10.77.0.1 OUTSTATION_BENCH_NIC=os-a \
  "$bin" --ignored --test-threads=1 "$@"
