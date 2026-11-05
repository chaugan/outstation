#!/usr/bin/env bash
# End-to-end test of slave-role `outstation bench` and its capture (T18)
# inside two throwaway network namespaces. Nothing outside them is
# touched.
#
#   $NS_O (outstation: RTU listeners)        $NS_P (SCADA master side)
#   s-o 10.79.0.1/24  <------- veth ------->  s-p 10.79.0.2/24
#   (+ /32 listen aliases added by the run)  route 192.168.10.0/24 dev s-p
#
# The Rust tests in crates/outstation/tests/slave_netns.rs run in $NS_O.
# A mock IEC 104 master (scripts/iec104-mock-master.py) connects from
# $NS_P (or over lo inside $NS_O for RTUs in 127/8), the bench must
# score >= 99 %, and the run's capture must hold only the run's own
# sessions although unrelated traffic flows on the same NIC and port.
#
# Usage: scripts/netns-slave-test.sh [extra test-binary args]
# Env:   NS_O / NS_P (defaults ostest-slave-o / ostest-slave-p; must
#        start with "ostest-"), CARGO_TARGET_DIR (honoured by cargo).
# Needs: sudo, iproute2, python3.
set -euo pipefail

NS_O="${NS_O:-ostest-slave-o}"
NS_P="${NS_P:-ostest-slave-p}"
for ns in "$NS_O" "$NS_P"; do
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

bin="$(cargo test -p outstation --test slave_netns --no-run --message-format=json 2>/dev/null \
  | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
            and m["target"]["name"] == "slave_netns":
        print(m["executable"])
')"
if [ -z "$bin" ]; then
  echo "could not build the slave_netns test binary" >&2
  exit 1
fi

cleanup() {
  for ns in "$NS_O" "$NS_P"; do
    sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
    sudo ip netns del "$ns" 2>/dev/null || true
  done
}
trap cleanup EXIT
for ns in "$NS_O" "$NS_P"; do
  sudo ip netns add "$ns"
  sudo ip -n "$ns" link set lo up
done
sudo ip -n "$NS_O" link add s-o type veth peer name s-p netns "$NS_P"
sudo ip -n "$NS_O" addr add 10.79.0.1/24 dev s-o
sudo ip -n "$NS_O" link set s-o up
sudo ip -n "$NS_P" addr add 10.79.0.2/24 dev s-p
sudo ip -n "$NS_P" link set s-p up
# The RTU listen IPs live behind s-o (as /32 aliases the run adds).
sudo ip -n "$NS_P" route add 192.168.10.0/24 dev s-p

sudo ip netns exec "$NS_O" env OUTSTATION_NETNS_TEST=1 \
  OUTSTATION_SLAVE_NIC=s-o OUTSTATION_SLAVE_OWN_IP=10.79.0.1 \
  OUTSTATION_SLAVE_MASTER_IP=10.79.0.2 OUTSTATION_SLAVE_PEER_NS="$NS_P" \
  "$bin" --ignored --test-threads=1 "$@"
