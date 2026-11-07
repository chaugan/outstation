#!/usr/bin/env bash
# Run netctl's privileged host-safety tests inside a throwaway network
# namespace. Nothing outside the namespace is touched: the tests create
# their own veth pairs, bridges, addresses, iptables rules and sysctl
# changes inside it, and the namespace is deleted on exit.
#
# Usage: scripts/netns-test.sh [extra test-binary args, e.g. a test name]
# Env:   NS (default ostest-netctl-1; must start with "ostest-"),
#        CARGO_TARGET_DIR (honoured by cargo as usual).
# Needs: sudo, iproute2, iptables, ethtool, python3.
set -euo pipefail

NS="${NS:-ostest-netctl-1}"
case "$NS" in
  ostest-*) ;;
  *) echo "NS must start with ostest-" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."

bin="$(cargo test -p netctl --test netns --no-run --message-format=json 2>/dev/null \
  | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") \
            and m["target"]["name"] == "netns":
        print(m["executable"])
')"
if [ -z "$bin" ]; then
  echo "could not build the netns test binary" >&2
  exit 1
fi

if sudo ip netns list | grep -qw "^$NS"; then
  echo "namespace $NS already exists; delete it first" >&2
  exit 1
fi
sudo ip netns add "$NS"
trap 'sudo ip netns del "$NS"' EXIT

sudo ip netns exec "$NS" env OUTSTATION_NETNS_TEST=1 "$bin" --ignored --test-threads=1 "$@"
