#!/usr/bin/env bash
#
# Install outstation as a systemd service.
#
#   sudo ./systemd/install.sh
#
# Assumes a release build already exists at target/release/outstation.
# Creates the outstation user, installs the binary to /usr/local/bin,
# drops the unit file into /etc/systemd/system, and enables the service.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/target/release/outstation"

if [[ ! -x "$BIN" ]]; then
    echo "no release binary at $BIN" >&2
    echo "build first:   cargo build --release -p outstation" >&2
    exit 1
fi

id -u outstation >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin outstation
install -m 0755 "$BIN" /usr/local/bin/outstation
install -d -o outstation -g outstation /var/lib/outstation
install -m 0644 "$REPO_ROOT/systemd/outstation.service" /etc/systemd/system/outstation.service

systemctl daemon-reload
systemctl enable outstation.service
systemctl restart outstation.service

echo
echo "outstation installed. Check status:"
echo "  sudo systemctl status outstation"
echo
echo "Web UI: http://127.0.0.1:8080"
