#!/usr/bin/env bash
#
# Install pcapreplay as a systemd service.
#
#   sudo ./systemd/install.sh
#
# Assumes a release build already exists at target/release/pcapreplay.
# Creates the pcapreplay user, installs the binary to /usr/local/bin,
# drops the unit file into /etc/systemd/system, and enables the service.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/target/release/pcapreplay"

if [[ ! -x "$BIN" ]]; then
    echo "no release binary at $BIN" >&2
    echo "build first:   cargo build --release -p pcapreplay" >&2
    exit 1
fi

id -u pcapreplay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin pcapreplay
install -m 0755 "$BIN" /usr/local/bin/pcapreplay
install -d -o pcapreplay -g pcapreplay /var/lib/pcapreplay
install -m 0644 "$REPO_ROOT/systemd/pcapreplay.service" /etc/systemd/system/pcapreplay.service

systemctl daemon-reload
systemctl enable pcapreplay.service
systemctl restart pcapreplay.service

echo
echo "pcapreplay installed. Check status:"
echo "  sudo systemctl status pcapreplay"
echo
echo "Web UI: http://127.0.0.1:8080"
