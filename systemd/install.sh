#!/usr/bin/env bash
#
# Install outstation as a systemd service.
#
#   sudo ./systemd/install.sh            # install; restart only if idle
#   sudo ./systemd/install.sh --restart  # restart even if a run is active
#
# Assumes a release build already exists at target/release/outstation.
# Creates the outstation user, installs the binary to /usr/local/bin,
# drops the unit file into /etc/systemd/system, and enables the service.
#
# A restart stops any run in progress. The script therefore checks the
# running instance first and, if a run is active, installs the new
# files but leaves the old process running and tells you how to
# restart later.

set -euo pipefail

FORCE_RESTART=0
for arg in "$@"; do
    case "$arg" in
        --restart) FORCE_RESTART=1 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/target/release/outstation"
UNIT_SRC="$REPO_ROOT/systemd/outstation.service"

if [[ ! -x "$BIN" ]]; then
    echo "no release binary at $BIN" >&2
    echo "build first:   cargo build --release -p outstation" >&2
    exit 1
fi

# Port the unit binds, for the status check and the printed URL.
PORT="$(sed -n 's/^ExecStart=.*--bind [^ :]*:\([0-9]*\).*/\1/p' "$UNIT_SRC" | head -n1)"
PORT="${PORT:-8080}"

# Is a run active on the currently running instance?
run_active() {
    systemctl is-active --quiet outstation.service || return 1
    command -v curl >/dev/null 2>&1 || return 1
    curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/api/runs?status=running" 2>/dev/null \
        | grep -q '"id"'
}

id -u outstation >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin outstation
# Install to a temp name and rename, so a running process keeps its
# (unlinked) old binary intact.
install -m 0755 "$BIN" /usr/local/bin/outstation.new
mv -f /usr/local/bin/outstation.new /usr/local/bin/outstation
install -d -o outstation -g outstation -m 0750 /var/lib/outstation
install -m 0644 "$UNIT_SRC" /etc/systemd/system/outstation.service

systemctl daemon-reload
systemctl enable outstation.service

if systemctl is-active --quiet outstation.service; then
    if [[ $FORCE_RESTART -eq 0 ]] && run_active; then
        echo
        echo "A run is in progress; NOT restarting outstation now."
        echo "The new binary and unit are installed. When the run has finished:"
        echo "  sudo systemctl restart outstation"
        echo "(or re-run this script with --restart to stop the run and restart now)"
    else
        systemctl restart outstation.service
    fi
else
    systemctl start outstation.service
fi

echo
echo "outstation installed. Check status:"
echo "  sudo systemctl status outstation"
echo
echo "The unit binds 0.0.0.0:${PORT}; the web UI is reachable at:"
echo "  http://127.0.0.1:${PORT}/            (on this machine)"
HOSTS="$(hostname -I 2>/dev/null || true)"
for ip in $HOSTS; do
    case "$ip" in
        *:*) echo "  http://[${ip}]:${PORT}/" ;;
        *) echo "  http://${ip}:${PORT}/" ;;
    esac
done
echo "  http://$(hostname):${PORT}/"
echo "There is no authentication; restrict access at the network layer."
echo "Other host names (reverse proxy, DNS alias) must be allowed with"
echo "--allow-host or OUTSTATION_ALLOW_HOSTS in the unit."
