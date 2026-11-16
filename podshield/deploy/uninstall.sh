#!/usr/bin/env bash
# Remove PodShield from this RHEL 9 host. Safe to run twice.
#
#   sudo bash deploy/uninstall.sh [--purge]
#
# Default: stops and removes the systemd units, the app in /opt/podshield, the CLI symlink,
# the firewall port and the SELinux port label that install.sh added.
# Keeps /etc/podshield (config) and /var/lib/podshield (database, reports, OVAL feed).
#   --purge   also delete /etc/podshield, /var/lib/podshield and the demo images
# Never touches: SELinux mode, dnf packages, podman.socket (other tools may use it).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/lib.sh
. "$HERE/lib.sh"

PURGE=0
while (( $# )); do
    case "$1" in
        --purge)   PURGE=1 ;;
        -h|--help) sed -n '2,11s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *)         die "unknown option: $1 (try --help)" ;;
    esac
    shift
done
require_root

printf '\n==> stopping and removing systemd units\n'
for unit in podshield-scan.timer podshield-watch.service podshield-api.service podshield-scan.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
    rm -f "$PS_UNIT_DIR/$unit"
    rm -rf "$PS_UNIT_DIR/$unit.d"
done
systemctl daemon-reload
systemctl reset-failed 'podshield-*' >/dev/null 2>&1 || true
pass "units stopped, disabled and removed"

# Read the listen address before the env file can be purged.
HOST="$(env_value PODSHIELD_HOST 127.0.0.1)"
PORT="$(env_value PODSHIELD_PORT 8080)"

printf '\n==> firewall and SELinux port label\n'
if [[ "$HOST" != 127.* && "$HOST" != localhost && "$HOST" != ::1 ]] \
        && command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld \
        && firewall-cmd --permanent --query-port="$PORT/tcp" >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="$PORT/tcp" >/dev/null
    firewall-cmd --reload >/dev/null
    pass "firewalld: closed $PORT/tcp"
else
    pass "firewalld: nothing to close"
fi
marker="$PS_STATE_DIR/.selinux-port-label"
if [[ -f "$marker" ]] && command -v semanage >/dev/null 2>&1; then
    labelled="$(head -n 1 "$marker")"
    if [[ "$labelled" =~ ^[0-9]+$ ]]; then
        semanage port -d -t http_port_t -p tcp "$labelled" 2>/dev/null || true
        pass "removed the SELinux label http_port_t from $labelled/tcp"
    fi
    rm -f "$marker"
else
    pass "no SELinux port label to remove"
fi

printf '\n==> application files\n'
if [[ -L /usr/local/bin/podshield ]] && [[ "$(readlink /usr/local/bin/podshield)" == "$PS_PREFIX"/* ]]; then
    rm -f /usr/local/bin/podshield
fi
rm -rf "$PS_PREFIX"
pass "removed $PS_PREFIX and /usr/local/bin/podshield"

if (( PURGE )); then
    rm -rf "$PS_CONF_DIR" "$PS_STATE_DIR"
    pass "purged $PS_CONF_DIR and $PS_STATE_DIR"
    if command -v podman >/dev/null 2>&1; then
        podman rmi -f localhost/demo-bad:latest localhost/demo-good:1.0.0 >/dev/null 2>&1 || true
        pass "removed the demo images (if they existed)"
    fi
else
    info "kept $PS_CONF_DIR and $PS_STATE_DIR (use --purge to delete them)"
fi

printf '\nPodShield is uninstalled. podman.socket and the dnf packages were left in place.\n'
