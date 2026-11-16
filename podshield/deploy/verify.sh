#!/usr/bin/env bash
# PodShield post-install verification for RHEL 9. Read-only: it changes nothing.
#
#   sudo bash deploy/verify.sh [--port N] [--host ADDR] [--avc-minutes N]
#
# Prints one PASS/FAIL line per check and exits 1 if any check fails.
#   --port N          API port (default: from /etc/podshield/podshield.env, else 8080)
#   --host ADDR       API listen address (default: from podshield.env, else 127.0.0.1)
#   --avc-minutes N   look for SELinux denials in the last N minutes (default 30)
#   --since EPOCH     ... or since this Unix time (used by selftest.sh)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/lib.sh
. "$HERE/lib.sh"

PORT=""
HOST=""
AVC_MINUTES=30
SINCE=""

while (( $# )); do
    case "$1" in
        --port)        PORT="${2:?--port needs a value}"; shift ;;
        --host)        HOST="${2:?--host needs a value}"; shift ;;
        --avc-minutes) AVC_MINUTES="${2:?--avc-minutes needs a value}"; shift ;;
        --since)       SINCE="${2:?--since needs a value}"; shift ;;
        -h|--help)     sed -n '2,10s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *)             die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

require_root "$@"
[[ "$AVC_MINUTES" =~ ^[0-9]+$ ]] || die "--avc-minutes must be a number"
[[ -z "$PORT" || "$PORT" =~ ^[0-9]+$ ]] || die "--port must be a number"
[[ -z "$SINCE" || "$SINCE" =~ ^[0-9]+$ ]] || die "--since must be a Unix timestamp"

HOST="${HOST:-$(env_value PODSHIELD_HOST 127.0.0.1)}"
PORT="${PORT:-$(env_value PODSHIELD_PORT 8080)}"
BASE="$(api_base "$HOST" "$PORT")"
SINCE="${SINCE:-$(( $(date +%s) - AVC_MINUTES * 60 ))}"
PY="$(ps_python)"
TMP="$(mktemp -d /tmp/podshield-verify.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

printf '\n==> PodShield verification (%s)\n' "$BASE"

# ------------------------------------------------------------------------------ SELinux
mode="$(getenforce 2>/dev/null || echo unknown)"
if [[ "$mode" == Enforcing ]]; then
    pass "SELinux is Enforcing"
else
    fail "SELinux is $mode (expected Enforcing; set it in /etc/selinux/config and reboot)"
fi

relabel="$(restorecon -R -n -v "$PS_PREFIX" "$PS_CONF_DIR" "$PS_STATE_DIR" 2>/dev/null | head -n 5 || true)"
if [[ -z "$relabel" ]]; then
    pass "file labels under /opt, /etc and /var/lib/podshield are correct"
else
    fail "some files have the wrong SELinux label (fix: restorecon -Rv $PS_PREFIX $PS_CONF_DIR $PS_STATE_DIR)"
    printf '%s\n' "$relabel" | sed 's/^/         /'
fi

# ------------------------------------------------------------------------------ podman
if systemctl is-enabled --quiet podman.socket 2>/dev/null && systemctl is-active --quiet podman.socket; then
    pass "podman.socket is enabled and active"
else
    fail "podman.socket is not enabled+active (systemctl enable --now podman.socket)"
fi
if [[ -S "$PS_SOCKET" ]] && curl --silent --fail --max-time 20 --unix-socket "$PS_SOCKET" \
        http://d/_ping >/dev/null 2>&1; then
    pass "Podman API answers on $PS_SOCKET"
else
    fail "Podman API does not answer on $PS_SOCKET (journalctl -u podman.service)"
fi

# ------------------------------------------------------------------------------ units
for unit in podshield-api.service podshield-watch.service podshield-scan.timer; do
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    if [[ "$enabled" == enabled && "$active" == active ]]; then
        pass "$unit is enabled and active"
    else
        fail "$unit is ${enabled:-missing}/${active:-inactive} (journalctl -u ${unit%.*} -n 50)"
    fi
done

if systemctl cat podshield-scan.service >/dev/null 2>&1; then
    result="$(systemctl show -p Result --value podshield-scan.service 2>/dev/null || true)"
    if [[ "$(systemctl is-failed podshield-scan.service 2>/dev/null || true)" == failed ]]; then
        fail "podshield-scan.service failed on its last run (result: $result; journalctl -u podshield-scan)"
    else
        pass "podshield-scan.service is installed (last result: ${result:-none yet})"
    fi
else
    fail "podshield-scan.service is not installed"
fi

next="$(systemctl show -p NextElapseUSecRealtime --value podshield-scan.timer 2>/dev/null || true)"
if [[ -n "$next" && "$next" != 0 && "$next" != n/a ]]; then
    pass "daily scan is scheduled (next: $next)"
else
    fail "podshield-scan.timer has no next run scheduled (systemctl list-timers podshield-scan.timer)"
fi

# ------------------------------------------------------------------------------ API
if wait_for_http "$BASE/api/health" 30; then
    code="$(http_code "$TMP/health.json" GET "$BASE/api/health")"
    summary="$("$PY" - "$TMP/health.json" <<'EOF' 2>/dev/null || true
import json, sys
h = json.load(open(sys.argv[1]))
scanners = h.get("scanners") or {}
parts = [f"{name}={'on' if s.get('available') else 'unavailable'}" for name, s in sorted(scanners.items())]
print(f"{len(scanners)}|{h.get('podman')}|{' '.join(parts)}")
EOF
)"
    count="${summary%%|*}"
    rest="${summary#*|}"
    podman_ok="${rest%%|*}"
    list="${rest#*|}"
    if [[ "$code" == 200 && "$count" =~ ^[1-9][0-9]*$ ]]; then
        pass "/api/health returns 200 with $count scanners: $list"
    else
        fail "/api/health returned $code without a scanner list"
    fi
    if [[ "$podman_ok" == True ]]; then
        pass "API reaches Podman (health.podman = true)"
    else
        fail "API cannot reach Podman (health.podman = ${podman_ok:-?}); check socket permissions"
    fi
else
    fail "/api/health did not return 200 within 30 s at $BASE (journalctl -u podshield-api -n 50)"
fi

code="$(http_code "$TMP/index.html" GET "$BASE/")"
if [[ "$code" == 200 ]] && grep -qi '<div id="root"\|<!doctype html' "$TMP/index.html"; then
    pass "dashboard is served at $BASE/"
else
    fail "dashboard not served at $BASE/ (HTTP $code; is $PS_PREFIX/frontend/dist/index.html there?)"
fi

# ------------------------------------------------------------------------------ files
if [[ -x /usr/local/bin/podshield ]] && /usr/local/bin/podshield --version >/dev/null 2>&1; then
    pass "CLI works: $(/usr/local/bin/podshield --version 2>&1)"
else
    fail "/usr/local/bin/podshield is missing or does not start"
fi

if [[ -f "$PS_CONF_DIR/config.toml" ]]; then
    pass "config present: $PS_CONF_DIR/config.toml"
else
    fail "missing $PS_CONF_DIR/config.toml"
fi

if [[ -s "$PS_OVAL_XML" ]] && head -c 8192 "$PS_OVAL_XML" | grep -q oval_definitions; then
    pass "OVAL feed present: $PS_OVAL_XML ($(du -h "$PS_OVAL_XML" | cut -f1))"
else
    fail "OVAL feed missing or invalid at $PS_OVAL_XML (re-run install.sh, or --oval-file PATH)"
fi

# ------------------------------------------------------------------------------ network
if [[ "$HOST" == 127.* || "$HOST" == localhost || "$HOST" == ::1 ]]; then
    pass "dashboard bound to $HOST only (no firewall port needed)"
elif systemctl is-active --quiet firewalld; then
    if firewall-cmd --query-port="$PORT/tcp" >/dev/null 2>&1; then
        pass "firewalld allows $PORT/tcp"
    else
        fail "firewalld does not allow $PORT/tcp (re-run install.sh --bind $HOST --port $PORT)"
    fi
else
    warn "firewalld is not running; $PORT/tcp is reachable without a firewall"
fi

# ------------------------------------------------------------------------------ AVC
denials="$(avc_denials_since "$SINCE")"
related="$(printf '%s\n' "$denials" | avc_podshield_related | sed '/^$/d')"
others=$(( $(printf '%s\n' "$denials" | sed '/^$/d' | wc -l) - $(printf '%s\n' "$related" | sed '/^$/d' | wc -l) ))
if [[ -z "$related" ]]; then
    pass "no SELinux denials for PodShield since $(date -d "@$SINCE" '+%H:%M:%S')"
else
    fail "$(printf '%s\n' "$related" | wc -l) SELinux denial(s) for PodShield since $(date -d "@$SINCE" '+%H:%M:%S') (ausearch -m AVC -ts recent)"
    printf '%s\n' "$related" | avc_brief | head -n 5 | sed 's/^/         /'
fi
if (( others > 0 )); then
    warn "$others unrelated SELinux denial(s) on this host in the same window (not PodShield)"
fi

# ------------------------------------------------------------------------------ summary
printf '\nverify: %d passed, %d failed, %d warning(s)\n' "$PASS_N" "$FAIL_N" "$WARN_N"
(( FAIL_N == 0 ))
