# shellcheck shell=bash
# Shared helpers for verify.sh, uninstall.sh, selftest.sh and demo/run-demo.sh.
# Source it; do not run it. install.sh is self-contained on purpose (it is the bootstrap).

PS_PREFIX=/opt/podshield
PS_CONF_DIR=/etc/podshield
PS_STATE_DIR=/var/lib/podshield
PS_ENV_FILE="$PS_CONF_DIR/podshield.env"
PS_OVAL_XML="$PS_STATE_DIR/oval/rhel-9.oval.xml"
PS_UNIT_DIR=/etc/systemd/system
PS_SOCKET=/run/podman/podman.sock
PS_UNITS=(podshield-api.service podshield-watch.service podshield-scan.service podshield-scan.timer)

PASS_N=0
FAIL_N=0
WARN_N=0
FAILED_CHECKS=()

pass() { PASS_N=$((PASS_N + 1)); printf '[ PASS ] %s\n' "$*"; }
fail() { FAIL_N=$((FAIL_N + 1)); FAILED_CHECKS+=("$*"); printf '[ FAIL ] %s\n' "$*"; }
warn() { WARN_N=$((WARN_N + 1)); printf '[ WARN ] %s\n' "$*"; }
info() { printf '         %s\n' "$*"; }
die()  { printf '[ FAIL ] %s\n' "$*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "run as root: sudo bash $0 $*"
}

# Python with json available: the PodShield venv once installed, else the platform python.
ps_python() {
    if [[ -x "$PS_PREFIX/venv/bin/python" ]]; then
        printf '%s\n' "$PS_PREFIX/venv/bin/python"
    else
        command -v python3 || command -v python3.11 || printf 'python3\n'
    fi
}

# Read KEY from /etc/podshield/podshield.env (written by install.sh), with a default.
env_value() {
    local key="$1" default="$2" value=""
    if [[ -r "$PS_ENV_FILE" ]]; then
        value="$(sed -n "s/^${key}=//p" "$PS_ENV_FILE" | tail -n 1)"
    fi
    printf '%s\n' "${value:-$default}"
}

# Base URL of the API as seen from this host (0.0.0.0 / :: are reached via loopback).
api_base() {
    local host port
    host="${1:-$(env_value PODSHIELD_HOST 127.0.0.1)}"
    port="${2:-$(env_value PODSHIELD_PORT 8080)}"
    case "$host" in
        0.0.0.0|'') host=127.0.0.1 ;;
        ::) host='[::1]' ;;
        *:*) host="[$host]" ;;
    esac
    printf 'http://%s:%s\n' "$host" "$port"
}

# HTTP status code of a request; the body goes to the file in $1.
#   http_code BODY_FILE METHOD URL [JSON]
http_code() {
    local body="$1" method="$2" url="$3" data="${4:-}"
    local -a args=(--silent --show-error --max-time "${HTTP_TIMEOUT:-60}" --output "$body"
                   --write-out '%{http_code}' -X "$method")
    if [[ -n "$data" ]]; then
        args+=(-H 'Content-Type: application/json' --data "$data")
    fi
    curl "${args[@]}" "$url" 2>/dev/null || printf '000'
}

# Wait until GET URL returns 200 (or the timeout in seconds passes).
wait_for_http() {
    local url="$1" timeout="${2:-30}" deadline code
    deadline=$((SECONDS + timeout))
    while (( SECONDS < deadline )); do
        code="$(curl --silent --output /dev/null --max-time 5 --write-out '%{http_code}' "$url" 2>/dev/null || true)"
        [[ "$code" == 200 ]] && return 0
        sleep 1
    done
    return 1
}

# SELinux denials (AVC, USER_AVC, SELINUX_ERR) logged at or after epoch $1, one raw audit
# record per line. Empty output means none. Needs root (ausearch).
avc_denials_since() {
    local since="$1" raw
    command -v ausearch >/dev/null 2>&1 || return 0
    raw="$(ausearch -m AVC,USER_AVC,SELINUX_ERR -ts boot --raw 2>/dev/null \
        || ausearch -m AVC,USER_AVC,SELINUX_ERR -ts today --raw 2>/dev/null || true)"
    [[ -n "$raw" ]] || return 0
    awk -v since="$since" '
        /denied|SELINUX_ERR/ {
            if (match($0, /audit\([0-9]+/)) {
                t = substr($0, RSTART + 6, RLENGTH - 6)
                if (t + 0 >= since + 0) print
            }
        }' <<<"$raw"
}

# Keep only denials that involve PodShield or the tools it drives.
avc_podshield_related() {
    grep -E 'comm="(podshield|uvicorn|python[0-9.]*|podman|conmon|crun|runc|catatonit|oscap[^"]*|skopeo|trivy|buildah|bzip2|curl|npm|node)"|podshield' || true
}

# One short line per denial: comm, permission, source -> target, class.
avc_brief() {
    sed -E 's/.*denied +\{ ?([^}]*)\}.*comm="([^"]*)".*scontext=[^:]*:[^:]*:([^: ]*)[^ ]* tcontext=[^:]*:[^:]*:([^: ]*)[^ ]* tclass=([^ ]*).*/\2: \1 \3 -> \4 (\5)/' | sort | uniq -c | sort -rn
}

# Mask anything that looks like a credential before a log leaves the machine.
# Values keep their first 4 characters, like PodShield's own masking.
sanitize_stream() {
    sed -E -f <(cat <<'SED'
s/(AKIA|ASIA)[A-Z0-9]{16}/\1****************/g
s/(gh[pousr]_)[A-Za-z0-9]{20,}/\1****/g
s/(github_pat_)[A-Za-z0-9_]{20,}/\1****/g
s/([Aa]uthorization: *(Bearer|Basic|token) +)[^ ]+/\1****/g
s#(://[^:/@ ]+:)[^@/ ]+@#\1****@#g
s/((password|passwd|secret|token|api_key|apikey|access_key|private_key)[a-z_]* *[=:] *["']?)([^*[:space:]"',]{4})[^[:space:]"',]*/\1\3****/gI
SED
)
}
