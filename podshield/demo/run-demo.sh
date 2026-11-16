#!/usr/bin/env bash
# PodShield demo: build a deliberately insecure image and a hardened one, let the watcher
# (podshield-watch.service) scan them automatically, and print both grades.
#
#   sudo bash demo/run-demo.sh [--timeout SECONDS] [--no-watch]
#
#   --timeout N   how long to wait for the watcher per image (default 900; CVE scans are slow)
#   --no-watch    do not wait for the watcher; scan directly with `podshield scan`
#
# Exit status: 0 = both images auto-scanned by the watcher and bad < good,
#              3 = grades obtained, but only by scanning directly (watcher did not react),
#              1 = failure.
# The last line is machine-readable:  DEMO_RESULT bad=F/0 good=A/96 mode=watcher

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/lib.sh
. "$DEMO_DIR/../deploy/lib.sh"

TIMEOUT=900
USE_WATCH=1
while (( $# )); do
    case "$1" in
        --timeout)  TIMEOUT="${2:?--timeout needs a value}"; shift ;;
        --no-watch) USE_WATCH=0 ;;
        -h|--help)  sed -n '2,14s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *)          die "unknown option: $1 (try --help)" ;;
    esac
    shift
done
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout must be a number of seconds"
require_root   # rootful Podman: the images must land in the storage the watcher watches

BAD=localhost/demo-bad:latest
GOOD=localhost/demo-good:1.0.0
CLI=/usr/local/bin/podshield
[[ -x "$CLI" ]] || die "podshield is not installed (run deploy/install.sh first)"
PY="$(ps_python)"

# Prints "id|last_scanned_at|grade|score" for the stored result of REF (empty if none).
stored() {
    "$CLI" report "$1" --json 2>/dev/null | "$PY" -c '
import json, sys
try:
    rows = json.load(sys.stdin)
except ValueError:
    rows = []
if rows:
    print("|".join(str(rows[0].get(k)) for k in ("id", "last_scanned_at", "grade", "score")))
' 2>/dev/null || true
}

build() {
    local file="$1" ref="$2"
    printf '\n==> building %s from %s\n' "$ref" "$file"
    # --format docker keeps HEALTHCHECK (the OCI format drops it). --pull=newer refreshes bases.
    podman build --pull=newer --format docker -t "$ref" -f "$DEMO_DIR/$file" "$DEMO_DIR"
}

# Wait until the stored scan of image ID is newer than PREVIOUS ("id|timestamp" before build).
wait_for_scan() {
    local id="$1" previous="$2" deadline now row
    deadline=$((SECONDS + TIMEOUT))
    while (( SECONDS < deadline )); do
        row="$(stored "$id")"
        if [[ -n "$row" ]]; then
            now="${row%%|*}|$(cut -d'|' -f2 <<<"$row")"
            if [[ "$(cut -d'|' -f2 <<<"$row")" != None && "$now" != "$previous" ]]; then
                return 0
            fi
        fi
        sleep 5
    done
    return 1
}

mode=watcher
if (( USE_WATCH )) && ! systemctl is-active --quiet podshield-watch.service; then
    warn "podshield-watch.service is not running; falling back to direct scans"
    mode=direct
fi
(( USE_WATCH )) || mode=direct

declare -A RESULT=()
for pair in "Containerfile.bad $BAD" "Containerfile.good $GOOD"; do
    file="${pair%% *}"
    ref="${pair#* }"
    before="$(stored "$ref")"
    before="${before%%|*}|$(cut -d'|' -f2 <<<"$before")"
    build "$file" "$ref" || die "podman build of $ref failed (network? see the output above)"
    id="$(podman image inspect --format '{{.Id}}' "$ref")"

    if [[ "$mode" == watcher ]]; then
        printf '==> waiting up to %ss for podshield-watch to scan %s (%s)\n' "$TIMEOUT" "$ref" "${id:0:12}"
        if wait_for_scan "$id" "$before"; then
            pass "watcher scanned $ref automatically"
        else
            warn "watcher did not scan $ref within ${TIMEOUT}s (journalctl -u podshield-watch); scanning directly"
            mode=direct-fallback
            "$CLI" scan "$ref" >/dev/null || true
        fi
    else
        printf '==> scanning %s directly\n' "$ref"
        "$CLI" scan "$ref" >/dev/null || true
    fi
    row="$(stored "$id")"
    [[ -n "$row" ]] || die "no stored result for $ref after the scan"
    RESULT[$ref]="$(cut -d'|' -f3 <<<"$row")/$(cut -d'|' -f4 <<<"$row")"
done

printf '\n==> results\n'
"$CLI" report "$BAD" 2>/dev/null | head -n 20 || true
printf '\n'
"$CLI" report "$GOOD" 2>/dev/null | head -n 20 || true

bad="${RESULT[$BAD]}"
good="${RESULT[$GOOD]}"
printf '\n  %-28s grade %-2s score %s\n' "$BAD" "${bad%/*}" "${bad#*/}"
printf '  %-28s grade %-2s score %s\n\n' "$GOOD" "${good%/*}" "${good#*/}"

status=0
if [[ "${bad#*/}" =~ ^[0-9]+$ && "${good#*/}" =~ ^[0-9]+$ ]] && (( ${bad#*/} < ${good#*/} )); then
    pass "the hardened image scores higher than the insecure one"
else
    fail "expected demo-bad to score lower than demo-good (bad=$bad good=$good)"
    status=1
fi
if (( status == 0 )) && [[ "$mode" != watcher ]]; then
    status=3
fi
printf 'DEMO_RESULT bad=%s good=%s mode=%s\n' "$bad" "$good" "$mode"
exit "$status"
