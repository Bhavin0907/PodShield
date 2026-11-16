#!/usr/bin/env bash
# PodShield one-command self-test for the RHEL 9 workstation.
#
#   cd ~/PodShield && git pull && sudo bash podshield/deploy/selftest.sh --push-log
#
# Runs every step even when an earlier one fails, prints a one-screen summary with a score, and
# writes the full log to ~/podshield-selftest-<timestamp>.log (home of the user who ran sudo).
#
#   --push-log           commit the (sanitized) log to the git branch `selftest-logs` and push it
#   --skip-install       do not run install.sh (test what is already installed)
#   --skip-integration   do not run the root integration tests (they take the longest)
#   --skip-demo          do not build and scan the demo images
#   --oval-file PATH     passed to install.sh (offline OVAL feed)
#   --port N, --bind A   passed to install.sh
#
# Steps: preflight, install, verify, unit tests, integration tests, demo, API smoke test,
# reboot safety, SELinux AVC check. The demo runs before the API smoke test so that there are
# scanned images for the image, report and rescan endpoints.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
# shellcheck source=deploy/lib.sh
. "$HERE/lib.sh"

PUSH_LOG=0
SKIP_INSTALL=0
SKIP_INTEGRATION=0
SKIP_DEMO=0
INSTALL_ARGS=()
while (( $# )); do
    case "$1" in
        --push-log)         PUSH_LOG=1 ;;
        --skip-install)     SKIP_INSTALL=1 ;;
        --skip-integration) SKIP_INTEGRATION=1 ;;
        --skip-demo)        SKIP_DEMO=1 ;;
        --oval-file|--port|--bind)
            [[ $# -ge 2 ]] || die "$1 needs a value"
            INSTALL_ARGS+=("$1" "$2"); shift ;;
        -h|--help) sed -n '2,19s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done
require_root

REAL_USER="${SUDO_USER:-root}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
REAL_HOME="${REAL_HOME:-/root}"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$REAL_HOME/podshield-selftest-$STAMP.log"
START_EPOCH="$(date +%s)"
TMPD="$(mktemp -d /tmp/podshield-selftest.XXXXXX)"
VENV="$SRC/backend/.venv-selftest"
WATCH_STOPPED=0

cleanup() {
    # Never leave the watcher stopped, even if the self-test is interrupted.
    if (( WATCH_STOPPED )); then systemctl start podshield-watch.service >/dev/null 2>&1 || true; fi
    rm -rf "$TMPD"
}
trap cleanup EXIT

# Run a command as the user who invoked sudo (git, npm and the unit tests stay theirs).
as_user() {
    if [[ "$REAL_USER" != root ]]; then
        runuser -u "$REAL_USER" -- env "HOME=$REAL_HOME" "PATH=$PATH" "$@"
    else
        "$@"
    fi
}

: > "$LOG"
chown "$REAL_USER": "$LOG" 2>/dev/null || true
chmod 0644 "$LOG"

# Summary rows.
S_NAME=()
S_STATUS=()
S_REASON=()
S_TIME=()
REASON=""

fmt_time() { printf '%dm%02ds' $(( $1 / 60 )) $(( $1 % 60 )); }

run_step() {
    local title="$1" fn="$2" t0 rc status
    printf '  running  %-22s ' "$title"
    printf '\n\n######## STEP: %s   (%s)\n' "$title" "$(date '+%F %T')" >>"$LOG"
    REASON=""
    t0=$SECONDS
    if "$fn" >>"$LOG" 2>&1; then rc=0; else rc=$?; fi
    case "$rc" in
        0) status=PASS ;;
        2) status=SKIP ;;
        *) status=FAIL ;;
    esac
    [[ -n "$REASON" ]] || REASON="exit status $rc"
    S_NAME+=("$title")
    S_STATUS+=("$status")
    S_REASON+=("$REASON")
    S_TIME+=("$(( SECONDS - t0 ))")
    printf '######## RESULT: %s  %s  (%s)\n' "$status" "$REASON" "$(fmt_time $(( SECONDS - t0 )))" >>"$LOG"
    printf '[%s] %s\n' "$status" "$(fmt_time $(( SECONDS - t0 )))"
}

# Last pytest summary line, without the ===== decoration.
pytest_summary() {
    grep -E '[0-9]+ (passed|failed|error|errors|skipped|deselected)|no tests ran' "$1" | tail -n 1 \
        | sed -E 's/=+//g; s/^ +| +$//g; s/ in [0-9.]+s.*$//'
}

# --------------------------------------------------------------------------- 1 preflight
step_preflight() {
    local problems=() notes=() id="" ver="" mode free_var mem url
    if [[ -r /etc/os-release ]]; then
        id="$(. /etc/os-release && echo "${ID:-}")"
        ver="$(. /etc/os-release && echo "${VERSION_ID:-}")"
    fi
    echo "os: $id $ver   kernel: $(uname -r)   host: $(hostname -f 2>/dev/null || hostname)"
    [[ "${ver%%.*}" == 9 ]] || problems+=("not EL9 ($id $ver)")
    mode="$(getenforce 2>/dev/null || echo unknown)"
    echo "selinux: $mode"
    [[ "$mode" == Enforcing ]] || problems+=("SELinux $mode")
    echo "user: $REAL_USER ($REAL_HOME)   repo: $SRC"
    as_user git -C "$SRC" log -1 --format='git: %h %s (%cr)' 2>/dev/null || echo "git: not a checkout"
    as_user git -C "$SRC" status --short 2>/dev/null | head -n 20 || true

    free_var="$(df -Pm /var | awk 'NR == 2 { print $4 }')"
    mem="$(free -m | awk '/^Mem:/ { print $2 }')"
    echo "free on /var: ${free_var} MB   memory: ${mem} MB   cpus: $(nproc)"
    (( free_var >= 4096 )) || problems+=("only ${free_var}MB free on /var")
    (( mem >= 1800 )) || notes+=("${mem}MB RAM")

    for url in https://registry.access.redhat.com/v2/ https://pypi.org/simple/pip/ \
               https://registry.npmjs.org/ https://security.access.redhat.com/data/oval/v2/; do
        if curl --silent --output /dev/null --max-time 20 "$url"; then
            echo "network: reachable  $url"
        else
            echo "network: UNREACHABLE  $url"
            problems+=("no access to ${url#https://}")
        fi
    done
    if (( ${#problems[@]} )); then
        REASON="$(IFS=';'; echo "${problems[*]}")"
        return 1
    fi
    REASON="EL $ver, $mode, ${free_var}MB free, network ok${notes:+, ${notes[*]}}"
}

# ------------------------------------------------------------------------------ 2 install
step_install() {
    if (( SKIP_INSTALL )); then REASON="--skip-install"; return 2; fi
    local rc warnings
    timeout 3600 bash "$SRC/deploy/install.sh" --skip-verify "${INSTALL_ARGS[@]}" 2>&1 | tee "$TMPD/install.out"
    rc=${PIPESTATUS[0]}
    warnings="$(grep -c '^\[ WARN \]' "$TMPD/install.out" || true)"
    if (( rc == 0 )); then
        REASON="installed, ${warnings} warning(s)"
        [[ "$warnings" == 0 ]] || REASON+=": $(grep -m1 '^\[ WARN \]' "$TMPD/install.out" | cut -c10-)"
        return 0
    fi
    (( rc == 124 )) && { REASON="timed out after 60 min"; return 1; }
    REASON="$(grep -m1 '^\[ FAIL \]' "$TMPD/install.out" | cut -c10-)"
    REASON="${REASON:-install.sh exited with $rc}"
    return 1
}

# ------------------------------------------------------------------------------- 3 verify
step_verify() {
    local rc line
    bash "$SRC/deploy/verify.sh" --since "$START_EPOCH" 2>&1 | tee "$TMPD/verify.out"
    rc=${PIPESTATUS[0]}
    line="$(grep -E '^verify: ' "$TMPD/verify.out" | tail -n 1 | sed 's/^verify: //')"
    REASON="${line:-verify.sh exited with $rc}"
    if (( rc != 0 )); then
        REASON+="; $(grep -m1 '^\[ FAIL \]' "$TMPD/verify.out" | cut -c10-)"
        return 1
    fi
}

# --------------------------------------------------------------------------- 4 unit tests
prepare_venv() {
    if [[ ! -x "$VENV/bin/python" ]]; then
        as_user python3.11 -m venv "$VENV" || return 1
    fi
    as_user "$VENV/bin/python" -m pip install --quiet --upgrade pip || return 1
    (cd "$SRC/backend" && as_user "$VENV/bin/python" -m pip install --quiet -e ".[dev]")
}

step_unit() {
    local rc
    if ! prepare_venv; then REASON="could not create the test venv (pip install -e .[dev])"; return 1; fi
    # PODSHIELD_CONFIG: /etc/podshield is root-only; unit tests must use built-in defaults.
    (cd "$SRC/backend" && as_user env PODSHIELD_CONFIG=/nonexistent/podshield-selftest.toml \
        PYTHONDONTWRITEBYTECODE=1 timeout 1800 "$VENV/bin/python" -m pytest \
        -m "unit and not integration" --ignore=tests/integration -p no:cacheprovider) \
        2>&1 | tee "$TMPD/unit.out"
    rc=${PIPESTATUS[0]}
    REASON="$(pytest_summary "$TMPD/unit.out")"
    REASON="${REASON:-pytest exited with $rc}"
    (( rc == 0 ))
}

# -------------------------------------------------------------------- 5 integration tests
step_integration() {
    if (( SKIP_INTEGRATION )); then REASON="--skip-integration"; return 2; fi
    [[ -x "$VENV/bin/python" ]] || prepare_venv || { REASON="no test venv"; return 1; }
    local rc summary
    # The watcher would scan every pstest-* image the suite builds; pause it meanwhile.
    if systemctl is-active --quiet podshield-watch.service; then
        systemctl stop podshield-watch.service && WATCH_STOPPED=1
    fi
    (cd "$SRC/backend" && env PYTHONDONTWRITEBYTECODE=1 timeout 5400 "$VENV/bin/python" -m pytest \
        tests/integration -m integration -rfEs -p no:cacheprovider) 2>&1 | tee "$TMPD/integ.out"
    rc=${PIPESTATUS[0]}
    if (( WATCH_STOPPED )); then
        systemctl start podshield-watch.service && WATCH_STOPPED=0
    fi
    summary="$(pytest_summary "$TMPD/integ.out")"
    REASON="${summary:-pytest exited with $rc}"
    (( rc == 124 )) && REASON="timed out after 90 min; $REASON"
    # Exit 5 = no tests collected; a summary without passed/failed/error = everything skipped.
    if (( rc == 5 )) || { (( rc == 0 )) && ! grep -qE 'passed|failed|error' <<<"$summary"; }; then
        REASON="nothing ran: $REASON"
        return 2
    fi
    (( rc == 0 ))
}

# ---------------------------------------------------------------------------------- 6 demo
step_demo() {
    if (( SKIP_DEMO )); then REASON="--skip-demo"; return 2; fi
    local rc result
    timeout 3000 bash "$SRC/demo/run-demo.sh" 2>&1 | tee "$TMPD/demo.out"
    rc=${PIPESTATUS[0]}
    result="$(grep -E '^DEMO_RESULT ' "$TMPD/demo.out" | tail -n 1 | sed 's/^DEMO_RESULT //')"
    case "$rc" in
        0) REASON="$result (auto-scanned by the watcher)" ;;
        3) REASON="watcher did not auto-scan; direct scan gave $result"; return 1 ;;
        124) REASON="timed out after 50 min"; return 1 ;;
        *) REASON="$(grep -m1 -E '^\[ FAIL \]' "$TMPD/demo.out" | cut -c10-)"
           REASON="${REASON:-run-demo.sh exited with $rc}${result:+; $result}"; return 1 ;;
    esac
}

# ---------------------------------------------------------------------------- 7 API smoke
SMOKE_OK=0
SMOKE_TOTAL=0
SMOKE_FAILED=()

# check NAME EXPECTED_CODE METHOD PATH [JSON]  -> body in $TMPD/body
check() {
    local name="$1" want="$2" method="$3" path="$4" data="${5:-}" code
    SMOKE_TOTAL=$((SMOKE_TOTAL + 1))
    code="$(http_code "$TMPD/body" "$method" "$BASE$path" "$data")"
    if [[ "$code" == "$want" ]]; then
        SMOKE_OK=$((SMOKE_OK + 1))
        printf '[ PASS ] %-34s %s %s -> %s\n' "$name" "$method" "$path" "$code"
        return 0
    fi
    SMOKE_FAILED+=("$name($code)")
    printf '[ FAIL ] %-34s %s %s -> %s (want %s)\n' "$name" "$method" "$path" "$code" "$want"
    head -c 400 "$TMPD/body" 2>/dev/null; echo
    return 1
}

json_get() { "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$TMPD/body" "$1" 2>/dev/null || true; }

step_api() {
    BASE="$(api_base)"
    PY="$(ps_python)"
    SMOKE_OK=0; SMOKE_TOTAL=0; SMOKE_FAILED=()
    echo "API base: $BASE"
    if ! wait_for_http "$BASE/api/health" 60; then
        REASON="API not reachable at $BASE"
        return 1
    fi
    local image="" scan_id="" enabled="" stream
    check "health" 200 GET /api/health && json_get 'len(d["scanners"])' | sed 's/^/         scanners: /'
    check "overview" 200 GET /api/overview
    if check "images list" 200 GET /api/images; then
        image="$(json_get 'next((i["short_id"] for i in d if any("demo-good" in t for t in i["repo_tags"])), d[0]["short_id"] if d else "")')"
    fi
    if [[ -n "$image" ]]; then
        check "image detail" 200 GET "/api/images/$image"
        check "html report" 200 GET "/api/reports/$image.html" && grep -qi '<html' "$TMPD/body" \
            || echo "         (report body is not HTML)"
        if check "start scan" 202 POST /api/scans "{\"image\": \"$image\", \"skip_cve\": true}"; then
            scan_id="$(json_get 'd["scan_id"]')"
        fi
    else
        echo "         no scanned images: image detail, report and scan checks skipped"
        SMOKE_FAILED+=("no-images")
    fi
    if [[ "$scan_id" =~ ^[0-9]+$ ]]; then
        SMOKE_TOTAL=$((SMOKE_TOTAL + 1))
        stream="$(curl --silent --no-buffer --max-time 900 "$BASE/api/scans/$scan_id/stream" 2>/dev/null || true)"
        printf '%s\n' "$stream" | tail -n 4
        if grep -q '^event: progress' <<<"$stream" && grep -q '"stage": "completed"' <<<"$stream"; then
            SMOKE_OK=$((SMOKE_OK + 1)); echo "[ PASS ] scan SSE stream reached 'completed'"
        else
            SMOKE_FAILED+=("sse"); echo "[ FAIL ] scan SSE stream did not reach 'completed'"
        fi
        check "scan detail" 200 GET "/api/scans/$scan_id"
    fi
    check "scan history" 200 GET /api/scans
    check "containers" 200 GET /api/containers
    HTTP_TIMEOUT=120 check "registry inspect (skopeo)" 200 POST /api/registry/inspect \
        '{"reference": "registry.access.redhat.com/ubi9/ubi-minimal:latest"}'
    if check "rules list" 200 GET /api/rules; then
        enabled="$(json_get 'next(r["enabled"] for r in d if r["id"] == "PS-008")')"
    fi
    if [[ "$enabled" == True || "$enabled" == False ]]; then
        local flip=false back=true
        [[ "$enabled" == True ]] || { flip=true; back=false; }
        check "rule toggle" 200 PATCH /api/rules/PS-008 "{\"enabled\": $flip}"
        check "rule restore" 200 PATCH /api/rules/PS-008 "{\"enabled\": $back}"
    fi
    check "unknown image -> 404" 404 GET /api/images/doesnotexist0000
    check "dashboard index" 200 GET /

    REASON="$SMOKE_OK/$SMOKE_TOTAL endpoint checks OK"
    if (( ${#SMOKE_FAILED[@]} )); then
        REASON+="; failed: ${SMOKE_FAILED[*]}"
        return 1
    fi
}

# ------------------------------------------------------------------------ 8 reboot safety
step_reboot() {
    local unit state bad=() n=0 out
    for unit in podman.socket podshield-api.service podshield-watch.service podshield-scan.timer; do
        state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        echo "$unit: ${state:-missing}"
        if [[ "$state" == enabled ]]; then n=$((n + 1)); else bad+=("$unit=${state:-missing}"); fi
    done
    [[ "$(systemctl show -p Persistent --value podshield-scan.timer 2>/dev/null)" == yes ]] \
        || bad+=("timer not Persistent")
    if [[ "$(findmnt -n -o FSTYPE -T "$PS_STATE_DIR" 2>/dev/null)" == tmpfs ]]; then
        bad+=("$PS_STATE_DIR is on tmpfs")
    fi
    out="$(systemd-analyze verify "$PS_UNIT_DIR"/podshield-api.service "$PS_UNIT_DIR"/podshield-watch.service \
            "$PS_UNIT_DIR"/podshield-scan.service "$PS_UNIT_DIR"/podshield-scan.timer 2>&1 | grep podshield || true)"
    echo "systemd-analyze verify: ${out:-clean}"
    [[ -z "$out" ]] || bad+=("systemd-analyze: $(head -n 1 <<<"$out")")

    # What a reboot does to the services: stop and start them, then expect a healthy API.
    systemctl restart podshield-api.service podshield-watch.service || bad+=("restart failed")
    if wait_for_http "$(api_base)/api/health" 60 && systemctl is-active --quiet podshield-watch.service; then
        echo "restart: API healthy and watcher active again"
    else
        bad+=("services not healthy after restart")
    fi
    if (( ${#bad[@]} )); then
        REASON="$n/4 enabled; $(IFS=';'; echo "${bad[*]}")"
        return 1
    fi
    REASON="4/4 units enabled at boot, timer persistent, restart OK"
}

# ----------------------------------------------------------------------- 9 SELinux AVCs
step_avc() {
    local denials related others mode
    mode="$(getenforce 2>/dev/null || echo unknown)"
    denials="$(avc_denials_since "$START_EPOCH")"
    related="$(printf '%s\n' "$denials" | avc_podshield_related | sed '/^$/d')"
    others=$(( $(printf '%s\n' "$denials" | sed '/^$/d' | wc -l) - $(printf '%s\n' "$related" | sed '/^$/d' | wc -l) ))
    echo "SELinux: $mode"
    if [[ -n "$related" ]]; then
        echo "PodShield-related denials:"
        printf '%s\n' "$related" | avc_brief
        printf '%s\n' "$related" | head -n 20
    fi
    if [[ -n "$denials" && -z "$related" ]]; then
        echo "unrelated denials:"; printf '%s\n' "$denials" | avc_brief | head -n 10
    fi
    if [[ "$mode" != Enforcing ]]; then REASON="SELinux is $mode"; return 1; fi
    if [[ -n "$related" ]]; then
        REASON="$(printf '%s\n' "$related" | wc -l) denial(s): $(printf '%s\n' "$related" | avc_brief | head -n 1 | sed 's/^ *[0-9]* //')"
        return 1
    fi
    REASON="Enforcing, 0 PodShield denials during the run${others:+ ($others unrelated)}"
    [[ "$others" != 0 ]] || REASON="Enforcing, 0 denials during the run"
}

# ----------------------------------------------------------------------------- push log
PUSH_STATUS=""

# git as the real user that can never stop to ask for anything: no terminal prompt, no GUI
# askpass, ssh in batch mode, and a hard timeout.
git_np() {
    as_user env GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= \
        GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=15" \
        timeout 120 git -C "$SRC" "$@"
}

# True when a push to $1 can authenticate without a prompt. Never prints a credential.
has_push_credentials() {
    local url="$1"
    case "$url" in
        https://*:*@*) return 0 ;;  # token embedded in the remote URL
        http://*|https://*)
            # Asks the configured credential helper(s) only; fails instead of prompting.
            printf 'url=%s\n\n' "$url" | git_np credential fill >/dev/null 2>&1 ;;
        *)  # ssh remote: authenticating needs a key that works in batch mode
            git_np ls-remote --heads origin </dev/null >/dev/null 2>&1 ;;
    esac
}

# Commit the (already sanitized) log to branch selftest-logs and push it. Uses a temporary
# index + commit-tree: no worktree, no checkout, and local branches are never touched.
push_log() {
    local branch=selftest-logs name url parent="" blob tree commit tmp ident=()
    as_user git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1 \
        || { PUSH_STATUS="skipped: $SRC is not a git checkout"; return 0; }
    url="$(as_user git -C "$SRC" remote get-url origin 2>/dev/null)" \
        || { PUSH_STATUS="skipped: no 'origin' remote"; return 0; }
    if ! has_push_credentials "$url"; then
        PUSH_STATUS="skipped: no saved GitHub credentials (README: Run the self-test)"
        return 0
    fi
    name="$(basename "$LOG")"
    as_user git -C "$SRC" config user.email >/dev/null 2>&1 \
        || ident=(-c user.name="PodShield selftest" -c user.email="selftest@podshield.invalid")
    tmp="$(as_user mktemp -d /tmp/podshield-logpush.XXXXXX)"
    if git_np fetch --quiet origin "+refs/heads/$branch:refs/remotes/origin/$branch" </dev/null >/dev/null 2>&1; then
        parent="$(as_user git -C "$SRC" rev-parse --verify --quiet "refs/remotes/origin/$branch")" || parent=""
    fi
    printf '\n  pushing the log to origin/%s ...\n' "$branch"
    if blob="$(as_user git -C "$SRC" hash-object -w --stdin <"$LOG")" \
        && if [[ -n "$parent" ]]; then
               as_user env GIT_INDEX_FILE="$tmp/index" git -C "$SRC" read-tree "$parent"
           else
               as_user env GIT_INDEX_FILE="$tmp/index" git -C "$SRC" read-tree --empty
           fi \
        && as_user env GIT_INDEX_FILE="$tmp/index" git -C "$SRC" update-index --add \
               --cacheinfo "100644,$blob,logs/$name" \
        && tree="$(as_user env GIT_INDEX_FILE="$tmp/index" git -C "$SRC" write-tree)" \
        && commit="$(as_user git "${ident[@]}" -C "$SRC" commit-tree "$tree" ${parent:+-p "$parent"} \
               -m "selftest: $name ($SCORE_LINE)")"; then
        if git_np push --quiet origin "$commit:refs/heads/$branch" </dev/null 2>"$tmp/push.err"; then
            PUSH_STATUS="pushed to branch $branch: logs/$name"
        else
            PUSH_STATUS="git push failed (log kept locally): $(sanitize_stream <"$tmp/push.err" | tail -n 1 | cut -c1-80)"
        fi
    else
        PUSH_STATUS="could not create the log commit (log kept locally)"
    fi
    rm -rf "$tmp"
}

# ---------------------------------------------------------------------------------- main
printf '\nPodShield self-test - full log: %s\n\n' "$LOG"
{
    printf 'PodShield self-test %s\nhost: %s\nargs: %s\n' "$STAMP" "$(hostname -f 2>/dev/null || hostname)" "${INSTALL_ARGS[*]:-}"
} >>"$LOG"

run_step "Preflight"            step_preflight
run_step "Install (install.sh)" step_install
run_step "Verify (verify.sh)"   step_verify
run_step "Backend unit tests"   step_unit
run_step "Integration tests"    step_integration
run_step "Demo (watcher scan)"  step_demo
run_step "API smoke test"       step_api
run_step "Reboot safety"        step_reboot
run_step "SELinux AVC check"    step_avc

# Root-run steps (integration tests) must not leave root-owned files in the user's checkout.
if [[ "$REAL_USER" != root ]]; then
    find "$SRC" -xdev -user root -not -path '*/node_modules/*' -exec chown "$REAL_USER": {} + 2>/dev/null || true
fi

pass_n=0; fail_n=0; skip_n=0
for s in "${S_STATUS[@]}"; do
    case "$s" in PASS) pass_n=$((pass_n + 1)) ;; FAIL) fail_n=$((fail_n + 1)) ;; *) skip_n=$((skip_n + 1)) ;; esac
done
ran=$((pass_n + fail_n))
pct=0; (( ran == 0 )) || pct=$(( pass_n * 100 / ran ))
SCORE_LINE="score $pass_n/$ran"
total_time=$(( $(date +%s) - START_EPOCH ))

summary() {
    local i rule='-----------------------------------------------------------------------------'
    printf '%s\n' "${rule//-/=}"
    printf ' PodShield self-test   %s   host %s\n' "$(date '+%F %H:%M')" "$(hostname -s 2>/dev/null || hostname)"
    printf ' git %s   SELinux %s   took %s\n' \
        "$(as_user git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo '?')" \
        "$(getenforce 2>/dev/null || echo '?')" "$(fmt_time "$total_time")"
    printf '%s\n' "$rule"
    for i in "${!S_NAME[@]}"; do
        printf ' [%s] %d %-21s %s\n' "${S_STATUS[$i]}" $((i + 1)) "${S_NAME[$i]}" "$(cut -c1-48 <<<"${S_REASON[$i]}")"
    done
    printf '%s\n' "$rule"
    printf ' SCORE %d/%d steps passed (%d%%)   %d failed   %d skipped\n' "$pass_n" "$ran" "$pct" "$fail_n" "$skip_n"
    failed_tests
}

# The first failing pytest tests (unit + integration), so they are visible without the log.
failed_tests() {
    local lines n
    lines="$(cat "$TMPD/unit.out" "$TMPD/integ.out" 2>/dev/null | grep -E '^(FAILED|ERROR) ' || true)"
    [[ -n "$lines" ]] || return 0
    n="$(wc -l <<<"$lines")"
    printf ' Failed tests (%d):\n' "$n"
    head -n 10 <<<"$lines" | sed -E 's/^(FAILED|ERROR) tests\//  /' | cut -c1-110
    (( n <= 10 )) || printf '  ... %d more in the log\n' $((n - 10))
}

{
    printf '\n\n######## SUMMARY\n'
    summary
    printf '\nFull reasons:\n'
    for i in "${!S_NAME[@]}"; do printf '  %s: [%s] %s\n' "${S_NAME[$i]}" "${S_STATUS[$i]}" "${S_REASON[$i]}"; done
} >>"$LOG"

# Never ship credentials: mask anything that looks like one, in place.
sanitize_stream <"$LOG" >"$TMPD/log.clean" && cat "$TMPD/log.clean" >"$LOG"

if (( PUSH_LOG )); then
    push_log || true
fi

printf '\n'
summary
printf ' Log  %s\n' "$LOG"
[[ -z "$PUSH_STATUS" ]] || printf ' Push %s\n' "$PUSH_STATUS"
printf '%s\n' "=============================================================================="
(( fail_n == 0 ))
