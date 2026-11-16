#!/usr/bin/env bash
# PodShield installer for RHEL 9 (also Rocky / AlmaLinux / CentOS Stream 9).
#
# Installs PodShield as native systemd services on this host. Safe to run twice: it upgrades
# the code, keeps an existing /etc/podshield/config.toml, and never changes SELinux modes.
#
#   sudo ./deploy/install.sh [options]
#
# Options:
#   --port N           dashboard port (default 8080)
#   --bind ADDR        address to listen on (default 127.0.0.1). The dashboard has no login,
#                      so any other address opens the firewall port: put authentication
#                      in front of it. 0.0.0.0 means every interface.
#   --oval-file PATH   use this OVAL feed (.xml or .xml.bz2) instead of downloading it
#   --refresh-oval     download the OVAL feed again even if it is already installed
#   --skip-oval        do not touch the OVAL feed
#   --dry-run          print the commands instead of running them (does not need root)
#   --skip-packages    do not run dnf
#   --skip-frontend    do not build or copy the dashboard
#   --skip-services    install files but do not enable or start any systemd unit
#   --no-timer         do not enable the daily scan timer
#   --no-watch         do not enable the Podman events watcher
#   --force            continue on an OS other than RHEL 9
#   -h, --help         show this help

set -Eeuo pipefail

PREFIX=/opt/podshield
CONF_DIR=/etc/podshield
STATE_DIR=/var/lib/podshield
OVAL_DIR="$STATE_DIR/oval"
OVAL_XML="$OVAL_DIR/rhel-9.oval.xml"
OVAL_URL="https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2"
UNIT_DIR=/etc/systemd/system
ENV_FILE="$CONF_DIR/podshield.env"
PYTHON_BIN=python3.11

PORT=8080
BIND=127.0.0.1
PORT_SET=0
BIND_SET=0
OVAL_FILE=""
REFRESH_OVAL=0
SKIP_OVAL=0
DRY_RUN=0
SKIP_PACKAGES=0
SKIP_FRONTEND=0
SKIP_SERVICES=0
ENABLE_TIMER=1
ENABLE_WATCH=1
FORCE=0

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WARNINGS=()
BUILD_TMP=""
cleanup() { [[ -z "$BUILD_TMP" ]] || rm -rf "$BUILD_TMP"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------------- output

log()  { printf '\n==> %s\n' "$*"; }
ok()   { (( DRY_RUN )) || printf '[ PASS ] %s\n' "$*"; }
warn() { printf '[ WARN ] %s\n' "$*" >&2; WARNINGS+=("$*"); }
die()  { printf '[ FAIL ] %s\n' "$*" >&2; exit 1; }

# An unexpected command failure (set -e) is reported with the command that caused it.
trap 'printf "[ FAIL ] line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

# Run a command, or only print it with --dry-run.
run() {
    if (( DRY_RUN )); then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

usage() { sed -n '2,/^set -E/{/^set -E/!s/^# \{0,1\}//p}' "${BASH_SOURCE[0]}"; }

# ---------------------------------------------------------------------------------- options

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value (try --help)"; }

while (( $# )); do
    case "$1" in
        --port)           need_value "$@"; PORT="$2"; PORT_SET=1; shift ;;
        --bind)           need_value "$@"; BIND="$2"; BIND_SET=1; shift ;;
        --oval-file)      need_value "$@"; OVAL_FILE="$2"; shift ;;
        --refresh-oval)   REFRESH_OVAL=1 ;;
        --skip-oval)      SKIP_OVAL=1 ;;
        --dry-run)        DRY_RUN=1 ;;
        --skip-packages)  SKIP_PACKAGES=1 ;;
        --skip-frontend)  SKIP_FRONTEND=1 ;;
        --skip-services)  SKIP_SERVICES=1 ;;
        --no-timer)       ENABLE_TIMER=0 ;;
        --no-watch)       ENABLE_WATCH=0 ;;
        --force)          FORCE=1 ;;
        -h|--help)        usage; exit 0 ;;
        *)                die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) \
    || die "--port must be a number between 1 and 65535 (got: $PORT)"
# Only characters that can appear in an IPv4/IPv6 address or a host name.
[[ "$BIND" =~ ^[A-Za-z0-9.:_-]+$ ]] || die "--bind must be an IP address or host name (got: $BIND)"

is_loopback() { [[ "$1" == 127.* || "$1" == localhost || "$1" == ::1 ]]; }

# ---------------------------------------------------------------------------------- checks

check_environment() {
    log "checking the host"
    if (( ! DRY_RUN )) && [[ $EUID -ne 0 ]]; then
        die "run as root: sudo $0 (or use --dry-run to preview)"
    fi
    [[ -f "$SRC_DIR/backend/pyproject.toml" ]] \
        || die "cannot find backend/pyproject.toml under $SRC_DIR; run this from a PodShield checkout"
    [[ -d "$SRC_DIR/deploy/systemd" ]] || die "missing $SRC_DIR/deploy/systemd"

    local id="" version="" like=""
    if [[ -r /etc/os-release ]]; then
        id="$(. /etc/os-release && echo "${ID:-}")"
        version="$(. /etc/os-release && echo "${VERSION_ID:-}")"
        like="$(. /etc/os-release && echo "${ID_LIKE:-}")"
    fi
    if [[ "${version%%.*}" == "9" ]] && [[ " $id $like " =~ (rhel|centos|rocky|almalinux) ]]; then
        ok "OS is $id $version"
    elif (( FORCE || DRY_RUN )); then
        warn "this does not look like RHEL 9 (found: ${id:-unknown} ${version:-?}); continuing"
    else
        die "this installer targets RHEL 9 (found: ${id:-unknown} ${version:-?}); use --force to override"
    fi

    # SELinux is reported, never changed.
    if command -v getenforce >/dev/null 2>&1; then
        local mode
        mode="$(getenforce)"
        if [[ "$mode" == "Enforcing" ]]; then
            ok "SELinux is Enforcing (left unchanged)"
        else
            warn "SELinux is $mode, not Enforcing. PodShield still works, but this installer will not change it; set enforcing mode yourself (see /etc/selinux/config)"
        fi
    else
        warn "getenforce not found; cannot report the SELinux mode"
    fi
}

# --------------------------------------------------------------------------------- packages

install_packages() {
    log "installing packages"
    if (( SKIP_PACKAGES )); then
        printf 'skipped (--skip-packages)\n'
        return
    fi
    command -v dnf >/dev/null 2>&1 || { (( DRY_RUN )) || die "dnf not found"; }
    run dnf install -y podman skopeo openscap-utils scap-security-guide \
        python3.11 python3.11-pip bzip2 curl
    ok "packages installed"
    if (( ! DRY_RUN )) && ! command -v oscap-podman >/dev/null 2>&1; then
        warn "oscap-podman is missing; CVE scanning with OpenSCAP will be skipped (dnf install openscap-utils)"
    fi
    if (( ! DRY_RUN )) && ! command -v trivy >/dev/null 2>&1; then
        warn "trivy is not installed (optional second CVE source, https://trivy.dev); PodShield works without it"
    fi
}

# --------------------------------------------------------------------------------- app files

install_backend() {
    log "installing the backend into $PREFIX/venv"
    run install -d -m 0755 "$PREFIX"
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        (( DRY_RUN )) && warn "$PYTHON_BIN is not installed yet" \
            || die "$PYTHON_BIN not found (dnf install python3.11)"
    fi
    if [[ ! -x "$PREFIX/venv/bin/python" ]]; then
        run "$PYTHON_BIN" -m venv "$PREFIX/venv"
    fi
    # Build from a private copy: setuptools writes build/ and *.egg-info next to pyproject.toml,
    # and doing that as root inside the user's checkout leaves root-owned files behind.
    local build=/tmp/podshield-build.dry-run
    if (( ! DRY_RUN )); then
        build="$(mktemp -d /tmp/podshield-build.XXXXXX)"
        BUILD_TMP="$build"
    fi
    run cp -R "$SRC_DIR/backend/pyproject.toml" "$SRC_DIR/backend/podshield" "$build/"
    run "$PREFIX/venv/bin/python" -m pip install --quiet --upgrade pip
    run "$PREFIX/venv/bin/python" -m pip install --quiet --upgrade "$build"
    # pip may keep an installed copy with the same version number; replace the code explicitly so
    # that re-running the installer always deploys the current checkout.
    run "$PREFIX/venv/bin/python" -m pip install --quiet --no-deps --force-reinstall "$build"
    if (( ! DRY_RUN )); then
        rm -rf "$build"
        BUILD_TMP=""
        "$PREFIX/venv/bin/podshield" --help >/dev/null 2>&1 \
            || die "the podshield CLI in $PREFIX/venv does not start; see the pip output above"
    fi
    # A regular (non-editable) install: the checkout can be moved or deleted afterwards.
    run ln -sfn "$PREFIX/venv/bin/podshield" /usr/local/bin/podshield
    ok "backend installed; CLI is /usr/local/bin/podshield"
}

install_frontend() {
    log "installing the dashboard"
    if (( SKIP_FRONTEND )); then
        printf 'skipped (--skip-frontend)\n'
        return
    fi
    local dist="$SRC_DIR/frontend/dist"
    if [[ -f "$dist/index.html" ]]; then
        ok "using the existing $dist (delete it to force a rebuild)"
    elif ! build_frontend; then
        return 0
    fi
    run rm -rf "$PREFIX/frontend/dist"
    run install -d -m 0755 "$PREFIX/frontend"
    # Plain recursive copy: do not carry over the builder's owner or the user_home_t SELinux
    # label from the home directory (restorecon below sets the /opt label anyway).
    run cp -R "$dist" "$PREFIX/frontend/dist"
    run chown -R root:root "$PREFIX/frontend"
    ok "dashboard installed in $PREFIX/frontend/dist"
}

# Vite 7 needs Node 20.19+ (or 22.12+). RHEL 9's default Node is older, hence the module stream.
node_is_recent_enough() {
    command -v node >/dev/null 2>&1 || return 1
    local v major minor
    v="$(node --version 2>/dev/null)" || return 1
    v="${v#v}"
    major="${v%%.*}"
    minor="${v#*.}"
    minor="${minor%%.*}"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    (( major >= 23 || (major == 22 && minor >= 12) || (major == 20 && minor >= 19) ))
}

install_node() {
    if node_is_recent_enough; then
        ok "Node.js $(node --version) is recent enough"
        return 0
    fi
    if (( SKIP_PACKAGES )); then
        warn "Node.js 20.19+ is required to build the dashboard and --skip-packages is set"
        return 1
    fi
    printf 'installing Node.js 20 (dnf module nodejs:20)\n'
    if ! run dnf module install -y nodejs:20; then
        # Another stream (RHEL's default is older) may already be enabled: switch it.
        run dnf module reset -y nodejs
        run dnf module install -y nodejs:20
    fi
    if (( DRY_RUN )); then
        return 0
    fi
    # A frozen lab repo can carry a nodejs:20 older than 20.19. RHEL 9.5+ also ships nodejs:22.
    if ! node_is_recent_enough; then
        printf 'Node.js %s is older than 20.19; trying the nodejs:22 stream\n' "$(node --version 2>/dev/null || echo '(missing)')"
        if dnf module reset -y nodejs && dnf module install -y nodejs:22; then
            :
        else
            warn "could not install the nodejs:22 module stream"
        fi
    fi
    if node_is_recent_enough; then
        ok "Node.js $(node --version) installed"
    else
        warn "Node.js $(node --version 2>/dev/null || echo missing) is older than 20.19, which Vite 7 needs; the build may fail"
    fi
}

# Build frontend/dist inside the checkout. Returns non-zero (after a warning) if it cannot.
build_frontend() {
    local web="$SRC_DIR/frontend"
    printf 'frontend/dist not found: building it\n'
    install_node || return 1
    if (( DRY_RUN )); then
        printf '[dry-run] (cd %q && npm ci && npm run build)\n' "$web"
        return 0
    fi
    command -v npm >/dev/null 2>&1 || { warn "npm not found after installing Node.js; the dashboard was not built"; return 1; }
    # Build as the user who ran sudo, so node_modules/ and dist/ in their checkout are not
    # owned by root. Falls back to root when run from a real root shell.
    local -a as_user=()
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
        local home
        home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        as_user=(runuser -u "$SUDO_USER" -- env "HOME=$home")
    fi
    if ! (cd "$web" && "${as_user[@]}" npm ci && "${as_user[@]}" npm run build); then
        warn "the dashboard build failed (see the output above); the API works without it. Fix the error and re-run the installer"
        return 1
    fi
    [[ -f "$SRC_DIR/frontend/dist/index.html" ]] || { warn "the build produced no frontend/dist/index.html"; return 1; }
    ok "dashboard built"
}

install_config() {
    log "writing the configuration"
    run install -d -m 0750 "$CONF_DIR"
    if [[ -e "$CONF_DIR/config.toml" ]]; then
        ok "kept existing $CONF_DIR/config.toml"
        # Refresh the example next to it so new options are discoverable after an upgrade.
        run install -m 0640 "$SRC_DIR/deploy/config.toml.example" "$CONF_DIR/config.toml.example"
    else
        run install -m 0640 "$SRC_DIR/deploy/config.toml.example" "$CONF_DIR/config.toml"
        run install -m 0640 "$SRC_DIR/deploy/config.toml.example" "$CONF_DIR/config.toml.example"
        ok "created $CONF_DIR/config.toml"
    fi
    run install -d -m 0750 "$STATE_DIR" "$OVAL_DIR"

    # Listen address and port live in a small env file read by podshield-api.service. It is kept
    # on re-runs unless --port or --bind is given, so a later upgrade does not reset them.
    if [[ -e "$ENV_FILE" ]] && (( ! PORT_SET && ! BIND_SET )); then
        local value
        value="$(sed -n 's/^PODSHIELD_PORT=//p' "$ENV_FILE" | tail -n 1)"
        [[ "$value" =~ ^[0-9]+$ ]] && PORT="$value"
        value="$(sed -n 's/^PODSHIELD_HOST=//p' "$ENV_FILE" | tail -n 1)"
        [[ "$value" =~ ^[A-Za-z0-9.:_-]+$ ]] && BIND="$value"
        ok "kept $ENV_FILE (listening on $BIND:$PORT)"
    elif (( DRY_RUN )); then
        printf '[dry-run] write %s (PODSHIELD_HOST=%s PODSHIELD_PORT=%s)\n' "$ENV_FILE" "$BIND" "$PORT"
    else
        printf '# Written by deploy/install.sh. Re-run it with --bind/--port, or edit and\n' > "$ENV_FILE"
        printf '# `systemctl restart podshield-api`.\nPODSHIELD_HOST=%s\nPODSHIELD_PORT=%s\n' \
            "$BIND" "$PORT" >> "$ENV_FILE"
        chmod 0640 "$ENV_FILE"
        ok "wrote $ENV_FILE (listening on $BIND:$PORT)"
    fi
}

# ---------------------------------------------------------------------------- podman socket

enable_podman_socket() {
    log "rootful Podman API socket"
    run systemctl enable --now podman.socket
    if (( DRY_RUN )); then
        return
    fi
    systemctl is-active --quiet podman.socket || die "podman.socket did not start: journalctl -u podman.socket"
    [[ -S /run/podman/podman.sock ]] || die "/run/podman/podman.sock is missing although podman.socket is active"
    # A real API call: socket activation starts podman.service on demand.
    if curl --silent --fail --max-time 20 --unix-socket /run/podman/podman.sock \
            http://d/_ping >/dev/null 2>&1; then
        ok "podman.socket is active and answers on /run/podman/podman.sock"
    else
        warn "podman.socket is active but /_ping did not answer; check journalctl -u podman.service"
    fi
}

# --------------------------------------------------------------------------------- OVAL feed

oval_is_valid() {
    [[ -s "$1" ]] && [[ "$(head -c 8192 "$1")" == *oval_definitions* ]]
}

install_oval() {
    log "OVAL vulnerability feed"
    if (( SKIP_OVAL )); then
        printf 'skipped (--skip-oval)\n'
        return
    fi
    if [[ -z "$OVAL_FILE" ]] && (( REFRESH_OVAL == 0 )) && oval_is_valid "$OVAL_XML"; then
        ok "feed already installed at $OVAL_XML (use --refresh-oval to download it again)"
        return
    fi

    # Work on a temporary name and move it into place only after it has been checked, so a
    # failed download never replaces a working feed.
    local tmp="$OVAL_XML.tmp" compressed=0
    if [[ -n "$OVAL_FILE" ]]; then
        [[ -r "$OVAL_FILE" ]] || die "--oval-file: cannot read $OVAL_FILE"
        if [[ "$(head -c 3 "$OVAL_FILE")" == BZh ]]; then
            run cp -f "$OVAL_FILE" "$tmp.bz2"
            compressed=1
        else
            run cp -f "$OVAL_FILE" "$tmp"
        fi
    elif run curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 \
            --max-time 900 --output "$tmp.bz2" "$OVAL_URL"; then
        compressed=1
    else
        rm -f "$tmp.bz2"
        warn "could not download $OVAL_URL. CVE scanning stays off until a feed is installed: fetch rhel-9.oval.xml.bz2 on a machine with internet access, copy it here and run  sudo ./deploy/install.sh --oval-file rhel-9.oval.xml.bz2"
        return 0
    fi
    if (( compressed )) && ! run bzip2 -df "$tmp.bz2"; then   # leaves $tmp (rhel-9.oval.xml.tmp)
        rm -f "$tmp.bz2" "$tmp"
        warn "the OVAL file is not valid bzip2 data; $OVAL_XML was not changed"
        return 0
    fi
    if (( DRY_RUN )); then
        printf '[dry-run] mv -f %s %s\n' "$tmp" "$OVAL_XML"
        return
    fi
    if oval_is_valid "$tmp"; then
        chmod 0640 "$tmp"
        mv -f "$tmp" "$OVAL_XML"
        ok "OVAL feed installed at $OVAL_XML ($(du -h "$OVAL_XML" | cut -f1))"
    else
        rm -f "$tmp"
        warn "the downloaded file is not an OVAL feed; $OVAL_XML was not changed"
    fi
}

# ---------------------------------------------------------------------------------- SELinux

apply_selinux_labels() {
    log "restoring SELinux file contexts"
    # Files under /opt, /etc and /var/lib already get default labels; restorecon only repairs
    # labels that are wrong (for example after copying from another directory).
    if (( DRY_RUN )) || command -v restorecon >/dev/null 2>&1; then
        run restorecon -Rv "$PREFIX" "$CONF_DIR" "$STATE_DIR"
        ok "file contexts restored"
    else
        warn "restorecon not found; skipped"
    fi
}

# ---------------------------------------------------------------------------------- systemd

install_units() {
    log "installing systemd units"
    local unit
    for unit in podshield-api.service podshield-watch.service podshield-scan.service podshield-scan.timer; do
        run install -m 0644 "$SRC_DIR/deploy/systemd/$unit" "$UNIT_DIR/$unit"
    done
    if (( DRY_RUN )) || command -v restorecon >/dev/null 2>&1; then
        run restorecon -F "$UNIT_DIR"/podshield-*
    fi
    run systemctl daemon-reload
    ok "units installed in $UNIT_DIR"
}

enable_services() {
    log "enabling services"
    if (( SKIP_SERVICES )); then
        printf 'skipped (--skip-services)\n'
        return
    fi
    run systemctl enable --now podshield-api.service
    # Pick up a new version after an upgrade; no-op for units that are not running.
    run systemctl try-restart podshield-api.service
    ok "podshield-api enabled"
    if (( ENABLE_WATCH )); then
        run systemctl enable --now podshield-watch.service
        run systemctl try-restart podshield-watch.service
        ok "podshield-watch enabled"
    fi
    if (( ENABLE_TIMER )); then
        run systemctl enable --now podshield-scan.timer
        ok "podshield-scan.timer enabled"
    fi
}

# ---------------------------------------------------------------------------------- firewall

open_firewall() {
    log "firewall"
    if is_loopback "$BIND"; then
        ok "listening on $BIND only: firewall left unchanged"
        return
    fi
    warn "the dashboard has no login and is listening on $BIND:$PORT; restrict who can reach it"
    if (( ! DRY_RUN )) && ! command -v firewall-cmd >/dev/null 2>&1; then
        warn "firewall-cmd not found; open $PORT/tcp yourself if a firewall is running"
        return
    fi
    if (( ! DRY_RUN )) && ! systemctl is-active --quiet firewalld; then
        warn "firewalld is not running; nothing to open"
        return
    fi
    run firewall-cmd --permanent --add-port="$PORT/tcp"
    run firewall-cmd --reload
    ok "firewalld: $PORT/tcp opened"
}

# ----------------------------------------------------------------------------------- finish

verify() {
    local script="$SRC_DIR/deploy/verify.sh"
    if [[ -f "$script" ]]; then
        log "verifying the installation"
        run env PODSHIELD_VERIFY_HOST="$BIND" PODSHIELD_VERIFY_PORT="$PORT" bash "$script"
    else
        printf '\n(deploy/verify.sh is not part of this phase yet; skipping the verification step)\n'
    fi
}

print_summary() {
    local host="$BIND"
    [[ "$host" == 0.0.0.0 || "$host" == :: ]] && host="$(hostname -f 2>/dev/null || hostname)"
    cat <<EOF

PodShield is installed.

  Dashboard   http://$host:$PORT
  CLI         podshield doctor | podshield scan --all
  Config      $CONF_DIR/config.toml   (listen address: $ENV_FILE)
  Database    $STATE_DIR/podshield.db
  Logs        journalctl -u podshield-api -u podshield-watch -u podshield-scan
EOF
    if is_loopback "$BIND"; then
        printf '\nBound to localhost. To reach it from your laptop:  ssh -L %s:127.0.0.1:%s user@this-host\n' \
            "$PORT" "$PORT"
    fi
    if (( ${#WARNINGS[@]} )); then
        printf '\n%d warning(s):\n' "${#WARNINGS[@]}"
        printf '  - %s\n' "${WARNINGS[@]}"
    fi
}

main() {
    check_environment
    install_packages
    install_backend
    install_frontend
    install_config
    enable_podman_socket
    install_oval
    apply_selinux_labels
    install_units
    enable_services
    open_firewall
    verify
    if (( DRY_RUN )); then
        log "dry run finished; nothing was changed"
    else
        print_summary
    fi
}

main
