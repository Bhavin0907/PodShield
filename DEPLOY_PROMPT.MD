# PodShield: RHEL 9 Integration (lean version)

## Your role
You are a senior RHEL systems engineer. PodShield (see @PROMPT.md) is built and tested.
Make it run as a native RHEL 9 system service on this single VM. This is a course demo, so keep
it simple and reliable. Work in the 3 phases below. After each phase, stop, list the files you
created or changed, give me the exact commands to test it, and wait for my confirmation.
Treat any existing deploy/ files from earlier phases as drafts to upgrade or replace.

## Hard constraints
- RHEL 9, SELinux stays Enforcing. Never use `setenforce 0` or `chcon` as a fix.
- Use RHEL-native tools only: dnf, systemd, journald, firewalld, semanage, restorecon.
- Scripts: bash with `set -euo pipefail`, idempotent (safe to run twice), must check for root,
  clear PASS/FAIL style output.

## Layout
/opt/podshield/              app code + venv (/opt/podshield/venv) + built frontend dist
/etc/podshield/config.toml   config (never overwrite if it already exists)
/var/lib/podshield/          SQLite DB, reports, oval/rhel-9.oval.xml
/usr/local/bin/podshield     symlink to the CLI

## Phase 1: Installer (deploy/install.sh)
1. Check root and EL9; warn if SELinux isn't Enforcing (don't change it).
2. `dnf install -y podman skopeo openscap-utils scap-security-guide python3.11 python3.11-pip bzip2 curl`
3. Create the layout above, venv with python3.11, install backend, copy prebuilt frontend dist.
4. Write config.toml from deploy/config.toml.example if missing.
5. `systemctl enable --now podman.socket`
6. Download and decompress the OVAL feed from
   https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2
   into /var/lib/podshield/oval/. If offline, accept `--oval-file PATH`.
7. `restorecon -Rv /opt/podshield /etc/podshield /var/lib/podshield`
8. Install and start the systemd units (Phase 2), apply firewall/SELinux (Phase 3), then run
   deploy/verify.sh and print the dashboard URL.
Flags: --port N (default 8080), --bind ADDR (default 127.0.0.1), --oval-file PATH.
Only open the firewall if --bind is not 127.0.0.1.

## Phase 2: systemd units (deploy/systemd/)
- podshield-api.service: uvicorn from the venv, Requires/After=podman.socket,
  Restart=on-failure, output to journald.
- podshield-watch.service: runs `podshield watch` to auto-scan on image pull/build.
- podshield-scan.service (oneshot) + podshield-scan.timer: daily full scan,

## Extra requirements
- frontend/dist is gitignored, so install.sh must build it: install Node.js 20 with
  `dnf module install -y nodejs:20` (RHEL's default Node is too old for Vite), then
  `npm ci && npm run build` in frontend/. Skip if dist already exists.
- The repo root is ~/PodShield and the project lives in ~/PodShield/podshield on the workstation.