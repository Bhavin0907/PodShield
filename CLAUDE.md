## Project context
PodShield: Container Image Security & Hygiene Auditor for Podman on RHEL 9 (course project).
- Repo root: PodShield/. The app lives in podshield/ (backend, frontend, deploy, demo, docs).
- Full spec: @PROMPT.md. RHEL integration spec: @DEPLOY_PROMPT.MD.
- Workflow: I code here on my laptop, push to GitHub, then git pull and run on a Red Hat
  Online Learning lab workstation (RHEL 9.5, Podman 5.2.2, user student with sudo). I can't
  SSH into it, so give me exact commands to run there and I'll paste back the output.
- The lab is wiped periodically, so everything must be reproducible via deploy/install.sh.

## Current status
- App phases 1 to 6 from PROMPT.md are done.
- RHEL integration (DEPLOY_PROMPT.MD) is implemented, not yet confirmed on the workstation:
  - deploy/install.sh: idempotent installer. Builds frontend/dist (gitignored) with Node 20,
    falling back to nodejs:22 if 20 < 20.19. Downloads OVAL (or --oval-file), restorecon, units,
    SELinux checks (port label only if confined; NoNewPrivileges off via drop-in only if
    sesearch says the policy would block it), firewall only for non-loopback --bind, then verify.
  - deploy/systemd/: api, watch, scan.service + daily scan.timer (Persistent). Hardening:
    PrivateTmp, ProtectHome=tmpfs, NoNewPrivileges. Run as root.
  - deploy/verify.sh (read-only PASS/FAIL), deploy/uninstall.sh (--purge), deploy/lib.sh
    (shared helpers, log sanitizer), demo/run-demo.sh (waits for the watcher, prints grades).
  - deploy/selftest.sh: one command runs everything and prints a one-screen summary.
    `--push-log` pushes the sanitized log to branch `selftest-logs`; read it with
    `git fetch origin selftest-logs`.
- Workstation command: `cd ~/PodShield && git pull && sudo bash podshield/deploy/selftest.sh --push-log`
- Next: read the selftest log from the selftest-logs branch and fix whatever failed.