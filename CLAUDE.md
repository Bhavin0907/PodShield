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
- RHEL integration (DEPLOY_PROMPT.MD) is done and confirmed on the workstation (af8a040,
  2026-11-16): selftest 8/8 PASS with --skip-demo (unit 1020, integration 49 passed/4 skipped,
  SELinux Enforcing, 0 AVC denials); the demo step passed on its own in the run before (35b176e).
  Bugs found on RHEL and fixed: Path.is_file EACCES on py3.11 (config.path_is_file); podman-py
  events filter encoding (watcher got no events); `skopeo inspect --config` drops Healthcheck
  (now --raw); build cache merging identical test fixtures. Trivy is not installed (optional).
  - deploy/install.sh: idempotent installer. Builds frontend/dist (gitignored) with Node 20,
    falling back to nodejs:22 if 20 < 20.19. Downloads OVAL (or --oval-file), restorecon, units,
    SELinux checks (port label only if confined; NoNewPrivileges off via drop-in only if
    sesearch says the policy would block it), firewall only for non-loopback --bind, then verify.
  - deploy/systemd/: api, watch, scan.service + daily scan.timer (Persistent). Hardening:
    PrivateTmp, ProtectHome=tmpfs, NoNewPrivileges. Run as root.
  - deploy/verify.sh (read-only PASS/FAIL), deploy/uninstall.sh (--purge), deploy/lib.sh
    (shared helpers, log sanitizer), demo/run-demo.sh (waits for the watcher, prints grades).
  - deploy/selftest.sh: one command runs everything and prints a one-screen summary.
    `--push-log` pushes the sanitized log to branch `selftest-logs` when GitHub credentials
    are saved (see README); read it with
    `git fetch origin selftest-logs`.
- Workstation command: `cd ~/PodShield && git pull && sudo bash podshield/deploy/selftest.sh --push-log`
- Next: rerun the selftest, read its log (selftest-logs branch or the on-screen failed-test
  list) and fix the remaining integration failures.