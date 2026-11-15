# PodShield: Container Image Security & Hygiene Auditor for Podman on RHEL

## Your role
You are a senior full-stack and Linux platform engineer. Build PodShield, a production-quality
security and hygiene auditor for Podman container images, running natively on RHEL 9 with SELinux
enforcing. Work in the phases defined below. After each phase, stop, summarize what you built,
list how to test it, and wait for my confirmation before continuing.

## Hard constraints
- Target OS: RHEL 9 (SELinux enforcing, firewalld active). Never suggest disabling SELinux.
- Container engine: Podman only. Never use Docker or docker-py.
- Backend: Python 3.11, FastAPI, Uvicorn, Pydantic v2, SQLite (via SQLModel or SQLAlchemy), full type hints.
- Podman access: the `podman` Python library (podman-py) over the Podman socket. Default to the
  rootful socket at unix:///run/podman/podman.sock; support the rootless socket at
  unix:///run/user/<UID>/podman/podman.sock via config. Fall back to `podman ... --format json`
  subprocess calls only where the API lacks a feature.
- Frontend: React 18 + Vite + TypeScript, Tailwind CSS, shadcn/ui, Recharts, lucide-react,
  TanStack Query and TanStack Table. Built as static files and served by FastAPI.
  No runtime CDN dependencies (the lab may be offline); bundle fonts locally.
- All subprocess calls use argument lists (never shell=True), with timeouts and error handling.
- If a tool is missing (oscap-podman, trivy, skopeo), degrade gracefully: mark that scanner as
  "unavailable" in results and the UI instead of crashing.

## Architecture
podshield/
  backend/
    podshield/
      main.py              # FastAPI app, serves API under /api and the built frontend at /
      config.py            # settings from /etc/podshield/config.toml with env overrides
      db.py, models.py     # SQLite at /var/lib/podshield/podshield.db
      podman_client.py     # podman-py wrapper: list images, inspect, history, containers
      scanners/
        hygiene.py         # rule engine (see Hygiene Rules)
        oscap.py           # wraps `oscap-podman <image> oval eval` with Red Hat OVAL feed
        trivy.py           # optional, wraps `trivy image --format json`
        trust.py           # parses /etc/containers/policy.json, registries.conf, signatures
        runtime.py         # audits running containers
        secrets.py         # regex secret detection in ENV and mounted image layers
        registry.py        # pre-pull remote audit via `skopeo inspect docker://...`
      scoring.py           # 0-100 score and A-F grade
      orchestrator.py      # runs a full scan of one or all images, stores results
      watcher.py           # listens to Podman events (pull, build, tag) and triggers scans
      cli.py               # `podshield scan [--all|IMAGE]`, `podshield report`, `podshield watch`
    tests/                 # pytest with mocked podman responses and sample inspect JSON
    pyproject.toml
  frontend/                # Vite React app
  deploy/
    systemd/ podshield-api.service, podshield-watch.service,
             podshield-scan.service, podshield-scan.timer
    install.sh             # idempotent installer for RHEL 9
    config.toml.example
  demo/
    Containerfile.bad      # deliberately insecure image for demos
    Containerfile.good     # hardened UBI-minimal image for comparison
  README.md

## Hygiene rules (each has id, title, severity, description, evidence, remediation)
Severity levels: critical, high, medium, low, info.
- PS-001 Runs as root (no USER or USER 0/root) — high
- PS-002 Uses :latest tag or untagged/dangling — medium
- PS-003 Secrets in ENV (keys, tokens, passwords by regex and name heuristics) — critical
- PS-004 Secrets found inside image filesystem layers — critical
- PS-005 Image older than configurable threshold (default 90 days) — medium
- PS-006 Base image not from a trusted source (UBI / allowlisted registries) — medium
- PS-007 Excessive image size (configurable, default > 1 GB) — low
- PS-008 Excessive layer count (default > 30) — low
- PS-009 Package manager caches left behind (dnf/yum/apt/apk caches) — low
- PS-010 Setuid/setgid binaries present — medium
- PS-011 No HEALTHCHECK defined — low
- PS-012 Missing OCI labels (maintainer, version, source) — info
- PS-013 Sensitive ports exposed (22, 23, 3389, database ports) — medium
- PS-014 Image unsigned or registry not covered by a signature policy — medium
- PS-015 Shell or package manager present in final image (informational, for minimal images) — info
Runtime rules for running containers:
- PS-R01 --privileged — critical
- PS-R02 SELinux labeling disabled (label=disable) — high
- PS-R03 Host network / PID / IPC namespace — high
- PS-R04 Sensitive host paths mounted (/, /etc, /var/run, podman socket) — critical
- PS-R05 Added dangerous capabilities (SYS_ADMIN, NET_ADMIN, etc.) — high
Rules must be pluggable: each rule is a class registered in a registry, with enable/disable and
severity overrides from config.
To inspect image filesystems, use `podman image mount` (rootful) or `podman unshare` (rootless),
always unmounting in a finally block.

## Scoring
Start at 100. Deduct per finding: critical 25, high 10, medium 4, low 1, info 0. CVEs contribute
the same deductions by severity, capped at 40 points total from CVEs. Floor at 0.
Grades: A >= 90, B >= 80, C >= 70, D >= 60, F < 60. Weights configurable.

## API (all JSON, under /api)
GET  /api/overview                 fleet stats, grade distribution, severity totals, trend
GET  /api/images                   list with grade, score, CVE counts, last scanned
GET  /api/images/{id}              full detail: findings, CVEs, layers, config, history
POST /api/scans                    body {image?: str, all?: bool}; returns scan_id
GET  /api/scans/{id}/stream        Server-Sent Events with live progress
GET  /api/scans                    history
GET  /api/containers               runtime posture of running containers
POST /api/registry/inspect         body {reference: str}; pre-pull audit via skopeo
GET  /api/rules, PATCH /api/rules/{id}   view and toggle rules
GET  /api/reports/{image_id}.html  downloadable standalone HTML report
GET  /api/health                   includes which scanners are available

## UI design (this must look excellent)
Aesthetic: modern security operations console. Dark mode by default with a light mode toggle.
Neutral zinc/slate surfaces, one accent color (emerald for "secure"), generous spacing, rounded-2xl
cards, subtle borders, smooth transitions. Inter font bundled locally.
Grade colors: A emerald, B green, C amber, D orange, F red. Severity colors consistent everywhere.
Layout: collapsible left sidebar (Overview, Images, Containers, Registry Scan, Scan History, Rules,
Settings), top bar with global search, "Scan all" button, and scanner availability indicator.
Pages:
1. Overview: KPI cards (images audited, fleet score, critical findings, CVEs), grade distribution
   bar chart, severity donut, fleet score trend line over time, "Top 5 riskiest images" list.
2. Images: TanStack table with search, filter by grade/severity/registry, sortable columns, row
   click opens detail.
3. Image detail: header with large circular score ring and grade badge, image name, size, age,
   base image. Tabs: Findings (grouped by severity, expandable, each with evidence and a
   copyable Containerfile remediation snippet), CVEs (table with CVE id, package, severity, fixed
   version), Layers (history with size bars), Config (pretty JSON). "Rescan" and "Download report".
4. Containers: cards per running container with runtime findings.
5. Registry Scan: input a remote reference, audit before pulling, show results in the same format.
6. Scan History: timeline of scans with status and duration.
7. Rules: toggle rules on/off and change severity.
Live scans show a progress panel driven by SSE. Use skeleton loaders, empty states with helpful
copy, and toast notifications. Fully responsive.

## Logging and ops
Log to stdout in structured form so journald captures it (systemd services). Never log secret
values; mask detected secrets in findings and the UI (show first 4 chars + ****).

## Phases
Phase 1: Backend skeleton, config, DB models, podman client, image inventory, CLI `podshield scan`
         with rules PS-001 to PS-003, PS-005, PS-011, PS-012. Unit tests.
Phase 2: Remaining hygiene rules including filesystem mount rules, secrets scanning, scoring.
Phase 3: oscap-podman and trivy scanners, trust checks, runtime rules, skopeo registry audit.
Phase 4: FastAPI endpoints, SSE progress, HTML report generation.
Phase 5: Frontend with the full design above, wired to the API.
Phase 6: Podman events watcher, systemd units and timer, install.sh, demo Containerfiles, README
         with RHEL setup, screenshots section, and troubleshooting (SELinux AVCs, socket perms).