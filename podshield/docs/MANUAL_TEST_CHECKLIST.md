# PodShield – Manual Test Checklist (RHEL 9)

Everything in this list needs a real RHEL 9 host with Podman, which the automated
suite could not use during development. Run it top to bottom after installation.
Mark each item **Pass / Fail / N/A** and note the date and tester at the bottom.

Placeholder: `rhel-vm` is the VM's host name. The dashboard listens on `127.0.0.1:8080`; install paths are `/opt/podshield`, `/etc/podshield`, `/var/lib/podshield`.

## 0. Preconditions

| # | Check | Command | Expected | Result |
|---|-------|---------|----------|--------|
| 0.1 | RHEL 9.x | `cat /etc/redhat-release` | Red Hat Enterprise Linux release 9.x | |
| 0.2 | SELinux enforcing | `getenforce` | `Enforcing` (never switch it off to make a test pass) | |
| 0.3 | firewalld running | `systemctl is-active firewalld` | `active` | |
| 0.4 | Podman present | `podman --version` | 4.x or newer | |
| 0.5 | Python 3.11+ | `python3 --version` | 3.11 or newer | |
| 0.6 | Scanners (optional) | `oscap --version; trivy --version` | present, or PodShield reports them as unavailable (not as an error) | |

## 1. Installation (`deploy/install.sh`)

| # | Check | Expected | Result |
|---|-------|----------|--------|
| 1.0 | `./deploy/install.sh --dry-run` (no root needed) | Prints every command; changes nothing | |
| 1.1 | Run `sudo ./deploy/install.sh` | Finishes without error; prints the dashboard URL (`http://127.0.0.1:8080`) | |
| 1.2 | Re-run the installer | Idempotent: no errors, no duplicated units or config; an existing `/etc/podshield/config.toml` is kept | |
| 1.3 | `systemctl status podshield-api podshield-watch podshield-scan.timer` | API and watcher `active (running)`; timer enabled (unless `--no-watch` / `--no-timer` was used) | |
| 1.4 | `ls -lZ /var/lib/podshield /etc/podshield` | Config is `0640` root; no `unlabeled_t` | |
| 1.5 | `sudo ausearch -m avc -ts recent` | No new AVC denials for PodShield | |
| 1.6 | `firewall-cmd --list-ports` | Installer opened **no** port. The dashboard listens on localhost only | |
| 1.7 | Reboot the VM | Service comes back on its own | |
| 1.8 | `getenforce` after installation | Still `Enforcing` | |

## 2. Functional – real images

Pull a small mix first: `podman pull ubi9/ubi-minimal`, `alpine:3.20`, `docker.io/library/nginx:latest`, and one old image (for example `centos:7`).

| # | Check | Expected | Result |
|---|-------|----------|--------|
| 2.1 | Open the UI at `http://127.0.0.1:8080` (on the VM, or through an SSH tunnel) | Overview loads; no console errors | |
| 2.2 | Health indicator | Podman = ok; each scanner reported honestly (ok / unavailable) | |
| 2.3 | **Scan all** | Live progress; every image reaches a terminal state; no spinner left running | |
| 2.4 | UBI image | Trusted base recognised; high grade | |
| 2.5 | Alpine image | OS-release found; CVE scan marked *unsupported/partial* for oscap, not a failure | |
| 2.6 | Old image (`centos:7`) | End-of-life finding; low grade | |
| 2.7 | Image detail | Findings grouped by severity; remediation text present; layers view renders | |
| 2.8 | Containers page | Running containers listed; a privileged container (`podman run -d --privileged --name pstest-priv alpine sleep 600`) is flagged | |
| 2.9 | Registry audit | `podman pull` source with an HTTP registry flagged; hostile text in the reference is rejected | |
| 2.10 | Override a rule in Settings/Rules | Grade changes; override survives a page reload and a service restart | |
| 2.11 | Report download | One self-contained HTML file, opens offline, no external requests | |
| 2.12 | History page | New scan shows trend vs the previous one | |

Clean up: `podman rm -f pstest-priv`.

## 3. Secrets handling

| # | Check | Expected | Result |
|---|-------|----------|--------|
| 3.1 | Build an image containing a **fake** key, for example `RUN echo AKIAIOSFODNN7EXAMPLE > /root/.pstest-key` (name the image `pstest-secret`) | | |
| 3.2 | Scan it | Secret finding appears; value shown masked (`AKIA****`) | |
| 3.3 | `curl -s http://127.0.0.1:8080/api/images/<id>` | Full value appears nowhere | |
| 3.4 | `sudo journalctl -u podshield-api \| grep AKIAIOSFODNN7EXAMPLE` | No match | |
| 3.5 | `sqlite3 /var/lib/podshield/podshield.db .dump \| grep AKIAIOSFODNN7EXAMPLE` | No match | |

## 4. Failure behaviour (on the VM)

| # | Action | Expected | Result |
|---|--------|----------|--------|
| 4.1 | `sudo systemctl stop podman.socket` (and `podman.service`) during a scan | UI shows a "connection lost / Podman unreachable" banner; scan ends as *failed* with a clear message; service stays up | |
| 4.2 | `sudo systemctl start podman.socket` | Next scan works without restarting PodShield | |
| 4.3 | `podman rmi` an image while a scan is running | That image is reported failed; the other images finish | |
| 4.4 | Fill the DB volume (use a small loop-mounted filesystem for `/var/lib/podshield`) | API returns 503 with a *disk full* message that names the path; no stack trace; no SQL in the message | |
| 4.5 | Corrupt the DB copy (`dd if=/dev/urandom of=podshield.db bs=1k count=4 conv=notrunc`) on a **test copy** | Startup stops with recovery instructions; the file is not silently replaced | |
| 4.6 | Wrong SELinux label on the DB (`chcon -t tmp_t`) | Read-only error that suggests `restorecon -Rv`; SELinux stays enforcing | |
| 4.7 | Kill the service during a scan (`kill -9`) | After restart the stale scan is marked failed; a new scan can be started | |
| 4.8 | Remove oscap/trivy from `PATH` | Scan completes; those scanners listed as unavailable | |

## 5. Performance (run on the VM, 20 real images)

```bash
cd <repo>/backend        # a checkout of the repository with the dev extras installed
sudo env "PATH=$PATH" PYTHONPATH=. .venv/bin/python -m tests.perf.perf_scan --real --limit 20 --concurrency 4 --out /tmp/perf_c4.json
sudo env "PATH=$PATH" PYTHONPATH=. .venv/bin/python -m tests.perf.perf_scan --real --limit 20 --concurrency 1 --out /tmp/perf_c1.json
```

| # | Check | Expected | Result |
|---|-------|----------|--------|
| 5.1 | Command exits with 0 | No image slower than 60 s (`slow_images` empty) | |
| 5.2 | Compare concurrency 4 with 1 | 4 is faster, or equal if the host is I/O bound | |
| 5.3 | Peak memory | Reasonable for the VM (record the number) | |
| 5.4 | UI stays responsive while scanning | Pages load in under a second | |

## 6. Security

| # | Check | Expected | Result |
|---|-------|----------|--------|
| 6.1 | Listening address | `ss -ltnp \| grep 8080` shows `127.0.0.1:8080`, not `0.0.0.0` (there is no login, so it must not be exposed) | |
| 6.2 | `curl -i "http://127.0.0.1:8080/api/images?q=%27%3B%20rm%20-rf%20/"` | Rejected (4xx) or treated as plain search text; nothing executed, no 500 | |
| 6.3 | Config file permissions | `/etc/podshield/config.toml` not world-writable | |
| 6.4 | No leftover mounts | After scans: `findmnt \| grep podshield` is empty and `podman images` has no `pstest-` leftovers | |
| 6.5 | `make security` | bandit: no findings; npm audit: no high/critical | |

## 7. Browser and device checks

| # | Check | Expected | Result |
|---|-------|----------|--------|
| 7.1 | Chrome, Firefox and Edge (current versions) | All pages render; no layout breakage | |
| 7.2 | Phone-width window (375 px) | No horizontal scroll; the scan button has a label | |
| 7.3 | Dark and light theme | Both readable; choice persists after reload | |
| 7.4 | Keyboard only | Every control reachable with Tab; focus visible | |
| 7.5 | Automated UI suite against the VM | With the tunnel up: `make test-e2e BASE_URL=http://localhost:8080` passes (chaos-dependent tests skip themselves) | |

The dashboard is bound to localhost on purpose, so from your laptop open a tunnel first:
`ssh -L 8080:127.0.0.1:8080 user@rhel-vm`, then browse to `http://localhost:8080`.

## 8. Automated tests on the VM

```bash
make test-unit
make test-api
sudo env "PATH=$PATH" make test-integration     # the 53 tests that could not run during development
make test-frontend
```

Record how many integration tests pass, skip (with reasons) and fail. Any failure
is a real finding: report it, do not edit the test to make it pass.

## Sign-off

| Tester | Date | RHEL / Podman versions | Overall result |
|--------|------|------------------------|----------------|
| | | | |
