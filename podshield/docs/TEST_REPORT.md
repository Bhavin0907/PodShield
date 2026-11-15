# PodShield – Test Report

Scope: testing and validation carried out **before** integration on RHEL 9.
Status: **ready for RHEL integration testing**, with the limitations in section 8.

## 1. Summary

| Area | Result |
|------|--------|
| Backend (unit, API, robustness) | **965 passed, 7 skipped, 0 failed** |
| Backend integration (needs Podman) | **53 written, 53 skipped here – not run** |
| Frontend (Vitest) | **117 passed** |
| End-to-end (Playwright, Chromium) | **33 passed** |
| Backend line coverage | **97 %** (3271 statements, 104 missed) |
| Frontend coverage | 87.4 % statements, 81 % branches, 83.6 % functions, 88.4 % lines |
| Static checks | `ruff check`, `ruff format --check`, `mypy --strict` (33 files): clean. `bandit`: 0 findings. `npm audit`: 0 vulnerabilities |
| Performance (20 images, synthetic) | 14.0 s total at concurrency 4; nothing near the 60 s per-image limit |

**Important:** the 53 integration tests were written against real Podman but have
never been executed, because no RHEL VM or Podman was available. They are not
counted as passed anywhere in this report. Section 8 and
[MANUAL_TEST_CHECKLIST.md](MANUAL_TEST_CHECKLIST.md) describe how to run them.

## 2. Environment used

| Item | Value |
|------|-------|
| OS | Windows (10.0.26200); no RHEL, no Podman, no SELinux, no firewalld |
| CPU | 20 logical CPUs |
| Python | 3.11.7 (venv), pytest, pytest-cov, mypy, ruff, bandit, psutil |
| Node | 22.20.0; Vite 7, Vitest 5.1, Playwright (Chromium), MSW 2.15, Testing Library |
| Podman | Simulated by `FakeSource` (unit/API) and by a demo server (`tests/e2e_server.py`) for E2E |
| Scanners | oscap and trivy not installed; their output is simulated from recorded fixtures |

## 3. Results per phase

| Phase | Focus | Tests | Outcome |
|-------|-------|-------|---------|
| T1 | Unit tests: config, scoring, rule matrix, secrets, scanners, Podman client, edge cases, pytest markers | 404 | all pass (one POSIX-only test skipped on Windows) |
| T2 | Test images/fixtures, "cannot assess" (unsupported) handling | 48 runnable + 53 integration | 48 pass; **integration not run** |
| T3 | API: every route, validation, hostile input, SSE ordering/resume, report, health, secret leakage | 99 | all pass |
| T4 | Frontend component, page, visual-contract and accessibility tests; Playwright E2E at desktop and mobile widths, light and dark theme | 117 Vitest + 33 Playwright | all pass |
| T5 | Robustness, concurrency, security audits, performance | 52 + perf harness | all pass |
| Earlier phases | Tests written while building phases 1–6 | 369 | all pass |
| **Backend total** | | **972 collected** (965 passed, 7 skipped) | |

The 7 skipped tests are platform limits of the Windows development machine
(`needs bash` ×2, `needs POSIX modes/symlinks` ×4, `geteuid is POSIX only` ×1).
They are expected to run on RHEL.

Make targets: `test-unit`, `test-api`, `test-integration`, `test-frontend`,
`test-e2e`, `test-all`, `coverage`, `coverage-frontend`, `typecheck`, `security`, `perf`.

## 4. Coverage

Backend, by module (unit + API + robustness, integration excluded):

| Module | Coverage | Module | Coverage |
|--------|----------|--------|----------|
| `api.py` | 90 % | `scanners/hygiene.py` | 100 % |
| `cli.py` | 94 % | `scanners/filesystem.py` | 94 % |
| `db.py` | 83 % | `scanners/mount.py` | 95 % |
| `orchestrator.py` | 98 % | `scanners/oscap.py` | 97 % |
| `scan_manager.py` | 87 % | `scanners/status.py` | 89 % |
| `podman_client.py` | 98 % | `factory.py` | 86 % |
| **Total** | **97 %** | | |

The weakest modules are `db.py` (the error paths for a disk-level fault that cannot
be forced portably), `factory.py` and `status.py` (they probe the real host), and
`scan_manager.py` (thread timing). `mount.py` is 95 % from unit tests, but its real
behaviour (mounting an image) is only exercised by the integration tests.

Frontend coverage fell from 94 % to 87.4 % after upgrading Vitest 2 to 5, because the
v8 provider counts code differently. No tests were removed. The per-file gaps were not analysed further.

## 5. Bugs found and fixed

All of these were fixed in the application, not by changing tests.

| # | Phase | Bug | Impact | Fix |
|---|-------|-----|--------|-----|
| 1 | T2 | Images that the scanners cannot assess (for example no recognisable OS release) were not distinguished from normal results | Misleading results | New `unsupported` / `partial` states via `ScannerUnsupported`, shown in the UI |
| 2 | T3 | SSE reconnect with `Last-Event-ID` hung when the id was past the end of the buffer | Hung stream in the browser | Resume logic rewritten; falls back to the stored scan record |
| 3 | T3 | A negative or non-numeric `Last-Event-ID` produced a negative event id or an error | Broken stream | Input validated; invalid values restart from the beginning |
| 4 | T3 | `assert` used for control flow in `patch_rule` | Disappears under `python -O`; 500 instead of 404 | Replaced by an explicit 404 |
| 5 | T4 | The **Scan all** button had no accessible name on narrow screens (icon only) | Screen readers cannot use it | `aria-label` added ("Scan all images" / "Scanning") |
| 6 | T4 | Settings page overflowed horizontally at 375 px (long config path) | Page scrolled sideways on phones | Single-column grid, `minmax(0,1fr)`, `break-all` on the path |
| 7 | T5 | An image removed during a scan disabled the filesystem scanner for the rest of the scan | All later images silently lost their filesystem checks | New `ScannerImageGone`: only that image is reported failed |
| 8 | T5 | A broken database left the SSE stream hanging and the scan "running" forever | UI spinner never ends | `mark_failed` always emits the terminal event (try/finally) |
| 9 | T5 | Database errors exposed raw SQL text in responses | Information leak, unhelpful | `explain_db_error` maps errors to actionable text (disk full, read-only with `restorecon` advice, locked, corrupt) |
| 10 | T5 | A corrupted database file caused a Python traceback at startup | Unusable message | `init_db` runs `PRAGMA quick_check`; startup and CLI exit with recovery steps; API returns 503 |
| 11 | T5 | (Found while adding parallel scanning) progress `current` assumed images finish in order | Wrong progress bar under concurrency | It now counts finished images |
| 12 | T5 | 3 critical, 1 high and 8 moderate npm vulnerabilities (old Vite/Vitest chain) | Supply-chain risk | Upgraded to Vite 7 / Vitest 5; `npm audit` reports 0 |
| 13 | T5 | `bandit` flagged the ElementTree import in `oscap.py` | False positive (types only; parsing uses `defusedxml`) | Narrow `# nosec B405`; B404/B603 skipped project-wide with a documented reason |

New capability added during T5: bounded parallel scanning (`[scan] max_concurrent_images`,
default 4, range 1–32).

### Test changes (and why)

| Change | Reason |
|--------|--------|
| Findings heading assertion changed to the exact text `Critical(1)` | The test expected a space; the UI was right |
| `/light/i` button query changed to `/^light$/i` | The old regex matched two buttons |
| SSE order test now sets `max_concurrent_images = 1`, plus a new parallel-invariants test | Strict image order only holds sequentially; parallel runs are checked for what must always hold (ids, terminal event last, counts) |
| Parallel tests use file-based SQLite | In-memory SQLite with a shared connection is not safe for threads |
| Disk-full: scan-level test uses a real `SQLITE_FULL` (`max_page_count`); request-level test injects the fault at the DB-API boundary | A tiny row can still fit into an existing page, so a real failure is not deterministic for a single request |
| AST audit reads sources as `utf-8-sig` | Some source files start with a BOM |
| Playwright config uses `fileURLToPath(import.meta.url)` | The package is ESM; `__dirname` does not exist |
| Ruff clean-up of tests (formatting, `next(...)`, tuple `startswith`) | Style only; no assertion was weakened |

No assertion was weakened or removed to make a test pass.

## 6. Performance

Command: `python -m tests.perf.perf_scan --images 20 --concurrency N`.
Raw output: [`perf/`](perf/). **These are synthetic figures** measured on a Windows
workstation: each of the 20 images is a generated tree of 5 × 3000 files of 4 KiB
plus planted secrets. Real timings need the VM.

| Run | Concurrency | Total | Avg per image* | Max per image* | Throughput | Peak memory |
|-----|------------|-------|----------------|----------------|------------|-------------|
| Real filesystem walk | 1 | 30.55 s | 1.53 s | 2.81 s | 0.65 img/s | 60.8 MB |
| Real filesystem walk | 4 | **14.00 s** | 2.73 s | 4.11 s | 1.43 img/s | 60.8 MB |
| + simulated 2 s external tool (stands in for oscap/trivy) | 1 | 61.62 s | 3.08 s | 4.27 s | 0.32 img/s | 60.5 MB |
| + simulated 2 s external tool | 4 | **23.11 s** | 4.57 s | 5.31 s | 0.87 img/s | 61.1 MB |

\* Wall-clock time for one image. It rises with concurrency because images share the
CPU and disk, but the whole run gets 2.2× (no tool) to 2.7× (with tool) faster.

- **No image took longer than 60 s** (`slow_images` is empty in every run).
- Memory stays flat (about 61 MB) regardless of concurrency.
- The filesystem walk is Python code and limited by the GIL; most of the gain
  on a real host should come from overlapping the oscap and trivy subprocesses.
  This must be confirmed on the VM: `make perf PERF_ARGS="--real --limit 20 --concurrency 4"`.

## 7. Robustness and security checks

| Check | Result |
|-------|--------|
| Podman socket lost mid-scan (sudden exception, each error type) | Scan ends *failed* with a clear message; the UI shows the connection banner; the next scan works |
| Image deleted during a scan | Only that image fails; the rest complete; scanner stays enabled |
| Disk full (real `SQLITE_FULL`) | Scan fails cleanly; API returns 503 with an actionable message, no SQL |
| Corrupted database | Detected at startup with recovery instructions; never silently replaced |
| Bounded concurrency | Verified that peak in-flight images equal 1, 2 or 4 for those settings; default is 4; result order is stable |
| Hostile input (shell metacharacters, option injection, path traversal, SQL, CRLF, NUL) on every route | Rejected or inert; no process started |
| Secrets | Full values appear in no API response, database row, log line or error body; masked as first 4 characters + `****` |
| Source audit (AST) | No `shell=True`, no `os.system`/`eval`/`exec`, every `subprocess.run` has a list argument and a timeout, no `Popen` |
| Report HTML | One self-contained file, no external references, XSS-safe |
| Dependencies | `npm audit`: 0 vulnerabilities. `bandit`: 0 findings |
| Test data | Fake secrets only (for example AWS's documented `AKIAIOSFODNN7EXAMPLE`); resources prefixed `pstest-`; tests clean up after themselves |

## 8. Limitations and open items

1. **Integration tests not run.** 53 tests need Linux, Podman and (some) root. Run
   `sudo env "PATH=$PATH" make test-integration` on the VM and record the results.
2. **No real Podman, SELinux or firewalld in the test environment.** SELinux
   enforcement, AVC denials and file labels are only covered by the manual checklist.
3. **oscap and trivy were simulated.** Their parsers are tested against recorded
   output; real tool behaviour and real scan times are unverified.
4. **Performance numbers are synthetic** and from Windows, not RHEL.
5. **Deleted images stay in the inventory.** PodShield does not prune images that
   disappear from Podman.
6. **No reports directory on disk.** Reports are generated on demand from the
   database, so "reports directory full" maps to the database-full case above.
7. **A timeout on one mount** still makes the filesystem scanner unavailable for the
   rest of that scan (a deliberate trade-off to avoid piling up hung mounts).
8. **The dashboard has no login** and listens on `127.0.0.1` only. Use an SSH
   tunnel for remote access; do not expose it.
9. **Demo-server health.** The E2E demo server reports scanners honestly as simulated;
   a pass there says nothing about real scanner availability.
10. **Frontend coverage** reads lower under Vitest 5 than under Vitest 2 (see section 4).
11. **Browsers:** E2E ran on Chromium only. Firefox/WebKit are in the manual checklist.
12. **Windows-only skips:** 7 backend tests skip on Windows and should run on RHEL.

## 9. Screenshots

Captured by `e2e/screenshots.spec.ts` from the demo server (fake data, no real
host information).

| Page | Desktop light | Desktop dark | Mobile light | Mobile dark |
|------|---------------|--------------|--------------|-------------|
| Overview | [view](screenshots/light-desktop-overview.png) | [view](screenshots/dark-desktop-overview.png) | [view](screenshots/light-mobile-overview.png) | [view](screenshots/dark-mobile-overview.png) |
| Images | [view](screenshots/light-desktop-images.png) | [view](screenshots/dark-desktop-images.png) | [view](screenshots/light-mobile-images.png) | [view](screenshots/dark-mobile-images.png) |
| Image detail | [view](screenshots/light-desktop-image-detail.png) | [view](screenshots/dark-desktop-image-detail.png) | [view](screenshots/light-mobile-image-detail.png) | [view](screenshots/dark-mobile-image-detail.png) |
| Containers | [view](screenshots/light-desktop-containers.png) | [view](screenshots/dark-desktop-containers.png) | [view](screenshots/light-mobile-containers.png) | [view](screenshots/dark-mobile-containers.png) |
| Registry | [view](screenshots/light-desktop-registry.png) | [view](screenshots/dark-desktop-registry.png) | [view](screenshots/light-mobile-registry.png) | [view](screenshots/dark-mobile-registry.png) |
| History | [view](screenshots/light-desktop-history.png) | [view](screenshots/dark-desktop-history.png) | [view](screenshots/light-mobile-history.png) | [view](screenshots/dark-mobile-history.png) |
| Rules | [view](screenshots/light-desktop-rules.png) | [view](screenshots/dark-desktop-rules.png) | [view](screenshots/light-mobile-rules.png) | [view](screenshots/dark-mobile-rules.png) |
| Settings | [view](screenshots/light-desktop-settings.png) | [view](screenshots/dark-desktop-settings.png) | [view](screenshots/light-mobile-settings.png) | [view](screenshots/dark-mobile-settings.png) |

## 10. How to reproduce

```bash
make test-unit && make test-api          # backend, no Podman needed
make test-frontend                       # Vitest
make test-e2e                            # Playwright against the demo server
make test-e2e BASE_URL=http://localhost:8000   # against a real install (via SSH tunnel)
make coverage coverage-frontend          # coverage reports
make typecheck security                  # mypy, bandit, npm audit
make perf                                # synthetic 20-image benchmark
sudo env "PATH=$PATH" make test-integration    # on the RHEL VM only
```
