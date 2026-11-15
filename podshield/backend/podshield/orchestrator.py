"""Runs scans of one or all images and stores the results."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Collection, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Self, TypeVar

from sqlalchemy import Engine
from sqlmodel import Session, col, select

import podshield.scanners  # noqa: F401  (registers built-in rules)
from podshield.config import Settings
from podshield.db import explain_db_error
from podshield.models import (
    FindingRecord,
    ImageRecord,
    ImageScanRecord,
    ImageSnapshotRecord,
    ScanHeartbeatRecord,
    ScannerRunRecord,
    ScanRecord,
    VulnerabilityRecord,
)
from podshield.podman_client import ImageSource, PodmanError
from podshield.sanitize import sanitize_image
from podshield.scanners.base import (
    ScannerError,
    ScannerImageGone,
    ScannerUnavailable,
    ScannerUnsupported,
)
from podshield.scanners.hygiene import Rule, build_rules, run_rules
from podshield.scanners.oscap import merge_vulnerabilities
from podshield.schemas import FilesystemReport, Finding, ImageInfo, Severity, Vulnerability
from podshield.scoring import Score, compute_score

log = logging.getLogger(__name__)

T = TypeVar("T")

HEARTBEAT_SECONDS = 10.0
# A scan with no heartbeat for this long is considered orphaned (3 missed beats and a margin).
STALE_GRACE_SECONDS = 45.0


@dataclass(frozen=True)
class ProgressEvent:
    scan_id: int
    stage: str  # started | image_started | image_done | image_failed | completed | failed
    # Images finished so far; image_started carries finished + 1 (the one being started).
    # With several images in flight this is a count, not the position in the list.
    current: int = 0
    total: int = 0
    image: str = ""
    message: str = ""


ProgressCallback = Callable[[ProgressEvent], None]
# Takes an image ID, returns what was found in its filesystem (see scanners.mount).
FilesystemScan = Callable[[str], FilesystemReport]
# Takes an image, returns CVEs (see scanners.oscap and scanners.trivy).
CveScan = Callable[[ImageInfo], list[Vulnerability]]


@dataclass
class ScannerOutcome:
    """What happened to one external scanner during one scan."""

    status: str = "ok"  # ok | unavailable | failed; stored as unsupported/partial, see `final`
    detail: str = ""
    succeeded: int = 0  # images this scanner produced a result for
    unsupported: list[str] = field(default_factory=list)  # "image: why" for images it cannot assess

    def final(self) -> tuple[str, str]:
        """(status, detail) to store. Images a scanner cannot assess are never "zero CVEs"."""
        if self.status != "ok" or not self.unsupported:
            return self.status, self.detail
        status = "partial" if self.succeeded else "unsupported"
        return status, "; ".join(self.unsupported)


@dataclass
class ImageResult:
    image: ImageInfo
    findings: list[Finding]
    score: Score
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    # scanner name -> why it produced no CVE data for this image (absent: it ran normally)
    cve_notes: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanSummary:
    scan_id: int
    status: str
    results: list[ImageResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Non-fatal degradations, e.g. a scanner is unavailable. Results are still valid, but
    # rules or CVE data that depend on the missing scanner are absent.
    warnings: list[str] = field(default_factory=list)
    scanners: dict[str, ScannerOutcome] = field(default_factory=dict)


def unique_cve_severities(vulns: Iterable[Vulnerability]) -> list[Severity]:
    """One severity per CVE id (the highest), so multi-package CVEs are not over-counted."""
    worst: dict[str, Severity] = {}
    for v in vulns:
        if v.cve_id not in worst or v.severity.rank > worst[v.cve_id].rank:
            worst[v.cve_id] = v.severity
    return list(worst.values())


class Orchestrator:
    def __init__(
        self,
        source: ImageSource,
        engine: Engine,
        settings: Settings,
        on_progress: ProgressCallback | None = None,
        fs_scanner: FilesystemScan | None = None,
        cve_scanners: Mapping[str, CveScan] | None = None,
    ) -> None:
        self.fs_scanner = fs_scanner
        self.cve_scanners = dict(cve_scanners or {})
        self.source = source
        self.engine = engine
        self.settings = settings
        self.on_progress = on_progress
        # Guards scanner bookkeeping and progress events when images are scanned in parallel.
        self._state_lock = threading.RLock()

    def _emit(self, event: ProgressEvent) -> None:
        if self.on_progress:
            try:
                self.on_progress(event)
            except Exception:
                log.exception("progress callback failed")

    def scan(self, image: str | None = None, scan_all: bool = False) -> ScanSummary:
        """Scan one image reference, or every image when ``scan_all`` is true."""
        scan_id = self.begin(image, scan_all)
        return self.run(scan_id, image, scan_all)

    def begin(self, image: str | None, scan_all: bool, status: str = "running") -> int:
        """Create the scan record and return its ID (lets the API answer before scanning)."""
        if bool(image) == scan_all:
            raise ValueError("specify exactly one of image or scan_all")
        target = "all" if scan_all else str(image)
        with Session(self.engine) as session:
            scan = ScanRecord(target=target, status=status)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id or 0
        touch_heartbeat(self.engine, scan_id)
        return scan_id

    def mark_failed(self, scan_id: int, error: str) -> None:
        """Last-resort failure marking for crashes outside the per-image error handling."""
        try:
            self._finish(scan_id, "failed", 0, error, ScanSummary(scan_id, "failed"))
        finally:
            # Even if the database is what broke (disk full, corrupted), clients must still be
            # told the scan is over, or their progress stream would wait forever.
            self._emit(ProgressEvent(scan_id, "failed", message=error))

    def run(self, scan_id: int, image: str | None, scan_all: bool) -> ScanSummary:
        """Execute a scan previously created with ``begin``."""
        with _Heartbeat(self.engine, scan_id):
            return self._run(scan_id, image, scan_all)

    def _run(self, scan_id: int, image: str | None, scan_all: bool) -> ScanSummary:
        target = "all" if scan_all else str(image)
        with Session(self.engine) as session:
            record = session.get(ScanRecord, scan_id)
            if record is not None and record.status != "running":
                record.status = "running"
                session.add(record)
                session.commit()

        log.info("scan started", extra={"scan_id": scan_id, "target": target})
        self._emit(ProgressEvent(scan_id, "started", message=target))
        summary = ScanSummary(scan_id=scan_id, status="running")

        try:
            images = self.source.list_images() if scan_all else [self.source.get_image(str(image))]
        except PodmanError as exc:
            self._finish(scan_id, "failed", 0, str(exc), summary)
            self._emit(ProgressEvent(scan_id, "failed", message=str(exc)))
            raise

        rules = build_rules(self.settings)
        total = len(images)
        results: list[ImageResult | None] = [None] * total
        finished = 0

        def process(index: int, info: ImageInfo) -> None:
            nonlocal finished
            with self._state_lock:
                self._emit(
                    ProgressEvent(scan_id, "image_started", finished + 1, total, info.display_name)
                )
            try:
                self._attach_filesystem(info, rules, summary)
                vulns, cve_notes = self._collect_vulnerabilities(info, summary)
                result = self._scan_image(scan_id, info, rules, vulns)
                result.cve_notes = cve_notes
            except Exception as exc:
                if isinstance(exc, ScannerImageGone):
                    log.warning(
                        "image removed during scan",
                        extra={"scan_id": scan_id, "image": info.short_id},
                    )
                else:
                    log.exception(
                        "image scan failed", extra={"scan_id": scan_id, "image": info.short_id}
                    )
                reason = explain_db_error(exc, self.engine.url.database or "the database") or str(
                    exc
                )
                with self._state_lock:
                    summary.errors.append(f"{info.display_name}: {reason}")
                    finished += 1
                    self._emit(
                        ProgressEvent(
                            scan_id, "image_failed", finished, total, info.display_name, reason
                        )
                    )
                return
            with self._state_lock:
                results[index] = result
                finished += 1
                self._emit(
                    ProgressEvent(
                        scan_id,
                        "image_done",
                        finished,
                        total,
                        info.display_name,
                        f"{result.score.grade} ({result.score.score})",
                    )
                )

        workers = max(1, min(self.settings.scan.max_concurrent_images, total))
        if workers == 1:
            for index, info in enumerate(images):
                process(index, info)
        else:
            with ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="podshield-image"
            ) as pool:
                for future in [pool.submit(process, i, info) for i, info in enumerate(images)]:
                    future.result()
        summary.results = [r for r in results if r is not None]

        failed_all = total > 0 and not summary.results
        summary.status = "failed" if failed_all else "completed"
        self._finish(
            scan_id,
            summary.status,
            len(summary.results),
            "; ".join(summary.errors) or None,
            summary,
        )
        self._emit(ProgressEvent(scan_id, summary.status, total, total))
        log.info(
            "scan finished",
            extra={"scan_id": scan_id, "status": summary.status, "images": len(summary.results)},
        )
        return summary

    # ------------------------------------------------------------------ scanners

    def _run_scanner(
        self,
        name: str,
        fn: Callable[[], T],
        label: str,
        summary: ScanSummary,
        notes: dict[str, str] | None = None,
    ) -> T | None:
        """Run one scanner call, recording availability. Never raises.

        Once a scanner reports it is unavailable it is not retried for the rest of the scan.
        """
        with self._state_lock:
            outcome = summary.scanners.setdefault(name, ScannerOutcome())
            if outcome.status == "unavailable":
                if notes is not None:
                    notes[name] = f"unavailable ({outcome.detail})"
                return None
        try:
            result = fn()
            with self._state_lock:
                outcome.succeeded += 1
            return result
        except ScannerImageGone:
            raise  # not the scanner's fault: the caller skips this image
        except ScannerUnsupported as exc:
            with self._state_lock:
                outcome.unsupported.append(f"{label}: {exc}")
                summary.warnings.append(f"{label}: {name} cannot assess this image ({exc})")
                if notes is not None:
                    notes[name] = f"unsupported ({exc})"
            log.info(
                "scanner unsupported", extra={"scanner": name, "image": label, "reason": str(exc)}
            )
            return None
        except ScannerUnavailable as exc:
            with self._state_lock:
                outcome.status, outcome.detail = "unavailable", str(exc)
                if notes is not None:
                    notes[name] = f"unavailable ({exc})"
                summary.warnings.append(f"{name} scan unavailable ({exc})")
            log.warning("scanner unavailable", extra={"scanner": name, "error": str(exc)})
        except ScannerError as exc:
            with self._state_lock:
                outcome.status, outcome.detail = "failed", str(exc)
                if notes is not None:
                    notes[name] = f"failed ({exc})"
                summary.warnings.append(f"{label}: {name} scan failed ({exc})")
            log.warning(
                "scanner failed", extra={"scanner": name, "image": label, "error": str(exc)}
            )
        except Exception as exc:
            with self._state_lock:
                outcome.status, outcome.detail = "failed", f"{type(exc).__name__}: {exc}"
                if notes is not None:
                    notes[name] = f"failed ({exc})"
                summary.warnings.append(f"{label}: {name} scan failed ({exc})")
            log.exception("scanner crashed", extra={"scanner": name, "image": label})
        return None

    def _attach_filesystem(self, info: ImageInfo, rules: list[Rule], summary: ScanSummary) -> None:
        """Mount and walk the image if an enabled rule needs it; degrade gracefully."""
        if self.fs_scanner is None or not any(r.needs_filesystem for r in rules):
            return
        report = self._run_scanner(
            "filesystem", partial(self.fs_scanner, info.id), info.display_name, summary
        )
        if report is None:
            return
        info.filesystem = report
        if report.truncated:
            with self._state_lock:
                summary.warnings.append(
                    f"{info.display_name}: filesystem scan hit its limits; results may be incomplete"
                )

    def _collect_vulnerabilities(
        self, info: ImageInfo, summary: ScanSummary
    ) -> tuple[list[Vulnerability], dict[str, str]]:
        collected: list[Vulnerability] = []
        notes: dict[str, str] = {}
        for name, scanner in self.cve_scanners.items():
            result = self._run_scanner(
                name, partial(scanner, info), info.display_name, summary, notes
            )
            collected.extend(result or [])
        return merge_vulnerabilities(collected), notes

    # --------------------------------------------------------------- persistence

    def _scan_image(
        self, scan_id: int, info: ImageInfo, rules: list[Rule], vulns: list[Vulnerability]
    ) -> ImageResult:
        findings = run_rules(info, rules)
        score = compute_score(findings, self.settings.scoring, unique_cve_severities(vulns))
        now = datetime.now(UTC)

        with Session(self.engine) as session:
            record = session.get(ImageRecord, info.id)
            if record is None:
                record = ImageRecord(id=info.id)
            record.repo_tags = info.repo_tags
            record.size = info.size
            record.created = info.created
            record.last_scanned_at = now
            record.last_scan_id = scan_id
            record.score = score.score
            record.grade = score.grade
            session.add(record)
            session.flush()  # image row must exist before findings reference it

            for f in findings:
                session.add(
                    FindingRecord(
                        scan_id=scan_id,
                        image_id=info.id,
                        rule_id=f.rule_id,
                        title=f.title,
                        severity=f.severity.value,
                        description=f.description,
                        evidence=f.evidence,
                        remediation=f.remediation,
                    )
                )
            for v in vulns:
                session.add(
                    VulnerabilityRecord(
                        scan_id=scan_id,
                        image_id=info.id,
                        cve_id=v.cve_id,
                        package=v.package,
                        installed_version=v.installed_version,
                        fixed_version=v.fixed_version,
                        severity=v.severity.value,
                        title=v.title,
                        url=v.url,
                        source=v.source,
                    )
                )
            snapshot = session.get(ImageSnapshotRecord, info.id)
            if snapshot is None:
                snapshot = ImageSnapshotRecord(image_id=info.id, scan_id=scan_id)
            snapshot.scan_id = scan_id
            snapshot.data = sanitize_image(info)
            session.add(snapshot)
            session.add(
                ImageScanRecord(
                    scan_id=scan_id,
                    image_id=info.id,
                    score=score.score,
                    grade=score.grade,
                    finding_count=len(findings),
                    scanned_at=now,
                )
            )
            session.commit()
        return ImageResult(image=info, findings=findings, score=score, vulnerabilities=vulns)

    def _finish(
        self, scan_id: int, status: str, images: int, error: str | None, summary: ScanSummary
    ) -> None:
        with Session(self.engine) as session:
            scan = session.get(ScanRecord, scan_id)
            if scan is None:
                return
            scan.status = status
            scan.finished_at = datetime.now(UTC)
            scan.images_scanned = images
            scan.error = error
            session.add(scan)
            beat = session.get(ScanHeartbeatRecord, scan_id)
            if beat is not None:
                session.delete(beat)
            for name, outcome in summary.scanners.items():
                status, detail = outcome.final()
                session.add(
                    ScannerRunRecord(scan_id=scan_id, scanner=name, status=status, detail=detail)
                )
            session.commit()


# ------------------------------------------------------------------- stored results


@dataclass
class StoredReport:
    image: ImageRecord
    findings: list[FindingRecord]
    vulnerabilities: list[VulnerabilityRecord] = field(default_factory=list)


def latest_reports(engine: Engine, reference: str | None = None) -> list[StoredReport]:
    """Latest stored results per image; optionally filtered by tag or ID prefix."""
    with Session(engine) as session:
        images = list(session.exec(select(ImageRecord).order_by(col(ImageRecord.score))))
        reports: list[StoredReport] = []
        for img in images:
            if img.last_scan_id is None:
                continue
            if reference and not (
                img.id.removeprefix("sha256:").startswith(reference.removeprefix("sha256:"))
                or any(reference == t or reference == t.split(":")[0] for t in img.repo_tags)
            ):
                continue
            findings = list(
                session.exec(
                    select(FindingRecord).where(
                        FindingRecord.image_id == img.id,
                        FindingRecord.scan_id == img.last_scan_id,
                    )
                )
            )
            findings.sort(key=lambda f: f.rule_id)
            vulns = list(
                session.exec(
                    select(VulnerabilityRecord).where(
                        VulnerabilityRecord.image_id == img.id,
                        VulnerabilityRecord.scan_id == img.last_scan_id,
                    )
                )
            )
            reports.append(StoredReport(image=img, findings=findings, vulnerabilities=vulns))
        return reports


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)  # SQLite drops tzinfo


def touch_heartbeat(engine: Engine, scan_id: int) -> None:
    """Record that the process owning this scan is alive (best effort)."""
    try:
        with Session(engine) as session:
            beat = session.get(ScanHeartbeatRecord, scan_id)
            if beat is None:
                beat = ScanHeartbeatRecord(scan_id=scan_id)
            beat.updated_at = datetime.now(UTC)
            session.add(beat)
            session.commit()
    except Exception:
        log.warning("could not write scan heartbeat", extra={"scan_id": scan_id}, exc_info=True)


class _Heartbeat:
    """Touches the scan's heartbeat from a side thread while the scan runs.

    A single image can take many minutes inside oscap or trivy without any progress event,
    so beating on events alone would make a healthy scan look dead.
    """

    def __init__(self, engine: Engine, scan_id: int, interval: float = HEARTBEAT_SECONDS) -> None:
        self._engine, self._scan_id, self._interval = engine, scan_id, interval
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop, name=f"scan-heartbeat-{scan_id}", daemon=True
        )

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            touch_heartbeat(self._engine, self._scan_id)

    def __enter__(self) -> Self:
        touch_heartbeat(self._engine, self._scan_id)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def fail_stale_scans(
    engine: Engine,
    grace_seconds: float = STALE_GRACE_SECONDS,
    exclude: Collection[int] = (),
) -> int:
    """Fail 'running'/'queued' scans whose owning process stopped heartbeating.

    Scans are also started by the CLI, the timer and the watcher, so a scan that is merely
    "running" may belong to a live process. Only scans with no heartbeat for
    ``grace_seconds`` (or, for scans that never beat, started that long ago) are failed.
    ``exclude`` lists scans the caller knows are alive (e.g. waiting in its own queue).
    """
    now = datetime.now(UTC)
    failed = 0
    with Session(engine) as session:
        candidates = list(
            session.exec(
                select(ScanRecord).where(col(ScanRecord.status).in_(["running", "queued"]))
            )
        )
        for scan in candidates:
            if scan.id in exclude:
                continue
            beat = session.get(ScanHeartbeatRecord, scan.id) if scan.id else None
            last_alive = _aware(beat.updated_at if beat else scan.started_at)
            if (now - last_alive).total_seconds() < grace_seconds:
                continue
            scan.status = "failed"
            scan.finished_at = now
            scan.error = "interrupted (the process running this scan stopped before it finished)"
            session.add(scan)
            if beat is not None:
                session.delete(beat)
            failed += 1
        session.commit()
    return failed


def scanner_runs(engine: Engine, scan_id: int) -> list[ScannerRunRecord]:
    with Session(engine) as session:
        return list(
            session.exec(select(ScannerRunRecord).where(ScannerRunRecord.scan_id == scan_id))
        )
