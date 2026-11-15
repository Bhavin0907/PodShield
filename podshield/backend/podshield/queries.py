"""Read-side queries that shape stored scan data for the API and HTML reports."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlmodel import Session, col, select

from podshield.api_models import (
    SEVERITIES,
    FindingOut,
    HistoryPoint,
    ImageDetail,
    ImageSummary,
    LayerOut,
    Overview,
    ScanDetail,
    ScannerRunOut,
    ScanOut,
    TrendPoint,
    VulnerabilityOut,
)
from podshield.config import Settings
from podshield.models import (
    FindingRecord,
    ImageRecord,
    ImageScanRecord,
    ImageSnapshotRecord,
    ScannerRunRecord,
    ScanRecord,
    VulnerabilityRecord,
)
from podshield.scanners.trust import split_reference
from podshield.schemas import Severity
from podshield.scoring import grade_for

GRADE_KEYS = ["A", "B", "C", "D", "F"]
_RANK = {s.value: s.rank for s in Severity}


class AmbiguousReferenceError(Exception):
    """An image ID prefix matched more than one image."""


def aware(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; everything we store is UTC, so put it back for API output."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def empty_counts() -> dict[str, int]:
    return {s: 0 for s in SEVERITIES}


# ------------------------------------------------------------------------ lookups


def resolve_image(session: Session, reference: str) -> ImageRecord | None:
    """Find an image by full ID, unique ID prefix (>= 4 chars), or exact repo tag."""
    ref = reference.removeprefix("sha256:")
    exact = session.get(ImageRecord, reference) or session.get(ImageRecord, ref)
    if exact is not None:
        return exact
    images = list(session.exec(select(ImageRecord)))
    for img in images:
        if reference in img.repo_tags:
            return img
    if len(ref) >= 4:
        matches = [i for i in images if i.id.removeprefix("sha256:").startswith(ref)]
        if len(matches) > 1:
            raise AmbiguousReferenceError(f"{reference!r} matches {len(matches)} images")
        if matches:
            return matches[0]
    return None


# ---------------------------------------------------------------------- aggregates


def finding_counts(session: Session) -> dict[str, dict[str, int]]:
    """Severity counts of each image's latest findings."""
    rows = session.exec(
        select(FindingRecord.image_id, FindingRecord.severity)
        .join(ImageRecord, col(ImageRecord.id) == col(FindingRecord.image_id))
        .where(col(FindingRecord.scan_id) == col(ImageRecord.last_scan_id))
    )
    out: dict[str, dict[str, int]] = defaultdict(empty_counts)
    for image_id, severity in rows:
        out[image_id][severity] += 1
    return out


def cve_counts(session: Session) -> dict[str, dict[str, int]]:
    """Unique-CVE counts per image by severity (a CVE counts once, at its worst severity)."""
    rows = session.exec(
        select(
            VulnerabilityRecord.image_id, VulnerabilityRecord.cve_id, VulnerabilityRecord.severity
        )
        .join(ImageRecord, col(ImageRecord.id) == col(VulnerabilityRecord.image_id))
        .where(col(VulnerabilityRecord.scan_id) == col(ImageRecord.last_scan_id))
    )
    worst: dict[tuple[str, str], str] = {}
    for image_id, cve_id, severity in rows:
        key = (image_id, cve_id)
        if key not in worst or _RANK[severity] > _RANK[worst[key]]:
            worst[key] = severity
    out: dict[str, dict[str, int]] = defaultdict(empty_counts)
    for (image_id, _cve), severity in worst.items():
        out[image_id][severity] += 1
    return out


def _summary(
    rec: ImageRecord, fcounts: dict[str, int] | None, ccounts: dict[str, int] | None
) -> ImageSummary:
    created = aware(rec.created)
    fc = fcounts or empty_counts()
    cc = ccounts or empty_counts()
    return ImageSummary(
        id=rec.id,
        short_id=rec.id.removeprefix("sha256:")[:12],
        name=rec.repo_tags[0] if rec.repo_tags else rec.id.removeprefix("sha256:")[:12],
        repo_tags=rec.repo_tags,
        registry=split_reference(rec.repo_tags[0])[0] if rec.repo_tags else "-",
        size=rec.size,
        created=created,
        age_days=(datetime.now(UTC) - created).days if created and created.year > 1 else None,
        score=rec.score,
        grade=rec.grade,
        last_scanned_at=aware(rec.last_scanned_at),
        finding_counts=dict(fc),
        cve_counts=dict(cc),
        cve_total=sum(cc.values()),
    )


def list_images(
    session: Session, q: str | None = None, grade: str | None = None
) -> list[ImageSummary]:
    fcounts, ccounts = finding_counts(session), cve_counts(session)
    out: list[ImageSummary] = []
    for rec in session.exec(select(ImageRecord)):
        if rec.last_scan_id is None:
            continue
        if grade and rec.grade != grade.upper():
            continue
        if q and not (
            q.lower() in rec.id.lower() or any(q.lower() in t.lower() for t in rec.repo_tags)
        ):
            continue
        out.append(_summary(rec, fcounts.get(rec.id), ccounts.get(rec.id)))
    return sorted(out, key=lambda s: (s.score if s.score is not None else 101, s.name))


# ------------------------------------------------------------------------ detail


def _finding_out(f: FindingRecord) -> FindingOut:
    return FindingOut(
        rule_id=f.rule_id,
        title=f.title,
        severity=Severity(f.severity),
        description=f.description,
        evidence=f.evidence,
        remediation=f.remediation,
    )


def _vuln_out(v: VulnerabilityRecord) -> VulnerabilityOut:
    return VulnerabilityOut(
        cve_id=v.cve_id,
        package=v.package,
        severity=Severity(v.severity),
        installed_version=v.installed_version,
        fixed_version=v.fixed_version,
        title=v.title,
        url=v.url,
        source=v.source,
    )


def layers_from_snapshot(data: dict[str, Any]) -> list[LayerOut]:
    out: list[LayerOut] = []
    for layer in data.get("layers", []):
        created = layer.get("created")
        out.append(
            LayerOut(
                created_by=layer.get("created_by", ""),
                created=aware(datetime.fromisoformat(created)) if created else None,
                size=layer.get("size", 0),
                empty=layer.get("empty", False),
                comment=layer.get("comment", ""),
            )
        )
    return out


def image_detail(session: Session, rec: ImageRecord) -> ImageDetail:
    scan_id = rec.last_scan_id
    findings = list(
        session.exec(
            select(FindingRecord).where(
                FindingRecord.image_id == rec.id, FindingRecord.scan_id == scan_id
            )
        )
    )
    findings.sort(key=lambda f: (-_RANK[f.severity], f.rule_id))
    vulns = list(
        session.exec(
            select(VulnerabilityRecord).where(
                VulnerabilityRecord.image_id == rec.id, VulnerabilityRecord.scan_id == scan_id
            )
        )
    )
    vulns.sort(key=lambda v: (-_RANK[v.severity], v.cve_id, v.package))
    snapshot = session.get(ImageSnapshotRecord, rec.id)
    history = session.exec(
        select(ImageScanRecord)
        .where(ImageScanRecord.image_id == rec.id)
        .order_by(col(ImageScanRecord.scanned_at), col(ImageScanRecord.id))
    )
    runs = session.exec(select(ScannerRunRecord).where(ScannerRunRecord.scan_id == scan_id))

    fc = empty_counts()
    for f in findings:
        fc[f.severity] += 1
    cc = cve_counts(session).get(rec.id)
    base = _summary(rec, fc, cc)
    data = snapshot.data if snapshot else {}
    config = {k: v for k, v in data.items() if k not in ("layers", "base_image")} or None

    return ImageDetail(
        **base.model_dump(),
        base_image=data.get("base_image"),
        last_scan_id=scan_id,
        findings=[_finding_out(f) for f in findings],
        vulnerabilities=[_vuln_out(v) for v in vulns],
        layers=layers_from_snapshot(data),
        config=config,
        history=[
            HistoryPoint(
                scan_id=h.scan_id,
                scanned_at=aware(h.scanned_at) or h.scanned_at,
                score=h.score,
                grade=h.grade,
                finding_count=h.finding_count,
            )
            for h in history
        ],
        scanners=[ScannerRunOut(scanner=r.scanner, status=r.status, detail=r.detail) for r in runs],
    )


# ----------------------------------------------------------------------- overview


def fleet_trend(session: Session, limit: int = 60) -> list[TrendPoint]:
    """Fleet score after each scan: mean of every image's latest score as of that scan."""
    latest: dict[str, int] = {}
    points: list[TrendPoint] = []
    current_scan: int | None = None
    current_at: datetime | None = None
    rows = session.exec(
        select(ImageScanRecord).order_by(col(ImageScanRecord.scanned_at), col(ImageScanRecord.id))
    )

    def flush() -> None:
        if current_scan is not None and current_at is not None and latest:
            points.append(
                TrendPoint(
                    scan_id=current_scan,
                    at=aware(current_at) or current_at,
                    score=round(sum(latest.values()) / len(latest), 1),
                )
            )

    for row in rows:
        if row.scan_id != current_scan:
            flush()
            current_scan, current_at = row.scan_id, row.scanned_at
        latest[row.image_id] = row.score
    flush()
    return points[-limit:]


def overview(session: Session, settings: Settings) -> Overview:
    images = list_images(session)
    grades = {g: 0 for g in GRADE_KEYS}
    sev_totals, cve_totals = empty_counts(), empty_counts()
    for img in images:
        if img.grade in grades:
            grades[img.grade] += 1
        for sev, n in img.finding_counts.items():
            sev_totals[sev] += n
        for sev, n in img.cve_counts.items():
            cve_totals[sev] += n
    scores = [i.score for i in images if i.score is not None]
    fleet = round(sum(scores) / len(scores), 1) if scores else None
    last_scan = session.exec(
        select(ScanRecord.finished_at)
        .where(col(ScanRecord.status) == "completed")
        .order_by(col(ScanRecord.id).desc())
    ).first()
    riskiest = sorted(images, key=lambda i: (i.score or 0, -i.finding_counts["critical"]))[:5]
    return Overview(
        images_audited=len(images),
        fleet_score=fleet,
        fleet_grade=grade_for(round(fleet), settings.scoring) if fleet is not None else None,
        grade_distribution=grades,
        severity_totals=sev_totals,
        cve_totals=cve_totals,
        critical_findings=sev_totals["critical"],
        total_cves=sum(cve_totals.values()),
        trend=fleet_trend(session),
        riskiest=riskiest,
        last_scan_at=aware(last_scan),
    )


# ---------------------------------------------------------------------- scan history


def _scan_out(rec: ScanRecord) -> ScanOut:
    started, finished = aware(rec.started_at), aware(rec.finished_at)
    return ScanOut(
        id=rec.id or 0,
        target=rec.target,
        status=rec.status,
        started_at=started or rec.started_at,
        finished_at=finished,
        duration_seconds=(finished - started).total_seconds() if started and finished else None,
        images_scanned=rec.images_scanned,
        error=rec.error,
    )


def list_scans(session: Session, limit: int = 100) -> list[ScanOut]:
    rows = session.exec(select(ScanRecord).order_by(col(ScanRecord.id).desc()).limit(limit))
    return [_scan_out(r) for r in rows]


def scan_detail(session: Session, scan_id: int) -> ScanDetail | None:
    rec = session.get(ScanRecord, scan_id)
    if rec is None:
        return None
    runs = session.exec(select(ScannerRunRecord).where(ScannerRunRecord.scan_id == scan_id))
    return ScanDetail(
        **_scan_out(rec).model_dump(),
        scanners=[ScannerRunOut(scanner=r.scanner, status=r.status, detail=r.detail) for r in runs],
    )
