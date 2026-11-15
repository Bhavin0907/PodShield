"""SQLModel tables. Findings store masked evidence only (never raw secret values)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScanRecord(SQLModel, table=True):
    """One invocation of a scan (one image or the whole fleet)."""

    __tablename__ = "scan"

    id: int | None = Field(default=None, primary_key=True)
    target: str  # image reference or "all"
    status: str = Field(default="running", index=True)  # running | completed | failed
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    images_scanned: int = 0
    error: str | None = None


class ImageRecord(SQLModel, table=True):
    """Latest known state of an image plus a pointer to its latest scan results."""

    __tablename__ = "image"

    id: str = Field(primary_key=True)  # full image ID
    repo_tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    size: int = 0
    created: datetime | None = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_scanned_at: datetime | None = None
    last_scan_id: int | None = Field(default=None, foreign_key="scan.id")
    score: int | None = None
    grade: str | None = Field(default=None, index=True)


class FindingRecord(SQLModel, table=True):
    __tablename__ = "finding"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    image_id: str = Field(foreign_key="image.id", index=True)
    rule_id: str = Field(index=True)
    title: str
    severity: str = Field(index=True)
    description: str
    evidence: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    remediation: str = ""


class VulnerabilityRecord(SQLModel, table=True):
    __tablename__ = "vulnerability"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    image_id: str = Field(foreign_key="image.id", index=True)
    cve_id: str = Field(index=True)
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    severity: str = Field(index=True)
    title: str = ""
    url: str = ""
    source: str = ""


class ScannerRunRecord(SQLModel, table=True):
    """Outcome of one external scanner during one scan (shown in the UI as availability)."""

    __tablename__ = "scanner_run"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    scanner: str  # filesystem | oscap | trivy
    status: str  # ok | unavailable | failed | disabled
    detail: str = ""


class ScanHeartbeatRecord(SQLModel, table=True):
    """Liveness marker for a scan that is queued or running, in any process.

    Scans are started by the API, the CLI, the timer and the events watcher. A starting API
    must only fail scans whose owner is gone, so running scans touch this row every few
    seconds and it is deleted when the scan finishes.
    """

    __tablename__ = "scan_heartbeat"

    scan_id: int = Field(primary_key=True, foreign_key="scan.id")
    updated_at: datetime = Field(default_factory=utcnow)


class ImageSnapshotRecord(SQLModel, table=True):
    """Sanitized config/layers of an image as of its latest scan (see ``sanitize``)."""

    __tablename__ = "image_snapshot"

    image_id: str = Field(primary_key=True, foreign_key="image.id")
    scan_id: int = Field(foreign_key="scan.id")
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class RuleOverrideRecord(SQLModel, table=True):
    """Rule toggles and severity changes made through the API (on top of config.toml)."""

    __tablename__ = "rule_override"

    rule_id: str = Field(primary_key=True)
    enabled: bool | None = None
    severity: str | None = None


class ImageScanRecord(SQLModel, table=True):
    """Score of one image in one scan; feeds history and fleet trend charts."""

    __tablename__ = "image_scan"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    image_id: str = Field(foreign_key="image.id", index=True)
    score: int
    grade: str
    finding_count: int = 0
    scanned_at: datetime = Field(default_factory=utcnow)
