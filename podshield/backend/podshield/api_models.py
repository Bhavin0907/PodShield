"""Request/response models for the HTTP API (these also drive the OpenAPI schema)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from podshield.refs import validate_reference
from podshield.schemas import Severity

SEVERITIES = [s.value for s in Severity]
GRADES = ["A", "B", "C", "D", "F"]


class FindingOut(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence: list[str]
    remediation: str


class VulnerabilityOut(BaseModel):
    cve_id: str
    package: str
    severity: Severity
    installed_version: str
    fixed_version: str
    title: str
    url: str
    source: str


class ImageSummary(BaseModel):
    id: str
    short_id: str
    name: str
    repo_tags: list[str]
    registry: str
    size: int
    created: datetime | None
    age_days: int | None
    score: int | None
    grade: str | None
    last_scanned_at: datetime | None
    finding_counts: dict[str, int]
    cve_counts: dict[str, int]
    cve_total: int


class LayerOut(BaseModel):
    created_by: str
    created: datetime | None
    size: int
    empty: bool
    comment: str = ""


class HistoryPoint(BaseModel):
    scan_id: int
    scanned_at: datetime
    score: int
    grade: str
    finding_count: int


class ScannerRunOut(BaseModel):
    scanner: str
    status: str  # ok | unavailable | unsupported | partial | failed
    detail: str


class ImageDetail(ImageSummary):
    base_image: str | None
    last_scan_id: int | None
    findings: list[FindingOut]
    vulnerabilities: list[VulnerabilityOut]
    layers: list[LayerOut]
    config: dict[str, Any] | None  # sanitized; None if the image predates snapshots
    history: list[HistoryPoint]
    scanners: list[ScannerRunOut]


class TrendPoint(BaseModel):
    scan_id: int
    at: datetime
    score: float


class Overview(BaseModel):
    images_audited: int
    fleet_score: float | None
    fleet_grade: str | None
    grade_distribution: dict[str, int]
    severity_totals: dict[str, int]
    cve_totals: dict[str, int]
    critical_findings: int
    total_cves: int
    trend: list[TrendPoint]
    riskiest: list[ImageSummary]
    last_scan_at: datetime | None


class ScanOut(BaseModel):
    id: int
    target: str
    status: str  # queued | running | completed | failed
    started_at: datetime
    finished_at: datetime | None
    duration_seconds: float | None
    images_scanned: int
    error: str | None


class ScanDetail(ScanOut):
    scanners: list[ScannerRunOut]


class ScanRequest(BaseModel):
    image: str | None = None
    all: bool = False
    skip_filesystem: bool = False
    skip_cve: bool = False

    @field_validator("image")
    @classmethod
    def _valid_reference(cls, v: str | None) -> str | None:
        return None if v is None else validate_reference(v)

    @model_validator(mode="after")
    def _exactly_one_target(self) -> ScanRequest:
        if bool(self.image) == self.all:
            raise ValueError("provide exactly one of 'image' or 'all: true'")
        return self


class ScanCreated(BaseModel):
    scan_id: int
    status: str


class RuleOut(BaseModel):
    id: str
    title: str
    description: str
    kind: str
    default_severity: Severity
    severity: Severity
    enabled: bool


class RulePatch(BaseModel):
    """Fields left out are unchanged; an explicit null clears the override."""

    enabled: bool | None = None
    severity: Severity | None = None


class ContainerOut(BaseModel):
    id: str
    short_id: str
    name: str
    image: str
    status: str
    score: int
    grade: str
    findings: list[FindingOut]


class RegistryRequest(BaseModel):
    reference: str = Field(min_length=1, max_length=512)

    @field_validator("reference")
    @classmethod
    def _valid_reference(cls, v: str) -> str:
        return validate_reference(v)


class RegistryOut(BaseModel):
    reference: str
    id: str
    score: int
    grade: str
    size: int
    created: datetime | None
    findings: list[FindingOut]
    skipped_rules: list[str]
    notes: list[str]
    layers: list[LayerOut]
    config: dict[str, Any]
