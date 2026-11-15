"""Pure domain types shared by the podman client, rules, scoring, and storage."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is more severe."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class LayerInfo(BaseModel):
    created_by: str = ""
    created: datetime | None = None
    size: int = 0
    comment: str = ""
    empty: bool = False


class Vulnerability(BaseModel):
    cve_id: str
    package: str
    severity: Severity
    installed_version: str = ""
    fixed_version: str = ""  # empty: no fix available (yet)
    title: str = ""
    url: str = ""
    source: str = ""  # oscap, trivy, or "oscap,trivy" after merging


class FsSecret(BaseModel):
    path: str
    reason: str
    masked_value: str = ""


class SetuidFile(BaseModel):
    path: str
    mode: str  # e.g. "4755"


class CacheDir(BaseModel):
    path: str
    files: int
    size: int


class FilesystemReport(BaseModel):
    """Facts gathered by walking a mounted image root filesystem."""

    files_scanned: int = 0
    truncated: bool = False  # a limit (file count or time) stopped the walk early
    secrets: list[FsSecret] = Field(default_factory=list)
    setuid_files: list[SetuidFile] = Field(default_factory=list)
    cache_dirs: list[CacheDir] = Field(default_factory=list)
    shells: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    # Selected os-release fields (ID, VERSION_ID, PRETTY_NAME, ...); empty if the image has none.
    os_release: dict[str, str] = Field(default_factory=dict)


class ImageInfo(BaseModel):
    """Normalized view of a Podman image, independent of API response shape."""

    model_config = ConfigDict(frozen=False)

    id: str
    repo_tags: list[str] = Field(default_factory=list)
    repo_digests: list[str] = Field(default_factory=list)
    created: datetime | None = None
    size: int = 0
    architecture: str = ""
    os: str = ""
    user: str = ""
    env: list[str] = Field(default_factory=list)
    entrypoint: list[str] = Field(default_factory=list)
    cmd: list[str] = Field(default_factory=list)
    exposed_ports: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    filesystem: FilesystemReport | None = None  # None: not scanned or scanner unavailable
    healthcheck: dict[str, object] | None = None
    layers: list[LayerInfo] = Field(default_factory=list)
    layer_count: int = 0

    @property
    def short_id(self) -> str:
        return self.id.removeprefix("sha256:")[:12]

    @property
    def display_name(self) -> str:
        return self.repo_tags[0] if self.repo_tags else self.short_id

    @property
    def is_dangling(self) -> bool:
        return not self.repo_tags and not self.repo_digests

    @property
    def env_pairs(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for item in self.env:
            name, _, value = item.partition("=")
            pairs.append((name, value))
        return pairs


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""
