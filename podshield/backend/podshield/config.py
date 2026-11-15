"""Settings loaded from /etc/podshield/config.toml with environment overrides.

Precedence (highest first): environment variables, config file, built-in defaults.

Environment variables:
    PODSHIELD_CONFIG            path to the TOML file (default /etc/podshield/config.toml)
    PODSHIELD_PODMAN_SOCKET     e.g. unix:///run/user/1000/podman/podman.sock
    PODSHIELD_DB_PATH           SQLite file path
    PODSHIELD_LOG_LEVEL         DEBUG, INFO, WARNING, ...
    PODSHIELD_STATIC_DIR        directory with the built frontend
    PODSHIELD_MAX_IMAGE_AGE_DAYS
"""

from __future__ import annotations

import logging
import os
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from podshield.schemas import Severity

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/podshield/config.toml"
DEFAULT_PODMAN_SOCKET = "unix:///run/podman/podman.sock"
DEFAULT_DB_PATH = "/var/lib/podshield/podshield.db"


class ConfigError(Exception):
    """Raised when the configuration file is unreadable or invalid."""


class PodmanSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    socket: str = DEFAULT_PODMAN_SOCKET
    timeout_seconds: int = Field(default=30, ge=1)
    # "rootful" mounts via `podman image mount`, "rootless" via `podman unshare` (Phase 2).
    mode: str = Field(default="rootful", pattern="^(rootful|rootless)$")


class DatabaseSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = DEFAULT_DB_PATH


LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class LoggingSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str = "INFO"

    @field_validator("level")
    @classmethod
    def _known_level(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in LOG_LEVELS:
            raise ValueError(f"must be one of {', '.join(LOG_LEVELS)} (got {value!r})")
        return upper


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Directory with the built frontend; empty = auto-detect (frontend/dist next to the repo).
    static_dir: str = ""


class WatcherSettings(BaseModel):
    """``podshield watch``: scan images as they appear."""

    model_config = ConfigDict(extra="forbid")

    # Podman image event actions that trigger a scan. `podman save` (used for Trivy) and
    # image mounts (used for filesystem checks) are deliberately not listed, so PodShield's
    # own scans cannot trigger more scans.
    actions: list[str] = Field(
        default_factory=lambda: ["pull", "build", "tag", "import", "loadfromarchive"]
    )
    # A pull emits several events (pull, tag, ...); wait for quiet before scanning.
    debounce_seconds: float = Field(default=5.0, ge=0)
    scan_on_start: bool = False  # scan every image once when the watcher starts


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_image_age_days: int = Field(default=90, ge=1)
    max_image_size_mb: int = Field(default=1024, ge=1)
    max_layers: int = Field(default=30, ge=1)


class ScanSettings(BaseModel):
    """How a single scan job processes its images."""

    model_config = ConfigDict(extra="forbid")

    # Images scanned in parallel inside one scan. Each one may mount a filesystem and run
    # oscap/trivy, which are heavy, so this is deliberately small. 1 means strictly sequential.
    max_concurrent_images: int = Field(default=4, ge=1, le=32)


class FilesystemSettings(BaseModel):
    """Limits for walking mounted image filesystems (PS-004, PS-009, PS-010, PS-015)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_file_size_kb: int = Field(default=1024, ge=1)  # larger files are not content-scanned
    max_files: int = Field(default=300_000, ge=1)
    timeout_seconds: int = Field(default=300, ge=10)
    max_reported: int = Field(default=50, ge=1)  # cap per finding category


class TrustSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trusted_registries: list[str] = Field(
        default_factory=lambda: [
            "registry.access.redhat.com",
            "registry.redhat.io",
            "quay.io/podman",
        ]
    )
    policy_path: str = "/etc/containers/policy.json"
    registries_conf: str = "/etc/containers/registries.conf"
    registries_conf_d: str = "/etc/containers/registries.conf.d"
    registries_d: str = "/etc/containers/registries.d"


class OscapSettings(BaseModel):
    """Red Hat OVAL scan via ``oscap-podman`` (CVEs for RHEL/UBI-based images)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    binary: str = "oscap-podman"
    # Download e.g. https://www.redhat.com/security/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2
    # once and refresh it periodically; PodShield never downloads it itself (offline labs).
    oval_path: str = "/var/lib/podshield/oval/rhel-9.oval.xml"
    timeout_seconds: int = Field(default=900, ge=30)
    # os-release IDs the OVAL feed covers. Other images are reported as "unsupported by OVAL"
    # instead of "zero CVEs"; trivy still covers them if it is installed.
    supported_os_ids: list[str] = Field(default_factory=lambda: ["rhel"])


class TrivySettings(BaseModel):
    """Optional ``trivy image`` scan (covers non-RHEL ecosystems too)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    binary: str = "trivy"
    timeout_seconds: int = Field(default=900, ge=30)
    skip_db_update: bool = False  # set true in offline labs with a pre-seeded cache
    cache_dir: str = ""
    # `podman save` writes the image tarball here; point at real disk if /tmp is a small tmpfs.
    tmp_dir: str = ""


class RegistrySettings(BaseModel):
    """Pre-pull audits with ``skopeo inspect``."""

    model_config = ConfigDict(extra="forbid")

    binary: str = "skopeo"
    timeout_seconds: int = Field(default=60, ge=5)
    tls_verify: bool = True
    authfile: str = ""


class ScoringSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    critical: int = Field(default=25, ge=0)
    high: int = Field(default=10, ge=0)
    medium: int = Field(default=4, ge=0)
    low: int = Field(default=1, ge=0)
    info: int = Field(default=0, ge=0)
    cve_cap: int = Field(default=40, ge=0)
    grade_a: int = 90
    grade_b: int = 80
    grade_c: int = 70
    grade_d: int = 60

    @model_validator(mode="after")
    def _grades_descend(self) -> ScoringSettings:
        if not 0 <= self.grade_d < self.grade_c < self.grade_b < self.grade_a <= 100:
            raise ValueError(
                "grade boundaries must satisfy 0 <= grade_d < grade_c < grade_b < grade_a <= 100"
            )
        return self

    def weight(self, severity: Severity) -> int:
        return int(getattr(self, severity.value))


class RuleOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    severity: Severity | None = None


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    podman: PodmanSettings = Field(default_factory=PodmanSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    watcher: WatcherSettings = Field(default_factory=WatcherSettings)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    trust: TrustSettings = Field(default_factory=TrustSettings)
    filesystem: FilesystemSettings = Field(default_factory=FilesystemSettings)
    oscap: OscapSettings = Field(default_factory=OscapSettings)
    trivy: TrivySettings = Field(default_factory=TrivySettings)
    registry: RegistrySettings = Field(default_factory=RegistrySettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    rules: dict[str, RuleOverride] = Field(default_factory=dict)

    def rule_override(self, rule_id: str) -> RuleOverride:
        return self.rules.get(rule_id, RuleOverride())


def _apply_env(data: dict[str, Any], env: dict[str, str]) -> None:
    def put(section: str, key: str, value: str) -> None:
        data.setdefault(section, {})[key] = value

    if v := env.get("PODSHIELD_PODMAN_SOCKET"):
        put("podman", "socket", v)
    if v := env.get("PODSHIELD_DB_PATH"):
        put("database", "path", v)
    if v := env.get("PODSHIELD_LOG_LEVEL"):
        put("logging", "level", v.upper())
    if v := env.get("PODSHIELD_STATIC_DIR"):
        put("server", "static_dir", v)
    if v := env.get("PODSHIELD_MAX_IMAGE_AGE_DAYS"):
        put("thresholds", "max_image_age_days", v)


def load_settings(
    path: str | os.PathLike[str] | None = None, env: dict[str, str] | None = None
) -> Settings:
    """Load settings. A missing config file is not an error (defaults are used)."""
    environ: dict[str, str] = dict(os.environ if env is None else env)
    config_path = Path(path or environ.get("PODSHIELD_CONFIG", DEFAULT_CONFIG_PATH))

    data: dict[str, Any] = {}
    if config_path.is_file():
        try:
            with config_path.open("rb") as fh:
                data = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"cannot read {config_path}: {exc}") from exc
    else:
        log.debug("config file %s not found, using defaults", config_path)

    _apply_env(data, environ)
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration in {config_path}: {exc}") from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
