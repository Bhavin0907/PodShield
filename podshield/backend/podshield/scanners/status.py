"""Live availability of every scanner, for `podshield doctor` and /api/health."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from podshield.config import Settings
from podshield.scanners.base import ScannerUnavailable
from podshield.scanners.oscap import OscapScanner
from podshield.scanners.registry import RegistryAuditor
from podshield.scanners.trivy import TrivyScanner


@dataclass(frozen=True)
class ScannerStatus:
    name: str
    available: bool
    detail: str = ""
    enabled: bool = True


def _filesystem_check(settings: Settings) -> None:
    if shutil.which("podman") is None:
        raise ScannerUnavailable("podman not found in PATH")
    geteuid = getattr(os, "geteuid", None)
    if settings.podman.mode == "rootful" and geteuid is not None and geteuid() != 0:
        raise ScannerUnavailable("podman.mode is 'rootful' but not running as root")


def _trust_check(settings: Settings) -> None:
    if not Path(settings.trust.policy_path).is_file():
        raise ScannerUnavailable(f"{settings.trust.policy_path} not found")


def scanner_statuses(settings: Settings) -> list[ScannerStatus]:
    checks: list[tuple[str, bool, Callable[[], None]]] = [
        ("filesystem", settings.filesystem.enabled, lambda: _filesystem_check(settings)),
        ("oscap", settings.oscap.enabled, OscapScanner(settings).check),
        ("trivy", settings.trivy.enabled, TrivyScanner(settings).check),
        ("skopeo", True, RegistryAuditor(settings).check),
        ("trust", True, lambda: _trust_check(settings)),
    ]
    statuses = []
    for name, enabled, check in checks:
        try:
            check()
            statuses.append(ScannerStatus(name, True, "", enabled))
        except ScannerUnavailable as exc:
            statuses.append(ScannerStatus(name, False, str(exc), enabled))
    return statuses
