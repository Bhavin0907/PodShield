"""Builds the objects a scan needs from settings. Shared by the CLI and the API."""

from __future__ import annotations

from sqlalchemy import Engine

from podshield.config import Settings
from podshield.orchestrator import CveScan, FilesystemScan, Orchestrator, ProgressCallback
from podshield.podman_client import ImageSource, PodmanClient
from podshield.scanners.mount import FilesystemScanner
from podshield.scanners.oscap import OscapScanner
from podshield.scanners.trivy import TrivyScanner


def make_podman_client(settings: Settings) -> PodmanClient:
    return PodmanClient(settings.podman.socket, settings.podman.timeout_seconds)


def make_cve_scanners(settings: Settings) -> dict[str, CveScan]:
    scanners: dict[str, CveScan] = {}
    if settings.oscap.enabled:
        scanners["oscap"] = OscapScanner(settings)
    if settings.trivy.enabled:
        scanners["trivy"] = TrivyScanner(settings)
    return scanners


def make_fs_scanner(settings: Settings) -> FilesystemScan | None:
    return FilesystemScanner(settings) if settings.filesystem.enabled else None


def make_orchestrator(
    settings: Settings,
    engine: Engine,
    source: ImageSource,
    *,
    on_progress: ProgressCallback | None = None,
    skip_filesystem: bool = False,
    skip_cve: bool = False,
) -> Orchestrator:
    return Orchestrator(
        source,
        engine,
        settings,
        on_progress,
        fs_scanner=None if skip_filesystem else make_fs_scanner(settings),
        cve_scanners={} if skip_cve else make_cve_scanners(settings),
    )
