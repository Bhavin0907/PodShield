"""Optional CVE scanning with ``trivy image``.

The image is exported with ``podman save`` and scanned from the tarball (``--input``), so no
Docker daemon or Podman socket integration is needed on the Trivy side.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any

from podshield.config import Settings
from podshield.scanners.base import ScannerError, ScannerUnavailable, run_tool
from podshield.scanners.oscap import merge_vulnerabilities
from podshield.schemas import ImageInfo, Severity, Vulnerability

log = logging.getLogger(__name__)

SOURCE = "trivy"
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def parse_report(report: dict[str, Any]) -> list[Vulnerability]:
    """Convert a ``trivy image --format json`` document to vulnerabilities."""
    vulns: list[Vulnerability] = []
    for result in report.get("Results") or []:
        for item in result.get("Vulnerabilities") or []:
            cve_id = item.get("VulnerabilityID")
            if not cve_id:
                continue
            vulns.append(
                Vulnerability(
                    cve_id=str(cve_id),
                    package=str(item.get("PkgName") or ""),
                    severity=_SEVERITY.get(str(item.get("Severity", "")).upper(), Severity.INFO),
                    installed_version=str(item.get("InstalledVersion") or ""),
                    fixed_version=str(item.get("FixedVersion") or ""),
                    title=str(item.get("Title") or ""),
                    url=str(item.get("PrimaryURL") or ""),
                    source=SOURCE,
                )
            )
    return merge_vulnerabilities(vulns)


class TrivyScanner:
    name = "trivy"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def check(self) -> None:
        cfg = self.settings.trivy
        if shutil.which(cfg.binary) is None:
            raise ScannerUnavailable(f"{cfg.binary} not installed (optional scanner)")
        if shutil.which("podman") is None:
            raise ScannerUnavailable("podman not found in PATH (needed for `podman save`)")

    def __call__(self, image: ImageInfo) -> list[Vulnerability]:
        self.check()
        cfg = self.settings.trivy
        tmp_root = cfg.tmp_dir or None
        if tmp_root:
            Path(tmp_root).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="podshield-trivy-", dir=tmp_root) as tmp:
            tarball = Path(tmp) / "image.tar"
            run_tool(
                ["podman", "save", "--format", "docker-archive", "-o", str(tarball), image.id],
                cfg.timeout_seconds,
            )
            cmd = [
                cfg.binary,
                "image",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln",
                "--timeout",
                f"{cfg.timeout_seconds}s",
                "--input",
                str(tarball),
            ]
            if cfg.skip_db_update:
                cmd += ["--skip-db-update", "--skip-java-db-update"]
            if cfg.cache_dir:
                cmd += ["--cache-dir", cfg.cache_dir]
            proc = run_tool(cmd, cfg.timeout_seconds + 30)
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerError(f"trivy returned invalid JSON: {exc}") from exc
        if not isinstance(report, dict):
            raise ScannerError("trivy returned an unexpected JSON document")
        vulns = parse_report(report)
        log.info("trivy finished", extra={"image": image.short_id, "vulnerabilities": len(vulns)})
        return vulns
