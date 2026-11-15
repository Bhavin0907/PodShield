from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from podshield.config import Settings
from podshield.scanners import base, trivy
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.trivy import TrivyScanner, parse_report
from podshield.schemas import ImageInfo, Severity
from tests.conftest import load_json


def test_parse_report() -> None:
    vulns = parse_report(load_json("trivy_report.json"))
    assert [v.cve_id for v in vulns][:2] == ["CVE-2024-7777", "CVE-2024-0001"]  # severity order
    by_id = {v.cve_id: v for v in vulns}
    assert len(vulns) == 3  # entry without an ID is dropped
    ssl = by_id["CVE-2024-0001"]
    assert ssl.severity is Severity.HIGH
    assert (ssl.package, ssl.installed_version, ssl.fixed_version) == (
        "openssl",
        "1:3.0.7-24.el9",
        "1:3.0.7-27.el9",
    )
    assert ssl.source == "trivy" and ssl.url.startswith("https://")
    assert by_id["CVE-2024-7777"].fixed_version == ""  # no fix available
    assert by_id["CVE-2024-8888"].severity is Severity.INFO  # UNKNOWN


@pytest.mark.parametrize("doc", [{}, {"Results": None}, {"Results": []}, {"Results": [{}]}])
def test_parse_report_empty(doc: dict[str, object]) -> None:
    assert parse_report(doc) == []


def test_unavailable_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    with pytest.raises(ScannerUnavailable, match="trivy not installed"):
        TrivyScanner(Settings())(ImageInfo(id="x"))
    monkeypatch.setattr(shutil, "which", lambda b: None if b == "podman" else "/usr/bin/trivy")
    with pytest.raises(ScannerUnavailable, match="podman"):
        TrivyScanner(Settings()).check()


def fake_subprocess(report: str, calls: list[list[str]]):  # type: ignore[no-untyped-def]
    def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        assert kwargs.get("timeout")
        if cmd[:2] == ["podman", "save"]:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"tar")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, report, "")

    return run


def test_scan_saves_image_then_runs_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    calls: list[list[str]] = []
    report = json.dumps(load_json("trivy_report.json"))
    monkeypatch.setattr(subprocess, "run", fake_subprocess(report, calls))
    settings = Settings()
    settings.trivy.skip_db_update = True
    settings.trivy.cache_dir = "/var/cache/trivy"
    vulns = TrivyScanner(settings)(ImageInfo(id="img123"))
    assert len(vulns) == 3

    save, scan = calls
    assert save[:4] == ["podman", "save", "--format", "docker-archive"]
    assert save[-1] == "img123"
    assert scan[:3] == ["trivy", "image", "--quiet"]
    assert "--skip-db-update" in scan and "--cache-dir" in scan
    assert scan[scan.index("--input") + 1] == save[save.index("-o") + 1]


def test_tarball_cleaned_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", fake_subprocess("{}", calls))
    TrivyScanner(Settings())(ImageInfo(id="x"))
    tarball = Path(calls[0][calls[0].index("-o") + 1])
    assert not tarball.exists() and not tarball.parent.exists()


def test_invalid_json_and_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(subprocess, "run", fake_subprocess("not json", []))
    with pytest.raises(ScannerError, match="invalid JSON"):
        TrivyScanner(Settings())(ImageInfo(id="x"))
    monkeypatch.setattr(subprocess, "run", fake_subprocess("[1, 2]", []))
    with pytest.raises(ScannerError, match="unexpected"):
        TrivyScanner(Settings())(ImageInfo(id="x"))

    def failing(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "FATAL db download failed")

    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(ScannerError, match="db download failed"):
        TrivyScanner(Settings())(ImageInfo(id="x"))


def test_run_tool_error_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_a: object, **_k: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(ScannerUnavailable):
        base.run_tool(["nope"], 1)

    def slow(cmd: list[str], **_k: object) -> None:
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(ScannerError, match="timed out"):
        base.run_tool(["x"], 1)
    assert trivy.SOURCE == "trivy"
