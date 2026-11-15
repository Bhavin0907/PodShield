"""An image the OVAL feed cannot assess is reported "unsupported", never as "zero CVEs"."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import Engine

from podshield.config import Settings
from podshield.orchestrator import Orchestrator, ScannerOutcome, scanner_runs
from podshield.scanners import oscap
from podshield.scanners.base import ScannerUnsupported
from podshield.scanners.filesystem import read_os_release, scan_tree
from podshield.schemas import FilesystemReport, ImageInfo, Severity, Vulnerability
from tests.conftest import FakeSource

UBI = {"ID": "rhel", "VERSION_ID": "9.4", "PRETTY_NAME": "Red Hat Enterprise Linux 9.4 (Plow)"}
ALPINE = {"ID": "alpine", "VERSION_ID": "3.19.1", "PRETTY_NAME": "Alpine Linux v3.19"}


def with_os(image: ImageInfo, release: dict[str, str]) -> ImageInfo:
    out = image.model_copy(deep=True)
    out.filesystem = FilesystemReport(os_release=release)
    return out


# ------------------------------------------------------------------ os-release reading


def test_os_release_is_read_from_usr_lib(tmp_path: Path) -> None:
    (tmp_path / "usr/lib").mkdir(parents=True)
    (tmp_path / "usr/lib/os-release").write_text(
        'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME="Alpine Linux v3.19"\n'
        "HOME_URL=https://alpinelinux.org/\n",
        encoding="utf-8",
    )
    assert read_os_release(tmp_path) == {
        "NAME": "Alpine Linux",
        "ID": "alpine",
        "VERSION_ID": "3.19.1",
        "PRETTY_NAME": "Alpine Linux v3.19",
    }


def test_os_release_falls_back_to_etc(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID='rhel'\n", encoding="utf-8")
    assert read_os_release(tmp_path) == {"ID": "rhel"}


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_os_release_symlink_to_the_host_is_never_followed(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    os.symlink("/etc/os-release", tmp_path / "etc/os-release")  # absolute: would be the HOST's
    assert read_os_release(tmp_path) == {}


def test_no_os_release_means_empty(tmp_path: Path) -> None:
    assert read_os_release(tmp_path) == {}


def test_garbage_os_release_is_harmless(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_bytes(b"\xff\xfe\x00not a file\n=\nID\n")
    assert read_os_release(tmp_path) == {}


def test_scan_tree_reports_os_release(tmp_path: Path) -> None:
    (tmp_path / "usr/lib").mkdir(parents=True)
    (tmp_path / "usr/lib/os-release").write_text("ID=rhel\n", encoding="utf-8")
    assert scan_tree(tmp_path).os_release == {"ID": "rhel"}


# ----------------------------------------------------------------------- the decision


@pytest.mark.parametrize(
    ("release", "unsupported"),
    [
        (UBI, False),
        ({"ID": "RHEL"}, False),  # case-insensitive
        (ALPINE, True),
        ({"ID": "debian", "PRETTY_NAME": "Debian GNU/Linux 12"}, True),
        ({"ID": "fedora"}, True),
        ({"NAME": "Mystery"}, True),
        ({}, False),  # no evidence: scan rather than guess
    ],
)
def test_unsupported_reason(
    good_image: ImageInfo, release: dict[str, str], unsupported: bool
) -> None:
    reason = oscap.unsupported_reason(with_os(good_image, release), ["rhel"])
    assert (reason is not None) is unsupported
    if reason:
        assert "OVAL" in reason


def test_reason_names_the_os(good_image: ImageInfo) -> None:
    reason = oscap.unsupported_reason(with_os(good_image, ALPINE), ["rhel"])
    assert reason is not None and "Alpine Linux v3.19" in reason


def test_no_filesystem_report_means_no_verdict(good_image: ImageInfo) -> None:
    good_image.filesystem = None
    assert oscap.unsupported_reason(good_image, ["rhel"]) is None


def test_supported_ids_are_configurable(good_image: ImageInfo) -> None:
    assert oscap.unsupported_reason(with_os(good_image, ALPINE), ["rhel", "alpine"]) is None


def test_scanner_raises_unsupported_before_running_anything(
    settings: Settings, good_image: ImageInfo, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = oscap.OscapScanner(settings)
    monkeypatch.setattr(scanner, "check", lambda: None)
    monkeypatch.setattr(oscap, "run_tool", lambda *a, **k: pytest.fail("oscap must not run"))
    with pytest.raises(ScannerUnsupported, match="Alpine"):
        scanner(with_os(good_image, ALPINE))


# --------------------------------------------------------------------- orchestration


def unsupported_scanner(img: ImageInfo) -> list[Vulnerability]:
    if img.filesystem and img.filesystem.os_release.get("ID") != "rhel":
        raise ScannerUnsupported("Alpine Linux v3.19 is not covered by the Red Hat OVAL feed")
    return []


def trivy_scanner(img: ImageInfo) -> list[Vulnerability]:
    return [
        Vulnerability(
            cve_id="CVE-2024-0001", package="musl", severity=Severity.HIGH, source="trivy"
        )
    ]


def test_unsupported_image_is_not_zero_cves(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    summary = Orchestrator(
        FakeSource([with_os(good_image, ALPINE)]),
        engine,
        settings,
        cve_scanners={"oscap": unsupported_scanner},
    ).scan(scan_all=True)

    assert summary.status == "completed"  # the scan itself did not fail
    (result,) = summary.results
    assert result.vulnerabilities == []
    assert "unsupported" in result.cve_notes["oscap"]
    assert summary.scanners["oscap"].final()[0] == "unsupported"
    assert any("cannot assess" in w for w in summary.warnings)
    (run,) = scanner_runs(engine, summary.scan_id)
    assert (run.scanner, run.status) == ("oscap", "unsupported")
    assert "Alpine" in run.detail and "OVAL" in run.detail


def test_trivy_still_reports_cves_for_an_oscap_unsupported_image(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    summary = Orchestrator(
        FakeSource([with_os(good_image, ALPINE)]),
        engine,
        settings,
        cve_scanners={"oscap": unsupported_scanner, "trivy": trivy_scanner},
    ).scan(scan_all=True)
    (result,) = summary.results
    assert [v.cve_id for v in result.vulnerabilities] == ["CVE-2024-0001"]
    runs = {r.scanner: r.status for r in scanner_runs(engine, summary.scan_id)}
    assert runs == {"oscap": "unsupported", "trivy": "ok"}


def test_a_mixed_scan_is_partial_not_ok(
    engine: Engine, settings: Settings, good_image: ImageInfo, bad_image: ImageInfo
) -> None:
    summary = Orchestrator(
        FakeSource([with_os(good_image, ALPINE), with_os(bad_image, UBI)]),
        engine,
        settings,
        cve_scanners={"oscap": unsupported_scanner},
    ).scan(scan_all=True)
    assert len(summary.results) == 2
    (run,) = scanner_runs(engine, summary.scan_id)
    assert run.status == "partial"
    assert "OVAL" in run.detail


def test_unsupported_does_not_stop_the_scanner_for_later_images(
    engine: Engine, settings: Settings, good_image: ImageInfo, bad_image: ImageInfo
) -> None:
    seen: list[str] = []

    def scanner(img: ImageInfo) -> list[Vulnerability]:
        seen.append(img.id)
        return unsupported_scanner(img)

    Orchestrator(
        FakeSource([with_os(good_image, ALPINE), with_os(bad_image, UBI)]),
        engine,
        settings,
        cve_scanners={"oscap": scanner},
    ).scan(scan_all=True)
    assert len(seen) == 2


def test_outcome_status_rules() -> None:
    assert ScannerOutcome().final() == ("ok", "")
    assert ScannerOutcome(status="failed", detail="boom", unsupported=["x: y"]).final() == (
        "failed",
        "boom",
    )
    assert ScannerOutcome(unsupported=["x: y"], succeeded=1).final() == ("partial", "x: y")
    assert ScannerOutcome(unsupported=["x: y"]).final() == ("unsupported", "x: y")


# ----------------------------------------------------------------------------- CLI


def test_cli_json_carries_the_unsupported_status(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    from podshield import cli

    summary = Orchestrator(
        FakeSource([with_os(good_image, ALPINE)]),
        engine,
        settings,
        cve_scanners={"oscap": unsupported_scanner},
    ).scan(scan_all=True)
    payload = {
        n: dict(zip(("status", "detail"), o.final(), strict=True))
        for n, o in summary.scanners.items()
    }
    assert payload["oscap"]["status"] == "unsupported"
    assert json.dumps(cli._result_json(summary.results[0]))  # serialisable
    assert "oscap" in cli._result_json(summary.results[0])["cve_notes"]
