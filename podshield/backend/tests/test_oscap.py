from __future__ import annotations

import bz2
import shutil
from pathlib import Path

import pytest

from podshield.config import Settings
from podshield.scanners import oscap
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.oscap import OscapScanner, merge_vulnerabilities, parse_results
from podshield.schemas import ImageInfo, Severity, Vulnerability
from tests.conftest import DATA

RESULTS = DATA / "oval_results.xml"


def by_key(vulns: list[Vulnerability]) -> dict[tuple[str, str], Vulnerability]:
    return {(v.cve_id, v.package): v for v in vulns}


def test_parse_results_extracts_only_true_definitions() -> None:
    vulns = by_key(parse_results(RESULTS))
    ids = {cve for cve, _ in vulns}
    assert ids == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "RHSA-2024:0001"}
    assert "CVE-2024-9999" not in ids  # result="false"


def test_severity_mapping_and_fixed_versions() -> None:
    vulns = by_key(parse_results(RESULTS))
    ssl = vulns[("CVE-2024-0001", "openssl")]
    assert ssl.severity is Severity.HIGH  # Red Hat "Important"
    assert ssl.fixed_version == "1:3.0.7-27.el9"
    assert ssl.source == "oscap"
    assert ssl.url.endswith("CVE-2024-0001")
    assert ("CVE-2024-0001", "openssl-libs") in vulns
    assert vulns[("CVE-2024-0003", "glibc")].severity is Severity.CRITICAL
    # "is signed with" and "is installed" criteria are not packages
    assert not any(pkg in {"Red", "openssl is signed"} for _, pkg in vulns)


def test_definition_without_cve_falls_back_to_advisory_and_title_severity() -> None:
    vulns = by_key(parse_results(RESULTS))
    bash = vulns[("RHSA-2024:0001", "bash")]
    assert bash.severity is Severity.MEDIUM  # from "(Moderate)"? no advisory severity -> title
    assert bash.fixed_version == "0:5.1.8-9.el9"


def test_each_cve_gets_every_package() -> None:
    vulns = by_key(parse_results(RESULTS))
    assert {("CVE-2024-0002", "openssl"), ("CVE-2024-0002", "openssl-libs")} <= set(vulns)


def test_metadata_falls_back_to_feed_file(tmp_path: Path) -> None:
    # results file with verdicts only; definitions live in the (bz2) feed
    text = RESULTS.read_text(encoding="utf-8")
    results_only = (
        text[: text.index("<oval-def:oval_definitions>")] + text[text.index("<results>") :]
    )
    results = tmp_path / "results.xml"
    results.write_text(results_only, encoding="utf-8")
    feed = tmp_path / "feed.oval.xml.bz2"
    feed.write_bytes(bz2.compress(text.encode("utf-8")))
    vulns = parse_results(results, feed)
    assert ("CVE-2024-0003", "glibc") in by_key(vulns)
    assert parse_results(results, None) == []  # no metadata anywhere


def test_no_vulnerable_definitions(tmp_path: Path) -> None:
    text = RESULTS.read_text(encoding="utf-8").replace('result="true"', 'result="false"')
    path = tmp_path / "r.xml"
    path.write_text(text, encoding="utf-8")
    assert parse_results(path) == []


def test_malformed_xml_raises_scanner_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.xml"
    path.write_text("<oval_results><oops", encoding="utf-8")
    with pytest.raises(ScannerError):
        parse_results(path)


def test_xml_entity_bombs_are_rejected(tmp_path: Path) -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><x>&b;</x>'
    )
    path = tmp_path / "bomb.xml"
    path.write_text(bomb, encoding="utf-8")
    with pytest.raises(Exception, match="(?i)entit|forbidden"):
        parse_results(path)


def test_merge_dedupes_and_keeps_highest_severity() -> None:
    a = Vulnerability(
        cve_id="CVE-1", package="p", severity=Severity.MEDIUM, source="oscap", fixed_version=""
    )
    b = Vulnerability(
        cve_id="CVE-1",
        package="p",
        severity=Severity.HIGH,
        source="trivy",
        fixed_version="2.0",
        installed_version="1.0",
        title="t",
    )
    c = Vulnerability(cve_id="CVE-2", package="q", severity=Severity.CRITICAL, source="trivy")
    merged = merge_vulnerabilities([a, b, c])
    assert [v.cve_id for v in merged] == ["CVE-2", "CVE-1"]  # most severe first
    one = merged[1]
    assert one.severity is Severity.HIGH
    assert one.fixed_version == "2.0" and one.installed_version == "1.0" and one.title == "t"
    assert one.source == "oscap,trivy"
    assert a.severity is Severity.MEDIUM  # inputs are not mutated


# ---- scanner wrapper


def make_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[OscapScanner, Settings]:
    settings = Settings()
    feed = tmp_path / "feed.xml"
    feed.write_text("<x/>", encoding="utf-8")
    settings.oscap.oval_path = str(feed)
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    return OscapScanner(settings), settings


def test_unavailable_without_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    with pytest.raises(ScannerUnavailable, match="openscap-utils"):
        OscapScanner(Settings()).check()


def test_unavailable_without_feed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    settings = Settings()
    settings.oscap.oval_path = str(tmp_path / "missing.xml")
    with pytest.raises(ScannerUnavailable, match="OVAL feed not found"):
        OscapScanner(settings)(ImageInfo(id="abc"))


def test_scan_runs_command_and_parses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, settings = make_scanner(tmp_path, monkeypatch)
    seen: dict[str, object] = {}

    def fake_run(cmd: list[str], timeout: int, ok_codes: tuple[int, ...] = (0,)) -> None:
        seen.update(cmd=cmd, timeout=timeout, ok_codes=ok_codes)
        results = Path(cmd[cmd.index("--results") + 1])
        shutil.copy(RESULTS, results)

    monkeypatch.setattr(oscap, "run_tool", fake_run)
    vulns = scanner(ImageInfo(id="imgid123"))
    cmd = seen["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:5] == ["oscap-podman", "imgid123", "oval", "eval", "--results"]
    assert cmd[-1] == settings.oscap.oval_path
    assert seen["ok_codes"] == (0, 2)
    assert {v.cve_id for v in vulns} >= {"CVE-2024-0001", "CVE-2024-0003"}
    assert vulns[0].severity is Severity.CRITICAL  # sorted by severity


def test_rootless_wraps_in_unshare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, settings = make_scanner(tmp_path, monkeypatch)
    settings.podman.mode = "rootless"
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int, ok_codes: tuple[int, ...] = (0,)) -> None:
        seen.append(cmd)
        shutil.copy(RESULTS, Path(cmd[cmd.index("--results") + 1]))

    monkeypatch.setattr(oscap, "run_tool", fake_run)
    scanner(ImageInfo(id="x"))
    assert seen[0][:3] == ["podman", "unshare", "oscap-podman"]


def test_missing_results_file_is_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner, _ = make_scanner(tmp_path, monkeypatch)
    monkeypatch.setattr(oscap, "run_tool", lambda *a, **k: None)
    with pytest.raises(ScannerError, match="no results"):
        scanner(ImageInfo(id="x"))
