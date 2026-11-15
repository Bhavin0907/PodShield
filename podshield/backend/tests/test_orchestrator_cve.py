from __future__ import annotations

from sqlalchemy import Engine
from sqlmodel import Session, select

from podshield.config import Settings
from podshield.models import ScannerRunRecord, VulnerabilityRecord
from podshield.orchestrator import (
    Orchestrator,
    latest_reports,
    scanner_runs,
    unique_cve_severities,
)
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.schemas import ImageInfo, Severity, Vulnerability
from tests.conftest import FakeSource


def vuln(cve: str, sev: Severity, pkg: str = "pkg", src: str = "oscap") -> Vulnerability:
    return Vulnerability(cve_id=cve, package=pkg, severity=sev, source=src, fixed_version="2")


def test_unique_cve_severities_counts_each_cve_once() -> None:
    sevs = unique_cve_severities(
        [
            vuln("CVE-1", Severity.MEDIUM, "a"),
            vuln("CVE-1", Severity.HIGH, "b"),
            vuln("CVE-2", Severity.LOW),
        ]
    )
    assert sorted(s.value for s in sevs) == ["high", "low"]


def test_cves_are_stored_scored_and_merged(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    oscap = lambda img: [vuln("CVE-1", Severity.HIGH, "openssl"), vuln("CVE-2", Severity.LOW)]
    trivy = lambda img: [vuln("CVE-1", Severity.CRITICAL, "openssl", "trivy")]
    summary = Orchestrator(
        FakeSource([good_image]),
        engine,
        settings,
        cve_scanners={"oscap": oscap, "trivy": trivy},
    ).scan(scan_all=True)

    (result,) = summary.results
    cves = {(v.cve_id, v.package): v for v in result.vulnerabilities}
    assert cves[("CVE-1", "openssl")].severity is Severity.CRITICAL
    assert cves[("CVE-1", "openssl")].source == "oscap,trivy"
    assert len(result.vulnerabilities) == 2
    assert result.score.score == 100 - 25 - 1  # critical + low, each CVE counted once
    assert summary.scanners["oscap"].status == "ok" and summary.scanners["trivy"].status == "ok"

    with Session(engine) as s:
        rows = s.exec(select(VulnerabilityRecord)).all()
        assert {(r.cve_id, r.severity) for r in rows} == {("CVE-1", "critical"), ("CVE-2", "low")}
        runs = {r.scanner: r.status for r in s.exec(select(ScannerRunRecord)).all()}
    assert runs == {"oscap": "ok", "trivy": "ok"}

    (report,) = latest_reports(engine)
    assert len(report.vulnerabilities) == 2
    assert {r.scanner for r in scanner_runs(engine, summary.scan_id)} == {"oscap", "trivy"}


def test_cve_deduction_is_capped(engine: Engine, settings: Settings, good_image: ImageInfo) -> None:
    many = lambda img: [vuln(f"CVE-{i}", Severity.CRITICAL) for i in range(10)]
    summary = Orchestrator(
        FakeSource([good_image]), engine, settings, cve_scanners={"oscap": many}
    ).scan(scan_all=True)
    assert summary.results[0].score.score == 60  # capped at 40 points


def test_unavailable_scanner_is_recorded_once_and_not_retried(
    engine: Engine, settings: Settings, good_image: ImageInfo, bad_image: ImageInfo
) -> None:
    calls = []

    def missing(img: ImageInfo) -> list[Vulnerability]:
        calls.append(img.id)
        raise ScannerUnavailable("trivy not installed (optional scanner)")

    summary = Orchestrator(
        FakeSource([good_image, bad_image]), engine, settings, cve_scanners={"trivy": missing}
    ).scan(scan_all=True)
    assert len(calls) == 1  # not retried for the second image
    assert summary.status == "completed" and len(summary.results) == 2
    assert summary.scanners["trivy"].status == "unavailable"
    assert summary.warnings == ["trivy scan unavailable (trivy not installed (optional scanner))"]
    with Session(engine) as s:
        (run,) = s.exec(select(ScannerRunRecord)).all()
    assert (run.scanner, run.status) == ("trivy", "unavailable")
    assert "not installed" in run.detail


def test_failure_on_one_image_does_not_block_others(
    engine: Engine, settings: Settings, good_image: ImageInfo, bad_image: ImageInfo
) -> None:
    def flaky(img: ImageInfo) -> list[Vulnerability]:
        if img.id == bad_image.id:
            raise ScannerError("oscap timed out after 900s")
        return [vuln("CVE-9", Severity.LOW)]

    summary = Orchestrator(
        FakeSource([bad_image, good_image]), engine, settings, cve_scanners={"oscap": flaky}
    ).scan(scan_all=True)
    assert len(summary.results) == 2
    assert summary.scanners["oscap"].status == "failed"
    assert any("timed out" in w and "localhost/demo-bad" in w for w in summary.warnings)
    by_id = {r.image.id: r for r in summary.results}
    assert by_id[good_image.id].vulnerabilities and not by_id[bad_image.id].vulnerabilities


def test_unexpected_scanner_crash_is_contained(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    def crash(img: ImageInfo) -> list[Vulnerability]:
        raise KeyError("boom")

    summary = Orchestrator(
        FakeSource([good_image]), engine, settings, cve_scanners={"trivy": crash}
    ).scan(scan_all=True)
    assert summary.status == "completed" and summary.results
    assert summary.scanners["trivy"].status == "failed"
    assert "KeyError" in summary.scanners["trivy"].detail


def test_one_scanner_down_other_still_contributes(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    def down(img: ImageInfo) -> list[Vulnerability]:
        raise ScannerUnavailable("no feed")

    summary = Orchestrator(
        FakeSource([good_image]),
        engine,
        settings,
        cve_scanners={
            "oscap": down,
            "trivy": lambda img: [vuln("CVE-5", Severity.HIGH, src="trivy")],
        },
    ).scan(scan_all=True)
    assert [v.cve_id for v in summary.results[0].vulnerabilities] == ["CVE-5"]
    assert summary.scanners["oscap"].status == "unavailable"
    assert summary.scanners["trivy"].status == "ok"


def test_rescan_replaces_latest_vulnerabilities(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    current = [vuln("CVE-1", Severity.HIGH)]
    orch = Orchestrator(
        FakeSource([good_image]),
        engine,
        settings,
        cve_scanners={"oscap": lambda img: list(current)},
    )
    orch.scan(scan_all=True)
    current.clear()  # patched
    second = orch.scan(scan_all=True)
    (report,) = latest_reports(engine)
    assert report.vulnerabilities == [] and report.image.last_scan_id == second.scan_id
    with Session(engine) as s:
        assert len(s.exec(select(VulnerabilityRecord)).all()) == 1  # history kept
