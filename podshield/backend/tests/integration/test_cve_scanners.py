"""oscap-podman and Trivy against real images.

Needs root (oscap-podman mounts the image), `oscap-podman` with an OVAL feed, and for the Trivy
tests `trivy` plus network access for its database. Missing prerequisites skip with a reason.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from podshield.config import Settings
from podshield.orchestrator import ImageResult, ScanSummary
from podshield.scanners.oscap import OscapScanner
from podshield.scanners.trivy import TrivyScanner
from tests.integration import support

pytestmark = [pytest.mark.integration, pytest.mark.requires_root, pytest.mark.requires_oscap]

ALPINE_REF = os.environ.get("PSTEST_ALPINE_IMAGE", "docker.io/library/alpine:3.19")
ALPINE_TAG = "localhost/pstest-alpine:3.19"


def _cve_scan(settings: Settings, ref: str, **scanners: object) -> tuple[ScanSummary, ImageResult]:
    summary = support.scan(settings, ref, cve_scanners=scanners)  # type: ignore[arg-type]
    assert summary.results, f"{ref}: {summary.errors}"
    return summary, summary.results[0]


@pytest.fixture
def alpine(pull_image: Callable[[str], str]) -> str:
    pull_image(ALPINE_REF)
    support.podman("tag", ALPINE_REF, ALPINE_TAG)  # purge() removes this by image ID
    return ALPINE_TAG


@pytest.mark.requires_network
def test_oscap_evaluates_a_real_ubi_image(base_image: str, isettings: Settings) -> None:
    summary, result = _cve_scan(isettings, base_image, oscap=OscapScanner(isettings))
    outcome = summary.scanners["oscap"]
    assert outcome.status == "ok", f"oscap did not run: {outcome.detail}"
    assert not outcome.unsupported and "oscap" not in result.cve_notes
    for vuln in result.vulnerabilities:
        assert vuln.source == "oscap" and vuln.cve_id.startswith(("CVE-", "RHSA-"))
        assert vuln.severity.value in {"critical", "high", "medium", "low"}
    print(f"\n  oscap on {base_image}: {len(result.vulnerabilities)} advisories")


@pytest.mark.requires_network
def test_oscap_scans_the_golden_image_too(
    build: Callable[[support.ImageCase], str], isettings: Settings
) -> None:
    """The golden image has no rpm binary, but its rpm database is intact, which is what counts."""
    summary, _ = _cve_scan(isettings, build(support.GOLDEN), oscap=OscapScanner(isettings))
    assert summary.scanners["oscap"].status == "ok", summary.scanners["oscap"].detail


@pytest.mark.requires_network
def test_alpine_is_reported_unsupported_not_zero_cves(alpine: str, isettings: Settings) -> None:
    summary, result = _cve_scan(isettings, alpine, oscap=OscapScanner(isettings))
    outcome = summary.scanners["oscap"]
    assert outcome.final()[0] == "unsupported", (outcome.status, outcome.detail)
    assert "Alpine" in outcome.final()[1] and "OVAL" in outcome.final()[1]
    assert result.vulnerabilities == []
    assert result.cve_notes["oscap"].startswith("unsupported")
    assert summary.status == "completed"  # unsupported is not a failure


@pytest.mark.requires_network
def test_alpine_unsupported_status_is_stored_for_the_ui(alpine: str, isettings: Settings) -> None:
    from podshield.orchestrator import scanner_runs

    summary, _ = _cve_scan(isettings, alpine, oscap=OscapScanner(isettings))
    runs = {r.scanner: r for r in scanner_runs(support.open_engine(isettings), summary.scan_id)}
    assert runs["oscap"].status == "unsupported"


@pytest.mark.requires_trivy
@pytest.mark.requires_network
def test_trivy_and_oscap_compared_on_ubi(
    base_image: str,
    isettings: Settings,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    summary, result = _cve_scan(
        isettings, base_image, oscap=OscapScanner(isettings), trivy=TrivyScanner(isettings)
    )
    for name in ("oscap", "trivy"):
        if summary.scanners[name].status != "ok":
            pytest.skip(f"{name} could not run: {summary.scanners[name].detail}")

    by_source: dict[str, set[str]] = {"oscap": set(), "trivy": set()}
    for v in result.vulnerabilities:
        for source in v.source.split(","):
            by_source[source].add(v.cve_id)
    both = by_source["oscap"] & by_source["trivy"]
    report: dict[str, Any] = {
        "image": base_image,
        "oscap": len(by_source["oscap"]),
        "trivy": len(by_source["trivy"]),
        "both": len(both),
        "only_oscap": sorted(by_source["oscap"] - both),
        "only_trivy": sorted(by_source["trivy"] - both),
    }
    artifact = Path(os.environ.get("PSTEST_ARTIFACTS", tmp_path)) / "cve-comparison-ubi.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(report, indent=2), encoding="utf-8")
    with capsys.disabled():
        print(
            f"\n  oscap vs trivy on {base_image}: oscap={report['oscap']} "
            f"trivy={report['trivy']} both={report['both']} "
            f"only-oscap={len(report['only_oscap'])} only-trivy={len(report['only_trivy'])} "
            f"-> {artifact}"
        )
    # The feeds legitimately differ (different advisories, package naming), so differences are
    # logged, not asserted. What must hold: findings are de-duplicated per (CVE, package).
    assert len({(v.cve_id, v.package) for v in result.vulnerabilities}) == len(
        result.vulnerabilities
    )


@pytest.mark.requires_trivy
@pytest.mark.requires_network
def test_trivy_covers_alpine_where_oscap_cannot(alpine: str, isettings: Settings) -> None:
    summary, result = _cve_scan(
        isettings, alpine, oscap=OscapScanner(isettings), trivy=TrivyScanner(isettings)
    )
    if summary.scanners["trivy"].status != "ok":
        pytest.skip(f"trivy could not run: {summary.scanners['trivy'].detail}")
    assert summary.scanners["oscap"].final()[0] == "unsupported"
    assert all(v.source == "trivy" for v in result.vulnerabilities)
    print(f"\n  trivy on {alpine}: {len(result.vulnerabilities)} CVEs (oscap: unsupported)")
