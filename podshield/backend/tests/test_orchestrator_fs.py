from __future__ import annotations

from sqlalchemy import Engine
from sqlmodel import Session, select

from podshield.config import RuleOverride, Settings
from podshield.models import FindingRecord
from podshield.orchestrator import Orchestrator
from podshield.scanners.mount import FilesystemScanUnavailable
from podshield.schemas import FilesystemReport, FsSecret, ImageInfo
from tests.conftest import FakeSource

FS_RULES = ("PS-004", "PS-009", "PS-010", "PS-015")


def test_filesystem_findings_flow_through_scan_and_score(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    called: list[str] = []

    def fs_scan(image_id: str) -> FilesystemReport:
        called.append(image_id)
        return FilesystemReport(
            secrets=[
                FsSecret(
                    path="/root/.ssh/id_rsa:1",
                    reason="Private key block pattern",
                    masked_value="----****",
                )
            ],
            shells=["/bin/sh"],
        )

    summary = Orchestrator(FakeSource([good_image]), engine, settings, fs_scanner=fs_scan).scan(
        scan_all=True
    )
    assert called == [good_image.id]
    (result,) = summary.results
    assert {"PS-004", "PS-015"} <= {f.rule_id for f in result.findings}
    assert result.score.score == 75 and result.score.grade == "C"  # -25 critical, info is free
    with Session(engine) as s:
        stored = {f.rule_id for f in s.exec(select(FindingRecord)).all()}
    assert "PS-004" in stored


def test_filesystem_unavailable_degrades_gracefully(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    def fs_scan(_image_id: str) -> FilesystemReport:
        raise FilesystemScanUnavailable("not running as root")

    summary = Orchestrator(FakeSource([good_image]), engine, settings, fs_scanner=fs_scan).scan(
        scan_all=True
    )
    assert summary.status == "completed" and len(summary.results) == 1
    assert len(summary.warnings) == 1
    assert "filesystem scan unavailable" in summary.warnings[0]
    assert "not running as root" in summary.warnings[0]
    assert not set(FS_RULES) & {f.rule_id for f in summary.results[0].findings}


def test_filesystem_not_mounted_when_no_rule_needs_it(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    for rule_id in FS_RULES:
        settings.rules[rule_id] = RuleOverride(enabled=False)

    def fs_scan(_image_id: str) -> FilesystemReport:
        raise AssertionError("must not mount")

    summary = Orchestrator(FakeSource([good_image]), engine, settings, fs_scanner=fs_scan).scan(
        scan_all=True
    )
    assert summary.status == "completed" and summary.warnings == []


def test_truncated_filesystem_scan_warns(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    summary = Orchestrator(
        FakeSource([good_image]),
        engine,
        settings,
        fs_scanner=lambda _i: FilesystemReport(truncated=True),
    ).scan(scan_all=True)
    assert any("limits" in w for w in summary.warnings)


def test_no_fs_scanner_means_no_fs_rules(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    summary = Orchestrator(FakeSource([good_image]), engine, settings).scan(scan_all=True)
    assert summary.warnings == []
