"""`podshield scan --all` end to end: real Podman, real filesystem mounts, results in SQLite.

Rootful and rootless are both covered: the suite follows the user running pytest. Tests that only
make sense in one mode skip with a reason in the other.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlmodel import Session, select

from podshield.config import Settings
from podshield.db import make_engine
from podshield.models import FindingRecord, ImageRecord, ScannerRunRecord, ScanRecord
from tests.integration import support
from tests.integration.support import GOLDEN, MOUNT_RULES, RULE_CASES, ImageCase

pytestmark = pytest.mark.integration

SAMPLE = ("PS-001", "PS-003", "PS-010", "PS-013")  # one cheap case per kind of check


def _cases(*rules: str) -> list[ImageCase]:
    return [c for c in RULE_CASES if c.rule in rules]


def test_scan_all_persists_every_result_in_sqlite(
    build: Callable[[ImageCase], str], isettings: Settings, tmp_path: Path
) -> None:
    cases = [GOLDEN, *_cases(*SAMPLE)]
    for case in cases:
        build(case)
    config = support.write_config(isettings, tmp_path / "config.toml")

    proc = support.run_cli(config, "scan", "--all", "--skip-cve", "--json")
    assert proc.returncode == 0, proc.stderr[-1500:]
    doc = json.loads(proc.stdout)
    assert doc["status"] == "completed"
    reported = {tag: img for img in doc["images"] for tag in img["tags"]}

    engine = make_engine(isettings.database.path)
    with Session(engine) as session:
        scan = session.get(ScanRecord, doc["scan_id"])
        assert scan is not None and scan.status == "completed"
        assert scan.images_scanned == len(doc["images"]) >= len(cases)
        assert scan.finished_at is not None

        for case in cases:
            assert case.ref in reported, f"{case.ref} missing from the scan output"
            record = session.get(ImageRecord, reported[case.ref]["id"])
            assert record is not None, f"{case.ref} was not stored"
            stored = {
                f.rule_id
                for f in session.exec(
                    select(FindingRecord).where(
                        FindingRecord.image_id == record.id, FindingRecord.scan_id == scan.id
                    )
                )
            }
            expected = set() if case.rule is None else {case.rule}
            if not support.IS_ROOT:
                expected -= MOUNT_RULES  # rootless without a working mount: skipped, not wrong
                stored -= MOUNT_RULES
            assert stored == expected, f"{case.ref}: stored {stored}, expected {expected}"
            assert record.grade == reported[case.ref]["grade"]
            assert record.score == reported[case.ref]["score"]

        assert session.get(ImageRecord, reported[GOLDEN.ref]["id"]).grade == "A"  # type: ignore[union-attr]
        runs = {
            r.scanner: r.status
            for r in session.exec(
                select(ScannerRunRecord).where(ScannerRunRecord.scan_id == scan.id)
            )
        }
    assert runs.get("filesystem") in {"ok", "unavailable"}  # recorded either way


def test_report_reads_back_what_scan_stored(
    build: Callable[[ImageCase], str], isettings: Settings, tmp_path: Path
) -> None:
    ref = build(GOLDEN)
    config = support.write_config(isettings, tmp_path / "config.toml")
    scanned = support.run_cli(config, "scan", ref, "--skip-cve", "--json")
    assert scanned.returncode == 0, scanned.stderr[-1500:]

    report = support.run_cli(config, "report", ref, "--json")  # a separate process: DB only
    assert report.returncode == 0, report.stderr[-1500:]
    (image,) = json.loads(report.stdout)
    assert image["grade"] == "A" and ref in image["tags"]


def test_a_second_scan_adds_history_instead_of_replacing_it(
    build: Callable[[ImageCase], str], isettings: Settings, tmp_path: Path
) -> None:
    ref = build(GOLDEN)
    config = support.write_config(isettings, tmp_path / "config.toml")
    for _ in range(2):
        assert support.run_cli(config, "scan", ref, "--skip-cve").returncode == 0
    with Session(make_engine(isettings.database.path)) as session:
        scans = session.exec(select(ScanRecord)).all()
    assert len(scans) == 2 and all(s.status == "completed" for s in scans)


@pytest.mark.skipif(support.IS_ROOT, reason="rootless behaviour: run this suite as a regular user")
def test_rootless_user_in_rootful_mode_skips_mount_rules_with_a_reason(
    build: Callable[[ImageCase], str], isettings: Settings
) -> None:
    isettings.podman.mode = "rootful"  # a non-root user asking for root-only mounts
    refs = [build(c) for c in (*_cases("PS-001", "PS-010"),)]
    summary = support.scan(isettings, all_images=True)

    fs = summary.scanners["filesystem"]
    assert fs.status == "unavailable"
    assert "not running as root" in fs.detail and "rootless" in fs.detail
    assert summary.status == "completed"  # the scan carries on without the mount rules
    seen = {r.image.repo_tags[0]: support.rule_ids(r) for r in summary.results if r.image.repo_tags}
    assert "PS-001" in seen[refs[0]]
    assert not (set().union(*seen.values()) & MOUNT_RULES)


@pytest.mark.skipif(support.IS_ROOT, reason="rootless behaviour: run this suite as a regular user")
def test_rootless_mode_mounts_through_podman_unshare(
    build: Callable[[ImageCase], str], isettings: Settings
) -> None:
    (case,) = _cases("PS-010")
    result = support.scan_one(isettings, build(case))  # isettings.podman.mode == "rootless"
    assert support.rule_ids(result) == {"PS-010"}, "setuid binary not found via `podman unshare`"
