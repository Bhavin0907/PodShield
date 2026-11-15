from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from podshield.config import Settings
from podshield.models import (
    FindingRecord,
    ImageRecord,
    ImageScanRecord,
    ScanHeartbeatRecord,
    ScanRecord,
)
from podshield.orchestrator import (
    Orchestrator,
    ProgressEvent,
    _Heartbeat,
    fail_stale_scans,
    latest_reports,
)
from podshield.podman_client import ImageNotFoundError, PodmanError
from podshield.schemas import ImageInfo
from tests.conftest import FakeSource


def test_scan_all_persists_results(
    engine: Engine, settings: Settings, bad_image: ImageInfo, good_image: ImageInfo
) -> None:
    events: list[ProgressEvent] = []
    orch = Orchestrator(FakeSource([bad_image, good_image]), engine, settings, events.append)
    summary = orch.scan(scan_all=True)

    assert summary.status == "completed"
    assert len(summary.results) == 2
    by_id = {r.image.id: r for r in summary.results}
    assert by_id[good_image.id].score.grade == "A"
    assert by_id[bad_image.id].score.grade in {"D", "F"}

    with Session(engine) as s:
        scan = s.get(ScanRecord, summary.scan_id)
        assert scan and scan.status == "completed" and scan.images_scanned == 2
        assert scan.finished_at is not None
        assert len(s.exec(select(ImageRecord)).all()) == 2
        assert len(s.exec(select(ImageScanRecord)).all()) == 2
        rules = {f.rule_id for f in s.exec(select(FindingRecord)).all()}
        assert {"PS-001", "PS-002", "PS-003", "PS-005", "PS-011", "PS-012"} <= rules

    assert next(e.stage for e in events) == "started"
    assert [e.stage for e in events][-1] == "completed"
    assert sum(e.stage == "image_done" for e in events) == 2


def test_stored_findings_never_contain_raw_secrets(
    engine: Engine, settings: Settings, bad_image: ImageInfo
) -> None:
    Orchestrator(FakeSource([bad_image]), engine, settings).scan(image="localhost/demo-bad:latest")
    with Session(engine) as s:
        blob = " ".join(
            " ".join(f.evidence) + f.description for f in s.exec(select(FindingRecord)).all()
        )
    assert "hunter2-super-secret" not in blob
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_rescan_updates_image_and_keeps_history(
    engine: Engine, settings: Settings, bad_image: ImageInfo
) -> None:
    orch = Orchestrator(FakeSource([bad_image]), engine, settings)
    first = orch.scan(scan_all=True)
    bad_image.user = "1001"  # fix PS-001
    second = orch.scan(scan_all=True)

    with Session(engine) as s:
        assert len(s.exec(select(ImageRecord)).all()) == 1
        assert len(s.exec(select(ImageScanRecord)).all()) == 2
        img = s.get(ImageRecord, bad_image.id)
        assert img and img.last_scan_id == second.scan_id
    assert second.results[0].score.score > first.results[0].score.score

    (report,) = latest_reports(engine)
    assert report.image.last_scan_id == second.scan_id
    assert "PS-001" not in {f.rule_id for f in report.findings}


def test_scan_single_image_not_found(engine: Engine, settings: Settings) -> None:
    orch = Orchestrator(FakeSource([]), engine, settings)
    with pytest.raises(ImageNotFoundError):
        orch.scan(image="nope")
    with Session(engine) as s:
        scan = s.exec(select(ScanRecord)).one()
        assert scan.status == "failed" and "nope" in (scan.error or "")


def test_one_bad_image_does_not_abort_fleet(
    engine: Engine,
    settings: Settings,
    bad_image: ImageInfo,
    good_image: ImageInfo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    orch = Orchestrator(FakeSource([bad_image, good_image]), engine, settings)
    original = orch._scan_image

    def flaky(scan_id: int, info: ImageInfo, rules: list, vulns: list) -> object:  # type: ignore[type-arg]
        if info.id == bad_image.id:
            raise RuntimeError("disk on fire")
        return original(scan_id, info, rules, vulns)

    monkeypatch.setattr(orch, "_scan_image", flaky)
    summary = orch.scan(scan_all=True)
    assert summary.status == "completed"
    assert len(summary.results) == 1
    assert "disk on fire" in summary.errors[0]


def test_podman_unavailable_marks_scan_failed(engine: Engine, settings: Settings) -> None:
    class Down:
        def list_images(self) -> list[ImageInfo]:
            raise PodmanError("socket down")

        def get_image(self, reference: str) -> ImageInfo:
            raise PodmanError("socket down")

    with pytest.raises(PodmanError):
        Orchestrator(Down(), engine, settings).scan(scan_all=True)
    with Session(engine) as s:
        assert s.exec(select(ScanRecord)).one().status == "failed"


def test_requires_exactly_one_target(engine: Engine, settings: Settings) -> None:
    orch = Orchestrator(FakeSource([]), engine, settings)
    with pytest.raises(ValueError):
        orch.scan()
    with pytest.raises(ValueError):
        orch.scan(image="x", scan_all=True)


def test_disabled_rule_produces_no_findings(
    engine: Engine, settings: Settings, bad_image: ImageInfo
) -> None:
    from podshield.config import RuleOverride

    settings.rules["PS-003"] = RuleOverride(enabled=False)
    summary = Orchestrator(FakeSource([bad_image]), engine, settings).scan(scan_all=True)
    assert "PS-003" not in {f.rule_id for f in summary.results[0].findings}


def test_latest_reports_reference_filter(
    engine: Engine, settings: Settings, bad_image: ImageInfo, good_image: ImageInfo
) -> None:
    Orchestrator(FakeSource([bad_image, good_image]), engine, settings).scan(scan_all=True)
    assert len(latest_reports(engine)) == 2
    assert len(latest_reports(engine, "localhost/demo-bad")) == 1
    assert len(latest_reports(engine, bad_image.id[:8])) == 1
    assert latest_reports(engine, "missing") == []


# ------------------------------------------------------------------ scan liveness heartbeat


def _scan(engine: Engine, status: str, age_seconds: float) -> int:
    started = datetime.now(UTC) - timedelta(seconds=age_seconds)
    with Session(engine) as s:
        rec = ScanRecord(target="all", status=status, started_at=started)
        s.add(rec)
        s.commit()
        assert rec.id is not None
        return rec.id


def _status(engine: Engine, scan_id: int) -> str:
    with Session(engine) as s:
        rec = s.get(ScanRecord, scan_id)
        assert rec is not None
        return rec.status


def _beat(engine: Engine, scan_id: int, age_seconds: float) -> None:
    with Session(engine) as s:
        s.add(
            ScanHeartbeatRecord(
                scan_id=scan_id, updated_at=datetime.now(UTC) - timedelta(seconds=age_seconds)
            )
        )
        s.commit()


def test_fresh_heartbeat_keeps_a_scan_alive_even_if_started_long_ago(engine: Engine) -> None:
    scan_id = _scan(engine, "running", age_seconds=3600)
    _beat(engine, scan_id, age_seconds=5)
    assert fail_stale_scans(engine) == 0
    assert _status(engine, scan_id) == "running"


def test_stale_heartbeat_or_no_heartbeat_fails_the_scan(engine: Engine) -> None:
    stale = _scan(engine, "running", age_seconds=3600)
    _beat(engine, stale, age_seconds=600)
    never_beat = _scan(engine, "queued", age_seconds=3600)
    assert fail_stale_scans(engine) == 2
    assert _status(engine, stale) == "failed" and _status(engine, never_beat) == "failed"
    with Session(engine) as s:
        assert s.exec(select(ScanHeartbeatRecord)).all() == []
        rec = s.get(ScanRecord, stale)
        assert rec is not None and rec.finished_at is not None
        assert "interrupted" in (rec.error or "")


def test_just_started_scan_without_heartbeat_gets_the_grace_period(engine: Engine) -> None:
    scan_id = _scan(engine, "running", age_seconds=1)
    assert fail_stale_scans(engine) == 0
    assert _status(engine, scan_id) == "running"


def test_excluded_scans_are_left_alone(engine: Engine) -> None:
    scan_id = _scan(engine, "queued", age_seconds=3600)
    assert fail_stale_scans(engine, exclude={scan_id}) == 0
    assert _status(engine, scan_id) == "queued"


def test_finished_scan_does_not_leave_a_heartbeat(
    engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    orch = Orchestrator(FakeSource([good_image]), engine, settings)
    scan_id = orch.begin(None, True)
    with Session(engine) as s:
        assert s.get(ScanHeartbeatRecord, scan_id) is not None  # alive while running
    orch.run(scan_id, None, True)
    with Session(engine) as s:
        assert s.get(ScanHeartbeatRecord, scan_id) is None
    assert _status(engine, scan_id) == "completed"


def test_heartbeat_thread_refreshes_while_running(engine: Engine) -> None:
    scan_id = _scan(engine, "running", age_seconds=0)
    with _Heartbeat(engine, scan_id, interval=0.05):
        time.sleep(0.3)
        with Session(engine) as s:
            first = s.get(ScanHeartbeatRecord, scan_id)
            assert first is not None
            stamp = first.updated_at
        time.sleep(0.2)
        with Session(engine) as s:
            later = s.get(ScanHeartbeatRecord, scan_id)
            assert later is not None and later.updated_at > stamp
