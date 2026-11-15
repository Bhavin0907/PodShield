"""T5: what happens when the world misbehaves (Podman, disk, database) and how scans scale."""

from __future__ import annotations

import ast
import json
import sqlite3
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, event, text
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, func, select

from podshield import cli
from podshield.config import Settings, load_settings
from podshield.db import DatabaseProblem, explain_db_error, init_db, make_engine
from podshield.main import create_app, create_default_app
from podshield.models import ImageRecord, ImageScanRecord, ScannerRunRecord, ScanRecord
from podshield.orchestrator import Orchestrator, ProgressEvent, fail_stale_scans
from podshield.podman_client import PodmanError, PodmanUnavailable
from podshield.scanners import mount
from podshield.scanners.base import ScannerError, ScannerImageGone
from podshield.schemas import FilesystemReport, ImageInfo, Severity, Vulnerability
from tests.conftest import FakeSource, trust_toml
from tests.test_api import ApiSource, cves, stream_events


def clone(image: ImageInfo, letter: str, *, env_vars: int = 0) -> ImageInfo:
    update: dict[str, Any] = {
        "id": "sha256:" + letter * 64,
        "repo_tags": [f"localhost/pstest-{letter}:1.0"],
    }
    if env_vars:
        update["env"] = [f"PSTEST_VAR_{i}={'x' * 60}" for i in range(env_vars)]
    return image.model_copy(deep=True, update=update)


@pytest.fixture
def build(
    settings: Settings, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., TestClient]:
    monkeypatch.setattr("podshield.main.find_static_dir", lambda _s: None)

    def factory(
        source: Any, fs: Any = None, cve: Any = None, eng: Engine | None = None
    ) -> TestClient:
        app = create_app(
            settings,
            engine=eng or engine,
            source_factory=lambda: source,
            fs_scanner_factory=lambda: fs,
            cve_scanner_factory=lambda: {"oscap": cve or cves},
        )
        return TestClient(app)

    return factory


def post_scan(client: TestClient, **body: Any) -> tuple[int, list[dict[str, Any]]]:
    resp = client.post("/api/scans", json=body)
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]
    return scan_id, stream_events(client, scan_id)


# ====================================================================== Podman socket lost


class SocketSource(ApiSource):
    """Podman that can be switched off, as when `systemctl stop podman.socket` happens."""

    HINT = (
        "Cannot connect to Podman at /run/podman/podman.sock. "
        "Is the socket running? Try: systemctl enable --now podman.socket"
    )

    def __init__(self, images: list[ImageInfo]) -> None:
        super().__init__(images)
        self.up = True

    def list_images(self) -> list[ImageInfo]:
        if not self.up:
            raise PodmanUnavailable(self.HINT)
        return super().list_images()

    def get_image(self, reference: str) -> ImageInfo:
        if not self.up:
            raise PodmanUnavailable(self.HINT)
        return super().get_image(reference)

    def ping(self) -> bool:
        return self.up


def test_socket_down_before_the_scan_fails_cleanly_with_the_fix(
    build: Callable[..., TestClient], good_image: ImageInfo
) -> None:
    source = SocketSource([good_image])
    client = build(source)
    source.up = False
    scan_id, events = post_scan(client, all=True)

    assert events[-1]["stage"] == "failed"
    assert "systemctl enable --now podman.socket" in events[-1]["message"]
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "failed" and "podman.socket" in scan["error"]
    assert scan["finished_at"] is not None
    assert client.get("/api/images").json() == []  # nothing half-saved

    health = client.get("/api/health").json()
    assert health["podman"] is False and health["status"] == "ok"  # the API itself is up


def test_the_service_recovers_when_the_socket_comes_back(
    build: Callable[..., TestClient], good_image: ImageInfo
) -> None:
    source = SocketSource([good_image])
    client = build(source)
    source.up = False
    assert post_scan(client, all=True)[1][-1]["stage"] == "failed"
    source.up = True
    _, events = post_scan(client, all=True)
    assert events[-1]["stage"] == "completed"
    assert len(client.get("/api/images").json()) == 1
    assert client.get("/api/health").json()["podman"] is True


def test_socket_down_for_a_single_image_scan(
    build: Callable[..., TestClient], good_image: ImageInfo
) -> None:
    source = SocketSource([good_image])
    client = build(source)
    source.up = False
    _, events = post_scan(client, image=good_image.repo_tags[0])
    assert events[-1]["stage"] == "failed" and "podman.socket" in events[-1]["message"]


class DyingMount:
    """Filesystem scanner that works for N images, then the socket drops."""

    def __init__(self, ok_images: int, exc: Exception) -> None:
        self.ok, self.exc, self.calls = ok_images, exc, 0
        self.lock = threading.Lock()

    def __call__(self, image_id: str) -> FilesystemReport:
        with self.lock:
            self.calls += 1
            n = self.calls
        if n > self.ok:
            raise self.exc
        return FilesystemReport(files_scanned=10)


@pytest.mark.parametrize(
    "exc",
    [
        ScannerError("podman image mount failed: Cannot connect to Podman socket"),
        ConnectionResetError("socket closed"),
        BrokenPipeError("broken pipe"),
        OSError(107, "Transport endpoint is not connected"),
    ],
    ids=["scanner-error", "connection-reset", "broken-pipe", "oserror"],
)
def test_socket_dying_mid_scan_degrades_the_remaining_images_not_the_scan(
    build: Callable[..., TestClient], settings: Settings, good_image: ImageInfo, exc: Exception
) -> None:
    settings.scan.max_concurrent_images = 1  # "mid-scan" needs a defined order
    images = [clone(good_image, c) for c in "abcd"]
    dying = DyingMount(ok_images=2, exc=exc)
    client = build(ApiSource(images), fs=dying)
    scan_id, events = post_scan(client, all=True)

    assert events[-1]["stage"] == "completed"
    assert [e["stage"] for e in events].count("image_done") == 4  # every image still graded
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "completed" and scan["images_scanned"] == 4
    fs = next(s for s in scan["scanners"] if s["scanner"] == "filesystem")
    assert fs["status"] == "failed" and fs["detail"]  # recorded, with the reason
    detail = client.get(f"/api/images/{images[-1].id}").json()
    assert any(s["scanner"] == "filesystem" and s["status"] != "ok" for s in detail["scanners"])
    assert dying.calls == 4, (
        "a failed scanner is retried for later images (unlike an unavailable one)"
    )


def test_every_scanner_failing_is_visible_and_the_scan_still_completes(
    build: Callable[..., TestClient], good_image: ImageInfo
) -> None:
    def broken_cve(_image: ImageInfo) -> list[Vulnerability]:
        raise ScannerError("oscap-podman: cannot connect to socket")

    client = build(
        ApiSource([good_image]),
        fs=DyingMount(0, ScannerError("mount: socket gone")),
        cve=broken_cve,
    )
    scan_id, events = post_scan(client, all=True)
    assert events[-1]["stage"] == "completed"
    names = {
        s["scanner"]: s["status"] for s in client.get(f"/api/scans/{scan_id}").json()["scanners"]
    }
    assert names == {"filesystem": "failed", "oscap": "failed"}


# ======================================================================== image removed mid-scan


class GoneForOne:
    def __init__(self, gone_id: str) -> None:
        self.gone_id, self.seen = gone_id, []  # type: str, list[str]

    def __call__(self, image_id: str) -> FilesystemReport:
        self.seen.append(image_id)
        if image_id == self.gone_id:
            raise ScannerImageGone(f"image {image_id[7:19]} was removed while it was being scanned")
        return FilesystemReport(files_scanned=1)


def test_an_image_deleted_mid_scan_is_skipped_and_the_rest_are_unaffected(
    build: Callable[..., TestClient], engine: Engine, settings: Settings, good_image: ImageInfo
) -> None:
    settings.scan.max_concurrent_images = 1
    images = [clone(good_image, c) for c in "abc"]
    fs = GoneForOne(images[1].id)
    client = build(ApiSource(images), fs=fs)
    scan_id, events = post_scan(client, all=True)

    by_image = {e["image"]: e for e in events if e["stage"] in {"image_done", "image_failed"}}
    assert by_image[images[1].repo_tags[0]]["stage"] == "image_failed"
    assert "removed" in by_image[images[1].repo_tags[0]]["message"]
    assert by_image[images[0].repo_tags[0]]["stage"] == "image_done"
    assert by_image[images[2].repo_tags[0]]["stage"] == "image_done"
    assert events[-1]["stage"] == "completed"

    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "completed" and scan["images_scanned"] == 2
    assert "removed" in scan["error"]  # visible in scan history
    stored = {i["id"] for i in client.get("/api/images").json()}
    assert stored == {images[0].id, images[2].id}, "no ghost entry for the deleted image"
    assert client.get(f"/api/images/{images[1].id}").status_code == 404
    # The scanner was not switched off for the images after it
    assert fs.seen == [i.id for i in images]
    statuses = {s["scanner"]: s["status"] for s in scan["scanners"]}
    assert statuses["filesystem"] == "ok"
    with Session(engine) as s:
        assert s.exec(select(func.count()).select_from(ImageScanRecord)).one() == 2


def test_when_every_image_vanishes_the_scan_fails_with_a_reason(
    build: Callable[..., TestClient], good_image: ImageInfo
) -> None:
    def gone(image_id: str) -> FilesystemReport:
        raise ScannerImageGone("image was removed while it was being scanned")

    client = build(ApiSource([good_image]), fs=gone)
    scan_id, events = post_scan(client, all=True)
    assert events[-1]["stage"] == "failed"
    assert "removed" in client.get(f"/api/scans/{scan_id}").json()["error"]


@pytest.mark.parametrize(
    "stderr",
    [
        "Error: 1234abcd: image not known",
        "Error: no such image: sha256:abcd",
        "Error: unable to find image 'x' locally",
        "Error: image abc not found",
    ],
)
def test_mount_recognises_podman_saying_the_image_is_gone(
    monkeypatch: pytest.MonkeyPatch, stderr: str
) -> None:
    monkeypatch.setattr(
        mount, "_run", lambda cmd, timeout: subprocess.CompletedProcess(cmd, 125, "", stderr)
    )
    with pytest.raises(ScannerImageGone), mount.mounted_image("sha256:" + "a" * 64):
        pass


def test_other_mount_failures_are_still_unavailable_not_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mount,
        "_run",
        lambda cmd, timeout: subprocess.CompletedProcess(cmd, 125, "", "Error: permission denied"),
    )
    with pytest.raises(mount.FilesystemScanUnavailable), mount.mounted_image("sha256:" + "a" * 64):
        pass


def test_rootless_helper_reports_a_removed_image_with_its_own_exit_code(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    settings.podman.mode = "rootless"
    monkeypatch.setattr(
        mount,
        "_run",
        lambda cmd, timeout: subprocess.CompletedProcess(
            cmd, mount.HELPER_IMAGE_GONE, "", "image gone\n"
        ),
    )
    with pytest.raises(ScannerImageGone, match="image gone"):
        mount.FilesystemScanner(settings)("sha256:" + "a" * 64)


def test_rootless_helper_main_maps_image_gone_to_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        mount,
        "_run",
        lambda cmd, timeout: subprocess.CompletedProcess(cmd, 125, "", "image not known"),
    )
    assert mount._helper_main(["sha256:" + "a" * 64]) == mount.HELPER_IMAGE_GONE
    assert "removed" in capsys.readouterr().err


# ==================================================================================== disk full


class SizeLimit:
    """Caps the SQLite file with PRAGMA max_page_count: a real "database or disk is full"."""

    def __init__(self, engine: Engine) -> None:
        self.pages: int | None = None
        engine_ref = engine

        @event.listens_for(engine, "connect")
        def _apply(dbapi_conn: sqlite3.Connection, _rec: object) -> None:
            if self.pages is not None:
                dbapi_conn.execute(f"PRAGMA max_page_count={self.pages}")

        self.engine = engine_ref

    def current_pages(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(text("PRAGMA page_count")).scalar_one())

    def fill_to(self, slack_pages: int) -> None:
        self.pages = self.current_pages() + slack_pages
        self.engine.dispose()  # new connections pick up the limit

    def release(self) -> None:
        self.pages = None
        self.engine.dispose()


@pytest.fixture
def small_disk(tmp_path: Path) -> tuple[Engine, SizeLimit]:
    eng = make_engine((tmp_path / "limited.db").as_posix())
    init_db(eng)
    return eng, SizeLimit(eng)


def test_disk_full_during_a_scan_ends_with_a_failed_event_and_the_fix(
    build: Callable[..., TestClient], small_disk: tuple[Engine, SizeLimit], good_image: ImageInfo
) -> None:
    eng, limit = small_disk
    client = build(ApiSource([good_image]), eng=eng)
    assert post_scan(client, all=True)[1][-1]["stage"] == "completed"

    limit.fill_to(slack_pages=3)
    heavy = [
        clone(good_image, c, env_vars=400) for c in "bcd"
    ]  # snapshots far bigger than the slack
    client2 = build(ApiSource(heavy), eng=eng)
    started = time.monotonic()
    scan_id, events = post_scan(client2, all=True)
    assert time.monotonic() - started < 30, (
        "the stream must end, not wait for a scan that cannot finish"
    )

    assert events[-1]["stage"] == "failed"
    failures = [e for e in events if e["stage"] == "image_failed"]
    assert failures and all(
        "disk" in e["message"].lower() and "full" in e["message"].lower() for e in failures
    )
    assert not any(token in json.dumps(events) for token in ("INSERT", "SELECT", "[SQL"))

    # Reading still works while the disk is full, including the standalone HTML report.
    assert client2.get("/api/images").status_code == 200
    image_id = client2.get("/api/images").json()[0]["id"]
    report = client2.get(f"/api/reports/{image_id}.html")
    assert report.status_code == 200 and "<html" in report.text.lower()

    # The scan record must not stay "running" forever: the sweeper closes it.
    with Session(eng) as s:
        row = s.get(ScanRecord, scan_id)
        assert row is not None
    fail_stale_scans(eng, grace_seconds=0)
    with Session(eng) as s:
        assert s.get(ScanRecord, scan_id).status == "failed"  # type: ignore[union-attr]

    # Free the space and the next scan works.
    limit.release()
    assert post_scan(client2, all=True)[1][-1]["stage"] == "completed"
    with eng.connect() as conn:
        assert conn.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"


def test_disk_full_on_a_write_request_is_a_503_with_guidance_not_a_500(
    build: Callable[..., TestClient], engine: Engine, good_image: ImageInfo
) -> None:
    """Request-level handling. The fault is injected at the DBAPI boundary (a real
    sqlite3.OperationalError), because a tiny row can still fit in an already-allocated page."""
    state = {"full": False}

    @event.listens_for(engine, "before_cursor_execute")
    def _fail(_conn: Any, _cur: Any, statement: str, *_rest: Any) -> None:
        if state["full"] and statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
            raise sqlite3.OperationalError("database or disk is full")

    client = build(ApiSource([good_image]))
    state["full"] = True
    resp = client.patch("/api/rules/PS-001", json={"enabled": False})
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "full" in detail.lower() and "free space" in detail.lower()
    assert "INSERT" not in detail and "Traceback" not in resp.text
    assert client.get("/api/rules").status_code == 200  # still serving reads
    state["full"] = False
    assert client.patch("/api/rules/PS-001", json={"enabled": False}).status_code == 200


def test_full_disk_does_not_lose_earlier_results(
    build: Callable[..., TestClient], small_disk: tuple[Engine, SizeLimit], good_image: ImageInfo
) -> None:
    eng, limit = small_disk
    client = build(ApiSource([good_image]), eng=eng)
    post_scan(client, all=True)
    before = client.get("/api/images").json()
    limit.fill_to(slack_pages=1)
    post_scan(build(ApiSource([clone(good_image, "z", env_vars=500)]), eng=eng), all=True)
    after = client.get("/api/images").json()
    assert [i["id"] for i in before] == [i["id"] for i in after]
    with Session(eng) as s:
        assert s.exec(select(func.count()).select_from(ImageRecord)).one() == 1


def test_explain_db_error_covers_the_known_failure_modes() -> None:
    def err(message: str) -> OperationalError:
        return OperationalError("stmt", {}, sqlite3.OperationalError(message))

    cases = {
        "database or disk is full": "full",
        "attempt to write a readonly database": "restorecon",
        "unable to open database file": "restorecon",
        "database is locked": "locked",
        "file is not a database": "Recovery",
        "database disk image is malformed": "Recovery",
    }
    for message, expected in cases.items():
        text_ = explain_db_error(err(message), "/var/lib/podshield/podshield.db")
        assert text_ and expected in text_, message
        assert "stmt" not in text_
        assert "disable SELinux" not in text_.replace("Do not disable SELinux", "")
    assert explain_db_error(ValueError("nope")) is None
    assert explain_db_error(err("something else entirely")) is not None  # generic, never raw SQL


# =============================================================================== corrupted SQLite


def make_populated_db(path: Path, image: ImageInfo, settings: Settings) -> None:
    eng = make_engine(path.as_posix())
    init_db(eng)
    app = create_app(
        settings,
        engine=eng,
        source_factory=lambda: FakeSource([image]),
        fs_scanner_factory=lambda: None,
        cve_scanner_factory=lambda: {"oscap": cves},
        static_dir=None,
    )
    with TestClient(app) as client:
        assert post_scan(client, all=True)[1][-1]["stage"] == "completed"
    eng.dispose()


GARBAGE = b"this is definitely not a sqlite database\n" * 200


def test_a_file_that_is_not_sqlite_gives_recovery_steps_not_a_traceback(tmp_path: Path) -> None:
    path = tmp_path / "bad.db"
    path.write_bytes(GARBAGE)
    with pytest.raises(DatabaseProblem) as caught:
        init_db(make_engine(path.as_posix()))
    message = str(caught.value)
    assert str(path.as_posix()) in message
    for needle in ("corrupted", "Recovery", "systemctl stop podshield", ".recover", "cp "):
        assert needle in message, needle
    assert "SELECT" not in message and "Traceback" not in message
    assert path.read_bytes() == GARBAGE, "the damaged file must be left untouched for recovery"


def test_a_structurally_damaged_database_is_detected_even_though_it_opens(
    tmp_path: Path, settings: Settings, good_image: ImageInfo
) -> None:
    path = tmp_path / "damaged.db"
    make_populated_db(path, good_image, settings)
    data = bytearray(path.read_bytes())
    assert len(data) > 8192
    data[4096:] = b"\xff" * (len(data) - 4096)  # keep page 1 (the header and schema), ruin the rest
    path.write_bytes(bytes(data))
    with pytest.raises(DatabaseProblem, match="corrupted"):
        init_db(make_engine(path.as_posix()))


def test_a_truncated_database_is_detected(
    tmp_path: Path, settings: Settings, good_image: ImageInfo
) -> None:
    path = tmp_path / "cut.db"
    make_populated_db(path, good_image, settings)
    size = path.stat().st_size
    path.write_bytes(path.read_bytes()[: size // 2])
    with pytest.raises(DatabaseProblem, match="Recovery"):
        init_db(make_engine(path.as_posix()))


def test_an_empty_file_is_just_a_new_database(tmp_path: Path) -> None:
    path = tmp_path / "empty.db"
    path.write_bytes(b"")
    init_db(make_engine(path.as_posix()))  # e.g. `touch podshield.db` by an installer


def test_a_healthy_database_passes_the_check(
    tmp_path: Path, settings: Settings, good_image: ImageInfo
) -> None:
    path = tmp_path / "ok.db"
    make_populated_db(path, good_image, settings)
    init_db(make_engine(path.as_posix()))


def test_the_service_refuses_to_start_on_a_corrupted_database(
    tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bad.db"
    path.write_bytes(GARBAGE)
    settings.database.path = path.as_posix()
    with pytest.raises(DatabaseProblem):
        create_app(settings, static_dir=None)

    monkeypatch.setattr("podshield.main.get_settings", lambda: settings)
    with pytest.raises(SystemExit) as exit_info:
        create_default_app()
    assert "Recovery" in str(exit_info.value) and "corrupted" in str(exit_info.value)


def test_the_cli_reports_a_corrupted_database_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bad.db"
    path.write_bytes(GARBAGE)
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f'[database]\npath = "{path.as_posix()}"\n' + trust_toml(tmp_path), encoding="utf-8"
    )
    code = cli.main(["--config", str(cfg), "report"])
    err = capsys.readouterr().err
    assert code == cli.EXIT_ERROR
    assert "corrupted" in err and "Recovery" in err and "Traceback" not in err


def test_corruption_discovered_while_running_is_a_503_with_recovery_steps(
    build: Callable[..., TestClient], good_image: ImageInfo, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = build(ApiSource([good_image]))
    post_scan(client, all=True)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise OperationalError(
            "SELECT secret_column FROM t",
            {"x": 1},
            sqlite3.DatabaseError("database disk image is malformed"),
        )

    monkeypatch.setattr("podshield.queries.list_images", boom)
    resp = client.get("/api/images")
    assert resp.status_code == 503
    assert "Recovery" in resp.json()["detail"]
    assert "SELECT" not in resp.text and "secret_column" not in resp.text
    assert client.get("/api/health").status_code == 200, "liveness must not depend on the database"


# ===================================================================== bounded concurrency


def test_concurrency_defaults_to_four_and_is_configurable(tmp_path: Path) -> None:
    assert Settings().scan.max_concurrent_images == 4
    cfg = tmp_path / "c.toml"
    cfg.write_text("[scan]\nmax_concurrent_images = 2\n", encoding="utf-8")
    assert load_settings(cfg, env={}).scan.max_concurrent_images == 2


@pytest.mark.parametrize("value", [0, -1, 33, 1000])
def test_concurrency_rejects_out_of_range_values(value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(scan={"max_concurrent_images": value})  # type: ignore[arg-type]


def test_concurrency_rejects_unknown_keys(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text("[scan]\nmax_parallel = 8\n", encoding="utf-8")
    with pytest.raises(Exception, match="max_parallel"):
        load_settings(cfg, env={})


class Probe:
    """Filesystem scanner that records how many images are being processed at once."""

    def __init__(self, hold: float = 0.15) -> None:
        self.hold, self.active, self.peak, self.lock = hold, 0, 0, threading.Lock()
        self.threads: set[str] = set()

    def __call__(self, image_id: str) -> FilesystemReport:
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.threads.add(threading.current_thread().name)
        time.sleep(self.hold)
        with self.lock:
            self.active -= 1
        return FilesystemReport(files_scanned=1)


def run_direct(
    settings: Settings, engine: Engine, images: list[ImageInfo], fs: Any
) -> tuple[Any, list[ProgressEvent]]:
    events: list[ProgressEvent] = []
    orch = Orchestrator(
        FakeSource(images),
        engine,
        settings,
        events.append,
        fs_scanner=fs,
        cve_scanners={"oscap": cves},
    )
    return orch.scan(scan_all=True), events


@pytest.mark.parametrize(("limit", "expected_peak"), [(1, 1), (2, 2), (4, 4)])
def test_never_more_images_in_flight_than_configured(
    settings: Settings, engine: Engine, good_image: ImageInfo, limit: int, expected_peak: int
) -> None:
    settings.scan.max_concurrent_images = limit
    probe = Probe()
    summary, _ = run_direct(settings, engine, [clone(good_image, c) for c in "abcdefgh"], probe)
    assert probe.peak == expected_peak  # reached it, and never went over
    assert summary.status == "completed" and len(summary.results) == 8


def test_default_concurrency_is_four_in_flight(
    settings: Settings, engine: Engine, good_image: ImageInfo
) -> None:
    probe = Probe()
    run_direct(settings, engine, [clone(good_image, c) for c in "abcdefghij"], probe)
    assert probe.peak == 4


def test_fewer_images_than_workers_does_not_oversubscribe(
    settings: Settings, engine: Engine, good_image: ImageInfo
) -> None:
    settings.scan.max_concurrent_images = 16
    probe = Probe()
    run_direct(settings, engine, [clone(good_image, c) for c in "ab"], probe)
    assert probe.peak == 2


def test_parallel_scan_stores_exactly_one_correct_result_per_image(
    settings: Settings, engine: Engine, bad_image: ImageInfo, good_image: ImageInfo, tmp_path: Path
) -> None:
    settings.scan.max_concurrent_images = 4
    images = [clone(bad_image if i % 2 else good_image, chr(97 + i)) for i in range(10)]
    probe = Probe(hold=0.05)
    summary, events = run_direct(settings, engine, images, probe)

    assert [r.image.id for r in summary.results] == [i.id for i in images], (
        "results keep input order"
    )
    with Session(engine) as s:
        rows = s.exec(select(ImageScanRecord)).all()
        assert len(rows) == 10 and len({r.image_id for r in rows}) == 10
        assert s.exec(select(func.count()).select_from(ImageRecord)).one() == 10
        outcomes = {r.scanner: r.status for r in s.exec(select(ScannerRunRecord)).all()}
    assert outcomes == {"filesystem": "ok", "oscap": "ok"}
    # Same input, same grade as a sequential run
    settings.scan.max_concurrent_images = 1
    other = make_engine((tmp_path / "sequential.db").as_posix())
    init_db(other)
    sequential, _ = run_direct(settings, other, images, Probe(hold=0))
    assert [(r.score.score, r.score.grade) for r in summary.results] == [
        (r.score.score, r.score.grade) for r in sequential.results
    ]
    assert summary.scanners["filesystem"].succeeded == 10, "bookkeeping is not lost under threads"
    done = [e.current for e in events if e.stage == "image_done"]
    assert done == list(range(1, 11))


def test_one_failing_image_does_not_stop_the_others_in_parallel(
    settings: Settings, engine: Engine, good_image: ImageInfo
) -> None:
    images = [clone(good_image, c) for c in "abcdef"]
    gone = images[2].id

    def fs(image_id: str) -> FilesystemReport:
        if image_id == gone:
            raise ScannerImageGone("removed")
        time.sleep(0.05)
        return FilesystemReport()

    summary, events = run_direct(settings, engine, images, fs)
    assert summary.status == "completed" and len(summary.results) == 5
    assert [e.stage for e in events].count("image_failed") == 1
    assert [e.current for e in events if e.stage in {"image_done", "image_failed"}] == [
        1,
        2,
        3,
        4,
        5,
        6,
    ]


def test_parallel_scan_is_actually_faster_when_the_work_is_io_bound(
    settings: Settings, engine: Engine, good_image: ImageInfo, tmp_path: Path
) -> None:
    """oscap/trivy are subprocesses (the GIL is released while they run); a sleep stands in."""
    images = [clone(good_image, c) for c in "abcdefgh"]
    settings.scan.max_concurrent_images = 1
    t0 = time.monotonic()
    run_direct(settings, engine, images, Probe(hold=0.2))
    sequential = time.monotonic() - t0
    other = make_engine((tmp_path / "parallel.db").as_posix())
    init_db(other)
    settings.scan.max_concurrent_images = 4
    t0 = time.monotonic()
    run_direct(settings, other, images, Probe(hold=0.2))
    parallel = time.monotonic() - t0
    assert parallel < sequential * 0.6, (sequential, parallel)


def test_an_unavailable_scanner_is_still_skipped_for_the_rest_of_a_parallel_scan(
    settings: Settings, engine: Engine, good_image: ImageInfo
) -> None:
    from podshield.scanners.base import ScannerUnavailable

    calls = []

    def fs(image_id: str) -> FilesystemReport:
        calls.append(image_id)
        raise ScannerUnavailable("podman not found in PATH")

    settings.scan.max_concurrent_images = 1
    summary, _ = run_direct(settings, engine, [clone(good_image, c) for c in "abc"], fs)
    assert len(calls) == 1 and summary.scanners["filesystem"].status == "unavailable"


def test_mark_failed_still_emits_the_event_when_the_database_is_broken(
    settings: Settings, engine: Engine, good_image: ImageInfo, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[ProgressEvent] = []
    orch = Orchestrator(FakeSource([good_image]), engine, settings, events.append)
    monkeypatch.setattr(
        orch, "_finish", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db gone"))
    )
    with pytest.raises(RuntimeError):
        orch.mark_failed(1, "boom")
    assert [e.stage for e in events] == ["failed"] and events[0].message == "boom"


# ====================================================================== static safety audit


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "podshield"
FORBIDDEN_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "eval",
    "exec",
    "pickle.loads",
    "marshal.loads",
}
# Long-lived streams legitimately have no overall timeout: they are read until the daemon exits.
POPEN_ALLOWED: set[str] = set()


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def python_files() -> list[Path]:
    return sorted(p for p in SOURCE_ROOT.rglob("*.py"))


def test_there_is_source_to_audit() -> None:
    assert len(python_files()) > 25


def test_no_shell_true_anywhere_in_the_product() -> None:
    offenders = []
    for path in python_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and not (
                        isinstance(kw.value, ast.Constant) and kw.value.value is False
                    ):
                        offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_no_dangerous_calls_in_the_product() -> None:
    offenders = []
    for path in python_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
            if isinstance(node, ast.Call) and dotted(node.func) in FORBIDDEN_CALLS:
                offenders.append(f"{path.name}:{node.lineno} {dotted(node.func)}")
    assert offenders == []


def test_every_subprocess_call_has_a_timeout_and_a_list_argument() -> None:
    runners = {
        "subprocess.run",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.call",
    }
    offenders = []
    for path in python_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            where = f"{path.name}:{node.lineno}"
            if name in runners:
                if "timeout" not in {k.arg for k in node.keywords}:
                    offenders.append(f"{where} {name} has no timeout")
                first = node.args[0] if node.args else None
                if isinstance(first, ast.Constant | ast.JoinedStr):
                    offenders.append(f"{where} {name} takes a string command")
            if name == "subprocess.Popen" and path.name not in POPEN_ALLOWED:
                offenders.append(f"{where} unreviewed subprocess.Popen")
    assert offenders == []


def test_secrets_are_not_logged_by_the_exception_handlers() -> None:
    """Error text that reaches users or logs must come from explain_db_error, never raw SQL."""
    text_ = explain_db_error(
        OperationalError(
            "INSERT INTO t VALUES (:s)",
            {"s": "AKIAIOSFODNN7EXAMPLE"},
            sqlite3.OperationalError("database or disk is full"),
        ),
        "/db",
    )
    assert text_ and "AKIA" not in text_ and "INSERT" not in text_


def test_severity_enum_is_unchanged_by_the_refactor() -> None:  # guards the grade pipeline inputs
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "info"]


def test_podman_errors_stay_in_one_hierarchy() -> None:
    assert issubclass(PodmanUnavailable, PodmanError)
