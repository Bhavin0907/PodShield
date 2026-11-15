"""`podshield watch` as a real subprocess: a pull, tag or build must trigger a scan within 30 s."""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlmodel import Session, select

from podshield.config import Settings
from podshield.models import ImageRecord, ScanRecord
from tests.integration import support
from tests.integration.support import GOLDEN, RULE_CASES, ImageCase

pytestmark = pytest.mark.integration

DEADLINE_SECONDS = 30
DEBOUNCE_SECONDS = 2
HELLO = "docker.io/library/hello-world:latest"


@dataclass
class Watcher:
    proc: subprocess.Popen[str]
    settings: Settings
    log: list[str] = field(default_factory=list)

    def scans_since(self, since: datetime) -> list[ScanRecord]:
        with Session(support.open_engine(self.settings)) as session:
            return [s for s in session.exec(select(ScanRecord)) if _utc(s.started_at) >= since]

    def wait_for_scan_of(self, tag: str, since: datetime) -> ImageRecord:
        """The image carrying ``tag`` was scanned after ``since``, within the 30 s budget."""
        deadline = time.monotonic() + DEADLINE_SECONDS
        while time.monotonic() < deadline:
            with Session(support.open_engine(self.settings)) as session:
                for record in session.exec(select(ImageRecord)):
                    if (
                        tag in record.repo_tags
                        and record.last_scanned_at
                        and (_utc(record.last_scanned_at) >= since)
                    ):
                        return record
            time.sleep(1)
        tail = "\n".join(self.log[-15:])
        raise AssertionError(f"no scan of {tag} within {DEADLINE_SECONDS}s. Watcher log:\n{tail}")


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)  # SQLite drops tzinfo


@pytest.fixture
def watcher(
    build: Callable[[ImageCase], str], isettings: Settings, tmp_path: Path
) -> Iterator[Watcher]:
    for case in (GOLDEN, *[c for c in RULE_CASES if c.rule == "PS-001"]):
        build(case)  # built first: the builds themselves must not be what we are measuring
    isettings.watcher.debounce_seconds = DEBOUNCE_SECONDS
    config = support.write_config(isettings, tmp_path / "config.toml")
    proc = subprocess.Popen(
        support.cli_command(config, "watch", "--debounce", str(DEBOUNCE_SECONDS), "--skip-cve"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    handle = Watcher(proc, isettings)
    ready = threading.Event()

    def pump() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            handle.log.append(line.rstrip())
            if "watcher started" in line:
                ready.set()

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    try:
        if not ready.wait(30):
            pytest.fail(
                "podshield watch did not start within 30 s:\n" + "\n".join(handle.log[-10:])
            )
        time.sleep(3)  # let the event stream connect before provoking events
        yield handle
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        thread.join(timeout=5)
        if proc.stderr:
            proc.stderr.close()


def test_tagging_an_image_triggers_a_scan(watcher: Watcher) -> None:
    tag = f"localhost/{support.PREFIX}watched:1.0.0"
    since = datetime.now(UTC)
    support.podman("tag", GOLDEN.ref, tag)
    record = watcher.wait_for_scan_of(tag, since)
    assert record.grade == "A"

    time.sleep(DEBOUNCE_SECONDS + 6)  # PodShield's own mounts must not cause more scans
    assert len(watcher.scans_since(since)) == 1, watcher.log[-10:]


def test_building_an_image_triggers_a_scan(watcher: Watcher) -> None:
    (case,) = [c for c in RULE_CASES if c.rule == "PS-001"]
    tag = f"localhost/{support.PREFIX}watch-build:1.0.0"
    since = datetime.now(UTC)
    support.podman(
        "build",
        "--format",
        "docker",
        "-t",
        tag,
        "-f",
        str(case.containerfile),
        "--build-arg",
        f"BASE={support.BASE_REF}",
        str(support.IMAGES_DIR),
    )
    record = watcher.wait_for_scan_of(tag, since)
    assert record.grade != "A"  # it runs as root (PS-001)


@pytest.mark.requires_network
def test_pulling_an_image_triggers_a_scan(
    watcher: Watcher, pull_image: Callable[[str], str]
) -> None:
    pull_image(HELLO)  # remembered for removal if the suite had to download it
    since = datetime.now(UTC)
    support.podman("pull", HELLO, timeout=300)  # emits a pull event even when up to date
    watcher.wait_for_scan_of(HELLO, since)


def test_removing_a_tagged_image_does_not_stop_the_watcher(watcher: Watcher) -> None:
    since = datetime.now(UTC)
    support.podman("tag", GOLDEN.ref, f"localhost/{support.PREFIX}gone:1.0.0")
    support.podman(
        "rmi", f"localhost/{support.PREFIX}gone:1.0.0"
    )  # an untag event; any queued scan is dropped
    support.podman("tag", GOLDEN.ref, f"localhost/{support.PREFIX}after:1.0.0")
    watcher.wait_for_scan_of(f"localhost/{support.PREFIX}after:1.0.0", since)
    assert watcher.proc.poll() is None, "watcher exited"
