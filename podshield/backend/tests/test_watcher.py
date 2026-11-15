from __future__ import annotations

import signal
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from podshield import cli
from podshield.config import WatcherSettings
from podshield.db import make_engine
from podshield.orchestrator import latest_reports
from podshield.schemas import FilesystemReport, ImageInfo
from podshield.watcher import ImageEvent, Watcher, parse_event
from tests.conftest import FakeSource, trust_toml

ACTIONS = {"pull", "tag", "build", "import", "loadfromarchive"}
SECOND = 1_000_000_000


def pull(
    image_id: str = "a" * 64, name: str = "docker.io/library/nginx:latest", t: int = 100
) -> dict[str, Any]:
    return {
        "Type": "image",
        "Action": "pull",
        "Actor": {"ID": image_id, "Attributes": {"name": name}},
        "time": t,
        "timeNano": t * SECOND,
    }


# -------------------------------------------------------------------------- parse_event


def test_parse_libpod_event() -> None:
    ev = parse_event(pull(), ACTIONS)
    assert ev == ImageEvent("pull", "a" * 64, "docker.io/library/nginx:latest", 100 * SECOND)
    assert ev is not None and ev.target == "a" * 64


def test_parse_docker_style_event() -> None:
    ev = parse_event({"status": "tag", "id": "sha256:abc", "Type": "image", "time": 5}, ACTIONS)
    assert ev is not None
    assert (ev.action, ev.image_id, ev.seconds) == ("tag", "sha256:abc", 5)


def test_parse_falls_back_to_name_without_id() -> None:
    ev = parse_event({"Type": "image", "Action": "build", "Name": "localhost/app:1"}, ACTIONS)
    assert ev is not None and ev.target == "localhost/app:1"


@pytest.mark.parametrize(
    "doc",
    [
        {"Type": "container", "Action": "pull", "Actor": {"ID": "x"}},
        {"Type": "image", "Action": "push", "Actor": {"ID": "x"}},
        {"Type": "image", "Action": "pull"},  # nothing to scan
        {},
    ],
)
def test_parse_ignores_irrelevant(doc: dict[str, Any]) -> None:
    assert parse_event(doc, ACTIONS) is None


def test_parse_keeps_removals_so_pending_scans_can_be_dropped() -> None:
    ev = parse_event({"Type": "image", "Action": "remove", "Actor": {"ID": "x"}}, ACTIONS)
    assert ev is not None and ev.action == "remove"


# ----------------------------------------------------------------------------- Watcher


class Script:
    """A fake event stream. Each connection plays the next list; items may be exceptions."""

    def __init__(self, *connections: list[Any]) -> None:
        self.connections = list(connections)
        self.since_args: list[int | None] = []
        self.stop: threading.Event | None = None

    def __call__(self, since: int | None) -> Iterator[dict[str, Any]]:
        self.since_args.append(since)
        if not self.connections:
            assert self.stop is not None
            self.stop.wait(5)  # idle stream
            return
        for item in self.connections.pop(0):
            if isinstance(item, Exception):
                raise item
            yield item


def run_watcher(
    script: Script,
    *,
    until: Callable[[list[str | None]], bool],
    settings: WatcherSettings | None = None,
    failing: set[str] | None = None,
    before_scan: Callable[[], None] | None = None,
    settle: float = 0.15,
) -> list[str | None]:
    """Run a watcher against ``script`` until ``until(scans)``, then stop it; return the scans."""
    scans: list[str | None] = []

    def scan(target: str | None) -> None:
        scans.append(target)
        if target in (failing or set()):
            raise RuntimeError("oscap exploded")

    watcher = Watcher(
        settings or WatcherSettings(debounce_seconds=0.05),
        script,
        scan,
        before_scan=before_scan,
        max_backoff=0.05,
        poll_seconds=0.01,
    )
    script.stop = watcher.stop
    thread = threading.Thread(target=watcher.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not until(scans) and time.monotonic() < deadline:
        time.sleep(0.01)
    met = until(scans)
    time.sleep(settle)  # let any unwanted extra scans show up
    watcher.stop.set()
    thread.join(5)
    assert not thread.is_alive(), "watcher did not stop"
    assert met, f"condition not met; scans so far: {scans}"
    return list(scans)


def test_events_are_coalesced_into_one_scan_per_image() -> None:
    a, b = "a" * 64, "b" * 64
    script = Script([pull(a, t=1), {**pull(a, t=2), "Action": "tag"}, pull(b, t=3), pull(a, t=4)])
    scans = run_watcher(script, until=lambda s: len(s) >= 2)
    assert sorted(str(s) for s in scans) == [a, b]


def test_remove_cancels_a_pending_scan() -> None:
    img = "c" * 64
    gone = {"Type": "image", "Action": "remove", "Actor": {"ID": img}, "timeNano": 2 * SECOND}
    began = time.monotonic()
    scans = run_watcher(
        Script([pull(img, t=1), gone]),
        settings=WatcherSettings(debounce_seconds=0.3),
        until=lambda _s: time.monotonic() - began > 0.6,
    )
    assert scans == []


def test_reconnects_with_since_and_skips_replayed_events() -> None:
    img, other = "d" * 64, "e" * 64
    first = pull(img, t=50)
    script = Script([first, ConnectionError("socket went away")], [first, pull(other, t=51)])
    scans = run_watcher(script, until=lambda s: len(s) >= 2)
    assert script.since_args[0] is None
    assert script.since_args[1] == 50  # resumes from the last event it saw
    assert sorted(str(s) for s in scans) == [img, other]  # img scanned once, not twice


def test_scan_failure_does_not_stop_the_watcher() -> None:
    bad, ok = "1" * 64, "2" * 64
    script = Script([pull(bad, t=1)], [pull(ok, t=2)])
    scans = run_watcher(script, until=lambda s: len(s) >= 2, failing={bad})
    assert scans == [bad, ok]


def test_scan_on_start_and_before_scan_hook() -> None:
    reloads: list[int] = []
    scans = run_watcher(
        Script(),
        settings=WatcherSettings(debounce_seconds=0.05, scan_on_start=True),
        until=lambda s: len(s) >= 1,
        before_scan=lambda: reloads.append(1),
    )
    assert scans == [None]  # None means "all images"
    assert reloads == [1]


def test_unlisted_actions_never_scan() -> None:
    began = time.monotonic()
    scans = run_watcher(
        Script([pull(t=1)]),
        settings=WatcherSettings(debounce_seconds=0.01, actions=["build"]),
        until=lambda _s: time.monotonic() - began > 0.4,
    )
    assert scans == []


# ------------------------------------------------------------------------- cli watch


def test_cli_watch_scans_pulled_image_then_stops_on_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_image: ImageInfo
) -> None:
    cfg = tmp_path / "config.toml"
    db = (tmp_path / "w.db").as_posix()
    cfg.write_text(
        f'[database]\npath = "{db}"\n[watcher]\ndebounce_seconds = 0.05\n' + trust_toml(tmp_path),
        encoding="utf-8",
    )

    class OneShotSource(FakeSource):
        closes = 0

        def close(self) -> None:
            type(self).closes += 1
            signal.raise_signal(signal.SIGTERM)  # simulate `systemctl stop` after the scan

    class FakeEvents:
        def __init__(self, *_a: object) -> None: ...

        def events(self, since: int | None) -> Iterator[dict[str, Any]]:
            yield pull(bad_image.id, name=bad_image.repo_tags[0], t=1)
            time.sleep(30)  # idle (daemon thread); the scan's SIGTERM ends the watcher first

        def close(self) -> None: ...

    source = OneShotSource([bad_image])
    monkeypatch.setattr(cli, "PodmanClient", FakeEvents)
    monkeypatch.setattr(cli, "_make_source", lambda _s: source)
    monkeypatch.setattr(cli, "FilesystemScanner", lambda _s: lambda _id: FilesystemReport())
    monkeypatch.setattr(cli, "_make_cve_scanners", lambda _s: {})

    old_term = signal.getsignal(signal.SIGTERM)
    # safety net so a regression fails the test instead of hanging the suite
    watchdog = threading.Timer(15, lambda: signal.raise_signal(signal.SIGINT))
    watchdog.daemon = True
    watchdog.start()
    began = time.monotonic()
    assert cli.main(["--config", str(cfg), "watch"]) == 0
    watchdog.cancel()
    assert time.monotonic() - began < 10
    assert OneShotSource.closes == 1
    assert signal.getsignal(signal.SIGTERM) is old_term  # handlers restored

    reports = latest_reports(make_engine(db))
    assert [r.image.repo_tags for r in reports] == [bad_image.repo_tags]
