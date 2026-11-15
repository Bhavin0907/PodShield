"""Scan images automatically when Podman reports a pull, build, tag or import.

Design:

* A reader thread consumes ``podman events`` and puts relevant image events on a queue. If the
  stream breaks or the socket goes away it reconnects with exponential backoff, asking Podman
  for events ``since`` the last one it saw, so nothing is missed while it was disconnected.
* The main loop coalesces events per image (a single ``podman pull`` emits several) and
  scans an image once no event for it has arrived for ``debounce_seconds``.
* A failing scan is logged and never stops the watcher.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from podshield.config import WatcherSettings
from podshield.podman_client import get_ci

log = logging.getLogger(__name__)

# Actions that mean "this image no longer exists": drop any scan queued for it.
GONE_ACTIONS = frozenset({"remove", "untag", "delete"})

EventStream = Callable[[int | None], Iterator[dict[str, Any]]]
ScanFn = Callable[[str | None], None]  # None means "scan every image"


@dataclass(frozen=True)
class ImageEvent:
    action: str
    image_id: str
    name: str
    time_nano: int

    @property
    def target(self) -> str:
        """What to hand to the scanner: the image ID when known (stable across re-tags)."""
        return self.image_id or self.name

    @property
    def seconds(self) -> int:
        return self.time_nano // 1_000_000_000


def parse_event(doc: dict[str, Any], actions: frozenset[str] | set[str]) -> ImageEvent | None:
    """Normalize a Podman event; None if it is not an image event we care about.

    Podman's REST API reports both libpod-style (``Action``, ``Actor.ID``) and Docker-style
    (``status``, ``id``) keys depending on version, so all of them are accepted.
    """
    if str(get_ci(doc, "Type", "type") or "").lower() != "image":
        return None
    action = str(get_ci(doc, "Action", "Status", "status") or "").lower()
    if action not in actions and action not in GONE_ACTIONS:
        return None
    actor = get_ci(doc, "Actor") or {}
    attrs = (get_ci(actor, "Attributes") or {}) if isinstance(actor, dict) else {}
    image_id = str(
        get_ci(doc, "ID", "id") or (get_ci(actor, "ID") if isinstance(actor, dict) else "") or ""
    )
    name = str(get_ci(doc, "Name", "name") or get_ci(attrs, "name") or "")
    time_nano = get_ci(doc, "timeNano")
    if not isinstance(time_nano, int):
        seconds = get_ci(doc, "time", "Time")
        time_nano = int(seconds) * 1_000_000_000 if isinstance(seconds, int | float) else 0
    if not image_id and not name:
        return None
    return ImageEvent(action, image_id, name, time_nano)


class Watcher:
    def __init__(
        self,
        settings: WatcherSettings,
        event_stream: EventStream,
        scan: ScanFn,
        *,
        before_scan: Callable[[], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_backoff: float = 60.0,
        poll_seconds: float = 0.5,
    ) -> None:
        self.settings = settings
        self._stream = event_stream
        self._scan = scan
        self._before_scan = before_scan
        self._clock = clock
        self._max_backoff = max_backoff
        self._poll = poll_seconds
        self._actions = {a.lower() for a in settings.actions}
        self._queue: queue.Queue[ImageEvent] = queue.Queue()
        self._seen: deque[tuple[str, str, int]] = deque(maxlen=512)
        self.stop = threading.Event()

    # ------------------------------------------------------------------ reader thread

    def _read_forever(self) -> None:
        since: int | None = None
        backoff = 1.0
        while not self.stop.is_set():
            try:
                for doc in self._stream(since):
                    backoff = 1.0  # connected and receiving
                    event = parse_event(doc, self._actions)
                    if event is None:
                        continue
                    since = max(since or 0, event.seconds) or since
                    key = (event.action, event.target, event.time_nano)
                    if event.time_nano and key in self._seen:
                        continue  # replayed by `since` after a reconnect
                    self._seen.append(key)
                    self._queue.put(event)
                    if self.stop.is_set():
                        return
                if self.stop.is_set():
                    return
                log.info("podman event stream ended, reconnecting")
            except Exception as exc:  # noqa: BLE001 - the reader must survive anything
                if self.stop.is_set():
                    return
                log.warning(
                    "podman event stream failed, retrying",
                    extra={"error": str(exc), "retry_in_seconds": backoff},
                )
            self.stop.wait(backoff)
            backoff = min(backoff * 2, self._max_backoff)

    # -------------------------------------------------------------------- main loop

    def run(self) -> None:
        """Block until ``stop`` is set."""
        reader = threading.Thread(target=self._read_forever, name="podman-events", daemon=True)
        reader.start()
        log.info(
            "watcher started",
            extra={
                "actions": sorted(self._actions),
                "debounce_seconds": self.settings.debounce_seconds,
            },
        )
        if self.settings.scan_on_start:
            self._run_scan(None)

        pending: dict[str, float] = {}  # target -> time at which it becomes due
        while not self.stop.is_set():
            now = self._clock()
            wait = self._poll
            if pending:
                wait = max(0.0, min(wait, min(pending.values()) - now))
            try:
                event = self._queue.get(timeout=wait)
            except queue.Empty:
                event = None
            if event is not None:
                self._accept(event, pending)
                continue  # drain the queue before deciding what is due

            now = self._clock()
            for target in [t for t, due in pending.items() if due <= now]:
                del pending[target]
                if self.stop.is_set():
                    break
                self._run_scan(target)
        log.info("watcher stopped")

    def _accept(self, event: ImageEvent, pending: dict[str, float]) -> None:
        log.info("image event", extra={"action": event.action, "image": event.target[:19]})
        if event.action in GONE_ACTIONS:
            pending.pop(event.target, None)
            return
        pending[event.target] = self._clock() + self.settings.debounce_seconds

    def _run_scan(self, target: str | None) -> None:
        label = target or "all"
        try:
            if self._before_scan:
                self._before_scan()
            log.info("watcher scan starting", extra={"target": label[:19]})
            self._scan(target)
        except Exception:
            log.exception("watcher scan failed", extra={"target": label[:19]})
