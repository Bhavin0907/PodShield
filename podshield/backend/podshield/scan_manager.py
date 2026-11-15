"""Runs scans in the background and buffers their progress events for SSE clients.

Scans are executed one at a time (a single worker thread); extra requests wait in a queue.
Events are kept in memory per scan, so a client that connects late, or reconnects, replays
everything from the start.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import Engine

from podshield.config import Settings
from podshield.orchestrator import Orchestrator, ProgressEvent
from podshield.podman_client import ImageSource, PodmanError

log = logging.getLogger(__name__)

TERMINAL_STAGES = {"completed", "failed"}


OrchestratorBuilder = Callable[
    [ImageSource, Callable[[ProgressEvent], None], bool, bool], Orchestrator
]


class ScanManager:
    def __init__(
        self,
        settings: Settings,
        engine: Engine,
        source_factory: Callable[[], ImageSource],
        orchestrator_builder: OrchestratorBuilder,
        keep_scans: int = 50,
    ) -> None:
        self.settings = settings
        self.engine = engine
        self._source_factory = source_factory
        self._build = orchestrator_builder
        self._keep = keep_scans
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="podshield-scan")
        self._events: OrderedDict[int, list[ProgressEvent]] = OrderedDict()
        self._active: set[int] = set()
        self._lock = threading.Lock()

    def active_scan_ids(self) -> set[int]:
        """Scans this manager has queued or is running (alive even without a heartbeat)."""
        with self._lock:
            return set(self._active)

    # ------------------------------------------------------------------ submission

    def submit(
        self,
        image: str | None,
        scan_all: bool,
        skip_filesystem: bool = False,
        skip_cve: bool = False,
    ) -> int:
        """Create a scan, queue it, and return its ID immediately."""
        source = self._source_factory()
        orch = self._build(source, self._record, skip_filesystem, skip_cve)
        scan_id = orch.begin(image, scan_all, status="queued")
        with self._lock:
            self._active.add(scan_id)
        self._record(ProgressEvent(scan_id, "queued", message="all" if scan_all else str(image)))
        self._executor.submit(self._run, orch, source, scan_id, image, scan_all)
        return scan_id

    def _run(
        self,
        orch: Orchestrator,
        source: ImageSource,
        scan_id: int,
        image: str | None,
        scan_all: bool,
    ) -> None:
        try:
            orch.run(scan_id, image, scan_all)
        except PodmanError:
            pass  # the orchestrator already recorded the failure and emitted the event
        except Exception as exc:
            log.exception("scan crashed", extra={"scan_id": scan_id})
            try:
                orch.mark_failed(scan_id, f"{type(exc).__name__}: {exc}")
            except Exception:
                log.exception("could not mark scan as failed", extra={"scan_id": scan_id})
        finally:
            with self._lock:
                self._active.discard(scan_id)
            close = getattr(source, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    log.exception("closing podman client failed")

    # ---------------------------------------------------------------------- events

    def _record(self, event: ProgressEvent) -> None:
        with self._lock:
            events = self._events.setdefault(event.scan_id, [])
            events.append(event)
            self._events.move_to_end(event.scan_id)
            while len(self._events) > self._keep:
                self._events.popitem(last=False)

    def events_since(self, scan_id: int, index: int) -> list[ProgressEvent] | None:
        """Events from ``index`` onward, or None if this scan is not buffered."""
        with self._lock:
            events = self._events.get(scan_id)
            return None if events is None else events[index:]

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
