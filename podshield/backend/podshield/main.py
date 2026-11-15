"""FastAPI application: JSON API under /api plus the built frontend at /.

``create_app`` takes optional factories so tests (and embedders) can swap Podman, the
scanners and the database for fakes.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from sqlalchemy import Engine
from sqlalchemy.exc import DatabaseError as SaDatabaseError

from podshield import __version__
from podshield.api import router
from podshield.config import Settings, get_settings
from podshield.db import DatabaseProblem, explain_db_error, init_db, make_engine
from podshield.factory import make_cve_scanners, make_fs_scanner
from podshield.logging_setup import configure_logging
from podshield.orchestrator import (
    STALE_GRACE_SECONDS,
    CveScan,
    FilesystemScan,
    Orchestrator,
    ProgressCallback,
    fail_stale_scans,
)
from podshield.overrides import RuleStore
from podshield.podman_client import ImageSource, PodmanClient
from podshield.scan_manager import ScanManager
from podshield.scanners.registry import RegistryAuditor

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS = 20.0

PLACEHOLDER = """<!doctype html><meta charset="utf-8"><title>PodShield</title>
<body style="font:16px system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem">
<h1>PodShield API is running</h1>
<p>The web UI has not been built. Run <code>npm install &amp;&amp; npm run build</code> in
<code>frontend/</code>, or set <code>server.static_dir</code> in the config file.</p>
<p>API docs: <a href="/api/docs">/api/docs</a></p></body>"""


def find_static_dir(settings: Settings) -> Path | None:
    candidates = []
    if settings.server.static_dir:
        candidates.append(Path(settings.server.static_dir))
    # Source checkout: <project>/backend/podshield/main.py -> <project>/frontend/dist
    candidates.append(Path(__file__).resolve().parents[2] / "frontend" / "dist")
    for path in candidates:
        if (path / "index.html").is_file():
            return path.resolve()
    return None


def _mount_frontend(app: FastAPI, static_dir: Path | None) -> None:
    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> Response:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        if static_dir is None:
            return HTMLResponse(PLACEHOLDER)
        if path:
            candidate = (static_dir / path).resolve()
            # resolve() + is_relative_to() stops ../ and symlink escapes
            if candidate.is_relative_to(static_dir) and candidate.is_file():
                return FileResponse(candidate)
        return FileResponse(static_dir / "index.html")


def create_app(
    settings: Settings | None = None,
    *,
    engine: Engine | None = None,
    source_factory: Callable[[], Any] | None = None,
    fs_scanner_factory: Callable[[], FilesystemScan | None] | None = None,
    cve_scanner_factory: Callable[[], dict[str, CveScan]] | None = None,
    registry_factory: Callable[[], RegistryAuditor] | None = None,
    static_dir: Path | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.logging.level)

    engine = engine or make_engine(settings.database.path)
    init_db(engine)
    stale = fail_stale_scans(engine)
    if stale:
        log.warning("marked %d interrupted scan(s) as failed", stale)
    rule_store = RuleStore(settings, engine)

    src = source_factory or (
        lambda: PodmanClient(settings.podman.socket, settings.podman.timeout_seconds)
    )
    fs_factory = fs_scanner_factory or (lambda: make_fs_scanner(settings))
    cve_factory = cve_scanner_factory or (lambda: make_cve_scanners(settings))
    reg_factory = registry_factory or (lambda: RegistryAuditor(settings))

    def build(
        source: ImageSource, on_progress: ProgressCallback, skip_fs: bool, skip_cve: bool
    ) -> Orchestrator:
        return Orchestrator(
            source,
            engine,
            settings,
            on_progress,
            fs_scanner=None if skip_fs else fs_factory(),
            cve_scanners={} if skip_cve else cve_factory(),
        )

    manager = ScanManager(settings, engine, src, build)

    async def sweep_stale_scans() -> None:
        """Fail scans whose process died (API, CLI, timer or watcher) without finishing."""
        while True:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
            try:
                n = await asyncio.to_thread(
                    fail_stale_scans, engine, STALE_GRACE_SECONDS, manager.active_scan_ids()
                )
                if n:
                    log.warning("marked %d orphaned scan(s) as failed", n)
            except Exception:
                log.exception("stale scan sweep failed")

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        sweeper = asyncio.create_task(sweep_stale_scans())
        try:
            yield
        finally:
            sweeper.cancel()
            manager.shutdown()

    app = FastAPI(
        title="PodShield",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.rule_store = rule_store
    app.state.scan_manager = manager
    app.state.source_factory = src
    app.state.registry_factory = reg_factory

    async def database_error(_request: Request, exc: Exception) -> JSONResponse:
        # Disk full, corrupted file, bad permissions: say what to do instead of a bare 500.
        message = (
            explain_db_error(exc, settings.database.path) or "Database error. See the service log."
        )
        log.error("database error during request", extra={"error": type(exc).__name__})
        return JSONResponse(status_code=503, content={"detail": message})

    app.add_exception_handler(SaDatabaseError, database_error)
    app.add_exception_handler(sqlite3.Error, database_error)
    app.include_router(router)
    _mount_frontend(app, static_dir if static_dir is not None else find_static_dir(settings))
    return app


def create_default_app() -> FastAPI:
    """Uvicorn factory: ``uvicorn --factory podshield.main:create_default_app``.

    Reads the config file; there is deliberately no module-level ``app`` so that importing
    this module never opens the database.
    """
    try:
        return create_app()
    except DatabaseProblem as exc:
        # A clean one-line-per-step message in the journal instead of a traceback.
        raise SystemExit(f"podshield: {exc}") from exc
