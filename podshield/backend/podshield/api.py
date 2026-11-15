"""HTTP API routes (everything lives under /api)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import time
from collections.abc import AsyncIterator, Iterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlmodel import Session

from podshield import __version__, queries
from podshield.api_models import (
    ContainerOut,
    FindingOut,
    ImageDetail,
    ImageSummary,
    Overview,
    RegistryOut,
    RegistryRequest,
    RuleOut,
    RulePatch,
    ScanCreated,
    ScanDetail,
    ScanOut,
    ScanRequest,
)
from podshield.config import Settings
from podshield.models import ScanRecord
from podshield.orchestrator import ProgressEvent
from podshield.overrides import RuleStore
from podshield.podman_client import PodmanError
from podshield.reports import CONTENT_SECURITY_POLICY, render_report
from podshield.sanitize import sanitize_image
from podshield.scan_manager import TERMINAL_STAGES, ScanManager
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.hygiene import rule_catalog
from podshield.scanners.registry import RegistryAuditor
from podshield.scanners.runtime import audit_containers
from podshield.scanners.status import scanner_statuses

router = APIRouter(prefix="/api")

SSE_POLL_SECONDS = 0.25
SSE_KEEPALIVE_SECONDS = 15.0


# ------------------------------------------------------------------------ dependencies


def get_session(request: Request) -> Iterator[Session]:
    with Session(request.app.state.engine) as session:
        yield session


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


def _find_image(session: Session, reference: str) -> Any:
    try:
        rec = queries.resolve_image(session, reference)
    except queries.AmbiguousReferenceError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if rec is None:
        raise HTTPException(status_code=404, detail=f"image not found: {reference}")
    return rec


# ---------------------------------------------------------------------------- overview


@router.get("/overview", response_model=Overview)
def get_overview(session: SessionDep, settings: SettingsDep) -> Overview:
    return queries.overview(session, settings)


# ----------------------------------------------------------------------------- images


@router.get("/images", response_model=list[ImageSummary])
def list_images(
    session: SessionDep,
    q: Annotated[str | None, Query(max_length=200)] = None,
    grade: Annotated[str | None, Query(pattern="^[A-Fa-f]$")] = None,
) -> list[ImageSummary]:
    return queries.list_images(session, q, grade)


@router.get("/images/{image_id}", response_model=ImageDetail)
def get_image(image_id: str, session: SessionDep) -> ImageDetail:
    return queries.image_detail(session, _find_image(session, image_id))


@router.get("/reports/{image_ref}.html", response_class=HTMLResponse)
def get_report(image_ref: str, session: SessionDep) -> HTMLResponse:
    """Standalone report. Use the image ID: repo tags may contain slashes."""
    detail = queries.image_detail(session, _find_image(session, image_ref))
    filename = re.sub(r"[^A-Za-z0-9._-]", "_", f"podshield-{detail.short_id}.html")
    return HTMLResponse(
        render_report(detail),
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "X-Content-Type-Options": "nosniff",
        },
    )


# ------------------------------------------------------------------------------ scans


@router.post("/scans", response_model=ScanCreated, status_code=202)
def create_scan(body: ScanRequest, request: Request) -> ScanCreated:
    manager: ScanManager = request.app.state.scan_manager
    scan_id = manager.submit(body.image, body.all, body.skip_filesystem, body.skip_cve)
    return ScanCreated(scan_id=scan_id, status="queued")


@router.get("/scans", response_model=list[ScanOut])
def list_scans(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[ScanOut]:
    return queries.list_scans(session, limit)


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, session: SessionDep) -> ScanDetail:
    detail = queries.scan_detail(session, scan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")
    return detail


def _sse(event: ProgressEvent, event_id: int) -> str:
    payload = json.dumps(dataclasses.asdict(event))
    return f"id: {event_id}\nevent: progress\ndata: {payload}\n\n"


@router.get("/scans/{scan_id}/stream")
async def stream_scan(
    scan_id: int,
    request: Request,
    last_event_id: Annotated[str | None, Header()] = None,
) -> StreamingResponse:
    """Server-sent events. Replays buffered events, so late or reconnecting clients catch up."""
    manager: ScanManager = request.app.state.scan_manager
    engine = request.app.state.engine

    def record_state() -> tuple[str, int, str] | None:
        with Session(engine) as session:
            rec = session.get(ScanRecord, scan_id)
            return None if rec is None else (rec.status, rec.images_scanned, rec.error or "")

    if manager.events_since(scan_id, 0) is None and record_state() is None:
        raise HTTPException(status_code=404, detail=f"scan not found: {scan_id}")

    try:
        # A negative id would make events[index:] slice from the end; clamp to the start.
        index = max(int(last_event_id) + 1, 0) if last_event_id is not None else 0
    except ValueError:
        index = 0

    async def events() -> AsyncIterator[str]:
        nonlocal index
        last_sent = time.monotonic()
        while True:
            if await request.is_disconnected():
                return
            pending = manager.events_since(scan_id, index)
            if pending is None:
                # Not buffered (server restarted or evicted): fall back to the stored record.
                state = record_state()
                if state is None:
                    return
                status, scanned, error = state
                if status in TERMINAL_STAGES:
                    yield _sse(ProgressEvent(scan_id, status, scanned, scanned, message=error), 0)
                    return
                pending = []
            for event in pending:
                yield _sse(event, index)
                index += 1
                last_sent = time.monotonic()
                if event.stage in TERMINAL_STAGES:
                    return
            if not pending:
                buffered = manager.events_since(scan_id, 0)
                if buffered and buffered[-1].stage in TERMINAL_STAGES:
                    return  # finished, and the client is already past its last event
                if time.monotonic() - last_sent >= SSE_KEEPALIVE_SECONDS:
                    yield ": keepalive\n\n"
                    last_sent = time.monotonic()
                await asyncio.sleep(SSE_POLL_SECONDS)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ------------------------------------------------------------------------- containers


@router.get("/containers", response_model=list[ContainerOut])
def list_containers(request: Request, settings: SettingsDep) -> list[ContainerOut]:
    source = request.app.state.source_factory()
    try:
        raw = source.list_containers()
    except PodmanError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        _close(source)
    return [
        ContainerOut(
            id=a.container.id,
            short_id=a.container.short_id,
            name=a.container.name or a.container.short_id,
            image=a.container.image,
            status=a.container.status,
            score=a.score.score,
            grade=a.score.grade,
            findings=[FindingOut.model_validate(f.model_dump()) for f in a.findings],
        )
        for a in audit_containers(raw, settings)
    ]


# --------------------------------------------------------------------------- registry


@router.post("/registry/inspect", response_model=RegistryOut)
def registry_inspect(body: RegistryRequest, request: Request) -> RegistryOut:
    auditor: RegistryAuditor = request.app.state.registry_factory()
    try:
        audit = auditor.audit(body.reference)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ScannerUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"registry audit unavailable: {exc}") from exc
    except ScannerError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    snapshot = sanitize_image(audit.image)
    return RegistryOut(
        reference=audit.reference,
        id=audit.image.id,
        score=audit.score.score,
        grade=audit.score.grade,
        size=audit.image.size,
        created=queries.aware(audit.image.created),
        findings=[FindingOut.model_validate(f.model_dump()) for f in audit.findings],
        skipped_rules=audit.skipped_rules,
        notes=audit.notes,
        layers=queries.layers_from_snapshot(snapshot),
        config={k: v for k, v in snapshot.items() if k not in ("layers", "base_image")},
    )


# ------------------------------------------------------------------------------ rules


def _rule_out(settings: Settings, rule_id: str) -> RuleOut | None:
    for info in rule_catalog(settings):
        if info.id == rule_id:
            return RuleOut(
                id=info.id,
                title=info.title,
                description=info.description,
                kind=info.kind,
                default_severity=info.default_severity,
                severity=info.severity,
                enabled=info.enabled,
            )
    return None


@router.get("/rules", response_model=list[RuleOut])
def list_rules(settings: SettingsDep) -> list[RuleOut]:
    return [
        RuleOut(
            id=i.id,
            title=i.title,
            description=i.description,
            kind=i.kind,
            default_severity=i.default_severity,
            severity=i.severity,
            enabled=i.enabled,
        )
        for i in rule_catalog(settings)
    ]


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def patch_rule(rule_id: str, patch: RulePatch, request: Request, settings: SettingsDep) -> RuleOut:
    if _rule_out(settings, rule_id) is None:
        raise HTTPException(status_code=404, detail=f"unknown rule: {rule_id}")
    store: RuleStore = request.app.state.rule_store
    store.update(
        rule_id,
        enabled=patch.enabled,
        severity=patch.severity,
        fields=set(patch.model_fields_set),
    )
    updated = _rule_out(settings, rule_id)
    if updated is None:  # the rule vanished between the check and the update
        raise HTTPException(status_code=404, detail=f"unknown rule: {rule_id}")
    return updated


# ------------------------------------------------------------------------------ health


@router.get("/health")
def health(request: Request, settings: SettingsDep) -> dict[str, object]:
    source = request.app.state.source_factory()
    try:
        podman_ok = bool(source.ping())
    except Exception:  # noqa: BLE001 - any ping failure means "Podman unreachable"
        podman_ok = False
    finally:
        _close(source)
    return {
        "status": "ok",
        "version": __version__,
        "podman": podman_ok,
        "scanners": {
            s.name: {"available": s.available, "enabled": s.enabled, "detail": s.detail}
            for s in scanner_statuses(settings)
        },
    }


def _close(source: Any) -> None:
    close = getattr(source, "close", None)
    if callable(close):
        close()
