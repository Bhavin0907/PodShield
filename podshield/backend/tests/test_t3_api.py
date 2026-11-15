"""T3: the HTTP API, endpoint by endpoint (TestClient on a temp SQLite database).

test_api.py covers behaviour per feature; this module covers the contract systematically:
every route and its status codes and schemas, error handling for unknown IDs and bad input,
SSE ordering, concurrent scans, the standalone report, health reporting, hostile input and
the guarantee that secret values never leave the process.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, TypeAdapter
from sqlalchemy import Engine, text
from sqlmodel import Session, select

from podshield.api_models import (
    ContainerOut,
    ImageDetail,
    ImageSummary,
    Overview,
    RegistryOut,
    RuleOut,
    ScanCreated,
    ScanDetail,
    ScanOut,
)
from podshield.config import Settings
from podshield.main import create_app
from podshield.models import (
    FindingRecord,
    ImageScanRecord,
    ScanHeartbeatRecord,
    ScanRecord,
)
from podshield.scanners.status import ScannerStatus
from podshield.schemas import ImageInfo
from tests.conftest import FakeSource, load_json
from tests.test_api import (
    SECRETS,
    ApiSource,
    MakeApp,
    StubAuditor,
    cves,
    run_scan,
    stream_events,
)

IMAGE_FIELDS = set(ImageSummary.model_fields)


def clone(image: ImageInfo, letter: str) -> ImageInfo:
    """A distinct image (own ID and tag) so one scan covers several."""
    return image.model_copy(
        deep=True,
        update={
            "id": "sha256:" + letter * 64,
            "repo_tags": [f"localhost/pstest-{letter}:1.0"],
        },
    )


def exact(data: Any, model: type[BaseModel]) -> None:
    """The JSON validates against the response model and carries exactly its fields."""
    TypeAdapter(model).validate_python(data)
    assert set(data) == set(model.model_fields), set(data) ^ set(model.model_fields)


def seeded(make_app: MakeApp, *images: ImageInfo, **kwargs: Any) -> tuple[TestClient, int]:
    client = make_app(list(images), **kwargs)
    scan_id, _ = run_scan(client, all=True)
    return client, scan_id


# ============================================================================ route matrix

# (method, path, JSON body, expected status) with {image}/{scan}/{rule} filled in by the test.
MATRIX: list[tuple[str, str, dict[str, Any] | None, int]] = [
    ("GET", "/api/overview", None, 200),
    ("GET", "/api/images", None, 200),
    ("GET", "/api/images/{image}", None, 200),
    ("GET", "/api/reports/{image}.html", None, 200),
    ("POST", "/api/scans", {"all": True, "skip_cve": True}, 202),
    ("GET", "/api/scans", None, 200),
    ("GET", "/api/scans/{scan}", None, 200),
    ("GET", "/api/scans/{scan}/stream", None, 200),
    ("GET", "/api/containers", None, 200),
    ("POST", "/api/registry/inspect", {"reference": "quay.io/x/y:1"}, 200),
    ("GET", "/api/rules", None, 200),
    ("PATCH", "/api/rules/{rule}", {"enabled": True}, 200),
    ("GET", "/api/health", None, 200),
]


def test_the_matrix_covers_every_route(make_app: MakeApp) -> None:
    spec = make_app([]).app.openapi()  # type: ignore[attr-defined]

    def generic(path: str) -> str:  # compare shapes, not parameter names
        return re.sub(r"\{[^}]+\}", "{}", path)

    documented = {(m.upper(), generic(p)) for p, ops in spec["paths"].items() for m in ops}
    tested = {(m, generic(p)) for m, p, _b, _s in MATRIX}
    assert documented == tested, documented ^ tested


@pytest.mark.parametrize(
    ("method", "path", "body", "status"), MATRIX, ids=[f"{m} {p}" for m, p, _b, _s in MATRIX]
)
def test_every_endpoint_answers_with_its_documented_schema(
    make_app: MakeApp,
    settings: Settings,
    bad_image: ImageInfo,
    good_image: ImageInfo,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    status: int,
) -> None:
    client = make_app(
        [bad_image, good_image],
        containers=load_json("containers.json"),
        registry_factory=lambda: StubAuditor(settings, bad_image),
    )
    scan_id, _ = run_scan(client, all=True)
    url = path.format(image=quote(bad_image.id, safe=""), scan=scan_id, rule="PS-001")

    resp = client.request(method, url, json=body)
    assert resp.status_code == status, resp.text[:300]
    data = None if "stream" in path or path.endswith(".html") else resp.json()

    if path == "/api/overview":
        exact(data, Overview)
        exact(data["riskiest"][0], ImageSummary)
    elif path == "/api/images":
        assert len(data) == 2
        for item in data:
            exact(item, ImageSummary)
    elif path == "/api/images/{image}":
        exact(data, ImageDetail)
    elif path == "/api/reports/{image}.html":
        assert resp.headers["content-type"].startswith("text/html")
    elif path == "/api/scans" and method == "POST":
        exact(data, ScanCreated)
        assert data["status"] == "queued"
        stream_events(client, data["scan_id"])  # let it finish before the app is torn down
    elif path == "/api/scans":
        assert len(data) == 1
        exact(data[0], ScanOut)
    elif path == "/api/scans/{scan}":
        exact(data, ScanDetail)
    elif path.endswith("/stream"):
        assert resp.headers["content-type"].startswith("text/event-stream")
    elif path == "/api/containers":
        assert data
        for item in data:
            exact(item, ContainerOut)
    elif path == "/api/registry/inspect":
        exact(data, RegistryOut)
    elif path == "/api/rules":
        for item in data:
            exact(item, RuleOut)
        assert {r["kind"] for r in data} == {"image", "runtime"}
        assert len(data) == 20  # PS-001..015 and PS-R01..R05
    elif path.startswith("/api/rules/"):
        exact(data, RuleOut)
    elif path == "/api/health":
        assert set(data) == {"status", "version", "podman", "scanners"}


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_unsupported_methods_are_405_not_500(make_app: MakeApp, method: str) -> None:
    client = make_app([])
    for path in ("/api/overview", "/api/images", "/api/scans", "/api/health", "/api/rules"):
        if method == "PATCH" and path == "/api/rules":
            continue
        assert client.request(method, path).status_code in (404, 405)


# ====================================================================== unknown ids (404)

UNKNOWN_ID = "sha256:" + "0" * 64


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", f"/api/images/{UNKNOWN_ID}", None),
        ("GET", "/api/images/does-not-exist", None),
        ("GET", f"/api/reports/{UNKNOWN_ID}.html", None),
        ("GET", "/api/reports/nope.html", None),
        ("GET", "/api/scans/987654", None),
        ("GET", "/api/scans/987654/stream", None),
        ("PATCH", "/api/rules/PS-999", {"enabled": False}),
        ("PATCH", "/api/rules/ps-001", {"enabled": False}),  # rule IDs are case-sensitive
    ],
)
def test_unknown_ids_are_404_with_a_json_detail(
    make_app: MakeApp, good_image: ImageInfo, method: str, path: str, body: dict[str, Any] | None
) -> None:
    client, _ = seeded(make_app, good_image)
    resp = client.request(method, path, json=body)
    assert resp.status_code == 404
    if not path.endswith(".html"):
        assert isinstance(resp.json()["detail"], str) and resp.json()["detail"]
    else:
        assert resp.headers["content-type"].startswith("application/json")  # never an HTML page


# ============================================================================ bad input (422)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/api/scans", {}),
        ("POST", "/api/scans", {"all": False}),
        ("POST", "/api/scans", {"all": "yes please"}),
        ("POST", "/api/scans", {"image": ""}),
        ("POST", "/api/scans", {"image": 42}),
        ("POST", "/api/scans", {"image": "alpine", "all": True}),
        ("POST", "/api/scans", {"image": "-v /:/host"}),
        ("POST", "/api/scans", {"all": True, "skip_cve": "maybe"}),
        ("POST", "/api/registry/inspect", {}),
        ("POST", "/api/registry/inspect", {"reference": ""}),
        ("POST", "/api/registry/inspect", {"reference": "x" * 513}),
        ("POST", "/api/registry/inspect", {"reference": ["alpine"]}),
        ("PATCH", "/api/rules/PS-001", {"enabled": "maybe"}),
        ("PATCH", "/api/rules/PS-001", {"severity": "urgent"}),
        ("PATCH", "/api/rules/PS-001", {"severity": 5}),
        ("GET", "/api/scans/abc", None),
        ("GET", "/api/scans/1.5", None),
        ("GET", "/api/scans/abc/stream", None),
        ("GET", "/api/scans?limit=0", None),
        ("GET", "/api/scans?limit=501", None),
        ("GET", "/api/scans?limit=-1", None),
        ("GET", "/api/scans?limit=ten", None),
        ("GET", "/api/images?grade=Z", None),
        ("GET", "/api/images?grade=AB", None),
        ("GET", f"/api/images?q={'x' * 201}", None),
    ],
)
def test_bad_input_is_422_and_changes_nothing(
    make_app: MakeApp,
    engine: Engine,
    good_image: ImageInfo,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    client, _ = seeded(make_app, good_image)
    with Session(engine) as session:
        before = len(session.exec(select(ScanRecord)).all())
    resp = client.request(method, path, json=body)
    assert resp.status_code == 422, (resp.status_code, resp.text[:200])
    assert isinstance(resp.json()["detail"], list)
    with Session(engine) as session:
        assert len(session.exec(select(ScanRecord)).all()) == before


def test_malformed_json_bodies_are_422(make_app: MakeApp) -> None:
    client = make_app([])
    for raw in (b"{", b"not json", b"[1, 2]", b'"just a string"', b""):
        resp = client.post("/api/scans", content=raw, headers={"content-type": "application/json"})
        assert resp.status_code == 422, raw
    resp = client.post(
        "/api/scans",
        content=b"all=true",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("params", ["grade=a", "grade=A", "limit=1", "limit=500", "q=ubi"])
def test_valid_boundary_input_is_accepted(
    make_app: MakeApp, good_image: ImageInfo, params: str
) -> None:
    client, _ = seeded(make_app, good_image)
    path = "/api/scans" if params.startswith("limit") else "/api/images"
    assert client.get(f"{path}?{params}").status_code == 200


# ========================================================================== SSE stream order


def raw_sse(client: TestClient, scan_id: int) -> list[str]:
    with client.stream("GET", f"/api/scans/{scan_id}/stream") as resp:
        return [line for line in resp.iter_lines()]


def test_sse_order_for_a_multi_image_scan(
    make_app: MakeApp, settings: Settings, bad_image: ImageInfo, good_image: ImageInfo
) -> None:
    # Strict start/done alternation is only guaranteed one image at a time; the parallel
    # default is covered by test_sse_invariants_with_parallel_images below.
    settings.scan.max_concurrent_images = 1
    client = make_app([bad_image, good_image, clone(good_image, "c")])
    resp = client.post("/api/scans", json={"all": True})
    scan_id = resp.json()["scan_id"]
    lines = raw_sse(client, scan_id)

    events = [json.loads(line[5:]) for line in lines if line.startswith("data:")]
    stages = [e["stage"] for e in events]
    expected = ["queued", "started"]
    for _ in range(3):
        expected += ["image_started", "image_done"]
    assert stages == expected + ["completed"], stages

    started = [e for e in events if e["stage"] == "image_started"]
    assert [e["current"] for e in started] == [1, 2, 3] and {e["total"] for e in started} == {3}
    assert events[-1]["current"] == events[-1]["total"] == 3
    assert {e["scan_id"] for e in events} == {scan_id}

    ids = [int(line[3:]) for line in lines if line.startswith("id:")]
    assert ids == list(range(len(events))), "event ids must be sequential for Last-Event-ID"
    assert all(line == "event: progress" for line in lines if line.startswith("event:"))
    assert lines.count("") >= len(events), "every event is terminated by a blank line"


def test_sse_invariants_with_parallel_images(
    make_app: MakeApp, settings: Settings, good_image: ImageInfo
) -> None:
    """With several images in flight the order interleaves, but these always hold."""
    assert settings.scan.max_concurrent_images == 4  # the documented default
    images = [clone(good_image, str(i)) for i in range(8)]
    client = make_app(images)
    _, events = run_scan(client, all=True)
    stages = [e["stage"] for e in events]
    assert stages[:2] == ["queued", "started"] and stages[-1] == "completed"
    assert stages.count("image_started") == stages.count("image_done") == 8

    per_image: dict[str, list[str]] = {}
    for e in events:
        if e["image"]:
            per_image.setdefault(e["image"], []).append(e["stage"])
    assert len(per_image) == 8
    assert all(seq == ["image_started", "image_done"] for seq in per_image.values())

    finished = [e["current"] for e in events if e["stage"] == "image_done"]
    assert finished == sorted(finished) == list(range(1, 9)), "progress never goes backwards"
    assert events[-1]["current"] == events[-1]["total"] == 8
    assert all(e["total"] == 8 for e in events if e["stage"].startswith("image_"))


def test_sse_stream_ends_after_the_terminal_event(make_app: MakeApp, good_image: ImageInfo) -> None:
    client = make_app([good_image])
    scan_id, events = run_scan(client, all=True)
    assert events[-1]["stage"] == "completed"
    # A second connection after completion replays and closes; it must not hang.
    started = time.monotonic()
    assert stream_events(client, scan_id) == events
    assert time.monotonic() - started < 10


def test_sse_order_for_a_failed_scan(make_app: MakeApp, good_image: ImageInfo) -> None:
    client = make_app([good_image])
    scan_id, events = run_scan(client, image="localhost/pstest-missing:1")
    stages = [e["stage"] for e in events]
    assert stages[:2] == ["queued", "started"] and stages[-1] == "failed"
    assert "completed" not in stages
    assert stages.count("failed") == 1
    assert events[-1]["message"]
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "failed" and scan["error"]


@pytest.mark.parametrize("last_id", ["0", "2", "99", "-5", "abc", ""])
def test_sse_resume_with_any_last_event_id_never_errors(
    make_app: MakeApp, good_image: ImageInfo, last_id: str
) -> None:
    client = make_app([good_image])
    scan_id, full = run_scan(client, all=True)
    resumed = stream_events(client, scan_id, **{"Last-Event-ID": last_id})
    assert resumed == full[len(full) if last_id == "99" else slice_start(last_id) :]


def slice_start(last_id: str) -> int:
    try:
        return max(int(last_id) + 1, 0)
    except ValueError:
        return 0


# ============================================================================ concurrency


class ProbeSource(ApiSource):
    """Records how many scans touch Podman at the same moment."""

    lock = threading.Lock()

    def __init__(self, images: list[ImageInfo], probe: dict[str, int]) -> None:
        super().__init__(images)
        self.probe = probe

    def _enter(self) -> None:
        with self.lock:
            self.probe["active"] += 1
            self.probe["max"] = max(self.probe["max"], self.probe["active"])
            self.probe["calls"] += 1
        time.sleep(0.03)  # long enough for a second concurrent scan to overlap, if it could
        with self.lock:
            self.probe["active"] -= 1

    def list_images(self) -> list[ImageInfo]:
        self._enter()
        return super().list_images()

    def get_image(self, reference: str) -> ImageInfo:
        self._enter()
        return super().get_image(reference)


def wait_until_done(client: TestClient, scan_ids: list[int], timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    pending = set(scan_ids)
    while pending and time.monotonic() < deadline:
        for scan_id in list(pending):
            if client.get(f"/api/scans/{scan_id}").json()["status"] in ("completed", "failed"):
                pending.discard(scan_id)
        time.sleep(0.1)
    assert not pending, f"scans still running after {timeout}s: {pending}"


@pytest.fixture
def probed_client(
    settings: Settings, engine: Engine, bad_image: ImageInfo, good_image: ImageInfo
) -> tuple[TestClient, dict[str, int]]:
    probe = {"active": 0, "max": 0, "calls": 0}
    images = [bad_image, good_image]
    app = create_app(
        settings,
        engine=engine,
        source_factory=lambda: ProbeSource(images, probe),
        fs_scanner_factory=lambda: None,
        cve_scanner_factory=lambda: {"oscap": cves},
        static_dir=None,
    )
    return TestClient(app), probe


def test_concurrent_scan_requests_are_serialised_and_never_double_scan(
    probed_client: tuple[TestClient, dict[str, int]], engine: Engine
) -> None:
    client, probe = probed_client
    n = 8

    def submit(_: int) -> int:
        return int(TestClient(client.app).post("/api/scans", json={"all": True}).json()["scan_id"])

    with ThreadPoolExecutor(max_workers=n) as pool:
        scan_ids = list(pool.map(submit, range(n)))
    assert len(set(scan_ids)) == n, "every request gets its own scan"
    wait_until_done(client, scan_ids)

    assert probe["max"] == 1, "two scans ran against Podman at the same time"
    assert probe["calls"] == n, "each scan lists the images exactly once"
    with Session(engine) as session:
        scans = session.exec(select(ScanRecord)).all()
        assert len(scans) == n and {s.status for s in scans} == {"completed"}
        assert {s.images_scanned for s in scans} == {2}

        per_pair = Counter((r.scan_id, r.image_id) for r in session.exec(select(ImageScanRecord)))
        assert len(per_pair) == n * 2 and set(per_pair.values()) == {1}, (
            "an image was scanned twice"
        )

        by_scan: dict[int, list[tuple[str, str]]] = {}
        for f in session.exec(select(FindingRecord)):
            by_scan.setdefault(f.scan_id, []).append((f.image_id, f.rule_id))
        shapes = {tuple(sorted(v)) for v in by_scan.values()}
        assert len(shapes) == 1, "scans of the same images must store identical findings"
        assert session.exec(select(ScanHeartbeatRecord)).all() == [], "heartbeats not cleaned up"
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA integrity_check")).scalar() == "ok"
    assert client.app.state.scan_manager.active_scan_ids() == set()  # type: ignore[attr-defined]


def test_same_image_requested_concurrently_makes_separate_complete_scans(
    probed_client: tuple[TestClient, dict[str, int]], bad_image: ImageInfo, engine: Engine
) -> None:
    client, probe = probed_client

    def submit(_: int) -> int:
        resp = TestClient(client.app).post("/api/scans", json={"image": bad_image.repo_tags[0]})
        assert resp.status_code == 202
        return int(resp.json()["scan_id"])

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(submit, range(4)))
    wait_until_done(client, ids)
    assert probe["max"] == 1 and probe["calls"] == 4
    with Session(engine) as session:
        history = session.exec(
            select(ImageScanRecord).where(ImageScanRecord.image_id == bad_image.id)
        ).all()
    assert len(history) == 4  # four scans, four history points, no duplicates inside any scan
    assert len({h.scan_id for h in history}) == 4


def test_reads_stay_available_while_scans_run(
    probed_client: tuple[TestClient, dict[str, int]],
) -> None:
    client, _ = probed_client
    ids = [client.post("/api/scans", json={"all": True}).json()["scan_id"] for _ in range(4)]
    statuses: list[int] = []
    stop = threading.Event()

    def reader() -> None:
        local = TestClient(client.app)
        while not stop.is_set():
            for path in ("/api/images", "/api/overview", "/api/scans", "/api/health"):
                statuses.append(local.get(path).status_code)

    threads = [threading.Thread(target=reader) for _ in range(3)]
    for t in threads:
        t.start()
    try:
        wait_until_done(client, ids)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=10)
    assert statuses and set(statuses) == {200}, Counter(statuses)


# ============================================================================== HTML report


FORBIDDEN_TAGS = {
    "link",
    "script",
    "img",
    "iframe",
    "object",
    "embed",
    "form",
    "a",
    "base",
    "audio",
    "video",
    "source",
    "input",
    "svg",
    "use",
}


class AssetAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.problems: list[str] = []
        self.in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in FORBIDDEN_TAGS:
            self.problems.append(f"<{tag}>")
        if tag == "style":
            self.in_style = True
        for name, value in attrs:
            v = (value or "").lower()
            if name.startswith("on"):
                self.problems.append(f"event handler {name}")
            if name in {"src", "href", "action", "data", "srcset", "poster", "formaction"}:
                self.problems.append(f"{name}={value}")
            if "://" in v or v.startswith(("//", "javascript:")) or "url(" in v:
                self.problems.append(f"{name}={value}")
            if tag == "meta" and name == "http-equiv" and v == "refresh":
                self.problems.append("meta refresh")

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_style:
            low = data.lower()
            for needle in ("url(", "@import", "http:", "https:", "@font-face", "expression("):
                if needle in low:
                    self.problems.append(f"style contains {needle}")


def test_report_has_no_external_references_for_any_image(
    make_app: MakeApp, bad_image: ImageInfo, good_image: ImageInfo
) -> None:
    nasty = clone(good_image, "d").model_copy(
        update={
            "labels": {
                "homepage": "https://evil.example/tracker.png?u=1",
                "org.opencontainers.image.source": "http://evil.example/repo",
            },
            "env": ["CALLBACK=https://evil.example/hook"],
        }
    )
    client, _ = seeded(make_app, bad_image, good_image, nasty)
    for image in (bad_image, good_image, nasty):
        resp = client.get(f"/api/reports/{quote(image.id, safe='')}.html")
        assert resp.status_code == 200
        audit = AssetAudit()
        audit.feed(resp.text)
        assert audit.problems == [], (image.id[:19], audit.problems)
        assert resp.text.lstrip().lower().startswith("<!doctype html")
        assert "<meta charset" in resp.text.lower()
        assert "default-src 'none'" in resp.headers["content-security-policy"]
        assert resp.headers["x-content-type-options"] == "nosniff"


def test_report_is_a_single_self_contained_download(
    make_app: MakeApp, bad_image: ImageInfo
) -> None:
    client, _ = seeded(make_app, bad_image)
    resp = client.get(f"/api/reports/{bad_image.id}.html")
    disposition = resp.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="podshield-')
    filename = disposition.split('"')[1]
    assert filename.endswith(".html") and all(c.isalnum() or c in "._-" for c in filename)
    assert len(resp.content) > 500


# ================================================================================== health


class DownSource(ApiSource):
    def __init__(self, mode: str) -> None:
        super().__init__([])
        self.mode = mode

    def ping(self) -> bool:
        if self.mode == "raise":
            raise ConnectionRefusedError("socket gone")
        return False


@pytest.mark.parametrize("mode", ["false", "raise"])
def test_health_reports_podman_down_without_failing(
    settings: Settings, engine: Engine, mode: str
) -> None:
    app = create_app(
        settings, engine=engine, source_factory=lambda: DownSource(mode), static_dir=None
    )
    resp = TestClient(app).get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["podman"] is False and resp.json()["status"] == "ok"


def test_health_reports_each_scanner_state(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "podshield.api.scanner_statuses",
        lambda _s: [
            ScannerStatus("filesystem", True, "", True),
            ScannerStatus("oscap", False, "oscap-podman not installed", True),
            ScannerStatus("trivy", False, "trivy not installed (optional scanner)", False),
            ScannerStatus("skopeo", True, "", True),
        ],
    )
    body = make_app([]).get("/api/health").json()
    assert body["scanners"] == {
        "filesystem": {"available": True, "enabled": True, "detail": ""},
        "oscap": {"available": False, "enabled": True, "detail": "oscap-podman not installed"},
        "trivy": {
            "available": False,
            "enabled": False,
            "detail": "trivy not installed (optional scanner)",
        },
        "skopeo": {"available": True, "enabled": True, "detail": ""},
    }


def test_health_reflects_real_host_state(make_app: MakeApp) -> None:
    """Unmocked: whatever this host has, each scanner reports a boolean and a reason if absent."""
    body = make_app([]).get("/api/health").json()
    assert set(body["scanners"]) == {"filesystem", "oscap", "trivy", "skopeo", "trust"}
    for state in body["scanners"].values():
        assert isinstance(state["available"], bool) and isinstance(state["enabled"], bool)
        assert state["available"] or state["detail"], "an unavailable scanner must say why"


def test_health_does_not_leak_configuration(make_app: MakeApp, settings: Settings) -> None:
    raw = make_app([]).get("/api/health").text
    assert settings.database.path not in raw and settings.podman.socket not in raw


# ================================================================== hostile input / metachars

PAYLOADS = [
    "; rm -rf /",
    "$(touch /tmp/pstest-pwned)",
    "`touch /tmp/pstest-pwned`",
    "alpine\n--privileged",
    "alpine\r\nX-Injected: 1",
    "x && id",
    "x | cat /etc/passwd",
    "x > /tmp/pstest-pwned",
    "../../etc/passwd",
    "' OR '1'='1",
    "'; DROP TABLE imagerecord; --",
    "a b",
    "${IFS}id",
    "--tls-verify=false",
    "-v /:/host",
    "\x00",
]


@pytest.fixture
def no_processes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Any attempt to start a process while handling a request fails the test."""
    attempts: list[str] = []

    def refuse(*args: Any, **_kwargs: Any) -> None:
        attempts.append(repr(args)[:200])
        raise AssertionError(f"a subprocess was started: {args!r}")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr("os.system", refuse)
    return attempts


def table_counts(engine: Engine) -> dict[str, int]:
    with engine.connect() as conn:
        names = [
            r[0]
            for r in conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            )
        ]
        return {
            n: int(conn.execute(text(f'SELECT COUNT(*) FROM "{n}"')).scalar() or 0) for n in names
        }


@pytest.mark.parametrize("payload", PAYLOADS, ids=[repr(p)[:24] for p in PAYLOADS])
def test_hostile_strings_are_rejected_or_inert_everywhere(
    make_app: MakeApp,
    engine: Engine,
    good_image: ImageInfo,
    no_processes: list[str],
    payload: str,
) -> None:
    client, _ = seeded(make_app, good_image)
    before = table_counts(engine)
    quoted = quote(payload, safe="")

    results = {
        "scan image": client.post("/api/scans", json={"image": payload}),
        "registry": client.post("/api/registry/inspect", json={"reference": payload}),
        "image path": client.get(f"/api/images/{quoted}"),
        "report path": client.get(f"/api/reports/{quoted}.html"),
        "rule path": client.patch(f"/api/rules/{quoted}", json={"enabled": False}),
        "search": client.get("/api/images", params={"q": payload}),
        "grade": client.get("/api/images", params={"grade": payload}),
        "stream": client.get(f"/api/scans/{quoted}/stream"),
    }
    for where, resp in results.items():
        assert resp.status_code < 500, (where, resp.status_code, resp.text[:200])
    # Executable-looking references never get past validation.
    if payload not in ("a b",):
        assert results["scan image"].status_code == 422
    assert results["registry"].status_code == 422
    assert results["search"].json() == [] or results["search"].status_code == 200
    assert results["rule path"].status_code in (404, 405)

    assert not no_processes
    assert not Path("/tmp/pstest-pwned").exists()
    assert table_counts(engine) == before, "hostile input changed stored data"


def test_a_legitimate_reference_still_works_after_all_that(
    make_app: MakeApp, good_image: ImageInfo
) -> None:
    client, _ = seeded(make_app, good_image)
    scan_id, events = run_scan(client, image=good_image.repo_tags[0])
    assert events[-1]["stage"] == "completed"
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "completed"


def test_the_real_registry_auditor_never_reaches_a_process_for_hostile_references(
    make_app: MakeApp, no_processes: list[str]
) -> None:
    client = make_app([])  # default registry_factory: the real RegistryAuditor
    for payload in PAYLOADS:
        assert client.post("/api/registry/inspect", json={"reference": payload}).status_code == 422
    assert not no_processes


# ============================================================================ secrets, always


def get_everything(client: TestClient, image: ImageInfo, scan_id: int) -> str:
    quoted = quote(image.id, safe="")
    bodies = [
        client.get("/api/overview").text,
        client.get("/api/images").text,
        client.get(f"/api/images/{quoted}").text,
        client.get(f"/api/reports/{quoted}.html").text,
        client.get("/api/scans").text,
        client.get(f"/api/scans/{scan_id}").text,
        "\n".join(raw_sse(client, scan_id)),
        client.get("/api/rules").text,
        client.get("/api/health").text,
        client.get("/openapi.json").text,
        client.get("/api/openapi.json").text,
    ]
    return "\n".join(bodies)


def test_secret_values_are_in_no_response_body(
    make_app: MakeApp, settings: Settings, bad_image: ImageInfo
) -> None:
    client = make_app(
        [bad_image],
        containers=load_json("containers.json"),
        registry_factory=lambda: StubAuditor(settings, bad_image),
    )
    scan_id, _ = run_scan(client, all=True)
    blob = get_everything(client, bad_image, scan_id)
    blob += client.get("/api/containers").text
    blob += client.post("/api/registry/inspect", json={"reference": "quay.io/x/y:1"}).text
    for secret in SECRETS:
        assert secret not in blob, f"{secret!r} leaked"
    assert "DB_PASSWORD" in blob  # names stay; values are masked


def test_secret_values_are_not_in_the_database_or_logs(
    make_app: MakeApp, engine: Engine, bad_image: ImageInfo, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    client = make_app([bad_image])
    run_scan(client, all=True)
    with engine.raw_connection() as raw:
        dump = "\n".join(raw.iterdump())  # type: ignore[attr-defined]
    for secret in SECRETS:
        assert secret not in dump, f"{secret!r} stored in SQLite"
        assert secret not in caplog.text, f"{secret!r} logged"


def test_error_responses_do_not_echo_stored_secrets(
    make_app: MakeApp, bad_image: ImageInfo
) -> None:
    client, _ = seeded(make_app, bad_image)
    for resp in (
        client.get("/api/images/nope"),
        client.get("/api/scans/9999"),
        client.post("/api/scans", json={}),
        client.patch("/api/rules/PS-001", json={"x": 1}),
    ):
        for secret in SECRETS:
            assert secret not in resp.text


def test_masking_keeps_a_recognisable_prefix_only(make_app: MakeApp, bad_image: ImageInfo) -> None:
    client, _ = seeded(make_app, bad_image)
    env = client.get(f"/api/images/{bad_image.id}").json()["config"]["env"]
    masked = [e for e in env if e.startswith(("DB_PASSWORD=", "AWS_ACCESS_KEY_ID="))]
    assert masked and all("****" in e for e in masked), env
    for entry in masked:
        value = entry.split("=", 1)[1]
        assert len(value) <= 12 and value.endswith("****")


def test_api_tests_use_only_the_documented_fake_secrets() -> None:
    assert set(SECRETS) <= {"hunter2-super-secret", "AKIAIOSFODNN7EXAMPLE"}


_UNUSED: tuple[Callable[..., Any], ...] = (FakeSource,)  # keep the shared import honest
