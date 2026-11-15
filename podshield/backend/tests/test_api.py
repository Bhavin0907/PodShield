from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session, select

from podshield.config import Settings
from podshield.main import create_app
from podshield.models import ScanRecord
from podshield.podman_client import ImageNotFoundError, PodmanError
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.registry import RegistryAudit, RegistryAuditor
from podshield.schemas import ImageInfo, LayerInfo, Severity, Vulnerability
from tests.conftest import FakeSource, load_json

SECRETS = ["hunter2-super-secret", "AKIAIOSFODNN7EXAMPLE"]


class ApiSource(FakeSource):
    def __init__(
        self,
        images: list[ImageInfo],
        containers: list[dict[str, Any]] | None = None,
        fail_containers: bool = False,
    ) -> None:
        super().__init__(images)
        self.containers = containers or []
        self.fail_containers = fail_containers

    def list_containers(self) -> list[dict[str, Any]]:
        if self.fail_containers:
            raise PodmanError("socket unreachable")
        return self.containers

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        pass


class StubAuditor(RegistryAuditor):
    def __init__(
        self, settings: Settings, image: ImageInfo | None = None, error: Exception | None = None
    ) -> None:
        super().__init__(settings)
        self.image, self.error = image, error

    def fetch(self, reference: str) -> ImageInfo:
        if self.error:
            raise self.error
        assert self.image is not None
        return self.image


def cves(image: ImageInfo) -> list[Vulnerability]:
    return [
        Vulnerability(
            cve_id="CVE-2024-0001",
            package="openssl",
            severity=Severity.HIGH,
            installed_version="1",
            fixed_version="2",
            source="oscap",
        ),
        Vulnerability(
            cve_id="CVE-2024-0002", package="zlib", severity=Severity.LOW, source="oscap"
        ),
    ]


MakeApp = Callable[..., TestClient]


@pytest.fixture
def make_app(
    settings: Settings, engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> MakeApp:
    # A built frontend/dist next to the repo must not leak into API tests.
    monkeypatch.setattr("podshield.main.find_static_dir", lambda _s: None)

    def factory(images: list[ImageInfo], **kwargs: Any) -> TestClient:
        source = ApiSource(
            images, kwargs.pop("containers", None), kwargs.pop("fail_containers", False)
        )
        app = create_app(
            settings,
            engine=engine,
            source_factory=lambda: source,
            fs_scanner_factory=lambda: None,
            cve_scanner_factory=lambda: {"oscap": cves},
            static_dir=kwargs.pop("static_dir", None),
            **kwargs,
        )
        return TestClient(app)

    return factory


def stream_events(client: TestClient, scan_id: int, **headers: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with client.stream("GET", f"/api/scans/{scan_id}/stream", headers=headers) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert resp.headers["cache-control"] == "no-cache"
        for line in resp.iter_lines():
            if line.startswith("data:"):
                out.append(json.loads(line[5:]))
    return out


def run_scan(client: TestClient, **body: Any) -> tuple[int, list[dict[str, Any]]]:
    resp = client.post("/api/scans", json=body)
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]
    return scan_id, stream_events(client, scan_id)


# ----------------------------------------------------------------------- scan lifecycle


def test_empty_database(make_app: MakeApp) -> None:
    client = make_app([])
    assert client.get("/api/images").json() == []
    assert client.get("/api/scans").json() == []
    body = client.get("/api/overview").json()
    assert body["images_audited"] == 0 and body["fleet_score"] is None
    assert body["trend"] == [] and body["riskiest"] == []


def test_scan_stream_and_results(
    make_app: MakeApp, bad_image: ImageInfo, good_image: ImageInfo
) -> None:
    client = make_app([bad_image, good_image])
    scan_id, events = run_scan(client, all=True)

    stages = [e["stage"] for e in events]
    assert stages[0] == "queued" and stages[1] == "started" and stages[-1] == "completed"
    assert stages.count("image_done") == 2
    assert all(e["scan_id"] == scan_id for e in events)

    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "completed" and scan["images_scanned"] == 2
    assert scan["duration_seconds"] is not None
    assert {s["scanner"] for s in scan["scanners"]} == {"oscap"}
    assert client.get("/api/scans").json()[0]["id"] == scan_id

    images = client.get("/api/images").json()
    assert len(images) == 2
    assert images[0]["score"] <= images[1]["score"]  # riskiest first
    worst = images[0]
    assert worst["finding_counts"]["critical"] >= 1
    assert worst["cve_counts"]["high"] == 1 and worst["cve_total"] == 2
    assert worst["created"].endswith(("Z", "+00:00"))  # timezone restored after SQLite

    detail = client.get(f"/api/images/{worst['id']}").json()
    assert detail["findings"][0]["severity"] == "critical"
    assert [v["cve_id"] for v in detail["vulnerabilities"]] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert detail["config"]["user"] is not None or detail["config"] is not None
    assert detail["history"][0]["scan_id"] == scan_id
    assert detail["scanners"][0]["status"] == "ok"
    assert detail["layers"]


def test_stream_replays_after_completion_and_resumes(
    make_app: MakeApp, good_image: ImageInfo
) -> None:
    client = make_app([good_image])
    scan_id, first = run_scan(client, all=True)
    assert stream_events(client, scan_id) == first
    resumed = stream_events(client, scan_id, **{"Last-Event-ID": "1"})
    assert resumed == first[2:]


def test_stream_unknown_scan_is_404(make_app: MakeApp) -> None:
    assert make_app([]).get("/api/scans/999/stream").status_code == 404
    assert make_app([]).get("/api/scans/999").status_code == 404


def test_stream_falls_back_to_stored_record_after_restart(
    make_app: MakeApp, engine: Engine, good_image: ImageInfo
) -> None:
    client = make_app([good_image])
    scan_id, _ = run_scan(client, all=True)
    fresh = make_app([good_image])  # new process: nothing buffered in memory
    events = stream_events(fresh, scan_id)
    assert [e["stage"] for e in events] == ["completed"]


def test_scan_of_unknown_image_fails_cleanly(make_app: MakeApp, good_image: ImageInfo) -> None:
    client = make_app([good_image])
    scan_id, events = run_scan(client, image="does-not-exist:latest")
    assert events[-1]["stage"] == "failed"
    assert "not found" in events[-1]["message"]
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "failed" and "not found" in scan["error"]


def test_scan_single_image_by_reference(make_app: MakeApp, bad_image: ImageInfo) -> None:
    client = make_app([bad_image])
    _, events = run_scan(client, image=bad_image.repo_tags[0], skip_cve=True)
    assert events[-1]["stage"] == "completed"
    detail = client.get(f"/api/images/{bad_image.id}").json()
    assert detail["vulnerabilities"] == []


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"all": False},
        {"image": "alpine", "all": True},
        {"image": "--help"},
        {"image": "-v /:/host"},
        {"image": "bad ref"},
    ],
)
def test_scan_request_validation(make_app: MakeApp, body: dict[str, Any]) -> None:
    client = make_app([])
    assert client.post("/api/scans", json=body).status_code == 422
    assert client.get("/api/scans").json() == []  # nothing was queued


def test_interrupted_scans_are_failed_on_startup(make_app: MakeApp, engine: Engine) -> None:
    old = datetime.now(UTC) - timedelta(minutes=10)  # well past the heartbeat grace period
    with Session(engine) as s:
        s.add(ScanRecord(target="all", status="running", started_at=old))
        s.add(ScanRecord(target="all", status="queued", started_at=old))
        s.commit()
    client = make_app([])
    assert {s["status"] for s in client.get("/api/scans").json()} == {"failed"}


def test_background_sweeper_fails_scans_orphaned_after_startup(
    make_app: MakeApp, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan whose process dies right before an API restart is caught a little later."""
    monkeypatch.setattr("podshield.main.SWEEP_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr("podshield.main.STALE_GRACE_SECONDS", 0.0)
    client = make_app([])
    with Session(engine) as s:
        rec = ScanRecord(
            target="all", status="running", started_at=datetime.now(UTC) - timedelta(seconds=5)
        )
        s.add(rec)
        s.commit()
    with client:  # entering the context runs the lifespan, which starts the sweeper
        for _ in range(100):
            if {s["status"] for s in client.get("/api/scans").json()} == {"failed"}:
                break
            time.sleep(0.05)
        assert {s["status"] for s in client.get("/api/scans").json()} == {"failed"}


def test_crashing_scan_is_marked_failed(
    make_app: MakeApp, good_image: ImageInfo, monkeypatch: pytest.MonkeyPatch
) -> None:
    from podshield.orchestrator import Orchestrator

    def boom(self: Orchestrator, *a: Any, **k: Any) -> Any:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(Orchestrator, "_attach_filesystem", boom, raising=True)
    monkeypatch.setattr(Orchestrator, "_scan_image", boom, raising=True)
    client = make_app([good_image])
    _, events = run_scan(client, all=True)
    assert events[-1]["stage"] == "failed"


# ------------------------------------------------------------------ overview and trend


def test_overview_and_trend(make_app: MakeApp, bad_image: ImageInfo, good_image: ImageInfo) -> None:
    client = make_app([bad_image, good_image])
    run_scan(client, image=good_image.repo_tags[0], skip_cve=True)
    run_scan(client, all=True)
    ov = client.get("/api/overview").json()
    images = client.get("/api/images").json()
    scores = [i["score"] for i in images]

    assert ov["images_audited"] == 2
    assert ov["fleet_score"] == round(sum(scores) / 2, 1)
    assert sum(ov["grade_distribution"].values()) == 2
    assert ov["total_cves"] == 4  # two CVEs on each of two images
    assert ov["cve_totals"]["high"] == 2
    assert ov["critical_findings"] == sum(i["finding_counts"]["critical"] for i in images)
    assert next(r["id"] for r in ov["riskiest"]) == images[0]["id"]
    assert len(ov["trend"]) == 2
    # After the first scan only the good image was known; the second adds the bad one.
    assert ov["trend"][0]["score"] > ov["trend"][1]["score"]
    assert ov["trend"][1]["score"] == ov["fleet_score"]


def test_image_filters_and_lookup(
    make_app: MakeApp, bad_image: ImageInfo, good_image: ImageInfo
) -> None:
    client = make_app([bad_image, good_image])
    run_scan(client, all=True)
    images = {i["id"]: i for i in client.get("/api/images").json()}
    bad = images[bad_image.id]

    assert [
        i["id"]
        for i in client.get("/api/images", params={"grade": bad["grade"]}).json()
        if i["id"] == bad_image.id
    ]
    assert client.get("/api/images", params={"q": "zzz-nope"}).json() == []
    tag = bad_image.repo_tags[0]
    assert client.get("/api/images", params={"q": tag.split(":")[0][:6]}).json()
    assert client.get("/api/images", params={"grade": "ZZ"}).status_code == 422

    short = bad_image.id.removeprefix("sha256:")[:8]
    assert client.get(f"/api/images/{short}").json()["id"] == bad_image.id
    assert client.get("/api/images/nope-nope").status_code == 404
    assert client.get("/api/images/abc").status_code == 404  # too short to be a prefix


def test_ambiguous_prefix_is_409(
    make_app: MakeApp, bad_image: ImageInfo, good_image: ImageInfo
) -> None:
    a = bad_image.model_copy(update={"id": "sha256:abcd1111" + "0" * 56, "repo_tags": ["a:1"]})
    b = good_image.model_copy(update={"id": "sha256:abcd2222" + "0" * 56, "repo_tags": ["b:1"]})
    client = make_app([a, b])
    run_scan(client, all=True)
    assert client.get("/api/images/abcd").status_code == 409
    assert client.get("/api/images/abcd1").status_code == 200


# ---------------------------------------------------------------------------- secrets


def test_no_secret_value_is_ever_returned_or_stored(
    make_app: MakeApp, bad_image: ImageInfo, tmp_path: Path, engine: Engine
) -> None:
    client = make_app([bad_image])
    _scan_id, events = run_scan(client, all=True)
    detail = client.get(f"/api/images/{bad_image.id}").json()
    report = client.get(f"/api/reports/{bad_image.id}.html").text
    everything = (
        json.dumps(
            [detail, client.get("/api/images").json(), client.get("/api/overview").json(), events]
        )
        + report
    )
    for secret in SECRETS:
        assert secret not in everything
    assert "DB_PASSWORD" in everything  # the variable name stays, only the value is masked

    from podshield.models import ImageSnapshotRecord

    with Session(engine) as s:
        snap = s.exec(select(ImageSnapshotRecord)).one()
    for secret in SECRETS:
        assert secret not in json.dumps(snap.data)
    assert any(e.startswith("DB_PASSWORD=hunt") for e in detail["config"]["env"])


# ---------------------------------------------------------------------------- reports


def test_report_is_standalone_and_escaped(make_app: MakeApp, good_image: ImageInfo) -> None:
    xss = "<script>alert(1)</script>"
    nasty = good_image.model_copy(
        update={
            "repo_tags": [f"evil/{xss}:1"],
            "labels": {"x": xss, "org.opencontainers.image.base.name": xss},
            "layers": [LayerInfo(created_by=f"RUN echo {xss}", size=10)],
        }
    )
    client = make_app([nasty])
    run_scan(client, all=True)
    resp = client.get(f"/api/reports/{nasty.id}.html")
    assert resp.status_code == 200
    assert "<script>alert(1)" not in resp.text
    assert "&lt;script&gt;" in resp.text
    assert resp.headers["content-type"].startswith("text/html")
    assert "default-src 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["content-disposition"].startswith('attachment; filename="podshield-')
    for needle in ("<link", "<script", "<img", "<iframe", "src=", "href=", "url(", "@import"):
        assert needle not in resp.text  # no external assets or active content


def test_report_contents(make_app: MakeApp, bad_image: ImageInfo) -> None:
    client = make_app([bad_image])
    run_scan(client, all=True)
    html = client.get(f"/api/reports/{bad_image.id}.html").text
    detail = client.get(f"/api/images/{bad_image.id}").json()
    assert f"Grade {detail['grade']}" in html
    assert "CVE-2024-0001" in html
    for f in detail["findings"]:
        assert f["rule_id"] in html
    assert client.get("/api/reports/unknown.html").status_code == 404


# ----------------------------------------------------------------------------- rules


def test_rules_list_and_patch_persist(
    make_app: MakeApp, bad_image: ImageInfo, settings: Settings, engine: Engine
) -> None:
    client = make_app([bad_image])
    rules = {r["id"]: r for r in client.get("/api/rules").json()}
    assert rules["PS-001"]["kind"] == "image" and rules["PS-R01"]["kind"] == "runtime"
    assert rules["PS-001"]["enabled"] is True

    run_scan(client, all=True, skip_cve=True)
    before = {f["rule_id"] for f in client.get(f"/api/images/{bad_image.id}").json()["findings"]}
    assert "PS-001" in before

    resp = client.patch("/api/rules/PS-001", json={"enabled": False})
    assert resp.status_code == 200 and resp.json()["enabled"] is False
    resp = client.patch("/api/rules/PS-002", json={"severity": "critical"})
    assert resp.json()["severity"] == "critical"
    assert resp.json()["default_severity"] != "critical"

    run_scan(client, all=True, skip_cve=True)
    after = client.get(f"/api/images/{bad_image.id}").json()["findings"]
    assert "PS-001" not in {f["rule_id"] for f in after}
    assert {f["rule_id"]: f["severity"] for f in after}.get("PS-002", "critical") == "critical"

    # Survives a restart (new app, same database)...
    settings.rules = {}  # a new process re-reads the config file, which has no rules
    restarted = make_app([bad_image])
    rules = {r["id"]: r for r in restarted.get("/api/rules").json()}
    assert rules["PS-001"]["enabled"] is False and rules["PS-002"]["severity"] == "critical"

    # ...and an explicit null clears the override.
    cleared = restarted.patch("/api/rules/PS-001", json={"enabled": None}).json()
    assert cleared["enabled"] is True
    # Fields left out are untouched.
    assert restarted.patch("/api/rules/PS-002", json={}).json()["severity"] == "critical"


def test_rule_patch_errors(make_app: MakeApp) -> None:
    client = make_app([])
    assert client.patch("/api/rules/PS-999", json={"enabled": False}).status_code == 404
    assert client.patch("/api/rules/PS-001", json={"severity": "urgent"}).status_code == 422
    assert client.patch("/api/rules/PS-001", json={"enabled": "maybe"}).status_code == 422


def test_api_override_layers_over_config_file(
    settings: Settings, engine: Engine, make_app: MakeApp
) -> None:
    from podshield.config import RuleOverride

    settings.rules["PS-001"] = RuleOverride(enabled=False, severity=Severity.LOW)
    client = make_app([])
    r = {x["id"]: x for x in client.get("/api/rules").json()}["PS-001"]
    assert r["enabled"] is False and r["severity"] == "low"
    # API change to enabled only; the file's severity override remains.
    client.patch("/api/rules/PS-001", json={"enabled": True})
    r = {x["id"]: x for x in client.get("/api/rules").json()}["PS-001"]
    assert r["enabled"] is True and r["severity"] == "low"
    # Clearing the API override falls back to the file value, not the default.
    client.patch("/api/rules/PS-001", json={"enabled": None})
    r = {x["id"]: x for x in client.get("/api/rules").json()}["PS-001"]
    assert r["enabled"] is False


# ------------------------------------------------------------------ containers/registry


def test_containers(make_app: MakeApp) -> None:
    client = make_app([], containers=load_json("containers.json"))
    body = client.get("/api/containers").json()
    assert {c["name"] for c in body} == {"evil", "web"}
    evil = next(c for c in body if c["name"] == "evil")
    assert evil["findings"] and evil["grade"] in "ABCDF"
    assert evil["findings"][0]["severity"] == "critical"


def test_containers_podman_down_is_503(make_app: MakeApp) -> None:
    client = make_app([], fail_containers=True)
    resp = client.get("/api/containers")
    assert resp.status_code == 503 and "unreachable" in resp.json()["detail"]


def test_registry_inspect(make_app: MakeApp, settings: Settings, bad_image: ImageInfo) -> None:
    client = make_app([], registry_factory=lambda: StubAuditor(settings, bad_image))
    body = client.post("/api/registry/inspect", json={"reference": "quay.io/x/y:1"}).json()
    assert body["findings"] and body["skipped_rules"] and body["notes"]
    assert body["layers"]
    assert not any(s in json.dumps(body) for s in SECRETS)
    assert isinstance(RegistryAudit, type)


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (ScannerUnavailable("skopeo not installed"), 503),
        (ScannerError("manifest unknown"), 502),
        (ValueError("bad reference"), 422),
    ],
)
def test_registry_inspect_errors(
    make_app: MakeApp, settings: Settings, error: Exception, status: int
) -> None:
    client = make_app([], registry_factory=lambda: StubAuditor(settings, error=error))
    assert client.post("/api/registry/inspect", json={"reference": "alpine"}).status_code == status


@pytest.mark.parametrize("ref", ["", "--tls-verify=false", "a b", "x" * 600])
def test_registry_inspect_rejects_bad_references(make_app: MakeApp, ref: str) -> None:
    assert make_app([]).post("/api/registry/inspect", json={"reference": ref}).status_code == 422


# ------------------------------------------------------------------- health and frontend


def test_health(make_app: MakeApp) -> None:
    body = make_app([]).get("/api/health").json()
    assert body["status"] == "ok" and body["podman"] is True
    assert set(body["scanners"]) >= {"oscap", "trivy", "skopeo"}


def test_placeholder_when_frontend_not_built(make_app: MakeApp) -> None:
    client = make_app([])
    resp = client.get("/")
    assert resp.status_code == 200 and "not been built" in resp.text
    assert client.get("/api/nope").status_code == 404  # API misses stay JSON 404s


def test_static_frontend_and_spa_fallback(make_app: MakeApp, tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>app</html>", encoding="utf-8")
    (dist / "assets" / "a.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("top secret", encoding="utf-8")
    client = make_app([], static_dir=dist.resolve())

    assert client.get("/").text == "<html>app</html>"
    assert client.get("/assets/a.js").text == "console.log(1)"
    assert client.get("/images/abc123").text == "<html>app</html>"  # client-side route
    assert client.get("/api/nope").status_code == 404
    for evil in ("/../secret.txt", "/%2e%2e/secret.txt", "/assets/..%2f..%2fsecret.txt"):
        assert "top secret" not in client.get(evil).text


def test_image_not_found_error_type() -> None:
    assert issubclass(ImageNotFoundError, PodmanError)
