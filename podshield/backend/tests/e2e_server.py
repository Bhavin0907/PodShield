"""A self-contained PodShield server for the Playwright suite. Not a pytest module.

Runs the real FastAPI app, real SQLite, real scoring and the built frontend, with Podman
and the external scanners replaced by deterministic fakes. That makes the browser tests
runnable on a laptop with neither Podman nor RHEL. On the VM, point Playwright at the real
service instead (see frontend/e2e/README in docs/TEST_REPORT.md).

    python -m tests.e2e_server --port 8765 [--db path.db] [--empty]

Test-only control endpoint (never present in the product):

    POST /__e2e/chaos  {"podman": bool, "filesystem": bool, "delay": seconds}

``podman=false`` simulates the socket being stopped: listing images and ping fail.
``filesystem=false`` makes the image-mount scanner fail, as it does when the socket drops
mid-scan. ``delay`` slows each image so the progress panel is observable.
"""

from __future__ import annotations

import argparse
import tempfile
import time
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Request

from podshield.config import Settings
from podshield.db import init_db, make_engine
from podshield.main import create_app
from podshield.podman_client import ImageNotFoundError, PodmanError, parse_inspect
from podshield.scanners.base import ScannerError
from podshield.schemas import (
    FilesystemReport,
    FsSecret,
    ImageInfo,
    SetuidFile,
    Severity,
    Vulnerability,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> Any:
    import json

    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def demo_images() -> list[ImageInfo]:
    bad = parse_inspect(_load("inspect_bad.json"), _load("history_bad.json"))
    good = parse_inspect(_load("inspect_good.json"))
    ancient = parse_inspect(_load("inspect_ancient.json"))
    untagged = parse_inspect(_load("inspect_untagged.json"))
    minimal = parse_inspect(_load("inspect_minimal.json"))
    return [bad, good, ancient, untagged, minimal]


class Chaos:
    def __init__(self) -> None:
        self.podman = True
        self.filesystem = True
        self.delay = 0.0


class DemoSource:
    def __init__(self, images: list[ImageInfo], chaos: Chaos) -> None:
        self.images, self.chaos = images, chaos

    def _check(self) -> None:
        if not self.chaos.podman:
            raise PodmanError(
                "Cannot connect to Podman at /run/user/1000/podman/podman.sock. "
                "Is the socket running? Try: systemctl --user enable --now podman.socket"
            )

    def list_images(self) -> list[ImageInfo]:
        self._check()
        return [i.model_copy(deep=True) for i in self.images]

    def get_image(self, reference: str) -> ImageInfo:
        self._check()
        for img in self.images:
            if reference in img.repo_tags or img.id.startswith(reference):
                return img.model_copy(deep=True)
        raise ImageNotFoundError(f"image not found: {reference}")

    def list_containers(self) -> list[dict[str, Any]]:
        self._check()
        return []

    def ping(self) -> bool:
        return self.chaos.podman

    def close(self) -> None:
        pass


def build_server(db_path: str, *, empty: bool = False) -> Any:
    chaos = Chaos()
    settings = Settings()
    engine = make_engine(db_path)
    init_db(engine)
    source = DemoSource([] if empty else demo_images(), chaos)

    def fs_scan(image_id: str) -> FilesystemReport:
        time.sleep(chaos.delay)
        if not chaos.filesystem:
            raise ScannerError("podman socket closed while mounting the image")
        # Fake, obviously non-real credentials; the real scanner masks them the same way.
        return FilesystemReport(
            files_scanned=1200,
            secrets=[
                FsSecret(path="/app/.env", reason="AWS access key id", masked_value="AKIA****")
            ],
            setuid_files=[SetuidFile(path="/usr/bin/su", mode="4755")],
            os_release={"ID": "rhel", "VERSION_ID": "9.4"},
        )

    def oscap(image: ImageInfo) -> list[Vulnerability]:
        return [
            Vulnerability(
                cve_id="CVE-2024-0001",
                package="openssl",
                severity=Severity.HIGH,
                installed_version="3.0.1",
                fixed_version="3.0.7",
                source="oscap",
                title="Fake OpenSSL issue",
                url="https://example.invalid/CVE-2024-0001",
            ),
            Vulnerability(
                cve_id="CVE-2024-0002", package="zlib", severity=Severity.LOW, source="oscap"
            ),
        ]

    app = create_app(
        settings,
        engine=engine,
        source_factory=lambda: source,
        fs_scanner_factory=lambda: fs_scan,
        cve_scanner_factory=lambda: {"oscap": oscap},
    )

    @app.post("/__e2e/chaos", include_in_schema=False)
    async def set_chaos(request: Request) -> dict[str, object]:
        body = await request.json()
        chaos.podman = bool(body.get("podman", chaos.podman))
        chaos.filesystem = bool(body.get("filesystem", chaos.filesystem))
        chaos.delay = float(body.get("delay", chaos.delay))
        return {"podman": chaos.podman, "filesystem": chaos.filesystem, "delay": chaos.delay}

    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--db", default=None)
    parser.add_argument("--empty", action="store_true", help="host with no images")
    args = parser.parse_args()
    db = args.db or str(Path(tempfile.mkdtemp(prefix="pstest-e2e-")) / "e2e.db")
    uvicorn.run(
        build_server(db, empty=args.empty), host=args.host, port=args.port, log_level="warning"
    )


if __name__ == "__main__":
    main()
