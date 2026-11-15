"""Run the full PodShield app against fake data, so the UI can be previewed without Podman.

    cd podshield/backend
    python scripts/demo_server.py            # http://127.0.0.1:8765

Uses the sample inspect documents from tests/fixtures, fake CVEs, and a throwaway database.
Click "Scan all" in the UI to see live progress and results.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from podshield.config import Settings  # noqa: E402
from podshield.main import create_app  # noqa: E402
from podshield.podman_client import parse_inspect  # noqa: E402
from podshield.schemas import ImageInfo, Severity, Vulnerability  # noqa: E402
from tests.conftest import FakeSource, hermetic_trust, load_json  # noqa: E402


class DemoSource(FakeSource):
    def __init__(self, images: list[ImageInfo], containers: list[dict[str, Any]]) -> None:
        super().__init__(images)
        self.containers = containers

    def get_image(self, reference: str) -> ImageInfo:
        time.sleep(0.4)  # make the progress panel visible
        return super().get_image(reference)

    def list_images(self) -> list[ImageInfo]:
        return list(self.images)

    def list_containers(self) -> list[dict[str, Any]]:
        return self.containers

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        pass


def fake_cves(image: ImageInfo) -> list[Vulnerability]:
    time.sleep(0.8)
    if "bad" not in image.display_name:
        return []
    return [
        Vulnerability(cve_id="CVE-2024-6387", package="openssh-server", severity=Severity.CRITICAL,
                      installed_version="8.7p1-34", fixed_version="8.7p1-38",
                      url="https://access.redhat.com/security/cve/CVE-2024-6387", source="oscap"),
        Vulnerability(cve_id="CVE-2024-2961", package="glibc", severity=Severity.HIGH,
                      installed_version="2.34-100", fixed_version="2.34-100.el9_4.2",
                      url="https://access.redhat.com/security/cve/CVE-2024-2961", source="oscap,trivy"),
        Vulnerability(cve_id="CVE-2023-4911", package="glibc", severity=Severity.HIGH,
                      installed_version="2.34-100", source="trivy"),
        Vulnerability(cve_id="CVE-2024-0727", package="openssl-libs", severity=Severity.MEDIUM,
                      installed_version="3.0.7", fixed_version="3.0.7-28", source="oscap"),
        Vulnerability(cve_id="CVE-2023-5678", package="zlib", severity=Severity.LOW,
                      installed_version="1.2.11", source="trivy"),
    ]


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="podshield-demo-"))
    settings = Settings()
    for key, value in hermetic_trust(tmp).items():
        setattr(settings.trust, key, value)
    settings.database.path = str(tmp / "demo.db")

    bad = parse_inspect(load_json("inspect_bad.json"), load_json("history_bad.json"))
    good = parse_inspect(load_json("inspect_good.json"))
    source = DemoSource([bad, good], load_json("containers.json"))

    app = create_app(
        settings,
        source_factory=lambda: source,
        fs_scanner_factory=lambda: None,
        cve_scanner_factory=lambda: {"oscap": fake_cves},
    )
    print(f"PodShield demo on http://127.0.0.1:8765  (data in {tmp})")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")


if __name__ == "__main__":
    main()
