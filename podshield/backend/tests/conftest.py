from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from podshield.config import Settings
from podshield.db import init_db, make_engine
from podshield.podman_client import ImageNotFoundError, parse_inspect
from podshield.schemas import ImageInfo
from tests.markers import skip_reason

DATA = Path(__file__).parent / "fixtures"


def load_json(name: str) -> Any:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


POLICY = {
    "default": [{"type": "reject"}],
    "transports": {
        "docker": {
            "registry.access.redhat.com": [
                {"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/etc/pki/key"}
            ]
        }
    },
}


def hermetic_trust(tmp_path: Path) -> dict[str, str]:
    """Trust config paths inside tmp_path so tests never read the real /etc/containers."""
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(POLICY), encoding="utf-8")
    return {
        "policy_path": policy.as_posix(),
        "registries_conf": (tmp_path / "registries.conf").as_posix(),
        "registries_conf_d": (tmp_path / "registries.conf.d").as_posix(),
        "registries_d": (tmp_path / "registries.d").as_posix(),
    }


def trust_toml(tmp_path: Path) -> str:
    body = "\n".join(f'{k} = "{v}"' for k, v in hermetic_trust(tmp_path).items())
    return f"[trust]\n{body}\n"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings()
    for key, value in hermetic_trust(tmp_path).items():
        setattr(s.trust, key, value)
    return s


@pytest.fixture
def bad_image() -> ImageInfo:
    return parse_inspect(load_json("inspect_bad.json"), load_json("history_bad.json"))


@pytest.fixture
def good_image() -> ImageInfo:
    return parse_inspect(load_json("inspect_good.json"))


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    eng = make_engine(str(tmp_path / "test.db"))
    init_db(eng)
    return eng


@pytest.fixture
def make_source() -> type[FakeSource]:
    return FakeSource


class FakeSource:
    """Stands in for PodmanClient so no Podman is needed."""

    def __init__(self, images: list[ImageInfo]) -> None:
        self.images = images

    def list_images(self) -> list[ImageInfo]:
        return list(self.images)

    def get_image(self, reference: str) -> ImageInfo:
        for img in self.images:
            if reference in img.repo_tags or img.id.startswith(reference):
                return img
        raise ImageNotFoundError(f"image not found: {reference}")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Everything outside tests/integration and tests/e2e is a unit test; mark it `unit`."""
    for item in items:
        parts = Path(str(item.fspath)).parts
        if "integration" in parts[-3:-1] or "e2e" in parts[-3:-1]:
            item.add_marker(pytest.mark.integration)
        else:
            item.add_marker(pytest.mark.unit)


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip, with a clear reason, tests whose tool or privilege is missing."""
    reason = skip_reason([m.name for m in item.iter_markers()])
    if reason:
        pytest.skip(reason)


# Shared with the API test modules (kept in test_api.py next to its helpers). Imported last:
# test_api imports FakeSource from this module.
from tests.test_api import make_app as make_app  # noqa: PLC0414  (re-exported fixture)
