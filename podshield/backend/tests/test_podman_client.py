from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from podshield.podman_client import PodmanError, parse_history, parse_inspect, parse_time
from tests.conftest import load_json


def test_parse_inspect_bad_image() -> None:
    img = parse_inspect(load_json("inspect_bad.json"), load_json("history_bad.json"))
    assert img.short_id == "3f1c9a7b2d4e"
    assert img.repo_tags == ["localhost/demo-bad:latest"]
    assert img.user == ""
    assert img.labels == {}  # null labels normalised
    assert img.entrypoint == []
    assert img.cmd == ["/bin/sh", "-c", "python app.py"]
    assert img.exposed_ports == ["22/tcp", "8080/tcp"]
    assert img.healthcheck is None
    assert img.layer_count == 3
    assert img.created == datetime(2023, 1, 15, 10, 20, 30, 123456, tzinfo=UTC)
    assert ("DB_PASSWORD", "hunter2-super-secret") in img.env_pairs
    assert len(img.layers) == 3 and img.layers[0].empty


def test_parse_inspect_good_image() -> None:
    img = parse_inspect(load_json("inspect_good.json"))
    assert img.user == "1001"
    assert img.healthcheck and img.healthcheck["Test"][0] == "CMD-SHELL"  # type: ignore[index]
    assert img.labels["org.opencontainers.image.version"] == "1.4.2"
    assert not img.is_dangling


def test_parse_inspect_top_level_fallbacks() -> None:
    doc: dict[str, Any] = {
        "Id": "abc",
        "RepoTags": ["<none>:<none>"],
        "User": "42",
        "Labels": {"a": "b"},
        "HealthCheck": {"Test": ["CMD", "true"]},
        "Config": {"Entrypoint": "/run.sh"},
    }
    img = parse_inspect(doc)
    assert img.user == "42"
    assert img.labels == {"a": "b"}
    assert img.healthcheck == {"Test": ["CMD", "true"]}
    assert img.entrypoint == ["/run.sh"]
    assert img.is_dangling


def test_parse_inspect_requires_id() -> None:
    with pytest.raises(PodmanError):
        parse_inspect({"RepoTags": []})


def test_parse_time_variants() -> None:
    assert parse_time(None) is None
    assert parse_time("garbage") is None
    assert parse_time(1673778030) == datetime(2023, 1, 15, 10, 20, 30, tzinfo=UTC)
    assert parse_time("2024-01-01T00:00:00+02:00") == datetime(2023, 12, 31, 22, 0, tzinfo=UTC)
    assert parse_time("2024-01-01T00:00:00.123456789Z") is not None


def test_parse_history_handles_both_key_styles() -> None:
    layers = parse_history(
        [
            {"CreatedBy": "RUN x", "Size": 5, "created": 1673778030},
            {"created_by": "CMD y", "size": 0},
        ]
    )
    assert layers[0].size == 5 and not layers[0].empty
    assert layers[1].empty
