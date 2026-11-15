"""T1: edge cases in inspect parsing and in the rules that depend on it."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from typing import Any

import pytest

from podshield.config import Settings
from podshield.podman_client import (
    ImageNotFoundError,
    PodmanClient,
    PodmanError,
    parse_inspect,
)
from podshield.scanners.hygiene import RULE_REGISTRY, Rule, build_rules, run_rules
from podshield.schemas import FilesystemReport, ImageInfo
from tests.conftest import DATA, load_json


def rule(rule_id: str, settings: Settings) -> Rule:
    return next(r for r in build_rules(settings) if r.id == rule_id)


def parse_fixture(name: str) -> ImageInfo:
    return parse_inspect(load_json(name))


# ---------------------------------------------------------------------- missing fields


def test_minimal_document_parses_to_safe_defaults() -> None:
    img = parse_fixture("inspect_minimal.json")
    assert img.id.startswith("1111")
    assert (img.user, img.env, img.cmd, img.entrypoint) == ("", [], [], [])
    assert img.exposed_ports == [] and img.labels == {} and img.healthcheck is None
    assert img.created is None and img.size == 0 and img.layer_count == 0
    assert img.is_dangling


def test_no_config_section_does_not_crash_any_rule(settings: Settings) -> None:
    img = parse_fixture("inspect_minimal.json").model_copy(
        update={"filesystem": FilesystemReport()}
    )
    findings = run_rules(img, build_rules(settings))
    ids = {f.rule_id for f in findings}
    # no USER, no tag, no healthcheck, no labels, unknown base, unsigned: all legitimately flagged
    assert {"PS-001", "PS-002", "PS-011", "PS-012"} <= ids
    assert "PS-005" not in ids  # unknown creation time is not "old"


def test_every_rule_survives_a_bare_image(settings: Settings) -> None:
    """A rule that raises would be swallowed by run_rules; call evaluate() directly instead."""
    bare = ImageInfo(id="x")
    for rule_cls in RULE_REGISTRY.values():
        rule_cls(settings).evaluate(bare)  # must not raise
        rule_cls(settings).evaluate(bare.model_copy(update={"filesystem": FilesystemReport()}))


# ------------------------------------------------------------------------- USER values


@pytest.mark.parametrize(
    "user",
    ["", "0", "00", "000", "root", "root:root", "0:0", "root:0", " root ", "0:1001"],
)
def test_ps001_flags_every_spelling_of_root(user: str, settings: Settings) -> None:
    img = parse_fixture("inspect_untagged.json").model_copy(update={"user": user})
    assert [f.rule_id for f in rule("PS-001", settings).evaluate(img)] == ["PS-001"]


@pytest.mark.parametrize(
    "user",
    # "ROOT" is not root: user names are case-sensitive on Linux (it would not even resolve)
    ["1001", "1001:0", "1001:1001", "65534", "nobody", "appuser:appgroup", "10", "1000:0", "ROOT"],
)
def test_ps001_accepts_non_root_users(user: str, settings: Settings) -> None:
    img = parse_fixture("inspect_untagged.json").model_copy(update={"user": user})
    assert rule("PS-001", settings).evaluate(img) == []


def test_numeric_user_in_config_is_converted_to_text() -> None:
    img = parse_fixture("inspect_wrong_types.json")
    assert img.user == "1001"


def test_ps001_user_with_group_only_part_root(settings: Settings) -> None:
    """`USER 1001:0` runs as uid 1001 (group root is OpenShift style) and is fine."""
    img = parse_fixture("inspect_multiarch_arm64.json")
    assert img.user == "1001:0"
    assert rule("PS-001", settings).evaluate(img) == []


# ----------------------------------------------------------------------------- ENV edge


def test_empty_env_is_fine(settings: Settings) -> None:
    img = parse_fixture("inspect_untagged.json")
    assert img.env == [] and img.env_pairs == []
    assert rule("PS-003", settings).evaluate(img) == []


@pytest.mark.parametrize("env", [["NOEQUALS"], ["="], ["A=b=c"], ["EMPTY="], [""]])
def test_odd_env_entries_do_not_crash(env: list[str], settings: Settings) -> None:
    img = ImageInfo(id="x", env=env)
    rule("PS-003", settings).evaluate(img)


def test_env_value_containing_equals_is_kept_whole(settings: Settings) -> None:
    img = ImageInfo(id="x", env=["DB_PASSWORD=abc=def==ghijkl"])
    assert img.env_pairs == [("DB_PASSWORD", "abc=def==ghijkl")]
    (finding,) = rule("PS-003", settings).evaluate(img)
    assert "abc=" in finding.evidence[0] and "ghijkl" not in finding.evidence[0]


# ---------------------------------------------------------------- tags, arch, age


def test_untagged_image_is_dangling_and_flagged(settings: Settings) -> None:
    img = parse_fixture("inspect_untagged.json")
    assert img.repo_tags == [] and img.is_dangling
    assert img.display_name == img.short_id
    (finding,) = rule("PS-002", settings).evaluate(img)
    assert "dangling" in finding.evidence[0]


def test_none_none_placeholder_tag_is_dropped() -> None:
    img = parse_inspect({"Id": "x", "RepoTags": ["<none>:<none>"]})
    assert img.repo_tags == [] and img.is_dangling


def test_multiarch_arm64_image_parses_and_scores_clean(settings: Settings) -> None:
    img = parse_fixture("inspect_multiarch_arm64.json")
    assert (img.architecture, img.os) == ("arm64", "linux")
    assert (
        run_rules(img.model_copy(update={"filesystem": FilesystemReport()}), build_rules(settings))
        == []
    )


def test_digest_only_image_is_pinned_not_dangling(settings: Settings) -> None:
    img = parse_inspect(
        {
            "Id": "x",
            "RepoTags": [],
            "RepoDigests": ["quay.io/podman/hello@sha256:" + "a" * 64],
        }
    )
    assert not img.is_dangling
    assert rule("PS-002", settings).evaluate(img) == []


def test_very_old_created_timestamp_is_flagged_with_age(settings: Settings) -> None:
    img = parse_fixture("inspect_ancient.json")
    assert img.created is not None and img.created.year == 1999
    (finding,) = rule("PS-005", settings).evaluate(img)
    assert "1999-12-31" in finding.evidence[0]


def test_epoch_zero_created_is_not_reported_as_ancient(settings: Settings) -> None:
    img = parse_fixture("inspect_epoch.json")
    assert rule("PS-005", settings).evaluate(img) == []


def test_unix_epoch_1970_is_old(settings: Settings) -> None:
    img = ImageInfo(id="x", created=datetime(1970, 1, 1, tzinfo=UTC))
    assert len(rule("PS-005", settings).evaluate(img)) == 1


def test_age_threshold_boundary(settings: Settings) -> None:
    from datetime import timedelta

    now = datetime.now(UTC)
    limit = settings.thresholds.max_image_age_days
    inside = ImageInfo(id="x", created=now - timedelta(days=limit, hours=-1))
    outside = ImageInfo(id="x", created=now - timedelta(days=limit + 1))
    assert rule("PS-005", settings).evaluate(inside) == []
    assert len(rule("PS-005", settings).evaluate(outside)) == 1


def test_naive_created_datetime_is_treated_as_utc(settings: Settings) -> None:
    img = ImageInfo(id="x", created=datetime(2001, 1, 1))  # no tzinfo
    assert len(rule("PS-005", settings).evaluate(img)) == 1


# ------------------------------------------------------------- malformed / wrong types


def test_wrong_types_are_tolerated() -> None:
    """Podman versions differ; a field with an unexpected type must not crash a scan."""
    img = parse_fixture("inspect_wrong_types.json")
    assert img.repo_tags == ["localhost/pstest-wrong:1.0"]  # a bare string becomes a list
    assert img.size == 0  # "not-a-number"
    assert img.created is None  # overflowing timestamp
    assert img.env == ["SINGLE=value"] and img.cmd == ["run.sh"]
    assert img.exposed_ports == ["8080/tcp"]  # list instead of mapping
    assert img.labels == {} and img.healthcheck is None and img.annotations == {}
    assert img.layer_count == 0


@pytest.mark.parametrize("doc", [[], "text", 42, None, [{"Id": "x"}]])
def test_non_object_inspect_documents_raise_podman_error(doc: Any) -> None:
    with pytest.raises(PodmanError):
        parse_inspect(doc)


def test_malformed_json_from_the_cli_is_a_clean_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    truncated = (DATA / "malformed_inspect.json").read_text(encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        json.loads(truncated)  # the fixture really is malformed

    def run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, truncated, "")

    monkeypatch.setattr(subprocess, "run", run)
    client = PodmanClient("unix:///nonexistent.sock")
    with pytest.raises(PodmanError, match="invalid JSON"):
        client._get_image_cli("localhost/pstest-trunc:1")


def test_cli_returns_non_dict_entries_as_clean_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, json.dumps(["not", "objects"]), "")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(PodmanError):
        PodmanClient("unix:///x.sock")._get_image_cli("img")


def test_cli_fallback_failure_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    client = PodmanClient("unix:///x.sock", timeout=1)

    def missing(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("podman")

    def slow(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, 1)

    def no_such(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 125, "", "Error: no such image: nope")

    def failing(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 125, "", "Error: storage is locked")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(PodmanError, match="not found"):
        client._cli_json(["images"])
    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(PodmanError, match="timed out"):
        client._cli_json(["images"])
    monkeypatch.setattr(subprocess, "run", no_such)
    with pytest.raises(ImageNotFoundError):
        client._cli_json(["images"])
    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(PodmanError, match="storage is locked"):
        client._cli_json(["images"])


def test_cli_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def run(cmd: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs, cmd=cmd)
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    monkeypatch.setattr(subprocess, "run", run)
    PodmanClient("unix:///x.sock")._cli_json(["images"])
    assert isinstance(seen["cmd"], list) and not seen.get("shell")
    assert seen["timeout"] == 30


def test_get_image_rejects_malicious_references() -> None:
    client = PodmanClient("unix:///x.sock")
    for bad in ["; rm -rf /", "$(id)", "`id`", "a\nb", "--privileged", ""]:
        with pytest.raises(PodmanError):
            client.get_image(bad)


# ------------------------------------------------------------------ port / size / layers


@pytest.mark.parametrize(
    ("ports", "hit"),
    [
        (["22/tcp"], True),
        (["22"], True),
        (["2222/tcp"], False),
        (["3306/tcp", "80/tcp"], True),
        ([], False),
        (["8080/tcp", "443/tcp"], False),
        (["abc/tcp"], False),
        (["22/udp"], True),
    ],
)
def test_ps013_port_variants(ports: list[str], hit: bool, settings: Settings) -> None:
    img = ImageInfo(id="x", exposed_ports=ports)
    assert bool(rule("PS-013", settings).evaluate(img)) is hit


def test_size_and_layer_thresholds_are_inclusive_upper_bounds(settings: Settings) -> None:
    limit = settings.thresholds.max_image_size_mb * 1024 * 1024
    assert rule("PS-007", settings).evaluate(ImageInfo(id="x", size=limit)) == []
    assert len(rule("PS-007", settings).evaluate(ImageInfo(id="x", size=limit + 1))) == 1
    layers = settings.thresholds.max_layers
    assert rule("PS-008", settings).evaluate(ImageInfo(id="x", layer_count=layers)) == []
    assert len(rule("PS-008", settings).evaluate(ImageInfo(id="x", layer_count=layers + 1))) == 1


def test_filesystem_rules_are_silent_when_the_image_was_not_mounted(settings: Settings) -> None:
    img = ImageInfo(id="x")  # filesystem is None: scanner unavailable or skipped
    for rid in ("PS-004", "PS-009", "PS-010", "PS-015"):
        assert rule(rid, settings).evaluate(img) == []
