from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from podshield.config import RuleOverride, Settings
from podshield.refs import validate_reference
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.registry import RegistryAuditor, normalize_reference, parse_skopeo
from podshield.schemas import Severity
from tests.conftest import load_json


@pytest.fixture
def skopeo(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Fake skopeo that answers `inspect` and `inspect --config`; returns the call log."""
    calls: list[list[str]] = []
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")

    def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        assert kwargs.get("timeout") and "shell" not in kwargs
        doc = load_json("skopeo_config.json" if "--config" in cmd else "skopeo_summary.json")
        return subprocess.CompletedProcess(cmd, 0, json.dumps(doc), "")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_parse_skopeo() -> None:
    img = parse_skopeo(
        load_json("skopeo_summary.json"),
        load_json("skopeo_config.json"),
        "docker.io/library/nginx:1.25",
    )
    assert img.id.startswith("sha256:aaaa")
    assert img.repo_tags == ["docker.io/library/nginx:1.25"]
    assert img.user == "" and img.cmd[0] == "nginx"
    assert img.exposed_ports == ["22/tcp", "80/tcp"]
    assert img.labels == {"maintainer": "someone@example.com"}
    assert img.layer_count == 2
    assert img.size == 32_000_000
    assert img.created is not None and img.created.year == 2022
    assert [layer.empty for layer in img.layers] == [False, True, False]
    assert [layer.size for layer in img.layers] == [30_000_000, 0, 2_000_000]
    assert ("DB_PASSWORD", "remote-secret-value") in img.env_pairs
    assert img.filesystem is None


def test_parse_skopeo_digest_reference() -> None:
    ref = "quay.io/x/y@sha256:" + "b" * 64
    img = parse_skopeo(load_json("skopeo_summary.json"), load_json("skopeo_config.json"), ref)
    assert img.repo_tags == [] and img.repo_digests == [ref]


def test_parse_skopeo_requires_digest() -> None:
    with pytest.raises(ScannerError, match="Digest"):
        parse_skopeo({}, {}, "x/y:1")


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("nginx", "nginx:latest"),
        ("docker://quay.io/podman/stable", "quay.io/podman/stable:latest"),
        ("myhost:5000/app", "myhost:5000/app:latest"),
        ("myhost:5000/app:2", "myhost:5000/app:2"),
        ("quay.io/x/y@sha256:" + "a" * 64, "quay.io/x/y@sha256:" + "a" * 64),
    ],
)
def test_normalize_reference(ref: str, expected: str) -> None:
    assert normalize_reference(ref) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "--tls-verify=false",
        "-x",
        "a b",
        "a;rm -rf /",
        "$(id)",
        "x\ny",
        "a" * 600,
        "../etc",
        "img`id`",
    ],
)
def test_reference_validation_rejects_injection(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_reference(bad)
    with pytest.raises(ValueError):
        normalize_reference(bad)


def test_audit_runs_rules_and_skips_fs_rules(skopeo: list[list[str]], settings: Settings) -> None:
    audit = RegistryAuditor(settings).audit("nginx")
    ids = {f.rule_id for f in audit.findings}
    # image config analysed without pulling
    assert {"PS-001", "PS-002", "PS-003", "PS-011", "PS-013", "PS-014"} <= ids
    assert audit.skipped_rules == ["PS-004", "PS-009", "PS-010", "PS-015"]
    assert not {"PS-004", "PS-009", "PS-010", "PS-015"} & ids
    assert any("Not evaluated before pulling" in n for n in audit.notes)
    assert audit.score.grade in {"D", "F"}
    assert audit.reference == "nginx:latest"
    secret_evidence = next(f for f in audit.findings if f.rule_id == "PS-003").evidence
    assert "remo****" in " ".join(secret_evidence)
    assert "remote-secret-value" not in " ".join(secret_evidence)


def test_skopeo_command_lines(skopeo: list[list[str]], settings: Settings) -> None:
    settings.registry.tls_verify = False
    settings.registry.authfile = "/run/user/1000/containers/auth.json"
    RegistryAuditor(settings).fetch("quay.io/podman/stable:v5")
    summary, config = skopeo
    assert summary[:3] == ["skopeo", "inspect", "--no-tags"]
    assert config[:3] == ["skopeo", "inspect", "--config"]
    for cmd in (summary, config):
        assert cmd[-1] == "docker://quay.io/podman/stable:v5"
        assert "--tls-verify=false" in cmd
        assert cmd[cmd.index("--authfile") + 1] == "/run/user/1000/containers/auth.json"


def test_audit_respects_rule_overrides(skopeo: list[list[str]], settings: Settings) -> None:
    settings.rules["PS-001"] = RuleOverride(enabled=False)
    settings.rules["PS-011"] = RuleOverride(severity=Severity.HIGH)
    audit = RegistryAuditor(settings).audit("nginx")
    by_id = {f.rule_id: f for f in audit.findings}
    assert "PS-001" not in by_id and by_id["PS-011"].severity is Severity.HIGH


def test_skopeo_missing(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    with pytest.raises(ScannerUnavailable, match="skopeo not installed"):
        RegistryAuditor(settings).audit("nginx")


def test_invalid_reference_never_reaches_skopeo(
    skopeo: list[list[str]], settings: Settings
) -> None:
    with pytest.raises(ValueError):
        RegistryAuditor(settings).audit("--authfile=/etc/shadow")
    assert skopeo == []


def test_skopeo_failure_and_bad_json(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **_k: subprocess.CompletedProcess(cmd, 1, "", "manifest unknown"),
    )
    with pytest.raises(ScannerError, match="manifest unknown"):
        RegistryAuditor(settings).audit("nginx:nope")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **_k: subprocess.CompletedProcess(cmd, 0, "garbage", "")
    )
    with pytest.raises(ScannerError, match="invalid JSON"):
        RegistryAuditor(settings).audit("nginx")
