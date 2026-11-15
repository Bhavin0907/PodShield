"""Static checks of the T2 integration fixtures; these run anywhere, no Podman needed.

They catch the mistakes that would otherwise only show up on the RHEL VM: a rule without an
image, CRLF line endings that break a bash script, a real-looking secret, a bad generated config.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from podshield.config import load_settings
from podshield.scanners.hygiene import RULE_REGISTRY
from tests.integration import support
from tests.integration.support import ALL_CASES, GOLDEN, IMAGES_DIR, RULE_CASES

FAKE_SECRETS_ALLOWED = {"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}


def test_every_image_rule_has_exactly_one_containerfile() -> None:
    assert [c.rule for c in RULE_CASES] == sorted(RULE_REGISTRY)
    assert len({c.name for c in ALL_CASES}) == len(ALL_CASES)
    assert len({c.ref for c in ALL_CASES}) == len(ALL_CASES)
    for case in ALL_CASES:
        assert case.containerfile.is_file(), case.containerfile


def test_every_resource_is_prefixed_pstest() -> None:
    for case in ALL_CASES:
        assert case.name.startswith("pstest-")
        assert "/pstest-" in case.ref


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda c: c.name)
def test_containerfile_shape(case: support.ImageCase) -> None:
    text = case.containerfile.read_text(encoding="utf-8")
    assert "\r" not in text, "CRLF line endings"
    assert "FROM ${BASE}" in text and "ARG BASE=registry.access.redhat.com/ubi9/ubi-minimal" in text
    assert "harden.sh clean" in text and "harden.sh finish" in text
    # the shell is removed by `finish`, so nothing may RUN after it
    after_finish = text.split("harden.sh finish", 1)[1]
    assert not re.search(r"^RUN ", after_finish, re.MULTILINE), "RUN after the shell is gone"
    assert len(text.splitlines()) < 40, "fixtures are meant to be small"


def test_only_documented_fake_secrets_are_used() -> None:
    tokens: set[str] = set()
    for path in IMAGES_DIR.glob("*"):
        text = path.read_text(encoding="utf-8")
        tokens |= set(re.findall(r"AKIA[0-9A-Z]{16}", text))
        tokens |= set(re.findall(r"(?:gh[pousr]_|github_pat_)\w+", text))
        tokens |= set(re.findall(r"BEGIN [A-Z ]*PRIVATE KEY", text))
        tokens |= set(re.findall(r"wJalr[\w/+]+", text))
    assert tokens <= FAKE_SECRETS_ALLOWED, tokens - FAKE_SECRETS_ALLOWED


def test_secret_fixtures_are_the_ones_we_think() -> None:
    env = (IMAGES_DIR / "pstest-env-secret.Containerfile").read_text(encoding="utf-8")
    layer = (IMAGES_DIR / "pstest-layer-secret.Containerfile").read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" in env and "AKIAIOSFODNN7EXAMPLE" in layer
    assert "/.aws/credentials" in layer


def test_harden_script_has_unix_line_endings_and_valid_syntax() -> None:
    script = IMAGES_DIR / "harden.sh"
    raw = script.read_bytes()
    assert b"\r" not in raw, "CRLF would break the script inside the image"
    assert raw.startswith(b"#!/bin/bash")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available for a syntax check")
    # via stdin: a Windows path would not mean anything to a WSL bash
    proc = subprocess.run([bash, "-n"], input=raw, capture_output=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")


def test_the_pstest_golden_differs_from_each_case_by_one_idea() -> None:
    """The cases stay close to golden: same labels block, same hardening calls."""
    golden = GOLDEN.containerfile.read_text(encoding="utf-8")
    for case in RULE_CASES:
        text = case.containerfile.read_text(encoding="utf-8")
        if case.rule == "PS-012":
            continue  # deliberately without the author/version/source labels
        for needle in (
            "org.opencontainers.image.authors",
            "org.opencontainers.image.version",
            "org.opencontainers.image.source",
        ):
            assert needle in text and needle in golden, (case.name, needle)


def test_generated_config_is_loadable_by_podshield(tmp_path: Path) -> None:
    settings = support.make_settings(tmp_path / "state", "unix:///tmp/pstest.sock")
    settings.registry.tls_verify = False
    config = support.write_config(settings, tmp_path / "config.toml")
    tomllib.loads(config.read_text(encoding="utf-8"))  # valid TOML
    loaded = load_settings(str(config))
    assert loaded.podman.socket == "unix:///tmp/pstest.sock"
    assert loaded.podman.mode == support.MODE
    assert loaded.database.path == settings.database.path
    assert loaded.thresholds.max_layers == 12 and loaded.thresholds.max_image_size_mb == 200
    assert loaded.registry.tls_verify is False
    assert loaded.trust.policy_path == settings.trust.policy_path


def test_test_policy_covers_local_registries_but_not_the_unsigned_case(tmp_path: Path) -> None:
    from podshield.scanners.trust import load_trust_policy

    settings = support.make_settings(tmp_path / "state", "unix:///x")
    policy = load_trust_policy(settings.trust)
    assert policy.is_signature_verified(GOLDEN.ref)
    assert policy.is_signature_verified(f"localhost:{support.REGISTRY_PORT}/pstest-golden:1.0.0")
    unsigned = next(c for c in RULE_CASES if c.rule == "PS-014")
    assert not policy.is_signature_verified(unsigned.ref)


def test_the_hygiene_rules_agree_with_the_fixture_policy(tmp_path: Path) -> None:
    """The golden image's config, as podman would report it, passes every config-level rule."""
    from podshield.scanners.hygiene import build_rules, run_rules
    from podshield.schemas import FilesystemReport, ImageInfo

    settings = support.make_settings(tmp_path / "state", "unix:///x")
    golden = ImageInfo(
        id="sha256:" + "a" * 64,
        repo_tags=[GOLDEN.ref],
        user="1001",
        labels={
            "org.opencontainers.image.authors": "x",
            "org.opencontainers.image.version": "1",
            "org.opencontainers.image.source": "x",
            "org.opencontainers.image.base.name": "registry.access.redhat.com/ubi9/ubi-minimal",
        },
        healthcheck={"Test": ["CMD", "/usr/bin/true"]},
        size=120 * 1024 * 1024,
        layer_count=5,
        filesystem=FilesystemReport(),
    )
    from datetime import UTC, datetime

    golden.created = datetime.now(UTC)
    assert run_rules(golden, build_rules(settings)) == []
