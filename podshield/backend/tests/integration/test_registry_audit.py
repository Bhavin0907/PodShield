"""Pre-pull registry audit against a throwaway local registry (skopeo, no image pulled).

Starts `registry:2` as the container ``pstest-registry`` on localhost:5000 (override with
PSTEST_REGISTRY_PORT). TLS verification is disabled for this local registry only, in the test
configuration, never in PodShield's defaults.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from podshield.config import Settings
from tests.integration import support
from tests.integration.support import GOLDEN, REGISTRY_PORT, RULE_CASES, ImageCase

pytestmark = pytest.mark.integration

REGISTRY = f"localhost:{REGISTRY_PORT}"


@pytest.fixture(scope="module")
def local_registry(pull_image: Callable[[str], str]) -> Iterator[str]:
    if not support.have("skopeo"):
        pytest.skip("skopeo is not installed (dnf install skopeo)")
    pull_image(support.REGISTRY_IMAGE)
    started = support.podman(
        "run",
        "-d",
        "--name",
        f"{support.PREFIX}registry",
        "-p",
        f"127.0.0.1:{REGISTRY_PORT}:5000",
        support.REGISTRY_IMAGE,
        check=False,
    )
    if started.returncode != 0:
        pytest.skip(
            f"cannot start the local registry (port {REGISTRY_PORT} busy?): "
            f"{started.stderr.strip()[-200:]}"
        )
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{REGISTRY_PORT}/v2/", timeout=2):
                    break
            except (urllib.error.URLError, OSError):
                if time.monotonic() > deadline:
                    pytest.skip("the local registry did not become ready within 30 s")
                time.sleep(0.5)
        yield REGISTRY
    finally:
        support.podman("rm", "-f", "-t", "0", "-v", f"{support.PREFIX}registry", check=False)


@pytest.fixture
def push(local_registry: str, build: Callable[[ImageCase], str]) -> Callable[[ImageCase], str]:
    def _push(case: ImageCase) -> str:
        target = f"{local_registry}/{case.name}:{case.tag}"
        support.podman("tag", build(case), target)
        # Keep docker schema 2 (gzip): an OCI conversion (e.g. a zstd compression default)
        # drops HEALTHCHECK, which would add PS-011 to every audit.
        support.podman(
            "push", "--tls-verify=false", "--format", "v2s2", "--compression-format", "gzip", target
        )
        return target

    return _push


@pytest.fixture
def audit(isettings: Settings, tmp_path: Path) -> Callable[[str], dict[str, object]]:
    isettings.registry.tls_verify = False  # local test registry only
    config = support.write_config(isettings, tmp_path / "config.toml")

    def run(reference: str) -> dict[str, object]:
        proc = support.run_cli(config, "registry", reference, "--json", timeout=180)
        assert proc.returncode == 0, proc.stderr[-1500:]
        doc: dict[str, object] = json.loads(proc.stdout)
        return doc

    return run


def _rules(doc: dict[str, object]) -> set[str]:
    findings = doc["findings"]
    assert isinstance(findings, list)
    return {f["rule_id"] for f in findings}


def test_golden_image_audits_clean_before_any_pull(
    push: Callable[[ImageCase], str], audit: Callable[[str], dict[str, object]]
) -> None:
    doc = audit(push(GOLDEN))
    assert _rules(doc) == set(), doc["findings"]
    assert doc["grade"] == "A"
    assert doc["skipped_rules"], "rules that need a pulled filesystem must be reported as skipped"


@pytest.mark.parametrize("rule", ["PS-001", "PS-002", "PS-003", "PS-013"])
def test_registry_audit_finds_config_level_rules(
    rule: str, push: Callable[[ImageCase], str], audit: Callable[[str], dict[str, object]]
) -> None:
    (case,) = [c for c in RULE_CASES if c.rule == rule]
    doc = audit(push(case))
    assert _rules(doc) == {rule}, doc["findings"]


def test_the_audit_does_not_pull_the_image(
    push: Callable[[ImageCase], str], audit: Callable[[str], dict[str, object]]
) -> None:
    target = push(GOLDEN)
    support.podman("rmi", "-f", target, check=False)  # drop only the registry-tagged name
    audit(target)
    assert not support.image_exists(target), "audit must not pull the image"


def test_unknown_image_is_a_clean_error_not_a_crash(
    local_registry: str, isettings: Settings, tmp_path: Path
) -> None:
    isettings.registry.tls_verify = False
    config = support.write_config(isettings, tmp_path / "config.toml")
    proc = support.run_cli(config, "registry", f"{local_registry}/pstest-nope:1", timeout=120)
    assert proc.returncode == 2
    assert "error:" in proc.stderr and "Traceback" not in proc.stderr
