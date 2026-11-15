"""One real image per hygiene rule, each of which must trigger exactly that rule.

The golden image must come out clean: grade A, no findings. Every image is built from
tests/integration/images/*.Containerfile on ubi-minimal and scanned through the real Podman API
(and, for the mount rules, the real filesystem scanner).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from podshield.config import Settings, TrustSettings
from podshield.orchestrator import ImageResult
from tests.integration import support
from tests.integration.support import GOLDEN, MOUNT_RULES, RULE_CASES, ImageCase

pytestmark = pytest.mark.integration


def _scan(case: ImageCase, build: Callable[[ImageCase], str], settings: Settings) -> ImageResult:
    ref = build(case)
    summary = support.scan(settings, ref)
    assert summary.results, f"{ref} was not scanned: {summary.errors}"
    fs = summary.scanners.get("filesystem")
    needs_mount = case.rule is None or case.rule in MOUNT_RULES
    if needs_mount and fs is not None and fs.status != "ok":
        if not support.IS_ROOT:
            pytest.skip(f"mount rules are skipped in rootless mode here: {fs.detail}")
        pytest.fail(f"filesystem scanner is {fs.status} on a rootful host: {fs.detail}")
    return summary.results[0]


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda c: str(c.rule))
def test_image_triggers_exactly_its_rule(
    case: ImageCase, build: Callable[[ImageCase], str], isettings: Settings
) -> None:
    result = _scan(case, build, isettings)
    found = support.rule_ids(result)
    details = {f.rule_id: f.evidence for f in result.findings}
    assert found == {case.rule}, f"{case.ref}: expected only {case.rule}, got {details}"


def test_golden_image_scores_a_with_no_findings(
    build: Callable[[ImageCase], str], isettings: Settings
) -> None:
    result = _scan(GOLDEN, build, isettings)
    assert result.findings == [], {f.rule_id: f.evidence for f in result.findings}
    assert (result.score.grade, result.score.score) == ("A", 100)


def test_stock_policy_flags_only_the_signature_rule_on_the_golden_image(
    build: Callable[[ImageCase], str], isettings: Settings
) -> None:
    """With the host's real policy.json a locally built image is never signature-verified."""
    isettings.trust = TrustSettings()  # the host's /etc/containers/*
    if not Path(isettings.trust.policy_path).is_file():
        pytest.skip("no /etc/containers/policy.json on this host")
    result = _scan(GOLDEN, build, isettings)
    assert support.rule_ids(result) == {"PS-014"}
    assert result.score.grade == "A"  # one MEDIUM finding costs 4 points
