"""T1: the marker-driven skip logic and the Makefile targets."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from tests import markers

ROOT = Path(__file__).resolve().parents[2]


def test_every_documented_marker_is_registered(pytestconfig: pytest.Config) -> None:
    registered = {line.split(":", 1)[0] for line in pytestconfig.getini("markers")}
    assert {
        "unit",
        "integration",
        "requires_root",
        "requires_oscap",
        "requires_trivy",
        "requires_network",
        "slow",
    } <= registered


def test_skip_reasons_name_what_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    monkeypatch.setattr(sys, "platform", "linux")
    assert "oscap-podman" in (markers.skip_reason(["requires_oscap"]) or "")
    assert "trivy" in (markers.skip_reason(["requires_trivy"]) or "")
    assert "podman" in (markers.skip_reason(["integration"]) or "")


def test_a_present_tool_means_no_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    assert markers.skip_reason(["requires_trivy"]) is None


def test_unknown_markers_never_skip() -> None:
    assert markers.skip_reason(["slow", "unit", "parametrize", "something_else"]) is None


@pytest.mark.skipif(sys.platform == "win32", reason="geteuid is POSIX only")
def test_root_check_follows_the_effective_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert "root" in (markers.check_root() or "")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert markers.check_root() is None


def test_root_check_on_platforms_without_geteuid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert "root" in (markers.check_root() or "")


def test_offline_switch_skips_network_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    markers._network_reachable.cache_clear()
    monkeypatch.setenv("PODSHIELD_TEST_OFFLINE", "1")
    try:
        assert "network" in (markers.check_network() or "")
    finally:
        markers._network_reachable.cache_clear()


def test_oscap_needs_the_feed_as_well_as_the_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setenv("PODSHIELD_OVAL_PATH", str(tmp_path / "missing.xml"))
    assert "OVAL feed" in (markers.check_oscap() or "")
    feed = tmp_path / "feed.xml"
    feed.write_text("<x/>", encoding="utf-8")
    monkeypatch.setenv("PODSHIELD_OVAL_PATH", str(feed))
    assert markers.check_oscap() is None


def test_makefile_defines_the_required_targets() -> None:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in (
        "test-unit",
        "test-integration",
        "test-api",
        "test-frontend",
        "test-e2e",
        "test-all",
        "coverage",
    ):
        assert f"\n{target}:" in text, target
    assert "--cov-fail-under=85" in text
    assert "\n    " not in text.replace("\n    $(", ""), "recipes must be indented with tabs"
