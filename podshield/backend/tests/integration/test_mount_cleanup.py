"""`podman image mount` must always be undone, even when the scan blows up half way."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from collections.abc import Callable

import pytest

from podshield.config import Settings
from podshield.scanners import mount
from tests.integration import support
from tests.integration.support import GOLDEN, ImageCase

pytestmark = pytest.mark.integration


def test_clean_scan_leaves_nothing_mounted(
    build: Callable[[ImageCase], str], isettings: Settings
) -> None:
    ref = build(GOLDEN)
    support.scan_one(isettings, ref)
    assert not support.is_mounted(ref)


def test_context_manager_unmounts_when_the_body_raises(build: Callable[[ImageCase], str]) -> None:
    """Runs under `podman unshare` when rootless, exactly like the real helper does."""
    ref = build(GOLDEN)
    iid = support.image_id(ref)
    code = textwrap.dedent(f"""
        from podshield.scanners.mount import mounted_image
        with mounted_image({iid!r}) as root:
            assert root.is_dir(), root
            raise RuntimeError("pstest: scan exploded mid-way")
    """)
    prefix = [] if support.IS_ROOT else ["podman", "unshare"]
    proc = subprocess.run(
        [*prefix, sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode != 0 and "scan exploded mid-way" in proc.stderr, proc.stderr[-800:]
    assert not support.is_mounted(ref), "image is still mounted after the failure"


@pytest.mark.skipif(not support.IS_ROOT, reason="in-process mounting needs root")
def test_scanner_unmounts_when_the_filesystem_walk_raises(
    build: Callable[[ImageCase], str], isettings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    ref = build(GOLDEN)
    iid = support.image_id(ref)

    def explode(*_a: object, **_k: object) -> None:
        raise RuntimeError("pstest: walk exploded")

    monkeypatch.setattr(mount, "scan_tree", explode)
    with pytest.raises(RuntimeError, match="walk exploded"):
        mount.FilesystemScanner(isettings)(iid)
    assert not support.is_mounted(ref)


@pytest.mark.skipif(not support.IS_ROOT, reason="in-process mounting needs root")
def test_orchestrated_scan_survives_a_crashing_filesystem_scan(
    build: Callable[[ImageCase], str], isettings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    ref = build(GOLDEN)
    monkeypatch.setattr(
        mount,
        "scan_tree",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("pstest: walk exploded")),
    )
    summary = support.scan(isettings, ref)
    assert summary.status == "completed" and summary.results  # degraded, not failed
    assert summary.scanners["filesystem"].status == "failed"
    assert not support.is_mounted(ref)
