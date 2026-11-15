"""Smallest possible integration test: proves the harness and the Podman connection.

The real integration suite (images per rule, runtime rules, scanners, watcher) is phase T2.
"""

from __future__ import annotations

import subprocess

import pytest

pytestmark = pytest.mark.integration


def test_podman_cli_works() -> None:
    proc = subprocess.run(
        ["podman", "info", "--format", "{{.Host.Arch}}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip()
