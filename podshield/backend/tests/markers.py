"""Environment checks behind the pytest markers.

A test marked ``requires_root``, ``requires_oscap``, ``requires_trivy``, ``requires_network`` or
``integration`` is *skipped with a reason* (never failed) when its prerequisite is missing, so
the same suite runs on a laptop and on the RHEL VM.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

NETWORK_PROBE = ("registry.access.redhat.com", 443)


@lru_cache(maxsize=1)
def _network_reachable() -> bool:
    if os.environ.get("PODSHIELD_TEST_OFFLINE") == "1":
        return False
    try:
        with socket.create_connection(NETWORK_PROBE, timeout=3):
            return True
    except OSError:
        return False


def check_integration() -> str | None:
    if sys.platform != "linux":
        return f"integration tests need Linux with Podman (running on {sys.platform})"
    if shutil.which("podman") is None:
        return "podman is not installed"
    return None


def check_root() -> str | None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        return "needs root (rootful Podman and image mounts); run with sudo"
    return None


def check_oscap() -> str | None:
    if shutil.which("oscap-podman") is None:
        return "oscap-podman is not installed (dnf install openscap-utils)"
    feed = Path(os.environ.get("PODSHIELD_OVAL_PATH", "/var/lib/podshield/oval/rhel-9.oval.xml"))
    if not feed.is_file():
        return f"OVAL feed not found at {feed} (set PODSHIELD_OVAL_PATH)"
    return None


def check_trivy() -> str | None:
    return None if shutil.which("trivy") else "trivy is not installed"


def check_network() -> str | None:
    if _network_reachable():
        return None
    return f"no network access to {NETWORK_PROBE[0]} (set PODSHIELD_TEST_OFFLINE=0 to retry)"


CHECKS: dict[str, Callable[[], str | None]] = {
    "integration": check_integration,
    "requires_root": check_root,
    "requires_oscap": check_oscap,
    "requires_trivy": check_trivy,
    "requires_network": check_network,
}


def skip_reason(marker_names: list[str]) -> str | None:
    """First unmet prerequisite for the given markers, or None if the test can run."""
    for name in marker_names:
        check = CHECKS.get(name)
        if check and (reason := check()):
            return reason
    return None
