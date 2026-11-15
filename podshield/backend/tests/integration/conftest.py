"""Fixtures for the integration suite: a private Podman API socket, image builds, cleanup.

Nothing here touches host configuration: the Podman API socket lives in a temp directory, the
signature policy is a temp file, and the SQLite database is per test. The session cleanup
removes every ``pstest-*`` container, mount and image (also those left by a crashed run), plus
any base image the suite itself had to pull.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from podshield.config import Settings
from tests.integration import support
from tests.integration.support import ImageCase

_PULLED_BY_US: list[str] = []  # image IDs the suite pulled (and therefore removes again)


# ----------------------------------------------------------------------------- cleanup


@pytest.fixture(scope="session", autouse=True)
def _pstest_cleanup() -> Iterator[None]:
    if support.have("podman"):
        support.purge()  # leftovers from an aborted earlier run
    yield
    if support.have("podman"):
        support.purge()
        for iid in _PULLED_BY_US:
            support.podman("rmi", "-f", iid, check=False)


# ----------------------------------------------------------------------------- podman


@pytest.fixture(scope="session")
def podman_socket(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """A private ``podman system service`` socket (no dependence on podman.socket being enabled)."""
    sock = tmp_path_factory.mktemp("pstest-sock") / "podman.sock"
    proc = subprocess.Popen(
        ["podman", "system", "service", "--time", "0", f"unix://{sock}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 30
        while not sock.exists():
            if proc.poll() is not None:
                err = proc.stderr.read() if proc.stderr else ""
                pytest.skip(f"podman system service exited immediately: {err.strip()[-300:]}")
            if time.monotonic() > deadline:
                pytest.skip("podman system service did not create its socket within 30 s")
            time.sleep(0.2)
        yield f"unix://{sock}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        if proc.stderr:
            proc.stderr.close()


@pytest.fixture(scope="session")
def pull_image() -> Callable[[str], str]:
    """Pull ``ref`` if missing; skip the test (with the reason) when the pull is impossible."""

    def pull(ref: str) -> str:
        if not support.image_exists(ref):
            proc = support.podman("pull", ref, check=False, timeout=900)
            if proc.returncode != 0:
                pytest.skip(f"cannot pull {ref}: {(proc.stderr or proc.stdout).strip()[-200:]}")
            _PULLED_BY_US.append(support.image_id(ref))
        return ref

    return pull


@pytest.fixture(scope="session")
def base_image(pull_image: Callable[[str], str]) -> str:
    return pull_image(support.BASE_REF)


@pytest.fixture(scope="session")
def build(base_image: str) -> Callable[[ImageCase], str]:
    """Build a case image once per session and return its reference."""
    built: dict[str, str] = {}

    def _build(case: ImageCase) -> str:
        for option in case.needs:
            if not support.build_supports(option):
                pytest.skip(f"this podman build does not support {option}")
        if case.ref not in built:
            support.build_image(case)
            built[case.ref] = case.ref
        return built[case.ref]

    return _build


@pytest.fixture
def isettings(tmp_path: Path, podman_socket: str) -> Settings:
    return support.make_settings(tmp_path / "state", podman_socket)
