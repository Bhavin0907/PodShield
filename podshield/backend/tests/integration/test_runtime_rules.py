"""PS-R01..R05 against real containers started with the risky flags."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from podshield.config import Settings
from podshield.podman_client import PodmanClient
from podshield.scanners.runtime import ContainerAudit, audit_containers
from tests.integration import support
from tests.integration.support import GOLDEN, PREFIX, ImageCase

pytestmark = pytest.mark.integration

# (container name suffix, podman run flags, rules that must fire, rules that may also fire)
RISKY: list[tuple[str, tuple[str, ...], set[str], set[str]]] = [
    # --privileged also disables SELinux labelling and may list capabilities.
    ("privileged", ("--privileged",), {"PS-R01"}, {"PS-R02", "PS-R05"}),
    ("nethost", ("--network", "host"), {"PS-R03"}, set()),
    ("pidhost", ("--pid", "host"), {"PS-R03"}, set()),
    ("nolabel", ("--security-opt", "label=disable"), {"PS-R02"}, set()),
    # :ro and no :z/:Z, so Podman never relabels the host's /etc.
    ("hostetc", ("-v", "/etc:/host-etc:ro"), {"PS-R04"}, set()),
    ("sysadmin", ("--cap-add", "SYS_ADMIN"), {"PS-R05"}, set()),
]


@pytest.fixture
def audit(
    build: Callable[[ImageCase], str], isettings: Settings
) -> Iterator[Callable[[str, tuple[str, ...]], ContainerAudit]]:
    """Start a container, return its audit; every container is force-removed afterwards."""
    image = build(GOLDEN)
    started: list[str] = []

    def run(name: str, flags: tuple[str, ...]) -> ContainerAudit:
        full = f"{PREFIX}rt-{name}"
        support.podman("run", "-d", "--name", full, *flags, image, "/usr/bin/sleep", "300")
        started.append(full)
        client = PodmanClient(isettings.podman.socket, isettings.podman.timeout_seconds)
        try:
            raw = client.list_containers()
        finally:
            client.close()
        mine = [a for a in audit_containers(raw, isettings) if a.container.name == full]
        assert len(mine) == 1, f"{full} not found among running containers"
        return mine[0]

    yield run
    for name in started:
        support.podman("rm", "-f", "-t", "0", "-v", name, check=False)


@pytest.mark.parametrize(
    ("name", "flags", "required", "allowed_extra"), RISKY, ids=[r[0] for r in RISKY]
)
def test_risky_flags_trigger_their_rule(
    name: str,
    flags: tuple[str, ...],
    required: set[str],
    allowed_extra: set[str],
    audit: Callable[[str, tuple[str, ...]], ContainerAudit],
) -> None:
    result = audit(name, flags)
    found = {f.rule_id for f in result.findings}
    assert required <= found, f"{flags}: expected {required}, got {found}"
    assert found <= required | allowed_extra, f"{flags}: unexpected rules {found - required}"


def test_each_rule_has_a_real_container_case() -> None:
    covered = set().union(*(r[2] for r in RISKY))
    assert covered == {"PS-R01", "PS-R02", "PS-R03", "PS-R04", "PS-R05"}


def test_a_default_container_is_clean(
    audit: Callable[[str, tuple[str, ...]], ContainerAudit],
) -> None:
    result = audit("plain", ())
    assert result.findings == [], [(f.rule_id, f.evidence) for f in result.findings]
    assert result.score.grade == "A"


def test_flags_that_look_similar_but_are_safe_do_not_trigger(
    audit: Callable[[str, tuple[str, ...]], ContainerAudit],
) -> None:
    result = audit(
        "safe",
        (
            "--cap-add",
            "NET_BIND_SERVICE",
            "--security-opt",
            "no-new-privileges",
            "-v",
            "pstest-safe-vol:/data",
        ),
    )
    try:
        assert result.findings == [], [(f.rule_id, f.evidence) for f in result.findings]
    finally:
        support.podman("volume", "rm", "-f", "pstest-safe-vol", check=False)
