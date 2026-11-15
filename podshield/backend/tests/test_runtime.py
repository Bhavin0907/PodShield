from __future__ import annotations

import pytest

from podshield.config import RuleOverride, Settings
from podshield.scanners.hygiene import rule_catalog
from podshield.scanners.runtime import (
    RUNTIME_REGISTRY,
    ContainerInfo,
    MountInfo,
    audit_containers,
    build_runtime_rules,
    parse_container,
    register_runtime,
    sensitive_mount_reason,
)
from podshield.schemas import Severity
from tests.conftest import load_json


@pytest.fixture
def containers() -> list[dict[str, object]]:
    return load_json("containers.json")  # type: ignore[no-any-return]


def test_parse_container(containers: list[dict[str, object]]) -> None:
    c = parse_container(containers[0])
    assert c.name == "evil" and c.short_id == "aaaaaaaaaaaa"
    assert c.privileged and c.network_mode == "host" and c.pid_mode == "host"
    assert c.image == "localhost/demo-bad:latest"
    assert len(c.mounts) == 4 and c.mounts[1].rw is False


def test_parse_container_tolerates_missing_sections() -> None:
    c = parse_container({"Id": "abc"})
    assert c.id == "abc" and not c.privileged and c.mounts == [] and c.cap_add == []


def test_evil_container_trips_every_rule(
    settings: Settings, containers: list[dict[str, object]]
) -> None:
    audits = {a.container.name: a for a in audit_containers(containers, settings)}
    evil = audits["evil"]
    assert {f.rule_id for f in evil.findings} == {
        "PS-R01",
        "PS-R02",
        "PS-R03",
        "PS-R04",
        "PS-R05",
    }
    assert evil.score.grade == "F"
    by_id = {f.rule_id: f for f in evil.findings}
    assert by_id["PS-R01"].severity is Severity.CRITICAL
    assert by_id["PS-R02"].severity is Severity.HIGH
    assert by_id["PS-R03"].evidence == [
        "Network namespace: host (--network host)",
        "PID namespace: host (--pid host)",
    ]
    assert by_id["PS-R05"].evidence == ["--cap-add SYS_ADMIN", "--cap-add NET_ADMIN"]
    mounts = by_id["PS-R04"].evidence
    assert len(mounts) == 2
    assert any("/run/podman/podman.sock" in m and "runtime socket" in m for m in mounts)
    assert any(m.startswith("/etc -> /host-etc (ro)") for m in mounts)
    assert not any("/srv/app/data" in m for m in mounts)
    assert not any("storage/volumes" in m for m in mounts)  # named volumes are fine


def test_hardened_container_is_clean(
    settings: Settings, containers: list[dict[str, object]]
) -> None:
    web = next(a for a in audit_containers(containers, settings) if a.container.name == "web")
    assert web.findings == []
    assert (web.score.score, web.score.grade) == (100, "A")


def test_audits_sorted_worst_first(settings: Settings, containers: list[dict[str, object]]) -> None:
    audits = audit_containers(containers, settings)
    assert [a.container.name for a in audits] == ["evil", "web"]


@pytest.mark.parametrize(
    ("opt", "hit"),
    [
        ("label=disable", True),
        ("label:disable", True),
        (" label=disable ", True),
        ("label=type:spc_t", False),
        ("seccomp=unconfined", False),
        ("label=level:s0:c1,c2", False),
    ],
)
def test_r02_variants(settings: Settings, opt: str, hit: bool) -> None:
    rule = next(r for r in build_runtime_rules(settings) if r.id == "PS-R02")
    assert bool(rule.evaluate(ContainerInfo(id="x", security_opt=[opt]))) is hit


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("/", True),
        ("/etc", True),
        ("/etc/", True),
        ("/var/run", True),
        ("/run", True),
        ("//etc", True),
        ("/etc/../etc", True),
        ("/var/run/docker.sock", True),
        ("/run/user/1000/podman/podman.sock", True),
        ("/var/lib/containers/storage", True),
        ("/root/.ssh", True),
        ("/etc/ssh/ssh_host_key", True),
        ("/srv/app", False),
        ("/etc/pki/tls/certs/ca-bundle.crt", False),
        ("/home/u/data", False),
        ("/opt", False),
        ("", False),
        ("relative/path", False),
    ],
)
def test_r04_paths(source: str, flagged: bool) -> None:
    assert (sensitive_mount_reason(source) is not None) is flagged


def test_r04_ignores_named_volumes(settings: Settings) -> None:
    rule = next(r for r in build_runtime_rules(settings) if r.id == "PS-R04")
    vol = ContainerInfo(id="x", mounts=[MountInfo(type="volume", source="/var/lib/containers/x")])
    assert rule.evaluate(vol) == []


def test_r05_ignores_safe_caps_and_flags_all(settings: Settings) -> None:
    rule = next(r for r in build_runtime_rules(settings) if r.id == "PS-R05")
    assert rule.evaluate(ContainerInfo(id="x", cap_add=["NET_BIND_SERVICE", "CHOWN"])) == []
    (f,) = rule.evaluate(ContainerInfo(id="x", cap_add=["all", "CAP_SYS_PTRACE"]))
    assert f.evidence == ["--cap-add ALL", "--cap-add SYS_PTRACE"]


def test_ipc_host_is_flagged(settings: Settings) -> None:
    rule = next(r for r in build_runtime_rules(settings) if r.id == "PS-R03")
    (f,) = rule.evaluate(ContainerInfo(id="x", ipc_mode="host"))
    assert f.evidence == ["IPC namespace: host (--ipc host)"]


def test_overrides_disable_and_severity(
    settings: Settings, containers: list[dict[str, object]]
) -> None:
    settings.rules["PS-R01"] = RuleOverride(enabled=False)
    settings.rules["PS-R02"] = RuleOverride(severity=Severity.LOW)
    evil = audit_containers(containers, settings)[0]
    by_id = {f.rule_id: f for f in evil.findings}
    assert "PS-R01" not in by_id
    assert by_id["PS-R02"].severity is Severity.LOW


def test_rule_catalog_includes_runtime_rules(settings: Settings) -> None:
    catalog = {r.id: r for r in rule_catalog(settings)}
    assert {"PS-R01", "PS-R02", "PS-R03", "PS-R04", "PS-R05"} <= set(catalog)
    assert {"PS-001", "PS-014"} <= set(catalog)
    assert catalog["PS-R01"].kind == "runtime" and catalog["PS-001"].kind == "image"
    assert [r.id for r in rule_catalog(settings)] == sorted(catalog)


def test_runtime_duplicate_registration_rejected() -> None:
    with pytest.raises(ValueError):

        @register_runtime
        class Dup(RUNTIME_REGISTRY["PS-R01"]):  # type: ignore[misc]
            pass


def test_crashing_runtime_rule_is_isolated(settings: Settings) -> None:
    class Boom(RUNTIME_REGISTRY["PS-R01"]):  # type: ignore[misc]
        def evaluate(self, container: ContainerInfo):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

    from podshield.scanners.runtime import audit_container

    rules = [Boom(settings), *build_runtime_rules(settings)]
    audit = audit_container(
        ContainerInfo(id="x" * 12, security_opt=["label=disable"]), rules, settings
    )
    assert [f.rule_id for f in audit.findings] == ["PS-R02"]
