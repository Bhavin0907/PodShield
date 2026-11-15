from __future__ import annotations

import pytest

from podshield.config import Settings
from podshield.scanners import hygiene
from podshield.scanners.hygiene import build_rules, run_rules
from podshield.schemas import (
    CacheDir,
    FilesystemReport,
    Finding,
    FsSecret,
    ImageInfo,
    SetuidFile,
    Severity,
)


def run(rule_id: str, image: ImageInfo, settings: Settings) -> list[Finding]:
    rules = [r for r in build_rules(settings) if r.id == rule_id]
    assert len(rules) == 1
    return run_rules(image, rules)


def with_fs(image: ImageInfo, **kwargs: object) -> ImageInfo:
    image.filesystem = FilesystemReport(**kwargs)  # type: ignore[arg-type]
    return image


def test_all_rules_registered() -> None:
    expected = {f"PS-{n:03d}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15)}
    assert expected <= set(hygiene.RULE_REGISTRY)


# ---- filesystem-backed rules are silent without a filesystem report


@pytest.mark.parametrize("rule_id", ["PS-004", "PS-009", "PS-010", "PS-015"])
def test_fs_rules_need_filesystem(settings: Settings, bad_image: ImageInfo, rule_id: str) -> None:
    assert hygiene.RULE_REGISTRY[rule_id].needs_filesystem
    assert bad_image.filesystem is None
    assert run(rule_id, bad_image, settings) == []
    with_fs(bad_image)  # empty report: still nothing
    assert run(rule_id, bad_image, settings) == []


# ---- PS-004


def test_ps004(settings: Settings, bad_image: ImageInfo) -> None:
    with_fs(
        bad_image,
        secrets=[
            FsSecret(
                path="/root/.ssh/id_rsa:1",
                reason="Private key block pattern",
                masked_value="----****",
            ),
            FsSecret(path="/home/u/.netrc", reason="netrc credentials"),
        ],
    )
    (finding,) = run("PS-004", bad_image, settings)
    assert finding.severity is Severity.CRITICAL
    assert "/root/.ssh/id_rsa:1 - Private key block pattern (----****)" in finding.evidence
    assert "/home/u/.netrc - netrc credentials" in finding.evidence
    assert "--mount=type=secret" in finding.remediation


def test_evidence_is_capped(settings: Settings, bad_image: ImageInfo) -> None:
    with_fs(bad_image, setuid_files=[SetuidFile(path=f"/bin/f{i}", mode="4755") for i in range(30)])
    (finding,) = run("PS-010", bad_image, settings)
    assert len(finding.evidence) == 21
    assert finding.evidence[-1] == "... and 10 more"


# ---- PS-006


def test_ps006_flags_unknown_base(settings: Settings, bad_image: ImageInfo) -> None:
    (finding,) = run("PS-006", bad_image, settings)
    assert finding.severity is Severity.MEDIUM
    assert any("could not be identified" in e for e in finding.evidence)


def test_ps006_declared_untrusted_base(settings: Settings, bad_image: ImageInfo) -> None:
    bad_image.labels = {"org.opencontainers.image.base.name": "docker.io/library/ubuntu:22.04"}
    (finding,) = run("PS-006", bad_image, settings)
    assert "docker.io/library/ubuntu:22.04" in finding.evidence[0]


@pytest.mark.parametrize(
    "base",
    [
        "registry.access.redhat.com/ubi9/ubi-minimal:9.4",
        "registry.redhat.io/rhel9/rhel-bootc:latest",
        "quay.io/podman/stable:v5",
        "ubi9/ubi-micro",
        "ubi8:latest",
    ],
)
def test_ps006_trusted_declared_base(settings: Settings, bad_image: ImageInfo, base: str) -> None:
    bad_image.labels = {"org.opencontainers.image.base.name": base}
    assert run("PS-006", bad_image, settings) == []


def test_ps006_base_name_from_annotations(settings: Settings, bad_image: ImageInfo) -> None:
    bad_image.annotations = {"org.opencontainers.image.base.name": "docker.io/alpine:3"}
    assert len(run("PS-006", bad_image, settings)) == 1


def test_ps006_ubi_labels_inherited(settings: Settings, bad_image: ImageInfo) -> None:
    bad_image.labels = {"vendor": "Red Hat, Inc.", "name": "ubi9/ubi-minimal"}
    assert run("PS-006", bad_image, settings) == []
    bad_image.labels = {"com.redhat.component": "ubi9-minimal-container"}
    assert run("PS-006", bad_image, settings) == []


def test_ps006_trusted_registry_tag(settings: Settings, good_image: ImageInfo) -> None:
    assert run("PS-006", good_image, settings) == []  # tag is on registry.access.redhat.com


def test_ps006_prefix_is_path_boundary(settings: Settings, bad_image: ImageInfo) -> None:
    bad_image.labels = {"org.opencontainers.image.base.name": "quay.io/podmanevil/img:1"}
    assert len(run("PS-006", bad_image, settings)) == 1


def test_ps006_allowlist_from_config(settings: Settings, bad_image: ImageInfo) -> None:
    bad_image.labels = {"org.opencontainers.image.base.name": "registry.corp.example/base/os:1"}
    assert len(run("PS-006", bad_image, settings)) == 1
    settings.trust.trusted_registries.append("registry.corp.example")
    assert run("PS-006", bad_image, settings) == []


# ---- PS-007 / PS-008


def test_ps007(settings: Settings, good_image: ImageInfo) -> None:
    assert run("PS-007", good_image, settings) == []
    good_image.size = 2 * 1024**3
    (finding,) = run("PS-007", good_image, settings)
    assert finding.severity is Severity.LOW
    assert "2.0 GiB" in finding.evidence[0]
    good_image.size = 1024**3  # exactly the limit is fine
    assert run("PS-007", good_image, settings) == []


def test_ps007_configurable(settings: Settings, good_image: ImageInfo) -> None:
    settings.thresholds.max_image_size_mb = 50
    assert len(run("PS-007", good_image, settings)) == 1  # 94 MiB


def test_ps008(settings: Settings, good_image: ImageInfo) -> None:
    good_image.layer_count = 30
    assert run("PS-008", good_image, settings) == []
    good_image.layer_count = 31
    (finding,) = run("PS-008", good_image, settings)
    assert finding.evidence[0] == "Layers: 31"
    settings.thresholds.max_layers = 40
    assert run("PS-008", good_image, settings) == []


# ---- PS-009


def test_ps009(settings: Settings, bad_image: ImageInfo) -> None:
    with_fs(bad_image, cache_dirs=[CacheDir(path="/var/cache/dnf", files=12, size=5 * 1024 * 1024)])
    (finding,) = run("PS-009", bad_image, settings)
    assert finding.severity is Severity.LOW
    assert finding.evidence == ["/var/cache/dnf: 12 files, 5.0 MiB"]


# ---- PS-010


def test_ps010(settings: Settings, bad_image: ImageInfo) -> None:
    with_fs(bad_image, setuid_files=[SetuidFile(path="/usr/bin/su", mode="4755")])
    (finding,) = run("PS-010", bad_image, settings)
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence == ["/usr/bin/su (mode 4755)"]
    assert "no-new-privileges" in finding.remediation


# ---- PS-013


def test_ps013(settings: Settings, bad_image: ImageInfo) -> None:
    bad_image.exposed_ports = ["22/tcp", "8080/tcp", "5432/tcp", "3306/udp"]
    (finding,) = run("PS-013", bad_image, settings)
    assert finding.evidence == ["22/tcp (SSH)", "5432/tcp (PostgreSQL)", "3306/udp (MySQL/MariaDB)"]


def test_ps013_clean(settings: Settings, good_image: ImageInfo) -> None:
    assert run("PS-013", good_image, settings) == []
    good_image.exposed_ports = ["8080", "weird/tcp"]
    assert run("PS-013", good_image, settings) == []


def test_ps013_bare_port_without_protocol(settings: Settings, good_image: ImageInfo) -> None:
    good_image.exposed_ports = ["22"]
    assert len(run("PS-013", good_image, settings)) == 1


# ---- PS-015


def test_ps015(settings: Settings, bad_image: ImageInfo) -> None:
    with_fs(bad_image, shells=["/bin/bash"], package_managers=["/usr/bin/microdnf"])
    (finding,) = run("PS-015", bad_image, settings)
    assert finding.severity is Severity.INFO
    assert finding.evidence == ["Shells: /bin/bash", "Package managers: /usr/bin/microdnf"]


def test_ps015_shell_only(settings: Settings, bad_image: ImageInfo) -> None:
    with_fs(bad_image, shells=["/bin/sh"])
    assert run("PS-015", bad_image, settings)[0].evidence == ["Shells: /bin/sh"]
