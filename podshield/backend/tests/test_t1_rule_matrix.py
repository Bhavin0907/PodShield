"""T1: every rule has at least one positive (triggers) and one negative (does not) case.

The base image is the saved `inspect_good.json` sample; each case changes just enough of it to
trip (or not trip) exactly one rule. A meta-test fails if a rule is added without cases, so the
matrix cannot silently go stale.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from podshield.config import Settings
from podshield.scanners.hygiene import RULE_REGISTRY, Rule, build_rules, run_rules
from podshield.scanners.runtime import (
    RUNTIME_REGISTRY,
    ContainerInfo,
    MountInfo,
    build_runtime_rules,
)
from podshield.schemas import CacheDir, FilesystemReport, FsSecret, ImageInfo, SetuidFile

Mutation = Callable[[ImageInfo], ImageInfo]

GIB = 1024**3


def with_fs(image: ImageInfo, **facts: object) -> ImageInfo:
    return image.model_copy(update={"filesystem": FilesystemReport(**facts)})  # type: ignore[arg-type]


def upd(**fields: object) -> Mutation:
    return lambda img: img.model_copy(update=fields)


def days_ago(n: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=n)


# rule id -> (mutation that must trigger it, mutation that must not trigger it)
IMAGE_CASES: dict[str, tuple[Mutation, Mutation]] = {
    "PS-001": (upd(user=""), upd(user="1001")),
    "PS-002": (upd(repo_tags=["localhost/app:latest"]), upd(repo_tags=["localhost/app:1.2.3"])),
    "PS-003": (
        upd(env=["AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"]),
        upd(env=["PATH=/usr/bin", "LANG=C.UTF-8"]),
    ),
    "PS-004": (
        lambda i: with_fs(
            i,
            secrets=[
                FsSecret(
                    path="/root/.aws/credentials",
                    reason="AWS credentials file",
                    masked_value="AKIA****",
                )
            ],
        ),
        lambda i: with_fs(i),
    ),
    "PS-005": (upd(created=days_ago(400)), upd(created=days_ago(1))),
    "PS-006": (
        upd(repo_tags=["docker.io/library/nginx:1.25"], labels={}, annotations={}),
        upd(),  # the sample is a ubi-minimal image
    ),
    "PS-007": (upd(size=2 * GIB), upd(size=10 * 1024 * 1024)),
    "PS-008": (upd(layer_count=60), upd(layer_count=3)),
    "PS-009": (
        lambda i: with_fs(i, cache_dirs=[CacheDir(path="/var/cache/dnf", files=10, size=1 << 20)]),
        lambda i: with_fs(i),
    ),
    "PS-010": (
        lambda i: with_fs(i, setuid_files=[SetuidFile(path="/usr/bin/su", mode="4755")]),
        lambda i: with_fs(i),
    ),
    "PS-011": (upd(healthcheck=None), upd(healthcheck={"Test": ["CMD", "true"]})),
    "PS-012": (upd(labels={}), upd()),
    "PS-013": (upd(exposed_ports=["22/tcp"]), upd(exposed_ports=["8080/tcp"])),
    "PS-014": (
        upd(repo_tags=["localhost/app:1"], repo_digests=[]),
        upd(),  # ubi-minimal from registry.access.redhat.com, covered by signedBy in the policy
    ),
    "PS-015": (lambda i: with_fs(i, shells=["/bin/sh"]), lambda i: with_fs(i)),
}

RUNTIME_CASES: dict[str, tuple[ContainerInfo, ContainerInfo]] = {
    "PS-R01": (ContainerInfo(id="x", privileged=True), ContainerInfo(id="x")),
    "PS-R02": (
        ContainerInfo(id="x", security_opt=["label=disable"]),
        ContainerInfo(id="x", security_opt=["no-new-privileges"]),
    ),
    "PS-R03": (
        ContainerInfo(id="x", network_mode="host"),
        ContainerInfo(id="x", network_mode="bridge"),
    ),
    "PS-R04": (
        ContainerInfo(id="x", mounts=[MountInfo(type="bind", source="/etc", destination="/h")]),
        ContainerInfo(
            id="x", mounts=[MountInfo(type="bind", source="/srv/data", destination="/d")]
        ),
    ),
    "PS-R05": (
        ContainerInfo(id="x", cap_add=["SYS_ADMIN"]),
        ContainerInfo(id="x", cap_add=["NET_BIND_SERVICE"]),
    ),
}


def only_rule(rule_id: str, settings: Settings) -> Rule:
    return next(r for r in build_rules(settings) if r.id == rule_id)


def test_matrix_covers_every_registered_rule() -> None:
    assert set(IMAGE_CASES) == set(RULE_REGISTRY), "add positive/negative cases for new rules"
    assert set(RUNTIME_CASES) == set(RUNTIME_REGISTRY)
    assert len(IMAGE_CASES) == 15 and len(RUNTIME_CASES) == 5  # PS-001..015, PS-R01..R05


@pytest.mark.parametrize("rule_id", sorted(IMAGE_CASES))
def test_image_rule_triggers_on_positive_case(
    rule_id: str, settings: Settings, good_image: ImageInfo
) -> None:
    positive, _ = IMAGE_CASES[rule_id]
    findings = only_rule(rule_id, settings).evaluate(positive(good_image))
    assert findings, f"{rule_id} should trigger"
    assert {f.rule_id for f in findings} == {rule_id}
    for f in findings:
        assert f.title and f.description and f.evidence and f.remediation
        assert f.severity is RULE_REGISTRY[rule_id].default_severity


@pytest.mark.parametrize("rule_id", sorted(IMAGE_CASES))
def test_image_rule_stays_quiet_on_negative_case(
    rule_id: str, settings: Settings, good_image: ImageInfo
) -> None:
    _, negative = IMAGE_CASES[rule_id]
    assert only_rule(rule_id, settings).evaluate(negative(good_image)) == []


@pytest.mark.parametrize("rule_id", sorted(IMAGE_CASES))
def test_full_engine_reports_the_rule_for_the_positive_case(
    rule_id: str, settings: Settings, good_image: ImageInfo
) -> None:
    positive, _ = IMAGE_CASES[rule_id]
    image = positive(good_image)
    if image.filesystem is None:
        image = image.model_copy(update={"filesystem": FilesystemReport()})
    assert rule_id in {f.rule_id for f in run_rules(image, build_rules(settings))}


def test_golden_sample_has_no_findings_at_all(settings: Settings, good_image: ImageInfo) -> None:
    image = with_fs(good_image)
    assert run_rules(image, build_rules(settings)) == []


@pytest.mark.parametrize("rule_id", sorted(RUNTIME_CASES))
def test_runtime_rule_positive_and_negative(rule_id: str, settings: Settings) -> None:
    positive, negative = RUNTIME_CASES[rule_id]
    rule = next(r for r in build_runtime_rules(settings) if r.id == rule_id)
    findings = rule.evaluate(positive)
    assert [f.rule_id for f in findings] == [rule_id]
    assert findings[0].evidence and findings[0].remediation
    assert rule.evaluate(negative) == []


def test_each_positive_case_trips_only_its_own_runtime_rule(settings: Settings) -> None:
    rules = build_runtime_rules(settings)
    for rule_id, (positive, _) in RUNTIME_CASES.items():
        hit = {f.rule_id for r in rules for f in r.evaluate(positive)}
        assert hit == {rule_id}, f"{rule_id} case also tripped {hit - {rule_id}}"
