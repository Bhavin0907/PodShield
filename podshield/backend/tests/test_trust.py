from __future__ import annotations

import json
from pathlib import Path

import pytest

from podshield.config import Settings, TrustSettings
from podshield.scanners import trust
from podshield.scanners.hygiene import build_rules, run_rules
from podshield.scanners.trust import load_trust_policy, split_reference
from podshield.schemas import ImageInfo, Severity

SIGNED = [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/k"}]
ACCEPT = [{"type": "insecureAcceptAnything"}]


def cfg_for(
    tmp_path: Path,
    policy: object | None = None,
    registries: str | None = None,
    registries_d: dict[str, str] | None = None,
) -> TrustSettings:
    cfg = TrustSettings(
        policy_path=str(tmp_path / "policy.json"),
        registries_conf=str(tmp_path / "registries.conf"),
        registries_conf_d=str(tmp_path / "registries.conf.d"),
        registries_d=str(tmp_path / "registries.d"),
    )
    if policy is not None:
        (tmp_path / "policy.json").write_text(
            policy if isinstance(policy, str) else json.dumps(policy), encoding="utf-8"
        )
    if registries is not None:
        (tmp_path / "registries.conf").write_text(registries, encoding="utf-8")
    if registries_d:
        (tmp_path / "registries.d").mkdir()
        for name, text in registries_d.items():
            (tmp_path / "registries.d" / name).write_text(text, encoding="utf-8")
    return cfg


@pytest.mark.parametrize(
    ("ref", "host", "scope"),
    [
        (
            "registry.access.redhat.com/ubi9/ubi-minimal:9.4",
            "registry.access.redhat.com",
            "registry.access.redhat.com/ubi9/ubi-minimal",
        ),
        ("localhost/demo-bad:latest", "localhost", "localhost/demo-bad"),
        ("myhost:5000/team/app:1.0", "myhost:5000", "myhost:5000/team/app"),
        ("myhost:5000/app", "myhost:5000", "myhost:5000/app"),
        ("quay.io/podman/stable@sha256:abc", "quay.io", "quay.io/podman/stable"),
        ("ubi9/ubi-minimal:latest", "docker.io", "docker.io/ubi9/ubi-minimal"),
        ("nginx", "docker.io", "docker.io/nginx"),
    ],
)
def test_split_reference(ref: str, host: str, scope: str) -> None:
    assert split_reference(ref) == (host, scope)


def test_most_specific_scope_wins(tmp_path: Path) -> None:
    policy = {
        "default": [{"type": "reject"}],
        "transports": {
            "docker": {
                "registry.example.com": ACCEPT,
                "registry.example.com/secure": SIGNED,
                "registry.example.com/secure/legacy": ACCEPT,
                "*.corp.example": SIGNED,
            }
        },
    }
    p = load_trust_policy(cfg_for(tmp_path, policy))
    assert p.is_signature_verified("registry.example.com/secure/app:1")
    assert not p.is_signature_verified("registry.example.com/secure/legacy:1")
    assert not p.is_signature_verified("registry.example.com/other:1")
    assert p.is_signature_verified("reg.corp.example/team/app:1")  # wildcard host
    assert not p.is_signature_verified("elsewhere.io/app:1")  # falls to reject default
    scope, _ = p.requirements_for("registry.example.com/secure/app:1")
    assert scope == "registry.example.com/secure"


def test_default_and_transport_default(tmp_path: Path) -> None:
    p = load_trust_policy(cfg_for(tmp_path, {"default": SIGNED}))
    assert p.is_signature_verified("anything.io/x:1")
    p = load_trust_policy(
        cfg_for(tmp_path, {"default": ACCEPT, "transports": {"docker": {"": SIGNED}}})
    )
    assert p.is_signature_verified("anything.io/x:1")


def test_sigstore_counts_as_verified(tmp_path: Path) -> None:
    p = load_trust_policy(
        cfg_for(
            tmp_path,
            {
                "default": ACCEPT,
                "transports": {
                    "docker": {"quay.io": [{"type": "sigstoreSigned", "keyPath": "/k"}]}
                },
            },
        )
    )
    assert p.is_signature_verified("quay.io/a/b:1")


def test_missing_and_broken_policy(tmp_path: Path) -> None:
    p = load_trust_policy(cfg_for(tmp_path))
    assert not p.policy_found and "not found" in (p.policy_error or "")
    assert not p.is_signature_verified("quay.io/a:1")
    p = load_trust_policy(cfg_for(tmp_path, "{not json"))
    assert not p.policy_found and "cannot parse" in (p.policy_error or "")
    p = load_trust_policy(cfg_for(tmp_path, "[1, 2]"))  # valid JSON, wrong shape
    assert p.policy_error is not None


def test_registries_conf(tmp_path: Path) -> None:
    cfg = cfg_for(
        tmp_path,
        {"default": ACCEPT},
        registries="""
unqualified-search-registries = ["registry.access.redhat.com", "quay.io"]

[[registry]]
location = "registry.lab.local:5000"
insecure = true

[[registry]]
prefix = "docker.io"
location = "mirror.lab.local"
blocked = true
""",
    )
    conf_d = tmp_path / "registries.conf.d"
    conf_d.mkdir()
    (conf_d / "10-extra.conf").write_text(
        '[[registry]]\nlocation = "dev.local"\ninsecure = true\n', encoding="utf-8"
    )
    p = load_trust_policy(cfg)
    assert p.unqualified_search == ["registry.access.redhat.com", "quay.io"]
    assert sorted(p.insecure_registries()) == ["dev.local", "registry.lab.local:5000"]
    entry = p.registry_entry("registry.lab.local:5000/app:1")
    assert entry is not None and entry.insecure
    assert p.registry_entry("quay.io/x:1") is None


def test_broken_registries_conf_is_ignored(tmp_path: Path) -> None:
    p = load_trust_policy(cfg_for(tmp_path, {"default": ACCEPT}, registries="[[registry"))
    assert p.registries == [] and p.policy_found


def test_registries_d_signature_stores(tmp_path: Path) -> None:
    yaml_text = """\
default-docker:
  lookaside: https://example.com/default
docker:
  registry.access.redhat.com:
    sigstore: https://access.redhat.com/webassets/docker/content/sigstore
  quay.io:
    use-sigstore-attachments: true
  other.io:
    lookaside-staging: file:///tmp/x
  plain.io:
    comment: nothing here
"""
    p = load_trust_policy(
        cfg_for(tmp_path, {"default": ACCEPT}, registries_d={"default.yaml": yaml_text})
    )
    assert p.signature_stores == {"registry.access.redhat.com", "quay.io", "other.io"}


# ---- PS-014 rule


def run014(settings: Settings, image: ImageInfo):  # type: ignore[no-untyped-def]
    return run_rules(image, [r for r in build_rules(settings) if r.id == "PS-014"])


def test_ps014_signed_registry_passes(settings: Settings, good_image: ImageInfo) -> None:
    assert run014(settings, good_image) == []  # conftest policy requires signedBy for RH


def test_ps014_unsigned_registry_flagged(settings: Settings, good_image: ImageInfo) -> None:
    good_image.repo_tags = ["quay.io/someone/app:1.0"]
    good_image.repo_digests = []
    (finding,) = run014(settings, good_image)
    assert finding.severity is Severity.MEDIUM
    assert "requires reject" in finding.evidence[0]
    assert "signedBy" in finding.remediation


def test_ps014_local_image(settings: Settings, bad_image: ImageInfo) -> None:
    (finding,) = run014(settings, bad_image)
    assert "localhost/demo-bad:latest" in finding.evidence[0]


def test_ps014_any_verified_reference_is_enough(settings: Settings, good_image: ImageInfo) -> None:
    good_image.repo_tags = ["localhost/mine:1", "registry.access.redhat.com/ubi9/ubi:9"]
    assert run014(settings, good_image) == []


def test_ps014_missing_policy(settings: Settings, good_image: ImageInfo, tmp_path: Path) -> None:
    settings.trust.policy_path = str(tmp_path / "nope.json")
    (finding,) = run014(settings, good_image)
    assert "Trust policy unavailable" in finding.evidence[0]


def test_ps014_dangling_image(settings: Settings, good_image: ImageInfo) -> None:
    good_image.repo_tags, good_image.repo_digests = [], []
    (finding,) = run014(settings, good_image)
    assert any("no registry reference" in e for e in finding.evidence)


def test_ps014_insecure_registry_flagged_even_if_signed(
    settings: Settings, good_image: ImageInfo, tmp_path: Path
) -> None:
    conf = tmp_path / "registries.conf"
    conf.write_text(
        '[[registry]]\nlocation = "registry.access.redhat.com"\ninsecure = true\n', encoding="utf-8"
    )
    (finding,) = run014(settings, good_image)
    assert any("insecure" in e for e in finding.evidence)


def test_policy_loaded_once_per_rule_instance(
    settings: Settings, good_image: ImageInfo, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    real = trust.load_trust_policy
    monkeypatch.setattr(trust, "load_trust_policy", lambda c: calls.append(1) or real(c))
    rules = [r for r in build_rules(settings) if r.id == "PS-014"]
    for _ in range(3):
        run_rules(good_image, rules)
    assert len(calls) == 1
