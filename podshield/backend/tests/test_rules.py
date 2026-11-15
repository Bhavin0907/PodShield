from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from podshield.config import RuleOverride, Settings
from podshield.scanners import hygiene
from podshield.scanners.hygiene import build_rules, rule_catalog, run_rules
from podshield.schemas import Finding, ImageInfo, Severity


def run(rule_id: str, image: ImageInfo, settings: Settings) -> list[Finding]:
    rules = [r for r in build_rules(settings) if r.id == rule_id]
    assert len(rules) == 1
    return run_rules(image, rules)


# ---- PS-001


@pytest.mark.parametrize("user", ["", "0", "root", "0:0", "root:root", " root "])
def test_ps001_flags_root(settings: Settings, good_image: ImageInfo, user: str) -> None:
    good_image.user = user
    findings = run("PS-001", good_image, settings)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


@pytest.mark.parametrize("user", ["1001", "appuser", "1001:1001", "nobody"])
def test_ps001_passes_non_root(settings: Settings, good_image: ImageInfo, user: str) -> None:
    good_image.user = user
    assert run("PS-001", good_image, settings) == []


# ---- PS-002


def test_ps002_flags_latest_only(settings: Settings, good_image: ImageInfo) -> None:
    good_image.repo_tags = ["localhost/app:latest"]
    assert len(run("PS-002", good_image, settings)) == 1


def test_ps002_flags_dangling(settings: Settings, good_image: ImageInfo) -> None:
    good_image.repo_tags = []
    good_image.repo_digests = []
    assert len(run("PS-002", good_image, settings)) == 1


def test_ps002_allows_pinned_tag_alongside_latest(
    settings: Settings, good_image: ImageInfo
) -> None:
    good_image.repo_tags = ["localhost/app:latest", "localhost/app:1.2.3"]
    assert run("PS-002", good_image, settings) == []


def test_ps002_allows_digest_only(settings: Settings, good_image: ImageInfo) -> None:
    good_image.repo_tags = []
    assert run("PS-002", good_image, settings) == []


def test_ps002_registry_port_without_tag_is_not_a_tag() -> None:
    assert hygiene._tag_of("registry:5000/app") == ""
    assert hygiene._tag_of("registry:5000/app:2.0") == "2.0"


# ---- PS-003


def test_ps003_detects_and_masks(settings: Settings, bad_image: ImageInfo) -> None:
    findings = run("PS-003", bad_image, settings)
    assert len(findings) == 1
    text = "\n".join(findings[0].evidence)
    assert "DB_PASSWORD" in text and "hunt****" in text
    assert "AWS_ACCESS_KEY_ID" in text and "AKIA****" in text
    assert "hunter2-super-secret" not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    # Not secrets: PATH, PWD, file references
    assert "PATH" not in text.replace("API_TOKEN_FILE", "")
    assert "API_TOKEN_FILE" not in text
    assert findings[0].severity is Severity.CRITICAL


def test_ps003_ignores_placeholders_and_non_secrets(
    settings: Settings, good_image: ImageInfo
) -> None:
    assert run("PS-003", good_image, settings) == []


def test_ps003_detects_credentials_in_url(settings: Settings, good_image: ImageInfo) -> None:
    good_image.env = ["DATABASE=postgres://admin:s3cretpw@db:5432/app"]
    findings = run("PS-003", good_image, settings)
    assert len(findings) == 1
    assert "s3cretpw" not in "".join(findings[0].evidence)


# ---- PS-005


def test_ps005_old_image(settings: Settings, bad_image: ImageInfo) -> None:
    findings = run("PS-005", bad_image, settings)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_ps005_fresh_image(settings: Settings, good_image: ImageInfo) -> None:
    assert run("PS-005", good_image, settings) == []


def test_ps005_threshold_is_configurable(settings: Settings, good_image: ImageInfo) -> None:
    good_image.created = datetime.now(UTC) - timedelta(days=40)
    assert run("PS-005", good_image, settings) == []
    settings.thresholds.max_image_age_days = 30
    assert len(run("PS-005", good_image, settings)) == 1


def test_ps005_unknown_or_epoch_created_is_skipped(
    settings: Settings, good_image: ImageInfo
) -> None:
    good_image.created = None
    assert run("PS-005", good_image, settings) == []
    good_image.created = datetime(1, 1, 1, tzinfo=UTC)
    assert run("PS-005", good_image, settings) == []


# ---- PS-011


def test_ps011(settings: Settings, bad_image: ImageInfo, good_image: ImageInfo) -> None:
    assert len(run("PS-011", bad_image, settings)) == 1
    assert run("PS-011", good_image, settings) == []
    good_image.healthcheck = {"Test": ["NONE"]}
    assert len(run("PS-011", good_image, settings)) == 1


# ---- PS-012


def test_ps012(settings: Settings, bad_image: ImageInfo, good_image: ImageInfo) -> None:
    findings = run("PS-012", bad_image, settings)
    assert len(findings) == 1
    assert "maintainer, version, source" in findings[0].evidence[0]
    assert run("PS-012", good_image, settings) == []


def test_ps012_accepts_legacy_labels(settings: Settings, good_image: ImageInfo) -> None:
    good_image.labels = {"maintainer": "me", "version": "1", "vcs-url": "https://x"}
    assert run("PS-012", good_image, settings) == []


# ---- engine


def test_all_phase1_rules_registered() -> None:
    assert {"PS-001", "PS-002", "PS-003", "PS-005", "PS-011", "PS-012"} <= set(
        hygiene.RULE_REGISTRY
    )


def test_disable_and_severity_override(settings: Settings, bad_image: ImageInfo) -> None:
    settings.rules["PS-001"] = RuleOverride(enabled=False)
    settings.rules["PS-011"] = RuleOverride(severity=Severity.HIGH)
    ids = {f.rule_id: f for f in run_rules(bad_image, build_rules(settings))}
    assert "PS-001" not in ids
    assert ids["PS-011"].severity is Severity.HIGH

    catalog = {r.id: r for r in rule_catalog(settings)}
    assert catalog["PS-001"].enabled is False
    assert catalog["PS-011"].severity is Severity.HIGH
    assert catalog["PS-011"].default_severity is Severity.LOW


def test_findings_sorted_by_severity(settings: Settings, bad_image: ImageInfo) -> None:
    findings = run_rules(bad_image, build_rules(settings))
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_crashing_rule_does_not_abort_scan(settings: Settings, bad_image: ImageInfo) -> None:
    class Boom(hygiene.Rule):
        id = "PS-TEST"
        title = "boom"
        default_severity = Severity.LOW
        description = ""

        def evaluate(self, image: ImageInfo) -> list[Finding]:
            raise RuntimeError("boom")

    rules = [Boom(settings), *build_rules(settings)]
    assert any(f.rule_id == "PS-001" for f in run_rules(bad_image, rules))


def test_duplicate_registration_rejected() -> None:
    with pytest.raises(ValueError):

        @hygiene.register
        class Dup(hygiene.Rule):
            id = "PS-001"
            title = "dup"
            default_severity = Severity.LOW
            description = ""

            def evaluate(self, image: ImageInfo) -> list[Finding]:
                return []
