"""T1: scoring arithmetic, CVE cap, floor and grade boundaries."""

from __future__ import annotations

import pytest

from podshield.config import ScoringSettings
from podshield.schemas import Finding, Severity
from podshield.scoring import compute_score, grade_for

CFG = ScoringSettings()


def findings(severity: Severity, n: int) -> list[Finding]:
    return [
        Finding(rule_id=f"PS-T{i}", title="t", severity=severity, description="d") for i in range(n)
    ]


def test_default_weights_match_the_specification() -> None:
    assert [CFG.weight(s) for s in Severity] == [25, 10, 4, 1, 0]
    assert CFG.cve_cap == 40
    assert (CFG.grade_a, CFG.grade_b, CFG.grade_c, CFG.grade_d) == (90, 80, 70, 60)


def test_no_findings_is_a_perfect_a() -> None:
    result = compute_score([], CFG)
    assert (result.score, result.grade) == (100, "A")


@pytest.mark.parametrize(
    ("severity", "points"),
    [
        (Severity.CRITICAL, 25),
        (Severity.HIGH, 10),
        (Severity.MEDIUM, 4),
        (Severity.LOW, 1),
        (Severity.INFO, 0),
    ],
)
def test_each_severity_deducts_its_weight(severity: Severity, points: int) -> None:
    assert compute_score(findings(severity, 1), CFG).score == 100 - points
    assert compute_score(findings(severity, 3), CFG).score == 100 - 3 * points


def test_deductions_add_up_across_severities() -> None:
    mixed = [
        *findings(Severity.CRITICAL, 1),
        *findings(Severity.HIGH, 2),
        *findings(Severity.MEDIUM, 3),
        *findings(Severity.LOW, 4),
        *findings(Severity.INFO, 9),
    ]
    assert compute_score(mixed, CFG).score == 100 - (25 + 20 + 12 + 4 + 0)


@pytest.mark.parametrize(
    ("lows", "score", "grade"),
    [
        (0, 100, "A"),
        (10, 90, "A"),  # exactly 90 is still an A
        (11, 89, "B"),
        (20, 80, "B"),  # 89 is a B, exactly 80 is a B
        (21, 79, "C"),
        (30, 70, "C"),
        (31, 69, "D"),
        (40, 60, "D"),  # exactly 60 is a D
        (41, 59, "F"),
        (60, 40, "F"),
    ],
)
def test_grade_boundaries_via_real_findings(lows: int, score: int, grade: str) -> None:
    result = compute_score(findings(Severity.LOW, lows), CFG)
    assert (result.score, result.grade) == (score, grade)


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (79, "C"),
        (70, "C"),
        (69, "D"),
        (60, "D"),
        (59, "F"),
        (1, "F"),
        (0, "F"),
    ],
)
def test_grade_for(score: int, grade: str) -> None:
    assert grade_for(score, CFG) == grade


def test_score_never_goes_below_zero() -> None:
    result = compute_score(findings(Severity.CRITICAL, 10), CFG)  # 250 points of deductions
    assert (result.score, result.grade) == (0, "F")
    assert compute_score(findings(Severity.CRITICAL, 4), CFG).score == 0  # exactly 100


def test_cve_deductions_are_capped_at_forty() -> None:
    one = compute_score([], CFG, [Severity.CRITICAL])
    assert one.score == 75
    two = compute_score([], CFG, [Severity.CRITICAL] * 2)
    assert two.score == 60  # 50 points, capped to 40
    assert compute_score([], CFG, [Severity.CRITICAL] * 500).score == 60
    assert compute_score([], CFG, [Severity.CRITICAL] * 500).grade == "D"


def test_cve_cap_boundaries() -> None:
    assert compute_score([], CFG, [Severity.LOW] * 39).score == 61  # under the cap
    assert compute_score([], CFG, [Severity.LOW] * 40).score == 60  # exactly the cap
    assert compute_score([], CFG, [Severity.LOW] * 41).score == 60  # over it


def test_cap_applies_to_cves_only_not_to_hygiene_findings() -> None:
    result = compute_score(findings(Severity.CRITICAL, 2), CFG, [Severity.CRITICAL] * 10)
    assert result.score == 100 - 50 - 40  # findings uncapped, CVEs capped
    result = compute_score(findings(Severity.CRITICAL, 3), CFG, [Severity.CRITICAL] * 10)
    assert result.score == 0  # and the floor still applies


def test_info_cves_cost_nothing() -> None:
    assert compute_score([], CFG, [Severity.INFO] * 100).score == 100


def test_custom_weights_and_cap() -> None:
    cfg = ScoringSettings(critical=50, high=20, medium=5, low=2, cve_cap=10)
    assert compute_score(findings(Severity.CRITICAL, 1), cfg).score == 50
    assert compute_score([], cfg, [Severity.HIGH] * 5).score == 90  # cap 10
    assert compute_score([], ScoringSettings(cve_cap=0), [Severity.CRITICAL] * 9).score == 100


def test_custom_grade_boundaries() -> None:
    cfg = ScoringSettings(grade_a=95, grade_b=85, grade_c=75, grade_d=65)
    assert [grade_for(s, cfg) for s in (95, 94, 85, 84, 75, 74, 65, 64)] == list("ABBCCDDF")


def test_score_is_an_int_between_0_and_100_for_any_input() -> None:
    for n in range(30):
        for severity in Severity:
            result = compute_score(findings(severity, n), CFG, [severity] * n)
            assert isinstance(result.score, int) and 0 <= result.score <= 100
            assert result.grade in set("ABCDF")


def test_accepts_generators() -> None:
    gen = (f for f in findings(Severity.HIGH, 2))
    assert compute_score(gen, CFG, (s for s in [Severity.LOW])).score == 100 - 20 - 1
