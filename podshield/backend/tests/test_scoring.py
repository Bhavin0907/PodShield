from __future__ import annotations

import pytest

from podshield.config import ScoringSettings
from podshield.schemas import Finding, Severity
from podshield.scoring import compute_score, grade_for


def f(sev: Severity) -> Finding:
    return Finding(rule_id="X", title="x", severity=sev, description="")


def test_perfect_score() -> None:
    s = compute_score([], ScoringSettings())
    assert (s.score, s.grade) == (100, "A")


def test_deductions() -> None:
    s = compute_score(
        [
            f(Severity.CRITICAL),
            f(Severity.HIGH),
            f(Severity.MEDIUM),
            f(Severity.LOW),
            f(Severity.INFO),
        ],
        ScoringSettings(),
    )
    assert s.score == 60
    assert s.grade == "D"


def test_floor_at_zero() -> None:
    assert compute_score([f(Severity.CRITICAL)] * 10, ScoringSettings()).score == 0


def test_cve_cap() -> None:
    cves = [Severity.CRITICAL] * 10
    assert compute_score([], ScoringSettings(), cves).score == 60


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
        (0, "F"),
    ],
)
def test_grade_boundaries(score: int, grade: str) -> None:
    assert grade_for(score, ScoringSettings()) == grade


def test_weights_configurable() -> None:
    cfg = ScoringSettings(high=50)
    assert compute_score([f(Severity.HIGH)], cfg).score == 50
