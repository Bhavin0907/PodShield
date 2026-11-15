"""0-100 score and A-F grade from findings (weights come from config)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from podshield.config import ScoringSettings
from podshield.schemas import Finding, Severity


@dataclass(frozen=True)
class Score:
    score: int
    grade: str


def grade_for(score: int, cfg: ScoringSettings) -> str:
    if score >= cfg.grade_a:
        return "A"
    if score >= cfg.grade_b:
        return "B"
    if score >= cfg.grade_c:
        return "C"
    if score >= cfg.grade_d:
        return "D"
    return "F"


def compute_score(
    findings: Iterable[Finding],
    cfg: ScoringSettings,
    cve_severities: Iterable[Severity] = (),
) -> Score:
    """Start at 100, deduct per finding; CVE deductions are capped at ``cfg.cve_cap``."""
    deduction = sum(cfg.weight(f.severity) for f in findings)
    cve_deduction = min(sum(cfg.weight(s) for s in cve_severities), cfg.cve_cap)
    score = max(0, 100 - deduction - cve_deduction)
    return Score(score=score, grade=grade_for(score, cfg))
