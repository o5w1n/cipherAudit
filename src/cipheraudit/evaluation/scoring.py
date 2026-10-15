"""Scoring (TRD §5c): deterministic and documented in every report.

score = 100 - sum(deductions), floored at 0, then capped at the lowest cap among all findings.
Grade: A >= 90, B >= 80, C >= 65, D >= 50, E >= 40, F < 40.
"""

from __future__ import annotations

from cipheraudit.models.findings import Finding, ScoreBreakdown

GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (65, "C"), (50, "D"), (40, "E")]

METHOD = (
    "Start at 100. Each finding deducts points by severity (critical 40, high 20, medium 10, low 3, info 0; "
    "some findings override this). The score cannot go below 0. Critical findings cap the score at 39 and high "
    "findings at 64, so one serious problem cannot be hidden by an otherwise good configuration. "
    "Grades: A 90+, B 80+, C 65+, D 50+, E 40+, F below 40."
)


def grade_for(score: int) -> str:
    return next((grade for threshold, grade in GRADE_THRESHOLDS if score >= threshold), "F")


def score(findings: list[Finding]) -> ScoreBreakdown:
    total = sum(f.deduct for f in findings)
    raw = max(0, 100 - total)
    capped = [(f.cap, f.title) for f in findings if f.cap is not None]
    cap, reason = min(capped) if capped else (None, None)
    if cap is None or cap >= raw:
        return ScoreBreakdown(total_deductions=total, cap=None, cap_reason=None, score=raw, grade=grade_for(raw))
    return ScoreBreakdown(total_deductions=total, cap=cap, cap_reason=reason, score=cap, grade=grade_for(cap))
