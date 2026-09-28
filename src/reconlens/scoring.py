"""Turns a list of findings into a 0-100 score and an A-F grade.

The model is intentionally simple and transparent: start at 100 and subtract a
fixed penalty per finding. It is a triage aid, not a formal risk rating.
"""

from __future__ import annotations

from collections.abc import Iterable

# Keyed by Severity value (0=info ... 4=critical) to avoid a circular import.
PENALTIES = {0: 0, 1: 3, 2: 7, 3: 15, 4: 25}

GRADE_THRESHOLDS = (("A", 90), ("B", 80), ("C", 65), ("D", 50))


def compute_score(severities: Iterable[int]) -> int:
    penalty = sum(PENALTIES[int(s)] for s in severities)
    return max(0, 100 - penalty)


def grade_for(score: int) -> str:
    for grade, threshold in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"
