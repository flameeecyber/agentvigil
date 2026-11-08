"""Trust scoring: one number a human can act on, with the arithmetic exposed."""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from .findings import Finding, Severity

GRADE_BANDS: List[Tuple[int, str, str]] = [
    (90, "A", "trusted"),
    (75, "B", "review"),
    (50, "C", "suspicious"),
    (25, "D", "untrusted"),
    (0, "F", "hostile"),
]


def score(findings: Iterable[Finding]) -> Tuple[int, str, str]:
    """Return (score, grade, verdict). Penalties are capped per severity."""
    findings = list(findings)
    penalty = 0
    for severity, cap in (
        (Severity.CRITICAL, 100),
        (Severity.HIGH, 60),
        (Severity.MEDIUM, 24),
        (Severity.LOW, 8),
    ):
        total = sum(f.severity.weight for f in findings if f.severity is severity)
        penalty += min(total, cap)
    value = max(0, 100 - penalty)
    for floor, grade, verdict in GRADE_BANDS:
        if value >= floor:
            return value, grade, verdict
    return 0, "F", "hostile"


def breakdown(findings: Iterable[Finding]) -> Dict[str, int]:
    """Penalty per capability, for the report's 'what this grants' section."""
    result: Dict[str, int] = {}
    for finding in findings:
        for cap in finding.capabilities or ("uncategorized",):
            result[cap] = result.get(cap, 0) + finding.severity.weight
    return dict(sorted(result.items(), key=lambda kv: -kv[1]))
