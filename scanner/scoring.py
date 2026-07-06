"""
scanner/scoring.py
====================
Computes an overall security score (0-100) and letter grade from all
collected findings, header results, TLS analysis, and CSP analysis --
loosely modeled after tools like Mozilla Observatory / SecurityHeaders.com
but extended with TLS and cookie posture.
"""
from __future__ import annotations

from utils.models import ScanResult, SecurityScore, Severity


def compute_score(result: ScanResult) -> SecurityScore:
    score = 100

    # Deduct for each finding based on severity weight, with diminishing
    # impact for repeated low-severity items to avoid unfairly punishing
    # sites with many minor informational notes.
    severity_counts: dict[Severity, int] = {s: 0 for s in Severity}
    for finding in result.findings:
        severity_counts[finding.severity] += 1

    for severity, count in severity_counts.items():
        if count == 0:
            continue
        # Full weight for first occurrence, 60% for subsequent ones of same severity.
        deduction = severity.weight + max(0, count - 1) * severity.weight * 0.4
        score -= deduction

    # CSP-specific penalty (already weighted 0-30)
    score -= result.csp.score_penalty * 0.5

    # TLS bonus/penalty already reflected via findings, but add a strong
    # penalty if TLS not supported at all on an https target.
    if result.network.protocol == "https" and not result.tls.supported:
        score -= 20

    score = max(0, min(100, round(score)))
    grade, color = SecurityScore.grade_for(score)
    return SecurityScore(score=score, grade=grade, color=color)
