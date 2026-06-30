from __future__ import annotations

from datetime import UTC, datetime

from tip.models import Severity


def calculate_risk(
    confidence: int,
    source_count: int,
    last_seen: datetime,
) -> int:
    """Return a deterministic 0-100 risk score."""
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age_hours = max(0.0, (datetime.now(UTC) - last_seen).total_seconds() / 3600)
    confidence_points = round(max(0, min(confidence, 100)) * 0.70)
    corroboration_points = min(max(source_count - 1, 0) * 10, 20)
    recency_points = 10 if age_hours <= 24 else 5 if age_hours <= 168 else 0
    return min(100, confidence_points + corroboration_points + recency_points)


def severity_for(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW
