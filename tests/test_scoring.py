from datetime import UTC, datetime, timedelta

from tip.models import Severity
from tip.scoring import calculate_risk, severity_for


def test_corroboration_and_recency_raise_score():
    recent = datetime.now(UTC)
    one_source = calculate_risk(80, 1, recent)
    three_sources = calculate_risk(80, 3, recent)
    assert one_source == 66
    assert three_sources == 86
    assert severity_for(three_sources) == Severity.CRITICAL


def test_old_low_confidence_indicator_is_low():
    old = datetime.now(UTC) - timedelta(days=30)
    score = calculate_risk(30, 1, old)
    assert score == 21
    assert severity_for(score) == Severity.LOW
