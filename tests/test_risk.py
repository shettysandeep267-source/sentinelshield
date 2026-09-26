"""
Tests for app.core.risk. Fill these in as soon as risk.score() is implemented
(Stage 10) - this is a good first module to TDD since it's pure logic with
no I/O.
"""

import pytest

from app.core import risk
from app.core.models import Severity


def test_classify_bands():
    assert risk.classify(0) == Severity.LOW
    assert risk.classify(29) == Severity.LOW
    assert risk.classify(30) == Severity.MEDIUM
    assert risk.classify(59) == Severity.MEDIUM
    assert risk.classify(60) == Severity.HIGH
    assert risk.classify(79) == Severity.HIGH
    assert risk.classify(80) == Severity.CRITICAL
    assert risk.classify(100) == Severity.CRITICAL


@pytest.mark.skip(reason="risk.score() not yet implemented - see TODO in app/core/risk.py")
def test_score_high_confidence_sqli_is_high_or_critical():
    score = risk.score(event_type="SQL_INJECTION", confidence=95)
    assert score >= 60
