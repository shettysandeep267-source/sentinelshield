"""
Tests for app.detectors.web_attack. Fill in once WebAttackDetector is
implemented (Stage 6-7). Use these as your controlled test matrix from
Phase 14 of the build plan - only ever run against your own lab traffic.
"""

import pytest

from app.core.models import Event
from app.detectors.web_attack import WebAttackDetector


@pytest.fixture
def detector():
    d = WebAttackDetector()
    d.load_rules()
    return d


@pytest.mark.skip(reason="WebAttackDetector not yet implemented")
def test_normal_request_produces_no_alert(detector):
    event = Event(event_type="HTTP_REQUEST", description="/index.html")
    assert detector.process(event) is None


@pytest.mark.skip(reason="WebAttackDetector not yet implemented")
def test_sqli_pattern_is_detected(detector):
    event = Event(event_type="HTTP_REQUEST", description="/products?id=1 UNION SELECT username,password FROM users")
    result = detector.process(event)
    assert result is not None
    assert result.event_type == "SQL_INJECTION"


@pytest.mark.skip(reason="WebAttackDetector not yet implemented")
def test_traversal_pattern_is_detected(detector):
    event = Event(event_type="HTTP_REQUEST", description="/download?file=../../../../etc/passwd")
    result = detector.process(event)
    assert result is not None
    assert result.event_type == "DIRECTORY_TRAVERSAL"
