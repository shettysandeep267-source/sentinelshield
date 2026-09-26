"""
Tests for app.detectors.port_scan. Fill in once PortScanDetector.process()
is implemented (Stage 5).
"""

import pytest

from app.core.models import Event
from app.detectors.port_scan import PortScanDetector


@pytest.mark.skip(reason="PortScanDetector.process() not yet implemented")
def test_many_ports_from_one_ip_triggers_alert():
    detector = PortScanDetector(window_seconds=10, port_threshold=3)
    result = None
    for port in [22, 80, 443, 8080]:
        result = detector.process(
            Event(source_ip="192.168.56.101", destination_port=port, event_type="TCP_CONNECTION")
        )
    assert result is not None
    assert result.event_type == "PORT_SCAN"


@pytest.mark.skip(reason="PortScanDetector.process() not yet implemented")
def test_few_ports_does_not_trigger_alert():
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    result = detector.process(
        Event(source_ip="192.168.56.102", destination_port=80, event_type="TCP_CONNECTION")
    )
    assert result is None
