"""
SentinelShield Detection Pipeline.

Connects collectors -> detectors -> risk scoring -> alerts -> database.

Supported detection engines:

    1. Port Scan Detection
    2. Web Attack Detection
    3. Brute-Force Detection
"""

import logging
from typing import Optional

from app.core.models import Event, Alert
from app.core.database import insert_event, insert_alert
from app.core.alerts import create_alert
from app.detectors.port_scan import PortScanDetector
from app.detectors.web_attack import WebAttackDetector
from app.detectors.brute_force import BruteForceDetector


log = logging.getLogger("sentinelshield.pipeline")


class DetectionPipeline:
    """
    Central SentinelShield detection pipeline.
    """

    def __init__(
        self,
        port_scan_detector: Optional[PortScanDetector] = None,
        web_attack_detector: Optional[WebAttackDetector] = None,
        brute_force_detector: Optional[BruteForceDetector] = None,
    ) -> None:

        self.port_scan_detector = (
            port_scan_detector
            or PortScanDetector()
        )

        self.web_attack_detector = (
            web_attack_detector
            or WebAttackDetector()
        )

        self.brute_force_detector = (
            brute_force_detector
            or BruteForceDetector()
        )

    # ========================================================================
    # Process Event
    # ========================================================================

    def process_event(
        self,
        event: Event,
    ) -> Optional[Alert]:
        """
        Process one SentinelShield Event.

        Returns:
            Alert if suspicious behavior is detected.
            None if the event is considered normal.
        """

        # --------------------------------------------------------------------
        # Store original event
        # --------------------------------------------------------------------

        event_id = insert_event(
            event
        )

        log.info(
            "EVENT | ID=%s | TYPE=%s | SOURCE=%s",
            event_id,
            event.event_type,
            event.source_ip,
        )

        detection = None

        # --------------------------------------------------------------------
        # PORT SCAN
        # --------------------------------------------------------------------

        if event.event_type in {
            "TCP_CONNECTION",
            "UDP_CONNECTION",
        }:

            detection = (
                self.port_scan_detector.process(
                    event
                )
            )

        # --------------------------------------------------------------------
        # WEB ATTACK
        # --------------------------------------------------------------------

        elif event.event_type == "HTTP_REQUEST":

            detection = (
                self.web_attack_detector.process(
                    event
                )
            )

        # --------------------------------------------------------------------
        # BRUTE FORCE
        # --------------------------------------------------------------------

        elif event.event_type in {
            "AUTH_FAILURE",
            "AUTH_SUCCESS",
        }:

            detection = (
                self.brute_force_detector.process(
                    event
                )
            )

        # --------------------------------------------------------------------
        # No detection
        # --------------------------------------------------------------------

        if detection is None:
            return None

        # --------------------------------------------------------------------
        # Store detection event
        # --------------------------------------------------------------------

        detection_id = insert_event(
            detection
        )

        log.warning(
            "DETECTION | ID=%s | TYPE=%s | SOURCE=%s",
            detection_id,
            detection.event_type,
            detection.source_ip,
        )

        # --------------------------------------------------------------------
        # Confidence
        # --------------------------------------------------------------------

        confidence = self._calculate_confidence(
            detection
        )

        # --------------------------------------------------------------------
        # Create alert
        # --------------------------------------------------------------------

        alert = create_alert(
            event_type=detection.event_type,
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            confidence=confidence,
            description=detection.description,
            evidence=detection.raw_data,
            recommended_action=(
                self._recommended_action(
                    detection.event_type
                )
            ),
        )

        # Connect alert with detection event.
        alert.related_event_ids = str(
            detection_id
        )

        # --------------------------------------------------------------------
        # Save alert
        # --------------------------------------------------------------------

        alert_id = insert_alert(
            alert
        )

        log.warning(
            "ALERT | ID=%s | TYPE=%s | "
            "SEVERITY=%s | RISK=%s",
            alert_id,
            alert.event_type,
            alert.severity.value,
            alert.risk_score,
        )

        return alert

    # ========================================================================
    # Confidence
    # ========================================================================

    @staticmethod
    def _calculate_confidence(
        detection: Event,
    ) -> int:
        """
        Assign detector confidence.

        Pattern matches and threshold-based detections use high
        confidence because a configured rule/threshold was crossed.
        """

        high_confidence_events = {
            "PORT_SCAN",
            "SQL_INJECTION",
            "XSS",
            "DIRECTORY_TRAVERSAL",
            "COMMAND_INJECTION",
            "BRUTE_FORCE",
            "SUCCESSFUL_BRUTE_FORCE",
        }

        if detection.event_type in high_confidence_events:
            return 90

        return 70

    # ========================================================================
    # Recommended Action
    # ========================================================================

    @staticmethod
    def _recommended_action(
        event_type: str,
    ) -> str:
        """
        Return a security recommendation for the analyst.
        """

        actions = {

            "PORT_SCAN":
                "Investigate the source host and review "
                "related network activity.",

            "SQL_INJECTION":
                "Review the affected endpoint, validate "
                "input handling, and inspect database logs.",

            "XSS":
                "Review the affected parameter and apply "
                "appropriate input validation and output encoding.",

            "DIRECTORY_TRAVERSAL":
                "Review file-access controls and verify that "
                "user input cannot access unintended files.",

            "COMMAND_INJECTION":
                "Investigate the request immediately and "
                "review server-side command execution paths.",

            "BRUTE_FORCE":
                "Review authentication logs, consider temporary "
                "IP throttling, and verify affected accounts.",

            "SUCCESSFUL_BRUTE_FORCE":
                "Immediately investigate the successful login, "
                "verify the account owner, and review authentication "
                "activity from the source IP.",
        }

        return actions.get(
            event_type,
            "Investigate the detected security event.",
        )