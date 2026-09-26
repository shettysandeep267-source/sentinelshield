"""
SentinelShield Risk Scoring Engine.

Converts detection attributes into a 0-100 risk score and a
corresponding Severity classification.
"""

from app.core.models import Severity


# ---------------------------------------------------------------------------
# Base risk weights
# ---------------------------------------------------------------------------

EVENT_TYPE_WEIGHTS = {
    "PORT_SCAN": 40,
    "BRUTE_FORCE": 55,
    "SQL_INJECTION": 70,
    "XSS": 60,
    "DIRECTORY_TRAVERSAL": 60,
    "COMMAND_INJECTION": 80,
    "FILE_INTEGRITY_VIOLATION": 75,
    "SURICATA_ALERT": 50,
}


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def score(
    event_type: str,
    confidence: int,
    frequency: int = 1,
    source_reputation: int = 0,
    target_importance: int = 0,
) -> int:
    """
    Calculate a 0-100 risk score.

    Args:
        event_type:
            Type of detected security event.

        confidence:
            Detector confidence from 0-100.

        frequency:
            Number of related events observed recently.

        source_reputation:
            Threat-intelligence reputation from 0-100.

        target_importance:
            Importance of the target asset from 0-100.

    Returns:
        Integer risk score between 0 and 100.
    """

    # ---------------------------------------------------------
    # Validate inputs
    # ---------------------------------------------------------

    confidence = max(0, min(int(confidence), 100))
    frequency = max(1, int(frequency))
    source_reputation = max(
        0,
        min(int(source_reputation), 100),
    )
    target_importance = max(
        0,
        min(int(target_importance), 100),
    )

    # ---------------------------------------------------------
    # Base event weight
    # ---------------------------------------------------------

    base = EVENT_TYPE_WEIGHTS.get(
        event_type,
        30,
    )

    # ---------------------------------------------------------
    # Confidence contribution
    # ---------------------------------------------------------

    calculated_score = base * (
        confidence / 100
    )

    # ---------------------------------------------------------
    # Frequency contribution
    # ---------------------------------------------------------

    calculated_score += min(
        frequency,
        10,
    ) * 2

    # ---------------------------------------------------------
    # Source reputation contribution
    # ---------------------------------------------------------

    calculated_score += (
        source_reputation * 0.2
    )

    # ---------------------------------------------------------
    # Target importance contribution
    # ---------------------------------------------------------

    calculated_score += (
        target_importance * 0.1
    )

    # ---------------------------------------------------------
    # Clamp to 0-100
    # ---------------------------------------------------------

    calculated_score = max(
        0,
        min(calculated_score, 100),
    )

    return int(calculated_score)


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

def classify(risk_score: int) -> Severity:
    """
    Convert a risk score into a Severity classification.

    80-100 → CRITICAL
    60-79  → HIGH
    30-59  → MEDIUM
    0-29   → LOW
    """

    risk_score = max(
        0,
        min(int(risk_score), 100),
    )

    if risk_score >= 80:
        return Severity.CRITICAL

    if risk_score >= 60:
        return Severity.HIGH

    if risk_score >= 30:
        return Severity.MEDIUM

    return Severity.LOW


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    print("==========================================")
    print(" SentinelShield Risk Engine Test")
    print("==========================================")
    print()

    test_events = [
        ("PORT_SCAN", 95),
        ("BRUTE_FORCE", 90),
        ("SQL_INJECTION", 95),
        ("XSS", 80),
        ("COMMAND_INJECTION", 95),
    ]

    for event_type, confidence in test_events:

        risk_score = score(
            event_type=event_type,
            confidence=confidence,
        )

        severity = classify(
            risk_score
        )

        print(
            f"{event_type:<25}"
            f" Risk: {risk_score:>3}/100"
            f"  Severity: {severity.value}"
        )