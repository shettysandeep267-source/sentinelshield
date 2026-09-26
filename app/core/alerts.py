"""
SentinelShield Alert Lifecycle Management.

Alert lifecycle:

    NEW
      ↓
    ACKNOWLEDGED
      ↓
    INVESTIGATING
      ↓
    RESOLVED
"""

from typing import Optional

from app.core.models import (
    Alert,
    AlertStatus,
    EngineSource,
)
from app.core import risk


# ---------------------------------------------------------------------------
# Alert creation
# ---------------------------------------------------------------------------

def create_alert(
    event_type: str,
    source_ip: Optional[str],
    confidence: int,
    description: str,
    evidence: Optional[str] = None,
    destination_ip: Optional[str] = None,
    recommended_action: Optional[str] = None,
) -> Alert:
    """
    Build a fully scored SentinelShield Alert.

    The alert is NOT saved to the database here.

    Persistence is handled by:

        database.insert_alert(alert)
    """

    # ---------------------------------------------------------
    # Calculate risk
    # ---------------------------------------------------------

    risk_score = risk.score(
        event_type=event_type,
        confidence=confidence,
    )

    # ---------------------------------------------------------
    # Determine severity
    # ---------------------------------------------------------

    severity = risk.classify(
        risk_score
    )

    # ---------------------------------------------------------
    # Build Alert
    # ---------------------------------------------------------

    alert = Alert(
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        severity=severity,
        confidence=confidence,
        risk_score=risk_score,
        description=description,
        evidence=evidence,
        recommended_action=recommended_action,
        status=AlertStatus.NEW,
        engine=EngineSource.SENTINELSHIELD,
    )

    return alert


# ---------------------------------------------------------------------------
# Valid alert transitions
# ---------------------------------------------------------------------------

VALID_TRANSITIONS = {

    AlertStatus.NEW: {
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.INVESTIGATING,
    },

    AlertStatus.ACKNOWLEDGED: {
        AlertStatus.INVESTIGATING,
        AlertStatus.RESOLVED,
    },

    AlertStatus.INVESTIGATING: {
        AlertStatus.RESOLVED,
    },

    AlertStatus.RESOLVED: set(),
}


# ---------------------------------------------------------------------------
# Transition validation
# ---------------------------------------------------------------------------

def transition(
    current: AlertStatus,
    target: AlertStatus,
) -> bool:
    """
    Return True if an alert can move from current to target status.
    """

    return target in VALID_TRANSITIONS.get(
        current,
        set(),
    )


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    print("==========================================")
    print(" SentinelShield Alert Engine Test")
    print("==========================================")
    print()

    alert = create_alert(
        event_type="PORT_SCAN",
        source_ip="192.168.56.101",
        destination_ip="192.168.56.10",
        confidence=95,
        description=(
            "Possible port scanning activity detected."
        ),
        evidence=(
            "15 distinct destination ports contacted "
            "within 10 seconds."
        ),
        recommended_action=(
            "Investigate the source host and review "
            "related network activity."
        ),
    )

    print(
        f"Alert Type:     {alert.event_type}"
    )

    print(
        f"Source IP:      {alert.source_ip}"
    )

    print(
        f"Destination IP: {alert.destination_ip}"
    )

    print(
        f"Confidence:     {alert.confidence}%"
    )

    print(
        f"Risk Score:     {alert.risk_score}/100"
    )

    print(
        f"Severity:       {alert.severity.value}"
    )

    print(
        f"Status:         {alert.status.value}"
    )

    print()

    print(
        "NEW → ACKNOWLEDGED:",
        transition(
            AlertStatus.NEW,
            AlertStatus.ACKNOWLEDGED,
        ),
    )

    print(
        "NEW → RESOLVED:",
        transition(
            AlertStatus.NEW,
            AlertStatus.RESOLVED,
        ),
    )