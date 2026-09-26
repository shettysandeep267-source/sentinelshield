"""
Central data models for SentinelShield.

Every collector/detector should ultimately produce an Event (raw telemetry)
and, when a rule matches, an Alert (a scored security finding derived from
one or more Events).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class EngineSource(str, Enum):
    """Which detection engine produced this event/alert.

    Tracking this explicitly avoids double-counting the same underlying
    attack when both the custom detection engine and Suricata fire on it.
    """
    SENTINELSHIELD = "SENTINELSHIELD"
    SURICATA = "SURICATA"


@dataclass
class Event:
    """Raw (or lightly normalized) telemetry from a collector."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str = "UNKNOWN"
    description: str = ""
    raw_data: Optional[str] = None
    engine: EngineSource = EngineSource.SENTINELSHIELD
    id: Optional[int] = None


@dataclass
class Alert:
    """A scored security finding, usually derived from one or more Events."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = "UNKNOWN"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    severity: Severity = Severity.LOW
    confidence: int = 0          # 0-100
    risk_score: int = 0          # 0-100, see core/risk.py
    description: str = ""
    evidence: Optional[str] = None
    recommended_action: Optional[str] = None
    status: AlertStatus = AlertStatus.NEW
    engine: EngineSource = EngineSource.SENTINELSHIELD
    related_event_ids: Optional[str] = None  # comma-separated event ids
    id: Optional[int] = None
