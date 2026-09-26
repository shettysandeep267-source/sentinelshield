"""
SentinelShield Port-Scan Detector.

Tracks destination ports contacted by each source IP within a rolling
time window.

When a source contacts enough distinct destination ports within the
configured window, a PORT_SCAN Event is generated.

This module performs detection only. Database storage and alert creation
are handled by the higher-level SentinelShield detection pipeline.
"""

import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from app.core.models import Event, EngineSource


# ---------------------------------------------------------------------------
# Default detection settings
# ---------------------------------------------------------------------------

TIME_WINDOW_SECONDS = 10
DISTINCT_PORT_THRESHOLD = 15


class PortScanDetector:
    """
    Stateful port-scan detector.

    Example:

        Source IP
            |
            +-- port 21
            +-- port 22
            +-- port 23
            +-- port 25
            +-- ...
            |
            +-- 15+ distinct ports
                    |
                    v
                PORT_SCAN
    """

    def __init__(
        self,
        window_seconds: int = TIME_WINDOW_SECONDS,
        port_threshold: int = DISTINCT_PORT_THRESHOLD,
    ) -> None:

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        if port_threshold <= 0:
            raise ValueError(
                "port_threshold must be greater than 0"
            )

        self.window_seconds = window_seconds
        self.port_threshold = port_threshold

        # ---------------------------------------------------------
        # source_ip -> list of (monotonic_time, destination_port)
        # ---------------------------------------------------------

        self._activity: Dict[
            str,
            List[Tuple[float, int]]
        ] = defaultdict(list)

        # Sources that have already triggered a scan alert.
        #
        # This prevents one scan from generating dozens of duplicate
        # PORT_SCAN events.
        self._alerted_sources: Set[str] = set()

    # -----------------------------------------------------------------------
    # Process event
    # -----------------------------------------------------------------------

    def process(
        self,
        event: Event,
    ) -> Optional[Event]:
        """
        Process one network Event.

        Returns:
            Event with event_type="PORT_SCAN" when a scan is detected.
            None when no scan is detected.
        """

        # ---------------------------------------------------------
        # Ignore events that cannot represent port activity
        # ---------------------------------------------------------

        if not event.source_ip:
            return None

        if event.destination_port is None:
            return None

        # We only care about TCP/UDP-style port activity.
        if event.protocol not in ("TCP", "UDP"):
            return None

        source_ip = event.source_ip
        destination_port = int(event.destination_port)

        now = time.monotonic()

        # ---------------------------------------------------------
        # Add current connection attempt
        # ---------------------------------------------------------

        self._activity[source_ip].append(
            (
                now,
                destination_port,
            )
        )

        # ---------------------------------------------------------
        # Remove old activity
        # ---------------------------------------------------------

        cutoff = now - self.window_seconds

        self._activity[source_ip] = [
            (timestamp, port)
            for timestamp, port
            in self._activity[source_ip]
            if timestamp >= cutoff
        ]

        # ---------------------------------------------------------
        # Count distinct destination ports
        # ---------------------------------------------------------

        distinct_ports = self._distinct_ports_in_window(
            source_ip,
            now,
        )

        # ---------------------------------------------------------
        # Check threshold
        # ---------------------------------------------------------

        if len(distinct_ports) < self.port_threshold:
            # If the source has fallen below the threshold because
            # old activity expired, allow it to trigger again later.
            self._alerted_sources.discard(source_ip)

            return None

        # ---------------------------------------------------------
        # Avoid duplicate alerts for the same active scan
        # ---------------------------------------------------------

        if source_ip in self._alerted_sources:
            return None

        self._alerted_sources.add(source_ip)

        # ---------------------------------------------------------
        # Create detection Event
        # ---------------------------------------------------------

        detected_event = Event(
            event_type="PORT_SCAN",
            source_ip=source_ip,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            protocol=event.protocol,
            description=(
                f"Possible port scan detected from {source_ip}. "
                f"{len(distinct_ports)} distinct destination ports "
                f"were contacted within "
                f"{self.window_seconds} seconds."
            ),
            raw_data=(
                f"distinct_ports={sorted(distinct_ports)}"
            ),
            engine=EngineSource.SENTINELSHIELD,
        )

        return detected_event

    # -----------------------------------------------------------------------
    # Distinct ports
    # -----------------------------------------------------------------------

    def _distinct_ports_in_window(
        self,
        source_ip: str,
        now: float,
    ) -> Set[int]:
        """
        Return the distinct destination ports contacted by a source
        within the current rolling time window.
        """

        cutoff = now - self.window_seconds

        return {
            port
            for timestamp, port
            in self._activity.get(source_ip, [])
            if timestamp >= cutoff
        }


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    print("==========================================")
    print(" SentinelShield Port-Scan Detector Test")
    print("==========================================")

    detector = PortScanDetector(
        window_seconds=10,
        port_threshold=5,
    )

    source_ip = "192.168.56.101"

    print()
    print("Sending simulated network events...")
    print()

    for port in [21, 22, 23, 25, 53]:

        event = Event(
            source_ip=source_ip,
            destination_ip="192.168.56.10",
            source_port=45000,
            destination_port=port,
            protocol="TCP",
            event_type="TCP_CONNECTION",
            description=(
                f"Test connection to port {port}"
            ),
        )

        result = detector.process(event)

        print(
            f"Port {port:>5} -> "
            f"{'PORT_SCAN DETECTED!' if result else 'normal'}"
        )

        if result:

            print()
            print("==========================================")
            print(" 🚨 PORT SCAN DETECTED")
            print("==========================================")
            print(f"Source IP:    {result.source_ip}")
            print(f"Destination:  {result.destination_ip}")
            print(f"Protocol:     {result.protocol}")
            print(f"Event Type:   {result.event_type}")
            print(f"Description:  {result.description}")
            print(f"Evidence:     {result.raw_data}")
            print("==========================================")