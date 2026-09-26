"""
SentinelShield Brute-Force Detector.

Detects repeated authentication failures from the same source IP
within a rolling time window.

Detection types:

    BRUTE_FORCE
    SUCCESSFUL_BRUTE_FORCE

This module only analyzes authentication events. It does not
perform login attempts or generate credentials.
"""

import time
from collections import defaultdict
from typing import Dict, List, Optional

from app.core.models import Event, EngineSource


# ============================================================================
# Detection settings
# ============================================================================

TIME_WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 5

# A successful login following this many recent failures is
# considered suspicious.
SUCCESS_FAILURE_THRESHOLD = 3


class BruteForceDetector:
    """
    Stateful authentication-abuse detector.

    Example:

        192.168.56.101

        AUTH_FAILURE
        AUTH_FAILURE
        AUTH_FAILURE
        AUTH_FAILURE
        AUTH_FAILURE
             ↓
        BRUTE_FORCE
    """

    def __init__(
        self,
        window_seconds: int = TIME_WINDOW_SECONDS,
        failure_threshold: int = FAILURE_THRESHOLD,
    ) -> None:

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        if failure_threshold <= 0:
            raise ValueError(
                "failure_threshold must be greater than 0"
            )

        self.window_seconds = window_seconds
        self.failure_threshold = failure_threshold

        # --------------------------------------------------------------------
        # source_ip -> list of failure timestamps
        # --------------------------------------------------------------------

        self._failures: Dict[
            str,
            List[float]
        ] = defaultdict(list)

        # Prevent repeated BRUTE_FORCE alerts for the same active burst.
        self._alerted_sources = set()

    # ------------------------------------------------------------------------
    # Process authentication event
    # ------------------------------------------------------------------------

    def process(
        self,
        event: Event,
    ) -> Optional[Event]:
        """
        Process an authentication event.

        Supported events:

            AUTH_FAILURE
            AUTH_SUCCESS

        Returns:
            Detection Event when suspicious behavior is detected.
            None otherwise.
        """

        # --------------------------------------------------------------------
        # Source IP is required
        # --------------------------------------------------------------------

        if not event.source_ip:
            return None

        if event.event_type not in {
            "AUTH_FAILURE",
            "AUTH_SUCCESS",
        }:
            return None

        source_ip = event.source_ip

        # Use monotonic time for rolling-window calculations.
        now = time.monotonic()

        # --------------------------------------------------------------------
        # AUTH_FAILURE
        # --------------------------------------------------------------------

        if event.event_type == "AUTH_FAILURE":

            self._failures[source_ip].append(
                now
            )

            self._prune_old_failures(
                source_ip,
                now,
            )

            failure_count = len(
                self._failures[source_ip]
            )

            # ---------------------------------------------------------------
            # Threshold reached
            # ---------------------------------------------------------------

            if failure_count >= self.failure_threshold:

                if source_ip in self._alerted_sources:
                    return None

                self._alerted_sources.add(
                    source_ip
                )

                return Event(
                    event_type="BRUTE_FORCE",
                    source_ip=source_ip,
                    destination_ip=event.destination_ip,
                    source_port=event.source_port,
                    destination_port=event.destination_port,
                    protocol=event.protocol or "AUTH",
                    description=(
                        f"Possible brute-force activity detected "
                        f"from {source_ip}. "
                        f"{failure_count} failed authentication "
                        f"attempts occurred within "
                        f"{self.window_seconds} seconds."
                    ),
                    raw_data=(
                        f"failure_count={failure_count}; "
                        f"window_seconds={self.window_seconds}"
                    ),
                    engine=EngineSource.SENTINELSHIELD,
                )

            return None

        # --------------------------------------------------------------------
        # AUTH_SUCCESS
        # --------------------------------------------------------------------

        if event.event_type == "AUTH_SUCCESS":

            self._prune_old_failures(
                source_ip,
                now,
            )

            failure_count = len(
                self._failures[source_ip]
            )

            # ---------------------------------------------------------------
            # Successful login after suspicious failures
            # ---------------------------------------------------------------

            if failure_count >= SUCCESS_FAILURE_THRESHOLD:

                # Clear the burst after reporting it.
                self._failures[source_ip].clear()
                self._alerted_sources.discard(
                    source_ip
                )

                return Event(
                    event_type="SUCCESSFUL_BRUTE_FORCE",
                    source_ip=source_ip,
                    destination_ip=event.destination_ip,
                    source_port=event.source_port,
                    destination_port=event.destination_port,
                    protocol=event.protocol or "AUTH",
                    description=(
                        f"Successful authentication occurred "
                        f"after {failure_count} recent failed "
                        f"attempts from {source_ip}."
                    ),
                    raw_data=(
                        f"previous_failures={failure_count}; "
                        f"window_seconds={self.window_seconds}"
                    ),
                    engine=EngineSource.SENTINELSHIELD,
                )

            return None

        return None

    # ------------------------------------------------------------------------
    # Remove old failures
    # ------------------------------------------------------------------------

    def _prune_old_failures(
        self,
        source_ip: str,
        now: float,
    ) -> None:
        """
        Remove authentication failures older than the rolling window.
        """

        cutoff = (
            now - self.window_seconds
        )

        self._failures[source_ip] = [
            timestamp
            for timestamp in self._failures[source_ip]
            if timestamp >= cutoff
        ]

        # If the window is empty, allow a future burst to trigger
        # a new alert.
        if not self._failures[source_ip]:

            self._alerted_sources.discard(
                source_ip
            )


# ============================================================================
# Manual smoke test
# ============================================================================

if __name__ == "__main__":

    print("==========================================")
    print(" SentinelShield Brute-Force Detector")
    print("==========================================")
    print()

    detector = BruteForceDetector(
        window_seconds=60,
        failure_threshold=5,
    )

    source_ip = "192.168.56.101"

    print(
        "Simulating authentication failures..."
    )
    print()

    # Five harmless simulated authentication events.
    for attempt in range(1, 6):

        event = Event(
            event_type="AUTH_FAILURE",
            source_ip=source_ip,
            destination_ip="192.168.56.10",
            protocol="AUTH",
            description=(
                f"Simulated authentication failure "
                f"#{attempt}"
            ),
        )

        result = detector.process(
            event
        )

        print(
            f"Attempt {attempt} → "
            f"{'🚨 BRUTE_FORCE DETECTED' if result else 'normal'}"
        )

        if result:

            print()
            print("------------------------------------------")
            print("Security Detection")
            print("------------------------------------------")
            print(
                f"Type:        {result.event_type}"
            )
            print(
                f"Source IP:   {result.source_ip}"
            )
            print(
                f"Description: {result.description}"
            )
            print(
                f"Evidence:    {result.raw_data}"
            )
            print("------------------------------------------")

    print()
    print(
        "Testing successful login after failures..."
    )

    success_event = Event(
        event_type="AUTH_SUCCESS",
        source_ip=source_ip,
        destination_ip="192.168.56.10",
        protocol="AUTH",
        description="Simulated successful authentication",
    )

    success_result = detector.process(
        success_event
    )

    print(
        "Successful login → "
        f"{success_result.event_type if success_result else 'normal'}"
    )