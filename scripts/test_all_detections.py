"""
SentinelShield complete detection pipeline test.

Uses simulated defensive test events only.
No real attacks or network scanning are performed.
"""

from app.core.database import init_db
from app.core.models import Event
from app.core.pipeline import DetectionPipeline


def show_alert(alert):
    print("------------------------------------------")
    print(f"Type:        {alert.event_type}")
    print(f"Source IP:   {alert.source_ip}")
    print(f"Severity:    {alert.severity.value}")
    print(f"Risk Score:  {alert.risk_score}/100")
    print(f"Confidence:  {alert.confidence}%")
    print(f"Status:      {alert.status.value}")
    print(f"Alert ID:    {alert.id}")
    print("------------------------------------------")


def main():

    print("==========================================")
    print(" SentinelShield Complete Detection Test")
    print("==========================================")
    print()

    init_db()

    pipeline = DetectionPipeline()

    # Use small thresholds for a fast local demonstration.
    pipeline.port_scan_detector.port_threshold = 5
    pipeline.brute_force_detector.failure_threshold = 5

    source_ip = "192.168.56.101"
    destination_ip = "192.168.56.10"

    # ========================================================================
    # 1. SQL Injection
    # ========================================================================

    print("[1] Testing SQL Injection")

    event = Event(
        event_type="HTTP_REQUEST",
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="HTTP",
        description=(
            "HTTP request test containing union select marker"
        ),
    )

    alert = pipeline.process_event(event)

    if alert:
        show_alert(alert)

    # ========================================================================
    # 2. XSS
    # ========================================================================

    print("[2] Testing XSS")

    event = Event(
        event_type="HTTP_REQUEST",
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="HTTP",
        description=(
            "HTTP request test containing <script> marker"
        ),
    )

    alert = pipeline.process_event(event)

    if alert:
        show_alert(alert)

    # ========================================================================
    # 3. Directory Traversal
    # ========================================================================

    print("[3] Testing Directory Traversal")

    event = Event(
        event_type="HTTP_REQUEST",
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="HTTP",
        description=(
            "HTTP request test containing ../ marker"
        ),
    )

    alert = pipeline.process_event(event)

    if alert:
        show_alert(alert)

    # ========================================================================
    # 4. Command Injection
    # ========================================================================

    print("[4] Testing Command Injection")

    event = Event(
        event_type="HTTP_REQUEST",
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="HTTP",
        description=(
            "HTTP request test containing ; whoami marker"
        ),
    )

    alert = pipeline.process_event(event)

    if alert:
        show_alert(alert)

    # ========================================================================
    # 5. Port Scan
    # ========================================================================

    print("[5] Testing Port Scan")

    for port in [21, 22, 23, 25, 53]:

        event = Event(
            event_type="TCP_CONNECTION",
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=45000,
            destination_port=port,
            protocol="TCP",
            description=(
                f"Simulated connection to port {port}"
            ),
        )

        alert = pipeline.process_event(event)

        if alert:
            show_alert(alert)

    # ========================================================================
    # 6. Brute Force
    # ========================================================================

    print("[6] Testing Brute Force")

    for attempt in range(1, 6):

        event = Event(
            event_type="AUTH_FAILURE",
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="AUTH",
            description=(
                f"Simulated authentication failure #{attempt}"
            ),
        )

        alert = pipeline.process_event(event)

        if alert:
            show_alert(alert)

    print()
    print("==========================================")
    print(" Complete Detection Test Finished")
    print("==========================================")


if __name__ == "__main__":
    main()