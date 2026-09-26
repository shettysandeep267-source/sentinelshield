"""
End-to-end SentinelShield detection pipeline test.

This test uses simulated network events and does NOT perform
real network scanning.
"""

from app.core.database import init_db
from app.core.models import Event
from app.core.pipeline import DetectionPipeline


def main():

    print("==========================================")
    print(" SentinelShield End-to-End Test")
    print("==========================================")
    print()

    init_db()

    pipeline = DetectionPipeline()

    source_ip = "192.168.56.101"
    destination_ip = "192.168.56.10"

    # Use five ports for this test.
    # The detector threshold is temporarily set to five.
    pipeline.port_scan_detector.port_threshold = 5

    ports = [
        21,
        22,
        23,
        25,
        53,
    ]

    for port in ports:

        event = Event(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=45000,
            destination_port=port,
            protocol="TCP",
            event_type="TCP_CONNECTION",
            description=(
                f"Test TCP connection to port {port}"
            ),
        )

        alert = pipeline.process_event(
            event
        )

        print(
            f"Port {port:>5} → "
            f"{'🚨 ALERT CREATED' if alert else 'normal'}"
        )

        if alert:

            print()
            print("------------------------------------------")
            print("Security Alert")
            print("------------------------------------------")
            print(
                f"Alert ID:    {alert.id}"
            )
            print(
                f"Event Type:  {alert.event_type}"
            )
            print(
                f"Source IP:   {alert.source_ip}"
            )
            print(
                f"Severity:    {alert.severity.value}"
            )
            print(
                f"Risk Score:  {alert.risk_score}/100"
            )
            print(
                f"Confidence:  {alert.confidence}%"
            )
            print(
                f"Status:      {alert.status.value}"
            )
            print("------------------------------------------")


if __name__ == "__main__":
    main()