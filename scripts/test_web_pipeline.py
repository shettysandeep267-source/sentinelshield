"""
SentinelShield Web Attack Pipeline Test.

Uses harmless test strings to verify that the defensive detection
pipeline creates database alerts correctly.
"""

from app.core.database import init_db
from app.core.models import Event
from app.core.pipeline import DetectionPipeline


def main():

    print("==========================================")
    print(" SentinelShield Web Pipeline Test")
    print("==========================================")
    print()

    init_db()

    pipeline = DetectionPipeline()

    test_cases = [
        (
            "SQL_INJECTION",
            "HTTP request test containing union select marker",
        ),
        (
            "XSS",
            "HTTP request test containing <script> marker",
        ),
        (
            "DIRECTORY_TRAVERSAL",
            "HTTP request test containing ../ marker",
        ),
        (
            "COMMAND_INJECTION",
            "HTTP request test containing ; whoami marker",
        ),
    ]

    for expected_type, description in test_cases:

        event = Event(
            event_type="HTTP_REQUEST",
            source_ip="192.168.56.101",
            destination_ip="192.168.56.10",
            protocol="HTTP",
            description=description,
        )

        alert = pipeline.process_event(
            event
        )

        if alert:

            print(
                f"✓ {expected_type:<25} "
                f"→ {alert.event_type}"
            )

            print(
                f"  Severity:   "
                f"{alert.severity.value}"
            )

            print(
                f"  Risk Score: "
                f"{alert.risk_score}/100"
            )

            print(
                f"  Confidence: "
                f"{alert.confidence}%"
            )

            print(
                f"  Alert ID:   "
                f"{alert.id}"
            )

        else:

            print(
                f"✗ {expected_type:<25} "
                f"→ NO ALERT"
            )

        print()


if __name__ == "__main__":
    main()