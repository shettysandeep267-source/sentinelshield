from app.core.database import init_db, insert_event, insert_alert
from app.core.models import Event, Alert, Severity


def main():
    # Make sure the database exists
    init_db()

    # ---------------------------------------------------------
    # Create a simulated network event
    # ---------------------------------------------------------

    event = Event(
        source_ip="192.168.56.101",
        destination_ip="192.168.56.10",
        source_port=45678,
        destination_port=22,
        protocol="TCP",
        event_type="PORT_SCAN",
        description="Multiple connection attempts detected from a single source.",
        raw_data="LAB TEST: simulated port scan event",
    )

    event_id = insert_event(event)

    print(f"[+] Event created: {event_id}")

    # ---------------------------------------------------------
    # Create the security alert
    # ---------------------------------------------------------

    alert = Alert(
        event_type="PORT_SCAN",
        source_ip="192.168.56.101",
        destination_ip="192.168.56.10",
        severity=Severity.HIGH,
        confidence=94,
        risk_score=82,
        description="Possible TCP port scanning activity detected.",
        evidence=(
            "Multiple destination ports were contacted by the same "
            "source IP within a short time window."
        ),
        recommended_action=(
            "Investigate the source host and review related network events."
        ),
        related_event_ids=str(event_id),
    )

    alert_id = insert_alert(alert)

    print(f"[+] Alert created: {alert_id}")

    print()
    print("==========================================")
    print("  SENTINELSHIELD TEST ALERT CREATED")
    print("==========================================")
    print(f"Alert ID:     {alert_id}")
    print(f"Event ID:     {event_id}")
    print("Type:         PORT_SCAN")
    print("Source IP:    192.168.56.101")
    print("Destination:  192.168.56.10")
    print("Severity:     HIGH")
    print("Confidence:   94%")
    print("Risk Score:   82/100")
    print("Status:       NEW")
    print("==========================================")


if __name__ == "__main__":
    main()