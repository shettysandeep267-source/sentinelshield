"""
SentinelShield Flask dashboard routes.

Connects the SOC dashboard to the SQLite database and provides:
- Dashboard overview
- Alert management
- Alert investigation
- Network telemetry
- Web attack detections
- Reports page
- Alert status API
"""

from flask import Blueprint, jsonify, render_template, request

from app.core.database import (
    get_alerts,
    get_alert_count,
    get_event_count,
    get_connection,
    update_alert_status,
)


# ============================================================
# DASHBOARD BLUEPRINT
# ============================================================

bp = Blueprint(
    "dashboard",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/dashboard-static",
)


# ============================================================
# DASHBOARD OVERVIEW
# ============================================================

@bp.route("/")
def overview():
    """
    Main SentinelShield Security Operations Center.

    Displays:
        - Total alerts
        - Critical alerts
        - High-risk alerts
        - Total events
        - Threat activity
        - Detection engine status
        - Severity distribution
        - Security timeline
        - Recent alerts
    """

    total_alerts = get_alert_count()

    critical_alerts = get_alert_count(
        severity="CRITICAL"
    )

    high_alerts = get_alert_count(
        severity="HIGH"
    )

    total_events = get_event_count()

    recent_alerts = get_alerts(
        limit=10
    )

    return render_template(
        "dashboard.html",
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        total_events=total_events,
        recent_alerts=recent_alerts,
    )


# ============================================================
# ALERT LIST
# ============================================================

@bp.route("/alerts")
def alerts_list():
    """
    Display all security alerts.

    Supported filters:

        /alerts

        /alerts?status=NEW

        /alerts?severity=HIGH

        /alerts?status=NEW&severity=HIGH
    """

    status = request.args.get("status")
    severity = request.args.get("severity")

    alerts = get_alerts(
        status=status,
        severity=severity,
        limit=100,
    )

    total_visible = len(alerts)

    high_critical = sum(
        1
        for alert in alerts
        if alert["severity"] in ("HIGH", "CRITICAL")
    )

    new_alerts = sum(
        1
        for alert in alerts
        if alert["status"] == "NEW"
    )

    resolved_alerts = sum(
        1
        for alert in alerts
        if alert["status"] == "RESOLVED"
    )

    return render_template(
        "alerts.html",
        alerts=alerts,
        selected_status=status,
        selected_severity=severity,
        total_visible=total_visible,
        high_critical=high_critical,
        new_alerts=new_alerts,
        resolved_alerts=resolved_alerts,
    )


# ============================================================
# ALERT DETAIL / INVESTIGATION
# ============================================================

@bp.route("/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    """
    Display a complete analyst investigation screen.
    """

    with get_connection() as conn:

        alert = conn.execute(
            """
            SELECT *
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()

        related_events = []

        if alert is not None:

            source_ip = alert["source_ip"]
            event_type = alert["event_type"]

            if source_ip:

                related_events = conn.execute(
                    """
                    SELECT *
                    FROM events
                    WHERE source_ip = ?
                    AND (
                        event_type = ?
                        OR event_type = 'HTTP_REQUEST'
                    )
                    ORDER BY timestamp DESC, id DESC
                    LIMIT 50
                    """,
                    (
                        source_ip,
                        event_type,
                    ),
                ).fetchall()

    if alert is None:

        return (
            render_template(
                "alert_detail.html",
                alert=None,
                alert_id=alert_id,
                related_events=[],
            ),
            404,
        )

    # Determine workflow status
    workflow = {
        "new": alert["status"] in ["NEW"],
        "acknowledged": alert["status"] in ["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"],
        "investigating": alert["status"] in ["INVESTIGATING", "RESOLVED"],
        "resolved": alert["status"] in ["RESOLVED"],
    }

    return render_template(
        "alert_detail.html",
        alert=alert,
        alert_id=alert_id,
        related_events=related_events,
        risk_score=alert["risk_score"],
        workflow=workflow,
    )


# ============================================================
# NETWORK MONITORING
# ============================================================

@bp.route("/network")
def network_view():
    """
    Display recent network telemetry.
    """

    with get_connection() as conn:

        events = conn.execute(
            """
            SELECT *
            FROM events
            ORDER BY timestamp DESC, id DESC
            LIMIT 100
            """
        ).fetchall()

    total_events = get_event_count()

    port_scans = sum(
        1
        for event in events
        if event["event_type"] == "PORT_SCAN"
    )

    tcp_events = sum(
        1
        for event in events
        if str(event["protocol"]).upper() == "TCP"
    )

    udp_events = sum(
        1
        for event in events
        if str(event["protocol"]).upper() == "UDP"
    )

    return render_template(
        "network.html",
        events=events,
        total_events=total_events,
        port_scans=port_scans,
        tcp_events=tcp_events,
        udp_events=udp_events,
    )


# ============================================================
# WEB ATTACK MONITORING
# ============================================================

@bp.route("/web-attacks")
def web_attacks_view():
    """
    Display detected web attacks.
    """

    web_attack_types = (
        "SQL_INJECTION",
        "XSS",
        "DIRECTORY_TRAVERSAL",
        "COMMAND_INJECTION",
    )

    placeholders = ",".join(
        "?" for _ in web_attack_types
    )

    with get_connection() as conn:

        alerts = conn.execute(
            f"""
            SELECT *
            FROM alerts
            WHERE event_type IN ({placeholders})
            ORDER BY timestamp DESC, id DESC
            LIMIT 100
            """,
            web_attack_types,
        ).fetchall()

    sql_injection = sum(
        1
        for alert in alerts
        if alert["event_type"] == "SQL_INJECTION"
    )

    xss = sum(
        1
        for alert in alerts
        if alert["event_type"] == "XSS"
    )

    command_injection = sum(
        1
        for alert in alerts
        if alert["event_type"] == "COMMAND_INJECTION"
    )

    directory_traversal = sum(
        1
        for alert in alerts
        if alert["event_type"] == "DIRECTORY_TRAVERSAL"
    )

    return render_template(
        "web_attacks.html",
        alerts=alerts,
        sql_injection=sql_injection,
        xss=xss,
        command_injection=command_injection,
        directory_traversal=directory_traversal,
        total_web_attacks=len(alerts),
    )


# ============================================================
# REPORTS
# ============================================================

@bp.route("/reports")
def reports_view():
    """
    Security reports page.
    """

    total_alerts = get_alert_count()

    critical_alerts = get_alert_count(
        severity="CRITICAL"
    )

    high_alerts = get_alert_count(
        severity="HIGH"
    )

    medium_alerts = get_alert_count(
        severity="MEDIUM"
    )

    low_alerts = get_alert_count(
        severity="LOW"
    )

    total_events = get_event_count()

    # Count attack types
    sql_injection_count = get_alert_count(
        severity=None
    )  # This will be calculated differently
    with get_connection() as conn:
        sql_injection = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE event_type = 'SQL_INJECTION'"
        ).fetchone()[0]
        xss = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE event_type = 'XSS'"
        ).fetchone()[0]
        traversal = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE event_type = 'DIRECTORY_TRAVERSAL'"
        ).fetchone()[0]
        cmd_injection = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE event_type = 'COMMAND_INJECTION'"
        ).fetchone()[0]
        port_scan = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE event_type = 'PORT_SCAN'"
        ).fetchone()[0]
        brute_force = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE event_type = 'BRUTE_FORCE'"
        ).fetchone()[0]

        # Status counts
        new_status = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'NEW'"
        ).fetchone()[0]
        acknowledged = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'ACKNOWLEDGED'"
        ).fetchone()[0]
        investigating = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'INVESTIGATING'"
        ).fetchone()[0]
        resolved = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'RESOLVED'"
        ).fetchone()[0]

    return render_template(
        "reports.html",
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
        total_events=total_events,
        sql_injection=sql_injection,
        xss=xss,
        traversal=traversal,
        cmd_injection=cmd_injection,
        port_scan=port_scan,
        brute_force=brute_force,
        new_status=new_status,
        acknowledged=acknowledged,
        investigating=investigating,
        resolved=resolved,
    )


# ============================================================
# ALERT STATUS API
# ============================================================

@bp.route(
    "/api/alerts/<int:alert_id>/status",
    methods=["POST"],
)
def update_alert_status_api(alert_id: int):
    """
    Update the status of an alert.

    Expected JSON:

        {
            "status": "ACKNOWLEDGED"
        }

    Supported lifecycle:

        NEW
          ↓
        ACKNOWLEDGED
          ↓
        INVESTIGATING
          ↓
        RESOLVED
    """

    data = request.get_json(
        silent=True
    ) or {}

    new_status = data.get("status")

    if not new_status:

        return jsonify({
            "ok": False,
            "error": "Missing status",
        }), 400

    new_status = str(new_status).upper().strip()

    valid_statuses = {
        "NEW",
        "ACKNOWLEDGED",
        "INVESTIGATING",
        "RESOLVED",
    }

    if new_status not in valid_statuses:

        return jsonify({
            "ok": False,
            "error": "Invalid alert status",
        }), 400

    try:

        update_alert_status(
            alert_id,
            new_status,
        )

    except ValueError as exc:

        return jsonify({
            "ok": False,
            "error": str(exc),
        }), 400

    return jsonify({
        "ok": True,
        "alert_id": alert_id,
        "status": new_status,
    })