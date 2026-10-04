from backend.correlation_engine import correlate_alerts


def test_related_alerts_form_one_incident():
    alerts = [
        {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "user": "admin",
            "ip": "10.0.0.5",
            "timestamp": "2026-10-04T12:00:30",
            "message": "Multiple failed login attempts",
        },
        {
            "type": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "user": "admin",
            "ip": "10.0.0.5",
            "timestamp": "2026-10-04T12:02:00",
            "message": "User privilege level was elevated",
        },
        {
            "type": "SENSITIVE_RESOURCE_ACCESS",
            "severity": "HIGH",
            "user": "admin",
            "ip": "10.0.0.5",
            "timestamp": "2026-10-04T12:03:00",
            "message": "Access to sensitive resource",
        },
    ]

    logs = [
        {
            "timestamp": "2026-10-04T12:00:30",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "SUCCESS",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T12:02:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "PRIVILEGE_ESCALATION",
            "status": "SUCCESS",
            "resource": "admin_panel",
        },
        {
            "timestamp": "2026-10-04T12:03:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "FILE_ACCESS",
            "status": "SUCCESS",
            "resource": "employee_salaries.csv",
        },
    ]

    incidents = correlate_alerts(alerts, logs)

    assert len(incidents) == 1
    assert incidents[0]["user"] == "admin"
    assert incidents[0]["ip"] == "10.0.0.5"
    assert len(incidents[0]["alerts"]) == 3


def test_different_users_form_separate_incidents():
    alerts = [
        {
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "user": "admin",
            "ip": "10.0.0.5",
            "timestamp": "2026-10-04T12:00:00",
            "message": "Brute force detected",
        },
        {
            "type": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "user": "rahul",
            "ip": "10.0.0.6",
            "timestamp": "2026-10-04T12:01:00",
            "message": "Privilege escalation detected",
        },
    ]

    logs = []

    incidents = correlate_alerts(alerts, logs)

    assert len(incidents) == 2