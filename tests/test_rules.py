from backend.detection_rules import (
    detect_privilege_escalation,
    detect_sensitive_access,
)


def test_privilege_escalation_detected():
    logs = [
        {
            "timestamp": "2026-10-04T12:10:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "PRIVILEGE_ESCALATION",
            "status": "SUCCESS",
            "resource": "admin_panel",
        }
    ]

    alerts = detect_privilege_escalation(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "PRIVILEGE_ESCALATION"
    assert alerts[0]["severity"] == "HIGH"


def test_sensitive_resource_access_detected():
    logs = [
        {
            "timestamp": "2026-10-04T12:15:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "FILE_ACCESS",
            "status": "SUCCESS",
            "resource": "employee_salaries.csv",
        }
    ]

    alerts = detect_sensitive_access(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "SENSITIVE_RESOURCE_ACCESS"
    assert alerts[0]["severity"] == "HIGH"


def test_normal_file_access_not_flagged():
    logs = [
        {
            "timestamp": "2026-10-04T12:20:00",
            "user": "bhuvan",
            "ip": "192.168.1.20",
            "event_type": "FILE_ACCESS",
            "status": "SUCCESS",
            "resource": "notes.txt",
        }
    ]

    alerts = detect_sensitive_access(logs)

    assert len(alerts) == 0