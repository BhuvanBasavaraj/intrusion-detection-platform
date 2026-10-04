from backend.detection_engine import detect_brute_force


def test_brute_force_detected():
    logs = [
        {
            "timestamp": "2026-10-04T09:31:02",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T09:31:08",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T09:31:14",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T09:31:20",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T09:31:27",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "SUCCESS",
            "resource": None,
        },
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "BRUTE_FORCE"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["user"] == "admin"
    assert alerts[0]["ip"] == "10.0.0.5"
    
def test_three_failures_not_brute_force():
    logs = [
        {
            "timestamp": "2026-10-04T10:00:00",
            "user": "user1",
            "ip": "10.0.0.10",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T10:00:05",
            "user": "user1",
            "ip": "10.0.0.10",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T10:00:10",
            "user": "user1",
            "ip": "10.0.0.10",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T10:00:15",
            "user": "user1",
            "ip": "10.0.0.10",
            "event_type": "LOGIN",
            "status": "SUCCESS",
            "resource": None,
        },
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 0
    
def test_failures_from_different_ips_not_combined():
    logs = [
        {
            "timestamp": "2026-10-04T11:00:00",
            "user": "admin",
            "ip": "10.0.0.1",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T11:00:05",
            "user": "admin",
            "ip": "10.0.0.1",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T11:00:10",
            "user": "admin",
            "ip": "10.0.0.2",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T11:00:15",
            "user": "admin",
            "ip": "10.0.0.2",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T11:00:20",
            "user": "admin",
            "ip": "10.0.0.2",
            "event_type": "LOGIN",
            "status": "SUCCESS",
            "resource": None,
        },
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 0
    
def test_failures_outside_time_window_not_combined():
    logs = [
        {
            "timestamp": "2026-10-04T12:00:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T12:01:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T12:02:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T12:06:00",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "FAILED",
            "resource": None,
        },
        {
            "timestamp": "2026-10-04T12:06:10",
            "user": "admin",
            "ip": "10.0.0.5",
            "event_type": "LOGIN",
            "status": "SUCCESS",
            "resource": None,
        },
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 0