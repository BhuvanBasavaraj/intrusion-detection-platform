from backend.risk_engine import calculate_risk


def test_low_risk():
    alerts = [
        {
            "type": "TEST",
            "severity": "LOW",
        }
    ]

    risk = calculate_risk(alerts)

    assert risk["score"] == 10
    assert risk["risk_level"] == "LOW"
    assert risk["alert_count"] == 1


def test_medium_risk():
    alerts = [
        {
            "type": "TEST",
            "severity": "HIGH",
        }
    ]

    risk = calculate_risk(alerts)

    assert risk["score"] == 30
    assert risk["risk_level"] == "MEDIUM"


def test_critical_risk_is_capped_at_100():
    alerts = [
        {"type": "TEST", "severity": "CRITICAL"},
        {"type": "TEST", "severity": "CRITICAL"},
        {"type": "TEST", "severity": "CRITICAL"},
    ]

    risk = calculate_risk(alerts)

    assert risk["score"] == 100
    assert risk["risk_level"] == "CRITICAL"