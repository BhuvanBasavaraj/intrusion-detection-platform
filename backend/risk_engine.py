SEVERITY_POINTS = {
    "LOW": 10,
    "MEDIUM": 20,
    "HIGH": 30,
    "CRITICAL": 40,
}


def calculate_risk(alerts: list[dict]) -> dict:
    score = 0

    for alert in alerts:
        score += SEVERITY_POINTS.get(alert["severity"], 0)

    score = min(score, 100)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "alert_count": len(alerts),
    }