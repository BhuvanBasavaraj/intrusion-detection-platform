from log_parser import load_logs
from detection_engine import detect_brute_force
from detection_rules import (
    detect_privilege_escalation,
    detect_sensitive_access,
)
from risk_engine import calculate_risk


logs = load_logs("data/security_logs.csv")

alerts = []

alerts.extend(detect_brute_force(logs))
alerts.extend(detect_privilege_escalation(logs))
alerts.extend(detect_sensitive_access(logs))

risk = calculate_risk(alerts)

print("Risk Assessment")
print("----------------")
print(f"Score: {risk['score']}")
print(f"Level: {risk['risk_level']}")
print(f"Alerts: {risk['alert_count']}")