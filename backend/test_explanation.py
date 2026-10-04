from log_parser import load_logs
from detection_engine import detect_brute_force
from detection_rules import (
    detect_privilege_escalation,
    detect_sensitive_access,
)
from correlation_engine import correlate_alerts
from explanation_engine import generate_incident_explanation


logs = load_logs("data/security_logs.csv")

alerts = []

alerts.extend(detect_brute_force(logs))
alerts.extend(detect_privilege_escalation(logs))
alerts.extend(detect_sensitive_access(logs))

incidents = correlate_alerts(alerts, logs)

for incident in incidents:
    explanation = generate_incident_explanation(incident)

    print("Incident Explanation")
    print("--------------------")
    print(explanation)