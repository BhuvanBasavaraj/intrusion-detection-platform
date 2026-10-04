from log_parser import load_logs
from detection_rules import (
    detect_privilege_escalation,
    detect_sensitive_access,
)


logs = load_logs("data/security_logs.csv")

privilege_alerts = detect_privilege_escalation(logs)
sensitive_alerts = detect_sensitive_access(logs)

print("Privilege escalation alerts:")
for alert in privilege_alerts:
    print(alert)

print("\nSensitive access alerts:")
for alert in sensitive_alerts:
    print(alert)