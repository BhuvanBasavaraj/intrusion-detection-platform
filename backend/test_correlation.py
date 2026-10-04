from log_parser import load_logs
from detection_engine import detect_brute_force
from detection_rules import (
    detect_privilege_escalation,
    detect_sensitive_access,
)
from correlation_engine import correlate_alerts


logs = load_logs("data/security_logs.csv")

alerts = []

alerts.extend(detect_brute_force(logs))
alerts.extend(detect_privilege_escalation(logs))
alerts.extend(detect_sensitive_access(logs))

incidents = correlate_alerts(alerts,logs)

print(f"Created {len(incidents)} incident(s)")

for incident in incidents:
    print("\n" + "=" * 50)
    print(f"Incident: {incident['incident_id']}")
    print(f"User: {incident['user']}")
    print(f"IP: {incident['ip']}")
    print(f"Alerts: {len(incident['alerts'])}")
    print(f"First event: {incident['first_timestamp']}")
    print(f"Last event: {incident['last_timestamp']}")

    print("\nAttack events:")

    for alert in incident["alerts"]:
        print(
            f"- {alert['timestamp']} | "
            f"{alert['type']} | "
            f"{alert['severity']}"
        )

    print("\nEvidence / Timeline:")

    for log in incident["timeline"]:
        print(
            f"- {log['timestamp']} | "
            f"{log['event_type']} | "
            f"{log['status']} | "
            f"{log['user']} | "
            f"{log['ip']}"
        )