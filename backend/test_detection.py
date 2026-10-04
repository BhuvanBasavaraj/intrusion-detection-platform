from log_parser import load_logs
from detection_engine import detect_brute_force


logs = load_logs("data/security_logs.csv")

alerts = detect_brute_force(logs)

print(f"Detected {len(alerts)} alert(s)")

for alert in alerts:
    print("\n🚨 ALERT")
    print(f"Type: {alert['type']}")
    print(f"Severity: {alert['severity']}")
    print(f"User: {alert['user']}")
    print(f"IP: {alert['ip']}")
    print(f"Message: {alert['message']}")