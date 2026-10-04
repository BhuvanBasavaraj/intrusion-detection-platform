from collections import defaultdict
from datetime import datetime


def detect_brute_force(logs: list[dict]) -> list[dict]:
    failed_attempts = defaultdict(list)
    alerts = []

    for log in logs:
        if log["event_type"] != "LOGIN":
            continue

        key = (log["user"], log["ip"])

        timestamp = datetime.fromisoformat(log["timestamp"])

        if log["status"] == "FAILED":
            failed_attempts[key].append(timestamp)

        elif log["status"] == "SUCCESS":
            failures = failed_attempts[key]

            recent_failures = [
                failure
                for failure in failures
                if (timestamp - failure).total_seconds() <= 300
            ]

            failed_attempts[key] = recent_failures

            if len(recent_failures) >= 4:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "user": log["user"],
                    "ip": log["ip"],
                    "message": (
                        f"{len(recent_failures)} failed login attempts "
                        "followed by a successful login"
                    ),
                    "timestamp": log["timestamp"],
                })

    return alerts