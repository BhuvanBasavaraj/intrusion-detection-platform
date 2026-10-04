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
                evidence = []
                
                for failure in recent_failures:
                    evidence.append({
                        "timestamp": failure.isoformat(),
                        "user": log["user"],
                        "ip": log["ip"],
                        "event_type": "LOGIN",
                        "status": "FAILED",
                        "resource": None,
                    })

                evidence.append(log)

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
                    "evidence": evidence,
                })

    return alerts