def detect_privilege_escalation(logs: list[dict]) -> list[dict]:
    alerts = []

    for log in logs:
        if log["event_type"] == "PRIVILEGE_ESCALATION":
            alerts.append({
                "type": "PRIVILEGE_ESCALATION",
                "severity": "HIGH",
                "user": log["user"],
                "ip": log["ip"],
                "message": "User privilege level was elevated",
                "timestamp": log["timestamp"],
                "evidence": [log],
            })

    return alerts

def detect_sensitive_access(logs: list[dict]) -> list[dict]:
    alerts = []

    sensitive_resources = {
        "employee_salaries.csv",
        "passwords.txt",
        "credentials.db",
        "customer_data.csv",
    }

    for log in logs:
        if (
            log["event_type"] == "FILE_ACCESS"
            and log["resource"] in sensitive_resources
        ):
            alerts.append({
                "type": "SENSITIVE_RESOURCE_ACCESS",
                "severity": "HIGH",
                "user": log["user"],
                "ip": log["ip"],
                "message": (
                    f"Access to sensitive resource: "
                    f"{log['resource']}"
                ),
                "timestamp": log["timestamp"],
                "evidence": [log],
            })

    return alerts