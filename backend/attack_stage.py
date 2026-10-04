def get_attack_stage(event: dict) -> str:
    event_type = event["event_type"]
    status = event["status"]

    if event_type == "LOGIN":
        if status == "FAILED":
            return "Initial Access Attempt"

        if status == "SUCCESS":
            return "Initial Access"

    if event_type == "PRIVILEGE_ESCALATION":
        return "Privilege Escalation"

    if event_type == "FILE_ACCESS":
        return "Data Access"

    return "Other Activity"