def generate_incident_explanation(incident: dict) -> str:
    alert_types = {
        alert["type"]
        for alert in incident["alerts"]
    }

    explanations = []

    if "BRUTE_FORCE" in alert_types:
        explanations.append(
            "Multiple failed login attempts were followed by "
            "a successful login from the same IP."
        )

    if "PRIVILEGE_ESCALATION" in alert_types:
        explanations.append(
            "The account then performed a privilege escalation."
        )

    if "SENSITIVE_RESOURCE_ACCESS" in alert_types:
        explanations.append(
            "The account accessed a sensitive resource."
        )

    if not explanations:
        return "Suspicious activity was detected."

    return " ".join(explanations)