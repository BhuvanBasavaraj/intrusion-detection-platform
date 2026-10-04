from datetime import datetime


def correlate_alerts(alerts: list[dict], time_window_seconds: int = 600) -> list[dict]:
    if not alerts:
        return []

    sorted_alerts = sorted(
        alerts,
        key=lambda alert: datetime.fromisoformat(alert["timestamp"])
    )

    incidents = []

    for alert in sorted_alerts:
        alert_time = datetime.fromisoformat(alert["timestamp"])

        matching_incident = None

        for incident in incidents:
            if (
                incident["user"] == alert["user"]
                and incident["ip"] == alert["ip"]
            ):
                last_event_time = datetime.fromisoformat(
                    incident["last_timestamp"]
                )

                time_difference = (
                    alert_time - last_event_time
                ).total_seconds()

                if 0 <= time_difference <= time_window_seconds:
                    matching_incident = incident
                    break

        if matching_incident:
            matching_incident["alerts"].append(alert)
            matching_incident["last_timestamp"] = alert["timestamp"]

        else:
            incidents.append({
                "incident_id": f"INC-{len(incidents) + 1:04d}",
                "user": alert["user"],
                "ip": alert["ip"],
                "first_timestamp": alert["timestamp"],
                "last_timestamp": alert["timestamp"],
                "alerts": [alert],
            })

    return incidents