from datetime import datetime


def correlate_alerts(
    alerts: list[dict], logs: list[dict], time_window_seconds: int = 600
) -> list[dict]:

    if not alerts:
        return []

    sorted_alerts = sorted(
        alerts, key=lambda alert: datetime.fromisoformat(alert["timestamp"])
    )

    incidents = []

    for alert in sorted_alerts:
        alert_time = datetime.fromisoformat(alert["timestamp"])

        matching_incident = None

        for incident in incidents:
            if incident["user"] == alert["user"] and incident["ip"] == alert["ip"]:
                last_event_time = datetime.fromisoformat(incident["last_timestamp"])

                time_difference = (alert_time - last_event_time).total_seconds()

                if 0 <= time_difference <= time_window_seconds:
                    matching_incident = incident
                    break

        if matching_incident:
            matching_incident["alerts"].append(alert)

            evidence = alert.get("evidence", [alert])
            evidence_times = [
                datetime.fromisoformat(event["timestamp"])
                for event in evidence
                ]

            latest_evidence_time = max(evidence_times)

            matching_incident["last_timestamp"] = max(
                datetime.fromisoformat(matching_incident["last_timestamp"]),
                latest_evidence_time,
            ).isoformat()

        else:
            evidence = alert.get("evidence", [alert])
            evidence_times = [
                datetime.fromisoformat(event["timestamp"]) for event in evidence
            ]

            earliest_time = min(evidence_times)
            latest_time = max(evidence_times)

            incidents.append(
                {
                    "incident_id": f"INC-{len(incidents) + 1:04d}",
                    "user": alert["user"],
                    "ip": alert["ip"],
                    "first_timestamp": earliest_time.isoformat(),
                    "last_timestamp": latest_time.isoformat(),
                    "alerts": [alert],
                    "timeline": [],
                }
            )

    # Attach raw log evidence to each incident
    for incident in incidents:
        first_time = datetime.fromisoformat(incident["first_timestamp"])
        last_time = datetime.fromisoformat(incident["last_timestamp"])

        for log in logs:
            if log["user"] == incident["user"] and log["ip"] == incident["ip"]:
                log_time = datetime.fromisoformat(log["timestamp"])

                if first_time <= log_time <= last_time:
                    incident["timeline"].append(log)

        incident["timeline"].sort(
            key=lambda log: datetime.fromisoformat(log["timestamp"])
        )

    return incidents
