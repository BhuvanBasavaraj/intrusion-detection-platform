import csv
from pathlib import Path


def load_logs(file_path: str) -> list[dict]:
    path = Path(file_path)

    with path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        logs = []

        for row in reader:
            logs.append({
                "timestamp": row["timestamp"],
                "user": row["user"],
                "ip": row["ip"],
                "event_type": row["event_type"],
                "status": row["status"],
                "resource": row["resource"] or None,
            })

    return logs