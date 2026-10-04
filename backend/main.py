from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from backend.log_parser import load_logs
from backend.detection_engine import detect_brute_force
from backend.detection_rules import (
    detect_privilege_escalation,
    detect_sensitive_access,
)
from backend.risk_engine import calculate_risk
from backend.correlation_engine import correlate_alerts
from backend.explanation_engine import generate_incident_explanation


app = FastAPI(title="Intrusion Detection Platform")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def analyze_logs():
    log_file = "data/uploaded_logs.csv"

    if not __import__("os").path.exists(log_file):
        log_file = "data/security_logs.csv"

    logs = load_logs(log_file)
    alerts = []

    alerts.extend(detect_brute_force(logs))
    alerts.extend(detect_privilege_escalation(logs))
    alerts.extend(detect_sensitive_access(logs))

    risk = calculate_risk(alerts)

    incidents = correlate_alerts(alerts, logs)

    for incident in incidents:
        incident["explanation"] = generate_incident_explanation(
            incident
        )

    return {
        "logs": logs,
        "alerts": alerts,
        "risk": risk,
        "incidents": incidents,
    }


@app.get("/api/status")
def root():
    return {
        "message": "Intrusion Detection Platform API is running"
    }


@app.get("/api/incidents")
def get_incidents():
    result = analyze_logs()

    return {
        "incidents": result["incidents"]
    }


@app.get("/api/risk")
def get_risk():
    result = analyze_logs()

    return result["risk"]


@app.get("/api/alerts")
def get_alerts():
    result = analyze_logs()

    return {
        "alerts": result["alerts"]
    }


@app.get("/api/logs")
def get_logs():
    result = analyze_logs()

    return {
        "logs": result["logs"]
    }
    
@app.post("/api/upload")
async def upload_logs(file: UploadFile = File(...)):
    contents = await file.read()

    upload_path = "data/uploaded_logs.csv"

    with open(upload_path, "wb") as output_file:
        output_file.write(contents)

    return {
        "message": "Log file uploaded successfully",
        "filename": file.filename,
    }
    
app.mount(
    "/",
    StaticFiles(directory="frontend", html=True),
    name="frontend",
)