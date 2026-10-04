const API_BASE_URL = "http://127.0.0.1:8000";


async function fetchData(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`);

    if (!response.ok) {
        throw new Error(`Failed to fetch ${endpoint}`);
    }

    return response.json();
}


/* -----------------------------
   Risk Overview
----------------------------- */

async function loadRisk() {
    const risk = await fetchData("/api/risk");

    document.getElementById("risk-score").textContent = risk.score;
    document.getElementById("risk-level").textContent = risk.risk_level;
    document.getElementById("alert-count").textContent = risk.alert_count;
}


/* -----------------------------
   Incidents
----------------------------- */

async function loadIncidents() {
    const data = await fetchData("/api/incidents");

    const container = document.getElementById("incidents-container");

    container.innerHTML = "";

    if (data.incidents.length === 0) {
        container.textContent = "No security incidents detected.";
        return;
    }

    data.incidents.forEach((incident) => {
        const incidentElement = document.createElement("div");

        incidentElement.className = "incident";

        incidentElement.innerHTML = `
            <div class="incident-header">
                <div class="incident-id">
                    ${incident.incident_id}
                </div>

                <div class="badge badge-critical">
                    CRITICAL
                </div>
            </div>

            <div class="incident-info">
                User: ${incident.user}
                &nbsp; | &nbsp;
                IP: ${incident.ip}
                &nbsp; | &nbsp;
                Alerts: ${incident.alerts.length}
            </div>

            <div class="incident-explanation">
                <strong>Attack Explanation</strong>
                <p>${incident.explanation}</p>
            </div>

            <div class="timeline">
                ${incident.timeline.map((event) => `
                    <div class="timeline-item">

                        <div class="timeline-time">
                            ${event.timestamp}
                        </div>

                        <div class="timeline-event">
                            ${event.event_type}
                        </div>

                        <div class="timeline-details">
                            Status: ${event.status}
                            ${event.resource
                                ? ` | Resource: ${event.resource}`
                                : ""}
                        </div>

                    </div>
                `).join("")}
            </div>
        `;

        container.appendChild(incidentElement);
    });

    document.getElementById("incident-count").textContent =
        data.incidents.length;
}


/* -----------------------------
   Raw Logs
----------------------------- */

async function loadLogs() {
    const data = await fetchData("/api/logs");

    const container = document.getElementById("logs-container");

    container.innerHTML = "";

    data.logs.forEach((log) => {
        const row = document.createElement("div");

        row.className = "log-row";

        const statusClass =
            log.status === "FAILED"
                ? "log-failed"
                : "log-success";

        row.innerHTML = `
            <span>${log.timestamp}</span>
            <span>${log.user}</span>
            <span>${log.ip}</span>
            <span class="${statusClass}">
                ${log.status}
            </span>
            <span>${log.event_type}</span>
        `;

        container.appendChild(row);
    });
}


/* -----------------------------
   Start Dashboard
----------------------------- */

async function initializeDashboard() {
    try {
        await loadRisk();
        await loadIncidents();
        await loadLogs();
    } catch (error) {
        console.error("Dashboard error:", error);

        document.getElementById("incidents-container").textContent =
            "Unable to connect to backend API.";
    }
}


initializeDashboard();