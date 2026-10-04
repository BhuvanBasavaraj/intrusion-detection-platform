# intrusion-detection-platform
Security log analysis and incident correlation platform for detecting and investigating suspicious activity.
# Find the Intruder — Intrusion Detection Platform

A web-based security log analysis platform that detects suspicious authentication and system activity, correlates related events into incidents, calculates risk, and reconstructs a probable attack timeline.

## Problem

Security logs often contain many individual events. A suspicious attack may only become obvious when multiple events are connected.

This project analyzes security logs to identify suspicious activity such as:

- Brute-force login attempts
- Privilege escalation
- Access to sensitive resources

It then correlates related alerts and presents them as an explainable security incident.

## Key Features

### Log Ingestion
- CSV security log ingestion
- Upload custom CSV log files through the web dashboard
- Built-in sample dataset for demonstration

### Detection Engine
Rule-based detection for:

- Brute-force authentication
- Privilege escalation
- Sensitive resource access

### Risk Scoring

Security alerts are assigned severity-based points:

- LOW = 10
- MEDIUM = 20
- HIGH = 30
- CRITICAL = 40

The total score is capped at 100 and mapped to a risk level.

### Incident Correlation

Related alerts are grouped using:

- Same user
- Same IP address
- Time proximity

This converts multiple isolated alerts into a single security incident.

### Evidence Timeline

Each incident contains the relevant raw log events, allowing investigators to trace what happened.

### Attack Explanation

The platform generates a human-readable explanation describing the detected attack sequence.

### Attack Stages

Timeline events are classified into stages such as:

- Initial Access Attempt
- Initial Access
- Privilege Escalation
- Data Access

## Architecture

```text
                Security Log CSV
                       |
                       v
                +--------------+
                |  Log Parser  |
                +--------------+
                       |
                       v
                +--------------+
                | Detection    |
                | Engine       |
                +--------------+
                       |
              +--------+--------+
              |        |        |
              v        v        v
          Brute     Privilege  Sensitive
          Force     Escalation  Access
              \        |        /
               \       |       /
                v      v      v
                +-------------+
                | Risk Engine |
                +-------------+
                       |
                       v
                +-------------+
                | Correlation |
                | Engine      |
                +-------------+
                       |
                       v
                +-------------+
                | Incident &  |
                | Timeline    |
                +-------------+
                       |
                       v
                +-------------+
                | FastAPI     |
                | Backend     |
                +-------------+
                       |
                       v
                +-------------+
                | Web         |
                | Dashboard   |
                +-------------+