# Mini Intrusion Detection System (Mini IDS)

**NETCRAFTZ Internship Project**

## 1. Project Overview

Mini Intrusion Detection System (Mini IDS) is a Python-based network security application designed to analyze network traffic, identify suspicious activities, and manage security alerts.

The application provides a Security Operations Center (SOC)-style dashboard for monitoring network events, investigating alerts, and reviewing security analysis reports.

## 2. Key Features

- **PCAP Analysis:** Upload and analyze network capture files.
- **Packet-Based Detection:** Identify suspicious network activities using detection rules.
- **Flow-Based Detection:** Analyze network communication patterns and suspicious flows.
- **Anomaly Detection:** Identify statistically unusual network behavior.
- **Behavior Detection:** Detect repeated or suspicious connection patterns.
- **Alert Scoring:** Calculate confidence scores for detected alerts.
- **Threat Prioritization:** Organize alerts based on their security importance.
- **Alert Management:** Store and review security alerts.
- **Live Alert Monitoring:** Receive alerts through WebSocket communication.
- **Database Integration:** Persist alerts and analysis history using SQLite.
- **PDF Reports:** Generate security analysis reports.
- **SOC Dashboard:** Visualize security events, traffic statistics, and alert information.

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Scapy | Packet analysis |
| Pandas | Network traffic processing |
| NumPy | Numerical operations |
| Streamlit | SOC dashboard |
| Plotly | Data visualization |
| FastAPI | Backend API |
| WebSocket | Real-time alert communication |
| SQLite | Persistent data storage |
| Pytest | Automated testing |

## 4. Project Architecture

The application follows a modular structure:

- **Frontend:** Streamlit-based security dashboard.
- **Backend:** FastAPI services and WebSocket alert communication.
- **Detection Engine:** Packet, flow, anomaly, and behavior-based detection.
- **Alert Management:** Confidence scoring, prioritization, and storage.
- **Database:** SQLite-based persistent records.
- **Reporting:** Security report generation.

## 5. Installation

Clone or download the project and open its directory.

Create a virtual environment:

```powershell
py -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

## 6. Running the Application

Start the Streamlit dashboard:

```powershell
streamlit run app.py
```

The dashboard will open in your browser.

For the backend API, use:

```powershell
uvicorn backend.api.main:app --reload
```

The backend API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

## 7. Running Tests

Run the automated test suite:

```powershell
python -m pytest tests/ -q
```

The latest recorded validation result was **56 tests passed**.

## 8. Supported Network Analysis

The application supports PCAP-based traffic analysis and includes detection logic for suspicious port scanning, sensitive service traffic, unusual traffic patterns, and repeated connections.

Detection results depend on the available capture data and configured detection thresholds.

## 9. Database

SQLite is used to maintain persistent security information, including alerts and analysis history.

## 10. Project Limitations

- Detection accuracy depends on traffic visibility, configured rules, and available capture data.
- Statistical and rule-based alerts require validation against labeled datasets.
- Live packet capture depends on operating-system support and packet-capture libraries.
- This project is an internship-level security monitoring prototype, not a replacement for a fully managed enterprise IDS/SOC platform.

## 11. Internship Information

**Organization:** NETCRAFTZ  
**Project:** Mini Intrusion Detection System  
**Category:** Network Security / Cybersecurity

---

*Developed as part of an internship project at NETCRAFTZ.*
