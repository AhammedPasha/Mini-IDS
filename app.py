import plotly.graph_objects as go
import hashlib
import tempfile
import asyncio
from pathlib import Path
from collections import Counter
from html import escape
from io import BytesIO
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from ids.live_alert_client import start_listener, drain_events
from backend.api.alert_service import save_and_broadcast_alerts

from ids.packet_analyzer import analyze_pcap, summarize_traffic
from ids.detection_engine import detect_suspicious_traffic
from ids.flow_analyzer import analyze_flows
from ids.flow_detection import detect_suspicious_flows
from ids.anomaly_detector import detect_statistical_anomalies
from ids.behavior_detector import detect_repeated_connections
from ids.alert_scoring import calculate_alert_confidence
from ids.threat_prioritizer import prioritize_alerts

from ids.database import (
    initialize_database,
    create_analysis_run,
    get_alert_history,
    get_analysis_history,
    create_incident,
    get_incidents,
    update_incident,
    assign_incident,
    add_incident_note,
    get_incident_notes,
    delete_alert,
    clear_alert_history,
    delete_analysis_run,
    clear_analysis_history,
    delete_incident,
    clear_incidents,
)



# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="MINI IDS | SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

initialize_database()



# ==========================================
# ADVANCED CYBER SOC THEME
# ==========================================

st.markdown("""
<style>

/* GLOBAL ENVIRONMENT */
.stApp {
    background:
        radial-gradient(ellipse at 15% 10%, #10263b 0%, transparent 38%),
        radial-gradient(ellipse at 85% 85%, #17102c 0%, transparent 35%),
        #050914;
    color: #e2e8f0;
}

.block-container {
    max-width: 1800px;
    padding-top: 1.2rem;
    padding-bottom: 3rem;
}

/* SIDEBAR */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #07111f, #0a1728, #080d19);
    border-right: 1px solid rgba(34, 211, 238, 0.25);
}

[data-testid="stSidebar"] > div:first-child {
    background: transparent;
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: #22d3ee !important;
    letter-spacing: 1px;
}

[data-testid="stSidebar"] label {
    color: #cbd5e1 !important;
}

/* HEADINGS */
h1, h2, h3, h4 {
    color: #e5f3ff !important;
    font-weight: 800 !important;
    letter-spacing: 0.5px;
}

h1 {
    text-shadow: 0 0 18px rgba(34, 211, 238, 0.2);
}

p, label, span {
    color: inherit;
}

/* SOC HEADER */
.soc-header {
    position: relative;
    overflow: hidden;
    background:
        linear-gradient(110deg, rgba(8, 25, 45, 0.98),
        rgba(12, 39, 62, 0.92), rgba(12, 15, 35, 0.98));
    border: 1px solid rgba(34, 211, 238, 0.5);
    border-radius: 16px;
    padding: 26px;
    margin-bottom: 24px;
    box-shadow:
        0 0 25px rgba(6, 182, 212, 0.12),
        inset 0 0 25px rgba(34, 211, 238, 0.04);
}

.soc-label {
    color: #22d3ee;
    font-size: 11px;
    letter-spacing: 4px;
    font-weight: 900;
}

.soc-subtitle {
    color: #94a3b8;
    font-size: 14px;
}

/* METRIC PANELS */
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #101e32, #0a1424);
    border: 1px solid rgba(34, 211, 238, 0.25);
    border-radius: 13px;
    padding: 17px;
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.22);
    transition: all 0.2s ease;
}

[data-testid="stMetric"]:hover {
    border-color: #22d3ee;
    box-shadow: 0 0 18px rgba(34, 211, 238, 0.16);
    transform: translateY(-2px);
}

[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
    font-size: 12px !important;
    font-weight: 700 !important;
}

[data-testid="stMetricValue"] {
    color: #22d3ee !important;
    font-weight: 900 !important;
}

/* CUSTOM METRIC CARDS */
.metric-card {
    background: linear-gradient(145deg, #111f33, #091321);
    border: 1px solid rgba(34, 211, 238, 0.28);
    border-radius: 13px;
    padding: 18px;
    min-height: 110px;
    box-shadow: 0 5px 18px rgba(0, 0, 0, 0.2);
}

/* BUTTONS */
.stButton > button,
.stDownloadButton > button {
    background: linear-gradient(100deg, #075985, #0e7490);
    color: #ffffff;
    border: 1px solid #22d3ee;
    border-radius: 9px;
    font-weight: 750;
    transition: all 0.2s ease;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: linear-gradient(100deg, #0e7490, #0891b2);
    color: white;
    border-color: #67e8f9;
    box-shadow: 0 0 16px rgba(34, 211, 238, 0.25);
}

/* INPUTS */
.stTextInput input,
.stTextArea textarea,
.stSelectbox div[data-baseweb="select"],
.stMultiSelect div[data-baseweb="select"] {
    background-color: #0c192b;
    color: #e2e8f0;
    border-color: #164e63;
    border-radius: 8px;
}

/* FILE UPLOAD */
[data-testid="stFileUploader"] {
    background: #0c192b;
    border: 1px dashed #0891b2;
    border-radius: 12px;
    padding: 12px;
}

/* TABLES */
[data-testid="stDataFrame"] {
    border: 1px solid rgba(34, 211, 238, 0.24);
    border-radius: 10px;
    overflow: hidden;
}

/* CHART CONTAINERS */
[data-testid="stPlotlyChart"] {
    background: rgba(10, 20, 36, 0.55);
    border: 1px solid rgba(34, 211, 238, 0.18);
    border-radius: 13px;
    padding: 8px;
}

/* EXPANDERS */
[data-testid="stExpander"] {
    background: rgba(12, 25, 43, 0.8);
    border: 1px solid rgba(34, 211, 238, 0.2);
    border-radius: 10px;
}

/* STATUS AND NOTIFICATIONS */
[data-testid="stAlert"] {
    border-radius: 10px;
}

/* DIVIDERS */
hr {
    border-color: rgba(34, 211, 238, 0.2) !important;
}

/* CAPTIONS */
[data-testid="stCaptionContainer"] {
    color: #8295ad;
}

/* SCROLLBAR */
::-webkit-scrollbar {
    width: 7px;
    height: 7px;
}

::-webkit-scrollbar-track {
    background: #070d18;
}

::-webkit-scrollbar-thumb {
    background: #155e75;
    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background: #22d3ee;
}


/* =========================================
   PREMIUM 3D SOC SIDEBAR NAVIGATION
========================================= */

@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,500,0,0');

[data-testid="stSidebar"] {
    background:
        radial-gradient(circle at 20% 5%, rgba(8,145,178,0.16), transparent 35%),
        linear-gradient(155deg, #0b1628, #080e1b 55%, #050914) !important;
    border-right: 1px solid rgba(34,211,238,0.35);
    box-shadow: 8px 0 30px rgba(0,0,0,0.45);
}

[data-testid="stSidebar"] [data-testid="stRadio"] > div[role="radiogroup"] {
    gap: 11px;
    padding: 8px 3px;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label {
    min-height: 52px;
    padding: 13px 15px;
    margin: 3px 0;
    border: 1px solid rgba(71,85,105,0.22);
    border-radius: 11px;
    background: linear-gradient(145deg, #14243a, #0a1424);
    box-shadow:
        5px 5px 10px rgba(0,0,0,0.35),
        inset 1px 1px 2px rgba(255,255,255,0.035);
    transition: all 0.22s ease;
    cursor: pointer;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
    transform: translateX(4px);
    border-color: rgba(34,211,238,0.65);
    background: linear-gradient(110deg, #12304a, #102238);
    box-shadow: 0 0 15px rgba(34,211,238,0.12);
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
    background: linear-gradient(110deg, #075985, #10324b, #102238);
    border: 1px solid #22d3ee;
    box-shadow:
        0 0 17px rgba(34,211,238,0.23),
        inset 0 1px 3px rgba(255,255,255,0.12),
        4px 5px 12px rgba(0,0,0,0.35);
    transform: translateX(4px);
}

[data-testid="stSidebar"] [data-testid="stRadio"] label p {
    color: #cbd5e1 !important;
    font-size: 13px;
    font-weight: 650;
    letter-spacing: 0.3px;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) p {
    color: #ffffff !important;
    font-weight: 800;
}

[data-testid="stSidebar"] [data-testid="stRadio"] input[type="radio"] {
    accent-color: #22d3ee;
}

[data-testid="stSidebar"] hr {
    border-color: rgba(34,211,238,0.2) !important;
}



/* SIDEBAR SYSTEM STATUS */

[data-testid="stSidebar"] [data-testid="stAlert"] {
    border-radius: 10px;
    border: 1px solid rgba(34, 211, 238, 0.25);
    background: rgba(8, 30, 47, 0.65);
    padding: 10px;
}

[data-testid="stSidebar"] [data-testid="stAlert"] p {
    font-size: 12px;
    font-weight: 700;
}


/* PREMIUM CAPTURE INPUT AREA */

[data-testid="stSidebar"] [data-testid="stFileUploader"] {
    background: rgba(8, 30, 47, 0.65);
    border: 1px solid rgba(34, 211, 238, 0.3);
    border-radius: 12px;
    padding: 10px;
}

[data-testid="stSidebar"] [data-testid="stFileUploader"] section {
    border: 1px dashed rgba(34, 211, 238, 0.5);
    border-radius: 9px;
    background: rgba(8, 20, 35, 0.7);
}

[data-testid="stSidebar"] [data-testid="stSlider"] {
    padding: 10px;
    border: 1px solid rgba(34, 211, 238, 0.2);
    border-radius: 10px;
    background: rgba(8, 30, 47, 0.45);
}


/* PREMIUM MINI IDS BRAND */

.ids-brand {
    text-align: center;
    padding: 22px 5px 20px;
    margin-bottom: 8px;
}

.ids-logo-frame {
    position: relative;
    width: 78px;
    height: 78px;
    margin: 0 auto 13px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 22px;
    background: linear-gradient(145deg, #173b56, #091526);
    border: 1px solid rgba(34,211,238,0.7);
    box-shadow:
        0 9px 20px rgba(0,0,0,0.45),
        0 0 22px rgba(34,211,238,0.2),
        inset 0 2px 5px rgba(255,255,255,0.12);
    transform: perspective(300px) rotateX(5deg);
}

.ids-logo-core {
    position: absolute;
    font-size: 67px;
    color: rgba(34,211,238,0.25);
    text-shadow: 0 0 16px #06b6d4;
}

.ids-logo-shield {
    position: relative;
    font-size: 35px;
    filter: drop-shadow(0 0 8px rgba(34,211,238,0.8));
}

.ids-brand-name {
    color: #f1f5f9;
    font-size: 25px;
    font-weight: 950;
    letter-spacing: 3px;
}

.ids-brand-name span {
    color: #22d3ee;
    text-shadow: 0 0 12px rgba(34,211,238,0.4);
}

.ids-brand-subtitle {
    margin-top: 5px;
    color: #8da6bd;
    font-size: 9px;
    letter-spacing: 2.3px;
    font-weight: 800;
}

.ids-brand-version {
    margin: 13px auto 0;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 6px 10px;
    border: 1px solid rgba(34,211,238,0.22);
    border-radius: 20px;
    color: #9fb7c9;
    background: rgba(8,30,47,0.7);
    font-size: 8px;
    letter-spacing: 1px;
}

.ids-online-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #22c55e;
    box-shadow: 0 0 9px #22c55e;
}

/* PROFESSIONAL SOC NAVIGATION ICONS */

.soc-nav-icon {
    height: 43px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #22d3ee;
    background: linear-gradient(145deg, #142b43, #091525);
    border: 1px solid rgba(34, 211, 238, 0.25);
    border-radius: 10px;
    box-shadow:
        3px 3px 7px rgba(0,0,0,0.4),
        inset 1px 1px 2px rgba(255,255,255,0.08);
}

.soc-nav-icon .material-symbols-rounded {
    font-size: 22px;
}

[data-testid="stSidebar"] [data-testid="stButton"] button {
    min-height: 43px;
    text-align: left;
    border-radius: 10px;
    background: linear-gradient(145deg, #14243a, #0a1424);
    border: 1px solid rgba(71,85,105,0.3);
    color: #cbd5e1;
    font-weight: 650;
    transition: all 0.2s ease;
}

[data-testid="stSidebar"] [data-testid="stButton"] button:hover {
    border-color: #22d3ee;
    color: #ffffff;
    background: linear-gradient(110deg, #123b56, #102238);
    transform: translateX(3px);
    box-shadow: 0 0 13px rgba(34,211,238,0.18);
}

</style>
""", unsafe_allow_html=True)



# ==========================================
# SIDEBAR NAVIGATION
# ==========================================

with st.sidebar:

    
    # MINI IDS BRANDING
    st.markdown(
        """
        <div style="text-align:center; padding:18px 5px;">
            <div style="font-size:42px;">🛡️</div>
            <div style="font-size:27px; font-weight:800; color:#22d3ee;">
                MINI IDS
            </div>
            <div style="font-size:10px; letter-spacing:2px; color:#94a3b8;">
                SECURITY OPERATIONS CENTER
            </div>
            <div style="font-size:10px; margin-top:12px; color:#22c55e;">
                ● THREAT DEFENSE PLATFORM
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.divider()


    # NAVIGATION
    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Live Monitor",
            "PCAP Analysis",
            "Alert Center",
            "Investigation",
            "Analytics",
            "Reports",
            "History",
        ],
        key="soc_navigation_radio",
        label_visibility="collapsed",
    )

    selected_page = page

    st.divider()

    # SYSTEM STATUS
    st.markdown("### SYSTEM STATUS")

    backend_status = st.session_state.get(
        "live_ws_status", "connecting"
    )

    if backend_status == "connected":
        st.success("Backend Connected")
    else:
        st.warning(
            "Backend " + str(backend_status).title()
        )

    st.caption("MINI IDS | Network Security Platform")
    st.caption("Version 1.0")



# ==========================================
# SOC HEADER
# ==========================================

st.markdown("""
<div class="soc-header">
    <div class="soc-label">
        MINI IDS / SECURITY OPERATIONS CENTER
    </div>
    <h1 style="border:0;margin:10px 0;">
        CYBER THREAT MONITORING
    </h1>
    <p class="soc-subtitle">
        Network intelligence • Intrusion detection •
        Threat investigation • Security analytics
    </p>
</div>
""", unsafe_allow_html=True)


# ==========================================
# WEBSOCKET LISTENER
# ==========================================

if "live_ws_events" not in st.session_state:

    events, stop_event, thread = start_listener()

    st.session_state["live_ws_events"] = events
    st.session_state["live_ws_stop_event"] = stop_event
    st.session_state["live_ws_thread"] = thread
    st.session_state["live_ws_status"] = "connecting"
    st.session_state["live_ws_error"] = ""
    st.session_state["live_alerts"] = []


# ==========================================
# LIVE ALERT MONITOR
# ==========================================

@st.fragment(run_every="2s")
def render_live_alert_monitor():

    incoming_events = drain_events(
        st.session_state["live_ws_events"]
    )

    for event in incoming_events:

        if event.get("type") == "connection_status":

            st.session_state["live_ws_status"] = event.get(
                "status", "disconnected"
            )

            st.session_state["live_ws_error"] = event.get(
                "error", ""
            )

        elif event.get("type") == "security_alert":

            alert = event.get("alert", {})

            live_record = {
                "timestamp": event.get("timestamp", ""),
                "rule_id": alert.get("rule_id", "Unknown"),
                "severity": str(
                    alert.get("severity", "unknown")
                ).upper(),
                "source_ip": alert.get("source_ip", "Unknown"),
                "destination_ip": alert.get(
                    "destination_ip", "Unknown"
                ),
                "evidence": alert.get("evidence", ""),
            }

            st.session_state["live_alerts"].insert(
                0, live_record
            )

            st.session_state["live_alerts"] = (
                st.session_state["live_alerts"][:100]
            )

    status = st.session_state["live_ws_status"]

    if status == "connected":
        st.success("WebSocket connected — receiving live alerts")
    else:
        st.warning(
            f"WebSocket {status} — reconnecting automatically"
        )

        if st.session_state["live_ws_error"]:
            st.caption(st.session_state["live_ws_error"])

    alerts = st.session_state["live_alerts"]

    severity_counts = {
        severity: sum(
            1 for alert in alerts
            if alert["severity"] == severity
        )
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }

    st.caption("LIVE SECURITY EVENT STATISTICS")

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Total Alerts", len(alerts))
    c2.metric("Critical", severity_counts["CRITICAL"])
    c3.metric("High", severity_counts["HIGH"])
    c4.metric("Medium", severity_counts["MEDIUM"])
    c5.metric("Low", severity_counts["LOW"])

    st.divider()

    f1, f2 = st.columns([1, 2])

    with f1:
        selected_severities = st.multiselect(
            "Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="live_severity_filter",
        )

    with f2:
        search_text = st.text_input(
            "Search alerts",
            placeholder="Search IP, rule or evidence",
            key="live_alert_search",
        )

    filtered_alerts = [
        alert for alert in alerts
        if alert["severity"] in selected_severities
        and search_text.lower() in " ".join(
            str(alert.get(field, ""))
            for field in [
                "rule_id",
                "source_ip",
                "destination_ip",
                "evidence",
            ]
        ).lower()
    ]

    st.caption(
        f"Showing {len(filtered_alerts)} of {len(alerts)} live alerts"
    )

    if st.button("Clear Live Alert Feed", key="clear_live_alerts"):
        st.session_state["live_alerts"] = []
        st.rerun(scope="fragment")

    if filtered_alerts:

        display_df = pd.DataFrame([
            {
                "Timestamp": a["timestamp"],
                "Rule ID": a["rule_id"],
                "Severity": a["severity"],
                "Source IP": a["source_ip"],
                "Destination IP": a["destination_ip"],
            }
            for a in filtered_alerts[:20]
        ])

        def severity_style(value):
            styles = {
                "CRITICAL": "background-color:#7f1d1d;color:white;",
                "HIGH": "background-color:#991b1b;color:white;",
                "MEDIUM": "background-color:#92400e;color:white;",
                "LOW": "background-color:#166534;color:white;",
            }
            return styles.get(value, "")

        st.dataframe(
            display_df.style.map(
                severity_style,
                subset=["Severity"],
            ),
            use_container_width=True,
            hide_index=True,
        )

        for alert in filtered_alerts[:20]:

            with st.expander(
                f"{alert['severity']} | "
                f"{alert['rule_id']} | {alert['source_ip']}"
            ):

                st.write("**Timestamp:**", alert["timestamp"])
                st.write("**Source IP:**", alert["source_ip"])
                st.write(
                    "**Destination IP:**",
                    alert["destination_ip"],
                )
                st.write("**Evidence:**", alert["evidence"])

    else:
        st.info("No alerts match the selected filters.")


# ==========================================
# SHARED SESSION DATA
# ==========================================

if "analysis_key" not in st.session_state:
    st.session_state["analysis_key"] = None

if "analysis_id" not in st.session_state:
    st.session_state["analysis_id"] = None

if "saved_count" not in st.session_state:
    st.session_state["saved_count"] = 0

if "flow_save_key" not in st.session_state:
    st.session_state["flow_save_key"] = None

if "flow_saved_count" not in st.session_state:
    st.session_state["flow_saved_count"] = 0



# ============================================================
# PART 2 — SHARED PCAP ANALYSIS ENGINE
# ============================================================

try:
    from ids.database import create_analysis_run
except ImportError:
    create_analysis_run = None


# PCAP INPUT IN SIDEBAR
st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    <div style="
        color:#22d3ee;
        font-size:14px;
        font-weight:800;
        letter-spacing:1.5px;
        padding:10px 0;
        border-bottom:1px solid rgba(34,211,238,0.25);
        margin-bottom:12px;
    ">
        📡 CAPTURE INPUT
    </div>
    """,
    unsafe_allow_html=True
)

uploaded_file = st.sidebar.file_uploader(
    "Upload Network Capture",
    type=["pcap", "pcapng", "cap"],
    key="redesign_pcap_uploader"
)

port_threshold = st.sidebar.slider(
    "Port Scan Threshold",
    min_value=2,
    max_value=50,
    value=10,
    key="redesign_port_threshold"
)

st.sidebar.caption("Upload a capture to activate packet and flow analysis.")


# DEFAULT SHARED ANALYSIS DATA
if "ids_traffic" not in st.session_state:
    st.session_state["ids_traffic"] = pd.DataFrame()

if "ids_summary" not in st.session_state:
    st.session_state["ids_summary"] = {}

if "ids_alerts" not in st.session_state:
    st.session_state["ids_alerts"] = []

if "ids_flows" not in st.session_state:
    st.session_state["ids_flows"] = pd.DataFrame()

if "ids_flow_alerts" not in st.session_state:
    st.session_state["ids_flow_alerts"] = []

if "ids_capture_name" not in st.session_state:
    st.session_state["ids_capture_name"] = "No capture uploaded"

if "ids_analysis_error" not in st.session_state:
    st.session_state["ids_analysis_error"] = ""

if "ids_capture_hash" not in st.session_state:
    st.session_state["ids_capture_hash"] = ""


# PROCESS A NEW CAPTURE ONLY ONCE
if uploaded_file is not None:

    uploaded_bytes = uploaded_file.getvalue()

    capture_hash = hashlib.sha256(
        uploaded_bytes
    ).hexdigest()

    analysis_key = (
        uploaded_file.name,
        capture_hash,
        port_threshold
    )

    if st.session_state.get("analysis_key") != analysis_key:

        temp_path = None

        try:
            suffix = Path(uploaded_file.name).suffix.lower()

            with tempfile.NamedTemporaryFile(
                suffix=suffix,
                delete=False
            ) as temp_file:

                temp_file.write(uploaded_bytes)
                temp_path = temp_file.name

            with st.spinner("Analyzing network traffic and detecting threats..."):

                # PACKET ANALYSIS
                traffic = analyze_pcap(temp_path)

                if traffic.empty:
                    raise ValueError(
                        "The uploaded capture contains no readable packets."
                    )

                summary = summarize_traffic(traffic)

                # PACKET-BASED DETECTION
                alerts = detect_suspicious_traffic(
                    traffic,
                    port_scan_threshold=port_threshold
                )

                alerts = [
                    calculate_alert_confidence(alert)
                    for alert in alerts
                ]

                alerts = prioritize_alerts(alerts)
                for alert in alerts:
                    alert.setdefault("detection_source", "PACKET")

                # CREATE ANALYSIS RECORD
                try:
                    if create_analysis_run is None:
                        raise RuntimeError(
                            "create_analysis_run is not available in ids.database"
                        )
                    analysis_id = create_analysis_run(
                        capture_name=uploaded_file.name,
                        capture_hash=capture_hash,
                        threshold=port_threshold
                    )
                except Exception as db_exc:
                    analysis_id = f"LOCAL-{capture_hash[:12]}"
                    st.warning(
                        "Analysis was processed, but the analysis-run "
                        f"record could not be created: {db_exc}"
                    )

                # FLOW ANALYSIS
                flows = analyze_flows(traffic)

                flow_alerts = detect_suspicious_flows(flows)

                anomaly_alerts = detect_statistical_anomalies(flows)
                behavior_alerts = detect_repeated_connections(flows)

                flow_alerts.extend(anomaly_alerts)
                flow_alerts.extend(behavior_alerts)

                flow_alerts = [
                    calculate_alert_confidence(alert)
                    for alert in flow_alerts
                ]

                flow_alerts = prioritize_alerts(flow_alerts)
                for alert in flow_alerts:
                    alert.setdefault("detection_source", "FLOW")

                # SAVE AND BROADCAST PACKET ALERTS
                saved_count = 0
                flow_saved_count = 0

                if alerts:
                    try:
                        saved_count = asyncio.run(
                            save_and_broadcast_alerts(
                                alerts=alerts,
                                capture_name=uploaded_file.name,
                                analysis_id=analysis_id,
                                detection_source="packet"
                            )
                        )
                    except Exception as publish_exc:
                        st.warning(
                            "Packet alerts were detected locally, but "
                            f"could not be saved/broadcast: {publish_exc}"
                        )

                # SAVE AND BROADCAST FLOW ALERTS
                if flow_alerts:
                    try:
                        flow_saved_count = asyncio.run(
                            save_and_broadcast_alerts(
                                alerts=flow_alerts,
                                capture_name=uploaded_file.name,
                                analysis_id=analysis_id,
                                detection_source="flow"
                            )
                        )
                    except Exception as publish_exc:
                        st.warning(
                            "Flow alerts were detected locally, but "
                            f"could not be saved/broadcast: {publish_exc}"
                        )

                # STORE SHARED RESULTS
                st.session_state["ids_traffic"] = traffic
                st.session_state["ids_summary"] = summary
                st.session_state["ids_alerts"] = alerts
                st.session_state["ids_flows"] = flows
                st.session_state["ids_flow_alerts"] = flow_alerts

                st.session_state["ids_capture_name"] = uploaded_file.name
                st.session_state["ids_analysis_error"] = ""

                st.session_state["analysis_key"] = analysis_key
                st.session_state["analysis_id"] = analysis_id
                st.session_state["saved_count"] = saved_count

                st.session_state["flow_save_key"] = (
                    analysis_id,
                    "flow_alerts"
                )
                st.session_state["flow_saved_count"] = flow_saved_count

                st.session_state["ids_capture_hash"] = capture_hash

        except Exception as exc:

            st.session_state["ids_analysis_error"] = str(exc)

            st.error(
                f"Could not analyze this capture: {exc}"
            )

        finally:

            if temp_path and Path(temp_path).exists():
                Path(temp_path).unlink(missing_ok=True)

else:
    # Clear previous capture data when the uploader is cleared.
    st.session_state["ids_traffic"] = pd.DataFrame()
    st.session_state["ids_summary"] = {}
    st.session_state["ids_alerts"] = []
    st.session_state["ids_flows"] = pd.DataFrame()
    st.session_state["ids_flow_alerts"] = []
    st.session_state["ids_capture_name"] = "No capture uploaded"
    st.session_state["analysis_key"] = None
    st.session_state["analysis_id"] = None
    st.session_state["saved_count"] = 0
    st.session_state["flow_save_key"] = None
    st.session_state["flow_saved_count"] = 0


# SHARED VARIABLES FOR ALL DASHBOARD PAGES
traffic = st.session_state["ids_traffic"]
summary = st.session_state["ids_summary"]

alerts = st.session_state["ids_alerts"]
flows = st.session_state["ids_flows"]
flow_alerts = st.session_state["ids_flow_alerts"]

soc_alerts = alerts + flow_alerts

capture_name = st.session_state["ids_capture_name"]

analysis_id = st.session_state.get("analysis_id", "Unknown")

packet_alert_count = len(alerts)
flow_alert_count = len(flow_alerts)
total_alert_count = len(soc_alerts)

# SEVERITY COUNTS
severity_counts = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
}

for alert in soc_alerts:

    severity = str(
        alert.get("severity", "LOW")
    ).upper()

    if severity in severity_counts:
        severity_counts[severity] += 1


# COMMON PAGE STATUS
has_capture = not traffic.empty

# ============================================================
# PART 3 — SOC DASHBOARD PAGES
# ============================================================

# COMMON HELPERS

def get_column(dataframe, candidates):
    for column in candidates:
        if column in dataframe.columns:
            return column
    return None


def get_severity_counts(records):
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for record in records:
        severity = str(record.get("severity", "LOW")).upper()
        if severity in counts:
            counts[severity] += 1

    return counts


def show_alert_table(records, key):
    if not records:
        st.info("No security alerts available.")
        return

    display_records = []

    for alert in records:
        display_records.append({
            "Detection Source": alert.get("detection_source", "IDS").upper(),
            "Rule ID": alert.get("rule_id", alert.get("rule", "UNKNOWN")),
            "Severity": str(alert.get("severity", "LOW")).upper(),
            "Source IP": alert.get("source_ip", "Unknown"),
            "Destination IP": alert.get("destination_ip", "Unknown"),
            "Confidence": (
    f"{alert.get('confidence_score')}% "
    f"({str(alert.get('confidence_level', 'N/A')).upper()})"
    if alert.get("confidence_score") is not None
    else "N/A"
),
            "Priority": alert.get("priority", "N/A"),
            "Evidence": alert.get("evidence", "No evidence available")
        })

    st.dataframe(
        pd.DataFrame(display_records),
        use_container_width=True,
        hide_index=True,
        key=key
    )


def show_severity_cards(records):
    counts = get_severity_counts(records)

    columns = st.columns(4)

    colors = {
        "CRITICAL": "#ff334f",
        "HIGH": "#ff8a3d",
        "MEDIUM": "#facc15",
        "LOW": "#22c55e"
    }

    for index, severity in enumerate(counts):
        with columns[index]:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div style="color:#94a3b8;font-size:12px;">
                        {severity} ALERTS
                    </div>
                    <div style="font-size:30px;font-weight:800;
                                color:{colors[severity]};">
                        {counts[severity]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )


def show_no_capture():
    st.info(
        "Upload a PCAP file using the Capture Input section "
        "in the sidebar to view network analysis."
    )



# ============================================================
# DASHBOARD PAGE
# ============================================================

if selected_page == "Dashboard":

    st.markdown("## 🛡️ SOC COMMAND CENTER")
    st.caption("Centralized network visibility • Threat detection • Security operations")

    # --------------------------------------------------------
    # DATA PREPARATION
    # --------------------------------------------------------

    total_packets = len(traffic) if traffic is not None else 0
    total_flows = len(flows) if flows is not None else 0
    total_alerts = len(soc_alerts) if soc_alerts else 0

    critical_count = sum(
        1 for a in (soc_alerts or [])
        if str(a.get("severity", "")).upper() == "CRITICAL"
    )
    high_count = sum(
        1 for a in (soc_alerts or [])
        if str(a.get("severity", "")).upper() == "HIGH"
    )
    medium_count = sum(
        1 for a in (soc_alerts or [])
        if str(a.get("severity", "")).upper() == "MEDIUM"
    )
    low_count = sum(
        1 for a in (soc_alerts or [])
        if str(a.get("severity", "")).upper() == "LOW"
    )

    source_col = next(
        (c for c in ["source_ip", "src_ip", "Source IP"] if traffic is not None and c in traffic.columns),
        None
    )
    destination_col = next(
        (c for c in ["destination_ip", "dst_ip", "Destination IP"] if traffic is not None and c in traffic.columns),
        None
    )
    protocol_col = next(
        (c for c in ["protocol", "Protocol"] if traffic is not None and c in traffic.columns),
        None
    )

    unique_sources = (
        int(traffic[source_col].nunique())
        if source_col and not traffic.empty else 0
    )
    unique_destinations = (
        int(traffic[destination_col].nunique())
        if destination_col and not traffic.empty else 0
    )

    # --------------------------------------------------------
    # SYSTEM STATUS
    # --------------------------------------------------------

    backend_status = str(
        st.session_state.get("live_ws_status", "Not connected")
    )

    status_color = (
        "🟢" if "connected" in backend_status.lower()
        else "🟠"
    )

    st.markdown(
        f"""
        <div style="
            background:linear-gradient(110deg,#101c30,#10283a,#101827);
            border:1px solid #164e63;
            border-left:4px solid #06b6d4;
            padding:15px 20px;
            border-radius:10px;
            margin-bottom:18px;">
            <div style="font-size:12px;color:#94a3b8;letter-spacing:2px;">
                SECURITY OPERATIONS STATUS
            </div>
            <div style="font-size:17px;color:#e2e8f0;font-weight:700;margin-top:5px;">
                {status_color} Backend: {escape(backend_status)}
                &nbsp;&nbsp; | &nbsp;&nbsp;
                Capture: {"🟢 ANALYZED" if has_capture else "🟠 WAITING FOR PCAP"}
            </div>
            <div style="font-size:11px;color:#64748b;margin-top:6px;">
                Analysis ID: {escape(str(analysis_id))}
                &nbsp; | &nbsp;
                Capture: {escape(str(capture_name))}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # --------------------------------------------------------
    # TOP SECURITY METRICS
    # --------------------------------------------------------

    st.markdown("### ◈ NETWORK SECURITY OVERVIEW")

    m1, m2, m3, m4, m5 = st.columns(5)

    m1.metric("Packets Inspected", f"{total_packets:,}")
    m2.metric("Network Flows", f"{total_flows:,}")
    m3.metric("Total Alerts", f"{total_alerts:,}")
    m4.metric("Critical Threats", f"{critical_count:,}")
    m5.metric("High Threats", f"{high_count:,}")

    st.markdown("---")

    # --------------------------------------------------------
    # THREAT DISTRIBUTION
    # --------------------------------------------------------

    left, right = st.columns([1, 1])

    with left:
        st.markdown("### THREAT SEVERITY DISTRIBUTION")

        severity_data = pd.DataFrame({
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Alerts": [
                critical_count,
                high_count,
                medium_count,
                low_count
            ]
        })

        if total_alerts:
            fig_severity = px.pie(
                severity_data,
                names="Severity",
                values="Alerts",
                hole=0.68,
                color="Severity",
                color_discrete_map={
                    "Critical": "#ef4444",
                    "High": "#f97316",
                    "Medium": "#eab308",
                    "Low": "#22c55e"
                }
            )
            fig_severity.update_layout(
                template="plotly_dark",
                height=320,
                margin=dict(l=10, r=10, t=20, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                legend=dict(orientation="h", y=-0.12)
            )
            st.plotly_chart(
                fig_severity,
                use_container_width=True,
                key="dashboard_severity_chart"
            )
        else:
            st.info("No detected alerts available for severity analysis.")

    with right:
        st.markdown("### OBSERVED NETWORK PROTOCOLS")

        if protocol_col and not traffic.empty:
            protocol_data = (
                traffic[protocol_col]
                .fillna("Unknown")
                .astype(str)
                .value_counts()
                .head(8)
                .reset_index()
            )
            protocol_data.columns = ["Protocol", "Packets"]

            fig_protocol = px.bar(
                protocol_data,
                x="Protocol",
                y="Packets",
                color="Protocol",
                text="Packets",
                color_discrete_sequence=[
                    "#06b6d4", "#3b82f6", "#8b5cf6",
                    "#14b8a6", "#f59e0b"
                ]
            )
            fig_protocol.update_layout(
                template="plotly_dark",
                height=320,
                showlegend=False,
                margin=dict(l=10, r=10, t=20, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)"
            )
            st.plotly_chart(
                fig_protocol,
                use_container_width=True,
                key="dashboard_protocol_chart"
            )
        else:
            st.info("Protocol statistics will appear after traffic analysis.")

    st.markdown("---")

    # --------------------------------------------------------
    # 3D NETWORK TOPOLOGY
    # --------------------------------------------------------

    st.markdown("### 🌐 3D OBSERVED NETWORK TOPOLOGY")
    st.caption(
        "Visual representation of source and destination IP communication "
        "observed in the analyzed capture. Positions are visual coordinates, "
        "not physical geographic locations."
    )

    if (
        traffic is not None
        and not traffic.empty
        and source_col
        and destination_col
    ):
        network_data = traffic[
            [source_col, destination_col]
        ].dropna().astype(str).head(250)

        network_ips = list(dict.fromkeys(
            network_data[source_col].tolist()
            + network_data[destination_col].tolist()
        ))[:50]

        alert_sources = {
            str(a.get("source_ip", ""))
            for a in (soc_alerts or [])
        }

        positions = {}

        for ip in network_ips:
            digest = hashlib.md5(ip.encode()).hexdigest()
            positions[ip] = (
                int(digest[0:4], 16) / 65535 * 10 - 5,
                int(digest[4:8], 16) / 65535 * 10 - 5,
                int(digest[8:12], 16) / 65535 * 10 - 5
            )

        edge_x, edge_y, edge_z = [], [], []

        for _, edge in network_data.iterrows():
            src = str(edge[source_col])
            dst = str(edge[destination_col])

            if src in positions and dst in positions:
                edge_x.extend([positions[src][0], positions[dst][0], None])
                edge_y.extend([positions[src][1], positions[dst][1], None])
                edge_z.extend([positions[src][2], positions[dst][2], None])

        node_x = [positions[ip][0] for ip in network_ips]
        node_y = [positions[ip][1] for ip in network_ips]
        node_z = [positions[ip][2] for ip in network_ips]

        node_colors = [
            "#ef4444" if ip in alert_sources else "#06b6d4"
            for ip in network_ips
        ]

        node_sizes = [
            10 if ip in alert_sources else 7
            for ip in network_ips
        ]

        fig_network = go.Figure()

        fig_network.add_trace(go.Scatter3d(
            x=edge_x,
            y=edge_y,
            z=edge_z,
            mode="lines",
            line=dict(color="#164e63", width=2),
            hoverinfo="none",
            name="Observed connections"
        ))

        fig_network.add_trace(go.Scatter3d(
            x=node_x,
            y=node_y,
            z=node_z,
            mode="markers+text",
            text=network_ips,
            textposition="top center",
            marker=dict(
                size=node_sizes,
                color=node_colors,
                opacity=0.95,
                line=dict(color="#e2e8f0", width=0.5)
            ),
            hovertemplate="IP: %{text}<extra></extra>",
            name="Network nodes"
        ))

        fig_network.update_layout(
            template="plotly_dark",
            height=570,
            margin=dict(l=0, r=0, t=10, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            scene=dict(
                bgcolor="rgba(0,0,0,0)",
                xaxis=dict(visible=False),
                yaxis=dict(visible=False),
                zaxis=dict(visible=False),
                camera=dict(eye=dict(x=1.6, y=1.6, z=1.2))
            ),
            legend=dict(orientation="h", y=0.02)
        )

        st.plotly_chart(
            fig_network,
            use_container_width=True,
            key="dashboard_3d_network"
        )

        st.markdown(
            "🔴 Alert-associated source IP &nbsp;&nbsp; "
            "🔵 Other observed network IPs",
            unsafe_allow_html=True
        )
    else:
        st.info("Upload and analyze a PCAP file to build the 3D network topology.")

    st.markdown("---")

    # --------------------------------------------------------
    # TOP ATTACK SOURCES AND RECENT EVENTS
    # --------------------------------------------------------

    left, right = st.columns([1, 1])

    with left:
        st.markdown("### ⚠️ TOP ALERT-GENERATING IPs")

        if soc_alerts:
            attacker_data = pd.DataFrame([
                {
                    "Source IP": str(a.get("source_ip", "Unknown")),
                    "Severity": str(a.get("severity", "LOW")).upper()
                }
                for a in soc_alerts
            ])

            attacker_counts = (
                attacker_data.groupby("Source IP")
                .size()
                .reset_index(name="Alert Count")
                .sort_values("Alert Count", ascending=False)
                .head(8)
            )

            fig_attackers = px.bar(
                attacker_counts,
                x="Alert Count",
                y="Source IP",
                orientation="h",
                text="Alert Count",
                color="Alert Count",
                color_continuous_scale=["#164e63", "#06b6d4", "#ef4444"]
            )

            fig_attackers.update_layout(
                template="plotly_dark",
                height=320,
                yaxis=dict(autorange="reversed"),
                coloraxis_showscale=False,
                margin=dict(l=10, r=10, t=20, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)"
            )

            st.plotly_chart(
                fig_attackers,
                use_container_width=True,
                key="dashboard_top_attackers"
            )
        else:
            st.info("No alert-generating IPs are currently available.")

    with right:
        st.markdown("### 📋 RECENT SECURITY EVENTS")

        if soc_alerts:
            recent_events = []

            for alert in soc_alerts[-8:][::-1]:
                recent_events.append({
                    "Severity": str(alert.get("severity", "LOW")).upper(),
                    "Rule": str(alert.get("rule_id", alert.get("rule", "Unknown"))),
                    "Source IP": str(alert.get("source_ip", "Unknown")),
                    "Destination IP": str(alert.get("destination_ip", "Unknown"))
                })

            st.dataframe(
                pd.DataFrame(recent_events),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No security events detected yet.")

    st.markdown("---")

    # --------------------------------------------------------
    # CAPTURE SUMMARY
    # --------------------------------------------------------

    st.markdown("### 📡 CAPTURE INTELLIGENCE")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Unique Source IPs", f"{unique_sources:,}")
    c2.metric("Unique Destination IPs", f"{unique_destinations:,}")

    total_bytes = 0
    if summary and isinstance(summary, dict):
        total_bytes = summary.get(
            "total_bytes",
            summary.get("Total Bytes", 0)
        )

    try:
        total_bytes = int(total_bytes or 0)
    except (TypeError, ValueError):
        total_bytes = 0

    c3.metric("Traffic Volume", f"{total_bytes:,} bytes")
    c4.metric("Capture File", str(capture_name)[:24] if has_capture else "No capture")

    st.caption(
        "Dashboard statistics are calculated from the currently loaded "
        "capture and detected alert records."
    )

    
    st.markdown("### IP INTELLIGENCE")

    import ipaddress

    ip_records = {}

    for alert in soc_alerts:

        for field in ["source_ip", "destination_ip"]:

            ip_value = str(alert.get(field, "")).strip()

            if not ip_value or ip_value == "Unknown":
                continue

            try:
                ip_obj = ipaddress.ip_address(ip_value)

                if ip_obj.is_loopback:
                    classification = "Loopback"
                elif ip_obj.is_link_local:
                    classification = "Link-Local"
                elif ip_obj.is_multicast:
                    classification = "Multicast"
                elif ip_obj.is_unspecified:
                    classification = "Unspecified"
                elif ip_obj.is_reserved:
                    classification = "Reserved"
                elif ip_obj.is_global:
                    classification = "Public"
                else:
                    classification = "Private"

                ip_records[ip_value] = {
                    "IP Address": ip_value,
                    "IP Version": f"IPv{ip_obj.version}",
                    "Classification": classification,
                    "Global Routability": (
                        "Yes" if ip_obj.is_global else "No"
                    )
                }

            except ValueError:
                continue

    if ip_records:

        ip_df = pd.DataFrame(list(ip_records.values()))

        st.markdown("#### OBSERVED IP ADDRESSES")

        public_count = sum(
            1 for item in ip_records.values()
            if item["Classification"] == "Public"
        )

        private_count = sum(
            1 for item in ip_records.values()
            if item["Classification"] == "Private"
        )

        col1, col2, col3 = st.columns(3)

        col1.metric("Unique IPs", len(ip_records))
        col2.metric("Public IPs", public_count)
        col3.metric("Private IPs", private_count)

        st.dataframe(
            ip_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info(
            "No valid IP addresses are currently available "
            "from the detected security alerts."
        )

    st.caption(
        "Classification is based on local IP address properties. "
        "This does not represent external threat reputation or GeoIP verification."
    )

    # GEOIP INTELLIGENCE
    import json
    import urllib.request
    from urllib.parse import quote

    st.markdown("---")
    st.markdown("#### 🌍 GEOIP THREAT MAP")

    public_ips = [
        ip for ip, details in ip_records.items()
        if details["Classification"] == "Public"
    ]

    manual_geo_ip = st.text_input(
        "Optional public IP lookup",
        placeholder="Example: 8.8.8.8",
        key="manual_geo_ip"
    ).strip()

    ips_to_lookup = public_ips[:10]

    if manual_geo_ip:

        try:
            manual_ip_obj = ipaddress.ip_address(manual_geo_ip)

            if manual_ip_obj.is_global:
                if manual_geo_ip not in ips_to_lookup:
                    if len(ips_to_lookup) >= 10:
                        ips_to_lookup = ips_to_lookup[:9]

                    ips_to_lookup.append(manual_geo_ip)
            else:
                st.warning("Enter a globally routable public IP address.")

        except ValueError:
            st.warning("Invalid IP address format.")

    if st.button(
        "🌐 RUN GEOIP LOOKUP",
        key="run_geoip_lookup"
    ):

        geo_results = []
        geo_errors = []

        for ip in ips_to_lookup:

            try:
                api_url = (
                    "https://free.freeipapi.com/api/v1/json/"
                    + quote(ip, safe="")
                )

                request = urllib.request.Request(
                    api_url,
                    headers={"User-Agent": "MiniIDS-SOC/1.0"}
                )

                with urllib.request.urlopen(
                    request,
                    timeout=8
                ) as response:

                    geo_data = json.loads(
                        response.read().decode("utf-8")
                    )

                if (
                    geo_data.get("countryName")
                    and geo_data.get("latitude") is not None
                    and geo_data.get("longitude") is not None
                ):

                    geo_results.append({
                        "IP Address": geo_data.get("ipAddress", ip),
                        "City": geo_data.get("cityName", "Unknown"),
                        "Region": geo_data.get("regionName", "Unknown"),
                        "Country": geo_data.get("countryName", "Unknown"),
                        "ASN": geo_data.get("asn", "Unknown"),
                        "Organization": geo_data.get(
                            "asnOrganization", "Unknown"
                        ),
                        "Latitude": geo_data["latitude"],
                        "Longitude": geo_data["longitude"],
                        "Proxy Indicator": (
                            "Yes" if geo_data.get("isProxy") else "No"
                        )
                    })

                else:
                    geo_errors.append(ip)

            except Exception:
                geo_errors.append(ip)

        st.session_state["ip_geo_results"] = geo_results
        st.session_state["ip_geo_errors"] = geo_errors

    geo_results = st.session_state.get("ip_geo_results", [])
    geo_errors = st.session_state.get("ip_geo_errors", [])

    if geo_results:

        st.markdown("##### GEOLOCATION RESULTS")

        geo_df = pd.DataFrame(geo_results)

        st.dataframe(
            geo_df.drop(columns=["Latitude", "Longitude"]),
            use_container_width=True,
            hide_index=True
        )

        geo_fig = px.scatter_geo(
            geo_df,
            lat="Latitude",
            lon="Longitude",
            hover_name="IP Address",
            hover_data=[
                "City",
                "Region",
                "Country",
                "Organization"
            ],
            color="Country",
            projection="natural earth",
            title="OBSERVED PUBLIC IP LOCATIONS"
        )

        geo_fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=500
        )

        st.plotly_chart(
            geo_fig,
            use_container_width=True,
            key="geoip_world_map"
        )

        st.caption(
            "Geographic locations are approximate IP-based estimates, "
            "not the exact physical locations of devices."
        )

    elif geo_errors:
        st.warning(
            f"GeoIP lookup could not retrieve results for "
            f"{len(geo_errors)} IP address(es). Check connectivity "
            "or try again later."
        )

    else:
        st.info(
            "Enter a public IP address or analyze traffic containing "
            "public IP addresses, then select RUN GEOIP LOOKUP."
        )




# ============================================================
# LIVE MONITOR PAGE
# ============================================================

if selected_page == "Live Monitor":

    st.markdown("## 🔴 LIVE SECURITY OPERATIONS")
    st.caption(
        "Real-time security event monitoring • WebSocket alert stream • "
        "Threat investigation"
    )

    backend_status = str(
        st.session_state.get(
            "live_ws_status",
            "Not connected"
        )
    )

    status_lower = backend_status.lower()

    if "connected" in status_lower and "not connected" not in status_lower:

        st.success(
            f"🟢 Backend connection: {backend_status}"
        )

    else:

        st.warning(
            f"🟠 Backend connection: {backend_status}"
        )

    st.markdown("---")

    # The fragment already handles:
    # - Live WebSocket connection
    # - Incoming alert events
    # - Severity statistics
    # - Alert filtering
    # - Live event display
    # - Alert evidence

    st.markdown("### 📡 LIVE SECURITY EVENT MONITOR")

    render_live_alert_monitor()

# ============================================================
# PCAP ANALYSIS PAGE
# ============================================================

if selected_page == "PCAP Analysis":

    st.markdown("## 📡 DEEP PACKET INSPECTION")
    st.caption(
        "PCAP forensics • Protocol analysis • Packet inspection • "
        "Directional network flows"
    )

    if not has_capture:
        show_no_capture()

    else:

        st.markdown(
            f"""
            <div style="
                background:linear-gradient(110deg,#101c30,#10283a);
                border:1px solid #164e63;
                border-radius:10px;
                padding:14px 18px;
                margin-bottom:18px;">
                <div style="color:#94a3b8;font-size:11px;letter-spacing:2px;">
                    CURRENT PCAP EVIDENCE
                </div>
                <div style="color:#e2e8f0;font-size:17px;font-weight:700;margin-top:5px;">
                    📁 {escape(str(capture_name))}
                </div>
                <div style="color:#64748b;font-size:11px;margin-top:5px;">
                    Analysis ID: {escape(str(analysis_id))}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # ----------------------------------------------------
        # TRAFFIC STATISTICS
        # ----------------------------------------------------

        st.markdown("### ◈ PACKET CAPTURE STATISTICS")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Total Packets",
            f"{summary.get('total_packets', len(traffic)):,}"
        )

        col2.metric(
            "Source IPs",
            f"{summary.get('unique_source_ips', 0):,}"
        )

        col3.metric(
            "Destination IPs",
            f"{summary.get('unique_destination_ips', 0):,}"
        )

        col4.metric(
            "Total Bytes",
            f"{summary.get('total_bytes', 0):,}"
        )

        st.markdown("---")

        # ----------------------------------------------------
        # PROTOCOL ANALYSIS
        # ----------------------------------------------------

        st.markdown("### 🌐 PROTOCOL INTELLIGENCE")

        protocol_column = get_column(
            traffic,
            ["protocol", "Protocol"]
        )

        if protocol_column and not traffic.empty:

            protocol_counts = (
                traffic[protocol_column]
                .fillna("Unknown")
                .astype(str)
                .value_counts()
                .reset_index()
            )

            protocol_counts.columns = ["Protocol", "Packets"]

            p1, p2 = st.columns([1, 1])

            with p1:
                fig_protocol = px.pie(
                    protocol_counts,
                    names="Protocol",
                    values="Packets",
                    hole=0.62,
                    color_discrete_sequence=[
                        "#06b6d4",
                        "#3b82f6",
                        "#8b5cf6",
                        "#14b8a6",
                        "#f59e0b"
                    ]
                )

                fig_protocol.update_layout(
                    template="plotly_dark",
                    height=340,
                    margin=dict(l=10, r=10, t=20, b=10),
                    paper_bgcolor="rgba(0,0,0,0)"
                )

                st.plotly_chart(
                    fig_protocol,
                    use_container_width=True,
                    key="pcap_protocol_chart"
                )

            with p2:
                fig_protocol_bar = px.bar(
                    protocol_counts,
                    x="Protocol",
                    y="Packets",
                    text="Packets",
                    color="Protocol",
                    color_discrete_sequence=[
                        "#06b6d4",
                        "#3b82f6",
                        "#8b5cf6",
                        "#14b8a6",
                        "#f59e0b"
                    ]
                )

                fig_protocol_bar.update_layout(
                    template="plotly_dark",
                    height=340,
                    showlegend=False,
                    margin=dict(l=10, r=10, t=20, b=10),
                    paper_bgcolor="rgba(0,0,0,0)"
                )

                st.plotly_chart(
                    fig_protocol_bar,
                    use_container_width=True,
                    key="pcap_protocol_bar_chart"
                )

        else:
            st.info("Protocol information is unavailable.")

        st.markdown("---")

        # ----------------------------------------------------
        # PACKET INSPECTION
        # ----------------------------------------------------

        st.markdown("### 🔬 PACKET-LEVEL INSPECTION")

        st.caption(
            "Inspect the packet records extracted from the uploaded capture."
        )

        if not traffic.empty:

            st.write(f"Total packet records: **{len(traffic):,}**")

            st.dataframe(
                traffic,
                use_container_width=True,
                hide_index=True,
                height=400
            )

            st.download_button(
                "⬇️ EXPORT PACKET DATA CSV",
                data=traffic.to_csv(index=False).encode("utf-8"),
                file_name="network_packet_analysis.csv",
                mime="text/csv",
                key="download_packet_csv"
            )

        else:
            st.info("No packet records available.")

        st.markdown("---")

        # ----------------------------------------------------
        # FLOW ANALYSIS
        # ----------------------------------------------------

        st.markdown("### 🔗 DIRECTIONAL FLOW ANALYSIS")

        if flows is not None and not flows.empty:

            flow_count = len(flows)

            total_flow_bytes = (
                int(flows["total_bytes"].fillna(0).sum())
                if "total_bytes" in flows.columns else 0
            )

            total_flow_packets = (
                int(flows["packet_count"].fillna(0).sum())
                if "packet_count" in flows.columns else 0
            )

            f1, f2, f3 = st.columns(3)

            f1.metric("Directional Flows", f"{flow_count:,}")
            f2.metric("Flow Packets", f"{total_flow_packets:,}")
            f3.metric("Flow Bytes", f"{total_flow_bytes:,}")

            st.dataframe(
                flows,
                use_container_width=True,
                hide_index=True,
                height=350
            )

            st.download_button(
                "⬇️ EXPORT FLOW DATA CSV",
                data=flows.to_csv(index=False).encode("utf-8"),
                file_name="network_flow_analysis.csv",
                mime="text/csv",
                key="download_flow_csv"
            )

        else:
            st.info("No directional flows were generated.")

        st.markdown("---")

        # ----------------------------------------------------
        # DETECTION RESULTS
        # ----------------------------------------------------

        st.markdown("### 🚨 DETECTION RESULTS")

        packet_total = len(alerts) if alerts else 0
        flow_total = len(flow_alerts) if flow_alerts else 0

        d1, d2, d3 = st.columns(3)

        d1.metric("Packet-Based Alerts", packet_total)
        d2.metric("Flow-Based Alerts", flow_total)
        d3.metric("Combined Alerts", packet_total + flow_total)

        if alerts or flow_alerts:

            detection_records = []

            for alert in (alerts or []):
                detection_records.append({
                    "Detection Source": "Packet",
                    "Severity": str(alert.get("severity", "LOW")).upper(),
                    "Rule": alert.get(
                        "rule_id",
                        alert.get("rule", "Unknown")
                    ),
                    "Source IP": alert.get("source_ip", "Unknown"),
                    "Destination IP": alert.get("destination_ip", "Unknown")
                })

            for alert in (flow_alerts or []):
                detection_records.append({
                    "Detection Source": "Flow",
                    "Severity": str(alert.get("severity", "LOW")).upper(),
                    "Rule": alert.get(
                        "rule_id",
                        alert.get("rule", "Unknown")
                    ),
                    "Source IP": alert.get("source_ip", "Unknown"),
                    "Destination IP": alert.get("destination_ip", "Unknown")
                })

            st.dataframe(
                pd.DataFrame(detection_records),
                use_container_width=True,
                hide_index=True
            )

        else:
            st.success(
                "No packet-based or flow-based detection alerts "
                "were generated for this capture."
            )



# ============================================================
# ALERT CENTER PAGE
# ============================================================

if selected_page == "Alert Center":

    st.markdown("## 🚨 SECURITY ALERT OPERATIONS CENTER")
    st.caption(
        "Centralized threat monitoring • Alert classification • "
        "Detection evidence"
    )

    all_alerts = soc_alerts or []

    # --------------------------------------------------------
    # ALERT STATISTICS
    # --------------------------------------------------------

    critical_alerts = [
        a for a in all_alerts
        if str(a.get("severity", "")).upper() == "CRITICAL"
    ]

    high_alerts = [
        a for a in all_alerts
        if str(a.get("severity", "")).upper() == "HIGH"
    ]

    medium_alerts = [
        a for a in all_alerts
        if str(a.get("severity", "")).upper() == "MEDIUM"
    ]

    low_alerts = [
        a for a in all_alerts
        if str(a.get("severity", "")).upper() == "LOW"
    ]

    st.markdown("### ◈ ALERT OVERVIEW")

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Total Alerts", len(all_alerts))
    c2.metric("Critical", len(critical_alerts))
    c3.metric("High", len(high_alerts))
    c4.metric("Medium", len(medium_alerts))
    c5.metric("Low", len(low_alerts))

    st.markdown("---")

    # --------------------------------------------------------
    # ALERT FILTERS
    # --------------------------------------------------------

    st.markdown("### 🔎 ALERT INVESTIGATION FILTERS")

    f1, f2 = st.columns(2)

    with f1:
        alert_filter = st.multiselect(
            "Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="alert_center_severity"
        )

    with f2:
        source_filter = st.multiselect(
            "Detection Source",
            ["Packet", "Flow"],
            default=["Packet", "Flow"],
            key="alert_center_source"
        )

    filtered_alerts = []

    for alert in all_alerts:

        severity = str(
            alert.get("severity", "LOW")
        ).upper()

        detection_source = str(
            alert.get("detection_source", alert.get("source_type", ""))
        ).lower()

        if detection_source not in ["packet", "flow"]:
            detection_source = (
                "packet"
                if alert in (alerts or [])
                else "flow"
            )

        source_label = (
            "Packet" if detection_source == "packet" else "Flow"
        )

        if severity not in alert_filter:
            continue

        if source_label not in source_filter:
            continue

        filtered_alerts.append(alert)

    st.markdown(
        f"### DETECTION RESULTS — {len(filtered_alerts)} ALERTS"
    )

    if filtered_alerts:
        show_alert_table(
            filtered_alerts[::-1],
            "alert_center_table"
        )
    else:
        st.info("No alerts match the selected filters.")

    st.markdown("---")

    # --------------------------------------------------------
    # SEVERITY DISTRIBUTION
    # --------------------------------------------------------

    st.markdown("### 📊 THREAT SEVERITY ANALYTICS")

    severity_data = pd.DataFrame({
        "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "Count": [
            len(critical_alerts),
            len(high_alerts),
            len(medium_alerts),
            len(low_alerts)
        ]
    })

    if len(all_alerts) > 0:

        fig_alerts = px.bar(
            severity_data,
            x="Severity",
            y="Count",
            color="Severity",
            text="Count",
            color_discrete_map={
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#22c55e"
            }
        )

        fig_alerts.update_layout(
            template="plotly_dark",
            height=320,
            showlegend=False,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(
            fig_alerts,
            use_container_width=True,
            key="alert_center_severity_chart"
        )

    else:
        st.info("Severity analytics will appear when alerts are detected.")

    st.markdown("---")

    # --------------------------------------------------------
    # PACKET-BASED ALERTS
    # --------------------------------------------------------

    st.markdown("### 📦 PACKET-BASED DETECTION ALERTS")

    packet_records = alerts or []

    st.metric("Packet Detection Count", len(packet_records))

    if packet_records:
        show_alert_table(
            packet_records[::-1],
            "packet_alert_table"
        )
    else:
        st.info("No packet-based alerts available.")

    st.markdown("---")

    # --------------------------------------------------------
    # FLOW-BASED ALERTS
    # --------------------------------------------------------

    st.markdown("### 🔗 FLOW-BASED DETECTION ALERTS")

    flow_records = flow_alerts or []

    st.metric("Flow Detection Count", len(flow_records))

    if flow_records:
        show_alert_table(
            flow_records[::-1],
            "flow_alert_table"
        )
    else:
        st.info("No flow-based alerts available.")

    st.markdown("---")

    # --------------------------------------------------------
    # ALERT EXPORT
    # --------------------------------------------------------

    st.markdown("### ⬇️ ALERT DATA EXPORT")

    if filtered_alerts:

        export_records = []

        for alert in filtered_alerts:
            export_records.append({
                "Severity": alert.get("severity", "LOW"),
                "Rule ID": alert.get(
                    "rule_id",
                    alert.get("rule", "Unknown")
                ),
                "Source IP": alert.get("source_ip", "Unknown"),
                "Destination IP": alert.get("destination_ip", "Unknown"),
                "Evidence": alert.get("evidence", "Not available")
            })

        export_df = pd.DataFrame(export_records)

        st.download_button(
            "⬇️ EXPORT FILTERED ALERTS CSV",
            data=export_df.to_csv(index=False).encode("utf-8"),
            file_name="security_alerts.csv",
            mime="text/csv",
            key="alert_center_export"
        )

    else:
        st.caption("No filtered alert records available to export.")



# ============================================================
# INVESTIGATION PAGE
# ============================================================

if selected_page == "Investigation":

    st.markdown("## 🔎 SOC INVESTIGATION & INCIDENT RESPONSE")
    st.caption(
        "Security investigation • Evidence analysis • Incident lifecycle management"
    )

    # ========================================================
    # ALERT INVESTIGATION
    # ========================================================

    st.markdown("### 01 / ALERT INVESTIGATION")

    if soc_alerts:

        alert_options = [
            f"{index + 1}. "
            f"{str(alert.get('severity', 'LOW')).upper()} | "
            f"{alert.get('source_ip', 'Unknown')} → "
            f"{alert.get('destination_ip', 'Unknown')} | "
            f"{alert.get('rule_id', alert.get('rule', 'UNKNOWN'))}"
            for index, alert in enumerate(soc_alerts)
        ]

        selected_alert_label = st.selectbox(
            "Select security event",
            alert_options,
            key="investigation_alert_select"
        )

        selected_index = alert_options.index(selected_alert_label)
        selected_alert = soc_alerts[selected_index]

        severity = str(
            selected_alert.get("severity", "LOW")
        ).upper()

        source_ip = str(
            selected_alert.get("source_ip", "Unknown")
        )

        destination_ip = str(
            selected_alert.get("destination_ip", "Unknown")
        )

        rule_id = str(
            selected_alert.get(
                "rule_id",
                selected_alert.get("rule", "UNKNOWN")
            )
        )

        st.markdown("---")

        a1, a2, a3, a4 = st.columns(4)

        a1.metric("Severity", severity)
        a2.metric("Source Address", source_ip)
        a3.metric("Destination", destination_ip)
        a4.metric(
            "Confidence",
            (
    f"{selected_alert.get('confidence_score')}% "
    f"({str(selected_alert.get('confidence_level', 'N/A')).upper()})"
    if selected_alert.get("confidence_score") is not None
    else "N/A"
)
        )

        st.markdown("### DETECTION EVIDENCE")

        left, right = st.columns(2)

        with left:
            st.markdown("**Detection Rule**")
            st.code(rule_id)

            st.markdown("**Alert Priority**")
            st.write(selected_alert.get("priority", "N/A"))

        with right:
            st.markdown("**Evidence Details**")
            st.warning(
                selected_alert.get(
                    "evidence",
                    "No additional evidence recorded."
                )
            )

        st.markdown("### 🌐 IP THREAT INTELLIGENCE")

        import ipaddress

        ip_columns = st.columns(2)

        for index, (label, ip_value) in enumerate([
            ("SOURCE IP", source_ip),
            ("DESTINATION IP", destination_ip)
        ]):

            with ip_columns[index]:

                st.markdown(f"**{label}**")

                try:
                    ip_obj = ipaddress.ip_address(ip_value)

                    if ip_obj.is_global:
                        st.success("Public IP address")
                    elif ip_obj.is_private:
                        st.info("Private network address")
                    elif ip_obj.is_loopback:
                        st.info("Loopback address")
                    elif ip_obj.is_link_local:
                        st.info("Link-local address")
                    else:
                        st.warning("Special-purpose IP address")

                    st.write(f"IP Version: IPv{ip_obj.version}")

                except ValueError:
                    st.warning("Missing or invalid IP address.")

        st.caption(
            "Local IP classification does not establish malicious reputation."
        )

        st.markdown("### INVESTIGATION RECOMMENDATIONS")

        st.markdown("""
        - Verify the source host and its ownership.
        - Review related network connections.
        - Inspect destination ports and affected services.
        - Correlate this event with other security alerts.
        - Record findings before escalating or resolving the incident.
        """)

        # ====================================================
        # INCIDENT CREATION
        # ====================================================

        st.markdown("---")
        st.markdown("### 02 / CREATE INCIDENT CASE")

        default_title = f"{rule_id} - {source_ip}"

        with st.form("create_incident_form"):

            incident_title = st.text_input(
                "Incident Title",
                value=default_title
            )

            incident_priority = st.selectbox(
                "Incident Priority",
                ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                index=1
            )

            initial_note = st.text_area(
                "Initial Investigation Note",
                placeholder="Record initial findings and observations..."
            )

            create_submitted = st.form_submit_button(
                "➕ CREATE INCIDENT CASE",
                use_container_width=True
            )

        if create_submitted:

            if not incident_title.strip():
                st.error("Incident title cannot be empty.")

            else:
                try:
                    incident_id = create_incident(
                        selected_alert,
                        incident_title.strip(),
                        incident_priority,
                        initial_note
                    )

                    st.success(
                        f"Incident #{incident_id} created successfully!"
                    )

                    st.rerun()

                except Exception as error:
                    st.error(f"Could not create incident: {error}")

    else:
        st.info("No alerts available for investigation.")

    # ========================================================
    # INCIDENT MANAGEMENT
    # ========================================================

    st.markdown("---")
    st.markdown("## 03 / INCIDENT CASE MANAGEMENT")

    incident_records = get_incidents() or []

    if incident_records:

        total_incidents = len(incident_records)

        open_incidents = sum(
            1 for i in incident_records
            if str(i.get("status", "")).upper() == "OPEN"
        )

        investigating_incidents = sum(
            1 for i in incident_records
            if str(i.get("status", "")).upper() == "INVESTIGATING"
        )

        resolved_incidents = sum(
            1 for i in incident_records
            if str(i.get("status", "")).upper() == "RESOLVED"
        )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Total Cases", total_incidents)
        c2.metric("Open", open_incidents)
        c3.metric("Investigating", investigating_incidents)
        c4.metric("Resolved", resolved_incidents)

        st.markdown("### INCIDENT ANALYTICS")

        chart_left, chart_right = st.columns(2)

        with chart_left:

            priority_order = [
                "CRITICAL", "HIGH", "MEDIUM", "LOW"
            ]

            priority_counts = {
                priority: sum(
                    1 for incident in incident_records
                    if str(
                        incident.get("priority", "MEDIUM")
                    ).upper() == priority
                )
                for priority in priority_order
            }

            priority_df = pd.DataFrame({
                "Priority": list(priority_counts.keys()),
                "Incidents": list(priority_counts.values())
            })

            priority_df = priority_df[
                priority_df["Incidents"] > 0
            ]

            if not priority_df.empty:

                priority_fig = px.pie(
                    priority_df,
                    names="Priority",
                    values="Incidents",
                    hole=0.58,
                    color="Priority",
                    color_discrete_map={
                        "CRITICAL": "#ef4444",
                        "HIGH": "#f97316",
                        "MEDIUM": "#eab308",
                        "LOW": "#22c55e"
                    }
                )

                priority_fig.update_layout(
                    template="plotly_dark",
                    height=320,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)"
                )

                st.plotly_chart(
                    priority_fig,
                    use_container_width=True,
                    key="incident_priority_chart"
                )

        with chart_right:

            status_df = pd.DataFrame({
                "Status": [
                    "OPEN",
                    "INVESTIGATING",
                    "RESOLVED"
                ],
                "Incidents": [
                    open_incidents,
                    investigating_incidents,
                    resolved_incidents
                ]
            })

            status_fig = px.bar(
                status_df,
                x="Status",
                y="Incidents",
                color="Status",
                text="Incidents",
                color_discrete_map={
                    "OPEN": "#ef4444",
                    "INVESTIGATING": "#eab308",
                    "RESOLVED": "#22c55e"
                }
            )

            status_fig.update_layout(
                template="plotly_dark",
                height=320,
                showlegend=False,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)"
            )

            st.plotly_chart(
                status_fig,
                use_container_width=True,
                key="incident_status_chart"
            )

        # ====================================================
        # ANALYST WORKLOAD
        # ====================================================

        st.markdown("### ANALYST WORKLOAD")

        analyst_df = pd.DataFrame({
            "Analyst": [
                incident.get("assigned_to") or "Unassigned"
                for incident in incident_records
            ]
        })

        analyst_summary = (
            analyst_df["Analyst"]
            .value_counts()
            .rename_axis("Analyst")
            .reset_index(name="Assigned Incidents")
        )

        st.dataframe(
            analyst_summary,
            use_container_width=True,
            hide_index=True
        )

        # ====================================================
        # CASE HISTORY AND MANAGEMENT
        # ====================================================

        st.markdown("---")
        st.markdown("### 📁 INCIDENT CASE HISTORY")

        for incident in incident_records:

            incident_id = incident["incident_id"]

            with st.expander(
                f"CASE #{incident_id} | "
                f"{incident['title']} | "
                f"{incident['status']}"
            ):

                left, right = st.columns(2)

                with left:
                    st.write("**Priority:**", incident["priority"])
                    st.write("**Source IP:**", incident["source_ip"])
                    st.write(
                        "**Destination IP:**",
                        incident["destination_ip"]
                    )

                with right:
                    st.write("**Rule:**", incident["rule_id"])
                    st.write("**Created:**", incident["created_at"])
                    st.write(
                        "**Assigned Analyst:**",
                        incident.get("assigned_to") or "Unassigned"
                    )

                st.markdown("**Detection Evidence**")
                st.write(
                    incident.get("evidence") or "No evidence recorded."
                )

                st.markdown("---")
                st.markdown("#### ANALYST ASSIGNMENT")

                analyst_name = st.text_input(
                    "Assign to Analyst",
                    value=incident.get("assigned_to") or "",
                    key=f"analyst_{incident_id}"
                )

                if st.button(
                    "ASSIGN ANALYST",
                    key=f"assign_{incident_id}"
                ):

                    if analyst_name.strip():

                        assign_incident(
                            incident_id,
                            analyst_name.strip()
                        )

                        st.success("Analyst assigned.")
                        st.rerun()

                    else:
                        st.warning("Enter an analyst name.")

                st.markdown("---")
                st.markdown("#### INCIDENT STATUS MANAGEMENT")

                status_options = [
                    "OPEN",
                    "INVESTIGATING",
                    "RESOLVED"
                ]

                priority_options = [
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL"
                ]

                current_status = incident.get("status", "OPEN")
                current_priority = incident.get("priority", "MEDIUM")

                new_status = st.selectbox(
                    "Incident Status",
                    status_options,
                    index=(
                        status_options.index(current_status)
                        if current_status in status_options else 0
                    ),
                    key=f"incident_status_{incident_id}"
                )

                new_priority = st.selectbox(
                    "Incident Priority",
                    priority_options,
                    index=(
                        priority_options.index(current_priority)
                        if current_priority in priority_options else 1
                    ),
                    key=f"incident_priority_{incident_id}"
                )

                if st.button(
                    "SAVE INCIDENT UPDATES",
                    key=f"save_incident_{incident_id}"
                ):

                    update_incident(
                        incident_id,
                        new_status,
                        new_priority,
                        incident.get("notes") or ""
                    )

                    st.success("Incident updated.")
                    st.rerun()

                st.markdown("---")
                st.markdown("#### INVESTIGATION NOTES")

                note_text = st.text_area(
                    "Add Investigation Note",
                    key=f"note_text_{incident_id}",
                    placeholder="Record investigation findings..."
                )

                note_analyst = (
                    incident.get("assigned_to") or "SOC Analyst"
                )

                if st.button(
                    "SAVE INVESTIGATION NOTE",
                    key=f"add_note_{incident_id}"
                ):

                    if note_text.strip():

                        add_incident_note(
                            incident_id,
                            note_analyst,
                            note_text.strip()
                        )

                        st.success("Investigation note saved.")
                        st.rerun()

                    else:
                        st.warning("Enter a note first.")

                saved_notes = get_incident_notes(incident_id)

                if saved_notes:

                    st.markdown("**PREVIOUS INVESTIGATION NOTES**")

                    for saved_note in saved_notes:

                        st.caption(
                            f"{saved_note['analyst']} | "
                            f"{saved_note['created_at']}"
                        )

                        st.write(saved_note["note"])
                        st.divider()

                else:
                    st.info("No investigation notes recorded.")

                st.markdown("---")
                st.markdown("#### INCIDENT DELETION")

                if st.button(
                    "🗑️ DELETE THIS INCIDENT",
                    key=f"prepare_delete_incident_{incident_id}"
                ):
                    st.session_state["confirm_delete_incident"] = int(incident_id)

                pending_incident = st.session_state.get(
                    "confirm_delete_incident"
                )

                if pending_incident == int(incident_id):
                    st.warning(
                        f"Confirm permanent deletion of incident #{incident_id} "
                        "and its investigation notes?"
                    )

                    delete_col, cancel_col = st.columns(2)

                    with delete_col:
                        if st.button(
                            "CONFIRM DELETE",
                            type="primary",
                            key=f"confirm_delete_incident_{incident_id}"
                        ):
                            if delete_incident(int(incident_id)):
                                st.success(f"Incident #{incident_id} deleted.")
                            else:
                                st.warning("Incident was not found.")

                            st.session_state.pop(
                                "confirm_delete_incident", None
                            )
                            st.rerun()

                    with cancel_col:
                        if st.button(
                            "CANCEL",
                            key=f"cancel_delete_incident_{incident_id}"
                        ):
                            st.session_state.pop(
                                "confirm_delete_incident", None
                            )
                            st.rerun()
        st.markdown("---")
        # INDIVIDUAL INCIDENT DELETION
        for incident in incident_records:
            incident_id = int(incident["incident_id"])

            col1, col2 = st.columns([4, 1])

            with col1:
                st.write(
                    f"CASE #{incident_id} — {incident['title']}"
                )

            with col2:
                if st.button(
                    "🗑️ DELETE",
                    key=f"individual_delete_{incident_id}"
                ):
                    st.session_state["confirm_delete_incident"] = incident_id

            if st.session_state.get("confirm_delete_incident") == incident_id:
                st.warning(
                    f"Confirm deletion of CASE #{incident_id} "
                    "and its investigation notes?"
                )

                confirm_col, cancel_col = st.columns(2)

                with confirm_col:
                    if st.button(
                        "CONFIRM DELETE",
                        key=f"confirm_individual_{incident_id}",
                        type="primary"
                    ):
                        delete_incident(incident_id)
                        st.session_state.pop(
                            "confirm_delete_incident", None
                        )
                        st.success("Incident deleted successfully.")
                        st.rerun()

                with cancel_col:
                    if st.button(
                        "CANCEL",
                        key=f"cancel_individual_{incident_id}"
                    ):
                        st.session_state.pop(
                            "confirm_delete_incident", None
                        )
                        st.rerun()

        st.markdown("#### BULK INCIDENT MANAGEMENT")

        if st.button(
            "⚠️ PREPARE TO DELETE ALL INCIDENT CASES",
            key="prepare_clear_incidents"
        ):
            st.session_state["confirm_clear_incidents"] = True

        if st.session_state.get("confirm_clear_incidents"):
            st.warning(
                "This permanently deletes all incident cases and their "
                "investigation notes. Saved alerts and analysis history "
                "will remain untouched."
            )

            clear_col, cancel_col = st.columns(2)

            with clear_col:
                if st.button(
                    "CONFIRM DELETE ALL",
                    type="primary",
                    key="confirm_clear_incidents_button"
                ):
                    deleted_count = clear_incidents()

                    st.session_state.pop(
                        "confirm_clear_incidents", None
                    )
                    st.session_state.pop(
                        "confirm_delete_incident", None
                    )

                    st.success(
                        f"Deleted {deleted_count} incident cases."
                    )
                    st.rerun()

            with cancel_col:
                if st.button(
                    "CANCEL",
                    key="cancel_clear_incidents_button"
                ):
                    st.session_state.pop(
                        "confirm_clear_incidents", None
                    )
                    st.rerun()
    else:
        st.info("No incident cases created yet.")

    # ========================================================
    # IP ADDRESS INVESTIGATION
    # ========================================================

    st.markdown("---")
    st.markdown("## 04 / IP ADDRESS INVESTIGATION")

    source_ips = sorted({
        str(alert.get("source_ip"))
        for alert in (soc_alerts or [])
        if alert.get("source_ip")
    })

    if source_ips:

        selected_ip = st.selectbox(
            "Select Source IP Address",
            source_ips,
            key="investigation_ip_select"
        )

        related_alerts = [
            alert for alert in (soc_alerts or [])
            if str(alert.get("source_ip")) == selected_ip
        ]

        targeted_ips = sorted({
            str(alert.get("destination_ip"))
            for alert in related_alerts
            if alert.get("destination_ip")
        })

        highest_severity = next(
            (
                severity for severity in
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                if any(
                    str(alert.get("severity", "LOW")).upper() == severity
                    for alert in related_alerts
                )
            ),
            "UNKNOWN"
        )

        c1, c2, c3 = st.columns(3)

        c1.metric("Related Alerts", len(related_alerts))
        c2.metric("Targeted IPs", len(targeted_ips))
        c3.metric("Highest Severity", highest_severity)

        st.write(
            "**Targeted addresses:**",
            ", ".join(targeted_ips) if targeted_ips else "None recorded"
        )

        show_alert_table(
            related_alerts[::-1],
            "investigation_related_alerts"
        )

    else:
        st.info("No source IP addresses available.")




# ============================================================
# ANALYTICS PAGE
# ============================================================

if selected_page == "Analytics":

    st.markdown("## 📊 SECURITY INTELLIGENCE & ANALYTICS")
    st.caption(
        "Network behavior • Attack patterns • Threat distribution • Risk indicators"
    )

    if not has_capture:

        show_no_capture()

    else:

        # ====================================================
        # TRAFFIC OVERVIEW
        # ====================================================

        st.markdown("### 01 / NETWORK TRAFFIC OVERVIEW")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Packets Inspected", f"{len(traffic):,}")
        col2.metric("Directional Flows", f"{len(flows):,}")
        col3.metric("Total Alerts", f"{total_alert_count:,}")
        col4.metric(
            "Unique Source IPs",
            f"{traffic[source_column].nunique():,}"
            if (source_column := get_column(
                traffic, ["source_ip", "src_ip", "Source IP"]
            )) else "N/A"
        )

        st.markdown("---")

        # ====================================================
        # ATTACK PATTERN ANALYSIS
        # ====================================================

        st.markdown("### 02 / ATTACK PATTERN ANALYSIS")

        if soc_alerts:

            rule_counts = Counter(
                str(alert.get(
                    "rule_id",
                    alert.get("rule", "UNKNOWN")
                ))
                for alert in soc_alerts
            )

            rule_df = pd.DataFrame(
                rule_counts.items(),
                columns=["Detection Rule", "Count"]
            ).sort_values("Count", ascending=True)

            fig_rules = px.bar(
                rule_df,
                x="Count",
                y="Detection Rule",
                orientation="h",
                text="Count",
                color="Count",
                color_continuous_scale=[
                    "#164e63", "#06b6d4", "#f97316", "#ef4444"
                ]
            )

            fig_rules.update_layout(
                template="plotly_dark",
                height=max(320, len(rule_df) * 45),
                coloraxis_showscale=False,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=20, b=10)
            )

            st.plotly_chart(
                fig_rules,
                use_container_width=True,
                key="analytics_attack_patterns"
            )

        else:
            st.info("No attack patterns detected.")

        st.markdown("---")

        # ====================================================
        # COMMUNICATION MATRIX
        # ====================================================

        st.markdown("### 03 / NETWORK COMMUNICATION MATRIX")

        flow_source = get_column(
            flows,
            ["source_ip", "src_ip"]
        )

        flow_destination = get_column(
            flows,
            ["destination_ip", "dst_ip"]
        )

        if (
            flow_source
            and flow_destination
            and not flows.empty
        ):

            matrix_data = (
                flows.groupby(
                    [flow_source, flow_destination],
                    dropna=False
                )
                .size()
                .reset_index(name="Flow Count")
                .sort_values("Flow Count", ascending=False)
            )

            st.dataframe(
                matrix_data,
                use_container_width=True,
                hide_index=True,
                height=320
            )

            st.caption(
                "Each row represents an observed source-to-destination "
                "communication pair."
            )

        else:
            st.info("Communication matrix data is unavailable.")

        st.markdown("---")

        # ====================================================
        # NETWORK RISK INDICATOR
        # ====================================================

        st.markdown("### 04 / NETWORK RISK INDICATOR")

        risk_score = min(
            100,
            severity_counts["CRITICAL"] * 40
            + severity_counts["HIGH"] * 25
            + severity_counts["MEDIUM"] * 10
            + severity_counts["LOW"] * 3
        )

        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        risk_left, risk_right = st.columns([1, 2])

        with risk_left:

            st.metric(
                "Calculated Risk Score",
                f"{risk_score}/100",
                risk_level
            )

            st.progress(risk_score / 100)

        with risk_right:

            st.markdown("**Risk Interpretation**")

            if risk_score >= 75:
                st.error(
                    "Critical indicator: multiple high-weight alerts "
                    "are contributing to the calculated score."
                )
            elif risk_score >= 50:
                st.warning(
                    "High indicator: prioritize review of detected threats."
                )
            elif risk_score >= 25:
                st.warning(
                    "Medium indicator: investigate suspicious activity."
                )
            else:
                st.success(
                    "Low indicator: no significant severity-weighted "
                    "alert accumulation in the current capture."
                )

        st.caption(
            "This project-specific indicator uses severity weights. "
            "It is not a calibrated enterprise risk assessment."
        )

        st.markdown("---")

        # ====================================================
        # DESTINATION PORT ANALYSIS
        # ====================================================

        st.markdown("### 05 / TOP TARGETED DESTINATION PORTS")

        destination_port_column = get_column(
            flows,
            ["destination_port", "dst_port"]
        )

        if destination_port_column and not flows.empty:

            port_counts = (
                flows[destination_port_column]
                .value_counts()
                .head(10)
                .reset_index()
            )

            port_counts.columns = [
                "Destination Port",
                "Flow Count"
            ]

            port_counts["Destination Port"] = (
                port_counts["Destination Port"].astype(str)
            )

            fig_ports = px.bar(
                port_counts,
                x="Destination Port",
                y="Flow Count",
                text="Flow Count",
                color="Flow Count",
                color_continuous_scale=[
                    "#164e63", "#06b6d4", "#ef4444"
                ]
            )

            fig_ports.update_layout(
                template="plotly_dark",
                height=350,
                coloraxis_showscale=False,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)"
            )

            st.plotly_chart(
                fig_ports,
                use_container_width=True,
                key="analytics_destination_ports"
            )

            st.dataframe(
                port_counts,
                use_container_width=True,
                hide_index=True
            )

        else:
            st.info("Destination port information is unavailable.")

        st.markdown("---")

        # ====================================================
        # SEVERITY BREAKDOWN
        # ====================================================

        st.markdown("### 06 / SECURITY SEVERITY BREAKDOWN")

        show_severity_cards(soc_alerts)

        severity_data = pd.DataFrame({
            "Severity": [
                "CRITICAL", "HIGH", "MEDIUM", "LOW"
            ],
            "Alerts": [
                severity_counts["CRITICAL"],
                severity_counts["HIGH"],
                severity_counts["MEDIUM"],
                severity_counts["LOW"]
            ]
        })

        if total_alert_count:

            fig_severity = px.pie(
                severity_data,
                names="Severity",
                values="Alerts",
                hole=0.6,
                color="Severity",
                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#eab308",
                    "LOW": "#22c55e"
                }
            )

            fig_severity.update_layout(
                template="plotly_dark",
                height=330,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)"
            )

            st.plotly_chart(
                fig_severity,
                use_container_width=True,
                key="analytics_severity_distribution"
            )


# ============================================================
# PART 4 — REPORTS, PDF EXPORT AND HISTORY
# ============================================================

# PDF REPORT GENERATOR

def create_security_pdf(
    alert_records,
    capture_name="Unknown",
    analysis_id="Unknown",
    traffic_summary=None,
    packet_alert_count=0,
    flow_alert_count=0
):

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle
    )

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0e7490"),
        fontSize=12,
        spaceBefore=10,
        spaceAfter=6
    )

    cell_style = ParagraphStyle(
        "ReportCell",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        wordWrap="CJK"
    )

    story = []

    story.append(
        Paragraph(
            "MINI IDS — SECURITY INCIDENT REPORT",
            title_style
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 10))

    story.append(
        Paragraph("CAPTURE INFORMATION", heading_style)
    )

    safe_capture = escape(str(capture_name))
    safe_analysis_id = escape(str(analysis_id))

    story.append(
        Paragraph(f"<b>PCAP File:</b> {safe_capture}", styles["Normal"])
    )

    story.append(
        Paragraph(f"<b>Analysis ID:</b> {safe_analysis_id}", styles["Normal"])
    )

    traffic_summary = traffic_summary or {}

    story.append(Spacer(1, 8))

    story.append(
        Paragraph("NETWORK TRAFFIC SUMMARY", heading_style)
    )

    summary_data = [
        ["Total Packets", "Unique Source IPs",
         "Unique Destination IPs", "Total Bytes"],

        [
            str(traffic_summary.get("total_packets", 0)),
            str(traffic_summary.get("unique_source_ips", 0)),
            str(traffic_summary.get("unique_destination_ips", 0)),
            str(traffic_summary.get("total_bytes", 0))
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[60 * mm, 60 * mm, 60 * mm, 60 * mm]
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, 1),
             colors.HexColor("#e0f2fe")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(summary_table)
    story.append(Spacer(1, 10))

    story.append(
        Paragraph("ALERT SUMMARY", heading_style)
    )

    story.append(
        Paragraph(
            f"<b>Packet-Based Alerts:</b> {packet_alert_count}"
            f" &nbsp;&nbsp; "
            f"<b>Flow-Based Alerts:</b> {flow_alert_count}"
            f" &nbsp;&nbsp; "
            f"<b>Total Alerts:</b> {len(alert_records)}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 8))

    story.append(
        Paragraph("DETECTED SECURITY EVENTS", heading_style)
    )

    
    headers = [
        "Detection Source",
        "Rule ID",
        "Severity",
        "Source IP",
        "Destination IP",
        "Confidence",
        "Priority",
        "Evidence"
    ]

    table_data = [[
        Paragraph(header, cell_style)
        for header in headers
    ]]

    for alert in alert_records:

        confidence_score = alert.get("confidence_score")
        confidence_level = alert.get("confidence_level", "N/A")

        confidence = (
            f"{confidence_score}% "
            f"({str(confidence_level).upper()})"
            if confidence_score is not None
            else "N/A"
        )

        row = [
            alert.get("detection_source", "IDS"),
            alert.get("rule_id", alert.get("rule", "UNKNOWN")),
            str(alert.get("severity", "LOW")).upper(),
            alert.get("source_ip", "Unknown"),
            alert.get("destination_ip", "Unknown"),
            confidence,
            alert.get("priority", "N/A"),
            alert.get("evidence", "No evidence")
        ]

        table_data.append([
            Paragraph(
                escape(str(value)),
                cell_style
            )
            for value in row
        ])

    if len(table_data) == 1:
        table_data.append([
            Paragraph("No security alerts detected.", cell_style),
            "", "", "", "", "", "", ""
        ])

    # CREATE THE TABLE ONCE, AFTER BUILDING ALL ROWS
    alert_table = Table(
        table_data,
        colWidths=[
            25 * mm,
            32 * mm,
            17 * mm,
            26 * mm,
            26 * mm,
            23 * mm,
            20 * mm,
            75 * mm
        ],
        repeatRows=1
    )

    alert_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f1f5f9")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )


    story.append(alert_table)

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "Generated by Mini IDS Security Operations Center.",
            styles["Italic"]
        )
    )

    doc.build(story)

    buffer.seek(0)

    return buffer.getvalue()


# ============================================================
# REPORTS PAGE
# ============================================================
    # ============================================================
# REPORTS PAGE
# ============================================================

if selected_page == "Reports":

    st.markdown("## 📄 SECURITY REPORT CENTER")
    st.caption(
        "Generate investigation-ready reports and export security evidence"
    )

    # --------------------------------------------------------
    # REPORT OVERVIEW
    # --------------------------------------------------------

    st.markdown("### 01 / REPORT OVERVIEW")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Alerts", total_alert_count)
    col2.metric("Packet Alerts", packet_alert_count)
    col3.metric("Flow Alerts", flow_alert_count)
    col4.metric(
        "Capture Status",
        "ANALYZED" if has_capture else "NO DATA"
    )

    st.markdown("---")

    if not has_capture:

        show_no_capture()

    else:

        # ----------------------------------------------------
        # CAPTURE INFORMATION
        # ----------------------------------------------------

        st.markdown("### 02 / ANALYSIS IDENTIFICATION")

        info1, info2 = st.columns(2)

        with info1:
            st.markdown("**PCAP Capture File**")
            st.code(str(capture_name))

        with info2:
            st.markdown("**Analysis ID**")
            st.code(str(analysis_id))

        # ----------------------------------------------------
        # BUILD REPORT DATA
        # ----------------------------------------------------

        csv_records = []

        for alert in soc_alerts:

            csv_records.append({
                "Detection Source": alert.get(
                    "detection_source", "IDS"
                ),
                "Rule ID": alert.get(
                    "rule_id",
                    alert.get("rule", "UNKNOWN")
                ),
                "Severity": str(
                    alert.get("severity", "LOW")
                ).upper(),
                "Source IP": alert.get(
                    "source_ip", "Unknown"
                ),
                "Destination IP": alert.get(
                    "destination_ip", "Unknown"
                ),
                "Confidence": (
    f"{alert.get('confidence_score')}% "
    f"({str(alert.get('confidence_level', 'N/A')).upper()})"
    if alert.get("confidence_score") is not None
    else "N/A"
),
                "Priority": alert.get(
                    "priority", "N/A"
                ),
                "Evidence": alert.get(
                    "evidence", "No evidence"
                )
            })

        report_columns = [
            "Detection Source",
            "Rule ID",
            "Severity",
            "Source IP",
            "Destination IP",
            "Confidence",
            "Priority",
            "Evidence"
        ]

        report_df = pd.DataFrame(
            csv_records,
            columns=report_columns
        )

        # ----------------------------------------------------
        # REPORT PREVIEW
        # ----------------------------------------------------

        st.markdown("### 03 / SECURITY EVENT REPORT")

        if not report_df.empty:

            st.dataframe(
                report_df,
                use_container_width=True,
                hide_index=True,
                height=350
            )

        else:

            st.success(
                "Analysis completed. No security alerts were detected."
            )

        # ----------------------------------------------------
        # EXPORT OPTIONS
        # ----------------------------------------------------

        st.markdown("---")
        st.markdown("### 04 / EXPORT CENTER")

        csv_data = report_df.to_csv(
            index=False
        ).encode("utf-8-sig")

        pdf_data = create_security_pdf(
            alert_records=soc_alerts,
            capture_name=capture_name,
            analysis_id=analysis_id,
            traffic_summary=summary,
            packet_alert_count=packet_alert_count,
            flow_alert_count=flow_alert_count
        )

        export1, export2 = st.columns(2)

        with export1:

            st.markdown("**CSV SECURITY DATA**")

            st.caption(
                "Structured alert records for spreadsheet analysis."
            )

            st.download_button(
                label="⬇️ DOWNLOAD ALERTS CSV",
                data=csv_data,
                file_name="mini_ids_security_alerts.csv",
                mime="text/csv",
                use_container_width=True
            )

        with export2:

            st.markdown("**PDF SECURITY REPORT**")

            st.caption(
                "Formatted report containing capture details, "
                "traffic statistics and detected security events."
            )

            st.download_button(
                label="📄 DOWNLOAD SECURITY PDF",
                data=pdf_data,
                file_name="mini_ids_security_report.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        # ----------------------------------------------------
        # REPORT CONTENTS
        # ----------------------------------------------------

        st.markdown("---")
        st.markdown("### 05 / REPORT CONTENTS")

        content1, content2 = st.columns(2)

        with content1:

            st.markdown("""
            - Capture and analysis identification
            - Network traffic statistics
            - Packet-based detection results
            - Flow-based detection results
            """)

        with content2:

            st.markdown("""
            - Alert severity information
            - Source and destination IP addresses
            - Detection rules and evidence
            - Confidence and priority information
            """)

    st.caption(
        "Reports are generated from the currently selected PCAP analysis."
    )

# ============================================================
# HISTORY PAGE
# ============================================================
if selected_page == "History":
    st.markdown("## 🗄️ SECURITY OPERATIONS HISTORY")
    st.caption(
        "Persistent database records • Previous analyses • Security events"
    )

    # ========================================================
    # SAVED ALERT HISTORY
    # ========================================================

    
    st.markdown("### 01 / SAVED SECURITY ALERTS")

    try:
        saved_alerts = get_alert_history(limit=100)

        if saved_alerts:
            saved_df = pd.DataFrame(saved_alerts)

            col1, col2 = st.columns(2)

            col1.metric(
                "Stored Alert Records",
                f"{len(saved_df):,}"
            )

            severity_column = get_column(
                saved_df,
                ["severity", "Severity"]
            )

            if severity_column:
                critical_count = (
                    saved_df[severity_column]
                    .astype(str)
                    .str.upper()
                    .eq("CRITICAL")
                    .sum()
                )
            else:
                critical_count = 0

            col2.metric(
                "Critical Alert Records",
                f"{critical_count:,}"
            )

            search_alerts = st.text_input(
                "🔎 Search saved alerts",
                placeholder="Search IP address, rule, severity or evidence...",
                key="history_alert_search"
            )

            filtered_alerts = saved_df.copy()

            if search_alerts.strip():
                search_mask = filtered_alerts.astype(str).apply(
                    lambda column: column.str.contains(
                        search_alerts.strip(),
                        case=False,
                        na=False,
                        regex=False
                    )
                ).any(axis=1)

                filtered_alerts = filtered_alerts[search_mask]

            st.caption(
                f"Showing {len(filtered_alerts)} of "
                f"{len(saved_df)} stored alert records"
            )

            st.dataframe(
                filtered_alerts,
                use_container_width=True,
                hide_index=True,
                height=350
            )

            st.download_button(
                "⬇️ EXPORT SAVED ALERT HISTORY",
                data=saved_df.to_csv(index=False).encode("utf-8-sig"),
                file_name="mini_ids_saved_alert_history.csv",
                mime="text/csv",
                use_container_width=True,
                key="export_saved_alert_history"
            )

            st.markdown("#### 🗑️ ALERT HISTORY MANAGEMENT")

            if "id" in saved_df.columns:
                alert_ids = [
                    int(alert_id)
                    for alert_id in saved_df["id"].dropna().tolist()
                ]

                if alert_ids:
                    def alert_label(alert_id):
                        row = next(
                            (
                                item for item in saved_alerts
                                if int(item.get("id", -1)) == alert_id
                            ),
                            {}
                        )

                        return (
                            f'#{alert_id} | '
                            f'{row.get("severity", "Unknown")} | '
                            f'{row.get("rule_id", "Unknown rule")} | '
                            f'{row.get("source_ip", "Unknown source")}'
                        )

                    selected_alert_id = st.selectbox(
                        "Select a saved alert to delete",
                        options=alert_ids,
                        format_func=alert_label,
                        key="history_select_alert_delete"
                    )

                    if st.button(
                        "🗑️ PREPARE TO DELETE SELECTED ALERT",
                        key="prepare_delete_alert"
                    ):
                        st.session_state["confirm_delete_alert"] = selected_alert_id

                    pending_alert = st.session_state.get(
                        "confirm_delete_alert"
                    )

                    if pending_alert is not None:
                        st.warning(
                            f"Confirm deletion of saved alert #{pending_alert}?"
                        )

                        confirm_col, cancel_col = st.columns(2)

                        with confirm_col:
                            if st.button(
                                "CONFIRM DELETE",
                                type="primary",
                                key="confirm_delete_alert_button"
                            ):
                                if delete_alert(int(pending_alert)):
                                    st.success("Saved alert deleted.")
                                else:
                                    st.warning("Alert record was not found.")

                                st.session_state.pop(
                                    "confirm_delete_alert", None
                                )
                                st.rerun()

                        with cancel_col:
                            if st.button(
                                "CANCEL",
                                key="cancel_delete_alert_button"
                            ):
                                st.session_state.pop(
                                    "confirm_delete_alert", None
                                )
                                st.rerun()
                else:
                    st.info("No alert IDs are available for deletion.")
            else:
                st.warning(
                    "Alert IDs are missing. Individual deletion is unavailable."
                )

            st.markdown("---")

            if st.button(
                "⚠️ PREPARE TO CLEAR ALL SAVED ALERTS",
                key="prepare_clear_alert_history"
            ):
                st.session_state["confirm_clear_alert_history"] = True

            if st.session_state.get("confirm_clear_alert_history"):
                st.warning(
                    "This permanently deletes all saved alert records. "
                    "Incident cases will remain untouched."
                )

                clear_col, cancel_col = st.columns(2)

                with clear_col:
                    if st.button(
                        "CONFIRM CLEAR ALL",
                        type="primary",
                        key="confirm_clear_alert_history_button"
                    ):
                        deleted_count = clear_alert_history()

                        st.session_state.pop(
                            "confirm_clear_alert_history", None
                        )

                        st.success(
                            f"Deleted {deleted_count} saved alert records."
                        )
                        st.rerun()

                with cancel_col:
                    if st.button(
                        "CANCEL",
                        key="cancel_clear_alert_history_button"
                    ):
                        st.session_state.pop(
                            "confirm_clear_alert_history", None
                        )
                        st.rerun()

        else:
            st.info("No saved alert records found.")

    except Exception as exc:
        st.error(f"Could not load saved alert history: {exc}")

    st.markdown("---")


        # ========================================================
        # ANALYSIS RUN HISTORY
        # ========================================================

    st.markdown("### 02 / PCAP ANALYSIS HISTORY")

    try:
        analysis_history = get_analysis_history(limit=50)

        if analysis_history:
            history_df = pd.DataFrame(analysis_history)

            col1, col2 = st.columns(2)

            col1.metric(
                "Recorded Analysis Runs",
                f"{len(history_df):,}"
            )

            col2.metric(
                "Available History Fields",
                f"{len(history_df.columns):,}"
            )

            search_runs = st.text_input(
                "🔎 Search analysis history",
                placeholder="Search capture name, analysis ID or date...",
                key="history_analysis_search"
            )

            filtered_history = history_df.copy()

            if search_runs.strip():
                history_mask = filtered_history.astype(str).apply(
                    lambda column: column.str.contains(
                        search_runs.strip(),
                        case=False,
                        na=False,
                        regex=False
                    )
                ).any(axis=1)

                filtered_history = filtered_history[history_mask]

            st.caption(
                f"Showing {len(filtered_history)} of "
                f"{len(history_df)} recorded analyses"
            )

            st.dataframe(
                filtered_history,
                use_container_width=True,
                hide_index=True,
                height=350
            )

            st.download_button(
                "⬇️ EXPORT ANALYSIS RUN HISTORY",
                data=history_df.to_csv(index=False).encode("utf-8-sig"),
                file_name="mini_ids_analysis_history.csv",
                mime="text/csv",
                use_container_width=True,
                key="export_analysis_history"
            )

            st.markdown("#### 🗑️ ANALYSIS HISTORY MANAGEMENT")

            analysis_ids = [
                str(row["analysis_id"])
                for row in analysis_history
                if row.get("analysis_id")
            ]

            if analysis_ids:
                selected_analysis = st.selectbox(
                    "Select an analysis run to delete",
                    options=analysis_ids,
                    format_func=lambda analysis_id: next(
                        (
                            f'{row.get("capture_name", "Unknown")} | '
                            f'{analysis_id} | '
                            f'{row.get("created_at", "")}'
                            for row in analysis_history
                            if str(row.get("analysis_id")) == analysis_id
                        ),
                        analysis_id
                    ),
                    key="history_select_analysis_delete"
                )

                if st.button(
                    "🗑️ PREPARE TO DELETE SELECTED ANALYSIS",
                    key="prepare_delete_analysis"
                ):
                    st.session_state["confirm_delete_analysis"] = selected_analysis

                pending_analysis = st.session_state.get(
                    "confirm_delete_analysis"
                )

                if pending_analysis:
                    st.warning(
                        f"Confirm deletion of analysis run: {pending_analysis}"
                    )

                    confirm_col, cancel_col = st.columns(2)

                    with confirm_col:
                        if st.button(
                            "CONFIRM DELETE",
                            type="primary",
                            key="confirm_delete_analysis_button"
                        ):
                            if delete_analysis_run(pending_analysis):
                                st.success("Analysis history record deleted.")
                            else:
                                st.warning("Analysis record was not found.")

                            st.session_state.pop(
                                "confirm_delete_analysis", None
                            )
                            st.rerun()

                    with cancel_col:
                        if st.button(
                            "CANCEL",
                            key="cancel_delete_analysis_button"
                        ):
                            st.session_state.pop(
                                "confirm_delete_analysis", None
                            )
                            st.rerun()

            st.markdown("---")

            if st.button(
                "⚠️ PREPARE TO CLEAR ALL ANALYSIS HISTORY",
                key="prepare_clear_analysis_history"
            ):
                st.session_state["confirm_clear_analysis_history"] = True

            if st.session_state.get("confirm_clear_analysis_history"):
                st.warning(
                    "This will permanently delete all saved analysis-run "
                    "history records. Saved alerts and incident cases will not "
                    "be deleted."
                )

                clear_col, cancel_col = st.columns(2)

                with clear_col:
                    if st.button(
                        "CONFIRM CLEAR ALL",
                        type="primary",
                        key="confirm_clear_analysis_history_button"
                    ):
                        deleted_count = clear_analysis_history()

                        st.session_state.pop(
                            "confirm_clear_analysis_history", None
                        )

                        st.success(
                            f"Deleted {deleted_count} analysis history records."
                        )
                        st.rerun()

                with cancel_col:
                    if st.button(
                        "CANCEL",
                        key="cancel_clear_analysis_history_button"
                    ):
                        st.session_state.pop(
                            "confirm_clear_analysis_history", None
                        )
                        st.rerun()

        else:
            st.info("No analysis runs found.")

    except Exception as exc:
        st.error(f"Could not load analysis history: {exc}")

    st.markdown("---")

    st.markdown("### 03 / DATABASE INFORMATION")

    st.success(
        "History is retrieved from the Mini IDS persistent database."
    )

    st.caption(
        "This page displays the latest 100 saved alert records "
        "and latest 50 analysis runs."
    )