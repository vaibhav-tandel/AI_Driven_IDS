# app.py — Premium Cybersecurity-Themed IDS Dashboard
"""
Launch: streamlit run dashboard/app.py
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from io import BytesIO
import time
import os
import sys
import threading
from datetime import datetime

# Setup paths
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(DASHBOARD_DIR)
sys.path.insert(0, PROJECT_DIR)

from realtime.db import IDSDatabase
from realtime.realtime_engine import RealtimeIDSEngine
from config import DASHBOARD_REFRESH_SECS, MAX_ALERTS_DISPLAY, FLOW_TIMEOUT

# ═══════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════
st.set_page_config(
    page_title="AI-IDS Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ═══════════════════════════════════════════════════
# CUSTOM CSS — Dark Cybersecurity Theme
# ═══════════════════════════════════════════════════
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');

    /* ── Global ── */
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #0d1526 30%, #111b2e 60%, #0a0e17 100%);
        color: #e0e6ed;
        font-family: 'Inter', sans-serif;
    }

    /* Hide default header, footer, deploy button & toolbar */
    header[data-testid="stHeader"] { background: transparent; }
    footer { display: none; }
    #MainMenu { visibility: hidden; }
    .stDeployButton { display: none !important; }
    .stAppDeployButton { display: none !important; }

    /* Keep native sidebar toggle controls visible */
    [data-testid="collapsedControl"] {
        display: flex !important;
        visibility: visible !important;
        opacity: 1 !important;
        z-index: 1000 !important;
    }
    button[aria-label="Open sidebar"],
    button[aria-label="Close sidebar"] {
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        width: 2.2rem !important;
        height: 2.2rem !important;
        border-radius: 10px !important;
        border: 1px solid rgba(0, 212, 255, 0.35) !important;
        background: rgba(13, 21, 38, 0.88) !important;
        color: #00d4ff !important;
        box-shadow: 0 0 14px rgba(0, 212, 255, 0.18) !important;
    }
    button[aria-label="Open sidebar"]:hover,
    button[aria-label="Close sidebar"]:hover {
        border-color: rgba(0, 212, 255, 0.6) !important;
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.28) !important;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0c1220 0%, #111d33 100%) !important;
        border-right: 1px solid rgba(0, 212, 255, 0.15);
    }
    section[data-testid="stSidebar"] .stMarkdown { color: #c0d0e0; }

    /* ── Sidebar form controls (selectbox, multiselect, inputs) ── */
    section[data-testid="stSidebar"] [data-baseweb="select"] > div {
        background: rgba(13, 21, 38, 0.92) !important;
        border: 1px solid rgba(0, 212, 255, 0.25) !important;
        border-radius: 10px !important;
        min-height: 40px;
    }
    section[data-testid="stSidebar"] [data-baseweb="select"] > div:hover {
        border-color: rgba(0, 212, 255, 0.45) !important;
        box-shadow: 0 0 0 1px rgba(0, 212, 255, 0.18) inset;
    }
    section[data-testid="stSidebar"] [data-baseweb="select"] span,
    section[data-testid="stSidebar"] [data-baseweb="select"] input,
    section[data-testid="stSidebar"] [data-baseweb="select"] div {
        color: #d6e7f7 !important;
    }
    section[data-testid="stSidebar"] [data-baseweb="tag"] {
        background: rgba(0, 212, 255, 0.15) !important;
        border: 1px solid rgba(0, 212, 255, 0.35) !important;
        color: #00d4ff !important;
    }
    section[data-testid="stSidebar"] [role="listbox"] {
        background: #0f1a2f !important;
        border: 1px solid rgba(0, 212, 255, 0.25) !important;
    }
    section[data-testid="stSidebar"] [role="option"] {
        color: #d6e7f7 !important;
        background: transparent !important;
    }
    section[data-testid="stSidebar"] [role="option"][aria-selected="true"] {
        background: rgba(0, 212, 255, 0.20) !important;
    }
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] .st-emotion-cache-16idsys p,
    section[data-testid="stSidebar"] .st-emotion-cache-ue6h4q {
        color: #9db6cf !important;
    }

    /* ── Metric Cards ── */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(13, 21, 38, 0.9), rgba(17, 27, 46, 0.8));
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 16px;
        padding: 20px 24px;
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 30px rgba(0, 212, 255, 0.05), inset 0 1px 0 rgba(255,255,255,0.05);
        transition: all 0.3s ease;
    }
    div[data-testid="stMetric"]:hover {
        border-color: rgba(0, 212, 255, 0.5);
        box-shadow: 0 8px 40px rgba(0, 212, 255, 0.15);
        transform: translateY(-2px);
    }
    div[data-testid="stMetric"] label {
        color: #7a8fa6 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.75rem !important;
        text-transform: uppercase;
        letter-spacing: 1.5px;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #00d4ff !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 2rem !important;
        font-weight: 700;
        text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
    }

    /* ── Headings ── */
    h1 { 
        color: #00d4ff !important;
        font-family: 'JetBrains Mono', monospace !important;
        text-shadow: 0 0 30px rgba(0, 212, 255, 0.2);
    }
    h2, h3 { 
        color: #8ec8e8 !important;
        font-family: 'Inter', sans-serif !important;
    }

    /* ── Custom Classes ── */
    .cyber-header {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.08), rgba(0, 255, 136, 0.04));
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 16px;
        padding: 24px 30px;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .cyber-header h1 {
        margin: 0 !important;
        font-size: 1.8rem !important;
    }
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 16px;
        border-radius: 20px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .status-active {
        background: rgba(0, 255, 136, 0.12);
        border: 1px solid rgba(0, 255, 136, 0.4);
        color: #00ff88;
    }
    .status-inactive {
        background: rgba(255, 51, 102, 0.12);
        border: 1px solid rgba(255, 51, 102, 0.4);
        color: #ff3366;
    }

    .alert-card {
        background: linear-gradient(135deg, rgba(13, 21, 38, 0.95), rgba(17, 27, 46, 0.85));
        border: 1px solid rgba(0, 212, 255, 0.15);
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 8px;
        transition: all 0.2s ease;
    }
    .alert-card:hover { border-color: rgba(0, 212, 255, 0.4); }

    .severity-critical { border-left: 4px solid #ff3366 !important; }
    .severity-high { border-left: 4px solid #ff9933 !important; }
    .severity-medium { border-left: 4px solid #ffcc00 !important; }
    .severity-low { border-left: 4px solid #00ff88 !important; }

    .pulse-dot {
        width: 10px; height: 10px;
        background: #00ff88;
        border-radius: 50%;
        display: inline-block;
        animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.4); }
        50% { opacity: 0.7; box-shadow: 0 0 0 10px rgba(0, 255, 136, 0); }
    }

    /* ── Plotly chart backgrounds ── */
    .stPlotlyChart { border-radius: 12px; overflow: hidden; }

    /* ── DataFrame styling ── */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
    }
    div[data-testid="stDataFrame"] div[data-testid="stDataFrameResizable"] {
        border: 1px solid rgba(0, 212, 255, 0.15);
        border-radius: 12px;
    }

    /* ── Scanner Line Animation ── */
    .scanner-line {
        width: 100%;
        height: 2px;
        background: linear-gradient(90deg, transparent, #00d4ff, transparent);
        animation: scan 3s ease-in-out infinite;
        margin: 8px 0;
        border-radius: 2px;
    }
    @keyframes scan {
        0% { opacity: 0.2; transform: scaleX(0.3); }
        50% { opacity: 1; transform: scaleX(1); }
        100% { opacity: 0.2; transform: scaleX(0.3); }
    }

    /* ── Tab styling ── */
    .stTabs [data-baseweb="tab-list"] { 
        gap: 4px;
        background: rgba(13, 21, 38, 0.5);
        border-radius: 12px;
        padding: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        color: #7a8fa6;
        font-family: 'JetBrains Mono', monospace;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(0, 212, 255, 0.15) !important;
        color: #00d4ff !important;
    }

    /* ── Buttons ── */
    .stDownloadButton > button {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.22), rgba(0, 212, 255, 0.1)) !important;
        border: 1px solid rgba(0, 212, 255, 0.45) !important;
        color: #00d4ff !important;
        font-family: 'JetBrains Mono', monospace !important;
        border-radius: 10px !important;
        transition: all 0.3s ease !important;
    }
    .stDownloadButton > button:hover {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.38), rgba(0, 212, 255, 0.2)) !important;
        box-shadow: 0 4px 20px rgba(0, 212, 255, 0.2) !important;
        transform: translateY(-1px) !important;
    }
    .stButton > button {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(0, 212, 255, 0.1)) !important;
        border: 1px solid rgba(0, 212, 255, 0.4) !important;
        color: #00d4ff !important;
        font-family: 'JetBrains Mono', monospace !important;
        border-radius: 10px !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.35), rgba(0, 212, 255, 0.2)) !important;
        box-shadow: 0 4px 20px rgba(0, 212, 255, 0.2) !important;
        transform: translateY(-1px) !important;
    }

    /* ── Severity Radio (Analytics) ── */
    div[data-testid="stRadio"] > div {
        background: rgba(13, 21, 38, 0.75);
        border: 1px solid rgba(0, 212, 255, 0.18);
        border-radius: 12px;
        padding: 8px 12px;
    }
    div[data-testid="stRadio"] label {
        color: #9db6cf !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.78rem !important;
        letter-spacing: 0.7px;
    }
    div[data-testid="stRadio"] label:has(input:checked) {
        color: #00d4ff !important;
        background: rgba(0, 212, 255, 0.12);
        border: 1px solid rgba(0, 212, 255, 0.35);
        border-radius: 10px;
        padding: 4px 10px;
    }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════
# PLOTLY THEME
# ═══════════════════════════════════════════════════
PLOTLY_BASE = dict(
    paper_bgcolor="rgba(10, 14, 23, 0.0)",
    plot_bgcolor="rgba(10, 14, 23, 0.0)",
    font=dict(family="JetBrains Mono, monospace", color="#8ec8e8", size=12),
    margin=dict(l=20, r=20, t=40, b=20),
    legend=dict(
        bgcolor="rgba(0,0,0,0)",
        font=dict(color="#7a8fa6", size=11),
    ),
)

PLOTLY_LAYOUT = dict(
    **PLOTLY_BASE,
    xaxis=dict(gridcolor="rgba(0, 212, 255, 0.06)", zeroline=False),
    yaxis=dict(gridcolor="rgba(0, 212, 255, 0.06)", zeroline=False),
)

CYBER_COLORS = ["#00d4ff", "#00ff88", "#ff3366", "#ff9933", "#ffcc00",
                "#a855f7", "#ec4899", "#06b6d4", "#34d399", "#f97316"]


def plotly_layout(**overrides):
    """Merge PLOTLY_LAYOUT with overrides (avoids duplicate keyword errors)."""
    merged = dict(PLOTLY_LAYOUT)
    merged.update(overrides)
    return merged


# ═══════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════

def init_db():
    return IDSDatabase()


def start_engine_bg(mode="auto"):
    """Start the IDS engine in background thread."""
    if "engine_started" not in st.session_state:
        st.session_state.engine_started = False

    if not st.session_state.engine_started:
        engine = RealtimeIDSEngine(mode=mode, flow_timeout=FLOW_TIMEOUT)
        engine.start(blocking=False)
        st.session_state.engine = engine
        st.session_state.engine_started = True
        st.session_state.capture_mode = engine.resolved_mode
        return engine
    return st.session_state.get("engine")


def severity_color(severity):
    return {
        "CRITICAL": "#ff3366",
        "HIGH": "#ff9933",
        "MEDIUM": "#ffcc00",
        "LOW": "#00ff88"
    }.get(severity, "#7a8fa6")


def severity_icon(severity):
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }.get(severity, "⚪")


def normalize_timestamp_series(series: pd.Series) -> pd.Series:
    """Safely parse mixed timestamp formats (epoch seconds/ms + datetime strings)."""
    if series is None or len(series) == 0:
        return series

    src = series.copy()
    parsed = pd.Series(pd.NaT, index=src.index, dtype="datetime64[ns]")

    numeric = pd.to_numeric(src, errors="coerce")

    # Epoch seconds range (2000-01-01 to 2200-01-01 approx)
    sec_mask = numeric.notna() & (numeric >= 946684800) & (numeric < 7258118400)
    if sec_mask.any():
        parsed.loc[sec_mask] = pd.to_datetime(numeric.loc[sec_mask], unit="s", errors="coerce")

    # Epoch milliseconds range for the same calendar window
    ms_mask = numeric.notna() & (numeric >= 946684800000) & (numeric < 7258118400000)
    if ms_mask.any():
        parsed.loc[ms_mask] = pd.to_datetime(numeric.loc[ms_mask], unit="ms", errors="coerce")

    remaining_mask = parsed.isna()
    if remaining_mask.any():
        parsed.loc[remaining_mask] = pd.to_datetime(src.loc[remaining_mask], errors="coerce")

    return parsed


def dataframe_to_excel_bytes(df: pd.DataFrame, sheet_name: str = "alerts") -> bytes:
    """Serialize a DataFrame to an in-memory Excel file using available engines."""
    output = BytesIO()
    export_df = df.copy()

    last_error = None
    for engine in ("openpyxl", "xlsxwriter"):
        try:
            with pd.ExcelWriter(output, engine=engine) as writer:
                export_df.to_excel(writer, index=False, sheet_name=sheet_name)
            output.seek(0)
            return output.getvalue()
        except ModuleNotFoundError as exc:
            last_error = exc
            output = BytesIO()
        except Exception as exc:
            last_error = exc
            output = BytesIO()

    if last_error:
        raise last_error
    raise RuntimeError("No Excel writer engine available")


def dataframe_to_download_payload(df: pd.DataFrame, basename: str, sheet_name: str = "alerts") -> dict:
    """Return best-effort download payload, falling back to CSV if Excel engine is missing."""
    try:
        return {
            "data": dataframe_to_excel_bytes(df, sheet_name=sheet_name),
            "file_name": f"{basename}.xlsx",
            "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "format": "Excel",
        }
    except ModuleNotFoundError:
        csv_bytes = df.to_csv(index=False).encode("utf-8")
        return {
            "data": csv_bytes,
            "file_name": f"{basename}.csv",
            "mime": "text/csv",
            "format": "CSV",
        }

def render_dark_table(df: pd.DataFrame, height: int = 320, use_container_width: bool = True):
    """Render dataframes using a dark cyber style instead of default white table visuals."""
    styled = (
        df.style
        .set_properties(**{
            "background-color": "#0f1a2f",
            "color": "#d6e7f7",
            "border": "1px solid rgba(0, 212, 255, 0.15)",
        })
        .set_table_styles([
            {
                "selector": "th",
                "props": [
                    ("background-color", "#111d33"),
                    ("color", "#00d4ff"),
                    ("font-family", "JetBrains Mono"),
                    ("border", "1px solid rgba(0, 212, 255, 0.2)"),
                ],
            }
        ])
    )
    st.dataframe(styled, height=height, use_container_width=use_container_width)


# ═══════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════
with st.sidebar:
    st.markdown("### 🛡️ IDS Controls")
    st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)

    # Capture mode selection
    capture_mode = st.selectbox(
        "🎯 Capture Mode",
        ["auto", "psutil", "simulation", "scapy"],
        index=0,
        help="auto = best available | psutil = real connections (no admin) | simulation = demo"
    )

    # Engine control
    if st.button("🚀 Start Monitoring", use_container_width=True):
        start_engine_bg(mode=capture_mode)

    if st.button("⏹ Stop Monitoring", use_container_width=True):
        if st.session_state.get("engine"):
            st.session_state.engine.stop()
            st.session_state.engine_started = False

    if st.button("🗑️ Clear Data", use_container_width=True):
        db = init_db()
        db.clear_all()

    st.divider()

    # Refresh rate
    refresh = st.slider("⏱ Refresh Rate (sec)", 1, 15, DASHBOARD_REFRESH_SECS)

    # Filter
    st.markdown("### 🔎 Filters")
    severity_filter = st.multiselect(
        "Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM"]
    )

    st.divider()

    # System info
    st.markdown("### ℹ️ System Info")
    engine = st.session_state.get("engine")
    if engine and st.session_state.get("engine_started"):
        stats = engine.get_stats()
        st.markdown(f"""
        <div style="
            background: rgba(0, 255, 136, 0.08);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 10px; padding: 12px;
            font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
        ">
            <div class="status-badge status-active">
                <div class="pulse-dot"></div> MONITORING
            </div>
            <br><br>
            📦 Packets: {stats['packets_processed']:,}<br>
            🔍 Flows: {stats['total_flows']:,}<br>
            🚨 Attacks: {stats['attack_flows']:,}
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="
            background: rgba(255, 51, 102, 0.08);
            border: 1px solid rgba(255, 51, 102, 0.3);
            border-radius: 10px; padding: 12px;
            font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
        ">
            <div class="status-badge status-inactive">⏹ OFFLINE</div>
        </div>
        """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════
is_active = st.session_state.get("engine_started", False)
status_class = "status-active" if is_active else "status-inactive"
status_text = '<span class="pulse-dot"></span><span>ACTIVE</span>' if is_active else "<span>⏹ OFFLINE</span>"
mode_suffix = f" • Mode: {st.session_state.get('capture_mode', 'N/A').upper()}" if st.session_state.get("engine_started") else ""

st.markdown(f"""
<div class="cyber-header">
    <div>
        <h1>🛡️ AI-IDS COMMAND CENTER</h1>
        <span style="color: #5a6f8a; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;">
            Powered by RandomForest + XGBoost Ensemble • CIC-IDS2017{mode_suffix}
        </span>
    </div>
    <div class="status-badge {status_class}">{status_text}</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════
db = init_db()
counts = db.get_alert_counts()
total = counts.get("total", 0) or 0
normal = counts.get("normal", 0) or 0
attacks = counts.get("attacks", 0) or 0
avg_conf = counts.get("avg_conf", 0) or 0

packet_rate = db.get_recent_packet_rate(seconds=60)

# Threat level
if attacks == 0:
    threat_level = "SAFE"
    threat_color = "#00ff88"
elif attacks / max(total, 1) < 0.1:
    threat_level = "LOW"
    threat_color = "#00d4ff"
elif attacks / max(total, 1) < 0.25:
    threat_level = "MEDIUM"
    threat_color = "#ffcc00"
elif attacks / max(total, 1) < 0.5:
    threat_level = "HIGH"
    threat_color = "#ff9933"
else:
    threat_level = "CRITICAL"
    threat_color = "#ff3366"


# ═══════════════════════════════════════════════════
# KPI METRICS
# ═══════════════════════════════════════════════════
m1, m2, m3, m4 = st.columns(4)

with m1:
    st.metric("Total Flows", f"{total:,}")
with m2:
    st.metric("🚨 Attacks", f"{attacks:,}")
with m3:
    st.metric("✅ Normal", f"{normal:,}")
with m4:
    st.markdown(f"""
    <div style="
        background: linear-gradient(135deg, rgba(13, 21, 38, 0.9), rgba(17, 27, 46, 0.8));
        border: 1px solid {threat_color}40;
        border-radius: 16px; padding: 20px 24px;
        box-shadow: 0 4px 30px {threat_color}10;
    ">
        <div style="color: #7a8fa6; font-family: 'JetBrains Mono', monospace;
             font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.5px;">
            Threat Level
        </div>
        <div style="color: {threat_color}; font-family: 'JetBrains Mono', monospace;
             font-size: 2rem; font-weight: 700; text-shadow: 0 0 20px {threat_color}30;">
            {threat_level}
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════
tab1, tab2, tab3 = st.tabs(["📊 Overview", "🚨 Alerts", "📈 Analytics"])


# ─── TAB 1: Overview ───
with tab1:
    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown("### 📈 Traffic Timeline")
        timeline = db.get_alerts_timeline(limit=200)
        if timeline:
            df_tl = pd.DataFrame(timeline)
            df_tl["timestamp"] = normalize_timestamp_series(df_tl["timestamp"])
            df_tl = df_tl.dropna(subset=["timestamp"])
            df_tl["is_attack"] = df_tl["attack_type"] != "Benign"

            # Group by time windows
            df_grouped = df_tl.set_index("timestamp").resample("5s").agg(
                total=("attack_type", "count"),
                attacks=("is_attack", "sum")
            ).reset_index()
            df_grouped["normal"] = df_grouped["total"] - df_grouped["attacks"]

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_grouped["timestamp"], y=df_grouped["normal"],
                name="Normal", fill="tozeroy",
                line=dict(color="#00ff88", width=2),
                fillcolor="rgba(0, 255, 136, 0.1)"
            ))
            fig.add_trace(go.Scatter(
                x=df_grouped["timestamp"], y=df_grouped["attacks"],
                name="Attacks", fill="tozeroy",
                line=dict(color="#ff3366", width=2),
                fillcolor="rgba(255, 51, 102, 0.1)"
            ))
            fig.update_layout(**plotly_layout(height=350, title=""))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("🔄 Waiting for data... Start monitoring to see traffic.")

        st.markdown("### ⚡ Live Packet Rate (Last 60s)")
        if packet_rate:
            df_pr = pd.DataFrame(packet_rate)
            df_pr["timestamp"] = normalize_timestamp_series(df_pr["timestamp"])
            df_pr = df_pr.dropna(subset=["timestamp"])
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_pr["timestamp"],
                y=df_pr["packets"],
                mode="lines+markers",
                name="Packets/sec",
                line=dict(color="#00d4ff", width=2),
                marker=dict(size=4, color="#00ff88"),
                fill="tozeroy",
                fillcolor="rgba(0, 212, 255, 0.12)",
            ))
            fig.update_layout(**plotly_layout(height=260, title=""))
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 🎯 Attack Distribution")
        attack_dist = db.get_attack_distribution()
        if attack_dist:
            df_dist = pd.DataFrame(attack_dist)
            fig = go.Figure(go.Pie(
                labels=df_dist["attack_type"],
                values=df_dist["count"],
                hole=0.55,
                marker=dict(colors=CYBER_COLORS, line=dict(color="#0a0e17", width=2)),
                textfont=dict(family="JetBrains Mono", color="#e0e6ed", size=11),
                hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>"
            ))
            fig.update_layout(**plotly_layout(height=350, showlegend=True))
            # Add center text
            fig.add_annotation(
                text=f"<b>{attacks}</b><br><span style='font-size:10px'>attacks</span>",
                font=dict(color="#00d4ff", family="JetBrains Mono", size=18),
                showarrow=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacks detected yet.")

    # Confidence gauge
    st.markdown("### 🎯 Average Detection Confidence")
    gauge_col1, gauge_col2, gauge_col3 = st.columns([1, 2, 1])
    with gauge_col2:
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=avg_conf,
            number=dict(suffix="%", font=dict(color="#00d4ff", size=48, family="JetBrains Mono")),
            gauge=dict(
                axis=dict(range=[0, 100], tickcolor="#5a6f8a",
                         tickfont=dict(color="#5a6f8a", size=10)),
                bar=dict(color="#00d4ff", thickness=0.7),
                bgcolor="rgba(0, 212, 255, 0.05)",
                borderwidth=1, bordercolor="rgba(0, 212, 255, 0.2)",
                steps=[
                    dict(range=[0, 50], color="rgba(255, 51, 102, 0.1)"),
                    dict(range=[50, 75], color="rgba(255, 204, 0, 0.1)"),
                    dict(range=[75, 100], color="rgba(0, 255, 136, 0.1)"),
                ],
                threshold=dict(line=dict(color="#00ff88", width=3), thickness=0.8, value=avg_conf)
            )
        ))
        fig.update_layout(**plotly_layout(height=300))
        st.plotly_chart(fig, use_container_width=True)


# ─── TAB 2: Alerts ───
with tab2:
    st.markdown("### 🚨 Recent Security Alerts")
    st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)

    alerts = db.get_recent_alerts(limit=MAX_ALERTS_DISPLAY)
    if alerts:
        df_all_alerts = pd.DataFrame(alerts)
        all_display_cols = [
            "timestamp", "attack_type", "severity", "confidence", "detection_method",
            "src_ip", "dst_ip", "src_port", "dst_port", "packet_count", "byte_count", "flow_duration",
            "geo_country", "geo_city"
        ]
        all_available_cols = [c for c in all_display_cols if c in df_all_alerts.columns]
        if "timestamp" in df_all_alerts.columns:
            df_all_alerts["timestamp"] = normalize_timestamp_series(df_all_alerts["timestamp"])
        all_payload = dataframe_to_download_payload(
            df_all_alerts[all_available_cols],
            basename="ids_all_recent_alerts",
            sheet_name="all_recent_alerts",
        )
        st.download_button(
            label=f"Download ALL Alerts ({all_payload['format']})",
            data=all_payload["data"],
            file_name=all_payload["file_name"],
            mime=all_payload["mime"],
            key="download_all_alerts_excel",
        )

        # Filter by severity
        filtered = [a for a in alerts if a.get("severity") in severity_filter]

        if filtered:
            for alert in filtered[:50]:  # Show top 50
                sev = alert.get("severity", "MEDIUM")
                icon = severity_icon(sev)
                color = severity_color(sev)
                ts_raw = alert.get("timestamp")
                if isinstance(ts_raw, (int, float)):
                    ts_text = datetime.fromtimestamp(ts_raw).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    ts_text = str(ts_raw)

                st.markdown(f"""
                <div class="alert-card severity-{sev.lower()}" style="font-family: 'JetBrains Mono', monospace;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="font-size: 1.1rem;">{icon}</span>
                            <span style="color: {color}; font-weight: 700;"> {alert['attack_type']}</span>
                            <span style="color: #5a6f8a; font-size: 0.8rem; margin-left: 12px;">
                                [{sev}]
                            </span>
                        </div>
                        <span style="color: #5a6f8a; font-size: 0.75rem;">{ts_text}</span>
                    </div>
                    <div style="margin-top: 8px; font-size: 0.8rem; color: #7a8fa6;">
                        <span style="color: #00d4ff;">SRC</span> {alert.get('src_ip', '?')}:{alert.get('src_port', '?')}
                        <span style="margin: 0 8px; color: #3a4f6a;">→</span>
                        <span style="color: #ff9933;">DST</span> {alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}
                        <span style="margin-left: 16px;">
                            Confidence: <span style="color: {'#00ff88' if alert.get('confidence', 0) > 80 else '#ffcc00'};">
                                {alert.get('confidence', 0):.1f}%
                            </span>
                        </span>
                        {f'<span style="margin-left: 16px;">🌍 {alert.get("geo_country", "")}, {alert.get("geo_city", "")}</span>' if alert.get("geo_country") else ''}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Also show as expandable table
            with st.expander("📋 View as Table"):
                df_alerts = pd.DataFrame(filtered[:100])
                display_cols = ["timestamp", "attack_type", "severity", "confidence",
                               "detection_method", "src_ip", "dst_ip", "dst_port",
                               "packet_count", "byte_count", "flow_duration",
                               "geo_country", "geo_city"]
                available_cols = [c for c in display_cols if c in df_alerts.columns]
                if "timestamp" in df_alerts.columns:
                    df_alerts["timestamp"] = normalize_timestamp_series(df_alerts["timestamp"])
                render_dark_table(df_alerts[available_cols], height=400)
        else:
            st.info("No alerts match the current severity filter.")
    else:
        st.info("🔄 No alerts yet. Start monitoring to detect intrusions.")


# ─── TAB 3: Analytics ───
with tab3:
    st.markdown("### 📈 Detailed Analytics")
    st.markdown('<div class="scanner-line"></div>', unsafe_allow_html=True)

    # Fetch recent alerts once (used in both columns and severity section below)
    recent_alerts = db.get_recent_alerts(limit=500)

    analytics_col1, analytics_col2 = st.columns(2)

    with analytics_col1:
        # Attacks by type bar chart
        st.markdown("#### Attack Types Breakdown")
        attack_dist = db.get_attack_distribution()
        if attack_dist:
            df_dist = pd.DataFrame(attack_dist)
            fig = go.Figure(go.Bar(
                x=df_dist["count"],
                y=df_dist["attack_type"],
                orientation="h",
                marker=dict(
                    color=CYBER_COLORS[:len(df_dist)],
                    line=dict(color="rgba(0, 212, 255, 0.3)", width=1)
                ),
                text=df_dist["count"],
                textposition="outside",
                textfont=dict(color="#00d4ff", family="JetBrains Mono", size=11)
            ))
            fig.update_layout(
                **plotly_layout(
                    height=max(300, len(df_dist) * 40),
                    yaxis=dict(autorange="reversed", gridcolor="rgba(0, 212, 255, 0.06)"),
                )
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack data yet.")

    with analytics_col2:
        # Confidence distribution
        st.markdown("#### Confidence Distribution")
        attack_alerts = [a for a in recent_alerts if a.get("attack_type") != "Benign"]
        if attack_alerts:
            confs = [a["confidence"] for a in attack_alerts]
            fig = go.Figure(go.Histogram(
                x=confs,
                nbinsx=20,
                marker=dict(
                    color="rgba(0, 212, 255, 0.6)",
                    line=dict(color="#00d4ff", width=1)
                ),
            ))
            fig.update_layout(**plotly_layout(
                height=300,
                xaxis=dict(gridcolor="rgba(0, 212, 255, 0.06)", zeroline=False, title="Confidence (%)"),
                yaxis=dict(gridcolor="rgba(0, 212, 255, 0.06)", zeroline=False, title="Count"),
            ))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No confidence data yet.")

    # Severity distribution
    st.markdown("#### Severity Distribution")
    if recent_alerts:
        sev_filtered = [a for a in recent_alerts if a.get("attack_type") != "Benign"]
        if sev_filtered:
            sev_counts = {}
            for a in sev_filtered:
                s = a.get("severity", "UNKNOWN")
                sev_counts[s] = sev_counts.get(s, 0) + 1

            sev_colors = {"CRITICAL": "#ff3366", "HIGH": "#ff9933",
                         "MEDIUM": "#ffcc00", "LOW": "#00ff88"}

            sev_col1, sev_col2, sev_col3, sev_col4 = st.columns(4)
            for col, sev in zip([sev_col1, sev_col2, sev_col3, sev_col4],
                               ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
                count = sev_counts.get(sev, 0)
                color = sev_colors[sev]
                with col:
                    st.markdown(f"""
                    <div style="
                        background: linear-gradient(135deg, rgba(13, 21, 38, 0.9), rgba(17, 27, 46, 0.8));
                        border: 1px solid {color}40; border-left: 4px solid {color};
                        border-radius: 12px; padding: 16px; text-align: center;
                    ">
                        <div style="color: #5a6f8a; font-family: 'JetBrains Mono', monospace;
                             font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px;">
                            {severity_icon(sev)} {sev}
                        </div>
                        <div style="color: {color}; font-family: 'JetBrains Mono', monospace;
                             font-size: 2rem; font-weight: 700; margin-top: 4px;">
                            {count}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

    st.markdown("#### Severity Drill-Down")
    severity_pick = st.radio(
        "Click a threat level to list matching alerts",
        ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        horizontal=True,
        key="analytics_severity_pick",
    )

    if recent_alerts:
        attack_only = [a for a in recent_alerts if a.get("attack_type") != "Benign"]
        if severity_pick == "ALL":
            filtered_alerts = attack_only
        else:
            filtered_alerts = [a for a in attack_only if str(a.get("severity", "")).upper() == severity_pick]

        st.caption(f"Showing {len(filtered_alerts)} alert(s) for {severity_pick}")
        if filtered_alerts:
            df_filtered = pd.DataFrame(filtered_alerts)
            display_cols = [
                "timestamp", "attack_type", "severity", "confidence", "detection_method",
                "src_ip", "dst_ip", "src_port", "dst_port", "packet_count", "byte_count", "flow_duration"
            ]
            available_cols = [c for c in display_cols if c in df_filtered.columns]
            if "timestamp" in df_filtered.columns:
                df_filtered["timestamp"] = normalize_timestamp_series(df_filtered["timestamp"])
            export_df = df_filtered[available_cols].copy()
            filtered_payload = dataframe_to_download_payload(
                export_df,
                basename=f"ids_{severity_pick.lower()}_alerts",
                sheet_name="severity_filtered_alerts",
            )
            st.download_button(
                label=f"Download {severity_pick} Alerts ({filtered_payload['format']})",
                data=filtered_payload["data"],
                file_name=filtered_payload["file_name"],
                mime=filtered_payload["mime"],
                key="download_severity_alerts_excel",
            )
            render_dark_table(export_df, height=320)
        else:
            st.info("No alerts found for the selected threat level.")


# ═══════════════════════════════════════════════════
# AUTO-REFRESH
# ═══════════════════════════════════════════════════
time.sleep(refresh)
st.rerun()
