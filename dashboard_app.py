# dashboard_app.py (Streamlit) — Simple alert log viewer
import streamlit as st
import pandas as pd
import os
import time

st.set_page_config(page_title="AI-Powered IDS Dashboard", layout="wide")
st.title("🛡️ AI-Powered IDS Dashboard")

log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "ids_alerts.log")

if os.path.exists(log_file):
    try:
        logs = pd.read_csv(log_file, sep=r"\s*\|\s*", header=None,
                           names=["Time", "Level", "Message"], engine="python")
        st.subheader(f"📝 Latest Alerts ({len(logs)} total)")
        st.dataframe(logs.tail(30), use_container_width=True)
    except Exception as e:
        st.warning(f"Error reading log file: {e}")
else:
    st.info("No alerts logged yet. Run the IDS engine first: `python run_ids.py`")

st.caption("Auto-refreshes every 5 seconds")
time.sleep(5)
st.rerun()
