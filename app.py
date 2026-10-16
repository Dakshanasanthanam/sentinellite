
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinellite.log_parser import parse_log_file
from sentinellite.detector import detect_threats

st.set_page_config(
    page_title="SentinelLite | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e5e7eb;
}
[data-testid="stSidebar"] {
    background-color: #111827;
}
[data-testid="stMetric"] {
    background-color: #172033;
    border: 1px solid #263449;
    padding: 18px;
    border-radius: 12px;
}
h1, h2, h3 {
    color: #e5e7eb;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ SentinelLite")
st.caption("Lightweight Security Operations Center | Security Event Monitoring")

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "sample_auth.log"


@st.cache_data
def load_events(file_path, modified_time):
    return parse_log_file(file_path)


try:
    events = load_events(str(LOG_FILE), LOG_FILE.stat().st_mtime)
except Exception as exc:
    st.error(f"Could not load the authentication log: {exc}")
    st.stop()

if isinstance(events, pd.DataFrame):
    df = events.copy()
else:
    df = pd.DataFrame(events)

if df.empty:
    st.warning("No events were found in the log file.")
    st.stop()

st.subheader("Security Overview")

total_events = len(df)

threats = detect_threats(events)
if isinstance(threats, pd.DataFrame):
    alerts_df = threats.copy()
else:
    alerts_df = pd.DataFrame(threats or [])

if alerts_df.empty:
    high_alerts = 0
else:
    severity_col = next(
        (c for c in alerts_df.columns if c.lower() == "severity"),
        None,
    )
    high_alerts = (
        int(alerts_df[severity_col].astype(str).str.lower()
            .isin(["high", "critical"]).sum())
        if severity_col else 0
    )

col1, col2, col3 = st.columns(3)
col1.metric("Total Events", total_events)
col2.metric("Alerts Detected", len(alerts_df))
col3.metric("High / Critical Alerts", high_alerts)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Event Distribution")
    event_col = next(
        (c for c in df.columns
         if c.lower() in ["event_type", "event", "type", "action"]),
        None,
    )

    if event_col:
        counts = df[event_col].astype(str).value_counts()
        st.bar_chart(counts)
    else:
        st.info("No recognized event-type column was found.")
        st.dataframe(df.head(10), use_container_width=True)

with right:
    st.subheader("Threat Alerts")
    if alerts_df.empty:
        st.success("No threats detected by the current detector.")
    else:
        st.dataframe(alerts_df, use_container_width=True)

st.divider()
st.subheader("Authentication Event Log")

if "event_type" in df.columns:
    event_types = sorted(df["event_type"].dropna().astype(str).unique())
    selected_types = st.multiselect(
        "Filter by event type",
        event_types,
        default=event_types,
    )
    filtered_df = df[df["event_type"].astype(str).isin(selected_types)]
else:
    filtered_df = df

st.dataframe(filtered_df, use_container_width=True)

st.download_button(
    "Download Events as CSV",
    data=filtered_df.to_csv(index=False).encode("utf-8"),
    file_name="sentinellite_events.csv",
    mime="text/csv",
)

report = {
    "total_events": total_events,
    "alerts_detected": len(alerts_df),
    "high_critical_alerts": high_alerts,
    "events": df.to_dict(orient="records"),
    "alerts": alerts_df.to_dict(orient="records"),
}

st.download_button(
    "Download Security Report (JSON)",
    data=json.dumps(report, indent=2, default=str),
    file_name="sentinellite_report.json",
    mime="application/json",
)

if st.button("Refresh Dashboard"):
    st.cache_data.clear()
    st.rerun()
o
