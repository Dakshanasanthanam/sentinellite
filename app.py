
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from src.sentinellite.log_parser import parse_log_file
from src.sentinellite.detector import detect_repeated_failures
from src.sentinellite.reporting import build_report


st.set_page_config(
    page_title="SentinelLite | SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.stApp {
    background: #0b1120;
    color: #e5edf7;
}
[data-testid="stHeader"] {
    background: rgba(11, 17, 32, 0.95);
}
[data-testid="stSidebar"] {
    background: #111a2c;
    border-right: 1px solid #263449;
}
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}
h1, h2, h3 {
    color: #edf5ff !important;
}
p, label, [data-testid="stCaptionContainer"] {
    color: #9aacc4;
}
.metric-card {
    background: #131e31;
    border: 1px solid #26364c;
    border-radius: 14px;
    padding: 20px;
    min-height: 125px;
}
.metric-label {
    color: #9aacc4;
    font-size: 0.88rem;
    margin-bottom: 12px;
}
.metric-value {
    color: #65e6c2;
    font-size: 2rem;
    font-weight: 700;
}
.section-card {
    background: #111a2c;
    border: 1px solid #263449;
    border-radius: 14px;
    padding: 18px;
}
.status-pill {
    display: inline-block;
    color: #65e6c2;
    background: #15382f;
    padding: 5px 10px;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
}
hr {
    border-color: #263449;
}
div[data-testid="stDataFrame"] {
    border: 1px solid #263449;
    border-radius: 10px;
}
.stDownloadButton button {
    background: #65e6c2;
    color: #0b1120;
    border: none;
    font-weight: 700;
    border-radius: 8px;
}
.stDownloadButton button:hover {
    background: #8af2d5;
    color: #0b1120;
}
</style>
""", unsafe_allow_html=True)


def metric_card(label, value):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.markdown(
    '<span class="status-pill">● MONITORING ACTIVE</span>',
    unsafe_allow_html=True,
)
st.title("🛡️ SentinelLite")
st.caption("SECURITY OPERATIONS CENTER  /  AUTHENTICATION MONITORING")

st.sidebar.markdown("## 🛡️ SentinelLite")
st.sidebar.caption("SECURITY CONTROL PANEL")
st.sidebar.divider()

st.sidebar.subheader("Detection settings")
threshold = st.sidebar.slider(
    "Failed login threshold",
    min_value=3,
    max_value=10,
    value=5,
)
window_minutes = st.sidebar.slider(
    "Detection window (minutes)",
    min_value=1,
    max_value=15,
    value=5,
)

st.sidebar.info(
    "Demo environment: all included authentication events are synthetic."
)

if st.sidebar.button("Reload analysis", use_container_width=True):
    st.rerun()

log_path = Path("data/sample_auth.log")

try:
    events, errors = parse_log_file(log_path)
    alerts = detect_repeated_failures(
        events,
        threshold=threshold,
        window_minutes=window_minutes,
    )
    report = build_report(events, errors, alerts)
except (OSError, ValueError, KeyError) as error:
    st.error(f"Unable to load or analyze logs: {error}")
    st.stop()

st.markdown("## Security overview")

c1, c2, c3, c4 = st.columns(4)

with c1:
    metric_card("TOTAL EVENTS", report["total_events"])
with c2:
    metric_card("INVALID RECORDS", report["invalid_records"])
with c3:
    metric_card("THREAT ALERTS", report["total_alerts"])
with c4:
    metric_card(
        "HIGH SEVERITY",
        report["severity_counts"].get("HIGH", 0),
    )

st.write("")
left, right = st.columns([1.65, 1])

with left:
    st.markdown("## 🚨 Threat alerts")

    if alerts:
        alert_df = pd.DataFrame(alerts)
        st.dataframe(
            alert_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No alerts matched the current detection settings.")

with right:
    st.markdown("## 📊 Event distribution")

    if not events.empty:
        counts = (
            events["event_type"]
            .value_counts()
            .rename_axis("Event type")
            .reset_index(name="Count")
        )
        st.bar_chart(counts, x="Event type", y="Count")

st.divider()
st.markdown("## 🔎 Authentication event explorer")

if not events.empty:
    filter_col1, filter_col2 = st.columns(2)

    available_types = sorted(events["event_type"].unique().tolist())

    with filter_col1:
        selected_types = st.multiselect(
            "Event type",
            options=available_types,
            default=available_types,
        )

    with filter_col2:
        available_ips = sorted(events["source_ip"].unique().tolist())
        selected_ips = st.multiselect(
            "Source IP",
            options=available_ips,
            default=available_ips,
        )

    filtered = events[
        events["event_type"].isin(selected_types)
        & events["source_ip"].isin(selected_ips)
    ].sort_values("timestamp", ascending=False)

    st.caption(f"Showing {len(filtered)} of {len(events)} events")
    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )

st.divider()
st.markdown("## 📄 Export investigation report")

report_payload = json.dumps(
    report,
    indent=2,
    default=str,
)

download_col, info_col = st.columns([1, 2])

with download_col:
    st.download_button(
        "⬇ Download JSON report",
        data=report_payload,
        file_name="sentinellite_report.json",
        mime="application/json",
        use_container_width=True,
    )

with info_col:
    st.caption(
        "Includes event totals, validation errors, alert severity, "
        "timestamps, and detection evidence."
    )

st.divider()
st.caption(
    "SentinelLite • Educational defensive security project • "
    f"Report generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
)

