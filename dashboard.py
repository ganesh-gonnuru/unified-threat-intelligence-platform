import json
import pandas as pd
import streamlit as st
from pathlib import Path

REPORT_FILE = Path("cross_feed_report.csv")
FEED_FILE = Path("feodo_feed.csv")
RUN_FILE = Path("last_run.json")

st.set_page_config(
    page_title="MISP Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("MISP Threat Intelligence Dashboard")
st.caption("Feodo IP Blocklist • Local threat intelligence reconciliation")

# Latest pipeline execution summary
st.subheader("Latest Pipeline Run")

if RUN_FILE.exists():
    try:
        with RUN_FILE.open("r", encoding="utf-8") as file:
            run_data = json.load(file)

        completed_at = run_data.get("completed_at_utc", "Unknown")
        total_unique = run_data.get("total_unique_ips", 0)
        existing = run_data.get("existing_in_misp", 0)
        not_found = run_data.get("not_found_in_misp", 0)
        failures = run_data.get("lookup_failures", 0)

        st.caption(f"Last completed (UTC): {completed_at}")

        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Unique Indicators Processed", total_unique)
        r2.metric("Found in MISP", existing)
        r3.metric("Not Found in MISP", not_found)
        r4.metric("Lookup Failures", failures)

    except (json.JSONDecodeError, OSError) as error:
        st.error(f"Could not read last_run.json: {error}")
else:
    st.warning("last_run.json not found. Run the pipeline first.")

st.divider()

if FEED_FILE.exists():
    feed_time = pd.Timestamp(
        FEED_FILE.stat().st_mtime, unit="s", tz="UTC"
    )
    st.caption(
        f"Local feed file last written: "
        f"{feed_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
else:
    st.warning("Local feed file not found; collection time unavailable.")

if not REPORT_FILE.exists():
    st.error("cross_feed_report.csv not found. Generate the report first.")
    st.stop()

df = pd.read_csv(REPORT_FILE).fillna("")

if df.empty:
    st.warning("The report contains no indicators.")
    st.stop()

df["event_count"] = pd.to_numeric(
    df["event_count"], errors="coerce"
).fillna(0).astype(int)

total_ips = df["ip"].nunique()
multi_event = int((df["event_count"] > 1).sum())
online = int((df["c2_status"].str.lower() == "online").sum())
offline = int((df["c2_status"].str.lower() == "offline").sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Unique IPs", total_ips)
c2.metric("IPs in Multiple Events", multi_event)
c3.metric("Reported Online", online)
c4.metric("Reported Offline", offline)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Indicators by Malware Family")
    malware_counts = (
        df["malware"].replace("", "Unknown").value_counts()
    )
    st.bar_chart(malware_counts)

with right:
    st.subheader("Reported C2 Status")
    status_counts = (
        df["c2_status"].replace("", "Unknown").value_counts()
    )
    st.bar_chart(status_counts)

st.subheader("Search and Filter Indicators")

malware_options = sorted(df["malware"].replace("", "Unknown").unique())
selected_malware = st.selectbox(
    "Malware family",
    ["All"] + malware_options,
)

status_options = sorted(df["c2_status"].replace("", "Unknown").unique())
selected_status = st.selectbox(
    "Reported C2 status",
    ["All"] + status_options,
)

filtered = df.copy()

if selected_malware != "All":
    filtered = filtered[
        filtered["malware"].replace("", "Unknown") == selected_malware
    ]

if selected_status != "All":
    filtered = filtered[
        filtered["c2_status"].replace("", "Unknown") == selected_status
    ]

search = st.text_input("Search IP, malware, or event ID").strip()

if search:
    mask = filtered.astype(str).apply(
        lambda column: column.str.contains(search, case=False, regex=False)
    ).any(axis=1)
    filtered = filtered[mask]

st.dataframe(filtered, use_container_width=True, hide_index=True)

st.download_button(
    "Download filtered results as CSV",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_threat_intelligence.csv",
    mime="text/csv",
)

st.caption(
    "Data source: saved Feodo feed report. "
    "C2 status reflects the source snapshot, not verified live activity."
)
