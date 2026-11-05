#!/usr/bin/env python3
"""Streamlit dashboard for unified TIP outputs."""
import json
from pathlib import Path
import pandas as pd
import streamlit as st

BASE = Path(__file__).resolve().parent
st.set_page_config(page_title="Unified Threat Intelligence Platform", page_icon="🛡️", layout="wide")
st.title("🛡️ Unified Threat Intelligence Platform")
st.caption("Feodo Tracker + indicators already imported into MISP. Feed inventory and imported indicators are reported separately.")

report_path = BASE / "unified_tip_report.json"
feed_path = BASE / "feed_inventory.csv"
ioc_path = BASE / "unified_indicators.csv"
if not report_path.exists() or not feed_path.exists() or not ioc_path.exists():
    st.warning("Unified outputs are not available yet. Run `python unified_ingest.py` from the project directory.")
    st.stop()

report = json.loads(report_path.read_text(encoding="utf-8"))
feeds = pd.read_csv(feed_path, dtype=str).fillna("")
iocs = pd.read_csv(ioc_path, dtype=str).fillna("")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Configured MISP feeds", f"{len(feeds):,}")
c2.metric("Unique indicators", f"{len(iocs):,}")
c3.metric("Multiple-source indicators", f"{int(report.get('indicators_in_multiple_sources', 0)):,}")
c4.metric("MISP attributes retrieved", f"{int(report.get('misp_attributes_retrieved', 0)):,}")
st.caption(f"Last successful unified run (UTC): {report.get('completed_at_utc', 'unknown')}")

if report.get("feed_inventory_error"):
    st.error("Feed inventory warning: " + str(report["feed_inventory_error"]))
if report.get("misp_attribute_error"):
    st.warning("MISP attribute retrieval warning: " + str(report["misp_attribute_error"]))

st.subheader("Feed inventory")
feed_search = st.text_input("Search feed name or URL", key="feed_search")
feed_status = st.selectbox("Enabled status", ["All", "Enabled", "Disabled", "Unknown"], key="feed_status")
filtered_feeds = feeds.copy()
if feed_search:
    mask = filtered_feeds.apply(lambda col: col.str.contains(feed_search, case=False, na=False)).any(axis=1)
    filtered_feeds = filtered_feeds[mask]
if feed_status != "All":
    target = {"Enabled": "1", "Disabled": "0", "Unknown": ""}[feed_status]
    filtered_feeds = filtered_feeds[filtered_feeds["enabled"].str.lower().isin([target, target == "1" and "true" or target == "0" and "false" or ""])]
st.dataframe(filtered_feeds, use_container_width=True, hide_index=True)
st.download_button("Download feed inventory CSV", feeds.to_csv(index=False).encode("utf-8"), "feed_inventory.csv", "text/csv")

st.subheader("Indicator explorer")
left, right, third = st.columns([2, 1, 1])
search = left.text_input("Search indicator, source, event, malware", key="ioc_search")
all_types = sorted(iocs["indicator_type"].dropna().unique().tolist())
selected_types = right.multiselect("Indicator types", all_types, default=all_types)
source_options = sorted({s.strip() for val in iocs["sources"] for s in str(val).split(";") if s.strip()})
selected_sources = third.multiselect("Sources", source_options, default=source_options)
filtered = iocs[iocs["indicator_type"].isin(selected_types)].copy()
if selected_sources:
    filtered = filtered[filtered["sources"].apply(lambda v: any(s in str(v).split("; ") for s in selected_sources))]
if search:
    mask = filtered.apply(lambda col: col.astype(str).str.contains(search, case=False, na=False)).any(axis=1)
    filtered = filtered[mask]

only_multi = st.checkbox("Only indicators found in multiple sources", value=False)
if only_multi:
    filtered = filtered[filtered["multiple_sources"].str.lower().isin(["true", "1", "yes"])]
st.caption(f"Showing {len(filtered):,} of {len(iocs):,} unique indicators")
st.dataframe(filtered, use_container_width=True, hide_index=True, height=460)
st.download_button("Download filtered indicators CSV", filtered.to_csv(index=False).encode("utf-8"), "filtered_unified_indicators.csv", "text/csv")

st.subheader("Indicator type distribution")
if not iocs.empty:
    counts = iocs["indicator_type"].value_counts().rename_axis("Indicator type").reset_index(name="Count")
    st.bar_chart(counts.set_index("Indicator type"))

st.subheader("Run summary")
st.json(report)
