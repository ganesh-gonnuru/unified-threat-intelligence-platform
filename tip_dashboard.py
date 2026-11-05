#!/usr/bin/env python3
"""Unified Streamlit dashboard for configured MISP feeds and Feodo indicators.

Reads feed configuration live from MISP, local Feodo exports, and an optional
unified indicator CSV. Direct Feodo lookups use MISP's attribute search API.
This dashboard does not enable, fetch, or import feeds.
"""
from __future__ import annotations

import ipaddress
import json
import os
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
import urllib3
from dotenv import load_dotenv
from pymisp import PyMISP

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
MISP_URL = (os.getenv("MISP_URL") or "").rstrip("/")
MISP_KEY = os.getenv("MISP_API_KEY") or ""
VERIFY_TLS = os.getenv("MISP_VERIFY_TLS", "false").strip().lower() in {
    "1", "true", "yes", "on"
}

st.set_page_config(
    page_title="Unified Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
)

# TIP_CUSTOM_SOC_THEME
st.markdown("""
<style>
    :root {
        color-scheme: dark;
    }

    .stApp {
        background: #0b1120;
    }

    [data-testid="stHeader"] {
        background: rgba(11, 17, 32, 0.95);
    }

    [data-testid="stSidebar"] {
        background: #101a2b;
        border-right: 1px solid #26364b;
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2.5rem;
        max-width: 1600px;
    }

    h1, h2, h3 {
        color: #e6edf7 !important;
        letter-spacing: -0.02em;
    }

    p, label, .stCaption {
        color: #aabbd0;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #152238, #101a2b);
        border: 1px solid #2a3c54;
        border-radius: 12px;
        padding: 18px 20px;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.16);
    }

    [data-testid="stMetricLabel"] {
        color: #aabbd0 !important;
        font-size: 0.88rem;
    }

    [data-testid="stMetricValue"] {
        color: #48d9e8 !important;
        font-weight: 700;
    }

    [data-testid="stMetricDelta"] {
        font-size: 0.8rem;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #2a3c54;
    }

    .stTabs [data-baseweb="tab"] {
        background: #111d30;
        border: 1px solid #26364b;
        border-radius: 8px 8px 0 0;
        padding: 10px 16px;
    }

    .stTabs [aria-selected="true"] {
        background: #17354a !important;
        border-bottom: 2px solid #48d9e8 !important;
    }

    div.stButton > button,
    div.stDownloadButton > button {
        border-radius: 8px;
        border: 1px solid #347d91;
        background: #15374a;
        color: #e6faff;
        font-weight: 600;
        transition: 0.15s ease-in-out;
    }

    div.stButton > button:hover,
    div.stDownloadButton > button:hover {
        background: #20546a;
        border-color: #48d9e8;
        color: white;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #26364b;
        border-radius: 10px;
        overflow: hidden;
    }

    [data-testid="stAlert"] {
        border-radius: 10px;
    }

    hr {
        border-color: #26364b;
    }

    code {
        color: #72e3ed;
        background: #101a2b;
    }
</style>
""", unsafe_allow_html=True)
st.title("🛡️ Unified Threat Intelligence Platform")
st.caption("MISP feed inventory + indicators available in MISP + Feodo Tracker local data")

if not MISP_URL or not MISP_KEY:
    st.error("MISP_URL or MISP_API_KEY is missing. Check the existing .env file.")
    st.stop()

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@st.cache_resource
def get_misp() -> PyMISP:
    """Create a reusable PyMISP client from .env settings."""
    return PyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_TLS, debug=False)


def as_dict(item: Any) -> dict:
    """Convert PyMISP objects and wrapped objects to dictionaries."""
    if hasattr(item, "to_dict"):
        try:
            item = item.to_dict()
        except Exception:
            return {}
    if not isinstance(item, dict):
        return {}
    for wrapper in ("Feed", "Attribute"):
        if isinstance(item.get(wrapper), dict):
            return item[wrapper]
    return item


def normalize_feed_payload(payload: Any) -> list:
    """Normalize common PyMISP feed response structures."""
    if hasattr(payload, "to_dict"):
        try:
            payload = payload.to_dict()
        except Exception:
            pass
    if isinstance(payload, dict):
        for key in ("feeds", "Feed", "response"):
            if key not in payload:
                continue
            candidate = payload[key]
            if isinstance(candidate, dict):
                if any(k in candidate for k in ("id", "name", "url")):
                    return [candidate]
                candidate = list(candidate.values())
            if isinstance(candidate, list):
                return candidate
        if any(k in payload for k in ("id", "name", "url")):
            return [payload]
    if isinstance(payload, list):
        return payload
    return []


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


@st.cache_data(ttl=60, show_spinner="Loading configured MISP feeds...")
def load_feed_inventory() -> pd.DataFrame:
    misp = get_misp()
    try:
        payload = misp.feeds(pythonify=False)
    except TypeError:
        payload = misp.feeds()
    items = normalize_feed_payload(payload)
    rows = []
    for raw in items:
        feed = as_dict(raw)
        if not feed:
            continue
        rows.append({
            "Feed ID": str(feed.get("id", "")),
            "Feed Name": str(feed.get("name", "")),
            "Provider URL": str(feed.get("url", "")),
            "Enabled": truthy(feed.get("enabled", False)),
            "Caching Enabled": truthy(feed.get("caching_enabled", False)),
            "Source Format": str(feed.get("source_format", "")),
            "Provider": str(feed.get("provider", "")),
            "Provider Network": str(feed.get("provider_network", "")),
        })
    # Remove duplicate representations of the same feed, preserving blank IDs.
    seen, unique = set(), []
    for row in rows:
        identity = ("id", row["Feed ID"]) if row["Feed ID"] else (
            "name_url", row["Feed Name"], row["Provider URL"]
        )
        if identity not in seen:
            seen.add(identity)
            unique.append(row)
    return pd.DataFrame(unique, columns=[
        "Feed ID", "Feed Name", "Provider URL", "Enabled",
        "Caching Enabled", "Source Format", "Provider", "Provider Network",
    ])


def normalize_indicator(value: Any) -> str:
    """Normalize IPs/CIDRs consistently; retain lowercase text for other values."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text.lower().rstrip(".")


def load_feodo() -> pd.DataFrame:
    """Load local Feodo JSON, falling back to its CSV export."""
    json_path = BASE / "feodo_indicators.json"
    csv_path = BASE / "feodo_feed.csv"
    records = []
    source_file = ""

    if json_path.exists():
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                for key in ("indicators", "data", "records", "results"):
                    if isinstance(payload.get(key), list):
                        records = payload[key]
                        break
                if not records and any(k in payload for k in ("ip", "dst_ip", "value")):
                    records = [payload]
            elif isinstance(payload, list):
                records = payload
            if records:
                source_file = json_path.name
        except Exception as exc:
            st.warning(f"Could not read {json_path.name}: {exc}")

    if not records and csv_path.exists():
        try:
            records = pd.read_csv(csv_path, dtype=str).fillna("").to_dict("records")
            source_file = csv_path.name
        except Exception as exc:
            st.warning(f"Could not read {csv_path.name}: {exc}")

    rows = []
    for record in records:
        if not isinstance(record, dict):
            continue
        value = str(
            record.get("dst_ip") or record.get("ip") or record.get("value")
            or record.get("indicator") or ""
        ).strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        rows.append({
            "indicator": value,
            "normalized_indicator": str(network),
            "indicator_type": "ip" if network.prefixlen == network.max_prefixlen else "cidr",
            "source": "Feodo Tracker",
            "malware": str(record.get("malware", "")),
            "c2_status": str(record.get("c2_status", "")),
            "first_seen_utc": str(record.get("first_seen_utc", "")),
            "last_online": str(record.get("last_online", "")),
            "source_file": source_file,
        })
    return pd.DataFrame(rows)


def load_unified_existing() -> pd.DataFrame:
    path = BASE / "unified_indicators.csv"
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, dtype=str).fillna("")
    except Exception as exc:
        st.warning(f"Could not read unified_indicators.csv: {exc}")
        return pd.DataFrame()


def extract_attributes(payload: Any) -> list[dict]:
    """Extract attributes from known MISP/PyMISP API response wrappers."""
    if hasattr(payload, "to_dict"):
        try:
            payload = payload.to_dict()
        except Exception:
            pass
    if isinstance(payload, list):
        found = []
        for item in payload:
            found.extend(extract_attributes(item))
        return found
    if not isinstance(payload, dict):
        return []
    for key in ("Attribute", "attributes"):
        value = payload.get(key)
        if isinstance(value, list):
            return [as_dict(x) for x in value if as_dict(x)]
        if isinstance(value, dict):
            # One attribute or a dictionary keyed by attribute ID.
            if "value" in value or "type" in value:
                return [value]
            return [as_dict(x) for x in value.values() if as_dict(x)]
    for key in ("response", "data"):
        if key in payload:
            found = extract_attributes(payload[key])
            if found:
                return found
    if "value" in payload and "type" in payload:
        return [payload]
    return []


@st.cache_data(ttl=300, show_spinner=False)
def check_feodo_in_misp(values_tuple: tuple[str, ...]) -> tuple[pd.DataFrame, list[str]]:
    """Search each Feodo value and return all exact matches with event metadata."""
    misp = get_misp()
    rows: list[dict] = []
    errors: list[str] = []

    for requested_value in values_tuple:
        value = str(requested_value).strip()
        if not value:
            continue
        try:
            # This is the same PyMISP attribute-search form that was confirmed
            # to return events 1775 and 1779 for 50.16.16.211.
            try:
                response = misp.search(
                    controller="attributes", value=value, pythonify=False
                )
            except TypeError:
                response = misp.search(controller="attributes", value=value)

            attributes = extract_attributes(response)
            target = normalize_indicator(value)
            for attribute in attributes:
                attr_value = str(attribute.get("value", "")).strip()
                if normalize_indicator(attr_value) != target:
                    continue
                event = attribute.get("Event") or attribute.get("event") or {}
                if not isinstance(event, dict):
                    event = {}
                event_id = str(event.get("id") or attribute.get("event_id") or "")
                event_name = str(event.get("info") or event.get("name") or "")
                rows.append({
                    "Feodo Indicator": value,
                    "MISP Attribute Value": attr_value,
                    "MISP Attribute Type": str(attribute.get("type", "")),
                    "MISP Event ID": event_id,
                    "MISP Event Name": event_name,
                    "MISP Attribute ID": str(attribute.get("id", "")),
                })
        except Exception as exc:
            errors.append(f"{value}: {type(exc).__name__}: {exc}")

    columns = [
        "Feodo Indicator", "MISP Attribute Value", "MISP Attribute Type",
        "MISP Event ID", "MISP Event Name", "MISP Attribute ID",
    ]
    matches = pd.DataFrame(rows, columns=columns)
    if not matches.empty:
        matches = matches.drop_duplicates(
            subset=["Feodo Indicator", "MISP Attribute ID", "MISP Event ID"]
        ).reset_index(drop=True)
    return matches, errors


# Acquire data. A feed inventory failure should not silently look like zero feeds.
try:
    feeds = load_feed_inventory()
except Exception as exc:
    st.error(f"Could not retrieve MISP feeds: {type(exc).__name__}: {exc}")
    st.stop()

feodo = load_feodo()
unified = load_unified_existing()

# Summary metrics
m1, m2, m3, m4 = st.columns(4)
m1.metric("Configured MISP feeds", f"{len(feeds):,}")
m2.metric("Enabled feeds", f"{int(feeds['Enabled'].sum()) if not feeds.empty else 0:,}")
m3.metric("Feodo indicators loaded", f"{len(feodo):,}")
m4.metric("Existing unified indicators", f"{len(unified):,}")

if not VERIFY_TLS:
    st.info(
        "Lab TLS mode: certificate verification is disabled for the self-signed "
        "MISP certificate. Use a trusted certificate and set MISP_VERIFY_TLS=true "
        "outside the lab."
    )

feed_tab, indicator_tab, feodo_tab, match_tab, status_tab = st.tabs([
    "MISP Feeds", "MISP / Unified Indicators", "Feodo Tracker",
    "Feodo ↔ MISP Matches", "System Status",
])

with feed_tab:
    st.subheader("Configured MISP feed inventory")
    st.caption("These are feed definitions configured in MISP. Enabled does not necessarily mean successfully imported or current.")
    query = st.text_input("Search feed name, provider, URL or ID", key="feed_q")
    status = st.selectbox("Feed status", ["All", "Enabled", "Disabled"], key="feed_status")
    view_feeds = feeds.copy()
    if query and not view_feeds.empty:
        mask = view_feeds.astype(str).apply(
            lambda column: column.str.contains(query, case=False, na=False, regex=False)
        ).any(axis=1)
        view_feeds = view_feeds[mask]
    if status == "Enabled":
        view_feeds = view_feeds[view_feeds["Enabled"]]
    elif status == "Disabled":
        view_feeds = view_feeds[~view_feeds["Enabled"]]
    st.write(f"Showing **{len(view_feeds):,}** of **{len(feeds):,}** configured feeds.")
    st.dataframe(
        view_feeds, use_container_width=True, hide_index=True, height=520,
        column_config={"Provider URL": st.column_config.LinkColumn("Provider URL", validate="^https?://")},
    )
    st.download_button(
        "Download MISP feed inventory", feeds.to_csv(index=False).encode("utf-8"),
        "misp_feed_inventory.csv", "text/csv",
    )

with indicator_tab:
    st.subheader("Indicators already exported from MISP")
    if unified.empty:
        st.warning("No unified_indicators.csv found. Run the existing unified ingestion script first.")
    else:
        report_path = BASE / "unified_tip_report.json"
        if report_path.exists():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                if report.get("misp_bulk_retrieval_complete") is False or report.get("misp_retrieval_limit_reached") is True:
                    st.warning("The current MISP export is incomplete because the retrieval safety limit was reached.")
            except Exception:
                pass
        search = st.text_input("Search indicator, event, source or malware", key="unified_q")
        if "indicator_type" in unified.columns:
            types = sorted(unified["indicator_type"].dropna().unique().tolist())
            selected_types = st.multiselect("Indicator types", types, default=types)
            view = unified[unified["indicator_type"].isin(selected_types)].copy()
        else:
            view = unified.copy()
        if search:
            mask = view.astype(str).apply(
                lambda column: column.str.contains(search, case=False, na=False, regex=False)
            ).any(axis=1)
            view = view[mask]
        st.write(f"Showing **{len(view):,}** rows of **{len(unified):,}** exported indicators.")
        st.dataframe(view.head(10000), use_container_width=True, hide_index=True, height=480)
        if len(view) > 10000:
            st.caption("Preview limited to 10,000 rows for browser performance; CSV download contains all filtered rows.")
        st.download_button(
            "Download filtered indicators", view.to_csv(index=False).encode("utf-8"),
            "filtered_unified_indicators.csv", "text/csv",
        )

with feodo_tab:
    st.subheader("Feodo Tracker indicators")
    if feodo.empty:
        st.warning("No Feodo local export found. Expected feodo_indicators.json or feodo_feed.csv in the project folder.")
    else:
        if "malware" in feodo.columns:
            malware_values = sorted(x for x in feodo["malware"].unique() if x)
            selected_malware = st.multiselect("Malware family", malware_values, default=malware_values)
            view = feodo[feodo["malware"].isin(selected_malware)] if selected_malware else feodo.iloc[0:0]
        else:
            view = feodo.copy()
        st.dataframe(view, use_container_width=True, hide_index=True)
        st.download_button(
            "Download Feodo indicators", feodo.to_csv(index=False).encode("utf-8"),
            "feodo_indicators_dashboard.csv", "text/csv",
        )
        if "malware" in feodo.columns and not feodo.empty:
            st.subheader("Feodo malware families")
            st.bar_chart(feodo["malware"].replace("", "Unknown").value_counts())

with match_tab:
    st.subheader("Exact Feodo indicator lookup against MISP")
    st.caption("Each selected Feodo IP is queried directly through MISP's attribute search API; this is independent of bulk pagination.")
    if feodo.empty:
        st.warning("No Feodo indicators are available to check.")
    else:
        max_checks = st.slider(
            "Maximum Feodo indicators to check per run", min_value=1,
            max_value=max(1, min(100, len(feodo))), value=min(5, len(feodo)),
        )
        if st.button("Check Feodo indicators in MISP", type="primary"):
            # Use original indicator values for exact API search. Normalized CIDRs
            # are retained for display but may differ from stored attribute values.
            values = tuple(feodo["indicator"].drop_duplicates().head(max_checks).tolist())
            with st.spinner(f"Checking {len(values)} indicators against MISP..."):
                matches, errors = check_feodo_in_misp(values)
            st.session_state["feodo_misp_matches"] = matches
            st.session_state["feodo_misp_errors"] = errors
            st.session_state["feodo_misp_checked"] = list(values)
        if "feodo_misp_matches" in st.session_state:
            matches = st.session_state["feodo_misp_matches"]
            errors = st.session_state.get("feodo_misp_errors", [])
            matched_values = matches["Feodo Indicator"].nunique() if not matches.empty else 0
            c1, c2, c3 = st.columns(3)
            c1.metric("Indicators with exact matches", f"{matched_values:,}")
            c2.metric("Matching MISP attributes", f"{len(matches):,}")
            c3.metric("Lookup errors", f"{len(errors):,}")
            if not matches.empty:
                st.dataframe(matches, use_container_width=True, hide_index=True)
                st.download_button(
                    "Download exact matches", matches.to_csv(index=False).encode("utf-8"),
                    "feodo_misp_exact_matches.csv", "text/csv",
                )
            else:
                st.info("No exact matches were returned for the checked indicators. This does not prove that all Feodo indicators are absent from MISP.")
            if errors:
                with st.expander("Lookup errors"):
                    st.code("\n".join(errors))

with status_tab:
    st.subheader("Local pipeline status")
    report_path = BASE / "unified_tip_report.json"
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            keys = [
                "started_at_utc", "completed_at_utc", "configured_misp_feeds",
                "misp_attributes_retrieved", "misp_bulk_pages_fetched",
                "misp_retrieval_limit_reached", "misp_bulk_retrieval_complete",
                "feodo_records_read", "feodo_indicators_with_exact_misp_matches",
                "indicators_in_multiple_sources", "feed_inventory_error",
                "misp_attribute_error", "notes",
            ]
            st.json({key: report.get(key) for key in keys if key in report})
            if report.get("misp_bulk_retrieval_complete") is False or report.get("misp_retrieval_limit_reached") is True:
                st.warning("Bulk MISP indicator export is incomplete. Feed inventory may still be complete.")
        except Exception as exc:
            st.warning(f"Could not parse unified_tip_report.json: {exc}")
    else:
        st.info("No unified_tip_report.json found yet. Feed inventory and local Feodo data can still be viewed.")
    st.write("Dashboard data loaded at (UTC):", datetime.now(timezone.utc).isoformat())
    if st.button("Refresh cached MISP feed data"):
        st.cache_data.clear()
        st.rerun()

st.divider()
st.caption("This dashboard displays configured feed definitions and locally available indicator exports. It does not enable, fetch, or import external MISP feeds automatically.")
