#!/usr/bin/env python3
"""Unified Threat Intelligence Platform dashboard.

Displays configured MISP feeds, normalized MISP indicators, CISA KEV records,
local Feodo Tracker data, exact Feodo-to-MISP matches, and ingestion status.
This dashboard does not enable, fetch, or import MISP feeds.
"""
from __future__ import annotations

import ipaddress
import json
import os
import warnings

import requests
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
    initial_sidebar_state="expanded",
)

# Visual system: dark SOC-style canvas, restrained cyan accents, clear hierarchy.
st.markdown("""
<style>
:root { --tip-bg: #0b1220; --tip-panel: #111c2e; --tip-border: #24344b; --tip-cyan: #48d9e8; --tip-muted: #94a9c4; }
.stApp { background: radial-gradient(ellipse at 12% 0%, #152b46 0%, #0b1220 42%, #080e18 100%); }
[data-testid="stHeader"] { background: rgba(8,14,24,0.82); }
.block-container { padding-top: 1.6rem; padding-bottom: 2.8rem; max-width: 1600px; }
.tip-hero { padding: 1.5rem 1.7rem; border: 1px solid #263c55; border-radius: 18px; background: linear-gradient(115deg, rgba(20,43,68,.97), rgba(13,25,42,.96) 58%, rgba(11,31,45,.96)); box-shadow: 0 16px 44px rgba(0,0,0,.20); margin-bottom: 1.2rem; }
.tip-eyebrow { color: #48d9e8; font-size: .76rem; font-weight: 800; letter-spacing: .18em; text-transform: uppercase; margin-bottom: .55rem; }
.tip-title { color: #f2f7ff; font-size: clamp(1.65rem, 3vw, 2.55rem); font-weight: 780; letter-spacing: -.035em; line-height: 1.1; margin: 0; }
.tip-subtitle { color: #a9bdd5; font-size: 1rem; margin-top: .65rem; margin-bottom: .9rem; }
.tip-pills { display:flex; gap:.5rem; flex-wrap:wrap; }
.tip-pill { color:#d8faff; border:1px solid #2a6678; background:rgba(25,105,125,.19); border-radius:999px; padding:.28rem .65rem; font-size:.75rem; font-weight:650; }
[data-testid="stMetric"] { background: linear-gradient(145deg, rgba(19,32,51,.96), rgba(14,24,39,.96)); border: 1px solid #26384e; border-radius: 14px; padding: 1rem 1.05rem; box-shadow: 0 8px 24px rgba(0,0,0,.13); min-height: 112px; }
[data-testid="stMetricLabel"] { color:#a8bad0 !important; font-size:.83rem !important; }
[data-testid="stMetricValue"] { color:#f3f8ff !important; font-weight:760; }
[data-testid="stMetricDelta"] { font-size:.78rem; }
.stTabs [data-baseweb="tab-list"] { gap:.35rem; border-bottom:1px solid #26384e; }
.stTabs [data-baseweb="tab"] { background:rgba(17,28,46,.75); border:1px solid transparent; border-radius:9px 9px 0 0; padding:.65rem .9rem; color:#a9bdd5; }
.stTabs [aria-selected="true"] { background:#17304a !important; color:#eafcff !important; border-color:#2c6477 !important; }
.stTabs [data-baseweb="tab-highlight"] { background-color:#48d9e8; }
h1, h2, h3 { letter-spacing:-.025em; }
h2, h3 { color:#e8f2ff; }
[data-testid="stDataFrame"] { border:1px solid #26384e; border-radius:12px; overflow:hidden; }
.stButton > button, .stDownloadButton > button { border-radius:9px; font-weight:650; border:1px solid #2c6477; transition:all .15s ease; }
.stButton > button[kind="primary"] { background:linear-gradient(100deg,#167e94,#24a9b5); color:white; border:0; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color:#48d9e8; color:#eaffff; }
[data-testid="stAlert"] { border-radius:10px; }
hr { border-color:#26384e; }
footer { visibility:hidden; }
@media (max-width: 800px) { .tip-hero { padding:1.1rem; } .tip-subtitle { font-size:.9rem; } }
</style>
<div class="tip-hero">
  <div class="tip-eyebrow">Security Operations · Threat Intelligence</div>
  <div class="tip-title">Unified Threat Intelligence Platform</div>
  <div class="tip-subtitle">Collect, normalize, explore, and correlate threat indicators and exploited-vulnerability intelligence.</div>
  <div class="tip-pills"><span class="tip-pill">MISP</span><span class="tip-pill">CISA KEV</span><span class="tip-pill">Feodo Tracker</span><span class="tip-pill">IOC Correlation</span></div>
</div>
""", unsafe_allow_html=True)

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


def load_cisa_kev() -> pd.DataFrame:
    """Load the separately maintained CISA KEV CSV export."""
    path = BASE / "cisa_kev.csv"
    if not path.exists():
        return pd.DataFrame()
    try:
        frame = pd.read_csv(path, dtype=str).fillna("")
        if "cve_id" in frame.columns:
            frame = frame.drop_duplicates(subset=["cve_id"], keep="last")
        return frame
    except Exception as exc:
        st.warning(f"Could not read cisa_kev.csv: {exc}")
        return pd.DataFrame()


def load_report() -> dict:
    """Read the latest ingestion report without making it a dashboard prerequisite."""
    path = BASE / "unified_tip_report.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        st.warning(f"Could not read unified_tip_report.json: {exc}")
        return {}


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


# Load each source independently so a feed inventory issue does not hide local data.
feed_error = None
try:
    feeds = load_feed_inventory()
except Exception as exc:
    feeds = pd.DataFrame(columns=[
        "Feed ID", "Feed Name", "Provider URL", "Enabled", "Caching Enabled",
        "Source Format", "Provider", "Provider Network",
    ])
    feed_error = f"{type(exc).__name__}: {exc}"

feodo = load_feodo()
unified = load_unified_existing()
cisa_kev = load_cisa_kev()
report = load_report()

# Executive summary metrics
st.markdown("### Platform snapshot")
st.caption("Live MISP feed metadata and the latest locally exported intelligence datasets.")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Configured MISP feeds", f"{len(feeds):,}" if not feed_error else "Unavailable")
m2.metric("Enabled feeds", f"{int(feeds['Enabled'].sum()) if not feeds.empty else 0:,}")
m3.metric("Unique MISP indicators", f"{len(unified):,}")
m4.metric("CISA KEV vulnerabilities", f"{len(cisa_kev):,}")
m5.metric("Feodo indicators", f"{len(feodo):,}")

if feed_error:
    st.warning(f"MISP feed inventory could not be loaded: {feed_error}. The displayed feed count is unavailable, not zero.")
if report.get("misp_retrieval_limit_reached") is True or report.get("misp_bulk_retrieval_complete") is False:
    st.warning("The latest MISP indicator export may be incomplete. See System Status for the ingestion report.")

if not VERIFY_TLS:
    st.info(
        "Lab TLS mode: certificate verification is disabled for the self-signed "
        "MISP certificate. Use a trusted certificate and set MISP_VERIFY_TLS=true "
        "outside the lab."
    )

overview_tab, feed_tab, indicator_tab, cisa_tab, feodo_tab, match_tab, status_tab = st.tabs([
    "Overview", "MISP Feeds", "Unified Indicators", "CISA KEV",
    "Feodo Tracker", "Feodo ↔ MISP Matches", "System Status",
])

with overview_tab:
    st.subheader("Threat intelligence overview")
    left, right = st.columns(2)
    with left:
        st.markdown("**Indicator types**")
        if not unified.empty:
            kind_col = "indicator_kind" if "indicator_kind" in unified.columns else ("type" if "type" in unified.columns else None)
            if kind_col:
                kind_counts = unified[kind_col].replace("", "unknown").value_counts().head(12)
                st.bar_chart(kind_counts)
            else:
                st.info("The unified indicator export does not contain an indicator-type column.")
        else:
            st.info("No unified indicator export is available yet.")
    with right:
        st.markdown("**Source and pipeline status**")
        st.write("MISP feed inventory:", "Error" if feed_error else ("Loaded" if not feeds.empty else "No feed records returned"))
        st.write("Unified indicator CSV:", "Available" if not unified.empty else "Missing or empty")
        st.write("CISA KEV CSV:", "Available" if not cisa_kev.empty else "Missing or empty")
        st.write("Feodo local data:", "Available" if not feodo.empty else "Missing or empty")
        if report:
            st.write("Last ingestion start (UTC):", report.get("started_at_utc", "Not recorded"))
            st.write("MISP retrieval complete:", report.get("misp_bulk_retrieval_complete", "Unknown"))
        else:
            st.info("No ingestion report found. Run the ingestion pipeline to populate status metadata.")

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

with cisa_tab:
    st.subheader("CISA Known Exploited Vulnerabilities (KEV)")
    st.caption("CISA KEV is vulnerability intelligence and is kept separate from MISP indicators.")
    if cisa_kev.empty:
        st.warning("No CISA KEV data found. Run the ingestion script to create cisa_kev.csv.")
    else:
        q = st.text_input("Search CVE, product, vendor, vulnerability or required action", key="cisa_q")
        view_kev = cisa_kev.copy()
        if "known_ransomware_campaign_use" in view_kev.columns:
            ransomware_filter = st.selectbox("Known ransomware campaign use", ["All", "Known", "Unknown"], key="kev_ransomware")
            if ransomware_filter == "Known":
                view_kev = view_kev[view_kev["known_ransomware_campaign_use"].str.lower().eq("known")]
            elif ransomware_filter == "Unknown":
                view_kev = view_kev[~view_kev["known_ransomware_campaign_use"].str.lower().eq("known")]
        if q:
            mask = view_kev.astype(str).apply(lambda col: col.str.contains(q, case=False, na=False, regex=False)).any(axis=1)
            view_kev = view_kev[mask]
        if "vendor_project" in view_kev.columns:
            vendors = sorted(x for x in view_kev["vendor_project"].dropna().unique().tolist() if x)
            selected_vendors = st.multiselect("Vendor / project", vendors, key="kev_vendors")
            if selected_vendors:
                view_kev = view_kev[view_kev["vendor_project"].isin(selected_vendors)]
        st.write(f"Showing **{len(view_kev):,}** of **{len(cisa_kev):,}** KEV records.")
        columns = [c for c in ["cve_id", "vendor_project", "product", "vulnerability_name", "date_added", "due_date", "known_ransomware_campaign_use", "required_action", "cwes"] if c in view_kev.columns]
        st.dataframe(view_kev[columns] if columns else view_kev, use_container_width=True, hide_index=True, height=520)
        st.download_button("Download filtered CISA KEV records", view_kev.to_csv(index=False).encode("utf-8"), "filtered_cisa_kev.csv", "text/csv")

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
    if report:
        keys = [
            "generated_at_utc", "started_at_utc", "completed_at_utc",
            "configured_misp_feeds", "feed_inventory_error",
            "cisa_kev_records_retrieved", "cisa_kev_error",
            "misp_attributes_seen_from_api", "misp_attributes_retrieved",
            "misp_attributes_unique_by_id_or_fallback", "misp_bulk_pages_fetched",
            "misp_retrieval_limit_reached", "misp_bulk_retrieval_complete",
            "misp_retrieval_error", "unique_indicators_written",
            "normalized_attributes_processed", "notes",
        ]
        st.json({key: report.get(key) for key in keys if key in report})
        if report.get("misp_bulk_retrieval_complete") is False or report.get("misp_retrieval_limit_reached") is True:
            st.warning("Bulk MISP indicator export is incomplete. Some indicators may be missing from the current CSV.")
        if report.get("feed_inventory_error"):
            st.warning("The ingestion report records a feed inventory error. Verify the MISP API response and permissions.")
    else:
        st.info("No unified_tip_report.json found yet. Run the ingestion pipeline to populate status metadata.")
    st.write("Dashboard data loaded at (UTC):", datetime.now(timezone.utc).isoformat())
    if st.button("Refresh dashboard data"):
        st.cache_data.clear()
        st.cache_resource.clear()
        st.rerun()



# Global IP geolocation map. Lookups are opt-in and capped to avoid sending the
# entire indicator dataset to a third-party service or triggering excessive requests.
@st.cache_data(ttl=86400, show_spinner=False)
def geolocate_public_ip(ip: str) -> dict | None:
    try:
        response = requests.get(f"https://ipwho.is/{ip}", timeout=8)
        response.raise_for_status()
        data = response.json()
        if not data.get("success", False):
            return None
        latitude, longitude = data.get("latitude"), data.get("longitude")
        if latitude is None or longitude is None:
            return None
        return {
            "ip": ip,
            "latitude": float(latitude),
            "longitude": float(longitude),
            "country": str(data.get("country") or "Unknown"),
            "region": str(data.get("region") or ""),
            "city": str(data.get("city") or ""),
            "isp": str((data.get("connection") or {}).get("isp") or ""),
        }
    except (requests.RequestException, ValueError, TypeError):
        return None


st.divider()
st.markdown("## 🌐 Global threat indicator map")
st.caption(
    "Approximate geolocation of selected public IP indicators in the current unified export. "
    "IP geolocation indicates the likely network endpoint location—not necessarily the attacker, "
    "victim, or physical location of an event."
)

if unified.empty:
    st.info("The map will be available after unified_indicators.csv contains data.")
else:
    ip_column = "normalized_indicator" if "normalized_indicator" in unified.columns else "indicator"
    kind_column = "indicator_kind" if "indicator_kind" in unified.columns else "type"
    if ip_column not in unified.columns:
        st.info("The current indicator export does not contain a recognized indicator column.")
    else:
        candidate_values = unified[ip_column].dropna().astype(str).drop_duplicates().tolist()
        public_ips = []
        for candidate in candidate_values:
            try:
                parsed = ipaddress.ip_address(candidate.strip())
                if parsed.is_global:
                    public_ips.append(str(parsed))
            except ValueError:
                continue
        public_ips = list(dict.fromkeys(public_ips))
        st.write(f"Public IP indicators available for mapping: **{len(public_ips):,}**")
        st.warning(
            "When you click the lookup button, up to 50 public IP addresses are sent to "
            "ipwho.is for geolocation. Do not use this feature if your data-sharing policy "
            "prohibits sending indicators to an external service. Private, reserved, and "
            "non-IP indicators are excluded."
        )
        max_map_ips = st.slider(
            "Maximum public IPs to geolocate", min_value=1,
            max_value=max(1, min(50, len(public_ips))),
            value=max(1, min(20, len(public_ips))), key="map_ip_limit",
            disabled=not public_ips,
        )
        if st.button("Build world threat map", type="primary", disabled=not public_ips):
            mapped_rows = []
            with st.spinner("Looking up approximate locations for selected public IPs..."):
                for ip in public_ips[:max_map_ips]:
                    result = geolocate_public_ip(ip)
                    if result:
                        mapped_rows.append(result)
            st.session_state["tip_geo_map_rows"] = mapped_rows
            st.session_state["tip_geo_map_requested"] = max_map_ips

        if "tip_geo_map_rows" in st.session_state:
            geo_df = pd.DataFrame(st.session_state["tip_geo_map_rows"])
            requested = st.session_state.get("tip_geo_map_requested", 0)
            if geo_df.empty:
                st.info("No geolocation results were returned. Check network access or try a smaller selection later.")
            else:
                try:
                    import plotly.express as px
                    country_counts = geo_df.groupby("country", as_index=False).agg(
                        indicator_count=("ip", "count"),
                        latitude=("latitude", "mean"),
                        longitude=("longitude", "mean"),
                    )
                    fig = px.scatter_geo(
                        geo_df, lat="latitude", lon="longitude",
                        hover_name="ip", hover_data={
                            "country": True, "region": True, "city": True, "isp": True,
                            "latitude": False, "longitude": False,
                        },
                        color="country", size=[1] * len(geo_df),
                        projection="natural earth",
                        title="Approximate locations of public IP indicators",
                    )
                    fig.update_geos(
                        showland=True, landcolor="#142338",
                        showocean=True, oceancolor="#08111e",
                        showcountries=True, countrycolor="#33465e",
                        showcoastlines=True, coastlinecolor="#526780",
                        bgcolor="rgba(0,0,0,0)",
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e8f2ff",
                        height=560, margin=dict(l=0, r=0, t=55, b=0),
                        legend_title_text="Country",
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    m1, m2, m3 = st.columns(3)
                    m1.metric("IPs mapped", f"{len(geo_df):,}")
                    m2.metric("Countries represented", f"{geo_df['country'].nunique():,}")
                    m3.metric("Lookups without a result", f"{max(0, requested - len(geo_df)):,}")
                    st.dataframe(geo_df, use_container_width=True, hide_index=True)
                    st.download_button(
                        "Download geolocation results",
                        geo_df.to_csv(index=False).encode("utf-8"),
                        "threat_ip_geolocations.csv", "text/csv",
                    )
                except ImportError:
                    st.error("Plotly is not installed in this virtual environment. Install it with: pip install plotly")

st.divider()
st.caption("This dashboard displays configured MISP feed definitions and locally ingested intelligence. It does not enable, fetch, or import external MISP feeds automatically.")
