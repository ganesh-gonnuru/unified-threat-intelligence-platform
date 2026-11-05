
import os
import urllib3
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from pymisp import PyMISP

load_dotenv()

st.set_page_config(
    page_title="MISP Feed Inventory",
    page_icon="🛡️",
    layout="wide"
)

st.title("MISP Feed Inventory")
st.caption("Configured threat intelligence feeds from your MISP instance")

@st.cache_data(ttl=60)
def load_feeds():
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )

    misp = PyMISP(
        os.getenv("MISP_URL"),
        os.getenv("MISP_API_KEY"),
        ssl=False,
        debug=False
    )

    result = misp.feeds()
    if isinstance(result, dict):
        feeds = result.get("feeds", result.get("Feed", []))
    else:
        feeds = result

    if isinstance(feeds, dict):
        feeds = [feeds]

    rows = []
    for item in feeds:
        feed = item.get("Feed", item) if isinstance(item, dict) else {}
        if not isinstance(feed, dict):
            continue

        rows.append({
            "Feed ID": feed.get("id", ""),
            "Feed Name": feed.get("name", ""),
            "Provider URL": feed.get("url", ""),
            "Enabled": str(feed.get("enabled", "")).lower()
                        in ("1", "true", "yes"),
            "Caching Enabled": str(
                feed.get("caching_enabled", "")
            ).lower() in ("1", "true", "yes"),
            "Source Format": feed.get("source_format", ""),
            "Provider": feed.get("provider", "")
        })

    return pd.DataFrame(rows)

try:
    df = load_feeds()

    if df.empty:
        st.warning("MISP returned no configured feeds.")
        st.stop()

    col1, col2, col3 = st.columns(3)
    col1.metric("Configured Feeds", len(df))
    col2.metric("Enabled Feeds", int(df["Enabled"].sum()))
    col3.metric("Disabled Feeds", int((~df["Enabled"]).sum()))

    search = st.text_input("Search feeds", placeholder="Enter a feed name or URL")

    status = st.selectbox(
        "Filter by status",
        ["All", "Enabled", "Disabled"]
    )

    filtered = df.copy()

    if search:
        mask = (
            filtered["Feed Name"].str.contains(
                search, case=False, na=False
            )
            | filtered["Provider URL"].str.contains(
                search, case=False, na=False
            )
            | filtered["Provider"].str.contains(
                search, case=False, na=False
            )
        )
        filtered = filtered[mask]

    if status == "Enabled":
        filtered = filtered[filtered["Enabled"]]
    elif status == "Disabled":
        filtered = filtered[~filtered["Enabled"]]

    st.subheader(f"Feeds ({len(filtered)})")

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Provider URL": st.column_config.LinkColumn(
                "Provider URL",
                validate="^https?://"
            )
        }
    )

    st.download_button(
        "Download feed inventory CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="misp_feed_inventory.csv",
        mime="text/csv"
    )

    st.caption(
        "This page displays configured feeds only. "
        "Enabled status does not guarantee that indicators "
        "have been imported or are up to date."
    )

except Exception as error:
    st.error("Could not load feeds from MISP.")
    st.code(f"{type(error).__name__}: {error}")
