import os
import urllib3
from dotenv import load_dotenv
from pymisp import PyMISP

load_dotenv()

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

misp = PyMISP(
    os.getenv("MISP_URL"),
    os.getenv("MISP_API_KEY"),
    ssl=False,
    debug=False,
)

feed_id = 14

try:
    feed = misp.get_feed(feed_id)

    if isinstance(feed, dict) and "Feed" in feed:
        feed = feed["Feed"]

    print("Feed ID:", feed.get("id"))
    print("Feed name:", feed.get("name"))
    print("Provider URL:", feed.get("url"))
    print("Enabled:", feed.get("enabled"))
    print("Cached:", feed.get("caching_enabled"))
    print("Source format:", feed.get("source_format"))

except Exception as error:
    print("Failed to inspect feed.")
    print("Error type:", type(error).__name__)
