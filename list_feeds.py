import os
import urllib3
from dotenv import load_dotenv
from pymisp import PyMISP

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

misp = PyMISP(
    os.getenv("MISP_URL"),
    os.getenv("MISP_API_KEY"),
    ssl=False,
    debug=False,
)

try:
    feeds = misp.feeds()
    print("MISP feeds retrieved:", len(feeds))

    for feed in feeds:
        print(
            "ID:", feed.get("Feed", {}).get("id"),
            "| Name:", feed.get("Feed", {}).get("name"),
            "| Enabled:", feed.get("Feed", {}).get("enabled"),
            "| Cached:", feed.get("Feed", {}).get("caching_enabled"),
        )

except Exception as error:
    print("Failed to retrieve MISP feeds.")
    print("Error type:", type(error).__name__)
