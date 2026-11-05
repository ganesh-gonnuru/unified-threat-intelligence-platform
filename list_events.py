import os
import urllib3
from dotenv import load_dotenv
from pymisp import PyMISP

load_dotenv()

misp_url = os.getenv("MISP_URL")
misp_key = os.getenv("MISP_API_KEY")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

misp = PyMISP(
    misp_url,
    misp_key,
    ssl=False,
    debug=False,
)

try:
    events = misp.search_index(limit=5)

    if not events:
        print("Connection successful, but no events were returned.")
    else:
        print(f"Retrieved {len(events)} event(s):\n")

        for event in events:
            print("Event ID:", event.get("id", "N/A"))
            print("Information:", event.get("info", "N/A"))
            print("-" * 40)

except Exception as error:
    print("Failed to retrieve events.")
    print("Error type:", type(error).__name__)
    print("Check your API permissions and MISP logs.")
