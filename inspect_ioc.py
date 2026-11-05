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

ip = "162.243.103.246"

try:
    result = misp.search(
        controller="attributes",
        value=ip,
        pythonify=False,
    )

    attributes = result.get("Attribute", [])

    for attribute in attributes:
        print("Value:", attribute.get("value"))
        print("Type:", attribute.get("type"))
        print("Category:", attribute.get("category"))
        print("Event ID:", attribute.get("event_id"))
        print("Comment:", attribute.get("comment"))
        print("To IDS:", attribute.get("to_ids"))
        print("-" * 35)

except Exception as error:
    print("Lookup failed:", type(error).__name__)
