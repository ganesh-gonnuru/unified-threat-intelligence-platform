import os
import urllib3
from collections import Counter
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

event_id = 1779

try:
    result = misp.get_event(event_id, pythonify=False)
    event = result.get("Event", result)

    attributes = event.get("Attribute", [])

    type_counts = Counter(
        attribute.get("type", "unknown")
        for attribute in attributes
    )

    print("Event:", event.get("info"))
    print("Total attributes:", len(attributes))
    print("\nAttribute counts by type:")

    for attribute_type, count in type_counts.most_common():
        print(f"{attribute_type}: {count}")

    ip_attributes = [
        attribute
        for attribute in attributes
        if attribute.get("type") in ("ip-src", "ip-dst")
    ]

    print("\nIP-related attributes:", len(ip_attributes))
    print("Sample IP-related values:")

    for attribute in ip_attributes[:10]:
        print(
            attribute.get("type"),
            "|",
            attribute.get("value")
        )

except Exception as error:
    print("Failed to inspect FireHOL attributes.")
    print("Error type:", type(error).__name__)
    print("Error:", str(error))
