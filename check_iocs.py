import os
import json
import urllib3
from pathlib import Path
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

records = json.loads(
    Path("feodo_indicators.json").read_text(encoding="utf-8")
)

existing = 0
missing = 0
failed = 0

for record in records:
    ip = record["ip"]

    try:
        result = misp.search(
            controller="attributes",
            value=ip,
            pythonify=False,
        )

        attributes = result.get("Attribute", [])

        if attributes:
            existing += 1
            event_ids = sorted({
                str(a.get("event_id"))
                for a in attributes
                if a.get("event_id")
            })
            print(f"EXISTS: {ip} | Event IDs: {', '.join(event_ids)}")
        else:
            missing += 1
            print(f"NOT FOUND: {ip}")

    except Exception as error:
        failed += 1
        print(f"LOOKUP FAILED: {ip} | {type(error).__name__}")

print("\nSummary")
print("Existing:", existing)
print("Not found:", missing)
print("Failed lookups:", failed)
