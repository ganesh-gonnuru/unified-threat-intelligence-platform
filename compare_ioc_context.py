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

report = []

for record in records:
    ip = record["ip"]

    result = misp.search(
        controller="attributes",
        value=ip,
        pythonify=False,
    )

    attributes = result.get("Attribute", [])
    matches = []

    for attribute in attributes:
        event_id = attribute.get("event_id")
        event_info = "Unavailable"

        if event_id:
            try:
                event = misp.get_event(event_id, pythonify=False)
                event_data = event.get("Event", event)
                event_info = event_data.get("info", "Unavailable")
            except Exception:
                event_info = "Event lookup failed"

        matches.append({
            "event_id": event_id,
            "event_info": event_info,
            "attribute_comment": attribute.get("comment"),
            "attribute_type": attribute.get("type"),
        })

    report.append({
        "ip": ip,
        "feed_malware": record.get("malware"),
        "feed_status": record.get("c2_status"),
        "feed_last_online": record.get("last_online"),
        "misp_matches": matches,
    })

Path("ioc_context_report.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)

print("Context comparison completed.")
print("Indicators processed:", len(report))
print("Report saved to: ioc_context_report.json")
