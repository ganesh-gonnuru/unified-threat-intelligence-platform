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

input_file = Path("feodo_indicators.json")
output_file = Path("reconciliation_report.json")

records = json.loads(input_file.read_text(encoding="utf-8"))
report = []

for record in records:
    ip = record["ip"]

    item = {
        "ip": ip,
        "feed_source": record.get("source"),
        "feed_malware": record.get("malware"),
        "feed_status": record.get("c2_status"),
        "misp_matches": [],
        "result": "LOOKUP_FAILED",
    }

    try:
        response = misp.search(
            controller="attributes",
            value=ip,
            pythonify=False,
        )

        attributes = response.get("Attribute", [])

        if not attributes:
            item["result"] = "NOT_FOUND"
        else:
            item["result"] = "EXISTS"

            for attribute in attributes:
                item["misp_matches"].append({
                    "event_id": attribute.get("event_id"),
                    "type": attribute.get("type"),
                    "category": attribute.get("category"),
                    "comment": attribute.get("comment"),
                    "to_ids": attribute.get("to_ids"),
                })

    except Exception as error:
        item["error_type"] = type(error).__name__

    report.append(item)

output_file.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)

print("IOC reconciliation completed")
print("Total indicators:", len(report))
print("Existing:", sum(r["result"] == "EXISTS" for r in report))
print("Not found:", sum(r["result"] == "NOT_FOUND" for r in report))
print("Lookup failures:", sum(r["result"] == "LOOKUP_FAILED" for r in report))
print("Report saved to:", output_file)
