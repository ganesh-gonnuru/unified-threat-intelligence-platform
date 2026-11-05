import csv
import json
from pathlib import Path
from collections import defaultdict

INPUT_FILE = Path("feodo_indicators.json")
CONTEXT_FILE = Path("ioc_context_report.json")
OUTPUT_FILE = Path("cross_feed_report.csv")

def main():
    if not INPUT_FILE.exists() or not CONTEXT_FILE.exists():
        print("Required JSON file not found.")
        print("Check feodo_indicators.json and ioc_context_report.json")
        return

    indicators = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    context = json.loads(CONTEXT_FILE.read_text(encoding="utf-8"))

    context_by_ip = {item["ip"]: item for item in context}
    rows = []

    for indicator in indicators:
        ip = indicator["ip"]
        context_item = context_by_ip.get(ip, {})
        matches = context_item.get("misp_matches", [])

        event_ids = sorted({
            str(match["event_id"])
            for match in matches
            if match.get("event_id")
        })

        rows.append({
            "ip": ip,
            "malware": indicator.get("malware", ""),
            "c2_status": indicator.get("c2_status", ""),
            "last_online": indicator.get("last_online", ""),
            "source": indicator.get("source", ""),
            "misp_event_ids": "; ".join(event_ids),
            "event_count": len(event_ids),
            "multiple_events": "Yes" if len(event_ids) > 1 else "No",
        })

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=[
            "ip",
            "malware",
            "c2_status",
            "last_online",
            "source",
            "misp_event_ids",
            "event_count",
            "multiple_events",
        ])
        writer.writeheader()
        writer.writerows(rows)

    print("Cross-feed report created.")
    print("Indicators reported:", len(rows))
    print("Indicators in multiple events:", sum(
        row["multiple_events"] == "Yes" for row in rows
    ))
    print("Saved to:", OUTPUT_FILE)

if __name__ == "__main__":
    main()
