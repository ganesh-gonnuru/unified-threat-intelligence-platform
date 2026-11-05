import csv
import ipaddress
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv
from pymisp import PyMISP

# Project files
BASE_DIR = Path(__file__).resolve().parent
FEED_FILE = BASE_DIR / "feodo_feed.csv"
INDICATORS_FILE = BASE_DIR / "feodo_indicators.json"
CONTEXT_FILE = BASE_DIR / "ioc_context_report.json"
RECONCILIATION_FILE = BASE_DIR / "reconciliation_report.json"
CSV_REPORT = BASE_DIR / "cross_feed_report.csv"
RUN_FILE = BASE_DIR / "last_run.json"

LOG_FILE = BASE_DIR / "pipeline.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
downloaded_at_utc = None

def download_feed():
    global downloaded_at_utc

    print("\n[1/5] Downloading Feodo feed...")

    response = requests.get(FEED_URL, timeout=30)
    response.raise_for_status()

    content = response.text

    if not content.strip():
        raise ValueError("Downloaded feed is empty.")

    # Validate the CSV header before writing any files.
    header_found = False

    for line in content.splitlines():
        stripped_line = line.strip()

        if not stripped_line or stripped_line.startswith("#"):
            continue

        columns = next(csv.reader([line]))
        columns = [column.strip().strip('"') for column in columns]

        required_columns = {
            "first_seen_utc",
            "dst_ip",
            "dst_port",
            "c2_status",
            "last_online",
            "malware",
        }

        if required_columns.issubset(set(columns)):
            header_found = True

        break

    if not header_found:
        raise ValueError(
            "Invalid Feodo CSV header. Existing feed was preserved."
        )

    # Write to a temporary file in the same directory.
    temp_file = BASE_DIR / "feodo_feed.tmp"

    try:
        temp_file.write_text(content, encoding="utf-8")

        # Atomically replace the previous feed after validation.
        os.replace(temp_file, FEED_FILE)
    finally:
        if temp_file.exists():
            temp_file.unlink()

    downloaded_at_utc = datetime.now(timezone.utc).isoformat()

    print(f"Downloaded {FEED_FILE.stat().st_size} bytes.")
    print(f"Feed downloaded at (UTC): {downloaded_at_utc}")
    logging.info("Feodo feed downloaded successfully.")
    logging.info("Downloaded bytes: %s", FEED_FILE.stat().st_size)



def parse_feed():
    print("\n[2/5] Validating and deduplicating IPs...")

    unique_records = {}
    invalid_count = 0

    with FEED_FILE.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        # Skip comments before the CSV header.
        while True:
            position = file.tell()
            line = file.readline()

            if not line:
                raise ValueError("CSV header not found in feed.")

            if line.strip() and not line.lstrip().startswith("#"):
                file.seek(position)
                break

        reader = csv.DictReader(file)

        for row in reader:
            raw_ip = (row.get("dst_ip") or "").strip()

            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                invalid_count += 1
                continue

            # Keep the first record for each unique IP.
            if ip not in unique_records:
                unique_records[ip] = {
                    "ip": ip,
                    "port": row.get("dst_port"),
                    "malware": row.get("malware"),
                    "c2_status": row.get("c2_status"),
                    "first_seen_utc": row.get("first_seen_utc"),
                    "last_online": row.get("last_online"),
                    "source": "Feodo IP Blocklist",
                }

    records = list(unique_records.values())

    INDICATORS_FILE.write_text(
        json.dumps(records, indent=2),
        encoding="utf-8",
    )

    print(f"Unique valid IPs: {len(records)}")
    print(f"Invalid records skipped: {invalid_count}")
    logging.info("Unique valid IPs: %s", len(records))
    logging.info("Invalid records skipped: %s", invalid_count)

    return records, invalid_count


def connect_to_misp():
    print("\n[3/5] Connecting to MISP...")

    load_dotenv(BASE_DIR / ".env")

    misp_url = os.getenv("MISP_URL")
    misp_key = os.getenv("MISP_API_KEY")

    if not misp_url or not misp_key:
        raise ValueError("MISP_URL or MISP_API_KEY is missing.")

    # For the existing isolated lab only. Certificate verification
    # should be enabled when a trusted certificate is configured.
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )

    misp = PyMISP(
        misp_url,
        misp_key,
        ssl=False,
        debug=False,
    )

    print("MISP API client initialized.")
    return misp


def reconcile(misp, records):
    print("\n[4/5] Reconciling indicators with MISP...")

    context_report = []
    reconciliation_report = []
    csv_rows = []

    for record in records:
        ip = record["ip"]

        context_item = {
            "ip": ip,
            "feed_malware": record.get("malware"),
            "feed_status": record.get("c2_status"),
            "feed_last_online": record.get("last_online"),
            "misp_matches": [],
            "result": "LOOKUP_FAILED",
        }

        try:
            result = misp.search(
                controller="attributes",
                value=ip,
                pythonify=False,
            )

            attributes = result.get("Attribute", [])

            if not attributes:
                context_item["result"] = "NOT_FOUND"
            else:
                context_item["result"] = "EXISTS"

                for attribute in attributes:
                    event_id = attribute.get("event_id")
                    event_info = "Unavailable"

                    if event_id:
                        try:
                            event = misp.get_event(
                                event_id,
                                pythonify=False,
                            )
                            event_data = event.get("Event", event)
                            event_info = event_data.get(
                                "info", "Unavailable"
                            )
                        except Exception:
                            event_info = "Event lookup failed"

                    context_item["misp_matches"].append({
                        "event_id": event_id,
                        "event_info": event_info,
                        "attribute_type": attribute.get("type"),
                        "category": attribute.get("category"),
                        "comment": attribute.get("comment"),
                        "to_ids": attribute.get("to_ids"),
                    })

        except Exception as error:
            context_item["error_type"] = type(error).__name__

        context_report.append(context_item)

        event_ids = sorted({
            str(match["event_id"])
            for match in context_item["misp_matches"]
            if match.get("event_id")
        })

        reconciliation_report.append({
            "ip": ip,
            "result": context_item["result"],
            "event_ids": event_ids,
            "feed_malware": record.get("malware"),
            "feed_status": record.get("c2_status"),
        })

        csv_rows.append({
            "ip": ip,
            "malware": record.get("malware", ""),
            "c2_status": record.get("c2_status", ""),
            "last_online": record.get("last_online", ""),
            "source": record.get("source", ""),
            "misp_event_ids": "; ".join(event_ids),
            "event_count": len(event_ids),
            "multiple_events": (
                "Yes" if len(event_ids) > 1 else "No"
            ),
        })

    CONTEXT_FILE.write_text(
        json.dumps(context_report, indent=2),
        encoding="utf-8",
    )

    RECONCILIATION_FILE.write_text(
        json.dumps(reconciliation_report, indent=2),
        encoding="utf-8",
    )

    with CSV_REPORT.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "ip",
                "malware",
                "c2_status",
                "last_online",
                "source",
                "misp_event_ids",
                "event_count",
                "multiple_events",
            ],
        )
        writer.writeheader()
        writer.writerows(csv_rows)

    return context_report


def main():
    started = datetime.now(timezone.utc)
    logging.info("pipeline started")

    try:
        download_feed()
        records, invalid_count = parse_feed()

        if not records:
            raise ValueError(
                "No valid IP indicators were found. "
                "Reports were not refreshed."
            )

        misp = connect_to_misp()
        context_report = reconcile(misp, records)

        existing = sum(
            item["result"] == "EXISTS"
            for item in context_report
        )
        missing = sum(
            item["result"] == "NOT_FOUND"
            for item in context_report
        )
        failed = sum(
            item["result"] == "LOOKUP_FAILED"
            for item in context_report
        )

        completed = datetime.now(timezone.utc)

        RUN_FILE.write_text(
            json.dumps({
                "started_at_utc": started.isoformat(),
                "completed_at_utc": completed.isoformat(),
                "feed_url": FEED_URL,
                "downloaded_at_utc": downloaded_at_utc,
                "total_unique_ips": len(records),
                "invalid_records": invalid_count,
                "existing_in_misp": existing,
                "not_found_in_misp": missing,
                "lookup_failures": failed,
            }, indent=2),
            encoding="utf-8",
        )

        print("\n[5/5] Pipeline completed.")
        print(f"Unique IPs: {len(records)}")
        print(f"Existing in MISP: {existing}")
        print(f"Not found in MISP: {missing}")
        print(f"Lookup failures: {failed}")
        print(f"Invalid records: {invalid_count}")
        print(f"CSV report: {CSV_REPORT.name}")
        print(f"Run metadata: {RUN_FILE.name}")
        logging.info(
    "Pipeline completed. Unique IPs=%s, existing=%s, missing=%s, failures=%s",
    len(records),
    existing,
    missing,
    failed,
)

        if failed:
            print(
                "\nWARNING: Some MISP lookups failed. "
                "Review the context report before interpreting "
                "missing indicators."
            )

    except Exception as error:
        logging.exception("pipeline failed")
        print("\nPipeline failed.")
        print("Error type:", type(error).__name__)
        print("Error:", str(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
