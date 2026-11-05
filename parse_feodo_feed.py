import csv
import json
import ipaddress
from pathlib import Path

INPUT_FILE = Path("feodo_feed.csv")
OUTPUT_FILE = Path("feodo_indicators.json")

def main():
    if not INPUT_FILE.exists():
        print("Feed file not found:", INPUT_FILE)
        return

    valid_records = {}
    invalid_count = 0

    with INPUT_FILE.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        # Skip comment lines before the CSV header.
        while True:
            position = file.tell()
            line = file.readline()

            if not line:
                print("CSV header not found.")
                return

            if line.strip() and not line.lstrip().startswith("#"):
                file.seek(position)
                break

        reader = csv.DictReader(file)

        for row in reader:
            ip = (row.get("dst_ip") or "").strip()

            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                invalid_count += 1
                continue

            if ip not in valid_records:
                valid_records[ip] = {
                    "ip": ip,
                    "port": row.get("dst_port"),
                    "malware": row.get("malware"),
                    "c2_status": row.get("c2_status"),
                    "first_seen_utc": row.get("first_seen_utc"),
                    "last_online": row.get("last_online"),
                    "source": "Feodo IP Blocklist",
                }

    records = list(valid_records.values())

    OUTPUT_FILE.write_text(
        json.dumps(records, indent=2),
        encoding="utf-8",
    )

    print("Feed parsing completed.")
    print("Unique valid IPs:", len(records))
    print("Invalid IP records skipped:", invalid_count)
    print("Saved to:", OUTPUT_FILE)

if __name__ == "__main__":
    main()
