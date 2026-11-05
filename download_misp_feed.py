import requests
from pathlib import Path

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
OUTPUT_FILE = Path("feodo_feed.csv")

try:
    response = requests.get(FEED_URL, timeout=30)
    response.raise_for_status()

    OUTPUT_FILE.write_text(response.text, encoding="utf-8")

    print("Feed downloaded successfully")
    print("HTTP status:", response.status_code)
    print("File:", OUTPUT_FILE)
    print("Size:", OUTPUT_FILE.stat().st_size, "bytes")
    print("\nFirst 10 lines:")

    for line in response.text.splitlines()[:10]:
        # Display feed structure without making network requests
        print(line)

except requests.RequestException as error:
    print("Feed download failed:", error)
