import requests

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

try:
    response = requests.get(FEED_URL, timeout=30)
    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    print("CISA KEV feed downloaded successfully")
    print("Total vulnerabilities:", len(vulnerabilities))
    print("\nFirst 3 records:\n")

    for item in vulnerabilities[:3]:
        print("CVE:", item.get("cveID"))
        print("Vendor:", item.get("vendorProject"))
        print("Product:", item.get("product"))
        print("Name:", item.get("vulnerabilityName"))
        print("-" * 40)

except requests.RequestException as error:
    print("Download failed:", error)

except ValueError as error:
    print("Could not parse JSON:", error)
