import os
import urllib3
from dotenv import load_dotenv
from pymisp import PyMISP

load_dotenv()

misp_url = os.getenv("MISP_URL")
misp_key = os.getenv("MISP_API_KEY")

if not misp_url or not misp_key:
    raise ValueError("MISP_URL or MISP_API_KEY is missing from .env")

# Disable warnings for the lab's self-signed TLS certificate.
# This is for local testing only.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    misp = PyMISP(
        misp_url,
        misp_key,
        ssl=False,
        debug=False,
    )

    version = misp.misp_instance_version
    print("MISP API connection successful.")
    print("MISP version:", version)

except Exception as error:
    print("MISP API connection failed.")
    print("Error type:", type(error).__name__)
    print("Check the API key, permissions, URL, and MISP logs.")
