import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = ROOT / "data" / "otx_raw.json"
URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

API_KEY = os.getenv("OTX_API_KEY")

if not API_KEY:
    sys.exit("OTX_API_KEY is not set")

try:
    response = requests.get(URL, headers={"X-OTX-API-KEY": API_KEY}, timeout=60)
    print("Status Code:", response.status_code)

    if response.status_code != 200:
        sys.exit(f"Failed to download OTX data: {response.text[:200]}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(response.json(), f, indent=4)

    print(f"OTX data saved to {OUTPUT_FILE}")

except requests.exceptions.RequestException as e:
    sys.exit(f"Request failed: {e}")
