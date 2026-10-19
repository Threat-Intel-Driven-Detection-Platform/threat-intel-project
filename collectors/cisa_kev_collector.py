import requests
import json
from datetime import datetime

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_FILE = "data/raw/cisa_kev/kev_raw.json"

response = requests.get(URL, timeout=60)

print("Status Code:", response.status_code)

if response.status_code == 200:
    data = response.json()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print("CISA KEV data collected successfully.")
    print("Vulnerabilities:", len(data.get("vulnerabilities", [])))
    print("Saved to:", OUTPUT_FILE)
else:
    print("Failed to collect CISA KEV.")
    print(response.text[:500])