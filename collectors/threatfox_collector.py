import os
import json
import requests

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
OUTPUT_FILE = "data/raw/threatfox/threatfox_raw.json"

auth_key = os.getenv("THREATFOX_AUTH_KEY")

if not auth_key:
    print("ERROR: THREATFOX_AUTH_KEY is not set.")
    exit(1)

headers = {
    "Auth-Key": auth_key
}

payload = {
    "query": "get_iocs",
    "days": 1
}

try:
    response = requests.post(
        API_URL,
        headers=headers,
        json=payload,
        timeout=60
    )

    print("Status Code:", response.status_code)

    if response.status_code != 200:
        print("ThreatFox collection failed.")
        print(response.text[:500])
        exit(1)

    data = response.json()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    iocs = data.get("data", [])

    print("ThreatFox data collected successfully.")
    print("IOCs:", len(iocs))
    print("Saved to:", OUTPUT_FILE)

except requests.exceptions.RequestException as e:
    print("Request failed:", e)