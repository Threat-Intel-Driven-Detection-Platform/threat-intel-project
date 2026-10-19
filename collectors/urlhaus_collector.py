import os
import json
import requests

API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
OUTPUT_FILE = "data/raw/urlhaus/urlhaus_raw.json"

auth_key = os.getenv("URLHAUS_AUTH_KEY")

if not auth_key:
    print("ERROR: URLHAUS_AUTH_KEY is not set.")
    exit(1)

headers = {
    "Auth-Key": auth_key
}

try:
    response = requests.get(
        API_URL,
        headers=headers,
        timeout=60
    )

    print("Status Code:", response.status_code)

    if response.status_code != 200:
        print("URLhaus collection failed.")
        print(response.text[:500])
        exit(1)

    data = response.json()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    urls = data.get("urls", [])

    print("URLhaus data collected successfully.")
    print("URLs:", len(urls))
    print("Saved to:", OUTPUT_FILE)

except requests.exceptions.RequestException as e:
    print("Request failed:", e)