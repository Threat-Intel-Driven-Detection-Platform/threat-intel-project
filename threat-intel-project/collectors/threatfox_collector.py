import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = ROOT / "data" / "threatfox_raw.json"
API_URL = "https://threatfox-api.abuse.ch/api/v1/"

auth_key = os.getenv("THREATFOX_AUTH_KEY")

if not auth_key:
    sys.exit("THREATFOX_AUTH_KEY is not set (get a free key from https://auth.abuse.ch/)")

response = requests.post(
    API_URL,
    headers={"Auth-Key": auth_key},
    json={"query": "get_iocs", "days": 1},
    timeout=60,
)

print("Status Code:", response.status_code)

data = response.json()

# FIX: never overwrite good raw data with an error response
# (previously a bad key produced {"query_status": "unknown_auth_key"} in threatfox_raw.json
#  and broke the normalizer with KeyError: 'data')
if data.get("query_status") != "ok":
    sys.exit(f"ThreatFox returned query_status={data.get('query_status')!r} - raw file NOT overwritten")

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4)

print(f"{len(data.get('data', []))} IOCs saved to {OUTPUT_FILE}")
