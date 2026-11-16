import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = ROOT / "data" / "urlhaus_raw.json"

AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

if not AUTH_KEY:
    sys.exit("URLHAUS_AUTH_KEY is not set")

URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.json"

response = requests.get(URL, timeout=120)
print("Status Code:", response.status_code)

if response.status_code != 200:
    sys.exit(f"Failed to download URLhaus data: {response.text[:200]}")

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT_FILE, "wb") as f:
    f.write(response.content)

print(f"URLhaus data saved to {OUTPUT_FILE}")
