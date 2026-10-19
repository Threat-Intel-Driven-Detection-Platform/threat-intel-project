import os
import requests
import json

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

auth_key = os.getenv("THREATFOX_AUTH_KEY")

headers = {
    "Auth-Key": auth_key
}

payload = {
    "query": "get_iocs",
    "days": 1
}

response = requests.post(
    API_URL,
    headers=headers,
    json=payload
)

print("Status Code:", response.status_code)

data = response.json()

output_file = "data/threatfox_raw.json"

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4)

print(f"IOC data saved to {output_file}")