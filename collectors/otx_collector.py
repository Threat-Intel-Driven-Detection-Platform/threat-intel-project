import os
import requests
import json

API_KEY = os.getenv("OTX_API_KEY")

URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

headers = {
    "X-OTX-API-KEY": API_KEY
}

try:
    response = requests.get(
        URL,
        headers=headers,
        timeout=60
    )

    print("Status Code:", response.status_code)

    if response.status_code == 200:
        data = response.json()

        with open("data/otx_raw.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        print("OTX data saved to data/otx_raw.json")

    else:
        print("Failed to download OTX data")
        print(response.text)

except requests.exceptions.Timeout:
    print("Request timed out while connecting to OTX")

except requests.exceptions.RequestException as e:
    print("Request failed:", e)