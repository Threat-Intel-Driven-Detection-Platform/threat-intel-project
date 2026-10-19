import json
import os
import requests


API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OUTPUT_FILE = "data/raw/otx/otx_raw.json"


def main():

    print("================================")
    print("AlienVault OTX Collection")
    print("================================")

    api_key = os.getenv("OTX_AUTH_KEY")

    if not api_key:
        print("ERROR: OTX_AUTH_KEY is not set.")
        return

    print("OTX key loaded: True")

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
        "User-Agent": "ThreatIntelProject/1.0"
    }

    params = {
        "page": 1
    }

    try:

        response = requests.get(
            API_URL,
            headers=headers,
            params=params,
            timeout=60
        )

        print("Status Code:", response.status_code)

        if response.status_code != 200:

            print("OTX collection failed.")
            print(response.text[:1000])
            return

        data = response.json()

        os.makedirs(
            os.path.dirname(OUTPUT_FILE),
            exist_ok=True
        )

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=4
            )

        pulses = data.get("results", [])

        print("Pulses collected:", len(pulses))
        print("Saved to:", OUTPUT_FILE)

    except requests.RequestException as e:

        print("Request error:", e)


if __name__ == "__main__":
    main()