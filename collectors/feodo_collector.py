import requests
import json

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
OUTPUT_FILE = "data/raw/feodo/feodo_raw.json"

response = requests.get(URL, timeout=60)

print("Status Code:", response.status_code)

if response.status_code == 200:

    data = response.json()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print("Feodo Tracker data collected successfully.")
    print("Records:", len(data))
    print("Saved to:", OUTPUT_FILE)

else:
    print("Feodo collection failed.")
    print(response.text[:500])