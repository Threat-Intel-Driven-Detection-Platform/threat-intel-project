import os
import requests

AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.json"

response = requests.get(URL)

print("Status Code:", response.status_code)

if response.status_code == 200:
    with open("data/urlhaus_raw.json", "wb") as f:
        f.write(response.content)

    print("URLhaus data saved to data/urlhaus_raw.json")
else:
    print("Failed to download URLhaus data")
    print(response.text)