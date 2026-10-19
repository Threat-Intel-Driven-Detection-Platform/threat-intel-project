import requests
import os

URL = "https://openphish.com/feed.txt"
OUTPUT_FILE = "data/raw/openphish/openphish_raw.txt"

response = requests.get(URL, timeout=60)

print("Status Code:", response.status_code)

if response.status_code == 200:
    with open(OUTPUT_FILE, "wb") as f:
        f.write(response.content)

    lines = response.text.splitlines()
    urls = [line.strip() for line in lines if line.strip()]

    print("OpenPhish feed collected successfully.")
    print("Phishing URLs:", len(urls))
    print("Saved to:", OUTPUT_FILE)

else:
    print("Failed to collect OpenPhish.")
    print(response.text[:500])