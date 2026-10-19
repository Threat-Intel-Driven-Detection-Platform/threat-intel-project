import json
from datetime import datetime, timezone

INPUT_FILE = "data/raw/openphish/openphish_raw.txt"
OUTPUT_FILE = "data/normalized/openphish_normalized.json"

collected_at = datetime.now(timezone.utc).isoformat()

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    urls = [
        line.strip()
        for line in f
        if line.strip()
    ]

# Remove duplicate URLs while preserving order
unique_urls = list(dict.fromkeys(urls))

normalized_iocs = []

for url in unique_urls:
    normalized_ioc = {
        "value": url,
        "canonical_type": "url",
        "source": "OpenPhish",
        "first_seen": None,
        "last_seen": None,
        "collected_at": collected_at,
        "confidence": None,
        "status": "active",
        "threat_type": "phishing",
        "malware": None,
        "tags": ["phishing"],
        "reference": "OpenPhish Community Feed"
    }

    normalized_iocs.append(normalized_ioc)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)

print("================================")
print("OpenPhish Normalization")
print("================================")
print("Raw URLs:", len(urls))
print("Unique URLs:", len(unique_urls))
print("Normalized IOCs:", len(normalized_iocs))
print("Duplicates removed:", len(urls) - len(unique_urls))
print("Saved to:", OUTPUT_FILE)