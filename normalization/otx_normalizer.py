import json

INPUT_FILE = "data/otx_raw.json"
OUTPUT_FILE = "data/otx_normalized.json"

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)

normalized_iocs = []

for pulse in raw_data["results"]:
    for indicator in pulse["indicators"]:

        normalized_ioc = {
            "id": str(indicator["id"]),
            "ioc": indicator["indicator"],
            "ioc_type": indicator["type"],
            "source": "OTX",
            "threat_type": "threat_intelligence",
            "malware": None,
            "confidence": None,
            "first_seen": indicator["created"],
            "last_seen": pulse["modified"],
            "reporter": pulse["author_name"],
            "tags": [
                pulse["name"],
                pulse["adversary"]
            ]
        }

        normalized_iocs.append(normalized_ioc)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)

print(f"Normalized {len(normalized_iocs)} OTX IOCs")
print(f"Saved to {OUTPUT_FILE}")