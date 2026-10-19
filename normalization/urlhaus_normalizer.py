import json


INPUT_FILE = "data/urlhaus_raw.json"
OUTPUT_FILE = "data/urlhaus_normalized.json"


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)


normalized_iocs = []

for record_id, records in raw_data.items():

    for item in records:

        normalized_ioc = {
            "id": record_id,
            "ioc": item["url"],
            "ioc_type": "url",
            "source": "URLhaus",
            "threat_type": item["threat"],
            "malware": None,
            "confidence": None,
            "first_seen": item["dateadded"],
            "last_seen": item["last_online"],
            "reporter": item["reporter"],
            "tags": item["tags"] if item["tags"] else []
        }

        normalized_iocs.append(normalized_ioc)


with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)


print(f"Normalized {len(normalized_iocs)} URLhaus IOCs")
print(f"Saved to {OUTPUT_FILE}")