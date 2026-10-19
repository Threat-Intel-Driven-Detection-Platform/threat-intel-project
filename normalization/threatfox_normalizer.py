import json


INPUT_FILE = "data/threatfox_raw.json"
OUTPUT_FILE = "data/threatfox_normalized.json"


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)


normalized_iocs = []

for item in raw_data["data"]:

    normalized_ioc = {
        "id": item["id"],
        "ioc": item["ioc"],
        "ioc_type": item["ioc_type"],
        "source": "ThreatFox",
        "threat_type": item["threat_type"],
        "malware": item["malware"],
        "confidence": item["confidence_level"],
        "first_seen": item["first_seen"],
        "last_seen": item["last_seen"],
        "reporter": item["reporter"],
        "tags": item["tags"]
    }

    normalized_iocs.append(normalized_ioc)


with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)


print(f"Normalized {len(normalized_iocs)} IOCs")
print(f"Saved to {OUTPUT_FILE}")