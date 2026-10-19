import json

INPUT_FILE = "data/raw/feodo/feodo_raw.json"
OUTPUT_FILE = "data/normalized/feodo_normalized.json"

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)

normalized_iocs = []
seen = set()

for item in raw_data:
    value = item.get("ip_address")

    if not value:
        continue

    value = value.strip()
    key = (value.lower(), "ipv4")

    if key in seen:
        continue

    seen.add(key)

    normalized_iocs.append({
        "source_record_id": str(item.get("ip_address")),
        "value": value,
        "canonical_type": "ipv4",
        "original_type": "ip_address",
        "source": "Feodo Tracker",
        "threat_type": "botnet_c2",
        "malware": item.get("malware"),
        "confidence": None,
        "first_seen": item.get("first_seen"),
        "last_seen": item.get("last_online"),
        "reporter": None,
        "tags": ["c2", "botnet"],
        "status": item.get("status"),
        "reference": "Feodo Tracker"
    })

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)

print("================================")
print("Feodo Tracker Normalization")
print("================================")
print("Raw Records:", len(raw_data))
print("Normalized IOCs:", len(normalized_iocs))
print("Duplicates removed:", len(raw_data) - len(normalized_iocs))
print("Saved to:", OUTPUT_FILE)