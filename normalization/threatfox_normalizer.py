import json

INPUT_FILE = "data/raw/threatfox/threatfox_raw.json"
OUTPUT_FILE = "data/normalized/threatfox_normalized.json"


def canonical_type(ioc_type):
    mapping = {
        "url": "url",
        "domain": "domain",
        "ip:port": "ip_port",
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "md5_hash": "md5",
        "sha1_hash": "sha1",
        "sha256_hash": "sha256"
    }

    return mapping.get(ioc_type, ioc_type)


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)

normalized_iocs = []
seen = set()

for item in raw_data.get("data", []):

    value = item.get("ioc")

    if not value:
        continue

    canonical = canonical_type(item.get("ioc_type"))

    key = (value.strip().lower(), canonical)

    if key in seen:
        continue

    seen.add(key)

    normalized_ioc = {
        "source_record_id": str(item.get("id")),
        "value": value.strip(),
        "canonical_type": canonical,
        "original_type": item.get("ioc_type"),
        "source": "ThreatFox",

        "threat_type": item.get("threat_type"),
        "threat_type_description": item.get("threat_type_desc"),

        "malware": item.get("malware"),

        "confidence": item.get("confidence_level"),

        "first_seen": item.get("first_seen"),
        "last_seen": item.get("last_seen"),

        "reporter": item.get("reporter"),

        "tags": item.get("tags"),

        "reference": item.get("reference"),

        "is_compromised": item.get("is_compromised")
    }

    normalized_iocs.append(normalized_ioc)


with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)

print("================================")
print("ThreatFox Normalization")
print("================================")
print("Raw IOCs:", len(raw_data.get("data", [])))
print("Unique IOCs:", len(normalized_iocs))
print("Duplicates removed:",
      len(raw_data.get("data", [])) - len(normalized_iocs))
print("Saved to:", OUTPUT_FILE)