import json

INPUT_FILE = "data/raw/urlhaus/urlhaus_raw.json"
OUTPUT_FILE = "data/normalized/urlhaus_normalized.json"


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)


urls = raw_data.get("urls", [])

normalized_iocs = []
seen = set()

for item in urls:

    value = item.get("url")

    if not value:
        continue

    key = value.strip().lower()

    if key in seen:
        continue

    seen.add(key)

    normalized_ioc = {
        "source_record_id": str(item.get("id")),
        "value": value.strip(),
        "canonical_type": "url",
        "original_type": "url",
        "source": "URLhaus",

        "threat_type": "malware_download",

        "malware": item.get("threat"),

        "confidence": None,

        "first_seen": item.get("date_added"),
        "last_seen": item.get("last_online"),

        "reporter": item.get("reporter"),

        "tags": item.get("tags"),

        "status": item.get("url_status"),

        "reference": item.get("urlhaus_reference")
    }

    normalized_iocs.append(normalized_ioc)


with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)


print("================================")
print("URLhaus Normalization")
print("================================")
print("Raw URLs:", len(urls))
print("Unique URLs:", len(normalized_iocs))
print(
    "Duplicates removed:",
    len(urls) - len(normalized_iocs)
)
print("Saved to:", OUTPUT_FILE)