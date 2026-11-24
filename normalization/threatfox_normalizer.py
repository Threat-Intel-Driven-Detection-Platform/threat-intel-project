import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "data" / "threatfox_raw.json"
OUTPUT_FILE = BASE_DIR / "data" / "threatfox_normalized.json"


with INPUT_FILE.open("r", encoding="utf-8") as f:
    raw_data = json.load(f)


if not isinstance(raw_data, dict) or raw_data.get("query_status") != "ok" or not isinstance(raw_data.get("data"), list):
    raise SystemExit(
        "Invalid ThreatFox export. Check query_status and data before normalization."
    )


normalized_iocs = []

required_fields = [
    "id",
    "ioc",
    "ioc_type",
    "threat_type",
    "malware",
    "confidence_level",
    "first_seen",
    "reporter",
]

for index, item in enumerate(raw_data["data"]):
    missing = [field for field in required_fields if field not in item]

    if missing:
        raise ValueError(
            f"Record at index {index} is missing required fields: {missing}"
        )

    normalized_ioc = {
        "id": item["id"],
        "ioc": item["ioc"],
        "ioc_type": item["ioc_type"],
        "source": "ThreatFox",
        "threat_type": item["threat_type"],
        "malware": item["malware"],
        "confidence": item["confidence_level"],
        "first_seen": item["first_seen"],
        "last_seen": item.get("last_seen"),
        "reporter": item["reporter"],
        "tags": item.get("tags") or [],
    }

    normalized_iocs.append(normalized_ioc)


OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT_FILE.open("w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4, ensure_ascii=False)


null_last_seen = sum(item["last_seen"] is None for item in normalized_iocs)
empty_tags = sum(not item["tags"] for item in normalized_iocs)

print(f"Normalized: {len(normalized_iocs)} IOCs")
print(f"Records with empty tags: {empty_tags}")
print(f"Records with null last_seen: {null_last_seen}")
print(f"Saved to: {OUTPUT_FILE}")
