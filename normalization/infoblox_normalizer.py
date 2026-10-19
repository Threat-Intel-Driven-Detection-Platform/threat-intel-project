import csv
import json
import os

INPUT_FILE = "data/raw/infoblox/repository/indicators/combined.csv"
OUTPUT_FILE = "data/normalized/infoblox_normalized.json"

normalized_iocs = []
seen = set()

type_mapping = {
    "domain": "domain",
    "ip": "ipv4",
    "url": "url",
    "sha256": "sha256",
    "email": "email"
}

raw_records = 0
skipped_records = 0

with open(
    INPUT_FILE,
    "r",
    encoding="utf-8-sig",
    newline=""
) as f:

    reader = csv.DictReader(f)

    print("Columns:", reader.fieldnames)

    for row in reader:

        raw_records += 1

        value = row.get("indicator")

        if not value:
            skipped_records += 1
            continue

        value = value.strip()

        original_type = (
            row.get("type") or ""
        ).strip().lower()

        canonical_type = type_mapping.get(original_type)

        if not canonical_type:
            skipped_records += 1
            continue

        key = (
            value.lower(),
            canonical_type
        )

        if key in seen:
            continue

        seen.add(key)

        classification = row.get("classification")

        tags = []

        if classification:
            tags.append(classification.strip())

        normalized_ioc = {
            "source_record_id": None,
            "value": value,
            "canonical_type": canonical_type,
            "original_type": original_type,
            "source": "Infoblox Threat Intelligence",
            "threat_type": "threat_intelligence",
            "malware": None,
            "confidence": None,
            "first_seen": row.get("detected_date"),
            "last_seen": row.get("detected_date"),
            "reporter": "Infoblox",
            "tags": tags,
            "status": "active",
            "reference": "Infoblox combined.csv"
        }

        normalized_iocs.append(normalized_ioc)


os.makedirs(
    os.path.dirname(OUTPUT_FILE),
    exist_ok=True
)

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        normalized_iocs,
        f,
        indent=4
    )


print("================================")
print("Infoblox Normalization")
print("================================")
print("Raw Records:", raw_records)
print("Unique IOCs:", len(normalized_iocs))
print("Skipped Records:", skipped_records)
print(
    "Duplicates removed:",
    raw_records - skipped_records - len(normalized_iocs)
)
print("Saved to:", OUTPUT_FILE)