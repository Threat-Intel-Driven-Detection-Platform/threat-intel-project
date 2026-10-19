import json


INPUT_FILE = "data/threatfox_normalized.json"
OUTPUT_FILE = "data/iocs_deduplicated.json"


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    iocs = json.load(f)


unique_iocs = []
seen = set()

for item in iocs:

    key = (item["ioc"], item["ioc_type"])

    if key not in seen:
        seen.add(key)
        unique_iocs.append(item)


with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(unique_iocs, f, indent=4)


print(f"Original IOCs: {len(iocs)}")
print(f"Unique IOCs: {len(unique_iocs)}")
print(f"Duplicates removed: {len(iocs) - len(unique_iocs)}")
print(f"Saved to {OUTPUT_FILE}")