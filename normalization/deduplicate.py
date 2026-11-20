import json

INPUT_FILE = "data/all_iocs.json"
OUTPUT_FILE = "data/iocs_deduplicated.json"

with open(INPUT_FILE, encoding="utf-8") as f:
    records = json.load(f)

unique = {}
for item in records:
    key = (
        item["ioc"].strip(),
        item["ioc_type"].strip().lower(),
        item.get("source", "unknown"),
    )
    if key not in unique:
        unique[key] = item
    else:
        old = unique[key]
        old["tags"] = list(dict.fromkeys(
            (old.get("tags") or []) + (item.get("tags") or [])
        ))
        for field in ("threat_type", "malware", "confidence",
                      "first_seen", "last_seen", "reporter"):
            if old.get(field) in (None, "") and item.get(field) not in (None, ""):
                old[field] = item[field]

result = list(unique.values())
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print("Input records:", len(records))
print("Unique IOC/type/source records:", len(result))
print("Duplicates removed:", len(records) - len(result))
print("Sources preserved:", sorted({x.get("source") for x in result}))
