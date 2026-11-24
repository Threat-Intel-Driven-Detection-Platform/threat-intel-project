import json
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parent.parent

INPUT_FILES = {
    "ThreatFox": ROOT / "data" / "threatfox_normalized.json",
    "URLhaus": ROOT / "data" / "urlhaus_normalized.json",
    "OTX": ROOT / "data" / "otx_normalized.json",
}

OUTPUT_FILE = ROOT / "data" / "all_iocs.json"

all_iocs = []
seen_ids = set()

for source, path in INPUT_FILES.items():
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open("r", encoding="utf-8") as f:
        records = json.load(f)

    if not isinstance(records, list):
        raise ValueError(f"{path.name} must contain a JSON list.")

    print(f"{source}: {len(records)} records")

    for index, item in enumerate(records):
        if not isinstance(item, dict):
            raise ValueError(f"Invalid record in {path.name}: {index}")

        for field in ("id", "ioc", "ioc_type", "source"):
            value = item.get(field)
            if value is None or not str(value).strip():
                raise ValueError(
                    f"Missing {field} in {path.name}, record {index}"
                )

        if item["source"] != source:
            raise ValueError(
                f"Source mismatch in {path.name}, record {index}"
            )

        key = (source, str(item["id"]))

        if key in seen_ids:
            raise ValueError(f"Duplicate source ID detected: {key}")

        seen_ids.add(key)
        all_iocs.append(item)


# Count repeated IOC values efficiently.
ioc_counts = Counter(
    (item["source"], item["ioc"], item["ioc_type"])
    for item in all_iocs
)

same_source_repeated = sum(
    count - 1 for count in ioc_counts.values() if count > 1
)

source_groups = defaultdict(set)

for item in all_iocs:
    source_groups[(item["ioc"], item["ioc_type"])].add(item["source"])

cross_source = sum(
    1 for sources in source_groups.values() if len(sources) > 1
)


# Save only after all validation succeeds.
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
temp_file = OUTPUT_FILE.with_suffix(".tmp")

with temp_file.open("w", encoding="utf-8") as f:
    json.dump(all_iocs, f, indent=2, ensure_ascii=False)

temp_file.replace(OUTPUT_FILE)

print("\n========== MERGE REPORT ==========")
print("Total records preserved:", len(all_iocs))
print("Duplicate source IDs:", 0)
print("Repeated IOC records within same source:", same_source_repeated)
print("IOCs shared across sources:", cross_source)
print("Records by source:", dict(Counter(x["source"] for x in all_iocs)))
print("Saved:", OUTPUT_FILE)
print("==================================")
