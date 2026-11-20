import json
from collections import Counter

FEEDS = [
    "data/threatfox_normalized.json",
    "data/urlhaus_normalized.json",
    "data/otx_normalized.json",
]
OUTPUT_FILE = "data/all_iocs.json"

ALIASES = {
    "url": "url",
    "ipv4": "ipv4",
    "domain": "domain",
    "hostname": "hostname",
    "ip:port": "ip:port",
    "sha256_hash": "sha256_hash",
    "filehash-sha256": "sha256_hash",
    "sha1_hash": "sha1_hash",
    "filehash-sha1": "sha1_hash",
    "md5_hash": "md5_hash",
    "filehash-md5": "md5_hash",
}

def merge_value(old, new):
    if old in (None, "", []):
        return new
    if new in (None, "", []):
        return old
    if isinstance(old, list) and isinstance(new, list):
        return list(dict.fromkeys(old + new))
    return old

merged = {}
counts = Counter()

for path in FEEDS:
    with open(path, encoding="utf-8") as f:
        records = json.load(f)

    for item in records:
        item = dict(item)
        item["ioc"] = str(item.get("ioc", "")).strip()
        raw_type = str(item.get("ioc_type", "")).strip().lower()
        item["ioc_type"] = ALIASES.get(raw_type, raw_type)

        if not item["ioc"] or not item["ioc_type"]:
            continue

        item.setdefault("tags", [])
        key = (item["ioc"], item["ioc_type"], item.get("source", "unknown"))

        if key not in merged:
            merged[key] = item
        else:
            for field, value in item.items():
                merged[key][field] = merge_value(merged[key].get(field), value)

        counts[item.get("source", "unknown")] += 1

result = list(merged.values())
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print("Feed records:", dict(counts))
print("Merged unique IOC/source records:", len(result))
print("Types:", dict(Counter(x["ioc_type"] for x in result)))
print("Saved:", OUTPUT_FILE)
