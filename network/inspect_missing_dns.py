import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

json_file = ROOT / "data/network/dns_queries.json"
raw_file = ROOT / "zeek/logs/dns.log"

with open(json_file, encoding="utf-8") as f:
    records = json.load(f)

missing_uids = {
    r["uid"]
    for r in records
    if not r.get("domain")
}

with open(raw_file, encoding="utf-8") as f:
    lines = f.readlines()

fields = None
found = 0

for line in lines:
    if line.startswith("#fields"):
        fields = line.strip().split("\t")[1:]
        continue

    if line.startswith("#") or not line.strip():
        continue

    values = line.strip().split("\t")

    if len(values) != len(fields):
        continue

    row = dict(zip(fields, values))

    if row.get("uid") in missing_uids:
        print("UID:", row.get("uid"))
        print("Original query:", row.get("query"))
        print("Original record:", row)
        print("-" * 60)

        found += 1

        if found == 10:
            break

print("Missing records inspected:", found)