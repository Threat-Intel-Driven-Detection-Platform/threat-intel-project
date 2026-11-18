import json

THREATFOX_FILE = "data/threatfox_normalized.json"
URLHAUS_FILE = "data/urlhaus_normalized.json"
OTX_FILE = "data/otx_normalized.json"

OUTPUT_FILE = "data/all_iocs.json"


# Load ThreatFox IOCs
with open(THREATFOX_FILE, "r", encoding="utf-8") as f:
    threatfox_iocs = json.load(f)


# Load URLhaus IOCs
with open(URLHAUS_FILE, "r", encoding="utf-8") as f:
    urlhaus_iocs = json.load(f)


# Load OTX IOCs
with open(OTX_FILE, "r", encoding="utf-8") as f:
    otx_iocs = json.load(f)


# Merge all sources
all_iocs = threatfox_iocs + urlhaus_iocs + otx_iocs


# Deduplicate IOCs
unique_iocs = []
seen = set()
duplicates = 0


for item in all_iocs:

    key = (item["ioc"], item["ioc_type"])

    if key in seen:
        duplicates += 1
        continue

    seen.add(key)
    unique_iocs.append(item)


# Save merged and deduplicated data
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(unique_iocs, f, indent=4)


# Results
print(f"ThreatFox IOCs: {len(threatfox_iocs)}")
print(f"URLhaus IOCs: {len(urlhaus_iocs)}")
print(f"OTX IOCs: {len(otx_iocs)}")
print(f"Total before deduplication: {len(all_iocs)}")
print(f"Unique IOCs: {len(unique_iocs)}")
print(f"Duplicates removed: {duplicates}")
print(f"Saved to {OUTPUT_FILE}")