import os
import json
import re

INPUT_DIR = "data/raw/talos/repository"
OUTPUT_FILE = "data/normalized/talos_normalized.json"

normalized_iocs = []
seen = set()

PATTERN_RE = re.compile(
    r"\[(?:[^\]]+)\s*=\s*['\"]([^'\"]+)['\"]\]"
)


def extract_ioc(pattern):
    if not pattern:
        return None

    match = PATTERN_RE.search(pattern)

    if match:
        return match.group(1)

    return None


def type_from_pattern(pattern):
    pattern_lower = pattern.lower()

    if "sha256" in pattern_lower:
        return "sha256"

    if "sha1" in pattern_lower:
        return "sha1"

    if "md5" in pattern_lower:
        return "md5"

    if "domain-name:value" in pattern_lower:
        return "domain"

    if "ipv4-addr:value" in pattern_lower:
        return "ipv4"

    if "ipv6-addr:value" in pattern_lower:
        return "ipv6"

    if "url:value" in pattern_lower:
        return "url"

    if "email-addr:value" in pattern_lower:
        return "email"

    return None


json_files = 0
indicator_objects = 0

for root, dirs, files in os.walk(INPUT_DIR):

    for filename in files:

        if not filename.lower().endswith(".json"):
            continue

        filepath = os.path.join(root, filename)
        json_files += 1

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                bundle = json.load(f)

        except Exception as e:
            print("Failed to read:", filepath)
            print("Error:", e)
            continue

        for obj in bundle.get("objects", []):

            if obj.get("type") != "indicator":
                continue

            indicator_objects += 1

            pattern = obj.get("pattern")
            value = extract_ioc(pattern)
            canonical_type = type_from_pattern(pattern)

            if not value or not canonical_type:
                continue

            value = value.strip()

            key = (
                value.lower(),
                canonical_type
            )

            if key in seen:
                continue

            seen.add(key)

            labels = obj.get("labels", [])

            normalized_iocs.append({
                "source_record_id": obj.get("id"),
                "value": value,
                "canonical_type": canonical_type,
                "original_type": pattern,
                "source": "Cisco Talos",
                "threat_type": "threat_intelligence",
                "malware": obj.get("description"),
                "confidence": None,
                "first_seen": obj.get("valid_from"),
                "last_seen": obj.get("modified"),
                "reporter": "Cisco Talos",
                "tags": labels,
                "status": "active",
                "reference": filename
            })


os.makedirs(
    os.path.dirname(OUTPUT_FILE),
    exist_ok=True
)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized_iocs, f, indent=4)


print("================================")
print("Cisco Talos Normalization")
print("================================")
print("JSON files scanned:", json_files)
print("Indicator objects:", indicator_objects)
print("Unique IOCs:", len(normalized_iocs))
print("Duplicates removed:",
      indicator_objects - len(normalized_iocs))
print("Saved to:", OUTPUT_FILE)