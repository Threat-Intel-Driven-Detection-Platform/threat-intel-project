import json
import os
from datetime import datetime


INPUT_FILE = "data/raw/otx/otx_raw.json"
OUTPUT_FILE = "data/normalized/otx_normalized.json"


TYPE_MAPPING = {
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "domain": "domain",
    "hostname": "hostname",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "email": "email",
    "Email": "email",
}


def normalize_value(value):
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    # Defanged indicators
    value = value.replace("[.]", ".")
    value = value.replace("[:]", ":")

    return value


def normalize_indicator(indicator, pulse):
    raw_type = indicator.get("type")
    raw_value = indicator.get("indicator")

    canonical_type = TYPE_MAPPING.get(raw_type)

    # CVEs are vulnerability intelligence, not IOC records
    if raw_type == "CVE":
        return None

    if not canonical_type:
        return None

    value = normalize_value(raw_value)

    if not value:
        return None

    record = {
        "value": value,
        "canonical_type": canonical_type,

        "source": "AlienVault OTX",

        "source_record_id": str(indicator.get("id", "")),

        "pulse_id": pulse.get("id"),
        "pulse_name": pulse.get("name"),

        "first_seen": indicator.get("created"),
        "last_seen": None,
        "expiration": indicator.get("expiration"),

        "confidence": None,

        "status": (
            "active"
            if indicator.get("is_active") == 1
            else "inactive"
        ),

        "threat_type": None,

        "malware": pulse.get("malware_families", []),

        "tags": pulse.get("tags", []),

        "description": (
            indicator.get("description")
            or pulse.get("description")
            or ""
        ),

        "tlp": pulse.get("tlp"),

        "mitre_techniques": pulse.get("attack_ids", []),

        "reference": pulse.get("references", []),

        "targeted_countries": pulse.get(
            "targeted_countries", []
        ),

        "industries": pulse.get(
            "industries", []
        ),
    }

    return record


def main():

    print("=" * 32)
    print("AlienVault OTX Normalization")
    print("=" * 32)

    if not os.path.exists(INPUT_FILE):
        print(f"Input file not found: {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    pulses = data.get("results", [])

    print(f"Pulses found: {len(pulses)}")

    normalized = []
    seen = set()

    skipped_unknown = 0
    skipped_cve = 0
    duplicate_count = 0

    for pulse in pulses:

        indicators = pulse.get("indicators", [])

        for indicator in indicators:

            raw_type = indicator.get("type")

            if raw_type == "CVE":
                skipped_cve += 1
                continue

            record = normalize_indicator(
                indicator,
                pulse
            )

            if record is None:
                skipped_unknown += 1
                continue

            key = (
                record["canonical_type"],
                record["value"].lower()
            )

            if key in seen:
                duplicate_count += 1
                continue

            seen.add(key)
            normalized.append(record)

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
            normalized,
            f,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("================================")
    print("OTX Normalization Complete")
    print("================================")

    print(f"Pulses processed: {len(pulses)}")
    print(f"Normalized IOCs: {len(normalized)}")
    print(f"Duplicates removed: {duplicate_count}")
    print(f"CVE indicators skipped: {skipped_cve}")
    print(f"Unknown/unsupported skipped: {skipped_unknown}")

    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()