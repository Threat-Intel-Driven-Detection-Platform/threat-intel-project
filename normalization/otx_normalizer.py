
import json
import hashlib
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = ROOT / "data" / "otx_checkpoint.json"
OUTPUT_FILE = ROOT / "data" / "otx_normalized.json"

TYPE_MAP = {
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "ipv4": "ip",
    "filehash-sha256": "sha256_hash",
    "filehash-sha1": "sha1_hash",
    "filehash-md5": "md5_hash",
    "cve": "cve",
    "yara": "yara",
    "email": "email",
    "sslcertfingerprint": "ssl_cert_fingerprint",
    "bitcoinaddress": "bitcoin_address",
}


def make_record_id(pulse_id, indicator_id, indicator, first_seen):
    """
    Generate a deterministic ID for each OTX observation.
    Including first_seen preserves separate observations of the
    same indicator within the same pulse.
    """
    raw = (
        f"OTX|{pulse_id}|{indicator_id}|"
        f"{indicator}|{first_seen}"
    )

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"OTX checkpoint not found: {INPUT_FILE}"
        )

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        raw_data = json.load(file)

    pulses = raw_data.get("results", [])

    if not isinstance(pulses, list):
        raise ValueError("Invalid OTX checkpoint: results must be a list")

    normalized_iocs = []
    skipped = 0

    for pulse in pulses:
        if not isinstance(pulse, dict):
            skipped += 1
            continue

        pulse_id = pulse.get("id")
        indicators = pulse.get("indicators") or []

        for indicator in indicators:
            if not isinstance(indicator, dict):
                skipped += 1
                continue

            value = indicator.get("indicator")
            original_type = indicator.get("type")

            if not value or not original_type:
                skipped += 1
                continue

            first_seen = indicator.get("created")
            indicator_id = indicator.get("id")

            type_key = str(original_type).strip().lower()

            normalized_type = TYPE_MAP.get(
                type_key,
                type_key.replace("-", "_").replace(" ", "_")
            )

            record = {
                "id": make_record_id(
                    pulse_id,
                    indicator_id,
                    value,
                    first_seen
                ),
                "source_id": (
                    str(indicator_id)
                    if indicator_id is not None
                    else None
                ),
                "pulse_id": (
                    str(pulse_id)
                    if pulse_id is not None
                    else None
                ),
                "ioc": str(value).strip(),
                "ioc_type": normalized_type,
                "original_ioc_type": original_type,
                "source": "OTX",
                "threat_type": "threat_intelligence",
                "malware": None,
                "confidence": None,
                "first_seen": first_seen,
                "last_seen": pulse.get("modified"),
                "reporter": pulse.get("author_name"),
                "tags": [
                    tag
                    for tag in (
                        [pulse.get("name"), pulse.get("adversary")]
                        + (pulse.get("tags") or [])
                    )
                    if tag
                ],
            }

            normalized_iocs.append(record)

    # Validate generated record IDs before saving.
    id_counts = Counter(
        (record["source"], record["id"])
        for record in normalized_iocs
    )

    duplicate_groups = {
        key: count
        for key, count in id_counts.items()
        if count > 1
    }

    if duplicate_groups:
        raise ValueError(
            f"Duplicate IDs still exist: {len(duplicate_groups)} groups. "
            "Output was not overwritten."
        )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    temp_file = OUTPUT_FILE.with_suffix(".json.tmp")

    with open(temp_file, "w", encoding="utf-8") as file:
        json.dump(
            normalized_iocs,
            file,
            indent=2,
            ensure_ascii=False
        )

    temp_file.replace(OUTPUT_FILE)

    type_counts = Counter(
        record["ioc_type"]
        for record in normalized_iocs
    )

    print("OTX NORMALIZATION COMPLETED")
    print(f"Input pulses: {len(pulses)}")
    print(f"Normalized indicators: {len(normalized_iocs)}")
    print(f"Skipped indicators: {skipped}")
    print(f"Duplicate ID groups: {len(duplicate_groups)}")
    print(f"Saved to: {OUTPUT_FILE}")

    print("\nIOC counts by normalized type:")

    for ioc_type, count in type_counts.most_common():
        print(f"{ioc_type}: {count}")


if __name__ == "__main__":
    main()
