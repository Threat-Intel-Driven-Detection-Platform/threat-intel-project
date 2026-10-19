import json
import os
import re


INPUT_FILE = "data/raw/misp/circl_osint_raw.json"
OUTPUT_FILE = "data/normalized/circl_normalized.json"


TYPE_MAP = {
    "domain": "domain",
    "hostname": "hostname",
    "ip-dst": "ipv4",
    "ip-src": "ipv4",
    "ip-dst|port": "ip_port",
    "ip-src|port": "ip_port",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "email-subject": "email",
    "filename|md5": "md5",
    "filename|sha1": "sha1",
    "filename|sha256": "sha256",
}


def clean_value(value):
    if not isinstance(value, str):
        return ""

    value = value.strip()

    # Defanging
    value = value.replace("[.]", ".")
    value = value.replace("[://]", "://")
    value = value.replace("[:]", ":")
    value = value.replace("[@]", "@")

    return value


def extract_ip_port(value):
    value = clean_value(value)

    # IPv4:port
    match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", value)

    if match:
        return value

    return value


def normalize_attribute(attribute, event):
    attr_type = attribute.get("type", "").lower()
    raw_value = attribute.get("value", "")

    if not raw_value:
        return None

    canonical_type = TYPE_MAP.get(attr_type)

    if not canonical_type:
        return None

    value = clean_value(raw_value)

    if not value:
        return None

    if canonical_type == "ip_port":
        value = extract_ip_port(value)

    return {
        "value": value,
        "canonical_type": canonical_type,
        "source": "CIRCL",
        "source_record_id": attribute.get("uuid"),
        "event_id": event.get("id"),
        "event_uuid": event.get("uuid"),
        "event_info": event.get("info"),
        "first_seen": attribute.get("first_seen"),
        "last_seen": attribute.get("last_seen"),
        "timestamp": attribute.get("timestamp"),
        "to_ids": attribute.get("to_ids"),
        "category": attribute.get("category"),
        "comment": attribute.get("comment"),
        "tags": [
            tag.get("name")
            for tag in attribute.get("Tag", [])
            if tag.get("name")
        ],
        "event_tags": [
            tag.get("name")
            for tag in event.get("Tag", [])
            if tag.get("name")
        ],
    }


def main():
    print("=" * 40)
    print("CIRCL MISP Normalization")
    print("=" * 40)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    events_container = raw_data.get("events", [])

    normalized = []
    seen = set()

    files_processed = 0
    attributes_seen = 0
    unsupported = 0

    for item in events_container:

        event_wrapper = item.get("data", {})
        event = event_wrapper.get("Event", {})

        if not event:
            continue

        files_processed += 1

        attributes = event.get("Attribute", [])

        for attribute in attributes:

            attributes_seen += 1

            record = normalize_attribute(attribute, event)

            if record is None:
                unsupported += 1
                continue

            key = (
                record["canonical_type"],
                record["value"].lower()
            )

            if key in seen:
                continue

            seen.add(key)
            normalized.append(record)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)

    duplicates = len(normalized)

    print()
    print("=" * 40)
    print("CIRCL MISP Normalization Complete")
    print("=" * 40)
    print(f"Events processed: {files_processed}")
    print(f"Attributes scanned: {attributes_seen}")
    print(f"Unique IOCs: {len(normalized)}")
    print(f"Unsupported/skipped: {unsupported}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
