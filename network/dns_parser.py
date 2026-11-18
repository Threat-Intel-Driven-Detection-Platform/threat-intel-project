
import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "zeek" / "logs" / "dns.log"
OUTPUT_FILE = PROJECT_ROOT / "data" / "network" / "dns_queries.json"


def parse_optional(value, data_type=str):
    """Convert missing Zeek values into None."""

    if value in ("-", "(empty)", ""):
        return None

    try:
        return data_type(value)
    except (ValueError, TypeError):
        return None


def parse_vector(value):
    """Convert Zeek vector fields into Python lists."""

    if value in ("-", "(empty)", ""):
        return []

    return [item.strip() for item in value.split(",") if item.strip()]


def parse_dns():
    records = []
    malformed = 0
    fields = None

    with open(INPUT_FILE, "r", encoding="utf-8") as file:

        for line in file:

            # Extract column names
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue

            # Skip metadata
            if line.startswith("#") or not line.strip():
                continue

            if fields is None:
                continue

            values = line.rstrip("\n").split("\t")

            if len(values) != len(fields):
                malformed += 1
                continue

            row = dict(zip(fields, values))

            timestamp_unix = parse_optional(
                row.get("ts"), float
            )

            timestamp = None

            if timestamp_unix is not None:
                timestamp = datetime.fromtimestamp(
                    timestamp_unix, timezone.utc
                ).isoformat()

            record = {
                "timestamp": timestamp,
                "timestamp_unix": timestamp_unix,
                "uid": row.get("uid"),
                "src_ip": row.get("id.orig_h"),
                "src_port": parse_optional(
                    row.get("id.orig_p"), int
                ),
                "dst_ip": row.get("id.resp_h"),
                "dst_port": parse_optional(
                    row.get("id.resp_p"), int
                ),
                "protocol": row.get("proto"),
                "domain": parse_optional(row.get("query")),
                "query_type": parse_optional(
                    row.get("qtype_name")
                ),
                "response_code": parse_optional(
                    row.get("rcode_name")
                ),
                "answers": parse_vector(row.get("answers"))
            }

            records.append(record)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output:
        json.dump(records, output, indent=2, ensure_ascii=False)

    print("DNS parsing completed!")
    print(f"Total records: {len(records)}")
    print(f"Malformed records: {malformed}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    parse_dns()
