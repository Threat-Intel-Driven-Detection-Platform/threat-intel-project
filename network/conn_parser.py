
import json
import csv
from pathlib import Path
from datetime import datetime, timezone


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "zeek" / "logs" / "conn.log"
OUTPUT_FILE = PROJECT_ROOT / "data" / "network" / "connections.json"


def parse_optional(value, data_type=str):
    """Convert Zeek missing values into None."""
    if value in ("-", "(empty)", ""):
        return None

    try:
        return data_type(value)
    except (ValueError, TypeError):
        return None


def parse_connections():
    records = []
    malformed = 0
    fields = None

    with open(INPUT_FILE, "r", encoding="utf-8") as file:

        for line in file:

            # Read column names
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue

            # Skip Zeek metadata
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
                "service": parse_optional(row.get("service")),
                "duration": parse_optional(
                    row.get("duration"), float
                ),
                "orig_bytes": parse_optional(
                    row.get("orig_bytes"), int
                ),
                "resp_bytes": parse_optional(
                    row.get("resp_bytes"), int
                ),
                "conn_state": parse_optional(
                    row.get("conn_state")
                )
            }

            records.append(record)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output:
        json.dump(records, output, indent=2, ensure_ascii=False)

    print("Connection parsing completed!")
    print(f"Total records: {len(records)}")
    print(f"Malformed records: {malformed}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    parse_connections()
