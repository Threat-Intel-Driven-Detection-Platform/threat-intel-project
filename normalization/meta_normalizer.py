import csv
import io
import json
import os
import re
import subprocess


REPO_PATH = "data/raw/meta_threat_research/repository"
OUTPUT_FILE = "data/normalized/meta_normalized.json"


SUPPORTED_TYPES = {
    "domain": "domain",
    "url": "url",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email"
}


def get_csv_files():
    command = [
        "git",
        "-C",
        REPO_PATH,
        "ls-tree",
        "-r",
        "--name-only",
        "HEAD"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8"
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    files = []

    for path in result.stdout.splitlines():
        path = path.strip()

        if not path.lower().startswith("indicators/csv/"):
            continue

        if not path.lower().endswith(".csv"):
            continue

        if path.lower().endswith(".ds_store"):
            continue

        files.append(path)

    return files


def read_git_file(path):
    command = [
        "git",
        "-C",
        REPO_PATH,
        "show",
        f"HEAD:{path}"
    ]

    result = subprocess.run(
        command,
        capture_output=True
    )

    if result.returncode != 0:
        return None

    raw = result.stdout

    for encoding in ["utf-8", "utf-8-sig", "latin-1"]:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue

    return None


def normalize_defanged(value):
    if not value:
        return ""

    value = value.strip()

    # Meta defangs network indicators such as:
    # example[.]com
    value = value.replace("[.]", ".")

    # Common defanged IP notation
    value = value.replace("[", "").replace("]", "")

    return value.strip()


def detect_type(indicator_type, value):
    indicator_type = indicator_type.lower().strip()
    value = value.strip()

    # Explicit Meta indicator type
    if "domain" in indicator_type:
        return "domain"

    if indicator_type == "url" or "url" in indicator_type:
        return "url"

    if "ipv4" in indicator_type or "ip address" in indicator_type:
        return "ipv4"

    if "ipv6" in indicator_type:
        return "ipv6"

    if "md5" in indicator_type:
        return "md5"

    if "sha1" in indicator_type or "sha-1" in indicator_type:
        return "sha1"

    if "sha256" in indicator_type or "sha-256" in indicator_type:
        return "sha256"

    if "email" in indicator_type:
        return "email"

    # Fallback detection
    value_lower = value.lower()

    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "md5"

    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "sha1"

    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "sha256"

    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        value
    ):
        return "ipv4"

    if re.match(r"^https?://", value_lower):
        return "url"

    if "@" in value and "." in value:
        return "email"

    return None


def find_indicator_columns(fieldnames):
    if not fieldnames:
        return None, None

    normalized = {}

    for field in fieldnames:
        clean = field.strip().lower()
        normalized[clean] = field

    type_candidates = [
        "indicator type",
        "type",
        "indicator_type",
        "ioc type",
        "ioc_type"
    ]

    value_candidates = [
        "indicator value",
        "indicator",
        "value",
        "ioc",
        "ioc value",
        "indicator_value"
    ]

    type_column = None
    value_column = None

    for candidate in type_candidates:
        if candidate in normalized:
            type_column = normalized[candidate]
            break

    for candidate in value_candidates:
        if candidate in normalized:
            value_column = normalized[candidate]
            break

    return type_column, value_column


def parse_csv(content, source_file):
    records = []

    try:
        reader = csv.DictReader(io.StringIO(content))

        if not reader.fieldnames:
            return records

        type_column, value_column = find_indicator_columns(
            reader.fieldnames
        )

        # Some Meta files have a different structure.
        # Search all fields if the normal columns aren't found.
        for row in reader:

            indicator_type = ""
            value = ""

            if type_column:
                indicator_type = row.get(type_column, "") or ""

            if value_column:
                value = row.get(value_column, "") or ""

            # Fallback: inspect row values
            if not value:
                for key, cell in row.items():
                    if not cell:
                        continue

                    cell = cell.strip()

                    detected = detect_type("", cell)

                    if detected:
                        value = cell
                        indicator_type = detected
                        break

            if not value:
                continue

            value = normalize_defanged(value)

            canonical_type = detect_type(
                indicator_type,
                value
            )

            if canonical_type not in SUPPORTED_TYPES.values():
                continue

            records.append({
                "source_file": source_file,
                "original_type": indicator_type,
                "value": value,
                "canonical_type": canonical_type
            })

    except Exception as e:
        print(
            f"Warning: failed parsing {source_file}: {e}"
        )

    return records


def main():

    print("================================")
    print("Meta Threat Research Normalization")
    print("================================")

    csv_files = get_csv_files()

    print("CSV files discovered:", len(csv_files))

    normalized_iocs = []
    seen = set()

    files_processed = 0
    files_failed = 0

    for source_file in csv_files:

        content = read_git_file(source_file)

        if content is None:
            files_failed += 1
            continue

        files_processed += 1

        records = parse_csv(
            content,
            source_file
        )

        for record in records:

            value = record["value"]
            canonical_type = record["canonical_type"]

            key = (
                value.lower(),
                canonical_type
            )

            if key in seen:
                continue

            seen.add(key)

            normalized_iocs.append({
                "source_record_id": None,
                "value": value,
                "canonical_type": canonical_type,
                "original_type": record["original_type"],
                "source": "Meta Threat Research",
                "threat_type": "threat_intelligence",
                "malware": None,
                "confidence": None,
                "first_seen": None,
                "last_seen": None,
                "reporter": "Meta",
                "tags": [
                    "meta-threat-research"
                ],
                "status": "active",
                "reference": record["source_file"]
            })

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
            normalized_iocs,
            f,
            indent=4,
            ensure_ascii=False
        )

    print("--------------------------------")
    print("Files processed:", files_processed)
    print("Files failed:", files_failed)
    print("Unique IOCs:", len(normalized_iocs))
    print(
        "Saved to:",
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()