import json
from pathlib import Path
from collections import Counter


BASE_DIR = Path(__file__).resolve().parent.parent

DB_FILE = BASE_DIR / "data" / "database" / "global_iocs.json"


ALLOWED_TYPES = {
    "domain",
    "hostname",
    "ipv4",
    "ip_port",
    "url",
    "sha256",
    "sha1",
    "md5",
    "email"
}


def main():

    print("=" * 70)
    print("GLOBAL IOC DATABASE VALIDATION")
    print("=" * 70)

    with open(DB_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    iocs = data["iocs"]
    metadata = data["metadata"]

    print(f"Loaded IOCs: {len(iocs):,}")

    errors = []

    seen = set()
    type_counts = Counter()
    source_counts = Counter()

    for index, ioc in enumerate(iocs):

        value = ioc.get("value")
        ioc_type = ioc.get("canonical_type")
        sources = ioc.get("sources")

        # Required fields
        if not value:
            errors.append(
                f"IOC #{index}: missing value"
            )

        if not ioc_type:
            errors.append(
                f"IOC #{index}: missing canonical_type"
            )

        if not sources:
            errors.append(
                f"IOC #{index}: missing sources"
            )

        # Type validation
        if ioc_type not in ALLOWED_TYPES:
            errors.append(
                f"IOC #{index}: invalid type {ioc_type}"
            )

        # Duplicate validation
        key = (
            value.lower()
            if ioc_type in {
                "domain",
                "hostname",
                "url",
                "email"
            }
            else value,
            ioc_type
        )

        if key in seen:
            errors.append(
                f"Duplicate IOC: {ioc_type} / {value}"
            )

        seen.add(key)

        type_counts[ioc_type] += 1

        for source in sources:
            source_counts[source] += 1

    print()
    print("Validation Results")
    print("-" * 40)

    print(
        f"Required fields: {'PASS' if not errors else 'FAIL'}"
    )

    print(
        f"Unique IOC keys: {'PASS' if len(seen) == len(iocs) else 'FAIL'}"
    )

    print(
        f"IOC types: {'PASS' if all(t in ALLOWED_TYPES for t in type_counts) else 'FAIL'}"
    )

    print()

    if errors:

        print(
            f"Errors found: {len(errors):,}"
        )

        for error in errors[:20]:
            print(" -", error)

        if len(errors) > 20:
            print(
                f"... and {len(errors) - 20:,} more"
            )

        raise SystemExit(1)

    print("ALL VALIDATION TESTS PASSED")

    print()
    print("IOC Type Distribution")
    print("-" * 40)

    for ioc_type, count in type_counts.most_common():
        print(
            f"{ioc_type:<15} {count:>10,}"
        )

    print()
    print("Source Coverage")
    print("-" * 40)

    for source, count in source_counts.most_common():
        print(
            f"{source:<15} {count:>10,}"
        )

    print()
    print("=" * 70)
    print("DATABASE VALIDATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()