import json
from pathlib import Path
from collections import Counter


BASE_DIR = Path(__file__).resolve().parent.parent
NORMALIZED_DIR = BASE_DIR / "data" / "normalized"
OUTPUT_DIR = BASE_DIR / "data" / "database"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "global_iocs.json"


SOURCE_FILES = sorted(
    NORMALIZED_DIR.glob("*_normalized.json")
)


def canonicalize_value(value):
    """
    Basic canonicalization for IOC values.

    We intentionally keep this conservative.
    We do NOT modify hashes or IP addresses.
    """
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    return value


def load_source(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(
            f"{file_path.name} does not contain a JSON list"
        )

    return data


def main():

    print("=" * 70)
    print("GLOBAL IOC MERGE")
    print("=" * 70)

    print(f"Normalized directory: {NORMALIZED_DIR}")
    print(f"Sources discovered: {len(SOURCE_FILES)}")
    print()

    global_iocs = {}

    source_counts = Counter()
    type_counts = Counter()

    total_records = 0
    skipped_records = 0
    duplicate_records = 0

    for file_path in SOURCE_FILES:

        source_name = file_path.stem.replace(
            "_normalized",
            ""
        )

        print(f"Processing: {source_name}")

        records = load_source(file_path)

        print(f"  Records: {len(records):,}")

        source_counts[source_name] += len(records)

        for record in records:

            total_records += 1

            value = canonicalize_value(
                record.get("value")
            )

            ioc_type = record.get(
                "canonical_type"
            )

            if not value or not ioc_type:
                skipped_records += 1
                continue

            type_counts[ioc_type] += 1

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

            if key not in global_iocs:

                global_iocs[key] = {
                    "value": value,
                    "canonical_type": ioc_type,
                    "sources": [],
                    "records": []
                }

            ioc = global_iocs[key]

            if source_name not in ioc["sources"]:
                ioc["sources"].append(source_name)

            ioc["records"].append(record)

            if len(ioc["records"]) > 1:
                duplicate_records += 1

    # ---------------------------------------------------------
    # Sort sources and records for deterministic output
    # ---------------------------------------------------------

    final_iocs = list(global_iocs.values())

    for ioc in final_iocs:
        ioc["sources"].sort()

    final_iocs.sort(
        key=lambda x: (
            x["canonical_type"],
            x["value"].lower()
        )
    )

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    unique_iocs = len(final_iocs)

    source_distribution = Counter()

    for ioc in final_iocs:
        for source in ioc["sources"]:
            source_distribution[source] += 1

    # ---------------------------------------------------------
    # Output
    # ---------------------------------------------------------

    output = {
        "metadata": {
            "total_source_records": total_records,
            "unique_global_iocs": unique_iocs,
            "duplicate_records": duplicate_records,
            "skipped_records": skipped_records,
            "source_files": len(SOURCE_FILES),
            "sources": sorted(source_counts.keys())
        },

        "statistics": {
            "records_by_source": dict(
                source_counts
            ),

            "unique_iocs_by_source": dict(
                source_distribution
            ),

            "records_by_type": dict(
                type_counts
            )
        },

        "iocs": final_iocs
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False
        )

    # ---------------------------------------------------------
    # Console report
    # ---------------------------------------------------------

    print()
    print("=" * 70)
    print("MERGE COMPLETE")
    print("=" * 70)

    print(
        f"Source files:        {len(SOURCE_FILES):,}"
    )

    print(
        f"Total records:       {total_records:,}"
    )

    print(
        f"Unique global IOCs:  {unique_iocs:,}"
    )

    print(
        f"Duplicate records:   {duplicate_records:,}"
    )

    print(
        f"Skipped records:     {skipped_records:,}"
    )

    print()
    print("Unique IOCs by source:")
    print("-" * 40)

    for source, count in sorted(
        source_distribution.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(
            f"{source:<20} {count:>10,}"
        )

    print()
    print("Records by IOC type:")
    print("-" * 40)

    for ioc_type, count in sorted(
        type_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(
            f"{ioc_type:<20} {count:>10,}"
        )

    print()
    print(
        f"Output: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()