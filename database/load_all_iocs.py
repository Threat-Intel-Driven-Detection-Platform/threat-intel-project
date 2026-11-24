import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = ROOT / "data" / "all_iocs.json"
DERIVED_FILE = ROOT / "data" / "url_derived_observables.json"
DEFAULT_DATABASE = ROOT / "data" / "threat_intel.db"


def make_original_ref(source, ioc_id, ioc):
    raw = f"{source}|{ioc_id}|{ioc}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(
        description="Rebuild original IOCs and derived observables."
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=DEFAULT_DATABASE,
        help="Target SQLite database path."
    )
    args = parser.parse_args()

    database_file = args.database.resolve()

    if not INPUT_FILE.exists():
        raise FileNotFoundError(INPUT_FILE)

    if not DERIVED_FILE.exists():
        raise FileNotFoundError(DERIVED_FILE)

    with INPUT_FILE.open("r", encoding="utf-8") as f:
        iocs = json.load(f)

    with DERIVED_FILE.open("r", encoding="utf-8") as f:
        observables = json.load(f)

    database_file.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(database_file)
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        conn.execute("BEGIN")

        # Remove old tables in dependency order.
        conn.execute("DROP TABLE IF EXISTS derived_observables")
        conn.execute("DROP TABLE IF EXISTS iocs")

        # Recreate the original IOC table.
        conn.execute("""
            CREATE TABLE iocs (
                id TEXT,
                ioc TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                threat_type TEXT,
                malware TEXT,
                confidence INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                reporter TEXT,
                tags TEXT,
                original_ioc_ref TEXT,
                UNIQUE(ioc, ioc_type, source)
            )
        """)

        # Insert original IOCs.
        for item in iocs:
            ioc_type = item.get("ioc_type")
            source = item.get("source")
            ioc = item.get("ioc")
            ioc_id = item.get("id")

            original_ref = None

            if ioc_type and ioc_type.lower() == "url":
                original_ref = make_original_ref(
                    source, ioc_id, ioc
                )

            tags = item.get("tags")
            tags_json = (
                json.dumps(tags, ensure_ascii=False)
                if tags is not None else None
            )

            conn.execute("""
                INSERT OR IGNORE INTO iocs (
                    id, ioc, ioc_type, source,
                    threat_type, malware, confidence,
                    first_seen, last_seen, reporter,
                    tags, original_ioc_ref
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc_id,
                ioc,
                ioc_type,
                source,
                item.get("threat_type"),
                item.get("malware"),
                item.get("confidence"),
                item.get("first_seen"),
                item.get("last_seen"),
                item.get("reporter"),
                tags_json,
                original_ref
            ))

        # Restore the unique reference index.
        conn.execute("""
            CREATE UNIQUE INDEX idx_iocs_original_ioc_ref
            ON iocs(original_ioc_ref)
        """)

        # Build the set of references that actually exist.
        valid_refs = {
            row[0]
            for row in conn.execute("""
                SELECT original_ioc_ref
                FROM iocs
                WHERE original_ioc_ref IS NOT NULL
            """)
        }

        # Recreate the derived observables table.
        conn.execute("""
            CREATE TABLE derived_observables (
                observable_id TEXT PRIMARY KEY,
                observable TEXT NOT NULL,
                observable_type TEXT NOT NULL,
                original_ioc_ref TEXT NOT NULL,
                FOREIGN KEY (original_ioc_ref)
                    REFERENCES iocs(original_ioc_ref)
            )
        """)

        # Import derived observables.
        inserted = 0

        for item in observables:
            ref = item["original_ioc_ref"]

            if ref not in valid_refs:
                raise ValueError(
                    f"Missing original IOC reference: {ref}"
                )

            cursor = conn.execute("""
                INSERT OR IGNORE INTO derived_observables (
                    observable_id,
                    observable,
                    observable_type,
                    original_ioc_ref
                )
                VALUES (?, ?, ?, ?)
            """, (
                item["observable_id"],
                item["observable"],
                item["observable_type"],
                ref
            ))

            inserted += cursor.rowcount

        # Validate before committing.
        original_count = conn.execute(
            "SELECT COUNT(*) FROM iocs"
        ).fetchone()[0]

        derived_count = conn.execute(
            "SELECT COUNT(*) FROM derived_observables"
        ).fetchone()[0]

        foreign_key_errors = conn.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        if foreign_key_errors:
            raise RuntimeError(
                f"Foreign key validation failed: {foreign_key_errors[:5]}"
            )

        missing_refs = conn.execute("""
            SELECT COUNT(*)
            FROM derived_observables d
            LEFT JOIN iocs i
                ON d.original_ioc_ref = i.original_ioc_ref
            WHERE i.original_ioc_ref IS NULL
        """).fetchone()[0]

        if missing_refs:
            raise RuntimeError(
                f"Found {missing_refs} orphan derived records."
            )

        conn.commit()

        print("\n========== REBUILD SUCCESS ==========")
        print("Database:", database_file)
        print("Original IOCs:", original_count)
        print("Derived observables:", derived_count)
        print("New derived records inserted:", inserted)
        print("Missing references:", missing_refs)
        print("Foreign key errors:", len(foreign_key_errors))
        print("=====================================")

    except Exception:
        conn.rollback()
        print("Rebuild failed. Transaction rolled back.")
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    main()
