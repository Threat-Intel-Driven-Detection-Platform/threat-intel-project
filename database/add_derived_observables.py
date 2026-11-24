
import json
import sqlite3
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DB_FILE = ROOT / "data" / "threat_intel.db"
INPUT_FILE = ROOT / "data" / "url_derived_observables.json"


def main():
    with INPUT_FILE.open(encoding="utf-8") as f:
        observables = json.load(f)

    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        conn.execute("BEGIN")

        # Add a unique reference to original IOC records.
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(iocs)")
        }

        if "original_ioc_ref" not in columns:
            conn.execute(
                "ALTER TABLE iocs ADD COLUMN original_ioc_ref TEXT"
            )

        # Create the derived observables table.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS derived_observables (
                observable_id TEXT PRIMARY KEY,
                observable TEXT NOT NULL,
                observable_type TEXT NOT NULL,
                original_ioc_ref TEXT NOT NULL,
                FOREIGN KEY (original_ioc_ref)
                    REFERENCES iocs(original_ioc_ref)
            )
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_iocs_original_ioc_ref
            ON iocs(original_ioc_ref)
        """)

        # Populate references for original URL records.
        rows = conn.execute("""
            SELECT id, ioc, ioc_type, source
            FROM iocs
            WHERE LOWER(ioc_type) = 'url'
        """).fetchall()

        ref_map = {}

        for ioc_id, ioc, ioc_type, source in rows:
            raw = f"{source}|{ioc_id}|{ioc}"
            ref = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()[:16]

            conn.execute("""
                UPDATE iocs
                SET original_ioc_ref = ?
                WHERE id = ? AND ioc = ?
                AND ioc_type = ? AND source = ?
            """, (ref, ioc_id, ioc, ioc_type, source))

            ref_map[ref] = True

        # Insert derived records.
        inserted = 0

        for item in observables:
            ref = item["original_ioc_ref"]

            if ref not in ref_map:
                raise ValueError(
                    f"Original IOC reference not found: {ref}"
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

        conn.commit()

        original_count = conn.execute("""
            SELECT COUNT(*) FROM iocs
        """).fetchone()[0]

        derived_count = conn.execute("""
            SELECT COUNT(*) FROM derived_observables
        """).fetchone()[0]

        print("Migration completed successfully.")
        print("Original IOCs:", original_count)
        print("Derived records:", derived_count)
        print("New records inserted:", inserted)

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    main()
