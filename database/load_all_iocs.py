import json
import sqlite3
import shutil
from datetime import datetime
from pathlib import Path

INPUT_FILE = Path("data/iocs_deduplicated.json")
DATABASE_FILE = Path("data/threat_intel.db")

if not INPUT_FILE.exists():
    raise SystemExit(f"Missing input file: {INPUT_FILE}")
if not DATABASE_FILE.exists():
    raise SystemExit(f"Database not found: {DATABASE_FILE}")

with INPUT_FILE.open(encoding="utf-8") as f:
    records = json.load(f)

backup = DATABASE_FILE.with_name(
    f"{DATABASE_FILE.stem}.before_safe_load_{datetime.now():%Y%m%d_%H%M%S}.db"
)
shutil.copy2(DATABASE_FILE, backup)
print("Database backup:", backup)

db = sqlite3.connect(DATABASE_FILE)
try:
    db.execute("BEGIN IMMEDIATE")

    db.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
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
        UNIQUE(ioc, ioc_type, source)
    )
    """)

    # Normalize existing type labels without deleting existing records.
    aliases = {
        "URL": "url",
        "IPv4": "ipv4",
        "FileHash-SHA256": "sha256_hash",
        "FileHash-SHA1": "sha1_hash",
        "FileHash-MD5": "md5_hash",
    }
    for old_type, new_type in aliases.items():
        db.execute(
            "UPDATE OR IGNORE iocs SET ioc_type=? WHERE ioc_type=?",
            (new_type, old_type),
        )

    inserted = 0
    for item in records:
        cur = db.execute("""
            INSERT OR IGNORE INTO iocs (
                id, ioc, ioc_type, source, threat_type, malware,
                confidence, first_seen, last_seen, reporter, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item.get("id"),
            item["ioc"],
            item["ioc_type"].lower(),
            item.get("source", "unknown"),
            item.get("threat_type"),
            item.get("malware"),
            item.get("confidence"),
            item.get("first_seen"),
            item.get("last_seen"),
            item.get("reporter"),
            json.dumps(item.get("tags") or []),
        ))
        inserted += cur.rowcount

    db.commit()
    total = db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    print("New records inserted:", inserted)
    print("Total records in database:", total)
    print("Records by source:")
    for source, count in db.execute(
        "SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY source"
    ):
        print(f"  {source}: {count}")
except Exception:
    db.rollback()
    raise
finally:
    db.close()
