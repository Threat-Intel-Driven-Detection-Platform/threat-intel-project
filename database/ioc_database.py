import sqlite3
import json


INPUT_FILE = "data/iocs_deduplicated.json"
DATABASE_FILE = "data/threat_intel.db"


# Read normalized IOC data
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    iocs = json.load(f)


# Connect to SQLite database
connection = sqlite3.connect(DATABASE_FILE)
cursor = connection.cursor()


# Create IOC table
cursor.execute("""
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


# Insert IOCs
for item in iocs:

    cursor.execute("""
    INSERT OR IGNORE INTO iocs (
        id,
        ioc,
        ioc_type,
        source,
        threat_type,
        malware,
        confidence,
        first_seen,
        last_seen,
        reporter,
        tags
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        item["id"],
        item["ioc"],
        item["ioc_type"],
        item["source"],
        item["threat_type"],
        item["malware"],
        item["confidence"],
        item["first_seen"],
        item["last_seen"],
        item["reporter"],
        json.dumps(item["tags"])
    ))


# Save changes
connection.commit()


# Check number of records
cursor.execute("SELECT COUNT(*) FROM iocs")
count = cursor.fetchone()[0]


print(f"Database created: {DATABASE_FILE}")
print(f"IOCs stored: {count}")


connection.close()