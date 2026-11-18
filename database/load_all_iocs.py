import sqlite3
import json


INPUT_FILE = "data/all_iocs.json"
DATABASE_FILE = "data/threat_intel.db"


# Load all normalized IOCs
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    iocs = json.load(f)


# Connect to database
connection = sqlite3.connect(DATABASE_FILE)
cursor = connection.cursor()


# Recreate the IOC table
cursor.execute("DROP TABLE IF EXISTS iocs")

cursor.execute("""
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
    UNIQUE(ioc, ioc_type, source)
)
""")


# Insert all IOCs
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


connection.commit()


# Verify database
cursor.execute("SELECT COUNT(*) FROM iocs")
total = cursor.fetchone()[0]

cursor.execute("""
SELECT source, COUNT(*)
FROM iocs
GROUP BY source
""")

sources = cursor.fetchall()


print(f"Total IOCs in database: {total}")

print("\nIOCs by source:")
for source, count in sources:
    print(f"  {source}: {count}")


connection.close()