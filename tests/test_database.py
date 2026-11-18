import sqlite3


DATABASE_FILE = "data/threat_intel.db"

connection = sqlite3.connect(DATABASE_FILE)
cursor = connection.cursor()


# Total IOCs
cursor.execute("SELECT COUNT(*) FROM iocs")
total = cursor.fetchone()[0]

print(f"Total IOCs: {total}")


# IOCs by source
print("\nIOCs by Source:")

cursor.execute("""
SELECT source, COUNT(*)
FROM iocs
GROUP BY source
ORDER BY COUNT(*) DESC
""")

for source, count in cursor.fetchall():
    print(f"  {source}: {count}")


# IOCs by type
print("\nIOC Types:")

cursor.execute("""
SELECT ioc_type, COUNT(*)
FROM iocs
GROUP BY ioc_type
ORDER BY COUNT(*) DESC
""")

for ioc_type, count in cursor.fetchall():
    print(f"  {ioc_type}: {count}")


# Threat types
print("\nThreat Types:")

cursor.execute("""
SELECT threat_type, COUNT(*)
FROM iocs
GROUP BY threat_type
ORDER BY COUNT(*) DESC
LIMIT 10
""")

for threat_type, count in cursor.fetchall():
    print(f"  {threat_type}: {count}")


connection.close()