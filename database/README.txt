THREAT INTEL DATABASE

This package creates the real SQLite database for the Threat-Intel-Driven Detection Platform.

1) Put global_iocs.json at:
   data\database\global_iocs.json

2) Copy this package's database folder into the project so you have:
   database\schema.sql
   database\build_database.py
   database\query_database.py

3) From the project root run:
   python database\build_database.py

4) The database will be created at:
   data\database\threat_intel.db

No MySQL/PostgreSQL/XAMPP server is required. SQLite is built into Python.

Query example:
   python database\query_database.py 0-solucionegos.top

The builder preserves IOC value/type, source provenance, observations, tags, malware, MITRE IDs, references and raw source metadata when those fields exist.
