# Threat Intelligence Database
## Database Schema & Data Dictionary

### 1. Overview
The SQLite database contains two tables:
- iocs: Original threat intelligence indicators.
- derived_observables: IP addresses, domains, and ports extracted from original URLs.

Derived observables are not additional original feed IOCs.

### 2. iocs Table

| Column | Type | Nullable | Description |
|---|---|---|---|
| id | TEXT | Yes | Original source record ID |
| ioc | TEXT | No | Original indicator value |
| ioc_type | TEXT | No | Original indicator type |
| source | TEXT | No | Threat intelligence feed |
| threat_type | TEXT | Yes | Threat classification |
| malware | TEXT | Yes | Associated malware |
| confidence | INTEGER | Yes | Source-provided confidence |
| first_seen | TEXT | Yes | First observed timestamp |
| last_seen | TEXT | Yes | Last observed timestamp |
| reporter | TEXT | Yes | Reporter information |
| tags | TEXT | Yes | Additional tags |
| original_ioc_ref | TEXT | Yes | Reference linking original URLs to derived records |

### 3. derived_observables Table

| Column | Type | Nullable | Description |
|---|---|---|---|
| observable_id | TEXT | No | Primary key |
| observable | TEXT | No | Extracted value |
| observable_type | TEXT | No | ip, domain, or port |
| original_ioc_ref | TEXT | No | Foreign key referencing iocs.original_ioc_ref |

### 4. Relationships
One original URL IOC can produce multiple derived observables.

The relationship is implemented through:
derived_observables.original_ioc_ref -> iocs.original_ioc_ref

The original_ioc_ref column in iocs has a unique index named idx_iocs_original_ioc_ref.

### 5. Observable Types
- ip: IP address explicitly present in a URL.
- domain: Domain extracted from a URL hostname.
- port: Explicit port included in a URL.

Ports must not be matched as standalone malicious indicators.

### 6. Data Provenance
Every derived observable retains original_ioc_ref, allowing analysts to retrieve the original URL, source, threat type, confidence, and timestamps through a JOIN.

### 7. Data Quality
- Original IOCs: 35,707
- Derived observables: 46,028
- Missing confidence: 33,740
- URLhaus and OTX records have missing confidence in the current dataset.
- Missing confidence values remain NULL; no default values are invented.
- Extracted IPs are not DNS-resolved addresses.

### 8. Database Information
- Engine: SQLite
- Database: data/threat_intel.db
- Extraction script: normalization/extract_url_observables.py
- Import script: database/add_derived_observables.py
- Quality report: docs/week4_ioc_distribution_report.md

### 9. Current Derived Statistics

| Type | Count |
|---|---:|
| IP | 15,509 |
| Domain | 18,443 |
| Port | 12,076 |
