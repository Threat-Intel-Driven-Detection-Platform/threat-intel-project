# Threat Intelligence Database
## Database Schema & Data Dictionary

### 1. Overview

The SQLite database contains two main tables:

- `iocs`: Stores original threat intelligence indicators collected from URLhaus, ThreatFox, and AlienVault OTX.
- `derived_observables`: Stores IP addresses, domains, and explicit ports extracted from original URL IOCs.

Derived observables are not additional original feed IOCs. They retain references to their original URL records.

### 2. iocs Table

| Column | Type | Nullable | Description |
|---|---|---|---|
| id | TEXT | No | Original source record ID |
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
| original_ioc_ref | TEXT | Yes | Unique reference used to link derived observables to original IOC records |

**Record Identity and Constraints**

- Original records are identified by the combination of `source` and `id`.
- A unique constraint is applied to `(source, id)`.
- `original_ioc_ref` has a unique constraint to prevent reference collisions.
- Repeated IOC values are not automatically discarded when they have different source record IDs.

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

`derived_observables.original_ioc_ref -> iocs.original_ioc_ref`

This relationship allows analysts to trace every extracted observable back to its original URL IOC.

### 5. Observable Types

- `ip`: IP address explicitly present as a URL hostname.
- `domain`: Domain extracted from a URL hostname.
- `port`: Explicit port included in a URL.

Ports must not be matched as standalone malicious indicators.

Extracted IP addresses represent URL host values; they are not DNS-resolved addresses.

### 6. Data Provenance

Every derived observable retains `original_ioc_ref`.

Analysts can retrieve the original URL, source, threat type, confidence, and timestamps through a JOIN between `derived_observables` and `iocs`.

### 7. Current Data Quality and Statistics

The following figures represent the current production database.

**Original IOCs: 119,989**

| Source | Count |
|---|---:|
| OTX | 80,621 |
| URLhaus | 33,209 |
| ThreatFox | 6,159 |
| **Total** | **119,989** |

**Derived Observables: 51,192**

| Type | Count |
|---|---:|
| IP | 16,200 |
| Domain | 22,279 |
| Port | 12,713 |
| **Total** | **51,192** |

**Data Quality Results**

| Check | Result |
|---|---:|
| Missing IOC | 0 |
| Missing IOC Type | 0 |
| Missing Source | 0 |
| Missing Threat Type | 0 |
| Missing First Seen | 0 |
| Missing Confidence | 113,830 |
| Invalid Confidence | 0 |
| Duplicate Original IOC Groups | 4,443 |
| Missing Derived Observable | 0 |
| Missing Derived Type | 0 |
| Missing Original Reference | 0 |

Missing confidence values remain `NULL`; no default values are invented.

The OTX dataset represents a partial collection, not the complete subscribed-pulses feed.

### 8. Database Information

- Engine: SQLite
- Database: `data/threat_intel.db`
- Merge script: `normalization/merge_iocs.py`
- URL extraction script: `normalization/extract_url_observables.py`
- Quality report: `normalization/ioc_quality_report.py`
- Complete database rebuild script: `database/load_all_iocs.py`

### 9. Rebuild Instructions

Run from the project root:

```powershell
python database/load_all_iocs.py
```

Required input files:

- `data/all_iocs.json`
- `data/url_derived_observables.json`

To rebuild a separate test database:

```powershell
python database/load_all_iocs.py --database data/threat_intel_rebuild_test.db
```

The rebuild process recreates both tables, imports original and derived records, and validates foreign key integrity.

**Important:** The rebuild replaces the tables in the selected database. Verify the database path before execution.

### 10. Database Integrity Verification

The current production database passed the following checks:

| Validation | Result |
|---|---:|
| SQLite Integrity Check | `ok` |
| Foreign Key Check | No errors |
| Original IOCs | 119,989 |
| Derived Observables | 51,192 |

### 11. Important Notes

- Original IOCs and derived observables must be counted separately.
- Preserve `(source, id)` as the original record identity.
- Do not discard records only because their IOC values are repeated.
- Keep derived observables linked to their original IOC references.
- Do not treat ports as standalone malicious indicators.
- Missing confidence values must remain `NULL`.
- Coordinate schema changes with the detection and integration teams.