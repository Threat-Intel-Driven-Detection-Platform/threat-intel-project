# Week 4 - Person 1 Handover
## Threat Intelligence, IOC Normalization & Database

### 1. Completed Work

Person 1 completed the following tasks:

- Collected and normalized threat intelligence from URLhaus, ThreatFox, and AlienVault OTX.
- Validated IOC records and preserved source-specific record identities.
- Updated the merge process to identify records using `(source, id)`, preserving separate observations even when IOC values are repeated.
- Extracted IP addresses, domains, and explicit ports from original URL IOCs.
- Preserved data provenance using `original_ioc_ref`.
- Added the `derived_observables` table to the SQLite database.
- Generated IOC distribution and data quality reports.
- Documented the database schema and relationships.
- Implemented and tested a complete database rebuild script.

### 2. Current Dataset Statistics

The following figures represent the current production database.

**Original IOCs: 119,989**

| Source | Count |
|---|---:|
| OTX | 80,621 |
| URLhaus | 33,209 |
| ThreatFox | 6,159 |
| **Total** | **119,989** |

**Original IOCs by Type**

| IOC Type | Count |
|---|---:|
| URL | 38,479 |
| Domain | 29,715 |
| SHA256 | 18,023 |
| MD5 | 9,428 |
| SHA1 | 8,883 |
| Hostname | 8,176 |
| IP:Port | 5,138 |
| CVE | 1,627 |
| IP | 378 |
| YARA | 88 |
| Email | 49 |
| SSL Certificate Fingerprint | 4 |
| Bitcoin Address | 1 |
| **Total** | **119,989** |

URL indicators account for approximately **32.07%** of original IOCs. URLhaus contributes the largest volume of URL indicators.

**Derived Observables: 51,192**

| Type | Count |
|---|---:|
| IP | 16,200 |
| Domain | 22,279 |
| Port | 12,713 |
| **Total** | **51,192** |

Derived observables originate from existing URL IOCs. They must not be counted as additional original feed IOCs.

### 3. Data Quality Findings

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

**Confidence Availability by Source**

| Source | Total | Missing | Available |
|---|---:|---:|---:|
| OTX | 80,621 | 80,621 | 0 |
| URLhaus | 33,209 | 33,209 | 0 |
| ThreatFox | 6,159 | 0 | 6,159 |

Missing confidence values are retained as `NULL`. No default confidence values are invented.

**Duplicate IOC Groups**

The 4,443 duplicate groups represent repeated IOC values under the report's grouping criteria. They do not mean that 4,443 records were deleted.

The merge process preserves separate source records using `(source, id)` as the record identity.

### 4. Database Structure

The database contains two main tables:

- `iocs`: Stores original threat intelligence indicators.
- `derived_observables`: Stores IP addresses, domains, and ports extracted from original URLs.

**Important database relationships:**

- Original IOC records are uniquely identified by `(source, id)`.
- `original_ioc_ref` provides a stable reference to an original IOC.
- `derived_observables.original_ioc_ref` references `iocs.original_ioc_ref`.

Each derived observable can be traced back to its original URL IOC, including its source and threat metadata.

### 5. Handover to Person 2 - Detection Engine

Person 2 should:

1. Read original IOCs and derived observables from the SQLite database.
2. Match derived IP observables against Zeek connection and HTTP host evidence.
3. Match derived domains against DNS and HTTP host evidence.
4. Use HTTP logs for URL and URI/path-level matching where available.
5. Keep explicit ports contextual to their associated host and original URL.
6. Preserve the original IOC reference and source in detection evidence.
7. Consider IOC type support when implementing matching logic.

**Example SQL Query**

```sql
SELECT
    d.observable,
    d.observable_type,
    i.ioc AS original_ioc,
    i.source,
    i.threat_type,
    i.confidence,
    i.original_ioc_ref
FROM derived_observables d
JOIN iocs i
    ON d.original_ioc_ref = i.original_ioc_ref;
```

**Important Notes**

- Do not match a port as a standalone malicious indicator.
- Extracted IPs and domains do not guarantee a match in the analyzed PCAP.
- Extracted IP addresses are URL host values, not DNS-resolved addresses.
- Derived observables are not new independent feed IOCs.
- Detection results should retain traceability to the original IOC.
- Full URL and URI matching requires suitable HTTP-level evidence.

### 6. Handover to Person 4 - Frontend and Reporting

Use the following statistics in dashboard summaries:

- Original IOCs: **119,989**
- Derived observables: **51,192**
- Derived IPs: **16,200**
- Derived domains: **22,279**
- Derived ports: **12,713**

The dashboard should distinguish:

- Original feed IOCs.
- Derived observables.
- IOC source distribution.
- IOC type distribution.
- Data quality and missing confidence.
- Collection scope and limitations.

**Important:** Do not combine original and derived counts into one IOC total.

The dashboard should also make clear that the OTX dataset represents a partial collection, not the complete subscribed-pulses feed.

### 7. OTX Collection Scope

The OTX dataset used in the current report is a partial collection.

- Pages collected: 390
- Pulses collected: 1,950
- Indicators normalized: 80,621
- Collection status: Partial

Additional pages were available but were not collected. Therefore, OTX statistics represent the collected sample only and must not be interpreted as the complete OTX feed inventory.

### 8. Database Rebuild Instructions

Run from the project root:

```powershell
python database/load_all_iocs.py
```

**Required input files:**

- `data/all_iocs.json`
- `data/url_derived_observables.json`

To rebuild a separate test database:

```powershell
python database/load_all_iocs.py --database data/threat_intel_rebuild_test.db
```

**Rebuild Process**

1. Drops the old `derived_observables` table.
2. Drops the old `iocs` table.
3. Recreates `iocs` and imports original indicators.
4. Creates the original IOC references and unique constraints.
5. Recreates `derived_observables`.
6. Imports derived observables.
7. Validates foreign key integrity and missing references.

**Important:** The rebuild process replaces the tables in the selected database. Always verify the database path before running it.

### 9. Production Database Verification

The current production database was verified successfully.

| Validation | Result |
|---|---:|
| SQLite Integrity Check | `ok` |
| Foreign Key Check | No errors |
| Original IOCs | 119,989 |
| Derived Observables | 51,192 |

A separate test database was also used to validate the rebuild process. Its test counts belong to that test dataset and should not be confused with the current production counts.

### 10. Deliverable Files

| File | Description |
|---|---|
| `collectors/otx_collector.py` | Collects OTX pulse data |
| `normalization/threatfox_normalizer.py` | Normalizes ThreatFox records |
| `normalization/merge_iocs.py` | Merges normalized IOC records |
| `normalization/extract_url_observables.py` | Extracts IPs, domains, and ports from URLs |
| `normalization/ioc_quality_report.py` | Generates IOC distribution and quality report |
| `database/load_all_iocs.py` | Complete database rebuild script |
| `data/all_iocs.json` | Merged original IOCs |
| `data/url_derived_observables.json` | Extracted derived observables |
| `data/threat_intel.db` | Production SQLite database |
| `docs/week4_ioc_distribution_report.md` | IOC distribution and quality report |
| `docs/database_schema_and_data_dictionary.md` | Database schema documentation |

### 11. Important Notes

- Use `load_all_iocs.py` as the complete database rebuild procedure.
- Do not use the legacy `ioc_database.py` as a full rebuild procedure.
- Keep both JSON input files available when rebuilding.
- Preserve `(source, id)` as the original record identity.
- Keep derived observables linked to their original IOC references.
- Treat missing confidence values as `NULL`.
- Coordinate future schema changes with the detection and integration teams.

---

**Status: Person 1 - Week 4 Implementation and Handover Prepared**