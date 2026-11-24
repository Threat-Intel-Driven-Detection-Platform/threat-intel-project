\# Week 4 - Person 1 Handover

\## Threat Intelligence, IOC Normalization \& Database



\### 1. Completed Work



Person 1 completed the following tasks:



\- Extracted IP addresses, domains, and explicit ports from original URL IOCs.

\- Preserved data provenance using `original\_ioc\_ref`.

\- Added the `derived\_observables` table to the SQLite database.

\- Generated IOC distribution and data quality reports.

\- Documented the database schema and relationships.

\- Implemented and tested a complete database rebuild script.



\### 2. Dataset Statistics



\*\*Original IOCs: 35,707\*\*



| Source | Count |

|---|---:|

| URLhaus | 33,205 |

| ThreatFox | 1,967 |

| OTX | 535 |

| \*\*Total\*\* | \*\*35,707\*\* |



\*\*Derived Observables: 46,028\*\*



| Type | Count |

|---|---:|

| IP | 15,509 |

| Domain | 18,443 |

| Port | 12,076 |

| \*\*Total\*\* | \*\*46,028\*\* |



Derived observables originate from existing URL IOCs. They must not be counted as additional original feed IOCs.



\### 3. Data Quality Findings



| Check | Result |

|---|---:|

| Missing IOC | 0 |

| Missing IOC Type | 0 |

| Missing Source | 0 |

| Missing Threat Type | 0 |

| Missing First Seen | 0 |

| Missing Confidence | 33,740 |

| Invalid Confidence | 0 |

| Duplicate Original IOC Groups | 0 |

| Missing Derived Observable | 0 |

| Missing Derived Type | 0 |

| Missing Original Reference | 0 |



\*\*Confidence Availability by Source\*\*



| Source | Total | Missing | Available |

|---|---:|---:|---:|

| URLhaus | 33,205 | 33,205 | 0 |

| OTX | 535 | 535 | 0 |

| ThreatFox | 1,967 | 0 | 1,967 |



Missing confidence values are retained as `NULL`. No default confidence values are invented.



\### 4. Database Structure



The database contains two main tables:



\- `iocs`: Stores original threat intelligence indicators.

\- `derived\_observables`: Stores IP addresses, domains, and ports extracted from original URLs.



\*\*Relationship:\*\*



`derived\_observables.original\_ioc\_ref` references `iocs.original\_ioc\_ref`.



Each derived observable can be traced back to its original URL IOC, including its source and threat metadata.



\### 5. Handover to Person 2 - Detection Engine



Person 2 should:



1\. Read derived observables from the SQLite database.

2\. Match derived IP observables against Zeek connection and HTTP host evidence.

3\. Match derived domains against DNS and HTTP host evidence.

4\. Use HTTP logs for URL and URI/path-level matching where available.

5\. Keep explicit ports contextual to their associated host and original URL.

6\. Preserve the original IOC reference and source in detection evidence.



\*\*Important Notes:\*\*



\- Do not match a port as a standalone malicious indicator.

\- Extracted IPs and domains do not guarantee a match in the analyzed PCAP.

\- Derived observables are not new independent feed IOCs.

\- Detection results should retain traceability to the original IOC.



\*\*Example SQL Query:\*\*



```sql

SELECT

&#x20;   d.observable,

&#x20;   d.observable\_type,

&#x20;   i.ioc AS original\_ioc,

&#x20;   i.source,

&#x20;   i.threat\_type,

&#x20;   i.confidence

FROM derived\_observables d

JOIN iocs i

&#x20;   ON d.original\_ioc\_ref = i.original\_ioc\_ref;

```



\### 6. Handover to Person 4 - Frontend and Reporting



Use the following statistics in dashboard summaries:



\- Original IOCs: 35,707

\- Derived observables: 46,028

\- Derived IPs: 15,509

\- Derived domains: 18,443

\- Derived ports: 12,076



The dashboard should distinguish:



\- Original feed IOCs.

\- Derived observables.

\- IOC source distribution.

\- IOC type distribution.

\- Data quality and missing confidence.



\*\*Important:\*\* Do not combine original and derived counts into one IOC total.



\### 7. Database Rebuild Instructions



Run from the project root:



```powershell

python database/load\_all\_iocs.py

```



\*\*Required input files:\*\*



\- `data/all\_iocs.json`

\- `data/url\_derived\_observables.json`



To rebuild a separate test database:



```powershell

python database/load\_all\_iocs.py --database data/threat\_intel\_rebuild\_test.db

```



\*\*Rebuild Process:\*\*



1\. Drops the old `derived\_observables` table.

2\. Drops the old `iocs` table.

3\. Recreates `iocs` and imports original indicators.

4\. Creates `original\_ioc\_ref` and its unique index.

5\. Recreates `derived\_observables`.

6\. Imports derived observables.

7\. Validates foreign key integrity and missing references.



\### 8. Rebuild Test Results



The rebuild process was executed twice on a separate test database.



Both runs completed successfully:



| Validation | Result |

|---|---:|

| Original IOCs | 35,707 |

| Derived Observables | 46,028 |

| Missing References | 0 |

| Foreign Key Errors | 0 |



The production database was not modified during these rebuild tests.



\### 9. Deliverable Files



| File | Description |

|---|---|

| `normalization/extract\_url\_observables.py` | Extracts IPs, domains, and ports from URLs |

| `normalization/ioc\_quality\_report.py` | Generates IOC quality report |

| `database/add\_derived\_observables.py` | Imports derived observables |

| `database/load\_all\_iocs.py` | Complete database rebuild script |

| `data/url\_derived\_observables.json` | Extracted observables |

| `docs/week4\_ioc\_distribution\_report.md` | IOC distribution and quality report |

| `docs/database\_schema\_and\_data\_dictionary.md` | Database schema documentation |



\### 10. Important Notes



\- Use `load\_all\_iocs.py` as the complete database rebuild procedure.

\- Do not use the legacy `ioc\_database.py` as a full rebuild procedure.

\- Keep both JSON input files available when rebuilding.

\- Coordinate future schema changes with the detection and integration team.



\---



\*\*Status: Person 1 - Week 4 Implementation and Handover Prepared\*\*</Writing
