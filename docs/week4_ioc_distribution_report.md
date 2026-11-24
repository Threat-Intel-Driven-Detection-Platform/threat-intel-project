# Week 4 - IOC Distribution & Data Quality Report

Generated: 2026-11-24 05:57 UTC

## 1. Executive Summary

- Original IOCs: **119,989**
- Derived observables: **51,192**
- Duplicate original IOC groups: **4,443**
- Derived observables are extracted from existing URL IOCs. They are not additional original feed IOCs.

## 2. Original IOCs by Source

| Source | IOC Count |
|---|---:|
| OTX | 80,621 |
| URLhaus | 33,209 |
| ThreatFox | 6,159 |

## 3. Original IOCs by Type

| IOC Type | Count |
|---|---:|
| url | 38,479 |
| domain | 29,715 |
| sha256_hash | 18,023 |
| md5_hash | 9,428 |
| sha1_hash | 8,883 |
| hostname | 8,176 |
| ip:port | 5,138 |
| cve | 1,627 |
| ip | 378 |
| yara | 88 |
| email | 49 |
| ssl_cert_fingerprint | 4 |
| bitcoin_address | 1 |

URL and URL-case variants account for **38,479 (32.07%)** of original IOCs.

### URL Dominance Explanation

The feed is strongly URL-dominated, mainly because URLhaus contributes a large volume of URL indicators. This affects network detection coverage: connection and DNS matching generally use IPs and domains, while full URL and URI matching requires suitable HTTP-level evidence such as Zeek http.log. Derived IP and domain observables improve the availability of host indicators, but do not guarantee matches without suitable network traffic.

## 4. Derived Observables

| Observable Type | Count |
|---|---:|
| domain | 22,279 |
| ip | 16,200 |
| port | 12,713 |

### Derived Observables by Source

| Source | Type | Count |
|---|---|---:|
| OTX | domain | 4,526 |
| OTX | ip | 670 |
| OTX | port | 645 |
| ThreatFox | domain | 33 |
| ThreatFox | ip | 41 |
| ThreatFox | port | 11 |
| URLhaus | domain | 17,720 |
| URLhaus | ip | 15,489 |
| URLhaus | port | 12,057 |

Derived IPs, domains, and explicit ports retain a reference to their original URL IOC. Ports are contextual metadata and must not be matched as standalone indicators.

## 5. Original IOC Data Quality

| Check | Result |
|---|---:|
| Missing IOC | 0 |
| Missing IOC Type | 0 |
| Missing Source | 0 |
| Missing Threat Type | 0 |
| Missing First Seen | 0 |
| Missing Confidence | 113,830 |
| Invalid Confidence | 0 |
| Duplicate original IOC groups (case-insensitive type) | 4,443 |

### Confidence Availability by Source

| Source | Total | Missing | Available | Missing % |
|---|---:|---:|---:|---:|
| OTX | 80,621 | 80,621 | 0 | 100.00% |
| URLhaus | 33,209 | 33,209 | 0 | 100.00% |
| ThreatFox | 6,159 | 0 | 6,159 | 0.00% |

Missing confidence values are source-related: URLhaus and OTX records in this dataset do not provide confidence values, while ThreatFox records do. Missing values are retained as NULL; no default confidence is invented.

## 6. Derived Data Quality

| Check | Result |
|---|---:|
| Missing Observable | 0 |
| Missing Observable Type | 0 |
| Missing Original Reference | 0 |

## 7. Interpretation and Limitations

- Original IOC counts and derived observable counts are reported separately.
- Derived observables originate from existing URLs and preserve provenance.
- Extracted IP addresses are URL host values, not DNS-resolved addresses.
- An extracted IP or domain does not imply that it appears in the analyzed PCAP.
- Detection coverage also depends on the available Zeek logs and matcher support.
- Missing confidence is not treated as zero confidence.

## 8. Reproduction

Run the following command from the project root:

```powershell
python normalization/ioc_quality_report.py
```

## 9. Collection Scope and Limitations

### AlienVault OTX

The OTX dataset used in this report is a partial collection, not a
complete subscribed-pulses feed export.

- Pages collected: 390
- Pulses collected: 1,950
- Indicators normalized: 80,621
- Collection status: Partial
- Pagination: Additional pages were available but were not collected.

The partial collection was retained as a bounded dataset to avoid
unnecessarily long collection runs. All collected indicators were
normalized and included in the merged IOC database.

Therefore, OTX counts in this report represent the collected sample
only and must not be interpreted as the complete OTX feed inventory.

