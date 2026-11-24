# Week 4 - IOC Distribution & Data Quality Report

Generated: 2026-11-24 02:30 UTC

## 1. Executive Summary

- Original IOCs: **35,707**
- Derived observables: **46,028**
- Duplicate original IOC groups: **0**
- Derived observables are extracted from existing URL IOCs. They are not additional original feed IOCs.

## 2. Original IOCs by Source

| Source | IOC Count |
|---|---:|
| URLhaus | 33,205 |
| ThreatFox | 1,967 |
| OTX | 535 |

## 3. Original IOCs by Type

| IOC Type | Count |
|---|---:|
| url | 33,919 |
| sha256_hash | 805 |
| ip:port | 222 |
| domain | 188 |
| FileHash-SHA256 | 160 |
| FileHash-MD5 | 123 |
| FileHash-SHA1 | 121 |
| hostname | 53 |
| sha1_hash | 41 |
| md5_hash | 41 |
| URL | 33 |
| IPv4 | 1 |

URL and URL-case variants account for **33,952 (95.08%)** of original IOCs.

### URL Dominance Explanation

The feed is strongly URL-dominated, mainly because URLhaus contributes a large volume of URL indicators. This affects network detection coverage: connection and DNS matching generally use IPs and domains, while full URL and URI matching requires suitable HTTP-level evidence such as Zeek http.log. Derived IP and domain observables improve the availability of host indicators, but do not guarantee matches without suitable network traffic.

## 4. Derived Observables

| Observable Type | Count |
|---|---:|
| domain | 18,443 |
| ip | 15,509 |
| port | 12,076 |

### Derived Observables by Source

| Source | Type | Count |
|---|---|---:|
| OTX | domain | 26 |
| OTX | ip | 7 |
| OTX | port | 7 |
| ThreatFox | domain | 701 |
| ThreatFox | ip | 13 |
| ThreatFox | port | 12 |
| URLhaus | domain | 17,716 |
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
| Missing Confidence | 33,740 |
| Invalid Confidence | 0 |
| Duplicate original IOC groups (case-insensitive type) | 0 |

### Confidence Availability by Source

| Source | Total | Missing | Available | Missing % |
|---|---:|---:|---:|---:|
| URLhaus | 33,205 | 33,205 | 0 | 100.00% |
| ThreatFox | 1,967 | 0 | 1,967 | 0.00% |
| OTX | 535 | 535 | 0 | 100.00% |

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
