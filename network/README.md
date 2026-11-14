
# Network Traffic Parsing and IOC Matching

## Overview

This module parses Zeek network logs, extracts structured network indicators, and compares observed network activity against threat intelligence IOCs stored in the project database.

## Input Files

- `zeek/logs/conn.log`
- `zeek/logs/dns.log`
- `data/threat_intel.db`

## Scripts

### Parsing and Extraction

- `conn_parser.py`: Parses Zeek connection logs.
- `dns_parser.py`: Parses Zeek DNS logs.
- `validate_outputs.py`: Validates parsed records against raw Zeek logs.
- `data_quality.py`: Analyzes network data quality.
- `extract_network_indicators.py`: Extracts unique network indicators.

### IOC Matching and Analysis

- `ioc_matcher.py`: Matches supported IOC types against observed DNS and connection activity.
- `test_matcher.py`: Runs controlled tests for IOC matching behavior.
- `validate_ioc_coverage.py`: Compares IOC indexes with observed network indicators.
- `inspect_host_groups.py`: Investigates URL-host DNS overlaps and destination-IP correlations.

## Output Files

- `data/network/connections.json`
- `data/network/dns_queries.json`
- `data/network/network_indicators.json`
- `data/network/ioc_matches.json`

## Parsing Results

- Connections: 182,383 records
- DNS Queries: 168,848 records
- Malformed connection records: 0
- Malformed DNS records: 0

## Network Indicator Extraction Results

- Queried Domains: 5,196
- Answer Domains: 1,797
- Answer IPs: 6,225
- Connection IPs: 1,729

## IOC Matching

The matcher supports the following matching categories:

- Exact Domain and Hostname matching against DNS queries.
- IPv4 matching against DNS answers and connection endpoints.
- Exact IP:Port matching against connection records.
- URL IP:Port matching against connection records.

URL hostnames are indexed separately and are not treated as exact URL matches.

### Matching Results

- Confirmed IOC match records: 0
- Unique matched IOCs: 0

The corrected matcher prevents URL hostnames from being incorrectly treated as full URL matches.

## Controlled Testing

Seven controlled tests were executed:

1. Exact Domain Matching
2. DNS Answer IPv4 Matching
3. Connection IPv4 Matching
4. Exact IP:Port Matching
5. URL IP:Port Matching
6. Prevention of URL Host Overmatching
7. Deduplication

**Result: 7/7 tests passed.**

These tests validate the implemented matching logic using controlled test IOCs. They do not establish that malicious IOCs were observed in the dataset.

## IOC Coverage and Host Correlation

Coverage analysis identified:

- Exact Domain IOC overlaps: 0
- URL-host DNS contextual overlaps: 10
- URL IP:Port connection overlaps: 0
- Standalone IPv4 and IP:Port exact overlaps: 0

Further investigation identified:

- 10 URL hosts with DNS overlaps.
- 6 hosts with destination-IP connections within a five-minute window after DNS activity.
- 44 host-group connection associations.

These results represent host-level network correlations, not confirmed URL matches or confirmed malicious downloads.

## Limitations

- The available input logs are `conn.log` and `dns.log`.
- Exact URL path matching is not possible using DNS and connection logs alone.
- Shared hosting and CDN IP addresses can produce ambiguous correlations.
- File-hash IOC matching is not implemented in this network matcher.
- A DNS lookup or destination-IP correlation does not prove that a specific URL or malicious file was accessed.

## Conclusion

The network parsing, indicator extraction, IOC matching, validation, and controlled testing stages have been implemented.

The available traffic data produced no confirmed IOC matches. Contextual URL-host correlations were identified and documented separately to avoid false positives.
