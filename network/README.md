# Network Traffic Parsing

## Overview
This module parses Zeek network logs and extracts
structured network indicators for threat intelligence matching.

## Input Files
- zeek/logs/conn.log
- zeek/logs/dns.log

## Scripts
- conn_parser.py: Parses connection logs.
- dns_parser.py: Parses DNS logs.
- validate_outputs.py: Validates parsed records.
- data_quality.py: Analyzes data quality.
- extract_network_indicators.py: Extracts unique network indicators.

## Output Files
- data/network/connections.json
- data/network/dns_queries.json
- data/network/network_indicators.json

## Extraction Results
- Queried Domains: 5,196
- Answer Domains: 1,797
- Answer IPs: 6,225
- Connection IPs: 1,729

## Validation
- Connections: 182,383 records
- DNS Queries: 168,848 records
- Malformed connection records: 0
- Malformed DNS records: 0