# Week 2 - Person 1: PCAP Preparation & Zeek Analysis

## Objective
Prepare the selected PCAP file and analyze the network traffic using Zeek.

## Input
PCAP:
CTU-SME-11-Experiment-VM-Microsoft-Windows7AD-1-malicious-cleaned.pcap

## Zeek Version
Zeek 9.0.1

## Processing
The PCAP was processed using:

zeek -r <PCAP_FILE>

## Main Outputs

- logs/conn.log
  - 182,392 records
  - Contains connection-level information such as timestamps, source/destination IPs, ports, protocols, connection state, and traffic statistics.

- logs/dns.log
  - 168,857 records
  - Contains DNS queries, source/destination information, query names, query types, answers, and DNS response information.

## Additional Zeek Logs
Zeek also generated additional protocol and analysis logs including:
- http.log
- files.log
- ssl.log
- kerberos.log
- ldap.log
- ntlm.log
- smb_files.log
- smb_mapping.log
- weird.log
- analyzer.log

## Handoff to Person 2

The primary files for the next stage are:

- zeek/logs/conn.log
- zeek/logs/dns.log

Person 2 will parse and structure these logs into network indicators including timestamps, source IPs, destination IPs, domains, and ports.

## Validation

The PCAP gzip archive was verified successfully using gzip -t before extraction.

Zeek successfully processed the PCAP and generated the required conn.log and dns.log files.
