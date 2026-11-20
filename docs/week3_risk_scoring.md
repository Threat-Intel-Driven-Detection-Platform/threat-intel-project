# Week 3 - Explainable Risk Scoring

## Purpose
Provide explainable prioritization for threat-intelligence IOC detections.
A risk score indicates investigation priority; it does not prove compromise.

## Scoring factors

| Factor | Points |
|---|---:|
| Confidence 90-100 | 30 |
| Confidence 75-89 | 24 |
| Confidence 50-74 | 16 |
| Confidence 1-49 | 8 |
| Unknown/invalid confidence | 0 |
| payload_delivery | 12 |
| botnet_cc | 10 |
| malware / credential_theft | 10 |
| phishing | 8 |
| EXACT_IP_PORT | 20 |
| URL_IP_PORT_MATCH | 18 |
| EXACT_DOMAIN | 15 |
| EXACT_IP | 14 |
| SUBDOMAIN_OF_IOC_DOMAIN | 12 |
| DNS observation | 5 |
| Connection with observed traffic bytes | 15 |
| S0 / no response observed | 0 |

Maximum raw score: 77.
Normalized score = round(raw score / 77 * 100).

## Risk levels
- Low: 0-24
- Medium: 25-49
- High: 50-74
- Critical: 75-100

## Connection evidence
Connection records are joined to detections using Zeek UID.
S0 indicates that no reply was observed. It receives no network activity points.
Observed traffic bytes can increase investigation priority but do not independently prove malicious activity.

## PCAP results
- 15 detections scored.
- 15/15 detections matched a connection record by UID.
- 15 High, 0 Critical.
- The matched connections were S0.
- No successful connection or payload execution is established by these records.

## Synthetic results
- 17 detections scored.
- 17 High, 0 Critical.

## Run
```bash
python3 -m unittest discover -s tests -p 'test_risk_scoring.py' -v

python3 -m risk_scoring.engine \
  --input results/zeek-real-test/pcap_ganna/detections.json \
  --connections results/zeek-real-test/pcap_ganna/connections.json \
  --output results/zeek-real-test/pcap_ganna/scored_detections.json
```

## Limitations
- IOC classification is threat-intelligence context, not proof of compromise.
- Network connection state and byte counts provide context, not proof of payload execution.
- MITRE ATT&CK techniques should only be assigned when observed behavior supports the mapping.
