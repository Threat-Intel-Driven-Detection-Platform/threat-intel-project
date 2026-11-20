# Week 3 – Risk Scoring Validation

## Scoring Logic Review

| Factor | Scoring |
|---|---:|
| Confidence 90–100 | 30 |
| Confidence 75–89 | 24 |
| Confidence 50–74 | 16 |
| Confidence 1–49 | 8 |
| Unknown confidence | 0 |
| Payload delivery | 12 |
| Botnet C2 | 10 |
| Malware / Credential theft | 10 |
| Phishing | 8 |
| Exact IP and port match | 20 |
| URL and IP/port match | 18 |
| Exact domain match | 15 |
| Exact IP match | 14 |
| Subdomain match | 12 |
| DNS evidence | 5 |
| Connection with traffic bytes | 15 |
| S0 connection state | 0 |

## Risk Levels

| Score | Risk Level |
|---|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

## Available Validation Results

| Test | Result |
|---|---|
| Risk scoring unit tests | PASS – 10/10 |
| PCAP detections scored | 15 |
| PCAP detections joined to connections | 15/15 |
| PCAP High risk detections | 15 |
| PCAP Critical risk detections | 0 |
| Synthetic detections scored | 17 |
| Synthetic High risk detections | 17 |
| Synthetic Critical risk detections | 0 |

## Review Notes

- S0 connections receive no network activity points.
- Risk scores prioritize investigations; they do not prove compromise.
- All 15 reviewed PCAP detections were classified as High.
- No Critical detections were reported in the reviewed outputs.

## Conclusion

The risk scoring unit tests passed (10/10).
The available PCAP and synthetic outputs were reviewed against the documented scoring logic.
