# Week 3 – Test Results

| Test | Expected Result | Current Status |
|---|---|---|
| Matching IOC event | IOC match alert | Pending Wazuh execution |
| Non-matching domain | No IOC-match alert | Pending Wazuh execution |
| Event without match_id | No IOC-match alert | Pending Wazuh execution |
| Confidence 95 | Wazuh level 8 | Pending Wazuh execution |
| Confidence 65 | Wazuh level 6 | Pending Wazuh execution |
| Risk scoring unit tests | All tests pass | PASS – 10/10 |
| PCAP risk scoring review | 15 detections scored | Reviewed |
| Synthetic risk scoring review | 17 detections scored | Reviewed |
| MITRE mapping review | Evidence-based mapping | Reviewed – 0 confirmed |

Wazuh alert generation and severity display have not been independently executed because the Wazuh VM is unavailable.
