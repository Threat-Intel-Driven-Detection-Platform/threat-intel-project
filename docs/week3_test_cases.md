# Week 3 – Test Cases

## 1. Matching Event Tests

| ID | Scenario | Input | Expected Result | Status |
|---|---|---|---|---|
| TC-01 | Exact domain match | evil-lab.test | IOC match alert | Prepared – Pending Execution |
| TC-02 | High confidence IOC | Confidence 95 | High severity rule | Prepared – Pending Execution |
| TC-03 | Payload delivery threat | threat_type: payload_delivery | Payload delivery alert | Prepared – Pending Execution |
| TC-04 | DNS IOC match | Exact domain in dns.log | DNS match alert | Prepared – Pending Execution |

## 2. Non-Matching Event Tests

| ID | Scenario | Input | Expected Result | Status |
|---|---|---|---|---|
| TC-05 | Event without match_id | Normal JSON event | No IOC-match alert | Prepared – Pending Execution |
| TC-06 | Unrelated domain | example.org | No IOC-match alert | Prepared – Pending Execution |
| TC-07 | Event without IOC evidence | Normal network event | No IOC-match alert | Prepared – Pending Execution |

## 3. Severity Validation

| ID | Confidence | Expected Rule Level | Status |
|---|---:|---:|---|
| TC-08 | 95 | 8 | Pending |
| TC-09 | 65 | 6 | Pending |
| TC-10 | Unknown | Base rule only, if matched | Pending |

## Execution Note
Wazuh rule execution is pending because the Wazuh VM is not currently accessible.
No test is marked as passed without execution.
