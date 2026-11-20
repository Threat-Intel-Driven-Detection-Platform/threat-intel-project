# Week 3 – Final Testing Report

## Scope
Testing, validation, and documentation of the Week 3 detection, risk-scoring, and MITRE deliverables.

## Completed Work
- Prepared matching and non-matching sample events.
- Prepared detection and severity test cases.
- Reviewed risk scoring logic and available outputs.
- Executed risk scoring unit tests: 10/10 PASS.
- Reviewed 15 PCAP detections and 17 synthetic detections.
- Reviewed MITRE mappings: 0 confirmed techniques; 2 candidate techniques only.
- Updated the project README.

## Pending Work
- Execute matching and non-matching tests against the live Wazuh Manager.
- Verify generated alerts and severity levels.
- Capture Wazuh Dashboard and alert screenshots.

## Blocker
The Wazuh VM is not accessible to the tester. The supplied setup documentation also states that the Dashboard and Indexer are not installed.

## Conclusion
The available risk-scoring tests passed and the risk/MITRE outputs were reviewed. Live Wazuh detection validation remains pending. No unexecuted test is reported as passed.
