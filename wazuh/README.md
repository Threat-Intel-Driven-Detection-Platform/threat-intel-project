# Wazuh Integration — Week 3

## 1. Overview

This module integrates the existing Week 2 Threat Intelligence Detection Pipeline with Wazuh Manager.

The integration reuses the existing IOC-matching results instead of implementing duplicate IOC-matching logic inside Wazuh.

**Implementation owner:** Kenzy
**Next phase owner:** Ganna

## 2. Environment

- Operating system: Ubuntu Server 24.04.3 LTS
- Virtualization: VMware Workstation
- Wazuh Manager: 4.14.10
- Allocated resources: 3 GB RAM, 2 vCPU, 60 GB virtual disk
- Input format: JSON array
- Integration format: JSON Lines (JSONL)
- Wazuh decoder: JSON

Only Wazuh Manager was installed. Wazuh Indexer and Dashboard are not part of this environment.

## 3. Integration Workflow

Week 2 IOC Matching → JSON Detection Results → JSONL Adapter → Wazuh Log Collector → JSON Decoder → Wazuh Archives

## 4. Project Files

| File | Purpose |
|---|---|
| `scripts/jsonl_adapter.py` | Converts a JSON array into JSONL |
| `samples/synthetic_detections.json` | Synthetic detection records used for testing |
| `samples/detections.jsonl` | Converted JSONL detection events |
| `config/localfile_snippet.xml` | Wazuh Log Collector configuration |
| `config/archives_snippet.xml` | Enables JSON event archiving |
| `evidence/manager_status.txt` | Wazuh Manager service status |
| `evidence/received_events.jsonl` | Events received by Wazuh during testing |

## 5. Wazuh Configuration

Add the contents of `config/localfile_snippet.xml` inside an appropriate `<ossec_config>` section of `/var/ossec/etc/ossec.conf`.

Set `<logall_json>yes</logall_json>` inside the existing `<global>` section, as described in `config/archives_snippet.xml`.

Do not replace the entire configuration file with either snippet.

Restart Wazuh Manager after applying and validating the configuration.

## 6. Running the Integration

Convert the detection data using the Python adapter. Check the adapter's input and output paths before running it on a new environment.

Create the ingestion directory:

```bash
sudo mkdir -p /var/log/wazuh-week2
sudo touch /var/log/wazuh-week2/detections.jsonl
sudo chmod 644 /var/log/wazuh-week2/detections.jsonl
```

After configuring the Wazuh Log Collector and restarting Wazuh Manager, append JSONL detection events to the monitored file:

```bash
sudo sh -c 'cat /home/kenzy/wazuh-integration/detections.jsonl >> /var/log/wazuh-week2/detections.jsonl'
```

The source path above belongs to the original Kenzy VM and must be adjusted on other environments.

## 7. Integration Test Results

The synthetic-event ingestion test completed successfully.

- Expected events: 17
- Archived events: 17
- Decoder: JSON
- Event source: `/var/log/wazuh-week2/detections.jsonl`
- Result: PASS

The original Week 2 `results/detections.json` contained no real IOC matches in the reviewed dataset. The 17 events used for integration testing are synthetic.

Successful archiving confirms event ingestion and JSON decoding. It does not demonstrate that custom detection rules, risk scoring, or MITRE ATT&CK mappings are complete.

## 8. Known Limitations

- The handover does not include the running VMware virtual machine.
- Wazuh Dashboard and Indexer were not installed.
- Some Indexer Connector warnings are expected in this Manager-only environment.
- Test events must not be described as real confirmed security incidents.
- Absolute file paths may need adjustment on a different Ubuntu installation.
- Archived events may include host metadata and should be reviewed before public sharing.

## 9. Next Steps — Ganna

1. Review the existing detection fields and JSON Decoder output.
2. Develop custom Wazuh detection rules.
3. Add custom decoders only if necessary.
4. Assign appropriate severity levels.
5. Implement explainable, rule-based risk scoring.
6. Map detections to MITRE ATT&CK techniques only when supported by evidence.
7. Prepare investigation records.
8. Test the new rules with matching and non-matching scenarios.
9. Hand the completed implementation to Neama for validation.

## 10. Handover Status

Kenzy completed Wazuh Manager setup, JSONL conversion, event ingestion configuration, and successful ingestion of 17 synthetic detection events.

Rule implementation, risk scoring, MITRE ATT&CK mapping, and final validation remain outside the scope of Kenzy's completed integration phase.