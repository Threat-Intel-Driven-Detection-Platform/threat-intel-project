# Week 3 – MITRE ATT&CK Validation

## Review Results

| Item | Result |
|---|---|
| Total detections reviewed | 15 |
| Confirmed MITRE techniques | 0 |
| Candidate techniques | 2 |
| Mapping policy | Followed |

## Candidate Techniques

| Technique ID | Technique | Status |
|---|---|---|
| T1071.001 | Web Protocols | Candidate only |
| T1071.004 | DNS | Candidate only |

## Findings

- IOC matches alone are insufficient to confirm MITRE techniques.
- The reviewed connections were in state S0 with zero transferred bytes.
- Payload delivery and command-and-control behavior are not independently confirmed.
- No MITRE technique is reported as detected without supporting evidence.

## Validation Conclusion

The reviewed MITRE mappings follow the evidence-based mapping policy.
No technique is confirmed by the currently available PCAP evidence.
