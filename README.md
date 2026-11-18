# Threat-Intel-Driven Detection Platform — Week 1 + Week 2

## Run it

```bash
# 1. get the real Zeek logs (they are stored with Git-LFS)
git lfs install && git lfs pull        # only needed if you cloned from GitHub

# 2. (optional) dependencies - only the collectors need them
pip install -r requirements.txt

# 3. run everything
python run_pipeline.py                 # add --reparse to rebuild the JSON from the Zeek logs
```

Python 3.8+ (tested on 3.12). The matcher itself uses only the standard library.
Takes about 1 minute (it loads ~140 MB of JSON).

## Outputs

| File | Meaning |
|---|---|
| `results/detections.json` | **Official Week 2 output** (flat record, input of Week 3). Real feeds only. |
| `results/sample_validation.json` | Proof the engine works: matches for `data/iocs/sample_iocs.json` (`source = LAB-SAMPLE`). Never mix with real detections. |
| `data/network/ioc_matches.json` | Legacy nested format (kept for old scripts). |

Detection record (core fields, as agreed): `match_id, timestamp, indicator, indicator_type, source, evidence_source, src_ip, dst_ip, domain, port`
plus additive context: `match_type, matched_field, ioc_value, ioc_type, threat_type, malware, confidence, ioc_first_seen, uid, protocol`.
Week 3 adds `risk_score, risk_level, wazuh_rule, mitre_technique`.

## Why 0 real matches (this is the data, not a bug)

1. **Time mismatch** — traffic is CTU-SME-11 captured **20–27 Feb 2023**; the IOC feeds were pulled **Sep–Oct 2026**. A fresh feed cannot contain indicators for 3-year-old traffic.
2. **Feed composition** — of 35,707 IOCs, 33,952 are URLs and 1,291 are file hashes. Conn/DNS logs can only match domains, IPs and ip:port (~1.3% of the feed). URLs need `http.log`, hashes need `files.log`.
3. The 10 URL-host DNS overlaps (github.com, raw.githubusercontent.com, dropbox, discord…) are legitimate shared hosts → correctly **not** reported as detections.

To get real hits: use a PCAP from the same period as the feed (or a fresh malware PCAP), or collect historical IOCs covering Feb 2023.

## Fixes in this version

- Output now follows the agreed flat detection record (`results/detections.json`) with deterministic `match_id`.
- URL IOCs with an IP host and no explicit port (`http://1.2.3.4/x`) are now matched on 80/443 (before: silently dropped).
- Subdomain matching: query `a.evil.com` now hits IOC `evil.com`.
- `run_pipeline.py`: one command, checks Git-LFS pointers, validates the sample IOCs.
- Collectors no longer overwrite good raw data with an error response (the old ThreatFox run left `{"query_status":"unknown_auth_key"}` in `threatfox_raw.json`, which crashes the normalizer); clear errors, CWD-independent paths.
- Zeek README record counts corrected (they included the 9 header/footer lines).
