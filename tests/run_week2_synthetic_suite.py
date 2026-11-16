#!/usr/bin/env python3
"""Run an isolated Week 2 synthetic suite against the project's real IOC matcher.

This suite reads only the three synthetic JSON files in data/ and writes only
results/synthetic_detections.json. It does not touch the real DB, real Zeek
logs, real parsed JSON, results/detections.json, or sample_validation.json.
"""
from __future__ import annotations

import json
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from network import ioc_matcher as matcher

IOC_FILE = ROOT / "data/iocs/synthetic_week2_iocs.json"
DNS_FILE = ROOT / "data/network/synthetic_week2_dns.json"
CONN_FILE = ROOT / "data/network/synthetic_week2_connections.json"
OUT_FILE = ROOT / "results/synthetic_detections.json"


def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


IOCS = load_json(IOC_FILE)
DNS = load_json(DNS_FILE)
CONNS = load_json(CONN_FILE)
MATCHES = matcher.run_matching(IOCS, DNS, CONNS, verbose=False)
DETECTIONS = [matcher.to_detection_record(m) for m in MATCHES]


class Week2SyntheticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by_uid = {}
        for m in MATCHES:
            cls.by_uid.setdefault(m["event"].get("uid"), []).append(m)

    def matching(self, uid, match_type=None):
        items = self.by_uid.get(uid, [])
        if match_type:
            items = [m for m in items if m["match_type"] == match_type]
        return items

    def test_00_corpus_is_larger_than_smoke_test(self):
        self.assertGreaterEqual(len(IOCS), 25)
        self.assertGreaterEqual(len(DNS), 40)
        self.assertGreaterEqual(len(CONNS), 60)

    def test_01_exact_domain_case_and_trailing_dot(self):
        self.assertEqual(len(self.matching("DNS-EXACT-01", "EXACT_DOMAIN")), 1)

    def test_02_subdomain_of_ioc_domain(self):
        self.assertEqual(len(self.matching("DNS-SUB-01", "SUBDOMAIN_OF_IOC_DOMAIN")), 1)

    def test_03_no_partial_domain_overmatch(self):
        self.assertEqual(self.matching("DNS-NO-PARTIAL-01"), [])

    def test_04_dns_answer_ipv4_match(self):
        self.assertEqual(len(self.matching("DNS-ANSWER-IP-01", "EXACT_IP")), 1)

    def test_05_connection_destination_ipv4(self):
        self.assertEqual(len(self.matching("CONN-DST-IP-01", "EXACT_IP")), 1)

    def test_06_connection_source_ipv4(self):
        self.assertEqual(len(self.matching("CONN-SRC-IP-01", "EXACT_IP")), 1)

    def test_07_exact_destination_ip_port(self):
        self.assertEqual(len(self.matching("CONN-IPPORT-DST-01", "EXACT_IP_PORT")), 1)

    def test_08_exact_source_ip_port(self):
        self.assertEqual(len(self.matching("CONN-SRC-IPPORT-01", "EXACT_IP_PORT")), 1)

    def test_09_url_ip_port_explicit(self):
        self.assertEqual(len(self.matching("CONN-URL-EXPLICIT-01", "URL_IP_PORT_MATCH")), 1)

    def test_10_url_ip_http_default_port(self):
        self.assertEqual(len(self.matching("CONN-URL-HTTP-DEFAULT-01", "URL_IP_PORT_MATCH")), 1)

    def test_11_url_ip_https_default_port(self):
        self.assertEqual(len(self.matching("CONN-URL-HTTPS-DEFAULT-01", "URL_IP_PORT_MATCH")), 1)

    def test_12_url_hostname_does_not_match_dns_domain(self):
        self.assertEqual(self.matching("DNS-URL-HOST-NEG-01"), [])

    def test_13_duplicate_event_is_deduplicated(self):
        self.assertEqual(len(self.matching("CONN-DUP-01", "EXACT_IP_PORT")), 1)

    def test_14_one_event_can_match_two_feed_records(self):
        found = self.matching("CONN-MULTI-IOC-01", "EXACT_IP")
        self.assertEqual(len(found), 2)
        self.assertEqual({m["ioc"]["source"] for m in found},
                         {"SyntheticLab", "SyntheticLab-SecondFeed"})

    def test_15_invalid_connection_port_does_not_match(self):
        self.assertEqual(self.matching("CONN-INVALID-PORT-01"), [])

    def test_16_invalid_connection_ip_does_not_match(self):
        self.assertEqual(self.matching("CONN-INVALID-IP-01"), [])

    def test_17_empty_dns_answers_are_safe(self):
        self.assertEqual(self.matching("DNS-EMPTY-ANSWERS-01"), [])

    def test_18_missing_dns_answers_are_safe(self):
        self.assertEqual(self.matching("DNS-MISSING-ANSWERS-01"), [])

    def test_19_port_upper_boundary_65535_is_valid_parser_input(self):
        self.assertEqual(matcher.parse_ip_port("203.0.113.21:65535"),
                         ("203.0.113.21", 65535))

    def test_20_port_zero_is_accepted_by_current_matcher(self):
        # The current parser explicitly accepts 0..65535. This records that behavior.
        self.assertEqual(matcher.parse_ip_port("203.0.113.22:0"),
                         ("203.0.113.22", 0))

    def test_21_bad_ip_port_ioc_is_ignored(self):
        self.assertNotIn(("203.0.113.17", 99999),
                         matcher.build_indexes(IOCS)[2])

    def test_22_bad_url_port_is_ignored(self):
        self.assertIsNone(matcher.parse_url("http://203.0.113.18:bad/path"))

    def test_23_detection_contract_has_required_fields(self):
        required = {"match_id", "timestamp", "indicator", "indicator_type",
                    "source", "evidence_source", "match_type", "matched_field",
                    "ioc_value", "ioc_type", "uid", "protocol"}
        self.assertTrue(DETECTIONS)
        self.assertTrue(all(required.issubset(d.keys()) for d in DETECTIONS))

    def test_24_detection_ids_are_unique(self):
        ids = [d["match_id"] for d in DETECTIONS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_25_url_match_is_endpoint_only_not_path_verification(self):
        url_matches = [m for m in MATCHES if m["match_type"] == "URL_IP_PORT_MATCH"]
        self.assertTrue(url_matches)
        self.assertTrue(all(m["matched_value"] in {
            "203.0.113.12:8080", "203.0.113.13:80", "203.0.113.14:443"
        } for m in url_matches))


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Week2SyntheticTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    if not result.wasSuccessful():
        print("\\nSynthetic suite failed. No output file was written.")
        return 1

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(DETECTIONS, f, indent=2, ensure_ascii=False)

    counts = Counter(m["match_type"] for m in MATCHES)
    print("\\n========== SYNTHETIC WEEK 2 SUMMARY ==========")
    print(f"IOC records: {len(IOCS)}")
    print(f"DNS records: {len(DNS)}")
    print(f"Connection records: {len(CONNS)}")
    print(f"Internal matches: {len(MATCHES)}")
    print(f"Flat detections written: {len(DETECTIONS)}")
    for kind, count in sorted(counts.items()):
        print(f"{kind}: {count}")
    print(f"Output: {OUT_FILE.relative_to(ROOT)}")
    print("Real project data and results/detections.json were not modified.")
    print("NOTE: URL_IP_PORT_MATCH validates IP:port only, not the HTTP path.")
    print("==============================================")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
