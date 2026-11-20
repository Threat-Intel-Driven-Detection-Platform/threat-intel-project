import unittest

from risk_scoring.engine import (
    confidence_weight,
    risk_level,
    score_detection,
    score_detections,
)


class TestRiskScoring(unittest.TestCase):

    def test_high_confidence_domain(self):
        r = score_detection({
            "confidence": 95,
            "threat_type": "test_domain",
            "match_type": "EXACT_DOMAIN",
            "evidence_source": "dns.log",
        })
        self.assertEqual(r["risk_score"], 65)

    def test_payload_delivery_without_connection_evidence(self):
        r = score_detection({
            "confidence": 75,
            "threat_type": "payload_delivery",
            "match_type": "EXACT_IP_PORT",
            "evidence_source": "conn.log",
        })
        self.assertEqual(r["risk_score"], 73)
        self.assertEqual(r["risk_level"], "High")

    def test_s0_receives_no_activity_points(self):
        r = score_detection({
            "confidence": 75,
            "threat_type": "payload_delivery",
            "match_type": "EXACT_IP_PORT",
            "evidence_source": "conn.log",
            "conn_state": "S0",
            "orig_bytes": 0,
            "resp_bytes": 0,
        })
        self.assertEqual(
            r["risk_score_details"]["network_evidence_points"], 0
        )

    def test_established_traffic_receives_activity_points(self):
        r = score_detection({
            "confidence": 75,
            "threat_type": "payload_delivery",
            "match_type": "EXACT_IP_PORT",
            "evidence_source": "conn.log",
            "conn_state": "SF",
            "orig_bytes": 100,
            "resp_bytes": 200,
        })
        self.assertEqual(
            r["risk_score_details"]["network_evidence_points"], 15
        )
        self.assertEqual(r["risk_score"], 92)

    def test_missing_confidence(self):
        self.assertEqual(confidence_weight(None)[1], 0)

    def test_invalid_confidence(self):
        self.assertEqual(confidence_weight("bad")[1], 0)
        self.assertEqual(confidence_weight(150)[1], 0)

    def test_empty_record(self):
        r = score_detection({})
        self.assertEqual(r["risk_score"], 0)
        self.assertEqual(r["risk_level"], "Low")

    def test_preserves_original_fields(self):
        r = score_detection({"match_id": "TEST-1"})
        self.assertEqual(r["match_id"], "TEST-1")

    def test_level_boundaries(self):
        self.assertEqual(risk_level(24), "Low")
        self.assertEqual(risk_level(25), "Medium")
        self.assertEqual(risk_level(50), "High")
        self.assertEqual(risk_level(75), "Critical")

    def test_batch_connection_join(self):
        detections = [{"uid": "A", "evidence_source": "conn.log"}]
        connections = [{
            "uid": "A", "conn_state": "S0",
            "orig_bytes": 0, "resp_bytes": 0
        }]
        results = score_detections(detections, connections)
        self.assertEqual(
            results[0]["risk_score_details"]["network_evidence_points"], 0
        )


if __name__ == "__main__":
    unittest.main()
