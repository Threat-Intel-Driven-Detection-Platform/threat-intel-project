"""Evidence-aware, explainable IOC risk scoring."""

import argparse
import json
from pathlib import Path

CONFIDENCE_WEIGHTS = {
    "90+": 30,
    "75-89": 24,
    "50-74": 16,
    "1-49": 8,
    "unknown": 0,
}

THREAT_WEIGHTS = {
    "payload_delivery": 12,
    "botnet_cc": 10,
    "malware": 10,
    "credential_theft": 10,
    "phishing": 8,
}

MATCH_WEIGHTS = {
    "EXACT_IP_PORT": 20,
    "URL_IP_PORT_MATCH": 18,
    "EXACT_DOMAIN": 15,
    "EXACT_IP": 14,
    "SUBDOMAIN_OF_IOC_DOMAIN": 12,
}

MAX_RAW_SCORE = 77


def confidence_weight(value):
    try:
        if value is None:
            return "unknown", 0
        value = float(value)
    except (TypeError, ValueError):
        return "unknown", 0

    if not 0 < value <= 100:
        return "unknown", 0
    if value >= 90:
        return "90+", 30
    if value >= 75:
        return "75-89", 24
    if value >= 50:
        return "50-74", 16
    return "1-49", 8


def risk_level(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def network_evidence(detection):
    source = str(detection.get("evidence_source") or "").lower()

    if source == "dns.log":
        return 5, "DNS observation recorded; no successful compromise inferred."

    if source == "conn.log":
        state = detection.get("conn_state")
        orig = detection.get("orig_bytes") or 0
        resp = detection.get("resp_bytes") or 0

        try:
            has_bytes = float(orig) > 0 or float(resp) > 0
        except (TypeError, ValueError):
            has_bytes = False

        if state == "S0":
            return 0, "S0: no reply observed; no connection activity points."

        if has_bytes:
            return 15, (
                f"Connection {state or 'unknown'} has observed traffic bytes."
            )

        return 0, (
            "Connection activity not established by available state/byte evidence."
        )

    return 0, "No supported network activity evidence."


def score_detection(detection):
    result = dict(detection)

    band, confidence_points = confidence_weight(
        detection.get("confidence")
    )
    threat = str(detection.get("threat_type") or "").lower()
    match = str(detection.get("match_type") or "").upper()

    threat_points = THREAT_WEIGHTS.get(threat, 0)
    match_points = MATCH_WEIGHTS.get(match, 0)
    network_points, network_reason = network_evidence(detection)

    raw = (
        confidence_points
        + threat_points
        + match_points
        + network_points
    )

    score = round((raw / MAX_RAW_SCORE) * 100)

    reasons = [
        f"Confidence ({band}): +{confidence_points}",
        f"Threat type ({threat or 'unknown'}): +{threat_points}",
        f"Match type ({match or 'unknown'}): +{match_points}",
        f"Network evidence: +{network_points}. {network_reason}",
    ]

    result["risk_score"] = score
    result["risk_level"] = risk_level(score)
    result["risk_score_details"] = {
        "raw_score": raw,
        "maximum_raw_score": MAX_RAW_SCORE,
        "confidence_points": confidence_points,
        "threat_type_points": threat_points,
        "match_type_points": match_points,
        "network_evidence_points": network_points,
        "reasons": reasons,
        "interpretation": (
            "IOC correlation priority. This score does not prove "
            "successful compromise or payload execution."
        ),
    }

    return result


def score_detections(detections, connections=None):
    by_uid = {
        item.get("uid"): item
        for item in (connections or [])
        if item.get("uid")
    }

    enriched = []
    for detection in detections:
        item = dict(detection)
        connection = by_uid.get(item.get("uid"))

        if connection:
            for field in ("conn_state", "orig_bytes", "resp_bytes"):
                item[field] = connection.get(field)

        enriched.append(score_detection(item))

    return enriched


def main():
    parser = argparse.ArgumentParser(
        description="Evidence-aware IOC risk scoring."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--connections", default=None)
    args = parser.parse_args()

    with Path(args.input).open(encoding="utf-8") as f:
        detections = json.load(f)

    connections = []
    if args.connections:
        with Path(args.connections).open(encoding="utf-8") as f:
            connections = json.load(f)

    if not isinstance(detections, list):
        raise ValueError("Input must be a JSON array.")

    scored = score_detections(detections, connections)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        json.dump(scored, f, indent=2, ensure_ascii=False)

    print("Input detections:", len(detections))
    print("Matched connections:", sum(
        1 for d in detections
        if any(c.get("uid") == d.get("uid") for c in connections)
    ) if connections else "Not supplied")
    print("Scored detections:", len(scored))
    print("Output:", output)

    for level in ("Low", "Medium", "High", "Critical"):
        count = sum(x["risk_level"] == level for x in scored)
        print(f"{level}: {count}")


if __name__ == "__main__":
    main()
