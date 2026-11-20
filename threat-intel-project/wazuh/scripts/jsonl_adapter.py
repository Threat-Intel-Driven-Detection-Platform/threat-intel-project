import json
from pathlib import Path

base = Path.home() / "wazuh-integration"
input_file = base / "input" / "synthetic_detections.json"
output_file = base / "detections.jsonl"

with input_file.open("r", encoding="utf-8") as f:
    detections = json.load(f)

if not isinstance(detections, list):
    raise ValueError("Expected a JSON array of detections")

with output_file.open("w", encoding="utf-8") as f:
    for detection in detections:
        if not isinstance(detection, dict):
            raise ValueError("Each detection must be a JSON object")
        f.write(json.dumps(detection, ensure_ascii=False) + "\n")

print(f"Converted {len(detections)} detections")
print(f"Output: {output_file}")
