#!/usr/bin/env python3
"""
One-command runner for the Week 1 + Week 2 pipeline.

    python run_pipeline.py            # normal run
    python run_pipeline.py --reparse  # force re-parsing Zeek logs -> JSON

Steps
  0. sanity checks (Python version, files present, Git-LFS pointers)
  1. Zeek logs -> data/network/connections.json + dns_queries.json (only if missing / --reparse)
  2. REAL matching: threat_intel.db vs network data -> results/detections.json
  3. SAMPLE validation: data/iocs/sample_iocs.json must produce the expected matches
  4. summary
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable

DB = ROOT / "data" / "threat_intel.db"
CONN_LOG = ROOT / "zeek" / "logs" / "conn.log"
DNS_LOG = ROOT / "zeek" / "logs" / "dns.log"
CONN_JSON = ROOT / "data" / "network" / "connections.json"
DNS_JSON = ROOT / "data" / "network" / "dns_queries.json"
DETECTIONS = ROOT / "results" / "detections.json"
SAMPLE_OUT = ROOT / "results" / "sample_validation.json"

# every sample IOC must produce at least one detection
EXPECTED_SAMPLE_IOCS = [
    "github.com",
    "githubusercontent.com",
    "140.82.121.3:443",
    "http://185.199.110.133/lab-sample.bin",
]


def fail(msg):
    print(f"\n[ERROR] {msg}")
    sys.exit(1)


def is_lfs_pointer(path):
    with open(path, "rb") as f:
        return f.read(40).startswith(b"version https://git-lfs")


def run(cmd):
    print(f"\n$ {' '.join(str(c) for c in cmd)}")
    if subprocess.run(cmd, cwd=ROOT).returncode != 0:
        fail(f"Step failed: {' '.join(str(c) for c in cmd)}")


def main():
    reparse = "--reparse" in sys.argv

    if sys.version_info < (3, 8):
        fail("Python 3.8+ required.")

    print("== 0. Checking inputs ==")
    for p in (DB, CONN_LOG, DNS_LOG):
        if not p.exists():
            fail(f"Missing file: {p.relative_to(ROOT)}")
    for p in (CONN_LOG, DNS_LOG):
        if is_lfs_pointer(p):
            fail(f"{p.relative_to(ROOT)} is a Git-LFS pointer, not the real log.\n"
                 "        Run:  git lfs install && git lfs pull")
    print("OK")

    print("\n== 1. Zeek logs -> JSON ==")
    if reparse or not (CONN_JSON.exists() and DNS_JSON.exists()):
        run([PY, "network/conn_parser.py"])
        run([PY, "network/dns_parser.py"])
    else:
        print("JSON already present (use --reparse to rebuild)")

    print("\n== 2. REAL IOC matching (threat_intel.db) ==")
    run([PY, "network/ioc_matcher.py"])

    print("\n== 3. SAMPLE validation (lab sample IOCs) ==")
    run([PY, "network/ioc_matcher.py", "--sample-iocs"])

    with open(SAMPLE_OUT, encoding="utf-8") as f:
        sample = json.load(f)
    hit_iocs = {d["ioc_value"] for d in sample}
    missing = [i for i in EXPECTED_SAMPLE_IOCS if i not in hit_iocs]

    with open(DETECTIONS, encoding="utf-8") as f:
        real = json.load(f)

    print("\n================ SUMMARY ================")
    print(f"Real IOC detections        : {len(real)}   -> results/detections.json")
    print(f"Sample detections          : {len(sample)}   -> results/sample_validation.json")
    for i in EXPECTED_SAMPLE_IOCS:
        print(f"  [{'OK' if i in hit_iocs else 'MISSING'}] {i}")
    if not real:
        print("\nNOTE: 0 real detections is the true result for this PCAP + feed "
              "(2023 traffic vs 2026 IOCs). See README -> 'Why 0 matches'.")
    print("=========================================")

    if missing:
        fail(f"Matcher did not detect expected sample IOCs: {missing}")


if __name__ == "__main__":
    main()
