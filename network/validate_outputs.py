
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

files = {
    "connections": {
        "raw": ROOT / "zeek/logs/conn.log",
        "json": ROOT / "data/network/connections.json"
    },
    "dns": {
        "raw": ROOT / "zeek/logs/dns.log",
        "json": ROOT / "data/network/dns_queries.json"
    }
}

for name, paths in files.items():

    with open(paths["raw"], encoding="utf-8") as f:
        raw_count = sum(
            1 for line in f
            if line.strip() and not line.startswith("#")
        )

    with open(paths["json"], encoding="utf-8") as f:
        records = json.load(f)

    print(f"\n--- {name.upper()} VALIDATION ---")
    print("Raw records:", raw_count)
    print("JSON records:", len(records))
    print("Count matches:", raw_count == len(records))

    if records:
        print("First record:", records[0])

        if name == "dns":
            missing_domains = sum(
                1 for r in records if not r.get("domain")
            )
            unique_domains = len({
                r["domain"].lower().rstrip(".")
                for r in records if r.get("domain")
            })

            print("Missing domains:", missing_domains)
            print("Unique domains:", unique_domains)

        else:
            missing_ips = sum(
                1 for r in records
                if not r.get("src_ip") or not r.get("dst_ip")
            )
            print("Records missing IPs:", missing_ips)
