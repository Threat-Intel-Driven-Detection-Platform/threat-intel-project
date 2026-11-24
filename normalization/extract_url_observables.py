import json
import ipaddress
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT / "data" / "all_iocs.json"
OUTPUT_FILE = ROOT / "data" / "url_derived_observables.json"


def stable_id(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


with INPUT_FILE.open(encoding="utf-8") as f:
    iocs = json.load(f)

derived = []
seen = set()
stats = Counter()

for item in iocs:
    if str(item.get("ioc_type", "")).lower() != "url":
        continue

    original_url = str(item.get("ioc", "")).strip()

    try:
        parsed = urlsplit(
            original_url if "://" in original_url else "//" + original_url
        )
        host = parsed.hostname

        if not host:
            stats["invalid_or_missing_host"] += 1
            continue

        host = host.rstrip(".").lower()

        try:
            ipaddress.ip_address(host)
            host_type = "ip"
            stats["ip_hosts"] += 1
        except ValueError:
            host_type = "domain"
            stats["domain_hosts"] += 1

        original_ref = stable_id(
            f'{item.get("source")}|{item.get("id")}|{original_url}'
        )

        common = {
            "original_ioc_ref": original_ref,
            "original_ioc_id": item.get("id"),
            "original_ioc": original_url,
            "original_ioc_type": item.get("ioc_type"),
            "source": item.get("source"),
            "confidence": item.get("confidence"),
            "threat_type": item.get("threat_type"),
            "malware": item.get("malware"),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "reporter": item.get("reporter"),
            "tags": item.get("tags", []),
        }

        host_key = (original_ref, host_type, host)

        if host_key not in seen:
            seen.add(host_key)
            derived.append({
                "observable_id": stable_id(
                    f"{original_ref}|{host_type}|{host}"
                ),
                "observable": host,
                "observable_type": host_type,
                **common,
            })
            stats["host_observables"] += 1

        try:
            port = parsed.port
        except ValueError:
            port = None
            stats["invalid_ports"] += 1

        if port is not None:
            port_value = str(port)
            port_key = (original_ref, "port", port_value)

            if port_key not in seen:
                seen.add(port_key)
                derived.append({
                    "observable_id": stable_id(
                        f"{original_ref}|port|{port_value}"
                    ),
                    "observable": port_value,
                    "observable_type": "port",
                    **common,
                })
                stats["port_observables"] += 1

    except ValueError:
        stats["invalid_urls"] += 1


OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT_FILE.open("w", encoding="utf-8") as f:
    json.dump(derived, f, indent=2, ensure_ascii=False)

print("URL Observable Extraction Complete")
print("-----------------------------------")
print("Total original IOCs:", len(iocs))
print("Derived observables:", len(derived))

for key, value in stats.items():
    print(f"{key}: {value}")

print("Output:", OUTPUT_FILE.relative_to(ROOT))
