
import json
import ipaddress
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DNS_FILE = ROOT / "data/network/dns_queries.json"
CONN_FILE = ROOT / "data/network/connections.json"

OUTPUT_FILE = ROOT / "data/network/network_indicators.json"


def normalize_domain(domain):
    if not domain:
        return None

    return domain.strip().lower().rstrip(".")


def extract_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


with open(DNS_FILE, encoding="utf-8") as f:
    dns_records = json.load(f)

with open(CONN_FILE, encoding="utf-8") as f:
    conn_records = json.load(f)


queried_domains = set()
answer_domains = set()
answer_ips = set()
connection_ips = set()

# Extract DNS indicators
for record in dns_records:

    domain = normalize_domain(record.get("domain"))

    if domain:
        queried_domains.add(domain)

    for answer in record.get("answers", []) or []:

        ip = extract_ip(answer)

        if ip:
            answer_ips.add(ip)
        else:
            domain = normalize_domain(answer)

            if domain:
                answer_domains.add(domain)


# Extract connection IPs
for record in conn_records:

    for field in ["src_ip", "dst_ip"]:

        ip = extract_ip(record.get(field))

        if ip:
            connection_ips.add(ip)


indicators = {
    "queried_domains": sorted(queried_domains),
    "answer_domains": sorted(answer_domains),
    "answer_ips": sorted(answer_ips),
    "connection_ips": sorted(connection_ips)
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(indicators, f, indent=4)

print("Network indicator extraction completed!")
print("Queried domains:", len(queried_domains))
print("Answer domains:", len(answer_domains))
print("Answer IPs:", len(answer_ips))
print("Connection IPs:", len(connection_ips))
print("Output:", OUTPUT_FILE)
